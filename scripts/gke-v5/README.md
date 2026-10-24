# V5: scripts for the CoCo peer-pods (TDX) environment

These scripts create, verify, measure and destroy the V5 environment: a GKE cluster with
Confidential Containers peer pods on Intel TDX. The numbering continues the V4.4c convention.
The V4.4c scripts in `scripts/gke/` keep their behaviour, because V4.4c is frozen. Every script
documents its inputs, its usage and its result in its header. Settings and pins come from
`_config.sh`. The attack labels (A5, A5b, A5c, A10 to A20) are defined in `attack_catalogue.md`.

## The scripts

Setup of the substrate:

    00_preflight_v5.sh       read-only preflight: tools, authentication, the offline suite. Run it before 12
    11_build_podvm_image.sh  builds our pod-VM image from the pinned CAA commit (mkosi, Fedora, TDX) and registers it as a GCE image
    12_create_cluster_v5.sh  cluster, containerd patch (scripted ssh), pod-VM subnet, tunnel firewall rules, A5b egress policy
    13_genpolicy.sh          generates policy.rego from the final runner Pod with genpolicy, then tightens it
    14_install_coco.sh       peerpods chart from the pinned CAA tag (bundles kata-deploy), CAA started on ADC
    15_render_caa_values.sh  peerpods service account (no key) and k8s/v5/caa/values-gcp.yaml
    16_install_trustee.sh    Trustee AS/RVPS/KBS, not used by the evaluated deployment (needs k8s/v5/trustee, not in this repository)
    23_build_services_image.sh  builds and pushes the services image (authority, gateway, init)
    30_deploy_v5.sh          deploys the two service principals, the trusted init and the controller identity

Probes:

    18_probe_peer_pod.sh     P1 smoke, P2 measured runner, P3 RTMR. Each probe ends in a named verdict, none uses exec
    19_probe_network.sh      A5 through the tunnel (policy and no-policy CONTROL probes), A5b, A5c metadata
    22_probe_attach.sh       the controller-to-runner channel: pods/attach round trips into a measured echo pod (ATTACH_OK)
    41_probe_a19.sh          offline: the measured runner policy denies host writes to the init-data files (A19)
    20_verify_evidence_offline.py  offline: quote structure, REPORTDATA binding, init-data search, RTMR3 replay, reference values JSON
    21_dcap_verify.sh        Intel DCAP QVL in a linux/amd64 container (booking_v5/dcap vendored verifier, PCS_API_KEY from env)

Verification:

    40_verify_v5.sh          the live substrate against the pinned Fixed Execution Profile
                             (CAA, RuntimeClass, both tunnel rules, the three policy rules,
                             pod-VM subnet, annotation allowlist, worker containerd, substrate hash).
                             `--offline` runs only the test suites and needs no cluster.
                             NetworkPolicies (A5) are verified live by 19, not by 40: 40
                             checks the fixed substrate, and agent-system does not exist yet.
    36_assert_observation_v5.sh  asks the deployed Authority whether it checks observations against the effect ledger

Runs on the deployed cluster:

    31_run_fragment_v5.sh    one cold fragment end to end, or a series (STEPS, REPEAT, POOL)
    32_negative_v5.sh        the negative cases live (A14, A10, A16, A11, A18), each must refuse with ledger delta zero
    33_demo_v5.sh            demo act 3: the agent's plan on the cluster, one attested TD per step, approval with
                             a passkey on the Authority's approval page (49), optional --attack
    34_expiry_v5.sh          A20 live: an intervention approval expires against the system clock of the deployed services
    35_transport_attack_v5.sh  the transport attack live, see `attack_catalogue.md`
    49_approval_page.sh      forwards the Authority's approval page to the person who approves

Live world (optional, see `k8s/v5/openbao/README.md`):

    37_install_openbao.sh    credential store and the gateway's way of proving who it is
    38_negative_live_v5.sh   what each party in the live world cannot reach
    39_live_evidence.py      checks one recorded live run against the claim it supports
    45_live_evaluation.sh    the live evaluation against Duffel, unattended, one evidence verdict per claim
    47_demo_up.sh, 48_demo_up_quick.sh, 47_demo_down.sh  bring a live demo cluster up and tear it down

Teardown:

    90_destroy_v5.sh         destroys everything V5 (pods → cluster → orphan VMs → firewall → DNS → subnet), keeps the pod-VM image and the service account
    91_cleanup_probe.sh      removes probe leftovers (namespaces, debugger pods, orphan pod VMs) and verifies that the substrate matches 12

Chains and helpers:

    97_offline_regenerate.sh  the offline tier of the final run: the whole suite as a gate, then every result artefact regenerated
    98a_freeze_prepare.sh    phase A of the final measurement: rebuilds the runner image and produces a new freeze candidate
    98b_measure_and_teardown.sh  phase B: deploys on the pinned freeze, runs every measurement, regenerates the tables, tears down
    99_full_run_v5.sh        the full chain unattended: offline suites, bring-up, verification, measurements, teardown
    100_final_chain.sh       the final measurement campaign in one command, resumable with START_AT
    pin_freeze.py            pins a verified freeze candidate in _config.sh and tests_v5_fixtures.py
    _config.sh, _genpolicy.sh, _node_pin.sh, _peerpod_cleanup.sh, _rules_backport.py, _run_lib.sh  shared by the scripts above

## Order of a run

    00 preflight → 12 cluster → 15 caa values → 14 coco → 40 verify
       → 13 genpolicy → 41 a19 → 23 services image → 30 deploy
         → 40 verify → 36 observation → 31 run → 32 negative → …

The pod-VM image (11, 30 to 60 minutes) is built once per overlay revision and before 15. The
runner and services images are built by `scripts/gke/20_build_push_images.sh` and 23. The live
world adds 37 and 38 after 30.

After a new pod-VM image, the probe sequence is: rebuild and push the runner image → 11 → 12 →
15 → 14 → 40 (substrate against the pin, record it) → 13 → 23 → 18 (expect P2 `EVIDENCE_OK`, P3
`RTMR_OK`) → 19 (expect metadata BLOCKED in the peer-pod probe) → 20 (expect
`INITDATA_MEASURED`, `V5_BINDING_OK`, `V5_RTMR3_REPLAY_OK`, exit 0) → 21 (expect VERIFIED on the
new image) → 22 (expect `ATTACH_OK`) → freeze the new reference values → 91 → 90.
`98a_freeze_prepare.sh` runs this sequence unattended up to the freeze candidate (without 11,
and from 12 on only with `CREATE_CLUSTER=1`).

## What the probes establish

| Question | Script | Finding |
|---|---|---|
| Can the CAA create a peer pod on GKE at all? | 12, 14, 18 | Yes. CAA 0.21.1 runs on the node service account with a pod-VM image built from source by 11 (`podvm-fedora-tdx-caa-0-21-1`). Google's pre-built `fedora-mkosi-tee-amd-1-11-0` boots under TDX, but its forwarder does not speak to CAA 0.21.1. An nginx peer pod became Ready in 93 s on c3-standard-4 TDX, with guest pull through `private.googleapis.com` only. |
| Do nginx and our runner image boot as peer pods, and how long does it take? | 18 | nginx 85 s. The runner under the measured profile (genpolicy init-data) takes 88 to 97 s cold. |
| Can evidence be fetched from the Attestation Agent with runtime data, and can RTMR3 be extended? | 18, 20, 21 | Evidence is obtained unprivileged (EVIDENCE_OK, 45 737 B). RTMR3 can be extended through `POST /aa/aael` with `enable_eventlog = true` in aa.toml, and the replay formula in 20 reproduces the live RTMR3. The init-data hash is not in the quote (MRCONFIGID is 0 on GCE and `bind_init_data` only compares), so a guest-side RTMR3 extend must happen before the agent starts. DCAP verification of the quote succeeds offline (21, `qv_result` OK). MRTD and RTMR0 to 2 are stable across repeated boots (20). |
| Does `pods/attach` (WebSocket) carry stdin and stdout through kata-remote? | 22, 31 | Yes. The runner protocol runs over `pods/attach`. Logs work through kata-remote as well. |
| Does A5 hold through the tunnel, and what does the deny rule do on the pod-VM NIC (A5b)? | 19 | A5 passes. Dataplane V2 enforces NetworkPolicy for peer pods, and the CONTROL probes show that the tunnel carries the full pod network. A5b is NOT_APPLICABLE as a probe in tunnelled mode, but the deny policy is live and was shown to be effective: it blocked our own VXLAN until rule 1001 was added. A5c: on an unhardened image the metadata server is reachable from inside the TD container. The pod-VM overlay closes it, see `k8s/v5/podvm-overlay/README.md`. |

If the CAA could not create a peer pod, or if evidence needed privileges, the fallback would
be GCE TDs launched by the controller. Neither condition occurred, so the fallback is not
used.

Lessons built into the scripts:

- Peer pods guest-pull over the VM NIC. Docker Hub images must come through `mirror.gcr.io`.
- VXLAN needs firewall rules in both directions plus an explicit allow inside the A5b deny
  policy (rule 1001), because the pod network runs underneath the substrate firewall.
- `describe || create` idempotency silently keeps stale rules, so 12 updates them.
- `gcloud … network-firewall-policies rules list` does not exist. Use `describe`.
- CAA 0.21.1 `peerpod-ctrl` has no gcp provider registered. Its `controllers/` directory has
  aws, azure, libvirt, ibmcloud, alibabacloud, byom and powervs, and no `gcp.go`, although the
  Makefile lists gcp. Every PeerPod CR on GCP therefore keeps its `peer.pod/finalizer` forever
  ("gcp cloud provider not supported"), and a namespace holding one never finishes
  Terminating. The CAA daemon itself deletes the VMs fine. 91 removes the finalizer once GCE
  confirms the VM is gone. The V5 controller does the same for its runner namespace (the
  alternative would be a one-file upstream fix of peerpod-ctrl).

Housekeeping: run `91_cleanup_probe.sh` after every probe session, because each peer pod is a
running c3 TDX VM. Run `90_destroy_v5.sh` when the cluster is not needed for days. 12 → 15 →
14 rebuilds it.

## Offline code that specifies the attacks

The offline tests (`python3 -m booking_v5.tests_v5_offline`) specify A10 to A17. Only the GKE
run demonstrates them.

    booking_v5/binding.py        the boot key as TD identity, the single bind, the canonical binding,
                                 the byte check before execution, the sealed session box
    booking_v5/evidence.py       runtime_data, Attestation Agent client and fake
    booking_v5/relying_party.py  Authority RP: step-bound nonces, the core and the strengthened invariant, scoped sessions
    booking_v5/pool.py           pool that does not reuse a TD and sweeps on start
    booking_v5/profile_v5.py     measured profile: kata-remote and the init-data annotation (pure function)
    k8s/v5/init-data/            aa.toml, cdh.toml, policy.rego (guest-side hardening)

## Design decisions

- The Authority runs outside a TD. Moving it into one is later work.
- The ledger invariant is the core: one boot key, at most one fragment. The RTMR3 history is
  the strengthened invariant on top of it, and the reference values require RTMR3 by default.
- The pool is either cold or a small static warm pool. The idle cost is measured, and there is
  no autoscaling question.
- A5b is part of the Fixed Execution Profile as its substrate-enforced half
  (`profile_v5.SUBSTRATE_PROFILE`). The Authority pins it next to the guest measurements (test
  A18).

## Design rules and why

- The TD identity is the boot key H(pk_boot), generated once right after boot. A binding
  freezes one (run, step, f, s) onto it. Core invariant (ledger): one boot key, at most one
  fragment. Strengthened invariant (RTMR3): history == [init-data, boot-key, bind]. The probe
  decides what the guest allows, and nothing is assumed.
- The canonical binding H("V5-BIND"||version||nonce||run||step||f||s||pk_boot||pk_sig) is the one
  definition used for runtime_data (pk_sig from binding v5.1 on). `evidence.py` re-exports
  `binding.canonical_binding`.
- Verified bytes: the TD checks H(fragment bytes) and H(envelope bytes) against the attested
  hashes right before V3 (`binding.Binding.verify_bytes`, test A16).
- Sessions are sealed to pk_boot and scoped server-side to (run, step, f, s, pk). The grant path
  looks sessions up by (run, step) (test A17).
- `policy.rego` is generated by genpolicy (13) and tightened. There is no manual "privileged"
  heuristic, and `${RUNNER_IMAGE}` is asserted to be rendered.
- 14 uses the peerpods chart of the pinned CAA tag. `CAA_VERSION` and `PODVM_IMAGE` are
  independent pins. 16 (not used by the evaluated deployment) asserts that `TRUSTEE_VERSION`
  is rendered into its manifests.
- 18 reports a named verdict per probe, separates the smoke probe from the measured-runner
  probe, and runs the RTMR probe as the container's initial command (the policy forbids exec).

## Pins: one CAA line, two image profiles (`V5_PINS=probe|freeze`)

`CAA_VERSION=0.21.1` (image `v0.21.1-amd64`), with the chart `install/charts/peerpods` of that
tag, which bundles kata-deploy (kata-remote) and peerpod-ctrl. Why not the documented 0.17.0:
the source tag shows that 0.17.0 has no chart, always attaches a public IP to the pod VM and
tunnels over it (incompatible with the dedicated subnet and A5b), and its entrypoint
hard-requires a key file.

- `probe` (default) uses our own pod-VM image from the pinned CAA commit (11, provenance in
  `results_v5/podvm-image/`). Google's pre-built `fedora-mkosi-tee-amd-1-11-0` is documented for
  CAA 0.17. It boots under TDX as a derived copy with `TDX_CAPABLE`, but its forwarder does not
  talk to CAA 0.21.1. `V5_DERIVED_IMAGE=1` re-enables that derived copy in 15. Newer pre-built
  images do not exist under that naming (0-21-x, 0-22-0, 1-12, 1-13 and 2-0 were probed).
- `freeze` leaves `PODVM_IMAGE` empty unless it is set, so the image must be named explicitly.
- `TRUSTEE_VERSION=<tag>` is empty by default, because the default deployment has no Trustee.

Credentials: the org policy `iam.disableServiceAccountKeyCreation` forbids service-account
keys, and Workload Identity does not cover hostNetwork pods (the CAA DaemonSet is one). So the
CAA runs on Application Default Credentials, that is the node service account. 12 creates the
node pool `v5-pool` with the service account `peerpods@…` (roles `compute.instanceAdmin.v1`,
`iam.serviceAccountUser`, `logging.logWriter`, `monitoring.metricWriter`,
`artifactregistry.reader`) and the scope `cloud-platform`, and retires `default-pool`. 14
starts the CAA binary directly, bypassing the entrypoint's key check. No key material exists
anywhere. The pool runs the GKE metadata server (`--workload-metadata GKE_METADATA`), so
ordinary pods (the orchestrator included) do not see the node service account. Only hostNetwork
pods do, and the CAA is the only one in this deployment. The TDs do not run on that node.

Networking: pod VMs live in a dedicated subnet (192.168.200.0/24, no public IP), and A5b is a
global network firewall policy keyed on that CIDR. The CAA's `TAGS` are Resource Manager tags,
not network tags, so tag-based rules were dropped.

## Known caveat: the containerd patch does not survive node recreation

GKE warns that boot-disk changes are lost on node (re)creation (upgrade, auto-repair,
autoscaling). 12 is idempotent, so re-running it re-applies the patch. For a measured run,
12 sets `--no-enable-autorepair` and a maintenance exclusion (`no_minor_or_node_upgrades`, 14
days, `V5_MAINTENANCE_EXCLUSION=0` to skip, `V5_EXCLUSION_DAYS` to change), because node
auto-upgrades cannot be disabled per pool while the cluster is in a release channel. GKE
therefore cannot recreate a node mid-campaign and silently remove the patch. The node version
is a pinned input of the freeze (`_node_pin.sh`: 12 requires that the version is offered, 30
checks the pin), and 40 checks the containerd configuration of every worker. A DaemonSet-based
patch would be the durable alternative if the CoCo chart did not already ship one for peer
pods.

## Pod-VM overlay, security gate and replay

- `k8s/v5/podvm-overlay/` is applied by 11 on top of CAA's podvm files. It measures the
  init-data digest into RTMR3 before the agents start and closes the metadata path (A5c). The
  image name gains `-ov<PODVM_OVERLAY_REV>`, and the overlay sha256 is in the provenance and in
  the image description. See `k8s/v5/podvm-overlay/README.md`.
- Security gate: the GHSA-fmg6-v47x-52wr mount-source fix is backported onto the 3.31.0
  `rules.rego` by `_rules_backport.py`, pinned by hash in `_genpolicy.sh`. The freeze test A19
  covers that a host CopyFile onto `/run/peerpod/*` is denied.
- `booking_v5/rtmr_replay.py` and `tests_rtmr_replay.py` hold the relying party's RTMR3 replay,
  pinned against a recorded live fixture. The expected history is [init-data, boot-key, bind].
- `aa.toml` enables the AA event log (`[eventlog_config]`), which is what makes `/aa/aael`
  extend RTMR3.

## The probe runs the production sequence

- `booking_v5/probe_bind.py` replaces a random-digest probe. Inside the pod VM it generates the
  boot key, records `v5 boot-key <pk>` and `v5 bind <run>/<step>/<f>/<s>` through
  `POST /aa/aael`, and fetches evidence over the canonical binding. It also fetches evidence
  before its own events, so "did the overlay measure the init-data" and "did our events land"
  stay separable. No phase is fatal: a failure leaves its reason in the log and the pod alive.
- `Dockerfile.runner` and `Dockerfile.k8s` copy `booking_v5` into the image. After a change to
  it, rebuild and push the runner image (`scripts/gke/20_build_push_images.sh`), otherwise
  `booking_v5.probe_bind` does not exist in the container and P2 fails.
- 18 draws the binding fields and the nonce (there is no Authority in a probe run), records them as
  `binding-<STAMP>.json`, and takes `runtime-data-<STAMP>.txt` from the runner's own
  `RUNTIME_DATA` line, so 20 and 21 work unchanged. P3 is "both AAEL events recorded".
- 20 reports `VERDICT v5-binding` (REPORTDATA against the canonical binding recomputed from the
  recorded fields and `PK_BOOT`, compared against the bytes of the hardware and not against our
  own file) and `VERDICT v5-rtmr3` (replay of [init-data, boot-key, bind]). Its exit code is 0
  only when both are OK. `V5_PROBE_DIR` points it at a synthetic run for the dry-run tests.
- `booking_v5/tests_probe_analysis.py` is the dry run of this analysis. It builds the evidence
  that a correct TD would produce from the real recorded quote, and checks that 20 goes red for
  a wrong step, a missing bind event, an unmeasured init-data and a foreign boot key.

## How the scripts reconcile and why

12 reconciles instead of keeping.

- **Priorities.** The policy has two allow rules, so `FW_PRIO_ALLOW < FW_PRIO_DENY` is not
  enough. With ALLOW=1000 and DENY=1001, the derived second allow would sit at the priority of
  the deny and do nothing. Both are named (`FW_PRIO_ALLOW_GOOGLEAPI`, `FW_PRIO_ALLOW_VXLAN`,
  collected in `FW_PRIO_ALLOWS`), all of them are overridable, and 12 validates every one
  against the deny, and for uniqueness, before touching a resource.
- **Reconcile, not "safe to rerun".** `describe || create` keeps whatever is there, which let a
  stale VXLAN rule survive a rerun. `fw_rule_ensure` and `fwp_rule_ensure` create when missing
  and otherwise update every field to the pin. The immutable fields of the pod-VM subnet (CIDR,
  network) are compared and abort the run, and its Private Google Access is switched back on.
  DNS zones are attached to our network if they are not, and record sets are updated when their
  rrdatas drift. A field that cannot be updated in place (the direction of a rule) aborts.
- **Association last.** All policy rules are created or reconciled first, and the policy is
  associated with the network at the end. The order deny → associate → allows would open a
  window on a rerun in which running pod VMs are denied everything, including their own VXLAN.
- **Association idempotency.** `gcloud compute network-firewall-policies associations` has
  only `create` and `delete`, with no `list` and no `describe`. Existence is therefore read
  from `network-firewall-policies describe "${FW_POLICY}"` (associations are a field on the
  policy itself).
- **Node patch.** See the caveat above. The remote patch snippet fails with a readable reason
  when the containerd config does not carry the key at all.

`booking_v5/tests_substrate_script.py` runs 12 against a fake gcloud and kubectl
(`booking_v5/testdata/fake_cloud.py`) that records every call. It asserts the three things
that otherwise cost a cluster run: the association happens after all rules, existing resources
are updated rather than kept, and an unrepairable drift aborts.

Further lessons:

- **The interpreter path.** The GKE image is built from `Dockerfile.k8s` on `python:3.11-slim`,
  where python3 is `/usr/local/bin/python3` and there is no `/usr/bin/python3`. A hardcoded
  path makes the run die as `CreateContainer: the file /usr/bin/python3 was not found`, after a
  full TD boot, CAA handshake and guest pull. `20_build_push_images.sh` therefore reads the path
  out of the built image and records `RUNNER_PYTHON` in `.digests`. 18 uses it and, where
  docker is available, preflights `RUNNER_PYTHON -m booking_v5.probe_bind` against the pinned
  image.
- **The image the cluster runs.** `booking_v5` must be copied into `Dockerfile.k8s`
  and not only into `Dockerfile.runner` (the local, offline variant). The build step checks
  that both `booking_v4` and `booking_v5` import before it pins the digest.
- **P1 on an overlay image.** Init-data is part of the measured boot path, and `initdata-measure`
  fails without `/run/peerpod/initdata.digest`. The guest does not gate itself, so on an image
  whose name ends in `-ov<rev>` P1 expects the pod to become Ready anyway
  (`READY_UNMEASURED_OK`). A failed measurement must not break the boot, and the Authority
  refuses the unmeasured TD (`V5_RTMR3_MISMATCH`). `NOT_READY` versus `NO_PODVM` tells an
  overlay that breaks the boot apart from a broken CAA.
- **19 on an overlay image.** Its peer-pod probes carry a permissive init-data
  (`booking_v5/permissive_policy.py`, request names read from the pinned `rules.patched.rego`).
  Without init-data, every A5 and A5c verdict would come back UNDECIDED. Such a TD cannot be
  confused with a runner TD: its init-data digest goes into RTMR3, so the Authority's reference
  pin refuses its evidence.
- **The probe deadline.** The probe manifest raises `activeDeadlineSeconds` (probe only,
  `PROBE_DEADLINE`), because 300 s counted from pod start has to cover TD boot, guest pull and
  the log-collection window. `booking_v5/tests_probe_manifests.py` locks these points down.
- **A5c needs a durable mechanism.** Removing the enablement symlink of
  `setup-nat-for-imds.service` does not hold, because mkosi's own preset
  (`30-coco.preset`: `enable setup-nat-for-imds.service`, the only preset entry for this unit)
  re-creates it during `make image`. 19 shows the effect: with the metadata path open, the
  regular-pod group is BLOCKED on 169.254.169.254:80 and the peer-pod group is OPEN, with
  `169.254.169.254 dev veth2 scope link` in the peer pod's route table. The overlay therefore
  hardens the image at build time, see `k8s/v5/podvm-overlay/README.md`.
- **19's CONTROL group and the canary.** The CONTROL group targets its own canary in
  `v5-netprobe-open`, which has no NetworkPolicy, so every CONTROL target is a plumbing
  baseline. An earlier version reused the canary of `v5-netprobe`, whose `default-deny-all`
  (`policyTypes: [Ingress, Egress]`) refused ingress regardless of the caller's namespace.
