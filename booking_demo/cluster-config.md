# Cluster configuration: complete walkthrough

This document describes the cluster configuration of the V5 deployment. It is read from
`scripts/gke/_config.sh`, `scripts/gke-v5/_config.sh`, `scripts/gke-v5/12_create_cluster_v5.sh`,
`scripts/gke-v5/30_deploy_v5.sh`, `k8s/apply/*`, `k8s/v5/*` and `booking_v5/profile_v5.py`.
Each block says what is set and what it achieves.

---

## 0. The three levels, to keep the terms clean

**The operator's machine.** The orchestrator and the controller run here as processes, and the
run record is kept here. The controller talks to the cluster through a Kubernetes identity of
its own, not as admin.

**GCP.** The project, the network, the firewall, the Artifact Registry and the pod-VM image.

**The cluster.** A GKE cluster with one worker pool. Authority and Gateway run in it
permanently. The runner is created per step and disappears again.

Why this split: the controller is trusted, but it must not be able to authorise anything. It
sits outside the cluster and holds a narrow role, so this can be read from its RBAC instead of
from its code.

---

## 1. Project, region, cluster

| What | Value |
|---|---|
| Project | `project-example` |
| Region and zone | `europe-west4`, `europe-west4-a` |
| Cluster | `thesis-v5`, zonal, Standard (not Autopilot) |
| Worker | 1 node, `e2-standard-4`, image type `UBUNTU_CONTAINERD` |
| Dataplane | Dataplane V2 (`--enable-dataplane-v2`) |
| Logging and monitoring | `SYSTEM` only, managed Prometheus off |
| Release channel | regular, `--no-enable-autorepair` |
| Registry | `europe-west1-docker.pkg.dev/<project>/thesis` |
| Namespace | `agent-system` |

Why `europe-west4`: TDX-capable C3 machines exist there and not in `europe-west1`.

Why Standard instead of Autopilot: the security argument rests on the pod spec of the runner.
Autopilot changes and validates pod specs, so the measured profile would no longer be our
profile.

Why Ubuntu and containerd: peer pods need them. COS is not supported.

Why Dataplane V2: without an enforced NetworkPolicy, the confinement of the runner is only
YAML. With Dataplane V2 it also applies to peer pods, and the network probe
(`scripts/gke-v5/19_probe_network.sh`) confirmed this on peer pods.

Why `--no-enable-autorepair`: an automatically replaced node would come back without the
containerd patch, and the measurement chain would be broken silently.

---

## 2. Identities in the cloud

The node pool is called `v5-pool` and runs under the service account
`peerpods@<project>.iam.gserviceaccount.com` with the scope `cloud-platform` and the roles
`compute.instanceAdmin.v1`, `iam.serviceAccountUser`, `logging.logWriter`,
`monitoring.metricWriter` and `artifactregistry.reader`.

Why it exists at all: the Cloud API Adaptor must be able to create and delete VMs, because
every TD is a Compute instance of its own.

Why through the node and not through a key: the organisation policy
`iam.disableServiceAccountKeyCreation` forbids keys, and Workload Identity does not apply to
`hostNetwork` pods, which the CAA DaemonSet is. So the CAA uses Application Default
Credentials from the node identity. No key material exists anywhere.

Why a pool of its own: scopes are immutable per pool, so the GKE default pool is retired and
`v5-pool` is created anew.

---

## 3. Network and firewall

The pod VMs get a subnet of their own, `v5-podvm`, `192.168.200.0/24`, with Private Google
Access.

The global firewall policy `v5-runner-td-policy` is attached to it:

| Priority | Direction | Action | From | To | Ports |
|---|---|---|---|---|---|
| 1000 | EGRESS | allow | 192.168.200.0/24 | 199.36.153.8/30 | tcp:443 |
| 1001 | EGRESS | allow | 192.168.200.0/24 | node CIDR | udp:4789 |
| 65000 | EGRESS | deny | 192.168.200.0/24 | 0.0.0.0/0 | all |

In addition there are private DNS zones for `googleapis.com`, `pkg.dev` and `gcr.io`, which
point to `private.googleapis.com`.

Why a subnet of its own: the CAA sets Resource Manager tags, not network tags. A rule over
tags would be laborious, and a rule over a CIDR is just as sharp. Every statement about the
runner TDs is therefore a statement about this CIDR.

Why these priorities: the implied allow of GCP sits at 65535, so our deny must come before
it, and every allow must come before the deny. The script checks this order, so that an allow
cannot silently become an ineffective entry.

Why the two exceptions: the TD pulls its container image itself over its own network card,
which needs the Google API VIP. And the pod network runs as VXLAN to its own worker, which
needs UDP 4789. Everything else is closed. The metadata server is not closed by the firewall
but shut off inside the image.

What this achieves: a TD has no route to the open internet and no route to another TD. If
something foreign runs in the runner, it cannot carry anything out.

---

## 4. Confidential computing: CAA, Kata, pod-VM image

| What | Value |
|---|---|
| Cloud API Adaptor | 0.21.1, Helm chart `peerpods` |
| Kata | 3.31.0 (subchart, agent, policy rules, genpolicy) |
| Pod VM | `c3-standard-4`, `TDX`, `pd-balanced`, 20 GB |
| Pod-VM image | `podvm-fedora-tdx-caa-0-21-1-ov<rev>`, built by us (`PODVM_OVERLAY_REV` in `scripts/gke-v5/_config.sh`) |
| Public IP | `USE_PUBLIC_IP: false` |
| Ports | forwarder tcp 15150, VXLAN udp 4789 |
| Limit | `PEERPODS_LIMIT_PER_NODE: 10` |
| RuntimeClass | `kata-remote` |

Why CAA 0.21.1 and nothing older: older versions have no Helm chart, always give every pod VM
a public IP and tunnel over it. That would be incompatible with the firewall claim.

Why an image of our own: the reference values must be reproducible. The image is a function
of the pinned CAA tag and our overlay, whose hash is recorded in the provenance.

The overlay does three things. It measures the init-data into RTMR3, because the init-data
does not appear in the quote on GCE. It orders the agents so that this measurement happens
before them. And it disables the IMDS NAT set-up of the pod VM (`setup-nat-for-imds`), so
that the metadata server cannot be reached from inside the TD. The build also removes the
mount unit `run-kata-containers.mount`, which would otherwise block the sandbox boot.

Why this matters: without our own measurement, nobody could verify which guest policy the TD
was started with. The expected RTMR3 history is exactly `[init-data, boot-key, bind]`, and the
Authority replays it.

---

## 5. What runs in the cluster

The deployment creates the namespace, the ServiceAccounts, the storage, the controller
identity, a ConfigMap with the freeze, optionally a Secret with the PCS key and two empty
Secrets. Then come the init Job, then Authority and Gateway, then the NetworkPolicies.

**Authority**, one replica, from the services image. The command is
`python3 -m booking_approval.service` with the arguments
`--db /data/authority.db --bind 0.0.0.0:8443 --verifier dcap
--gateway-observe gateway-observe.agent-system.svc.cluster.local:8444`, plus the arguments of
the approval gate (`--credentials`, `--approval-bind 0.0.0.0:8450`, `--origin`,
`--frame-ancestor`, see `k8s/v5/services/services.yaml`). The approval page on 8450 has no
Service and is reached only through `kubectl port-forward`. The Authority has its own PVC and
`automountServiceAccountToken: false`.

**Gateway**, one replica, same image, arguments
`serve --role gateway --db /data/gateway.db --bind 0.0.0.0:8443 --observe 0.0.0.0:8444
--world-db /data/world.db --idempotent`. Its own PVC. No API token.

**Two Services for the Gateway**: `gateway` on 8443 and `gateway-observe` on 8444.

**Trusted init**, a one-shot Job. It seeds both databases from one minting, computes the
init-data digest of the deployment from the runner image and publishes the anchors only.

All containers run as `runAsNonRoot`, UID 65532, with `readOnlyRootFilesystem`,
`allowPrivilegeEscalation: false`, `capabilities: drop ALL` and
`seccompProfile: RuntimeDefault`.

Why two separate surfaces on the Gateway: execution and reading the ledger are different
capabilities. The Authority may read, to check the reported observation against what the
Gateway wrote down. It may not execute. This is visible in the manifest and not only in the
code.

Why a separate init Job: the key material is created in the cluster and not on the operator's
machine. The Job may write only two Secrets, through a Role with `resourceNames`.

Why a PVC per role: Authority and Gateway share no state. A compromised Gateway cannot
rewrite the grant history.

---

## 6. RBAC

| Resource | orchestrator-sa | controller-sa | runner-sa | v5-controller | init-sa |
|---|---|---|---|---|---|
| Pods create/delete | denied | denied | denied | allowed | denied |
| Pods get/list/watch | denied | allowed | denied | allowed | denied |
| pods/attach | denied | allowed | denied | allowed | denied |
| pods/portforward | denied | denied | denied | allowed | denied |
| Jobs CRUD | denied | allowed | denied | denied | denied |
| Secrets | denied | denied | denied | `ar-pull` only | two named only |
| PeerPod CRs | denied | denied | denied | get, list, patch | denied |
| Deployments, Roles, anything cluster-wide | denied | denied | denied | denied | denied |

`orchestrator-sa`, `runner-sa`, `authority-sa` and `gateway-sa` have
`automountServiceAccountToken: false`, appear in no binding and therefore have no rights at
all.

Why `v5-controller` may create pods but not read ConfigMaps: it is meant to start TDs, attach
to them and clean them up again. It must not be able to touch the reference values or the
Authority. The deploy script checks this actively and aborts if the context can read
ConfigMaps.

Why `pods/attach` with `get` and `create`: the channel to the runner is an attach stream. Over
WebSocket the handshake is a GET, over SPDY it is a POST. Both verbs mean the same thing, and
no other identity is granted either.

Why `peerpods` only with `get`, `list` and `patch`: this is the cleanup path. The finalizer is
removed only once the cloud has confirmed that the VM is gone. The controller cannot create
or delete PeerPod CRs.

---

## 7. NetworkPolicies in `agent-system`

First `default-deny-all` over all pods, for ingress and egress. Then only these paths are opened:

| From | To | Port |
|---|---|---|
| runner | authority | 8443 |
| runner | gateway | 8443 |
| runner | kube-dns | 53 |
| authority | gateway-observe | 8444 |
| authority | Intel PCS, that is 0.0.0.0/0 | 443 |
| gateway | DNS only | 53 |

Not present and therefore forbidden: Authority to the execution surface of the Gateway,
Gateway to Authority, runner to anything else, and every pod to the observation surface
except the Authority.

Why DNS only through the namespace selector: the usual rule with an additional pod label is
dropped on Dataplane V2. This was bisected live. Namespace plus port stays narrow enough.

Why the Authority may reach the open internet on 443: it fetches the DCAP collateral from
Intel. It is trusted, and the security argument concerns the confinement of the runner.

Why the Gateway may only use DNS: the counterparty is in-process here. In a real setup this
would be the place where a single destination address would be opened.

---

## 8. The runner pod

It is created with `generateName: runner-td-`, the label `app: runner`,
`runtimeClassName: kata-remote`, the annotation `io.katacontainers.config.hypervisor.cc_init_data`
holding base64(gzip(TOML)) and in addition the plain-text digest in `v5/init-data-sha256`.

`serviceAccountName: runner-sa`, `automountServiceAccountToken: false`,
`restartPolicy: Never`, memory 512 Mi, CPU 100m, `/tmp` as a 16 Mi tmpfs, the image pinned by
digest, and the command fixed to `python -m booking_v5.runner_main`.

The pod spec is a pure function of image, namespace and name. Fragment, envelope, policy and
credential are not in it. They arrive over the attach stream.

Why the command is fixed in the manifest and does not come from the entrypoint: the command is
part of what the measured guest policy pins down.

Why a pure function: two different fragments produce a byte-identical pod template. This makes
it checkable offline that untrusted content does not end up in the pod spec.

Why a pod and not a Job as in V4: the TDs of the warm pool live until they are bound, and the
controller manages their lifecycle itself.

---

## 9. The Fixed Execution Profile has two halves

The **guest half** is measured by the hardware: MRTD, RTMR0 to 2, the init-data hash and the
image digest that the guest policy enforces.

The **substrate half** is established by the controller and asserted as a hash:
RuntimeClass `kata-remote`, machine `c3-standard-4`, TEE `TDX`, subnet `192.168.200.0/24`,
firewall rules `v5-allow-peerpod-tunnel` and `v5-runner-td-policy:65000-deny-egress`, and
NetworkPolicies `default-deny-all` and `runner-egress`.

The Authority accepts only the combination, with pinned reference values for both halves.

Why this separation: attestation proves that the TD is genuine and what ran in it. It does
not prove which network the VM sits in. The controller produces that, and so it must assert it
explicitly to the Authority for it to become verifiable.

---

## 10. What is not connected

By default there is no LoadBalancer and no Ingress. Everything is ClusterIP, and access from
outside goes through the Kubernetes API.

There is no Trustee and no KBS in operation. `TRUSTEE_VERSION` is empty, the Authority runs
with `--verifier dcap` and verifies in-process. It is the relying party in the RATS sense, and
there is no additional service that would have to be trusted.

There is no secret store such as OpenBao in the default deployment. The anchors are created in
the init Job. OpenBao is an optional extension behind the Gateway (`k8s/v5/openbao/`) and does
not change the research question.

There is no model in the cluster. The orchestrator calls the external model API from the
operator's machine. The cluster has no egress to it.

There is no real outside world by default. The world is in-process in the Gateway,
`--world-db /data/world.db`. The Gateway is the only place where, in a real setup, the backend
identity would live.

There is no API token for orchestrator, runner, Authority and Gateway. `orchestrator-sa`,
`runner-sa`, `authority-sa` and `gateway-sa` cannot talk to the Kubernetes API at all.

There is no DevOps application in the cluster. The Gateway image knows only the booking world.

---

## 11. Where the controller runs

On the operator's machine, with a token context instead of the admin context. The deploy
script mints it with `kubectl create token v5-controller --duration=6h`.

The demo call looks like this:

```
python3 -m booking_demo.run --mode v5 --mail fraud-payee --model openai --approve wait \
  --project "$PROJECT" --zone "$ZONE" --registry europe-west1-docker.pkg.dev \
  --impersonate "v5-controller@$PROJECT.iam.gserviceaccount.com" \
  --admin-context "$(kubectl config current-context)" --pool 5 --attack a16
```

Why this is worth stating: during a run the controller does not act as admin. If someone asks
whether an all-powerful process simply collects everything here, the answer is the
`v5-controller` Role from section 6.

---

## 12. Lifecycle and cost

The chain `99_full_run_v5.sh` runs unattended: offline suites, bring-up, verify, deploy,
verify, measurements, teardown. On an error it stops and leaves the cluster standing.
`DESTROY_ON_FAILURE=1` reverses this. It commits nothing.

The cluster is destroyed after the measurements with `90_destroy_v5.sh`. A standing cluster
with C3 instances is the real cost, so cleaning up is part of the chain and not a matter of
discipline.

The warm pool is the reason why a step usually takes about 23 seconds instead of about 110.
These are the medians of `total_s` over the attested steps of the cluster runs recorded under
`results_v5/demo/` (warm and cold hand-offs).

---

## 13. Known open points

The runner image of a freeze can lag behind the source tree. A freeze is bound to a runner
digest. If the runner sources change afterwards, the image of the freeze no longer matches the
tree line by line. The recorded runs stay functionally valid when the changed paths are on the
Authority side, because they take effect in the cluster through the rebuilt services image.
The reproducibility chain does not stay valid, because the freeze is bound to a runner digest
that the changed tree no longer produces. The rule is to rebuild once, after the code
freeze. A new digest changes `policy.rego` through genpolicy, and with it the init-data hash,
RTMR3 and therefore all reference values and measurements.

The init-data digest was once not reproducible, because the generator wrote its own timestamp
into the comment header. This is fixed. The generator writes no timestamp any more, a
preflight in `scripts/gke-v5/40_verify_v5.sh` compares both renderings, and four tests cover it.
