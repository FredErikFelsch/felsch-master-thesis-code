# Environment and reproducibility

The V0 to V2 monitors and their tests need only the standard library, so a reviewer can run
them without a package resolver. The V2 experiment scripts are the exception described below.
From V3 on, the code needs a few third-party packages, and the live path needs more.

## Requirements

- Python 3.10 or newer (the code uses `X | Y` type unions).
- V0 to V2 (`booking_v0`, `booking_v1`, `booking_v2`) and their tests: standard library only
  (for example `dataclasses`, `hashlib`, `hmac` and `json`). `run_v2.py` and `run_v2_1.py`
  also record a run manifest through `booking_v4.manifest`. That import needs `booking_v3` and
  `booking_v4` and with them `cryptography`.
- V3 to V5, the approval gate and the offline suites additionally import `cryptography`
  (signatures, WebAuthn), `PyYAML`, `requests` and `pyasn1`.
  `requirements-offline.txt` records the exact versions of the environment in which the
  offline suites ran green (Python 3.13.3, macOS). It is a record of that environment, not a
  general lock file. The Linux reference run (Python 3.10.12) used neighbouring versions and
  gave the same verdicts.
- The clients of the live path (Kubernetes, Google Cloud, the model providers) are imported
  only when a cluster or a model is used. No offline suite needs them, and they are not pinned.
- The tests that evaluate the measured policy (`tests_probe_manifests`,
  `tests_kata_policy_image`) need OPA 0.68.0. They use the first runnable binary among
  `$OPA_BIN`, the cached `results_v5/opa/opa` and `opa` on the `PATH`. The cache is filled
  for the local machine by `scripts/gke-v5/41_probe_a19.sh`. Without a runnable OPA these
  tests are skipped and say so.

## Layout and module names

The V0 to V2 packages are `booking_v0`, `booking_v1` and `booking_v2`. Each has its own
`policy.py`, `monitor.py` and `scenarios.py`.

All three versions ship together. `booking_v1` imports the unchanged leaf modules of
`booking_v0` (tools, agent, state_machine). `booking_v2` reuses the V1.2 machinery (approval,
clock, constraints, effects, freeze, ledger, lifecycle, schema) and adds `world.py`, `facts.py`,
its own `policy.py` and `monitor.py`. So V0 and V1 must both be present for V2 to run, and the
V2 experiment scripts also need V3 and V4.

## Running

All commands run from the repository root.

```bash
python3 run.py               # V0 experiment
python3 -m booking_v0.tests  # V0 tests
python3 run_v1.py            # V1.2 experiment
python3 -m booking_v1.tests  # V1.2 tests
python3 run_v2.py            # V2 experiment
python3 run_v2_1.py          # V2.1 experiment (P2.1 and the lying-world scenarios)
python3 -m booking_v2.tests  # V2 tests
python3 verify.py            # every offline test module, with a diff against the previous run
```

`python3 verify.py --quick` skips the slow service and durable modules. `-k <text>` selects
modules by name, for example `-k booking_v5`.

## Determinism

The V1 harness fixes the clock (`issued_at`, `expires_at`, `now`) and all identifiers
(`run_id`, `approver_id`, `approval_id`), so results and the policy digest are stable across
runs. No wall-clock, randomness or network is used in the core logic.

## Archiving for the thesis

When citing a specific result, record the git commit hash of the repository alongside the
reported policy digest and the schema and registry versions. For P1 that is digest `522cdeca…`
with `ps-1` and `cr-1`. For P2 it is digest
`66c97606690fe0cd7d442928cf4db514157e682d8f8b6ee53fb13cfdb458e655` with schema version
`ps-3`, constraint-registry version `cr-1` and fact-registry version `fr-2`. These values
identify the exact artefact and semantics that produced the numbers.

## Evaluated configuration

This is the configuration that Chapter 7 evaluates. Everything below is measured together.
Every record carries `manifest` (`booking_v4.manifest`: git commit, policy digests, registry
versions, TTLs, clock mode, verifier, image digests, freeze), so a number names its own
provenance. A20 is defined in `scripts/gke-v5/attack_catalogue.md`, A9 in `booking_v4/tests_k8s.py`
and A21 in `booking_v4/experiment_durable.py`.

### Policies

P2.1 (`booking_v2.policy.default_p2_1`, digest `254054d2…`) closes the drift between offer and
booking, the gap between select and its reply, the negative price and the unconfirmed payment.
It does so with four additive fact-registry kinds (`fr-2.1`: `arg_field`,
`arg_affordable_bounded`, `produced_equals_map_lookup`, `produced_equals_const`). P3 wraps P2.1
(digest `de054d83…`, with pay approval `28df9deb…`). P2 (`66c97606…`) stays the frozen V2
baseline. `run_v2_1.py` measures the lying-world scenarios under both.

### Approval gated on the pending record

`Authority.decide_intervention` signs only a fragment that a runner submitted and the Authority
parked, and the deployment surface names the refusal. The two intervention scenarios park
first, and one more scenario (`adv-approve-unsubmitted-fragment`) pins the gate. `decision_id`
on the wire keeps a new decision from replaying a stale approval out of the reply table.

### System clock in the deployed services

`service_process_tcp` and `service_v5` run `SystemClock`, and `--now` pins the clock for
offline fixtures only. `TOKEN_TTL` is 120 s and `INTERVENTION_TTL` is 300 s. The human may
shorten the intervention window but not lengthen it. The harness issues live approvals with
`booking_v1.approval.live_window`. `booking_demo.expiry` (A20) shows an approval expiring and
the control completing, and `tests_demo` steps the clock offline.

### Single writer

`DurableStore` holds an exclusive `flock`. A second service on a live store exits with code 3
(`StoreBusy`). `experiment_durable` records A21.

### Verifier

The service binary appraises with DCAP only. Every session and run record carries
`appraisal = {verifier, qv_result, fmspc, advisory_ids, tcb_level_date_tag, tcb_eval_ref_num,
collateral_earliest_expiration}`. The field is a record only, and the decision stays
`qv_result == OK`.

### Harness surface

In the V4 manifest `k8s/apply/authority.yaml`, `test.*` and `read.*` exist only on the
Authority's own listener (`--harness-bind`, port 8445). That listener is not in the Service and
is admitted to no pod, and attack A9 reaches it by port-forwarding the Deployment. The V5
services manifest (`k8s/v5/services/services.yaml`) starts no harness listener. A known limit
remains: a principal with `pods/portforward` on the namespace (the `v5-controller` role has it)
can still reach a harness listener where one is started. The surface is a test aid, not a trust
boundary.

### Reference values

A debug TD (`TDATTRIBUTES.DEBUG`) is refused before any pin is compared. `ReferenceValues()`
requires RTMR3 by default, and the weaker form has to be requested explicitly.

## Regenerating the results

`results_v3`, `results_v4_process`, `results_v4_durable` and `results_v2_1` are regenerated
offline (`python3 -m booking_v3.experiment`, `python3 -m booking_v4.experiment`,
`python3 -m booking_v4.experiment_durable` and `python3 run_v2_1.py`). `results_v4_container`
needs Docker (`python3 -m booking_v4.experiment_container`). `results_v4_k8s` and the V5 live
records (`results_v5/e2e`, `expiry` and `demo`) need the cluster (`scripts/gke`,
`scripts/gke-v5`).
`booking_v5.tests_v5_experiment` compares against `results_v4_container/results.json`. It skips,
naming the digests, when that file was measured on a different configuration. On this
configuration it expects 28 scenarios with 20 exact and 8 invariant, because the argument swap
of the intervention joins the family that is refused earlier.

For the lying world, `run_v2_1.py` (V2 plane) and `python3 -m booking_v3.experiment_world`
(V3 plane, in-process and durable) write `results_v2_1` and `results_v3/world`. `report_v5.py`
reads both for the macros of the lying-provider results (`worldScenarios`, `worldLeaksPTwo`). `booking_v3.tests.TestLyingWorld` pins the table.
