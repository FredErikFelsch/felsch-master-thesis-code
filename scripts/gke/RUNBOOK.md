# V4.4c GKE runbook (minimal cost)

The end-to-end walkthrough for the real Kubernetes run: create a disposable, cheap GKE cluster
from version-controlled scripts, run the V4.4c live evaluation, archive the evidence, and
destroy everything. Nothing here is clicked together by hand. Every step is one script.

> Rule for cost: the cluster is disposable and the only meaningful cost is
> leaving it running. Run `90_destroy_cluster.sh` when you are done. Everything
> else in this profile rounds to cents per run.

## What it costs (and why it is almost free)

| Item | Choice | Cost |
|------|--------|------|
| GKE management fee | one **zonal Standard** cluster | **$0** (free tier covers one zonal cluster) |
| Nodes | **2× Spot `e2-standard-2`** (2 dedicated vCPU / 8 GB each) | ~**$0.04/h** (~$0.13/h on-demand) |
| Boot disk | 32 GB `pd-standard` | ~$0.001/h |
| Networking | ClusterIP only, no LoadBalancer | $0 |
| Metrics | managed-prometheus off, SYSTEM logging | negligible |
| Artifact Registry | one ~250 MB image | ~$0.03/mo (purge with `90 --purge-images`) |

A full create, run and destroy cycle is well under an hour of node time, which is a couple of
cents. The failure mode that actually costs money is forgetting to destroy. Two idle Spot
`e2-standard-2` cost about $30 a month, and on-demand about $100 a month. So: destroy.

> Why `e2-standard-2`, not `e2-medium`: `e2-medium` is shared-core with only ~940m
> allocatable, and the GKE Dataplane V2 kube-system pods (anetd/cilium, kube-dns,
> konnectivity, metrics, fluentbit, pdcsi) take 700 to 800m of it. Authority,
> controller, init and every runner Job request 100m each (the runner profile is
> frozen), so on e2-medium they sat in `Pending: Insufficient cpu` (observed live).
> Two `e2-standard-2` (~1930m allocatable each) leave ample headroom. Still cents.

Why **Standard, not Autopilot**: the V4.4c claim is about the exact runner Pod profile.
Autopilot mutates and validates pod specs and injects defaults, which would break the "fixed
profile, byte-identical for every fragment" property. Standard accepts the precise spec
that `k8s_backend` builds.

Why **Spot**: the experiment is short and fully re-runnable, and a rare preemption just means
re-running. Set `USE_SPOT=false` for an on-demand node if you want zero preemption risk during
a long debugging session.

## One-time local prerequisites (done once by the operator, never scripted)

By design, the scripts do not perform interactive authentication. They only check it. Do these
once on your machine:

    gcloud auth login                              # human login
    gcloud auth application-default login          # ADC for the clients
    gcloud config set project <YOUR_PROJECT_ID>
    gcloud components install gke-gcloud-auth-plugin
    docker buildx version                           # buildx present (Docker Desktop has it)

`00_check_prerequisites.sh` verifies all of the above without changing anything.

## Knobs (override any as environment variables, the defaults are the minimal-cost profile)

    REGION=europe-west1   ZONE=europe-west1-c   CLUSTER=thesis-v44c
    NODE_MACHINE=e2-standard-2   NUM_NODES=2   USE_SPOT=true
    DISK_TYPE=pd-standard   DISK_SIZE=32   CLUSTER_SCOPE=zonal
    AR_LOCATION=<REGION>   AR_REPO=thesis   IMAGE_NAME=booking   IMAGE_TAG=v44c

## The happy path: cheap enforcement smoke (recommended first run)

This proves the core V4.4c claim (A1 to A9) and costs a few cents.

    ./scripts/gke/00_check_prerequisites.sh     # ~5 s   read-only checks
    ./scripts/gke/10_create_cluster.sh          # ~5 to 8 min  enables APIs, creates cluster
    ./scripts/gke/20_build_push_images.sh       # ~2 to 4 min  buildx amd64 --push, pins digest
    ./scripts/gke/30_deploy.sh                  # ~2 min  applies k8s/apply in trust order
    PROBE_IMAGE=busybox:1.36 \
      ./scripts/gke/50_run_security_suite.sh --enforcement-only   # ~3 min  A1 to A9 (runs 40 first)
    ./scripts/gke/90_destroy_cluster.sh         # ~3 to 5 min  archives digests, deletes cluster

All commands run from the repository root.

A9 (crash-after-grant) uses the Authority's harness listener (port 8445, `--harness-bind` in
`authority.yaml`). That surface is never on the application port. It is not in the Service,
the NetworkPolicy admits no pod to it, and the harness reaches it with
`kubectl port-forward deploy/authority` (kubelet path). No deploy-time flag is needed, and
nothing about the deployment is weaker for the test run.

## The freeze run: everything mandatory, no skips

The freeze gate refuses to pass by omission. It requires the enforcement suite with no skipped
tests and the full semantic-equivalence run, and it fails unless every result field of the
Kubernetes `results.json` equals the container backend's. The run manifest is compared in its
configuration half (policies, registry, TTLs), because its provenance half differs per run.

    ./scripts/gke/00_check_prerequisites.sh
    ./scripts/gke/10_create_cluster.sh
    ./scripts/gke/20_build_push_images.sh
    ./scripts/gke/30_deploy.sh
    PROBE_IMAGE=busybox:1.36 \
      ./scripts/gke/50_run_security_suite.sh --freeze     # 40 + A1 to A9 + in-cluster equivalence
    ./scripts/gke/90_destroy_cluster.sh          # archives results_v4_k8s/environment/image-digests.env

`50 --freeze` verifies that the Authority pod runs its harness listener (`--harness-bind`),
saves the enforcement-suite log under `results_v4_k8s/evidence/`,
then runs part B through `60_run_freeze_eval.sh`. Archive `results_v4_k8s/results.json`,
`results_v4_k8s/results.md`, both evidence logs (`enforcement-suite-*.log`,
`eval-harness-*.log`) and `results_v4_k8s/environment/image-digests.env` as the V4.4c freeze
record before destroying.

### How the frozen evaluation runs in-cluster (`60_run_freeze_eval.sh`, `k8s/apply/eval.yaml`)

The frozen evaluation harness co-locates the durable Authority/Gateway with itself, and the
runner Job pods must reach that Authority. But runner egress is confined to `app=authority:8443`,
and a pod cannot reach your laptop. So the harness runs inside the cluster, in its own
namespace `agent-eval`, as a Job that carries `app=authority`, is fronted by a Service named
`authority`, binds `0.0.0.0:8443` and advertises `authority.agent-eval.svc.cluster.local:8443`
to its runners. The runner side is identical to agent-system (runner-sa without token,
default-deny, a copy of `runner-egress` that `tests_k8s_offline` keeps equal). The harness
holds the controller Role's verbs (`eval-sa`). Nothing in agent-system is touched, so
the enforcement topology and its Service endpoints stay clean. `60` waits for the harness's
`RC=<n>` line, copies `results.json` and `results.md` out with `kubectl exec cat`, keeps the
harness log as evidence and performs the comparison. To run only the frozen evaluation
(after a green enforcement run), use `RUN_EVAL=1 ./scripts/gke/50_run_security_suite.sh` or
simply `./scripts/gke/60_run_freeze_eval.sh`.

Budget: every V3 scenario with a few fragments each, one Job each (about 10 to 20 s per Job for
schedule, attach, execute, delete-and-confirm), so expect 15 to 30 minutes. The harness Job's
`activeDeadlineSeconds` is 7200.

## Teardown discipline

`90_destroy_cluster.sh` first archives `scripts/gke/.digests` (the resolved image digest and
the `runner_process.py` sha256, which is evidence that survives the cluster) to
`results_v4_k8s/environment/image-digests.env`. Then it deletes the cluster, which removes
every namespace, PVC and Secret, so all in-cluster authority material is gone. Add
`--purge-images` to also delete the Artifact Registry image. Re-running any earlier script
recreates the environment reproducibly from version control.

## Troubleshooting quick hits

* **`gke-gcloud-auth-plugin` not found** → `gcloud components install gke-gcloud-auth-plugin`.
* **`arm64`/exec-format pod crash** → you built on Apple Silicon without buildx. Step 20
  already forces `--platform linux/amd64`, so ensure buildx is the active builder.
* **init Job hangs on a redeploy** → the `init-egress` NetworkPolicy allows it to reach
  the API. If you edited policies, confirm `app=trusted-init` egress to 443 and DNS.
* **Image pull `403 Forbidden` from `*-docker.pkg.dev`** → the node service account
  lacks `roles/artifactregistry.reader` (common on newer or auto-created projects).
  `20_build_push_images.sh` grants it (repository-scoped). If you hit this on an older
  cluster, grant it to the node SA (`PROJNUM-compute@developer.gserviceaccount.com`
  for the default SA) and re-run `30` after about 1 to 2 min.
* **PVC `ZONE_RESOURCE_POOL_EXHAUSTED`** → the zone is transiently out of that disk
  type. `storage.yaml` uses `premium-rwo` (pd-SSD) to dodge a busy pd-balanced pool.
  If a whole zone is exhausted, recreate in another (`ZONE=europe-west1-b` …).
* **Pods `Insufficient cpu`** → you overrode `NODE_MACHINE` with a shared-core type
  (e2-medium/small). The default `e2-standard-2` has the headroom. Recreate (90, 10).
* **Runner DNS blocked / A5 positive control fails** → check the DNS egress rule of the runner
  NetworkPolicy. On Dataplane V2 the `namespaceSelector: kube-system` + port 53 rule works,
  while pod-label and ipBlock rules do not.
* **`internal controller error` on spawn** → `kubectl -n agent-system logs deploy/controller`
  shows the `[controller-audit]` line with the real cause (for example a 403 on pods/attach).
* **Empty replies through port-forward** → check `/tmp/k8s-port-forward.log` (`K8S_PORTFORWARD_LOG` overrides it). A busy
  local 8443/9443 is refused fail-closed (`lsof -nP -iTCP:8443 -sTCP:LISTEN`).
* **Redeploy `30` stuck at the init Job** → `30` stops authority and controller first
  (the init Job needs the ReadWriteOnce PVC). If you see `Multi-Attach`, that is why.
* **`40`/`50` fail on `pods/attach` verbs** → the controller Role needs both `get` and
  `create` (WebSocket attach is a GET). Check that `rbac.yaml` was re-applied by `30`.
* **`context deadline exceeded` right after cluster creation** → transient
  control-plane warm-up. Just re-run the step.
* **Spot node preempted mid-run** → just re-run `50`. State on the PVC survives. Re-run
  from `30` if the node was replaced.
* **A9 fails on the harness port** → the Authority pod is not running `--harness-bind` (check
  `kubectl get deploy/authority -o jsonpath='{.spec.template.spec.containers[0].args}'`) or a
  stale local port-forward holds 8445.
* **`50 --freeze` dies on prerequisites** → it refuses to pass by omission. Provide
  `PROBE_IMAGE` and keep `results_v4_container/results.json`.
* **`60` dies with `harness did not report RC=`** → run
  `kubectl -n agent-eval logs job/eval-harness` and `kubectl -n agent-eval get jobs,pods`.
  A runner Job stuck in Pending is CPU (see above), a `403` on pods/attach is the
  eval-harness Role, and a hang at the first scenario is the harness not reaching its own
  `authority.agent-eval` Service (check `eval-harness-policy`).
