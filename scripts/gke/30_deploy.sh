#!/usr/bin/env bash
# 30_deploy.sh: deploys the manifests in trust order, from version control only.
#
# Needs:  kubectl with a context for the cluster from 10, python3, and scripts/gke/.digests from
#         20_build_push_images.sh. Images are pinned by digest from that file.
# Usage:  ./scripts/gke/30_deploy.sh
# Result: The Authority and the controller running with the NetworkPolicies in force. If the
#         trusted init Job or a rollout fails, the script dumps diagnostics and exits non zero.
#
# Nothing here is clicked together by hand: the manifests in k8s/ are applied in a
# fixed sequence that follows the trust order:
#   1. namespace, ServiceAccounts, RBAC (orchestrator and runner get no Job verbs).
#   2. the Authority PVC.
#   3. the controller Secret, pre-created empty (init-sa can only patch it).
#   4. the trusted init Job: seeds the PVC and writes the controller Secret in-cluster.
#      The script waits for it to complete (and release the RWO PVC) before the Authority
#      mounts it. The authority material is created here, not in the repository and not
#      by the orchestrator.
#   5. the Authority Deployment (restore-only), then the controller Deployment.
#   6. the NetworkPolicies last, so they do not block the init Job's API egress on a first
#      deploy (default-deny would). From here on every pod is confined.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

[ -f "${DIGEST_FILE}" ] || die "no ${DIGEST_FILE}: run 20_build_push_images.sh first"
# shellcheck disable=SC1090
source "${DIGEST_FILE}"
export CONTROLLER_IMAGE RUNNER_IMAGE
[ -n "${CONTROLLER_IMAGE:-}" ] && [ -n "${RUNNER_IMAGE:-}" ] || die "digests not set"

# Substitute only ${CONTROLLER_IMAGE} and ${RUNNER_IMAGE}, with python3: it is present
# anyway, and it avoids the gettext/envsubst dependency that stock macOS lacks.
render() {
  CTRL_IMG="${CONTROLLER_IMAGE}" RUN_IMG="${RUNNER_IMAGE}" python3 - "${APPLY_DIR}/$1" <<'PY'
import os, sys
s = open(sys.argv[1]).read()
s = s.replace("${CONTROLLER_IMAGE}", os.environ["CTRL_IMG"]).replace("${RUNNER_IMAGE}", os.environ["RUN_IMG"])
sys.stdout.write(s)
PY
}

# Directory for init-pod log snapshots: pods of a failed Job can be garbage-collected
# (ttlSecondsAfterFinished / backoff cleanup) before a post-mortem runs, so logs are
# captured while the pods still exist.
INIT_LOG_DIR="$(mktemp -d)"

# snapshot_init_logs: save the current log of every init pod (idempotent overwrite).
snapshot_init_logs() {
  local pod
  for pod in $(kubectl -n "${NAMESPACE}" get pods -l job-name=trusted-init \
                 -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    kubectl -n "${NAMESPACE}" logs "${pod}" --all-containers --tail=200 \
      > "${INIT_LOG_DIR}/${pod}.log" 2>&1 || true
  done
}

# wait_job NAME TIMEOUT_SECONDS
#   returns 0 on Complete, 1 on Failed, 2 on timeout. Unlike
#   `kubectl wait --for=condition=complete`, a failed Job returns immediately.
wait_job() {
  local name="$1" timeout="$2" elapsed=0 conds
  while [ "${elapsed}" -lt "${timeout}" ]; do
    snapshot_init_logs
    conds="$(kubectl -n "${NAMESPACE}" get job "${name}" \
      -o jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}' 2>/dev/null || true)"
    grep -q '^Complete=True' <<<"${conds}" && return 0
    grep -q '^Failed=True'   <<<"${conds}" && return 1
    sleep 5; elapsed=$((elapsed + 5))
  done
  return 2
}

# rollout_or_die DEPLOYMENT TIMEOUT: `rollout status`, and on failure dump the pod
# state + logs of that Deployment (Pending/CrashLoop/probe failures are visible at once).
rollout_or_die() {
  local deploy="$1" timeout="$2"
  if kubectl -n "${NAMESPACE}" rollout status "deploy/${deploy}" --timeout="${timeout}"; then
    return 0
  fi
  echo "----- PODS (app=${deploy}) -----";     kubectl -n "${NAMESPACE}" get pods -l "app=${deploy}" -o wide 2>&1 || true
  echo "----- POD DESCRIBE (app=${deploy}) -----"; kubectl -n "${NAMESPACE}" describe pods -l "app=${deploy}" 2>&1 || true
  echo "----- POD LOGS (app=${deploy}) -----"; kubectl -n "${NAMESPACE}" logs -l "app=${deploy}" --all-containers --tail=100 2>&1 || true
  echo "----- PREVIOUS LOGS (app=${deploy}) -----"; kubectl -n "${NAMESPACE}" logs -l "app=${deploy}" --all-containers --previous --tail=100 2>&1 || true
  echo "----- NODE ALLOCATION -----";          kubectl describe nodes 2>&1 | grep -A 8 'Allocated resources' || true
  echo "----- RECENT EVENTS -----";            kubectl -n "${NAMESPACE}" get events --sort-by=.lastTimestamp 2>&1 | tail -30 || true
  die "deployment ${deploy} did not become ready within ${timeout} (diagnostics above)"
}

# dump_init_diagnostics: everything needed to see why init failed, in one place.
dump_init_diagnostics() {
  snapshot_init_logs
  echo "----- TRUSTED INIT JOB -----";   kubectl -n "${NAMESPACE}" describe job trusted-init 2>&1 || true
  echo "----- PODS -----";               kubectl -n "${NAMESPACE}" get pods -l job-name=trusted-init -o wide 2>&1 || true
  echo "----- POD DESCRIBE -----";       kubectl -n "${NAMESPACE}" describe pods -l job-name=trusted-init 2>&1 || true
  echo "----- POD LOGS (snapshots) -----"
  local f
  for f in "${INIT_LOG_DIR}"/*.log; do
    [ -f "${f}" ] || { echo "(no pod logs captured)"; break; }
    echo "=== $(basename "${f}" .log) ==="; cat "${f}"
  done
  echo "----- RECENT EVENTS -----";      kubectl -n "${NAMESPACE}" get events --sort-by=.lastTimestamp 2>&1 | tail -40 || true
  echo "----- ACTIVE NETWORKPOLICIES -----"; kubectl -n "${NAMESPACE}" get networkpolicy 2>&1 || true
}

say "1/6 namespace, service accounts, RBAC"
kubectl apply -f "${APPLY_DIR}/namespace.yaml"
kubectl apply -f "${APPLY_DIR}/serviceaccounts.yaml"
kubectl apply -f "${APPLY_DIR}/rbac.yaml"

say "2/6 authority durability volume"
kubectl apply -f "${APPLY_DIR}/storage.yaml"

say "3/6 pre-create the controller Secret empty (trusted deploy step, cluster-admin)"
# init-sa only patches this by name. It cannot create Secrets. Pre-creating it
# empty here (idempotent) is what lets the init RBAC stay create-free.
kubectl -n "${NAMESPACE}" create secret generic "${BOOTSTRAP_SECRET}" \
  --dry-run=client -o yaml | kubectl apply -f -

say "4/6 trusted init (seed PVC + patch the controller Secret in-cluster)"
# Jobs are largely immutable: delete any prior init Job so a re-run actually runs.
kubectl -n "${NAMESPACE}" delete job trusted-init --ignore-not-found --wait=true
# On a redeploy the Authority from a previous run still holds the ReadWriteOnce PVC. The
# init Job mounts the same volume. Scheduled on another node it would sit in Pending
# forever (Multi-Attach error). The Authority is the single writer of that store, so
# it must be down while init (re)seeds it. Scale both apps to 0 and wait until their
# pods are gone. Step 5 rolls them out again. No-op on a first deploy.
for app in controller authority; do
  if kubectl -n "${NAMESPACE}" get "deploy/${app}" >/dev/null 2>&1; then
    say "  redeploy: stopping ${app} (releases the RWO volume for the init Job)"
    kubectl -n "${NAMESPACE}" scale "deploy/${app}" --replicas=0
    kubectl -n "${NAMESPACE}" wait --for=delete pod -l "app=${app}" --timeout=120s || true
  fi
done
# On a redeploy the NetworkPolicies from the previous run are still active while
# init runs. Make that visible up front (init-egress must allow app=trusted-init).
if kubectl -n "${NAMESPACE}" get networkpolicy -o name 2>/dev/null | grep -q .; then
  say "  note: NetworkPolicies from a previous deploy are active during init"
fi
render init.yaml | kubectl apply -f -
# 600s: tolerate a cold first image pull. The actual work takes seconds.
set +e
wait_job trusted-init 600
rc=$?
set -e
case "${rc}" in
  0) say "  trusted init completed" ;;
  1) dump_init_diagnostics; die "trusted init Job failed (diagnostics above)" ;;
  *) dump_init_diagnostics; die "trusted init Job timed out after 600s (diagnostics above)" ;;
esac
rm -rf "${INIT_LOG_DIR}"

say "5/6 authority, then controller"
render authority.yaml | kubectl apply -f -
# The harness surface (A9 fault injection, read-back) is on the Authority's own 8445
# listener (authority.yaml), unreachable from any pod by NetworkPolicy. No patching.
rollout_or_die authority 120s
render controller.yaml | kubectl apply -f -
rollout_or_die controller 120s

say "6/6 network policies (default-deny + confinement)"
kubectl apply -f "${APPLY_DIR}/networkpolicy.yaml"

say "deployed. pods:"
kubectl -n "${NAMESPACE}" get pods -o wide