#!/usr/bin/env bash
# 60_run_freeze_eval.sh: runs the frozen evaluation in-cluster (semantic equivalence).
#
# Needs:  kubectl, python3, scripts/gke/.digests from 20_build_push_images.sh, and
#         results_v4_container/results.json as the baseline.
# Usage:  ./scripts/gke/60_run_freeze_eval.sh. Also invoked by `50_run_security_suite.sh --freeze` (part B).
# Result: results_v4_k8s/results.json and results.md, and the harness log under
#         results_v4_k8s/evidence. Exit code non zero on any deviation.
#
# Applies k8s/apply/eval.yaml (namespace agent-eval: harness Job that co-locates
# the durable Authority and plays the controller role, runner-sa, default-deny,
# a copy of runner-egress that tests_k8s_offline keeps equal), waits for the harness to
# finish, copies results_v4_k8s/{results.json,results.md} out of the pod into
# ./results_v4_k8s/, keeps the harness log as evidence, and compares every result field of
# results.json with the container backend's, plus the configuration half of the run manifest
# (policies, registry, TTLs) and P8/P9.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

[ -f "${DIGEST_FILE}" ] || die "no ${DIGEST_FILE}: run 20_build_push_images.sh first"
# shellcheck disable=SC1090
source "${DIGEST_FILE}"
[ -n "${CONTROLLER_IMAGE:-}" ] && [ -n "${RUNNER_IMAGE:-}" ] || die "digests not set"

EVAL_NS="agent-eval"
JOB="eval-harness"
OUT_DIR="${MOCKS_DIR}/results_v4_k8s"
EVIDENCE_DIR="${OUT_DIR}/evidence"
mkdir -p "${OUT_DIR}" "${EVIDENCE_DIR}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
HARNESS_LOG="${EVIDENCE_DIR}/eval-harness-${STAMP}.log"

render() {
  CTRL_IMG="${CONTROLLER_IMAGE}" RUN_IMG="${RUNNER_IMAGE}" python3 - "${APPLY_DIR}/$1" <<'PY'
import os, sys
s = open(sys.argv[1]).read()
s = s.replace("${CONTROLLER_IMAGE}", os.environ["CTRL_IMG"]).replace("${RUNNER_IMAGE}", os.environ["RUN_IMG"])
sys.stdout.write(s)
PY
}

pod_of_job() {
  kubectl -n "${EVAL_NS}" get pods -l "job-name=${JOB}" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
}

cleanup() {
  # Always tear the harness down. Leftover runner Jobs in agent-eval go with it.
  kubectl -n "${EVAL_NS}" delete job "${JOB}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl -n "${EVAL_NS}" delete jobs -l managed-by=trusted-runner-controller \
    --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

say "1/4 applying the in-cluster evaluation topology (${EVAL_NS})"
kubectl -n "${EVAL_NS}" delete job "${JOB}" --ignore-not-found --wait=true >/dev/null 2>&1 || true
render eval.yaml | kubectl apply -f -

say "2/4 waiting for the harness to finish (every V3 scenario, one Job per fragment, about 15 to 30 min)"
# The container prints RC=<n> when the evaluation is done, then idles so the results can
# be copied out. Poll the log for that marker. A Failed pod ends the wait early.
deadline=$(( $(date +%s) + 7200 ))
pod=""; rc=""
while [ "$(date +%s)" -lt "${deadline}" ]; do
  [ -n "${pod}" ] || pod="$(pod_of_job)"
  if [ -n "${pod}" ]; then
    phase="$(kubectl -n "${EVAL_NS}" get pod "${pod}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    kubectl -n "${EVAL_NS}" logs "${pod}" > "${HARNESS_LOG}" 2>/dev/null || true
    rc="$(grep -E '^RC=[0-9]+$' "${HARNESS_LOG}" | tail -1 | cut -d= -f2 || true)"
    [ -n "${rc}" ] && break
    if [ "${phase}" = "Failed" ] || [ "${phase}" = "Succeeded" ]; then break; fi
  fi
  sleep 10
done
[ -n "${pod}" ] || die "harness pod never appeared (kubectl -n ${EVAL_NS} describe job ${JOB})"
echo "----- HARNESS LOG (tail) -----"; tail -40 "${HARNESS_LOG}"
[ -n "${rc}" ] || { kubectl -n "${EVAL_NS}" describe pod "${pod}" | tail -30; die "harness did not report RC= (timeout or crash, full log: ${HARNESS_LOG})"; }
[ "${rc}" = "0" ] || die "in-cluster evaluation exited with rc=${rc} (log: ${HARNESS_LOG})"

say "3/4 copying results out of the harness pod"
kubectl -n "${EVAL_NS}" exec "${pod}" -- cat /app/results_v4_k8s/results.json > "${OUT_DIR}/results.json"
kubectl -n "${EVAL_NS}" exec "${pod}" -- cat /app/results_v4_k8s/results.md   > "${OUT_DIR}/results.md"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${OUT_DIR}/results.json" \
  || die "results.json is not valid JSON"
say "  wrote ${OUT_DIR}/results.json and results.md, harness log ${HARNESS_LOG}"

say "4/4 comparing results_v4_k8s against results_v4_container (semantic equivalence)"
( cd "${MOCKS_DIR}" && python3 - <<'PY'
import json, sys
k = json.load(open("results_v4_k8s/results.json"))
c = json.load(open("results_v4_container/results.json"))
if not (k.get("p8_differential_conformance") and k.get("p9_all_dispatches_authorized")):
    sys.exit("FREEZE FAIL: P8/P9 not satisfied on the Kubernetes backend")
# The run manifest names the provenance of each record (time, host, git, images) and is
# different per run by design. Its configuration half must agree, the rest is not compared.
mk, mc = k.pop("manifest", {}) or {}, c.pop("manifest", {}) or {}
for key in ("policies", "registry", "ttl"):
    if mk.get(key) != mc.get(key):
        sys.exit(f"FREEZE FAIL: manifest.{key} differs: k8s={mk.get(key)} container={mc.get(key)}")
if k != c:
    diffk = sorted(key for key in set(k) | set(c) if k.get(key) != c.get(key))
    sys.exit(f"FREEZE FAIL: k8s results differ from container backend in {diffk}")
print(f"OK: Kubernetes results compare equal in every result field to the container backend "
      f"({len(k['results'])}/{len(k['results'])}, P8, P9); same policies, registry and TTLs")
PY
) || die "semantic-equivalence comparison failed"
say "in-cluster frozen evaluation complete"
