#!/usr/bin/env bash
# 50_run_security_suite.sh: runs the live evaluation against the deployed cluster.
#
# Needs:  The deployment from 30_deploy.sh, python3, kubectl, and for --freeze the image digests
#         from 20_build_push_images.sh and results_v4_container/results.json.
# Usage:  ./scripts/gke/50_run_security_suite.sh [--enforcement-only|--freeze]
# Result: The suite output, and for --freeze the evidence under results_v4_k8s/evidence. Exit code
#         non zero on any failure.
#
# Two modes:
#   --enforcement-only  run only the enforcement suite (default). The semantic
#                       evaluation is skipped. Enough for a smoke check.
#   --freeze            the V4.4c freeze gate. Everything mandatory must run and
#                       pass: platform verification, the full enforcement suite
#                       with no skipped tests, and the frozen evaluation (P8/P9) whose
#                       results.json must equal the container backend's in every result
#                       field and in the configuration half of the run manifest
#                       (policies, registry, TTLs). Any skip, failure or missing
#                       prerequisite exits non-zero, so the freeze cannot pass by omission.
#
# Two artefacts, kept apart (see booking_v4/k8s_deployment.py):
#   A. the enforcement suite (booking_v4.tests_k8s) against the full in-cluster
#      enforcement topology. RBAC via `kubectl auth can-i --as`, runner network
#      confinement via probe vs in-cluster canary, Job lifecycle, controller-crash,
#      and crash-after-grant -> EFFECT_UNCERTAIN. The Python helpers open their own
#      short-lived port-forwards per operation, so the crash test does not leave a
#      dead forward behind. This script starts no global port-forward.
#   B. the frozen evaluation (booking_v4.experiment_k8s) run in-cluster by
#      60_run_freeze_eval.sh (namespace agent-eval, the harness co-locates the
#      durable Authority and presents as app=authority to its runner Jobs), which
#      copies results_v4_k8s/ out and compares it with the container backend's
#      results.json.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

# An unknown argument is refused, so a mistyped --freeze does not run as a smoke check.
case "${1:-}" in
  ""|--enforcement-only) MODE="enforcement-only" ;;
  --freeze) MODE="freeze" ;;
  *) die "usage: $0 [--enforcement-only|--freeze]" ;;
esac

say "verifying platform first (RBAC + NetworkPolicy enforcement)"
"${SCRIPT_DIR}/40_verify_platform.sh"

export K8S_LIVE=1
export K8S_NAMESPACE="${NAMESPACE}"
export PROBE_IMAGE="${PROBE_IMAGE:-busybox:1.36}"
export EXPECTED_RUNNER_IMAGE="${RUNNER_IMAGE:-}"
[ -f "${DIGEST_FILE}" ] && { source "${DIGEST_FILE}"; export RUNNER_IMAGE EXPECTED_RUNNER_IMAGE="${RUNNER_IMAGE}"; }

if [ "${MODE}" = "freeze" ]; then
  say "freeze mode: enforcing all prerequisites"
  [ -n "${PROBE_IMAGE:-}" ] || die "freeze needs PROBE_IMAGE (network confinement test)"
  [ -f "${MOCKS_DIR}/results_v4_container/results.json" ] \
    || die "freeze needs results_v4_container/results.json (the container backend's frozen record)"
  # A9 needs the harness listener live in the Authority pod (its own port 8445,
  # authority.yaml). A freeze must not pass with A9 wired to a missing surface.
  auth_args="$(kubectl -n "${NAMESPACE}" get deploy/authority \
    -o jsonpath='{.spec.template.spec.containers[0].args}' 2>/dev/null || true)"
  case "${auth_args}" in
    *--harness-bind*) : ;;
    *) die "freeze: Authority is not running --harness-bind (A9 needs the harness listener). Redeploy with ./30_deploy.sh" ;;
  esac
fi

say "A. running the live enforcement suite (booking_v4.tests_k8s)"
evidence_dir="${MOCKS_DIR}/results_v4_k8s/evidence"
if [ "${MODE}" = "freeze" ]; then
  mkdir -p "${evidence_dir}"
  suite_log="${evidence_dir}/enforcement-suite-$(date -u +%Y%m%dT%H%M%SZ).log"
else
  suite_log="$(mktemp)"
fi
( cd "${MOCKS_DIR}" && python3 -m booking_v4.tests_k8s -v ) 2>&1 | tee "${suite_log}"
if [ "${MODE}" = "freeze" ]; then
  if grep -Eq "skipped=[1-9]|\.\.\. skipped" "${suite_log}"; then
    die "freeze: the enforcement suite skipped mandatory tests (see ${suite_log})"
  fi
  say "enforcement evidence saved to ${suite_log}"
fi

if [ "${MODE}" = "freeze" ] || [ "${RUN_EVAL:-}" = "1" ]; then
  say "B. running the frozen evaluation in-cluster (60_run_freeze_eval.sh)"
  [ -n "${RUNNER_IMAGE:-}" ] || die "RUNNER_IMAGE not set (run 20_build_push_images.sh)"
  "${SCRIPT_DIR}/60_run_freeze_eval.sh" || die "freeze: in-cluster frozen evaluation failed"
else
  say "B. SKIPPED (enforcement-only): use --freeze, or RUN_EVAL=1 for the frozen evaluation alone"
fi

# Keep the freeze evidence log. Only the enforcement-only temp log is discarded.
[ "${MODE}" = "freeze" ] || rm -f "${suite_log}"
say "security suite complete (${MODE})"