#!/usr/bin/env bash
# 47_demo_up.sh: brings the CoCo cluster up for a live demo against Duffel, on the pinned freeze.
#
# Needs:  DUFFEL_TOKEN (a test-mode token) in the environment, gcloud, kubectl, helm, docker, and the
#         pinned freeze from _config.sh.
# Usage:  export DUFFEL_TOKEN=duffel_test_...
#         caffeinate -ims ./scripts/gke-v5/47_demo_up.sh
#         then: python3 -m booking_demo.serve   (mode "v5 cluster", world duffel)
# Result: A running cluster with the world duffel deployed. Exit code non zero if a bring-up step or
#         the readiness check fails. Tear down with 47_demo_down.sh.
#
# The steps:
#
#   00 preflight, 12 cluster, 15 CAA values, 14 CoCo
#   23 services image (current code), 30 deploy with BOOKING_WORLD=duffel, 37 OpenBao
#   checks: gateway serves world duffel with the current adapter, Authority binds the
#           policy admission, 38 network proofs, 40 (both reported, not fatal)
#
# No 13/20: the runner image and its init-data are the pinned freeze (_config.sh), so no
# new measurement is needed.
# No -e: every step reports its own status through step(), and the chain decides.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCKS_DIR="$(cd "${HERE}/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"; mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/demo-up-${STAMP}.log"
exec > >(tee -a "${LOG}") 2>&1

source "${HERE}/_run_lib.sh"
NS="agent-system"

finish() { summarise "$1" "Demo cluster ready" "Demo cluster FAILED"; exit "$1"; }

say "preflight"
[ -n "${DUFFEL_TOKEN:-}" ] || die "DUFFEL_TOKEN is not set (37 stores it in OpenBao)"
case "${DUFFEL_TOKEN}" in duffel_test_*) ;; *) die "DUFFEL_TOKEN is not a test-mode token (duffel_test_...)";; esac
common_preflight
if kubectl cluster-info >/dev/null 2>&1; then
    say "a cluster is already reachable ($(kubectl config current-context)), skipping 00/12/15/14"
    HAVE_CLUSTER=1
else
    HAVE_CLUSTER=0
fi

if [ "${HAVE_CLUSTER}" = "0" ]; then
    step "00 preflight"         ./scripts/gke-v5/00_preflight_v5.sh      || finish 1
    step "12 create cluster"    ./scripts/gke-v5/12_create_cluster_v5.sh || finish 1
    step "15 render caa values" ./scripts/gke-v5/15_render_caa_values.sh || finish 1
    step "14 install coco"      ./scripts/gke-v5/14_install_coco.sh      || finish 1
fi
step "23 build services (current code)" ./scripts/gke-v5/23_build_services_image.sh || finish 1
step "30 deploy (world duffel)" env BOOKING_WORLD=duffel RESEED_WORLD=1 ./scripts/gke-v5/30_deploy_v5.sh || finish 1
step "37 OpenBao + credential"  ./scripts/gke-v5/37_install_openbao.sh || finish 1

ready() {
    kubectl -n "${NS}" logs deploy/gateway | grep -m1 "\[gateway\] world=duffel" || return 1
    kubectl -n "${NS}" logs deploy/authority | grep -m1 "policy admission bound" || return 1
    kubectl -n "${NS}" exec deploy/gateway -- grep -q HOLD_UNSUPPORTED_CARRIERS /app/booking_live/duffel.py \
        || { echo "gateway runs an older adapter"; return 1; }
    kubectl -n "${NS}" exec deploy/gateway -- grep -q arg_equals_const /app/booking_v2/facts.py \
        || { echo "services image predates the journey binding"; return 1; }
    kubectl -n "${NS}" exec deploy/gateway -- grep -q "def effect_identity" /app/booking_v3/gateway.py \
        || { echo "services image predates the gateway-derived idempotency key"; return 1; }
    kubectl -n "${NS}" exec deploy/gateway -- grep -q "def require_test_mode" /app/booking_live/duffel.py \
        || { echo "services image predates the Duffel test-mode guard"; return 1; }
    kubectl -n "${NS}" logs deploy/authority | grep "approval-gate\] installed" >/dev/null \
        || { echo "the Authority runs without the approval gate (booking_approval)"; return 1; }
}
step "gateway world duffel, admission bound, current adapter" ready || finish 1
step "38 network proofs (reported)" ./scripts/gke-v5/38_negative_live_v5.sh || true
step "40 verify (reported)"         ./scripts/gke-v5/40_verify_v5.sh        || true

cat <<'NEXT'

########################################################################
DEMO CLUSTER READY (world duffel, pinned freeze).

  ./scripts/gke-v5/49_approval_page.sh   # the Authority's approval page, http://localhost:8450/
  python3 -m booking_demo.serve          # http://127.0.0.1:8765/
  mode "v5 cluster - attested (CoCo)", world duffel, model openai

The dashboard starts v5 runs without DUFFEL_TOKEN in their environment.
When done:  caffeinate -ims ./scripts/gke-v5/47_demo_down.sh
########################################################################
NEXT
finish 0
