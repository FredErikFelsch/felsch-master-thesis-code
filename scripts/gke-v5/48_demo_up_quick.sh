#!/usr/bin/env bash
# 48_demo_up_quick.sh: the quick way up for a live demo, the same steps as 47_demo_up.sh minus the evidence.
#
# Needs:  DUFFEL_TOKEN (a duffel_test_ token) in the environment, gcloud, kubectl, helm, docker, and
#         the pinned freeze from _config.sh.
# Usage:  export DUFFEL_TOKEN=duffel_test_...
#         caffeinate -ims ./scripts/gke-v5/48_demo_up_quick.sh            # ~15 min with a cluster, ~40 without
#         SKIP_BUILD=1 caffeinate -ims ./scripts/gke-v5/48_demo_up_quick.sh   # services image unchanged
# Result: A running cluster with the world duffel deployed. Exit code non zero if a bring-up step or
#         the readiness check fails. Tear down with 47_demo_down.sh.
#
# The steps:
#
#   00 preflight, 12 cluster, 15 CAA values, 14 CoCo   (skipped when a cluster is reachable)
#   23 services image (skipped with SKIP_BUILD=1 when the deployed image is current)
#   30 deploy with BOOKING_WORLD=duffel, 37 OpenBao
#   the readiness checks of 47 (gateway world, admission bound, current adapter)
#
# Not run here: 38 network proofs and 40 verify (all offline suites). Those make 47 take about
# 90 minutes. They produce evaluation evidence and are not a precondition of a demo. Run them
# with 47 when the cluster is meant to produce evidence.
# No -e: every step reports its own status through step(), and the chain decides.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCKS_DIR="$(cd "${HERE}/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"; mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/demo-up-quick-${STAMP}.log"
exec > >(tee -a "${LOG}") 2>&1

source "${HERE}/_run_lib.sh"
NS="agent-system"

finish() { summarise "$1" "Demo cluster ready (quick)" "Demo cluster FAILED"; exit "$1"; }

say "preflight"
[ -n "${DUFFEL_TOKEN:-}" ] || die "DUFFEL_TOKEN is not set (37 stores it in OpenBao)"
case "${DUFFEL_TOKEN}" in duffel_test_*) ;; *) die "DUFFEL_TOKEN is not a test-mode token (duffel_test_...)";; esac
common_preflight
if kubectl cluster-info >/dev/null 2>&1; then
    say "a cluster is already reachable ($(kubectl config current-context)), skipping 00/12/15/14"
else
    step "00 preflight"         ./scripts/gke-v5/00_preflight_v5.sh      || finish 1
    step "12 create cluster"    ./scripts/gke-v5/12_create_cluster_v5.sh || finish 1
    step "15 render caa values" ./scripts/gke-v5/15_render_caa_values.sh || finish 1
    step "14 install coco"      ./scripts/gke-v5/14_install_coco.sh      || finish 1
fi
if [ "${SKIP_BUILD:-0}" = "1" ]; then
    say "SKIP_BUILD=1: not rebuilding the services image (the readiness checks below still verify it is current)"
else
    step "23 build services (current code)" ./scripts/gke-v5/23_build_services_image.sh || finish 1
fi
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
    kubectl config get-contexts v5-controller >/dev/null 2>&1 || { echo "no kube context v5-controller"; return 1; }
}
step "gateway world duffel, admission bound, current adapter, controller context" ready || finish 1

cat <<'NEXT'

########################################################################
DEMO CLUSTER READY (world duffel, pinned freeze, no evidence suites run).

  Terminal 0:  ./scripts/gke-v5/49_approval_page.sh        # the Authority's approval page, http://localhost:8450/
  Terminal 1:  python3 -m ui.approval_api --authority-url http://localhost:8450/   # http://localhost:8766/  (the one view)
  Terminal 2:  AGENT_BRAIN=openai python3 -m ui.agent_api --host 0.0.0.0
  Terminal 3:  docker compose -f ui/docker-compose.yml up   # Open WebUI, model v5-duffel
  Optional:    python3 -m booking_demo.serve                # the dashboard, port 8765

Set the demo controls (external input, node attacker, attacker's order) before each message.
The v5 runs start without DUFFEL_TOKEN in their environment (it lives in OpenBao only).
When done:  caffeinate -ims ./scripts/gke-v5/47_demo_down.sh
########################################################################
NEXT
finish 0
