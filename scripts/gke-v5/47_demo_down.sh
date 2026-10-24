#!/usr/bin/env bash
# 47_demo_down.sh: tears the demo cluster down.
#
# Needs:  gcloud authenticated, and 90_destroy_v5.sh and 91_cleanup_probe.sh next to it.
# Usage:  caffeinate -ims ./scripts/gke-v5/47_demo_down.sh
# Result: The probe resources cleaned (91), the cluster destroyed (90), orphaned pvc-* disks deleted,
#         and a final check that no cluster is left. Exit code non zero if the destroy or the final
#         check fails.
#
# GKE does not delete the disks of PVCs with the cluster. They are deleted here, but only pvc-*
# disks in this zone that no VM uses (attachment is checked per disk).
# No -e: every step reports its own status through step(), and the chain decides.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCKS_DIR="$(cd "${HERE}/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"; mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/demo-down-${STAMP}.log"
exec > >(tee -a "${LOG}") 2>&1

source "${HERE}/_run_lib.sh"
ZONE="${V5_ZONE:-${V5_REGION:-europe-west4}-a}"      # as _config.sh derives it

cleanup_disks() {
    local name users n=0
    while read -r name users; do
        [ -n "${name}" ] || continue
        case "${name}" in pvc-*) ;; *) continue ;; esac
        [ -z "${users}" ] || { echo "  keep ${name} (attached)"; continue; }
        gcloud compute disks delete "${name}" --zone "${ZONE}" --quiet && n=$((n + 1))
    done < <(gcloud compute disks list --filter="zone~${ZONE}" --format="value(name,users)")
    echo "  deleted ${n} orphaned pvc disk(s) in ${ZONE}"
}

finish() { summarise "$1" "Demo cluster down" "Demo teardown FAILED"; exit "$1"; }

step "91 cleanup probe"   ./scripts/gke-v5/91_cleanup_probe.sh || true
step "90 destroy"         ./scripts/gke-v5/90_destroy_v5.sh    || finish 1
step "orphaned pvc disks" cleanup_disks                         || true
# Only the demo cluster counts: another cluster in the project (the V4.4c one, say) is not ours.
step "nothing left" bash -c 'gcloud container clusters list --filter="name=$1" --format="value(name)" | grep -q . && exit 1; exit 0' \
    _ "${V5_CLUSTER:-thesis-v5}" || finish 1
finish 0
