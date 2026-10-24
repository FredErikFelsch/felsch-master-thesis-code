#!/usr/bin/env bash
# 97_offline_regenerate.sh: runs the offline tier of the final run, with no cluster, image build or measurement.
#
# Needs:  python3 with the repository packages, verify.py in the repository root, and docker only
#         with WITH_CONTAINER=1.
# Usage:  ./scripts/gke-v5/97_offline_regenerate.sh
# Result: The whole test suite as a gate, then every recorded result artefact below V5 regenerated
#         in dependency order, then the V5 equivalence record and the thesis tables. A log under
#         results_v5/runs. Exit code non zero if any step failed.
#
# Why it exists: 99 runs only two unittest commands offline, and 98b starts at experiment_v5,
# which reads results_v4_container/results.json as its baseline, while report_v5 reads
# results_v2_1 and results_v3/world for the lying-provider macros. After a change below V5 those recorded
# artefacts are the stale part of the run, and no other step regenerates them. This script
# duplicates nothing from 98a, 98b or 99.
#
# Order matters. verify.py runs first as a gate, because regenerating results from
# a red tree only records the break in JSON. Then V0 to V4 in layer order, then
# experiment_v5, which compares against the V4 baseline, then report_v5, which reads
# everything above.
#
# Environment:
#   SKIP_VERIFY      1 to skip the suite gate, default 0. Only for a rerun minutes
#                    after a green verify.py, not before a freeze.
#   QUICK_VERIFY     1 to run verify.py --quick, default 0. The slow modules are the
#                    service and durable ones, so a freeze run keeps them in.
#   WITH_CONTAINER   1 to also regenerate results_v4_container (the V5 baseline).
#                    Default 0, because it needs a docker daemon and the runner
#                    image, and the baseline only moves when V3 semantics move.
#   WITH_REPORT      0 to stop before report_v5, default 1. Set 0 when the timing
#                    series of the current line are not measured yet and 98b will
#                    build the tables with its own --cold-stamp/--warm-stamp.
#   RUNNER_IMAGE     image for the container baseline, only read with WITH_CONTAINER=1.
# No -e: every step reports its own status through step(), and the chain decides.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCKS_DIR="$(cd "${HERE}/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"; mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/offline-${STAMP}.log"
exec > >(tee -a "${LOG}") 2>&1

source "${HERE}/_run_lib.sh"

SKIP_VERIFY="${SKIP_VERIFY:-0}"
QUICK_VERIFY="${QUICK_VERIFY:-0}"
WITH_CONTAINER="${WITH_CONTAINER:-0}"
WITH_REPORT="${WITH_REPORT:-1}"

finish() {
    # finish <rc>: summarise and exit. No teardown, this tier owns no cluster.
    local rc="$1"
    summarise "${rc}" "Offline regeneration done" "Offline regeneration FAILED"
    exit "${rc}"
}

# --- preflight ---------------------------------------------------------------
say "preflight"
command -v python3 >/dev/null || die "python3 not on PATH"
[ -f "${MOCKS_DIR}/verify.py" ] || die "verify.py not found in ${MOCKS_DIR}"
if [ "${WITH_CONTAINER}" = "1" ]; then
    command -v docker >/dev/null || die "WITH_CONTAINER=1 but docker is not on PATH"
    docker info >/dev/null 2>&1 || die "WITH_CONTAINER=1 but the docker daemon is not reachable"
fi
say "preflight ok"

# --- gate: the suite must be green before anything is recorded ---------------
run_verify() {
    local args=(verify.py)
    [ "${QUICK_VERIFY}" = "1" ] && args+=(--quick)
    python3 "${args[@]}"
}
if [ "${SKIP_VERIFY}" = "0" ]; then
    step "verify.py (full suite, gate)" run_verify || finish 1
else
    say "SKIP_VERIFY=1: the suite gate is skipped, the recorded results below are only as good as the last verify.py"
fi

# --- V0 to V4: the recorded baselines, in layer order ------------------------
step "booking_v0.experiment      (results)"             python3 -m booking_v0.experiment         || finish 1
step "booking_v1.experiment      (results_v1)"          python3 -m booking_v1.experiment         || finish 1
step "booking_v2.experiment      (results_v2, v2_1)"    python3 -m booking_v2.experiment         || finish 1
step "booking_v3.experiment      (results_v3)"          python3 -m booking_v3.experiment         || finish 1
step "booking_v3.experiment_world(results_v3/world)"    python3 -m booking_v3.experiment_world   || finish 1
step "booking_v4.experiment      (results_v4_process)"  python3 -m booking_v4.experiment         || finish 1
step "booking_v4.experiment_durable (results_v4_durable)" python3 -m booking_v4.experiment_durable || finish 1

# --- the V5 baseline, only on request ----------------------------------------
if [ "${WITH_CONTAINER}" = "1" ]; then
    step "booking_v4.experiment_container (results_v4_container, the V5 baseline)" \
        python3 -m booking_v4.experiment_container || finish 1
else
    say "WITH_CONTAINER=0: results_v4_container kept as recorded. It is the baseline experiment_v5 compares against, so regenerate it whenever V3 semantics move."
fi

# --- V5 equivalence and the tables -------------------------------------------
step "booking_v5.experiment_v5 (equivalence against the V4 baseline)" \
    python3 -m booking_v5.experiment_v5 || finish 1

if [ "${WITH_REPORT}" = "1" ]; then
    step "booking_v5.report_v5 (thesis tables)" python3 -m booking_v5.report_v5 || finish 1
else
    say "WITH_REPORT=0: tables not rebuilt here, 98b builds them with the timing series of its own run"
fi

finish 0
