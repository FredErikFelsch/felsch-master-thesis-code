#!/usr/bin/env bash
# 98b_measure_and_teardown.sh: phase B of the final measurement. Deploys on the pinned freeze, runs every measurement the evaluation reports, regenerates the tables and tears the cluster down.
#
# Needs:  PCS_API_KEY in the environment, a freeze candidate from phase A whose stamp the operator
#         pinned in _config.sh and tests_v5_fixtures.py, the evaluation approver credentials and
#         the harness key, OPENAI_API_KEY unless SKIP_DEMO=1, and gcloud, kubectl, helm and docker.
# Usage:  export PCS_API_KEY=...
#         caffeinate -ims ./scripts/gke-v5/98b_measure_and_teardown.sh
# Result: The regenerated thesis tables, a log under results_v5/runs and the destroyed cluster. On
#         failure the cluster is left running for inspection unless DESTROY_ON_FAILURE=1. Exit code
#         non zero on failure.
#
# It runs unattended.
#
# Environment:
#   PCS_API_KEY          required
#   COLD_REPEAT          cold-path repetitions, default 10
#   WARM_REPEAT          warm-path repetitions, default 10
#   WARM_POOL            warm pool size, default 5
#   PRICE_PER_HOUR       list price for the cost table, optional
#   PRICE_SOURCE         provenance string for that price, optional
#   DESTROY_ON_FAILURE   1 to tear down even on failure, default 0
#   START_AT             resume at a step instead of the beginning, for a rerun on a
#                        cluster that is still up. One of: deploy, security, timing,
#                        demo, report, teardown. Default deploy.
#   EXPIRY_TTL/EXPIRY_WAIT/EXPIRY_POOL
#                        parameters of the expiry run, default 60/70/2. The window has
#                        to outlast a TD hand-off, otherwise the control half of the
#                        test expires before it is redeemed.
#   TOLERATE_SUBSTRATE_VARIANCE
#                        1 (default) lets the two timing series survive a refusal that is
#                        shown to come only from the provider's RTMR0 field: every other pinned
#                        measurement byte-equal to the freeze, zero measured effects. The refusal
#                        stands, the run is excluded from the statistics and recorded in
#                        summary.json. 0 makes every refusal fail the series. The security steps
#                        (31 accepted chain, 32, 41, 34) do not get this flag.
#   SKIP_DEMO            1 to skip the demo matrix, default 0
#   DEMO_MODELS          comma separated model ids for the matrix,
#                        default "gpt-5.4-mini,gpt-5.6-luna". One run per model, so
#                        every record carries its own start.model_id.
#   OPENAI_API_KEY       required unless SKIP_DEMO=1
#   OPENAI_BASE_URL      the relay endpoint, if the models are not reached directly
# No -e: every step reports its own status through step(), and the chain decides.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCKS_DIR="$(cd "${HERE}/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"; mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/measure-${STAMP}.log"
exec > >(tee -a "${LOG}") 2>&1

source "${HERE}/_run_lib.sh"

# The approval gate: every run of this measurement is unattended, so 30 must pin the harness
# authenticator beside the passkey (the eval credentials), and 31, 32, 34 and the demo matrix
# answer with its key. Without this block 30 pins the demo file (passkeys only) and every
# harness decision is refused with "credential is not pinned".
export APPROVER_CREDENTIALS="${APPROVER_CREDENTIALS:-${MOCKS_DIR}/k8s/v5/approver-credentials.eval.json}"
export HARNESS_APPROVER_KEY="${HARNESS_APPROVER_KEY:-${HOME}/.config/thesis-v5/harness-approver.json}"
[ -f "${APPROVER_CREDENTIALS}" ] && [ -f "${HARNESS_APPROVER_KEY}" ] || {
    echo "ABORT: the measurement needs ${APPROVER_CREDENTIALS} and ${HARNESS_APPROVER_KEY}:"
    echo "  python3 -m booking_approval.enroll harness --approver harness:eval \\"
    echo "      --credentials k8s/v5/approver-credentials.eval.json --key-out ~/.config/thesis-v5/harness-approver.json"
    exit 2; }

COLD_REPEAT="${COLD_REPEAT:-10}"
WARM_REPEAT="${WARM_REPEAT:-10}"
WARM_POOL="${WARM_POOL:-5}"
DESTROY_ON_FAILURE="${DESTROY_ON_FAILURE:-0}"
SKIP_DEMO="${SKIP_DEMO:-0}"
DEMO_MODELS="${DEMO_MODELS:-gpt-5.4-mini,gpt-5.6-luna}"
START_AT="${START_AT:-deploy}"
EXPIRY_TTL="${EXPIRY_TTL:-60}"
EXPIRY_WAIT="${EXPIRY_WAIT:-70}"
EXPIRY_POOL="${EXPIRY_POOL:-2}"

# Phases in order. want <phase> says whether that phase is still to run.
_PHASES="deploy security timing demo report teardown"
want() {
    local target="$1" seen=0 p
    for p in ${_PHASES}; do
        [ "${p}" = "${START_AT}" ] && seen=1
        [ "${p}" = "${target}" ] && { [ "${seen}" = "1" ] && return 0 || return 1; }
    done
    return 1
}

finish() {
    local rc="$1"
    if [ "${rc}" != "0" ] && [ "${DESTROY_ON_FAILURE}" = "1" ]; then
        printf '\n[%s] DESTROY_ON_FAILURE=1: tearing down anyway\n' "$(ts)"
        ./scripts/gke-v5/91_cleanup_probe.sh || true
        ./scripts/gke-v5/90_destroy_v5.sh    || true
    elif [ "${rc}" != "0" ]; then
        printf '\n[%s] cluster left running for inspection.\n' "$(ts)"
        printf '     tear down: ./scripts/gke-v5/91_cleanup_probe.sh && ./scripts/gke-v5/90_destroy_v5.sh\n'
    fi
    summarise "${rc}" "Measurement run done" "Measurement run FAILED"
    exit "${rc}"
}

# --- preflight: the pin must be in place -------------------------------------
say "preflight"
[ -n "${PCS_API_KEY:-}" ] || die "PCS_API_KEY is not set"
common_preflight

PINNED="$(grep -oE 'FREEZE_STAMP="\$\{FREEZE_STAMP:-[^}]*\}"' "${HERE}/_config.sh" | sed -E 's/.*:-([^}]*)\}.*/\1/')"
[ -n "${PINNED}" ] || die "cannot read FREEZE_STAMP from _config.sh"
FREEZE_JSON="${MOCKS_DIR}/results_v5/freeze-candidate/freeze-${PINNED}.json"
[ -f "${FREEZE_JSON}" ] || die "no freeze record for the pinned stamp ${PINNED} (${FREEZE_JSON})"

FIX_STAMP="$(grep -oE '^STAMP\s*=\s*"[^"]+"' "${MOCKS_DIR}/booking_v5/tests_v5_fixtures.py" | head -1 | sed -E 's/.*"([^"]+)".*/\1/')"
[ "${FIX_STAMP}" = "${PINNED}" ] || die "tests_v5_fixtures.STAMP is ${FIX_STAMP:-<unset>} but _config.sh pins ${PINNED}. Pin both before phase B"

if [ "${SKIP_DEMO}" = "0" ]; then
    [ -n "${OPENAI_API_KEY:-}" ] \
        || die "SKIP_DEMO=0 but OPENAI_API_KEY is unset. The demo matrix would fail after the cluster is up"
    if [ -n "${OPENAI_BASE_URL:-}" ]; then
        # Only check reachability. A 401 is a good sign here, because it means
        # that the relay answers.
        curl -s -o /dev/null -m 10 "${OPENAI_BASE_URL%/}/models" \
            || die "relay ${OPENAI_BASE_URL} not reachable. Start it or run with SKIP_DEMO=1"
        say "relay reachable: ${OPENAI_BASE_URL}"
    else
        say "no OPENAI_BASE_URL set, the demo will talk to the provider directly"
    fi
    say "demo models: ${DEMO_MODELS}"
fi

case " ${_PHASES} " in *" ${START_AT} "*) : ;; *) die "START_AT must be one of: ${_PHASES}" ;; esac
[ "${START_AT}" = "deploy" ] || say "resuming at phase '${START_AT}', earlier phases skipped"

say "preflight ok, pinned freeze ${PINNED}"

# --- deploy on the new line --------------------------------------------------
if want deploy; then
    step "23 build services image" ./scripts/gke-v5/23_build_services_image.sh || finish 1
    step "30 deploy"               ./scripts/gke-v5/30_deploy_v5.sh            || finish 1
    step "40 verify (deployed)"    ./scripts/gke-v5/40_verify_v5.sh            || finish 1
fi

# --- security -----------------------------------------------------------------
if want security; then
    step "31 accepted chain" ./scripts/gke-v5/31_run_fragment_v5.sh || finish 1
    step "32 negative"       ./scripts/gke-v5/32_negative_v5.sh     || finish 1
    step "41 probe a19"      ./scripts/gke-v5/41_probe_a19.sh       || finish 1
    run_expiry() {
        TTL="${EXPIRY_TTL}" WAIT="${EXPIRY_WAIT}" POOL="${EXPIRY_POOL}" \
            ./scripts/gke-v5/34_expiry_v5.sh
    }
    step "34 expiry (ttl ${EXPIRY_TTL}s, wait ${EXPIRY_WAIT}s, pool ${EXPIRY_POOL})" run_expiry || finish 1
fi

# --- timing -------------------------------------------------------------------
# Only the latency series tolerate the provider's RTMR0 variance. The security runs (31 on its
# own, 32, 41, 34) do not get the flag, so there every refusal fails the step.
run_cold() { REPEAT="${COLD_REPEAT}" POOL=0 TOLERATE_SUBSTRATE_VARIANCE="${TOLERATE_SUBSTRATE_VARIANCE:-1}" \
             ./scripts/gke-v5/31_run_fragment_v5.sh; }
run_warm() { REPEAT="${WARM_REPEAT}" POOL="${WARM_POOL}" TOLERATE_SUBSTRATE_VARIANCE="${TOLERATE_SUBSTRATE_VARIANCE:-1}" \
             ./scripts/gke-v5/31_run_fragment_v5.sh; }
E2E="${MOCKS_DIR}/results_v5/e2e"
newest_series() {
    # newest_series <pool|nopool> [marker] -> stamp of the newest series of that kind.
    # Without it report_v5 picks the series with the most repetitions, which may be an
    # older one from an earlier freeze line.
    local kind="$1" marker="${2:-}" d
    for d in $(ls -dt "${E2E}"/*/ 2>/dev/null); do
        [ -f "${d}/summary.json" ] || continue
        [ -n "${marker}" ] && [ ! "${d}/summary.json" -nt "${marker}" ] && continue
        local pool
        pool="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('pool_size',0))" "${d}/summary.json" 2>/dev/null)" || continue
        if [ "${kind}" = "pool" ] && [ "${pool:-0}" -gt 0 ]; then basename "${d%/}"; return 0; fi
        if [ "${kind}" = "nopool" ] && [ "${pool:-0}" -eq 0 ]; then basename "${d%/}"; return 0; fi
    done
    return 1
}

if want timing; then
    TIMING_MARKER="$(mktemp "${TMPDIR:-/tmp}/v5timing.XXXXXX")"
    step "31 timing cold (N=${COLD_REPEAT}, pool 0)"            run_cold || finish 1
    step "31 timing warm (N=${WARM_REPEAT}, pool ${WARM_POOL})" run_warm || finish 1
    COLD_STAMP="$(newest_series nopool "${TIMING_MARKER}")" || die "no cold series was written"
    WARM_STAMP="$(newest_series pool   "${TIMING_MARKER}")" || die "no warm series was written"
    rm -f "${TIMING_MARKER}"
    say "timing series of this run: cold ${COLD_STAMP}, warm ${WARM_STAMP}"
fi

# --- semantics and the real model --------------------------------------------
if want demo; then
    step "experiment_v5 (equivalence, offline)" python3 -m booking_v5.experiment_v5 || finish 1
    if [ "${SKIP_DEMO}" = "0" ]; then
        IFS=',' read -ra _models <<< "${DEMO_MODELS}"
        for _m in "${_models[@]}"; do
            _m="$(echo "${_m}" | xargs)"   # trim
            [ -n "${_m}" ] || continue
            # --approve auto: 33 defaults to --approve wait (a person on the approval page). The
            # matrix is unattended and answers with the harness key (approver kind "harness").
            step "33 demo matrix (${_m})" \
                env DEMO_OPENAI_MODEL="${_m}" ./scripts/gke-v5/33_demo_v5.sh --approve auto || finish 1
        done
    else
        say "SKIP_DEMO=1: demo matrix skipped, t6 tables keep the previous runs"
    fi
fi

# --- tables -------------------------------------------------------------------
build_report() {
    # Pass the series of this run explicitly. Without them report_v5 chooses by the number
    # of repetitions and can take a series from an older line.
    local args=(-m booking_v5.report_v5)
    [ -n "${COLD_STAMP:-}" ]     && args+=(--cold-stamp "${COLD_STAMP}")
    [ -n "${WARM_STAMP:-}" ]     && args+=(--warm-stamp "${WARM_STAMP}")
    [ -n "${PRICE_PER_HOUR:-}" ] && args+=(--price-per-hour "${PRICE_PER_HOUR}")
    [ -n "${PRICE_SOURCE:-}" ]   && args+=(--price-source "${PRICE_SOURCE}")
    python3 "${args[@]}"
}
if want report; then
    step "report_v5 (regenerate the thesis tables)" build_report || finish 1
fi

# --- teardown -----------------------------------------------------------------
if want teardown; then
    step "91 cleanup probe" ./scripts/gke-v5/91_cleanup_probe.sh || finish 1
    step "90 destroy"       ./scripts/gke-v5/90_destroy_v5.sh    || finish 1
fi

cat <<'NEXT'

########################################################################
MEASUREMENT COMPLETE. The tables under thesis/tables/ are regenerated.

Check before committing:
  git -C . diff --stat thesis/tables/
  Every number of the evaluation chapter comes from a macro, so the prose follows
  automatically. Read t3-latency and t4-cost-ops once: if the cold and warm
  medians moved a lot, the derived sentences about shares and speed-up are
  still correct but worth re-reading.
########################################################################
NEXT

finish 0
