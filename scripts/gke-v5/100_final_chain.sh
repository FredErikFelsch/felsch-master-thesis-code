#!/usr/bin/env bash
# 100_final_chain.sh: runs the final measurement campaign in one command, from the gate to the teardown.
#
# Needs:  gcloud, kubectl, helm, python3, PCS_API_KEY and DUFFEL_TOKEN exported, a model API key
#         unless SKIP_MODEL_RUNS=1 (see Environment), the approver credentials of the evaluation.
# Usage:  Export the variables first, then call it under caffeinate so the machine stays awake.
#           export PCS_API_KEY=... DUFFEL_TOKEN=duffel_test_... ANTHROPIC_API_KEY=sk-ant-...
#           caffeinate -ims ./scripts/gke-v5/100_final_chain.sh
#         Resume after a failure at a phase. Earlier phases are skipped and their results are
#         read from disk.
#           START_AT=live caffeinate -ims ./scripts/gke-v5/100_final_chain.sh
# Result: A log under results_v5/runs, the results of every phase, and an exit code that is
#         non zero if any hard or soft step failed. Nothing is committed.
#
# Phases, in order:
#
#   gate      40 --offline, everything green or nothing starts
#   freeze    98a: rebuild the runner image, new freeze candidate (includes 18, 19, 20, 21 and 22)
#   pin       you accept the candidate (prompt), 100 pins it with pin_freeze.py, 40 --offline again
#   measure   98b: deploy on the pinned freeze, security runs, timing series, report_v5, teardown
#   cluster   a fresh cluster (00, 12, 15, 14) for the live part, because 98b destroys the first one
#   deploy    the Duffel world on that cluster (23, 30, 37) plus the checks 36 and 38, once for 45 and the model runs
#   live      45: Duffel evidence (5, 7, 6a to 6c, 8, 9) on the world deployed in phase deploy
#   recovery  probe_recovery_closed against the deployed gateway
#   human     the run with a person and a passkey (waits for you, skipped after HUMAN_WAIT seconds)
#   models    real model runs on Duffel (clean and attack mails), the model runs of the evaluation (chapter 7)
#   report    final report_v5 with the timing series of 98b, the price and its source
#   down      47_demo_down.sh (not after a failure, so a failure can be inspected)
#
# Hard stops end the chain, because nothing after them makes sense: gate, freeze, pin, measure,
# cluster. Soft steps are recorded and the chain goes on, and the exit code is non zero at the end:
# live, recovery, human, every single model run, report.
#
# Environment:
#   PCS_API_KEY, DUFFEL_TOKEN   required
#   ANTHROPIC_API_KEY           required for the model runs (MODEL_PROVIDER=anthropic, the default),
#                               OPENAI_API_KEY with MODEL_PROVIDER=openai. Both unless SKIP_MODEL_RUNS=1.
#                               The preflight sends one 5 token request, so an empty balance stops the
#                               chain before the cluster is touched.
#   MODEL_PROVIDER              anthropic (default) or openai
#   MODEL_IDS                   comma separated model ids, default claude-sonnet-5-5
#   OPENAI_BASE_URL             optional relay with MODEL_PROVIDER=openai
#   START_AT                    one of: gate freeze pin measure cluster deploy live recovery human models report down
#   CREATE_CLUSTER              for 98a, default: 1 when no cluster is reachable, else 0
#   ACCEPT_FREEZE               ask (default) shows the candidate and asks, auto pins without asking
#   PRICE_PER_HOUR              default 0.2116884
#   PRICE_SOURCE                default "GCE list price c3-standard-4, europe-west4, retrieved 2026-10-01"
#   DEMO_MODELS                 only for the scripted matrix of 98b, which calls no model
#   DUFFEL_MODEL_RUNS           runs per model and mail, default 5
#   DUFFEL_MODEL_MAILS          mail variants, default "clean fraud"
#   DUFFEL_MODEL_PLAN           fixed or agent, default agent (the model proposes the plan)
#   SKIP_MODEL_RUNS             1 to skip the model runs
#   SKIP_LIVE                   1 skips 45 and the recovery probe, to repeat only the model runs on a fresh
#                               cluster (the Duffel world is deployed in phase deploy either way)
#   HUMAN_RUN                   1 (default) the run with a person, 0 skips it
#   HUMAN_WAIT                  seconds to wait for you before the human run, default 900
#   JOURNEY, POOL               default JFK-FRA and 3
#   KEEP_CLUSTER                1 keeps the cluster at the end, default 0
# No -e: every step reports its own status through step(), and hard() or soft() decides.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCKS_DIR="$(cd "${HERE}/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"; mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/final-chain-${STAMP}.log"
exec > >(tee -a "${LOG}") 2>&1

source "${HERE}/_run_lib.sh"

START_AT="${START_AT:-gate}"
ACCEPT_FREEZE="${ACCEPT_FREEZE:-ask}"
PRICE_PER_HOUR="${PRICE_PER_HOUR:-0.2116884}"
PRICE_SOURCE="${PRICE_SOURCE:-GCE list price c3-standard-4, europe-west4, retrieved 2026-10-01}"
DEMO_MODELS="${DEMO_MODELS:-gpt-5.4-mini,gpt-5.6-luna}"
MODEL_PROVIDER="${MODEL_PROVIDER:-anthropic}"
MODEL_IDS="${MODEL_IDS:-claude-sonnet-5-5}"
DUFFEL_MODEL_RUNS="${DUFFEL_MODEL_RUNS:-5}"
DUFFEL_MODEL_MAILS="${DUFFEL_MODEL_MAILS:-clean fraud}"
DUFFEL_MODEL_PLAN="${DUFFEL_MODEL_PLAN:-agent}"
SKIP_MODEL_RUNS="${SKIP_MODEL_RUNS:-0}"
SKIP_LIVE="${SKIP_LIVE:-0}"
HUMAN_RUN="${HUMAN_RUN:-1}"
HUMAN_WAIT="${HUMAN_WAIT:-900}"
JOURNEY="${JOURNEY:-JFK-FRA}"
POOL="${POOL:-3}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
STATE="${LOG_DIR}/final-chain.state"       # the pinned stamp survives a resume
declare -a SOFT_FAILED=()

_PHASES="gate freeze pin measure cluster deploy live recovery human models report down"
want() {
    # want <phase>: true from START_AT on
    local target="$1" seen=0 p
    for p in ${_PHASES}; do
        [ "${p}" = "${START_AT}" ] && seen=1
        [ "${p}" = "${target}" ] && { [ "${seen}" = "1" ] && return 0 || return 1; }
    done
    return 1
}

finish() {
    # finish <rc>: summary, soft failures included, and what to check next
    local rc="$1"
    if [ "${#SOFT_FAILED[@]}" -gt 0 ]; then
        printf '\nSOFT FAILURES (the chain went on):\n'; printf '  %s\n' "${SOFT_FAILED[@]}"
        [ "${rc}" = "0" ] && rc=1
    fi
    summarise "${rc}" "Final chain done" "Final chain FAILED"
    cat <<'NEXT'

########################################################################
AFTER THE CHAIN: the phases from START_AT on have run, and nothing is committed.
  1. Read the step list and the soft failures above. A failed phase is rerun
     with START_AT=<phase>.
  2. Review the regenerated tables (git diff --stat thesis/tables/) and the
     logs under results_v5/runs before committing anything.
########################################################################
NEXT
    exit "${rc}"
}

soft() {
    # soft "name" cmd...: a failing step is recorded and the chain goes on
    local name="$1"; shift
    FAILED_STEP=""
    step "${name}" "$@" || SOFT_FAILED+=("${name}")
    FAILED_STEP=""
}

hard() {
    # hard "name" cmd...: a failing step ends the chain, the cluster stays up for inspection
    step "$@" || { say "HARD STOP at: $1 (the cluster, if any, is left running)"; finish 1; }
}

# --- preflight --------------------------------------------------------------------
say "preflight (start at ${START_AT})"
case " ${_PHASES} " in *" ${START_AT} "*) : ;; *) die "START_AT must be one of: ${_PHASES}" ;; esac
[ -n "${PCS_API_KEY:-}" ]   || die "PCS_API_KEY is not set"
[ -n "${DUFFEL_TOKEN:-}" ]  || die "DUFFEL_TOKEN is not set"
case "${MODEL_PROVIDER}" in anthropic|openai) : ;; *) die "MODEL_PROVIDER must be anthropic or openai" ;; esac
if [ "${SKIP_MODEL_RUNS}" != "1" ]; then
    _first_model="$(echo "${MODEL_IDS}" | cut -d, -f1 | xargs)"
    if [ "${MODEL_PROVIDER}" = "anthropic" ]; then
        [ -n "${ANTHROPIC_API_KEY:-}" ] || die "ANTHROPIC_API_KEY is not set (or SKIP_MODEL_RUNS=1)"
        python3 -c "import anthropic" 2>/dev/null || die "the anthropic package is missing: pip install anthropic"
        python3 - "${_first_model}" <<'PY' || die "the model check failed (key, balance or model id), see the message above"
import sys, anthropic
try:
    r = anthropic.Anthropic().messages.create(model=sys.argv[1], max_tokens=5,
                                              messages=[{"role": "user", "content": "ok"}])
    print("[model check] ok:", sys.argv[1], r.usage.input_tokens, "in,", r.usage.output_tokens, "out")
except Exception as exc:
    print("[model check] FAILED:", type(exc).__name__, str(exc)[:300])
    sys.exit(1)
PY
    else
        [ -n "${OPENAI_API_KEY:-}" ] || die "OPENAI_API_KEY is not set (or SKIP_MODEL_RUNS=1)"
        _base="${OPENAI_BASE_URL:-https://api.openai.com/v1}"
        _answer="$(curl -s -m 30 "${_base%/}/chat/completions" -H "Authorization: Bearer ${OPENAI_API_KEY}" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"${_first_model}\",\"messages\":[{\"role\":\"user\",\"content\":\"ok\"}],\"max_completion_tokens\":5}")"
        echo "${_answer}" | grep -q '"error"' && die "the model check failed: ${_answer:0:300}"
        say "model check ok: ${_first_model}"
    fi
fi
# 98b checks for OPENAI_API_KEY before its scripted matrix, which calls no model. With the other provider
# a placeholder satisfies that check, and nothing reaches OpenAI.
[ -n "${OPENAI_API_KEY:-}" ] || export OPENAI_API_KEY="unused-the-98b-matrix-is-scripted"
common_preflight
export APPROVER_CREDENTIALS="${APPROVER_CREDENTIALS:-${MOCKS_DIR}/k8s/v5/approver-credentials.eval.json}"
export HARNESS_APPROVER_KEY="${HARNESS_APPROVER_KEY:-${HOME}/.config/thesis-v5/harness-approver.json}"
[ -f "${APPROVER_CREDENTIALS}" ] && [ -f "${HARNESS_APPROVER_KEY}" ] \
    || die "missing ${APPROVER_CREDENTIALS} or ${HARNESS_APPROVER_KEY} (python3 -m booking_approval.enroll harness ...)"
say "preflight ok"

# --- gate -------------------------------------------------------------------------
if want gate; then
    hard "gate: 40 offline" ./scripts/gke-v5/40_verify_v5.sh --offline
fi

# --- freeze (98a) -----------------------------------------------------------------
cluster_reachable() { kubectl cluster-info >/dev/null 2>&1; }
if want freeze; then
    if [ -z "${CREATE_CLUSTER:-}" ]; then
        if cluster_reachable; then CREATE_CLUSTER=0; else CREATE_CLUSTER=1; fi
    fi
    say "98a with CREATE_CLUSTER=${CREATE_CLUSTER}"
    MARKER="$(mktemp "${TMPDIR:-/tmp}/v5chainmarker.XXXXXX")"
    hard "98a freeze prepare" env -u START_AT CREATE_CLUSTER="${CREATE_CLUSTER}" ./scripts/gke-v5/98a_freeze_prepare.sh
    CAND="$(find results_v5/freeze-candidate -maxdepth 1 -name 'freeze-*.json' -newer "${MARKER}" -type f \
            | xargs -r ls -t | head -1)"
    rm -f "${MARKER}"
    [ -n "${CAND}" ] || { say "98a wrote no new freeze candidate"; finish 1; }
    basename "${CAND}" | sed -E 's/^freeze-//; s/\.json$//' > "${STATE}"
    say "freeze candidate: ${CAND}"
fi

# --- pin (the operator's acceptance) -----------------------------------------------
if want pin; then
    [ -s "${STATE}" ] || die "no candidate stamp in ${STATE}. Run from START_AT=freeze"
    FSTAMP="$(cat "${STATE}")"
    say "candidate ${FSTAMP}"
    printf '  runner source hash : %s\n' "$(python3 scripts/gke/_runner_source_hash.py .)"
    printf '  pinned in .digests : %s\n' "$(sed -n 's/^RUNNER_SOURCE_SHA256=//p' scripts/gke/.digests | tail -1)"
    printf '  runner image       : %s\n' "$(sed -n 's/^RUNNER_IMAGE=//p' scripts/gke/.digests | tail -1)"
    for f in "results_v5/probe/substrate-40-${FSTAMP}.txt" "results_v5/probe/network-"*; do
        [ -f "${f}" ] && grep -hE 'substrate profile hash|^A5C_' "${f}" 2>/dev/null | head -3 | sed 's/^/  /'
    done
    if [ "${ACCEPT_FREEZE}" != "auto" ]; then
        ans=""
        read -r -p "Pin freeze ${FSTAMP} as the freeze of record? Type yes: " ans </dev/tty || ans=""
        [ "${ans}" = "yes" ] || { say "not accepted, nothing pinned. Cluster left up: tear down with 91 and 90 if the candidate is rejected"; finish 1; }
    fi
    hard "pin ${FSTAMP}"       python3 scripts/gke-v5/pin_freeze.py "${FSTAMP}"
    hard "gate: 40 offline (after the pin)" ./scripts/gke-v5/40_verify_v5.sh --offline
fi

# --- measure (98b) ----------------------------------------------------------------
if want measure; then
    hard "98b measure and teardown" env -u START_AT PRICE_PER_HOUR="${PRICE_PER_HOUR}" PRICE_SOURCE="${PRICE_SOURCE}" \
        DEMO_MODELS="${DEMO_MODELS}" ./scripts/gke-v5/98b_measure_and_teardown.sh
fi

# --- a fresh cluster for the live part -----------------------------------------------
if want cluster; then
    if cluster_reachable; then
        say "a cluster is reachable ($(kubectl config current-context)), no bring-up"
    else
        hard "00 preflight"         ./scripts/gke-v5/00_preflight_v5.sh
        hard "12 create cluster"    ./scripts/gke-v5/12_create_cluster_v5.sh
        hard "15 render caa values" ./scripts/gke-v5/15_render_caa_values.sh
        hard "14 install coco"      ./scripts/gke-v5/14_install_coco.sh
    fi
fi

# --- the Duffel world: services image, deployment, credential, 36 and 38 -----------------
# Deployed once here for 45 and for the model runs. 45 is told not to deploy again.
if want deploy; then
    hard "23 build services"        ./scripts/gke-v5/23_build_services_image.sh
    hard "30 deploy (world duffel)" env -u START_AT BOOKING_WORLD=duffel ./scripts/gke-v5/30_deploy_v5.sh
    hard "37 OpenBao + credential"  ./scripts/gke-v5/37_install_openbao.sh
    # The two checks that 45 does not contain: the deployed Authority checks observations against the
    # ledger, and what each party can and cannot reach from its own position (runner pod and TD,
    # gateway, controller). 99 runs the same two.
    soft "36 observation check"                  ./scripts/gke-v5/36_assert_observation_v5.sh
    soft "38 network and gate proofs (live)"     ./scripts/gke-v5/38_negative_live_v5.sh
fi

# --- live evaluation on Duffel (45) -----------------------------------------------
if want live; then
    if [ "${SKIP_LIVE}" = "1" ]; then
        say "SKIP_LIVE=1, 45 skipped"
    else
        soft "45 live evaluation" env -u START_AT SKIP_OFFLINE=1 SKIP_DEPLOY=1 JOURNEY="${JOURNEY}" POOL="${POOL}" ./scripts/gke-v5/45_live_evaluation.sh
    fi
fi

# --- recovery probe ------------------------------------------------------------------
if want recovery && [ "${SKIP_LIVE}" != "1" ]; then
    probe() { python3 -m booking_v5.probe_recovery_closed --context "$(kubectl config current-context)"; }
    soft "probe_recovery_closed" probe
fi

# --- the run with a person -----------------------------------------------------------
human_run() {
    # 49 serves the approval page, 33 runs the demo and waits for the passkey decision
    local ans="" pf rc
    printf '\n>>> PASSKEY RUN. Be at the machine with your authenticator.\n'
    printf '>>> Open http://localhost:8450/ when asked, approve the payment there.\n'
    read -r -t "${HUMAN_WAIT}" -p ">>> Press Enter when you are ready (skipped after ${HUMAN_WAIT} s): " ans </dev/tty \
        || { say "no answer, the human run is skipped (rerun with START_AT=human)"; return 0; }
    ./scripts/gke-v5/49_approval_page.sh &
    pf=$!
    sleep 10
    env -u DUFFEL_TOKEN ./scripts/gke-v5/33_demo_v5.sh --world duffel --pool "${POOL}" --mail clean \
        --approve wait --journey "${JOURNEY}"
    rc=$?
    kill "${pf}" 2>/dev/null; wait "${pf}" 2>/dev/null
    return "${rc}"
}
if want human; then
    if [ "${HUMAN_RUN}" = "1" ]; then soft "human run (passkey)" human_run; else say "HUMAN_RUN=0, skipped"; fi
fi

# --- real model runs on Duffel -------------------------------------------------------
model_run() {
    # model_run <model> <mail>
    local marker rc run_dir
    marker="$(mktemp "${TMPDIR:-/tmp}/v5model.XXXXXX")"
    env -u DUFFEL_TOKEN DEMO_ANTHROPIC_MODEL="$1" DEMO_OPENAI_MODEL="$1" ./scripts/gke-v5/33_demo_v5.sh \
        --world duffel --pool "${POOL}" --model "${MODEL_PROVIDER}" --plan "${DUFFEL_MODEL_PLAN}" --mail "$2" --approve auto --journey "${JOURNEY}"
    rc=$?
    # What the run ended with. A run that stops at plan formation exits 0 and looks green otherwise.
    run_dir="$(find results_v5/demo -maxdepth 1 -type d -name "*-${MODEL_PROVIDER}-duffel" -newer "${marker}" \
               | xargs -r ls -td 2>/dev/null | head -1)"
    rm -f "${marker}"
    if [ -n "${run_dir}" ]; then
        python3 -c "import json,sys; e=json.load(open(sys.argv[1]+'/events.json')); m=[x.get('message') or x['kind'] for x in e if x['kind']=='end']; print('[model run] ended:', (m[-1] if m else 'no end event')[:160], '|', sys.argv[1])" "${run_dir}"
    fi
    return "${rc}"
}
if want models; then
    if [ "${SKIP_MODEL_RUNS}" = "1" ]; then
        say "SKIP_MODEL_RUNS=1, skipped"
    else
        IFS=',' read -ra _models <<< "${MODEL_IDS}"
        for _m in "${_models[@]}"; do
            _m="$(echo "${_m}" | xargs)"; [ -n "${_m}" ] || continue
            for _mail in ${DUFFEL_MODEL_MAILS}; do
                for _i in $(seq 1 "${DUFFEL_MODEL_RUNS}"); do
                    soft "model ${_m} mail ${_mail} run ${_i}/${DUFFEL_MODEL_RUNS}" model_run "${_m}" "${_mail}"
                done
            done
        done
    fi
fi

# --- final report ------------------------------------------------------------------
final_report() {
    # The timing series of this campaign, read from the 98b log. Without them report_v5 would pick
    # the series with the most repetitions, possibly one of an earlier campaign.
    local lastlog cold warm args=(-m booking_v5.report_v5)
    lastlog="$(ls -t results_v5/runs/measure-*.log 2>/dev/null | head -1)"
    [ -n "${lastlog}" ] || { echo "no 98b log found"; return 1; }
    cold="$(sed -nE 's/.*timing series of this run: cold ([^,]+), warm (.*)$/\1/p' "${lastlog}" | tail -1)"
    warm="$(sed -nE 's/.*timing series of this run: cold ([^,]+), warm (.*)$/\2/p' "${lastlog}" | tail -1)"
    [ -n "${cold}" ] && [ -n "${warm}" ] || { echo "no timing series recorded in ${lastlog}"; return 1; }
    echo "series: cold ${cold}, warm ${warm}"
    python3 "${args[@]}" --cold-stamp "${cold}" --warm-stamp "${warm}" \
        --price-per-hour "${PRICE_PER_HOUR}" --price-source "${PRICE_SOURCE}"
}
if want report; then
    soft "report_v5 (final)" final_report
fi

# --- teardown ---------------------------------------------------------------------
if want down; then
    if [ "${KEEP_CLUSTER}" = "1" ]; then
        say "KEEP_CLUSTER=1, the cluster stays up"
    elif [ "${#SOFT_FAILED[@]}" -gt 0 ]; then
        say "soft failures recorded, the cluster stays up for inspection (47_demo_down.sh tears it down)"
    else
        soft "47 demo down" ./scripts/gke-v5/47_demo_down.sh
    fi
fi

finish 0
