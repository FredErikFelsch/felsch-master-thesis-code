#!/usr/bin/env bash
# 99_full_run_v5.sh: runs the full V5 chain unattended: offline suites, cluster bring-up, verification, measurements and teardown.
#
# Needs:  PCS_API_KEY in the environment, gcloud (authenticated), kubectl, a running docker daemon,
#         the evaluation approver credentials and the harness key, and pinned digests at
#         results_v4_k8s/environment/image-digests.env whose runner source hash matches the source
#         (or REBUILD_RUNNER=1).
# Usage:  export PCS_API_KEY=...
#         caffeinate -ims ./scripts/gke-v5/99_full_run_v5.sh
# Result: A log under results_v5/runs. A failing step stops the chain and, by default, leaves the
#         cluster up so the failure can be inspected. Exit code non zero on failure, 2 on a failed
#         preflight. Nothing is committed to git: commits stay a manual decision.
#
# It is designed to survive the operator walking away. Every step is timestamped and logged.
#
# Variables go before caffeinate, not between it and the script: caffeinate runs its
# first argument as a command, so `caffeinate -ims FOO=1 ./99...` tries to execute a
# program called "FOO=1" and fails before the run starts.
#
#   REBUILD_RUNNER=1 KEEP_CLUSTER=1 caffeinate -ims ./scripts/gke-v5/99_full_run_v5.sh
#
#   BOOKING_WORLD=duffel DUFFEL_TOKEN=duffel_test_... KEEP_CLUSTER=1 \
#       caffeinate -ims ./scripts/gke-v5/99_full_run_v5.sh
#
# Exporting them first and then calling caffeinate on its own is equivalent.
#
# Environment:
#   PCS_API_KEY          required, the Authority needs it to appraise (30_deploy_v5.sh)
#   BOOKING_WORLD        optional, "duffel" runs the live path (37, 38) after the deploy;
#                        unset or "mock" is the recorded run against the V2 catalogue
#   DUFFEL_TOKEN         required when BOOKING_WORLD=duffel. Never written to a file
#   RESEED_WORLD         0 (default) a deploy that changes BOOKING_WORLD aborts in 30;
#                        1 deletes authority-db and gateway-db and seeds the new world
#   DESTROY_ON_FAILURE   0 (default) keep the cluster on failure, 1 tear it down anyway
#   REBUILD_RUNNER       0 (default) keep the pinned runner image. 1 rebuilds it via
#                        scripts/gke/20_build_push_images.sh, which changes its digest
#                        and therefore invalidates policy, init-data and the freeze
#   SKIP_OFFLINE         0 (default) run the offline suites first, 1 to skip them
#   ATTACK_SERIES        0 (default) no live attack, 1 runs 35 twice: once on a field the
#                        policy binds and once on a field no binding reads (mock world only,
#                        35 refuses a live-world gateway)
#   WARM_SERIES          0 (default) no warm series, 1 adds a warm series to 31 (POOL=5,
#                        REPEAT=10) so the warm timings come from the same image as everything else
#   KEEP_CLUSTER         0 (default) tear the cluster down at the end, 1 keeps it up
# No -e: every step reports its own status through step(), and the chain decides.
set -uo pipefail

MOCKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1
# Unattended evaluation: the Authority's approval gate accepts the harness key
# only where it is pinned, so this deployment pins the evaluation credential set (a passkey
# plus the harness key). Its runs record every decision with kind "harness".
export APPROVER_CREDENTIALS="${APPROVER_CREDENTIALS:-${MOCKS_DIR}/k8s/v5/approver-credentials.eval.json}"
export HARNESS_APPROVER_KEY="${HARNESS_APPROVER_KEY:-${HOME}/.config/thesis-v5/harness-approver.json}"
[ -f "${APPROVER_CREDENTIALS}" ] && [ -f "${HARNESS_APPROVER_KEY}" ] || {
    echo "ABORT: evaluation needs ${APPROVER_CREDENTIALS} and ${HARNESS_APPROVER_KEY}:"
    echo "  python3 -m booking_approval.enroll harness --approver harness:eval \\"
    echo "      --credentials k8s/v5/approver-credentials.eval.json --key-out ~/.config/thesis-v5/harness-approver.json"
    exit 2; }

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"
LOG="${LOG_DIR}/full-run-${STAMP}.log"
mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG}") 2>&1

DESTROY_ON_FAILURE="${DESTROY_ON_FAILURE:-0}"
REBUILD_RUNNER="${REBUILD_RUNNER:-0}"
SKIP_OFFLINE="${SKIP_OFFLINE:-0}"
# The live transport attack of the evaluation and the warm timing series. Both are opt-in so
# the default run keeps the shape every earlier measurement had.
ATTACK_SERIES="${ATTACK_SERIES:-0}"
WARM_SERIES="${WARM_SERIES:-0}"
# Keep the cluster after a green run, for an extra series or an inspection by hand.
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"

# The image pins this run starts from, and where a rebuild writes them back.
PINNED_DIGESTS="results_v4_k8s/environment/image-digests.env"

FAILED_STEP=""
declare -a COMPLETED=()


# --- helpers ---------------------------------------------------------------

ts() { date -u +%H:%M:%SZ; }

say() { printf '\n[%s] %s\n' "$(ts)" "$*"; }

die() { printf '\n[%s] ABORT: %s\n' "$(ts)" "$*"; exit 2; }

step() {
    # Run one named step. Records it on success, sets FAILED_STEP and returns
    # non-zero on failure so the caller can stop the chain.
    local name="$1"; shift
    local t0=${SECONDS} rc=0
    printf '\n===== [%s] START %s =====\n' "$(ts)" "${name}"
    # Capture the exit code directly at the command. After a "fi" without an else
    # branch $? is zero even if the condition failed, and the run would then report
    # a FAIL with rc=0 and carry on.
    "$@" || rc=$?
    if [ "${rc}" -eq 0 ]; then
        printf '===== [%s] OK    %s  (%ss) =====\n' "$(ts)" "${name}" "$((SECONDS - t0))"
        COMPLETED+=("${name}")
        return 0
    fi
    printf '===== [%s] FAIL  %s  (rc=%s, %ss) =====\n' "$(ts)" "${name}" "${rc}" "$((SECONDS - t0))"
    FAILED_STEP="${name}"
    return "${rc}"
}

notify() {
    # Best-effort desktop notification. Never fails the run.
    osascript -e "display notification \"$2\" with title \"$1\"" >/dev/null 2>&1 || true
}

finish() {
    local rc="$1"
    # On failure the cluster is kept by default so the fault can be inspected.
    # DESTROY_ON_FAILURE=1 trades that for not paying for an idle TDX cluster.
    if [ "${rc}" != "0" ] && [ "${DESTROY_ON_FAILURE}" = "1" ]; then
        printf '\n[%s] DESTROY_ON_FAILURE=1: tearing the cluster down anyway\n' "$(ts)"
        ./scripts/gke-v5/91_cleanup_probe.sh || true
        ./scripts/gke-v5/90_destroy_v5.sh    || true
    elif [ "${rc}" != "0" ]; then
        printf '\n[%s] cluster left running for inspection.\n' "$(ts)"
        printf '     tear down with: ./scripts/gke-v5/91_cleanup_probe.sh && ./scripts/gke-v5/90_destroy_v5.sh\n'
    fi
    printf '\n========================================\n'
    printf '[%s] run %s\n' "$(ts)" "${STAMP}"
    printf 'completed steps: %s\n' "${#COMPLETED[@]}"
    # `${a[@]}` on an empty array is an unbound-variable error under `set -u` in bash 3.2,
    # which is the bash macOS ships, and finish() also runs when nothing completed.
    for s in ${COMPLETED[@]+"${COMPLETED[@]}"}; do printf '  OK   %s\n' "${s}"; done
    if [ -n "${FAILED_STEP}" ]; then
        printf '  FAIL %s\n' "${FAILED_STEP}"
        printf '\nVERDICT: FAILED at %s\n' "${FAILED_STEP}"
    else
        printf '\nVERDICT: all steps green\n'
    fi
    printf 'total: %s min\nlog: %s\n' "$((SECONDS / 60))" "${LOG}"
    printf '========================================\n'
    if [ "${rc}" = "0" ]; then
        if [ "${KEEP_CLUSTER}" = "1" ]; then
            notify "V5 run green" "all steps passed, cluster kept"
        else
            notify "V5 run green" "all steps passed, cluster destroyed"
        fi
    else
        notify "V5 run FAILED" "${FAILED_STEP:-preflight}, see ${LOG##*/}"
    fi
    exit "${rc}"
}


# --- preflight: fail before caffeinate was worth it -------------------------

say "preflight"
[ -n "${PCS_API_KEY:-}" ] || die "PCS_API_KEY is not set (30_deploy_v5.sh would die mid-run)"
command -v gcloud  >/dev/null || die "gcloud not on PATH"
command -v kubectl >/dev/null || die "kubectl not on PATH"
command -v docker  >/dev/null || die "docker not on PATH"
gcloud auth print-access-token >/dev/null 2>&1 || die "gcloud is not authenticated"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

# The guest this run would measure must be built from the code this run contains. The
# step "pin known image digests" below restores scripts/gke/.digests from the archive
# named here, that archive is written by a teardown, and it can therefore be older than
# the source. Then the runner may answer the v5-hello with pk_boot alone while the
# services already require pk_sig, and the run dies in step 31 after a full cluster
# bring-up. A measurement against a guest of a different protocol version would be invalid,
# so this check is fail-closed and a missing record counts as a mismatch.
check_runner_image_matches_source() {
    local want have
    want="$(python3 scripts/gke/_runner_source_hash.py "${MOCKS_DIR}")" \
        || die "cannot hash the runner source (scripts/gke/_runner_source_hash.py)"
    have="$(sed -n 's/^RUNNER_SOURCE_SHA256=//p' "${PINNED_DIGESTS}" | tail -1)"
    if [ "${want}" = "${have}" ]; then
        say "runner image matches the source (${want:0:12})"
        return 0
    fi
    say "the pinned runner image does not match the source this run would measure:"
    say "  source now  : ${want}"
    say "  image built : ${have:-<not recorded, the pin predates this check>}"
    die "rebuild the guest first: REBUILD_RUNNER=1 $0"
}
if [ "${REBUILD_RUNNER}" = "1" ]; then
    say "REBUILD_RUNNER=1: the guest is rebuilt in this run, source check not needed"
else
    [ -f "${PINNED_DIGESTS}" ] || die "no pinned digests at ${PINNED_DIGESTS}"
    check_runner_image_matches_source
fi
say "preflight ok (destroy_on_failure=${DESTROY_ON_FAILURE} rebuild_runner=${REBUILD_RUNNER})"


# --- offline suites ---------------------------------------------------------

if [ "${SKIP_OFFLINE}" = "0" ]; then
    step "offline: booking_v5" \
        python3 -m unittest discover -s booking_v5 -p 'tests_*.py' -t . || finish 1
    step "offline: booking_demo" \
        python3 -m booking_demo.tests_demo || finish 1
fi


# --- cluster bring-up -------------------------------------------------------

step "pin known image digests" \
    cp "${PINNED_DIGESTS}" scripts/gke/.digests || finish 1

if [ "${REBUILD_RUNNER}" = "1" ]; then
    say "WARNING: rebuilding the runner image changes its digest. Policy, init-data"
    say "         and the freeze record all become stale after this run"
    step "rebuild runner image" ./scripts/gke/20_build_push_images.sh || finish 1
fi

step "00 preflight"          ./scripts/gke-v5/00_preflight_v5.sh      || finish 1
step "12 create cluster"     ./scripts/gke-v5/12_create_cluster_v5.sh || finish 1
step "15 render caa values"  ./scripts/gke-v5/15_render_caa_values.sh || finish 1
step "14 install coco"       ./scripts/gke-v5/14_install_coco.sh      || finish 1

# Substrate against the pins, before agent-system exists.
step "40 verify (substrate)" ./scripts/gke-v5/40_verify_v5.sh --substrate || finish 1

step "13 genpolicy"          ./scripts/gke-v5/13_genpolicy.sh         || finish 1
# A19 against the policy 13 has just rendered, named explicitly. 41's own default is the
# probe policy of the last freeze, which a new runner image makes stale, and a stale policy
# would pass while saying nothing about what this run measures. The file below is the one
# whose digest goes into init-data and therefore into RTMR3. No cluster needed, so it runs
# here and not at the end: a policy that does not hold makes everything after it pointless.
step "41 a19 against the rendered policy" \
    ./scripts/gke-v5/41_probe_a19.sh "${MOCKS_DIR}/k8s/v5/init-data/policy.rego" || finish 1
step "23 build services"     ./scripts/gke-v5/23_build_services_image.sh || finish 1

# Without this the next run's "pin known image digests" restores the old archive and
# puts the guest that was just rebuilt back on the shelf, silently. Only after 23, so
# the archive carries the services image as well.
if [ "${REBUILD_RUNNER}" = "1" ]; then
    step "archive the rebuilt pins" \
        cp scripts/gke/.digests "${PINNED_DIGESTS}" || finish 1
fi
step "30 deploy"             ./scripts/gke-v5/30_deploy_v5.sh         || finish 1

# The live world, when one was asked for. BOOKING_WORLD is unset by default, so this
# whole block is skipped and the run is the recorded one, against the V2 catalogue.
# 37 must come after 30: the seeder has written the world into both stores by then, and
# the gateway it patches has to exist.
if [ -n "${BOOKING_WORLD:-}" ] && [ "${BOOKING_WORLD}" != "mock" ]; then
    if [ -z "${DUFFEL_TOKEN:-}" ] && [ -z "${SERPAPI_KEY:-}" ]; then
        say "BOOKING_WORLD=${BOOKING_WORLD} but neither DUFFEL_TOKEN nor SERPAPI_KEY is set."
        say "37 would store nothing and the gateway would refuse to start. Stopping here."
        finish 1
    fi
    step "37 credential store"   ./scripts/gke-v5/37_install_openbao.sh   || finish 1
    step "38 negative (live)"    ./scripts/gke-v5/38_negative_live_v5.sh  || finish 1
fi

# This includes the "v5 no harness listener" check.
step "40 verify (deployed)"  ./scripts/gke-v5/40_verify_v5.sh         || finish 1
# Ten seconds, right here, because the answer decides whether the measurements below are
# evidence at all. The same question is asked again from the run record further down, and
# that one confirms what the record says rather than what the service says.
step "36 observation check (deployed)" \
    ./scripts/gke-v5/36_assert_observation_v5.sh || finish 1


# --- measurements -----------------------------------------------------------

# The happy path must not only succeed, it must succeed on a deployment that has the
# check. A record that says `unknown` is not evidence for anything the attack would
# afterwards show, and that combination would otherwise go unnoticed until the cluster
# is already gone.
assert_observation_bound() {
    python3 - "${MOCKS_DIR}/results_v5/e2e" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
newest = max((d for d in out.iterdir() if (d / "run.json").exists()),
             key=lambda d: (d / "run.json").stat().st_mtime)
value = json.loads((newest / "run.json").read_text())["manifest"].get("observation_check")
print(f"{newest.name}: observation_check = {value}")
if value != "bound":
    raise SystemExit("the Authority of this deployment does not check observations "
                     "against the effect ledger, so nothing after this is evidence for it")
PY
}

step "31 run fragment"       ./scripts/gke-v5/31_run_fragment_v5.sh   || finish 1
step "observation check bound" assert_observation_bound               || finish 1
step "32 negative"           ./scripts/gke-v5/32_negative_v5.sh       || finish 1

if [ "${ATTACK_SERIES}" = "1" ]; then
    step "35 transport rewrites a bound field" \
        ./scripts/gke-v5/35_transport_attack_v5.sh || finish 1
    # ATTACK_INSERT=1, because in the running world every field of a booking is read by
    # some rule. Adding one is the only way to touch a field no rule reads, and that is the
    # claim: the digest covers the whole response.
    step "35 transport writes a field no rule reads" \
        env ATTACK_FIELD=status ATTACK_VALUE=confirmed-by-someone-else ATTACK_INSERT=1 \
        ./scripts/gke-v5/35_transport_attack_v5.sh || finish 1
fi

if [ "${WARM_SERIES}" = "1" ]; then
    # POOL=5, not 2. The sizing rule is measured: a replacement boots in about 87 s and a
    # warm run takes about 21 s, so sustained warm hand-offs need POOL >= ceil(87/21) = 5.
    # A POOL=2 series delivers 8 warm and 4 cold out of 12, in the pattern cold, warm, warm,
    # cold, and a mixed series is not a warm series.
    # TOLERATE_SUBSTRATE_VARIANCE is for a latency series only: it changes no decision, it
    # only keeps a provider RTMR0 refusal from aborting twenty minutes of measurement.
    step "31 warm series (pool 5, ten repetitions)" \
        env POOL=5 REPEAT=10 TOLERATE_SUBSTRATE_VARIANCE=1 \
        ./scripts/gke-v5/31_run_fragment_v5.sh || finish 1
fi


# --- teardown ---------------------------------------------------------------

if [ "${KEEP_CLUSTER}" = "1" ]; then
    step "91 cleanup probe"  ./scripts/gke-v5/91_cleanup_probe.sh     || finish 1
    say "KEEP_CLUSTER=1: the cluster stays up. Tear it down with 90_destroy_v5.sh."
    finish 0
fi

step "91 cleanup probe"      ./scripts/gke-v5/91_cleanup_probe.sh     || finish 1
step "90 destroy"            ./scripts/gke-v5/90_destroy_v5.sh        || finish 1

finish 0
