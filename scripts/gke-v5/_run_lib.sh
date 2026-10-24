#!/usr/bin/env bash
# _run_lib.sh: shared helpers for the unattended run scripts (45, 47, 48, 97, 98a, 98b, 100).
#
# Needs:  The caller sets LOG and STAMP before sourcing, and defines DESTROY_ON_FAILURE if it
#         wants the teardown-on-failure behaviour.
# Usage:  source "${HERE}/_run_lib.sh"
# Result: The functions ts, say, die, step, notify, newest_stamp, summarise, common_preflight and
#         require_cluster, and the variables FAILED_STEP and COMPLETED. Each caller defines its
#         own finish.

FAILED_STEP=""
declare -a COMPLETED=()

ts() { date -u +%H:%M:%SZ; }

say() { printf '\n[%s] %s\n' "$(ts)" "$*"; }

die() { printf '\n[%s] ABORT: %s\n' "$(ts)" "$*"; exit 2; }

step() {
    # step "name" cmd args...  -> records the step, returns the command's code
    local name="$1"; shift
    local t0=${SECONDS} rc=0
    printf '\n===== [%s] START %s =====\n' "$(ts)" "${name}"
    # Capture the exit code directly at the command. After a "fi" without an else
    # branch $? is zero even if the condition failed.
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
    # Best-effort desktop notification (macOS). It does not fail the run.
    osascript -e "display notification \"$2\" with title \"$1\"" >/dev/null 2>&1 || true
}

newest_stamp() {
    # newest_stamp <dir> <prefix> [marker-file]
    # The stamp of the newest matching file. With a marker file only files newer than the
    # marker count, so a run does not pick up an old stamp when the step that should have
    # produced one wrote nothing.
    local dir="$1" prefix="$2" marker="${3:-}" f
    if [ -n "${marker}" ] && [ -e "${marker}" ]; then
        f="$(find "${dir}" -maxdepth 1 -name "${prefix}*" -newer "${marker}" -type f 2>/dev/null \
             | xargs -r ls -t 2>/dev/null | head -1)"
    else
        f="$(ls -t "${dir}/${prefix}"*.txt "${dir}/${prefix}"*.json 2>/dev/null | head -1)" || true
    fi
    [ -n "${f}" ] || return 1
    basename "${f}" | sed -E "s/^${prefix}//; s/\.(txt|json)$//"
}

summarise() {
    # summarise <rc> <title-on-success> <title-on-failure>
    local rc="$1"
    printf '\n========================================\n'
    printf '[%s] run %s\n' "$(ts)" "${STAMP}"
    printf 'completed steps: %s\n' "${#COMPLETED[@]}"
    for s in ${COMPLETED[@]+"${COMPLETED[@]}"}; do printf '  OK   %s\n' "${s}"; done
    [ -n "${FAILED_STEP}" ] && printf '  FAIL %s\n\nVERDICT: FAILED at %s\n' "${FAILED_STEP}" "${FAILED_STEP}"
    [ -z "${FAILED_STEP}" ] && printf '\nVERDICT: all steps green\n'
    printf 'total: %s min\nlog: %s\n' "$((SECONDS / 60))" "${LOG}"
    printf '========================================\n'
    if [ "${rc}" = "0" ]; then notify "$2" "see ${LOG##*/}"; else notify "$3" "${FAILED_STEP:-preflight}"; fi
}

common_preflight() {
    command -v gcloud  >/dev/null || die "gcloud not on PATH"
    command -v kubectl >/dev/null || die "kubectl not on PATH"
    command -v docker  >/dev/null || die "docker not on PATH"
    gcloud auth print-access-token >/dev/null 2>&1 || die "gcloud is not authenticated"
    docker info >/dev/null 2>&1 || die "docker daemon not reachable"
}

require_cluster() {
    # Without a reachable cluster 18, 19, 22 and 40 fail at once.
    kubectl cluster-info >/dev/null 2>&1 \
        || die "no reachable Kubernetes cluster (kubectl has no working context). Bring one up first, or run with CREATE_CLUSTER=1"
}
