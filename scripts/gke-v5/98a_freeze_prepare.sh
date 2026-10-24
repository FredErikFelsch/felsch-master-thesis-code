#!/usr/bin/env bash
# 98a_freeze_prepare.sh: phase A of the final measurement. Rebuilds the runner image and produces a NEW freeze candidate.
#
# Needs:  PCS_API_KEY in the environment, a reachable cluster (or CREATE_CLUSTER=1), gcloud, kubectl,
#         helm and docker, and the preflight tools of _run_lib.sh.
# Usage:  export PCS_API_KEY=...
#         caffeinate -ims ./scripts/gke-v5/98a_freeze_prepare.sh
# Result: results_v5/freeze-candidate/freeze-<stamp>.json, with the stamp printed in the hand-over
#         text, and the cluster left running for phase B. Exit code non zero if any step failed.
#
# It runs unattended and stops before anything is pinned, because pinning a freeze is an
# acceptance decision and not a script step.
#
# What it does: rebuild and push the runner image, regenerate the guest policy and the
# init-data from the new image digest, run the probe chain so that a real quote carries
# the new init-data, record the substrate, assemble the freeze candidate and verify it.
# The cluster is left running for phase B.
#
# Environment:
#   PCS_API_KEY     required
#   CREATE_CLUSTER  1 to bring a cluster up first (00, 12, 15, 14), default 0
#   RESUME_FROM     stamp of a failed run of this script (the name of its freeze-prepare log).
#                   Skips the cluster bring-up, the rebuild and the probes of that run and goes on
#                   with the substrate check, with the stamps those steps wrote. Only valid while the
#                   cluster of that run is still up and nothing was changed on it since.
#   ALLOW_A5C_OPEN  1 to freeze an image whose metadata server is reachable from the TD
#                   (default 0: refused). The A5c/B1 state is not taken from a label. It is read
#                   from the image provenance and checked against 19.
# No -e: every step reports its own status through step(), and the chain decides.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCKS_DIR="$(cd "${HERE}/../.." && pwd)"
cd "${MOCKS_DIR}" || exit 1

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_DIR="${MOCKS_DIR}/results_v5/runs"; mkdir -p "${LOG_DIR}"
LOG="${LOG_DIR}/freeze-prepare-${STAMP}.log"
exec > >(tee -a "${LOG}") 2>&1

source "${HERE}/_run_lib.sh"

CREATE_CLUSTER="${CREATE_CLUSTER:-0}"
ALLOW_A5C_OPEN="${ALLOW_A5C_OPEN:-0}"
RESUME_FROM="${RESUME_FROM:-}"
PROBE="${MOCKS_DIR}/results_v5/probe"
CAND="${MOCKS_DIR}/results_v5/freeze-candidate"

say "preflight"
[ -n "${PCS_API_KEY:-}" ] || die "PCS_API_KEY is not set"
common_preflight
say "preflight ok (create_cluster=${CREATE_CLUSTER})"

mkdir -p "${PROBE}" "${CAND}"
before="$(ls "${PROBE}" 2>/dev/null | sort)"

# Time marker of the run. Everything created later than this file belongs to this run, so an
# old stamp cannot be picked up by mistake.
MARKER="$(mktemp "${TMPDIR:-/tmp}/v5runmarker.XXXXXX")"
if [ -n "${RESUME_FROM}" ]; then
    [ -f "${LOG_DIR}/freeze-prepare-${RESUME_FROM}.log" ] \
        || die "RESUME_FROM=${RESUME_FROM}: no log ${LOG_DIR}/freeze-prepare-${RESUME_FROM}.log"
    python3 - "${MARKER}" "${RESUME_FROM}" <<'PY' || die "cannot date the marker from ${RESUME_FROM}"
import calendar, os, sys, time
stamp = calendar.timegm(time.strptime(sys.argv[2], "%Y%m%dT%H%M%SZ"))
os.utime(sys.argv[1], (stamp, stamp))
PY
    # What the failed run found in the probe directory before it started.
    before="$(find "${PROBE}" -mindepth 1 -maxdepth 1 ! -newer "${MARKER}" -exec basename {} \; | sort)"
    say "RESUME_FROM=${RESUME_FROM}: no bring-up, no rebuild, no probes, the stamps of that run are read from disk"
fi

finish() { summarise "$1" "Freeze prepare done" "Freeze prepare FAILED"; exit "$1"; }

# --- optional cluster bring-up ------------------------------------------------
if [ "${CREATE_CLUSTER}" != "1" ]; then
    require_cluster
    say "cluster reachable: $(kubectl config current-context 2>/dev/null || echo unknown)"
fi

if [ "${CREATE_CLUSTER}" = "1" ] && [ -z "${RESUME_FROM}" ]; then
    step "00 preflight"         ./scripts/gke-v5/00_preflight_v5.sh      || finish 1
    step "12 create cluster"    ./scripts/gke-v5/12_create_cluster_v5.sh || finish 1
    step "15 render caa values" ./scripts/gke-v5/15_render_caa_values.sh || finish 1
    step "14 install coco"      ./scripts/gke-v5/14_install_coco.sh      || finish 1
fi

if [ -z "${RESUME_FROM}" ]; then
    # --- the rebuild that makes a new freeze necessary ---------------------------
    step "20 build and push runner image" ./scripts/gke/20_build_push_images.sh || finish 1
    step "13 genpolicy (new init-data)"   ./scripts/gke-v5/13_genpolicy.sh     || finish 1
    # The services image carries its own copy of k8s/v5/init-data (Dockerfile.services), which is
    # what the Authority pins, while the controller renders from the working tree. After a fresh 13
    # the two only agree if the image is rebuilt, and 40 compares those two. Step 20 above
    # also rewrites scripts/gke/.digests, which drops SERVICES_IMAGE, so without this line 40 has
    # nothing to compare and reports FAIL every time, late in the run. 99 has the same step in the
    # same place for the same two reasons.
    step "23 build services"              ./scripts/gke-v5/23_build_services_image.sh || finish 1

    # --- probe chain: a real quote has to carry the new init-data ----------------
    step "18 probe peer pod"  ./scripts/gke-v5/18_probe_peer_pod.sh || finish 1
    step "19 probe network"   ./scripts/gke-v5/19_probe_network.sh  || finish 1

fi

QUOTE_STAMP="$(newest_stamp "${PROBE}" "verdict-" "${MARKER}")" \
    || die "18 produced no new verdict-<stamp>.txt. Nothing was measured in this run"
NET_STAMP="$(newest_stamp "${PROBE}" "network-" "${MARKER}")" \
    || say "WARNING: 19 produced no new network-<stamp> file"

PINNED="$(grep -oE 'FREEZE_STAMP="\$\{FREEZE_STAMP:-[^}]*\}"' "${HERE}/_config.sh" | sed -E 's/.*:-([^}]*)\}.*/\1/')"
[ "${QUOTE_STAMP}" != "${PINNED}" ] \
    || die "the new quote stamp equals the already pinned freeze ${PINNED}. This run measured nothing new"
say "quote stamp:   ${QUOTE_STAMP}"
say "network stamp: ${NET_STAMP:-<none>}"

# A5c, measured: 19's verdict on the peer pod under policy. A hardening label is not accepted
# in place of the measurement, because an image built without the hardening can still carry the
# label while the TD reaches 169.254.169.254.
A5C_VERDICT="$(grep -oE '^A5C_(CLOSED|OPEN|UNDECIDED)' "${PROBE}/network-${NET_STAMP:-none}.txt" 2>/dev/null | head -1)"
say "A5c measured:  ${A5C_VERDICT:-<no 19 verdict>}"
if [ "${A5C_VERDICT}" != "A5C_CLOSED" ] && [ "${ALLOW_A5C_OPEN}" != "1" ]; then
    die "A5c is not closed on the measured image (${A5C_VERDICT:-no verdict}). Rebuild with V5_HARDEN_A5C=noop or set ALLOW_A5C_OPEN=1 knowingly"
fi

if [ -z "${RESUME_FROM}" ]; then
    step "20 verify evidence offline" python3 ./scripts/gke-v5/20_verify_evidence_offline.py "${QUOTE_STAMP}" || finish 1
    step "21 dcap verify"             ./scripts/gke-v5/21_dcap_verify.sh "${QUOTE_STAMP}"                     || finish 1
    step "22 probe attach"            ./scripts/gke-v5/22_probe_attach.sh                                     || finish 1
fi

ATTACH_STAMP="$(newest_stamp "${PROBE}" "attach-" "${MARKER}")" \
    || say "WARNING: 22 produced no new attach-<stamp> file"
say "attach stamp:  ${ATTACH_STAMP:-<none>}"

# build_freeze reads the substrate hash from substrate-40-<stamp>.txt. 40 does not write that
# file itself, so its output must be stored under the quote stamp.
verify_substrate() {
    ./scripts/gke-v5/40_verify_v5.sh | tee "${PROBE}/substrate-40-${QUOTE_STAMP}.txt"
}
step "40 verify (substrate)" verify_substrate || finish 1

grep -qE 'substrate profile hash:[[:space:]]+PASS' "${PROBE}/substrate-40-${QUOTE_STAMP}.txt" \
    || die "the recorded output of 40_verify_v5.sh carries no PASS substrate profile hash. A freeze needs a green substrate"

# --- assemble the candidate --------------------------------------------------
say "copying the new probe artefacts into freeze-candidate/"
after="$(ls "${PROBE}" | sort)"
comm -13 <(echo "${before}") <(echo "${after}") | while read -r f; do
    [ -n "${f}" ] && cp -v "${PROBE}/${f}" "${CAND}/"
done

# The measured image is the one the live CAA boots (peer-pods-cm PODVM_IMAGE_NAME), not
# whichever provenance happens to lie in the candidate directory, which can belong to another
# image revision than the one that booted.
IMAGE_NAME="$(kubectl -n confidential-containers-system get cm peer-pods-cm \
    -o jsonpath='{.data.PODVM_IMAGE_NAME}' 2>/dev/null | sed 's#.*/##')"
[ -n "${IMAGE_NAME}" ] || die "cannot read PODVM_IMAGE_NAME from peer-pods-cm, so the measured image is unknown"
say "measured image: ${IMAGE_NAME}"
PROV_SRC="${MOCKS_DIR}/results_v5/podvm-image/${IMAGE_NAME}.provenance.txt"
[ -f "${PROV_SRC}" ] || die "no provenance for the measured image ${IMAGE_NAME} (${PROV_SRC})"
cp -v "${PROV_SRC}" "${CAND}/"

build_args=(build "results_v5/freeze-candidate" --stamp "${QUOTE_STAMP}")
[ -n "${NET_STAMP:-}" ]    && build_args+=(--network "${NET_STAMP}")
[ -n "${ATTACH_STAMP:-}" ] && build_args+=(--attach "${ATTACH_STAMP}")
[ -n "${IMAGE_NAME:-}" ]   && build_args+=(--image "${IMAGE_NAME}")
# The RUN init-data digest (what production runners are measured under) is rendered into the
# freeze, the probe digest stays recorded as probe_init_data.
# Read from the digests file step 20 just wrote, not from an inherited variable: the freeze must
# name the image that was built in this run.
RUNNER_IMAGE="$(sed -n 's/^RUNNER_IMAGE=//p' ./scripts/gke/.digests | tr -d '"')"
[ -n "${RUNNER_IMAGE}" ] || die "scripts/gke/.digests names no RUNNER_IMAGE, so the run init-data digest cannot be rendered"
build_args+=(--runner-image "${RUNNER_IMAGE}")

step "freeze_record build"  python3 -m booking_v5.freeze_record "${build_args[@]}"                          || finish 1
step "freeze_record verify" python3 -m booking_v5.freeze_record verify results_v5/freeze-candidate --stamp "${QUOTE_STAMP}" || finish 1

# --- hand over ---------------------------------------------------------------
cat <<HANDOVER

########################################################################
PHASE A COMPLETE. The cluster is still running. Nothing is pinned yet.

New freeze candidate: results_v5/freeze-candidate/freeze-${QUOTE_STAMP}.json

Do these by hand, then start phase B:

  1. Read the candidate and the 40 output. Confirm the substrate is green,
     DCAP verified, attach OK and the network verdicts are what you expect.

  2. Pin the stamp (_config.sh and booking_v5/tests_v5_fixtures.py,
     the previous line stays as the secondary set):
       python3 scripts/gke-v5/pin_freeze.py ${QUOTE_STAMP}

  3. Offline suites green, then commit:
       ./scripts/gke-v5/40_verify_v5.sh --offline

  4. Start phase B:
       caffeinate -ims ./scripts/gke-v5/98b_measure_and_teardown.sh

If the candidate is not acceptable, tear down with
  ./scripts/gke-v5/91_cleanup_probe.sh && ./scripts/gke-v5/90_destroy_v5.sh
########################################################################
HANDOVER

rm -f "${MARKER}"
finish 0
