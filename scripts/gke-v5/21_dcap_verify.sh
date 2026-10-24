#!/usr/bin/env bash
# 21_dcap_verify.sh: DCAP-verifies a recorded probe quote inside a linux/amd64 container.
#
# Needs:  Docker, the evidence log of a probe run (results_v5/probe/evidence-<STAMP>.log from 18),
#         and PCS_API_KEY (an Intel PCS subscription key) in the environment. Without the key
#         the container parses the quote but does not verify it.
# Usage:  ./21_dcap_verify.sh 20260903T145942Z            verify
#         DCAP_DEBUG=1 ./21_dcap_verify.sh <STAMP>          also print the raw QVL diagnostics
# Result: results_v5/probe/dcap-<STAMP>.txt.
#
# Intel's QVL is x86_64 Linux only and PCS is unreachable from sandboxes, so this runs in a
# linux/amd64 container (under Rosetta on an Apple machine). The key is passed as an
# environment variable at run time and is never baked into the image.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
STAMP="${1:?usage: $0 <STAMP>}"
OUT="${MOCKS_DIR}/results_v5/probe"
command -v docker >/dev/null || die "docker not installed (Docker Desktop)"
[ -f "${OUT}/evidence-${STAMP}.log" ] || die "no ${OUT}/evidence-${STAMP}.log"
[ -n "${PCS_API_KEY:-}" ] || say "PCS_API_KEY not set: the container will parse but not verify"
say "building dcap-verify image (first build downloads Intel's QVL packages, ~1 min)"
docker build --platform linux/amd64 -q -t v5-dcap-verify -f "${MOCKS_DIR}/docker/dcap-verify/Dockerfile" "${MOCKS_DIR}" >/dev/null
say "verifying quote of run ${STAMP}"
docker run --rm --platform linux/amd64 -e PCS_API_KEY -e DCAP_DEBUG="${DCAP_DEBUG:-0}" \
  -v "${OUT}:/work:ro" v5-dcap-verify "${STAMP}" | tee "${OUT}/dcap-${STAMP}.txt"
say "recorded: ${OUT}/dcap-${STAMP}.txt"
