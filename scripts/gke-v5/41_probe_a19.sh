#!/usr/bin/env bash
# 41_probe_a19.sh: checks offline and deterministically that the measured runner policy denies host writes to the init-data files (A19).
#
# Needs:  python3 with booking_v5, curl, and network access the first time, to fetch a pinned OPA
#         into results_v5/opa (it is cached afterwards). No cluster is needed.
# Usage:  ./41_probe_a19.sh [POLICY.rego]     default: the frozen runner policy of FREEZE_STAMP (_config.sh)
# Result: The verdict of booking_v5.probe_a19 on stdout. Exit code from that probe.
#
# The measured runner policy must deny a host CopyFileRequest onto /run/peerpod/* (the init-data
# files), while a path inside the sandbox share dir is allowed (positive control). A19 is the
# attack label of attack_catalogue.md. The kata-agent enforces this genpolicy policy. Its digest is in the freeze and 40 checks that the
# ConfigMap equals the freeze, so evaluating it with OPA answers, for the enforced policy itself,
# whether the write is allowed. A live CopyFile is not used: the agent is reachable only over the
# forwarder's mutual-TLS ttrpc on the pod VM, which kata-agent-ctl cannot speak.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"

OPA_VERSION="${OPA_VERSION:-0.68.0}"
OPA_DIR="${MOCKS_DIR}/results_v5/opa"
OPA="${OPA_DIR}/opa"
POLICY="${1:-${MOCKS_DIR}/results_v5/freeze-candidate/runner-peer-${FREEZE_STAMP}.policy.rego}"

[ -f "${POLICY}" ] || die "policy not found: ${POLICY} (pass the measured runner policy.rego)"
POLICY="$(cd "$(dirname "${POLICY}")" && pwd)/$(basename "${POLICY}")"   # absolute: the script cds to MOCKS_DIR below

# --- ensure a pinned opa binary for this OS/arch (cached, from the GitHub release) -----------
if [ ! -x "${OPA}" ]; then
  mkdir -p "${OPA_DIR}"
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"       # linux | darwin
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "unsupported arch $(uname -m)" ;;
  esac
  # OPA static asset names: opa_linux_{amd64,arm64}_static, opa_darwin_amd64, opa_darwin_arm64_static
  if [ "${os}" = "darwin" ] && [ "${arch}" = "amd64" ]; then asset="opa_darwin_amd64"
  else asset="opa_${os}_${arch}_static"; fi
  say "fetching opa ${OPA_VERSION} (${asset})"
  curl -fsSL -o "${OPA}" \
    "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/${asset}"
  chmod +x "${OPA}"
fi
# A cached binary of another version would otherwise be used without notice, and 40 would then
# reject it. The whole output is read first, as in 40 (grep -q under pipefail races with opa).
opa_out="$("${OPA}" version 2>/dev/null)" || true
printf '%s\n' "${opa_out}" | grep -qE "^Version:[[:space:]]+${OPA_VERSION}$" \
  || die "${OPA} is not OPA ${OPA_VERSION}: delete it and re-run"

say "A19 against measured policy: $(basename "${POLICY}")"
cd "${MOCKS_DIR}"
python3 -m booking_v5.probe_a19 --opa "${OPA}" --policy "${POLICY}"
