#!/usr/bin/env bash
# _genpolicy.sh: produces the guest policy for one concrete Pod manifest with CoCo's genpolicy, then applies our tightenings.
#
# Needs:  docker (genpolicy is a Linux binary and runs as linux/amd64), curl, python3, gcloud for a
#         short-lived registry token, and KATA_VERSION from _config.sh. Network access the first
#         time, to fetch the pinned kata release asset.
# Usage:  _genpolicy.sh POD_YAML OUT_REGO       (called by 13, 18 and 22)
# Result: OUT_REGO, the derived k8s/v5/genpolicy-settings.json and the patched rules under
#         results_v5/genpolicy-<kata>/rules.patched.rego. Exit code non zero if any gate fails.
#
# The policy is generated with kata ${KATA_VERSION}, the agent version inside our pod-VM image.
# genpolicy is taken from the pinned kata release asset
# kata-tools-static-${KATA_VERSION}-amd64.tar.zst and run under Docker (linux/amd64).
#
# The generator receives the Pod manifest that will be launched, the rules.rego of the same
# pinned Kata release with the backport of _rules_backport.py, settings derived from the pinned
# upstream defaults, and short-lived Artifact Registry credentials to inspect the image layers.
# The resulting policy pins, among other things, the namespace, the container command, the
# environment, the mounts and the image layers (dm-verity roots).
#
# GKE/containerd sends the OCI Runtime Spec version of its release in CreateContainerRequest:
# 1.2.1 on node 1.35.8-gke.1036000 and 1.3.0 on 1.35.8-gke.1225000. The version is part of
# what the node sends, so it follows NODE_VERSION. The upstream genpolicy settings of our Kata
# release may still default to OCI 1.1.0, and if the policy and the runtime versions differ the
# Kata Agent rejects the container. The OCI version the GKE runtime sends is therefore pinned
# here.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
POD_YAML="${1:?pod yaml}"
OUT_REGO="${2:?output rego}"
command -v docker >/dev/null || die "docker required (runs the Linux genpolicy binary)"

# --- runtime and policy compatibility pin ----------------------------------------------------
# KATA_VERSION and GENPOLICY_OCI_VERSION are separate pins:
#   KATA_VERSION           the version of genpolicy and rules.rego, and of the Kata Agent inside
#                          the pod-VM image
#   GENPOLICY_OCI_VERSION  the OCI Runtime Spec version the host container runtime emits and the
#                          Kata Agent receives in CreateContainerRequest
# The GKE/containerd runtime observed in the live probe sends input.OCI.Version = 1.3.0
# (node 1.35.8-gke.1225000, node 1.35.8-gke.1036000 sent 1.2.1).
GENPOLICY_OCI_VERSION="${GENPOLICY_OCI_VERSION:-1.3.0}"

TOOLS="${MOCKS_DIR}/results_v5/genpolicy-${KATA_VERSION}"
mkdir -p "${TOOLS}"

# --- fetch genpolicy and the matching policy assets from the pinned Kata release -------------
if [ ! -x "${TOOLS}/genpolicy" ]; then
  asset="kata-tools-static-${KATA_VERSION}-amd64.tar.zst"
  say "downloading ${asset} (genpolicy, rules.rego, settings)"
  curl -fsSL -o "${TOOLS}/${asset}" \
    "https://github.com/kata-containers/kata-containers/releases/download/${KATA_VERSION}/${asset}"
  docker run --rm --platform linux/amd64 -v "${TOOLS}:/t" alpine:3.20 sh -c "
      set -eu
      apk add -q zstd tar
      cd /t
      tar --zstd -xf ${asset} \
        ./opt/kata/bin/genpolicy \
        ./opt/kata/share/defaults/kata-containers/rules.rego \
        ./opt/kata/share/defaults/kata-containers/genpolicy-settings.json
    "
  mv "${TOOLS}/opt/kata/bin/genpolicy" "${TOOLS}/genpolicy"
  mv "${TOOLS}/opt/kata/share/defaults/kata-containers/rules.rego" "${TOOLS}/rules.rego"
  mv "${TOOLS}/opt/kata/share/defaults/kata-containers/genpolicy-settings.json" "${TOOLS}/genpolicy-settings.upstream.json"
  rm -rf "${TOOLS}/opt" "${TOOLS}/${asset}"
  chmod +x "${TOOLS}/genpolicy"
fi

# --- security gate: GHSA-fmg6-v47x-52wr / CVE-2026-77176, genpolicy <= 4.0.0 -----------------
# The rules.rego of Kata 3.31.0 validates mount destinations but not mount sources, so a
# malicious host can back approved mount points with attacker-chosen guest paths or
# content. Fixed upstream in 4.1.0 (commit 788e2df4). Our agent stays 3.31.0, so the
# three-edit fix is backported onto the 3.31.0 rules (_rules_backport.py) and the result
# is pinned by hash: a different upstream file or a failed backport stops the build.
# The pinned hash also covers the image-source rule (two further edits in _rules_backport.py:
# the call and the rule allow_image_source with its three cases). Re-pin only after reviewing
# the diff.
RULES_PATCHED_SHA256="${RULES_PATCHED_SHA256:-cf220e811a23c719a4f378903f2523194ee9a4cf5cb6bb307df0eda00e0198e2}"
patched_sha="$(python3 "$(dirname "${BASH_SOURCE[0]}")/_rules_backport.py" "${TOOLS}/rules.rego" "${TOOLS}/rules.patched.rego")" \
  || die "rules.rego backport failed (upstream rules.rego changed? see _rules_backport.py)"
[ "${patched_sha}" = "${RULES_PATCHED_SHA256}" ] || \
  die "patched rules.rego hash ${patched_sha} != pinned ${RULES_PATCHED_SHA256} (re-pin only after reviewing the diff)"
say "rules.rego: kata ${KATA_VERSION} + GHSA-fmg6-v47x-52wr backport, sha256 ${patched_sha:0:16}…"

# --- derive our settings from the pinned upstream defaults -----------------------------------
# The settings are derived from the settings that ship with the pinned Kata release, not
# maintained as a separate file. The changes:
#   1. OCI Runtime Spec version: GKE/containerd sends the OCI version of the node (see
#      GENPOLICY_OCI_VERSION above). genpolicy must model that value, otherwise the generated
#      policy rejects the sandbox before our runner can start.
#   2. Controller stream requests, required for the controller hand-off: ReadStreamRequest,
#      WriteStreamRequest and CloseStdinRequest.
#   3. Pause-container sysctls: the values GKE injects, pinned instead of widening
#      allow_linux_sysctl.
# ExecProcessRequest stays disabled. The generated Rego below disables it once more.
python3 - "${TOOLS}/genpolicy-settings.upstream.json" "${V5_K8S_DIR}/genpolicy-settings.json" \
  "${GENPOLICY_OCI_VERSION}" <<'PY'
import json
import sys

src, dst, oci_version = sys.argv[1:4]

with open(src, "r", encoding="utf-8") as f:
    d = json.load(f)

if "kata_config" not in d:
    raise SystemExit("upstream genpolicy settings contain no kata_config")

if "request_defaults" not in d:
    raise SystemExit("upstream genpolicy settings contain no request_defaults")

# GKE/containerd -> Kata Agent runtime OCI version.
d["kata_config"]["oci_version"] = oci_version
# GKE/containerd injects these network sysctls into the Pod sandbox OCI spec.
# Kata genpolicy 3.31.0 only models two of them by default.
#
# The values observed on our V5 GKE platform are pinned instead of weakening
# allow_linux_sysctl. If GKE changes this runtime profile later, the probe fails
# closed and this platform profile is updated.

gke_pause_sysctls = {
    "net.core.optmem_max": "20480",
    "net.core.somaxconn": "1024",

    "net.ipv4.conf.all.accept_redirects": "0",
    "net.ipv4.conf.all.forwarding": "1",
    "net.ipv4.conf.all.route_localnet": "1",
    "net.ipv4.conf.default.forwarding": "1",

    "net.ipv4.ip_forward": "1",
    "net.ipv4.ip_unprivileged_port_start": "0",
    "net.ipv4.ping_group_range": "0 2147483647",

    "net.ipv4.tcp_fin_timeout": "60",
    "net.ipv4.tcp_keepalive_intvl": "60",
    "net.ipv4.tcp_keepalive_probes": "5",
    "net.ipv4.tcp_keepalive_time": "300",
    "net.ipv4.tcp_rmem": "4096 87380 6291456",
    "net.ipv4.tcp_syn_retries": "6",
    "net.ipv4.tcp_tw_reuse": "0",
    "net.ipv4.tcp_wmem": "4096 16384 4194304",

    "net.ipv4.udp_rmem_min": "4096",
    "net.ipv4.udp_wmem_min": "4096",

    "net.ipv6.conf.all.disable_ipv6": "1",
    "net.ipv6.conf.default.accept_ra": "0",
    "net.ipv6.conf.default.disable_ipv6": "1",

    "net.netfilter.nf_conntrack_generic_timeout": "600",
    "net.netfilter.nf_conntrack_tcp_be_liberal": "1",
    "net.netfilter.nf_conntrack_tcp_timeout_close_wait": "3600",
    "net.netfilter.nf_conntrack_tcp_timeout_established": "86400",
}

d["pause_container"]["Linux"]["Sysctl"].update(gke_pause_sysctls)
# Streams needed for controller attach / hand-off.
rd = d["request_defaults"]
rd["ReadStreamRequest"] = True
rd["WriteStreamRequest"] = True
rd["CloseStdinRequest"] = True

with open(dst, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=2)
    f.write("\n")
PY

# --- fail closed if the generated settings do not carry the expected OCI pin -----------------
actual_oci="$(python3 - "${V5_K8S_DIR}/genpolicy-settings.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    d = json.load(f)

print(d["kata_config"]["oci_version"])
PY
)"
[ "${actual_oci}" = "${GENPOLICY_OCI_VERSION}" ] || \
  die "genpolicy OCI version mismatch: got ${actual_oci}, expected ${GENPOLICY_OCI_VERSION}"
say "genpolicy settings: kata=${KATA_VERSION}, OCI=${actual_oci}"

# --- working directory -----------------------------------------------------------------------
work="$(mktemp -d)"
cleanup() { rm -rf "${work}"; }
trap cleanup EXIT
cp "${POD_YAML}" "${work}/pod.yaml"
cp "${V5_K8S_DIR}/genpolicy-settings.json" "${work}/settings.json"
mkdir -p "${work}/docker"

# --- short-lived Artifact Registry credential for genpolicy ----------------------------------
# genpolicy inspects the image layers to produce the image policy and the dm-verity roots.
python3 - "${AR_HOST}" "$(gcloud auth print-access-token)" > "${work}/docker/config.json" <<'PY'
import base64
import json
import sys

host, token = sys.argv[1:3]
auth = base64.b64encode(f"oauth2accesstoken:{token}".encode()).decode()
print(json.dumps({"auths": {host: {"auth": auth}}}))
PY
chmod 600 "${work}/docker/config.json"

# --- run genpolicy ---------------------------------------------------------------------------
# -s ignores manifest fields genpolicy does not model, for example activeDeadlineSeconds. Those
# fields are enforced by Kubernetes and the kubelet rather than inside the guest. The guest
# policy still pins the security-relevant container description: image, command, env, mounts,
# namespace and image layers.
say "genpolicy (kata ${KATA_VERSION}, OCI ${GENPOLICY_OCI_VERSION}) on $(basename "${POD_YAML}"), pulls image layers once (cache: ${TOOLS}/layers)"
mkdir -p "${TOOLS}/layers"
docker run --rm --platform linux/amd64 -v "${work}:/w" -v "${TOOLS}:/kata:ro" -v "${TOOLS}/layers:/layers" \
  -e DOCKER_CONFIG=/w/docker -w /layers python:3.12-slim \
  /kata/genpolicy -y /w/pod.yaml -p /kata/rules.patched.rego -j /w/settings.json -u -r -s \
  > "${work}/generated.rego"
[ -s "${work}/generated.rego" ] || die "genpolicy produced no policy"

# --- tighten the generated policy ------------------------------------------------------------
# CopyFileRequest stays as generated (path-restricted). A blanket CopyFileRequest deny breaks
# peer pods, because the shim copies files such as /etc/hosts, /etc/resolv.conf and projected
# ServiceAccount material.
# ExecProcessRequest is disabled. P2 and P3 of 18 therefore run their probe as the container's
# initial command and do not use kubectl exec.
# SetPolicyRequest is disabled, so the untrusted host cannot replace the policy after boot.
{
  # No timestamp in this header. It is part of policy.rego, policy.rego is part of the
  # init-data, and the init-data digest is measured into RTMR3 and pinned as a reference value.
  # A clock in it made every rendering produce a different digest, so the reference values
  # could not be re-derived from the sources, and a deployment whose policy was rendered at a
  # different minute than the services image was built refused every run with rtmr3-mismatch
  # (the TD's RTMR3 replays against the digest of the policy on disk).
  # The rendering is identified by what the header keeps: the genpolicy version, the OCI
  # version, the hash of the backported rules and the pod manifest it was generated for.
  # The echo line below is part of the measured policy: change its text only with a new freeze.
  echo "# GENERATED by genpolicy (kata ${KATA_VERSION}, OCI ${GENPOLICY_OCI_VERSION}, rules.rego + GHSA-fmg6-v47x-52wr backport ${patched_sha:0:16}) for $(basename "${POD_YAML}"); tightened by _genpolicy.sh"
  sed \
    -e 's/^default ExecProcessRequest := true/default ExecProcessRequest := false/' \
    -e 's/^default SetPolicyRequest := true/default SetPolicyRequest := false/' \
    "${work}/generated.rego"
} > "${OUT_REGO}"

# --- sanity checks ---------------------------------------------------------------------------
grep -q "ExecProcessRequest" "${OUT_REGO}" || die "unexpected policy shape: no ExecProcessRequest rule"
grep -q "SetPolicyRequest" "${OUT_REGO}" || die "unexpected policy shape: no SetPolicyRequest rule"
grep -q "^default ExecProcessRequest := false" "${OUT_REGO}" || die "ExecProcessRequest is not fail-closed"
grep -q "^default SetPolicyRequest := false" "${OUT_REGO}" || die "SetPolicyRequest is not fail-closed"

say "policy written: ${OUT_REGO} ($(wc -l < "${OUT_REGO}") lines)"
