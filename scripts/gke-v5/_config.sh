#!/usr/bin/env bash
# _config.sh: shared configuration for the CoCo peer-pods (TDX) environment.
#
# Needs:  ../gke/_config.sh (the V4.4c project and registry settings, MOCKS_DIR, say, die) and
#         _node_pin.sh next to this file.
# Usage:  source "$(dirname "${BASH_SOURCE[0]}")/_config.sh" from every script in this directory.
#         Overrides come only from V5_*-prefixed variables.
# Result: The variables and helper functions the V5 scripts share. Nothing is created or run.
#         There are no secrets in this file.
#
# Strict mode is set only when a script sources it. In an interactive shell (`source _config.sh`)
# -e/-u would kill the terminal on the first failing command or unset variable.
[[ $- == *i* ]] || set -euo pipefail
if [ -n "${ZSH_VERSION:-}" ]; then _CFG_SELF="${(%):-%x}"; else _CFG_SELF="${BASH_SOURCE[0]}"; fi
_V5_CFG_DIR="$(dirname "${_CFG_SELF}")"          # kept: the sourced ../gke/_config.sh reassigns _CFG_SELF
source "${_V5_CFG_DIR}/../gke/_config.sh"
# The V5 scripts print their own prefix. Otherwise say and die behave as in ../gke/_config.sh.
say()  { printf '\033[1;34m[v5]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[v5] ERROR:\033[0m %s\n' "$*" >&2; [[ $- == *i* ]] && return 1; exit 1; }

# The V4.4c config above already sets REGION/ZONE/CLUSTER/NODE_MACHINE/NUM_NODES, so
# `${VAR:-default}` would silently keep the V4.4c values. V5 therefore assigns its own
# values unconditionally and takes overrides only from V5_*-prefixed variables.
# TDX C3 confidential VMs exist in europe-west4 (not west1), see the supported configurations.
REGION="${V5_REGION:-europe-west4}"
ZONE="${V5_ZONE:-${REGION}-a}"
CLUSTER="${V5_CLUSTER:-thesis-v5}"
LOCATION_ARGS=(--zone "${ZONE}")

# Worker: peer pods require Ubuntu with containerd (COS is not supported).
NODE_MACHINE="${V5_NODE_MACHINE:-e2-standard-4}"
NUM_NODES="${V5_NUM_NODES:-1}"
NODE_IMAGE="${V5_NODE_IMAGE:-UBUNTU_CONTAINERD}"

# Peer pod VMs (the TDs): one per runner fragment.
PODVM_MACHINE="${PODVM_MACHINE:-c3-standard-4}"
PODVM_CONFIDENTIAL_TYPE="${PODVM_CONFIDENTIAL_TYPE:-TDX}"
PODVM_DISK_TYPE="${PODVM_DISK_TYPE:-pd-balanced}"
# --- Pins ------------------------------------------------------------------------
# One CAA release train for both profiles (checked against the source tags):
#   * CAA < 0.18 has no Helm chart, always gives pod VMs a public IP and tunnels over it
#     (incompatible with A5b), and its entrypoint hard-requires GCP_CREDENTIALS.
#   * CAA 0.21.1: Helm chart (bundles kata-deploy + kata-remote), internal IPs
#     (USE_PUBLIC_IP=false), GCP_SUBNETWORK, INITDATA. Every env var is mapped to a
#     flag in Go, so the entrypoint's key check can be bypassed (14 does that).
# The two pin profiles differ only in the pod-VM image:
#   probe  : our own image from the pinned CAA commit (11_build_podvm_image.sh), named after
#            the overlay revision.
#   freeze : no default, the image must be named explicitly with PODVM_IMAGE.
CAA_VERSION="${CAA_VERSION:-0.21.1}"          # git tag v${CAA_VERSION}, chart at src/cloud-api-adaptor/install/charts/peerpods
CAA_IMAGE_TAG="${CAA_IMAGE_TAG:-v${CAA_VERSION}-amd64}"
KATA_VERSION="${KATA_VERSION:-3.31.0}"          # kata-deploy subchart of the peerpods chart (guest agent, policy rules, genpolicy)
# Our pod-VM overlay (k8s/v5/podvm-overlay: initdata-measure into RTMR3, agent ordering, A5c).
# Bump when the overlay changes: the image name and the reference values change with it.
PODVM_OVERLAY_REV="${PODVM_OVERLAY_REV:-14}"
# The pod-VM hardening is on by default. When both were opt-in, image revisions were built
# without them unnoticed and A5c (the pod VM's metadata server reachable from the TD) reopened.
# noop = neutralise setup-nat-for-imds.sh and leave the unit graph unchanged (masking the unit
# did not boot). B1 = drop run-kata-containers.mount.
# 11_build_podvm_image.sh refuses anything else unless V5_ALLOW_UNHARDENED=1.
export V5_HARDEN_A5C="${V5_HARDEN_A5C:-noop}"
export V5_HARDEN_B1="${V5_HARDEN_B1:-1}"
# The CAA commit the pod-VM image is built from. The tag alone is not a pin: a tag can be
# moved, and an image whose source can change is not a reproducible reference value.
# 11_build_podvm_image.sh refuses to build when the clone lands on anything else.
CAA_COMMIT="${CAA_COMMIT:-ea3ea1f063b10073a551d97e11d31169ca4648f5}"          # v0.21.1
# The patches applied to that source before `make binaries`, in order. Part of the image
# identity, so their hash goes into the provenance beside the overlay hash.
PODVM_PATCH_DIR="${PODVM_PATCH_DIR:-${MOCKS_DIR}/k8s/v5/podvm-patches}"
# The frozen reference line the services are seeded from (30) and checked against (40).
# Earlier lines stay on disk under results_v5/ (secondary, verifiable).
# pin_freeze.py appends one line per pin, and the last one is the pin below.
# pinned by pin_freeze.py: 20260924T152405Z (previous line: 20260924T044611Z)
# pinned by pin_freeze.py: 20260925T084140Z (previous line: 20260924T152405Z)
# pinned by pin_freeze.py: 20260929T111343Z (previous line: 20260925T084140Z)
# pinned by pin_freeze.py: 20260930T155610Z (previous line: 20260929T111343Z)
# pinned by pin_freeze.py: 20261002T141743Z (previous line: 20260930T155610Z)
# pinned by pin_freeze.py: 20261003T073223Z (previous line: 20261002T141743Z)
# pinned by pin_freeze.py: 20261016T100620Z (previous line: 20261003T073223Z)
FREEZE_STAMP="${FREEZE_STAMP:-20261016T100620Z}"
V5_PINS="${V5_PINS:-probe}"
case "${V5_PINS}" in
  probe)
    # Our own image from the pinned CAA tag (11_build_podvm_image.sh, provenance in
    # results_v5/podvm-image/). Google's pre-built fedora-mkosi-tee-amd-1-11-0 was tried
    # first: it boots under TDX (derived copy with TDX_CAPABLE) but its 2025 forwarder does
    # not talk to CAA 0.21.1. V5_DERIVED_IMAGE=1 re-enables that derived copy in 15.
    PODVM_SOURCE_IMAGE_PROJECT="${PODVM_SOURCE_IMAGE_PROJECT:-it-cloud-gcp-prod-osc-devel}"
    PODVM_SOURCE_IMAGE="${PODVM_SOURCE_IMAGE:-fedora-mkosi-tee-amd-1-11-0}"
    PODVM_IMAGE_PROJECT="${PODVM_IMAGE_PROJECT:-${PROJECT}}"
    # ov<rev> = with our overlay. The pre-overlay image podvm-fedora-tdx-caa-0-21-1 stays for comparison
    PODVM_IMAGE="${PODVM_IMAGE:-podvm-fedora-tdx-caa-${CAA_VERSION//./-}-ov${PODVM_OVERLAY_REV}}"
    ;;
  freeze)
    PODVM_IMAGE_PROJECT="${PODVM_IMAGE_PROJECT:-${PROJECT}}"
    PODVM_IMAGE="${PODVM_IMAGE:-}"
    ;;
  *) die "V5_PINS must be probe or freeze (got ${V5_PINS})" ;;
esac

# --- Cloud credentials for the CAA -------------------------------------------------
# The org policy iam.disableServiceAccountKeyCreation forbids SA keys, and GKE Workload
# Identity does not apply to hostNetwork pods (the CAA DaemonSet is one). The CAA
# therefore runs on Application Default Credentials, that is the node service account. That
# SA is the peerpods SA (compute.instanceAdmin.v1, iam.serviceAccountUser and three logging,
# monitoring and registry read roles, see ensure_peerpods_sa) and the node
# pool carries the cloud-platform scope. Scopes are immutable per pool, so 12 creates
# a dedicated pool and retires GKE's default-pool. No key material anywhere.
PEERPODS_SA_NAME="${PEERPODS_SA_NAME:-peerpods}"
NODE_POOL="${V5_NODE_POOL:-v5-pool}"
# The node version is an input of the freeze: NODE_VERSION, check_node_pin.
source "${_V5_CFG_DIR}/_node_pin.sh"
peerpods_sa() { printf '%s@%s.iam.gserviceaccount.com' "${PEERPODS_SA_NAME}" "${PROJECT}"; }
ensure_peerpods_sa() {
  local sa; sa="$(peerpods_sa)"
  gcloud iam service-accounts describe "${sa}" --project "${PROJECT}" >/dev/null 2>&1 || \
    gcloud iam service-accounts create "${PEERPODS_SA_NAME}" --project "${PROJECT}" --display-name "Peerpods (CAA) node service account"
  local role
  for role in roles/compute.instanceAdmin.v1 roles/iam.serviceAccountUser roles/logging.logWriter roles/monitoring.metricWriter roles/artifactregistry.reader; do
    gcloud projects add-iam-policy-binding "${PROJECT}" --member "serviceAccount:${sa}" --role "${role}" --quiet >/dev/null
  done
}
TRUSTEE_VERSION="${TRUSTEE_VERSION:-}"               # Trustee (AS/RVPS/KBS) release for 16_install_trustee.sh. Empty: the evaluated deployment runs no Trustee

# Network: CAA tunnel port, and a dedicated subnet for the pod VMs. The CAA's `TAGS`
# are Resource Manager tags (key=value), not legacy network tags, so firewalling by
# tag would need secure-tag policies. A dedicated subnet is simpler and just as
# precise: every rule about "the runner TDs" is a rule about this CIDR (A5b).
PEERPOD_TUNNEL_PORT=15150   # agent-protocol-forwarder (tcp), CAA -> pod VM
PEERPOD_VXLAN_PORT=4789     # pod network tunnel (udp), worker <-> pod VM
PODVM_SUBNET="${PODVM_SUBNET:-v5-podvm}"
PODVM_SUBNET_CIDR="${PODVM_SUBNET_CIDR:-192.168.200.0/24}"   # outside 10.128.0.0/9 (auto-mode VPC reservation) and outside GKE pod/service ranges
FW_POLICY="${FW_POLICY:-v5-runner-td-policy}"     # global network firewall policy (egress rules by src range)
# Firewall priorities: GCP's implied egress-allow sits at 65535. Our DENY must beat it
# (65000) and every specific ALLOW must beat the DENY (1000). Each ALLOW rule has its own
# named priority instead of an inline "+1" at three call sites: a config where the derived
# priority silently reached or passed the DENY (say ALLOW=1000, DENY=1001) would otherwise
# turn the second allow into a no-op that nothing checks. 12 validates all of them.
# These four are overridable (the v4.4c config sets none of them, so no value can leak in),
# which is why 12 validates them instead of trusting the file.
FW_PRIO_ALLOW="${FW_PRIO_ALLOW:-1000}"
FW_PRIO_ALLOW_GOOGLEAPI="${FW_PRIO_ALLOW_GOOGLEAPI:-${FW_PRIO_ALLOW}}"          # pod VM -> private.googleapis.com (guest pull)
FW_PRIO_ALLOW_VXLAN="${FW_PRIO_ALLOW_VXLAN:-$((FW_PRIO_ALLOW + 1))}"            # pod VM -> its worker (the tunnelled pod network)
FW_PRIO_DENY="${FW_PRIO_DENY:-65000}"
#: every ALLOW priority in the policy, for validation and for the verification scripts
FW_PRIO_ALLOWS=("${FW_PRIO_ALLOW_GOOGLEAPI}" "${FW_PRIO_ALLOW_VXLAN}")
GOOGLE_API_VIP="199.36.153.8/30"   # private.googleapis.com: the only direct egress a pod VM gets (image pull)

V5_K8S_DIR="${MOCKS_DIR}/k8s/v5"
require_v5_pins() {
  [ -n "${CAA_VERSION}" ] || die "CAA_VERSION not set"
  [ -n "${PODVM_IMAGE}" ] || die "PODVM_IMAGE not set: build one with 11_build_podvm_image.sh or set PODVM_IMAGE"
}

# Nothing in this file may run a command at source time: every script in this directory and
# the offline tests source it.


