# shellcheck shell=bash
# _node_pin.sh: the node version the frozen policy was generated against, and the checks that enforce it.
#
# Needs:  gcloud and kubectl, and PROJECT, CLUSTER, LOCATION_ARGS, ZONE and die from _config.sh.
# Usage:  Sourced by _config.sh. 12 calls require_node_version_offered, 30 calls check_node_pin.
#         V5_NODE_VERSION overrides the pin.
# Result: NODE_VERSION and the functions node_version_offered, require_node_version_offered,
#         pool_node_version and check_node_pin. Nothing is created or run on sourcing.
#
# Why it is pinned: the policy in the TD (policy.rego, measured into RTMR3 through init-data)
# checks the OCI spec the node's kubelet and containerd produce. The sandbox sysctls are an
# exact allow-list from k8s/v5/genpolicy-settings.json. A newer node version sends one more
# or one other sysctl, the TD refuses CreateContainer and the warm pool stays at 0/N. That is
# fail-closed and intended (the host is untrusted), so the node version is an input of the
# freeze. A wanted upgrade is a new freeze line (13 genpolicy, then 98a), not a silent drift.
#
# GKE removes old patch versions from a channel after some weeks. The pin then cannot be
# created any more, and 12 says so instead of creating a pool the policy will refuse.

# Node 1.35.8-gke.1036000 sends OCI 1.2.1 and GKE no longer offers it. 1.35.8-gke.1225000
# sends OCI 1.3.0, so its policy is generated with GENPOLICY_OCI_VERSION=1.3.0 (13) and needs
# its own freeze line (98a).
NODE_VERSION="${V5_NODE_VERSION:-1.35.8-gke.1225000}"

node_version_offered() {   # is NODE_VERSION still a valid node version in this zone?
  # The cluster is on a release channel (12: --release-channel regular). A channel's versions
  # are listed under channels[].validVersions, not under the top-level validNodeVersions,
  # which is the list for clusters without a channel. A version can appear only in the channel
  # list, and a check of the top-level list alone would refuse a version the cluster was just
  # created with. Both lists are consulted.
  gcloud container get-server-config "${LOCATION_ARGS[@]}" --project "${PROJECT}" \
      --format=json 2>/dev/null | python3 -c '
import json, sys
want = sys.argv[1]
cfg = json.load(sys.stdin)
offered = set(cfg.get("validNodeVersions", []))
for ch in cfg.get("channels", []):
    offered.update(ch.get("validVersions", []))
sys.exit(0 if want in offered else 1)
' "${NODE_VERSION}"
}

require_node_version_offered() {
  node_version_offered || die "node version ${NODE_VERSION} is no longer offered in ${ZONE}.
    The frozen policy was generated against it. Either pin an offered version that produces
    the same sandbox spec (V5_NODE_VERSION=..., then check with 18) or cut a new freeze line
    for a new version (13 genpolicy, then 98a)."
}

pool_node_version() {      # the version a node pool runs, empty if it does not exist
  gcloud container node-pools describe "$1" --cluster "${CLUSTER}" "${LOCATION_ARGS[@]}" \
      --project "${PROJECT}" --format='value(version)' 2>/dev/null
}

check_node_pin() {         # every node runs NODE_VERSION (kubelet reports it with a leading v)
  # All nodes, not only NODE_POOL: an old pool left beside a pinned one would still receive
  # the CAA DaemonSet and runner pods, and a check scoped to one pool name would miss it.
  local rows bad
  rows="$(kubectl get nodes \
      -o jsonpath='{range .items[*]}{.metadata.name} {.status.nodeInfo.kubeletVersion} {.status.nodeInfo.containerRuntimeVersion}{"\n"}{end}')"
  [ -n "${rows}" ] || die "no nodes in the cluster"
  bad="$(printf '%s\n' "${rows}" | awk -v want="v${NODE_VERSION}" 'NF && $2 != want')"
  if [ -n "${bad}" ]; then
    printf '%s\n' "${bad}" | sed 's/^/    /'
    die "node version drift: every node must run ${NODE_VERSION} (the frozen policy's node).
    The TD would refuse CreateContainer. Create a pinned pool (V5_NODE_POOL=<new name> 12),
    delete the drifted pool, then 14."
  fi
  printf '%s\n' "${rows}" | sed "s/^/  node pinned ${NODE_VERSION}: /"
}
