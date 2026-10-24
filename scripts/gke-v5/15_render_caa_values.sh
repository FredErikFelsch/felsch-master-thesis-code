#!/usr/bin/env bash
# 15_render_caa_values.sh: ensures the peer-pods service account and renders the values file for the CAA chart.
#
# Needs:  gcloud, the node pool from 12 running as that service account, the pins from _config.sh,
#         and a pod-VM image (from 11, or V5_DERIVED_IMAGE=1 to derive one from a source image).
# Usage:  ./scripts/gke-v5/15_render_caa_values.sh
# Result: k8s/v5/caa/values-gcp.yaml. Safe to rerun, and nothing secret is written anywhere.
#
# There is no service-account key: the org policy forbids keys, and the CAA runs on the node
# service account instead (see _config.sh, "Cloud credentials").
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project; require_v5_pins
SA="$(peerpods_sa)"

say "service account ${SA} + roles"
ensure_peerpods_sa

say "checking that the node pool ${NODE_POOL} runs as ${SA} with the cloud-platform scope"
pool_sa="$(gcloud container node-pools describe "${NODE_POOL}" --cluster "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(config.serviceAccount)' 2>/dev/null || true)"
[ "${pool_sa}" = "${SA}" ] || die "node pool ${NODE_POOL} is missing or runs as '${pool_sa}'. Run 12_create_cluster_v5.sh first"

if [ "${V5_DERIVED_IMAGE:-0}" = 1 ]; then
  PODVM_IMAGE="${PODVM_SOURCE_IMAGE}-tdx"
  say "pod-VM image ${PODVM_IMAGE} in ${PROJECT}: derived from ${PODVM_SOURCE_IMAGE_PROJECT}/${PODVM_SOURCE_IMAGE} with the confidential guest-OS features"
  if ! gcloud compute images describe "${PODVM_IMAGE}" --project "${PROJECT}" >/dev/null 2>&1; then
    gcloud compute images create "${PODVM_IMAGE}" --project "${PROJECT}" \
      --source-image "${PODVM_SOURCE_IMAGE}" --source-image-project "${PODVM_SOURCE_IMAGE_PROJECT}" \
      --guest-os-features UEFI_COMPATIBLE,TDX_CAPABLE,SEV_SNP_CAPABLE,SEV_CAPABLE,GVNIC \
      --description "CoCo pod-VM probe image: copy of ${PODVM_SOURCE_IMAGE_PROJECT}/${PODVM_SOURCE_IMAGE} + TDX/SNP guest-OS features (V5 derived probe image)"
  fi
fi
say "pod-VM image: ${PODVM_IMAGE_PROJECT}/${PODVM_IMAGE}"
gcloud compute images describe "${PODVM_IMAGE}" --project "${PODVM_IMAGE_PROJECT}" --format='value(status,guestOsFeatures.type)' \
  || die "image ${PODVM_IMAGE} not found in ${PODVM_IMAGE_PROJECT} (11_build_podvm_image.sh)"

say "rendering k8s/v5/caa/values-gcp.yaml (chart: install/charts/peerpods of CAA v${CAA_VERSION})"
NETWORK="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(network)')"
[ -n "${NETWORK}" ] || die "could not determine the cluster network"
mkdir -p "${V5_K8S_DIR}/caa"
cat > "${V5_K8S_DIR}/caa/values-gcp.yaml" <<YAML
# Rendered by 15_render_caa_values.sh. Do not edit, re-run the script instead.
# Credentials: none in here. The CAA uses the node SA (${SA}).
# 14 bypasses the entrypoint's GCP_CREDENTIALS check by starting the binary directly.
provider: gcp
image:
  name: quay.io/confidential-containers/cloud-api-adaptor
  tag: "${CAA_IMAGE_TAG}"
secrets:
  mode: reference
  existingSecretName: ""
webhook:
  enabled: false          # needs cert-manager, our profile sets runtimeClassName itself
resourceCtrl:
  enabled: true           # deletes dangling pod VMs (a stale TD must not survive its pod)
daemonset:
  updateStrategy:         # hostNetwork: a surged pod collides on :8000 with the old one
    maxUnavailable: 1
    maxSurge: 0
providerConfigs:
  gcp:
    GCP_PROJECT_ID: "${PROJECT}"
    GCP_ZONE: "${ZONE}"
    GCP_NETWORK: "global/networks/${NETWORK}"
    GCP_SUBNETWORK: "regions/${REGION}/subnetworks/${PODVM_SUBNET}"
    GCP_MACHINE_TYPE: "${PODVM_MACHINE}"
    GCP_DISK_TYPE: "${PODVM_DISK_TYPE}"
    GCP_CONFIDENTIAL_TYPE: "${PODVM_CONFIDENTIAL_TYPE}"
    DISABLECVM: "false"
    USE_PUBLIC_IP: "false"
    PODVM_IMAGE_NAME: "projects/${PODVM_IMAGE_PROJECT}/global/images/${PODVM_IMAGE}"
    ROOT_VOLUME_SIZE: "20"
    FORWARDER_PORT: "${PEERPOD_TUNNEL_PORT}"
    VXLAN_PORT: "${PEERPOD_VXLAN_PORT}"
    PEERPODS_LIMIT_PER_NODE: "10"
YAML
cat "${V5_K8S_DIR}/caa/values-gcp.yaml"
say "values rendered (keys follow providers/gcp.yaml of the pinned chart)"
