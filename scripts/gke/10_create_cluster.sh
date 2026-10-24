#!/usr/bin/env bash
# 10_create_cluster.sh: creates the GKE cluster reproducibly, with NetworkPolicy enforced.
#
# Needs:  gcloud with an active account and project, and the settings from _config.sh.
# Usage:  ./scripts/gke/10_create_cluster.sh
# Result: A zonal cluster with a single small node pool and kubectl pointed at it. Idempotent: if
#         the cluster already exists it only refreshes credentials.
#
# The runner confinement claim (NetworkPolicy) is only meaningful on a CNI that enforces it, so
# the cluster is created with Dataplane V2 (`--enable-dataplane-v2`), which enforces
# NetworkPolicy natively. The whole cluster is disposable and 90_destroy_cluster.sh removes it
# completely.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

say "enabling the required GCP APIs (idempotent)"
gcloud services enable container.googleapis.com artifactregistry.googleapis.com \
  --project "${PROJECT}"

if gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" \
     --project "${PROJECT}" >/dev/null 2>&1; then
  say "cluster ${CLUSTER} already exists, refreshing credentials only"
else
  spot_flag=()
  [ "${USE_SPOT}" = "true" ] && spot_flag=(--spot)
  say "creating ${CLUSTER_SCOPE} cluster ${CLUSTER} (Dataplane V2 NetworkPolicy;"
  say "  ${NUM_NODES}× ${NODE_MACHINE}${USE_SPOT:+, spot=${USE_SPOT}}, ${DISK_SIZE}GB ${DISK_TYPE}, minimal-cost)"
  gcloud container clusters create "${CLUSTER}" \
    --project "${PROJECT}" \
    "${LOCATION_ARGS[@]}" \
    --enable-dataplane-v2 \
    --num-nodes "${NUM_NODES}" \
    --machine-type "${NODE_MACHINE}" \
    ${spot_flag[@]+"${spot_flag[@]}"} \
    --disk-type "${DISK_TYPE}" \
    --disk-size "${DISK_SIZE}" \
    --no-enable-basic-auth \
    --enable-ip-alias \
    --workload-pool "${PROJECT}.svc.id.goog" \
    --no-enable-managed-prometheus \
    --logging=SYSTEM \
    --monitoring=SYSTEM \
    --release-channel regular
fi

say "fetching kubeconfig credentials"
gcloud container clusters get-credentials "${CLUSTER}" \
  "${LOCATION_ARGS[@]}" --project "${PROJECT}"

# The node service account is granted repository-scoped Artifact Registry read access in
# 20_build_push_images.sh (after the repo exists), not here. That keeps the grant to one
# repository instead of the project, and in the step that owns the registry.

say "cluster ready: $(kubectl config current-context)"
