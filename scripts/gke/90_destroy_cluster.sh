#!/usr/bin/env bash
# 90_destroy_cluster.sh: destroys the evaluation environment completely.
#
# Needs:  gcloud with an active account and project.
# Usage:  ./scripts/gke/90_destroy_cluster.sh [--purge-images]
# Result: The GKE cluster deleted, and the resolved image digests archived under
#         results_v4_k8s/environment/. Idempotent: a missing cluster is not an error.
#
# The evaluation environment is created reproducibly from version-controlled scripts and can be
# destroyed completely after an experiment. This deletes the GKE cluster
# (and with it every namespace, PVC, Secret and Job, so all in-cluster authority material is
# gone). The Artifact Registry images are left by default (rebuilding is slow). Pass
# --purge-images to remove them too.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

PURGE_IMAGES=0
[ "${1:-}" = "--purge-images" ] && PURGE_IMAGES=1

# Archive the resolved image digest and runner hash before anything is torn down:
# these describe the executed artefact (evidence for the evaluation), not the cluster,
# and stay valid after the cluster is gone.
if [ -f "${DIGEST_FILE}" ]; then
  archive_dir="${MOCKS_DIR}/results_v4_k8s/environment"
  mkdir -p "${archive_dir}"
  cp "${DIGEST_FILE}" "${archive_dir}/image-digests.env"
  say "archived image digests to results_v4_k8s/environment/image-digests.env"
fi

if gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" \
     --project "${PROJECT}" >/dev/null 2>&1; then
  say "deleting cluster ${CLUSTER} (this removes all namespaces, PVCs and secrets)"
  gcloud container clusters delete "${CLUSTER}" "${LOCATION_ARGS[@]}" \
    --project "${PROJECT}" --quiet
else
  say "cluster ${CLUSTER} not found, nothing to delete"
fi

if [ "${PURGE_IMAGES}" -eq 1 ]; then
  say "purging Artifact Registry images under ${IMAGE_BASE}/${IMAGE_NAME}"
  gcloud artifacts docker images delete "${IMAGE_BASE}/${IMAGE_NAME}" \
    --project "${PROJECT}" --delete-tags --quiet || true
fi

# Drop the working copy only after it is archived. The archive is the evidence.
rm -f "${DIGEST_FILE}"
say "environment destroyed (image-digest evidence preserved under results_v4_k8s/environment/)."
