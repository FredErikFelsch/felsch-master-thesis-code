#!/usr/bin/env bash
# 20_build_push_images.sh: builds and pushes the one code image and records its digest.
#
# Needs:  docker buildx, gcloud with an active account and project, and Dockerfile.k8s.
# Usage:  ./scripts/gke/20_build_push_images.sh
# Result: The image in Artifact Registry and scripts/gke/.digests (gitignored) with the image
#         digest, the runner hashes and the interpreter path. 30_deploy.sh consumes that file.
#
# Reproducibility: the deployment pins the image by digest (image@sha256:...), not by a mutable
# tag, so the bytes that ran are recoverable. No secret enters the image or the repository.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

say "ensuring Artifact Registry repo ${AR_REPO} exists in ${AR_LOCATION}"
if ! gcloud artifacts repositories describe "${AR_REPO}" \
      --location "${AR_LOCATION}" --project "${PROJECT}" >/dev/null 2>&1; then
  gcloud artifacts repositories create "${AR_REPO}" \
    --repository-format docker --location "${AR_LOCATION}" \
    --project "${PROJECT}" --description "thesis v4.4c images"
fi

# Grant the GKE node service account repository-scoped read access, so the nodes can pull
# this image. On newer or auto-created projects the default Compute Engine SA no longer has
# Artifact Registry access, and image pulls fail with 403 Forbidden. The grant is scoped to
# this repository, not the project, and lives here because this step owns the registry. It
# uses IAM, not an imagePullSecret, so no registry credentials enter Kubernetes. Idempotent.
say "granting the GKE node service account read-only access to Artifact Registry"
PROJECT_NUMBER="$(gcloud projects describe "${PROJECT}" --format='value(projectNumber)')"
NODE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
gcloud artifacts repositories add-iam-policy-binding "${AR_REPO}" \
  --location "${AR_LOCATION}" --project "${PROJECT}" \
  --member="serviceAccount:${NODE_SA}" \
  --role="roles/artifactregistry.reader" --quiet >/dev/null
say "verifying the Artifact Registry reader binding"
gcloud artifacts repositories get-iam-policy "${AR_REPO}" \
  --location "${AR_LOCATION}" --project "${PROJECT}" --format=yaml \
  | grep -F "${NODE_SA}" >/dev/null \
  || die "GKE node service account ${NODE_SA} has no Artifact Registry read access"
say "  Artifact Registry pull identity: ${NODE_SA}"

say "configuring docker auth for ${AR_HOST} (uses the existing gcloud login)"
gcloud auth configure-docker "${AR_HOST}" --quiet

say "building + pushing ${IMAGE_REF} for linux/amd64 (GKE e2 nodes are x86-64)"
# Explicit --platform so a build on an ARM machine (Apple Silicon) does not push an
# arm64 image that the x86-64 nodes cannot exec. buildx pushes in the same step.
docker buildx build --platform linux/amd64 \
  -f "${MOCKS_DIR}/Dockerfile.k8s" -t "${IMAGE_REF}" --push "${MOCKS_DIR}"

# Resolve the immutable digest and pin everything to it.
DIGEST="$(gcloud artifacts docker images describe "${IMAGE_REF}" \
            --project "${PROJECT}" --format='value(image_summary.digest)')"
[ -n "${DIGEST}" ] || die "could not resolve pushed image digest"
IMAGE_PINNED="${IMAGE_BASE}/${IMAGE_NAME}@${DIGEST}"

# The interpreter path inside the image, read out of the image itself. python:3.11-slim puts
# it at /usr/local/bin/python3 and has no /usr/bin/python3, so a manifest that sets an explicit
# command must use this value. Guessing it costs a full TD boot and guest pull to find out,
# and the failure arrives as "CreateContainer: the file ... was not found" inside the guest.
say "resolving the interpreter path and checking booking_v5 inside the image"
# Running an amd64 image on an arm64 Mac needs working emulation. If it is unavailable the
# image is still fine, it just cannot be inspected here, and 18 falls back to a PATH
# lookup. So distinguish "cannot run the image at all" (warn, continue) from "ran it and the
# module is missing" (fail, because that would surface only inside the guest, after a full TD
# boot and pull).
RUNNER_PYTHON=""
if docker run --rm --platform linux/amd64 --entrypoint true "${IMAGE_REF}" >/dev/null 2>&1; then
  RUNNER_PYTHON="$(docker run --rm --platform linux/amd64 --entrypoint sh "${IMAGE_REF}" \
                     -c 'command -v python3' 2>/dev/null | tr -d '\r')"
  [ -n "${RUNNER_PYTHON}" ] || die "no python3 in ${IMAGE_REF} (the image is unusable for every entrypoint)"
  docker run --rm --platform linux/amd64 --entrypoint "${RUNNER_PYTHON}" "${IMAGE_REF}" \
    -c 'import booking_v4.runner_process, booking_v5.probe_bind, booking_v5.runner_main' >/dev/null 2>&1 \
    || die "booking_v4.runner_process, booking_v5.probe_bind or booking_v5.runner_main does not import in ${IMAGE_REF} (is booking_v5 COPYed in Dockerfile.k8s?)"
  say "  interpreter: ${RUNNER_PYTHON}, booking_v4 and booking_v5 import"
else
  say "  WARNING: cannot run the linux/amd64 image on this machine (no emulation?). RUNNER_PYTHON stays unset,"
  say "           18 will fall back to a PATH lookup. Verify the command by hand if the probe fails in CreateContainer."
fi

# Two content hashes. RUNNER_SOURCE_SHA covers the runner code this image contains, so 99 can
# refuse to measure a guest that is older than the code (see scripts/gke/_runner_source_hash.py).
# RUNNER_SHA is the hash of runner_process.py. It is pinned in the freeze record, so each
# backend's record can be checked against the same runner bytes.
RUNNER_SOURCE_SHA="$(python3 "$(dirname "${BASH_SOURCE[0]}")/_runner_source_hash.py" "${MOCKS_DIR}")"
[ -n "${RUNNER_SOURCE_SHA}" ] || die "could not hash the runner source"

RUNNER_SHA="$(python3 - "$MOCKS_DIR" <<'PY'
import hashlib, sys, os
p = os.path.join(sys.argv[1], "booking_v4", "runner_process.py")
print(hashlib.sha256(open(p, "rb").read()).hexdigest())
PY
)"

umask 077
{
  echo "# V4.4c resolved digests (gitignored, regenerated by 20_build_push_images.sh)"
  echo "CONTROLLER_IMAGE=${IMAGE_PINNED}"
  echo "RUNNER_IMAGE=${IMAGE_PINNED}"
  echo "RUNNER_PROCESS_SHA256=${RUNNER_SHA}"
  echo "RUNNER_SOURCE_SHA256=${RUNNER_SOURCE_SHA}"
  echo "RUNNER_PYTHON=${RUNNER_PYTHON}"
} > "${DIGEST_FILE}"

say "pinned image: ${IMAGE_PINNED}"
say "runner_process.py sha256: ${RUNNER_SHA}"
say "runner source sha256: ${RUNNER_SOURCE_SHA}"
say "interpreter in the image: ${RUNNER_PYTHON}"
say "wrote ${DIGEST_FILE}"
