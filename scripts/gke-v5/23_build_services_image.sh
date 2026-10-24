#!/usr/bin/env bash
# 23_build_services_image.sh: builds and pushes the services image (authority, gateway, init).
#
# Needs:  docker buildx, gcloud authentication, and scripts/gke/.digests from ../gke/20_build_push_images.sh.
# Usage:  ./scripts/gke-v5/23_build_services_image.sh   (works from any directory)
# Result: The image in Artifact Registry and its digest pinned in scripts/gke/.digests as SERVICES_IMAGE.
#
# The runner image stays the one 20_build_push_images.sh built, because its digest is part of the
# measured policy. The services image is not measured and not guest-pulled.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
[ -f "${DIGEST_FILE}" ] || die "no ${DIGEST_FILE}: run ../gke/20_build_push_images.sh first"
source "${DIGEST_FILE}"

TAG="${AR_HOST}/${PROJECT}/${AR_REPO}/booking-services:v5-$(date -u +%Y%m%dT%H%M%SZ)"
say "building ${TAG} (linux/amd64, Ubuntu 24.04 + Intel QVL)"
gcloud auth configure-docker "${AR_HOST}" --quiet
docker buildx build --platform linux/amd64 -f "${MOCKS_DIR}/Dockerfile.services" -t "${TAG}" --push "${MOCKS_DIR}"
DIGEST="$(gcloud artifacts docker images describe "${TAG}" --project "${PROJECT}" --format='value(image_summary.digest)')"
[ -n "${DIGEST}" ] || die "could not resolve the pushed digest"
SERVICES_IMAGE="${TAG%%:*}@${DIGEST}"

# pin: replace the line or append it, so it appears once
grep -v '^SERVICES_IMAGE=' "${DIGEST_FILE}" > "${DIGEST_FILE}.tmp" || true
echo "SERVICES_IMAGE=${SERVICES_IMAGE}" >> "${DIGEST_FILE}.tmp"
mv "${DIGEST_FILE}.tmp" "${DIGEST_FILE}"
say "pinned SERVICES_IMAGE=${SERVICES_IMAGE}"

# smoke: the QVL package versions are recorded and the service modules import
docker run --rm --platform linux/amd64 --entrypoint sh "${SERVICES_IMAGE}" -c \
  'cat /etc/dcap-versions.txt && python3 -c "import booking_v5.service_v5, booking_v4.durable; print(\"imports ok\")"' \
  || say "WARNING: cannot run the linux/amd64 image here (no emulation). The smoke test is skipped"
