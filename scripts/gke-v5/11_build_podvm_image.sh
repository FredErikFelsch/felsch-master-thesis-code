#!/usr/bin/env bash
# 11_build_podvm_image.sh: builds our pod-VM image from the pinned CAA commit and registers it as a GCE image.
#
# Needs:  gcloud and gsutil, a project, and the pins from _config.sh (CAA_VERSION, CAA_COMMIT,
#         PODVM_PATCH_DIR, the overlay revision). The peer-pods service account runs the builder VM.
# Usage:  ./11_build_podvm_image.sh                  build and register ${PODVM_IMAGE}
#         KEEP_BUILDER=1 ./11_build_podvm_image.sh   leave the builder VM for inspection
# Result: A GCE image with the confidential guest-OS features, and a provenance file under
#         results_v5/podvm-image/. The builder VM is deleted unless KEEP_BUILDER=1. If the image
#         already exists the script exits 0 without building. To rebuild, use a new PODVM_IMAGE_BUILD.
#
# The image is built with mkosi (Fedora, TEE_PLATFORM=tdx) on a temporary GCE builder VM. It is a
# function of the pinned CAA commit, the overlay and the patches, which gives reproducible reference values
# instead of a third-party image. No secrets are involved. The builder uses the peer-pods service account.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
: "${CAA_VERSION:?}"
OVERLAY_DIR="${V5_K8S_DIR}/podvm-overlay"
# The overlay (initdata-measure, agent ordering, A5c) is part of what the image measures, so
# its hash is part of the image identity: name = CAA tag + overlay revision, provenance = both hashes.
OVERLAY_SHA256="$(cd "${OVERLAY_DIR}" && find . -type f ! -name README.md -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -c1-64)"
# The CAA source patches (the bounded provider retry in process-user-data) are part of
# the image just as much as the overlay is, so they get the same treatment: one hash over all
# of them, refused if the directory is empty, and both hashes land in the provenance.
: "${CAA_COMMIT:?CAA_COMMIT not pinned in _config.sh}"
PATCH_DIR="${PODVM_PATCH_DIR:?PODVM_PATCH_DIR not set in _config.sh}"
[ -d "${PATCH_DIR}" ] || die "no patch directory at ${PATCH_DIR}"
PATCH_LIST="$(cd "${PATCH_DIR}" && ls -1 *.patch 2>/dev/null | sort)"
[ -n "${PATCH_LIST}" ] || die "no *.patch in ${PATCH_DIR}: the image is defined by its patches, so an empty directory is a mistake, not a configuration"
PATCH_SHA256="$(cd "${PATCH_DIR}" && ls -1 *.patch | sort | xargs sha256sum | sha256sum | cut -c1-64)"
say "CAA ${CAA_VERSION} pinned at ${CAA_COMMIT}, patches $(printf '%s ' ${PATCH_LIST})(${PATCH_SHA256:0:12})"
IMAGE="${PODVM_IMAGE_BUILD:-podvm-fedora-tdx-caa-${CAA_VERSION//./-}-ov${PODVM_OVERLAY_REV}}"
# The hardening is on by default. An unhardened image needs V5_ALLOW_UNHARDENED=1, so a
# forgotten variable cannot produce one.
if [ "${V5_HARDEN_A5C}" != "noop" ] || [ "${V5_HARDEN_B1}" != "1" ]; then
  [ "${V5_ALLOW_UNHARDENED:-0}" = "1" ] \
    || die "refusing to build ${IMAGE} with V5_HARDEN_A5C=${V5_HARDEN_A5C} V5_HARDEN_B1=${V5_HARDEN_B1} (expected noop/1). Set V5_ALLOW_UNHARDENED=1 to do it knowingly"
  say "WARNING: building ${IMAGE} without the hardening (V5_ALLOW_UNHARDENED=1)"
fi
say "hardening: V5_HARDEN_A5C=${V5_HARDEN_A5C} V5_HARDEN_B1=${V5_HARDEN_B1}"
BUILDER="${BUILDER_NAME:-v5-podvm-builder}"
BUILDER_MACHINE="${BUILDER_MACHINE:-e2-standard-8}"
BUCKET="${PODVM_BUCKET:-${PROJECT}-v5-podvm}"
OUT="${MOCKS_DIR}/results_v5/podvm-image"; mkdir -p "${OUT}"
SA="$(peerpods_sa)"

if gcloud compute images describe "${IMAGE}" --project "${PROJECT}" >/dev/null 2>&1; then
  say "image ${IMAGE} already exists, nothing to build (set PODVM_IMAGE_BUILD for a new name)"
  gcloud compute images describe "${IMAGE}" --project "${PROJECT}" --format='value(status,guestOsFeatures.type,description)'
  exit 0
fi

say "bucket gs://${BUCKET} (raw image transfer)"
gsutil ls -b "gs://${BUCKET}" >/dev/null 2>&1 || gsutil mb -p "${PROJECT}" -l "${REGION}" "gs://${BUCKET}"
gsutil iam ch "serviceAccount:${SA}:objectAdmin" "gs://${BUCKET}" >/dev/null

say "builder VM ${BUILDER} (${BUILDER_MACHINE}, Ubuntu 24.04, SA ${SA})"
if ! gcloud compute instances describe "${BUILDER}" --zone "${ZONE}" --project "${PROJECT}" >/dev/null 2>&1; then
  gcloud compute instances create "${BUILDER}" --zone "${ZONE}" --project "${PROJECT}" \
    --machine-type "${BUILDER_MACHINE}" --image-family ubuntu-2404-lts-amd64 --image-project ubuntu-os-cloud \
    --boot-disk-size 100GB --boot-disk-type pd-balanced \
    --service-account "${SA}" --scopes cloud-platform \
    --labels purpose=v5-podvm-builder
  sleep 30
fi

# The remote build script. Everything the image contains is a function of the pinned CAA commit,
# the patches and the overlay.
cat > "${OUT}/remote-build.sh" <<REMOTE
#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -q
sudo apt-get install -y -q docker.io docker-buildx qemu-utils make git jq
sudo usermod -aG docker "\$USER" || true
sudo systemctl enable --now docker
# yq v4 (mikefarah), the version and checksum the CAA Makefile.defaults pins
if ! command -v yq >/dev/null; then
  curl -fsSL -o /tmp/yq https://github.com/mikefarah/yq/releases/download/v4.35.1/yq_linux_amd64
  echo "bd695a6513f1196aeda17b174a15e9c351843fb1cef5f9be0af170f2dd744f08  /tmp/yq" | sha256sum -c -
  sudo install -m 0755 /tmp/yq /usr/local/bin/yq
fi
WORK=\$HOME/caa
[ -d "\$WORK" ] || git clone -q --depth 1 --branch "v${CAA_VERSION}" https://github.com/confidential-containers/cloud-api-adaptor.git "\$WORK"
git -C "\$WORK" rev-parse HEAD > \$HOME/caa-commit.txt
# A tag can be moved. The image is a reference value, so the source is pinned to a commit and
# a clone that lands anywhere else stops the build before anything is compiled.
have_commit="\$(cat \$HOME/caa-commit.txt)"
if [ "\$have_commit" != "${CAA_COMMIT}" ]; then
  echo "CAA clone is at \$have_commit, expected ${CAA_COMMIT} (tag v${CAA_VERSION} moved?)" >&2
  exit 7
fi
# --- V5 source patches, applied before make binaries ---------------------------------------
# The patch repairs the producer of /run/peerpod/initdata. Upstream discarded the newProvider
# error, skipped the cloud config and still reported success, so the init-data was missing in
# 3 of 13 boots while systemd recorded a clean completion. \`--check\` runs first, so a patch that
# does not apply stops the build instead of being skipped.
mkdir -p \$HOME/podvm-patches
tar -xzf \$HOME/podvm-patches.tar.gz -C \$HOME/podvm-patches
patched=0
for patch in \$(ls -1 \$HOME/podvm-patches/*.patch | sort); do
  git -C "\$WORK" apply --check -p1 "\$patch" || { echo "patch does not apply: \$patch" >&2; exit 8; }
  git -C "\$WORK" apply -p1 "\$patch" || { echo "patch failed to apply: \$patch" >&2; exit 8; }
  echo "applied \$(basename \$patch) \$(sha256sum \$patch | cut -d' ' -f1)" | tee -a \$HOME/patches-applied.txt
  patched=\$((patched + 1))
done
[ "\$patched" -gt 0 ] || { echo "no patches applied: the image would not match its provenance" >&2; exit 8; }
# The postcondition, on the built tree rather than on the patch: the repaired producer must be
# in the source that is about to be compiled.
grep -q "newProviderWithRetry" "\$WORK/src/cloud-api-adaptor/pkg/userdata/provision.go" \
  || { echo "provision.go does not carry the bounded provider retry after patching" >&2; exit 8; }
cd "\$WORK/src/cloud-api-adaptor/podvm-mkosi"
sudo -E env TEE_PLATFORM=tdx PODVM_DISTRO=fedora make binaries
# --- V5 overlay (initdata-measure into RTMR3, agent ordering, A5c, B1) on top of CAA's podvm/files ---
TREE=resources/binaries-tree
# apply-hardening.sh is a build-time script, not image content: extract it to its own
# directory (never into \$TREE) so it cannot end up shipped inside the pod-VM image.
mkdir -p \$HOME/podvm-overlay-src
tar -xzf \$HOME/podvm-overlay.tar.gz -C \$HOME/podvm-overlay-src
sudo tar -xzf \$HOME/podvm-overlay.tar.gz -C "\$TREE" --exclude README.md --exclude apply-hardening.sh
sudo chmod 0755 "\$TREE/usr/local/bin/initdata-measure"
# Build-time hardening of the rootfs, with its own postconditions (apply-hardening.sh):
#   A5c  with V5_HARDEN_A5C=noop (the default) replace the body of setup-nat-for-imds.sh with a
#        no-op, so the workload-facing IMDS path is never set up and the unit graph stays as
#        CAA ships it. Masking the unit (V5_HARDEN_A5C=1) did not boot.
#   B1   remove CAA 0.21.1's run-kata-containers.mount, whose source directory does not
#        exist in the built image. The failed mount keeps kata-agent from starting, so
#        agent.sock never appears, the forwarder never listens on :15150 and the
#        sandbox boot dies as FailedCreatePodSandBox/DeadlineExceeded. That can look
#        like a TDX, firewall or A5c problem.
# Its output is recorded in the image provenance: what was masked and what was removed is
# part of the image identity, not just of the build log.
chmod +x \$HOME/podvm-overlay-src/apply-hardening.sh
sudo -E env V5_HARDEN_A5C="${V5_HARDEN_A5C:-0}" V5_HARDEN_B1="${V5_HARDEN_B1:-0}" \\
  \$HOME/podvm-overlay-src/apply-hardening.sh "\$TREE" | tee \$HOME/hardening.txt
sudo find "\$TREE/etc/systemd/system" "\$TREE/usr/lib/systemd/system-preset" -maxdepth 2 \\
  \( -name '*v5*' -o -name 'initdata-measure*' \) | sort > \$HOME/overlay-applied.txt
# Gates on the tree that is about to be sealed into the image, independent of the hardening
# script's own postconditions. Glob, not the exact name: CAA ships the file as
# run-kata\\x2dcontainers.mount.
# Only gate on B1 when B1 was actually requested. An unconditional gate would demand the
# success of a step the build skipped.
if [ "\${V5_HARDEN_B1:-0}" = "1" ]; then
  [ -z "\$(sudo find "\$TREE/etc/systemd" "\$TREE/usr/lib/systemd" -name 'run-kata*containers.mount' 2>/dev/null)" ] \
    || { echo "ERROR: run-kata-containers.mount survived the hardening step" >&2; exit 1; }
fi
# A .wants/ entry that stopped being a symlink is a sign that a sed followed a symlink and
# rewrote the target in place (which removes the agent-protocol-forwarder). Such a tree is not
# shipped, whatever the flags say. (CAA itself ships copies in podvm/files and systemd accepts
# them. The gate checks that our hardening step has not mangled anything.)
broken="\$(find "\$TREE/etc/systemd" \( -path '*.wants/*' -o -path '*.requires/*' \) -type f 2>/dev/null || true)"
[ -z "\${broken}" ] || { echo "ERROR: enablement entries are regular files: \${broken}" >&2; exit 1; }
# Every V5 image must carry the script, the unit and its enablement.
# The enablement is shipped as a symlink in the overlay and not left to \`systemctl preset\`.
# The root is squashfs under dm-verity, so /etc is read-only at boot and the preset run says
# so ("Failed to populate /etc with preset unit settings: Read-only file system"). Without the
# symlink nothing pulls the unit in, RTMR3 stays zero and the P2 check still passes. This gate
# keeps such a silently unmeasured TD from being built.
[ -x "\$TREE/usr/local/bin/initdata-measure" ] || { echo "ERROR: initdata-measure missing from the tree" >&2; exit 1; }
[ -f "\$TREE/etc/systemd/system/initdata-measure.service" ] || { echo "ERROR: initdata-measure.service missing from the tree" >&2; exit 1; }
[ -L "\$TREE/etc/systemd/system/multi-user.target.wants/initdata-measure.service" ] \\
  || { echo "ERROR: initdata-measure.service is not enabled (no multi-user.target.wants symlink)" >&2; exit 1; }
# The symlink above does not survive \`make image\` on its own: a preset-all with Fedora's
# \`disable *\` removes it (see podvm-overlay/README.md). Three anchors must be in the tree.
[ -f "\$TREE/usr/lib/systemd/system-preset/20-v5.preset" ] || { echo "ERROR: 20-v5.preset missing from the tree" >&2; exit 1; }
for a in attestation-agent kata-agent; do
  [ -f "\$TREE/etc/systemd/system/\$a.service.d/10-v5-measure.conf" ] || { echo "ERROR: \$a drop-in missing from the tree" >&2; exit 1; }
done
sudo -E env TEE_PLATFORM=tdx PODVM_DISTRO=fedora make image
cd build
sha256sum system.raw | tee \$HOME/system.raw.sha256
# Gate on the built image, not only on the tree: mount the squashfs root (partition 2, dm-verity
# hash is partition 3) and check what the pod VM will actually boot. An image can pass every
# tree gate and still ship without the enablement.
LOOP="\$(sudo losetup -fP --show system.raw)"
sudo mkdir -p /mnt/pv && sudo mount -o ro -t squashfs "\${LOOP}p2" /mnt/pv
img_ok=1
[ -x /mnt/pv/usr/local/bin/initdata-measure ]                                       || { echo "ERROR(image): script missing" >&2; img_ok=0; }
[ -f /mnt/pv/etc/systemd/system/initdata-measure.service ]                          || { echo "ERROR(image): unit missing" >&2; img_ok=0; }
[ -e /mnt/pv/etc/systemd/system/multi-user.target.wants/initdata-measure.service ]  || { echo "ERROR(image): unit not enabled (wants symlink gone)" >&2; img_ok=0; }
[ -f /mnt/pv/usr/lib/systemd/system-preset/20-v5.preset ]                           || { echo "ERROR(image): 20-v5.preset missing" >&2; img_ok=0; }
for a in attestation-agent kata-agent; do
  [ -f "/mnt/pv/etc/systemd/system/\$a.service.d/10-v5-measure.conf" ]            || { echo "ERROR(image): \$a drop-in missing" >&2; img_ok=0; }
done
# A5c as a no-op script. Gate on the built image: the body is ours and the unit is not masked.
if [ "\${V5_HARDEN_A5C:-0}" = "noop" ]; then
  sudo grep -q "V5 A5c" /mnt/pv/usr/local/bin/setup-nat-for-imds.sh                  || { echo "ERROR(image): setup-nat-for-imds.sh is not the V5 no-op" >&2; img_ok=0; }
  [ ! -L /mnt/pv/etc/systemd/system/setup-nat-for-imds.service ] || [ "\$(readlink /mnt/pv/etc/systemd/system/setup-nat-for-imds.service)" != "/dev/null" ] \\
                                                                                        || { echo "ERROR(image): setup-nat-for-imds.service is masked in noop mode" >&2; img_ok=0; }
fi
{ echo "image multi-user.target.wants:"; sudo ls -la /mnt/pv/etc/systemd/system/multi-user.target.wants/; } > \$HOME/image-wants.txt
sudo umount /mnt/pv; sudo losetup -d "\$LOOP"
[ "\$img_ok" = 1 ] || { echo "ERROR: the built image does not carry the V5 measurement, not uploading" >&2; exit 1; }
sudo mv system.raw disk.raw
sudo tar --format=oldgnu -Sczf podvm.tar.gz disk.raw
gsutil cp podvm.tar.gz "gs://${BUCKET}/${IMAGE}.tar.gz"
echo REMOTE_BUILD_OK
REMOTE

say "building on ${BUILDER} (30 to 60 min, log: ${OUT}/remote-build-${IMAGE}.log)"
# A fresh VM needs a minute until the guest agent has installed the ssh key.
for i in $(seq 1 12); do
  gcloud compute scp "${OUT}/remote-build.sh" "${BUILDER}:~/remote-build.sh" --zone "${ZONE}" --project "${PROJECT}" --quiet 2>/dev/null && break
  [ "${i}" -lt 12 ] || die "cannot ssh into ${BUILDER} after 3 min"
  sleep 15
done
# COPYFILE_DISABLE: bsdtar on macOS would add ._* resource forks to the overlay (for example
# etc/systemd/system/kata-agent.service.d/._10-v5-measure.conf). They are harmless to systemd
# but not ours, so they must not end up in the image.
COPYFILE_DISABLE=1 tar -czf "${OUT}/podvm-overlay-${OVERLAY_SHA256:0:12}.tar.gz" -C "${OVERLAY_DIR}" .
gcloud compute scp "${OUT}/podvm-overlay-${OVERLAY_SHA256:0:12}.tar.gz" "${BUILDER}:~/podvm-overlay.tar.gz" --zone "${ZONE}" --project "${PROJECT}" --quiet
COPYFILE_DISABLE=1 tar -czf "${OUT}/podvm-patches-${PATCH_SHA256:0:12}.tar.gz" -C "${PATCH_DIR}" .
gcloud compute scp "${OUT}/podvm-patches-${PATCH_SHA256:0:12}.tar.gz" "${BUILDER}:~/podvm-patches.tar.gz" --zone "${ZONE}" --project "${PROJECT}" --quiet
# `set -o pipefail` would abort here, silently, with the remote's exit code, before the
# grep below ever runs. When the hardening step fails, the build then stops after two lines of
# output and looks as if it had simply finished. Capture the status instead and say what
# happened, including where the remote log stops.
rc=0
gcloud compute ssh "${BUILDER}" --zone "${ZONE}" --project "${PROJECT}" --quiet \
  --command "bash ~/remote-build.sh" 2>&1 | tee "${OUT}/remote-build-${IMAGE}.log" || rc=$?
if [ "${rc}" != 0 ]; then
  say "the remote build exited ${rc}, its last lines were:"
  tail -15 "${OUT}/remote-build-${IMAGE}.log" >&2
fi
grep -q REMOTE_BUILD_OK "${OUT}/remote-build-${IMAGE}.log" \
  || die "remote build did not finish (exit ${rc}). It stopped where the log ends: ${OUT}/remote-build-${IMAGE}.log"
gcloud compute ssh "${BUILDER}" --zone "${ZONE}" --project "${PROJECT}" --quiet \
  --command "cat ~/system.raw.sha256 ~/caa-commit.txt ~/patches-applied.txt ~/overlay-applied.txt ~/hardening.txt ~/image-wants.txt" > "${OUT}/${IMAGE}.provenance.txt"
echo "overlay_sha256=${OVERLAY_SHA256} overlay_rev=${PODVM_OVERLAY_REV}" >> "${OUT}/${IMAGE}.provenance.txt"
# The provenance names everything the image is built from: the pinned upstream commit, these
# patches and the overlay hash above.
echo "caa_commit=${CAA_COMMIT} patch_sha256=${PATCH_SHA256} patches=$(printf '%s,' ${PATCH_LIST})" >> "${OUT}/${IMAGE}.provenance.txt"

say "registering GCE image ${IMAGE} (TDX_CAPABLE, SEV_SNP_CAPABLE, UEFI_COMPATIBLE, GVNIC)"
gcloud compute images create "${IMAGE}" --project "${PROJECT}" \
  --source-uri "gs://${BUCKET}/${IMAGE}.tar.gz" \
  --guest-os-features UEFI_COMPATIBLE,TDX_CAPABLE,SEV_SNP_CAPABLE,GVNIC \
  --description "CoCo pod-VM image: cloud-api-adaptor v${CAA_VERSION} (mkosi fedora, TEE_PLATFORM=tdx) + V5 overlay rev ${PODVM_OVERLAY_REV} sha256 ${OVERLAY_SHA256:0:16} (initdata-measure->RTMR3, A5c=${V5_HARDEN_A5C}, B1=${V5_HARDEN_B1}), provenance in results_v5/podvm-image/"
gcloud compute images describe "${IMAGE}" --project "${PROJECT}" --format='value(status,guestOsFeatures.type)'
cat "${OUT}/${IMAGE}.provenance.txt"

if [ "${KEEP_BUILDER:-0}" != 1 ]; then
  say "deleting builder VM ${BUILDER}"
  gcloud compute instances delete "${BUILDER}" --zone "${ZONE}" --project "${PROJECT}" --quiet
fi
say "done. Use it: PODVM_IMAGE=${IMAGE} PODVM_IMAGE_PROJECT=${PROJECT} ./scripts/gke-v5/15_render_caa_values.sh && ./scripts/gke-v5/14_install_coco.sh"
