#!/usr/bin/env bash
# 16_install_trustee.sh: deploys Trustee (Attestation Service, RVPS and KBS) in the namespace `trustee`.
#
# Needs:  kubectl, a cluster, the rendered manifests in k8s/v5/trustee, and TRUSTEE_VERSION set
#         in the environment.
# Usage:  ./scripts/gke-v5/16_install_trustee.sh
# Result: The Trustee deployments applied and the KBS rollout complete.
#
# Not used by the evaluated deployment, which appraises the evidence locally with DCAP and runs
# no Trustee. The manifests under k8s/v5/trustee are not part of this repository, so the script
# stops at its first check unless they are supplied. In a Trustee deployment the AS would be the
# RATS Verifier, with the reference values (pod-VM MRTD and RTMRs, init-data hash) registered
# from the probe measurements.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
[ -n "${TRUSTEE_VERSION}" ] || die "TRUSTEE_VERSION not set"
[ -d "${V5_K8S_DIR}/trustee" ] || die "no k8s/v5/trustee/ manifests (not part of this repository)"
# The overlay pins the image tags from TRUSTEE_VERSION (rendered, not just guarded).
grep -rq "${TRUSTEE_VERSION}" "${V5_K8S_DIR}/trustee" || die "k8s/v5/trustee does not reference TRUSTEE_VERSION=${TRUSTEE_VERSION}. Render it first"
kubectl apply -k "${V5_K8S_DIR}/trustee"
kubectl -n trustee rollout status deploy/kbs --timeout=300s
say "Trustee up. Register the reference values with the Trustee RVPS (no script for this in the repository)"
