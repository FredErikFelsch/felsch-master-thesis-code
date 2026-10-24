#!/usr/bin/env bash
# 00_check_prerequisites.sh: verifies the local toolchain and an existing gcloud authentication.
#
# Needs:  gcloud, kubectl, docker, python3 and gke-gcloud-auth-plugin installed, and a gcloud
#         login and project configured once, locally.
# Usage:  ./scripts/gke/00_check_prerequisites.sh
# Result: A list of missing tools and notes. Exit code non zero if anything is missing. It is
#         read-only and safe to run at any time.
#
# This script does not authenticate. By design, interactive auth (`gcloud init`,
# `gcloud auth login`) is the operator's responsibility and is done once, locally, before
# running any of these scripts. The script only checks that an active account and a project
# are configured, and that the required CLIs are installed.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"

fail=0
need() { command -v "$1" >/dev/null 2>&1 || { echo "  MISSING: $1"; fail=1; }; }

say "checking local tools"
need gcloud
need kubectl
need docker
need python3           # also renders manifests at deploy time (no gettext/envsubst needed)
need gke-gcloud-auth-plugin  # kubectl needs this to auth to a GKE kubeconfig

say "checking gcloud authentication (not modifying it)"
active="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)"
if [ -z "${active}" ]; then
  echo "  no active gcloud account: authenticate locally first (gcloud auth login)"
  fail=1
else
  echo "  active account: ${active}"
fi

if [ -z "${PROJECT}" ]; then
  echo "  no project set: run gcloud config set project <PROJECT_ID>"
  fail=1
else
  echo "  project: ${PROJECT}"
fi

say "checking Application Default Credentials for the Kubernetes/Docker clients"
if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  echo "  note: ADC not found. If 20/30 fail on auth, run:"
  echo "        gcloud auth application-default login   (once, locally)"
fi

[ "${fail}" -eq 0 ] || die "prerequisites not satisfied (see MISSING/notes above)"
say "prerequisites OK: project ${PROJECT}, cluster ${CLUSTER} in ${REGION}"
