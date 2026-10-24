#!/usr/bin/env bash
# _config.sh: shared configuration for the reproducible GKE bootstrap.
#
# Needs:  gcloud with an active account and project. The scripts assume a working gcloud
#         authentication already exists (see 00_check_prerequisites.sh) and do not run
#         `gcloud auth login` or `gcloud init`.
# Usage:  Sourced by every 00..90 script here and by the V5 configuration. Override any value from
#         the environment before running a script, e.g.  REGION=europe-west1 ./10_create_cluster.sh
# Result: The variables and the helpers say, die and require_project. It reads the active gcloud
#         project (it does not set or switch it) and derives all names deterministically, so the
#         same commands rebuild the same environment.
#
# This file contains no secrets and no credentials. All authority material is minted in-cluster
# by the trusted init step at deploy time.
# Strict mode is set only when a script sources it. In an interactive shell (`source _config.sh`)
# -e/-u would kill the terminal on the first failing command or unset variable.
[[ $- == *i* ]] || set -euo pipefail

# --- project (read-only, not modified by these scripts) ----------------------
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null || true)}"

# --- location and cluster (minimal-cost profile) -----------------------------
# The evaluation cares about correctness, not scale or HA. Every default here is
# the cheapest option that still runs the experiment. Each is a single knob.
#   * one zonal Standard cluster  -> the GKE management fee is $0 (the free tier covers
#     one zonal cluster, a regional cluster or a second cluster would start the
#     $0.10/h fee). Standard, not Autopilot, so the scripts control the exact runner Pod
#     spec. The V4.4c claim is about that fixed profile, and Autopilot mutates and
#     validates pod specs.
#   * two Spot e2-standard-2 nodes (2 dedicated vCPU, 8 GB each) -> about $0.04/h. e2-medium
#     is shared-core, and the Dataplane V2 kube-system pods leave too little CPU for our
#     init, authority, controller and runner pods ("Insufficient cpu"), see RUNBOOK.md.
#     The experiment is short and fully re-runnable, so a rare Spot preemption just means
#     re-running.
#   * small pd-standard boot disk -> 32 GB instead of the 100 GB pd-balanced default.
#   * ClusterIP only, no LoadBalancer, managed-prometheus off, SYSTEM logging only.
# The dominant cost risk is forgetting to destroy: two idle Spot e2-standard-2 cost about
# $30 a month. 90_destroy_cluster.sh is the real cost control, so run it.
REGION="${REGION:-europe-west1}"
ZONE="${ZONE:-${REGION}-c}"
CLUSTER="${CLUSTER:-thesis-v44c}"
NODE_MACHINE="${NODE_MACHINE:-e2-standard-2}"
NUM_NODES="${NUM_NODES:-2}"
USE_SPOT="${USE_SPOT:-true}"          # Spot node(s). Set false for on-demand
DISK_TYPE="${DISK_TYPE:-pd-standard}" # cheapest persistent disk
DISK_SIZE="${DISK_SIZE:-32}"          # GB node boot disk
# A regional cluster spreads the node pool across zones (HA the evaluation does not need, and it
# would also start the management fee). Default to a single-zone (zonal) cluster;
# set CLUSTER_SCOPE=regional to override. LOCATION_ARGS is used by every gcloud
# cluster command, so the choice is made in one place.
CLUSTER_SCOPE="${CLUSTER_SCOPE:-zonal}"
if [ "${CLUSTER_SCOPE}" = "regional" ]; then
  LOCATION_ARGS=(--region "${REGION}")
else
  LOCATION_ARGS=(--zone "${ZONE}")
fi

# --- Artifact Registry + images ----------------------------------------------
AR_LOCATION="${AR_LOCATION:-${REGION}}"
AR_REPO="${AR_REPO:-thesis}"
AR_HOST="${AR_LOCATION}-docker.pkg.dev"
IMAGE_BASE="${AR_HOST}/${PROJECT}/${AR_REPO}"
# Single code image runs runner, controller, authority and init entrypoints.
IMAGE_NAME="${IMAGE_NAME:-booking}"
IMAGE_TAG="${IMAGE_TAG:-v44c}"
IMAGE_REF="${IMAGE_BASE}/${IMAGE_NAME}:${IMAGE_TAG}"

# --- kubernetes --------------------------------------------------------------
NAMESPACE="${NAMESPACE:-agent-system}"

# --- repo layout -------------------------------------------------------------
# Path of this file, in bash and in zsh (`source` from a zsh terminal has no BASH_SOURCE).
if [ -n "${ZSH_VERSION:-}" ]; then _CFG_SELF="${(%):-%x}"; else _CFG_SELF="${BASH_SOURCE[0]}"; fi
SCRIPT_DIR="$(cd "$(dirname "${_CFG_SELF}")" && pwd)"
MOCKS_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
K8S_DIR="${MOCKS_DIR}/k8s"
APPLY_DIR="${K8S_DIR}/apply"        # manifests that are applied to the cluster
REF_DIR="${K8S_DIR}/reference"      # documentation anchors, not applied by any script
# Build/push writes the resolved digest here. Gitignored, not committed.
DIGEST_FILE="${SCRIPT_DIR}/.digests"
# The controller Secret the trusted init patches (pre-created empty by the deploy step).
BOOTSTRAP_SECRET="${BOOTSTRAP_SECRET:-deployment-bootstrap}"

say()  { printf '\033[1;34m[v44c]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[v44c] ERROR:\033[0m %s\n' "$*" >&2; [[ $- == *i* ]] && return 1; exit 1; }

require_project() {
  [ -n "${PROJECT}" ] || die "no active gcloud project (run 00_check_prerequisites.sh)"
}
