#!/usr/bin/env bash
# 33_demo_v5.sh: runs the demo's third act on the cluster.
#
# Needs:  The deployment from 30, the dashboard started first (python3 -m booking_demo.serve), the
#         approval page forwarded by 49_approval_page.sh, and the admin kube context as the
#         current context.
# Usage:  scripts/gke-v5/33_demo_v5.sh [--mail fraud] [--model openai] [--attack a16,a10] [--pool 5] ...
#         Everything after the script name goes to booking_demo.run unchanged.
# Result: Every step of the agent's plan runs in a fresh attested TD, the human approves the
#         payment with a passkey on the Authority's approval page, and optional attacks run first.
#
# The cluster arguments come from _config.sh: the same identities as 31 (the narrow controller
# context and the impersonated controller service account) plus the admin context of this shell.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
cd "${MOCKS_DIR}"
GSA="v5-controller@${PROJECT}.iam.gserviceaccount.com"
kubectl config get-contexts v5-controller >/dev/null 2>&1 || die "no kube context v5-controller: run 30_deploy_v5.sh"
ADMIN_CONTEXT="$(kubectl config current-context)"
[ "${ADMIN_CONTEXT}" != "v5-controller" ] || die "the current context is the controller. The demo needs the admin context (gcloud container clusters get-credentials ${CLUSTER})"
say "controller: kube context v5-controller (GCE probe via ${GSA}), approvals: the Authority's page (49), admin context ${ADMIN_CONTEXT}"
# On a gated Authority, unattended runs (--approve auto|deny) answer with the harness key,
# when one exists and the deployment pins it. --approve wait asks the person on 49's page.
HARNESS_ARGS=()
KEY="${HARNESS_APPROVER_KEY:-${HOME}/.config/thesis-v5/harness-approver.json}"
[ -f "${KEY}" ] && HARNESS_ARGS=(--harness-approver-key "${KEY}")
python3 -m booking_demo.run --mode v5 --context v5-controller --admin-context "${ADMIN_CONTEXT}" \
  --project "${PROJECT}" --zone "${ZONE}" --registry "${AR_HOST}" --impersonate "${GSA}" \
  ${HARNESS_ARGS[@]+"${HARNESS_ARGS[@]}"} \
  --approve wait "$@"
