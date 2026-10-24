#!/usr/bin/env bash
# 34_expiry_v5.sh: A20 live. An intervention approval expires against the deployed services' system clock.
#
# Needs:  The controller context from 30, the approval page forwarded by 49_approval_page.sh, and
#         the admin context as the current context, as for 33.
# Usage:  ./34_expiry_v5.sh                 TTL=20 WAIT=25
#         TTL=60 WAIT=70 ./34_expiry_v5.sh
#         POOL=2 ./34_expiry_v5.sh          warm TDs for the five fragment runs
# Result: results_v5/expiry/<stamp>.json with the run manifest.
#
# A20 is the expiry case of attack_catalogue.md. The payment parks, the human approves with a short window
# (TTL, default 20 s), and the resubmission after WAIT (default 25 s) is refused at the grant with
# "validity window", with no effect. A fresh approval then completes the same fragment (the control).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
cd "${MOCKS_DIR}"
GSA="v5-controller@${PROJECT}.iam.gserviceaccount.com"
kubectl config get-contexts v5-controller >/dev/null 2>&1 || die "no kube context v5-controller: run 30_deploy_v5.sh"
ADMIN_CONTEXT="$(kubectl config current-context)"
[ "${ADMIN_CONTEXT}" != "v5-controller" ] || die "the current context is the controller. The run needs the admin context (gcloud container clusters get-credentials ${CLUSTER})"
say "A20 expiry: ttl=${TTL:-20}s wait=${WAIT:-25}s pool=${POOL:-0}, controller v5-controller, admin context ${ADMIN_CONTEXT}"
# On a gated Authority, unattended runs (--approve auto|deny) answer with the harness key,
# when one exists and the deployment pins it. --approve wait asks the person on 49's page.
HARNESS_ARGS=()
KEY="${HARNESS_APPROVER_KEY:-${HOME}/.config/thesis-v5/harness-approver.json}"
[ -f "${KEY}" ] && HARNESS_ARGS=(--harness-approver-key "${KEY}")
python3 -m booking_demo.expiry --mode v5 --context v5-controller --admin-context "${ADMIN_CONTEXT}" \
  --project "${PROJECT}" --zone "${ZONE}" --registry "${AR_HOST}" --impersonate "${GSA}" \
  ${HARNESS_ARGS[@]+"${HARNESS_ARGS[@]}"} \
  --ttl "${TTL:-20}" --wait "${WAIT:-25}" --pool "${POOL:-0}" "$@"
