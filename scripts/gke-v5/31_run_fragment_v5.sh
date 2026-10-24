#!/usr/bin/env bash
# 31_run_fragment_v5.sh: runs one cold fragment end to end on the live cluster.
#
# Needs:  The deployment from 30 (it creates the kube context v5-controller), python3 with
#         kubernetes, google-auth and requests, and gcloud impersonation of the controller
#         service account.
# Usage:  STEPS=3 ./31_run_fragment_v5.sh              chain three happy-path steps in one run (three TDs)
#         REPEAT=5 ./31_run_fragment_v5.sh             five cold-path repetitions, writes summary.json
#         POOL=2 REPEAT=5 ./31_run_fragment_v5.sh      warm pool of 2, five repetitions
#         TOLERATE_SUBSTRATE_VARIANCE=1 REPEAT=10 ...  latency series: a refusal that is shown to come
#                                                      only from the provider's RTMR0 field does not abort the run.
#                                                      Off by default, and ignored without REPEAT>1.
#                                                      Never set this for a security run.
# Result: One fragment per repetition: spawn, attest, session, execute, ledger delta, destroy.
#         It runs under the narrow controller identity that 30 created.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
GSA="v5-controller@${PROJECT}.iam.gserviceaccount.com"
kubectl config get-contexts v5-controller >/dev/null 2>&1 || die "no kube context v5-controller: run 30_deploy_v5.sh"
python3 -c 'import kubernetes, google.auth' 2>/dev/null || die "pip3 install kubernetes google-auth requests"
say "controller: kube context v5-controller, GCE probe via impersonation of ${GSA}"
cd "${MOCKS_DIR}"
# The flag is set only when it was requested explicitly. Without the variable every refusal
# fails the series.
# The expansion below is the bash 3.2 safe form: under `set -u`, "${ARR[@]}" on an empty array
# is an unbound-variable error and ${ARR[@]+...} is not.
TOLERATE_ARGS=()
[ "${TOLERATE_SUBSTRATE_VARIANCE:-0}" = "1" ] && TOLERATE_ARGS+=(--tolerate-substrate-variance)

python3 -m booking_approval.harness_e2e run --context v5-controller --project "${PROJECT}" --zone "${ZONE}" \
  --registry "${AR_HOST}" --impersonate "${GSA}" \
  --steps "${STEPS:-1}" --repeat "${REPEAT:-1}" --pool "${POOL:-0}" ${TOLERATE_ARGS[@]+"${TOLERATE_ARGS[@]}"}
