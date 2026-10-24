#!/usr/bin/env bash
# 32_negative_v5.sh: runs the negative cases live against the deployed services.
#
# Needs:  The deployment from 30 (kube context v5-controller), python3 with booking_approval,
#         and gcloud impersonation of the controller service account.
# Usage:  ./scripts/gke-v5/32_negative_v5.sh
# Result: The output of `harness_e2e negative`. Each case must refuse and leave the ledger delta
#         at zero.
#
# The cases (attack labels as in attack_catalogue.md) are A14 (no evidence, no legacy
# provisioning), A10 (a transport that lies about the boot key), A16 (the bytes delivered after
# attestation differ from the attested ones) and A11 (a runner binds once: a second challenge on
# the live stream is refused inside the TD). A18 (wrong substrate hash gives
# substrate-profile-mismatch) runs here too. A17 (scope and idempotency) is enforced live by the
# existing V3/V4.2 mechanisms and shown offline. The Authority-side td-already-bound is offline too.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
GSA="v5-controller@${PROJECT}.iam.gserviceaccount.com"
kubectl config get-contexts v5-controller >/dev/null 2>&1 || die "no kube context v5-controller: run 30_deploy_v5.sh"
cd "${MOCKS_DIR}"
python3 -m booking_approval.harness_e2e negative --context v5-controller --project "${PROJECT}" --zone "${ZONE}" \
  --registry "${AR_HOST}" --impersonate "${GSA}"
