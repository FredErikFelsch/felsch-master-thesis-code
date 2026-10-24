#!/usr/bin/env bash
# 40_verify_platform.sh: verifies that the platform enforces what the claim relies on.
#
# Needs:  The deployment from 30_deploy.sh, kubectl and gcloud.
# Usage:  ./scripts/gke/40_verify_platform.sh
# Result: OK or FAIL lines per check. Exit code non zero on any deviation, so a broken platform
#         is not mistaken for a passing security run.
#
# Two things the offline tests cannot check, asserted here against the live
# cluster before the security suite runs:
#   (a) the CNI enforces NetworkPolicy (Dataplane V2), else runner confinement is
#       vacuous;
#   (b) the RBAC matrix is the intended one, via `kubectl auth can-i --as=...`
#       (prove-first): the orchestrator SA is denied every Job/pod-mutation verb,
#       and only the controller SA holds the Job lifecycle + pods/attach.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

NS="${NAMESPACE}"
SA="system:serviceaccount:${NS}"
fail=0

say "(0) the ServiceAccounts exist (a can-i --as check is valid for any principal)"
for sa in orchestrator-sa controller-sa runner-sa authority-sa; do
  kubectl -n "${NS}" get sa "${sa}" -o name >/dev/null 2>&1 \
    && echo "  OK: ${sa} exists" || { echo "  FAIL: ${sa} missing"; fail=1; }
done

say "(a) NetworkPolicy enforcement (Dataplane V2)"
dpv2="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" \
        --project "${PROJECT}" --format='value(networkConfig.datapathProvider)' 2>/dev/null || true)"
np="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" \
      --project "${PROJECT}" --format='value(networkPolicy.enabled)' 2>/dev/null || true)"
if [ "${dpv2}" = "ADVANCED_DATAPATH" ] || [ "${np}" = "True" ]; then
  echo "  OK: NetworkPolicy is enforced (datapath=${dpv2:-n/a} networkPolicy=${np:-n/a})"
else
  echo "  FAIL: NetworkPolicy not enforced (datapath=${dpv2:-n/a} networkPolicy=${np:-n/a})"
  fail=1
fi

# can EXPECT VERB RESOURCE SA
#   RESOURCE may be `resource/subresource` (e.g. pods/attach). kubectl reads
#   `can-i create pods/attach` as "the Pod named attach" (TYPE/NAME syntax), which
#   is always "no" and proves nothing. A subresource must be passed via
#   --subresource. This helper does that split, so the RBAC matrix is asked the
#   question it claims to ask.
can() {
  local expect="$1" verb="$2" res="$3" sa="$4" got
  local sub_args=()
  if [[ "${res}" == */* ]]; then
    sub_args=(--subresource "${res#*/}")
    res="${res%%/*}"
  fi
  # ${arr[@]+"${arr[@]}"}: an empty array is "unbound" under set -u on macOS bash 3.2.
  got="$(kubectl -n "${NS}" auth can-i "${verb}" "${res}" ${sub_args[@]+"${sub_args[@]}"} \
           --as "${SA}:${sa}" 2>/dev/null || true)"
  if [ "${got}" = "${expect}" ]; then
    echo "  OK: ${sa} can-i ${verb} ${3} = ${got}"
  else
    echo "  FAIL: ${sa} can-i ${verb} ${3} = ${got} (expected ${expect})"; fail=1
  fi
}

say "(b) RBAC matrix: orchestrator-sa is denied every launch verb"
can no  create jobs         orchestrator-sa
can no  delete jobs         orchestrator-sa
can no  update jobs         orchestrator-sa
can no  patch  jobs         orchestrator-sa
can no  create pods         orchestrator-sa
can no  create pods/attach  orchestrator-sa
can no  get    pods/attach  orchestrator-sa
can no  create pods/exec    orchestrator-sa
can no  get    secrets      orchestrator-sa

say "(b) RBAC matrix: controller-sa holds the launch lifecycle, the listed extra verbs are denied"
can yes create jobs         controller-sa
can yes delete jobs         controller-sa
can yes get    jobs         controller-sa
can yes create pods/attach  controller-sa
can yes get    pods/attach  controller-sa
can yes get    pods/log     controller-sa
can no  update jobs         controller-sa
can no  patch  jobs         controller-sa
can no  create pods         controller-sa
can no  create pods/exec    controller-sa
can no  get    secrets      controller-sa
can no  create configmaps   controller-sa
can no  patch  deployments  controller-sa
can no  create roles        controller-sa
can no  create rolebindings controller-sa

say "(b) RBAC matrix: runner-sa holds none of the checked verbs"
can no  create jobs         runner-sa
can no  get    secrets      runner-sa
can no  create pods/attach  runner-sa
can no  get    pods/attach  runner-sa
can no  list   pods         runner-sa

[ "${fail}" -eq 0 ] || die "platform verification FAILED: do not trust a security run on this cluster"
say "platform verified: NetworkPolicy enforced and RBAC matrix correct"