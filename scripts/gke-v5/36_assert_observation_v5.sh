#!/usr/bin/env bash
# 36_assert_observation_v5.sh: asks the deployed Authority whether it checks observations against the effect ledger.
#
# Needs:  The deployment from 30, the kube context v5-controller, python3 with booking_v5.
# Usage:  ./scripts/gke-v5/36_assert_observation_v5.sh
# Result: Prints `observation_check = <answer>`. Exit 0 only on `bound`. `unbound` means the
#         deployment was started without --gateway-observe. Anything else means the question
#         itself did not get through.
#
# Ten seconds, no TD, no run. The answer decides whether everything after it is evidence: a
# refusal from a deployment that never had the check looks the same as a refusal from one
# that has it, and only the second is worth reporting. Asked from a run record, the answer
# would arrive only after a cold fragment has finished. Asked here it arrives right after the
# deploy.
#
# The port-forward is `booking_v5.e2e_live.PortForward`, the one the live run uses, and not a
# hand-rolled `kubectl port-forward deploy/authority`. The controller identity cannot do the
# latter: it holds `pods/portforward` and no rights on deployments, and hiding
# kubectl's stderr would turn the refusal into a bare "connection refused". Asking with the
# mechanism the run uses also means this answer is the answer the run would get.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
kubectl config get-contexts v5-controller >/dev/null 2>&1 || die "no kube context v5-controller: run 30_deploy_v5.sh"

OBS="$(cd "${MOCKS_DIR}" && python3 -c "
from booking_v5.e2e_live import PortForward, _observation_check
try:
    with PortForward('v5-controller', 'authority', 8443) as pf:
        print(_observation_check(pf.endpoint))
except Exception as exc:
    print(f'unreachable ({type(exc).__name__}: {exc})')
" | tail -1)"

say "observation_check = ${OBS}"
[ "${OBS}" = "bound" ] || die "the deployed Authority reports '${OBS}', not 'bound'. Nothing measured after this would be evidence for the observation check. Look at --gateway-observe on the authority deployment and at the gateway's 8444 listener."
