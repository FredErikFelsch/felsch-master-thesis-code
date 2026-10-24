#!/usr/bin/env bash
# 35_transport_attack_v5.sh: runs the transport attack live on the cluster.
#
# Needs:  The deployment from 30 (kube context v5-controller), SERVICES_IMAGE pinned by 23, the
#         gateway transport-attack manifest, python3 with booking_v4 and booking_v5. The deployment
#         must be a mock-world one: a live-world gateway (patched by 37) is refused.
# Usage:  ./35_transport_attack_v5.sh                  rewrite booking_ref (a field the binding reads)
#         ATTACK_FIELD=status ATTACK_VALUE=SETTLED ./35_transport_attack_v5.sh
#                                                      rewrite a field no binding reads
#         ATTACK_INSERT=1 adds the field where the response does not carry it.
# Result: Container logs under results_v5/e2e/attack-logs-<stamp> and a verdict. Exit code 0 only if
#         the run was refused as designed. The honest gateway is restored on every exit path,
#         including a failure, because the cluster is shared with every other step of the run.
#
# A party at the address the controller hands the machine in the clear rewrites one field
# of the gateway's answer on the way back to the runner. The gateway performed the honest
# operation and recorded the digest of the honest response, so the Authority's check finds
# the reported effect and the recorded effect disagreeing, and refuses to sign the state
# that would have carried the forged value into the fact store.
#
# The second usage form is the stronger result: the digest covers the whole response, so the
# check does not rest on a field list an attacker could dodge by choosing a dull field.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
kubectl config get-contexts v5-controller >/dev/null 2>&1 || die "no kube context v5-controller: run 30_deploy_v5.sh"
[ -f "${DIGEST_FILE}" ] || die "no ${DIGEST_FILE}: run 23_build_services_image.sh"
source "${DIGEST_FILE}"
[ -n "${SERVICES_IMAGE:-}" ] || die "SERVICES_IMAGE not pinned"

NAMESPACE=agent-system
ATTACK_FIELD="${ATTACK_FIELD:-booking_ref}"
ATTACK_VALUE="${ATTACK_VALUE:-FORGED-BY-THE-TRANSPORT}"
# ATTACK_INSERT=1 writes the field even where the response does not carry it. In the
# running world every field of a booking is read by some rule, so adding one is the only
# way to touch a field no rule reads. That is the live form of the offline
# `adv-transport-rewrites-unbound-field`.
ATTACK_INSERT="${ATTACK_INSERT:-0}"
LOGS_COLLECTED=0
SVC_DIR="${V5_K8S_DIR}/services"
OUT="${MOCKS_DIR}/results_v5/e2e"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

render() {   # placeholder substitution as in 30 (the services image) plus the attack parameters
  SVC="${SERVICES_IMAGE}" FIELD="${ATTACK_FIELD}" VALUE="${ATTACK_VALUE}" \
  INSERT="${ATTACK_INSERT}" python3 - "$1" <<'PY'
import os, sys
s = open(sys.argv[1]).read()
for k, v in (("${SERVICES_IMAGE}", os.environ["SVC"]),
             ("${ATTACK_FIELD}", os.environ["FIELD"]),
             ("${ATTACK_VALUE}", os.environ["VALUE"])):
    s = s.replace(k, v)
# The flag is a whole argument or nothing at all, so the honest form carries no empty
# string that argparse would have to ignore.
s = s.replace('"${ATTACK_INSERT_FLAG}", ', '"--insert", ' if os.environ["INSERT"] == "1" else "")
sys.stdout.write(s)
PY
}

collect_logs() {
  # Before the restore, because the restore replaces the pod and takes its logs with it.
  # The proxy prints one JSON line per relayed connection that ended badly and one per
  # rewrite, so a diagnosis starts from this file.
  [ "${LOGS_COLLECTED}" = "1" ] && return 0
  LOGS_COLLECTED=1
  local dir="${OUT}/attack-logs-${STAMP}"
  mkdir -p "${dir}"
  local pod
  pod="$(kubectl -n "${NAMESPACE}" get pods -l app=gateway -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -n "${pod}" ]; then
    for c in transport-proxy gateway; do
      kubectl -n "${NAMESPACE}" logs "${pod}" -c "${c}" --tail=300 > "${dir}/${c}.log" 2>&1 || true
    done
  fi
  kubectl -n "${NAMESPACE}" logs deploy/authority --tail=300 > "${dir}/authority.log" 2>&1 || true
  say "container logs: ${dir}"
  if [ -s "${dir}/transport-proxy.log" ]; then
    say "  transport-proxy (last 20 lines):"
    tail -20 "${dir}/transport-proxy.log" | sed 's/^/    /'
  fi
}

restore_honest_gateway() {
  collect_logs
  say "restoring the honest gateway (the Deployment only)"
  # Only the gateway Deployment. Applying the whole services.yaml re-applies the
  # trusted-init Job as well, and a Job's pod template is immutable, so the restore
  # would end in a wall of "field is immutable" and leave the operator guessing whether
  # the gateway had come back.
  SVC="${SERVICES_IMAGE}" RUN="${RUNNER_IMAGE}" python3 - "${SVC_DIR}/services.yaml" <<'PY' | kubectl apply -f - >/dev/null
import os, sys
text = open(sys.argv[1]).read()
for key, value in (("${SERVICES_IMAGE}", os.environ["SVC"]), ("${RUNNER_IMAGE}", os.environ["RUN"])):
    text = text.replace(key, value)
docs = [d for d in text.split("\n---")
        if "kind: Deployment" in d and "name: gateway" in d]
if len(docs) != 1:
    sys.exit(f"expected exactly one gateway Deployment in services.yaml, found {len(docs)}")
sys.stdout.write(docs[0])
PY
  kubectl -n "${NAMESPACE}" rollout status deploy/gateway --timeout=180s >/dev/null || true
  say "honest gateway back: $(kubectl -n "${NAMESPACE}" get deploy gateway -o jsonpath='{.spec.template.spec.containers[*].name}')"
}
# The attack manifest is a mock-world gateway. On a live world 37 has patched the gateway to read
# its provider credential from OpenBao (BAO_ADDR). The attack pod would replace that gateway, and
# the restore above brings back only the services.yaml Deployment, without the OpenBao patch, so
# the live gateway would stay down. A live world is therefore refused before anything changes.
if kubectl -n "${NAMESPACE}" get deploy gateway -o jsonpath='{.spec.template.spec.containers[*].env[*].name}' 2>/dev/null \
    | grep -qw BAO_ADDR; then
  die "the deployed gateway is a live-world gateway (BAO_ADDR, patched by 37). 35 runs against the mock world only"
fi
trap restore_honest_gateway EXIT

# --- 1. the check must be on before the attack means anything -------------------------
# One implementation of the question, in 36, asked against the deployed Authority. A
# refusal from a deployment that never had the check looks the same as a refusal from one
# that has it, and only the second is evidence.
say "1/4 confirming the Authority checks observations against the effect ledger"
"$(dirname "${BASH_SOURCE[0]}")/36_assert_observation_v5.sh" \
  || die "the attack would prove nothing against this deployment"

# --- 2. put the transport on the path --------------------------------------------------
say "2/4 deploying the gateway pod with a transport that rewrites '${ATTACK_FIELD}'"
render "${SVC_DIR}/gateway-transport-attack.yaml" | kubectl apply -f - >/dev/null
kubectl -n "${NAMESPACE}" rollout status deploy/gateway --timeout=300s
kubectl -n "${NAMESPACE}" get deploy gateway -o jsonpath='{range .spec.template.spec.containers[*]}  container {.name}: {.args}{"\n"}{end}'

# --- 2b. does the transport relay at all? ----------------------------------------------
# Five seconds instead of two and a half minutes. An unknown method is answered by the
# gateway with a structured error reply, so a WireError here shows the round trip. A
# timeout shows that the proxy swallows the answer, which otherwise costs whole TD runs
# before anyone asks this question directly.
say "2b/4 smoke: one round trip through the transport (a rejected dummy method counts as the pass)"
(cd "${MOCKS_DIR}" && python3 -c "
import sys
from booking_v4 import wire
from booking_v4.services import _call
from booking_v5.e2e_live import PortForward
# A method that does not exist. The gateway rejects it with a structured error reply,
# and what matters is that this reply comes back through the proxy. The rejection is the
# evidence, not a fault.
with PortForward('v5-controller', 'gateway', 8443) as pf:
    try:
        _call(pf.endpoint, 'gateway.this_method_does_not_exist_on_purpose', {})
        print('  PASS: the transport relays (the gateway answered without an error)')
    except wire.WireError as exc:
        print('  PASS: the transport relays. The gateway rejected the dummy method as')
        print(f'        expected, and its rejection came back through the proxy: {exc}')
    except Exception as exc:
        sys.exit(f'  FAIL: the transport does not relay: {type(exc).__name__}: {exc}')
") || die "the transport does not relay. A run through it would only reproduce that"

# --- 3. one run against it -------------------------------------------------------------
# The refusal is the expected outcome, so e2e_live's own exit code is not the verdict.
say "3/4 one four-step run through the transport"
cd "${MOCKS_DIR}"
set +e
python3 -m booking_approval.harness_e2e run --context v5-controller --project "${PROJECT}" --zone "${ZONE}" \
  --registry "${AR_HOST}" --impersonate "v5-controller@${PROJECT}.iam.gserviceaccount.com" \
  --steps 4 --repeat 1 --pool 0 --run-id "attack-${STAMP}"
set -e

# --- 4. the verdict, from the record and from what the attacker did --------------------
collect_logs
say "4/4 verdict"
python3 - "${OUT}" "${ATTACK_FIELD}" "${OUT}/attack-logs-${STAMP}/transport-proxy.log" <<'PY'
import json, pathlib, sys

out, field, proxy_log = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])

# An attack that never fired is not a result in either direction. Counting the rewrites the
# transport reports, rather than inferring them from the run's outcome, keeps an
# honest run from being written down as a successful attack.
tampered, absent = 0, []
if proxy_log.exists():
    for line in proxy_log.read_text().splitlines():
        try:
            event = json.loads(line)
        except Exception:
            continue
        if event.get("event") == "tampered":
            tampered += 1
        elif event.get("event") == "field-absent":
            absent.append(event.get("payload_keys"))
print(f"the transport rewrote {tampered} response(s)")
if tampered == 0:
    for keys in absent:
        print(f"  the response carried no {field!r}; its fields were: {keys}")
    raise SystemExit(
        "NOT ARMED: the transport never rewrote anything, so this run measures nothing "
        "about the observation check. Target a field the running world produces, or set "
        "ATTACK_INSERT=1 to add one.")
newest = max((d for d in out.iterdir() if (d / "run.json").exists()),
             key=lambda d: (d / "run.json").stat().st_mtime)
record = json.loads((newest / "run.json").read_text())
print(f"record: {newest}")
print(f"observation_check in the manifest: {record['manifest'].get('observation_check')}")

steps = record["steps"]
for s in steps:
    print(f"  step {s.get('step')}: outcome={s.get('outcome')} accepted={s.get('accepted')} "
          f"result_status={s.get('result_status')} successor={s.get('has_successor')}\n"
          f"          reason={s.get('result_reason')} effects={s.get('effects')} "
          f"refusal={s.get('refusal')} harness_error={s.get('harness_error')}")

if not steps:
    raise SystemExit("the record has no steps at all: the run died before it wrote one")

accepted = [s for s in steps if s.get("accepted")]
if len(steps) >= 4 and all(s.get("accepted") for s in steps):
    raise SystemExit(f"ATTACK SUCCEEDED: every step was accepted with '{field}' rewritten on the wire")

blocked = next((s for s in steps if not s.get("accepted")), None)
if blocked is None:
    # Every recorded step was accepted as a session, and the run still stopped early. The
    # step that carries the reason is the last one, because a refused finalisation leaves
    # the session accepted and the successor absent.
    blocked = steps[-1]
text = json.dumps(blocked)
expected = "observation" in text or "RECONCILE" in text or "FINALIZE_REFUSED" in text
print()
print(f"the run stopped at step {blocked.get('step')} after {len(accepted)} accepted step(s)")
if not expected:
    print("WARNING: it stopped, but the record does not name the observation check.")
    print("         Look at the step above before this counts as evidence.")
    raise SystemExit(2)
print(f"REFUSED as designed: the rewritten '{field}' never entered the fact store")
PY
say "done. The honest gateway is restored by the exit trap."
