#!/usr/bin/env bash
# 38_negative_live_v5.sh: shows what each party in the live world cannot reach.
#
# Needs:  The deployment from 30 and the credential store from 37, kubectl, gcloud, python3 with
#         booking_approval for the controller probe, and the patched rules from 13
#         (results_v5/genpolicy-<kata>/rules.patched.rego) for the TD probe.
# Usage:  ./scripts/gke-v5/38_negative_live_v5.sh
#         PEER_PROBE=0 skips the TD block (it costs one TD boot, about two to three minutes).
#         PEER_TIMEOUT and PROBE_IMAGE override the TD wait and the probe image.
# Result: A table of cases and results_v5/negative/negative-live-<stamp>.json, plus the TD probe log
#         next to it. Exit code non zero if any case did not hold.
#
# A DENY in the monitor is half the statement. The other half is that nothing happened on
# any layer underneath, and that half needs an attempt. This script makes the attempt from
# each party's own network position and with each party's own identity, and records what
# came back.
#
#   runner  -> api.duffel.com:443    must fail   (default-deny, egress only to the Authority,
#                                                 the gateway's execution port and DNS)
#   runner  -> openbao:8200          must fail   (no route, and no token to present)
#   runner  -> a ServiceAccount token           must be absent (automount disabled)
#   gateway -> openbao:8200          must work   (it holds the credentials)
#   gateway reads its credential     must work
#   gateway OpenBao identity         must be the k8s-auth role, not the dev-mode root token
#   gateway with a live-mode token   must be refused (Duffel Test Mode only)
#   gateway -> api.duffel.com:443    must work   (the provider it was configured for)
#   gateway -> evil.example:443      must fail   at the application layer
#   gateway redirects (source check) must not be followed
#   gateway -> http (not https)      must fail   at the application layer
#   controller -> create_run, decide_intervention, a forged passkey assertion
#                                    must fail   (the approval gate)
#   controller changes the approver set          must not be allowed
#
# The application-layer cases are the interesting ones. The network grants HTTPS in general,
# because a NetworkPolicy cannot name a host. Which provider may be reached is the gateway's
# own allow-list, so evil.example and plain http are checked inside the gateway pod, against
# the code that is deployed there. The redirect case is a source check, not a live request:
# it confirms that the deployed RequestsTransport.request passes allow_redirects=False.
#
# The first runner probe is a pod, not a TD. It carries the runner's labels and
# ServiceAccount, so the same NetworkPolicy applies to it.
#
# The second runner probe is a TD: a peer pod (kata-remote, TDX) in agent-system itself, with
# the runner's labels and ServiceAccount, under the deployed NetworkPolicy, trying the same
# targets from inside the TD:
#
#   td is a TDX pod VM            must hold        (captured from GCE while the VM lives)
#   td -> gateway:8443            must be reached  (positive control: the tunnel works and
#                                                   the runner's one allowed path is open)
#   td -> kube-dns:53             must be reached  (DNS, the policy allows it)
#   td -> api.duffel.com:443      must fail
#   td -> openbao:8200            must fail
#   td -> gateway-observe:8444    must fail        (the ledger is not the runner's)
#   td -> 1.1.1.1:443             must fail        (no general egress)
#   td -> 169.254.169.254:80      must fail        (no metadata server)
#   td has a SA token             must be absent
#
# The probe TD carries a permissive policy (booking_v5.permissive_policy, as in 19): its
# init-data digest goes into RTMR3, so the Authority refuses its evidence and it cannot be
# taken for the runner. The pod VM's confidential type is captured while it lives.
# The substrate baseline without any policy stays 19_probe_network.sh.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

OUT="${MOCKS_DIR}/results_v5/negative"; mkdir -p "${OUT}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="${OUT}/negative-live-${STAMP}.json"
PROBE_IMAGE="${PROBE_IMAGE:-mirror.gcr.io/library/busybox:1.36}"
PROBE_POD="runner-netprobe"
PASS=0; FAIL=0
RESULTS=()

record() {  # name expected observed verdict
  local verdict="$4"
  if [ "${verdict}" = "PASS" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
  RESULTS+=("$(printf '{"case":"%s","expected":"%s","observed":"%s","verdict":"%s"}' \
    "$1" "$2" "$3" "${verdict}")")
  printf '  %-34s %-12s %-28s %s\n' "$1" "$2" "$3" "${verdict}"
}

say "the runner's position: a pod with the runner's labels and ServiceAccount"
kubectl -n "${NAMESPACE}" delete pod "${PROBE_POD}" --ignore-not-found --wait=true >/dev/null
kubectl -n "${NAMESPACE}" run "${PROBE_POD}" --image="${PROBE_IMAGE}" --restart=Never \
  --overrides='{"spec":{"serviceAccountName":"runner-sa","automountServiceAccountToken":false},"metadata":{"labels":{"app":"runner"}}}' \
  --command -- sleep 600 >/dev/null
kubectl -n "${NAMESPACE}" wait --for=condition=ready pod/"${PROBE_POD}" --timeout=120s >/dev/null

probe_runner() {  # host port
  kubectl -n "${NAMESPACE}" exec "${PROBE_POD}" -- \
    timeout 8 nc -z -w 5 "$1" "$2" >/dev/null 2>&1 && echo "reached" || echo "no route"
}

printf '\n  %-34s %-12s %-28s %s\n' CASE EXPECTED OBSERVED VERDICT
printf '  %s\n' "$(printf '%.0s-' {1..92})"

obs="$(probe_runner api.duffel.com 443)"
[ "${obs}" = "no route" ] && v=PASS || v=FAIL
record "runner -> api.duffel.com:443" "no route" "${obs}" "${v}"

obs="$(probe_runner openbao.agent-system.svc 8200)"
[ "${obs}" = "no route" ] && v=PASS || v=FAIL
record "runner -> openbao:8200" "no route" "${obs}" "${v}"

obs="$(kubectl -n "${NAMESPACE}" exec "${PROBE_POD}" -- \
  sh -c 'test -r /var/run/secrets/kubernetes.io/serviceaccount/token && echo present || echo absent' 2>/dev/null || echo absent)"
[ "${obs}" = "absent" ] && v=PASS || v=FAIL
record "runner has a SA token" "absent" "${obs}" "${v}"

if [ "${PEER_PROBE:-1}" = "1" ]; then
  say "the runner's position as a TD: a peer pod with the runner's labels and ServiceAccount"
  TD_POD="runner-tdprobe"
  RULES_REGO="${MOCKS_DIR}/results_v5/genpolicy-${KATA_VERSION}/rules.patched.rego"
  OV_TD=""
  if [ -f "${RULES_REGO}" ]; then
    OV_TD="$(RULES_REGO="${RULES_REGO}" PROBE_IMAGE="${PROBE_IMAGE}" MOCKS_DIR="${MOCKS_DIR}" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.environ["MOCKS_DIR"])
from booking_v5.permissive_policy import permissive_policy
from booking_v5.profile_v5 import INIT_DATA_ANNOTATION, init_data_annotation_value, init_data_document, init_data_hash
with open(os.environ["RULES_REGO"]) as fh:
    doc = init_data_document(os.environ["PROBE_IMAGE"], policy_rego=permissive_policy(fh.read()))
print(json.dumps({
    "metadata": {"labels": {"app": "runner"},
                 "annotations": {INIT_DATA_ANNOTATION: init_data_annotation_value(doc),
                                 "v5/init-data-sha256": init_data_hash(doc),
                                 "v5/policy": "PERMISSIVE-probe-only"}},
    "spec": {"runtimeClassName": "kata-remote", "serviceAccountName": "runner-sa",
             "automountServiceAccountToken": False}}))
PY
)"
  fi
  if [ -z "${OV_TD}" ]; then
    for c in "td -> gateway:8443" "td -> kube-dns:53" "td -> api.duffel.com:443" "td -> openbao:8200" \
             "td -> gateway-observe:8444" "td -> 1.1.1.1:443" "td -> 169.254.169.254:80" "td has a SA token"; do
      record "${c}" "-" "no probe (no ${RULES_REGO##*/})" FAIL
    done
  else
    kubectl -n "${NAMESPACE}" delete pod "${TD_POD}" --ignore-not-found --wait=true >/dev/null
    kubectl -n "${NAMESPACE}" run "${TD_POD}" --restart=Never --image="${PROBE_IMAGE}" \
      --overrides="${OV_TD}" -- sh -c "
        for t in 'gateway.${NAMESPACE}.svc.cluster.local 8443' 'kube-dns.kube-system.svc.cluster.local 53' \
                 'api.duffel.com 443' 'openbao.${NAMESPACE}.svc.cluster.local 8200' \
                 'gateway-observe.${NAMESPACE}.svc.cluster.local 8444' '1.1.1.1 443' '169.254.169.254 80'; do
          set -- \$t; r=BLOCKED
          for i in 1 2 3; do nc -z -w 3 \$1 \$2 && { r=OPEN; break; }; sleep 1; done
          echo \"PROBE \$r \$1:\$2\"; done
        test -r /var/run/secrets/kubernetes.io/serviceaccount/token && echo 'PROBE SATOKEN present' || echo 'PROBE SATOKEN absent'" >/dev/null
    t0=$(date +%s); deadline=$(( t0 + ${PEER_TIMEOUT:-600} )); vm_line=""; phase=""
    while :; do
      phase="$(kubectl -n "${NAMESPACE}" get pod "${TD_POD}" -o jsonpath='{.status.phase}' 2>/dev/null || echo UNKNOWN)"
      [ "${phase}" = "Succeeded" ] || [ "${phase}" = "Failed" ] && break
      [ "$(date +%s)" -lt "${deadline}" ] || break
      [ -n "${vm_line}" ] || vm_line="$(gcloud compute instances list --project "${PROJECT}" \
        --filter="name~^podvm-${TD_POD}-" \
        --format='value(name,confidentialInstanceConfig.confidentialInstanceType,networkInterfaces[0].subnetwork.basename())' \
        2>/dev/null | head -1)"
      sleep 5
    done
    TD_LOG="${OUT}/negative-live-${STAMP}-td.txt"
    { echo "phase=${phase} after $(( $(date +%s) - t0 )) s"; echo "pod VM (captured while alive): ${vm_line:-none}"
      kubectl -n "${NAMESPACE}" logs "${TD_POD}" 2>&1 || true; } > "${TD_LOG}"
    td_obs() {  # host:port -> reached | no route | no result
      local r; r="$(grep -E "^PROBE (OPEN|BLOCKED) $1\$" "${TD_LOG}" | awk '{print $2}' | head -1)"
      case "${r}" in OPEN) echo reached;; BLOCKED) echo "no route";; *) echo "no result";; esac
    }
    # Without a TD that really ran, nothing below is BLOCKED. It is undecided (see 19).
    case "${vm_line}" in *TDX*) v=PASS;; *) v=FAIL;; esac
    record "td is a TDX pod VM" "TDX" "$(echo "${vm_line:-none}" | awk '{print $2}')" "${v}"
    for pair in "gateway.${NAMESPACE}.svc.cluster.local:8443|reached|td -> gateway:8443" \
                "kube-dns.kube-system.svc.cluster.local:53|reached|td -> kube-dns:53" \
                "api.duffel.com:443|no route|td -> api.duffel.com:443" \
                "openbao.${NAMESPACE}.svc.cluster.local:8200|no route|td -> openbao:8200" \
                "gateway-observe.${NAMESPACE}.svc.cluster.local:8444|no route|td -> gateway-observe:8444" \
                "1.1.1.1:443|no route|td -> 1.1.1.1:443" \
                "169.254.169.254:80|no route|td -> 169.254.169.254:80"; do
      IFS='|' read -r target expected name <<< "${pair}"
      obs="$(td_obs "${target}")"
      [ "${obs}" = "${expected}" ] && v=PASS || v=FAIL
      record "${name}" "${expected}" "${obs}" "${v}"
    done
    obs="$(grep -E '^PROBE SATOKEN ' "${TD_LOG}" | awk '{print $3}' | head -1)"
    [ "${obs}" = "absent" ] && v=PASS || v=FAIL
    record "td has a SA token" "absent" "${obs:-no result}" "${v}"
    kubectl -n "${NAMESPACE}" delete pod "${TD_POD}" --ignore-not-found --wait=false >/dev/null
    say "TD probe log: ${TD_LOG}"
  fi
fi

say "the gateway's position: its own pod, its own code, its own credentials"

gw_python() {  # a snippet that prints one word
  kubectl -n "${NAMESPACE}" exec deploy/gateway -- python3 -c "$1" 2>/dev/null || echo "error"
}

obs="$(gw_python '
import os, urllib.request
addr = os.environ.get("BAO_ADDR", "")
try:
    with urllib.request.urlopen(addr + "/v1/sys/health?standbyok=true", timeout=5) as r:
        print("reached" if r.status < 500 else "unhealthy")
except Exception:
    print("no route")')"
[ "${obs}" = "reached" ] && v=PASS || v=FAIL
record "gateway -> openbao:8200" "reached" "${obs}" "${v}"

obs="$(gw_python '
from booking_live.secrets import secret_source_from_env
try:
    src = secret_source_from_env()
    print("holds" if (src.read("DUFFEL_TOKEN") or src.read("SERPAPI_KEY")) else "empty")
except Exception as e:
    print(type(e).__name__)')"
[ "${obs}" = "holds" ] && v=PASS || v=FAIL
record "gateway reads its credential" "holds" "${obs}" "${v}"

# The gateway's OpenBao identity is the k8s-auth role, not the dev-mode root token. Its client
# token must carry no root policy and must be refused outside secret/data/agent. Only one word
# is printed, so the token itself stays in the pod.
obs="$(gw_python '
import os
from booking_live.secrets import BaoSecrets, secret_source_from_env
src = secret_source_from_env()
if os.environ.get("BAO_TOKEN") or not isinstance(src, BaoSecrets) or not src.role:
    print("static-token")
else:
    tok = src._authenticated()
    h = {"X-Vault-Token": tok}
    st, body = src._call("GET", src.address + "/v1/auth/token/lookup-self", headers=h)
    pols = set(((body or {}).get("data") or {}).get("policies") or [])
    other, _ = src._call("GET", src.address + "/v1/sys/policies/acl", headers=h)
    print("least-privilege" if st == 200 and "root" not in pols and other == 403
          else "root" if "root" in pols else f"other-{st}-{other}")')"
[ "${obs}" = "least-privilege" ] && v=PASS || v=FAIL
record "gateway OpenBao identity" "least-privilege" "${obs}" "${v}"

# Test Mode is enforced by the deployed adapter, not assumed: a live-mode token is refused
# before any transport exists. Checked against the code in the gateway pod, with a dummy
# token (the real one is not touched).
obs="$(gw_python '
from booking_live.duffel import LiveModeRefused, require_test_mode
try:
    require_test_mode("duffel_live_" + "0" * 20)
    print("accepted")
except LiveModeRefused:
    print("refused")')"
[ "${obs}" = "refused" ] && v=PASS || v=FAIL
record "gateway with a live-mode token" "refused" "${obs}" "${v}"

obs="$(gw_python '
import socket
try:
    socket.create_connection(("api.duffel.com", 443), timeout=8).close()
    print("reached")
except Exception:
    print("no route")')"
[ "${obs}" = "reached" ] && v=PASS || v=FAIL
record "gateway -> api.duffel.com:443" "reached" "${obs}" "${v}"

# The application layer, against the deployed code. The network would allow this host.
obs="$(gw_python '
from booking_live.world import RequestsTransport, HostNotAllowed
try:
    RequestsTransport()._check("https://evil.example/air/orders")
    print("allowed")
except HostNotAllowed:
    print("app-layer denied")')"
[ "${obs}" = "app-layer denied" ] && v=PASS || v=FAIL
record "gateway -> evil.example:443" "app-layer denied" "${obs}" "${v}"

obs="$(gw_python '
import inspect
from booking_live.world import RequestsTransport
print("not followed" if "allow_redirects=False" in inspect.getsource(RequestsTransport.request) else "followed")')"
[ "${obs}" = "not followed" ] && v=PASS || v=FAIL
record "gateway redirects (source check)" "not followed" "${obs}" "${v}"

obs="$(gw_python '
from booking_live.world import RequestsTransport, HostNotAllowed
try:
    RequestsTransport()._check("http://api.duffel.com/air/orders")
    print("allowed")
except HostNotAllowed:
    print("plain http denied")')"
[ "${obs}" = "plain http denied" ] && v=PASS || v=FAIL
record "gateway -> http (not https)" "plain http denied" "${obs}" "${v}"

# The approval gate, from the controller's position and with what a compromised
# controller holds: its own context and port-forwards, the HMAC constant every image carries,
# a policy. It must neither create a run nor approve a step, and a key the Authority has not
# pinned must not pass on the approval page. And it must not be able to change who is pinned.
gate="$(cd "${MOCKS_DIR}" && python3 -m booking_approval.probe_controller --context v5-controller 2>/dev/null || echo '{}')"
for c in "create_run with the HMAC constant" "decide_intervention" "forged assertion on the approval page"; do
  obs="$(printf '%s' "${gate}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], "not run"))' "${c}")"
  [ "${obs}" = "refused" ] && v=PASS || v=FAIL
  record "controller: ${c}" "refused" "${obs}" "${v}"
done
if kubectl --context v5-controller auth can-i update configmaps -n "${NAMESPACE}" >/dev/null 2>&1; then obs="yes"; else obs="no"; fi
[ "${obs}" = "no" ] && v=PASS || v=FAIL
record "controller can change the approver set" "no" "${obs}" "${v}"

kubectl -n "${NAMESPACE}" delete pod "${PROBE_POD}" --ignore-not-found --wait=false >/dev/null

{
  printf '{\n  "stamp": "%s",\n  "cluster": "%s",\n  "namespace": "%s",\n' \
    "${STAMP}" "${CLUSTER}" "${NAMESPACE}"
  printf '  "passed": %d,\n  "failed": %d,\n  "cases": [\n    ' "${PASS}" "${FAIL}"
  printf '%s' "$(IFS=$'\n'; echo "${RESULTS[*]}" | paste -sd, - | sed 's/,/,\n    /g')"
  printf '\n  ]\n}\n'
} > "${REPORT}"

printf '\n  %d passed, %d failed\n' "${PASS}" "${FAIL}"
say "recorded: ${REPORT}"
[ "${FAIL}" -eq 0 ] || die "negative evidence incomplete: ${FAIL} case(s) did not hold"
