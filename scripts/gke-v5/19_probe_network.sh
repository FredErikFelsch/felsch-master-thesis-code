#!/usr/bin/env bash
# 19_probe_network.sh: probes the runner network boundary per path, in throwaway namespaces.
#
# Needs:  The cluster with peer pods (14), the firewall policy from 12, the patched rules from 13
#         (results_v5/genpolicy-<kata>/rules.patched.rego), the NetworkPolicy manifest, kubectl,
#         gcloud, python3 with booking_v5.
# Usage:  ./scripts/gke-v5/19_probe_network.sh
#         PROBE_IMAGE and PEER_TIMEOUT override the probe image and the peer-pod wait.
#         KEEP_V5_PROBES=1 skips the cleanup for a post-mortem.
# Result: results_v5/probe/network-<stamp>.txt with one block per probe and the verdict lines
#         SUBNET_OK, SUBNET_MISSING or SUBNET_UNDECIDED and A5C_CLOSED, A5C_OPEN or A5C_UNDECIDED.
#
# The boundary, per path:
#   A5   tunnelled peer-pod networking (CoCo default): pod egress goes through the
#        worker's pod netns, so NetworkPolicy runner-egress must confine it as it does
#        a regular pod.
#   A5b  optional direct pod-VM egress (CoCo's external-networking mode, experimental):
#        only the VPC firewall can confine it. This half is judged only if that mode is
#        shown to be enabled. Otherwise it is reported as NOT_APPLICABLE, not as passed.
# It also checks that the pod VM's NIC sits in the pod-VM subnet, because a firewall policy keyed
# on a CIDR that no VM is in protects nothing. Uses the V4.4c policy set in a throwaway namespace.
# (A5, A5b and A5c are attack labels, see attack_catalogue.md.)
#
# An empty peer-pod block does not count as a result. A TD guest-pulls its image itself and its
# NIC only reaches private.googleapis.com (firewall policy from 12), so a docker.io image never
# arrives. The wait then runs out and `logs` has nothing to say. The probe therefore uses a
# mirror.gcr.io image (as in 18), waits 600 s, and always prints the pod phase and the last event.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
NS="v5-netprobe"; NS_OPEN="v5-netprobe-open"
OUT="${MOCKS_DIR}/results_v5/probe"; mkdir -p "${OUT}"; STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="${OUT}/network-${STAMP}.txt"

# The probe namespaces are removed on every exit: normal end, a `die`, or Ctrl-C. The trap is
# registered before either namespace exists, so a failure partway through the setup below still
# cleans up whatever got created. KEEP_V5_PROBES=1 skips this for a post-mortem.
cleanup_network_probes() {
  if [ "${KEEP_V5_PROBES:-0}" = "1" ]; then say "cleanup SKIPPED (KEEP_V5_PROBES=1)"; return; fi
  local ns
  for ns in "${NS}" "${NS_OPEN}"; do
    say "cleanup: removing ${ns} probe resources"
    kubectl -n "${ns}" delete pod --all --wait=false >/dev/null 2>&1 || true
    kubectl -n "${ns}" delete peerpods.confidentialcontainers.org --all --wait=false >/dev/null 2>&1 || true
    kubectl delete namespace "${ns}" --wait=false >/dev/null 2>&1 || true
  done
}
trap cleanup_network_probes EXIT

# Guest pull inside the TD: Docker Hub is unreachable, Google's mirror is (see 18).
PROBE_IMAGE="${PROBE_IMAGE:-mirror.gcr.io/library/busybox:1.36}"
PEER_TIMEOUT="${PEER_TIMEOUT:-600s}"
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
sed "s/namespace: agent-system/namespace: ${NS}/" "${APPLY_DIR}/networkpolicy.yaml" | kubectl apply -f - >/dev/null
kubectl -n "${NS}" run canary --image="${PROBE_IMAGE}" --labels=app=netcanary --restart=Never \
  -- sh -c 'while true; do nc -lk -p 9000; done' >/dev/null 2>&1 || true
kubectl -n "${NS}" expose pod canary --port 9000 --name canary >/dev/null 2>&1 || true
CANARY_IP="$(kubectl -n "${NS}" get svc canary -o jsonpath='{.spec.clusterIP}')"
CANARY_FQDN="canary.${NS}.svc.cluster.local"

# Control namespace without any NetworkPolicy: separates "policy blocks it" from
# "peer-pod plumbing (tunnel, ClusterIP translation) does not deliver it".
# The control must target a canary in its own namespace. Otherwise target-side policy in
# ${NS} would contaminate the no-policy baseline.
kubectl create namespace "${NS_OPEN}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "${NS_OPEN}" delete networkpolicy --all >/dev/null 2>&1 || true
kubectl -n "${NS_OPEN}" run canary --image="${PROBE_IMAGE}" --labels=app=netcanary --restart=Never \
  -- sh -c 'while true; do nc -lk -p 9000; done' >/dev/null 2>&1 || true
kubectl -n "${NS_OPEN}" expose pod canary --port 9000 --name canary >/dev/null 2>&1 || true
CANARY_OPEN_IP="$(kubectl -n "${NS_OPEN}" get svc canary -o jsonpath='{.spec.clusterIP}')"
CANARY_OPEN_FQDN="canary.${NS_OPEN}.svc.cluster.local"

# kube-dns pod IP (not the Service IP): tells ClusterIP translation apart from raw reachability.
KUBEDNS_POD_IP="$(kubectl -n kube-system get pods -l k8s-app=kube-dns -o jsonpath='{.items[0].status.podIP}')"

# --- overrides for the two pod kinds ------------------------------------------------------
# On the V5 pod-VM overlay the init-data is measured at boot. A network probe is not about
# policy enforcement, so it carries a permissive policy (booking_v5.permissive_policy,
# derived from the pinned rules.rego). That is enough to satisfy the measured boot path, and it
# cannot be confused with the runner: its init-data digest goes into RTMR3, so such a TD's
# evidence is refused by the Authority's reference pin.
# On a pre-overlay image the annotation is harmless, so it is set unconditionally.
OV_REGULAR='{"spec":{"automountServiceAccountToken":false}}'
RULES_REGO="${MOCKS_DIR}/results_v5/genpolicy-${KATA_VERSION}/rules.patched.rego"
[ -f "${RULES_REGO}" ] || die "no ${RULES_REGO}: run 13_genpolicy.sh once so the pinned rules are present"
OV_PEER="$(RULES_REGO="${RULES_REGO}" PROBE_IMAGE="${PROBE_IMAGE}" MOCKS_DIR="${MOCKS_DIR}" python3 - <<'PY'
import json, os, sys
sys.path.insert(0, os.environ["MOCKS_DIR"])
from booking_v5.permissive_policy import permissive_policy
from booking_v5.profile_v5 import INIT_DATA_ANNOTATION, init_data_annotation_value, init_data_document, init_data_hash
with open(os.environ["RULES_REGO"]) as fh:
    doc = init_data_document(os.environ["PROBE_IMAGE"], policy_rego=permissive_policy(fh.read()))
print(json.dumps({
    "metadata": {"annotations": {INIT_DATA_ANNOTATION: init_data_annotation_value(doc),
                                 "v5/init-data-sha256": init_data_hash(doc),
                                 "v5/policy": "PERMISSIVE-probe-only"}},
    "spec": {"runtimeClassName": "kata-remote", "automountServiceAccountToken": False}}))
PY
)"
[ -n "${OV_PEER}" ] || die "could not build the peer-pod init-data override"

# probe LABEL OVERRIDES_JSON TIMEOUT [NAMESPACE]
#   -> prints pod phase, last event, then OPEN/BLOCKED per target and the route table
probe() {
  local label="$1" overrides="$2" timeout="$3" ns="${4:-${NS}}" t0 t1 phase
  local canary_fqdn="${CANARY_FQDN}" canary_ip="${CANARY_IP}"
  if [ "${ns}" = "${NS_OPEN}" ]; then
    canary_fqdn="${CANARY_OPEN_FQDN}"
    canary_ip="${CANARY_OPEN_IP}"
  fi

  kubectl -n "${ns}" delete pod np --ignore-not-found --wait=true >/dev/null
  t0=$(date +%s)
  kubectl -n "${ns}" run np --restart=Never --image="${PROBE_IMAGE}" --labels=app=runner \
    --overrides="${overrides}" -- sh -c "
      for t in '${canary_fqdn} 9000' '${canary_ip} 9000' '1.1.1.1 443' 'kube-dns.kube-system.svc.cluster.local 53' '${KUBEDNS_POD_IP} 53' '169.254.169.254 80'; do
        set -- \$t; r=BLOCKED
        for i in 1 2 3; do nc -z -w 3 \$1 \$2 && { r=OPEN; break; }; sleep 1; done
        echo \"\$r \$1:\$2\" | sed 's/^OPEN /OPEN    /'; done
      echo '-- routes --'; ip route 2>/dev/null | head -5; echo '-- addrs --'; ip -4 addr 2>/dev/null | grep inet" >/dev/null
  local deadline=$(( t0 + ${timeout%s} )) vm_line=""
  while :; do
    phase="$(kubectl -n "${ns}" get pod np -o jsonpath='{.status.phase}' 2>/dev/null || echo UNKNOWN)"
    [ "${phase}" = "Succeeded" ] || [ "${phase}" = "Failed" ] && break
    [ "$(date +%s)" -lt "${deadline}" ] || break
    # peer pod: capture NIC subnet, IP and service account once, while the VM is alive
    if [ -z "${vm_line}" ] && printf '%s' "${overrides}" | grep -q kata-remote; then
      vm_line="$(gcloud compute instances list --project "${PROJECT}" --filter="name~^podvm-np-" \
        --format='value(name,networkInterfaces[0].subnetwork.basename(),networkInterfaces[0].networkIP,serviceAccounts[0].email)' 2>/dev/null | head -1)"
    fi
    sleep 5
  done
  t1=$(date +%s)
  echo "== ${label} =="
  [ -z "${vm_line}" ] || echo "-- pod VM (captured while alive): ${vm_line}"
  echo "-- pod: ns=${ns} phase=${phase} after $((t1-t0)) s, last event: $(kubectl -n "${ns}" get events --field-selector involvedObject.name=np \
        --sort-by=.lastTimestamp -o jsonpath='{.items[-1:].reason}: {.items[-1:].message}' 2>/dev/null | tail -c 300)"
  if [ "${phase}" = "Succeeded" ] || [ "${phase}" = "Failed" ]; then kubectl -n "${ns}" logs np 2>&1
  else echo "NO_RESULT (pod never ran, the verdict for this path is UNDECIDED, not BLOCKED)"; fi
}

{
  probe "regular pod (baseline: A5 as in V4.4c)" "${OV_REGULAR}" 180s
  probe "peer pod, tunnelled networking (A5)" "${OV_PEER}" "${PEER_TIMEOUT}"
  probe "CONTROL regular pod, no policy (plumbing baseline)" "${OV_REGULAR}" 180s "${NS_OPEN}"
  probe "CONTROL peer pod, no policy (tunnel + ClusterIP translation without policy)" "${OV_PEER}" "${PEER_TIMEOUT}" "${NS_OPEN}"
  echo "== pod VM NIC / service account (A5b precondition: NIC in ${PODVM_SUBNET_CIDR}, metadata exposure: SA on the VM) =="
  echo "   see the '-- pod VM (captured while alive)' lines above. The CAA deletes each pod VM as soon as its pod finishes"
  echo "== direct external networking enabled? (A5b precondition, CAA config) =="
  # Only external-networking settings count. GCP_NETWORK/GCP_SUBNETWORK are the tunnel substrate, not the mode.
  kubectl -n confidential-containers-system get cm peer-pods-cm -o yaml 2>/dev/null | grep -iE "EXTERNAL" \
    || echo "no external-networking setting found -> A5b NOT_APPLICABLE (tunnelled mode)"
  echo "== A5b firewall policy as deployed (deny all direct TD egress, allow only the Google API VIP) =="
  # describe carries the rules, because gcloud has no `rules list` for this resource
  gcloud compute network-firewall-policies describe "${FW_POLICY}" --global --project "${PROJECT}" \
    --format="table(rules.priority,rules.direction,rules.action,rules.match.srcIpRanges.list(),rules.match.destIpRanges.list(),rules.match.layer4Configs.list())" 2>/dev/null \
    || echo "policy ${FW_POLICY} not found"
} | tee "${LOG}"

if grep -qE "captured while alive.*podvm-np-\S+\s+${PODVM_SUBNET}\s" "${LOG}"; then echo "SUBNET_OK ${PODVM_SUBNET}" | tee -a "${LOG}"
elif ! grep -q "captured while alive" "${LOG}"; then echo "SUBNET_UNDECIDED: no pod VM was observed while alive (peer-pod probe never created one, or it lived shorter than one poll)" | tee -a "${LOG}"
else echo "SUBNET_MISSING: pod VMs are not in ${PODVM_SUBNET}. The A5b firewall policy does not apply to them" | tee -a "${LOG}"; fi
# A5c: the pod VM's metadata server as seen from the peer pod under policy. It is judged here,
# not only printed, so that a lost hardening cannot go unnoticed. Only the "peer pod, tunnelled
# networking (A5)" block counts.
a5c_line="$(awk '/^== peer pod, tunnelled networking \(A5\) ==/{on=1; next} /^== /{on=0} on && /169\.254\.169\.254:80/' "${LOG}" | head -1)"
case "${a5c_line}" in
  BLOCKED*) echo "A5C_CLOSED (peer pod under policy: ${a5c_line})" | tee -a "${LOG}" ;;
  OPEN*)    echo "A5C_OPEN (peer pod under policy: ${a5c_line}): the pod VM's metadata server is reachable from the TD" | tee -a "${LOG}" ;;
  *)        echo "A5C_UNDECIDED (no metadata line in the peer-pod block)" | tee -a "${LOG}" ;;
esac
say "verdict lines are in ${LOG}. A5: the policy probes must agree (canary BLOCKED, 1.1.1.1 BLOCKED, DNS OPEN). The CONTROL probes show what the substrate delivers without policy"
say "A5b: judged only when direct external networking is enabled and SUBNET_OK holds. Then re-run the peer-pod probe with and without the deny rule in ${FW_POLICY}"
