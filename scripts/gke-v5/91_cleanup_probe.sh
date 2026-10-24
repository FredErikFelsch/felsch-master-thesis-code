#!/usr/bin/env bash
# 91_cleanup_probe.sh: removes everything the probes (18, 19, manual diagnosis) left behind and verifies the substrate.
#
# Needs:  gcloud and kubectl with the cluster reachable, and the pins from _config.sh.
# Usage:  ./91_cleanup_probe.sh                 clean and verify
#         ./91_cleanup_probe.sh --force-orphans also delete pod VMs no pod owns any more
# Result: Probe pods, namespaces, stale PeerPod CRs and node-debugger pods removed, without touching
#         the cluster, the CoCo installation or the substrate (subnet, firewall, DNS). Then a check
#         that the substrate matches what 12 declares, so the next run starts from a known state.
#         Exit code non zero if the substrate drifted. Idempotent and safe to run at any time.
#
# Every peer pod is a running c3-standard-4 TDX instance: a forgotten probe pod costs
# money by the hour. The CAA deletes the VM when the pod goes. Orphans (CAA restarted
# while a pod existed) stay behind and are only reported unless --force-orphans is given.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
source "$(dirname "${BASH_SOURCE[0]}")/_peerpod_cleanup.sh"
require_project
FORCE_ORPHANS=0; [ "${1:-}" = "--force-orphans" ] && FORCE_ORPHANS=1

PROBE_NAMESPACES=(v5-probe v5-netprobe v5-netprobe-open)

# --- 1. probe pods and namespaces ------------------------------------------------------
say "cleanup: probe namespaces ${PROBE_NAMESPACES[*]} (peer pods inside are deleted first, so the CAA removes their VMs)"
# A peer pod whose sandbox never came up has nothing to unwind and stays in Terminating
# forever, so `--wait=true` here means "block for the full timeout on the very pods this
# cleanup exists for". Ask politely, wait a bounded 60 s so a healthy pod can shut down and
# let the CAA delete its VM, then force what is left. The VMs of force-removed pods are
# caught in step 2 as orphans.
for ns in "${PROBE_NAMESPACES[@]}"; do
  kubectl get namespace "${ns}" >/dev/null 2>&1 || continue
  kubectl -n "${ns}" delete pod --all --wait=false >/dev/null 2>&1 || true
done
for _ in $(seq 1 30); do
  left=0
  for ns in "${PROBE_NAMESPACES[@]}"; do
    kubectl get namespace "${ns}" >/dev/null 2>&1 || continue
    [ -n "$({ kubectl -n "${ns}" get pod -o name 2>/dev/null || true; })" ] && left=1
  done
  [ "${left}" = "0" ] && break
  sleep 2
done
for ns in "${PROBE_NAMESPACES[@]}"; do
  kubectl get namespace "${ns}" >/dev/null 2>&1 || continue
  stuck="$({ kubectl -n "${ns}" get pod -o name 2>/dev/null || true; })"
  if [ -n "${stuck}" ]; then
    say "  ${ns}: still Terminating after 60 s, force-removing: $(printf '%s ' ${stuck})"
    kubectl -n "${ns}" delete pod --all --grace-period=0 --force >/dev/null 2>&1 || true
  fi
  kubectl delete namespace "${ns}" --wait=false >/dev/null 2>&1 || true
done
# --- 1b. peer pods outside the probe namespaces ----------------------------------------
# The runners live in agent-system, so a run that died between spawn and destroy leaves a
# pod the loop above never sees. Same rule as the controller: terminal pods only, and a
# finalizer comes off only once GCE confirms the VM is gone.
clear_stale_peer_pods

say "cleanup: node-debugger pods (kubectl debug node/…) in every namespace"
# (pipefail: grep/awk without a match must not end the script)
{ kubectl get pods -A 2>/dev/null | awk '/node-debugger/ {print $1" "$2}' || true; } | \
  while read -r ns name; do [ -n "${name}" ] && kubectl -n "${ns}" delete pod "${name}" --wait=false >/dev/null 2>&1 || true; done

# --- 2. pod VMs: wait for the CAA, then report or remove orphans -----------------------
say "cleanup: waiting up to 180 s for the CAA to delete the pod VMs of the removed pods"
for _ in $(seq 1 18); do
  n="$(gcloud compute instances list --project "${PROJECT}" --filter="name~^podvm-" --format='value(name)' | wc -l | tr -d ' ')"
  [ "${n}" = "0" ] && break; sleep 10
done
orphans="$(gcloud compute instances list --project "${PROJECT}" --filter="name~^podvm-" --format='value(name,zone.basename())' || true)"
if [ -n "${orphans}" ]; then
  # A pod VM is an orphan when no kata-remote pod in the cluster is left at all, or when
  # its name does not match any existing pod (podvm-<pod name>-<hash>).
  live_pods="$(kubectl get pods -A -o jsonpath='{range .items[?(@.spec.runtimeClassName=="kata-remote")]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
  while read -r name zone; do
    pod="${name#podvm-}"; pod="${pod%-*}"
    if grep -qx "${pod}" <<<"${live_pods}"; then say "pod VM ${name} belongs to live pod ${pod}, kept"; continue; fi
    if [ "${FORCE_ORPHANS}" = "1" ]; then
      say "deleting orphan pod VM ${name} (${zone})"
      gcloud compute instances delete "${name}" --zone "${zone}" --project "${PROJECT}" --quiet
    else
      say "ORPHAN pod VM ${name} (${zone}): a running c3 TDX instance without a pod. Re-run with --force-orphans to delete it"
    fi
  done <<<"${orphans}"
fi

# --- 2b. PeerPod CRs: the peerpod-ctrl finalizer (peer.pod/finalizer) keeps a namespace
# Terminating until the VM is confirmed gone. Once GCE shows no instance for a CR, the
# finalizer is only ballast (for example 4 CRs, 0 VMs and a namespace stuck for hours).
say "cleanup: PeerPod CRs whose VM no longer exists (finalizer removed), then wait for the namespaces to disappear"
for ns in "${PROBE_NAMESPACES[@]}"; do
  kubectl get namespace "${ns}" >/dev/null 2>&1 || continue
  for pp in $(kubectl -n "${ns}" get peerpods.confidentialcontainers.org -o name 2>/dev/null); do
    inst="$(kubectl -n "${ns}" get "${pp}" -o jsonpath='{.spec.instanceID}' 2>/dev/null || true)"
    if [ -n "${inst}" ] && gcloud compute instances list --project "${PROJECT}" --filter="id=${inst} OR name=${inst}" --format='value(name)' | grep -q .; then
      say "  ${ns}/${pp}: VM ${inst} still exists, leaving the finalizer to the controller"; continue
    fi
    kubectl -n "${ns}" patch "${pp}" --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1 || true
  done
done
for _ in $(seq 1 36); do
  left=0; for ns in "${PROBE_NAMESPACES[@]}"; do kubectl get namespace "${ns}" >/dev/null 2>&1 && left=1; done
  [ "${left}" = "0" ] && break; sleep 5
done
[ "${left:-0}" = "0" ] || say "WARNING: a probe namespace is still Terminating. 18 waits for it. Inspect with: kubectl get ns -o jsonpath='{.items[*].status.conditions}'"

# --- 3. substrate verification: what 12 declares must be what the project has -----------
say "verify: substrate state (as declared by 12_create_cluster_v5.sh)"
ok=1
check() { if eval "$2" >/dev/null 2>&1; then printf '  OK       %s\n' "$1"; else printf '  MISSING  %s\n' "$1"; ok=0; fi; }
NETWORK="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(network)' 2>/dev/null || true)"
check "cluster ${CLUSTER}"                       "[ -n '${NETWORK}' ]"
check "subnet ${PODVM_SUBNET} ${PODVM_SUBNET_CIDR}" "gcloud compute networks subnets describe ${PODVM_SUBNET} --region ${REGION} --project ${PROJECT} --format='value(ipCidrRange)' | grep -qx '${PODVM_SUBNET_CIDR}'"
check "fw v5-allow-peerpod-tunnel allows tcp:${PEERPOD_TUNNEL_PORT} and udp:${PEERPOD_VXLAN_PORT}" \
      "gcloud compute firewall-rules describe v5-allow-peerpod-tunnel --project ${PROJECT} --format='value(allowed)' | grep -q \"'${PEERPOD_TUNNEL_PORT}'\" && gcloud compute firewall-rules describe v5-allow-peerpod-tunnel --project ${PROJECT} --format='value(allowed)' | grep -q \"'${PEERPOD_VXLAN_PORT}'\""
check "fw v5-allow-peerpod-tunnel-return (VXLAN pod VM -> worker)" "gcloud compute firewall-rules describe v5-allow-peerpod-tunnel-return --project ${PROJECT}"
check "policy ${FW_POLICY} rule ${FW_PRIO_ALLOW_GOOGLEAPI} (allow Google API VIP)" "gcloud compute network-firewall-policies rules describe ${FW_PRIO_ALLOW_GOOGLEAPI} --firewall-policy ${FW_POLICY} --global-firewall-policy --project ${PROJECT}"
check "policy ${FW_POLICY} rule ${FW_PRIO_ALLOW_VXLAN} (allow VXLAN to node subnet)" "gcloud compute network-firewall-policies rules describe ${FW_PRIO_ALLOW_VXLAN} --firewall-policy ${FW_POLICY} --global-firewall-policy --project ${PROJECT}"
check "policy ${FW_POLICY} rule ${FW_PRIO_DENY} (deny all)" "gcloud compute network-firewall-policies rules describe ${FW_PRIO_DENY} --firewall-policy ${FW_POLICY} --global-firewall-policy --project ${PROJECT}"
check "policy ${FW_POLICY} associated with network ${NETWORK:-?}" "gcloud compute network-firewall-policies describe ${FW_POLICY} --global --project ${PROJECT} --format='value(associations.name)' | grep -q '${FW_POLICY}-'"
for z in v5-googleapis v5-pkgdev v5-gcrio; do check "private DNS zone ${z}" "gcloud dns managed-zones describe ${z} --project ${PROJECT}"; done
check "CAA DaemonSet ready" "kubectl -n confidential-containers-system rollout status ds/cloud-api-adaptor-daemonset --timeout=10s"
check "RuntimeClass kata-remote" "kubectl get runtimeclass kata-remote"
# The same match as 40 (whitespace-tolerant, config.d included). The loop runs in a subshell,
# because `exit` inside eval would otherwise end this script instead of failing the check.
check "containerd discard_unpacked_layers=false on every node" \
      "(for n in \$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do gcloud compute ssh \$n --zone ${ZONE} --project ${PROJECT} --quiet --command 'grep -Eqs \"^[[:space:]]*discard_unpacked_layers[[:space:]]*=[[:space:]]*false\" /etc/containerd/config.toml /etc/containerd/config.d/*.toml' || exit 1; done)"

# --- 4. what still costs money ----------------------------------------------------------
say "cost-relevant resources still running:"
gcloud compute instances list --project "${PROJECT}" --format='table(name,machineType.basename(),status,zone.basename())' --filter="status=RUNNING"
if [ "${ok}" = "1" ]; then say "clean: probes removed, substrate matches 12. Next: 20 (offline) needs no cluster, 90_destroy_v5.sh tears everything down."
else die "substrate drifted from 12. Re-run ./scripts/gke-v5/12_create_cluster_v5.sh (idempotent) and then 91 again"; fi
