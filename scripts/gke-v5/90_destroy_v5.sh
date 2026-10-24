#!/usr/bin/env bash
# 90_destroy_v5.sh: destroys the V5 evaluation environment completely (mirror of gke/90 for V4.4c).
#
# Needs:  gcloud, kubectl, and the pins from _config.sh.
# Usage:  ./scripts/gke-v5/90_destroy_v5.sh [--purge-image]
# Result: An environment record under results_v5/environment/destroyed-<stamp>.env, and the
#         environment removed. Idempotent: every missing resource is reported, not an error.
#
# The environment is created from version-controlled scripts (12, 15, 14) and can be destroyed
# completely after an experiment. A later re-run must rebuild it from
# nothing. This removes, in dependency order: peer pods (so the CAA deletes their TDX VMs), the
# cluster, orphaned pod VMs, the tunnel firewall rules, the A5b firewall policy (association,
# rules, policy), the private DNS zones and the pod-VM subnet.
#
# Kept by default (slow or identity-bearing, not part of an experiment's state):
#   * the pod-VM image ${PODVM_IMAGE} (11 takes 30 to 60 min)   -> --purge-image
#   * the peerpods service account and its IAM bindings          -> never (12 reuses it)
#   * Artifact Registry images (V4.4c 90 handles them)           -> never here
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
PURGE_IMAGE=0; [ "${1:-}" = "--purge-image" ] && PURGE_IMAGE=1
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"; ENV_DIR="${MOCKS_DIR}/results_v5/environment"; mkdir -p "${ENV_DIR}"

# Record what is being destroyed: the pins describe the executed environment and stay
# valid evidence after the resources are gone.
{
  echo "destroyed_at=${STAMP}"; echo "cluster=${CLUSTER}"; echo "zone=${ZONE}"
  echo "caa_version=${CAA_VERSION}"; echo "kata_version=${KATA_VERSION}"; echo "podvm_image=${PODVM_IMAGE}"
  echo "podvm_machine=${PODVM_MACHINE}"; echo "podvm_confidential_type=${PODVM_CONFIDENTIAL_TYPE}"
  echo "podvm_subnet=${PODVM_SUBNET} ${PODVM_SUBNET_CIDR}"; echo "fw_policy=${FW_POLICY}"
  echo "trustee_version=${TRUSTEE_VERSION:-not-installed}"
} > "${ENV_DIR}/destroyed-${STAMP}.env"
say "environment record: ${ENV_DIR}/destroyed-${STAMP}.env"

# --- 1. peer pods first, so the CAA removes their VMs while it still runs -----------------
if gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" >/dev/null 2>&1; then
  gcloud container clusters get-credentials "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" >/dev/null 2>&1 || true
  say "deleting every kata-remote pod so the CAA tears down the pod VMs"
  kubectl get pods -A -o jsonpath='{range .items[?(@.spec.runtimeClassName=="kata-remote")]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}' 2>/dev/null | \
    while read -r ns name; do [ -n "${name}" ] && kubectl -n "${ns}" delete pod "${name}" --wait=false >/dev/null 2>&1 || true; done
  for _ in $(seq 1 18); do
    [ "$(gcloud compute instances list --project "${PROJECT}" --filter="name~^podvm-" --format='value(name)' | wc -l | tr -d ' ')" = "0" ] && break; sleep 10
  done
  say "deleting cluster ${CLUSTER} (removes all namespaces, the CoCo install and the secrets)"
  gcloud container clusters delete "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --quiet
else
  say "cluster ${CLUSTER} not found, nothing to delete"
fi

# --- 2. orphaned pod VMs (CAA gone before it could delete them) --------------------------
gcloud compute instances list --project "${PROJECT}" --filter="name~^podvm-" --format='value(name,zone.basename())' | \
  while read -r name zone; do [ -n "${name}" ] && { say "deleting orphaned pod VM ${name}"; gcloud compute instances delete "${name}" --zone "${zone}" --project "${PROJECT}" --quiet; }; done

# --- 3. firewall: VPC rules, then the policy (association -> rules -> policy) -------------
for rule in v5-allow-peerpod-tunnel v5-allow-peerpod-tunnel-return; do
  gcloud compute firewall-rules describe "${rule}" --project "${PROJECT}" >/dev/null 2>&1 && \
    { say "deleting firewall rule ${rule}"; gcloud compute firewall-rules delete "${rule}" --project "${PROJECT}" --quiet; } || say "firewall rule ${rule} not found"
done
if gcloud compute network-firewall-policies describe "${FW_POLICY}" --global --project "${PROJECT}" >/dev/null 2>&1; then
  for assoc in $(gcloud compute network-firewall-policies describe "${FW_POLICY}" --global --project "${PROJECT}" --format='value(associations[].name)' | tr ';' ' '); do
    say "removing association ${assoc}"
    gcloud compute network-firewall-policies associations delete --firewall-policy "${FW_POLICY}" --global-firewall-policy --name "${assoc}" --project "${PROJECT}" --quiet || true
  done
  for prio in $(gcloud compute network-firewall-policies describe "${FW_POLICY}" --global --project "${PROJECT}" --format='value(rules[].priority)' | tr ';' ' '); do
    [ "${prio}" -ge 2147483644 ] && continue   # the four implicit goto_next rules cannot be deleted
    gcloud compute network-firewall-policies rules delete "${prio}" --firewall-policy "${FW_POLICY}" --global-firewall-policy --project "${PROJECT}" --quiet || true
  done
  say "deleting firewall policy ${FW_POLICY}"
  gcloud compute network-firewall-policies delete "${FW_POLICY}" --global --project "${PROJECT}" --quiet
else say "firewall policy ${FW_POLICY} not found"; fi

# --- 4. private DNS zones (records first, the zone refuses to go while non-empty) --------
for zone in v5-googleapis v5-pkgdev v5-gcrio; do
  gcloud dns managed-zones describe "${zone}" --project "${PROJECT}" >/dev/null 2>&1 || { say "DNS zone ${zone} not found"; continue; }
  gcloud dns record-sets list --zone "${zone}" --project "${PROJECT}" --format='value(name,type)' | \
    while read -r name type; do
      case "${type}" in NS|SOA) continue ;; esac
      gcloud dns record-sets delete "${name}" --type "${type}" --zone "${zone}" --project "${PROJECT}" --quiet >/dev/null || true
    done
  say "deleting DNS zone ${zone}"; gcloud dns managed-zones delete "${zone}" --project "${PROJECT}" --quiet
done

# --- 5. pod-VM subnet (last: every VM in it must be gone) --------------------------------
gcloud compute networks subnets describe "${PODVM_SUBNET}" --region "${REGION}" --project "${PROJECT}" >/dev/null 2>&1 && \
  { say "deleting subnet ${PODVM_SUBNET}"; gcloud compute networks subnets delete "${PODVM_SUBNET}" --region "${REGION}" --project "${PROJECT}" --quiet; } || say "subnet ${PODVM_SUBNET} not found"

# --- 6. optional: the pod-VM image ------------------------------------------------------
if [ "${PURGE_IMAGE}" = "1" ] && [ -n "${PODVM_IMAGE}" ]; then
  gcloud compute images describe "${PODVM_IMAGE}" --project "${PODVM_IMAGE_PROJECT}" >/dev/null 2>&1 && \
    { say "purging pod-VM image ${PODVM_IMAGE}"; gcloud compute images delete "${PODVM_IMAGE}" --project "${PODVM_IMAGE_PROJECT}" --quiet; } || say "image ${PODVM_IMAGE} not found"
else say "pod-VM image ${PODVM_IMAGE} kept (pass --purge-image to remove it, 11 rebuilds it in 30 to 60 min)"; fi

say "remaining compute instances in ${PROJECT}:"; gcloud compute instances list --project "${PROJECT}" --format='table(name,status,zone.basename())' || true
say "V5 environment destroyed. Rebuild: 12 -> 15 -> 14 -> 18 -> 19."
