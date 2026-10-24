#!/usr/bin/env bash
# 12_create_cluster_v5.sh: creates the GKE cluster for CoCo peer pods and the network policy around it.
#
# Needs:  gcloud, kubectl, python3, ssh access to the nodes through gcloud, and the settings from
#         _config.sh (project, location, node pin, firewall priorities, pod-VM subnet). The script
#         validates them before it creates anything. Run 00_preflight_v5.sh first.
# Usage:  ./scripts/gke-v5/12_create_cluster_v5.sh
#         V5_MAINTENANCE_EXCLUSION=0 skips the upgrade exclusion, V5_EXCLUSION_DAYS=<n> sets its length.
# Result: One Ubuntu/containerd worker (the TDs are separate VMs) with Dataplane V2 and the
#         containerd patch peer pods need, a dedicated pod-VM subnet, the firewall policy that
#         confines direct pod-VM egress (A5b), and private DNS zones for the Google APIs.
#         kubectl points at the cluster afterwards. Safe to rerun: security relevant resources
#         are reconciled, not just created.
#
# The patch step uses `gcloud compute ssh`. It is the one place where a node is touched by hand,
# and it is scripted so that it is reproducible and recorded.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

# Validate every config value this script depends on before creating resources
# (`set -u` would catch a missing one too, but only after the cluster exists).
: "${FW_PRIO_ALLOW:?FW_PRIO_ALLOW not set}"
: "${FW_PRIO_DENY:?FW_PRIO_DENY not set}"
: "${FW_POLICY:?FW_POLICY not set}"
: "${PODVM_SUBNET:?PODVM_SUBNET not set}"
: "${PODVM_SUBNET_CIDR:?PODVM_SUBNET_CIDR not set}"
: "${PEERPOD_TUNNEL_PORT:?PEERPOD_TUNNEL_PORT not set}"
: "${NODE_IMAGE:?NODE_IMAGE not set}"
# Every allow priority must beat the deny, not just the base one: the policy carries two
# allows and a config like ALLOW=1000 / DENY=1001 would leave the second one at or behind the
# deny, where it does nothing. Also refuse duplicates, which would make one rule overwrite
# the other on `rules update`.
for prio in "${FW_PRIO_ALLOWS[@]}"; do
  [ "${prio}" -lt "${FW_PRIO_DENY}" ] || die "allow priority ${prio} must be smaller than FW_PRIO_DENY (${FW_PRIO_DENY}): GCP evaluates the lower number first"
done
[ "$(printf '%s\n' "${FW_PRIO_ALLOWS[@]}" | sort -u | wc -l)" -eq "${#FW_PRIO_ALLOWS[@]}" ] || \
  die "duplicate allow priorities in FW_PRIO_ALLOWS (${FW_PRIO_ALLOWS[*]}): each policy rule needs its own"
[ "${FW_PRIO_DENY}" -lt 65535 ] || die "FW_PRIO_DENY must beat GCP's implied egress-allow at 65535"
[[ "${PODVM_SUBNET_CIDR}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]] || die "PODVM_SUBNET_CIDR is not a CIDR: ${PODVM_SUBNET_CIDR}"
[ "${NODE_IMAGE}" = "UBUNTU_CONTAINERD" ] || die "peer pods need NODE_IMAGE=UBUNTU_CONTAINERD (got ${NODE_IMAGE})"

say "enabling APIs"
gcloud services enable container.googleapis.com compute.googleapis.com artifactregistry.googleapis.com --project "${PROJECT}"

say "peerpods service account $(peerpods_sa) (becomes the node SA and with it the CAA's credentials, see _config.sh)"
ensure_peerpods_sa

if gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" >/dev/null 2>&1; then
  cluster_status="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(status)')"
  [ "${cluster_status}" = "RUNNING" ] || \
    die "cluster ${CLUSTER} exists but status=${cluster_status}. Delete or recover it before continuing"
  say "cluster ${CLUSTER} exists, refreshing credentials"
else
  say "creating ${CLUSTER} (${NUM_NODES}× ${NODE_MACHINE}, ${NODE_IMAGE}, Dataplane V2)"
  gcloud container clusters create "${CLUSTER}" \
    --project "${PROJECT}" \
    "${LOCATION_ARGS[@]}" \
    --enable-dataplane-v2 \
    --num-nodes "${NUM_NODES}" \
    --machine-type "${NODE_MACHINE}" \
    --image-type "${NODE_IMAGE}" \
    --disk-type pd-standard \
    --disk-size 50 \
    --no-enable-basic-auth \
    --enable-ip-alias \
    --workload-pool "${PROJECT}.svc.id.goog" \
    --no-enable-managed-prometheus \
    --logging=SYSTEM \
    --monitoring=SYSTEM \
    --release-channel regular \
    --no-enable-autorepair
fi
gcloud container clusters get-credentials "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}"

# Node auto-upgrades are part of the release-channel model and cannot be switched off per node
# pool while the cluster is enrolled in a channel. A recreated node comes back without the
# containerd patch below. Only the prechecks of 18 and 40 would notice, after the pod-VM image
# and the reference values were already frozen. A maintenance exclusion is the supported way to
# hold upgrades off for the duration of a measurement campaign.
#   V5_MAINTENANCE_EXCLUSION=0   skip it (short probing session)
#   V5_EXCLUSION_DAYS=<n>        how long to hold upgrades off (default 14)
if [ "${V5_MAINTENANCE_EXCLUSION:-1}" = "1" ]; then
  excl_name="${V5_EXCLUSION_NAME:-v5-freeze}"
  # The exclusion name is a dictionary key and may contain a dash, which a gcloud format projection
  # cannot address. Read the whole policy as JSON and pick the key out with python.
  excl_end="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" \
      --format=json 2>/dev/null | python3 -c '
import json, sys
name = sys.argv[1]
try:
    excl = json.load(sys.stdin).get("maintenancePolicy", {}).get("window", {}).get("maintenanceExclusions", {})
except Exception:
    excl = {}
print(excl.get(name, {}).get("endTime", ""))' "${excl_name}" || true)"
  now_rfc="$(python3 -c 'import datetime;print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
  if [ -n "${excl_end}" ] && [[ "${excl_end}" > "${now_rfc}" ]]; then
    say "maintenance exclusion ${excl_name} already holds until ${excl_end}"
  else
    end_rfc="$(python3 -c "import datetime,sys;print((datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=int(sys.argv[1]))).strftime('%Y-%m-%dT%H:%M:%SZ'))" "${V5_EXCLUSION_DAYS:-14}")"
    say "maintenance exclusion ${excl_name}: no minor or node upgrades until ${end_rfc} (the containerd patch does not survive a node recreation)"
    [ -n "${excl_end}" ] && gcloud container clusters update "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" \
      --remove-maintenance-exclusion "${excl_name}" >/dev/null 2>&1 || true
    gcloud container clusters update "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" \
      --add-maintenance-exclusion-name "${excl_name}" \
      --add-maintenance-exclusion-start "${now_rfc}" \
      --add-maintenance-exclusion-end "${end_rfc}" \
      --add-maintenance-exclusion-scope no_minor_or_node_upgrades >/dev/null || \
      say "WARNING: could not set the maintenance exclusion. A node recreation would silently remove the containerd patch. 18 rechecks it, but do not freeze reference values without it"
  fi
else
  say "maintenance exclusion SKIPPED (V5_MAINTENANCE_EXCLUSION=0): a node recreation removes the containerd patch"
fi

# Node pool with the peerpods SA and the cloud-platform scope (immutable per pool).
# GKE's default-pool is retired once ours is Ready. The CAA DaemonSet selects on the
# node label node.kubernetes.io/worker=, which gcloud refuses (reserved prefix) but
# kubectl sets fine (as in the CoCo docs). Done below after the nodes are Ready.
pool_exists() { gcloud container node-pools describe "$1" --cluster "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" >/dev/null 2>&1; }
if ! pool_exists "${NODE_POOL}"; then
  # Pinned to the node version the frozen policy was generated against (see _node_pin.sh).
  require_node_version_offered
  say "node pool ${NODE_POOL}: ${NUM_NODES}× ${NODE_MACHINE}, node ${NODE_VERSION}, SA $(peerpods_sa), scope cloud-platform"
  gcloud container node-pools create "${NODE_POOL}" --cluster "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" \
    --node-version "${NODE_VERSION}" --num-nodes "${NUM_NODES}" --machine-type "${NODE_MACHINE}" --image-type "${NODE_IMAGE}" \
    --disk-type pd-standard --disk-size 50 --service-account "$(peerpods_sa)" --scopes cloud-platform \
    --workload-metadata GKE_METADATA --no-enable-autorepair
fi
pool_sa="$(gcloud container node-pools describe "${NODE_POOL}" --cluster "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(config.serviceAccount)')"
pool_scopes="$(gcloud container node-pools describe "${NODE_POOL}" --cluster "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(config.oauthScopes)')"
pool_version="$(pool_node_version "${NODE_POOL}")"
[ "${pool_version}" = "${NODE_VERSION}" ] || die "node pool ${NODE_POOL} runs ${pool_version}, the freeze needs ${NODE_VERSION} (re-run with V5_NODE_POOL=<new name>)"
[ "${pool_sa}" = "$(peerpods_sa)" ] || die "node pool ${NODE_POOL} runs as ${pool_sa}, expected $(peerpods_sa) (delete the pool and re-run)"
[[ "${pool_scopes}" == *cloud-platform* ]] || die "node pool ${NODE_POOL} lacks the cloud-platform scope (delete the pool and re-run)"
if pool_exists default-pool; then
  say "retiring GKE's default-pool (wrong SA/scopes for the CAA)"
  gcloud container node-pools delete default-pool --cluster "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --quiet
fi
kubectl wait --for=condition=Ready node --all --timeout=300s >/dev/null
kubectl label nodes --all node.kubernetes.io/worker= --overwrite >/dev/null

say "patching containerd on every worker: discard_unpacked_layers=false (peer pods need the layers)"
# Not idempotent by nature: this edits a node boot disk and does not survive a node
# recreation (see the maintenance exclusion above). The remote snippet is written so that a
# config which does not carry the key at all fails with a readable reason instead of a bare
# non-zero exit from a `grep` that found nothing.
for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
  gcloud compute ssh "${node}" --zone "${ZONE}" --project "${PROJECT}" --quiet --command \
    'set -e
conf=/etc/containerd/config.toml
grep -Eq "^[[:space:]]*discard_unpacked_layers[[:space:]]*=" "$conf" || {
  echo "no discard_unpacked_layers key in $conf: containerd config layout changed, patch by hand" >&2; exit 3; }
sudo sed -i "s/discard_unpacked_layers = true/discard_unpacked_layers = false/" "$conf"
sudo systemctl restart containerd
grep -Eq "^[[:space:]]*discard_unpacked_layers[[:space:]]*=[[:space:]]*false" "$conf"' \
    || die "containerd patch failed on ${node} (see the message above). Peer pods cannot guest-pull without it"
done

NETWORK="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(network)')"
CLUSTER_SUBNET="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" --format='value(subnetwork)')"
[ -n "${NETWORK}" ] && [ -n "${CLUSTER_SUBNET}" ] || die "could not determine the cluster's network/subnetwork"
SUBNET_NAME="${CLUSTER_SUBNET##*/}"
# The tunnel allow-rule is about this cluster's nodes, so the source range is this
# cluster's subnetwork (not "some subnet in the region").
NODE_CIDR="$(gcloud compute networks subnets describe "${SUBNET_NAME}" --region "${REGION}" --project "${PROJECT}" --format='value(ipCidrRange)')"
[ -n "${NODE_CIDR}" ] || die "could not determine the node subnet CIDR of ${SUBNET_NAME}"
say "cluster network ${NETWORK}, node subnet ${SUBNET_NAME} (${NODE_CIDR})"

# --- reconcile helpers ------------------------------------------------------------------
# `describe || create` keeps whatever is already there, which is not enough for a rerun.
# A stale allow list would stay in place and every worker to pod-VM frame would be dropped.
# For anything security relevant the helpers below reconcile: create when missing, otherwise
# update every field that matters here, and refuse loudly where a field cannot be updated in place
# (direction, CIDR, network).

fw_rule_ensure() {   # NAME DIRECTION ALLOW SRC DST PRIO DESC
  local name="$1" dir="$2" allow="$3" src="$4" dst="$5" prio="$6" desc="$7" have_dir
  if gcloud compute firewall-rules describe "${name}" --project "${PROJECT}" >/dev/null 2>&1; then
    have_dir="$(gcloud compute firewall-rules describe "${name}" --project "${PROJECT}" --format='value(direction)')"
    [ "${have_dir}" = "${dir}" ] || die "firewall rule ${name} has direction ${have_dir}, expected ${dir} (immutable: delete it and re-run)"
    gcloud compute firewall-rules update "${name}" --project "${PROJECT}" \
      --allow "${allow}" --source-ranges "${src}" --destination-ranges "${dst}" \
      --priority "${prio}" --description "${desc}" >/dev/null
  else
    gcloud compute firewall-rules create "${name}" --project "${PROJECT}" --network "${NETWORK}" \
      --direction "${dir}" --allow "${allow}" --priority "${prio}" \
      --source-ranges "${src}" --destination-ranges "${dst}" --description "${desc}" >/dev/null
  fi
}

fwp_rule_ensure() {  # PRIO DIRECTION ACTION SRC DST LAYER4 DESC
  local prio="$1" dir="$2" action="$3" src="$4" dst="$5" l4="$6" desc="$7" have_dir
  local sel=(--firewall-policy "${FW_POLICY}" --global-firewall-policy --project "${PROJECT}")
  if gcloud compute network-firewall-policies rules describe "${prio}" "${sel[@]}" >/dev/null 2>&1; then
    have_dir="$(gcloud compute network-firewall-policies rules describe "${prio}" "${sel[@]}" --format='value(direction)')"
    [ "${have_dir}" = "${dir}" ] || die "policy rule ${prio} has direction ${have_dir}, expected ${dir} (delete it and re-run)"
    gcloud compute network-firewall-policies rules update "${prio}" "${sel[@]}" \
      --action "${action}" --src-ip-ranges "${src}" --dest-ip-ranges "${dst}" \
      --layer4-configs "${l4}" --description "${desc}" >/dev/null
  else
    gcloud compute network-firewall-policies rules create "${prio}" "${sel[@]}" \
      --direction "${dir}" --action "${action}" --src-ip-ranges "${src}" --dest-ip-ranges "${dst}" \
      --layer4-configs "${l4}" --description "${desc}" >/dev/null
  fi
}

say "pod-VM subnet ${PODVM_SUBNET} (${PODVM_SUBNET_CIDR}) in network ${NETWORK}: every runner TD gets its NIC here"
# CIDR and network are immutable and they are the whole basis of A5b (every rule about "the
# runner TDs" is a rule about this range), so a mismatch is fatal rather than ignored.
# Private Google Access is reconciled: without it the guest pull cannot reach the API VIP.
if subnet_json="$(gcloud compute networks subnets describe "${PODVM_SUBNET}" --region "${REGION}" --project "${PROJECT}" \
      --format='value[separator=" "](ipCidrRange,network,privateIpGoogleAccess)' 2>/dev/null)"; then
  read -r have_cidr have_net have_pga <<<"${subnet_json}"
  [ "${have_cidr}" = "${PODVM_SUBNET_CIDR}" ] || \
    die "subnet ${PODVM_SUBNET} has range ${have_cidr}, pinned is ${PODVM_SUBNET_CIDR} (immutable: delete the subnet or fix PODVM_SUBNET_CIDR, every A5b rule keys on this range)"
  [ "${have_net##*/}" = "${NETWORK##*/}" ] || \
    die "subnet ${PODVM_SUBNET} lives in network ${have_net##*/}, the cluster is in ${NETWORK##*/} (immutable: delete the subnet and re-run)"
  if [ "${have_pga}" != "True" ]; then
    say "subnet ${PODVM_SUBNET}: enabling Private Google Access (was ${have_pga}). The guest pull needs the API VIP"
    gcloud compute networks subnets update "${PODVM_SUBNET}" --region "${REGION}" --project "${PROJECT}" \
      --enable-private-ip-google-access >/dev/null
  fi
else
  gcloud compute networks subnets create "${PODVM_SUBNET}" --project "${PROJECT}" --network "${NETWORK}" \
    --region "${REGION}" --range "${PODVM_SUBNET_CIDR}" --enable-private-ip-google-access >/dev/null
fi

say "firewall: CAA forwarder ${PEERPOD_TUNNEL_PORT}/tcp + VXLAN ${PEERPOD_VXLAN_PORT}/udp, only from the node subnet ${NODE_CIDR} to the pod-VM subnet"
fw_rule_ensure "v5-allow-peerpod-tunnel" INGRESS "tcp:${PEERPOD_TUNNEL_PORT},udp:${PEERPOD_VXLAN_PORT}" \
  "${NODE_CIDR}" "${PODVM_SUBNET_CIDR}" "${FW_PRIO_ALLOW}" \
  "CoCo peer pods: worker -> pod VM (agent forwarder + VXLAN), node subnet only"

# The return path: without it a peer pod reaches nothing through the tunnel.
# VXLAN is UDP with a varying source port, so pod-VM -> worker packets are new flows, not
# replies. GCP's default-allow-internal covers 10.128.0.0/9 only and the pod-VM subnet lies
# outside it by design. Two rules are needed: ingress on the workers from the pod-VM subnet
# (here) and an egress allow rule in the deny policy (below).
say "firewall: VXLAN ${PEERPOD_VXLAN_PORT}/udp return path, only from the pod-VM subnet to the node subnet ${NODE_CIDR}"
fw_rule_ensure "v5-allow-peerpod-tunnel-return" INGRESS "udp:${PEERPOD_VXLAN_PORT}" \
  "${PODVM_SUBNET_CIDR}" "${NODE_CIDR}" "${FW_PRIO_ALLOW}" \
  "CoCo peer pods: pod VM -> worker (VXLAN return path), pod-VM subnet only"

say "firewall policy ${FW_POLICY}: runner-TD egress over the direct NIC (A5b)"
# Egress rules keyed by source range need a network firewall policy (legacy VPC egress rules
# select targets only by tag/SA). Replies to the worker's tunnel are stateful and unaffected.
# The order matters on a rerun: all rules are created or reconciled first and the policy is
# associated with the network last. The reverse order (deny, associate, then the allows) opens
# a window in which running pod VMs are denied everything, including their own VXLAN.
policy_preexisting=1
if ! gcloud compute network-firewall-policies describe "${FW_POLICY}" --global --project "${PROJECT}" >/dev/null 2>&1; then
  policy_preexisting=0
  gcloud compute network-firewall-policies create "${FW_POLICY}" --global --project "${PROJECT}" \
    --description "V5 A5b: runner TDs may not reach anything over their own NIC unless explicitly allowed" >/dev/null
fi

say "  rule ${FW_PRIO_DENY}: DENY all egress from ${PODVM_SUBNET_CIDR}"
fwp_rule_ensure "${FW_PRIO_DENY}" EGRESS deny "${PODVM_SUBNET_CIDR}" 0.0.0.0/0 all \
  "deny all direct egress from runner TDs"
# Peer pods pull their container image inside the guest, over the pod VM's own NIC. The only
# egress opened for that is Google's private API VIP (private.googleapis.com, tcp 443);
# private DNS zones steer googleapis.com / pkg.dev / gcr.io onto it. Everything else stays
# denied (A5b). The metadata server is implicitly reachable and is removed in the pod-VM
# image instead (A5c).
say "  rule ${FW_PRIO_ALLOW_GOOGLEAPI}: ALLOW ${PODVM_SUBNET_CIDR} -> ${GOOGLE_API_VIP} tcp:443 (image pull)"
fwp_rule_ensure "${FW_PRIO_ALLOW_GOOGLEAPI}" EGRESS allow "${PODVM_SUBNET_CIDR}" "${GOOGLE_API_VIP}" tcp:443 \
  "runner TDs: image pull via private.googleapis.com only"
say "  rule ${FW_PRIO_ALLOW_VXLAN}: ALLOW ${PODVM_SUBNET_CIDR} -> ${NODE_CIDR} udp:${PEERPOD_VXLAN_PORT} (VXLAN to the worker)"
fwp_rule_ensure "${FW_PRIO_ALLOW_VXLAN}" EGRESS allow "${PODVM_SUBNET_CIDR}" "${NODE_CIDR}" "udp:${PEERPOD_VXLAN_PORT}" \
  "runner TDs: VXLAN to their worker only (tunnelled pod network, A5 applies there)"

say "private DNS zones -> ${GOOGLE_API_VIP} (googleapis.com, pkg.dev, gcr.io) in network ${NETWORK}"
gcloud services enable dns.googleapis.com --project "${PROJECT}" >/dev/null
VIP_A="199.36.153.8,199.36.153.9,199.36.153.10,199.36.153.11"
record_ensure() {  # ZONE NAME TYPE RRDATAS
  local zone="$1" name="$2" type="$3" rrdatas="$4" have
  if have="$(gcloud dns record-sets describe "${name}" --type "${type}" --zone "${zone}" --project "${PROJECT}" \
        --format='value[delimiter=","](rrdatas)' 2>/dev/null)"; then
    [ "${have}" = "${rrdatas}" ] && return 0
    say "  DNS ${zone}/${name} ${type}: ${have} -> ${rrdatas}"
    gcloud dns record-sets update "${name}" --type "${type}" --ttl 300 --zone "${zone}" --project "${PROJECT}" --rrdatas "${rrdatas}" >/dev/null
  else
    gcloud dns record-sets create "${name}" --type "${type}" --ttl 300 --zone "${zone}" --project "${PROJECT}" --rrdatas "${rrdatas}" >/dev/null
  fi
}
private_zone() {   # NAME DOMAIN APEX_A_TARGET WILDCARD_TARGET
  local name="$1" domain="$2" apex="$3" wild="$4" nets
  if nets="$(gcloud dns managed-zones describe "${name}" --project "${PROJECT}" \
        --format='value[delimiter=","](privateVisibilityConfig.networks.networkUrl)' 2>/dev/null)"; then
    # A zone that is not attached to this network resolves nothing for the pod VMs, and the
    # plain `describe || create` would walk past that silently.
    case ",${nets}," in
      *"/${NETWORK##*/},"*) : ;;
      *) say "  zone ${name} is not attached to network ${NETWORK##*/}, attaching"
         gcloud dns managed-zones update "${name}" --project "${PROJECT}" \
           --networks "$(printf '%s' "${nets},${NETWORK}" | sed 's/^,//')" >/dev/null ;;
    esac
  else
    gcloud dns managed-zones create "${name}" --project "${PROJECT}" --dns-name "${domain}." --visibility private \
      --networks "${NETWORK}" --description "V5: route ${domain} to private.googleapis.com for the pod VMs" >/dev/null
  fi
  record_ensure "${name}" "${apex}" A "${VIP_A}"
  record_ensure "${name}" "*.${domain}." CNAME "${wild}"
}
private_zone v5-googleapis googleapis.com private.googleapis.com. private.googleapis.com.
private_zone v5-pkgdev     pkg.dev        pkg.dev.                pkg.dev.
private_zone v5-gcrio      gcr.io         gcr.io.                 gcr.io.

# Last step: only now does the policy take effect on the network.
# A policy created in this run cannot carry our association yet, so it is associated directly.
# A policy that existed before must either carry an association with our name that targets this
# cluster network, or it gets one now.
assoc_name="${FW_POLICY}-${NETWORK##*/}"
if [ "${policy_preexisting}" = "0" ]; then
  say "associating newly created firewall policy ${FW_POLICY} with network ${NETWORK##*/} (A5b becomes active now)"
  gcloud compute network-firewall-policies associations create --firewall-policy "${FW_POLICY}" --global-firewall-policy \
    --network "${NETWORK}" --name "${assoc_name}" --project "${PROJECT}" >/dev/null
else
  assoc_yaml="$(gcloud compute network-firewall-policies describe "${FW_POLICY}" --global --project "${PROJECT}" \
      --format='yaml(associations)' 2>/dev/null)" \
    || die "could not read associations of existing firewall policy ${FW_POLICY}"
  if printf '%s\n' "${assoc_yaml}" | grep -Fq "name: ${assoc_name}"; then
    printf '%s\n' "${assoc_yaml}" | grep -Fq "/networks/${NETWORK##*/}" \
      || die "association ${assoc_name} exists but does not target network ${NETWORK##*/}"
    say "firewall policy ${FW_POLICY} already associated with ${NETWORK##*/}"
  else
    say "associating firewall policy ${FW_POLICY} with network ${NETWORK##*/} (A5b becomes active now)"
    gcloud compute network-firewall-policies associations create --firewall-policy "${FW_POLICY}" --global-firewall-policy \
      --network "${NETWORK}" --name "${assoc_name}" --project "${PROJECT}" >/dev/null
  fi
fi

say "NOTE: the CAA must place pod VMs in ${PODVM_SUBNET} (GCP_SUBNETWORK). 19_probe_network.sh verifies that the pod VM's NIC is in ${PODVM_SUBNET_CIDR}."
say "cluster ready: $(kubectl config current-context)"
