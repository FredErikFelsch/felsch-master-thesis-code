#!/usr/bin/env bash
# 00_preflight_v5.sh: read-only preflight for the CoCo peer-pods (TDX) deployment.
#
# Needs:  gcloud (authenticated, project set), kubectl, helm, python3 with pyyaml and
#         cryptography, gke-gcloud-auth-plugin. The settings come from _config.sh.
# Usage:  ./scripts/gke-v5/00_preflight_v5.sh
#         Run it before 12_create_cluster_v5.sh.
# Result: One OK, WARN or FAIL line per item. Exit code non-zero on any FAIL.
#
# It checks what 12_create_cluster_v5.sh, 14_install_coco.sh and 18_probe_peer_pod.sh depend on
# and creates nothing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
fail=0
ok()   { printf '  \033[1;32mOK\033[0m    %s\n' "$*"; }
warn() { printf '  \033[1;33mWARN\033[0m  %s\n' "$*"; }
bad()  { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=1; }

say "1. local tools"
for t in gcloud kubectl helm python3 gke-gcloud-auth-plugin; do
  command -v "$t" >/dev/null 2>&1 && ok "$t" || bad "$t missing"
done
python3 -c "import yaml, cryptography" 2>/dev/null && ok "python: yaml + cryptography" || bad "python: pip install pyyaml cryptography"
python3 -m booking_v5.tests_v5_offline >/dev/null 2>&1 && ok "booking_v5 offline suite passes" || bad "booking_v5 offline suite fails"

say "2. gcloud identity and project"
acct="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)"
[ -n "${acct}" ] && ok "active account ${acct}" || bad "no active gcloud account"
[ -n "${PROJECT}" ] && ok "project ${PROJECT}" || bad "no project set"
gcloud auth application-default print-access-token >/dev/null 2>&1 && ok "ADC present" || warn "ADC missing (gcloud auth application-default login)"

say "3. APIs (12 enables them, but enabling needs serviceusage rights)"
for api in container.googleapis.com compute.googleapis.com artifactregistry.googleapis.com iam.googleapis.com; do
  if gcloud services list --enabled --project "${PROJECT}" --format='value(config.name)' 2>/dev/null | grep -q "^${api}$"; then ok "${api} enabled"; else warn "${api} not enabled yet (12 will try)"; fi
done

say "4. IAM: can this account do what 12/14 need? (Resource Manager testIamPermissions)"
perms=(container.clusters.create compute.firewalls.create compute.instances.setMetadata iam.serviceAccounts.create resourcemanager.projects.setIamPolicy)
token="$(gcloud auth print-access-token 2>/dev/null || true)"
have=""
if [ -n "${token}" ]; then
  body="$(python3 -c 'import json,sys; print(json.dumps({"permissions": sys.argv[1:]}))' "${perms[@]}")"
  have="$(curl -sS -X POST -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
           "https://cloudresourcemanager.googleapis.com/v1/projects/${PROJECT}:testIamPermissions" -d "${body}" 2>/dev/null \
         | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin).get("permissions", [])))' 2>/dev/null || true)"
fi
if [ -z "${have}" ]; then warn "could not query IAM permissions (no token or API error). Continuing, 12 will surface any denial"; fi
for p in "${perms[@]}"; do
  if echo "${have}" | grep -q "^${p}$"; then ok "${p}"; else
    case "$p" in
      iam.serviceAccounts.create|resourcemanager.projects.setIamPolicy) warn "${p} not confirmed: needed once to create the CAA service account with compute rights (12). Ask an owner if it fails" ;;
      *) [ -n "${have}" ] && bad "${p} missing" || warn "${p} not confirmed" ;;
    esac
  fi
done

say "5. TDX C3 in ${ZONE}: machine type, confidential support, quota"
if gcloud compute machine-types describe "${PODVM_MACHINE}" --zone "${ZONE}" --project "${PROJECT}" >/dev/null 2>&1; then
  ok "${PODVM_MACHINE} exists in ${ZONE}"
else bad "${PODVM_MACHINE} not available in ${ZONE} (TDX C3 zones: europe-west4-a/b/c, europe-west9-a/b)"; fi
gcloud compute machine-types describe "${NODE_MACHINE}" --zone "${ZONE}" --project "${PROJECT}" >/dev/null 2>&1 \
  && ok "${NODE_MACHINE} (worker) exists in ${ZONE}" || bad "${NODE_MACHINE} not in ${ZONE}"
case "${ZONE}" in
  europe-west4-a|europe-west4-b|europe-west4-c|europe-west9-a|europe-west9-b) ok "${ZONE} is a documented TDX C3 zone" ;;
  *) bad "${ZONE} is not a documented TDX C3 zone (europe-west4-a/b/c, europe-west9-a/b). Set V5_ZONE" ;;
esac
q="$(gcloud compute regions describe "${REGION}" --project "${PROJECT}" --format=json 2>/dev/null || echo "{}")"
for metric in C3_CPUS CPUS IN_USE_ADDRESSES; do
  line="$(python3 - "$metric" <<PY
import json,sys
d=json.loads('''${q}''') if '''${q}''' else {}
for x in d.get("quotas",[]):
    if x["metric"]==sys.argv[1]: print(f'{x["metric"]} limit={x["limit"]:.0f} usage={x["usage"]:.0f}')
PY
)"
  [ -n "${line}" ] && echo "        ${line}" || warn "quota ${metric} not listed"
done
c3limit="$(python3 - <<PY
import json
d=json.loads('''${q}''') if '''${q}''' else {}
print(next((int(x["limit"]) for x in d.get("quotas",[]) if x["metric"]=="C3_CPUS"),0))
PY
)"
[ "${c3limit:-0}" -ge 12 ] && ok "C3_CPUS quota ${c3limit} (4 per TD, 12 = 3 TDs in parallel)" || bad "C3_CPUS quota ${c3limit} too low in ${REGION}: request an increase (IAM & Admin > Quotas)"

say "6. GKE version for Ubuntu/containerd in ${ZONE} (regular channel)"
ver="$(gcloud container get-server-config --zone "${ZONE}" --project "${PROJECT}" --format='value(channels[?channel==REGULAR].defaultVersion)' 2>/dev/null | head -1)"
[ -n "${ver}" ] && ok "regular channel default ${ver}" || warn "could not read GKE server config"

say "7. CoCo pod-VM image reachable? (14 needs the pin, 12 does not)"
if [ -n "${PODVM_IMAGE}" ]; then
  gcloud compute images describe "${PODVM_IMAGE}" --project "${PROJECT}" >/dev/null 2>&1 \
    && ok "PODVM_IMAGE ${PODVM_IMAGE} readable" || bad "PODVM_IMAGE ${PODVM_IMAGE} not readable from ${PROJECT}"
else warn "PODVM_IMAGE not set yet: fine for 12, required for 14 (build it with 11_build_podvm_image.sh)"; fi
ok "pin profile V5_PINS=${V5_PINS}: CAA ${CAA_VERSION} (${CAA_IMAGE_TAG}), pod-VM image ${PODVM_IMAGE_PROJECT}/${PODVM_IMAGE:-<unset>}, node SA $(peerpods_sa)"
[ -n "${CAA_VERSION}" ] && ok "CAA_VERSION=${CAA_VERSION}" || warn "CAA_VERSION not set"

say "8. SSH to GKE nodes (12 patches containerd via gcloud compute ssh)"
if gcloud compute firewall-rules list --project "${PROJECT}" --format='value(name,sourceRanges,allowed)' 2>/dev/null | grep -qiE "tcp:22|allow-ssh"; then
  ok "an SSH firewall rule exists (default-allow-ssh or custom)"
else warn "no SSH allow rule found. 12 needs tcp:22 from your IP or IAP tunnelling (--tunnel-through-iap)"; fi
if [ -f "$HOME/.ssh/google_compute_engine" ]; then ok "gcloud ssh key present"; else warn "gcloud will generate an ssh key on first use"; fi

say "9. V4.4c image digest available for the measured-runner probe (18)"
[ -f "${DIGEST_FILE}" ] && ok "scripts/gke/.digests present" || warn "no .digests: run ../gke/20_build_push_images.sh before 18"

[ "${fail}" -eq 0 ] || die "preflight FAILED: fix the FAIL lines before 12_create_cluster_v5.sh"
say "preflight OK. WARN lines are acceptable for 12. The pod-VM image pin and the CAA service account are needed before 14"
