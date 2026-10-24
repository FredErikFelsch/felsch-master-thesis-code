#!/usr/bin/env bash
# 14_install_coco.sh: installs cloud-api-adaptor (peer pods, GCP provider) from the chart shipped in the pinned CAA tag.
#
# Needs:  The cluster from 12, the rendered values file from 15, the pod-VM image from 11, helm,
#         git, gcloud with ssh access to the nodes, and the pins from _config.sh.
# Usage:  ./scripts/gke-v5/14_install_coco.sh
# Result: The CAA daemonset running as the node service account, the RuntimeClass kata-remote, and
#         the kata-remote annotation allowlist reduced to cc_init_data. Exits non-zero if stale
#         probe peer pods cannot be cleared or a node cannot be hardened.
#
# The chart bundles kata-deploy (kata-remote shim and RuntimeClass) and peerpod-ctrl, so no
# separate CoCo operator is needed. Credentials come from the node service account via ADC.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
source "$(dirname "${BASH_SOURCE[0]}")/_peerpod_cleanup.sh"
require_project; require_v5_pins
command -v helm >/dev/null || die "helm not installed (brew install helm)"
NS=confidential-containers-system

# A CAA rollout cannot become Ready while stale probe PeerPods are still registered as
# non-Ready. Eleven old probe CRs, for example, kept the startup probe red for the full 600 s
# timeout. Only our disposable V5 probe namespaces are cleaned. A finalizer is removed only for
# a CR whose VM GCE no longer lists, the rule of 91_cleanup_probe.sh. A CR whose VM still runs
# aborts the install before the CAA is touched, so no pod VM is orphaned.
cleanup_stale_v5_probes() {
  local ns name inst blocked

  for ns in v5-probe v5-netprobe v5-netprobe-open; do
    kubectl get namespace "${ns}" >/dev/null 2>&1 || continue

    say "cleanup: removing stale probe resources in ${ns} before CAA rollout"

    kubectl -n "${ns}" delete pod --all --wait=false >/dev/null 2>&1 || true
    kubectl -n "${ns}" delete peerpods.confidentialcontainers.org --all --wait=false >/dev/null 2>&1 || true
    kubectl delete namespace "${ns}" --wait=false >/dev/null 2>&1 || true
  done

  # Give peerpod-ctrl a moment to remove its CRs. A cluster that never ran 14/18/19 before
  # has no peerpods CRD at all yet, so `kubectl get` exits non-zero. The `|| true` inside the
  # group absorbs that, so the awk count comes out 0 instead of ending the script under -e.
  probe_crs() {
    { kubectl get peerpods.confidentialcontainers.org -A --no-headers 2>/dev/null || true; } |
      awk '$1=="v5-probe" || $1=="v5-netprobe" || $1=="v5-netprobe-open" {print $1" "$2}'
  }
  for _ in $(seq 1 15); do
    [ -z "$(probe_crs)" ] && return 0
    sleep 2
  done

  # It will not happen on its own here: peerpod-ctrl of CAA 0.21.1 registers no gcp provider,
  # so its finalizer (peer.pod/finalizer) is never removed and the CR stays forever. Waiting
  # longer only wastes the run, and refusing here would block every rerun. Do what 91 does,
  # with 91's rule: a finalizer is ballast only once GCE confirms the VM is gone. While a VM
  # still exists the finalizer is doing its job and removing it would orphan a running c3 TDX
  # instance.
  say "peerpod-ctrl has no gcp provider (CAA ${CAA_VERSION}): clearing finalizers of CRs whose VM is gone"
  blocked=""
  while read -r ns name; do
    [ -n "${name}" ] || continue
    inst="$(kubectl -n "${ns}" get peerpods.confidentialcontainers.org "${name}" -o jsonpath='{.spec.instanceID}' 2>/dev/null || true)"
    if [ -n "${inst}" ] && gcloud compute instances list --project "${PROJECT}" \
         --filter="id=${inst} OR name=${inst}" --format='value(name)' 2>/dev/null | grep -q .; then
      say "  ${ns}/${name}: pod VM ${inst} still exists, leaving the finalizer alone"
      blocked="${blocked} ${ns}/${name}(vm ${inst})"
      continue
    fi
    say "  ${ns}/${name}: no pod VM for instanceID ${inst:-<none>}, removing the finalizer"
    kubectl -n "${ns}" patch peerpods.confidentialcontainers.org "${name}" \
      --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1 || true
  done < <(probe_crs)

  for _ in $(seq 1 15); do
    [ -z "$(probe_crs)" ] && return 0
    sleep 2
  done

  kubectl get peerpods.confidentialcontainers.org -A >&2 || true
  if [ -n "${blocked}" ]; then
    die "stale V5 probe PeerPods whose pod VM still runs:${blocked}. Delete those VMs first (91_cleanup_probe.sh --force-orphans), then re-run 14"
  fi
  die "stale V5 probe PeerPods remain even after clearing their finalizers. Inspect them: kubectl get peerpods.confidentialcontainers.org -A -o yaml"
}
# Terminal peer pods anywhere, not just in the three probe namespaces. A failed
# runner-td in agent-system holds the node-wide startup probe at 500 just as well, and
# the rollout then runs into its full 600 s timeout.
clear_stale_peer_pods
cleanup_stale_v5_probes

say "pin profile V5_PINS=${V5_PINS}: CAA ${CAA_VERSION} (${CAA_IMAGE_TAG}), pod-VM image ${PODVM_IMAGE_PROJECT}/${PODVM_IMAGE}"
[ -f "${V5_K8S_DIR}/caa/values-gcp.yaml" ] || die "k8s/v5/caa/values-gcp.yaml not rendered yet (15_render_caa_values.sh)"

work="${MOCKS_DIR}/results_v5/caa-src"; mkdir -p "${work}"
if [ ! -d "${work}/cloud-api-adaptor" ]; then
  git -C "${work}" clone -q --depth 1 --branch "v${CAA_VERSION}" https://github.com/confidential-containers/cloud-api-adaptor.git
fi
have="$(git -C "${work}/cloud-api-adaptor" describe --tags --exact-match 2>/dev/null || true)"
[ "${have}" = "v${CAA_VERSION}" ] || die "${work}/cloud-api-adaptor is at '${have}', expected v${CAA_VERSION} (delete the directory and re-run)"
chart="${work}/cloud-api-adaptor/src/cloud-api-adaptor/install/charts/peerpods"
[ -f "${chart}/Chart.yaml" ] || die "no peerpods chart in CAA v${CAA_VERSION} (charts exist from 0.18.0)"

say "worker label node.kubernetes.io/worker= (DaemonSet selector)"
kubectl label nodes --all node.kubernetes.io/worker= --overwrite >/dev/null

say "helm: peerpods chart ($(grep '^appVersion' "${chart}/Chart.yaml")) into ${NS}"
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# GKE admits system-node-critical pods only where a ResourceQuota with that priority
# scope exists (kube-system has one). kata-deploy uses that class, so grant it here.
kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ResourceQuota
metadata:
  name: critical-pods
  namespace: ${NS}
spec:
  hard:
    pods: "50"
  scopeSelector:
    matchExpressions:
    - operator: In
      scopeName: PriorityClass
      values: ["system-node-critical", "system-cluster-critical"]
YAML
( cd "${chart}" && helm dependency update . >/dev/null && \
  helm upgrade --install peerpods . -f providers/gcp.yaml -f "${V5_K8S_DIR}/caa/values-gcp.yaml" \
    --force-conflicts -n "${NS}" --wait=hookOnly --timeout 10m )

# The image's entrypoint.sh refuses to start without GCP_CREDENTIALS (a key file). Every
# setting is read from the environment by the binary itself (FlagRegistrar), so 14 starts
# the binary directly and the Go client falls back to Application Default Credentials, that
# is the node SA. Helm 4 (server-side apply) would conflict with this patch on the next
# upgrade, hence --force-conflicts above: helm resets the field, the patch re-applies it.
# (Helm 4 accepts only plugins as post-renderers, so a script cannot do this in-release.)
# The image (debian base + iptables) ships no CA bundle, so TLS to compute.googleapis.com
# fails with "certificate signed by unknown authority". Mount the node's bundle read-only.
say "starting the CAA binary directly (ADC instead of a key file), with the node's CA bundle"
ops='{"op":"replace","path":"/spec/template/spec/containers/0/command","value":["/usr/local/bin/cloud-api-adaptor","gcp"]}'
# Items added by an earlier run survive helm's server-side apply (other manager), so add
# the CA mount only once (a duplicate volume name would be rejected).
if ! kubectl -n "${NS}" get ds cloud-api-adaptor-daemonset -o jsonpath='{.spec.template.spec.volumes[*].name}' | grep -qw host-ca; then
  ops="${ops},"'{"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"host-ca","hostPath":{"path":"/etc/ssl/certs/ca-certificates.crt","type":"File"}}}'
  ops="${ops},"'{"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"host-ca","mountPath":"/etc/ssl/certs/ca-certificates.crt","readOnly":true}}'
  ops="${ops},"'{"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{"name":"SSL_CERT_FILE","value":"/etc/ssl/certs/ca-certificates.crt"}}'
fi
kubectl -n "${NS}" patch ds cloud-api-adaptor-daemonset --type json -p "[${ops}]" >/dev/null
kubectl -n "${NS}" rollout status ds/cloud-api-adaptor-daemonset --timeout=600s
kubectl get runtimeclass kata-remote >/dev/null || die "RuntimeClass kata-remote missing (kata-deploy subchart)"
# The RuntimeClass schedules only onto nodes labelled katacontainers.io/kata-runtime=true,
# which kata-deploy sets after installing the shim on the node. Wait for it.
say "waiting for kata-deploy to label the worker (katacontainers.io/kata-runtime=true)"
for i in $(seq 1 60); do
  n="$(kubectl get nodes -l katacontainers.io/kata-runtime=true -o name | wc -l | tr -d ' ')"
  [ "${n}" -ge 1 ] && break
  sleep 10
done
[ "${n}" -ge 1 ] || { kubectl -n "${NS}" get pods -o wide; kubectl -n "${NS}" logs -l name=kata-deploy --tail=40 || true; die "no node labelled katacontainers.io/kata-runtime=true after 10 min (kata-deploy did not finish)"; }

# --- V5 annotation hardening (Fixed Execution Profile invariant, checked by the
# "annotation allowlist" check of 40_verify_v5.sh) ---
# kata-deploy has just written its hypervisor config on every kata-enabled worker, with its own
# default enable_annotations allowlist. Anything on it that reshapes the VM (kernel params,
# firmware, image, machine type, vCPU/memory, debug) would let a pod manifest change what is
# measured while the reference values stay pinned. The allowlist is therefore reduced to
# cc_init_data now, right after kata-deploy is done and before any pod can run. This is a
# V5-specific hardening, not the fix for CVE-2026-44210 (that CVE is virtio_fs_extra_args and
# kernel_params being enabled by default, fixed upstream in Kata 3.31.0).
#
# `kubectl debug node/` is unreliable for this (it can return silent empty reads, "got ''").
# `gcloud compute ssh` talks to the node directly, so write and verify happen in the same remote
# shell instead of two ephemeral debug pods racing each other. kata-deploy writes the allowlist
# to two paths (legacy and runtimes/remote). Both are patched and verified.
say "hardening kata-remote annotation allowlist to cc_init_data only"
for kn in $(kubectl get nodes -l katacontainers.io/kata-runtime=true -o jsonpath='{.items[*].metadata.name}'); do
  gcloud compute ssh "${kn}" --zone "${ZONE}" --project "${PROJECT}" --quiet --command \
    'set -eu
found=0
for conf in \
  /opt/kata/share/defaults/kata-containers/configuration-remote.toml \
  /opt/kata/share/defaults/kata-containers/runtimes/remote/configuration-remote.toml
do
  [ -f "$conf" ] || continue
  found=1
  tmp="$(mktemp)"
  sudo awk '"'"'/^[[:space:]]*enable_annotations[[:space:]]*=/ {
    print "enable_annotations = [\"cc_init_data\"]"
    if ($0 ~ /\]/) next
    skip=1
    next
  }
  skip && /\]/ { skip=0; next }
  skip { next }
  { print }'"'"' "$conf" > "$tmp"
  sudo cp "$tmp" "$conf"
  rm -f "$tmp"
  applied="$(sudo sed -n '"'"'s/^[[:space:]]*enable_annotations[[:space:]]*=[[:space:]]*//p'"'"' "$conf" | tail -1)"
  [ "$applied" = '"'"'["cc_init_data"]'"'"' ] || { echo "ERROR: $conf -> $applied" >&2; exit 2; }
  echo "$conf: enable_annotations = $applied"
done
[ "$found" = "1" ] || { echo "ERROR: no remote Kata configuration found on this node" >&2; exit 3; }' \
    || die "annotation hardening failed on ${kn}"
done

say "CAA log (should show the gcp config and no credentials error):"
kubectl -n "${NS}" logs ds/cloud-api-adaptor-daemonset -c cloud-api-adaptor-con --tail=20 | grep -v '^\s*$' || true
say "CoCo ready: runtimeclass kata-remote present, CAA running as node SA $(peerpods_sa)"
