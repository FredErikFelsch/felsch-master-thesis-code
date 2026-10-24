#!/usr/bin/env bash
# 37_install_openbao.sh: installs the credential store and the gateway's way of proving who it is.
#
# Needs:  30_deploy_v5.sh run before (the gateway's ServiceAccount must exist), kubectl, gcloud,
#         python3, and DUFFEL_TOKEN (required for world duffel) or SERPAPI_KEY in the environment.
#         Neither is echoed or written to a file here.
# Usage:  ./scripts/gke-v5/37_install_openbao.sh   (before the first live run)
# Result: OpenBao running with the provider credentials in secret/agent, Kubernetes auth for the
#         gateway, and the gateway patched to use it. Idempotent: re-running rewrites the same
#         secrets, the same policy and the same role.
#
# The steps:
#   1  a root token for the dev server, generated here, kept in a Secret
#   2  OpenBao itself, plus the ClusterRoleBinding that lets it call TokenReview
#   3  the two provider credentials, from this shell's environment into secret/agent
#   4  a policy that grants read on that path only
#   5  Kubernetes auth, bound to the audience `openbao`, with a role for gateway-sa
#   6  the network rules a live world needs, and the gateway patch that uses them
#
# The runner is not mentioned in this script. It has no ServiceAccount token, no OpenBao role
# and no network route to OpenBao, so there is nothing to deny it.
#
# The server runs in development mode: it keeps its data in memory and is unsealed at start.
# A restart loses every secret, and a rerun of this script puts them back. That is enough to
# show where a credential lives, and not suitable for anything else.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project

BAO_DIR="${V5_K8S_DIR}/openbao"
OPENBAO_IMAGE="${OPENBAO_IMAGE:-docker.io/openbao/openbao:2.4.1}"
BAO_ROLE_NAME="${BAO_ROLE_NAME:-gateway}"
BAO_AUDIENCE="${BAO_AUDIENCE:-openbao}"
GATEWAY_SA="${GATEWAY_SA:-gateway-sa}"

[ -n "${DUFFEL_TOKEN:-}" ] || [ -n "${SERPAPI_KEY:-}" ] || \
  die "neither DUFFEL_TOKEN nor SERPAPI_KEY is set, there would be nothing to store"

# One placeholder, substituted with python: macOS has no envsubst, and 30_deploy_v5.sh
# solves the same problem the same way.
render_one() {   # render_one FILE PLACEHOLDER VALUE
  PH="$2" VAL="$3" python3 - "$1" <<'PY'
import os, sys
sys.stdout.write(open(sys.argv[1]).read().replace(os.environ["PH"], os.environ["VAL"]))
PY
}

# `bao` inside the pod, with the root token from the Secret. The token travels on the stdin of
# `kubectl exec` (printf is a shell builtin) and is exported inside the pod before the command
# runs, so it is in no argument list, neither on the operator machine nor in the pod. The
# provider credentials of step 3 are different: they are arguments of `bao kv put` and are
# visible in both process lists while that one command runs.
bao_exec() {
  printf '%s\n' "${ROOT_TOKEN}" | kubectl -n "${NAMESPACE}" exec -i deploy/openbao -- \
    sh -c 'read -r BAO_TOKEN && export BAO_TOKEN BAO_ADDR=http://127.0.0.1:8200 && exec "$@"' bao_exec "$@"
}

say "1/6 root token for the dev server (generated here, never printed)"
if ! kubectl -n "${NAMESPACE}" get secret openbao-root >/dev/null 2>&1; then
  ROOT_TOKEN="root-$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)"
  printf '%s' "${ROOT_TOKEN}" | kubectl -n "${NAMESPACE}" create secret generic openbao-root --from-file=token=/dev/stdin
else
  ROOT_TOKEN="$(kubectl -n "${NAMESPACE}" get secret openbao-root -o jsonpath='{.data.token}' | base64 -d)"
  say "    reusing the existing openbao-root Secret"
fi

say "2/6 OpenBao (${OPENBAO_IMAGE}) and the TokenReview binding"
render_one "${BAO_DIR}/openbao.yaml" '${OPENBAO_IMAGE}' "${OPENBAO_IMAGE}" | kubectl apply -f -
kubectl -n "${NAMESPACE}" rollout status deploy/openbao --timeout=180s
kubectl -n "${NAMESPACE}" wait --for=condition=ready pod -l app=openbao --timeout=120s

say "3/6 the provider credentials into secret/agent"
KV_ARGS=()
[ -n "${DUFFEL_TOKEN:-}" ] && KV_ARGS+=("DUFFEL_TOKEN=${DUFFEL_TOKEN}")
[ -n "${SERPAPI_KEY:-}" ] && KV_ARGS+=("SERPAPI_KEY=${SERPAPI_KEY}")
bao_exec bao kv put secret/agent "${KV_ARGS[@]}" >/dev/null
say "    stored: $(printf '%s ' "${KV_ARGS[@]%%=*}")"

say "4/6 a policy that reads that path only"
bao_exec sh -c 'cat <<POLICY | bao policy write gateway -
path "secret/data/agent" {
  capabilities = ["read"]
}
POLICY' >/dev/null
bao_exec bao policy read gateway >/dev/null || die "the gateway policy was not written"

say "5/6 Kubernetes auth, bound to the audience ${BAO_AUDIENCE}"
bao_exec sh -c 'bao auth list | grep -q "^kubernetes/" || bao auth enable kubernetes' >/dev/null
# kubernetes_host from inside the pod: the in-cluster API address, not a guess.
bao_exec sh -c 'bao write auth/kubernetes/config \
    kubernetes_host="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}" \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt' >/dev/null
# The audience matters: a token minted for `openbao` is accepted here and is useless
# against the Kubernetes API, so the gateway keeps automountServiceAccountToken: false.
bao_exec bao write "auth/kubernetes/role/${BAO_ROLE_NAME}" \
    bound_service_account_names="${GATEWAY_SA}" \
    bound_service_account_namespaces="${NAMESPACE}" \
    audience="${BAO_AUDIENCE}" \
    policies=gateway ttl=1h >/dev/null

say "6/6 network rules for a live world, and the gateway patch"
MASTER_CIDR="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" \
  --format='value(privateClusterConfig.masterIpv4CidrBlock)' 2>/dev/null || true)"
if [ -z "${MASTER_CIDR}" ]; then
  MASTER_CIDR="0.0.0.0/0"
  say "    WARNING: no private master CIDR found (the cluster from 12 is not a private cluster)."
  say "             OpenBao's egress to the API server is left open to any IPv4 address on 443."
  say "             Patch the NetworkPolicy openbao-policy by hand for a tighter rule."
fi
say "    master CIDR for OpenBao's TokenReview egress: ${MASTER_CIDR}"
render_one "${BAO_DIR}/networkpolicy-live.yaml" '${MASTER_CIDR}' "${MASTER_CIDR}" | kubectl apply -f -
kubectl -n "${NAMESPACE}" patch deployment gateway --patch-file "${BAO_DIR}/gateway-live-patch.yaml"
kubectl -n "${NAMESPACE}" rollout status deploy/gateway --timeout=180s

say "done. The gateway now reads its credentials from OpenBao."
say "Verify with: scripts/gke-v5/38_negative_live_v5.sh"
