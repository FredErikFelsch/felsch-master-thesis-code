#!/usr/bin/env bash
# 30_deploy_v5.sh: deploys the two service principals, the trusted init and the controller identity onto the verified substrate.
#
# Needs:  The substrate from 12, 15 and 14, verified by 40. scripts/gke/.digests with RUNNER_IMAGE,
#         RUNNER_PYTHON and SERVICES_IMAGE (from 23), results_v5/freeze-candidate/freeze-<FREEZE_STAMP>.json,
#         PCS_API_KEY in the environment, and the approver credentials file.
# Usage:  ./scripts/gke-v5/30_deploy_v5.sh
#         BOOKING_WORLD  the counterparty to seed for. "mock" (default) is the V2 catalogue.
#                        A live world additionally needs 37_install_openbao.sh.
#         RESEED_WORLD   0 (default) aborts on a world change, 1 deletes both stores and seeds anew.
# Result: The five steps below applied. Safe to rerun: a rerun mints nothing new, it re-pins the
#         frozen reference and the init-data digest on the existing stores. A deploy record is
#         written under results_v5/e2e/.
#
# The five steps:
#
#   1  namespace, service accounts, PVCs (V4.4c files, unchanged) and the V5 ones
#   2  the frozen reference as ConfigMap v5-freeze, the PCS key as Secret (from $PCS_API_KEY),
#      the controller Secret pre-created empty (init only patches it, in V5 with the anchors only)
#   3  trusted init Job: seeds authority.db and gateway.db from one minting, computes the
#      deployment's init-data digest from RUNNER_IMAGE (13_genpolicy.sh must have produced
#      k8s/v5/init-data/policy.rego for this image and the runner_main command)
#   4  authority and gateway Deployments (one image, two roles), Services, NetworkPolicies
#   5  controller identity: an SA with a narrow Role in the cluster, a token-based kubeconfig
#      context, and a GCP service account with instances.get and registry read, used by
#      impersonation
#
# The Authority appraises with DCAP only. The service binary has no other verifier.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
source "${DIGEST_FILE}"
[ -n "${SERVICES_IMAGE:-}" ] || die "SERVICES_IMAGE not pinned: run 23_build_services_image.sh"
[ -n "${RUNNER_IMAGE:-}" ] || die "RUNNER_IMAGE not pinned: run ../gke/20_build_push_images.sh"
FREEZE_STAMP="${FREEZE_STAMP:?set in _config.sh}"
FREEZE_JSON="${MOCKS_DIR}/results_v5/freeze-candidate/freeze-${FREEZE_STAMP}.json"
[ -f "${FREEZE_JSON}" ] || die "no ${FREEZE_JSON}"
# Before anything is deployed: the nodes run the version the frozen policy expects, else
# every TD would refuse CreateContainer and the warm pool would hang at 0/N.
check_node_pin
SVC_DIR="${V5_K8S_DIR}/services"
OUT="${MOCKS_DIR}/results_v5/e2e"; mkdir -p "${OUT}"

# Which counterparty this deployment reaches. "mock" is the V2 catalogue and the default,
# so a deploy that does not ask for a live world deploys the catalogue. A live
# world additionally needs 37_install_openbao.sh, which puts the credential in reach.
BOOKING_WORLD="${BOOKING_WORLD:-mock}"

render() {   # substitute the placeholders with python (no envsubst on macOS)
  SVC="${SERVICES_IMAGE}" RUN="${RUNNER_IMAGE}" WORLD="${BOOKING_WORLD}" python3 - "$1" <<'PY'
import os, sys
s = open(sys.argv[1]).read()
for k, v in (("${SERVICES_IMAGE}", os.environ["SVC"]), ("${RUNNER_IMAGE}", os.environ["RUN"]),
             ("${BOOKING_WORLD}", os.environ["WORLD"])):
    s = s.replace(k, v)
sys.stdout.write(s)
PY
}

wait_job() {   # wait_job NAME SECONDS: complete -> 0, failed -> die
  local name="$1" t0=$(date +%s)
  while :; do
    local st; st="$(kubectl -n "${NAMESPACE}" get job "${name}" -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}/{.status.conditions[?(@.type=="Failed")].status}' 2>/dev/null)"
    [ "${st%%/*}" = "True" ] && return 0
    [ "${st##*/}" = "True" ] && { kubectl -n "${NAMESPACE}" logs "job/${name}" | tail -20; die "job ${name} FAILED"; }
    [ $(( $(date +%s) - t0 )) -lt "$2" ] || die "job ${name} did not complete in $2 s"
    sleep 3
  done
}

# --- the world a deployment is seeded for cannot change in place ------------------------
# `booking_v5.service_v5.seed` refuses to re-seed a store as another counterparty, which is
# the real guard and stays where it is. But the stores live on RWO PVCs that survive both a
# redeploy and KEEP_CLUSTER=1, so a `BOOKING_WORLD=duffel` deploy onto a cluster that was
# last deployed as "mock" only discovers this ~90 s in, inside a failed init Job. The check
# below is the same refusal, one second in and with the way out spelled out.
RESEED_WORLD="${RESEED_WORLD:-0}"

stores_world() {
  # The counterparty the existing stores were seeded for. Empty when there are none.
  kubectl -n "${NAMESPACE}" get pvc authority-db >/dev/null 2>&1 || return 0
  local w
  w="$(kubectl -n "${NAMESPACE}" get pvc authority-db \
         -o jsonpath='{.metadata.annotations.v5\.world}' 2>/dev/null)"
  # A PVC without the annotation was created by a catalogue deployment, so an unannotated
  # store counts as "mock" rather than as unknown.
  printf '%s' "${w:-mock}"
}

drop_stores() {
  # Delete both stores. This is destructive: the ledger of the old world is gone.
  say "RESEED_WORLD=1: dropping authority-db and gateway-db before the seed"
  for app in authority gateway; do
    kubectl -n "${NAMESPACE}" scale deployment "${app}" --replicas=0 >/dev/null 2>&1 || true
  done
  kubectl -n "${NAMESPACE}" delete job trusted-init-v5 --ignore-not-found --wait=true >/dev/null
  for app in authority gateway; do
    kubectl -n "${NAMESPACE}" wait --for=delete pod -l "app=${app}" --timeout=120s >/dev/null 2>&1 || true
  done
  kubectl -n "${NAMESPACE}" delete pvc authority-db gateway-db --ignore-not-found --wait=true
  say "  stores deleted. 1/5 recreates authority-db and 3/5 recreates gateway-db, both empty"
}

seeded_world="$(stores_world)"
if [ -n "${seeded_world}" ] && [ "${seeded_world}" != "${BOOKING_WORLD}" ]; then
  if [ "${RESEED_WORLD}" = "1" ]; then
    drop_stores
  else
    say "the stores on this cluster were seeded for world '${seeded_world}', this deploy asks for '${BOOKING_WORLD}'."
    say "A seeded store does not change its counterparty, so the world can only change by deleting"
    say "both stores. That drops the effect ledger of the previous deployment, which is why it is"
    say "a decision and not a fallback:"
    say ""
    say "    RESEED_WORLD=1 BOOKING_WORLD=${BOOKING_WORLD} $0"
    say ""
    say "or by hand:"
    say "    kubectl -n ${NAMESPACE} scale deploy authority gateway --replicas=0"
    say "    kubectl -n ${NAMESPACE} delete job trusted-init-v5 --ignore-not-found"
    say "    kubectl -n ${NAMESPACE} delete pvc authority-db gateway-db"
    die "world mismatch: stores='${seeded_world}' requested='${BOOKING_WORLD}'"
  fi
fi

say "1/5 namespace, service accounts, RBAC, storage (V4.4c files) and the V5 additions"
kubectl apply -f "${APPLY_DIR}/namespace.yaml"
kubectl apply -f "${APPLY_DIR}/serviceaccounts.yaml"
kubectl apply -f "${APPLY_DIR}/storage.yaml"
kubectl apply -f "${SVC_DIR}/controller-identity.yaml"

say "2/5 frozen reference (ConfigMap v5-freeze from $(basename "${FREEZE_JSON}")), PCS key, empty controller Secret"
kubectl -n "${NAMESPACE}" create configmap v5-freeze --from-file=freeze.json="${FREEZE_JSON}" \
  --dry-run=client -o yaml | kubectl apply -f -
if [ -n "${PCS_API_KEY:-}" ]; then
  kubectl -n "${NAMESPACE}" create secret generic pcs-api-key --from-literal=key="${PCS_API_KEY}" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  say "  pcs-api-key set"
else
  die "PCS_API_KEY is not set: the Authority appraises with DCAP only and could not appraise"
fi
kubectl -n "${NAMESPACE}" create secret generic deployment-bootstrap --dry-run=client -o yaml | kubectl apply -f - >/dev/null
# Who may approve: the enrolled approver credentials, public keys only. The
# Authority pins this set on its first start and refuses a changed one. A deployment for an
# unattended evaluation passes a file that also holds a harness key
# (APPROVER_CREDENTIALS=k8s/v5/approver-credentials.eval.json). The demo pins passkeys only.
APPROVER_CREDENTIALS="${APPROVER_CREDENTIALS:-${MOCKS_DIR}/k8s/v5/approver-credentials.json}"
[ -f "${APPROVER_CREDENTIALS}" ] || die "no approver credentials at ${APPROVER_CREDENTIALS}: enrol one with
    python3 -m booking_approval.enroll passkey --approver <name> --credentials ${APPROVER_CREDENTIALS}"
(cd "${MOCKS_DIR}" && python3 -m booking_approval.enroll list --credentials "${APPROVER_CREDENTIALS}") | sed 's/^/  approver: /'
kubectl -n "${NAMESPACE}" create configmap approver-credentials \
  --from-file=approver-credentials.json="${APPROVER_CREDENTIALS}" --dry-run=client -o yaml | kubectl apply -f -

say "3/5 trusted init (both stores from one minting, only the anchors are published)"
kubectl -n "${NAMESPACE}" delete job trusted-init-v5 --ignore-not-found --wait=true
for app in authority gateway; do        # RWO PVCs: the roles must be down while init (re)seeds
  kubectl -n "${NAMESPACE}" scale deployment "${app}" --replicas=0 >/dev/null 2>&1 || true
  kubectl -n "${NAMESPACE}" wait --for=delete pod -l "app=${app}" --timeout=120s >/dev/null 2>&1 || true
done
render "${SVC_DIR}/services.yaml" | python3 -c '
import sys, yaml
docs = [d for d in yaml.safe_load_all(sys.stdin) if d]
keep = [d for d in docs if d["kind"] not in ("Deployment", "Service")]     # everything but the roles, first
yaml.safe_dump_all(keep, sys.stdout)' | kubectl apply -f -
wait_job trusted-init-v5 600
kubectl -n "${NAMESPACE}" logs job/trusted-init-v5 | tail -3
# Record the counterparty on the stores, so the next deploy can refuse a world change in a
# second. The annotation is a marker, not the guard: seed() refuses a re-seed to another world
# whatever it says, and an annotation that lies only costs the 90 s of a failed init Job.
for pvc in authority-db gateway-db; do
  kubectl -n "${NAMESPACE}" annotate pvc "${pvc}" "v5.world=${BOOKING_WORLD}" --overwrite >/dev/null
done
# The anchors (public keys) go to the operator machine for the controller: it cannot read
# this Secret itself (its Role has no access to it), and it needs only the anchors from it.
kubectl -n "${NAMESPACE}" get secret deployment-bootstrap -o jsonpath='{.data.controller-config\.json}' | base64 -d \
  | python3 -c 'import json,sys; c=json.load(sys.stdin); assert set(c)=={"anchors"}, c.keys(); json.dump(c, open(sys.argv[1],"w")); print("  controller config: anchors only (no bootstrap) OK ->", sys.argv[1])' "${OUT}/controller-config.json"
# The human secret is not published. The approval gate uses it inside the Authority only,
# after a verified passkey assertion. Remove a Secret an older deploy may have left.
kubectl -n "${NAMESPACE}" delete secret human-approver --ignore-not-found >/dev/null

say "4/5 authority and gateway (one image, two roles), Services, NetworkPolicies"
render "${SVC_DIR}/services.yaml" | kubectl apply -f -
kubectl apply -f "${SVC_DIR}/networkpolicy.yaml"
kubectl -n "${NAMESPACE}" rollout status deployment/authority --timeout=300s
if [ "${BOOKING_WORLD}" = "mock" ]; then
  kubectl -n "${NAMESPACE}" rollout status deployment/gateway --timeout=300s
else
  # A gateway seeded for a live world refuses to start until it holds the credential
  # (booking_live.startup.verify_world), and the credential arrives with
  # 37_install_openbao.sh, which needs this Deployment to exist before it can patch it.
  # The gateway is therefore expected to be down at this point. Waiting for it here would wait
  # for the fail-closed behaviour to stop working, so 37 does the wait.
  say "  gateway not awaited: world=${BOOKING_WORLD} holds no credential until 37_install_openbao.sh"
fi
for app in authority gateway; do
  kubectl -n "${NAMESPACE}" logs deployment/"${app}" 2>/dev/null | head -2 || true
done

say "5/5 controller identity"
# (a) in-cluster: a token for the narrow SA, in its own kubeconfig context
CTX="v5-controller"
TOKEN="$(kubectl -n "${NAMESPACE}" create token v5-controller --duration=6h)"
CLUSTER_NAME="$(kubectl config view --minify -o jsonpath='{.clusters[0].name}')"
kubectl config set-credentials "${CTX}" --token="${TOKEN}" >/dev/null
kubectl config set-context "${CTX}" --cluster="${CLUSTER_NAME}" --user="${CTX}" --namespace="${NAMESPACE}" >/dev/null
say "  kube context '${CTX}' created (6 h token). The controller is started with --context ${CTX}"
kubectl --context "${CTX}" auth can-i create pods -n "${NAMESPACE}" >/dev/null || die "context ${CTX} cannot create pods"
kubectl --context "${CTX}" auth can-i create deployments -n "${NAMESPACE}" >/dev/null 2>&1 && die "context ${CTX} can create deployments: the Role is too wide"
kubectl --context "${CTX}" auth can-i get configmaps -n "${NAMESPACE}" >/dev/null 2>&1 && die "context ${CTX} can read configmaps: the Role is too wide"
for verb in update patch delete create; do     # the approver set must not be the controller's to change
  kubectl --context "${CTX}" auth can-i "${verb}" configmaps -n "${NAMESPACE}" >/dev/null 2>&1 \
    && die "context ${CTX} can ${verb} configmaps: it could change who may approve"
done
kubectl -n "${NAMESPACE}" logs deployment/authority 2>/dev/null | grep "approval-gate\] installed" >/dev/null \
  || die "the Authority runs without the approval gate"
say "  approval gate installed. Approval page: ./scripts/gke-v5/49_approval_page.sh (admin context)"
# (b) on GCP: a dedicated SA with instances.get and registry read, used by impersonation (no key file)
GSA="v5-controller@${PROJECT}.iam.gserviceaccount.com"
gcloud iam service-accounts describe "${GSA}" --project "${PROJECT}" >/dev/null 2>&1 \
  || gcloud iam service-accounts create v5-controller --project "${PROJECT}" --display-name "V5 controller (probe + registry read)" >/dev/null
gcloud iam roles describe v5ControllerProbe --project "${PROJECT}" >/dev/null 2>&1 \
  || gcloud iam roles create v5ControllerProbe --project "${PROJECT}" --title "V5 controller probe" \
       --permissions compute.instances.get --stage GA >/dev/null
gcloud projects add-iam-policy-binding "${PROJECT}" --member "serviceAccount:${GSA}" \
  --role "projects/${PROJECT}/roles/v5ControllerProbe" --condition=None --quiet >/dev/null
gcloud artifacts repositories add-iam-policy-binding "${AR_REPO}" --location "${AR_LOCATION}" --project "${PROJECT}" \
  --member "serviceAccount:${GSA}" --role roles/artifactregistry.reader --quiet >/dev/null
OPERATOR="$(gcloud config get-value account 2>/dev/null)"
gcloud iam service-accounts add-iam-policy-binding "${GSA}" --project "${PROJECT}" \
  --member "user:${OPERATOR}" --role roles/iam.serviceAccountTokenCreator --quiet >/dev/null
say "  GCP SA ${GSA}: instances.get and artifactregistry.reader. ${OPERATOR} may impersonate it"

{
  echo "deployed_at=$(date -u +%Y%m%dT%H%M%SZ) freeze=${FREEZE_STAMP} verifier=dcap"
  echo "services_image=${SERVICES_IMAGE}"
  echo "runner_image=${RUNNER_IMAGE}"
  echo "controller_context=${CTX} controller_gsa=${GSA}"
} | tee "${OUT}/deploy-$(date -u +%Y%m%dT%H%M%SZ).txt"
say "done. Next: 31_run_fragment_v5.sh (it port-forwards the observation port and impersonates ${GSA})"
