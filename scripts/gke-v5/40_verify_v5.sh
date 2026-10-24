#!/usr/bin/env bash
# 40_verify_v5.sh: verifies the live GKE/CoCo substrate and runs every offline suite before a measured run.
#
# Needs:  python3 with the repository packages and OPA 0.68.0 (OPA_BIN, results_v5/opa/opa or PATH).
#         The live part also needs gcloud, kubectl, the cluster from 12 and 14, and the pinned
#         digests in scripts/gke/.digests for the init-data comparison.
# Usage:  ./40_verify_v5.sh              substrate, plus the deployment if one is present
#         ./40_verify_v5.sh --offline    the offline suites only, no cluster
#         ./40_verify_v5.sh --substrate  substrate only, never the deployment (pre-deploy pass)
# Result: One CHECK line per item and a VERDICT line. Exit code 1 on any failed check or suite,
#         in both modes, and 2 on a usage error. A measured or freeze run is valid only after
#         this script passed.
#
# What it covers:
#   - every offline test module of the repository (booking_v5.tests_verify_inventory keeps this
#     list complete) and the Kata agent policy suite against OPA 0.68.0
#   - CAA and kata-remote live, with the pinned CAA image
#   - the worker containerd prerequisite
#   - the firewall resources, the pod-VM subnet and the firewall-policy association
#   - the Kata remote annotations, reduced to cc_init_data
#   - the pinned substrate profile hash
#   - the V5 services, once 30_deploy_v5.sh has run
#
# It does not repeat the reconciliation of 12_create_cluster_v5.sh, does not test network
# behaviour (19_probe_network.sh does), and does not require the agent-system deployment.

# No -e: every check and suite records its result, and the verdict at the end decides.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
# The pinned image digests, for the init-data comparison further down. Optional: 40 also runs
# against a substrate that was never deployed to, and then there is nothing to compare.
[ -f "${DIGEST_FILE}" ] && source "${DIGEST_FILE}"
# _config.sh sets -e for the scripts that source it. Here every failure is collected instead.
set +e

CAA_NS="confidential-containers-system"
OFFLINE=0
SUBSTRATE_ONLY=0
FAILED=0
FAILED_CHECKS=0        # a live check: the substrate is not what was pinned
FAILED_SUITES=0        # an offline suite: our own code or its portability

case "${1:-}" in
  "") ;;
  --offline) OFFLINE=1 ;;
  --substrate) SUBSTRATE_ONLY=1 ;;
  *) echo "usage: $0 [--offline|--substrate]" >&2; exit 2 ;;
esac

# --- helpers ---------------------------------------------------------------------------------
check() {   # check NAME RC DETAIL
  local name="$1" rc="$2" detail="$3"
  if [ "${rc}" = "0" ]; then
    printf 'CHECK %-30s PASS  %s\n' "${name}:" "${detail}"
  else
    printf 'CHECK %-30s FAIL  %s\n' "${name}:" "${detail}"
    FAILED=1
    # Two different kinds of red would otherwise end up in one verdict: "the cluster is not
    # what was pinned" and "an offline suite is broken on this machine". Both block a freeze,
    # but only the first says anything about the substrate.
    [ "${IN_SUITES:-0}" = "1" ] && FAILED_SUITES=1 || FAILED_CHECKS=1
  fi
}

suite() {   # suite PYTHON_MODULE LABEL  (sets IN_SUITES so the verdict can tell the two apart)
  local module="$1" label="$2" out rc summary
  out="$(cd "${MOCKS_DIR}" && python3 -m "${module}" 2>&1)"
  rc=$?
  summary="$(printf '%s\n' "${out}" | grep -E '^(Ran|OK|FAILED|All [0-9]+ tests passed|[0-9]+ cases:)' | tr '\n' ' ')"
  [ -n "${summary}" ] || summary="no unittest summary"
  IN_SUITES=1 check "${label}" "${rc}" "${summary}"
  if [ "${rc}" != "0" ]; then
    printf '%s\n' "${out}" | grep -E '^(FAIL|ERROR):' | sed 's/^/      /'
    printf '      full output: (cd %s && python3 -m %s)\n' "${MOCKS_DIR}" "${module}"
  fi
}

# --- OPA 0.68.0 for the Kata agent policy suite (booking_v5.tests_kata_policy_image) ---------
# The suite skips itself when no OPA of this version is found. A skip is not a pass, so a
# missing or different OPA is a failed check here, not a silent pass.
OPA_VERSION="0.68.0"          # the version 41_probe_a19.sh pins
find_opa() {   # print the first OPA binary that reports OPA_VERSION, else nothing
  local cand out
  for cand in "${OPA_BIN:-}" "${MOCKS_DIR}/results_v5/opa/opa" "$(command -v opa 2>/dev/null)"; do
    [ -n "${cand}" ] && [ -x "${cand}" ] || continue
    # Read the whole output first. `opa version | grep -q` lets grep leave after the first line,
    # opa then dies of SIGPIPE and pipefail turns a match into a miss (a race).
    out="$("${cand}" version 2>/dev/null)" || true
    if printf '%s\n' "${out}" | grep -qE "^Version:[[:space:]]+${OPA_VERSION}$"; then
      printf '%s\n' "${cand}"
      return 0
    fi
  done
  return 1
}

# --- 1. offline regression suites ------------------------------------------------------------
# The lower layers first: a break in V0 to V4 is reported before the V5 suites that rest on it.
# V0 to V2 are script-style modules ("All N tests passed.").
suite booking_v0.tests "V0 baseline"
suite booking_v1.tests "V1 lifecycle and constraints"
suite booking_v2.tests "V2 effect ledger"
suite booking_v3.tests "V3 monitor, Authority, gateway"
suite booking_v3.tests_negative "V3 negative cases: forged, replayed, misdirected tokens and records"
suite booking_v3.tests_failure_ledger "V3 failure ledger: what the Authority records after a failed or uncertain effect"
suite booking_v3.tests_gateway_order "V3 gateway order: a spent then expired token is a past dispatch, each binding refuses alone"
suite booking_v4.tests "V4 durable store, restart, crash windows"
suite booking_v4.tests_controller "V4 controller (container-dependent cases may skip)"
suite booking_v4.tests_container "V4 container profile (skips without a container runtime)"
suite booking_v4.tests_container_env "V4 container environment"
suite booking_v4.tests_k8s "V4 Kubernetes profile (skips without a cluster)"
suite booking_v4.tests_k8s_offline "V4 Kubernetes manifests, offline"
suite booking_v4.tests_endpoint "V4 service endpoint surface"
suite booking_v5.tests_v5_offline "offline tests"
suite booking_v5.tests_v5_fixtures "fixture tests"
suite booking_v5.tests_rtmr_replay "rtmr replay tests"
# The RTMR0 tolerance of the latency series must not become a gap, so its suite belongs in
# this verification run and not only in verify.py.
suite booking_v5.tests_substrate_variance "substrate variance tests"
suite booking_v5.tests_runner_phases "runner phase-order tests"
suite booking_v5.tests_peerpod_backend "peer-pod cleanup tests"
suite booking_v5.tests_probe_analysis "probe analysis dry run"
suite booking_v5.tests_substrate_script "cluster script (12)"
suite booking_v5.tests_probe_manifests "probe scripts (18/19)"
suite booking_v5.tests_podvm_overlay "pod-VM overlay hardening"
suite booking_v5.tests_v5_protocol "attach protocol end to end"
suite booking_v5.tests_gateway_ledger "effect ledger over the durable gateway, role surfaces"
suite booking_v5.tests_v5_service "V5 end to end over the real services (offline)"
suite booking_v5.tests_collateral_cache "DCAP collateral cache: validity-bounded, no network per verdict"
suite booking_v5.tests_v5_continuation "continuation gate: second session only for a pending intervention"
suite booking_v5.tests_v5_experiment "semantic equivalence of the attested path"
suite booking_demo.tests_demo "demo acts (scripted agent, V0 baseline and V3 monitor)"
suite booking_demo.tests_report_llm "agent-run analysis: provider, malicious, utility, fail-closed classes"
suite booking_v4.tests_recovery_support "V4 recovery test double: the removed effectful recovery still recovers (control)"
suite booking_v4.tests_durable "V4.2 durable semantics (regression)"
suite booking_v5.tests_v5_deploy "V5 deployment artefacts (manifests, identity, scripts)"

# --- the live world (Duffel) ---
# Offline over recorded provider answers: no network, no credential, no cluster. These pin
# the live wiring the final evidence depends on, so a freeze cannot outrun them.
suite booking_live.tests_startup "live world: spec, effect map, context, admission, scenario/fault knobs"
suite booking_live.tests_live "live adapter: provider deviations, payment status/order/amount/currency, form accepted / meaning refused"
suite booking_live.tests_secrets "live credential sources (env, OpenBao)"
suite booking_live.tests_durable_live "live payment through the durable two-phase dispatch (UNCERTAIN survives)"
suite booking_demo.tests_live_wiring "live profile wiring (no credential on the controller in v5)"
suite booking_demo.tests_v5_duffel_composition "V5 x Duffel composition: PL1 activated, isolated policy attacks, uncertain payment, a16 alone"
suite booking_v5.tests_v5_world_config "seeded world: fail-closed gateway and Authority admission"
suite booking_v5.tests_v5_openbao "OpenBao deployment artefacts"
suite booking_v4.tests_service_world "one fail-closed world wiring for every entry point"
suite booking_v4.tests_effect_identity "downstream idempotency key: derived by the gateway, not by the controller"
suite booking_live.tests_evidence_fault "the uncertain-outcome evidence names its injected fault"
suite booking_demo.tests_chat_routing "chat routing: one input resumes a waiting run, which is not replanned or approved by it"
suite ui.tests_ui "UI: the approval facade and the chat facade are kept apart"
suite ui.tests_session_edges "UI and session edges: pause ends the turn, cross-conversation, pending approval, CSRF, orphan"
suite booking_demo.tests_chat_models "chat continuation: each tool result once, the human's reply after them"
suite booking_v5.tests_a5c_record "A5c: the freeze names the measured image and reads its hardening, 19 judges the metadata path"
suite booking_approval.tests_webauthn "approval gate: a forged, replayed or misdirected WebAuthn assertion is refused"
suite booking_approval.tests_gate "approval gate: only a pinned passkey creates a run or approves a step, the controller cannot"
suite booking_approval.tests_surface "approval gate: the page the Authority serves, request hygiene, pinned approvers"
suite booking_demo.tests_approval_gate "approval gate: whole runs decided at the Authority (person, harness), no bypass"

# --- the remaining test modules ---
suite booking_approval.tests_concurrency "approval service: one serve lock, no interleaved mutation and persistence"
suite booking_approval.tests_counter "approval gate: the signature counter does not go back"
suite booking_approval.tests_enroll_rogue "enrolment needs a one-time code and the operator's confirmation of the key"
suite booking_approval.tests_surface_window "approval surface: closed methods are refused from the first request"
suite booking_v5.tests_binding_and_aa "binding version guard, the AA reply is parsed"
suite booking_v5.tests_call_sites "every call site goes through the guarded entry point"
suite booking_v5.tests_code_closure "code closure: normalize types, intervention report, shipped flags and pins"
suite booking_v5.tests_collateral_ssrf "DCAP collateral is fetched only from the pinned root CRL URL"
suite booking_v5.tests_freeze_digests "probe and run init-data digests, the deployment reproduces the run digest"
suite booking_v5.tests_probe_recovery_closed "probe recovery path is closed"
suite booking_v5.tests_session_package_sender "session package: what a missing sender authentication does and does not reach"
suite booking_v5.tests_successor_fact_boundary "characterisation: the Authority signs a changed fact of a bound runner (accepted limit, not a defence)"
suite booking_v5.tests_v5_attested_decision "attested decision path"
suite booking_v5.tests_v5_equivalence_evaluation "equivalence evaluation of the attested path"
suite booking_v5.tests_v5_initdata_determinism "init-data digest is deterministic"
suite booking_v5.tests_v5_observation "observation surface and its trust assumption"
suite booking_v5.tests_v5_transport_proxy "attested transport proxy"

# The Kata agent policy against OPA 0.68.0. OPA_BIN is handed to the suite.
if OPA_FOUND="$(find_opa)"; then
  export OPA_BIN="${OPA_FOUND}"
  check "OPA ${OPA_VERSION}" 0 "${OPA_FOUND}"
  suite booking_v5.tests_kata_policy_image "Kata agent policy: pinned image, one guest pull, annotation (OPA ${OPA_VERSION})"
else
  check "OPA ${OPA_VERSION}" 1 "not found (set OPA_BIN, run 41_probe_a19.sh, or put it on PATH): the Kata policy suite would only skip"
fi

# Pins this list against the modules that exist, and verify.py's package list.
suite booking_v5.tests_verify_inventory "test inventory: 40_verify_v5.sh and verify.py cover every test module"

if [ "${OFFLINE}" = "1" ]; then
  echo
  if [ "${FAILED}" = "0" ]; then echo "VERDICT: offline checks PASS"; else echo "VERDICT: offline checks FAILED"; fi
  exit "${FAILED}"
fi

require_project
require_v5_pins

# --- 2. cluster network ----------------------------------------------------------------------
NETWORK="$(gcloud container clusters describe "${CLUSTER}" "${LOCATION_ARGS[@]}" --project "${PROJECT}" \
  --format='value(network)' 2>/dev/null)"
rc=$?
if [ "${rc}" = "0" ] && [ -n "${NETWORK}" ]; then
  check "cluster network" 0 "${NETWORK}"
else
  check "cluster network" 1 "could not determine cluster network"
  NETWORK=""
fi

# --- 3. CAA and kata-remote ------------------------------------------------------------------
ready="$(kubectl -n "${CAA_NS}" get ds cloud-api-adaptor-daemonset \
  -o jsonpath='{.status.numberReady}/{.status.desiredNumberScheduled}' 2>/dev/null)"
if [ -n "${ready}" ] && [ "${ready%/*}" = "${ready#*/}" ] && [ "${ready%/*}" != "0" ]; then
  check "caa daemonset" 0 "ready ${ready}"
else
  check "caa daemonset" 1 "ready ${ready:-missing}"
fi

handler="$(kubectl get runtimeclass kata-remote -o jsonpath='{.handler}' 2>/dev/null)"
if [ "${handler}" = "kata-remote" ]; then
  check "runtimeclass" 0 "kata-remote handler=${handler}"
else
  check "runtimeclass" 1 "expected kata-remote, got ${handler:-missing}"
fi

caa_image="$(kubectl -n "${CAA_NS}" get ds cloud-api-adaptor-daemonset \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="cloud-api-adaptor-con")].image}' 2>/dev/null)"
expected_caa_image="quay.io/confidential-containers/cloud-api-adaptor:${CAA_IMAGE_TAG}"
if [ "${caa_image}" = "${expected_caa_image}" ]; then
  check "caa image pin" 0 "${caa_image}"
else
  check "caa image pin" 1 "expected ${expected_caa_image}, got ${caa_image:-missing}"
fi

# --- 4. worker containerd prerequisite -------------------------------------------------------
# Peer pods require discard_unpacked_layers=false. 12 applies it, 40 checks that it still holds
# before a measured run.
nodes="$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)"
if [ -z "${nodes}" ]; then
  check "worker nodes" 1 "no nodes found"
else
  for node in ${nodes}; do
    value="$(gcloud compute ssh "${node}" --zone "${ZONE}" --project "${PROJECT}" --quiet --command '
grep -h "^[[:space:]]*discard_unpacked_layers[[:space:]]*=" \
  /etc/containerd/config.toml \
  /etc/containerd/config.d/*.toml \
  2>/dev/null || true
' 2>/dev/null)"
    rc=$?
    if [ "${rc}" != "0" ]; then
      check "containerd ${node}" 1 "could not read configuration"
    elif printf '%s\n' "${value}" | grep -Eq 'discard_unpacked_layers[[:space:]]*=[[:space:]]*false'; then
      check "containerd ${node}" 0 "discard_unpacked_layers=false"
    else
      check "containerd ${node}" 1 "discard_unpacked_layers=false not found"
    fi
  done
fi

# --- 5. VPC firewall resources ---------------------------------------------------------------
# 12 owns the reconciliation. 40 checks that the resources the pinned substrate needs are
# present, and 19 later checks the network behaviour from inside the pods.
for rule in v5-allow-peerpod-tunnel v5-allow-peerpod-tunnel-return; do
  gcloud compute firewall-rules describe "${rule}" --project "${PROJECT}" >/dev/null 2>&1
  check "fw ${rule}" "$?" "VPC firewall rule"
done
for prio in "${FW_PRIO_DENY}" "${FW_PRIO_ALLOWS[@]}"; do
  gcloud compute network-firewall-policies rules describe "${prio}" --firewall-policy "${FW_POLICY}" \
    --global-firewall-policy --project "${PROJECT}" >/dev/null 2>&1
  check "fw policy rule ${prio}" "$?" "${FW_POLICY}"
done

# --- 6. pod-VM subnet ------------------------------------------------------------------------
subnet_info="$(gcloud compute networks subnets describe "${PODVM_SUBNET}" --region "${REGION}" --project "${PROJECT}" \
  --format='value(ipCidrRange,privateIpGoogleAccess)' 2>/dev/null)"
rc=$?
if [ "${rc}" != "0" ] || [ -z "${subnet_info}" ]; then
  check "podvm subnet" 1 "${PODVM_SUBNET} missing or unreadable"
else
  read -r subnet_cidr private_google_access <<<"${subnet_info}"
  if [ "${subnet_cidr}" = "${PODVM_SUBNET_CIDR}" ] && [ "${private_google_access}" = "True" ]; then
    check "podvm subnet" 0 "${PODVM_SUBNET}=${subnet_cidr}, private-google-access=true"
  else
    check "podvm subnet" 1 "${PODVM_SUBNET}: cidr=${subnet_cidr:-missing}, private-google-access=${private_google_access:-missing}, expected ${PODVM_SUBNET_CIDR}/True"
  fi
fi

# --- 7. firewall-policy association ----------------------------------------------------------
# `associations list` does not exist in the gcloud interface used here. The association is
# part of the policy's describe output.
if [ -z "${NETWORK}" ]; then
  check "fw policy association" 1 "cluster network unavailable"
else
  assoc_name="${FW_POLICY}-${NETWORK##*/}"
  assoc_yaml="$(gcloud compute network-firewall-policies describe "${FW_POLICY}" --global --project "${PROJECT}" \
    --format='yaml(associations)' 2>/dev/null)"
  rc=$?
  if [ "${rc}" != "0" ] || [ -z "${assoc_yaml}" ]; then
    check "fw policy association" 1 "${FW_POLICY} missing or unreadable"
  elif printf '%s\n' "${assoc_yaml}" | grep -Fq "name: ${assoc_name}" &&
       printf '%s\n' "${assoc_yaml}" | grep -Fq "/networks/${NETWORK##*/}"; then
    check "fw policy association" 0 "${assoc_name} -> ${NETWORK##*/}"
  else
    check "fw policy association" 1 "expected ${assoc_name} -> ${NETWORK##*/}"
  fi
fi

# --- 8. Kata remote annotation hardening -----------------------------------------------------
# The allowlist must read ["cc_init_data"]. kata-deploy writes two remote configurations.
# 14_install_coco.sh hardens both, and 40 reads both again from every kata-enabled worker.
kata_nodes="$(kubectl get nodes -l katacontainers.io/kata-runtime=true -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)"
if [ -z "${kata_nodes}" ]; then
  check "annotation allowlist" 1 "no kata-enabled node found"
else
  conf1="/opt/kata/share/defaults/kata-containers/configuration-remote.toml"
  conf2="/opt/kata/share/defaults/kata-containers/runtimes/remote/configuration-remote.toml"
  for node in ${kata_nodes}; do
    report="$(gcloud compute ssh "${node}" --zone "${ZONE}" --project "${PROJECT}" --quiet --command '
for conf in \
  /opt/kata/share/defaults/kata-containers/configuration-remote.toml \
  /opt/kata/share/defaults/kata-containers/runtimes/remote/configuration-remote.toml
do
  [ -f "$conf" ] || continue
  value="$(sudo sed -n '"'"'s/^[[:space:]]*enable_annotations[[:space:]]*=[[:space:]]*//p'"'"' "$conf" | tail -1)"
  printf "%s\t%s\n" "$conf" "$value"
done
' 2>/dev/null)"
    rc=$?
    expected1="${conf1}"$'\t''["cc_init_data"]'
    expected2="${conf2}"$'\t''["cc_init_data"]'
    if [ "${rc}" = "0" ] && printf '%s\n' "${report}" | grep -Fxq "${expected1}" &&
       printf '%s\n' "${report}" | grep -Fxq "${expected2}"; then
      check "annotations ${node}" 0 "both remote configs = [\"cc_init_data\"]"
    else
      compact="$(printf '%s\n' "${report}" | tr '\n' ' ')"
      check "annotations ${node}" 1 "${compact:-remote configuration unreadable}"
    fi
  done
fi

# --- 9. substrate profile hash ---------------------------------------------------------------
hash="$(cd "${MOCKS_DIR}" && python3 -c '
from booking_v5.profile_v5 import substrate_profile_hash
print(substrate_profile_hash())
' 2>/dev/null)"
rc=$?
if [ "${rc}" = "0" ] && [ -n "${hash}" ]; then
  check "substrate profile hash" 0 "${hash} (pin in Authority reference values)"
else
  check "substrate profile hash" 1 "could not compute substrate profile hash"
fi

# --- 10. V5 services (judged only once 30_deploy_v5.sh has run, absent = SKIP, not FAIL) -----
NS_SVC="${NAMESPACE:-agent-system}"
# Which checks run is decided by the caller, not by what happens to be in the cluster.
# A kept cluster (KEEP_CLUSTER=1) still carries the previous run's agent-system, so an
# auto-detect makes the pre-deploy pass check a deployment this run has not built yet. It
# would fail on the init-data digest (23 has not run) and on the controller RBAC (30 has not
# run), late in a bring-up, with nothing wrong.
if [ "${SUBSTRATE_ONLY}" = "1" ]; then
  printf 'CHECK %-30s SKIP  %s\n' "v5 services:" "--substrate: the deployment is verified after 23 and 30"
elif kubectl -n "${NS_SVC}" get deployment authority >/dev/null 2>&1; then
  for app in authority gateway; do
    ready="$(kubectl -n "${NS_SVC}" get deployment "${app}" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)"
    role_arg="$(kubectl -n "${NS_SVC}" get deployment "${app}" -o jsonpath='{.spec.template.spec.containers[0].args}' 2>/dev/null)"
    cmd_arg="$(kubectl -n "${NS_SVC}" get deployment "${app}" -o jsonpath='{.spec.template.spec.containers[0].command}' 2>/dev/null)"
    # The Authority runs behind the approval gate: entry point booking_approval.service (it
    # restores the authority role itself, then installs the gate and the approval page), so its
    # args carry --approval-bind instead of --role authority.
    if [ "${ready}" = "1" ] && printf '%s' "${role_arg}" | grep -q "\"--role\",\"${app}\""; then
      check "v5 ${app} role" 0 "ready 1/1, --role ${app}"
    elif [ "${ready}" = "1" ] && [ "${app}" = "authority" ] \
         && printf '%s' "${cmd_arg}" | grep -q "booking_approval.service" \
         && printf '%s' "${role_arg}" | grep -q "\"--approval-bind\""; then
      check "v5 ${app} role" 0 "ready 1/1, booking_approval.service (authority role behind the approval gate)"
    else
      check "v5 ${app} role" 1 "ready=${ready:-0} cmd=${cmd_arg} args=${role_arg}"
    fi
  done

  # No harness listener in the attested configuration: the test./read. surface exists only in
  # the V4 manifest for A9. Here no args carry --harness-bind and no container exposes a second
  # port, so the controller has no harness it could reach through pods/portforward.
  harness=""
  for app in authority gateway; do
    args="$(kubectl -n "${NS_SVC}" get deployment "${app}" -o jsonpath='{.spec.template.spec.containers[*].args}' 2>/dev/null)"
    ports="$(kubectl -n "${NS_SVC}" get deployment "${app}" -o jsonpath='{.spec.template.spec.containers[*].ports[*].containerPort}' 2>/dev/null)"
    printf '%s' "${args}" | grep -q -- "--harness-bind" && harness="${harness} ${app}:args"
    printf '%s' "${ports}" | grep -qw "8445" && harness="${harness} ${app}:port-8445"
  done
  if [ -z "${harness}" ]; then
    check "v5 no harness listener" 0 "no --harness-bind, no port 8445 on authority/gateway"
  else
    check "v5 no harness listener" 1 "harness surface present:${harness}"
  fi

  # The reference the Authority was seeded from must be the frozen file on disk. FREEZE_STAMP
  # comes from _config.sh. Between a re-measurement (18 to 22, new freeze) and the redeploy (30)
  # the ConfigMap still carries the previous line. That is reported as PASS with the line named,
  # because it is a deployment state, not a substrate defect. A ConfigMap that matches no
  # recorded freeze is the failure.
  cm_sha="$(kubectl -n "${NS_SVC}" get configmap v5-freeze -o jsonpath='{.data.freeze\.json}' 2>/dev/null | shasum -a 256 | cut -d' ' -f1)"
  file_sha="$(shasum -a 256 "${MOCKS_DIR}/results_v5/freeze-candidate/freeze-${FREEZE_STAMP}.json" 2>/dev/null | cut -d' ' -f1)"
  other=""
  for f in "${MOCKS_DIR}"/results_v5/freeze-*/freeze-*.json "${MOCKS_DIR}"/results_v5/freeze-candidate/freeze-*.json; do
    [ -f "${f}" ] || continue
    [ "$(shasum -a 256 "${f}" | cut -d' ' -f1)" = "${cm_sha}" ] && other="$(basename "${f}")"
  done
  if [ -n "${cm_sha}" ] && [ "${cm_sha}" = "${file_sha}" ]; then
    check "v5 reference configmap" 0 "v5-freeze == freeze-${FREEZE_STAMP}.json"
  elif [ -n "${cm_sha}" ] && [ -n "${other}" ]; then
    check "v5 reference configmap" 0 "v5-freeze == ${other} (previous line deployed, run 30 for ${FREEZE_STAMP})"
  else
    check "v5 reference configmap" 1 "v5-freeze (${cm_sha:0:12}) matches no recorded freeze (want freeze-${FREEZE_STAMP}.json ${file_sha:0:12})"
  fi

  # The init-data digest the Authority pins must equal the one the controller will send.
  # The Authority computes it inside the services image, which carries its own copy of
  # k8s/v5/init-data (Dockerfile.services). The controller computes it from the working tree.
  # A services image built before the last 13_genpolicy.sh therefore pins a policy nobody
  # renders any more, and every run dies with rtmr3-mismatch after a full TD boot. That is
  # expensive to find by running, so this compares the two numbers directly. It needs no
  # cluster state: both sides are computed here.
  # This is not an `if` without an `else`: a check that silently does not run looks the same as
  # a check that passed, and that is the failure this block prevents.
  if [ -z "${RUNNER_IMAGE:-}" ] || [ -z "${SERVICES_IMAGE:-}" ]; then
    check "v5 init-data digest" 1 "not compared: no pinned images in ${DIGEST_FILE} (run ../gke/20_build_push_images.sh and 23)"
  else
    idd_tree="$(cd "${MOCKS_DIR}" && python3 -c "
from booking_v5.service_v5 import deployment_init_data_digest
import sys
print(deployment_init_data_digest(sys.argv[1]))" "${RUNNER_IMAGE}" 2>/dev/null)"
    idd_image="$(docker run --rm --platform linux/amd64 --entrypoint python3 "${SERVICES_IMAGE}" -c "
from booking_v5.service_v5 import deployment_init_data_digest
import sys
print(deployment_init_data_digest(sys.argv[1]))" "${RUNNER_IMAGE}" 2>/dev/null | tr -d '\r')"
    if [ -z "${idd_tree}" ] || [ -z "${idd_image}" ]; then
      check "v5 init-data digest" 1 "could not compute both sides (tree='${idd_tree:0:12}' image='${idd_image:0:12}'). Can docker run the amd64 services image?"
    elif [ "${idd_tree}" = "${idd_image}" ]; then
      check "v5 init-data digest" 0 "controller and Authority agree (${idd_tree:0:12})"
    else
      check "v5 init-data digest" 1 "controller renders ${idd_tree:0:12}, the Authority pins ${idd_image:0:12}. Rebuild the services image (23) after 13_genpolicy.sh, then redeploy (30)"
    fi
  fi

  # The controller Secret carries the anchors only (no bootstrap outside the authority pod).
  keys="$(kubectl -n "${NS_SVC}" get secret deployment-bootstrap -o jsonpath='{.data.controller-config\.json}' 2>/dev/null | base64 -d 2>/dev/null | python3 -c 'import json,sys; print(",".join(sorted(json.load(sys.stdin))))' 2>/dev/null)"
  if [ "${keys}" = "anchors" ]; then
    check "v5 controller secret" 0 "anchors only"
  else
    check "v5 controller secret" 1 "keys=${keys:-unreadable}"
  fi

  # The controller identity holds the five verbs it needs and none of five that would rewrite
  # the services.
  if kubectl config get-contexts v5-controller >/dev/null 2>&1; then
    bad=""
    for v in "create pods" "get pods/attach" "create pods/portforward" "get pods/log" "patch peerpods.confidentialcontainers.org"; do
      kubectl --context v5-controller auth can-i ${v} -n "${NS_SVC}" >/dev/null 2>&1 || bad="${bad} missing:${v// /-}"
    done
    for v in "create deployments" "get configmaps" "get secrets" "delete services" "create networkpolicies"; do
      kubectl --context v5-controller auth can-i ${v} -n "${NS_SVC}" >/dev/null 2>&1 && bad="${bad} EXTRA:${v// /-}"
    done
    if [ -z "${bad}" ]; then
      check "v5 controller identity" 0 "context v5-controller: spawn/attach/portforward/log/peerpods, none of the five extra verbs"
    else
      check "v5 controller identity" 1 "${bad}"
    fi
  else
    check "v5 controller identity" 1 "no kube context v5-controller (30_deploy_v5.sh creates it)"
  fi
else
  printf 'CHECK %-30s SKIP  %s\n' "v5 services:" "not deployed (30_deploy_v5.sh)"
fi

# --- verdict ---------------------------------------------------------------------------------
echo
if [ "${FAILED}" = "0" ]; then
  echo "VERDICT: live GKE/CoCo substrate verification PASS"
  echo "NEXT: 18_probe_peer_pod.sh -> evidence verification -> 19_probe_network.sh"
else
  [ "${FAILED_CHECKS:-0}" = "1" ] && echo "VERDICT: the substrate does not match the pin. Do not record a freeze or measured run"
  [ "${FAILED_SUITES:-0}" = "1" ] && echo "VERDICT: an offline suite is red. The cluster checks above may all be green, but a freeze needs both"
fi
exit "${FAILED}"
