#!/usr/bin/env bash
# 18_probe_peer_pod.sh: probes the peer-pod boot path, the measured runner and the runtime measurement.
#
# Needs:  The cluster with the CAA from 14, the pod-VM image pin, kubectl, gcloud, python3 with
#         booking_v5. P2 and P3 also need the digest file written by ../gke/20_build_push_images.sh
#         (without it only P1 runs). docker is optional and used for a preflight of the runner image.
# Usage:  ./scripts/gke-v5/18_probe_peer_pod.sh
#         P1_TIMEOUT (overlay images only), SKIP_P1=1 (dev runs only, not for the final freeze),
#         P2_TIMEOUT (use 600 for the final freeze) and KEEP_V5_PROBES=1 (skip the cleanup for a
#         post-mortem).
# Result: Timings, verdicts and raw evidence under results_v5/probe/. Exit code non zero if P1 or P2
#         miss their expected outcome.
#
# Three separate questions, each with its own verdict:
#   P1 boot path  a peer pod without init-data (nginx). On a pre-overlay image this is the
#                 plumbing smoke test          -> READY / FAILED. On a V5 overlay image
#                 (-ov<rev>) initdata-measure fails without a digest and the agents carry
#                 only Wants=/After= on it, so the same pod must still come up: the guest
#                 does not gate itself, the Authority refuses the unmeasured TD
#                                              -> READY_UNMEASURED_OK / NOT_READY / NO_PODVM
#   P2 measured   does our runner image boot under our measured profile (kata-remote
#                 + cc_init_data from booking_v5.profile_v5) and obtain evidence
#                 with a runtime_data from the Attestation Agent, unprivileged?   -> EVIDENCE_OK / .../EVIDENCE_FAIL
#   P3 rtmr       did both AAEL events of the production sequence land?           -> RTMR_OK / RTMR_INCOMPLETE(n/2)
# P2 and P3 run their checks as the container's initial command and report through the log:
# the measured policy forbids exec (ExecProcessRequest := false), so `kubectl exec` would be
# refused and is not used as a probe.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
OUT="${MOCKS_DIR}/results_v5/probe"; mkdir -p "${OUT}"
NS="v5-probe"

say "cleanup: deleting stale probe resources from earlier runs"
kubectl -n "${NS}" delete pod --all --wait=false >/dev/null 2>&1 || true
kubectl -n "${NS}" delete peerpods.confidentialcontainers.org --all --wait=false >/dev/null 2>&1 || true

# The probe workloads are removed on every exit: normal end, an early `exit 0` (no
# DIGEST_FILE), a `die`, or Ctrl-C. KEEP_V5_PROBES=1 skips this for a post-mortem.
cleanup_probe() {
  if [ "${KEEP_V5_PROBES:-0}" = "1" ]; then say "cleanup SKIPPED (KEEP_V5_PROBES=1)"; return; fi
  say "cleanup: removing ${NS} probe workloads"
  kubectl -n "${NS}" delete pod --all --wait=false >/dev/null 2>&1 || true
  kubectl -n "${NS}" delete peerpods.confidentialcontainers.org --all --wait=false >/dev/null 2>&1 || true
}
trap cleanup_probe EXIT

# A namespace 91 deleted moments ago may still be Terminating (peer-pod finalizers wait for the
# VM). `apply` cannot revive it and new pods are Forbidden there. Wait for it to be gone first.
for _ in $(seq 1 60); do
  [ "$(kubectl get namespace "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Terminating" ] || break
  sleep 5
done
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# wait_ready NAME TIMEOUT -> prints "NAME READY <s>" or "NAME FAILED/TIMEOUT <s>". Returns 1 on failure
wait_ready() {
  local name="$1" timeout="$2" t0 t1 phase
  t0=$(date +%s)
  if kubectl -n "${NS}" wait --for=condition=Ready "pod/${name}" --timeout="${timeout}" >/dev/null 2>&1; then
    t1=$(date +%s); echo "${name} READY $((t1 - t0)) s" | tee -a "${OUT}/boot-times-${STAMP}.txt"; return 0
  fi
  t1=$(date +%s); phase="$(kubectl -n "${NS}" get pod "${name}" -o jsonpath='{.status.phase}' 2>/dev/null || echo unknown)"
  echo "${name} FAILED/TIMEOUT after $((t1 - t0)) s (phase=${phase})" | tee -a "${OUT}/boot-times-${STAMP}.txt"
  kubectl -n "${NS}" describe pod "${name}" | tail -25 | tee -a "${OUT}/boot-times-${STAMP}.txt"
  return 1
}

say "precheck: containerd discard_unpacked_layers=false still in place (kata-deploy rewrites the config)"
for node in $(kubectl get nodes -o jsonpath='{.items[*].metadata.name}'); do
  line="$(gcloud compute ssh "${node}" --zone "${ZONE}" --project "${PROJECT}" --quiet --command \
    "grep -h discard_unpacked_layers /etc/containerd/config.toml /etc/containerd/config.d/*.toml 2>/dev/null" 2>/dev/null || true)"
  echo "${node}: ${line:-<not set>}"
  echo "${line}" | grep -q "= true" && die "discard_unpacked_layers=true on ${node}: re-run 12_create_cluster_v5.sh (patch) and then 18"
done

# Stale probe pods first: the CAA's startup probe stays red while any peer pod is not
# Ready, and a stale Pending peer pod waits for the CAA socket (deadlock).
say "cleanup: removing probe pods from earlier runs"
kubectl -n "${NS}" delete pod --all --wait=true --timeout=120s >/dev/null 2>&1 || true

say "precheck: CAA DaemonSet ready and its hypervisor socket present (a fresh rollout needs a moment)"
kubectl -n confidential-containers-system rollout status ds/cloud-api-adaptor-daemonset --timeout=300s >/dev/null
for i in $(seq 1 30); do
  kubectl -n confidential-containers-system logs ds/cloud-api-adaptor-daemonset --tail=200 2>/dev/null | grep -q "server started" && break
  sleep 5
done
sleep 10

# --- P1: what "a peer pod without init-data" means depends on the pod-VM image ----------
# Without the V5 overlay, init-data is optional: with no init-data the agent still starts and
# nginx becomes Ready, which makes a fine smoke test for the CAA plumbing.
# With the overlay (image name ends in -ov<rev>) `initdata-measure` fails without
# /run/peerpod/initdata.digest. The agents do not depend on it (Wants=/After= drop-ins, no
# Requires=), so the pod still becomes Ready. P1 on an overlay image is therefore the regression
# check that a failed measurement does not break the boot. A Requires= would make the guest gate
# itself. It must also have produced a pod VM, so that a broken CAA cannot hide behind a boot
# failure. Fail-closed lives in the Authority (V5_RTMR3_MISMATCH), not here.
OVERLAY_IMAGE=0; case "${PODVM_IMAGE}" in *-ov*) OVERLAY_IMAGE=1 ;; esac
P1_TIMEOUT="${P1_TIMEOUT:-180}"     # seconds, a healthy peer pod is Ready in 85-120 s
SKIP_P1="${SKIP_P1:-0}"             # 1 skips P1 entirely (dev runs only, not for the final freeze)

podvm_exists() {  # podvm_exists POD -> 0 if GCE has a pod VM for that pod
  [ -n "$(gcloud compute instances list --project "${PROJECT}" --filter="name~^podvm-$1" --format='value(name)' 2>/dev/null)" ]
}

if [ "${SKIP_P1}" = "1" ]; then
  say "P1 SKIPPED (SKIP_P1=1): dev run only, the freeze run needs a real P1 verdict"
  P1="SKIPPED"
else
  # guest-pull: the image is fetched inside the TD and only private.googleapis.com is reachable,
  # so Docker Hub images come through Google's mirror.
  kubectl -n "${NS}" delete pod nginx-peer --ignore-not-found --wait=true >/dev/null
  kubectl -n "${NS}" run nginx-peer --restart=Never --image=mirror.gcr.io/library/nginx:latest \
    --overrides='{"spec":{"runtimeClassName":"kata-remote"}}' >/dev/null

  if [ "${OVERLAY_IMAGE}" = "1" ]; then
    say "P1 boot survives a failed measurement: a peer pod without init-data must still become Ready on ${PODVM_IMAGE}"
    P1=""; saw_vm=0; t0=$(date +%s)
    while [ "$(( $(date +%s) - t0 ))" -lt "${P1_TIMEOUT}" ]; do
      podvm_exists nginx-peer && saw_vm=1
      if [ "$(kubectl -n "${NS}" get pod nginx-peer -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)" = "True" ]; then
        P1="READY_UNMEASURED_OK"; break
      fi
      sleep 10
    done
    if [ -z "${P1}" ]; then
      [ "${saw_vm}" = "1" ] && P1="NOT_READY" || P1="NO_PODVM"
    fi
    {
      echo "nginx-peer (no init-data) ${P1} after $(( $(date +%s) - t0 )) s, pod VM seen: ${saw_vm}"
      kubectl -n "${NS}" get pod nginx-peer -o jsonpath='{.status.phase}{"\n"}' 2>/dev/null
      kubectl -n "${NS}" get events --field-selector involvedObject.name=nginx-peer \
        --sort-by=.lastTimestamp -o jsonpath='{.items[-1:].reason}: {.items[-1:].message}' 2>/dev/null | tail -c 300; echo
    } | tee -a "${OUT}/boot-times-${STAMP}.txt"
  else
    say "P1 smoke: nginx as a peer pod (no init-data, pre-overlay image ${PODVM_IMAGE})"
    P1=FAILED; wait_ready nginx-peer 600s && P1=READY
  fi
  gcloud compute instances list --project "${PROJECT}" --filter="name~podvm" \
    --format="table(name,machineType.basename(),confidentialInstanceConfig,tags.items)" | tee "${OUT}/podvm-instances-${STAMP}.txt"

  # --- isolate P1 from P2: a non-starting nginx-peer left running would keep
  # retrying CreatePodSandbox while runner-peer (P2) is probed right after it. That race
  # leaves nginx-peer-resource-* stragglers behind. Do not start P2 until both the PeerPod CR
  # and its pod VM are confirmed gone. ---
  say "P1 complete: removing the P1 peer pod before P2"
  # This teardown is always the pathological case: the pod never got a sandbox, so its
  # deletion has nothing to unwind and it stays Terminating while kubelet waits for a runtime
  # that never started. The CAA does not delete the pod VM because it never finished creating
  # the pod. And the PeerPod CR keeps peer.pod/finalizer because peerpod-ctrl of CAA 0.21.1
  # registers no gcp provider. Waiting for any of that to resolve itself only burns the timeout
  # and then fails a run whose P1 just succeeded. The three steps are therefore done here, in
  # an order that cannot leave a running c3 TDX instance unaccounted for: API object, then VM,
  # then finalizer.
  kubectl -n "${NS}" delete pod nginx-peer --ignore-not-found --wait=false >/dev/null 2>&1 || true
  for _ in $(seq 1 15); do
    kubectl -n "${NS}" get pod nginx-peer >/dev/null 2>&1 || break
    sleep 2
  done
  if kubectl -n "${NS}" get pod nginx-peer >/dev/null 2>&1; then
    say "  nginx-peer still Terminating (no sandbox to unwind), force-removing the API object"
    kubectl -n "${NS}" delete pod nginx-peer --grace-period=0 --force >/dev/null 2>&1 || true
  fi
  # The VM goes before the finalizer: if the delete fails, a CR still points at the instance,
  # which is what 91 looks for. The other way round a running TDX VM would be orphaned.
  for vm in $(gcloud compute instances list --project "${PROJECT}" \
                --filter='name~^podvm-nginx-peer-' --format='value(name)' 2>/dev/null); do
    say "  deleting pod VM ${vm} (its pod never started, so the CAA will not)"
    gcloud compute instances delete "${vm}" --zone "${ZONE}" --project "${PROJECT}" --quiet >/dev/null 2>&1 || true
  done
  # Now the finalizer protects nothing.
  for pp in $(kubectl -n "${NS}" get peerpods.confidentialcontainers.org -o name 2>/dev/null); do
    kubectl -n "${NS}" patch "${pp}" --type=merge -p '{"metadata":{"finalizers":null}}' >/dev/null 2>&1 || true
  done
  kubectl -n "${NS}" delete peerpods.confidentialcontainers.org --all --wait=false >/dev/null 2>&1 || true

  p1_clean=0
  for _ in $(seq 1 90); do
    peerpods="$({ kubectl -n "${NS}" get peerpods.confidentialcontainers.org -o name 2>/dev/null || true; } | wc -l | tr -d ' ')"
    podvms="$(gcloud compute instances list --project "${PROJECT}" --filter='name~^podvm-nginx-peer-' --format='value(name)' 2>/dev/null)"
    if [ "${peerpods}" = "0" ] && [ -z "${podvms}" ]; then p1_clean=1; break; fi
    sleep 2
  done
  [ "${p1_clean}" = "1" ] || die "P1 resources did not clean up. Refusing to start P2 on a dirty probe substrate"
fi

p1_ok() {   # the expected P1 outcome for this image generation
  [ "${P1}" = "SKIPPED" ] && return 0
  if [ "${OVERLAY_IMAGE}" = "1" ]; then [ "${P1}" = "READY_UNMEASURED_OK" ]; else [ "${P1}" = "READY" ]; fi
}
p1_hint() {
  if [ "${OVERLAY_IMAGE}" = "1" ]; then
    case "${P1}" in
      NOT_READY) echo "the pod VM exists but the pod never became Ready: the overlay breaks the boot when the measurement fails (a Requires= crept back in, or an ordering cycle). Read the serial log" ;;
      NO_PODVM)  echo "no pod VM was created at all: this is CAA/peer-pod plumbing, not the overlay (check the CAA log)" ;;
      *)         echo "unexpected P1 result ${P1}" ;;
    esac
  else
    echo "peer pods do not boot on this cluster"
  fi
}

if [ ! -f "${DIGEST_FILE}" ]; then
  echo "P1 no-init-data peer pod: ${P1}" | tee -a "${OUT}/verdict-${STAMP}.txt"
  p1_ok || die "abort: $(p1_hint)"
  say "P2/P3 skipped: no ${DIGEST_FILE} (run ../gke/20_build_push_images.sh, then 18 again)"
  exit 0
fi
say "P2 measured runner: our image under the measured profile, the production V5 bind sequence as initial command"
source "${DIGEST_FILE}"
# The interpreter path comes from the image, not from a guess: the GKE image is built on
# python:3.11-slim, where python3 lives at /usr/local/bin/python3 and /usr/bin/python3 does
# not exist. 20_build_push_images.sh reads it out of the image and records it here. A
# .digests without the line falls back to a PATH lookup.
RUNNER_PY="${RUNNER_PYTHON:-python3}"
say "runner interpreter: ${RUNNER_PY} (from ${DIGEST_FILE##*/})"
# Preflight, if docker is available: a wrong command or a missing module surfaces otherwise
# only after a full TD boot and guest pull, as CreateContainer failing inside the guest.
if command -v docker >/dev/null 2>&1; then
  docker run --rm --platform linux/amd64 --entrypoint "${RUNNER_PY}" "${RUNNER_IMAGE}" \
    -c 'import booking_v5.probe_bind' >/dev/null 2>&1 \
    || die "the runner image cannot run '${RUNNER_PY} -m booking_v5.probe_bind'. Rebuild and push it (../gke/20_build_push_images.sh)"
  say "preflight: ${RUNNER_PY} -m booking_v5.probe_bind runs in the pinned image"
else
  say "preflight SKIPPED (no docker): a wrong interpreter path or a missing booking_v5 shows up as CreateContainer failing in the guest"
fi
# The probe does not attest over a random digest. It runs the production sequence
# (booking_v5.probe_bind): boot key, AAEL "v5 boot-key", AAEL "v5 bind", then evidence over the
# canonical binding. There is no Authority in a probe run, so the binding fields and the nonce
# are generated here and recorded. 20 recomputes the binding from this file and checks
# REPORTDATA and RTMR3 against it. That makes the probe evidence a fixture for the whole chain.
BIND_RUN="probe-${STAMP}"
BIND_STEP=1
BIND_FRAG="$(python3 -c 'import os;print(os.urandom(32).hex())')"
BIND_STATE="$(python3 -c 'import os;print(os.urandom(32).hex())')"
BIND_NONCE="$(python3 -c 'import os;print(os.urandom(32).hex())')"
python3 -c "import json,sys;json.dump({'run':sys.argv[1],'step':int(sys.argv[2]),'fragment_hash':sys.argv[3],'state_hash':sys.argv[4],'nonce':sys.argv[5]},open(sys.argv[6],'w'),indent=2)" \
  "${BIND_RUN}" "${BIND_STEP}" "${BIND_FRAG}" "${BIND_STATE}" "${BIND_NONCE}" "${OUT}/binding-${STAMP}.json"
# Two passes: (1) the probe manifest without init-data for genpolicy, (2) the same manifest
# with init-data carrying the policy genpolicy produced for it. The policy pins namespace,
# command, env and mounts, so it must be generated from the manifest that is launched.
render_runner_peer() {   # IMAGE NS POLICY_FILE_OR_EMPTY  (binding fields from the environment)
python3 - "$@" <<'PY'
import os, sys, yaml
from booking_v5.profile_v5 import build_runner_pod_manifest
image, ns, policy_file = sys.argv[1:4]
policy = open(policy_file).read() if policy_file else None
m = build_runner_pod_manifest(image=image, namespace=ns, name="runner-peer", policy_rego=policy)
c = m["spec"]["containers"][0]
c.pop("stdin", None); c.pop("stdinOnce", None)
# The measured policy pins the command, so it must be identical in both passes (the pass without
# init-data is only genpolicy's input). booking_v5.probe_bind performs the production sequence and
# prints one line per phase. It does not exit on a failed phase, so the log stays collectable.
c["command"] = [os.environ["RUNNER_PY"], "-m", "booking_v5.probe_bind",
                "--run", os.environ["BIND_RUN"], "--step", os.environ["BIND_STEP"],
                "--fragment", os.environ["BIND_FRAG"], "--state", os.environ["BIND_STATE"],
                "--nonce", os.environ["BIND_NONCE"], "--idle", "1800"]
# A probe-only deviation from the fixed profile: activeDeadlineSeconds is 300 s there, which is
# counted from pod start and has to cover TD boot (85-120 s) plus guest pull plus the idle
# window in which the log is collected. A deadline hit would report DeadlineExceeded and lose
# the evidence for a reason that has nothing to do with attestation. The production runner
# keeps 300 s. The policy is generated from this manifest, so the deviation stays measured.
m["spec"]["activeDeadlineSeconds"] = int(os.environ.get("PROBE_DEADLINE", "2400"))
m["spec"]["serviceAccountName"] = "default"     # probe namespace has no runner-sa
m["spec"]["imagePullSecrets"] = [{"name": "ar-pull"}]   # guest-pull auth (CAA -> auth.json in the TD)
if not policy_file:
    m["metadata"]["annotations"] = {}           # pass 1: plain manifest for genpolicy
yaml.safe_dump(m, sys.stdout)
PY
}
export BIND_RUN BIND_STEP BIND_FRAG BIND_STATE BIND_NONCE RUNNER_PY
render_runner_peer "${RUNNER_IMAGE}" "${NS}" "" > "${OUT}/runner-peer-${STAMP}.plain.yaml"
"$(dirname "${BASH_SOURCE[0]}")/_genpolicy.sh" "${OUT}/runner-peer-${STAMP}.plain.yaml" "${OUT}/runner-peer-${STAMP}.policy.rego"
render_runner_peer "${RUNNER_IMAGE}" "${NS}" "${OUT}/runner-peer-${STAMP}.policy.rego" > "${OUT}/runner-peer-${STAMP}.yaml"
# Short-lived registry credential for the guest pull (the operator's gcloud token, ~1 h). In V5
# proper the controller mints this per spawn from its own identity.
kubectl -n "${NS}" create secret docker-registry ar-pull --docker-server "${AR_HOST}" \
  --docker-username oauth2accesstoken --docker-password "$(gcloud auth print-access-token)" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "${NS}" delete pod runner-peer --ignore-not-found --wait=true >/dev/null
kubectl -n "${NS}" apply -f "${OUT}/runner-peer-${STAMP}.yaml" >/dev/null
P2_TIMEOUT="${P2_TIMEOUT:-240}"     # seconds, healthy runners take 86-113 s. Use 600 for the final freeze
P2=FAILED; wait_ready runner-peer "${P2_TIMEOUT}s" && P2=BOOTED
sleep 30
kubectl -n "${NS}" logs runner-peer 2>&1 | tee "${OUT}/evidence-${STAMP}.log" >/dev/null
# The guest's boot log, while its VM still exists. On a FAILED run the CAA retries for about
# four minutes and there is time to fetch it by hand. On a successful run the VM goes with the
# pod moments later, and that is the run where the question "did initdata-measure run" matters.
# The log is therefore recorded here on every run, next to the evidence, for one API call.
podvm="$(gcloud compute instances list --project "${PROJECT}" \
           --filter="name~^podvm-runner-peer" --format='value(name)' 2>/dev/null | head -1)"
if [ -n "${podvm}" ]; then
  if gcloud compute instances get-serial-port-output "${podvm}" --zone "${ZONE}" \
       --project "${PROJECT}" > "${OUT}/serial-runner-peer-${STAMP}.txt" 2>/dev/null; then
    say "guest boot log: ${OUT##*/}/serial-runner-peer-${STAMP}.txt ($(wc -l < "${OUT}/serial-runner-peer-${STAMP}.txt" | tr -d ' ') lines, VM ${podvm})"
    sed 's/\x1b\[[0-9;]*m//g' "${OUT}/serial-runner-peer-${STAMP}.txt" \
      | grep -nE "initdata-measure|Dependency failed|Failed to start" | tail -5 || true
  else
    say "WARNING: no serial output for ${podvm} (already gone?)"
  fi
else
  say "WARNING: no pod VM found for runner-peer, cannot record the guest boot log"
fi
grep -q "^EVIDENCE_OK" "${OUT}/evidence-${STAMP}.log" && P2="EVIDENCE_OK" || P2="${P2}/EVIDENCE_FAIL"
# The runtime_data is derived in the TD (the canonical binding), not drawn here. Take it from
# the log so that 20 and 21 can use it.
{ grep -m1 '^RUNTIME_DATA ' "${OUT}/evidence-${STAMP}.log" | awk '{print $2}' || true; } > "${OUT}/runtime-data-${STAMP}.txt"
[ -s "${OUT}/runtime-data-${STAMP}.txt" ] || say "WARNING: no RUNTIME_DATA line, the runner did not reach the bind phase"
# P3 is the two AAEL events of the production sequence, not a probe-only extend.
n_ok="$(grep -c '^AAEL_OK ' "${OUT}/evidence-${STAMP}.log" || true)"
if [ "${n_ok}" = "2" ]; then P3="RTMR_OK"; else P3="RTMR_INCOMPLETE(${n_ok}/2)"; fi

echo "----- VERDICT ${STAMP} -----" | tee "${OUT}/verdict-${STAMP}.txt"
echo "P1 no-init-data peer pod: ${P1}"  | tee -a "${OUT}/verdict-${STAMP}.txt"
echo "P2 measured runner:       ${P2}"  | tee -a "${OUT}/verdict-${STAMP}.txt"
echo "P3 runtime measurement:   ${P3}   (both AAEL events of the production sequence)" | tee -a "${OUT}/verdict-${STAMP}.txt"
p1_ok || die "abort: $(p1_hint)"
[ "${P2}" = EVIDENCE_OK ] || die "abort: the measured runner cannot obtain evidence unprivileged"
say "recorded under ${OUT}/. Next: python3 scripts/gke-v5/20_verify_evidence_offline.py ${STAMP}, then 19_probe_network.sh"
