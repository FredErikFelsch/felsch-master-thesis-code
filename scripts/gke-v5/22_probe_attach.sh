#!/usr/bin/env bash
# 22_probe_attach.sh: probes the controller-to-runner channel through `pods/attach` on a measured peer pod.
#
# Needs:  The cluster with the CAA from 14, the digest file written by ../gke/20_build_push_images.sh,
#         kubectl, gcloud, docker for _genpolicy.sh, and python3 with booking_v5 and the kubernetes
#         client (pip3 install kubernetes).
# Usage:  ./scripts/gke-v5/22_probe_attach.sh
#         ATTACH_ROUNDS (default 5) sets the number of round trips, P2_TIMEOUT (default 300) the
#         wait for the pod in seconds, PROBE_DEADLINE (default 1200) its activeDeadlineSeconds.
#         KEEP_V5_PROBES=1 skips the cleanup for a post-mortem.
# Result: results_v5/probe/attach-<stamp>.txt (one line per round, then a JSON summary that
#         booking_v5.freeze_record reads), with the manifest and the policy beside it. Exit code
#         non zero unless the verdict is ATTACH_OK.
#
# The question: can the Authority's controller hold a bidirectional line channel into a peer pod
# that runs under the measured profile (kata-remote with cc_init_data, exec forbidden), through
# the API path production uses (API server, kubelet, CRI stream, kata shim,
# agent-protocol-forwarder, kata-agent, container stdin and stdout)?
#   ATTACH_OK      every round trip came back unchanged and the stream stayed open throughout
#   ATTACH_FAIL    the stream opened but a round trip was lost, garbled or timed out
#   ATTACH_DENIED  the API refused the attach (policy, RBAC). The fallback would be a ServiceEndpoint.
#   NOT_READY      the pod never became Ready, which is a boot question for 18, not a channel question
#
# The probe does not use `kubectl attach`. It speaks booking_v5.attach_transport.KubernetesAttachStream,
# the class the controller uses. The echo pod is the runner image with a Python echo loop as its
# initial command. The policy is generated from that manifest (genpolicy pins the command), so the
# channel is shown under a real measured policy rather than a permissive one.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/_config.sh"
require_project
OUT="${MOCKS_DIR}/results_v5/probe"; mkdir -p "${OUT}"
NS="v5-probe"
POD="runner-attach"
ROUNDS="${ATTACH_ROUNDS:-5}"

python3 -c 'import kubernetes' 2>/dev/null \
  || die "the kubernetes python client is missing on this machine: pip3 install kubernetes"
[ -f "${DIGEST_FILE}" ] || die "no ${DIGEST_FILE} (run ../gke/20_build_push_images.sh first)"
source "${DIGEST_FILE}"
RUNNER_PY="${RUNNER_PYTHON:-python3}"

cleanup_probe() {
  if [ "${KEEP_V5_PROBES:-0}" = "1" ]; then say "cleanup SKIPPED (KEEP_V5_PROBES=1)"; return; fi
  say "cleanup: removing ${NS}/${POD}"
  kubectl -n "${NS}" delete pod "${POD}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  kubectl -n "${NS}" delete peerpods.confidentialcontainers.org --all --wait=false >/dev/null 2>&1 || true
}
trap cleanup_probe EXIT

# A namespace 91 deleted moments ago may still be Terminating (see 18).
for _ in $(seq 1 60); do
  [ "$(kubectl get namespace "${NS}" -o jsonpath='{.status.phase}' 2>/dev/null)" = "Terminating" ] || break
  sleep 5
done
kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# --- manifest: the measured runner profile, stdin kept, initial command = echo loop ---------
render_attach_pod() {   # IMAGE NS POLICY_FILE_OR_EMPTY
python3 - "$@" <<'PY'
import os, sys, yaml
from booking_v5.profile_v5 import build_runner_pod_manifest
image, ns, policy_file = sys.argv[1:4]
policy = open(policy_file).read() if policy_file else None
m = build_runner_pod_manifest(image=image, namespace=ns, name=os.environ["POD"], policy_rego=policy)
c = m["spec"]["containers"][0]
# stdin stays on, it is the channel. stdinOnce is off so that a reconnect during the probe does
# not end the container. The production profile keeps stdinOnce. This is a probe deviation, and
# the policy is generated from this manifest, so it stays measured.
c["stdin"] = True
c["stdinOnce"] = False
c["tty"] = False
# Echo loop: one line in, "echo:<line>" out, flushed per line. It exits on EOF or "quit".
c["command"] = [os.environ["RUNNER_PY"], "-u", "-c",
                "import sys\n"
                "print('ATTACH_READY', flush=True)\n"
                "for line in sys.stdin:\n"
                "    line = line.rstrip('\\n')\n"
                "    if line == 'quit': break\n"
                "    print('echo:' + line, flush=True)\n"]
m["spec"]["activeDeadlineSeconds"] = int(os.environ.get("PROBE_DEADLINE", "1200"))
m["spec"]["serviceAccountName"] = "default"     # probe namespace has no runner-sa
m["spec"]["imagePullSecrets"] = [{"name": "ar-pull"}]
if not policy_file:
    m["metadata"]["annotations"] = {}           # pass 1: plain manifest for genpolicy
yaml.safe_dump(m, sys.stdout)
PY
}
export POD RUNNER_PY
render_attach_pod "${RUNNER_IMAGE}" "${NS}" "" > "${OUT}/${POD}-${STAMP}.plain.yaml"
"$(dirname "${BASH_SOURCE[0]}")/_genpolicy.sh" "${OUT}/${POD}-${STAMP}.plain.yaml" "${OUT}/${POD}-${STAMP}.policy.rego"
render_attach_pod "${RUNNER_IMAGE}" "${NS}" "${OUT}/${POD}-${STAMP}.policy.rego" > "${OUT}/${POD}-${STAMP}.yaml"

# Short-lived registry credential for the guest pull, as in 18.
kubectl -n "${NS}" create secret docker-registry ar-pull --docker-server "${AR_HOST}" \
  --docker-username oauth2accesstoken --docker-password "$(gcloud auth print-access-token)" \
  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl -n "${NS}" delete pod "${POD}" --ignore-not-found --wait=true >/dev/null
kubectl -n "${NS}" apply -f "${OUT}/${POD}-${STAMP}.yaml" >/dev/null

say "waiting for ${POD} under the measured policy (TD boot and guest pull, 85 to 120 s)"
t0=$(date +%s)
if ! kubectl -n "${NS}" wait --for=condition=Ready "pod/${POD}" --timeout="${P2_TIMEOUT:-300}s" >/dev/null 2>&1; then
  kubectl -n "${NS}" describe pod "${POD}" | tail -20
  echo "ATTACH NOT_READY after $(( $(date +%s) - t0 )) s" | tee "${OUT}/attach-${STAMP}.txt"
  die "the echo pod never became Ready. That is a boot question for 18 (P2), not one about the channel"
fi
say "${POD} READY after $(( $(date +%s) - t0 )) s, attaching through the API server"

# --- the probe itself: the controller's stream class, N round trips, one open stream --------
set +e
python3 - "${NS}" "${POD}" "${ROUNDS}" "${OUT}/attach-${STAMP}.txt" <<'PY'
import json, os, sys, time
ns, pod, rounds, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
from kubernetes import config
config.load_kube_config()
from booking_v5.attach_transport import KubernetesAttachStream, TransportError

lines, verdict, rtts = [], "ATTACH_FAIL", []
try:
    t0 = time.monotonic()
    s = KubernetesAttachStream(ns, pod, "runner").open()
    lines.append(f"attach opened in {time.monotonic() - t0:.2f} s")
    # The banner is not read here: stdout written before the attach goes to the container log,
    # not to a later attach stream. The shell checks it with `kubectl logs` afterwards.
    ok = True
    for i in range(rounds):
        nonce = os.urandom(8).hex()
        t = time.monotonic()
        s.write_line(f"ping {i} {nonce}")
        got = s.read_line()
        rtt = time.monotonic() - t
        rtts.append(rtt)
        good = got == f"echo:ping {i} {nonce}"
        ok = ok and good
        lines.append(f"round {i}: {'ok ' if good else 'BAD'} rtt={rtt*1000:.0f} ms got={got!r}")
    s.write_line("quit")
    s.close()
    verdict = "ATTACH_OK" if ok else "ATTACH_FAIL"
except TransportError as e:
    lines.append(f"transport error: {e}")
except Exception as e:                          # noqa: BLE001
    msg = str(e)
    denied = any(k in msg for k in ("403", "Forbidden", "denied", "policy"))
    verdict = "ATTACH_DENIED" if denied else "ATTACH_FAIL"
    lines.append(f"{type(e).__name__}: {msg[:300]}")

summary = {"verdict": verdict, "rounds": rounds, "rtt_ms": [round(r * 1000) for r in rtts]}
with open(out, "w") as f:
    f.write("\n".join(lines) + "\n" + json.dumps(summary) + "\n")
print("\n".join(lines))
print(f"ATTACH {verdict}  rounds={rounds} rtt_ms={summary['rtt_ms']}")
sys.exit(0 if verdict == "ATTACH_OK" else 1)
PY
rc=$?
set -e
# Informational only: with stdin=true behind kata-remote, stdout reaches the attach stream and
# not reliably the container log (a recorded run had ATTACH_OK with the banner absent from
# `kubectl logs`). The echoed nonces show that the loop ran. The controller reads the stream,
# not the log.
if kubectl -n "${NS}" logs "${POD}" 2>/dev/null | grep -q '^ATTACH_READY'; then
  echo "banner: ATTACH_READY also in the container log" | tee -a "${OUT}/attach-${STAMP}.txt"
else
  echo "banner: not in the container log (informational, stdin containers log through the stream)" | tee -a "${OUT}/attach-${STAMP}.txt"
fi
say "recorded: ${OUT}/attach-${STAMP}.txt (manifest and policy alongside)"
[ "${rc}" = 0 ] || die "attach probe did not pass, read ${OUT}/attach-${STAMP}.txt (ATTACH_DENIED: fall back to a ServiceEndpoint)"
