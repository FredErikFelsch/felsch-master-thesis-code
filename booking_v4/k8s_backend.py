"""The Kubernetes runner launch backend.

`KubernetesRunnerProvisioner` replaces the Docker `ContainerRunnerProvisioner` and runs one
short-lived Kubernetes Job per fragment, without changing the runner, the wire protocol, the
controller contract or the Authority and Gateway semantics. The runner (`runner_process.py`) is the
same program. Its stdin and stdout protocol is transported over `pods/attach` instead of a Docker
Popen, so that the runner does not have to become a TCP server.

The module has two parts.

  * `FIXED_PROFILE` and `build_runner_job_manifest(...)` form a pure function that builds the
    runner Job manifest from trusted configuration only. It takes no fragment, envelope or policy,
    so the untrusted execution input does not enter the Pod spec (it arrives over the attach
    stream). This is verifiable offline. `tests_k8s_offline.py` shows that two different fragments
    yield an identical Pod template and that the profile matches the hardening of the container
    backend.

  * `KubernetesRunnerProvisioner` and `KubernetesRunnerHandle` form the live backend. It needs a
    real cluster and the `kubernetes` client, and it mirrors the lifecycle of the container
    provisioner. It creates the Job, waits until the pod is running and opens the attach stream.
    Only then does it establish the fragment-bound session and send the provisioning line. On
    `execute` it sends the execution line, accepts one result line on a clean exit, deletes the
    Job, confirms it is gone and returns the result. The `kubernetes` import is lazy, so the
    module imports and the offline tests run without the client installed.

The offline checks do not show the enforced boundary (RBAC denies the orchestrator
ServiceAccount any Job verbs, a NetworkPolicy confines the runner). That is shown only on a real
cluster, by `tests_k8s.py`.
"""

from __future__ import annotations

import copy
import re
import time
import uuid

from booking_v3.envelope import StateEnvelope
from booking_v3.fragment import ActionFragment

from . import wire

# The fixed runner launch profile, the Kubernetes form of the Docker hardening of the
# container backend. Every value here is trusted controller configuration. The orchestrator
# cannot select any of it, and none of it depends on the fragment.
FIXED_PROFILE = {
    "service_account": "runner-sa",
    "uid": 65532,
    "memory_limit": "512Mi",
    "cpu_request": "100m",
    "tmp_size": "16Mi",
    # Bounds the whole Job (scheduling, startup, execution and teardown), so it has to
    # exceed the controller's own startup and execution budget, or Kubernetes could
    # kill a runner the controller still expects to finish. tests_k8s_offline checks it
    # against _START_TIMEOUT + _EXEC_TIMEOUT.
    "active_deadline_seconds": 300,
    "ttl_seconds_after_finished": 60,
    "managed_by": "trusted-runner-controller",
}


# The runner image has to be pinned by digest (repo@sha256:<64 hex>).
# `require_pinned_image` checks this, and the provisioner calls it at construction,
# before any launch.
_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")


def require_pinned_image(image: str) -> str:
    """Return ``image`` iff it is digest-pinned.

    Accepts ``repo/name@sha256:<64 lowercase hex>`` and rejects any tag
    (``name:latest``, ``name:v1``) or a bare name. The controller launches only
    digest-pinned runners, so the bytes that ran can be recovered and a mutable
    tag cannot be swapped in underneath the trusted profile.

    Raises:
        ValueError: The image is not digest-pinned.
    """
    if not isinstance(image, str) or not _DIGEST_RE.search(image):
        raise ValueError(
            f"runner image must be digest-pinned (repo@sha256:<64 hex>), got {image!r} "
            f"(fail-closed: a mutable tag is not an acceptable trusted profile)")
    return image


def build_runner_job_manifest(*, image: str, namespace: str, name: str,
                              profile: dict | None = None) -> dict:
    """Build the runner Job manifest from trusted configuration only (pure, no cluster).

    The function takes no fragment, envelope or policy: the untrusted execution
    input reaches the runner over the attach stream and not through the Pod spec,
    so the Pod template is the same for every fragment. Mapping to the Docker
    hardening of the container backend:

        digest-pinned image      -> image: ...@sha256:<digest>
        --network none           -> (default-deny + NetworkPolicy, see manifests)
        --read-only              -> readOnlyRootFilesystem: true
        /tmp tmpfs 16Mi          -> emptyDir{medium: Memory, sizeLimit: 16Mi}
        --cap-drop ALL           -> capabilities.drop: [ALL]
        no-new-privileges        -> allowPrivilegeEscalation: false
        UID 65532                -> runAsNonRoot + runAsUser: 65532
        --memory 512m            -> resources.limits.memory: 512Mi
        no Kubernetes API        -> runner-sa + automountServiceAccountToken: false
        single, no retry         -> completions/parallelism 1, backoffLimit 0,
                                     restartPolicy Never
        force teardown           -> ttlSecondsAfterFinished + controller deletes

    The per-container `--pids-limit 256` has no portable PodSpec equivalent and is
    a documented deployment difference.

    Args:
        image: The digest-pinned runner image.
        namespace: The namespace of the Job.
        name: The Job name.
        profile: Overrides of `FIXED_PROFILE` (tests only).

    Returns:
        The Job manifest as a dict.
    """
    p = {**FIXED_PROFILE, **(profile or {})}
    uid = p["uid"]
    labels = {"app": "runner", "managed-by": p["managed_by"]}
    pod_template = {
        "metadata": {"labels": dict(labels)},
        "spec": {
            "serviceAccountName": p["service_account"],
            "automountServiceAccountToken": False,   # no Kubernetes API token
            "restartPolicy": "Never",
            "enableServiceLinks": False,
            # no hostNetwork / hostPID / hostIPC / hostPath anywhere
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": uid,
                "runAsGroup": uid,
                "fsGroup": uid,
                "seccompProfile": {"type": "RuntimeDefault"},
            },
            "containers": [{
                "name": "runner",
                "image": image,                       # digest-pinned, trusted
                # No command or args override: the image ENTRYPOINT runs
                # `python3 -m booking_v4.runner_process`, and nothing that builds
                # this manifest can choose another command.
                "stdin": True,
                "stdinOnce": True,
                "tty": False,
                "securityContext": {
                    "readOnlyRootFilesystem": True,
                    "allowPrivilegeEscalation": False,
                    "runAsNonRoot": True,
                    "runAsUser": uid,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {
                    "limits": {"memory": p["memory_limit"]},
                    "requests": {"memory": p["memory_limit"], "cpu": p["cpu_request"]},
                },
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
            }],
            "volumes": [{
                "name": "tmp",
                "emptyDir": {"medium": "Memory", "sizeLimit": p["tmp_size"]},
            }],
        },
    }
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name, "namespace": namespace, "labels": dict(labels)},
        "spec": {
            "backoffLimit": 0,                        # no retry after a crash
            "completions": 1,
            "parallelism": 1,
            "activeDeadlineSeconds": p["active_deadline_seconds"],
            "ttlSecondsAfterFinished": p["ttl_seconds_after_finished"],
            "template": pod_template,
        },
    }


def pod_template_of(manifest: dict) -> dict:
    """Return a copy of the Pod template of a Job manifest, the part that must not vary with the fragment."""
    return copy.deepcopy(manifest["spec"]["template"])


# ---------------------------------------------------------------------------
# Live backend: needs a real cluster and the `kubernetes` client.
# The `kubernetes` import is lazy so this module imports without it.
# ---------------------------------------------------------------------------

_START_TIMEOUT = 120   # seconds to confirm the runner pod is RUNNING
_EXEC_TIMEOUT = 120    # seconds for the runner to produce its result
_DELETE_TIMEOUT = 60   # seconds to confirm the Job is gone


def _k8s():
    """Import the kubernetes client lazily, only when a Job is launched.

    Returns ``(client, stream)``, where ``stream`` is the function
    ``kubernetes.stream.stream`` (the WebSocket attach and exec helper), not the
    ``kubernetes.stream`` package of the same name. Calling the package raises
    ``TypeError: 'module' object is not callable`` at the first pods/attach.
    """
    from kubernetes import client
    from kubernetes.stream import stream
    return client, stream


class KubernetesRunnerHandle:
    """Single-use handle on one runner Job, with its open attach stream.

    Mirrors the container handle: T4 (a valid result is held) is reached only
    after strict validation, and the result is returned only after the Job is
    confirmed deleted. The runner and wire protocol are unchanged. Only the
    transport (attach) and the teardown (Job deletion) differ from Docker.
    """

    def __init__(self, provisioner: "KubernetesRunnerProvisioner",
                 job_name: str, pod_name: str, attach) -> None:
        self._prov = provisioner
        self.job_name = job_name
        self.pod_name = pod_name
        self._attach = attach
        self._used = False
        self.removed = False

    def _delete_job_and_wait(self) -> None:
        """Delete the Job and wait for a 404. Sets `removed` only on a confirmed absence."""
        client, _ = _k8s()
        from kubernetes.client.rest import ApiException
        self._prov._batch.delete_namespaced_job(
            self.job_name, self._prov._namespace,
            body=client.V1DeleteOptions(propagation_policy="Foreground",
                                        grace_period_seconds=0))
        deadline = time.monotonic() + _DELETE_TIMEOUT
        while time.monotonic() < deadline:
            try:
                self._prov._batch.read_namespaced_job(self.job_name, self._prov._namespace)
            except ApiException as exc:
                if exc.status == 404:
                    self.removed = True          # only a real 404 proves absence
                    return
                raise                             # 403, timeout or 5xx does not mean removed
            time.sleep(0.3)
        raise RuntimeError(f"runner Job {self.job_name} not confirmed deleted (fail-closed)")

    def execute(self, policy, envelope, fragment, intervention_approval=None):
        """Send the untrusted execution input, collect the one result and delete the Job.

        Raises:
            RuntimeError: The handle was used before, the runner did not exit cleanly with
                one result line, or the Job deletion could not be confirmed.
        """
        if self._used:
            raise RuntimeError("this runner handle was already used (single use)")
        self._used = True
        execution = wire.encode({
            "v": wire.WIRE_VERSION, "kind": "execution",
            "policy": wire.policy_to_wire(policy),
            "envelope": wire.envelope_to_wire(envelope),
            "fragment": wire.fragment_to_wire(fragment),
            "intervention": wire.intervention_to_wire(intervention_approval)}) + "\n"
        try:
            self._attach.write_stdin(execution)
            stdout, stderr = self._prov._drain(self._attach, _EXEC_TIMEOUT)
            returncode = self._prov._pod_exit_code(self.pod_name)
            result = _parse_runner_output(stdout, stderr, returncode)
            self._delete_job_and_wait()
            return result
        finally:
            try:
                self._attach.close()
            except Exception:
                pass
            if not self.removed:
                try:
                    self._delete_job_and_wait()
                except Exception:
                    pass


def _parse_runner_output(stdout: str, stderr: str, returncode: int):
    """Decode the runner's result, which requires a clean exit and one result line on stdout.

    Raises:
        RuntimeError: Non-zero exit code or not exactly one non-empty stdout line.
    """
    if returncode != 0:
        raise RuntimeError(
            f"runner pod exited {returncode} (fail-closed); "
            f"stdout: {stdout[-400:]!r} stderr: {stderr[-400:]!r}")
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if len(lines) != 1:
        raise RuntimeError(
            f"expected exactly one result line on stdout, got {len(lines)} (fail-closed)")
    return wire.result_from_wire(wire.decode_line(lines[0]))


class KubernetesRunnerProvisioner:
    """Trusted launch backend: one short-lived Job per fragment.

    Same interface as the container provisioner (`spawn(fragment, envelope)`), so
    the controller relays it unchanged. In the deployed topology only the
    controller pod holds it (`controller_k8s_process`). The semantic-equivalence
    harness in `k8s_deployment` holds it as well. The orchestrator holds only the
    narrow controller RPC.

    Args:
        namespace: The namespace the runner Jobs are created in.
        image: The digest-pinned runner image.
        authority: A `RemoteAuthorityHandle` on the Authority.
        anchors: The trust anchors handed to each runner.
        bootstrap: The provisioner credential for session establishment.
        authority_endpoint: The wire form of the endpoint the runner connects to.

    Raises:
        ValueError: The image is not digest-pinned.
    """

    def __init__(self, *, namespace: str, image: str, authority, anchors, bootstrap,
                 authority_endpoint: dict) -> None:
        client, _ = _k8s()
        self._namespace = namespace
        # Refuse a non-digest image at construction, so no launch path can run a
        # mutable tag under the trusted profile.
        self._image = require_pinned_image(image)  # digest-pinned repo ref, trusted
        self._authority = authority               # RemoteAuthorityHandle (TCP)
        self._anchors = anchors
        self._bootstrap = bootstrap
        self._authority_endpoint = authority_endpoint  # wire form of the runner's ServiceEndpoint
        self._batch = client.BatchV1Api()
        self._core = client.CoreV1Api()

    def spawn(self, fragment: ActionFragment, envelope: StateEnvelope) -> KubernetesRunnerHandle:
        """Launch one runner Job for one exact fragment and return its single-use handle."""
        client, stream = _k8s()
        name = f"runner-{uuid.uuid4().hex[:12]}"
        manifest = build_runner_job_manifest(
            image=self._image, namespace=self._namespace, name=name)
        self._batch.create_namespaced_job(self._namespace, manifest)
        credential = None
        try:
            pod_name = self._await_pod_running(name)  # confirm the pod runs first
            # The Python client attaches over a WebSocket. Its HTTP handshake is a
            # GET regardless of the `connect_post_...` name, so the API server
            # authorises it as the RBAC verb `get` on pods/attach (a create-only Role
            # yields 403 "cannot get resource pods/attach"). The controller Role
            # therefore grants get and create on pods/attach, the only attach verbs,
            # and they are granted to no other ServiceAccount.
            attach = stream(
                self._core.connect_post_namespaced_pod_attach, pod_name, self._namespace,
                container="runner", stdin=True, stdout=True, stderr=True, tty=False,
                _preload_content=False)
            # The fragment-bound session is minted only after the pod runs. The
            # TypeError fallback mirrors the other backends, whose in-process booking_v3
            # Authority takes no request_nonce. `RemoteAuthorityHandle` accepts it.
            nonce = uuid.uuid4().hex
            try:
                credential = self._authority.establish_runner_session(
                    self._bootstrap, fragment.run_id, fragment.fragment_hash,
                    envelope.state_hash, request_nonce=nonce)
            except TypeError:
                credential = self._authority.establish_runner_session(
                    self._bootstrap, fragment.run_id, fragment.fragment_hash,
                    envelope.state_hash)
            provisioning = wire.encode({
                "v": wire.WIRE_VERSION, "kind": "provisioning",
                "endpoint": self._authority_endpoint,   # TCP ClusterIP of Authority
                "credential": wire.credential_to_wire(credential),
                "anchors": wire.anchors_to_wire(self._anchors)}) + "\n"
            attach.write_stdin(provisioning)
        except Exception:
            self._force_delete(name)
            if credential is not None:
                self._authority.revoke_runner_session(credential)
            raise
        return KubernetesRunnerHandle(self, name, pod_name, attach)

    # --- helpers ---
    def _await_pod_running(self, job_name: str) -> str:
        """Return the name of the Job's pod once it runs, or raise RuntimeError after _START_TIMEOUT."""
        deadline = time.monotonic() + _START_TIMEOUT
        while time.monotonic() < deadline:
            pods = self._core.list_namespaced_pod(
                self._namespace, label_selector=f"job-name={job_name}")
            for pod in pods.items:
                if pod.status and pod.status.phase == "Running":
                    return pod.metadata.name
            time.sleep(0.3)
        raise RuntimeError(f"runner pod for Job {job_name} did not reach Running (fail-closed)")

    def _pod_exit_code(self, pod_name: str) -> int:
        """Return the exit code of the runner container, or raise RuntimeError after _EXEC_TIMEOUT."""
        deadline = time.monotonic() + _EXEC_TIMEOUT
        while time.monotonic() < deadline:
            pod = self._core.read_namespaced_pod(pod_name, self._namespace)
            for cs in (pod.status.container_statuses or []):
                term = cs.state.terminated if cs.state else None
                if term is not None:
                    return term.exit_code
            time.sleep(0.2)
        raise RuntimeError("runner pod did not terminate in time (killed, fail-closed)")

    def _drain(self, attach, timeout: float):
        """Read stdout and stderr from the attach stream until it closes or `timeout` passes."""
        out, err = [], []
        deadline = time.monotonic() + timeout
        while attach.is_open() and time.monotonic() < deadline:
            attach.update(timeout=1)
            if attach.peek_stdout():
                out.append(attach.read_stdout())
            if attach.peek_stderr():
                err.append(attach.read_stderr())
        return "".join(out), "".join(err)

    def _force_delete(self, job_name: str) -> None:
        """Delete a Job on a best-effort basis, for teardown after a failed spawn. Errors are ignored."""
        client, _ = _k8s()
        try:
            self._batch.delete_namespaced_job(
                job_name, self._namespace,
                body=client.V1DeleteOptions(propagation_policy="Foreground",
                                            grace_period_seconds=0))
        except Exception:
            pass

    def _delete_and_confirm_absent(self, job_name: str) -> None:
        """Delete one Job and block until a real 404 confirms it is gone.

        A 404 on the delete itself counts as already gone.

        Raises:
            RuntimeError: The deletion could not be confirmed within _DELETE_TIMEOUT.
        """
        client, _ = _k8s()
        from kubernetes.client.rest import ApiException
        try:
            self._batch.delete_namespaced_job(
                job_name, self._namespace,
                body=client.V1DeleteOptions(propagation_policy="Foreground",
                                            grace_period_seconds=0))
        except ApiException as exc:
            if exc.status != 404:                 # already gone is fine, anything else is not
                raise
        deadline = time.monotonic() + _DELETE_TIMEOUT
        while time.monotonic() < deadline:
            try:
                self._batch.read_namespaced_job(job_name, self._namespace)
            except ApiException as exc:
                if exc.status == 404:
                    return
                raise
            time.sleep(0.3)
        raise RuntimeError(f"orphan Job {job_name} not confirmed deleted (fail-closed)")

    def cleanup_orphans(self) -> None:
        """Delete every Job this controller manages, before the controller serves RPCs.

        No handle survives a restart (the handle map is in memory), so every such
        Job is an orphan. Each deletion is confirmed by a 404. If one cannot be
        confirmed, this raises and `controller_k8s_process` does not start serving.

        Raises:
            RuntimeError: A deletion could not be confirmed.
        """
        jobs = self._batch.list_namespaced_job(
            self._namespace, label_selector=f"managed-by={FIXED_PROFILE['managed_by']}")
        for job in jobs.items:
            self._delete_and_confirm_absent(job.metadata.name)
