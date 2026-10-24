"""The container backend: one clean, hardened OCI container per fragment.

The trusted ContainerRunnerProvisioner starts one fresh, single-use container per fragment via
``docker run`` and confirms that it is running. Only then does it establish the fragment-bound
runner session and write the trusted provisioning message on stdin. It returns a single-use handle.
The untrusted orchestrator holds only the handle. It submits the execution input and reads the
result, and it does not see the credential, the bootstrap or the service socket internals. The wire
protocol (canonical JSON over stdin and stdout) and the service protocol (JSON-RPC over the
deployment UDS) are the ones of the process backend.

Two deployments live here. ``create_durable_container_deployment`` is the real stack: the durable
Authority and Gateway service with the ContainerRunnerProvisioner in place of the process
provisioner. ``create_container_deployment`` keeps the non-durable service and exists only for the
process-versus-container microbenchmark, where the isolation technology is the only variable.

What the container adds over a fresh process: its own mount, PID, network, IPC and UTS namespaces, a
read-only root filesystem, all capabilities dropped, no-new-privileges, a non-root UID, a private
tmpfs as the only writable path, a pids and a memory limit, and no external network
(`--network none`, loopback still exists inside the namespace). Besides stdin and stdout, the
runner's only channel to the outside is the deployment's Unix domain socket, bind-mounted
read-only. The runner only connect()s it and neither creates nor removes anything in that
directory. The filesystem is therefore no longer a shared ambient channel, and the runner cannot
reach the process image, environment or files of the orchestrator or the provisioner. The
security semantics are unchanged, only the place where the protocol runs changes.

Phase measurement does not affect results and is off by default. With tracing enabled the runner
emits three stderr markers on the host-wide CLOCK_MONOTONIC. Combined with parent timestamps they
split the deployment cost into four phases on five boundaries (T0..T5, see measure_support.phases).
In measurement mode the provisioner waits for the child's ready marker before establishing the
session, so session and provisioning cost falls in handoff-in and not in cold start. The markers
go to stderr and do not touch decisions, facts or the single stdout result line.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field

from booking_v1.clock import Clock

from booking_v3.envelope import StateEnvelope, TrustAnchors
from booking_v3.fragment import ActionFragment
from booking_v3.provisioner import create_deployment

from . import wire
from .endpoint import ServiceEndpoint
from .measure_support import await_ready, parse_trace, phases
from .services import DeploymentServer

_TIMEOUT = 120           # seconds per fragment, generous for cold container starts
_START_TIMEOUT = 30      # seconds to confirm the container is running
_CONTAINER_SOCK_DIR = "/sock"  # in-container mount point for the deployment UDS
_DEFAULT_IMAGE = "thesis/runner:v4.3"


def _resolve_image(image: str) -> str:
    """Resolve an image reference to its content digest.

    Pinning every ``docker run`` to the immutable ``sha256:...`` id is the
    local equivalent of a registry repo-digest: every fragment runs the same
    measured bytes. If the image is absent or has no digest, provisioning does
    not start, so no run uses a moving tag.

    Raises:
        RuntimeError: The image is not present locally or has no content digest.
    """
    out = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(
            f"runner image {image!r} not present locally (fail-closed; "
            f"--pull=never): {out.stderr.strip()}")
    image_id = out.stdout.strip()
    if not image_id.startswith("sha256:"):
        raise RuntimeError(
            f"runner image {image!r} did not resolve to a content digest: {image_id!r}")
    return image_id


def _hardening_flags(host_sock_dir: str, trace: bool) -> list[str]:
    """Return the container isolation flags applied to every fragment run.

    Every flag narrows the runner's reach. Besides stdin and stdout, the
    bind-mounted deployment socket is the runner's only channel to the
    outside, and it is mounted read-only: the runner only connect()s it.
    """
    flags = [
        "--pull", "never",              # do not fetch from a registry: run the pinned bytes
        "--network", "none",            # no external network (loopback still exists)
        "--read-only",                   # immutable root filesystem
        "--tmpfs", "/tmp:rw,size=16m,mode=1777",  # the only application-writable path
        "--cap-drop", "ALL",            # no Linux capabilities
        "--security-opt", "no-new-privileges",
        "--user", "65532:65532",        # non-root UID and GID
        "--pids-limit", "256",
        "--memory", "512m",
        "-v", f"{host_sock_dir}:{_CONTAINER_SOCK_DIR}:ro",  # the deployment socket, read-only
    ]
    if trace:
        flags += ["-e", "RUNNER_TRACE=1"]
    return flags


def _inspect_running(name: str) -> str | None:
    """Return the container's State.Status, or None if it does not exist."""
    out = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", name],
        capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return out.stdout.strip()


def _wait_running(name: str, timeout: float) -> bool:
    """Return True once the container reaches 'running', False after `timeout` or an early exit.

    A `docker run` Popen only shows that the docker CLI started, not that the
    container exists or runs. This polls the daemon until the container is
    running (the runner blocks reading stdin, so it stays running) or the
    timeout elapses. A container that does not reach 'running' stops the
    provisioning.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = _inspect_running(name)
        if status == "running":
            return True
        if status in ("exited", "dead"):
            return False  # started and already died: not a live runner
        time.sleep(0.02)
    return False


def _remove_container(name: str) -> str:
    """Force-remove the container and check the outcome.

    Returns:
        'removed' on success, 'absent' if the container was already gone
        ('No such container').

    Raises:
        RuntimeError: Any other docker error, so a failed teardown is not ignored.
    """
    out = subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
    if out.returncode == 0:
        return "removed"
    if "No such container" in out.stderr:
        return "absent"
    raise RuntimeError(f"docker rm -f {name} failed: {out.stderr.strip()}")


def _parse_child_output(stdout: str, stderr: str, returncode: int) -> object:
    """Decode the runner's result, which requires a clean exit and one result line on stdout.

    The rule is the same as in the process backend. stderr (logs and trace
    markers) does not enter the decision and cannot smuggle a result.

    Raises:
        RuntimeError: Non-zero exit code or not exactly one non-empty stdout line.
    """
    if returncode != 0:
        raise RuntimeError(
            f"runner container exited {returncode} (fail-closed); "
            f"stdout: {stdout[-400:]!r} stderr: {stderr[-400:]!r}")
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if len(lines) != 1:
        raise RuntimeError(
            f"expected exactly one result line on stdout, got {len(lines)} (fail-closed)")
    return wire.result_from_wire(wire.decode_line(lines[0]))


class ContainerRunnerHandle:
    """A single-use handle on one spawned runner container.

    execute() always attempts to remove the container, whatever happens:
    timeout, malformed output, decode failure or a parent-side exception.
    ``removed`` records whether that succeeded. In measurement mode the phase
    timings of this fragment are in ``self.timings`` after execute() returns.
    """

    def __init__(self, process: subprocess.Popen, container_name: str,
                 t0: int | None = None, ready_stderr: str = "",
                 timeout: int = _TIMEOUT) -> None:
        self._process = process
        self._container_name = container_name
        self._t0 = t0
        self._ready_stderr = ready_stderr
        self._timeout = timeout
        self._used = False
        self.removed = False
        self.timings: dict | None = None

    def _teardown(self) -> None:
        """Remove the container and record the outcome in `removed`. All teardown goes through here."""
        outcome = _remove_container(self._container_name)
        self.removed = outcome in ("removed", "absent")

    def execute(self, policy, envelope, fragment, intervention_approval=None):
        """Send the untrusted execution input and collect the one result.

        T4 (a valid result is held) is taken only after strict validation, so
        parsing time does not count as teardown. T5 is taken after the
        container is confirmed removed.

        Raises:
            RuntimeError: The handle was used before, the runner timed out, or its
                output was not one result line on a clean exit.
        """
        if self._used:
            raise RuntimeError("this runner container was already used (single use)")
        self._used = True
        execution = wire.encode({
            "v": wire.WIRE_VERSION, "kind": "execution",
            "policy": wire.policy_to_wire(policy),
            "envelope": wire.envelope_to_wire(envelope),
            "fragment": wire.fragment_to_wire(fragment),
            "intervention": wire.intervention_to_wire(intervention_approval)}) + "\n"
        try:
            try:
                stdout, stderr_tail = self._process.communicate(
                    input=execution, timeout=self._timeout)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.communicate()
                raise RuntimeError("runner container timed out (killed and reaped)")
            result = _parse_child_output(stdout, stderr_tail, self._process.returncode)
            t4 = time.monotonic_ns()
            self._teardown()
            t5 = time.monotonic_ns()
            if self._t0 is not None:
                full_stderr = self._ready_stderr + stderr_tail
                self.timings = phases(self._t0, t4, t5, parse_trace(full_stderr))
            return result
        finally:
            if self._process.poll() is None:
                self._process.kill()
                self._process.wait()
            if not self.removed:
                try:
                    self._teardown()
                except Exception:
                    pass  # last-resort cleanup, the primary path already raised

    @property
    def exited(self) -> bool:
        """Return True once this fragment's container has been removed."""
        return self.removed


class ContainerRunnerProvisioner:
    """Trusted runner provisioner for the container backend.

    Mirrors the RunnerProvisioner interface of booking_v3 (spawn(fragment, envelope)), so
    the orchestrator, scenarios and experiment drive it unchanged. Every spawn starts the
    digest-pinned image with the full hardening profile. The session is established only
    after the container is confirmed running, and a failure in between removes the
    container and revokes the session, so no credential outlives a runner that did not run.

    Args:
        authority: The Authority, or a facade on it, that establishes sessions.
        anchors: The trust anchors handed to each runner.
        bootstrap: The provisioner credential.
        host_sock_dir: The host directory bind-mounted at /sock.
        service_socket: The in-container path of the deployment socket.
        image: The image id from `_resolve_image`.
        trace: Enable the phase markers of measurement mode.
    """

    def __init__(self, authority, anchors: TrustAnchors, bootstrap,
                 host_sock_dir: str, service_socket: str, image: str,
                 trace: bool = False) -> None:
        self._authority = authority
        self._anchors = anchors
        self._bootstrap = bootstrap
        self._host_sock_dir = host_sock_dir
        self._service_socket = service_socket  # in-container path to the UDS
        self._image = image
        self._trace = trace
        self._handles: list[ContainerRunnerHandle] = []
        self.spawned_names: list[str] = []
        self.lifecycle: list[dict] = []

    def spawn(self, fragment: ActionFragment, envelope: StateEnvelope) -> ContainerRunnerHandle:
        """Provision one fresh runner container for one fragment and return its handle.

        Raises:
            RuntimeError: The container did not reach 'running' in time.
        """
        prior_all_removed = all(h.removed for h in self._handles)
        name = f"booking-runner-{uuid.uuid4().hex[:12]}"
        cmd = (["docker", "run", "-i", "--name", name]
               + _hardening_flags(self._host_sock_dir, self._trace)
               + [self._image])
        t0 = time.monotonic_ns()
        process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        credential = None
        ready_stderr = ""
        try:
            # Confirm that the container exists and runs before minting any credential.
            if self._trace:
                ready_stderr = await_ready(process, _TIMEOUT)  # app-level readiness
            else:
                if not _wait_running(name, _START_TIMEOUT):
                    raise RuntimeError(
                        f"runner container {name} did not reach 'running' (fail-closed)")
            # The in-process booking_v3 Authority of the non-durable deployment takes no
            # request_nonce, the durable facade does.
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
                "endpoint": ServiceEndpoint.uds(self._service_socket).to_wire(),
                "credential": wire.credential_to_wire(credential),
                "anchors": wire.anchors_to_wire(self._anchors)}) + "\n"
            process.stdin.write(provisioning)
            process.stdin.flush()
        except Exception:
            process.kill()
            process.wait()
            try:
                _remove_container(name)
            finally:
                if credential is not None:
                    self._authority.revoke_runner_session(credential)
            raise
        handle = ContainerRunnerHandle(
            process, name, t0=t0 if self._trace else None, ready_stderr=ready_stderr)
        self._handles.append(handle)
        self.spawned_names.append(name)
        self.lifecycle.append({
            "name": name, "fragment_index": fragment.fragment_index,
            "spawned_after_all_prior_removed": prior_all_removed})
        return handle

    def cleanup(self) -> None:
        """Remove any runner container still present (deployment teardown safety)."""
        for handle in self._handles:
            if not handle.removed:
                try:
                    handle._teardown()
                except Exception:
                    pass


@dataclass
class ContainerDeployment:
    """Non-durable container deployment, used only by the microbenchmark."""

    authority: object
    gateway: object
    anchors: TrustAnchors
    provisioner: ContainerRunnerProvisioner
    bootstrap: object
    image: str
    server: DeploymentServer = field(repr=False, default=None)
    _sock_dir: str = field(repr=False, default=None)

    def close(self) -> None:
        """Remove leftover containers, stop the service and delete the socket directory."""
        try:
            self.provisioner.cleanup()
        finally:
            if self.server is not None:
                self.server.close()
            if self._sock_dir and os.path.isdir(self._sock_dir):
                shutil.rmtree(self._sock_dir, ignore_errors=True)

    def __enter__(self) -> "ContainerDeployment":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _prepare_socket_dir() -> tuple[str, str, str]:
    """Create a host directory for the deployment socket.

    The callers make the directory traversable and the socket connectable for
    the non-root container UID. Connect permission is not the security boundary
    (the RunnerCredential is), so this grants no authority. The mount is
    read-only, so the container cannot create or remove anything there.

    Returns:
        (directory, host socket path, in-container socket path).
    """
    host_sock_dir = tempfile.mkdtemp(prefix="booking-container-")
    host_socket_path = os.path.join(host_sock_dir, "authority.sock")
    container_socket_path = f"{_CONTAINER_SOCK_DIR}/authority.sock"
    return host_sock_dir, host_socket_path, container_socket_path


def create_container_deployment(clock: Clock, executor=None) -> ContainerDeployment:
    """Build the non-durable container deployment (microbenchmark only).

    It mirrors the non-durable process backend, so the isolation technology is
    the only variable in the process-versus-container measurement. The
    evaluation runs on the durable stack below, not on this. Tracing is off
    unless CONTAINER_RUNNER_TRACE=1, which only the measurement harness sets.
    """
    image = _resolve_image(os.environ.get("RUNNER_IMAGE", _DEFAULT_IMAGE))
    trace = os.environ.get("CONTAINER_RUNNER_TRACE") == "1"
    base = create_deployment(clock, executor=executor)
    host_sock_dir, host_socket_path, container_socket_path = _prepare_socket_dir()
    server = DeploymentServer(base, socket_path=host_socket_path)
    os.chmod(host_sock_dir, 0o755)
    os.chmod(host_socket_path, 0o666)
    provisioner = ContainerRunnerProvisioner(
        base.authority, base.anchors, base.bootstrap,
        host_sock_dir, container_socket_path, image, trace=trace)
    return ContainerDeployment(
        authority=base.authority, gateway=base.gateway, anchors=base.anchors,
        provisioner=provisioner, bootstrap=base.bootstrap, image=image,
        server=server, _sock_dir=host_sock_dir)


# --- the durable stack: durable services plus container runner ----------------

def create_durable_container_deployment(clock: Clock, executor=None):
    """Build the container deployment the evaluation runs on: durable services plus container runners.

    Authority and gateway follow the rules of `booking_v4.durable`, as in the durable
    process deployment, and the ContainerRunnerProvisioner replaces the process
    provisioner. Tracing is off unless CONTAINER_RUNNER_TRACE=1.
    """
    from .durable import (AuthorityFacade, DurableDeploymentServer,
                          DurableProcessDeployment, GatewayFacade,
                          HumanApprovalClient, _RestoredDeployment)

    image = _resolve_image(os.environ.get("RUNNER_IMAGE", _DEFAULT_IMAGE))
    trace = os.environ.get("CONTAINER_RUNNER_TRACE") == "1"

    class DurableContainerDeployment(DurableProcessDeployment):
        """Durable service stack with a hardened container runner per fragment.

        The host socket directory is created once and kept across service
        restarts, as the durable process deployment keeps its socket address. A
        service crash rebuilds Authority and gateway from the store and binds the
        same `/sock/authority.sock` again, so a container provisioned before the
        restart still reaches the restored service over its unchanged read-only
        mount. Every provisioner wired so far (one per restart) is tracked, so
        `close` removes the runner containers of all of them.
        """

        def __init__(self, clock, executor=None, **kw) -> None:
            (self._host_sock_dir, self._host_socket_path,
             self._container_socket_path) = _prepare_socket_dir()
            os.chmod(self._host_sock_dir, 0o755)  # traversable by the non-root UID
            self._all_provisioners: list[ContainerRunnerProvisioner] = []
            super().__init__(clock, executor=executor, **kw)

        def _wire_up(self, authority, gateway, bootstrap) -> None:
            self._real_authority = authority
            self._real_gateway = gateway
            self.bootstrap = bootstrap
            self.anchors = authority.anchors()
            self.server = DurableDeploymentServer(
                _RestoredDeployment(authority, gateway), self.store,
                socket_path=self._host_socket_path,  # the same path across restarts
                downstream_idempotent=self._downstream_idempotent,
                enable_test_api=self._enable_test_api)
            os.chmod(self._host_socket_path, 0o666)  # connectable by the non-root UID
            self.authority = AuthorityFacade(authority, self.server.socket_path)
            self.human_interface = HumanApprovalClient(self.server.socket_path, self.human)
            self.gateway = GatewayFacade(gateway, self.server.socket_path)
            self.provisioner = ContainerRunnerProvisioner(
                self.authority, self.anchors, self.bootstrap,
                self._host_sock_dir, self._container_socket_path, image, trace=trace)
            self._all_provisioners.append(self.provisioner)

        def close(self) -> None:
            """Remove the runner containers of every provisioner, then stop the service."""
            try:
                for prov in self._all_provisioners:  # the runners of every restart
                    prov.cleanup()
            finally:
                super().close()
                if os.path.isdir(self._host_sock_dir):
                    shutil.rmtree(self._host_sock_dir, ignore_errors=True)

    dep = DurableContainerDeployment(clock, executor=executor)
    dep.image = image
    return dep


def create_durable_container_service(clock: Clock, executor=None):
    """Build the durable Authority and gateway service and a runner socket directory, but no provisioner.

    This is the harness-side half of the controller split. The launch mechanism
    (the ContainerRunnerProvisioner, Docker, the image, the credential injection)
    is absent here and lives only in the separate controller process. The
    returned object exposes the Authority and gateway service (for trusted run
    activation and the adversarial scenarios) and the socket-mount paths the
    controller needs. Its `provisioner` is None, and no image is resolved.
    """
    from .durable import (AuthorityFacade, DurableDeploymentServer,
                          DurableProcessDeployment, GatewayFacade,
                          HumanApprovalClient, _RestoredDeployment)

    class _DurableContainerService(DurableProcessDeployment):
        """The durable service on a container-mountable socket, without a provisioner."""

        def __init__(self, clock, executor=None, **kw) -> None:
            (self._host_sock_dir, self._host_socket_path,
             self._container_socket_path) = _prepare_socket_dir()
            os.chmod(self._host_sock_dir, 0o755)
            super().__init__(clock, executor=executor, **kw)

        def _wire_up(self, authority, gateway, bootstrap) -> None:
            self._real_authority = authority
            self._real_gateway = gateway
            self.bootstrap = bootstrap
            self.anchors = authority.anchors()
            self.server = DurableDeploymentServer(
                _RestoredDeployment(authority, gateway), self.store,
                socket_path=self._host_socket_path,
                downstream_idempotent=self._downstream_idempotent,
                enable_test_api=self._enable_test_api)
            os.chmod(self._host_socket_path, 0o666)
            self.authority = AuthorityFacade(authority, self.server.socket_path)
            self.human_interface = HumanApprovalClient(self.server.socket_path, self.human)
            self.gateway = GatewayFacade(gateway, self.server.socket_path)
            self.provisioner = None  # no launch mechanism in the harness process

        def close(self) -> None:
            """Stop the service and remove the socket directory."""
            super().close()
            if os.path.isdir(self._host_sock_dir):
                shutil.rmtree(self._host_sock_dir, ignore_errors=True)

    return _DurableContainerService(clock, executor=executor)
