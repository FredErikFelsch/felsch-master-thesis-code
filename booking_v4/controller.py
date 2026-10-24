"""The trusted runner controller as a separate trust domain: orchestrator-side client and factory.

The launch mechanism moves out of the orchestrator's process into a separate trusted runner
controller process, reached over a narrow RPC:

    orchestrator ──(narrow RPC: spawn/execute)──▶ controller process
                 ◀────────── opaque handle id ────

The controller process alone owns the provisioner bootstrap, the trusted service endpoint, the trust
anchors, the fixed runner image and the container lifecycle backend. The orchestrator-facing
contract is small. `spawn(fragment, envelope)` returns an opaque handle id and
`execute(handle_id, execution_input)` runs it. There is no field in which an orchestrator could name
an image, endpoint, environment, mount, bootstrap, credential, capability, service account, runtime
class or command, and the strict key-set decoding rejects any such attempt.

This module is the orchestrator-side client plus the deployment factory that wires it to a freshly
launched controller process. It constructs no launch backend and makes no Docker call. The launch
backend is constructed only in `controller_process.py` (Docker) and `controller_k8s_process.py`
(Kubernetes Jobs). The import of `container_backend` here serves the default image tag and the
durable service without a provisioner.

What this shows: the launch mechanism is structurally separate. The orchestrator-facing object
graph contains no launch backend and can select no launch-profile parameters. It does not show
that a fully compromised orchestrator (arbitrary code under an OS principal that still has ambient
Docker access) cannot launch a container by other means. In the Kubernetes deployment that comes
from RBAC, which denies the orchestrator ServiceAccount any Job verbs. Controller initialisation is
trusted here as well. Adversarial control begins only after the controller has been provisioned
with its fixed launch configuration. The Kubernetes deployment moves that provisioning from the
orchestrator to a trusted init Job and to Kubernetes RBAC.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

from booking_v1.clock import Clock

from booking_v3.envelope import StateEnvelope
from booking_v3.fragment import ActionFragment

from . import wire
from .container_backend import _DEFAULT_IMAGE, create_durable_container_service
from .endpoint import ServiceEndpoint
from .services import _call

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_READY_TIMEOUT = 30  # seconds to wait for the controller process to bind

# The narrow controller contract. These key sets are the whole orchestrator-facing surface.
# Anything else (image, endpoint, environment, mounts, bootstrap, credential, capabilities)
# is rejected by the strict decoding in `controller_process`.
CONTROLLER_METHODS: dict[str, set[str]] = {
    "controller.spawn": {"fragment", "envelope"},
    "controller.execute": {"handle_id", "policy", "envelope", "fragment", "intervention"},
}


class ControllerRunnerHandle:
    """Opaque, single-use handle held by the untrusted orchestrator.

    It carries only the controller endpoint and an opaque handle id string,
    not a container id, a credential or any provisioning material. execute()
    relays the untrusted execution input to the controller and returns the one
    RunnerResult.
    """

    def __init__(self, endpoint: ServiceEndpoint, handle_id: str) -> None:
        self._endpoint = endpoint
        self._handle_id = handle_id
        self._used = False

    @property
    def handle_id(self) -> str:
        """Return the opaque id under which the controller knows this runner."""
        return self._handle_id

    def execute(self, policy, envelope, fragment, intervention_approval=None):
        """Relay the untrusted execution input to the controller and return the RunnerResult.

        Raises:
            RuntimeError: The handle was used before.
            WireError: The controller refused the request, for example an unknown handle.
        """
        if self._used:
            raise RuntimeError("this runner handle was already used (single use)")
        self._used = True
        reply = _call(self._endpoint, "controller.execute", {
            "handle_id": self._handle_id,
            "policy": wire.policy_to_wire(policy),
            "envelope": wire.envelope_to_wire(envelope),
            "fragment": wire.fragment_to_wire(fragment),
            "intervention": wire.intervention_to_wire(intervention_approval)})
        return wire.result_from_wire(reply["result"])


class ControllerRunnerProvisioner:
    """The untrusted orchestrator's whole provisioning interface.

    Mirrors the RunnerProvisioner of booking_v3 (`spawn(fragment, envelope)`) so the
    orchestrator, scenarios and experiment drive it unchanged, but it holds only
    the controller's RPC endpoint. It has no bootstrap, no image, no service
    endpoint and no Docker access. It can submit (fragment, envelope) and receive
    an opaque handle, nothing more.
    """

    def __init__(self, endpoint) -> None:
        # A ServiceEndpoint or a bare UDS path. Locally this is a UDS, in a cluster the
        # controller pod's TCP Service endpoint. The contract is the same.
        self._endpoint = ServiceEndpoint.coerce(endpoint)
        self.spawned_handle_ids: list[str] = []

    def spawn(self, fragment: ActionFragment, envelope: StateEnvelope) -> ControllerRunnerHandle:
        """Ask the controller to launch one runner and return its opaque handle."""
        reply = _call(self._endpoint, "controller.spawn", {
            "fragment": wire.fragment_to_wire(fragment),
            "envelope": wire.envelope_to_wire(envelope)})
        handle_id = reply["handle_id"]
        self.spawned_handle_ids.append(handle_id)
        return ControllerRunnerHandle(self._endpoint, handle_id)


class _ControllerProcess:
    """Launches and owns the trusted controller as a separate OS process.

    The trusted provisioning configuration (service endpoint, bootstrap, anchors,
    image, bind-mount paths) is handed to the controller over its stdin at
    startup and does not pass through the orchestrator-facing surface. The
    controller binds its narrow RPC endpoint (UDS or TCP) and reports that
    endpoint on a one-line handshake. Then it serves until terminated.
    """

    def __init__(self, config: dict, bind: tuple = ("uds",)) -> None:
        self._dir = tempfile.mkdtemp(prefix="booking-controller-")
        if bind[0] == "uds":
            self.rpc_socket = os.path.join(self._dir, "controller.sock")
            launch = ["--uds", self.rpc_socket]
        else:  # ("tcp", host, port), port 0 means ephemeral and is reported on the handshake
            self.rpc_socket = None
            launch = ["--tcp", f"{bind[1]}:{bind[2]}"]
        self.endpoint: ServiceEndpoint | None = None
        self._process = subprocess.Popen(
            [sys.executable, "-m", "booking_v4.controller_process", *launch],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=(None if os.environ.get("V4_CONTROLLER_STDERR") == "inherit"
                    else subprocess.PIPE),
            cwd=_REPO_ROOT, text=True)
        try:
            self._process.stdin.write(json.dumps(config) + "\n")
            self._process.stdin.flush()
            self._await_ready()
            self._process.stdin.close()  # the config is delivered, no more input
        except Exception:
            self.close()
            raise

    def _await_ready(self) -> None:
        """Read the controller's endpoint handshake within _READY_TIMEOUT seconds.

        A plain ``readline`` would block forever if the controller hangs before
        writing anything, so every read waits in ``select`` on the remaining
        budget. When the budget is spent the launch raises instead of hanging
        the caller. The handshake is the controller's only stdout line, so the
        text buffer cannot hide a second line from ``select``.

        Raises:
            RuntimeError: The controller exited or stayed silent until the timeout.
        """
        deadline = time.monotonic() + _READY_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("controller process did not report its endpoint in time")
            readable, _, _ = select.select([self._process.stdout], [], [], remaining)
            if not readable:
                if self._process.poll() is not None:
                    raise RuntimeError("controller process exited before reporting its endpoint")
                continue
            line = self._process.stdout.readline()
            if line == "":  # EOF: the process ended without a handshake
                err = self._process.stderr.read() if self._process.stderr else ""
                raise RuntimeError(f"controller process exited before ready: {err[-400:]!r}")
            try:
                msg = json.loads(line)
            except Exception:
                continue
            if isinstance(msg, dict) and "endpoint" in msg:
                self.endpoint = ServiceEndpoint.from_wire(msg["endpoint"])
                return

    @property
    def alive(self) -> bool:
        """Return True while the controller process runs."""
        return self._process.poll() is None

    @property
    def pid(self) -> int:
        """Return the operating-system process id of the controller."""
        return self._process.pid

    def kill(self) -> None:
        """Force-kill the controller process (crash-semantics tests)."""
        if self._process.poll() is None:
            self._process.kill()
            self._process.wait()

    def close(self) -> None:
        """Terminate the controller, close its streams and remove its socket directory."""
        try:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait()
        finally:
            for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
            import shutil
            shutil.rmtree(self._dir, ignore_errors=True)


@dataclass
class ControllerDeployment:
    """Deployment where provisioning is a separate trusted process.

    Authority, gateway, anchors and bootstrap are those of the inner durable
    container service, unchanged, so every scenario, including the adversarial
    ones that model an attacker holding Authority material, behaves as on the
    other backends. Only ``provisioner`` differs. It is the narrow controller
    client and holds no provisioning authority.
    """

    authority: object
    gateway: object
    anchors: object
    provisioner: ControllerRunnerProvisioner
    bootstrap: object
    human_interface: object
    _inner: object = field(repr=False, default=None)
    _controller: _ControllerProcess = field(repr=False, default=None)

    @property
    def controller(self) -> _ControllerProcess:
        """Return the controller process this deployment launched."""
        return self._controller

    def close(self) -> None:
        """Stop the controller process, then the inner service deployment."""
        try:
            if self._controller is not None:
                self._controller.close()
        finally:
            if self._inner is not None:
                self._inner.close()

    def __enter__(self) -> "ControllerDeployment":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def create_controller_deployment(clock: Clock, executor=None, *,
                                 controller_bind: tuple = ("uds",)) -> ControllerDeployment:
    """Build a deployment on the controller backend (fits the booking_v3 scenario hook).

    Builds only the durable Authority and gateway service in this harness
    process, with no runner provisioner, no Docker and no image resolution. It
    then launches the controller process with the trusted provisioning config and
    hands the orchestrator only the narrow client. The launch mechanism (the
    container provisioner, Docker, the pinned image digest, the credential
    injection) is constructed only inside the controller process. The returned
    ``provisioner`` is the narrow client, and ``_inner.provisioner`` is None, so
    the orchestrator's process can launch a runner only by asking the controller.

    Scope: the service exposes Authority, gateway and bootstrap because the
    adversarial scenarios (token replay, cross-step, direct grant) need that
    access to reproduce the same results. That concerns conformance on the
    workflow-authority axis. The trust-boundary property added here is only that
    the launch mechanism is not in the orchestrator's process. The image is
    passed as a tag, and the controller resolves and pins the digest itself.
    """
    service = create_durable_container_service(clock, executor=executor)
    config = {
        "host_service_socket": service._host_socket_path,
        "host_sock_dir": service._host_sock_dir,
        "container_socket": service._container_socket_path,
        "image": os.environ.get("RUNNER_IMAGE", _DEFAULT_IMAGE),  # tag only
        "bootstrap_secret": service.bootstrap.secret,
        "anchors": wire.anchors_to_wire(service.anchors),
    }
    controller = _ControllerProcess(config, bind=controller_bind)
    provisioner = ControllerRunnerProvisioner(controller.endpoint)
    return ControllerDeployment(
        authority=service.authority, gateway=service.gateway, anchors=service.anchors,
        provisioner=provisioner, bootstrap=service.bootstrap,
        human_interface=service.human_interface, _inner=service, _controller=controller)
