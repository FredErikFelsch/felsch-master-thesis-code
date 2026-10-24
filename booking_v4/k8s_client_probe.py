"""Live helpers that drive the deployed controller pod.

These are the small integration helpers the live enforcement suite (`tests_k8s.py`) uses to exercise
the in-cluster topology. They keep two roles apart, as the trust model requires.

  * Trusted setup (`activate_run`). Before a lifecycle test the run must exist in the deployed
    Authority, or `establish_runner_session` refuses. Activating a run needs a
    workflow approval. In this prototype the approval is an HMAC under the trusted approver key
    baked into the shared code image, so the trusted harness mints it with `approve()` and calls
    `create_run` directly on the Authority endpoint. This authority belongs to the trusted test
    harness, not to the untrusted orchestrator.

  * Untrusted path (`ControllerRunnerProvisioner`). The orchestrator holds only the narrow
    controller RPC (spawn and execute over fragment and envelope), pointed at the controller pod.
    It does not see the approval, the bootstrap or any launch material.

Port-forwards are short-lived and opened per operation on a fixed local port, so the
controller-crash test (which deletes the controller pod) does not leave a dead forward behind. The
next operation opens a fresh forward to the new pod, and a handle minted before the crash fails
against it, because the new pod's in-memory handle map is empty. The module needs a real cluster
and is imported only inside the live tests, not when `tests_k8s` is imported.

Configuration (environment, set by scripts/gke/50_run_security_suite.sh):
    K8S_NAMESPACE            namespace (default agent-system)
    CONTROLLER_LOCAL_PORT    local port for the controller forward (default 9443)
    AUTHORITY_LOCAL_PORT     local port for the Authority forward (default 8443)
    CONTROLLER_POD_LABEL     controller pod selector (default app=controller)
    K8S_PORTFORWARD_LOG      log file of the port-forwards (default /tmp/k8s-port-forward.log)
"""

from __future__ import annotations

import contextlib
import os
import socket
import subprocess
import time

from booking_v1.approval import approve

from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3
from booking_v3.scenarios import APPROVER_ID

from . import wire
from .controller import ControllerRunnerProvisioner
from .endpoint import ServiceEndpoint
from .services import _call

_NS = os.environ.get("K8S_NAMESPACE", "agent-system")
_POD_LABEL = os.environ.get("CONTROLLER_POD_LABEL", "app=controller")
_CTRL_PORT = int(os.environ.get("CONTROLLER_LOCAL_PORT", "9443"))
_AUTH_PORT = int(os.environ.get("AUTHORITY_LOCAL_PORT", "8443"))
_MANAGED_BY = "trusted-runner-controller"


@contextlib.contextmanager
def _port_forward(service: str, local_port: int, remote_port: int, kind: str = "svc"):
    """Open a short-lived `kubectl port-forward <kind>/<service>` on a fixed local port.

    `kind="deploy"` reaches a container port that is not in the Service (the
    Authority's harness listener 8445).

    The local port is fixed, not ephemeral, so an endpoint minted inside one forward
    is still the right address in the next. The crash test relies on this, because
    it deletes the controller pod and forwards to its successor.

    Yields:
        The local TCP endpoint of the forward.

    Raises:
        RuntimeError: The local port is already in use, or the forward did not come up.
    """
    # A local port that is already in use (a stale port-forward, another local service)
    # is refused: the new forward would fail with "address already in use" while
    # `_await_local_port` connected to whatever listens there. After the wait the forward
    # is also checked to be still alive.
    if _local_port_open(local_port):
        raise RuntimeError(
            f"local port {local_port} is already in use (stale kubectl port-forward or "
            "a local service?). Refusing to talk to an unknown backend")
    log_path = os.environ.get("K8S_PORTFORWARD_LOG", "/tmp/k8s-port-forward.log")
    log = open(log_path, "a")
    log.write(f"--- port-forward {kind}/{service} {local_port}:{remote_port}\n")
    log.flush()
    proc = subprocess.Popen(
        ["kubectl", "-n", _NS, "port-forward", f"{kind}/{service}",
         f"{local_port}:{remote_port}"],
        stdout=log, stderr=log)
    try:
        _await_local_port(local_port, deadline=time.monotonic() + 20)
        if proc.poll() is not None:
            raise RuntimeError(f"kubectl port-forward exited early (see {log_path})")
        yield ServiceEndpoint.tcp("127.0.0.1", local_port)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def _local_port_open(port: int) -> bool:
    """Return True if something accepts connections on 127.0.0.1:port."""
    with contextlib.closing(socket.socket()) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _await_local_port(port: int, deadline: float) -> None:
    """Wait until 127.0.0.1:port accepts a connection, or raise RuntimeError at the deadline."""
    while time.monotonic() < deadline:
        with contextlib.closing(socket.socket()) as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.3)
    raise RuntimeError(f"port-forward to :{port} did not become ready")


def activate_run(run_id: str):
    """Activate ``run_id`` in the deployed Authority (trusted setup) and return (policy, s0).

    Mints the workflow approval with `approve()` (trusted approver key) and
    calls `create_run` on the Authority endpoint. This is authority of the
    trusted harness, which the untrusted orchestrator does not have.

    Raises:
        RuntimeError: The Authority refused the run.
    """
    from booking_v1.approval import live_window
    policy = default_p3()
    issued, expires = live_window()               # the deployed Authority runs the system clock
    approval = approve(policy, approver_id=APPROVER_ID, approval_id=f"appr-{run_id}",
                       run_id=run_id, issued_at=issued, expires_at=expires)
    with _port_forward("authority", _AUTH_PORT, 8443) as authority_ep:
        reply = _call(authority_ep, "authority.create_run", {
            "policy": wire.policy_to_wire(policy),
            "approval": wire.approval_to_wire(approval), "run_id": run_id})
    if reply.get("envelope") is None:
        raise RuntimeError(f"create_run refused: {reply.get('reason')}")
    s0 = wire.envelope_from_wire(reply["envelope"])
    return policy, s0


def _first_fragment(policy, run_id: str, s0):
    """Return the honest first fragment of the booking_v3 happy path, with `s0` as its envelope."""
    return honest_fragment(policy, run_id, 0, happy_path_arguments()[0]), s0


def spawn_only(run_id: str | None = None):
    """Activate a run and spawn its first fragment through the controller without executing it.

    ``run_id`` defaults to a fresh id per call: the durable Authority replays the
    recorded reply for a repeated request identity, so a fixed id would bring
    back a stale refusal from an earlier deployment on the same PVC.

    Returns:
        (handle, policy, fragment, envelope).
    """
    run_id = run_id or f"k8s-live-crash-{int(time.time())}"
    policy, s0 = activate_run(run_id)
    fragment, envelope = _first_fragment(policy, run_id, s0)
    with _port_forward("controller", _CTRL_PORT, 9443) as controller_ep:
        provisioner = ControllerRunnerProvisioner(controller_ep)
        return provisioner.spawn(fragment, envelope), policy, fragment, envelope


def execute_handle(handle, policy, fragment, envelope):
    """Execute a previously spawned handle through a fresh forward to the controller."""
    with _port_forward("controller", _CTRL_PORT, 9443):
        return handle.execute(policy, envelope, fragment, None)


def spawn_execute_once(run_id: str | None = None):
    """Run one spawn and execute round trip through the controller.

    The launched Job manifest is read back by label, so the test can assert that
    the fixed profile is what reached the API server, independent of the fragment.

    Returns:
        (result, launched_job_manifest).
    """
    run_id = run_id or f"k8s-live-{int(time.time())}"
    policy, s0 = activate_run(run_id)
    fragment, envelope = _first_fragment(policy, run_id, s0)
    with _port_forward("controller", _CTRL_PORT, 9443) as controller_ep:
        provisioner = ControllerRunnerProvisioner(controller_ep)
        handle = provisioner.spawn(fragment, envelope)
        job_manifest = _latest_managed_job()
        result = handle.execute(policy, envelope, fragment, None)
    return result, job_manifest


def _latest_managed_job() -> dict:
    """Return the newest Job managed by the controller, read from the API server."""
    import json
    out = subprocess.run(
        ["kubectl", "-n", _NS, "get", "jobs", "-l", f"managed-by={_MANAGED_BY}",
         "--sort-by=.metadata.creationTimestamp", "-o", "json"],
        capture_output=True, text=True, check=True, timeout=60).stdout
    items = json.loads(out).get("items", [])
    if not items:
        raise RuntimeError("no managed runner Job found after spawn")
    return items[-1]


def restart_controller() -> None:
    """Force-kill the controller pod and wait until the Recreate rollout is Ready.

    The controller pod carries a TCP readiness probe on 9443, so Ready means the new
    controller's RPC listener is up, and cleanup_orphans has run before it.
    """
    subprocess.run(
        ["kubectl", "-n", _NS, "delete", "pod", "-l", _POD_LABEL,
         "--grace-period=0", "--force"], capture_output=True, text=True,
        check=False, timeout=60)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        proc = subprocess.run(
            ["kubectl", "-n", _NS, "rollout", "status", "deploy/controller",
             "--timeout=20s"], capture_output=True, text=True, check=False, timeout=30)
        if proc.returncode == 0:
            return
        time.sleep(2)
    raise RuntimeError("controller did not become Ready after restart")
