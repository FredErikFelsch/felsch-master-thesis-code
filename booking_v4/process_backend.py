"""The process backend: one exec-started OS process per fragment.

The trusted ProcessRunnerProvisioner exec-starts a fresh interpreter (spawn,
not fork, because a fork would inherit the parent's whole memory image) with
a minimal environment. It establishes the fragment-bound runner session only
once the process exists, writes the trusted provisioning message and returns
a single-use handle. The untrusted orchestrator holds only the handle: it can
submit the execution input and read the result, and it does not see the
credential, the bootstrap or the service socket internals.

What this backend shows: a runner needs no Python object reference or shared
heap with orchestrator, Authority or gateway. All protocol state crosses an
explicit serialised boundary, and the minimal environment closes the
environment channel too. It does not show that a fully compromised
orchestrator process could not reach provisioner secrets, because provisioner
and orchestrator share one interpreter here. That needs the provisioner as a
separate service (the runner controller, `booking_v4.controller`). The
filesystem also remains a shared ambient channel, which the container backend
closes.

The child's stdout is a strict protocol channel: one RunnerResult line and a
clean exit, or the result is rejected. Logging goes to stderr. Process
identity (PIDs, spawn and exit order) is test telemetry recorded by the
provisioner and carries no security meaning. The runner_no inside the child
restarts at 1 in every fresh interpreter.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field

from booking_v1.clock import Clock

from booking_v3.envelope import StateEnvelope, TrustAnchors
from booking_v3.fragment import ActionFragment
from booking_v3.provisioner import create_deployment
from booking_v3.runner import RunnerResult

from . import wire
from .endpoint import ServiceEndpoint
from .measure_support import await_ready, parse_trace, phases
from .services import DeploymentServer

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TIMEOUT = 120  # seconds per fragment, generous for cold interpreter starts


def _runner_environment(trace: bool = False) -> dict[str, str]:
    """Return the minimal environment a runner process receives.

    Only PATH and PYTHONUNBUFFERED are passed. Otherwise the runner would
    inherit the provisioner's whole environment (API keys, cloud and proxy
    credentials, tokens), an ambient input channel next to the serialised
    boundary that all security-relevant runner inputs are meant to cross.

    ``trace`` adds the measurement-only RUNNER_TRACE flag (stderr phase
    markers). It is off for every conformance run, so the evaluation
    environment does not change.
    """
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONUNBUFFERED": "1",
    }
    if trace:
        env["RUNNER_TRACE"] = "1"
    return env


def _parse_child_output(stdout: str, stderr: str, returncode: int) -> RunnerResult:
    """Decode the runner's result, which requires a clean exit and one result line on stdout.

    A runner that exits non-zero, stays silent or prints anything besides the
    single result is rejected, so it cannot hide a protocol violation behind a
    trailing valid line.

    Raises:
        RuntimeError: Non-zero exit code or not exactly one non-empty stdout line.
    """
    if returncode != 0:
        raise RuntimeError(
            f"runner exited {returncode} (fail-closed); "
            f"stdout: {stdout[-400:]!r} stderr: {stderr[-400:]!r}")
    lines = [ln for ln in stdout.splitlines() if ln.strip()]
    if len(lines) != 1:
        raise RuntimeError(
            f"expected exactly one result line on stdout, got {len(lines)} (fail-closed)")
    return wire.result_from_wire(wire.decode_line(lines[0]))


class ProcessRunnerHandle:
    """A single-use handle on one spawned runner process.

    execute() always terminates the process, whatever happens: timeout,
    malformed output, decode failure or a parent-side exception, so a runner
    whose result was rejected does not live on.
    """

    def __init__(self, process: subprocess.Popen, pid: int,
                 t0: int | None = None, ready_stderr: str = "",
                 timeout: int = _TIMEOUT) -> None:
        self._process = process
        self.pid = pid
        self._t0 = t0
        self._ready_stderr = ready_stderr
        self._timeout = timeout
        self._used = False
        self.timings: dict | None = None

    def execute(self, policy, envelope, fragment, intervention_approval=None) -> RunnerResult:
        """Send the untrusted execution input and collect the one result.

        T4 (a valid result is held) is taken only after strict validation, so
        parsing time does not count as teardown. Teardown for a process is the
        reap, which takes almost no time. The container backend measures the
        same boundary against a container removal.

        Raises:
            RuntimeError: The handle was used before, the runner timed out, or its
                output was not one result line on a clean exit.
        """
        if self._used:
            raise RuntimeError("this runner process was already used (single use)")
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
                self._process.communicate()  # reap, so no zombie survives a timeout
                raise RuntimeError("runner process timed out (killed and reaped)")
            result = _parse_child_output(stdout, stderr_tail, self._process.returncode)
            t4 = time.monotonic_ns()
            # communicate() has already reaped the process, so this wait does not block
            # and t5 follows t4 almost at once.
            if self._process.poll() is None:
                self._process.wait()
            t5 = time.monotonic_ns()
            if self._t0 is not None:
                full_stderr = self._ready_stderr + stderr_tail
                self.timings = phases(self._t0, t4, t5, parse_trace(full_stderr))
            return result
        finally:
            if self._process.poll() is None:
                self._process.kill()
                self._process.wait()

    @property
    def exited(self) -> bool:
        """Return True once the runner process has terminated."""
        return self._process.poll() is not None


class ProcessRunnerProvisioner:
    """Trusted runner provisioner for the process backend.

    Mirrors the RunnerProvisioner interface of booking_v3 (spawn(fragment, envelope)),
    so the orchestrator, scenarios and experiment drive it unchanged. It records
    lifecycle telemetry: per spawn, whether every previously spawned runner process
    had already exited. That shows one process lifetime per fragment, not only four
    distinct PIDs.

    Args:
        authority: The Authority, or a facade on it, that establishes sessions.
        anchors: The trust anchors handed to each runner.
        bootstrap: The provisioner credential.
        service_socket: The UDS path of the deployment service.
        trace: Enable the phase markers of measurement mode.
    """

    def __init__(self, authority, anchors: TrustAnchors, bootstrap, service_socket: str,
                 trace: bool = False) -> None:
        self._authority = authority
        self._anchors = anchors
        self._bootstrap = bootstrap
        self._service_socket = service_socket
        self._trace = trace
        self._handles: list[ProcessRunnerHandle] = []
        self.spawned_pids: list[int] = []
        self.lifecycle: list[dict] = []

    def spawn(self, fragment: ActionFragment, envelope: StateEnvelope) -> ProcessRunnerHandle:
        """Provision one fresh runner process for one fragment and return its handle.

        The process is started first. In measurement mode the provisioner then
        waits for the child's ready marker (so session establishment and
        provisioning fall in handoff-in, not in cold start), and only then
        establishes the session and writes the provisioning message. A failure
        in between kills the process and revokes the session, so no credential
        outlives a runner that did not run.
        """
        prior_all_exited = all(h.exited for h in self._handles)
        t0 = time.monotonic_ns()
        process = subprocess.Popen(
            [sys.executable, "-m", "booking_v4.runner_process"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=_REPO_ROOT, env=_runner_environment(self._trace), text=True)
        credential = None
        ready_stderr = ""
        try:
            if self._trace:
                ready_stderr = await_ready(process, self._timeout_seconds())
            # The in-process booking_v3 Authority of the non-durable deployment takes no
            # request_nonce, the durable facade and RemoteAuthorityHandle do.
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
            if credential is not None:
                self._authority.revoke_runner_session(credential)
            raise
        handle = ProcessRunnerHandle(
            process, process.pid,
            t0=t0 if self._trace else None, ready_stderr=ready_stderr)
        self._handles.append(handle)
        self.spawned_pids.append(process.pid)
        self.lifecycle.append({
            "pid": process.pid, "fragment_index": fragment.fragment_index,
            "spawned_after_all_prior_exited": prior_all_exited})
        return handle

    @staticmethod
    def _timeout_seconds() -> float:
        """Return the per-fragment timeout in seconds."""
        return float(_TIMEOUT)


@dataclass
class ProcessDeployment:
    """One wired process-backend deployment, with the fields of the booking_v3 Deployment."""

    authority: object
    gateway: object
    anchors: TrustAnchors
    provisioner: ProcessRunnerProvisioner
    bootstrap: object
    server: DeploymentServer = field(repr=False, default=None)

    def close(self) -> None:
        """Stop the deployment service."""
        self.server.close()

    def __enter__(self) -> "ProcessDeployment":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def create_process_deployment(clock: Clock, executor=None) -> ProcessDeployment:
    """Build a non-durable process deployment (fits the booking_v3 scenario hook)."""
    base = create_deployment(clock, executor=executor)
    server = DeploymentServer(base)
    # Measurement-only tracing, off for conformance. PROCESS_RUNNER_TRACE=1 turns
    # on the same phase markers the container backend uses.
    trace = os.environ.get("PROCESS_RUNNER_TRACE") == "1"
    provisioner = ProcessRunnerProvisioner(
        base.authority, base.anchors, base.bootstrap, server.socket_path, trace=trace)
    return ProcessDeployment(
        authority=base.authority, gateway=base.gateway, anchors=base.anchors,
        provisioner=provisioner, bootstrap=base.bootstrap, server=server)
