"""The runner child entrypoint: one fresh interpreter, one fragment, exit.

Started by the trusted provisioner via spawn and exec, not fork, so no parent
memory is inherited. The child reads two messages on stdin, kept apart by
their origin:

    line 1  trusted provisioning input, written by the provisioner at spawn:
            trust anchors, the deployment service endpoint, and the
            ephemeral fragment-bound runner credential
    line 2  untrusted execution input, originating from the orchestrator:
            fragment, envelope and policy, all verified cryptographically
            by the monitor before anything is trusted

It then runs the booking_v3 EphemeralRunner unchanged, with the
Authority and Gateway proxies duck-typed in place of in-process objects,
writes one RunnerResult line on stdout, and dies.
"""

from __future__ import annotations

import os
import sys
import time
import traceback

from booking_v3.runner import EphemeralRunner

from . import wire
from .endpoint import ServiceEndpoint
from .services import AuthorityClient, GatewayClient


def _trace(event: str) -> None:
    """Write one phase marker on stderr when RUNNER_TRACE=1.

    These markers are measurement only and not part of the protocol. stdout
    stays the strict protocol channel (one RunnerResult line, clean exit). The
    markers do not touch decisions, facts or the wire result. They let the
    trusted parent split the four deployment phases (cold start, handoff-in,
    execution, handoff-out) on the host-wide CLOCK_MONOTONIC. Without
    RUNNER_TRACE=1 nothing is written.

    Emitted boundaries:
        ready    the runner is up and imported, before reading any input (T1)
        precall  inputs received and reconstructed, before execute()   (T2)
        postcall execute() returned, before the result is written       (T3)
    """
    if os.environ.get("RUNNER_TRACE") != "1":
        return
    try:  # best effort: telemetry must not alter the runner's execution
        sys.stderr.write(f"TRACE {event} {time.monotonic_ns()}\n")
        sys.stderr.flush()
    except Exception:
        pass


def main() -> int:
    """Read the provisioning and execution lines, run the fragment and write the result."""
    _trace("ready")
    provisioning = wire.decode_line(sys.stdin.readline())
    p = wire._expect(provisioning, "provisioning",
                     {"endpoint", "credential", "anchors"})
    credential = wire.credential_from_wire(p["credential"])
    anchors = wire.anchors_from_wire(p["anchors"])
    endpoint = ServiceEndpoint.from_wire(p["endpoint"])
    authority = AuthorityClient(endpoint)
    gateway = GatewayClient(endpoint)

    execution = wire.decode_line(sys.stdin.readline())
    e = wire._expect(execution, "execution",
                     {"policy", "envelope", "fragment", "intervention"})
    policy = wire.policy_from_wire(e["policy"])
    envelope = wire.envelope_from_wire(e["envelope"])
    fragment = wire.fragment_from_wire(e["fragment"])
    intervention = wire.intervention_from_wire(e["intervention"])

    runner = EphemeralRunner(authority, gateway, anchors, credential)
    _trace("precall")
    result = runner.execute(policy, envelope, fragment, intervention)
    _trace("postcall")
    sys.stdout.write(wire.encode(wire.result_to_wire(result)) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # report every failure as RUNNER_ERROR
        # The RunnerResult reason flows back to the untrusted orchestrator, so an
        # unexpected or internal failure must not leak its detail. WireError is
        # protocol-level input validation and is safe to name. Anything else
        # returns a fixed reason, with the detail audited on stderr (trusted side).
        if isinstance(exc, wire.WireError):
            reason = f"WireError: {exc}"
        else:
            reason = "runner internal error"
            try:
                sys.stderr.write("[runner-audit] " + traceback.format_exc())
                sys.stderr.flush()
            except Exception:
                pass
        sys.stdout.write(wire.encode({
            "v": wire.WIRE_VERSION, "kind": "runner-result",
            "status": "RUNNER_ERROR", "reason": reason,
            "payload": None, "envelope": None, "runner_no": -1}) + "\n")
        sys.stdout.flush()
        sys.exit(1)
