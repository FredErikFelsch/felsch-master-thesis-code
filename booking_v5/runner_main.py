"""The V5 runner entrypoint, which runs inside the confidential VM.

The V4 runner (`booking_v4.runner_process`) reads two lines and executes. The V5 runner first
proves what it is, before anyone hands it a credential, and then checks that the bytes it was
given are the bytes that were attested before it executes them.

    boot     derive the sealing and the verdict key and record both in RTMR3. Announce them
             only after the controller's v5-open (stdout before an attach reaches the log,
             not the stream)
    bind     freeze the single binding on the challenge                    (v5-challenge)
    attest   evidence over the canonical binding                           (v5-evidence)
    open     decrypt the credential and the trust anchors, sealed to the boot key (v5-session)
    verify   the offered octets must hash to the attested hashes           (v5-execution)
    execute  the frozen booking_v3 EphemeralRunner, unchanged
    result   one runner-result line on stdout, then exit

The runner does not rely on the controller for any of this. The controller transports lines.
It cannot make the runner attest to a fragment it was not bound to (`bind` happens once),
read the credential (sealed to a key that stays in the TD), or swap the fragment after
attestation (`verify_bytes`).

stdout is the protocol channel and carries only the lines above. Diagnostics go to stderr
through `_audit`, so they cannot be mistaken for protocol lines.
"""
from __future__ import annotations

import sys
from typing import Callable, Optional, TextIO

from booking_v4 import wire
from booking_v4.services import AuthorityClient, GatewayClient
from booking_v3.runner import EphemeralRunner

from . import protocol
from .runner_bind import AttestationAgent, RunnerError, V5Runner


def _audit(message: str) -> None:
    """Write one diagnostic line to stderr, which is not the protocol channel."""
    try:
        sys.stderr.write(f"[v5-runner] {message}\n")
        sys.stderr.flush()
    except Exception:                                   # noqa: BLE001 (stderr may already be closed)
        pass


def _default_execute(policy, envelope, fragment, intervention, anchors, endpoint, credential,
                     gateway_endpoint=None, signer=None):
    """Run the frozen V3 monitor with the V4 service proxies.

    V5 changes two things: the Authority and the gateway may be two services (two endpoints,
    two principals), and the monitor signs the verdict it reports with this TD's verdict key.

    Returns:
        The V3 run result.
    """
    runner = EphemeralRunner(AuthorityClient(endpoint), GatewayClient(gateway_endpoint or endpoint),
                             anchors, credential, signer=signer)
    return runner.execute(policy, envelope, fragment, intervention)


def serve(rx: TextIO, tx: TextIO, aa: Optional[AttestationAgent] = None,
          execute: Callable = _default_execute) -> int:
    """Run one fragment and return the process exit code.

    One TD serves one call for one fragment.

    Args:
        rx: the protocol input (stdin in the TD).
        tx: the protocol output (stdout in the TD).
        aa: the Attestation Agent client, the loopback default when None.
        execute: the monitor call, `_default_execute` in production.

    Returns:
        0 after the result line was written. Errors propagate to `__main__`.
    """
    runner = V5Runner.boot(aa)
    protocol.parse_open(rx.readline())                  # wait for the controller to be attached
    tx.write(protocol.hello(runner.keys) + "\n")
    tx.flush()

    challenge = protocol.parse_challenge(rx.readline())
    evidence = runner.attest(challenge)
    tx.write(protocol.evidence(evidence) + "\n")
    tx.flush()

    sealed, endpoint, gateway_endpoint = protocol.parse_session(rx.readline())
    package_octets = runner.open_session(sealed)        # only this TD, for this binding
    # The anchors come out of the sealed package, not off the wire. That keeps them from being
    # read or altered in transit, but sealing does not authenticate the sender. Anyone who knows
    # the public boot key can seal a package. The Authority's own re-checks at the grant are what
    # stop a substituted package from yielding an effect (see booking_v4.wire.session_package_to_wire
    # and booking_v5.tests_session_package_sender).
    credential, anchors = wire.session_package_from_wire(wire.decode_line(package_octets.decode()))

    fragment_octets, envelope_octets, policy, intervention = protocol.parse_execution(rx.readline())
    # The bytes check belongs here, inside the TD, on the octets themselves and against the
    # hashes the hardware attested. It raises BytesMismatch, which fails the run. The third
    # argument of the callback is the raw session package that `open_session` returned. The
    # credential and the anchors were already decoded from it above.
    result = runner.execute(
        fragment_octets, envelope_octets,
        lambda f, e, cred: execute(policy, protocol.parse_envelope_octets(e),
                                   protocol.parse_fragment_octets(f), intervention,
                                   anchors, endpoint, credential, gateway_endpoint,
                                   runner.signer))
    tx.write(wire.encode(wire.result_to_wire(result)) + "\n")
    tx.flush()
    return 0


def main() -> int:
    """Serve one fragment on stdin and stdout and return the exit code."""
    return serve(sys.stdin, sys.stdout)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:          # report the failure as one RUNNER_ERROR line and exit non-zero
        # The reason travels back to the controller, so only protocol-level input validation is
        # named. Everything else is written to stderr and reported as one fixed string, as the
        # V4 runner does.
        if isinstance(exc, (wire.WireError, RunnerError)):
            reason = f"{type(exc).__name__}: {exc}"
        else:
            reason = "runner internal error"
            _audit(f"{type(exc).__name__}: {exc}")
        sys.stdout.write(wire.encode({
            "v": wire.WIRE_VERSION, "kind": "runner-result",
            "status": "RUNNER_ERROR", "reason": reason,
            "payload": None, "envelope": None, "runner_no": -1}) + "\n")
        sys.stdout.flush()
        sys.exit(1)
