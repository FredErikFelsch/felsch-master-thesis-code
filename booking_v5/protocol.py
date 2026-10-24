"""The V5 attach protocol: seven lines between the controller and the TD.

Both sides use one definition, so the bytes the Authority attests are the bytes the runner
parses. Every line is one canonical `booking_v4.wire` JSON message. The transport only has to
carry lines (`pods/attach` stdin/stdout in production, an in-memory pipe in the tests).

    controller                                    runner (inside the TD)
    ---------------------------------------------------------------------------
    v5-open       -->                               the controller is attached, the runner may speak
                                <--  v5-hello       pk_boot and pk_sig, right after boot
    v5-challenge  -->                               run, step, hashes, nonce
                                <--  v5-evidence    quote over the canonical binding
    v5-session    -->                               credential and anchors, sealed to pk_boot
    v5-execution  -->                               fragment and envelope octets
                                <--  runner-result  one line, then exit

The execution line carries base64 octets and not decoded objects, because the bytes fed in
must be the bytes that were attested. If the runner re-encoded a parsed object to check the
hash, it would be checking its own serialiser, not the transport. So the octets travel
unchanged. `Binding.verify_bytes` decodes them only to derive the V3 identifiers, requires the
encoding to be canonical and compares the identifiers with the attested ones. Only then are
the octets handed to the monitor.
"""
from __future__ import annotations

import base64
from typing import Any, Mapping

from booking_v4 import wire

from .binding import RunnerKeys
from .evidence import Evidence
from .runner_bind import Challenge

KIND_OPEN = "v5-open"          # controller to runner: attached, the runner may speak
KIND_HELLO = "v5-hello"
KIND_CHALLENGE = "v5-challenge"
KIND_EVIDENCE = "v5-evidence"
KIND_SESSION = "v5-session"
KIND_EXECUTION = "v5-execution"


class ProtocolError(wire.WireError):
    """A line was not the message the protocol expects at this point."""


def _line(kind: str, **fields: Any) -> str:
    return wire.encode({"v": wire.WIRE_VERSION, "kind": kind, **fields})


def _parse(line: str, kind: str, keys: set[str]) -> dict:
    """Decode one line and require its key set to match `keys` (unknown keys are rejected)."""
    message = wire.decode_line(line)
    if message.get("kind") != kind:
        raise ProtocolError(f"expected {kind!r}, got {message.get('kind')!r}")
    if set(message) - {"v"} != keys | {"kind"}:
        raise ProtocolError(f"{kind}: key set mismatch, got {sorted(set(message) - {'v'})}")
    return message


# --- the bytes that get attested ---------------------------------------------

def fragment_bytes(fragment) -> bytes:
    """Return the canonical octets of a fragment.

    `wire.encode` sorts keys and drops whitespace, so the result depends only on the
    fragment's content.
    """
    return wire.encode(wire.fragment_to_wire(fragment)).encode()


def envelope_bytes(envelope) -> bytes:
    """Return the canonical octets of a state envelope."""
    return wire.encode(wire.envelope_to_wire(envelope)).encode()


def attested_hashes(fragment, envelope) -> tuple[str, str]:
    """Return (fragment_hash, state_hash), which the Authority binds and the TD re-checks.

    These are V3's own identifiers (`ActionFragment.fragment_hash`, the canonical digest of
    every fragment field, and `StateEnvelope.state_hash`, signed by the Authority), so the V5
    binding names the same objects the V3 grant path and the gateway token bind. V3, V4 and
    V5 therefore share one identifier per object.
    """
    return fragment.fragment_hash, envelope.state_hash


def hashes_of_octets(fragment_octets: bytes, envelope_octets: bytes) -> tuple[str, str]:
    """Derive the V3 identifiers of the octets handed to the TD.

    The octets must be canonical (decoding and re-encoding yields the same bytes, so no
    semantic content hides in a non-canonical encoding). The caller compares the returned
    identifiers with the attested ones.

    Args:
        fragment_octets: the fragment octets from the execution line.
        envelope_octets: the envelope octets from the execution line.

    Returns:
        (fragment_hash, state_hash) of the decoded objects.

    Raises:
        ProtocolError: an encoding is not canonical.
        booking_v4.wire.WireError: the octets do not decode.
    """
    fragment = parse_fragment_octets(fragment_octets)
    envelope = parse_envelope_octets(envelope_octets)
    if fragment_bytes(fragment) != fragment_octets:
        raise ProtocolError("fragment octets are not canonical")
    if envelope_bytes(envelope) != envelope_octets:
        raise ProtocolError("envelope octets are not canonical")
    return attested_hashes(fragment, envelope)


# --- messages ----------------------------------------------------------------

def open_line() -> str:
    """Return the controller's first line.

    Under kata-remote, stdout written before an attach goes to the container log and not to
    the attach stream, so the runner waits until the controller has attached and said so.
    Every runner line is then an answer.
    """
    return _line(KIND_OPEN)


def parse_open(line: str) -> None:
    """Check that `line` is the controller's open line."""
    _parse(line, KIND_OPEN, set())


def hello(keys: RunnerKeys) -> str:
    """Return the hello line, which carries both public keys.

    Announcing them separately would let a transport pair a genuine sealing key with a
    verdict key of its own. The canonical binding covers both, so such a pair is refused, and
    one message keeps that visible.
    """
    return _line(KIND_HELLO, pk_boot=keys.pk_boot.hex(), pk_sig=keys.pk_sig.hex())


def parse_hello(line: str) -> RunnerKeys:
    """Read the runner's two public keys from its hello line."""
    m = _parse(line, KIND_HELLO, {"pk_boot", "pk_sig"})
    return RunnerKeys(bytes.fromhex(m["pk_boot"]), bytes.fromhex(m["pk_sig"]))


def challenge(c: Challenge) -> str:
    """Return the controller's challenge line: what the TD binds to and the nonce to attest over."""
    return _line(KIND_CHALLENGE, run_id=c.run_id, step=c.step, fragment_hash=c.fragment_hash,
                 state_hash=c.state_hash, nonce=c.nonce.hex())


def parse_challenge(line: str) -> Challenge:
    """Read a challenge line."""
    m = _parse(line, KIND_CHALLENGE, {"run_id", "step", "fragment_hash", "state_hash", "nonce"})
    return Challenge(m["run_id"], int(m["step"]), m["fragment_hash"], m["state_hash"],
                     bytes.fromhex(m["nonce"]))


def evidence(ev: Evidence) -> str:
    """Return the runner's evidence line."""
    return _line(KIND_EVIDENCE, **ev.to_wire())


def parse_evidence(line: str) -> Evidence:
    """Read an evidence line.

    Raises:
        ProtocolError: the line or the evidence it carries is malformed.
    """
    m = _parse(line, KIND_EVIDENCE, {"platform", "blob_parts", "runtime_data"})
    try:
        return Evidence.from_wire(m)
    except ValueError as e:
        raise ProtocolError(f"{KIND_EVIDENCE}: {e}") from None


def session(sealed: Mapping[str, str], endpoint, gateway_endpoint=None) -> str:
    """Return the session line: the sealed package and where to send the grant request.

    The package holds the credential and the trust anchors, sealed by the Authority to this
    TD's boot key (`booking_v4.wire.session_package_to_wire` explains why the anchors travel
    inside it). The Authority endpoint and the gateway endpoint stay in the clear, because
    substituting one only misroutes a request that no real gateway would then honour. That is
    a denial of service and gives no authority.

    Args:
        sealed: the sealed box from `binding.seal_to`.
        endpoint: the Authority endpoint.
        gateway_endpoint: the gateway endpoint, or None for the legacy single service.

    Returns:
        The encoded line.
    """
    return _line(KIND_SESSION, sealed=dict(sealed), endpoint=endpoint.to_wire(),
                 gateway_endpoint=gateway_endpoint.to_wire() if gateway_endpoint is not None else None)


def parse_session(line: str) -> tuple[dict, Any, Any]:
    """Read a session line.

    Returns:
        (sealed, authority_endpoint, gateway_endpoint). The gateway endpoint falls back to the
        Authority endpoint for the legacy single service.
    """
    from booking_v4.endpoint import ServiceEndpoint
    m = _parse(line, KIND_SESSION, {"sealed", "endpoint", "gateway_endpoint"})
    sealed = wire.expect_keys(m["sealed"], {"eph_pub", "nonce", "ct"}, "sealed box")
    authority = ServiceEndpoint.from_wire(m["endpoint"])
    gateway = ServiceEndpoint.from_wire(m["gateway_endpoint"]) if m["gateway_endpoint"] is not None else authority
    return sealed, authority, gateway


def execution(fragment_octets: bytes, envelope_octets: bytes, policy, intervention=None) -> str:
    """Return the execution line: the octets to run, plus the policy and optional intervention.

    Args:
        fragment_octets: canonical fragment octets (`fragment_bytes`).
        envelope_octets: canonical envelope octets (`envelope_bytes`).
        policy: the V3 policy.
        intervention: an optional V3 intervention.

    Returns:
        The encoded line.
    """
    return _line(KIND_EXECUTION,
                 fragment=base64.b64encode(fragment_octets).decode(),
                 envelope=base64.b64encode(envelope_octets).decode(),
                 policy=wire.policy_to_wire(policy),
                 intervention=wire.intervention_to_wire(intervention))


def parse_execution(line: str) -> tuple[bytes, bytes, Any, Any]:
    """Read an execution line.

    The caller checks the octets against the attested hashes before the monitor sees them.

    Returns:
        (fragment_octets, envelope_octets, policy, intervention), with the octets as raw bytes.
    """
    m = _parse(line, KIND_EXECUTION, {"fragment", "envelope", "policy", "intervention"})
    return (base64.b64decode(m["fragment"]), base64.b64decode(m["envelope"]),
            wire.policy_from_wire(m["policy"]), wire.intervention_from_wire(m["intervention"]))


def parse_fragment_octets(octets: bytes):
    """Decode fragment octets into a fragment object."""
    return wire.fragment_from_wire(wire.decode_line(octets.decode()))


def parse_envelope_octets(octets: bytes):
    """Decode envelope octets into a state envelope object."""
    return wire.envelope_from_wire(wire.decode_line(octets.decode()))
