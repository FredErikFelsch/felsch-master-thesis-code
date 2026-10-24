"""The runner's own signature over the verdict it computed.

Without it, the Authority learns a runner's decision over a channel that carries no
authentication of its own::

    runner  --{credential, fragment, admission_event}-->  Authority

The credential is a bearer secret and the Authority does not recompute policy. A party
that reads one message therefore holds everything it needs to report an ALLOW for a
fragment the monitor had just denied. The attested binding of booking_v5 shows the
identity of a request. It does not show that the request had been admitted.

A ``RunnerAttestation`` closes that gap. The runner signs a statement with a key that
exists only inside it, and the Authority verifies the signature against the public half it
recorded when the session was established. Two rules apply:

1. The Authority does not read a field out of the statement it was handed. It rebuilds the
   statement it expects from its own ledger plus the request it is about to act on, and
   requires a signature over that. Forging a request therefore requires a signature over a
   statement the forger has no key for.
2. Every statement names its phase, so an attestation collected on one path (a denial, say)
   is not a valid attestation on another (a grant), even for the same fragment.

The signature is only as strong as the origin of the key. In booking_v5 the key is derived
inside the confidential VM from the same seed as the sealing key, before any fragment is
known, and its public half is covered both by the hardware quote (``canonical_binding``) and
by RTMR3. The Authority therefore verifies a verdict that chains to the attestation evidence,
not just a verdict that arrived on a session it once opened.

Sessions without a verify key keep the plain behaviour: ``require`` returns OK and nothing
else in their path changes. booking_v3 and booking_v4 treat the host beneath the runner as
trusted, so the check applies only on the stage whose threat model introduces a hostile
host, and the frozen ablations stay comparable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from booking_v1.freeze import canonical_bytes, thaw

from .envelope import SigningKey, VerifyKey

#: Bumped whenever the statement layout changes. A runner and an Authority that disagree
#: about the layout produce different bytes and therefore fail the signature check. There
#: is no version negotiation on this path. The value is named after booking_v5, the first
#: version whose runners hold a signing key. booking_v3 and booking_v4 runners do not sign.
ATTESTATION_VERSION = "v5.1"

PHASE_GRANT = "grant"
PHASE_DENY = "deny"
PHASE_INTERVENTION = "intervention"
PHASE_FINALIZE = "finalize"

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


def event_digest(event: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 of one audit event, as both sides compute it.

    ``canonical_bytes`` thaws and sorts, so a frozen and a plain mapping with the same
    content hash identically.
    """
    return hashlib.sha256(canonical_bytes(thaw(event))).hexdigest()


def _statement(phase: str, **fields: Any) -> dict:
    """Return a statement dict with kind, version and phase."""
    return {"kind": "runner-attestation", "v": ATTESTATION_VERSION, "phase": phase, **fields}


def grant_statement(run_id: str, step: int, state_hash: str, fragment_hash: str,
                    operation: str, request_hash: str, admission_hash: str) -> dict:
    """Return the statement a runner signs when it asks for an execution grant.

    It covers everything the effect depends on. ``request_hash`` is the hash the capability
    token will carry, so the arguments the gateway sees are the arguments the monitor
    admitted. ``admission_hash`` is the digest of the audit event, so the ALLOW that lands in
    the chain is the ALLOW the runner signed.

    Args:
        run_id: The run.
        step: The step of the fragment.
        state_hash: The input state hash.
        fragment_hash: The fragment's hash.
        operation: The tool name.
        request_hash: ``authority.request_hash`` of operation and arguments.
        admission_hash: ``event_digest`` of the admission event.

    Returns:
        The statement dict.
    """
    return _statement(PHASE_GRANT, run_id=run_id, step=int(step), state_hash=state_hash,
                      fragment_hash=fragment_hash, decision=DECISION_ALLOW,
                      operation=operation, request_hash=request_hash,
                      admission_hash=admission_hash)


def deny_statement(run_id: str, state_hash: str, fragment_hash: str, admission_hash: str) -> dict:
    """Return the statement a runner signs when it terminates a run with a DENY.

    It has no step field: the session already pins one (run, fragment, state) triple, and the
    step is covered by ``admission_hash`` because the admission event carries it.

    Args:
        run_id: The run.
        state_hash: The input state hash.
        fragment_hash: The fragment's hash.
        admission_hash: ``event_digest`` of the DENY admission event.

    Returns:
        The statement dict.
    """
    return _statement(PHASE_DENY, run_id=run_id, state_hash=state_hash,
                      fragment_hash=fragment_hash, decision=DECISION_DENY,
                      admission_hash=admission_hash)


def intervention_statement(run_id: str, step: int, state_hash: str, fragment_hash: str) -> dict:
    """Return the statement a runner signs when a step needs a human decision.

    Args:
        run_id: The run.
        step: The step that needs approval.
        state_hash: The input state hash.
        fragment_hash: The fragment's hash.

    Returns:
        The statement dict.
    """
    return _statement(PHASE_INTERVENTION, run_id=run_id, step=int(step), state_hash=state_hash,
                      fragment_hash=fragment_hash, decision=DECISION_REQUIRE_APPROVAL)


def finalize_statement(run_id: str, grant_id: str, outcome: str, admission_hash: str,
                       effect_hash: str, proposed_state_hash: str) -> dict:
    """Return the statement a runner signs when it reports the outcome of its effect.

    Signing ``proposed_state_hash`` stops a party on the channel from having an arbitrary
    fact store signed into a successor envelope: the facts are inside the proposal, the
    proposal is named by its hash, and the hash is inside the signature.

    Args:
        run_id: The run.
        grant_id: The grant the report answers.
        outcome: The runner's outcome label.
        admission_hash: ``event_digest`` of the admission event.
        effect_hash: ``event_digest`` of the effect event.
        proposed_state_hash: The successor's state hash, or the empty string when no
            successor is proposed.

    Returns:
        The statement dict.
    """
    return _statement(PHASE_FINALIZE, run_id=run_id, grant_id=grant_id, outcome=outcome,
                      admission_hash=admission_hash, effect_hash=effect_hash,
                      proposed_state_hash=proposed_state_hash)


@dataclass(frozen=True)
class RunnerAttestation:
    """One signed statement.

    It carries no authority of its own. It is only checked against a statement the
    verifying side rebuilt for itself.
    """

    statement: Mapping[str, Any]
    signature: str

    def binding(self) -> dict:
        """Return the signed statement as a plain dict."""
        return dict(thaw(self.statement))


def sign(signing_key: SigningKey, statement: Mapping[str, Any]) -> RunnerAttestation:
    """Sign one statement with the runner's own key.

    Args:
        signing_key: The runner's key.
        statement: The statement to sign.

    Returns:
        The RunnerAttestation.
    """
    return RunnerAttestation(statement=dict(thaw(statement)),
                             signature=signing_key.sign(canonical_bytes(statement)))


def require(verify_key: VerifyKey | None, expected: Mapping[str, Any],
            attestation: RunnerAttestation | None) -> tuple[bool, str]:
    """Return whether this call may proceed, and why not if it may not.

    The presented attestation must be a signature by this session's runner over the statement
    the caller rebuilt. The statements are compared as canonical bytes rather than field by
    field, so an added or renamed field is a mismatch rather than an ignored extra.

    Args:
        verify_key: The session's runner key. None means the session has no attested
            decisions (booking_v3, booking_v4), so nothing is required.
        expected: The statement the caller rebuilt.
        attestation: The presented attestation, or None.

    Returns:
        A pair (ok, reason).
    """
    if verify_key is None:
        return True, "no runner attestation required for this session"
    if not isinstance(attestation, RunnerAttestation):
        return False, "no attested decision presented"
    if canonical_bytes(attestation.statement) != canonical_bytes(expected):
        return False, "attested decision does not match the statement this call requires"
    if not verify_key.verify(attestation.signature, canonical_bytes(expected)):
        return False, "attested decision is not signed by this session's runner"
    return True, "attested decision verified"
