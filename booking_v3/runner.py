"""The ephemeral runner: one fragment, one lifetime.

A runner is created for one fragment and is unusable afterwards. It starts
with no state and no secret: everything it works with arrives as the
digest-checked policy, the signature-verified envelope and the fragment, plus
the trust anchors baked into its image. Its lifecycle is the transition
protocol:

    receive (fragment, envelope, policy)
    -> verify + check()                       (phase A, no effect)
    -> request execution grant                (Authority: atomic, pre-effect)
    -> gateway.execute(token, fragment)       (phase B, the one effect)
    -> validate result (producers, postconditions)
    -> propose successor envelope
    -> finalise with the Authority
    -> die

Every early exit (deny, approval required, grant refused) happens before the
effect, so a rejected fragment leaves the world untouched.

The runner can also sign every verdict it reports. A runner that was given a signing key
states its decision in a `booking_v3.runner_attestation` statement and the Authority
verifies it against the public half recorded for the session. Without a key the
attestation field stays None and the Authority requires nothing. booking_v5 injects the
key of the attested TD, so the verdict the Authority acts on is the one the measured code
computed, not just one that arrived on its channel.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any, Mapping

from booking_v1.effects import EffectOutcome
from booking_v1.freeze import thaw, to_canonical
from booking_v2.facts import FactStore, ObservedFact

from . import runner_attestation as ra
from .authority import Authority, InterventionApproval, TransitionRecord, adopted_state, request_hash
from .envelope import StateEnvelope, TrustAnchors, chain_extend, serialize_facts
from .fragment import ActionFragment
from .gateway import GatewayRefusal, ToolGateway
from .monitor import V3Decision, check, validate_effect

_instance_counter = itertools.count(1)


@dataclass(frozen=True)
class RunnerResult:
    """What one runner lifetime produced.

    Attributes:
        status: One of STEP_COMPLETED, DENIED, REQUIRE_APPROVAL, GRANT_REFUSED,
            EFFECT_FAILED, EFFECT_UNCERTAIN, FINALIZE_REFUSED.
        envelope: The signed successor S_{i+1}, only on STEP_COMPLETED.
        reason: Human-readable outcome description.
        payload: The confirmed, validated tool payload (agent-visible result),
            only on STEP_COMPLETED. Every other outcome returns None, so an
            unvalidated result can neither be observed nor reused.
        runner_no: The unique instance number (evidence of separate runners).
    """

    status: str
    envelope: StateEnvelope | None
    reason: str
    payload: Mapping[str, Any] | None
    runner_no: int


class EphemeralRunner:
    """A trusted, single-use execution environment for one fragment."""

    def __init__(self, authority: Authority, gateway: ToolGateway,
                 anchors: TrustAnchors, credential, signer=None) -> None:
        """Create a runner for one fragment.

        Args:
            authority: The Authority the runner reports to.
            gateway: The Tool Gateway that performs the effect.
            anchors: The public keys baked into the runner image.
            credential: The fragment-bound RunnerCredential from the provisioner.
            signer: The key this runner signs its verdicts with, or None.
        """
        self._authority = authority
        self._gateway = gateway
        self._anchors = anchors
        # The key this runner signs its own verdicts with, or None. booking_v5 passes the
        # Ed25519 key of the attested TD (covered by the quote and by RTMR3). booking_v3
        # and booking_v4 pass nothing, and the Authority then requires no attestation.
        self._signer = signer
        # The fragment-bound RunnerCredential is injected by the trusted
        # RunnerProvisioner (see provisioner.py). A runner cannot provision
        # itself, and the provisioner does not hand the credential to the orchestrator. The attested
        # deployments establish the session via attested TLS instead.
        self._credential = credential
        self._destroyed = False
        self.runner_no = next(_instance_counter)

    def execute(
        self,
        policy,
        envelope: StateEnvelope,
        fragment: ActionFragment,
        intervention_approval: InterventionApproval | None = None,
    ) -> RunnerResult:
        """Run the full single-fragment lifecycle, then become unusable.

        Args:
            policy: The policy delivered with the fragment.
            envelope: The signed input state.
            fragment: The fragment to execute.
            intervention_approval: The human approval, for a step that requires one.

        Returns:
            The RunnerResult of this lifetime.

        Raises:
            RuntimeError: If the runner was already used.
        """
        if self._destroyed:
            raise RuntimeError("this runner was already destroyed (single use)")
        try:
            return self._execute(policy, envelope, fragment, intervention_approval)
        finally:
            self._destroyed = True

    # Internals.
    def _attest(self, statement) -> "ra.RunnerAttestation | None":
        """Sign one verdict statement, or None when this runner holds no signing key."""
        return None if self._signer is None else ra.sign(self._signer, statement)

    def _result(self, status: str, reason: str, *, envelope=None, payload=None) -> RunnerResult:
        """Build a RunnerResult carrying this runner's number."""
        return RunnerResult(status=status, envelope=envelope, reason=reason,
                            payload=payload, runner_no=self.runner_no)

    def _execute(self, policy, envelope, fragment, intervention_approval) -> RunnerResult:
        """Run phases A and B and report to the Authority."""
        # Phase A: verification and admission. No effect can occur in here.
        outcome = check(policy, envelope, fragment, self._anchors, intervention_approval)
        admission_event = to_canonical({
            "kind": "admission", "run_id": fragment.run_id,
            "step_index": fragment.fragment_index, "fragment_hash": fragment.fragment_hash,
            "tool": fragment.operation, "args": thaw(fragment.arguments),
            "decision": outcome.decision.value, "reason": outcome.reason,
        })
        admission_hash = ra.event_digest(admission_event)
        if outcome.decision is V3Decision.DENY:
            self._authority.report_denial(
                self._credential, fragment.run_id, admission_event,
                self._attest(ra.deny_statement(
                    run_id=fragment.run_id, state_hash=envelope.state_hash,
                    fragment_hash=fragment.fragment_hash, admission_hash=admission_hash)))
            return self._result("DENIED", outcome.reason)
        if outcome.decision is V3Decision.REQUIRE_APPROVAL:
            self._authority.report_intervention_required(
                self._credential, fragment.run_id, fragment.fragment_index, fragment.fragment_hash,
                self._attest(ra.intervention_statement(
                    run_id=fragment.run_id, step=fragment.fragment_index,
                    state_hash=envelope.state_hash, fragment_hash=fragment.fragment_hash)))
            return self._result("REQUIRE_APPROVAL", outcome.reason)

        grant, why = self._authority.request_execution_grant(
            self._credential, fragment, envelope.state_hash, admission_event, intervention_approval,
            self._attest(ra.grant_statement(
                run_id=fragment.run_id, step=fragment.fragment_index,
                state_hash=envelope.state_hash, fragment_hash=fragment.fragment_hash,
                operation=fragment.operation,
                request_hash=request_hash(fragment.operation, fragment.arguments),
                admission_hash=admission_hash)))
        if grant is None:
            # The atomic global check refused: stale state, wrong step, replay,
            # concurrent effect, spent action_id, elapsed or missing approval.
            # Zero effects have been executed.
            return self._result("GRANT_REFUSED", why)

        # Phase B: the one effect, through the capability token only.
        try:
            result = self._gateway.execute(grant.token, fragment)
        except Exception as exc:                         # noqa: BLE001 because the transport broke after the request left
            return self._lost_transport(fragment, envelope, grant, admission_event, exc)
        if isinstance(result, GatewayRefusal):
            # FAILED asserts that no effect happened. That holds for every refusal the
            # gateway decides before it consumes the token, but not for an already spent
            # token: then a dispatch was started, by whoever spent it, and this runner
            # cannot know how it ended. Mapping both to FAILED would let a token the
            # orchestrator had spent against the same fragment park the run as "certainly
            # no effect" while the booking stood. Some pre-dispatch refusals (an expired
            # token, a binding mismatch) are therefore reported as FAILED without any
            # dispatch.
            outcome = "UNCERTAIN" if result.dispatch_attempted else "FAILED"
            return self._finalize_failure(
                fragment, envelope, grant, admission_event, outcome,
                error=f"gateway refused: {result.reason}", payload=None)

        if result.outcome is EffectOutcome.FAILED:
            return self._finalize_failure(
                fragment, envelope, grant, admission_event, "FAILED",
                error=result.error, payload=result.payload)
        if result.outcome is EffectOutcome.UNCERTAIN:
            return self._finalize_failure(
                fragment, envelope, grant, admission_event, "UNCERTAIN",
                error=result.error, payload=result.payload)

        # Confirmed: extract facts and check postconditions, fail-closed.
        step = fragment.fragment_index
        outputs, ok = validate_effect(policy, step, result.payload, outcome.store, fragment.arguments)
        if not ok:
            return self._finalize_failure(
                fragment, envelope, grant, admission_event, "INTEGRITY_FAILED",
                error="post-effect integrity check failed (fail-closed)", payload=result.payload)

        produced_names = [name for name, _v, _ft in outputs]
        effect_event = to_canonical({
            "kind": "effect", "run_id": fragment.run_id, "step_index": step,
            "fragment_hash": fragment.fragment_hash, "outcome": "CONFIRMED",
            "payload": thaw(result.payload) if result.payload is not None else None,
            "error": None, "produced_facts": produced_names,
        })
        new_head = chain_extend(envelope.audit_head, [admission_event, effect_event])

        # Rebuild the successor fact store: verified prior facts plus the new,
        # provenance-anchored ones.
        new_store = FactStore(fragment.run_id)
        for name in outcome.store.names():
            new_store.put(outcome.store.get(name))
        # producing_seq keeps its booking_v2 meaning: the sequence number of the
        # producing effect event in the archived chain. Committed transitions
        # contribute (admission, effect) pairs, so the effect of step i sits at
        # index 2*i + 1, matching the booking_v2 monitor's numbering.
        producing_seq = 2 * step + 1
        for name, value, ftype in outputs:
            new_store.put(ObservedFact(
                name=name, value=value, ftype=ftype, source_tool=fragment.operation,
                producing_seq=producing_seq, run_id=fragment.run_id,
                fragment_id=fragment.fragment_hash[:16], timestamp=grant.issued_at,
                integrity=new_head))

        proposed = StateEnvelope(
            run_id=envelope.run_id, policy_digest=envelope.policy_digest,
            approval_id=envelope.approval_id, step_index=step + 1,
            facts=serialize_facts(new_store), audit_head=new_head,
            previous_state_hash=envelope.state_hash)
        record = TransitionRecord(
            run_id=fragment.run_id, grant_id=grant.grant_id,
            outcome="CONFIRMED_VALIDATED", admission_event=admission_event,
            effect_event=effect_event, proposed=proposed)
        signed, why = self._authority.finalize_transition(
            self._credential, record, self._attest(ra.finalize_statement(
                run_id=record.run_id, grant_id=record.grant_id, outcome=record.outcome,
                admission_hash=admission_hash, effect_hash=ra.event_digest(effect_event),
                proposed_state_hash=proposed.state_hash)))
        if signed is None:
            return self._result("FINALIZE_REFUSED", why)
        payload = dict(thaw(result.payload)) if result.payload is not None else None
        return self._result("STEP_COMPLETED", f"step {step} confirmed and validated",
                            envelope=signed, payload=payload)

    def _lost_transport(self, fragment, envelope, grant, admission_event, exc) -> RunnerResult:
        """Report a step whose request left without an answer coming back.

        The effect may have happened. The runner may ask the gateway what it recorded for
        this grant, read only (`dispatch_outcome` performs no external call), and it does
        not send the request again. Whatever the lookup says, the step is reported
        UNCERTAIN. A stored confirmation reaches the runner without the answer it was
        waiting for, so no payload and no postcondition were checked here, and a successor
        built from it would carry a fact nobody validated. The Authority takes over the
        report and parks the run, instead of leaving it in EFFECT_PENDING.
        """
        lookup = getattr(self._gateway, "dispatch_outcome", None)
        recorded = "no lookup available"
        if lookup is not None:
            try:
                answer = lookup(grant.token, fragment)
                recorded = f"the gateway holds outcome {getattr(getattr(answer, 'outcome', None), 'value', 'none')}"
            except Exception as lookup_exc:              # noqa: BLE001 because unknown stays unknown
                recorded = f"the gateway lookup failed ({type(lookup_exc).__name__})"
        return self._finalize_failure(
            fragment, envelope, grant, admission_event, "UNCERTAIN",
            error=f"gateway transport lost after the request ({type(exc).__name__}), {recorded}; "
                  "not repeated, not trusted",
            payload=None)

    def _finalize_failure(self, fragment, envelope, grant, admission_event,
                          outcome: str, *, error, payload) -> RunnerResult:
        """Report a failed, uncertain or unvalidated effect. No successor exists."""
        effect_event = to_canonical({
            "kind": "effect", "run_id": fragment.run_id,
            "step_index": fragment.fragment_index, "fragment_hash": fragment.fragment_hash,
            "outcome": outcome,
            "payload": thaw(payload) if payload is not None else None,
            "error": error, "produced_facts": [],
        })
        record = TransitionRecord(
            run_id=fragment.run_id, grant_id=grant.grant_id, outcome=outcome,
            admission_event=admission_event, effect_event=effect_event, proposed=None)
        signed, why = self._authority.finalize_transition(
            self._credential, record, self._attest(ra.finalize_statement(
                run_id=record.run_id, grant_id=record.grant_id, outcome=record.outcome,
                admission_hash=ra.event_digest(admission_event),
                effect_hash=ra.event_digest(effect_event), proposed_state_hash="")))
        # There is no successor on this path either, so a missing envelope says nothing. What
        # counts is whether the Authority took over the failure, and which state it adopted. A
        # refusal must not be reported as a failure the Authority recorded.
        adopted = adopted_state(why)
        if signed is not None or adopted is None:
            return self._result("FINALIZE_REFUSED", why)
        # The status follows the state the Authority adopted, not the runner's own label: a
        # label the ledger contradicted comes back as parked-for-reconciliation, not as "failed".
        status = "EFFECT_FAILED" if adopted == "EFFECT_FAILED" else "EFFECT_UNCERTAIN"
        if adopted == "EFFECT_RECONCILE":
            return self._result(status, why)       # the Authority's reason: report contradicted the ledger
        return self._result(status, error or f"effect {outcome}")
