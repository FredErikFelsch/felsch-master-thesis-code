"""The stateless monitor: the booking_v2 decision as a pure function.

The booking_v2 monitor is an object carrying its own facts, cursor and
events. Here the same decision is a pure function whose entire state arrives
as the verified envelope. The cursor is envelope.step_index, and the fact store
is deserialised from envelope.facts. All predicate code of booking_v2 (schema,
constraints, bindings, producers, postconditions) is reused unchanged. On
verified state this monitor should decide as booking_v2 does, and the
differential traces in experiment.py check that.

Enforcement order:

    0   policy digest equals the envelope's approved digest
    0a  envelope hash and Authority signature verify, facts deserialise
    0b  fragment is bound to this envelope: run, policy, step, declarations
    1   tool identity == P.flow[step]
    2   argument schema (extra = forbid)
    3   local constraint, fail-closed
    4   cross-step bindings against the envelope's facts, fail-closed
    5   manual-intervention mark: valid fragment-bound approval or
        REQUIRE_APPROVAL

The consumable-rights counter, the action_id ledger, approval expiry and
freshness are not checked here. They are global, order-sensitive checks and
live in the Authority's atomic pre-effect grant.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from booking_v1 import constraints
from booking_v1.approval import kind_fits
from booking_v1.freeze import canonical_bytes
from booking_v1.schema import validate_args
from booking_v2 import facts as facts_mod
from booking_v2.facts import FactStore

from .authority import InterventionApproval
from .envelope import StateEnvelope, TrustAnchors, deserialize_facts, verify_envelope
from .fragment import ActionFragment, required_capability, required_facts


class V3Decision(str, Enum):
    """The stateless monitor's decision for one fragment."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class CheckResult:
    """The outcome of one stateless check.

    ``store`` is the deserialised, verified fact store. It is only present on
    ALLOW or REQUIRE_APPROVAL, so a caller cannot reach facts from an envelope
    that failed verification.
    """

    decision: V3Decision
    reason: str
    store: FactStore | None = None


def _deny(reason: str) -> CheckResult:
    """Return a DENY result without a fact store."""
    return CheckResult(decision=V3Decision.DENY, reason=reason)


def check(
    policy,
    envelope: StateEnvelope,
    fragment: ActionFragment,
    anchors: TrustAnchors,
    intervention_approval: InterventionApproval | None = None,
) -> CheckResult:
    """Decide one fragment against one verified envelope. Pure and stateless.

    Args:
        policy: The policy delivered with the fragment. It is trusted only once
            its digest matches the envelope.
        envelope: The signed input state.
        fragment: The proposed fragment.
        anchors: The public keys the runner was provisioned with.
        intervention_approval: The human approval, for a step that requires one.

    Returns:
        The decision, a reason and, on ALLOW or REQUIRE_APPROVAL, the verified
        fact store.
    """
    # 0. The delivered policy is untrusted until its digest matches the envelope.
    try:
        if policy.digest() != envelope.policy_digest:
            return _deny("policy digest does not match the approved run")
    except Exception:
        return _deny("policy does not canonicalise (fail-closed)")

    # 0a. Envelope integrity and authenticity, then fact deserialisation.
    ok, why = verify_envelope(envelope, anchors.envelope_key)
    if not ok:
        return _deny(f"envelope rejected: {why}")
    try:
        store = deserialize_facts(envelope.run_id, envelope.facts)
    except Exception:
        return _deny("envelope facts do not deserialize (fail-closed)")

    # 0b. Fragment-envelope binding and declaration equality.
    if fragment.run_id != envelope.run_id:
        return _deny("fragment is bound to a different run")
    if fragment.policy_digest != envelope.policy_digest:
        return _deny("fragment is bound to a different policy")
    if fragment.fragment_index != envelope.step_index:
        return _deny(f"fragment step {fragment.fragment_index} does not match envelope step {envelope.step_index}")
    step = envelope.step_index
    flow = policy.allowed_flow
    if step >= len(flow):
        return _deny("flow is already complete")
    if fragment.declared_facts != required_facts(policy, step):
        return _deny("declared facts do not equal the policy-derived facts")
    if fragment.declared_capability != required_capability(policy, step):
        return _deny("declared capability does not equal the policy-derived capability")

    # 1. Tool identity.
    expected = flow[step]
    if fragment.operation != expected:
        return _deny(f"out-of-policy action: expected {expected!r}, got {fragment.operation!r}")

    # 2. Argument schema (extra = forbid).
    ok, why = validate_args(fragment.operation, fragment.arguments)
    if not ok:
        return _deny(f"argument schema violated: {why}")

    # 3. Local constraint, fail-closed.
    local = policy.local_at(step)
    if local is not None:
        try:
            if not constraints.evaluate(local, fragment.arguments, policy):
                return _deny(f"parameter constraint violated at step {step}: {constraints.describe(local, policy)}")
        except Exception:
            return _deny("constraint evaluation error (fail-closed)")

    # 4. Cross-step bindings against the envelope's facts, fail-closed.
    for spec in policy.bindings_at(step):
        try:
            passed, desc = facts_mod.eval_binding(spec, fragment.arguments, store)
        except Exception:
            return _deny("binding evaluation error (fail-closed)")
        if not passed:
            return _deny(f"cross-step binding violated at step {step}: {desc}")

    # 5. Manual-intervention mark. Presence and fragment binding are checked
    # here. Expiry and single use are the Authority's, inside the atomic grant.
    if step in getattr(policy, "approval_required_steps", ()):
        ok, why = _intervention_binds(intervention_approval, fragment, anchors)
        if not ok:
            return CheckResult(
                decision=V3Decision.REQUIRE_APPROVAL,
                reason=f"manual intervention required at step {step}: {why}",
                store=store)

    return CheckResult(
        decision=V3Decision.ALLOW,
        reason="matches approved flow, schema, local constraint and cross-step bindings",
        store=store)


def _intervention_binds(
    approval: InterventionApproval | None,
    fragment: ActionFragment,
    anchors: TrustAnchors,
) -> tuple[bool, str]:
    """Check presence, signature, approver kind and fragment binding of an approval."""
    if approval is None:
        return False, "no intervention approval presented"
    if not anchors.intervention_key.verify(approval.signature, canonical_bytes(approval.binding())):
        return False, "intervention signature does not verify"
    if not kind_fits(approval.approver_kind, approval.approver_id):
        return False, "intervention approver kind is unknown or does not fit the approver id"
    if (approval.run_id != fragment.run_id
            or approval.step_index != fragment.fragment_index
            or approval.fragment_hash != fragment.fragment_hash):
        return False, "intervention approval binds a different fragment"
    return True, "intervention approval binds this fragment"


def validate_effect(
    policy, step: int, payload: Mapping[str, Any] | None, store: FactStore,
    args: Mapping[str, Any] | None = None,
) -> tuple[list[tuple[str, Any, str]], bool]:
    """Run the step's producers and postconditions on a confirmed payload.

    Mirrors the booking_v2 post-effect gate: every declared producer must yield a
    valid typed value and every postcondition must hold, otherwise the whole step
    fails its validation and produces no facts (fail-closed).

    Args:
        policy: The verified policy.
        step: The step that ran.
        payload: The confirmed payload, or None.
        store: The fact store of the input envelope.
        args: The admitted arguments of the fragment, which an `arg_field`
            producer reads.

    Returns:
        A pair ``(outputs, ok)``. ``outputs`` is empty when ``ok`` is False.
    """
    specs = policy.producers_at(step)
    if not specs:
        return [], True
    if payload is None:
        return [], False
    outputs: list[tuple[str, Any, str]] = []
    for spec in specs:
        try:
            name, value, ftype = facts_mod.run_producer(spec, payload, args)
            frozen = facts_mod.build_value(value, ftype)
        except Exception:
            return [], False
        outputs.append((name, frozen, ftype))
    produced = {name: value for name, value, _ft in outputs}
    for spec in policy.postconditions_at(step):
        try:
            ok, _desc = facts_mod.eval_postcondition(spec, produced, store)
        except Exception:
            return [], False
        if not ok:
            return [], False
    return outputs, True
