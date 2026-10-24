"""Self-contained tests for the V1.2 monitor.

Run:
    python3 -m booking_v1.tests

Coverage: EFFECT_PENDING is entered and only ACTIVE proceeds. Executor exceptions
become UNCERTAIN and are audited. Admission is committed before the effect. A lock
serialises submit. Approval and action replay are refused via the ledger. Expiry is
checked against the injected clock. The event chain covers effects and is deep-frozen. Policy validation is
complete.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import replace

from booking_v0.tools import ToolCall

from . import constraints
from .abstraction import alpha1
from .approval import (
    ApprovalExpired, ApprovalRejected, InvalidApprovalSignature, PolicyDigestMismatch,
    RunMismatch, approve,
)
from .clock import FixedClock
from .constraints import ConstraintSpec, budget_ceiling
from .effects import EffectOutcome, EffectResult, default_executor
from .freeze import MAX_STR, canonical_bytes, to_canonical
from .ledger import RunAlreadyActivated, RunLedger
from .lifecycle import PolicyState, Decision
from .monitor import PolicyMonitor, _hash
from .policy import Policy, default_p1
from .schema import PolicyInvalid

T0 = 1_700_000_000
NOW = T0 + 10
EXP = T0 + 3600


def _appr(policy, run="run-t", *, grant=True, expires=EXP, aid=None):
    return approve(policy, approver_id="a", approval_id=aid or f"ap-{run}", run_id=run, issued_at=T0, expires_at=expires, grant=grant)


def _mon(*, executor=None, run="run-t", ledger=None):
    policy = default_p1()
    kwargs = dict(run_id=run, clock=FixedClock(NOW), ledger=ledger or RunLedger())
    if executor is not None:
        kwargs["executor"] = executor
    return PolicyMonitor(policy=policy, approval=_appr(policy, run), **kwargs)


def _to_pay(m):
    for c in (ToolCall("search", {"to": "FRA"}), ToolCall("select", {"flight": "LH123"}), ToolCall("book", {"flight": "LH123", "action_id": "book-1"})):
        assert m.submit(c)[0] is Decision.ALLOW


def _pay(amount, recipient="airline:LH", action_id="p1", **extra):
    return ToolCall("pay", {"amount_minor": amount, "currency": "EUR", "recipient": recipient, "action_id": action_id, **extra})


# Core.

def test_benign_completes_confirmed() -> None:
    m = _mon()
    _to_pay(m)
    assert m.submit(_pay(34900))[0] is Decision.ALLOW
    assert m.state is PolicyState.COMPLETED
    assert all(e.outcome is EffectOutcome.CONFIRMED for e in m.effects)


def test_amount_boundary() -> None:
    m = _mon()
    _to_pay(m)
    assert m.submit(_pay(40000))[0] is Decision.ALLOW
    m = _mon()
    _to_pay(m)
    assert m.submit(_pay(40001))[0] is Decision.DENY


def test_admitted_boundaries() -> None:
    m = _mon()
    _to_pay(m)
    assert m.submit(_pay(34900, "attacker:acct-666"))[0] is Decision.ALLOW
    m = _mon()
    _to_pay(m)
    assert m.submit(_pay(1))[0] is Decision.ALLOW


# EFFECT_PENDING, only ACTIVE proceeds, no terminal overwrite.

def test_effect_pending_is_entered_and_blocks_reentrant_submit() -> None:
    # An executor that re-enters submit while the state is EFFECT_PENDING.
    seen = {}

    def reentrant(call):
        seen["state_during_effect"] = m.state
        # A nested submit during the pending effect must be denied.
        d, _r, _res = m.submit(ToolCall("search", {"to": "FRA"}))
        seen["nested_decision"] = d
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload={"ok": True})

    m = _mon(executor=reentrant)
    _to_pay(m)
    m.submit(_pay(34900))
    assert seen["state_during_effect"] is PolicyState.EFFECT_PENDING
    assert seen["nested_decision"] is Decision.DENY
    assert m.state is PolicyState.COMPLETED


def test_two_parallel_submits_one_grant() -> None:
    # A slow executor holds EFFECT_PENDING while a second thread tries to pay.
    barrier = threading.Event()
    release = threading.Event()

    def slow(call):
        # Only the pay effect is slow, so the barrier proves pay is in flight.
        if call.tool != "pay":
            return default_executor(call)
        barrier.set()
        release.wait(timeout=2)
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload={"ok": True})

    m = _mon(executor=slow)
    _to_pay(m)
    results = {}

    def first():
        results["first"] = m.submit(_pay(34900, action_id="a1"))[0]

    t = threading.Thread(target=first)
    t.start()
    barrier.wait(timeout=2)  # first is now inside the effect (EFFECT_PENDING)
    results["second"] = m.submit(_pay(34900, action_id="a2"))[0]  # must be denied
    release.set()
    t.join(timeout=2)
    assert results["second"] is Decision.DENY
    assert results["first"] is Decision.ALLOW
    assert m.state is PolicyState.COMPLETED


# Executor exceptions.

def test_executor_exception_becomes_uncertain_and_is_audited() -> None:

    def boom(call):
        if call.tool == "pay":
            raise RuntimeError("network exploded")
        return default_executor(call)

    m = _mon(executor=boom)
    _to_pay(m)
    decision, _reason, _res = m.submit(_pay(34900))
    assert decision is Decision.ALLOW
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    # The grant is audited: an admission ALLOW and an effect UNCERTAIN both exist.
    assert any(a.decision is Decision.ALLOW and a.tool == "pay" for a in m.admissions)
    assert any(e.outcome is EffectOutcome.UNCERTAIN and e.tool == "pay" for e in m.effects)


def test_invalid_executor_result_becomes_uncertain() -> None:

    def bad(call):
        return "not an EffectResult" if call.tool == "pay" else default_executor(call)

    m = _mon(executor=bad)
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.state is PolicyState.EFFECT_UNCERTAIN


def test_invalid_payload_shape_becomes_uncertain_and_audited() -> None:
    # An EffectResult with a non-mapping payload must not crash the monitor.

    def bad_payload(call):
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=[1]) if call.tool == "pay" else default_executor(call)

    m = _mon(executor=bad_payload)
    _to_pay(m)
    decision, _reason, _res = m.submit(_pay(34900))
    assert decision is Decision.ALLOW
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert any(e.outcome is EffectOutcome.UNCERTAIN and e.tool == "pay" for e in m.effects)
    assert m.verify_chain() is True


def test_book_requires_action_id() -> None:
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("book", {"flight": "LH123"}))[0] is Decision.DENY  # no action_id


# Replay resistance and clock.

def test_run_activates_only_once() -> None:
    policy = default_p1()
    ledger = RunLedger()
    appr = _appr(policy, "run-x")
    PolicyMonitor(policy=policy, approval=appr, run_id="run-x", clock=FixedClock(NOW), ledger=ledger)
    try:
        PolicyMonitor(policy=policy, approval=appr, run_id="run-x", clock=FixedClock(NOW), ledger=ledger)
    except RunAlreadyActivated:
        return
    raise AssertionError("same run activated twice")


def test_ledger_action_uniqueness() -> None:
    # The ledger consumes a (run_id, action_id) at most once. This is the seam a
    # durable store would back with a unique constraint. Single-activation already
    # blocks a second monitor for the same run (test_run_activates_only_once), so
    # the action ledger is the second layer against replayed grants.
    ledger = RunLedger()
    assert ledger.consume_action("run-a", "x1") is True
    assert ledger.consume_action("run-a", "x1") is False   # replay
    assert ledger.consume_action("run-a", "x2") is True     # different action
    assert ledger.consume_action("run-b", "x1") is True     # different run


def test_expired_approval_refused() -> None:
    policy = default_p1()
    # Approval expired relative to the trusted clock.
    try:
        PolicyMonitor(policy=policy, approval=_appr(policy, "run-e", expires=NOW - 1), run_id="run-e", clock=FixedClock(NOW), ledger=RunLedger())
    except ApprovalExpired:
        return
    raise AssertionError("expired approval activated")


# Schema and policy validation.

def test_unknown_missing_type_currency_denied() -> None:
    m = _mon()
    _to_pay(m)
    assert m.submit(_pay(34900, callback_url="http://x"))[0] is Decision.DENY
    m = _mon()
    _to_pay(m)
    assert m.submit(ToolCall("pay", {"amount_minor": 34900, "currency": "EUR", "action_id": "p"}))[0] is Decision.DENY
    m = _mon()
    _to_pay(m)
    assert m.submit(ToolCall("pay", {"amount_minor": 349.0, "currency": "EUR", "recipient": "airline:LH", "action_id": "p"}))[0] is Decision.DENY
    m = _mon()
    _to_pay(m)
    assert m.submit(ToolCall("pay", {"amount_minor": 34900, "currency": "USD", "recipient": "airline:LH", "action_id": "p"}))[0] is Decision.DENY


def test_pay_requires_action_id() -> None:
    m = _mon()
    _to_pay(m)
    assert m.submit(ToolCall("pay", {"amount_minor": 34900, "currency": "EUR", "recipient": "airline:LH"}))[0] is Decision.DENY


def test_invalid_policies_rejected() -> None:
    base = default_p1()
    bads = [
        dict(budget_minor=-1), dict(budget_minor=True), dict(currency=""),
        dict(policy_id=""), dict(allowed_flow=()),
        dict(allowed_flow=("search", "nope"), max_executions={"search": 1, "nope": 1}),
        dict(step_constraints={9: budget_ceiling()}),
        dict(step_constraints={3: ConstraintSpec("no_such_kind", {})}),
        dict(step_constraints={3: ConstraintSpec("budget_ceiling", {})}),  # missing params
        dict(max_executions={"search": 1, "select": 1, "book": 1}),  # missing pay counter
        dict(max_executions={"search": 1, "select": 1, "book": 1, "pay": 1, "read_secret": 1}),  # extra
        dict(step_constraints={0: budget_ceiling()}),  # references params not in 'search'
    ]
    for bad in bads:
        try:
            Policy(
                policy_id=bad.get("policy_id", "bad"), task=base.task,
                allowed_flow=bad.get("allowed_flow", base.allowed_flow),
                max_executions=bad.get("max_executions", dict(base.max_executions)),
                budget_minor=bad.get("budget_minor", base.budget_minor),
                currency=bad.get("currency", base.currency),
                step_constraints=bad.get("step_constraints", {3: budget_ceiling()}),
            )
        except PolicyInvalid:
            continue
        raise AssertionError(f"invalid policy accepted: {bad}")


# Deep immutability and audit chain over effects.

def test_normalize_nested_is_deeply_immutable() -> None:
    # The normaliser freezes recursively, so a nested value cannot be mutated.
    frozen = to_canonical({"a": {"b": [1, {"c": "x"}]}})
    try:
        frozen["a"]["b"][1]["c"] = "tampered"  # type: ignore[index]
        raise AssertionError("nested value was mutable")
    except (TypeError, AttributeError):
        pass


def test_malformed_args_safe_deny_no_crash() -> None:
    # A cyclic extra argument must not crash the monitor. It takes a safe DENY.
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    cyclic: dict = {"flight": "LH123"}
    cyclic["self"] = cyclic
    decision, reason, _ = m.submit(ToolCall("select", cyclic))
    assert decision is Decision.DENY
    assert "malformed" in reason
    assert m.state is PolicyState.TERMINATED
    assert m.verify_chain() is True


def test_non_canonical_payload_becomes_uncertain() -> None:

    def bad_payload(call):
        # A payload containing a set is not canonical.
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload={"x": {1, 2}}) if call.tool == "pay" else default_executor(call)

    m = _mon(executor=bad_payload)
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert m.verify_chain() is True


def test_empty_action_id_denied() -> None:
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("book", {"flight": "LH123", "action_id": ""}))[0] is Decision.DENY


def test_expiry_enforced_per_grant() -> None:
    # A monitor activated in-window must refuse a grant once the window elapses.
    class MutableClock:
        def __init__(self, t): self.t = t
        def now(self): return self.t

    policy = default_p1()
    clock = MutableClock(NOW)
    m = PolicyMonitor(policy=policy, approval=_appr(policy, "run-exp", expires=NOW + 100), run_id="run-exp", clock=clock, ledger=RunLedger())
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    clock.t = NOW + 1000  # window elapsed
    decision, reason, _ = m.submit(ToolCall("select", {"flight": "LH123"}))
    assert decision is Decision.DENY
    assert "validity window" in reason
    assert m.state is PolicyState.TERMINATED


def test_effect_event_correlates_to_admission() -> None:
    m = _mon()
    _to_pay(m)
    m.submit(_pay(34900, action_id="pay-42"))
    pay_effect = [e for e in m.effects if e.tool == "pay"][-1]
    assert pay_effect.action_id == "pay-42"
    # admission_seq points at an admission event that is an ALLOW for pay.
    admission = next(a for a in m.admissions if a.seq == pay_effect.admission_seq)
    assert admission.tool == "pay" and admission.decision is Decision.ALLOW


def test_effect_in_chain_and_payload_frozen() -> None:
    m = _mon()
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.verify_chain() is True
    eff = m.effects[-1]
    # The payload is a read-only mapping, mutation raises.
    try:
        eff.payload["paid"] = "forged"  # type: ignore[index]
        raise AssertionError("effect payload was mutable")
    except (TypeError, AttributeError):
        pass


def test_chain_detects_tampered_event() -> None:
    m = _mon()
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.verify_chain() is True
    # Replace an admission event (index 0) with an altered copy. The chain breaks.
    ev = m._events[0]
    m._events[0] = replace(ev, reason="tampered reason")
    assert m.verify_chain() is False


def test_genesis_bound_to_run_policy_approval() -> None:
    policy = default_p1()
    a = PolicyMonitor(policy=policy, approval=_appr(policy, "run-1"), run_id="run-1", clock=FixedClock(NOW), ledger=RunLedger())
    b = PolicyMonitor(policy=policy, approval=_appr(policy, "run-2"), run_id="run-2", clock=FixedClock(NOW), ledger=RunLedger())
    assert a.chain_head != b.chain_head  # different genesis by run/approval


# Structural sanity.

def test_off_policy_wrong_order_duplicate() -> None:
    m = _mon()
    m.submit(ToolCall("search", {"to": "FRA"}))
    assert m.submit(ToolCall("read_secret", {"key": "k"}))[0] is Decision.DENY
    m = _mon()
    m.submit(ToolCall("search", {"to": "FRA"}))
    m.submit(ToolCall("select", {"flight": "LH123"}))
    assert m.submit(_pay(34900))[0] is Decision.DENY
    m = _mon()
    _to_pay(m)
    assert m.submit(_pay(34900, action_id="p1"))[0] is Decision.ALLOW
    assert m.submit(_pay(34900, action_id="p2"))[0] is Decision.DENY


def test_approval_failures() -> None:
    policy = default_p1()
    for build, exc in [
        (lambda: _appr(policy, "r", grant=False), ApprovalRejected),
        (lambda: _appr(policy, "other"), RunMismatch),
    ]:
        try:
            PolicyMonitor(policy=policy, approval=build(), run_id="r", clock=FixedClock(NOW), ledger=RunLedger())
            raise AssertionError("bad approval activated")
        except exc:
            pass
    # forged signature
    appr = _appr(policy, "r")
    try:
        PolicyMonitor(policy=policy, approval=replace(appr, signature="0" * 64), run_id="r", clock=FixedClock(NOW), ledger=RunLedger())
        raise AssertionError("forged approval activated")
    except InvalidApprovalSignature:
        pass
    # tampered policy digest
    appr = _appr(policy, "r2")
    tampered = replace(policy, budget_minor=999900, step_constraints={3: budget_ceiling()})
    try:
        PolicyMonitor(policy=tampered, approval=appr, run_id="r2", clock=FixedClock(NOW), ledger=RunLedger())
        raise AssertionError("tampered policy activated")
    except PolicyDigestMismatch:
        pass


def test_constraint_exception_fails_closed_no_leak() -> None:
    policy = default_p1()
    m = PolicyMonitor(policy=policy, approval=_appr(policy, "rc"), run_id="rc", clock=FixedClock(NOW), ledger=RunLedger())
    _to_pay(m)
    original = constraints._REGISTRY["budget_ceiling"]

    def raiser(_p, _a, _pol):
        raise RuntimeError("secret detail")

    constraints._REGISTRY["budget_ceiling"] = (raiser, original[1])
    try:
        decision, reason, _ = m.submit(_pay(34900))
    finally:
        constraints._REGISTRY["budget_ceiling"] = original
    assert decision is Decision.DENY
    assert "secret detail" not in reason
    assert m.state is PolicyState.TERMINATED


def test_overlong_mapping_key_and_toolname_denied() -> None:
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    # Overlong mapping key in an argument -> malformed DENY (normaliser rejects it).
    big_key = "k" * (MAX_STR + 1)
    d, reason, _ = m.submit(ToolCall("select", {"flight": "LH123", big_key: "x"}))
    assert d is Decision.DENY and "malformed" in reason
    # Overlong tool name -> malformed DENY.
    m2 = _mon()
    d2, reason2, _ = m2.submit(ToolCall("s" * (MAX_STR + 1), {"to": "FRA"}))
    assert d2 is Decision.DENY and "malformed" in reason2


def test_overlong_error_becomes_uncertain() -> None:

    def big_error(call):
        return EffectResult(outcome=EffectOutcome.CONFIRMED, error="e" * (MAX_STR + 1)) if call.tool == "pay" else default_executor(call)

    m = _mon(executor=big_error)
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert m.verify_chain() is True


def test_pair_list_payload_uncertain() -> None:

    def pair_list(call):
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=[("a", 1)]) if call.tool == "pay" else default_executor(call)

    m = _mon(executor=pair_list)
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.state is PolicyState.EFFECT_UNCERTAIN


def test_pair_list_args_denied() -> None:
    m = _mon()
    d, reason, _ = m.submit(ToolCall("search", [("to", "FRA")]))
    assert d is Decision.DENY and "malformed" in reason


def test_arbitrary_object_and_cycle_payload_uncertain() -> None:

    def obj_payload(call):
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload={"x": object()}) if call.tool == "pay" else default_executor(call)

    m = _mon(executor=obj_payload)
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.state is PolicyState.EFFECT_UNCERTAIN

    def cyclic_payload(call):
        if call.tool != "pay":
            return default_executor(call)
        d: dict = {"a": 1}
        d["self"] = d
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=d)

    m2 = _mon(executor=cyclic_payload)
    _to_pay(m2)
    m2.submit(_pay(34900))
    assert m2.state is PolicyState.EFFECT_UNCERTAIN


def test_genesis_delimiter_ambiguity_regression() -> None:
    # A delimiter-joined genesis collides for two distinct (run_id, approval_id)
    # pairs. The canonical genesis used by the monitor does not.
    D = "deadbeef"
    p1 = {"run_id": "a|" + D + "|b", "approval_id": "c"}
    p2 = {"run_id": "a", "approval_id": "b|" + D + "|c"}
    naive1 = f"genesis|{p1['run_id']}|{D}|{p1['approval_id']}"
    naive2 = f"genesis|{p2['run_id']}|{D}|{p2['approval_id']}"
    assert naive1 == naive2  # the delimiter-joined form is ambiguous
    c1 = canonical_bytes({"kind": "genesis", "run_id": p1["run_id"], "policy_digest": D, "approval_id": p1["approval_id"]})
    c2 = canonical_bytes({"kind": "genesis", "run_id": p2["run_id"], "policy_digest": D, "approval_id": p2["approval_id"]})
    assert c1 != c2  # the canonical form is not


def test_independent_chain_reconstruction() -> None:
    # A reviewer holding the exported inputs can recompute the genesis and verify
    # the whole chain without the monitor object.
    policy = default_p1()
    approval = _appr(policy, "run-rec")
    m = PolicyMonitor(policy=policy, approval=approval, run_id="run-rec", clock=FixedClock(NOW), ledger=RunLedger())
    _to_pay(m)
    m.submit(_pay(34900))

    binding_digest = hashlib.sha256(canonical_bytes(approval.binding())).hexdigest()
    genesis = hashlib.sha256(canonical_bytes({
        "kind": "genesis", "run_id": "run-rec", "policy_digest": policy.digest(),
        "approval_id": approval.approval_id, "approval_binding_digest": binding_digest,
    })).hexdigest()
    assert genesis == m.genesis

    prev = genesis
    for e in m.events:
        assert e.prev_hash == prev
        assert e.record_hash == _hash(prev, e.chain_payload())
        prev = e.record_hash
    assert prev == m.chain_head


def test_chain_truncation_is_invisible_without_an_external_head() -> None:
    """Dropping the trailing events leaves a chain that verifies from the genesis.

    The dropped events are the payment's admission and effect. Only a head held
    outside the chain (here recorded before the cut) exposes the truncation.
    """
    policy = default_p1()
    m = PolicyMonitor(policy=policy, approval=_appr(policy, "run-tr"), run_id="run-tr",
                      clock=FixedClock(NOW), ledger=RunLedger())
    _to_pay(m)
    m.submit(_pay(34900))
    assert m.state is PolicyState.COMPLETED
    head = m.chain_head
    events = list(m.events)
    assert len(events) == 8
    truncated = events[:-2]                      # the log now ends before the payment
    prev = m.genesis
    for e in truncated:                          # continuity from genesis: intact
        assert e.prev_hash == prev
        prev = e.record_hash
    assert prev != head                          # the anchor catches it
    assert m.verify_chain(expected_head=head) is True
    assert m.verify_chain(expected_head="0" * 64) is False


def test_alpha1_separates_amount_not_recipient() -> None:
    policy = default_p1()
    assert alpha1(_pay(34900, "airline:LH"), policy, 3) == ("pay", True)
    assert alpha1(_pay(34900, "attacker:acct-666"), policy, 3) == ("pay", True)
    assert alpha1(_pay(499900), policy, 3) == ("pay", False)


def main() -> None:
    """Run all tests and report."""
    tests = [
        test_benign_completes_confirmed,
        test_amount_boundary,
        test_admitted_boundaries,
        test_effect_pending_is_entered_and_blocks_reentrant_submit,
        test_two_parallel_submits_one_grant,
        test_executor_exception_becomes_uncertain_and_is_audited,
        test_invalid_executor_result_becomes_uncertain,
        test_invalid_payload_shape_becomes_uncertain_and_audited,
        test_book_requires_action_id,
        test_run_activates_only_once,
        test_ledger_action_uniqueness,
        test_expired_approval_refused,
        test_unknown_missing_type_currency_denied,
        test_pay_requires_action_id,
        test_invalid_policies_rejected,
        test_normalize_nested_is_deeply_immutable,
        test_malformed_args_safe_deny_no_crash,
        test_non_canonical_payload_becomes_uncertain,
        test_empty_action_id_denied,
        test_expiry_enforced_per_grant,
        test_effect_event_correlates_to_admission,
        test_effect_in_chain_and_payload_frozen,
        test_chain_detects_tampered_event,
        test_genesis_bound_to_run_policy_approval,
        test_off_policy_wrong_order_duplicate,
        test_approval_failures,
        test_constraint_exception_fails_closed_no_leak,
        test_overlong_mapping_key_and_toolname_denied,
        test_overlong_error_becomes_uncertain,
        test_pair_list_payload_uncertain,
        test_pair_list_args_denied,
        test_arbitrary_object_and_cycle_payload_uncertain,
        test_genesis_delimiter_ambiguity_regression,
        test_independent_chain_reconstruction,
        test_chain_truncation_is_invisible_without_an_external_head,
        test_alpha1_separates_amount_not_recipient,
    ]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")


if __name__ == "__main__":
    main()
