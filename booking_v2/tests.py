"""Self-contained tests for the V2 monitor.

Run:
    python3 -m booking_v2.tests

Covers the two exit criteria. V2a: cross-step consistency (book matches select,
pay matches the confirmed booking) and the
affordability of the booking before its effect. V2b: provenance (facts come only
from confirmed results, are typed and immutable, and the agent can neither forge,
alter nor replay them). Post-effect integrity: a confirmed result that a producer
or a postcondition cannot validate stops the flow fail-closed.
"""

from __future__ import annotations

from dataclasses import replace

from booking_v0.tools import ToolCall
from booking_v1.approval import ApprovalError, approve
from booking_v1.clock import FixedClock
from booking_v1.effects import EffectOutcome, EffectResult
from booking_v1.ledger import RunLedger
from booking_v1.lifecycle import Decision, PolicyState

from .facts import (
    BindingSpec, DuplicateFact, FactStore, FactTypeError, ObservedFact,
    PostconditionSpec, ProducerSpec, build_value, eval_binding,
)
from .monitor import PolicyMonitor
from .policy import Policy, PolicyInvalid, default_p2, default_p2_1
from .world import faulting_executor, v2_executor

T0 = 1_700_000_000
NOW = T0 + 10
EXP = T0 + 3600


def _appr(policy, run="run-t", *, grant=True):
    """Return a signed approval for ``run`` with the fixed test window."""
    return approve(policy, approver_id="a", approval_id=f"ap-{run}", run_id=run, issued_at=T0, expires_at=EXP, grant=grant)


def _mon(*, executor=None, run="run-t", policy=None):
    """Return a monitor for ``policy`` (default P2), activated for ``run``."""
    policy = policy or default_p2()
    kwargs = dict(run_id=run, clock=FixedClock(NOW), ledger=RunLedger())
    if executor is not None:
        kwargs["executor"] = executor
    return PolicyMonitor(policy=policy, approval=_appr(policy, run), **kwargs)


def _payload_executor(tool_name, payload):
    """An executor that returns a fixed confirmed payload for one tool."""
    def _execute(call):
        if call.tool == tool_name:
            return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=payload)
        return v2_executor(call)
    return _execute


def _search_select_book(m, select="LH123", book="LH123"):
    """Run search, select and book and return the last decision."""
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    d_sel = m.submit(ToolCall("select", {"flight": select}))[0]
    if d_sel is not Decision.ALLOW:
        return d_sel
    return m.submit(ToolCall("book", {"flight": book, "action_id": "book-1"}))[0]


def _pay(amount, recipient="airline:LH", currency="EUR", action_id="pay-1"):
    """Build a pay call in minor units."""
    return ToolCall("pay", {"amount_minor": amount, "currency": currency, "recipient": recipient, "action_id": action_id})


def _good_book_payload(flight="LH123", price=34900, currency="EUR", recipient="airline:LH", **over):
    """Return a well-formed booking payload, with ``over`` replacing fields."""
    payload = {"booking_ref": "BK", "flight_id": flight, "price_minor": price, "currency": currency, "recipient": recipient}
    payload.update(over)
    return payload


# Benign.

def test_benign_consistent_flow_completes() -> None:
    m = _mon()
    assert _search_select_book(m) is Decision.ALLOW
    assert m.submit(_pay(34900, "airline:LH"))[0] is Decision.ALLOW
    assert m.state is PolicyState.COMPLETED


# V2a cross-step.

def test_book_must_match_select() -> None:
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("book", {"flight": "LH999", "action_id": "b1"}))[0] is Decision.DENY
    assert m.state is PolicyState.TERMINATED


def test_select_must_be_offered() -> None:
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "ZZZ"}))[0] is Decision.DENY


def test_book_over_budget_denied_before_effect() -> None:
    # AF456 is offered, so selecting it is allowed, but at 412 EUR it exceeds the
    # 400 EUR budget. The booking is denied at admission, before any effect, so no
    # booking fact ever exists.
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "AF456"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("book", {"flight": "AF456", "action_id": "b1"}))[0] is Decision.DENY
    assert m.state is PolicyState.TERMINATED
    assert not any(e.tool == "book" for e in m.effects)
    assert "booking_amount_minor" not in m.facts()


def test_pay_amount_must_match_booking() -> None:
    m = _mon()
    assert _search_select_book(m) is Decision.ALLOW
    assert m.submit(_pay(1, "airline:LH"))[0] is Decision.DENY  # An underpayment is blocked.


def test_pay_recipient_must_match_booking() -> None:
    m = _mon()
    assert _search_select_book(m) is Decision.ALLOW
    assert m.submit(_pay(34900, "attacker:acct-666"))[0] is Decision.DENY


def test_pay_currency_must_match_booking() -> None:
    m = _mon()
    assert _search_select_book(m) is Decision.ALLOW
    assert m.submit(_pay(34900, "airline:LH", currency="USD"))[0] is Decision.DENY


# V2b provenance.

def test_facts_come_only_from_confirmed_effects() -> None:
    m = _mon()
    assert _search_select_book(m) is Decision.ALLOW
    facts = m.facts()
    # The booking price is the world's authoritative value, not anything the agent
    # supplied. The book call carries no price.
    assert facts["booking_amount_minor"].value == 34900
    assert facts["booking_recipient"].value == "airline:LH"
    assert facts["booking_amount_minor"].source_tool == "book"
    # Each fact is anchored to a real effect event in the audit chain.
    integrity_hashes = {e.record_hash for e in m.effects}
    assert facts["booking_amount_minor"].integrity in integrity_hashes


def test_failed_booking_yields_no_facts_and_blocks_payment() -> None:
    m = _mon(executor=faulting_executor({"book": EffectOutcome.FAILED}))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))  # effect fails
    assert m.state is PolicyState.EFFECT_FAILED
    assert "booking_amount_minor" not in m.facts()  # no fact without a confirmed effect
    assert m.submit(_pay(34900, "airline:LH"))[0] is Decision.DENY


def test_uncertain_booking_yields_no_facts() -> None:
    m = _mon(executor=faulting_executor({"book": EffectOutcome.UNCERTAIN}))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert "booking_amount_minor" not in m.facts()


def test_book_result_flight_mismatch_fails_closed() -> None:
    # The agent requests LH123, but the tool confirms a different flight. The
    # postcondition booking_flight_id == selected_flight_id catches it.
    m = _mon(executor=_payload_executor("book", _good_book_payload(flight="LH999")))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert "booking_flight_id" not in m.facts()


def test_book_result_wrong_typed_price_fails_closed() -> None:
    # A price returned as a string does not match the declared int type.
    m = _mon(executor=_payload_executor("book", _good_book_payload(price="34900")))
    assert _search_select_book(m) is Decision.ALLOW  # admission of book still ALLOW
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert "booking_amount_minor" not in m.facts()


def test_book_result_missing_recipient_fails_closed() -> None:
    payload = {"booking_ref": "BK", "flight_id": "LH123", "price_minor": 34900, "currency": "EUR"}
    m = _mon(executor=_payload_executor("book", payload))
    assert _search_select_book(m) is Decision.ALLOW
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    # All-or-nothing: not a single booking fact is produced, not even the ones
    # whose fields were present in the payload.
    assert not any(name.startswith("booking_") for name in m.facts())


def test_malformed_offers_payload_fails_closed() -> None:
    m = _mon(executor=_payload_executor("search", {"offers": "not-a-list"}))
    m.submit(ToolCall("search", {"to": "FRA"}))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert "offer_flight_ids" not in m.facts()


def test_agent_cannot_forge_a_missing_fact() -> None:
    # A binding whose fact is absent fails closed, so a payment without a recorded
    # booking cannot be authorised by any agent-supplied value.
    store = FactStore("run-x")
    b = BindingSpec("arg_equals_fact", {"arg": "amount_minor", "fact": "booking_amount_minor"})
    ok, _ = eval_binding(b, {"amount_minor": 34900}, store)
    assert ok is False


def test_replayed_fact_from_other_run_is_rejected() -> None:
    # A fact tagged with another run is not valid in this run's store.
    store = FactStore("run-A")
    foreign = ObservedFact(name="booking_amount_minor", value=34900, ftype="int", source_tool="book",
                           producing_seq=3, run_id="run-B", fragment_id="fragment_3", timestamp=NOW, integrity="deadbeef")
    try:
        store.put(foreign)
        raise AssertionError("store accepted a foreign-run fact")
    except ValueError:
        pass
    assert store.valid("booking_amount_minor") is None


def test_fact_store_rejects_duplicate_put() -> None:
    store = FactStore("run-A")
    f = ObservedFact(name="x", value=1, ftype="int", source_tool="book", producing_seq=1,
                     run_id="run-A", fragment_id="fragment_1", timestamp=NOW, integrity="h")
    store.put(f)
    try:
        store.put(replace(f, value=2))
        raise AssertionError("store accepted a duplicate fact name")
    except DuplicateFact:
        pass


# Typed and immutable facts.

def test_fact_value_is_typed_and_immutable() -> None:
    try:
        build_value("34900", "int")
        raise AssertionError("string accepted as int")
    except FactTypeError:
        pass
    frozen = build_value({"a": 1, "b": {"c": 2}}, "map")
    try:
        frozen["a"] = 9  # type: ignore[index]
        raise AssertionError("map fact value is mutable")
    except TypeError:
        pass


# Strict policy validation.

def test_duplicate_producer_fact_name_rejected() -> None:
    base = default_p2()
    try:
        Policy(policy_id="dup", task=base.task, allowed_flow=base.allowed_flow,
               max_executions=dict(base.max_executions), budget_minor=base.budget_minor, currency=base.currency,
               step_producers={0: (
                   ProducerSpec("field", {"name": "x", "payload_key": "a"}),
                   ProducerSpec("field", {"name": "x", "payload_key": "b"}),
               )})
        raise AssertionError("duplicate fact name accepted")
    except PolicyInvalid:
        pass


def test_affordable_ceiling_must_equal_budget() -> None:
    base = default_p2()
    bindings = dict(base.step_bindings)
    bindings[2] = (BindingSpec("arg_affordable", {"arg": "flight", "price_fact": "offer_prices", "ceiling": 999}),)
    try:
        replace(base, step_bindings=bindings)
        raise AssertionError("affordability ceiling different from budget accepted")
    except PolicyInvalid:
        pass


def test_currency_binding_must_equal_policy_currency() -> None:
    base = default_p2()
    bindings = dict(base.step_bindings)
    bindings[2] = (BindingSpec("arg_maps_to_const", {"arg": "flight", "map_fact": "offer_currencies", "expected": "USD"}),)
    try:
        replace(base, step_bindings=bindings)
        raise AssertionError("currency binding different from policy currency accepted")
    except PolicyInvalid:
        pass


def test_book_currency_bound_before_effect() -> None:
    # The offered currency is not EUR, so the booking is denied before its effect,
    # even though the flight is offered and selected.
    usd_offers = {"offers": [{"flight_id": "LH123", "price_minor": 34900, "currency": "USD", "merchant": "airline:LH"}]}
    m = _mon(executor=_payload_executor("search", usd_offers))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))[0] is Decision.DENY
    assert m.state is PolicyState.TERMINATED
    assert not any(e.tool == "book" for e in m.effects)


def test_duplicate_map_key_rejected() -> None:
    dup_offers = {"offers": [
        {"flight_id": "LH123", "price_minor": 34900, "currency": "EUR", "merchant": "airline:LH"},
        {"flight_id": "LH123", "price_minor": 34900, "currency": "EUR", "merchant": "airline:LH"},
    ]}
    m = _mon(executor=_payload_executor("search", dup_offers))
    m.submit(ToolCall("search", {"to": "FRA"}))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert "offer_prices" not in m.facts()


def test_no_tool_result_on_integrity_failure() -> None:
    m = _mon(executor=_payload_executor("book", _good_book_payload(flight="LH999")))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    _decision, _reason, tool_result = m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert tool_result is None  # a result that failed validation is not handed back


def _faulting_with_payload(outcome):
    """A book executor that returns a payload alongside a non-confirmed outcome."""
    def _execute(call):
        if call.tool == "book":
            return EffectResult(outcome=outcome, payload=_good_book_payload(), error="e")
        return v2_executor(call)
    return _execute


def test_no_tool_result_on_failed_effect_with_payload() -> None:
    m = _mon(executor=_faulting_with_payload(EffectOutcome.FAILED))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    _d, _r, tool_result = m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))
    assert m.state is PolicyState.EFFECT_FAILED
    assert tool_result is None


def test_no_tool_result_on_uncertain_effect_with_payload() -> None:
    m = _mon(executor=_faulting_with_payload(EffectOutcome.UNCERTAIN))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    _d, _r, tool_result = m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert tool_result is None


def test_binding_references_unproduced_fact_rejected() -> None:
    base = default_p2()
    try:
        Policy(policy_id="ref", task=base.task, allowed_flow=base.allowed_flow,
               max_executions=dict(base.max_executions), budget_minor=base.budget_minor, currency=base.currency,
               step_bindings={1: (BindingSpec("arg_equals_fact", {"arg": "flight", "fact": "never_produced"}),)})
        raise AssertionError("binding on an unproduced fact accepted")
    except PolicyInvalid:
        pass


def test_invalid_policy_rejected() -> None:
    base = default_p2()
    try:
        Policy(policy_id="bad", task=base.task, allowed_flow=base.allowed_flow,
               max_executions=dict(base.max_executions), budget_minor=base.budget_minor, currency=base.currency,
               step_bindings={9: (BindingSpec("arg_equals_fact", {"arg": "flight", "fact": "x"}),)})
    except PolicyInvalid:
        return
    raise AssertionError("invalid policy accepted")


# Inherited V1 guarantees and activation.

def test_off_policy_and_duplicate_still_blocked() -> None:
    m = _mon()
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("read_secret", {"key": "k"}))[0] is Decision.DENY

    m2 = _mon(run="run-dup")
    assert _search_select_book(m2) is Decision.ALLOW
    assert m2.submit(_pay(34900, "airline:LH"))[0] is Decision.ALLOW
    assert m2.submit(_pay(34900, "airline:LH", action_id="pay-2"))[0] is Decision.DENY  # completed


def test_tampered_and_rejected_approval_refused() -> None:
    policy = default_p2()
    try:
        PolicyMonitor(policy=policy, approval=_appr(policy, "r", grant=False), run_id="r", clock=FixedClock(NOW), ledger=RunLedger())
        raise AssertionError("rejected approval activated")
    except ApprovalError:
        pass
    appr = _appr(policy, "r2")
    tampered = replace(policy, task=policy.task + " (tampered after approval)")
    try:
        PolicyMonitor(policy=tampered, approval=appr, run_id="r2", clock=FixedClock(NOW), ledger=RunLedger())
        raise AssertionError("tampered policy activated")
    except ApprovalError:
        pass


def test_audit_chain_intact() -> None:
    m = _mon()
    assert _search_select_book(m) is Decision.ALLOW
    m.submit(_pay(34900, "airline:LH"))
    assert m.verify_chain() is True
    # Effect events name the facts they produced.
    book_effect = [e for e in m.effects if e.tool == "book"][-1]
    assert "booking_amount_minor" in book_effect.produced_facts


# Adversarial world: the counterparty, not the agent, lies.
#
# The V2 scenarios put the attacker in the agent's arguments. These cases put a plausible
# but wrong value into the tool reply and check where P2.1 closes the gap P2 left, and
# where neither does (V2b establishes consistency and provenance, not truth).


def test_world_booking_price_drift_from_offer_fails_closed() -> None:
    """A booking price that drifts from the offer is paid under P2 and parked under P2.1.

    The offer says 34900, the booking confirms 39999 (still under budget). Under P2
    the drifted amount becomes the fact and is paid. Under P2.1 the postcondition
    booking_amount_minor == offer_prices[selected_flight_id] fails the step.
    """
    leaky = _mon(executor=_payload_executor("book", _good_book_payload(price=39999)))
    assert _search_select_book(leaky) is Decision.ALLOW
    assert leaky.submit(_pay(39999))[0] is Decision.ALLOW      # P2: the drifted amount is paid
    m = _mon(policy=default_p2_1(), executor=_payload_executor("book", _good_book_payload(price=39999)))
    assert _search_select_book(m) is Decision.ALLOW
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert "booking_amount_minor" not in m.facts()
    assert m.submit(_pay(39999))[0] is Decision.DENY


def test_world_booking_currency_drift_from_offer_fails_closed() -> None:
    m = _mon(policy=default_p2_1(), executor=_payload_executor("book", _good_book_payload(currency="USD")))
    assert _search_select_book(m) is Decision.ALLOW
    assert m.state is PolicyState.EFFECT_UNCERTAIN
    assert "booking_currency" not in m.facts()


def test_world_select_reply_cannot_shift_the_selected_fact() -> None:
    """Under P2.1 a select reply naming another flight does not change the fact.

    The agent selects LH123 (bound to the offer set), the reply names LH250. The
    fact is the admitted argument (`arg_field`), so booking LH250 is denied.
    """
    leaky = _mon(executor=_payload_executor("select", {"selected_flight_id": "LH250"}))
    assert leaky.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert leaky.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    assert leaky.facts()["selected_flight_id"].value == "LH250"   # P2: the reply shifts the fact
    m = _mon(policy=default_p2_1(), executor=_payload_executor("select", {"selected_flight_id": "LH250"}))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    assert m.facts()["selected_flight_id"].value == "LH123"
    assert m.submit(ToolCall("book", {"flight": "LH250", "action_id": "b1"}))[0] is Decision.DENY


def test_world_negative_offer_price_is_not_affordable() -> None:
    """A negative observed price must not admit the irreversible booking."""
    offers = {"offers": [{"flight_id": "LH123", "price_minor": -5, "currency": "EUR"}]}
    m = _mon(policy=default_p2_1(), executor=_payload_executor("search", offers))
    assert m.submit(ToolCall("search", {"to": "FRA"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {"flight": "LH123"}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("book", {"flight": "LH123", "action_id": "b1"}))[0] is Decision.DENY


def test_world_pay_reply_not_paid_is_unreconciled() -> None:
    """A CONFIRMED transport whose reply says paid: false is not a completed payment."""
    m = _mon(policy=default_p2_1(), executor=_payload_executor("pay", {"paid": False, "error": "declined"}))
    assert _search_select_book(m) is Decision.ALLOW
    assert m.submit(_pay(34900))[0] is Decision.ALLOW
    assert m.state is PolicyState.EFFECT_UNCERTAIN


def test_world_plausible_attacker_recipient_is_the_documented_v2b_limit() -> None:
    """A plausible recipient chosen by the counterparty is paid under P2 and P2.1.

    A counterparty that confirms the booking with a plausible, well-typed recipient
    of its own choosing produces a fact, and the payment to that recipient is
    allowed. Nothing in V2 establishes who the counterparty is (source assurance).
    The test pins the limit, so a later version that closes it has to change this
    expectation explicitly.
    """
    for policy in (default_p2(), default_p2_1()):
        m = _mon(policy=policy, executor=_payload_executor("book", _good_book_payload(recipient="attacker:acct-666")))
        assert _search_select_book(m) is Decision.ALLOW
        assert m.state is PolicyState.ACTIVE
        assert m.facts()["booking_recipient"].value == "attacker:acct-666"
        assert m.submit(_pay(34900, recipient="attacker:acct-666"))[0] is Decision.ALLOW
        assert m.state is PolicyState.COMPLETED


def test_policy_rejects_map_lookup_postcondition_on_non_map_fact() -> None:
    p = default_p2_1()
    bad = dict(p.step_postconditions)
    bad[2] = bad[2] + (PostconditionSpec("produced_equals_map_lookup", {
        "produced": "booking_amount_minor", "map_fact": "selected_flight_id", "key_fact": "selected_flight_id"}),)
    try:
        replace(p, step_postconditions=bad)
    except PolicyInvalid:
        pass
    else:
        raise AssertionError("map-lookup postcondition on a scalar fact must be rejected")


def main():
    """Run all tests and report."""
    tests = [
        test_benign_consistent_flow_completes,
        test_book_must_match_select,
        test_select_must_be_offered,
        test_book_over_budget_denied_before_effect,
        test_pay_amount_must_match_booking,
        test_pay_recipient_must_match_booking,
        test_pay_currency_must_match_booking,
        test_facts_come_only_from_confirmed_effects,
        test_failed_booking_yields_no_facts_and_blocks_payment,
        test_uncertain_booking_yields_no_facts,
        test_book_result_flight_mismatch_fails_closed,
        test_book_result_wrong_typed_price_fails_closed,
        test_book_result_missing_recipient_fails_closed,
        test_malformed_offers_payload_fails_closed,
        test_agent_cannot_forge_a_missing_fact,
        test_replayed_fact_from_other_run_is_rejected,
        test_fact_store_rejects_duplicate_put,
        test_fact_value_is_typed_and_immutable,
        test_duplicate_producer_fact_name_rejected,
        test_affordable_ceiling_must_equal_budget,
        test_currency_binding_must_equal_policy_currency,
        test_book_currency_bound_before_effect,
        test_duplicate_map_key_rejected,
        test_no_tool_result_on_integrity_failure,
        test_no_tool_result_on_failed_effect_with_payload,
        test_no_tool_result_on_uncertain_effect_with_payload,
        test_binding_references_unproduced_fact_rejected,
        test_invalid_policy_rejected,
        test_off_policy_and_duplicate_still_blocked,
        test_tampered_and_rejected_approval_refused,
        test_audit_chain_intact,
        test_world_booking_price_drift_from_offer_fails_closed,
        test_world_booking_currency_drift_from_offer_fails_closed,
        test_world_select_reply_cannot_shift_the_selected_fact,
        test_world_negative_offer_price_is_not_affordable,
        test_world_pay_reply_not_paid_is_unreconciled,
        test_world_plausible_attacker_recipient_is_the_documented_v2b_limit,
        test_policy_rejects_map_lookup_postcondition_on_non_map_fact,
    ]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")


if __name__ == "__main__":
    main()
