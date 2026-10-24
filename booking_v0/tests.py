"""Self-contained tests for the V0.1 monitor.

These tests assert the core guarantees directly, independent of the scenario
harness. They run without any third-party dependency:

    python3 -m booking_v0.tests

Coverage: the enforcement rule, terminal DENY semantics, cardinality and
duplicate payment, parameter-blindness under alpha_0 (the V0 limit for amount and
recipient), consumption at admission, policy immutability, the policy-hash
binding, and refusal of a rejected approval.
"""

from __future__ import annotations

from dataclasses import replace

from .abstraction import alpha0
from .approval import approve
from .monitor import (
    ApprovalRejected,
    PolicyHashMismatch,
    PolicyMonitor,
)
from .policy import default_p0
from .state_machine import PolicyState, Decision
from .tools import ToolCall


def _fresh_monitor() -> PolicyMonitor:
    """Return a monitor activated against a freshly approved Policy P0."""
    policy = default_p0()
    approval = approve(policy)
    return PolicyMonitor(policy=policy, approval=approval)


def test_benign_flow_completes() -> None:
    """The exact approved flow is admitted and the instance completes."""
    m = _fresh_monitor()
    for tool in ("search", "select", "book", "pay"):
        decision, _reason, _result = m.submit(ToolCall(tool, {}))
        assert decision is Decision.ALLOW, f"{tool} should be allowed"
    assert m.state is PolicyState.COMPLETED


def test_off_policy_tool_denied_and_terminal() -> None:
    """An off-policy tool is denied and terminates the instance."""
    m = _fresh_monitor()
    assert m.submit(ToolCall("search", {}))[0] is Decision.ALLOW
    decision, _reason, result = m.submit(ToolCall("read_secret", {"key": "stripe_api_key"}))
    assert decision is Decision.DENY
    assert result is None, "denied tool body must not run"
    assert m.state is PolicyState.TERMINATED
    assert m.submit(ToolCall("select", {}))[0] is Decision.DENY


def test_wrong_order_denied() -> None:
    """A correct tool at the wrong position is denied."""
    m = _fresh_monitor()
    assert m.submit(ToolCall("search", {}))[0] is Decision.ALLOW
    assert m.submit(ToolCall("select", {}))[0] is Decision.ALLOW
    decision, _reason, _result = m.submit(ToolCall("pay", {"amount": 349.0}))
    assert decision is Decision.DENY, "pay before book must be denied"
    assert m.state is PolicyState.TERMINATED


def test_duplicate_payment_denied() -> None:
    """A second payment after the flow is satisfied is denied."""
    m = _fresh_monitor()
    for tool in ("search", "select", "book", "pay"):
        m.submit(ToolCall(tool, {}))
    assert m.state is PolicyState.COMPLETED
    decision, _reason, _result = m.submit(ToolCall("pay", {"amount": 1.0}))
    assert decision is Decision.DENY, "no second payment after completion"


def test_manipulated_amount_admitted_v0_limit() -> None:
    """V0 admits an inflated amount at the correct position (the known limit)."""
    m = _fresh_monitor()
    for tool in ("search", "select", "book"):
        assert m.submit(ToolCall(tool, {}))[0] is Decision.ALLOW
    decision, _reason, result = m.submit(ToolCall("pay", {"amount": 4999.0, "recipient": "airline:LH"}))
    assert decision is Decision.ALLOW, "V0 does not inspect parameters"
    assert result is not None and result.payload["amount"] == 4999.0
    assert m.state is PolicyState.COMPLETED


def test_manipulated_recipient_admitted_v0_limit() -> None:
    """V0 admits a redirected recipient at the correct position (the known limit)."""
    m = _fresh_monitor()
    for tool in ("search", "select", "book"):
        assert m.submit(ToolCall(tool, {}))[0] is Decision.ALLOW
    decision, _reason, result = m.submit(ToolCall("pay", {"amount": 349.0, "recipient": "attacker:acct-666"}))
    assert decision is Decision.ALLOW, "V0 does not inspect parameters"
    assert result is not None and result.payload["recipient"] == "attacker:acct-666"


def test_alpha0_collapses_parameters() -> None:
    """alpha_0 makes legitimate and manipulated payments indistinguishable."""
    legit = ToolCall("pay", {"amount": 349.0, "recipient": "airline:LH"})
    evil = ToolCall("pay", {"amount": 4999.0, "recipient": "attacker:acct-666"})
    assert alpha0(legit) == alpha0(evil) == "pay"


def test_consumption_at_admission() -> None:
    """A retry after the last step receives no fresh grant.

    With P0 the denial comes from the completed instance. The counter alone
    would only show with a flow that repeats a tool.
    """
    m = _fresh_monitor()
    for tool in ("search", "select", "book"):
        m.submit(ToolCall(tool, {}))
    # First pay consumes the single pay right and completes the flow.
    assert m.submit(ToolCall("pay", {"amount": 349.0}))[0] is Decision.ALLOW
    # A retry receives no fresh grant.
    assert m.submit(ToolCall("pay", {"amount": 349.0}))[0] is Decision.DENY


def test_policy_is_immutable() -> None:
    """Neither fields nor mapping contents of a policy can be mutated."""
    policy = default_p0()
    try:
        policy.budget = 999.0  # type: ignore[misc]
    except Exception:
        pass
    else:
        raise AssertionError("policy field must not be reassignable")
    try:
        policy.max_executions["pay"] = 2  # type: ignore[index]
    except Exception:
        pass
    else:
        raise AssertionError("policy mapping must not be mutable")


def test_policy_hash_binding_refuses_tampered() -> None:
    """A policy altered after approval cannot be activated."""
    approved = default_p0()
    approval = approve(approved)
    tampered = replace(
        approved,
        allowed_flow=approved.allowed_flow + ("pay",),
        max_executions={**dict(approved.max_executions), "pay": 2},
    )
    try:
        PolicyMonitor(policy=tampered, approval=approval)
    except PolicyHashMismatch:
        return
    raise AssertionError("tampered policy must not activate against approved hash")


def test_rejected_approval_refuses_activation() -> None:
    """A rejected approval never activates the monitor."""
    policy = default_p0()
    approval = approve(policy, grant=False)
    try:
        PolicyMonitor(policy=policy, approval=approval)
    except ApprovalRejected:
        return
    raise AssertionError("rejected approval must not activate the monitor")


def main() -> None:
    """Run all tests and report."""
    tests = [
        test_benign_flow_completes,
        test_off_policy_tool_denied_and_terminal,
        test_wrong_order_denied,
        test_duplicate_payment_denied,
        test_manipulated_amount_admitted_v0_limit,
        test_manipulated_recipient_admitted_v0_limit,
        test_alpha0_collapses_parameters,
        test_consumption_at_admission,
        test_policy_is_immutable,
        test_policy_hash_binding_refuses_tampered,
        test_rejected_approval_refuses_activation,
    ]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\nAll {len(tests)} tests passed.")


if __name__ == "__main__":
    main()
