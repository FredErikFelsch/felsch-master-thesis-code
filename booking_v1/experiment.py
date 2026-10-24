"""The experiment harness for System Model V1.2.

What this measures: whether the deterministic monitor makes the specified decision
on each fixed scenario, under the stated trusted-computing-base and single-instance
assumptions. This is model conformance, not a security evaluation against a live
adversary. The adversarial scenarios are fixed call traces, not real indirect
prompt injection. A real IPI evaluation is a separate suite (booking_demo).

Outputs:
    A console table.
    results_v1_2/results.json
    results_v1_2/results.md
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field, replace

from .approval import ApprovalError, approve
from .clock import FixedClock
from .constraints import CONSTRAINT_REGISTRY_VERSION, budget_ceiling
from .effects import faulting_executor, default_executor
from .freeze import canonical_bytes, thaw
from .ledger import RunAlreadyActivated, RunLedger
from .lifecycle import PolicyState, Decision
from .monitor import PolicyMonitor
from .policy import POLICY_SCHEMA_VERSION, Policy, default_p1
from .schema import tool_manifest_hash
from .scenarios import (
    EXPECTED_BENIGN,
    EXPECTED_BLOCK,
    EXPECTED_LEAK,
    EXPECTED_EFFECT_FAILED,
    EXPECTED_EFFECT_UNCERTAIN,
    EXPECTED_REFUSED,
    ActivationScenario,
    ExecutionScenario,
    activation_scenarios,
    execution_scenarios,
)

APPROVER_ID = "approver:alice"
ISSUED_AT = 1_700_000_000
EXPIRES_AT = ISSUED_AT + 3600
NOW = ISSUED_AT + 10


@dataclass
class ScenarioResult:
    """The outcome of one scenario, as written to results.json."""

    name: str
    kind: str
    description: str
    expected: str
    final_state: str
    verdict: str
    matches_prediction: bool
    audit_ok: bool | None = None  # None for activation scenarios (no monitor)
    steps: list[dict] = field(default_factory=list)
    effects: list[dict] = field(default_factory=list)
    run_id: str = ""
    approval_id: str = ""
    genesis: str = ""
    chain_head: str = ""
    approval_binding: dict = field(default_factory=dict)
    approval_binding_digest: str = ""
    approval_signature: str = ""
    note: str = ""


def _approval(policy: Policy, run_id: str, *, grant: bool = True, expires_at: int = EXPIRES_AT):
    """Build the harness's signed approval for a run, with the fixed window."""
    return approve(
        policy,
        approver_id=APPROVER_ID,
        approval_id=f"appr-{run_id}",
        run_id=run_id,
        issued_at=ISSUED_AT,
        expires_at=expires_at,
        grant=grant,
    )


def _execution_verdict(expected: str, state: PolicyState, admissions, effects) -> tuple[str, bool]:
    """Derive a verdict for an execution scenario and whether it was predicted.

    Args:
        expected: The predicted outcome class.
        state: The final lifecycle state.
        admissions: The monitor's admission events.
        effects: The monitor's effect events.

    Returns:
        The verdict string and whether it matches the prediction.
    """
    any_deny = any(a.decision is Decision.DENY for a in admissions)
    last_denied = bool(admissions) and admissions[-1].decision is Decision.DENY
    all_confirmed = all(e.outcome.value == "CONFIRMED" for e in effects)

    if expected == EXPECTED_BENIGN:
        ok = state is PolicyState.COMPLETED and not any_deny and all_confirmed
        return ("BENIGN_COMPLETED" if ok else "BENIGN_FAILED"), ok
    if expected == EXPECTED_BLOCK:
        ok = last_denied and state not in (PolicyState.ACTIVE, PolicyState.EFFECT_PENDING)
        return ("CALL_BLOCKED" if ok else "CALL_LEAKED"), ok
    if expected == EXPECTED_LEAK:
        ok = state is PolicyState.COMPLETED and not any_deny
        return ("CALL_ADMITTED_V1_LIMIT" if ok else "UNEXPECTED_BLOCK"), ok
    if expected == EXPECTED_EFFECT_FAILED:
        ok = state is PolicyState.EFFECT_FAILED
        return ("EFFECT_FAILED" if ok else "WRONG_STATE"), ok
    if expected == EXPECTED_EFFECT_UNCERTAIN:
        ok = state is PolicyState.EFFECT_UNCERTAIN
        return ("EFFECT_UNCERTAIN" if ok else "WRONG_STATE"), ok
    return "UNKNOWN", False


def run_execution(policy: Policy, scenario: ExecutionScenario) -> ScenarioResult:
    """Run one execution scenario end to end through the policy lifecycle.

    Args:
        policy: The policy to approve and enforce.
        scenario: The scripted scenario, with optional effect faults.

    Returns:
        The scenario result with steps, effects and the approval binding.
    """
    agent = scenario.agent
    run_id = f"run-{scenario.name}"
    clock = FixedClock(NOW)
    ledger = RunLedger()
    approval = _approval(policy, run_id, grant=True)
    executor = faulting_executor(scenario.effect_faults) if scenario.effect_faults else default_executor
    monitor = PolicyMonitor(policy=policy, approval=approval, run_id=run_id, clock=clock, ledger=ledger, executor=executor)

    while True:
        call = agent.next_call()
        if call is None:
            break
        decision, _reason, result = monitor.submit(call)
        if decision is Decision.ALLOW and result is not None:
            agent.observe(result)

    verdict, matches = _execution_verdict(scenario.expected, monitor.state, monitor.admissions, monitor.effects)
    steps = [
        {
            "seq": a.seq, "tool": a.tool, "args": thaw(a.args), "expected": a.expected,
            "decision": a.decision.value, "reason": a.reason, "state_after": a.state_after.value,
        }
        for a in monitor.admissions
    ]
    effects = [
        {
            "seq": e.seq, "tool": e.tool, "outcome": e.outcome.value,
            "payload": thaw(e.payload) if e.payload is not None else None,
            "error": e.error, "state_after": e.state_after.value,
            "admission_seq": e.admission_seq, "action_id": e.action_id,
        }
        for e in monitor.effects
    ]
    binding = approval.binding()
    binding_digest = hashlib.sha256(canonical_bytes(binding)).hexdigest()
    return ScenarioResult(
        name=scenario.name, kind="execution", description=scenario.description,
        expected=scenario.expected, final_state=monitor.state.value, verdict=verdict,
        matches_prediction=matches, audit_ok=monitor.verify_chain(), steps=steps,
        effects=effects, run_id=monitor.run_id, approval_id=monitor.approval_id,
        genesis=monitor.genesis, chain_head=monitor.chain_head,
        approval_binding=binding, approval_binding_digest=binding_digest,
        approval_signature=approval.signature,
    )


def run_activation(policy: Policy, scenario: ActivationScenario) -> ScenarioResult:
    """Run one activation scenario and check that activation is refused.

    Args:
        policy: The approved policy.
        scenario: The activation scenario. Its mode selects the attack.

    Returns:
        The scenario result. Its note names the refusal exception.
    """
    refused = False
    note = ""
    run_id = f"run-{scenario.name}"
    clock = FixedClock(NOW)
    ledger = RunLedger()

    try:
        if scenario.mode == "reject":
            PolicyMonitor(policy=policy, approval=_approval(policy, run_id, grant=False), run_id=run_id, clock=clock, ledger=ledger)
        elif scenario.mode == "tamper":
            appr = _approval(policy, run_id, grant=True)
            tampered = replace(policy, budget_minor=999900, step_constraints={3: budget_ceiling()})
            PolicyMonitor(policy=tampered, approval=appr, run_id=run_id, clock=clock, ledger=ledger)
        elif scenario.mode == "expired":
            PolicyMonitor(policy=policy, approval=_approval(policy, run_id, expires_at=NOW - 1), run_id=run_id, clock=clock, ledger=ledger)
        elif scenario.mode == "wrong_run":
            appr = _approval(policy, "run-OTHER", grant=True)
            PolicyMonitor(policy=policy, approval=appr, run_id=run_id, clock=clock, ledger=ledger)
        elif scenario.mode == "replay":
            appr = _approval(policy, run_id, grant=True)
            PolicyMonitor(policy=policy, approval=appr, run_id=run_id, clock=clock, ledger=ledger)  # first ok
            PolicyMonitor(policy=policy, approval=appr, run_id=run_id, clock=clock, ledger=ledger)  # replay
    except (ApprovalError, RunAlreadyActivated) as exc:
        refused = True
        note = type(exc).__name__

    verdict = "ACTIVATION_REFUSED" if refused else "ACTIVATION_ALLOWED_UNEXPECTED"
    matches = refused and scenario.expected == EXPECTED_REFUSED
    return ScenarioResult(
        name=scenario.name, kind="activation", description=scenario.description,
        expected=scenario.expected, final_state="NOT_ACTIVATED" if refused else "ACTIVE",
        verdict=verdict, matches_prediction=matches, note=note,
    )


def run_all() -> list[ScenarioResult]:
    """Run every scenario against Policy P1 and return the results."""
    policy = default_p1()
    results = [run_execution(policy, s) for s in execution_scenarios()]
    results += [run_activation(policy, s) for s in activation_scenarios()]
    return results


def _fmt_pay(args: dict) -> str:
    """Format the payment fields of a step for the console."""
    return f"  amount_minor={args.get('amount_minor')} {args.get('currency')} recipient={args.get('recipient')}"


def _print_console(policy: Policy, results: list[ScenarioResult]) -> None:
    """Print a compact console report."""
    print("=" * 84)
    print("System Model V1.2, Tool Identity plus Local Parameter Constraints (hardened)")
    print("=" * 84)
    print(f"Policy {policy.policy_id}: flow = {' -> '.join(policy.allowed_flow)}")
    print(f"Policy SHA-256: {policy.digest()[:16]}...")
    print("Model conformance of the deterministic monitor, under the stated TCB and")
    print("single-instance assumptions. Attack traces are fixed call sequences, not IPI.")
    print("-" * 84)

    for r in results:
        print(f"\n[{r.name}]  ({r.expected})  {r.description}")
        for s in r.steps:
            mark = "ALLOW" if s["decision"] == "ALLOW" else "DENY "
            arg = _fmt_pay(s["args"]) if s["tool"] == "pay" else ""
            print(f"    seq {s['seq']}: {mark} {s['tool']:<12} (exp {str(s['expected']):<8}){arg}")
        if r.kind == "activation":
            print(f"    activation refused via {r.note}")
        flag = "OK" if r.matches_prediction else "MISMATCH"
        chain = "n/a" if r.audit_ok is None else ("ok" if r.audit_ok else "BROKEN")
        print(f"    => final={r.final_state}  verdict={r.verdict}  [{flag}] (chain {chain})")

    total = len(results)
    conforms = sum(1 for r in results if r.matches_prediction)
    chains_ok = all(r.audit_ok for r in results if r.audit_ok is not None)
    print("\n" + "-" * 84)
    print(f"Monitor conforms to spec on {conforms}/{total} scenarios (conformance, not a security proof).")
    print(f"Audit event-chains intact on all scenarios: {chains_ok}")
    print("\nV1.2 enforces tool-sequence conformance and the configured local constraint")
    print("for the evaluated traces, under the stated TCB and single-instance assumptions.")
    print("It does not validate values against dynamically selected prices, flights or")
    print("recipients; static local rules could restrict individual cases, but general")
    print("validation needs trusted cross-step bindings -> V2.")
    print("=" * 84)


def _write_outputs(policy: Policy, results: list[ScenarioResult], out_dir: str) -> None:
    """Write results.json and results.md into ``out_dir``."""
    os.makedirs(out_dir, exist_ok=True)
    record = {
        "system_model": "V1.2",
        "policy": json.loads(policy.to_json()),
        "policy_digest": policy.digest(),
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "constraint_registry_version": CONSTRAINT_REGISTRY_VERSION,
        "tool_manifest_hash": tool_manifest_hash(),
        "measures": "model conformance of the deterministic monitor under stated TCB and single-instance assumptions",
        "results": [asdict(r) for r in results],
    }
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, default=str)

    lines = ["# V1.2 Experiment Results (hardened)\n\n"]
    lines.append(
        "Measures model conformance of the deterministic monitor under the stated "
        "trusted-computing-base and single-instance assumptions. Attack traces are "
        "fixed call sequences, not real indirect prompt injection.\n\n"
    )
    lines.append(f"Policy **{policy.policy_id}**, digest `{policy.digest()}`\n\n")
    lines.append("| Scenario | Kind | Expected | Final state | Verdict | Conforms | Chain |\n")
    lines.append("|---|---|---|---|---|---|---|\n")
    for r in results:
        chain = "n/a" if r.audit_ok is None else ("ok" if r.audit_ok else "BROKEN")
        lines.append(
            f"| {r.name} | {r.kind} | {r.expected} | {r.final_state} | {r.verdict} | "
            f"{'yes' if r.matches_prediction else 'NO'} | {chain} |\n"
        )
    lines.append("\n## Conclusion\n\n")
    lines.append(
        "The over-budget payment and the unknown parameter are denied. The recipient "
        "redirect, the underpayment and the select/book mismatch are admitted: these "
        "cases are not prevented by the current V1.2 constraint. Static local rules "
        "could restrict individual cases, whereas general validation against "
        "dynamically selected prices, flights and recipients requires trusted "
        "cross-step bindings (V2). Failed and uncertain effects reach EFFECT_FAILED "
        "and EFFECT_UNCERTAIN, never COMPLETED. Activation is refused for a tampered "
        "policy and for a rejected, expired, wrong-run or replayed approval.\n"
    )
    with open(os.path.join(out_dir, "results.md"), "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def main() -> None:
    """Run the experiment and write all outputs."""
    policy = default_p1()
    results = run_all()
    _print_console(policy, results)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v1_2")
    _write_outputs(policy, results, out_dir)
    print(f"\nWrote results to {out_dir}/results.json and results.md")


if __name__ == "__main__":
    main()
