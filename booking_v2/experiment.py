"""Harness for System Model V2 and V2.1.

It measures model conformance of the deterministic monitor on the frozen scenarios.
V2 runs them under P2 (``main``). V2.1 runs them under P2.1 and adds the
lying-world scenarios under P2.1 and P2 side by side (``main_v2_1``).

Outputs:
    results_v2/results.json and results.md (V2)
    results_v2_1/results.json and results.md (V2.1)
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, replace

from booking_v0.agent import ScriptedAgent
from booking_v1.approval import ApprovalError, approve
from booking_v1.clock import FixedClock
from booking_v1.effects import EffectOutcome
from booking_v1.freeze import thaw
from booking_v1.ledger import RunAlreadyActivated, RunLedger
from booking_v1.lifecycle import PolicyState, Decision

from .monitor import PolicyMonitor
from .policy import default_p2, default_p2_1
from .world import v2_executor, faulting_executor, lying_executor
from .scenarios import (
    EXPECTED_BENIGN, EXPECTED_BLOCK, EXPECTED_EFFECT_FAILED, EXPECTED_LEAK, EXPECTED_REFUSED,
    EXPECTED_UNRECONCILED,
    ActivationScenario, ExecutionScenario, activation_scenarios, execution_scenarios, world_scenarios,
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
    audit_ok: bool | None = None
    steps: list[dict] = field(default_factory=list)
    facts: dict = field(default_factory=dict)
    note: str = ""


def _approval(policy, run_id, *, grant=True):
    """Build the harness's signed approval for a run, with the fixed window."""
    return approve(policy, approver_id=APPROVER_ID, approval_id=f"appr-{run_id}", run_id=run_id, issued_at=ISSUED_AT, expires_at=EXPIRES_AT, grant=grant)


def _verdict(expected, state, admissions, effects=(), leak_effect=None):
    """Return the verdict of one run against its expectation and whether it matches.

    `effects` and `leak_effect` make the verdict effect-aware. A block counts only
    if the named irreversible effect did not run CONFIRMED, and a predicted leak
    counts only if it did (or, without a named effect, if the flow completed). A
    denied last call alone is not a block.

    Args:
        expected: The predicted outcome class.
        state: The final lifecycle state.
        admissions: The monitor's admission events.
        effects: The monitor's effect events.
        leak_effect: The tool whose confirmed execution is the leak, or None.

    Returns:
        The verdict string and whether it matches the prediction.
    """
    any_deny = any(a.decision is Decision.DENY for a in admissions)
    last_denied = bool(admissions) and admissions[-1].decision is Decision.DENY
    leaked = (any(e.tool == leak_effect and e.outcome is EffectOutcome.CONFIRMED for e in effects)
              if leak_effect else state is PolicyState.COMPLETED)
    if expected == EXPECTED_BENIGN:
        ok = state is PolicyState.COMPLETED and not any_deny
        return ("BENIGN_COMPLETED" if ok else "BENIGN_FAILED"), ok
    if expected == EXPECTED_BLOCK:
        # An attack must end in a denied admission and a terminated instance, and the
        # irreversible effect must not have run. A different end state is not accepted
        # as a correct block.
        ok = last_denied and state is PolicyState.TERMINATED and not leaked
        return ("CALL_BLOCKED" if ok else "CALL_LEAKED"), ok
    if expected == EXPECTED_EFFECT_FAILED:
        ok = state is PolicyState.EFFECT_FAILED
        return ("EFFECT_FAILED" if ok else "WRONG_STATE"), ok
    if expected == EXPECTED_UNRECONCILED:
        ok = state is PolicyState.EFFECT_UNCERTAIN and not leaked
        return ("EFFECT_UNRECONCILED" if ok else ("CALL_LEAKED" if leaked else "WRONG_STATE")), ok
    if expected == EXPECTED_LEAK:
        return ("LEAK_AS_PREDICTED" if leaked else "UNEXPECTEDLY_BLOCKED"), leaked
    return "UNKNOWN", False


def _facts_view(monitor) -> dict:
    """Return the monitor's facts as plain JSON values with their provenance."""
    out = {}
    for name, fact in monitor.facts().items():
        value = sorted(fact.value) if isinstance(fact.value, frozenset) else thaw(fact.value)
        out[name] = {"value": value, "type": fact.ftype, "source": fact.source_tool, "producing_seq": fact.producing_seq,
                     "fragment_id": fact.fragment_id, "run_id": fact.run_id, "integrity": fact.integrity}
    return out


def run_execution(policy, scenario: ExecutionScenario, *, baseline: bool = False) -> ScenarioResult:
    """Run one execution scenario under ``policy``.

    Args:
        policy: The policy to approve and enforce.
        scenario: The scenario. World scenarios use the lying executor.
        baseline: Evaluate a world scenario against its `expected_baseline`
            (the frozen P2 column of the V2.1 table).

    Returns:
        The scenario result with steps and facts.
    """
    agent = _fresh_agent(scenario.agent)
    run_id = f"run-{scenario.name}"
    expected = scenario.expected_baseline if baseline and scenario.expected_baseline else scenario.expected
    executor = faulting_executor(scenario.effect_faults) if scenario.effect_faults else v2_executor
    if scenario.world_overrides:
        executor = lying_executor(scenario.world_overrides)
    monitor = PolicyMonitor(policy=policy, approval=_approval(policy, run_id), run_id=run_id, clock=FixedClock(NOW), ledger=RunLedger(), executor=executor)
    while True:
        call = agent.next_call()
        if call is None:
            break
        decision, _r, result = monitor.submit(call)
        if decision is Decision.ALLOW and result is not None:
            agent.observe(result)
    verdict, matches = _verdict(expected, monitor.state, monitor.admissions, monitor.effects, scenario.leak_effect)
    steps = [{"seq": a.seq, "tool": a.tool, "args": thaw(a.args), "expected": a.expected,
              "decision": a.decision.value, "reason": a.reason, "state_after": a.state_after.value} for a in monitor.admissions]
    effects = [{"tool": e.tool, "outcome": e.outcome.value} for e in monitor.effects]
    name = f"{scenario.name} [{policy.policy_id}]" if scenario.world_overrides else scenario.name
    return ScenarioResult(name, "execution" if not scenario.world_overrides else "world", scenario.description, expected,
                          monitor.state.value, verdict, matches, monitor.verify_chain(), steps, _facts_view(monitor),
                          note=f"effects: {effects}" if scenario.world_overrides else "")


def _fresh_agent(agent):
    """Return a fresh copy of a scripted agent, so one scenario can run under two policies.

    The script is fixed, but the cursor advances, so each run needs its own copy.
    """
    return ScriptedAgent(name=agent.name, description=agent.description, script=list(agent._script))


def run_activation(policy, scenario: ActivationScenario) -> ScenarioResult:
    """Run one activation scenario and check that activation is refused.

    Args:
        policy: The approved policy.
        scenario: The activation scenario (reject or tamper).

    Returns:
        The scenario result. Its note names the refusal exception.
    """
    refused, note = False, ""
    run_id = f"run-{scenario.name}"
    try:
        if scenario.mode == "reject":
            PolicyMonitor(policy=policy, approval=_approval(policy, run_id, grant=False), run_id=run_id, clock=FixedClock(NOW), ledger=RunLedger())
        elif scenario.mode == "tamper":
            appr = _approval(policy, run_id)
            tampered = replace(policy, task=policy.task + " (tampered after approval)")
            PolicyMonitor(policy=tampered, approval=appr, run_id=run_id, clock=FixedClock(NOW), ledger=RunLedger())
    except (ApprovalError, RunAlreadyActivated) as exc:
        refused, note = True, type(exc).__name__
    verdict = "ACTIVATION_REFUSED" if refused else "ACTIVATION_ALLOWED_UNEXPECTED"
    return ScenarioResult(scenario.name, "activation", scenario.description, scenario.expected,
                          "NOT_ACTIVATED" if refused else "ACTIVE", verdict,
                          refused and scenario.expected == EXPECTED_REFUSED, None, [], {}, note)


def run_all(policy=None):
    """Run the frozen scenarios against ``policy`` (default P2) and return the results."""
    policy = policy or default_p2()
    return [run_execution(policy, s) for s in execution_scenarios()] + [run_activation(policy, s) for s in activation_scenarios()]


def run_all_v2_1():
    """Run the V2.1 set and return the results.

    The twelve frozen scenarios run under P2.1, then each world scenario runs under
    P2.1 and, as the baseline column, under the frozen P2.
    """
    p21, p2 = default_p2_1(), default_p2()
    results = run_all(p21)
    for s in world_scenarios():
        results.append(run_execution(p21, s))
        results.append(run_execution(p2, s, baseline=True))
    return results


def _print(policy, results):
    """Print a compact console report."""
    print("=" * 84)
    print("System Model V2, Cross-Step Bindings (V2a) and Provenanced Facts (V2b)")
    print("=" * 84)
    print(f"Policy {policy.policy_id}: flow = {' -> '.join(policy.allowed_flow)}")
    print(f"Policy SHA-256: {policy.digest()[:16]}...")
    print("Model conformance of the deterministic monitor, under the stated TCB assumptions.")
    print("-" * 84)
    for r in results:
        print(f"\n[{r.name}]  ({r.expected})  {r.description}")
        for s in r.steps:
            mark = "ALLOW" if s["decision"] == "ALLOW" else "DENY "
            extra = ""
            if s["tool"] == "pay":
                extra = f"  amount={s['args'].get('amount_minor')} {s['args'].get('currency')} recipient={s['args'].get('recipient')}"
            elif s["tool"] in ("select", "book"):
                extra = f"  flight={s['args'].get('flight')}"
            print(f"    seq {s['seq']}: {mark} {s['tool']:<12}{extra}")
        if r.kind == "activation":
            print(f"    activation refused via {r.note}")
        if r.facts:
            print(f"    facts: {', '.join(sorted(r.facts))}")
        flag = "OK" if r.matches_prediction else "MISMATCH"
        chain = "n/a" if r.audit_ok is None else ("ok" if r.audit_ok else "BROKEN")
        print(f"    => final={r.final_state}  verdict={r.verdict}  [{flag}] (chain {chain})")
    total = len(results)
    ok = sum(1 for r in results if r.matches_prediction)
    chains = all(r.audit_ok for r in results if r.audit_ok is not None)
    print("\n" + "-" * 84)
    print(f"Monitor conforms to spec on {ok}/{total} scenarios (conformance, not a security proof).")
    print(f"Audit event-chains intact on all execution scenarios: {chains}")
    print("\nV2a: a compromised agent cannot swap security-relevant values between steps.")
    print("V2b: authorization-relevant values come only from confirmed, recorded facts.")
    print("=" * 84)


def _write(policy, results, out_dir, system_model="V2"):
    """Write results.json (with the run manifest) and results.md into ``out_dir``."""
    os.makedirs(out_dir, exist_ok=True)
    # Every version's record carries the same run manifest, which lives in booking_v4.
    # It reads booking_v3 constants, so it is imported only when results are written.
    from booking_v4.manifest import run_manifest
    record = {"system_model": system_model, "policy": json.loads(policy.to_json()), "policy_digest": policy.digest(),
              "manifest": run_manifest(clock_mode=f"fixed:{NOW}"),
              "results": [asdict(r) for r in results]}
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, default=str)
    lines = [f"# {system_model} Experiment Results\n\n",
             "Cross-step bindings (V2a) and provenanced facts (V2b). Model conformance of the deterministic monitor.\n\n",
             f"Policy **{policy.policy_id}**, digest `{policy.digest()}`\n\n",
             "| Scenario | Kind | Expected | Final state | Verdict | Conforms |\n|---|---|---|---|---|---|\n"]
    for r in results:
        lines.append(f"| {r.name} | {r.kind} | {r.expected} | {r.final_state} | {r.verdict} | {'yes' if r.matches_prediction else 'NO'} |\n")
    with open(os.path.join(out_dir, "results.md"), "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def main():
    """Run the V2 experiment and write all outputs."""
    policy = default_p2()
    results = run_all()
    _print(policy, results)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v2")
    _write(policy, results, out_dir)
    print(f"\nWrote results to {out_dir}/results.json and results.md")


def main_v2_1():
    """Run the V2.1 experiment (`run_v2_1.py`) and write all outputs.

    P2.1 runs on the frozen twelve, then the lying-world scenarios run under P2.1 and
    P2 side by side. The last world scenario is a predicted leak under both policies.
    It pins the limit of V2b.
    """
    policy = default_p2_1()
    results = run_all_v2_1()
    _print(policy, results)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v2_1")
    _write(policy, results, out_dir, system_model="V2.1")
    print(f"\nWrote results to {out_dir}/results.json and results.md")


if __name__ == "__main__":
    main()
