"""The lying world on the fragmented plane.

Run from the repository root:  python3 -m booking_v3.experiment_world

Six scenarios with an honest agent and a lying counterparty (the replies of
`booking_v2.scenarios.world_scenarios`), driven through the orchestrator under two
policies:

    P2.1   what P3 wraps (`default_p3()`)
    P2     the frozen booking_v2 baseline policy lifted onto the fragmented plane
           (`Policy3(base=default_p2())`)

and on two backends: the in-process deployment and the durable process backend (the
booking_v4 services on a durable store). The table therefore separates three factors: the
plane (booking_v2 monitor or fragments, compare `results_v2_1`), the policy (P2 or P2.1)
and the backend (in-process or durable). The frozen scenarios, their digests and their
records are untouched. This is a separate record, `results_v3/world/`.

Verdicts are effect-aware, as in booking_v2: a block counts only if the named irreversible
effect did not run, a predicted leak only if it did. On the fragmented plane a failed
post-effect check does not terminate the run: the effect ran, no successor state is
signed, the run parks in EFFECT_UNCERTAIN and no later step has an input state
(`EFFECT_UNRECONCILED`).
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

from booking_v2.policy import default_p2
from booking_v3 import scenarios as v3s
from booking_v3.policy import Policy3, default_p3
from booking_v3.scenarios import (EXPECTED_DENIED, EXPECTED_LEAK, EXPECTED_UNRECONCILED, NOW,
                                  run_world_scenario, world_scenarios)


@dataclass
class WorldResult:
    """The outcome of one world scenario under one policy on one backend."""

    name: str
    policy: str                 # "P2.1" | "P2"
    backend: str                # "in-process" | "durable"
    expected: str
    verdict: str
    matches_prediction: bool
    statuses: list
    final_status: str
    executed_ops: list
    leak_effect: str | None
    last_reason: str


def _verdict(expected: str, final_status: str, statuses: list, executed_ops: list,
             leak_effect: str | None) -> tuple[str, bool]:
    """Return the effect-aware verdict and whether it matches the prediction.

    Mirrors `booking_v2.experiment._verdict` on the fragmented-plane vocabulary.

    Args:
        expected: The predicted outcome class.
        final_status: The run's final state.
        statuses: The runner statuses in order.
        executed_ops: The operations the gateway dispatched.
        leak_effect: The operation whose dispatch is the leak, or None.

    Returns:
        The verdict string and whether it matches.
    """
    leaked = (leak_effect in executed_ops) if leak_effect else final_status == "COMPLETED"
    last = statuses[-1] if statuses else ""
    if expected == EXPECTED_DENIED:
        ok = last == "DENIED" and final_status == "TERMINATED" and not leaked
        return ("CALL_BLOCKED" if ok else "CALL_LEAKED"), ok
    if expected == EXPECTED_UNRECONCILED:
        ok = last == "EFFECT_UNCERTAIN" and final_status == "EFFECT_UNCERTAIN" and not leaked
        return ("EFFECT_UNRECONCILED" if ok else ("CALL_LEAKED" if leaked else "WRONG_STATE")), ok
    if expected == EXPECTED_LEAK:
        return ("LEAK_AS_PREDICTED" if leaked else "UNEXPECTEDLY_BLOCKED"), leaked
    return "UNKNOWN", False


def _policies() -> list[tuple[str, Policy3]]:
    """Return the two policies, labelled P2.1 and P2."""
    return [("P2.1", default_p3()), ("P2", Policy3(base=default_p2()))]


def run_backend(backend: str, factory=None) -> list[WorldResult]:
    """Run all six scenarios under both policies on one backend.

    Args:
        backend: The backend label written into each result.
        factory: The deployment factory, or None for the in-process deployment.

    Returns:
        One WorldResult per scenario and policy.
    """
    v3s.set_deployment_factory(factory)
    try:
        out = []
        for ws in world_scenarios():
            for label, policy in _policies():
                expected = ws.expected if label == "P2.1" else ws.expected_baseline
                o = run_world_scenario(ws, policy)
                verdict, ok = _verdict(expected, o.final_status, o.statuses, o.executed_ops, ws.leak_effect)
                out.append(WorldResult(ws.name, label, backend, expected, verdict, ok, list(o.statuses),
                                       o.final_status, list(o.executed_ops), ws.leak_effect,
                                       o.reasons[-1] if o.reasons else ""))
        return out
    finally:
        v3s.set_deployment_factory(None)


def run_all(durable: bool = True) -> list[WorldResult]:
    """Run every scenario on the in-process backend and, if requested, on the durable one."""
    results = run_backend("in-process")
    if durable:
        # booking_v4 imports booking_v3, so its durable backend is loaded only here.
        from booking_v4.durable import create_durable_process_deployment
        results += run_backend("durable", create_durable_process_deployment)
    return results


def backends_agree(results: list[WorldResult]) -> bool:
    """Return whether every backend gives the same verdict, statuses and executed ops."""
    def key(r):
        """Group results by scenario and policy."""
        return (r.name, r.policy)
    by = {}
    for r in results:
        by.setdefault(key(r), {})[r.backend] = (r.verdict, r.statuses, r.final_status, r.executed_ops)
    return all(len(set(map(str, v.values()))) == 1 for v in by.values())


def _write(results: list[WorldResult], out_dir: str) -> None:
    """Write results.json (with the run manifest) and results.md into ``out_dir``."""
    os.makedirs(out_dir, exist_ok=True)
    from booking_v4.manifest import run_manifest
    policies = {label: p.digest() for label, p in _policies()}
    record = {"system_model": "V3", "experiment": "lying-world",
              "policies": policies, "manifest": run_manifest(clock_mode=f"fixed:{NOW}"),
              "all_as_predicted": all(r.matches_prediction for r in results),
              "backends_agree": backends_agree(results),
              "leaks": {label: sorted(r.name for r in results if r.policy == label and r.backend == "in-process"
                                      and r.verdict == "LEAK_AS_PREDICTED") for label in policies},
              "results": [asdict(r) for r in results]}
    with open(os.path.join(out_dir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, default=str)
    lines = ["# V3 lying-world results\n\n",
             "Honest agent, lying counterparty, V3 fragmented execution. P2.1 is the policy the final P3 wraps, "
             "P2 the frozen V2b policy lifted onto the V3 plane. Not part of the frozen scenario list "
             "(booking_v3.scenarios.all_scenarios).\n\n",
             f"Policies: {', '.join(f'{k} `{v[:16]}…`' for k, v in policies.items())}\n\n",
             f"All as predicted: **{record['all_as_predicted']}**. Backends agree: **{record['backends_agree']}**\n\n",
             "| Scenario | Policy | Backend | Expected | Verdict | Statuses | Final | Executed |\n|---|---|---|---|---|---|---|---|\n"]
    for r in results:
        lines.append(f"| {r.name} | {r.policy} | {r.backend} | {r.expected} | {r.verdict} | "
                     f"{' '.join(r.statuses)} | {r.final_status} | {' '.join(r.executed_ops)} |\n")
    with open(os.path.join(out_dir, "results.md"), "w", encoding="utf-8") as fh:
        fh.writelines(lines)


def main() -> int:
    """Run the experiment, print the table, write the record and return the exit code."""
    results = run_all()
    print(f"{'scenario':26s} {'policy':5s} {'backend':10s} {'expected':20s} {'verdict':20s} ok")
    for r in results:
        print(f"{r.name:26s} {r.policy:5s} {r.backend:10s} {r.expected:20s} {r.verdict:20s} {'yes' if r.matches_prediction else 'NO'}")
    print(f"\nall as predicted: {all(r.matches_prediction for r in results)}   backends agree: {backends_agree(results)}")
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v3", "world")
    _write(results, out_dir)
    print(f"Wrote {out_dir}/results.json and results.md")
    return 0 if all(r.matches_prediction for r in results) and backends_agree(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
