"""Live expiry of a manual-intervention approval.

This is acceptance test A20: an intervention approval is valid only within its window. The
deployed services run the system clock, so a validity window is a real one. This scenario
makes that observable on any chain. The payment parks (REQUIRE_APPROVAL), the
human approves it with a short window, and the resubmission arrives after the window and is
refused at the grant, so no effect runs. As the control, a fresh approval inside its window
completes the same fragment, so the earlier refusal can only be due to the expired window.

    python3 -m booking_demo.expiry --mode local                 # fake TDs, real services, a stepped clock
    python3 -m booking_demo.expiry --mode v5 --context v5-controller --admin-context <ctx> \
        --project P --zone Z --registry R [--impersonate GSA] --ttl 20 --wait 25

In `v5` mode the record is written to `results_v5/expiry/<stamp>.json`, and it is printed in
both modes. It carries `clock_mode`, `ttl_s`, `waited_s`, `late` and `control` (status and
reason of each attempt), `pay_effects_after_late`, `pay_effects_after_control`,
`pending_after_control`, the run status and `pass`.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from typing import Callable

from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import p3_with_pay_approval

MOCKS = pathlib.Path(__file__).resolve().parent.parent


def run_expiry(chain, *, ttl: int, wait: int, sleep: Callable[[int], None], run_id: str = "run-expiry",
               clock_mode: str = "live") -> dict:
    """Run the expiry scenario on `chain` and return its record.

    The pay step parks, is approved with `ttl`, and is resubmitted after `wait` seconds
    (more than `ttl`). The expected result is GRANT_REFUSED on the validity window and no
    pay effect. The control then approves again and resubmits at once, and the expected
    result is STEP_COMPLETED with one pay effect.

    Args:
        chain: The chain to run on.
        ttl: The approval window in seconds.
        wait: Seconds to wait before the late resubmission.
        sleep: How to wait (`time.sleep`, or a stepped clock's `advance`).
        run_id: The run id.
        clock_mode: The clock mode written to the record and the manifest.

    Returns:
        The record, with `pass` set when both expectations hold.

    Raises:
        RuntimeError: A step before the payment did not complete, or the payment did not park.
    """
    policy = p3_with_pay_approval()
    envelope = chain.create_run(policy, run_id)
    args = happy_path_arguments()
    for step in range(3):
        fragment = honest_fragment(policy, run_id, step, args[step])
        result, _trace = chain.execute(policy, envelope, fragment, None)
        if result.status != "STEP_COMPLETED":
            raise RuntimeError(f"step {step} did not complete: {result.status} {result.reason}")
        envelope = result.envelope
    pay = honest_fragment(policy, run_id, 3, args[3])
    parked, _ = chain.execute(policy, envelope, pay, None)
    if parked.status != "REQUIRE_APPROVAL":
        raise RuntimeError(f"pay did not park: {parked.status} {parked.reason}")
    # COMMITTED only: `chain.ledger()` reports PENDING intents as well, and here the question
    # is how many effects were confirmed, not how many were attempted.
    committed = lambda: sum(1 for e in chain.ledger() if e.get("state", "COMMITTED") == "COMMITTED")
    ledger_before = committed()

    approval = chain.decide_intervention(run_id, 3, pay.fragment_hash, True, ttl=ttl, fragment=pay)
    t0 = time.time()
    sleep(wait)
    late, _ = chain.execute(policy, envelope, pay, approval)
    ledger_after_late = committed()

    fresh = chain.decide_intervention(run_id, 3, pay.fragment_hash, True, ttl=ttl, fragment=pay)
    control, _ = chain.execute(policy, envelope, pay, fresh)
    ledger_after_control = committed()

    record = {
        "scenario": "A20-intervention-expiry", "clock_mode": clock_mode, "chain": chain.name,
        "ttl_s": ttl, "waited_s": wait, "wall_s": round(time.time() - t0, 1),
        "approval": {"issued_at": approval.issued_at, "expires_at": approval.expires_at},
        "late": {"status": late.status, "reason": late.reason},
        "control": {"status": control.status, "reason": control.reason},
        "pay_effects_after_late": ledger_after_late - ledger_before,
        "pay_effects_after_control": ledger_after_control - ledger_before,
        # An attempt the gateway started and did not confirm is counted apart from the effects.
        "pending_after_control": sum(1 for e in chain.ledger()
                                     if e.get("state", "COMMITTED") != "COMMITTED"),
        "run_status": chain.run_status(run_id),
    }
    from booking_v4.manifest import run_manifest
    record["manifest"] = run_manifest(clock_mode=clock_mode)
    record["pass"] = (late.status == "GRANT_REFUSED" and "validity window" in (late.reason or "")
                      and record["pay_effects_after_late"] == 0
                      and control.status == "STEP_COMPLETED" and record["pay_effects_after_control"] == 1)
    return record


class SteppedClock:
    """A clock with the `now()` of `FixedClock` that the offline scenario advances by hand.

    It stands in for waiting.
    """

    def __init__(self, t: int) -> None:
        self._t = t

    def now(self) -> int:
        """Return the current stepped time in seconds."""
        return self._t

    def advance(self, seconds: int) -> None:
        """Move the clock forward by `seconds`."""
        self._t += seconds


def main(argv=None) -> int:
    """Run the command line. Returns 0 when the expiry scenario passes, else 1."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=("local", "v5"), default="local")
    ap.add_argument("--ttl", type=int, default=20, help="approval window in seconds (capped at INTERVENTION_TTL)")
    ap.add_argument("--wait", type=int, default=25, help="seconds to wait before the late resubmission")
    ap.add_argument("--context", default="v5-controller")
    ap.add_argument("--admin-context", default=None)
    ap.add_argument("--approval-url", default="http://localhost:8450")
    ap.add_argument("--harness-approver-key", default=None,
                    help="on a gated Authority: the harness key that approves (twice, with --ttl)")
    ap.add_argument("--project", default=None)
    ap.add_argument("--zone", default=None)
    ap.add_argument("--registry", default=None)
    ap.add_argument("--impersonate", default=None)
    ap.add_argument("--controller-config", default=str(MOCKS / "results_v5" / "e2e" / "controller-config.json"))
    ap.add_argument("--pool", type=int, default=0)
    args = ap.parse_args(argv)
    from .chains import AttestedChain
    if args.mode == "local":
        clock = SteppedClock(1_700_000_010)
        chain = AttestedChain.local(clock)
        try:
            record = run_expiry(chain, ttl=args.ttl, wait=args.wait, sleep=clock.advance, clock_mode="stepped")
        finally:
            chain.close()
    else:
        chain = AttestedChain.cluster(args.context, args.admin_context, args.project, args.zone, args.registry,
                                      args.impersonate, args.controller_config, pool=args.pool,
                                      approval_url=args.approval_url, harness_key=args.harness_approver_key)
        try:
            record = run_expiry(chain, ttl=args.ttl, wait=args.wait, sleep=time.sleep, clock_mode="live",
                                run_id=f"run-expiry-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}")
        finally:
            chain.close()
        out = MOCKS / "results_v5" / "expiry"
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.json"
        path.write_text(json.dumps(record, indent=2, default=str))
        print(f"recorded: {path}")
    print(json.dumps(record, indent=2, default=str))
    print("VERDICT expiry:", "REFUSED ON THE WINDOW, CONTROL COMPLETED" if record["pass"] else "CHECK RECORD")
    return 0 if record["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
