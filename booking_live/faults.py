"""Deterministic fault injection at the gateway, for the uncertain-outcome experiment.

The uncertain-outcome experiment needs a payment whose request crossed the effect boundary
while its answer did not come back. Duffel's scenario routes cannot produce that for a hold
order paid from balance (their 202 cases are instant orders with card payments), so the
condition is injected where it would occur in reality, between the counterparty and the
gateway.

    lose-payment-response
        The payment is sent and executed by the counterparty. When the counterparty
        confirms it, the gateway withholds that answer and reports UNCERTAIN, as it would
        after a connection that dropped after the request. A payment the counterparty
        refused is passed through unchanged, because then nothing crossed.

The fault is deployment configuration (`WORLD_FAULT` on the gateway), off by default,
announced at start-up, and named in the error of every result it touches, so a run record
cannot present an injected loss as a natural one. The payment tool is found through the
effect map, not by name. The withheld identifiers are logged on the gateway only, because
they are the operator's ground truth for the later reconciliation and not something the
run may learn.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from booking_v1.effects import EffectOutcome, EffectResult

from .effects import PAYMENT, tools_of_kind

LOSE_PAYMENT_RESPONSE = "lose-payment-response"
#: knob -> the fault's type as the evidence records it.
FAULT_TYPES = {LOSE_PAYMENT_RESPONSE: "drop_provider_response_after_dispatch"}
FAULTS = frozenset(FAULT_TYPES)


class FaultRefused(ValueError):
    """An unknown fault name. The gateway must not start with a fault it cannot name."""


def with_fault(executor: Callable[[Any], EffectResult], fault: Optional[str],
               effects: Mapping[str, Optional[str]],
               log: Callable[[str], None] = print) -> Callable[[Any], EffectResult]:
    """Wrap `executor` with `fault`, or return it unchanged for None.

    Args:
        executor: The world executor.
        fault: A knob of `FAULTS`, or None.
        effects: The world's effect map, which names the payment tools.
        log: Where the withheld identifiers are written (the gateway's stdout).

    Returns:
        The wrapped executor.

    Raises:
        FaultRefused: when `fault` is not one of `FAULTS`.
    """
    if not fault:
        return executor
    if fault not in FAULTS:
        raise FaultRefused(f"unknown fault {fault!r}, expected one of {sorted(FAULTS)}")
    payment_tools = tools_of_kind(effects, PAYMENT)

    def _execute(call) -> EffectResult:
        result = executor(call)
        tool = getattr(call, "tool", None)
        if tool not in payment_tools or result.outcome is not EffectOutcome.CONFIRMED:
            return result
        payload = dict(result.payload or {})
        action_id = (getattr(call, "args", {}) or {}).get("action_id")
        identity = getattr(call, "effect_identity", None)
        # `scripts/gke-v5/39_live_evidence.py` parses this line (`payment_id=<id>;`), so its
        # format stays fixed.
        log(f"[gateway] FAULT {fault}: {tool} action_id={action_id} effect_identity={identity} "
            f"counterparty CONFIRMED order_id={payload.get('order_id')} "
            f"payment_id={payload.get('payment_id')}; response withheld from the run")
        return EffectResult(outcome=EffectOutcome.UNCERTAIN,
                            error=f"{tool} outcome not established: response lost "
                                  f"(injected fault {fault})")

    return _execute
