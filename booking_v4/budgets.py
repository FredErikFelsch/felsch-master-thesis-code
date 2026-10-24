"""The time budgets of one effectful dispatch, staged so the inner party always answers first.

A runner that calls the gateway waits at most `RPC_TIMEOUT_S`. If the provider could
keep the gateway busy longer than that, the runner would give up while the gateway is still
dispatching, and the run would stay in EFFECT_PENDING with nobody left to report the outcome. The
stages therefore nest, each one longer than the one it contains by at least `MARGIN_S`:

    provider request          PROVIDER_REQUEST_TIMEOUT_S, one HTTP request (booking_live.world)
    gateway dispatch          GATEWAY_DISPATCH_BUDGET_S, every request one tool sends, then UNCERTAIN
    runner RPC                RPC_TIMEOUT_S (booking_v4.services), the runner's wait for the gateway
    attach stream             booking_v5.attach_transport, the controller's wait for the runner

`with_deadline` enforces the gateway stage even when a provider call does not return. Nothing here
sends a request again: a dispatch that outlasts its budget is answered UNCERTAIN, and the run is
parked for reconciliation. The module sits in `booking_v4` because the runner image copies only
`booking_v0` to `booking_v5` and `booking_v4.services` needs it
(`booking_v5.tests_code_closure.TheRunnerImageImportsOnItsOwn`). The relations are pinned by
`booking_v5.tests_code_closure.TheTimeoutsAreStagedWithMargin`.
"""
from __future__ import annotations

import threading
from typing import Any, Callable

from booking_v1.effects import EffectOutcome, EffectResult

#: Seconds between two nested stages. Enough for a scheduling delay or a slow reply, not a retry.
MARGIN_S = 10.0
#: One HTTP request to the counterparty.
PROVIDER_REQUEST_TIMEOUT_S = 15.0
#: The most requests one tool sends in sequence (pay_order: pre-payment read, payment, settlement read).
MAX_PROVIDER_REQUESTS_PER_TOOL = 3
#: Everything one dispatch may take at the gateway.
GATEWAY_DISPATCH_BUDGET_S = PROVIDER_REQUEST_TIMEOUT_S * MAX_PROVIDER_REQUESTS_PER_TOOL + MARGIN_S
#: The runner's wait for a deployment service, connect and read.
RPC_TIMEOUT_S = GATEWAY_DISPATCH_BUDGET_S + MARGIN_S


def with_deadline(executor: Callable[[Any], EffectResult], budget_s: float | None = None
                  ) -> Callable[[Any], EffectResult]:
    """Wrap `executor` so the caller waits no longer than `budget_s` for one call.

    The call runs in a daemon thread. When the budget runs out the caller gets UNCERTAIN, because
    the request may still be in flight and the effect may yet happen, as after a dropped
    connection. An exception of the executor is raised in the caller as before.

    Args:
        executor: The effect executor of a gateway.
        budget_s: The budget in seconds, `GATEWAY_DISPATCH_BUDGET_S` (read at call time) when None.

    Returns:
        The wrapped executor.
    """
    def _execute(call) -> EffectResult:
        limit = GATEWAY_DISPATCH_BUDGET_S if budget_s is None else budget_s
        box: dict = {}

        def _target() -> None:
            try:
                box["result"] = executor(call)
            except BaseException as exc:                     # noqa: BLE001 (handed to the caller)
                box["error"] = exc
        worker = threading.Thread(target=_target, name="dispatch-budget", daemon=True)
        worker.start()
        worker.join(limit)
        if worker.is_alive():
            return EffectResult(outcome=EffectOutcome.UNCERTAIN,
                                error=f"dispatch budget of {limit:g} s exceeded, the effect may have happened")
        if "error" in box:
            raise box["error"]
        return box["result"]
    _execute.budget_s = budget_s
    return _execute
