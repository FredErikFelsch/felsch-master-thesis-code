"""Effect execution, separated from the admission decision.

Admission decides whether an action is authorised. Execution is what actually
happens when the tool runs, and it can succeed, fail, or leave an uncertain
outcome (a payment that timed out). The monitor keeps these apart: it grants the
right at admission, then runs the effect through an executor and records the
outcome. The flow advances only on a confirmed effect.

The executor is injectable. The default runs the V0 mock tools and reports a
confirmed outcome. Tests and scenarios pass an executor that forces a failure or
an uncertain outcome, to exercise the effect-aware states without a real network.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

from booking_v0.tools import ToolCall, run_tool

from .freeze import canonical_bytes, thaw, to_canonical


def response_digest(outcome: str, payload: Mapping[str, Any] | None) -> str:
    """Return the digest of one gateway response (outcome and payload).

    Both sides compute it the same way. Used by booking_v3.authority, which compares
    it with the effect a runner reports, and by booking_v4.durable, which stores it
    with the committed outcome. The error field is not covered because it does not
    become a fact. ``thaw`` and ``canonical_bytes`` make a frozen mapping and a plain
    one with the same content hash identically.

    Args:
        outcome: The effect outcome, for example ``"CONFIRMED"``.
        payload: The response payload, or None.

    Returns:
        The SHA-256 hex digest.
    """
    return hashlib.sha256(canonical_bytes(
        {"outcome": str(outcome), "payload": thaw(payload) if payload is not None else None}
    )).hexdigest()


class EffectOutcome(str, Enum):
    """The outcome of executing an admitted action."""

    CONFIRMED = "CONFIRMED"      # the effect definitely happened
    FAILED = "FAILED"            # the effect definitely did not happen
    UNCERTAIN = "UNCERTAIN"      # the outcome is unknown (needs reconciliation)


@dataclass(frozen=True)
class EffectResult:
    """The result of one effect execution."""

    outcome: EffectOutcome
    payload: Mapping[str, Any] | None = None
    error: str | None = None


# An executor maps an (immutable) call to an effect result.
Executor = Callable[[ToolCall], EffectResult]


def default_executor(call: ToolCall) -> EffectResult:
    """Run the V0 mock tool and report a confirmed outcome."""
    result = run_tool(call, injection=None)
    return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=result.payload)


def safe_execute(executor: Executor, call: ToolCall) -> EffectResult:
    """Run an executor and guarantee a valid EffectResult.

    A raising executor, or one that returns something that is not a valid
    EffectResult, is turned into an UNCERTAIN outcome. UNCERTAIN is the safe
    default for effectful tools: after an unexpected error nobody can claim the
    effect did not happen, so reconciliation is required rather than assuming
    success or clean failure. This keeps the effect state machine authoritative:
    no exception escapes into the monitor.

    The whole result is normalised here, once. The outcome must be a valid enum,
    the payload must be a mapping or None, and the error must be a string or None.
    A bad shape becomes UNCERTAIN rather than being passed on to crash the monitor
    later. The payload is deep-frozen here so that every downstream consumer (the
    audit event and the returned ToolResult) works from the same immutable copy.

    Args:
        executor: The executor to run.
        call: The admitted call.

    Returns:
        A valid EffectResult. Any fault becomes UNCERTAIN.
    """
    try:
        result = executor(call)
    except Exception:
        return EffectResult(outcome=EffectOutcome.UNCERTAIN, error="executor raised before outcome could be established")
    if not isinstance(result, EffectResult) or not isinstance(result.outcome, EffectOutcome):
        return EffectResult(outcome=EffectOutcome.UNCERTAIN, error="executor returned an invalid result")
    # The payload must actually be a mapping (or None). A pair-list or other shape
    # is not silently coerced. The error must be a string (or None).
    if result.payload is not None and not isinstance(result.payload, Mapping):
        return EffectResult(outcome=EffectOutcome.UNCERTAIN, error="executor returned a non-mapping payload")
    if result.error is not None and not isinstance(result.error, str):
        return EffectResult(outcome=EffectOutcome.UNCERTAIN, error="executor returned an invalid error value")
    # Normalise the payload and the error and check that both serialise, all
    # inside the guard. Any deviation (non-string keys, sets, cycles, non-finite floats,
    # oversized values or cumulative size) becomes a safe UNCERTAIN with no payload.
    try:
        payload = to_canonical(dict(result.payload)) if result.payload is not None else None
        error = to_canonical(result.error) if result.error is not None else None
    except Exception:
        return EffectResult(outcome=EffectOutcome.UNCERTAIN, payload=None, error="executor returned a non-canonical payload or error")
    return EffectResult(outcome=result.outcome, payload=payload, error=error)


def faulting_executor(faults: Mapping[str, EffectOutcome]) -> Executor:
    """Return an executor that forces an outcome for named tools.

    Args:
        faults: A mapping from tool name to the outcome to force. A tool not in
            the mapping runs normally (confirmed). This models an environment
            fault (a rejected or timed-out payment), not agent behaviour.

    Returns:
        The executor.
    """

    def _execute(call: ToolCall) -> EffectResult:
        forced = faults.get(call.tool)
        if forced is EffectOutcome.FAILED:
            return EffectResult(outcome=EffectOutcome.FAILED, error="effect rejected by environment")
        if forced is EffectOutcome.UNCERTAIN:
            return EffectResult(outcome=EffectOutcome.UNCERTAIN, error="effect timed out, outcome unknown")
        return default_executor(call)

    return _execute
