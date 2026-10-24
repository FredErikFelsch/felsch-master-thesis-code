"""The trusted world and the V2 effect executor.

In V2 the values that matter for authorisation must come from the environment,
not from the agent. The world here stands in for the airline and the payment
service. It holds the authoritative flight catalogue. The book tool consults the
world and returns the real price, currency and merchant, independent of anything
the agent claimed. Those authoritative results are what the monitor later records
as facts.

The executor is injectable, as in V1. A faulting variant forces a failed
or uncertain effect to exercise the effect-aware states.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from booking_v1.effects import EffectOutcome, EffectResult

# Authoritative catalogue. price_minor is integer minor units (cents).
_CATALOGUE: dict[str, dict[str, Any]] = {
    "LH123": {"to": "FRA", "price_minor": 34900, "currency": "EUR", "merchant": "airline:LH"},
    "LH250": {"to": "FRA", "price_minor": 37500, "currency": "EUR", "merchant": "airline:LH"},
    "AF456": {"to": "FRA", "price_minor": 41200, "currency": "EUR", "merchant": "airline:AF"},
}


def _search(args: Mapping[str, Any]) -> dict:
    """Return the catalogue offers for the requested destination."""
    destination = args.get("to", "FRA")
    offers = [
        {"flight_id": fid, "price_minor": f["price_minor"], "currency": f["currency"], "merchant": f["merchant"]}
        for fid, f in _CATALOGUE.items() if f["to"] == destination
    ]
    return {"offers": offers}


def _select(args: Mapping[str, Any]) -> dict:
    """Echo the selected flight."""
    return {"selected_flight_id": args.get("flight")}


def _book(args: Mapping[str, Any]) -> EffectResult:
    """Book a catalogue flight and confirm the world's price, currency and merchant."""
    fid = args.get("flight")
    flight = _CATALOGUE.get(fid)
    if flight is None:
        # A flight that does not exist cannot be booked. The effect fails cleanly.
        return EffectResult(outcome=EffectOutcome.FAILED, error=f"unknown flight {fid!r}")
    payload = {
        "booking_ref": "BK-" + str(fid),
        "flight_id": fid,
        "price_minor": flight["price_minor"],
        "currency": flight["currency"],
        "recipient": flight["merchant"],
    }
    return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=payload)


def _pay(args: Mapping[str, Any]) -> dict:
    """Record a payment with the supplied amount, currency and recipient."""
    return {"paid": True, "amount_minor": args.get("amount_minor"), "currency": args.get("currency"), "recipient": args.get("recipient")}


def v2_executor(call) -> EffectResult:
    """Execute a tool against the trusted world.

    Every tool confirms, except a booking of an unknown flight, which fails.
    """
    tool = call.tool
    args = call.args
    if tool == "search":
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=_search(args))
    if tool == "select":
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=_select(args))
    if tool == "book":
        return _book(args)
    if tool == "pay":
        return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=_pay(args))
    # Any other tool would have been denied earlier. Report a benign confirm.
    return EffectResult(outcome=EffectOutcome.CONFIRMED, payload={})


def faulting_executor(faults: Mapping[str, EffectOutcome]) -> Callable:
    """Return an executor that forces an outcome for named tools (environment fault).

    Args:
        faults: Maps a tool name to the outcome to force. Other tools run
            against the trusted world.

    Returns:
        The executor.
    """
    def _execute(call) -> EffectResult:
        forced = faults.get(call.tool)
        if forced is EffectOutcome.FAILED:
            return EffectResult(outcome=EffectOutcome.FAILED, error="effect rejected by environment")
        if forced is EffectOutcome.UNCERTAIN:
            return EffectResult(outcome=EffectOutcome.UNCERTAIN, error="effect timed out, outcome unknown")
        return v2_executor(call)
    return _execute


def lying_executor(overrides: Mapping[str, Mapping[str, Any]]) -> Callable:
    """Return an executor whose counterparty confirms a reply of its own choosing.

    This is the adversary V2 sets aside by assumption, a malicious but allow-listed
    counterparty. The outcome is CONFIRMED but the content is false.

    Args:
        overrides: Maps a tool name to the payload the world returns for it,
            well-typed and plausible, instead of the catalogue answer. Other
            tools go to the honest world.

    Returns:
        The executor.
    """
    def _execute(call) -> EffectResult:
        forced = overrides.get(call.tool)
        if forced is not None:
            return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=dict(forced))
        return v2_executor(call)
    return _execute
