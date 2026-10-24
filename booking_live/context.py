"""Deployment defaults for a live call: what the gateway fills in when an argument is absent.

The journey (origin, destination, date, cabin) is part of the approved plan and the policy
binds every search argument to it (`booking_live.journey`). A monitored search therefore
carries all four, and this module passes them on as the monitor admitted them.

What is left here is a fallback for calls that name no journey (the diagnostics, an
unbound catalogue-style `search(to)`, and `select`, which carries only the offer), so a
provider does not receive `origin=None`. It is deployment configuration, it does not
override the journey values a call carries, and it is not part of any approval.

The context has no switch that overrides the agent's destination or narrows the offers to
one carrier, because such switches only hide provider refusals, for instance a replayed
stored refusal when the idempotency key is not bound to the run.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any, Callable


@dataclass(frozen=True)
class RunContext:
    """Defaults for a call that names no journey.

    Attributes:
        origin: The default origin.
        destination: The default destination, or None.
        days_ahead: The default travel date, counted from today.
        cabin: The default cabin.
    """

    origin: str
    destination: str | None = None
    days_ahead: int = 30
    cabin: str = "economy"

    @property
    def departure_date(self) -> str:
        """The travel date, `days_ahead` days from today, ISO formatted."""
        return (date.today() + timedelta(days=self.days_ahead)).isoformat()


class _Call:
    """The call shape the world executors read (`tool`, `args`)."""

    def __init__(self, tool: str | None, args: dict) -> None:
        self.tool, self.args = tool, args


def with_context(executor: Callable[[Any], Any], context: RunContext) -> Callable[[Any], Any]:
    """Wrap `executor` so every call carries a complete journey for the provider.

    The call's own `origin`, `destination` (or `to`), `date` and `cabin` win, as the monitor
    admitted them. The context supplies only what is absent. The adapter reads `origin`,
    `destination`, `departure_date` and `cabin`, and `departure_date` is always taken from
    `date` or the context.

    Args:
        executor: The world executor.
        context: The deployment defaults.

    Returns:
        The wrapped executor.
    """
    def _execute(call) -> Any:
        args = dict(getattr(call, "args", {}) or {})
        enriched = {**args,
                    "origin": args.get("origin") or context.origin,
                    "destination": args.get("destination") or args.get("to") or context.destination,
                    "departure_date": args.get("date") or context.departure_date,
                    "cabin": args.get("cabin") or context.cabin}
        return executor(_Call(getattr(call, "tool", None), enriched))

    return _execute
