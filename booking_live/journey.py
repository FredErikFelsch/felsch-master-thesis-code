"""The journey of a live search: stated by the plan, approved by a human, bound by the policy.

A real search needs an origin, a destination, a date and a cabin. Where they come from is
the security question. They do not come from the untrusted input (the invoice mail) or from
a deployment default the human did not see, but from the task: the model reads the user's
request and proposes them in the plan, the human approves the plan, and the compiled
policy binds every search argument to the approved value (`arg_equals_const`).

    user request ──► model proposes plan.parameters ──► human approves
                                                           │
    agent: search(origin, to, date, cabin) ──► monitor: each arg == approved value

An injected "fly to LHR instead" is denied before the provider is contacted, in the same
way as a forged order id at the payment step. The deployment-level `RunContext` is not the
source of the journey: the agent cannot change it, but the human did not approve it either.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Mapping

from booking_v2.policy import BindingSpec, PolicyInvalid

#: plan parameter -> argument of `search` (booking_v1.schema)
JOURNEY_ARGS: dict[str, str] = {"origin": "origin", "destination": "to", "date": "date", "cabin": "cabin"}
CABINS = frozenset({"economy", "premium_economy", "business", "first"})
_IATA = re.compile(r"^[A-Z]{3}$")


@dataclass(frozen=True)
class Journey:
    """A validated journey. Construction refuses anything a provider could misread.

    Raises:
        PolicyInvalid: for an origin or destination that is not a 3-letter IATA code, equal
            origin and destination, a date that is not ISO or not in the future, or an
            unknown cabin.
    """

    origin: str
    destination: str
    date: str
    cabin: str = "economy"

    def __post_init__(self) -> None:
        for name in ("origin", "destination"):
            value = str(getattr(self, name)).strip().upper()
            if not _IATA.match(value):
                raise PolicyInvalid(f"journey {name} must be a 3-letter IATA code, got {getattr(self, name)!r}")
            object.__setattr__(self, name, value)
        if self.origin == self.destination:
            raise PolicyInvalid("journey origin and destination must differ")
        try:
            day = date.fromisoformat(str(self.date))
        except ValueError as exc:
            raise PolicyInvalid(f"journey date must be ISO YYYY-MM-DD, got {self.date!r}") from exc
        if day <= date.today():
            raise PolicyInvalid(f"journey date {day} is not in the future")
        object.__setattr__(self, "date", day.isoformat())
        cabin = str(self.cabin).strip().lower().replace(" ", "_")
        if cabin not in CABINS:
            raise PolicyInvalid(f"journey cabin must be one of {sorted(CABINS)}, got {self.cabin!r}")
        object.__setattr__(self, "cabin", cabin)

    @classmethod
    def from_parameters(cls, params: Mapping[str, object]) -> "Journey":
        """Build the journey from a plan's `parameters`. Every field is required."""
        missing = [k for k in JOURNEY_ARGS if not params.get(k)]
        if missing:
            raise PolicyInvalid(f"the plan must state the journey: missing {missing}")
        return cls(**{k: str(params[k]) for k in JOURNEY_ARGS})

    @classmethod
    def default(cls, destination: str = "FRA", origin: str = "JFK", days_ahead: int = 30,
                cabin: str = "economy") -> "Journey":
        """Build the journey of a `--plan fixed` run that names none (a pre-approved policy)."""
        return cls(origin, destination, (date.today() + timedelta(days=days_ahead)).isoformat(), cabin)

    @classmethod
    def parse(cls, spec: str) -> "Journey":
        """Parse `ORIGIN-DEST[:YYYY-MM-DD[:cabin]]`, as given on the command line.

        A missing date is 30 days ahead, a missing cabin is economy.
        """
        route, _, rest = spec.partition(":")
        origin, _, destination = route.partition("-")
        day, _, cabin = rest.partition(":")
        day = day or (date.today() + timedelta(days=30)).isoformat()
        return cls(origin, destination, day, cabin or "economy")

    def as_parameters(self) -> dict[str, str]:
        """Return the journey as plan parameters."""
        return {"origin": self.origin, "destination": self.destination, "date": self.date, "cabin": self.cabin}

    def as_search_args(self) -> dict[str, str]:
        """Return the journey as the arguments of a `search` call."""
        return {JOURNEY_ARGS[k]: v for k, v in self.as_parameters().items()}


def journey_bindings(journey: Journey) -> tuple[BindingSpec, ...]:
    """Build one `arg_equals_const` per search argument, in a fixed order so the digest is stable."""
    return tuple(BindingSpec("arg_equals_const", {"arg": arg, "expected": value})
                 for arg, value in journey.as_search_args().items())
