"""Policy P0: the approved authorisation artefact of System Model V0.

In V0 the policy is minimal. It authorises one ordered sequence of critical
actions and bounds how often each may run. It does not constrain the parameters
of those actions. V0 is meant to show this gap, and V1 closes it with parameter
constraints.

The policy is a plain, human-legible data object. The human approver sees this
artefact, and the monitor enforces the same artefact afterwards. There is no LLM
translation between approval and enforcement.

The policy is immutable. After construction none of its fields can be reassigned
and its mapping fields cannot be mutated in place. Any change produces a
different object with a different hash, which the monitor refuses to activate
against an approval frozen for the original.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping


@dataclass(frozen=True)
class Policy:
    """A task-specific authorisation policy.

    Attributes:
        policy_id: Stable identifier of the policy, e.g. ``"P0"``.
        task: The natural-language user task the policy was derived from. Stored
            for legibility and for the record only. The monitor does not read
            it.
        allowed_flow: The ordered sequence of tool names the agent is
            authorised to execute. Enforced position by position.
        max_executions: Upper bound on how often each tool may run inside one
            policy instance. In V0 the exact-sequence rule already implies a
            count of one per step. This field makes the cardinality explicit and
            foreshadows the consumable-rights model (UCON) used later.
        budget: The monetary ceiling extracted from the user task. In V0 this is
            recorded but not enforced by the monitor. V1 turns it into a
            parameter constraint on ``pay.amount``.
    """

    policy_id: str
    task: str
    allowed_flow: tuple[str, ...]
    max_executions: Mapping[str, int] = field(default_factory=dict)
    budget: float | None = None

    def __post_init__(self) -> None:
        """Freeze the mutable fields so the whole policy is immutable.

        ``allowed_flow`` is coerced to a tuple and ``max_executions`` to a
        read-only mapping. Because the dataclass is frozen, the assignments go
        through ``object.__setattr__``.
        """
        object.__setattr__(self, "allowed_flow", tuple(self.allowed_flow))
        object.__setattr__(
            self, "max_executions", MappingProxyType(dict(self.max_executions))
        )

    def canonical_bytes(self) -> bytes:
        """Return a stable byte serialisation for hashing.

        The serialisation is deterministic (sorted keys, no whitespace noise) so
        that the same policy always yields the same hash. The approval step
        freezes this hash. The monitor rejects any instance whose policy hash
        does not match the approved one.
        """
        payload = {
            "policy_id": self.policy_id,
            "task": self.task,
            "allowed_flow": list(self.allowed_flow),
            "max_executions": dict(sorted(self.max_executions.items())),
            "budget": self.budget,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        """Return the SHA-256 hex digest of the canonical policy bytes."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_json(self) -> str:
        """Return an indented JSON view for the record and for display."""
        data = {
            "policy_id": self.policy_id,
            "task": self.task,
            "allowed_flow": list(self.allowed_flow),
            "max_executions": dict(self.max_executions),
            "budget": self.budget,
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "Policy":
        """Construct a Policy from a plain dictionary (e.g. loaded JSON)."""
        return cls(
            policy_id=data["policy_id"],
            task=data["task"],
            allowed_flow=tuple(data["allowed_flow"]),
            max_executions=dict(data.get("max_executions", {})),
            budget=data.get("budget"),
        )


def default_p0() -> Policy:
    """Return the frozen Policy P0 for the small booking use case.

    Task: book a hand-luggage flight to FRA within a 400 EUR budget and pay for
    it once. The approved flow is search, select, book, pay. Each step runs at
    most once. The budget is recorded but not enforced in V0.

    The task does not say "cheapest". Selecting by a criterion (for example the
    lowest price) is not something V0 can enforce, because V0 reads no tool
    output and inspects no parameters. Criterion-bound selection at
    the monitor is a V2 concern. Stating an unenforced property in the approved
    artefact would misrepresent what the monitor guarantees.
    """
    return Policy(
        policy_id="P0",
        task="Book a hand-luggage flight to FRA within a 400 EUR budget and pay once.",
        allowed_flow=("search", "select", "book", "pay"),
        max_executions={"search": 1, "select": 1, "book": 1, "pay": 1},
        budget=400.0,
    )
