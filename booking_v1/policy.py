"""Policy P1 (V1.2): declarative, versioned, validated and immutable.

Design points:

- Constraints are declarative ConstraintSpec objects of a registered kind. The
  policy carries no constraint behaviour. It selects a registered kind. The digest
  covers the declared registry version, so the approval binds that version. It does
  not cryptographically bind the evaluator implementation. See constraints.py for
  the scope of this claim.
- The approved artefact is versioned. The policy hash covers the policy schema
  version and the constraint registry version, so a change in either invalidates
  old approvals.
- The policy validates fully (currency, budget, flow, tools, counts, constraint
  indices and kinds). An invalid policy cannot be constructed.
- Money is integer minor units with an explicit currency. The budget is stored in
  one field, budget_minor, which the budget_ceiling constraint reads.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .constraints import CONSTRAINT_REGISTRY_VERSION, ConstraintSpec, budget_ceiling
from .freeze import canonical_bytes
from .schema import validate_policy

# Bumped whenever the policy structure changes. Part of the approved artefact.
POLICY_SCHEMA_VERSION = "ps-1"


@dataclass(frozen=True)
class Policy:
    """A task-specific authorisation policy with step-indexed declarative constraints."""

    policy_id: str
    task: str
    allowed_flow: tuple[str, ...]
    max_executions: Mapping[str, int] = field(default_factory=dict)
    budget_minor: int = 0
    currency: str = "EUR"
    step_constraints: Mapping[int, ConstraintSpec] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Freeze mutable fields and validate. An invalid policy cannot exist."""
        object.__setattr__(self, "allowed_flow", tuple(self.allowed_flow))
        object.__setattr__(self, "max_executions", MappingProxyType(dict(self.max_executions)))
        object.__setattr__(self, "step_constraints", MappingProxyType(dict(self.step_constraints)))
        validate_policy(self)

    def constraint_at(self, step_index: int) -> ConstraintSpec | None:
        """Return the constraint spec bound to ``step_index``, or None."""
        return self.step_constraints.get(step_index)

    def _canonical_dict(self) -> dict:
        """Return the canonical dict that the digest covers."""
        return {
            "policy_id": self.policy_id,
            "task": self.task,
            "allowed_flow": list(self.allowed_flow),
            "max_executions": dict(sorted(self.max_executions.items())),
            "budget_minor": self.budget_minor,
            "currency": self.currency,
            "step_constraints": {
                str(i): self.step_constraints[i].canonical()
                for i in sorted(self.step_constraints)
            },
            "policy_schema_version": POLICY_SCHEMA_VERSION,
            "constraint_registry_version": CONSTRAINT_REGISTRY_VERSION,
        }

    def digest(self) -> str:
        """Return the SHA-256 hex digest of the canonical policy artefact."""
        return hashlib.sha256(canonical_bytes(self._canonical_dict())).hexdigest()

    def to_json(self) -> str:
        """Return an indented JSON view for the record and for display."""
        return json.dumps(self._canonical_dict(), indent=2)


def default_p1() -> Policy:
    """Return the frozen, validated Policy P1 for the booking use case."""
    return Policy(
        policy_id="P1",
        task="Book a hand-luggage flight to FRA within a 400 EUR budget and pay once.",
        allowed_flow=("search", "select", "book", "pay"),
        max_executions={"search": 1, "select": 1, "book": 1, "pay": 1},
        budget_minor=40000,
        currency="EUR",
        step_constraints={3: budget_ceiling()},
    )
