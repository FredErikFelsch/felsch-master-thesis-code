"""Strict tool-argument schemas (extra = forbid) and complete policy validation.

Two checks guard the boundary. First, a call could carry unknown parameters a
real tool might interpret, so every call is validated against a per-tool schema
that forbids unknown parameters and checks types. For effectful tools an
``action_id`` is required, so an idempotency key always exists. Second, an
inconsistent policy must not be accepted. The validator therefore checks that every
flow tool has one counter, no counter exists for a non-flow tool,
constraint indices are in range and not booleans, every constraint kind is
registered and its parameters validate, and each constraint only references
parameters that exist in its step's tool schema.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import constraints


class PolicyInvalid(Exception):
    """Raised when a policy fails validation at construction or activation."""


@dataclass(frozen=True)
class ArgSchema:
    """A strict schema for one tool's arguments (extra = forbid)."""

    required: frozenset[str]
    types: Mapping[str, type]
    optional: frozenset[str] = field(default_factory=frozenset)

    def allowed(self) -> frozenset[str]:
        """Return every accepted parameter name."""
        return self.required | self.optional

    def validate(self, args: Mapping[str, Any]) -> tuple[bool, str]:
        """Return (ok, reason). Unknown parameters are forbidden."""
        keys = set(args.keys())
        unknown = keys - set(self.allowed())
        if unknown:
            return False, f"unknown parameters: {sorted(unknown)}"
        missing = set(self.required) - keys
        if missing:
            return False, f"missing parameters: {sorted(missing)}"
        for name, value in args.items():
            expected = self.types.get(name)
            if expected is None:
                continue
            if expected is int and isinstance(value, bool):
                return False, f"parameter {name!r} must be int, not bool"
            if not isinstance(value, expected):
                return False, f"parameter {name!r} must be {expected.__name__}"
        return True, "arguments match the tool schema"


# The single source of truth for which tools produce an external, not freely
# repeatable effect (book, pay, pay_order, restart_deployment). Effectful tools
# require an action_id. Reads accept it optionally. The requirement is derived
# from this set below, so the classification and the schema cannot drift apart. A hash of the
# resulting manifest is part of the approved artefact.
EFFECTFUL_TOOLS: frozenset[str] = frozenset({"book", "pay", "pay_order", "restart_deployment"})

# Bound on an idempotency key so it stays a sane external key.
MAX_ACTION_ID_LEN = 200

# Base argument contracts, before the action_id rule is applied.
#
# This is the closed tool vocabulary: a policy can only name a tool listed here, and a
# fragment for any other tool fails schema validation before the monitor evaluates a
# single rule. Two applications share the registry: the booking desk
# (search, select, book, pay) and the on-call cluster agent (list_deployments,
# restart_deployment). Adding a tool changes `tool_manifest_hash()`, which every
# approval binds.
#
# `pay_order` serves the live world. A real provider settles an order and derives the
# payee from it, so `pay_order` names the order instead of a recipient. Two orders of
# the same amount stay distinguishable, which two payments of the same amount to the
# same payee are not. `pay` keeps its contract, so recorded mock runs stay valid.
#
# `search` takes three optional journey fields: `origin`, `date` (YYYY-MM-DD) and
# `cabin`. A live policy binds each one to the approved value with `arg_equals_const`,
# so the agent cannot change the journey. They are optional so that every catalogue
# fragment `search(to)` stays valid.
_BASE_SCHEMAS: dict[str, dict] = {
    "search": {"required": {"to"}, "optional": {"origin", "date", "cabin"},
               "types": {"to": str, "origin": str, "date": str, "cabin": str}},
    "select": {"required": {"flight"}, "types": {"flight": str}},
    "book": {"required": {"flight"}, "types": {"flight": str}},
    "pay": {"required": {"amount_minor", "currency", "recipient"}, "types": {"amount_minor": int, "currency": str, "recipient": str}},
    "pay_order": {"required": {"order_id", "amount_minor", "currency"}, "types": {"order_id": str, "amount_minor": int, "currency": str}},
    "read_secret": {"required": {"key"}, "types": {"key": str}},
    "list_deployments": {"required": {"namespace"}, "types": {"namespace": str}},
    "restart_deployment": {"required": {"name"}, "types": {"name": str}},
}


def _build_schemas() -> dict[str, ArgSchema]:
    """Build the tool schemas, deriving the action_id rule from EFFECTFUL_TOOLS."""
    schemas: dict[str, ArgSchema] = {}
    for tool, base in _BASE_SCHEMAS.items():
        types = {**base["types"], "action_id": str}
        declared_optional = frozenset(base.get("optional", ()))
        if tool in EFFECTFUL_TOOLS:
            required = frozenset(base["required"] | {"action_id"})
            optional = declared_optional
        else:
            required = frozenset(base["required"])
            optional = declared_optional | {"action_id"}
        schemas[tool] = ArgSchema(required=required, types=types, optional=optional)
    return schemas


TOOL_SCHEMAS: dict[str, ArgSchema] = _build_schemas()


def tool_manifest_hash() -> str:
    """Return a stable hash over the tool schemas and the effectful classification."""
    manifest = {
        tool: {
            "required": sorted(s.required),
            "optional": sorted(s.optional),
            "types": {k: v.__name__ for k, v in sorted(s.types.items())},
            "effectful": tool in EFFECTFUL_TOOLS,
        }
        for tool, s in sorted(TOOL_SCHEMAS.items())
    }
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_args(tool: str, args: Mapping[str, Any]) -> tuple[bool, str]:
    """Validate a tool call's arguments against its schema (extra = forbid).

    Also enforces that an action_id, when present, is a non-empty, bounded string,
    so an idempotency key is always a usable external key.

    Args:
        tool: The tool name.
        args: The call's arguments.

    Returns:
        A pair (ok, reason).
    """
    schema = TOOL_SCHEMAS.get(tool)
    if schema is None:
        return False, f"no schema for tool {tool!r}"
    ok, reason = schema.validate(args)
    if not ok:
        return ok, reason
    action_id = args.get("action_id")
    if action_id is not None:
        if not action_id or len(action_id) > MAX_ACTION_ID_LEN:
            return False, "action_id must be a non-empty string within the length bound"
    return True, reason


def validate_policy(policy: Any) -> None:
    """Validate a policy fully.

    Raises:
        PolicyInvalid: On the first problem found.
    """
    if not isinstance(policy.policy_id, str) or not policy.policy_id:
        raise PolicyInvalid("policy_id must be a non-empty string")
    if not isinstance(policy.task, str):
        raise PolicyInvalid("task must be a string")
    if not isinstance(policy.currency, str) or not policy.currency:
        raise PolicyInvalid("currency must be a non-empty string")
    if isinstance(policy.budget_minor, bool) or not isinstance(policy.budget_minor, int):
        raise PolicyInvalid("budget_minor must be an integer")
    if policy.budget_minor < 0:
        raise PolicyInvalid("budget_minor must be non-negative")
    if not policy.allowed_flow:
        raise PolicyInvalid("allowed_flow must not be empty")

    for tool in policy.allowed_flow:
        if tool not in TOOL_SCHEMAS:
            raise PolicyInvalid(f"unknown tool in flow: {tool!r}")

    # Counters: every flow tool has one counter, and no other tool has one.
    counts: dict[str, int] = {}
    for tool in policy.allowed_flow:
        counts[tool] = counts.get(tool, 0) + 1
    flow_tools = set(counts)
    counter_tools = set(policy.max_executions)
    missing_counters = flow_tools - counter_tools
    if missing_counters:
        raise PolicyInvalid(f"flow tools without a counter: {sorted(missing_counters)}")
    extra_counters = counter_tools - flow_tools
    if extra_counters:
        raise PolicyInvalid(f"counters for tools outside the flow: {sorted(extra_counters)}")
    for tool, limit in policy.max_executions.items():
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise PolicyInvalid(f"max_executions[{tool!r}] must be a non-negative integer")
        if limit < counts.get(tool, 0):
            raise PolicyInvalid(f"max_executions[{tool!r}]={limit} is below its {counts[tool]} occurrences")

    # Constraints: the index is in range and not a bool, the kind is registered, the
    # params are valid and the referenced parameters exist in the step's tool schema.
    n = len(policy.allowed_flow)
    for index, spec in policy.step_constraints.items():
        if isinstance(index, bool) or not isinstance(index, int) or not (0 <= index < n):
            raise PolicyInvalid(f"constraint step index out of range: {index!r}")
        try:
            constraints.validate_spec(spec)
        except ValueError as exc:
            raise PolicyInvalid(str(exc))
        step_tool = policy.allowed_flow[index]
        step_schema = TOOL_SCHEMAS.get(step_tool)
        referenced = constraints.referenced_tool_params(spec)
        unknown = referenced - set(step_schema.allowed())
        if unknown:
            raise PolicyInvalid(
                f"constraint at step {index} references parameters not in {step_tool!r}: {sorted(unknown)}"
            )
