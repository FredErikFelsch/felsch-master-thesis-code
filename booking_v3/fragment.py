"""ActionFragment: the unit of proposed execution.

A fragment is produced by the untrusted agent, so every field is a claim, not a
grant. The declared fields (facts, capability) are commitments the monitor
compares against the policy-derived values. A mismatch is denied. The
fragment_hash covers all fields canonically, so later artefacts (execution
grants, capability tokens, intervention approvals, audit events) can bind to
one proposal, arguments included, rather than to a step number that could be
proposed again.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Mapping

from booking_v1.freeze import canonical_bytes, thaw, to_canonical


class FragmentInvalid(Exception):
    """Raised when a fragment is structurally invalid (fail-closed at the door)."""


def required_facts(policy, step: int) -> tuple[str, ...]:
    """Return the sorted fact names the step's bindings read, derived from the policy.

    Args:
        policy: The policy.
        step: The step index.

    Returns:
        The sorted fact names.
    """
    names = set()
    for spec in policy.bindings_at(step):
        ref = spec.params.get("fact") or spec.params.get("price_fact") or spec.params.get("map_fact")
        if ref is not None:
            names.add(ref)
    return tuple(sorted(names))


def required_capability(policy, step: int) -> str:
    """Return the capability name the step needs, which is the operation at that flow position.

    Args:
        policy: The policy.
        step: The step index.

    Returns:
        The operation name.
    """
    return policy.allowed_flow[step]


@dataclass(frozen=True)
class ActionFragment:
    """One proposed execution unit, canonicalised and hashed at construction.

    Attributes:
        run_id: The run this proposal claims to belong to.
        fragment_index: The step it claims to execute (0-based).
        policy_digest: The policy it claims to run under.
        operation: The tool name.
        arguments: The tool arguments, canonicalised on receipt.
        action_id: The idempotency token for effectful steps (must equal
            ``arguments["action_id"]`` when that key is present).
        declared_facts: The fact names the step's bindings will read (sorted).
        declared_capability: The capability name the step needs.
        fragment_hash: SHA-256 over the canonical form of all fields above.
    """

    run_id: str
    fragment_index: int
    policy_digest: str
    operation: str
    arguments: Mapping[str, Any]
    action_id: str | None = None
    declared_facts: tuple[str, ...] = ()
    declared_capability: str = ""
    fragment_hash: str = field(init=False, default="")

    def __post_init__(self) -> None:
        """Validate the fields, canonicalise the arguments and compute ``fragment_hash``."""
        for name in ("run_id", "policy_digest", "operation"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise FragmentInvalid(f"{name} must be a non-empty string")
        if isinstance(self.fragment_index, bool) or not isinstance(self.fragment_index, int) or self.fragment_index < 0:
            raise FragmentInvalid("fragment_index must be a non-negative integer")
        if self.action_id is not None and not isinstance(self.action_id, str):
            raise FragmentInvalid("action_id must be a string or None")
        if not isinstance(self.declared_capability, str):
            raise FragmentInvalid("declared_capability must be a string")
        try:
            args = to_canonical(dict(self.arguments))
        except Exception as exc:
            raise FragmentInvalid(f"non-canonical arguments: {exc}")
        object.__setattr__(self, "arguments", args)
        declared = tuple(self.declared_facts)
        if not all(isinstance(n, str) and n for n in declared):
            raise FragmentInvalid("declared_facts must be non-empty strings")
        object.__setattr__(self, "declared_facts", tuple(sorted(declared)))
        # The separate action_id field and the schema-visible argument must agree,
        # so no later consumer can be confused about which token was consumed.
        embedded = self.arguments.get("action_id")
        if embedded is not None and embedded != self.action_id:
            raise FragmentInvalid("action_id field does not match arguments['action_id']")
        if embedded is None and self.action_id is not None:
            raise FragmentInvalid("action_id field set but absent from arguments")
        object.__setattr__(self, "fragment_hash", hashlib.sha256(canonical_bytes(self.binding())).hexdigest())

    def binding(self) -> dict:
        """Return the canonical content the fragment_hash covers."""
        return {
            "kind": "action-fragment",
            "run_id": self.run_id,
            "fragment_index": self.fragment_index,
            "policy_digest": self.policy_digest,
            "operation": self.operation,
            "arguments": thaw(self.arguments),
            "action_id": self.action_id,
            "declared_facts": list(self.declared_facts),
            "declared_capability": self.declared_capability,
        }


def honest_fragment(policy, run_id: str, step: int, arguments: Mapping[str, Any]) -> ActionFragment:
    """Build the fragment an honest agent would propose for a policy step.

    Fills operation, declared facts and capability from the policy. Adversarial
    scenarios construct ActionFragment directly with manipulated fields.

    Args:
        policy: The policy.
        run_id: The run.
        step: The step index.
        arguments: The tool arguments, including ``action_id`` for effectful tools.

    Returns:
        The fragment.
    """
    return ActionFragment(
        run_id=run_id,
        fragment_index=step,
        policy_digest=policy.digest(),
        operation=policy.allowed_flow[step],
        arguments=dict(arguments),
        action_id=arguments.get("action_id"),
        declared_facts=required_facts(policy, step),
        declared_capability=required_capability(policy, step),
    )
