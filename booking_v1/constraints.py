"""Declarative constraints bound to a trusted registry.

A constraint that carried its own ``satisfied`` method would make the policy
object carry behaviour. Two constraints could then produce the same canonical form
yet decide oppositely, and the policy hash would not distinguish them. A
constraint in a policy is therefore pure data, a ``ConstraintSpec`` of a registered
kind and its parameters. The behaviour lives in a single trusted registry, keyed by
kind, so a policy cannot carry its own evaluator. It can only select a
registered kind.

Scope of the binding: the approval binds the declared registry
version, under the assumption that the trusted runtime immutably binds this
version to the reviewed evaluator implementation. It does not cryptographically
bind the evaluator source. If the evaluator were swapped without bumping the
version, an approval would still verify. That is outside the threat model (which
assumes an immutable trusted base) but it is a real caveat. A stronger binding is
a hash over the signed build artefact, or later a TEE measurement of the loaded
code.

Adding a new constraint kind means registering trusted code once, under a new
kind string, and bumping the registry version.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

# Bumped whenever the set of registered kinds or their semantics changes. It is
# part of the approved artefact, so a change invalidates old approvals.
CONSTRAINT_REGISTRY_VERSION = "cr-1"


@dataclass(frozen=True)
class ConstraintSpec:
    """A declarative constraint: a registered kind plus its parameters.

    Attributes:
        kind: A key into the trusted registry, e.g. ``"budget_ceiling"``.
        params: The parameters for that kind. Kept as a read-only mapping.
    """

    kind: str
    params: Mapping[str, Any]

    def __post_init__(self) -> None:
        """Copy ``params`` into a read-only mapping."""
        object.__setattr__(self, "params", MappingProxyType(dict(self.params)))

    def canonical(self) -> dict:
        """Return a deterministic dict form (kind plus sorted params)."""
        return {"kind": self.kind, "params": dict(sorted(self.params.items()))}


# An evaluator decides a spec against an action's arguments and the policy. It
# must be a pure function of its inputs and must not raise on ordinary input. The
# monitor still wraps it fail-closed.
Evaluator = Callable[[Mapping[str, Any], Mapping[str, Any], Any], bool]
Describer = Callable[[Mapping[str, Any], Any], str]


def _budget_ceiling_eval(params: Mapping[str, Any], args: Mapping[str, Any], policy: Any) -> bool:
    """Return whether the amount is a non-negative integer within the budget, in the policy currency."""
    amount_param = params["amount_param"]
    currency_param = params["currency_param"]
    if args.get(currency_param) != policy.currency:
        return False
    value = args.get(amount_param)
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return 0 <= value <= policy.budget_minor


def _budget_ceiling_describe(params: Mapping[str, Any], policy: Any) -> str:
    """Return the bound as text, for example ``amount_minor in [0, 40000] EUR``."""
    return f"{params['amount_param']} in [0, {policy.budget_minor}] {policy.currency}"


# The trusted registry. Constraint behaviour is defined here and nowhere else in V1.
_REGISTRY: dict[str, tuple[Evaluator, Describer]] = {
    "budget_ceiling": (_budget_ceiling_eval, _budget_ceiling_describe),
}


# The required parameter names and types for each kind. Used to validate a spec
# fully at policy activation, so a spec cannot be missing or mistyped parameters.
REQUIRED_PARAM_TYPES: dict[str, dict[str, type]] = {
    "budget_ceiling": {"amount_param": str, "currency_param": str},
}


def is_registered(kind: str) -> bool:
    """Return whether ``kind`` is a known constraint kind."""
    return kind in _REGISTRY


def validate_spec(spec: "ConstraintSpec") -> None:
    """Validate a spec's kind and parameters.

    Raises:
        ValueError: If the kind is unregistered or a parameter is missing,
            unknown or of the wrong type.
    """
    if not is_registered(spec.kind):
        raise ValueError(f"unregistered constraint kind: {spec.kind!r}")
    required = REQUIRED_PARAM_TYPES.get(spec.kind, {})
    keys = set(spec.params.keys())
    missing = set(required) - keys
    if missing:
        raise ValueError(f"constraint {spec.kind!r} missing params: {sorted(missing)}")
    extra = keys - set(required)
    if extra:
        raise ValueError(f"constraint {spec.kind!r} has unknown params: {sorted(extra)}")
    for name, typ in required.items():
        value = spec.params[name]
        if not isinstance(value, typ) or (typ is str and not value):
            raise ValueError(f"constraint {spec.kind!r} param {name!r} must be a non-empty {typ.__name__}")


def referenced_tool_params(spec: "ConstraintSpec") -> frozenset[str]:
    """Return the tool-argument names a spec references (for cross-checking)."""
    if spec.kind == "budget_ceiling":
        return frozenset({spec.params["amount_param"], spec.params["currency_param"]})
    return frozenset()


def evaluate(spec: ConstraintSpec, args: Mapping[str, Any], policy: Any) -> bool:
    """Evaluate a spec against arguments and a policy via the trusted registry.

    Args:
        spec: The constraint to evaluate.
        args: The call's arguments.
        policy: The policy that supplies the bound (budget and currency).

    Returns:
        Whether the arguments satisfy the constraint.

    Raises:
        KeyError: If the kind is not registered. The monitor treats any exception
            here as fail-closed (DENY).
    """
    evaluator, _describe = _REGISTRY[spec.kind]
    return evaluator(spec.params, args, policy)


def describe(spec: ConstraintSpec, policy: Any) -> str:
    """Return a legible description of a spec under a policy.

    Args:
        spec: The constraint to describe.
        policy: The policy that supplies the bound.

    Returns:
        A short human-readable statement of the bound.
    """
    _evaluator, describer = _REGISTRY[spec.kind]
    return describer(spec.params, policy)


def budget_ceiling(amount_param: str = "amount_minor", currency_param: str = "currency") -> ConstraintSpec:
    """Return a budget-ceiling constraint spec. The bound is the policy budget.

    Args:
        amount_param: The tool argument that carries the amount in minor units.
        currency_param: The tool argument that carries the currency.

    Returns:
        A ConstraintSpec of kind ``budget_ceiling``.
    """
    return ConstraintSpec(
        kind="budget_ceiling",
        params={"amount_param": amount_param, "currency_param": currency_param},
    )
