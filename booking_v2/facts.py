"""Typed, provenanced facts and the producer, binding and postcondition registries.

This module holds the core of V2. A fact is a value the monitor observed from a
confirmed tool result. It is typed, deeply immutable and carries its provenance:
which tool produced it, in which step, in which run, and to which audit event it
is bound. The agent can neither create a fact nor change one. Authorisation checks
in V2 compare an agent-supplied argument against such a fact.

Three registries keep the behaviour out of the policy, as the constraint registry
did in V1. Producers extract facts from a confirmed payload. Bindings
compare a call argument against a stored fact before admission. Postconditions
compare a freshly produced fact against an earlier fact after a confirmed effect.
A policy can only select a registered kind. It cannot carry its own code.

Scope note (V2b, provenance). Provenance here means monitor-originated and
run-scoped. A fact is admitted to the store only by the monitor, only from a
confirmed tool result, and only for the current run. That is not yet source
assurance. Whether the result came from an authenticated, allow-listed
counterparty is a separate question, handled together with attestation.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from booking_v1.freeze import deep_freeze, normalize, to_canonical

# Part of the approved artefact (the policy digest covers it). Kinds are only added,
# not changed, so the version stays the same and existing digests remain valid.
# Additions are listed under FACT_REGISTRY_EXTENSION.
FACT_REGISTRY_VERSION = "fr-2"
#: Labels the additive extension of FACT_REGISTRY_VERSION. The kinds `arg_field`,
#: `arg_affordable_bounded`, `arg_equals_const`, `produced_equals_map_lookup` and
#: `produced_equals_const` were added and no existing kind changed. A policy that uses only the original kinds
#: keeps its digest and its semantics. Policy P2.1 (`policy.default_p2_1`) uses the new
#: ones. This label is recorded in the run manifest (booking_v4.manifest), not in the
#: policy digest.
FACT_REGISTRY_EXTENSION = "fr-2.1"

# The value types a fact may declare. A producer's declared type is validated
# against the actual value, so ``ftype`` is a checked invariant, not a label.
KNOWN_FTYPES = frozenset({"int", "str", "bool", "scalar", "set", "map"})


class FactTypeError(ValueError):
    """Raised when a produced value does not match its declared fact type."""


class DuplicateFact(ValueError):
    """Raised when a second value is offered for an already recorded fact name."""


def _check_ftype(ftype: str, value: Any) -> bool:
    """Return whether ``value`` matches the declared fact type ``ftype``."""
    if ftype == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if ftype == "str":
        return isinstance(value, str)
    if ftype == "bool":
        return isinstance(value, bool)
    if ftype == "set":
        return isinstance(value, frozenset)
    if ftype == "map":
        return isinstance(value, Mapping)
    if ftype == "scalar":
        return isinstance(value, (int, float, str)) and not isinstance(value, bool)
    return False


def build_value(value: Any, ftype: str) -> Any:
    """Normalise and deeply freeze a produced value and check it against ``ftype``.

    Sets are kept as frozensets of normalised scalar items. Every other value is
    run through the canonical gate, so a nested payload becomes recursively
    immutable and is known to serialise. A value that is not of its declared type,
    that is not canonical, or that carries a nested mutable component raises. The
    caller treats any exception as a post-effect integrity failure, fail-closed.

    Args:
        value: The raw value returned by a producer.
        ftype: The declared type tag, one of ``KNOWN_FTYPES``.

    Returns:
        A deeply immutable value of the declared type.

    Raises:
        FactTypeError: If the value does not match ``ftype``.
        NonCanonical: If the value is not canonical or contains a mutable nested
            component.
    """
    if ftype == "set":
        if not isinstance(value, (set, frozenset)):
            raise FactTypeError("set fact value is not a set")
        return frozenset(normalize(item) for item in value)
    frozen = deep_freeze(to_canonical(value))
    if not _check_ftype(ftype, frozen):
        raise FactTypeError(f"value {frozen!r} is not of declared type {ftype!r}")
    return frozen


@dataclass(frozen=True)
class ObservedFact:
    """A typed, deeply immutable value observed from a confirmed tool result.

    Attributes:
        name: The fact name, e.g. ``"booking_amount_minor"``.
        value: The observed value, frozen and validated against ``ftype``.
        ftype: The value type, one of ``KNOWN_FTYPES``.
        source_tool: The tool whose confirmed result produced the fact.
        producing_seq: The sequence number of the producing effect event.
        run_id: The run the fact belongs to. A fact from another run is invalid.
        fragment_id: A human-readable id of the producing fragment.
        timestamp: The trusted clock time at production.
        integrity: The record hash of the producing effect event, anchoring the
            fact in the audit chain.
    """

    name: str
    value: Any
    ftype: str
    source_tool: str
    producing_seq: int
    run_id: str
    fragment_id: str
    timestamp: int
    integrity: str

    def __post_init__(self) -> None:
        """Freeze and type-check the value."""
        # This runs on every construction, so the invariant holds even for a fact
        # built outside the monitor's own producer path.
        object.__setattr__(self, "value", build_value(self.value, self.ftype))


class FactStore:
    """The monitor's trusted store of observed facts for one run."""

    def __init__(self, run_id: str) -> None:
        """Create an empty store for ``run_id``."""
        self._run_id = run_id
        self._facts: dict[str, ObservedFact] = {}

    def put(self, fact: ObservedFact) -> None:
        """Record a fact. Facts are write-once per name within a run.

        Raises:
            ValueError: If the fact belongs to another run.
            DuplicateFact: If a fact of that name is already recorded. A second
                value is not silently ignored, so a producer collision is visible.
        """
        if fact.run_id != self._run_id:
            raise ValueError("fact run_id does not match the store")
        if fact.name in self._facts:
            raise DuplicateFact(f"fact {fact.name!r} is already recorded")
        self._facts[fact.name] = fact

    def get(self, name: str) -> ObservedFact | None:
        """Return the fact by name, or None if it has not been observed."""
        return self._facts.get(name)

    def valid(self, name: str) -> ObservedFact | None:
        """Return the fact only if it exists and belongs to this run."""
        fact = self._facts.get(name)
        if fact is None or fact.run_id != self._run_id:
            return None
        return fact

    def names(self) -> tuple[str, ...]:
        """Return the recorded fact names."""
        return tuple(sorted(self._facts))


# Producer registry.

# A producer extracts one named fact from a confirmed payload. It raises if the
# expected data is missing, which the monitor treats as a post-effect integrity
# failure (fail-closed).
Producer = Callable[[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]], tuple[str, Any, str]]


def _prod_field(params: Mapping[str, Any], payload: Mapping[str, Any], args: Mapping[str, Any]) -> tuple[str, Any, str]:
    """Record one field of the confirmed payload."""
    value = payload[params["payload_key"]]
    return params["name"], value, params.get("ftype", "scalar")


def _prod_arg_field(params: Mapping[str, Any], payload: Mapping[str, Any], args: Mapping[str, Any]) -> tuple[str, Any, str]:
    """Record the admitted argument of this step as the fact, not a field of the reply.

    Used for a value the monitor checked before admission (the selected flight, bound
    to the observed offer set by ``arg_in_fact_set``), so a reply naming another item
    cannot change the fact.
    """
    value = args[params["arg"]]
    return params["name"], value, params.get("ftype", "scalar")


def _prod_set_of_field(params: Mapping[str, Any], payload: Mapping[str, Any], args: Mapping[str, Any]) -> tuple[str, Any, str]:
    """Record the set of one field across a list in the payload."""
    items = payload[params["payload_list_key"]]
    item_key = params["item_key"]
    value = frozenset(it[item_key] for it in items)
    return params["name"], value, "set"


def _prod_map_of_fields(params: Mapping[str, Any], payload: Mapping[str, Any], args: Mapping[str, Any]) -> tuple[str, Any, str]:
    """Record a key-to-value map across a list in the payload. Duplicate keys raise."""
    items = payload[params["payload_list_key"]]
    key_field = params["key_field"]
    value_field = params["value_field"]
    value: dict[Any, Any] = {}
    for it in items:
        key = it[key_field]
        if key in value:
            # A repeated key would make the map ambiguous, so the result is
            # rejected and the effect fails its post-effect check, fail-closed.
            raise ValueError("duplicate map key")
        value[key] = it[value_field]
    return params["name"], value, "map"


_PRODUCERS: dict[str, Producer] = {
    "field": _prod_field,
    "arg_field": _prod_arg_field,
    "set_of_field": _prod_set_of_field,
    "map_of_fields": _prod_map_of_fields,
}

# Required parameter names and types per producer kind, plus the optional ones.
_PRODUCER_REQUIRED: dict[str, dict[str, type]] = {
    "field": {"name": str, "payload_key": str},
    "arg_field": {"name": str, "arg": str},
    "set_of_field": {"name": str, "payload_list_key": str, "item_key": str},
    "map_of_fields": {"name": str, "payload_list_key": str, "key_field": str, "value_field": str},
}
_PRODUCER_OPTIONAL: dict[str, dict[str, type]] = {
    "field": {"ftype": str},
    "arg_field": {"ftype": str},
}


# Binding registry (checked before admission, fail-closed).

# A binding takes its parameters, the call's arguments and the fact store.
Binding = Callable[[Mapping[str, Any], Mapping[str, Any], "FactStore"], tuple[bool, str]]


def _bind_arg_equals_fact(params: Mapping[str, Any], args: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require an argument to equal a recorded fact."""
    fact = store.valid(params["fact"])
    if fact is None:
        return False, f"required fact {params['fact']!r} is missing"
    ok = args.get(params["arg"]) == fact.value
    return ok, f"{params['arg']} must equal fact {params['fact']}"


def _bind_arg_in_fact_set(params: Mapping[str, Any], args: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require an argument to be a member of a recorded set fact."""
    fact = store.valid(params["fact"])
    if fact is None:
        return False, f"required fact {params['fact']!r} is missing"
    ok = args.get(params["arg"]) in fact.value
    return ok, f"{params['arg']} must be one of fact {params['fact']}"


def _bind_arg_affordable(params: Mapping[str, Any], args: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require the observed price of the chosen item to be within a fixed ceiling.

    This moves the budget check ahead of the irreversible booking. The price comes
    from a map fact the monitor recorded from ``search``, not from the agent.
    """
    fact = store.valid(params["price_fact"])
    if fact is None:
        return False, f"required price fact {params['price_fact']!r} is missing"
    price = fact.value.get(args.get(params["arg"]))
    if isinstance(price, bool) or not isinstance(price, int):
        return False, f"no observed price for {params['arg']}"
    ok = price <= params["ceiling"]
    return ok, f"observed price of {params['arg']} must be within {params['ceiling']}"


def _bind_arg_affordable_bounded(params: Mapping[str, Any], args: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Apply `arg_affordable` with the domain of V1's ``budget_ceiling``, ``0 <= price``.

    A negative observed price is an invalid observation and must not admit an
    irreversible booking. This is an extension kind (FACT_REGISTRY_EXTENSION).
    """
    fact = store.valid(params["price_fact"])
    if fact is None:
        return False, f"required price fact {params['price_fact']!r} is missing"
    price = fact.value.get(args.get(params["arg"]))
    if isinstance(price, bool) or not isinstance(price, int):
        return False, f"no observed price for {params['arg']}"
    ok = 0 <= price <= params["ceiling"]
    return ok, f"observed price of {params['arg']} must be within 0..{params['ceiling']}"


def _bind_arg_maps_to_const(params: Mapping[str, Any], args: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require the chosen item to map, in an observed map fact, to a fixed constant.

    Used to bind the offered currency of the chosen flight to the approved
    currency before the booking, so a price comparison later is in the right unit.
    """
    fact = store.valid(params["map_fact"])
    if fact is None:
        return False, f"required map fact {params['map_fact']!r} is missing"
    value = fact.value.get(args.get(params["arg"]))
    ok = value == params["expected"]
    return ok, f"{params['arg']} must map to {params['expected']!r} in {params['map_fact']}"


def _bind_arg_equals_const(params: Mapping[str, Any], args: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require an argument to equal a constant the human approved with the policy.

    The source of the value is the approval itself: the constant is part of the policy
    and therefore of its digest. This is an extension kind (FACT_REGISTRY_EXTENSION). Used for the journey of a live search (origin,
    destination, date, cabin), which the task fixes and untrusted content must not move.
    An absent argument is not the constant, so it is refused as well.
    """
    ok = args.get(params["arg"]) == params["expected"]
    return ok, f"{params['arg']} must equal the approved {params['expected']!r}"


_BINDINGS: dict[str, Binding] = {
    "arg_equals_fact": _bind_arg_equals_fact,
    "arg_in_fact_set": _bind_arg_in_fact_set,
    "arg_affordable": _bind_arg_affordable,
    "arg_affordable_bounded": _bind_arg_affordable_bounded,
    "arg_maps_to_const": _bind_arg_maps_to_const,
    "arg_equals_const": _bind_arg_equals_const,
}

_BINDING_REQUIRED: dict[str, dict[str, type]] = {
    "arg_equals_fact": {"arg": str, "fact": str},
    "arg_in_fact_set": {"arg": str, "fact": str},
    "arg_affordable": {"arg": str, "price_fact": str, "ceiling": int},
    "arg_affordable_bounded": {"arg": str, "price_fact": str, "ceiling": int},
    "arg_maps_to_const": {"arg": str, "map_fact": str, "expected": str},
    "arg_equals_const": {"arg": str, "expected": str},
}


# Postcondition registry (checked after a confirmed effect, fail-closed).

Postcondition = Callable[[Mapping[str, Any], Mapping[str, Any], "FactStore"], tuple[bool, str]]


def _post_produced_equals_fact(params: Mapping[str, Any], produced: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require a value the effect produced to match an earlier fact.

    This closes the gap between what the agent requested and what the tool
    confirmed. The booked flight id in the result must equal the selected flight,
    independent of what the agent asked to book.
    """
    if params["produced"] not in produced:
        return False, f"expected produced fact {params['produced']!r} is missing"
    earlier = store.valid(params["fact"])
    if earlier is None:
        return False, f"required earlier fact {params['fact']!r} is missing"
    ok = produced[params["produced"]] == earlier.value
    return ok, f"produced {params['produced']} must equal earlier fact {params['fact']}"


def _post_produced_equals_map_lookup(params: Mapping[str, Any], produced: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require a produced value to equal an earlier map fact at an earlier key fact.

    This closes the price and currency drift between the offer and the booking: the
    confirmed booking amount must be the offered price of the selected flight, and the
    confirmed booking currency the offered currency. Without it, affordability before
    the booking only bounds the offer, and a counterparty that confirms a different
    amount is paid that amount.
    """
    if params["produced"] not in produced:
        return False, f"expected produced fact {params['produced']!r} is missing"
    key = store.valid(params["key_fact"])
    table = store.valid(params["map_fact"])
    if key is None or table is None:
        return False, f"required earlier facts {params['key_fact']!r}/{params['map_fact']!r} are missing"
    if not isinstance(table.value, Mapping) or key.value not in table.value:
        return False, f"no entry for {params['key_fact']} in {params['map_fact']}"
    ok = produced[params["produced"]] == table.value[key.value]
    return ok, f"produced {params['produced']} must equal {params['map_fact']}[{params['key_fact']}]"


def _post_produced_equals_const(params: Mapping[str, Any], produced: Mapping[str, Any], store: "FactStore") -> tuple[bool, str]:
    """Require a value the effect produced to equal a policy constant.

    Used for the payment result: a confirmed ``pay`` whose reply does not say
    ``paid: true`` is not a completed payment, whatever the transport reported.
    """
    if params["produced"] not in produced:
        return False, f"expected produced fact {params['produced']!r} is missing"
    ok = produced[params["produced"]] == params["expected"]
    return ok, f"produced {params['produced']} must equal {params['expected']!r}"


_POSTCONDITIONS: dict[str, Postcondition] = {
    "produced_equals_fact": _post_produced_equals_fact,
    "produced_equals_map_lookup": _post_produced_equals_map_lookup,
    "produced_equals_const": _post_produced_equals_const,
}

_POSTCONDITION_REQUIRED: dict[str, dict[str, type]] = {
    "produced_equals_fact": {"produced": str, "fact": str},
    "produced_equals_map_lookup": {"produced": str, "map_fact": str, "key_fact": str},
    "produced_equals_const": {"produced": str, "expected": object},
}


# Declarative specs (data the policy carries).

def _readonly(params: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return a read-only copy of ``params``."""
    return MappingProxyType(dict(params))


@dataclass(frozen=True)
class ProducerSpec:
    """A declarative producer: a registered kind plus its parameters."""

    kind: str
    params: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "params", _readonly(self.params))

    def canonical(self) -> dict:
        """Return a deterministic dict form (kind plus sorted params)."""
        return {"kind": self.kind, "params": dict(sorted(self.params.items()))}


@dataclass(frozen=True)
class BindingSpec:
    """A declarative binding: a registered kind plus its parameters."""

    kind: str
    params: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "params", _readonly(self.params))

    def canonical(self) -> dict:
        """Return a deterministic dict form (kind plus sorted params)."""
        return {"kind": self.kind, "params": dict(sorted(self.params.items()))}


@dataclass(frozen=True)
class PostconditionSpec:
    """A declarative postcondition: a registered kind plus its parameters."""

    kind: str
    params: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "params", _readonly(self.params))

    def canonical(self) -> dict:
        """Return a deterministic dict form (kind plus sorted params)."""
        return {"kind": self.kind, "params": dict(sorted(self.params.items()))}


# Registration queries and spec validation.

def producer_registered(kind: str) -> bool:
    """Return whether ``kind`` is a registered producer kind."""
    return kind in _PRODUCERS


def binding_registered(kind: str) -> bool:
    """Return whether ``kind`` is a registered binding kind."""
    return kind in _BINDINGS


def postcondition_registered(kind: str) -> bool:
    """Return whether ``kind`` is a registered postcondition kind."""
    return kind in _POSTCONDITIONS


def _validate_params(kind: str, params: Mapping[str, Any], required: Mapping[str, type], optional: Mapping[str, type]) -> None:
    """Check names and types of a spec's parameters. Raise ValueError on any problem."""
    keys = set(params)
    missing = set(required) - keys
    if missing:
        raise ValueError(f"{kind!r} missing params: {sorted(missing)}")
    extra = keys - set(required) - set(optional)
    if extra:
        raise ValueError(f"{kind!r} has unknown params: {sorted(extra)}")
    for name, typ in {**required, **optional}.items():
        if name not in params:
            continue
        value = params[name]
        if typ is object:
            if isinstance(value, (dict, list, set)):
                raise ValueError(f"{kind!r} param {name!r} must be a scalar constant")
            continue
        if typ is int:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{kind!r} param {name!r} must be an int")
        elif not isinstance(value, typ) or (typ is str and not value):
            raise ValueError(f"{kind!r} param {name!r} must be a non-empty {typ.__name__}")


def validate_producer_spec(spec: ProducerSpec) -> None:
    """Validate a producer kind, its parameters and its declared type.

    Raises:
        ValueError: On the first problem found.
    """
    if not producer_registered(spec.kind):
        raise ValueError(f"unregistered producer kind: {spec.kind!r}")
    _validate_params(spec.kind, spec.params, _PRODUCER_REQUIRED[spec.kind], _PRODUCER_OPTIONAL.get(spec.kind, {}))
    ft = producer_ftype(spec)
    if ft not in KNOWN_FTYPES:
        raise ValueError(f"producer {spec.params.get('name')!r} declares unknown ftype {ft!r}")


def validate_binding_spec(spec: BindingSpec) -> None:
    """Validate a binding kind and its parameters.

    Raises:
        ValueError: On the first problem found.
    """
    if not binding_registered(spec.kind):
        raise ValueError(f"unregistered binding kind: {spec.kind!r}")
    _validate_params(spec.kind, spec.params, _BINDING_REQUIRED[spec.kind], {})


def validate_postcondition_spec(spec: PostconditionSpec) -> None:
    """Validate a postcondition kind and its parameters.

    Raises:
        ValueError: On the first problem found.
    """
    if not postcondition_registered(spec.kind):
        raise ValueError(f"unregistered postcondition kind: {spec.kind!r}")
    _validate_params(spec.kind, spec.params, _POSTCONDITION_REQUIRED[spec.kind], {})


def producer_ftype(spec: ProducerSpec) -> str:
    """Return the fact type a producer yields (for cross-checking bindings)."""
    if spec.kind == "set_of_field":
        return "set"
    if spec.kind == "map_of_fields":
        return "map"
    return spec.params.get("ftype", "scalar")


def postcondition_fact_refs(spec: PostconditionSpec) -> tuple[str, ...]:
    """Return the earlier fact names a postcondition compares against."""
    return tuple(spec.params[k] for k in ("fact", "map_fact", "key_fact") if k in spec.params)


def binding_fact_ref(spec: BindingSpec) -> str | None:
    """Return the fact name a binding depends on, or None."""
    return spec.params.get("fact") or spec.params.get("price_fact") or spec.params.get("map_fact")


# Evaluation entry points.

def run_producer(spec: ProducerSpec, payload: Mapping[str, Any], args: Mapping[str, Any] | None = None) -> tuple[str, Any, str]:
    """Extract a fact from a confirmed payload or from the admitted arguments.

    The extraction runs through the trusted producer registry. The monitor treats
    any exception as a failed post-effect check.

    Args:
        spec: The producer to run.
        payload: The confirmed payload.
        args: The frozen argument snapshot the monitor admitted for this step.

    Returns:
        The fact name, the raw value and the declared fact type.
    """
    return _PRODUCERS[spec.kind](spec.params, payload, args if args is not None else {})


def eval_binding(spec: BindingSpec, args: Mapping[str, Any], store: FactStore) -> tuple[bool, str]:
    """Evaluate a binding against arguments and the fact store.

    A missing fact makes the binding fail. The monitor treats an exception as a
    denial.

    Args:
        spec: The binding to evaluate.
        args: The call's arguments.
        store: The run's fact store.

    Returns:
        A pair (ok, description).
    """
    return _BINDINGS[spec.kind](spec.params, args, store)


def eval_postcondition(spec: PostconditionSpec, produced: Mapping[str, Any], store: FactStore) -> tuple[bool, str]:
    """Evaluate a postcondition against produced facts and the store.

    A missing fact makes the postcondition fail. The monitor treats an exception
    as a failure.

    Args:
        spec: The postcondition to evaluate.
        produced: The facts this step produced, by name.
        store: The run's fact store with the earlier facts.

    Returns:
        A pair (ok, description).
    """
    return _POSTCONDITIONS[spec.kind](spec.params, produced, store)
