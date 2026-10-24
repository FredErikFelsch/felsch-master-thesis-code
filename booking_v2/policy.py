"""Policy P2: V1 plus per-step producers, cross-step bindings and postconditions.

P2 keeps everything from V1 (an ordered flow, per-tool counters, integer minor
units, a local budget ceiling on the payment) and adds three declarative fields
per step. Producers say which facts a confirmed step contributes. Bindings say
which arguments of a step must match earlier facts before admission.
Postconditions say which facts a confirmed step must have produced consistently
with earlier facts. All reference only registered kinds, so the policy still
carries no behaviour, and all are covered by the policy digest.

Validation is strict and total at construction. A producer with unknown or
mistyped parameters, a binding or postcondition that references a fact no earlier
step produces, a set binding on a non-set fact, an affordability binding on a
non-map fact, or two producers that emit the same fact name are all rejected here,
so an ill-formed policy cannot be constructed and therefore cannot activate.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace, dataclass, field
from types import MappingProxyType
from typing import Mapping

from booking_v1.constraints import CONSTRAINT_REGISTRY_VERSION, ConstraintSpec, budget_ceiling, validate_spec, referenced_tool_params
from booking_v1.freeze import canonical_bytes
from booking_v1.schema import TOOL_SCHEMAS

from .facts import (
    FACT_REGISTRY_VERSION, BindingSpec, PostconditionSpec, ProducerSpec,
    binding_fact_ref, postcondition_fact_refs, producer_ftype,
    validate_binding_spec, validate_postcondition_spec, validate_producer_spec,
)

POLICY_SCHEMA_VERSION = "ps-3"


class PolicyInvalid(Exception):
    """Raised when a P2 policy fails validation at construction."""


@dataclass(frozen=True)
class Policy:
    """A task-specific policy with local constraints, producers, bindings and postconditions."""

    policy_id: str
    task: str
    allowed_flow: tuple[str, ...]
    max_executions: Mapping[str, int] = field(default_factory=dict)
    budget_minor: int = 0
    currency: str = "EUR"
    step_local: Mapping[int, ConstraintSpec] = field(default_factory=dict)
    step_producers: Mapping[int, tuple[ProducerSpec, ...]] = field(default_factory=dict)
    step_bindings: Mapping[int, tuple[BindingSpec, ...]] = field(default_factory=dict)
    step_postconditions: Mapping[int, tuple[PostconditionSpec, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Freeze the mutable fields and validate. An invalid policy cannot exist."""
        object.__setattr__(self, "allowed_flow", tuple(self.allowed_flow))
        object.__setattr__(self, "max_executions", MappingProxyType(dict(self.max_executions)))
        object.__setattr__(self, "step_local", MappingProxyType(dict(self.step_local)))
        object.__setattr__(self, "step_producers", MappingProxyType({k: tuple(v) for k, v in self.step_producers.items()}))
        object.__setattr__(self, "step_bindings", MappingProxyType({k: tuple(v) for k, v in self.step_bindings.items()}))
        object.__setattr__(self, "step_postconditions", MappingProxyType({k: tuple(v) for k, v in self.step_postconditions.items()}))
        self._validate()

    def local_at(self, step: int) -> ConstraintSpec | None:
        """Return the local constraint bound to ``step``, or None."""
        return self.step_local.get(step)

    def producers_at(self, step: int) -> tuple[ProducerSpec, ...]:
        """Return the producers of ``step``."""
        return self.step_producers.get(step, ())

    def bindings_at(self, step: int) -> tuple[BindingSpec, ...]:
        """Return the bindings checked before ``step`` is admitted."""
        return self.step_bindings.get(step, ())

    def postconditions_at(self, step: int) -> tuple[PostconditionSpec, ...]:
        """Return the postconditions checked after ``step`` is confirmed."""
        return self.step_postconditions.get(step, ())

    def _validate(self) -> None:
        """Check the whole policy. Raise PolicyInvalid on the first problem."""
        if not isinstance(self.policy_id, str) or not self.policy_id:
            raise PolicyInvalid("policy_id must be a non-empty string")
        # Three ASCII capitals. The currency is shown to the approver next to every amount, so
        # free text could carry a bidirectional control, a lookalike or a second amount.
        if (not isinstance(self.currency, str)
                or re.fullmatch(r"[A-Z]{3}", self.currency, flags=re.ASCII) is None):
            raise PolicyInvalid("currency must be three ASCII capital letters")
        if isinstance(self.budget_minor, bool) or not isinstance(self.budget_minor, int) or self.budget_minor < 0:
            raise PolicyInvalid("budget_minor must be a non-negative integer")
        if not self.allowed_flow:
            raise PolicyInvalid("allowed_flow must not be empty")
        counts: dict[str, int] = {}
        for tool in self.allowed_flow:
            if tool not in TOOL_SCHEMAS:
                raise PolicyInvalid(f"unknown tool in flow: {tool!r}")
            counts[tool] = counts.get(tool, 0) + 1
        if set(self.max_executions) != set(counts):
            raise PolicyInvalid("every flow tool needs exactly one counter and no others")
        for tool, limit in self.max_executions.items():
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < counts[tool]:
                raise PolicyInvalid(f"max_executions[{tool!r}] must be an integer at least its occurrences")
        n = len(self.allowed_flow)

        def _range(idx: int) -> None:
            if isinstance(idx, bool) or not isinstance(idx, int) or not (0 <= idx < n):
                raise PolicyInvalid(f"step index out of range: {idx!r}")

        # Local constraints.
        for idx, spec in self.step_local.items():
            _range(idx)
            try:
                validate_spec(spec)
            except ValueError as exc:
                raise PolicyInvalid(str(exc))
            step_schema = TOOL_SCHEMAS[self.allowed_flow[idx]]
            if referenced_tool_params(spec) - set(step_schema.allowed()):
                raise PolicyInvalid(f"local constraint at step {idx} references unknown parameters")

        # Producers, and the fact-name to (step, ftype) map. A duplicate fact name
        # across any producers is rejected, so the store cannot face a collision.
        produced: dict[str, tuple[int, str]] = {}
        for idx, specs in self.step_producers.items():
            _range(idx)
            for s in specs:
                try:
                    validate_producer_spec(s)
                except ValueError as exc:
                    raise PolicyInvalid(str(exc))
                # An `arg_field` producer records an argument as a fact, so the argument
                # has to be one this tool takes. Bindings carry the same check (below).
                # A producer naming a parameter outside the schema would record whatever
                # the agent put there. Whether the argument is also constrained is
                # checked by booking_v3.policy.Policy3.
                if s.kind == "arg_field":
                    arg = s.params["arg"]
                    if arg not in TOOL_SCHEMAS[self.allowed_flow[idx]].allowed():
                        raise PolicyInvalid(
                            f"producer at step {idx} records unknown argument {arg!r}")
                name = s.params["name"]
                if name in produced:
                    raise PolicyInvalid(f"duplicate produced fact name: {name!r}")
                produced[name] = (idx, producer_ftype(s))

        # Bindings. A referenced fact must exist and be produced at an earlier
        # step, because producers run after admission. Set and affordability
        # bindings require the matching fact type.
        for idx, specs in self.step_bindings.items():
            _range(idx)
            for s in specs:
                try:
                    validate_binding_spec(s)
                except ValueError as exc:
                    raise PolicyInvalid(str(exc))
                arg = s.params.get("arg")
                if arg is not None and arg not in TOOL_SCHEMAS[self.allowed_flow[idx]].allowed():
                    raise PolicyInvalid(f"binding at step {idx} references unknown argument {arg!r}")
                ref = binding_fact_ref(s)
                if ref is not None:
                    if ref not in produced:
                        raise PolicyInvalid(f"binding at step {idx} references unproduced fact {ref!r}")
                    prod_step, prod_ft = produced[ref]
                    if prod_step >= idx:
                        raise PolicyInvalid(f"binding at step {idx} references fact {ref!r} not produced earlier")
                    if s.kind == "arg_in_fact_set" and prod_ft != "set":
                        raise PolicyInvalid(f"binding at step {idx} needs a set fact, {ref!r} is {prod_ft}")
                    if s.kind in ("arg_affordable", "arg_affordable_bounded", "arg_maps_to_const") and prod_ft != "map":
                        raise PolicyInvalid(f"binding at step {idx} needs a map fact, {ref!r} is {prod_ft}")
                # A budget ceiling must be the policy budget, and a bound currency
                # must be the policy currency, so the digest cannot drift from the
                # approved values.
                if s.kind in ("arg_affordable", "arg_affordable_bounded") and s.params["ceiling"] != self.budget_minor:
                    raise PolicyInvalid(f"affordability ceiling at step {idx} must equal budget_minor")
                if s.kind == "arg_maps_to_const" and s.params["expected"] != self.currency:
                    raise PolicyInvalid(f"currency binding at step {idx} must equal the policy currency")

        # Postconditions. The produced fact must come from this step, and the
        # compared fact from an earlier step.
        for idx, specs in self.step_postconditions.items():
            _range(idx)
            for s in specs:
                try:
                    validate_postcondition_spec(s)
                except ValueError as exc:
                    raise PolicyInvalid(str(exc))
                prod = s.params["produced"]
                if prod not in produced or produced[prod][0] != idx:
                    raise PolicyInvalid(f"postcondition at step {idx} needs a fact produced at that step, got {prod!r}")
                for ref in postcondition_fact_refs(s):
                    if ref not in produced or produced[ref][0] >= idx:
                        raise PolicyInvalid(f"postcondition at step {idx} references fact {ref!r} not produced earlier")
                if s.kind == "produced_equals_map_lookup" and produced[s.params["map_fact"]][1] != "map":
                    raise PolicyInvalid(f"postcondition at step {idx} needs a map fact, {s.params['map_fact']!r} is not one")

    def _canonical(self) -> dict:
        """Return the canonical dict that the digest covers."""
        return {
            "policy_id": self.policy_id,
            "task": self.task,
            "allowed_flow": list(self.allowed_flow),
            "max_executions": dict(sorted(self.max_executions.items())),
            "budget_minor": self.budget_minor,
            "currency": self.currency,
            "step_local": {str(i): self.step_local[i].canonical() for i in sorted(self.step_local)},
            "step_producers": {str(i): [p.canonical() for p in self.step_producers[i]] for i in sorted(self.step_producers)},
            "step_bindings": {str(i): [b.canonical() for b in self.step_bindings[i]] for i in sorted(self.step_bindings)},
            "step_postconditions": {str(i): [p.canonical() for p in self.step_postconditions[i]] for i in sorted(self.step_postconditions)},
            "policy_schema_version": POLICY_SCHEMA_VERSION,
            "constraint_registry_version": CONSTRAINT_REGISTRY_VERSION,
            "fact_registry_version": FACT_REGISTRY_VERSION,
        }

    def digest(self) -> str:
        """Return the SHA-256 hex digest of the canonical policy artefact."""
        return hashlib.sha256(canonical_bytes(self._canonical())).hexdigest()

    def to_json(self) -> str:
        """Return an indented JSON view for the record and for display."""
        return json.dumps(self._canonical(), indent=2)


def default_p2() -> Policy:
    """Return the frozen Policy P2 for the booking use case."""
    return Policy(
        policy_id="P2",
        task="Book a flight to FRA within a 400 EUR budget and pay once, consistently across steps.",
        allowed_flow=("search", "select", "book", "pay"),
        max_executions={"search": 1, "select": 1, "book": 1, "pay": 1},
        budget_minor=40000,
        currency="EUR",
        step_local={3: budget_ceiling()},
        step_producers={
            0: (
                ProducerSpec("set_of_field", {"name": "offer_flight_ids", "payload_list_key": "offers", "item_key": "flight_id"}),
                ProducerSpec("map_of_fields", {"name": "offer_prices", "payload_list_key": "offers", "key_field": "flight_id", "value_field": "price_minor"}),
                ProducerSpec("map_of_fields", {"name": "offer_currencies", "payload_list_key": "offers", "key_field": "flight_id", "value_field": "currency"}),
            ),
            1: (ProducerSpec("field", {"name": "selected_flight_id", "payload_key": "selected_flight_id", "ftype": "str"}),),
            2: (
                ProducerSpec("field", {"name": "booking_flight_id", "payload_key": "flight_id", "ftype": "str"}),
                ProducerSpec("field", {"name": "booking_amount_minor", "payload_key": "price_minor", "ftype": "int"}),
                ProducerSpec("field", {"name": "booking_currency", "payload_key": "currency", "ftype": "str"}),
                ProducerSpec("field", {"name": "booking_recipient", "payload_key": "recipient", "ftype": "str"}),
            ),
        },
        step_bindings={
            1: (BindingSpec("arg_in_fact_set", {"arg": "flight", "fact": "offer_flight_ids"}),),
            2: (
                BindingSpec("arg_equals_fact", {"arg": "flight", "fact": "selected_flight_id"}),
                BindingSpec("arg_maps_to_const", {"arg": "flight", "map_fact": "offer_currencies", "expected": "EUR"}),
                BindingSpec("arg_affordable", {"arg": "flight", "price_fact": "offer_prices", "ceiling": 40000}),
            ),
            3: (
                BindingSpec("arg_equals_fact", {"arg": "amount_minor", "fact": "booking_amount_minor"}),
                BindingSpec("arg_equals_fact", {"arg": "currency", "fact": "booking_currency"}),
                BindingSpec("arg_equals_fact", {"arg": "recipient", "fact": "booking_recipient"}),
            ),
        },
        step_postconditions={
            2: (PostconditionSpec("produced_equals_fact", {"produced": "booking_flight_id", "fact": "selected_flight_id"}),),
        },
    )


def default_p2_1() -> Policy:
    """Return Policy P2.1: P2 plus bindings that tie the booking to the observed offer.

    P2 (`default_p2`) stays frozen, because V3 to V5 and every recorded result carry its
    digest. P2.1 uses the extension kinds (facts.FACT_REGISTRY_EXTENSION) and closes,
    in-process:

    * The selected flight is the admitted argument (already bound to the observed
      offer set), not the flight the select reply names (`arg_field`).
    * The confirmed booking amount and currency must be the offered ones of the
      selected flight (`produced_equals_map_lookup`), so a counterparty that confirms
      a different amount is not paid that amount.
    * A negative observed price is not affordable (`arg_affordable_bounded`).
    * A confirmed `pay` must say `paid: true` (`produced_equals_const`).

    P2.1 does not establish who the counterparty is. A plausible, well-typed recipient
    of the counterparty's choosing still becomes a fact (source assurance). `tests.py`
    pins that limit.
    """
    p2 = default_p2()
    producers = dict(p2.step_producers)
    producers[1] = (ProducerSpec("arg_field", {"name": "selected_flight_id", "arg": "flight", "ftype": "str"}),)
    producers[3] = (ProducerSpec("field", {"name": "payment_paid", "payload_key": "paid", "ftype": "bool"}),)
    bindings = dict(p2.step_bindings)
    bindings[2] = tuple(
        BindingSpec("arg_affordable_bounded", dict(b.params)) if b.kind == "arg_affordable" else b
        for b in p2.step_bindings[2])
    posts = dict(p2.step_postconditions)
    posts[2] = p2.step_postconditions[2] + (
        PostconditionSpec("produced_equals_map_lookup", {"produced": "booking_amount_minor", "map_fact": "offer_prices", "key_fact": "selected_flight_id"}),
        PostconditionSpec("produced_equals_map_lookup", {"produced": "booking_currency", "map_fact": "offer_currencies", "key_fact": "selected_flight_id"}),
    )
    posts[3] = (PostconditionSpec("produced_equals_const", {"produced": "payment_paid", "expected": True}),)
    return replace(p2, policy_id="P2.1",
                   task=p2.task + " The booking must confirm the offered price, the payment must confirm.",
                   step_producers=producers, step_bindings=bindings, step_postconditions=posts)
