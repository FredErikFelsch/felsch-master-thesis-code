"""Policy P3: a booking_v2 policy plus per-step manual-intervention marks.

The policy language of booking_v2 is unchanged. The additions are
``approval_required_steps``, the steps whose admission needs a human
InterventionApproval in addition to the policy checks, and one validation rule:
a step that records an unconstrained argument as a fact must be one of those
steps. The base policy object is reused unchanged. The P3 digest covers the base digest and the marks, so
the initial approval binds the intervention marks as well.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from booking_v1.constraints import referenced_tool_params
from booking_v1.freeze import canonical_bytes
from booking_v2.policy import default_p2_1, Policy, PolicyInvalid

POLICY3_SCHEMA_VERSION = "ps3-1"


@dataclass(frozen=True)
class Policy3:
    """A P3 policy: a frozen base policy plus manual-intervention marks."""

    base: Policy
    approval_required_steps: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        """Validate and sort the marks, then apply the source rule."""
        steps = tuple(self.approval_required_steps)
        n = len(self.base.allowed_flow)
        for idx in steps:
            if isinstance(idx, bool) or not isinstance(idx, int) or not (0 <= idx < n):
                raise PolicyInvalid(f"approval step index out of range: {idx!r}")
        if len(set(steps)) != len(steps):
            raise PolicyInvalid("duplicate approval step index")
        object.__setattr__(self, "approval_required_steps", tuple(sorted(steps)))
        self._require_a_source_for_every_recorded_argument(set(steps))

    def _require_a_source_for_every_recorded_argument(self, approval_steps: set[int]) -> None:
        """Require a named source for every recorded argument, or a human decision.

        Design rule: a value a policy constrains comes from the user's utterance, from
        the approval interaction, or from an observation the monitor made itself. A value
        with no such source is not admitted by default.

        An `arg_field` producer turns an argument into a fact that later steps are
        admitted against. That is sound while the same step constrains the argument,
        because the recorded value is then the checked value. Without a constraint the
        value has no observed source. The only remaining source is a manual
        intervention, whose approval binds the fragment hash and therefore these
        arguments. So the step must be marked, or the policy is rejected.

        Without this rule, an agent-proposed plan could drop a binding and keep its
        producer. The resulting policy would record an unchecked argument with full
        provenance.

        Raises:
            PolicyInvalid: If such a step is not in ``approval_steps``.
        """
        for idx, specs in self.base.step_producers.items():
            unconstrained = sorted(
                s.params["arg"] for s in specs
                if s.kind == "arg_field" and not self._constrains(idx, s.params["arg"]))
            if unconstrained and idx not in approval_steps:
                raise PolicyInvalid(
                    f"step {idx} records argument(s) {unconstrained} as facts but constrains "
                    f"none of them; such a step requires a human decision "
                    f"(approval_required_steps)")

    def _constrains(self, idx: int, arg: str) -> bool:
        """Return whether this step checks `arg` before admission, by a binding or a local rule.

        `local_at` returns one spec or None, not a tuple, unlike the other three accessors.
        """
        if any(s.params.get("arg") == arg for s in self.base.bindings_at(idx)):
            return True
        local = self.base.local_at(idx)
        return local is not None and arg in referenced_tool_params(local)

    # Delegation to the unchanged base policy.
    @property
    def allowed_flow(self):
        """Return the ordered tool names of the approved flow."""
        return self.base.allowed_flow

    @property
    def max_executions(self):
        """Return the consumable-rights cap of the base policy."""
        return self.base.max_executions

    @property
    def budget_minor(self):
        """Return the payment budget in minor currency units."""
        return self.base.budget_minor

    @property
    def currency(self):
        """Return the currency the budget is denominated in."""
        return self.base.currency

    def local_at(self, step: int):
        """Return the local constraint of a step, or None."""
        return self.base.local_at(step)

    def producers_at(self, step: int):
        """Return the fact producers of a step."""
        return self.base.producers_at(step)

    def bindings_at(self, step: int):
        """Return the cross-step bindings of a step."""
        return self.base.bindings_at(step)

    def postconditions_at(self, step: int):
        """Return the postconditions of a step."""
        return self.base.postconditions_at(step)

    def digest(self) -> str:
        """Return the P3 digest, covering the base digest and the marks."""
        return hashlib.sha256(canonical_bytes({
            "policy3_schema_version": POLICY3_SCHEMA_VERSION,
            "base_digest": self.base.digest(),
            "approval_required_steps": list(self.approval_required_steps),
        })).hexdigest()


def default_p3() -> Policy3:
    """Return P3 for the booking use case, without intervention marks.

    P3 wraps P2.1 (booking_v2.policy.default_p2_1): the offer-vs-booking drift, the
    select-reply gap, the negative price and the unconfirmed payment are closed on
    every backend that runs a Policy3. P2 (`default_p2`) stays the frozen baseline.
    Its recorded results are the ablation, not this configuration.
    """
    return Policy3(base=default_p2_1())


def p3_with_pay_approval() -> Policy3:
    """Return P3 with a manual-intervention mark on the payment step."""
    return Policy3(base=default_p2_1(), approval_required_steps=(3,))
