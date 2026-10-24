"""What a human approves, and how the Authority displays it.

An approval object is built from the material the Authority acts on, not from a display
field a client sent:

    plan   the compiled policy (wire form) for one run id. Its digest is what `create_run`
           admits, so the page shows the rules the monitor will enforce
    step   one fragment the Authority refused for want of approval. Its hash is what the
           signed `InterventionApproval` binds, so the page shows the arguments it binds

The object id is a hash over the object, so an answer for one object cannot be applied to
another, and the challenge a passkey signs is derived from the object id and the decision.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping

from booking_v1.freeze import canonical_bytes, thaw
from booking_v4 import wire

PLAN = "plan"
STEP = "step"
DECISIONS = ("approve", "reject")


class ObjectInvalid(Exception):
    """The material does not form a valid approval object."""


@dataclass(frozen=True)
class ApprovalObject:
    """One thing a person decides on.

    Attributes:
        kind: PLAN or STEP.
        run_id: The run it belongs to.
        body: The Authority-held material ({"policy": wire} or {"fragment": wire}).
    """

    kind: str
    run_id: str
    body: Mapping[str, Any]

    @property
    def object_id(self) -> str:
        """The hash over kind, run id and body, which every decision is bound to."""
        return hashlib.sha256(canonical_bytes({
            "kind": self.kind, "run_id": self.run_id, "body": thaw(self.body)})).hexdigest()

    @property
    def step_index(self) -> int | None:
        """The position of the fragment in the flow (step objects only)."""
        return int(self.body["fragment"]["fragment_index"]) if self.kind == STEP else None

    @property
    def fragment_hash(self) -> str | None:
        """The hash the signed intervention approval binds (step objects only)."""
        return str(self.body["fragment"]["fragment_hash"]) if self.kind == STEP else None

    def policy(self):
        """Return the compiled policy of a plan object (digest re-checked by the wire decoder)."""
        return wire.policy_from_wire(self.body["policy"])

    def fragment(self):
        """Return the fragment of a step object (hash re-checked by the wire decoder)."""
        return wire.fragment_from_wire(self.body["fragment"])


def plan_object(policy_wire: Mapping[str, Any], run_id: str) -> ApprovalObject:
    """Build a plan approval object. The policy must decode and its digest must match.

    Args:
        policy_wire: The compiled policy in wire form.
        run_id: The run the plan is for.

    Returns:
        The approval object.

    Raises:
        ObjectInvalid: when the run id is not a string of 1 to 200 characters or the policy
            does not decode.
    """
    if not isinstance(run_id, str) or not run_id or len(run_id) > 200:
        raise ObjectInvalid("run_id must be a non-empty string of at most 200 characters")
    try:
        wire.policy_from_wire(policy_wire)
    except Exception as exc:     # WireError, PolicyInvalid and KeyError all mean "not a policy"
        raise ObjectInvalid(f"not a compiled policy: {exc}") from None
    return ApprovalObject(PLAN, run_id, {"policy": thaw(policy_wire)})


def step_object(fragment_wire: Mapping[str, Any], attempt: int = 0) -> ApprovalObject:
    """Build a step approval object. The fragment hash must match its reconstruction.

    Args:
        fragment_wire: The fragment in wire form.
        attempt: The number of earlier decisions on the same fragment. An approval that
            expired before the resubmission leaves the Authority asking again for the same
            fragment, and that second question is a new object with its own page and its
            own decision.

    Returns:
        The approval object.

    Raises:
        ObjectInvalid: when the fragment does not decode or its hash does not match.
    """
    try:
        fragment = wire.fragment_from_wire(fragment_wire)
    except Exception as exc:
        raise ObjectInvalid(f"not a fragment: {exc}") from None
    return ApprovalObject(STEP, fragment.run_id, {"fragment": thaw(fragment_wire), "attempt": int(attempt)})


def challenge_material(object_id: str, decision: str, nonce: str, expires_at: int) -> bytes:
    """Derive the challenge a passkey signs over from the object, the decision and a nonce.

    Args:
        object_id: The object the decision is for.
        decision: "approve" or "reject".
        nonce: A fresh random value.
        expires_at: When the challenge expires (seconds).

    Returns:
        The 32-byte challenge.

    Raises:
        ObjectInvalid: when the decision is unknown.
    """
    if decision not in DECISIONS:
        raise ObjectInvalid(f"decision must be one of {DECISIONS}")
    return hashlib.sha256(canonical_bytes({
        "kind": "approval-challenge", "object_id": object_id, "decision": decision,
        "nonce": nonce, "expires_at": int(expires_at)})).digest()


# --- display -------------------------------------------------------------------------

def _rule(kind: str, params: Mapping[str, Any]) -> str:
    """Render one compiled rule as a short line, in the monitor's own terms."""
    return f"{kind}(" + ", ".join(f"{k}={params[k]!r}" for k in sorted(params)) + ")"


def plan_view(obj: ApprovalObject) -> dict:
    """Render the plan as the Authority reads it from the compiled policy.

    Fixed arguments (`arg_equals_const`) are listed separately: they are the journey the
    person approves. Everything else is shown as the rule the monitor enforces.
    """
    w = obj.body["policy"]
    base = w["base"]
    approvals = set(int(s) for s in w.get("approval_required_steps", []))
    steps = []
    for i, tool in enumerate(base.get("allowed_flow", [])):
        rules = list(base.get("step_bindings", {}).get(str(i), []))
        local = base.get("step_local", {}).get(str(i))
        if local:
            rules.append(local)
        fixed = {r["params"]["arg"]: r["params"]["expected"] for r in rules if r.get("kind") == "arg_equals_const"}
        checks = [_rule(r["kind"], r.get("params", {})) for r in rules if r.get("kind") != "arg_equals_const"]
        steps.append({"index": i, "tool": tool, "approval": i in approvals,
                      "fixed": fixed, "checks": checks,
                      "max_executions": base.get("max_executions", {}).get(tool)})
    return {"kind": PLAN, "run_id": obj.run_id, "digest": w["digest"], "task": base.get("task", ""),
            "budget_minor": base.get("budget_minor"), "currency": base.get("currency"), "steps": steps}


def step_view(obj: ApprovalObject) -> dict:
    """Render the payment (or other approval-bound step) with the arguments the fragment carries."""
    f = obj.body["fragment"]
    return {"kind": STEP, "run_id": obj.run_id, "step": int(f["fragment_index"]), "tool": f["operation"],
            "arguments": dict(f["arguments"]), "fragment_hash": f["fragment_hash"],
            "policy_digest": f["policy_digest"], "attempt": int(obj.body.get("attempt", 0))}


def view(obj: ApprovalObject) -> dict:
    """Return the display form of an object, by kind."""
    return plan_view(obj) if obj.kind == PLAN else step_view(obj)
