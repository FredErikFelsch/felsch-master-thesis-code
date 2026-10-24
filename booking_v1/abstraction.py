"""The authority abstraction alpha_1, as a policy- and step-indexed family.

    V0    alpha_0(a)     = tool(a)
    V1    alpha_{P,i}(a) = ( tool(a), k_{P,i}(a) )

k_{P,i} is the local constraint bound to step i of policy P, evaluated through the
trusted constraint registry, and true by default when step i has no constraint.

This module gives the pure projection, used in the model and in tests. The monitor
does not call it directly for the decision. It evaluates the constraint inside a
fail-closed block (a constraint that raises must yield DENY, not an exception that
escapes). Keeping the projection pure and the fail-closed handling in the monitor
separates the definition of authority from the defensive handling of faults.
"""

from __future__ import annotations

from booking_v0.tools import ToolCall

from . import constraints
from .policy import Policy


def alpha1(call: ToolCall, policy: Policy, step_index: int) -> tuple[str, bool]:
    """Return the V1 authority token ``(tool, constraint_satisfied)`` at a step.

    Args:
        call: The attempted action.
        policy: The approved policy.
        step_index: The flow position the call is evaluated at.

    Returns:
        The tool name and whether the step's constraint holds. A step without
        a constraint counts as satisfied.
    """
    spec = policy.constraint_at(step_index)
    satisfied = True if spec is None else constraints.evaluate(spec, call.args, policy)
    return call.tool, satisfied
