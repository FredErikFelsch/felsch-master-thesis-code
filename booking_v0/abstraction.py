"""The authority abstraction alpha, which each later version refines.

The monitor does not decide on a raw action. It decides on the projection of an
action under an authority abstraction alpha. The abstraction fixes which
properties of an action are security-relevant. Everything alpha discards is
invisible to enforcement.

V0 uses alpha_0, which projects an action onto its tool name alone:

    alpha_0(a) = tool(a)

Two actions with the same tool but different parameters are therefore equal
under alpha_0. This is why a payment with a manipulated amount or
recipient is admitted at the correct sequence position: it is indistinguishable
from the legitimate payment under alpha_0. The limitation follows from alpha_0,
not from an omission in the code.

Each version refines alpha. Later versions also harden the machinery around the
monitor, but the authority decision itself changes only through alpha:

    V0   alpha_0(a) = tool(a)
    V1   alpha_1(a) = (tool(a), constraints_satisfied(a))
    V2   alpha_2(a) = (tool(a), bindings_anchored(a))

Keeping alpha in one place makes this refinement a localised change and makes
the boundary of each version explicit and testable.
"""

from __future__ import annotations

from .tools import ToolCall


def alpha0(call: ToolCall) -> str:
    """Project an action onto its V0-observable authority token.

    Args:
        call: The attempted action.

    Returns:
        The tool name. Parameters are discarded because under alpha_0 they
        carry no authority.
    """
    return call.tool
