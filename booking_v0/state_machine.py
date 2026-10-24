"""The policy lifecycle as an explicit finite automaton.

The lifecycle separates two authority regimes. In PLANNING the agent holds only
minimal rights and may propose a policy. The single authority-increasing
transition is ``approve``, which lies outside the agent's reach and moves the
instance to ACTIVE.

Inside ACTIVE authority is non-increasing. This is not stated as an inclusion of
the currently enabled actions, because the enabled action moves along
the sequence (from search to select to book to pay), and those singletons are not
nested. What is non-increasing is the remaining authority, measured either as the
multiset of remaining consumable rights (each step decrements one) or as the set
of continuations still admissible from the current state (each step removes the
ones that started with a different action). Both shrink monotonically. The only
transition that can enlarge them is a fresh trusted approval, which starts a new
instance.

Implementation status. The PLANNING and PENDING_APPROVAL states are part of the
model but are not exercised by the V0 harness. The experiment injects P0 directly
as the approved artefact and runs the trusted approval over it. A real proposal
step, where the untrusted agent authors the policy, is modelled here and
implemented in a later version.

    PLANNING --propose--> PENDING_APPROVAL --approve--> ACTIVE
                                          --reject---> REJECTED (terminal)
    ACTIVE --step (admitted)--> ACTIVE
    ACTIVE --last step admitted--> COMPLETED (terminal)
    ACTIVE --step (denied)--> TERMINATED (terminal)

A denial ends the instance. This is the strictest rule and the easiest to
reason about. Allowing a retry or a return to PLANNING would be a separate design
decision.
"""

from __future__ import annotations

from enum import Enum


class PolicyState(str, Enum):
    """The lifecycle states of one policy instance.

    PLANNING and PENDING_APPROVAL are modelled but not exercised by the V0
    harness (see the module docstring). ACTIVE onwards is fully implemented.
    """

    PLANNING = "PLANNING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    TERMINATED = "TERMINATED"
    REJECTED = "REJECTED"


# States in which the instance has finished and accepts no further action.
TERMINAL_STATES: frozenset[PolicyState] = frozenset(
    {PolicyState.COMPLETED, PolicyState.TERMINATED, PolicyState.REJECTED}
)


class Decision(str, Enum):
    """The verdict the monitor returns for one attempted action."""

    ALLOW = "ALLOW"
    DENY = "DENY"
