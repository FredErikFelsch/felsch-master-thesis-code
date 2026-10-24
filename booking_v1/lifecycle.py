"""The V1.2 policy lifecycle, made effect-aware.

The cursor must not reach COMPLETED before the tool has actually run, otherwise a
failed effect could still be reported as a completed flow. The lifecycle therefore
separates the authorisation decision from the effect outcome. The right is granted
at admission (at-most-once grant), but the flow only advances on a confirmed effect.

    ACTIVE --admit--> EFFECT_PENDING --confirmed--> ACTIVE or COMPLETED
                                     --failed-----> EFFECT_FAILED    (terminal)
                                     --uncertain--> EFFECT_UNCERTAIN (terminal)
                                     --report contradicts the gateway ledger-->
                                                    EFFECT_RECONCILE (terminal)
    ACTIVE --deny--> TERMINATED (terminal)
    (activation) --> ACTIVE, or refused before ACTIVE

EFFECT_FAILED means it is certain no effect happened (for example a synchronous
rejection). The flow stops. A retry, if any, is a policy decision made outside
the monitor. EFFECT_UNCERTAIN means the outcome is unknown (for example a payment
timeout). It requires reconciliation or a human decision, not an automatic
retry, because a blind retry could pay twice. EFFECT_RECONCILE is set by
booking_v3.authority, not by the V1 monitor.
"""

from __future__ import annotations

from enum import Enum

# The decision type is shared with V0 and re-exported from here.
from booking_v0.state_machine import Decision

__all__ = ["Decision", "PolicyState", "TERMINAL_STATES"]


class PolicyState(str, Enum):
    """The lifecycle states of one policy instance in V1.2."""

    PLANNING = "PLANNING"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTIVE = "ACTIVE"
    EFFECT_PENDING = "EFFECT_PENDING"
    COMPLETED = "COMPLETED"
    TERMINATED = "TERMINATED"
    REJECTED = "REJECTED"
    EFFECT_FAILED = "EFFECT_FAILED"
    EFFECT_UNCERTAIN = "EFFECT_UNCERTAIN"
    #: The effect committed, but the runner's report did not match the gateway's
    #: record (set by booking_v3.authority). Unlike EFFECT_UNCERTAIN the outcome is
    #: known. The run is parked until a person reconciles it.
    EFFECT_RECONCILE = "EFFECT_RECONCILE"


# States in which the instance is finished and accepts no further action.
TERMINAL_STATES: frozenset[PolicyState] = frozenset(
    {
        PolicyState.COMPLETED,
        PolicyState.TERMINATED,
        PolicyState.REJECTED,
        PolicyState.EFFECT_FAILED,
        PolicyState.EFFECT_UNCERTAIN,
        PolicyState.EFFECT_RECONCILE,
    }
)
