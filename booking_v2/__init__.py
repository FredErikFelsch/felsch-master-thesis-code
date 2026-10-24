"""System Model V2: cross-step bindings (V2a) and provenanced facts (V2b).

V2 reuses the V1.2 machinery (lock, effect lifecycle, audit chain, ledger, clock,
signed approval) and adds a trusted fact store. A confirmed tool result produces
typed, deeply immutable, run-scoped facts that the agent cannot create or change.
A later step is admitted only if its arguments match those facts (bindings), and a
confirmed effect only advances the flow if its declared facts extract and its
postconditions hold. Otherwise the step is parked fail-closed in EFFECT_UNCERTAIN
and no fact is recorded. V2a and V2b name the two exit criteria (consistency and
provenance, see scenarios.py). The authority abstraction is state dependent:

    V1   alpha_1(a) = (tool, local_constraint_ok)
    V2   alpha_2^P(i, a, F_i) = (tool, local_constraint_ok, bindings_satisfied(a, F_i))

where F_i is the trusted fact state before step i, built only from confirmed and
validated results.
"""

__all__ = ["world", "facts", "policy", "monitor", "scenarios", "experiment"]
