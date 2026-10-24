"""System Model V1.2: tool identity plus local parameter constraints.

V1 reuses the frozen V0 tools and agent and adds a step-indexed local constraint.
The reports label this model V1.2, the revision of V1 implemented here. The
modules below make the added check sound as part of the trusted base:

    clock        the trusted clock interface (FixedClock, SystemClock)
    ledger       run ledger for single activation and idempotent grants
    lifecycle    effect-aware states (EFFECT_PENDING, EFFECT_FAILED,
                 EFFECT_UNCERTAIN, EFFECT_RECONCILE)
    constraints  declarative specs bound to a trusted registry (approval binds the
                 declared registry version, which assumes the runtime binds it to
                 the reviewed evaluator, see constraints.py)
    schema       strict per-tool argument schemas (extra = forbid) and policy validation
    freeze       deep, canonical immutability of arguments and audit records
    approval     signed approval bound to policy, versions, tool manifest, run, window
    effects      injectable executor, admission and effect kept separate
    monitor      fail-closed ordering, idempotency, hash-chained append-only audit
    policy       declarative, versioned, validated Policy P1
    abstraction  alpha_{P,i}

The reference-monitor assumptions are complete mediation, tamper resistance and
exclusive tool access. In a single process they are assumptions, not enforced
boundaries. booking_v4 provides the isolation.
"""

__all__ = [
    "clock",
    "ledger",
    "freeze",
    "lifecycle",
    "constraints",
    "schema",
    "approval",
    "effects",
    "policy",
    "abstraction",
    "monitor",
    "scenarios",
    "experiment",
]
