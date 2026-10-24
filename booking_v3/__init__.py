"""Fragmented execution over ephemeral runners.

This package drops the in-process trust assumption of booking_v2. A run
executes as a sequence of ActionFragments, each on its own single-use runner.
The booking_v2 decision becomes a pure function over a signed StateEnvelope
(stateless monitor). A minimal persistent Authority signs every state
transition, enforces freshness, step order, idempotency and manual
intervention atomically in a pre-effect execution grant, and issues
single-use capability tokens that a Tool Gateway verifies before it calls the
world. The orchestrator that carries all of it is untrusted. booking_v3 is
the base that booking_v4 and booking_v5 deploy.

    alpha_3^P(f, S) = verify(S) and bound(f, S) and alpha_2^P(S.step, f.action, S.facts)
"""

__all__ = [
    "fragment", "envelope", "policy", "authority", "monitor",
    "gateway", "runner", "runner_attestation", "orchestrator", "provisioner",
    "scenarios", "experiment", "experiment_world",
]
