"""Contract-Enforced Agent Authorisation, System Model V0 (Exact Trace).

This package is the first of the versions booking_v0 to booking_v5. It
implements the V0 system model: an untrusted agent may only propose a task-specific
authorisation policy, a trusted human approves it, and a deterministic external
reference monitor afterwards enforces the approved action sequence. Every
deviation from that sequence is denied, and no authority is amplified without a
fresh trusted approval. The harness labels its report "System Model V0.1", the
revision of V0 implemented here.

Module layout (ports and adapters):

    policy         Policy P0 data model and loader (the approved, immutable artefact).
    tools          Five mock tools plus their deterministic effects.
    abstraction    The authority abstraction alpha_0, which later versions refine.
    state_machine  Policy lifecycle as an explicit finite automaton.
    monitor        The deterministic reference monitor (the trusted core).
    approval       The trusted approval channel (freezes the policy hash).
    agent          The Agent port and a ScriptedAgent adapter for V0.
    scenarios      The frozen execution and activation scenarios.
    experiment     Harness that runs all scenarios and reports results.

The security-relevant boundary is the monitor. The agent is outside the trusted
computing base and is, in V0, a fixed script. A real LLM agent is a second
adapter behind the same port. It is added in booking_demo, which runs against the
V5 deployment.
"""

__all__ = [
    "policy",
    "tools",
    "abstraction",
    "state_machine",
    "monitor",
    "approval",
    "agent",
    "scenarios",
    "experiment",
]
