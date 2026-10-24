"""One description of each live world, and a start-up check that refuses a half-migrated system.

Four things have to agree before a gateway may serve a live world: which counterparty it
reaches, which policy binds its steps, which tools exist in the closed vocabulary, and
which credential it holds. Each is configured in a different place and can be changed on
its own, and a system where three of the four moved fails in the middle of a run with a
message that explains nothing.

They are therefore described once, here, and checked at start-up. A mismatch is refused
before the first request rather than discovered at the third step.

    verify_configuration("duffel", policy, secrets)
      → Configuration(world, flow, policy, executor, descriptor)
      → or ConfigurationRefused, naming what disagrees

This module is also the only source of the world-to-policy mapping. The demo profile
(`booking_demo.live`) and the cluster gateway (`booking_v5.service_v5`) both read it, so
the two cannot drift apart.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from booking_v1.schema import TOOL_SCHEMAS
from booking_v4.budgets import with_deadline

from .context import RunContext, with_context
from .faults import FaultRefused, with_fault
from .effects import (BOOKING, CATALOGUE_EFFECTS, PAYMENT, EffectMap, WorldSpecError,
                      tools_of_kind, validate_effects)
from .duffel import LiveModeRefused, trusted_configuration as duffel_configuration
from .journey import Journey, journey_bindings
from .policy import pl1, pl1_with_pay_approval, pla1
from .secrets import (DUFFEL_ENV, SERPAPI_ENV, SecretSource, credentials,
                      secret_source_from_env)
from .world import Credentials, live_executor


class ConfigurationRefused(RuntimeError):
    """The configured parts do not describe one coherent system. Do not start."""


class PolicyNotAdmitted(ValueError):
    """The Authority refuses to activate a policy its deployed world cannot execute.

    A `ValueError`, so the durable Authority reports it as a classified refusal
    (`envelope: None` with a stable reason) and not as an internal error.
    """


@dataclass(frozen=True)
class WorldSpec:
    """Everything that follows from choosing a counterparty.

    `effects` classifies every tool the world serves into a canonical effect kind
    (`booking_live.effects`). It is the only place where a world's tool names meet the
    rest of the system: the observed world view, the run summary and the Authority's
    policy admission read the kind, not the name.

    `sells` follows from it: a world sells when one of its tools is a PAYMENT. World A is
    a search service, so a flow with a payment step is refused, not merely warned about.
    """

    name: str
    flow: tuple[str, ...]
    policy: Callable[[], Any]
    approved_policy: Callable[[], Any]
    credential_env: str
    approvals: tuple[str, ...]
    effects: EffectMap
    #: Defaults the gateway fills in for absent journey fields only (`booking_live.context`).
    context: RunContext | None = None
    #: The world's plan parameters: plan.parameters -> {tool: constant
    #: bindings}. They are what the human approves beyond steps and budget, e.g. the
    #: journey of a live search. None: the world has none.
    parameters: Callable[[Mapping[str, str]], Mapping[str, tuple]] | None = None
    #: The parameters of a pre-approved (`--plan fixed`) run that names none.
    default_parameters: Callable[[], Mapping[str, str]] | None = None
    #: The adapter's own settings (label -> value). Trusted deployment configuration,
    #: not part of what the human approves.
    provider_configuration: Callable[[], Mapping[str, str]] | None = None

    @property
    def sells(self) -> bool:
        """Whether one of the world's tools is a PAYMENT."""
        return bool(tools_of_kind(self.effects, PAYMENT))


WORLDS: dict[str, WorldSpec] = {
    "duffel": WorldSpec(
        name="duffel",
        flow=("search", "select", "book", "pay_order"),
        policy=pl1,
        approved_policy=pl1_with_pay_approval,
        credential_env=DUFFEL_ENV,
        approvals=("pay_order",),
        effects={"search": None, "select": None, "book": BOOKING, "pay_order": PAYMENT},
        # Fallback for calls without a journey only. Monitored searches carry the
        # approved one (booking_live.journey).
        context=RunContext(origin="JFK", destination="FRA"),
        parameters=lambda p: {"search": journey_bindings(Journey.from_parameters(p))},
        default_parameters=lambda: Journey.default().as_parameters(),
        provider_configuration=duffel_configuration,
    ),
    "serpapi": WorldSpec(
        name="serpapi",
        flow=("search", "select"),
        policy=pla1,
        approved_policy=pla1,
        credential_env=SERPAPI_ENV,
        approvals=(),
        effects={"search": None, "select": None},
        context=RunContext(origin="MUC", destination="LHR"),
    ),
}


def _validate_worlds() -> None:
    """Check that every world classifies its whole flow with canonical kinds.

    The check runs at import, so a world added with an incomplete map does not reach a
    process that could serve it.
    """
    for spec in WORLDS.values():
        try:
            validate_effects(spec.effects, spec.flow)
        except WorldSpecError as exc:
            raise ConfigurationRefused(f"world {spec.name!r}: {exc}") from exc


_validate_worlds()

#: Tools that move value, in any described world. Derived from the effect maps, so a new
#: world's payment tool is covered without being named here.
SELLING_TOOLS = frozenset(tools_of_kind(CATALOGUE_EFFECTS, PAYMENT).union(
    *(tools_of_kind(spec.effects, PAYMENT) for spec in WORLDS.values())))


@dataclass(frozen=True)
class Configuration:
    """A coherent live configuration, and the record of it that belongs in a trace."""

    world: str
    flow: tuple[str, ...]
    policy: Any                     # None when only the world half was checked
    executor: Callable[[Any], Any]

    @property
    def descriptor(self) -> dict:
        """Return what every run record, evidence file and ledger row should carry.

        The provider confers no authority, but a trace must say which counterparty it ran
        against, since a recorded run whose world is unstated cannot be reproduced.
        """
        return {"world": self.world, "policy_id": getattr(self.policy, "policy_id", None)
                or getattr(getattr(self.policy, "base", None), "policy_id", None),
                "flow": list(self.flow)}


def world_configuration(world: str) -> dict[str, str]:
    """Return what the deployment fixes for `world`, as a viewer should see it next to a plan.

    Everything here is trusted configuration of the gateway side. None of it is in the
    policy the human approves, so the dashboard shows it in a box of its own instead of
    implying an approval that did not happen.

    Args:
        world: A key of `WORLDS`.

    Returns:
        Label -> value, provider settings first, then the generic ones.
    """
    spec = WORLDS[world]
    config = dict(spec.provider_configuration() if spec.provider_configuration else {})
    if spec.context is not None:
        c = spec.context
        config["journey defaults"] = (f"{c.origin}->{c.destination}, +{c.days_ahead} days, {c.cabin}: "
                                      "filled in for absent fields only, an approved journey always wins")
    # A statement about the controller process. The controller identity is a privileged
    # provisioner and a trust assumption, not a technical barrier.
    config["credential"] = ("held by the gateway (OpenBao, read-only role), not by the controller process "
                            "(the controller is a trusted provisioner)")
    return config


def _flow_of(policy: Any) -> tuple[str, ...]:
    """Return the step flow of a Policy or a Policy3."""
    base = getattr(policy, "base", policy)
    return tuple(getattr(base, "allowed_flow", ()))


def verify_world(world: str, source: SecretSource | None = None,
                 transport: Any = None, fault: str | None = None) -> Configuration:
    """Make the half of the check a gateway can make on its own, and build its executor.

    A gateway does not see a policy. It holds a credential, reaches a counterparty and
    executes what a token permits, and the policy lives with the Authority. This function
    therefore checks what the gateway knows: that the world is one of the described ones,
    and that the credential it needs is held. The policy half is `verify_policy`, and it
    runs where a policy exists, wherever a run is created.

    Each half is checked where the knowledge is, and both are fail-closed, so a gateway
    without a credential and a policy that does not match its world are each refused at
    their own boundary.

    Args:
        world: A key of `WORLDS`.
        source: Where the credential comes from (the environment when None).
        transport: Injected for tests, so no network is needed.
        fault: A knob of `booking_live.faults`, or None.

    Returns:
        A `Configuration` without a policy, whose executor is ready for the gateway.

    Raises:
        ConfigurationRefused: for an unknown world, a missing or non-test credential, or an
            unknown fault.
    """
    spec = WORLDS.get(world)
    if spec is None:
        raise ConfigurationRefused(
            f"unknown world {world!r}, expected one of {sorted(WORLDS)}")

    creds: Credentials = credentials(source or secret_source_from_env())
    held = creds.duffel_token if world == "duffel" else creds.serpapi_key
    if not held:
        raise ConfigurationRefused(
            f"world {world!r} needs a credential, {spec.credential_env} is not set")

    context = spec.context
    try:
        executor = live_executor(world, creds, transport)
    except LiveModeRefused as exc:
        raise ConfigurationRefused(f"world {world!r}: {exc}") from None
    if context is not None:
        # Defaults for absent journey fields only. Bound arguments pass unchanged.
        executor = with_context(executor, context)
    try:
        # Inside the deadline, so the fault sees the outcome the counterparty's answer produced.
        executor = with_fault(executor, fault, spec.effects)
    except FaultRefused as exc:
        raise ConfigurationRefused(f"world {world!r}: {exc}") from exc
    # Outermost: one dispatch never outlasts the gateway budget, so the runner's RPC (the next
    # stage out) is answered UNCERTAIN instead of timing out on a dispatch still in flight.
    executor = with_deadline(executor)
    return Configuration(world=world, flow=spec.flow, policy=None, executor=executor)


def verify_policy(world: str, policy: Any,
                  offered_tools: Sequence[str] | None = None) -> tuple[str, ...]:
    """Make the policy half of the check, which needs no credential.

    A controller that does not hold the provider credential can check this half: that
    world, policy, vocabulary and effect map describe one system. The credential half
    (`verify_world`) belongs to the process that executes, the gateway.

    Args:
        world: `"duffel"` or `"serpapi"`.
        policy: The policy the run will be activated with, `Policy` or `Policy3`.
        offered_tools: The tool names the agent is given, when there are any to check.

    Returns:
        The checked flow.

    Raises:
        ConfigurationRefused: naming what disagrees.
    """
    spec = WORLDS.get(world)
    if spec is None:
        raise ConfigurationRefused(
            f"unknown world {world!r}, expected one of {sorted(WORLDS)}")
    flow = _flow_of(policy)

    unknown = [t for t in flow if t not in TOOL_SCHEMAS]
    if unknown:
        raise ConfigurationRefused(
            f"the policy names tools outside the closed vocabulary: {unknown}")

    # What the configuration means is checked before whether it matches the table. A
    # payment step in a world with no payment endpoint gets that message rather than a
    # generic shape mismatch, and checking it first is also what makes the rule reachable.
    if not spec.sells:
        selling = [t for t in flow if t in SELLING_TOOLS]
        if selling:
            raise ConfigurationRefused(
                f"world {world!r} sells nothing, but the flow contains {selling}")

    if flow != spec.flow:
        raise ConfigurationRefused(
            f"world {world!r} expects the flow {spec.flow}, the policy declares {flow}")

    try:
        validate_effects(spec.effects, flow)
    except WorldSpecError as exc:
        raise ConfigurationRefused(f"world {world!r}: {exc}") from exc

    if offered_tools is not None:
        missing = [t for t in flow if t not in set(offered_tools)]
        if missing:
            raise ConfigurationRefused(f"the agent is never offered: {missing}")
        stale = [t for t in offered_tools if t in SELLING_TOOLS and t not in flow]
        if stale:
            raise ConfigurationRefused(
                f"the agent is offered a payment tool outside the flow: {stale}")
    return flow


def verify_configuration(world: str, policy: Any,
                         source: SecretSource | None = None,
                         offered_tools: Sequence[str] | None = None,
                         transport: Any = None) -> Configuration:
    """Check that world, policy, vocabulary and credential describe one system.

    This runs both halves: `verify_world` (credential held, executor built) and
    `verify_policy`.

    Args:
        world: `"duffel"` or `"serpapi"`.
        policy: The policy this deployment will enforce, `Policy` or `Policy3`.
        source: Where the credential comes from. The environment by default, OpenBao in
            the cluster. Any source that yields the credential will do.
        offered_tools: The tool names the agent is given, when there are any to check.
        transport: Injected for tests, so this can be exercised without a network.

    Returns:
        A `Configuration` whose executor is ready to be handed to `ExternalWorld`.

    Raises:
        ConfigurationRefused: naming what disagrees.
    """
    base = verify_world(world, source, transport)
    flow = verify_policy(world, policy, offered_tools)
    return Configuration(world=world, flow=flow, policy=policy,
                         executor=base.executor)


def admit_policy(world: str) -> Callable[[Any], None]:
    """Build the Authority's admission rule for a deployment seeded with a live `world`.

    The client-side check (`verify_configuration`) runs where a demo builds its profile.
    The Authority is where a run is activated, so it checks again, over what it alone
    knows: the world this deployment was seeded for. A policy is admitted when its flow is
    non-empty, every step is a tool the world classifies, and every step classified as
    PAYMENT requires a human approval.

    The rule does not require the flow to equal `spec.flow`, because a plan the agent
    proposed and a human approved may use a prefix or subset of the world's tools. It must
    not name a tool the deployed gateway cannot execute.

    Args:
        world: A key of `WORLDS`.

    Returns:
        A callable raising `PolicyNotAdmitted` for a policy outside the world.

    Raises:
        ConfigurationRefused: when `world` is not described.
    """
    spec = WORLDS.get(world)
    if spec is None:
        raise ConfigurationRefused(f"unknown world {world!r}, expected one of {sorted(WORLDS)}")

    def _admit(policy: Any) -> None:
        flow = _flow_of(policy)
        if not flow:
            raise PolicyNotAdmitted(f"world {world!r}: the policy declares no flow")
        foreign = [t for t in flow if t not in spec.effects]
        if foreign:
            raise PolicyNotAdmitted(
                f"world {world!r} does not serve {foreign}, it serves {sorted(spec.effects)}")
        # A step the world classifies as a payment waits for a person. Which steps pay comes from
        # the effect classification, not from a tool name. Without this check the rule would
        # hold only because the compiler of the demo marks the step.
        marked = set(getattr(policy, "approval_required_steps", ()))
        unmarked = [t for i, t in enumerate(flow) if spec.effects[t] == PAYMENT and i not in marked]
        if unmarked:
            raise PolicyNotAdmitted(
                f"world {world!r}: {unmarked} pays and the policy does not require an approval at that step")

    return _admit


def with_parameter_bindings(policy: Any, bindings_by_tool: Mapping[str, tuple]) -> Any:
    """Return `policy` (Policy or Policy3) with constant bindings prepended at the named tools.

    This is generic over worlds: the world says which bindings its parameters mean, and
    this function places them at the step where that tool runs. The result is a new,
    re-validated policy with its own digest, so the approval covers the parameters.

    Args:
        policy: The policy to extend.
        bindings_by_tool: Tool name -> bindings to prepend at that tool's step.

    Returns:
        The new policy.
    """
    base = getattr(policy, "base", policy)
    bindings = dict(base.step_bindings)
    for tool, specs in bindings_by_tool.items():
        if tool in base.allowed_flow:
            i = base.allowed_flow.index(tool)
            bindings[i] = tuple(specs) + tuple(bindings.get(i, ()))
    new_base = dataclasses.replace(base, step_bindings=bindings)
    return dataclasses.replace(policy, base=new_base) if policy is not base else new_base
