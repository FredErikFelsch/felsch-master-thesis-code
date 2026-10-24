"""The trusted runner provisioner: the only holder of the bootstrap.

The untrusted orchestrator's interface is "start me a runner for this
fragment on this envelope", not "give me a runner credential". The
provisioner holds the Authority's bootstrap credential, establishes the
fragment-bound runner session and injects it into the fresh runner, so the
credential exists only inside trusted components:

    Untrusted Orchestrator
        | request runner (fragment, envelope)
        v
    RunnerProvisioner            holds the bootstrap credential
        | establish_runner_session(bootstrap, run, fragment, state)
        v
    Authority
        | RunnerCredential (bound to run, fragment_hash, state_hash)
        v
    EphemeralRunner

In the attested deployments the bootstrap is replaced by attestation: a
session is established only for a runner whose measurement verifies, over
attested TLS.
"""

from __future__ import annotations

from dataclasses import dataclass

from booking_v1.clock import Clock

from .authority import Authority, HumanApprovalCredential, ProvisionerCredential
from .envelope import StateEnvelope, TrustAnchors
from .fragment import ActionFragment
from .gateway import ToolGateway
from .runner import EphemeralRunner


class RunnerProvisioner:
    """Trusted runner factory. Deployment wiring hands it the bootstrap once."""

    def __init__(self, authority: Authority, gateway: ToolGateway,
                 anchors: TrustAnchors, bootstrap: ProvisionerCredential) -> None:
        """Create a provisioner.

        Args:
            authority: The Authority that establishes runner sessions.
            gateway: The Tool Gateway every runner calls.
            anchors: The public keys runners are provisioned with.
            bootstrap: The provisioner bootstrap credential.
        """
        self._authority = authority
        self._gateway = gateway
        self._anchors = anchors
        self._bootstrap = bootstrap

    def spawn(self, fragment: ActionFragment, envelope: StateEnvelope) -> EphemeralRunner:
        """Provision one fresh runner for one fragment on one state.

        Args:
            fragment: The fragment the runner will execute.
            envelope: The signed input state.

        Returns:
            The runner, holding a session credential bound to both.
        """
        credential = self._authority.establish_runner_session(
            self._bootstrap, fragment.run_id, fragment.fragment_hash,
            envelope.state_hash)
        return EphemeralRunner(self._authority, self._gateway, self._anchors, credential)


@dataclass(frozen=True)
class Deployment:
    """One wired deployment, built by ``create_deployment``.

    The bootstrap credential exists only at construction time, inside this
    wiring and inside the provisioner it is handed to. The untrusted
    orchestrator receives only ``provisioner`` (plus the public anchors). The
    ``bootstrap`` field is deployment-side and exists so that experiment
    harnesses can play the role of a trusted runner directly. ``human`` is the
    HumanApprovalCredential, held by the approval interface. The attested
    deployments replace the construction-time bootstrap by attestation
    evidence.
    """

    authority: Authority
    gateway: ToolGateway
    anchors: TrustAnchors
    provisioner: RunnerProvisioner
    bootstrap: ProvisionerCredential
    human: HumanApprovalCredential | None = None


def create_deployment(clock: Clock, executor=None) -> Deployment:
    """Build Authority, Tool Gateway and RunnerProvisioner as one deployment.

    This is the trusted deployment factory. ``Authority.create`` mints the
    Authority together with its bootstrap and human credentials. The bootstrap
    is handed to the provisioner here and cannot be obtained from the Authority
    afterwards.

    Args:
        clock: The trusted clock for Authority and gateway.
        executor: The world executor behind the gateway, or None for the
            booking_v2 world.

    Returns:
        The wired Deployment.
    """
    authority, bootstrap, human = Authority.create(clock)
    if executor is not None:
        gateway = ToolGateway(authority.token_key(), clock, executor=executor)
    else:
        gateway = ToolGateway(authority.token_key(), clock)
    anchors = authority.anchors()
    provisioner = RunnerProvisioner(authority, gateway, anchors, bootstrap)
    return Deployment(authority=authority, gateway=gateway, anchors=anchors,
                      provisioner=provisioner, bootstrap=bootstrap, human=human)
