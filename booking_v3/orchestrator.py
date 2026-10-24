"""The untrusted orchestrator. It transports state and schedules runners but holds no authority.

This is the honest reference implementation. It creates a fresh ephemeral
runner per fragment and threads the signed envelope from one runner to the
next. Nothing it carries is trusted by anyone: the envelope is signed, the
policy is digest-checked, the fragment is checked by the monitor. The
adversarial orchestrators of the experiment (replaying, tampering, forking,
skipping) live in the tests, where each manipulation is a scenario.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .authority import InterventionApproval
from .envelope import StateEnvelope
from .fragment import honest_fragment
from .provisioner import RunnerProvisioner
from .runner import RunnerResult


@dataclass
class OrchestrationReport:
    """The observable outcome of one orchestrated run."""

    results: list[RunnerResult] = field(default_factory=list)
    final_envelope: StateEnvelope | None = None

    @property
    def statuses(self) -> list[str]:
        """Return the status of every runner result, in order."""
        return [r.status for r in self.results]

    @property
    def runner_nos(self) -> list[int]:
        """Return the runner number of every result, in order."""
        return [r.runner_no for r in self.results]


class Orchestrator:
    """Requests one fresh runner per fragment and carries state between them.

    The orchestrator holds only a reference to the trusted provisioner. It
    can ask for runners, but the provisioner hands it no runner credential, key
    or capability.
    """

    def __init__(self, provisioner: RunnerProvisioner) -> None:
        """Create an orchestrator that spawns runners through ``provisioner``."""
        self._provisioner = provisioner

    def run(
        self,
        policy,
        s0: StateEnvelope,
        step_arguments: list[Mapping[str, Any]],
        interventions: Mapping[int, InterventionApproval] | None = None,
    ) -> OrchestrationReport:
        """Drive a run across separate ephemeral runners, one per step.

        Args:
            policy: The policy delivered to every runner.
            s0: Any signed envelope of the run, so a run can be resumed mid-flow.
            step_arguments: The arguments of the remaining steps, in order.
            interventions: Human approvals by step index.

        Returns:
            The runner results and, if every step completed, the final envelope.
        """
        interventions = dict(interventions or {})
        report = OrchestrationReport()
        envelope = s0
        for arguments in step_arguments:
            # The step comes from the envelope, not from an external counter,
            # so the same orchestrator can resume a run from any signed S_i.
            step = envelope.step_index
            fragment = honest_fragment(policy, envelope.run_id, step, arguments)
            runner = self._provisioner.spawn(fragment, envelope)
            result = runner.execute(policy, envelope, fragment, interventions.get(step))
            report.results.append(result)
            if result.status != "STEP_COMPLETED":
                return report
            envelope = result.envelope
        report.final_envelope = envelope
        return report


def happy_path_arguments() -> list[dict[str, Any]]:
    """Return the arguments of the consistent LH123 booking, as in the booking_v2 happy path."""
    return [
        {"to": "FRA"},
        {"flight": "LH123"},
        {"flight": "LH123", "action_id": "book-1"},
        {"amount_minor": 34900, "currency": "EUR", "recipient": "airline:LH", "action_id": "pay-1"},
    ]
