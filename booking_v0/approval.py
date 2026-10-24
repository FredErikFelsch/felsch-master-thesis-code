"""The trusted approval channel.

In V0 the approval channel is a trusted component modelled as a simple function.
A human approver sees the exact policy artefact and either approves or rejects
it. On approval the policy hash is frozen and returned. The monitor is then
constructed against that frozen hash, so it refuses to enforce any artefact
other than the one whose hash was approved.

The function stands in for a trusted channel. It models a trusted input that
the agent cannot reach, not a piece of application logic.
"""

from __future__ import annotations

from dataclasses import dataclass

from .policy import Policy


@dataclass(frozen=True)
class Approval:
    """The result of a trusted approval decision.

    Attributes:
        policy: The approved policy artefact.
        approved: Whether the human approved it.
        digest: The frozen SHA-256 digest of the approved policy.
    """

    policy: Policy
    approved: bool
    digest: str


def approve(policy: Policy, grant: bool = True) -> Approval:
    """Approve or reject a proposed policy and freeze its hash.

    Args:
        policy: The policy the agent proposed during planning.
        grant: The trusted human decision. Defaults to True for the automated
            experiment. A real deployment sources this from the human.

    Returns:
        An Approval carrying the frozen digest. The digest is computed even on
        rejection so the record is complete, but only an approved policy is
        activated by the harness.
    """
    return Approval(policy=policy, approved=grant, digest=policy.digest())
