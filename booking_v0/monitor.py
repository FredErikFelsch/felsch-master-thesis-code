"""The deterministic reference monitor: the trusted core of System Model V0.

The monitor is the only trusted component in the data path. It mediates every
critical tool call. It is activated only against an accepted approval whose hash
matches the policy it is handed. For each attempted action it returns ALLOW or
DENY by a fixed rule and updates its own state. It reads neither tool output
nor agent reasoning and parses no natural language. Its decision
depends only on the authority abstraction alpha_0 of the action, the current
cursor and the consumption counters.

Activation guards:
    A monitor is bound to an Approval, not merely to a hash. Activation is
    refused if the approval was rejected (ApprovalRejected) or if the policy
    handed in does not reproduce the approved hash (PolicyHashMismatch). Both
    are ActivationRefused. This closes the gap between approval and enforcement
    from both sides: a rejected approval never activates, and a policy altered
    after approval never activates.

V0 enforcement rule (exact trace plus cardinality):

    1. If the instance is not ACTIVE, DENY.
    2. If alpha_0 of the action is not the tool expected at the cursor, DENY and
       terminate the instance.
    3. If the consumption budget for the tool is exhausted, DENY and terminate.
    4. Otherwise consume the right at admission, ALLOW, run the tool, advance the
       cursor. When the cursor passes the end of the flow, complete the instance.

The rule does not inspect ``call.args``. Under alpha_0 a payment
with a manipulated amount or recipient is equal to the legitimate payment, so it
is admitted at the correct sequence position. This is the boundary V0
demonstrates.

Security property (stated here as the code contract):
    Every admitted trace tau is a prefix of the approved flow C (tau <= C).
    Consequently the set of executable effects, observed under alpha_0, is a
    function of the approved policy alone and is independent of how the agent was
    influenced. Compromise can change which prefix is reached (and, in V0 only,
    the parameters of an admitted step), but not the sequence or the count of
    critical actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .abstraction import alpha0
from .approval import Approval
from .policy import Policy
from .state_machine import PolicyState, Decision, TERMINAL_STATES
from .tools import ToolCall, ToolResult, run_tool


@dataclass
class StepRecord:
    """The record of one monitor decision.

    It is appended to the log and not changed afterwards.
    """

    index: int
    tool: str
    args: dict[str, Any]
    expected: str | None
    decision: Decision
    reason: str
    state_after: PolicyState


class ActivationRefused(Exception):
    """Base class for a refusal to activate the monitor."""


class ApprovalRejected(ActivationRefused):
    """Raised when activation is attempted against a rejected approval."""


class PolicyHashMismatch(ActivationRefused):
    """Raised when the activated policy does not match the approved hash."""


class PolicyMonitor:
    """A single-instance deterministic reference monitor.

    The monitor is constructed around a policy and the approval that authorises
    it. If the approval was rejected, or if the policy does not reproduce the
    approved hash, construction fails. This closes the time-of-check to
    time-of-use gap between approval and enforcement.
    """

    def __init__(self, policy: Policy, approval: Approval) -> None:
        """Activate the monitor against an approval.

        Args:
            policy: The policy instance to enforce.
            approval: The trusted approval decision.

        Raises:
            ApprovalRejected: If the approval was not granted.
            PolicyHashMismatch: If ``policy`` does not reproduce the approved
                hash.
        """
        if not approval.approved:
            raise ApprovalRejected("cannot activate a policy whose approval was rejected")
        if policy.digest() != approval.digest:
            raise PolicyHashMismatch(
                "activated policy does not match the approved artefact"
            )
        self._policy = policy
        self._approval = approval
        self._cursor = 0
        self._remaining = dict(policy.max_executions)
        self._state = PolicyState.ACTIVE
        self._log: list[StepRecord] = []

    @property
    def state(self) -> PolicyState:
        """Return the current lifecycle state of the instance."""
        return self._state

    @property
    def log(self) -> list[StepRecord]:
        """Return the ordered list of decisions made so far."""
        return list(self._log)

    def _expected_tool(self) -> str | None:
        """Return the tool expected at the current cursor, or None if past end."""
        flow = self._policy.allowed_flow
        if self._cursor < len(flow):
            return flow[self._cursor]
        return None

    def submit(self, call: ToolCall) -> tuple[Decision, str, ToolResult | None]:
        """Mediate one attempted tool call.

        Args:
            call: The action the untrusted agent attempts.

        Returns:
            A triple of the decision, a short reason, and the tool result. The
            result is present only on ALLOW. On DENY it is None because the tool
            body never runs.
        """
        index = len(self._log)
        expected = self._expected_tool()
        observed = alpha0(call)

        # Rule 1: the instance must be active.
        if self._state in TERMINAL_STATES:
            return self._deny(
                index, call, expected,
                f"instance is {self._state.value}, not ACTIVE",
                terminal=False,
            )

        # Rule 2: the alpha_0 projection must match the expected sequence position.
        if observed != expected:
            return self._deny(
                index, call, expected,
                f"out-of-policy action: expected {expected!r}, got {observed!r}",
                terminal=True,
            )

        # Rule 3: the consumption budget must not be exceeded.
        if self._remaining.get(call.tool, 0) <= 0:
            return self._deny(
                index, call, expected,
                f"consumption budget for {call.tool!r} exhausted",
                terminal=True,
            )

        # Rule 4: admit. Parameters are not inspected in V0.
        return self._allow(index, call, expected)

    def _allow(
        self, index: int, call: ToolCall, expected: str | None
    ) -> tuple[Decision, str, ToolResult]:
        """Admit a call, consume the right at admission, run the tool, advance.

        Consumption happens at admission, before the effect runs. A repeated
        attempt therefore receives no fresh grant: the counter is already spent
        and the cursor has already advanced. This is the at-most-once stance a
        payment tool needs: a retry cannot run the effect a second time. If the
        tool body raises, the right stays spent and no step record is written.
        """
        self._remaining[call.tool] = self._remaining.get(call.tool, 0) - 1
        self._cursor += 1
        if self._cursor >= len(self._policy.allowed_flow):
            self._state = PolicyState.COMPLETED
        reason = "matches approved flow under alpha_0 (parameters not inspected in V0)"
        result = run_tool(call, injection=None)
        self._log.append(
            StepRecord(
                index=index,
                tool=call.tool,
                args=dict(call.args),
                expected=expected,
                decision=Decision.ALLOW,
                reason=reason,
                state_after=self._state,
            )
        )
        return Decision.ALLOW, reason, result

    def _deny(
        self,
        index: int,
        call: ToolCall,
        expected: str | None,
        reason: str,
        terminal: bool,
    ) -> tuple[Decision, str, None]:
        """Deny a call and, if terminal, terminate the instance."""
        if terminal and self._state not in TERMINAL_STATES:
            self._state = PolicyState.TERMINATED
        self._log.append(
            StepRecord(
                index=index,
                tool=call.tool,
                args=dict(call.args),
                expected=expected,
                decision=Decision.DENY,
                reason=reason,
                state_after=self._state,
            )
        )
        return Decision.DENY, reason, None
