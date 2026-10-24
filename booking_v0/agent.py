"""The Agent port and the V0 ScriptedAgent adapter.

The agent is outside the trusted computing base. It is assumed to be fully
compromised after contact with foreign data: it may attempt any tool call in any
order with any parameters. What it may not do is manipulate the monitor, forge
the approval, or reach an effect that bypasses the monitor.

To keep V0 reproducible the agent is a fixed script. Each scenario is a list of
attempted tool calls that already encodes the agent's post-injection behaviour.
This is deterministic and needs no model API. The Agent protocol below is the
port. A real LLM agent is a second adapter behind the same port. It is added in
booking_demo, which runs against the V5 deployment.
"""

from __future__ import annotations

from typing import Protocol

from .tools import ToolCall, ToolResult


class Agent(Protocol):
    """The port every agent adapter implements.

    An agent proposes tool calls and observes their results. In V0 the script
    already encodes the agent's reaction to an injection. The monitor sits
    between ``next_call`` and any effect.
    """

    def next_call(self) -> ToolCall | None:
        """Return the next attempted tool call, or None when the agent is done."""
        ...

    def observe(self, result: ToolResult) -> None:
        """Receive the observation produced by an admitted tool call."""
        ...


class ScriptedAgent:
    """A deterministic agent that replays a fixed list of attempted calls.

    Attributes:
        name: A short scenario label.
        description: What the script models, including any injection.
    """

    def __init__(self, name: str, description: str, script: list[ToolCall]) -> None:
        """Create a scripted agent.

        Args:
            name: Scenario label, e.g. ``"benign-happy-path"``.
            description: One-line explanation of the modelled behaviour.
            script: The ordered attempted tool calls. The script is fixed. The
                monitor decides which of these actually run.
        """
        self.name = name
        self.description = description
        self._script = list(script)
        self._index = 0
        self.observations: list[ToolResult] = []

    def next_call(self) -> ToolCall | None:
        """Return the next scripted call, or None when the script is exhausted."""
        if self._index >= len(self._script):
            return None
        call = self._script[self._index]
        self._index += 1
        return call

    def observe(self, result: ToolResult) -> None:
        """Record an observation. The scripted agent does not adapt to it."""
        self.observations.append(result)
