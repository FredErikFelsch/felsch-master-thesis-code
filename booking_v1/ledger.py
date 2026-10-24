"""A run ledger: the seam for persistent replay protection.

In-memory idempotency and single-activation are not enough on their own. After a
restart a local set is empty, and the same signed approval could activate a second
monitor for the same run and repeat a payment. The real fix is a durable store
with unique constraints and compare-and-swap. This module is that store's
interface, with an in-memory implementation.

The security property the ledger provides, given a shared and durable instance:

- A run_id can be activated at most once (single activation per approval run).
- A (run_id, action_id) pair can be consumed at most once (idempotent grants).

A real deployment backs this with a transactional database:

    UNIQUE(run_id)
    UNIQUE(run_id, action_id)

Sharing one RunLedger across monitor instances in this model demonstrates the
property across "restarts" within a process. Two separate in-memory ledgers do not
share state, so the guarantee holds only under the assumption that all monitor
instances use one consistent, durable ledger. Ideally the ledger write, the audit
admission and the state change commit in the same transaction. In this in-memory
model the ledger and the event log are still two separate stores, which a real
implementation would unify.
"""

from __future__ import annotations

import threading


class RunAlreadyActivated(Exception):
    """Raised when a run_id is activated a second time."""


class RunLedger:
    """A thread-safe, in-memory run ledger (a stand-in for a durable store)."""

    def __init__(self) -> None:
        """Create an empty ledger."""
        self._activated: set[str] = set()
        self._consumed: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def activate(self, run_id: str) -> None:
        """Record a run activation. Raise if the run was already activated.

        Raises:
            RunAlreadyActivated: If ``run_id`` has been activated before.
        """
        with self._lock:
            if run_id in self._activated:
                raise RunAlreadyActivated(f"run {run_id!r} was already activated")
            self._activated.add(run_id)

    def consume_action(self, run_id: str, action_id: str) -> bool:
        """Consume an action_id for a run.

        A second consumption of the same pair is refused.

        Args:
            run_id: The run the action belongs to.
            action_id: The idempotency key of the action.

        Returns:
            True if this is the first consumption, False if it is a replay.
        """
        with self._lock:
            key = (run_id, action_id)
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True
