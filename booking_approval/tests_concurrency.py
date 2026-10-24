"""Parallel RPCs on the shared SQLite connection do not lose a committed run.

Run:
    python3 -m booking_approval.tests_concurrency

The first test tries to force, with events rather than timing, the interleaving that once
lost a run: B takes its pre-request snapshot, then A creates its run while B waits. Without
serialisation B's `BEGIN IMMEDIATE` failed on the shared connection and its rollback restored
the older snapshot. With the server serialised by `_serve_lock`, A cannot start before B has
finished, so the waits time out and both requests complete in turn. The check: every run
answered with an envelope is known to the live Authority and to the state a restart restores.
"""
from __future__ import annotations

import threading
import unittest

from booking_v1.approval import approve
from booking_v3.authority import Authority
from booking_v4 import wire

from .tests_gate import GateFixture, T0

WAIT = 1.0           # a hook that is not reached, because the server serialises, times out quickly


class ParallelRequestsKeepEveryCommittedRun(GateFixture):
    """Concurrent `create_run` calls leave no run behind in the live or the restored state."""

    def _create_run_message(self, run_id: str) -> dict:
        """Build a well-formed `authority.create_run` request with a valid approval."""
        approval = approve(self.policy, approver_id="fred", approval_id=f"appr-{run_id}", run_id=run_id,
                           issued_at=T0 - 60, expires_at=T0 + 3600)
        return {"v": wire.WIRE_VERSION, "method": "authority.create_run", "request_id": f"t:{run_id}",
                "params": {"policy": wire.policy_to_wire(self.policy),
                           "approval": wire.approval_to_wire(approval), "run_id": run_id}}

    def test_a_failing_second_request_does_not_revert_the_first(self):
        authority = self.server._dep.authority
        b_snapshotted, a_created, b_done = (threading.Event() for _ in range(3))
        real_export, real_put = authority.export_state, self.server._put_states
        replies: dict[str, dict] = {}
        b_paused: list[bool] = []

        def export_state():
            """B pauses once, right after its pre-request snapshot, until A has created the run."""
            state = real_export()
            if threading.current_thread().name == "B" and not b_paused:
                b_paused.append(True)
                b_snapshotted.set()
                a_created.wait(WAIT)
            return state

        def put_states():
            """A pauses after the run exists and its transaction is open, until B has failed."""
            if threading.current_thread().name == "A":
                a_created.set()
                b_done.wait(WAIT)
            return real_put()

        authority.export_state, self.server._put_states = export_state, put_states

        def request(name: str, run_id: str) -> None:
            try:
                replies[name] = self.server._serve(self._create_run_message(run_id)) or {}
            finally:
                if name == "B":
                    b_done.set()

        tb = threading.Thread(target=request, args=("B", "run-b"), name="B")
        ta = threading.Thread(target=request, args=("A", "run-a"), name="A")
        tb.start()
        self.assertTrue(b_snapshotted.wait(WAIT))
        ta.start()
        for t in (ta, tb):
            t.join(WAIT * 2)
        authority.export_state, self.server._put_states = real_export, real_put

        for name, run_id in (("A", "run-a"), ("B", "run-b")):
            self.assertIsNotNone(replies[name].get("envelope"), f"{name} was not served: {replies[name]}")
            self.assertIsNotNone(authority.status(run_id),
                                 f"{name} got an envelope but the Authority has forgotten {run_id}")
        restored = Authority.restore(self.clock, self.a_store.load_states()[0])        # what a restart sees
        for run_id in ("run-a", "run-b"):
            self.assertIsNotNone(restored.status(run_id), f"{run_id} is missing after a restart")

    def test_many_parallel_requests_all_survive_a_restart(self):
        """No forced interleaving: sixteen threads create a run each through `_serve`."""
        run_ids = [f"run-p{i}" for i in range(16)]
        replies: dict[str, dict] = {}
        threads = [threading.Thread(target=lambda r=r: replies.__setitem__(
            r, self.server._serve(self._create_run_message(r)) or {})) for r in run_ids]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        restored = Authority.restore(self.clock, self.a_store.load_states()[0])
        for run_id in run_ids:
            self.assertIsNotNone(replies[run_id].get("envelope"), f"{run_id}: {replies[run_id]}")
            self.assertIsNotNone(self.server._dep.authority.status(run_id), f"{run_id} forgotten live")
            self.assertIsNotNone(restored.status(run_id), f"{run_id} missing after a restart")


if __name__ == "__main__":
    unittest.main()
