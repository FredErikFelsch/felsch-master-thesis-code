"""The Authority's listener does not serve `create_run` before the gate is installed.

Run:
    python3 -m booking_approval.tests_surface_window

`booking_approval.service.start` opens the Authority's TCP listener inside `start_authority`
and installs the approval gate afterwards. The closed methods are passed to `start_authority`,
so they are refused from the moment the listener is bound. The test hooks
`ApprovalGate.install`, so a request arrives deterministically between the two steps. The
other tests check that the bare Authority role needs an explicit `--no-approval-gate`, and
that a gate refuses to be installed on a listener that was opened without the closed methods
(`install(require_preclosed=True)`).
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v3.policy import p3_with_pay_approval
from booking_v4 import wire
from booking_v4.services import _call
from booking_v5 import service_v5
from booking_v5.tests_v5_fixtures import FREEZE, STAMP

from . import service as approval_service
from .credentials import CredentialSet
from .gate import ApprovalGate
from .softauthn import SoftwareAuthenticator

T0 = 1_700_000_010


class TheListenerIsNeverOpenBeforeTheFilter(unittest.TestCase):
    """No request reaches `create_run` between the listener opening and the gate installing."""

    def setUp(self):
        from booking_v5.binding import PROTOCOL_VERSION
        self.tmp = tempfile.mkdtemp(prefix="approval-window-")
        freeze = json.loads((FREEZE / f"freeze-{STAMP}.json").read_text())
        freeze["binding_version"] = PROTOCOL_VERSION.decode()
        freeze_path = os.path.join(self.tmp, "freeze.json")
        with open(freeze_path, "w", encoding="utf-8") as fh:
            json.dump(freeze, fh)
        self.a_db = os.path.join(self.tmp, "authority.db")
        service_v5.seed(self.a_db, os.path.join(self.tmp, "gateway.db"), freeze_path, FixedClock(T0))
        self.policy = p3_with_pay_approval()
        self.clock = FixedClock(T0)

    def _create_run(self, endpoint, run_id: str) -> dict:
        """Call `authority.create_run` with an approval minted by whoever holds the module-level key."""
        approval = approve(self.policy, approver_id="mallory", approval_id=f"A-{run_id}", run_id=run_id,
                           issued_at=T0 - 10, expires_at=T0 + 3600)
        try:
            return _call(endpoint, "authority.create_run", {
                "policy": wire.policy_to_wire(self.policy), "approval": wire.approval_to_wire(approval),
                "run_id": run_id})
        except wire.WireError as exc:
            return {"error": str(exc)}

    def test_no_create_run_between_listener_and_install(self):
        creds = CredentialSet((SoftwareAuthenticator.generate().credential("fred", kind="passkey"),))
        cpath = os.path.join(self.tmp, "creds.json")
        creds.save(cpath)
        seen: dict = {}
        real_install = ApprovalGate.install

        def install_after_a_request(gate, **kwargs):
            """Send the request of a local peer that connects right after the listener opened."""
            seen["reply"] = self._create_run(gate._server.endpoint, "run-window")
            return real_install(gate, **kwargs)

        with mock.patch.object(ApprovalGate, "install", install_after_a_request):
            server, store, _gate, surface, astore = approval_service.start(
                self.a_db, ("127.0.0.1", 0), ("127.0.0.1", 0), cpath, self.clock,
                verifier_factory=lambda: object())
        try:
            self.assertIn("requires the approval surface", seen["reply"].get("error", ""),
                          f"create_run was served before the gate was installed: {seen['reply']}")
            self.assertIsNone(server._dep.authority.status("run-window"))
        finally:
            surface.close()
            server.close()
            store.close()
            astore.close()

    def test_the_authority_role_cli_refuses_to_start_without_the_gate(self):
        """The bare role is a test configuration and must be asked for explicitly."""
        import contextlib
        import io
        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(io.StringIO()):
            service_v5.main(["serve", "--role", "authority", "--db", self.a_db, "--bind", "127.0.0.1:0"])
        self.assertIn("test configuration", str(caught.exception))

    def test_a_gate_cannot_be_installed_on_a_listener_that_was_open_before(self):
        server, store = service_v5.start_authority(self.a_db, ("127.0.0.1", 0), self.clock,
                                                   verifier_factory=lambda: object())
        creds = CredentialSet((SoftwareAuthenticator.generate().credential("fred", kind="passkey"),))
        from .store import ApprovalStore
        astore = ApprovalStore(os.path.join(self.tmp, "approval.db"))
        try:
            gate = ApprovalGate(server, astore, creds, self.clock)
            with self.assertRaises(RuntimeError):
                gate.install(require_preclosed=True)
        finally:
            server.close()
            store.close()
            astore.close()


if __name__ == "__main__":
    unittest.main()
