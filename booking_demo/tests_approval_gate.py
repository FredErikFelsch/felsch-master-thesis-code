"""A whole demo run behind the Authority's approval gate.

Run:
    python3 -m booking_demo.tests_approval_gate

The V5 local chain (fake TDs in threads, real durable services on loopback, real RTMR3
replay) with `booking_approval` installed on its Authority, the Duffel profile over recorded
provider answers. The session obtains every decision at the Authority: the harness key for
`--approve auto|deny`, a person on the approval page for `--approve wait` (played here by a
thread that signs with a passkey-kind software key). The gate opens the payment's page from
the Authority's own refusal of the fragment rather than from a stand-in.
"""
from __future__ import annotations

import json
import os
import pathlib
import socket
import tempfile
import threading
import time
import unittest

from booking_approval.client import ApprovalClient, HarnessApprover
from booking_approval.credentials import CredentialSet
from booking_approval.gate import ApprovalGate
from booking_approval.softauthn import SoftwareAuthenticator
from booking_approval.store import ApprovalStore
from booking_approval.surface import ApprovalSurface
from booking_approval.webauthn import b64url_decode
from booking_live.tests_durable_live import ScriptedTransport
from booking_v1.clock import FixedClock
from booking_v4 import wire
from booking_v4.services import _call

from .chains import AttestedChain
from .mail import mail
from .session import NOW, DemoSession
from .tests_v5_duffel_composition import _agent, _answers, _profile


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class GatedRun(unittest.TestCase):
    """One local V5 chain with the gate, a harness key and a person's key pinned."""

    def setUp(self):
        self.transport = ScriptedTransport(_answers())
        self.app = _profile(self.transport)
        self.clock = FixedClock(NOW)
        self.chain = AttestedChain.local(self.clock, world=self.app.world_factory())
        dep = self.chain.deployment
        self.person = SoftwareAuthenticator.generate()
        harness = SoftwareAuthenticator.generate()
        creds = CredentialSet((self.person.credential("fred", kind="passkey"),
                               harness.credential("harness:eval", kind="harness")))
        tmp = tempfile.mkdtemp(prefix="gated-run-")
        self.store = ApprovalStore(os.path.join(tmp, "approval.db"))
        port = _free_port()
        self.url = f"http://localhost:{port}"
        self.gate = ApprovalGate(dep.authority_server, self.store, creds, self.clock, origin=self.url).install()
        self.surface = ApprovalSurface(self.gate, ("127.0.0.1", port))
        self.chain.approvals = ApprovalClient(self.chain.authority, self.url)
        self.chain.harness = HarnessApprover(self.url, harness)
        self.out = pathlib.Path(tempfile.mkdtemp(prefix="gated-demo-"))

    def tearDown(self):
        self.surface.close()
        self.chain.close()
        self.store.close()

    def run_session(self, approve_mode: str, hook=lambda req: True):
        """Run one demo session in `approve_mode`. Returns the summary and the recorded events."""
        summary = DemoSession("v5-local", _agent(), mail("clean"), self.out, approve_hook=hook,
                              chain=self.chain, profile=self.app, approve_mode=approve_mode,
                              approval_timeout=20).run()
        return summary, json.loads((self.out / "events.json").read_text())

    def person_on_the_page(self, decisions: dict):
        """A thread that answers every pending page like a person would (passkey kind)."""
        stop = threading.Event()

        def loop():
            seen = set()
            while not stop.is_set():
                for v in self.gate.pending_views():
                    oid = v["object_id"]
                    if oid in seen:
                        continue
                    seen.add(oid)
                    decision = decisions.get(v["view"]["kind"], "approve")
                    ch = self.gate.issue_challenge(oid, decision)
                    a = self.person.assertion(b64url_decode(ch["challenge"]), self.url)
                    a["challenge"] = ch["challenge"]
                    self.gate.decide(oid, decision, a)
                time.sleep(0.1)
        threading.Thread(target=loop, daemon=True).start()
        return stop


class TheHarnessDecidesUnattendedRuns(GatedRun):
    """With `--approve auto|deny` the harness key answers at the Authority."""

    def test_auto_completes_and_every_decision_is_recorded_as_harness(self):
        summary, events = self.run_session("auto")
        self.assertEqual(summary["run_status"], "COMPLETED", summary)
        plan = next(e for e in events if e["kind"] == "plan_decision")
        pay = next(e for e in events if e["kind"] == "approval")
        self.assertEqual((plan["approver"], plan["approver_kind"]), ("approver:harness:eval", "harness"))
        self.assertTrue(pay["granted"])
        self.assertEqual(pay["approver_kind"], "harness")

    def test_deny_rejects_the_payment_at_the_authority(self):
        summary, events = self.run_session("deny", hook=lambda req: False)
        self.assertNotEqual(summary["run_status"], "COMPLETED")
        pay = next(e for e in events if e["kind"] == "approval")
        self.assertFalse(pay["granted"])
        self.assertEqual(pay["authority_state"], "rejected")
        self.assertFalse(any(e.get("tool") == "pay_order" and e.get("status") == "STEP_COMPLETED"
                             for e in events if e["kind"] == "decision"))


class APersonDecidesOnThePage(GatedRun):
    """With `--approve wait` a person answers on the approval page, signing with a passkey."""

    def test_wait_shows_the_authority_page_and_records_the_passkey(self):
        stop = self.person_on_the_page({})
        try:
            summary, events = self.run_session("wait")
        finally:
            stop.set()
        self.assertEqual(summary["run_status"], "COMPLETED", summary)
        links = [e for e in events if e["kind"] == "approval_request"]
        self.assertEqual([e["subject"] for e in links], ["plan", "step"])
        self.assertTrue(all(e["url"].startswith(self.url + "/approve/") for e in links))
        pay = next(e for e in events if e["kind"] == "approval")
        self.assertEqual((pay["approver"], pay["approver_kind"]), ("approver:fred", "passkey"))

    def test_the_payment_page_shows_the_fragment_the_authority_refused(self):
        seen = {}
        orig = self.gate.decide

        def spy(oid, decision, assertion, ttl=None):
            seen[oid] = self.gate.object_view(oid)["view"]
            return orig(oid, decision, assertion, ttl)
        self.gate.decide = spy
        stop = self.person_on_the_page({})
        try:
            summary, events = self.run_session("wait")
        finally:
            stop.set()
        step = next(v for v in seen.values() if v["kind"] == "step")
        pay_proposal = [e for e in events if e["kind"] == "proposal" and e["tool"] == "pay_order"][-1]
        self.assertEqual(step["tool"], "pay_order")
        self.assertEqual(step["arguments"]["order_id"], pay_proposal["arguments"]["order_id"])


class TheControllerCannotBypassTheGate(GatedRun):
    """Behind the gate the controller cannot open a run without a decision."""

    def test_create_run_with_the_hmac_constant_is_refused(self):
        from booking_v1.approval import approve
        from booking_live.policy import pl1_with_pay_approval
        policy = pl1_with_pay_approval()
        approval = approve(policy, approver_id="x", approval_id="A", run_id="r", issued_at=NOW - 1, expires_at=NOW + 99)
        with self.assertRaisesRegex(wire.WireError, "requires the approval surface"):
            _call(self.chain.authority, "authority.create_run", {"policy": wire.policy_to_wire(policy),
                                                                  "approval": wire.approval_to_wire(approval),
                                                                  "run_id": "r"})

    def test_without_an_approver_nothing_is_created(self):
        self.chain.harness = None
        with self.assertRaisesRegex(RuntimeError, "nobody can decide the plan"):
            self.run_session("auto")
        self.assertEqual(self.chain.deployment.base.authority.status("demo-run"), None)


class AnExpiredApprovalIsAskedAgain(unittest.TestCase):
    """An expired intervention approval is asked for again (acceptance test A20, behind the gate).

    The late resubmission is refused, the Authority asks again, the gate opens a second page
    for the same fragment, and the fresh approval completes it.
    """

    def test_expiry_then_a_fresh_approval_on_a_new_page(self):
        from .expiry import SteppedClock, run_expiry
        clock = SteppedClock(NOW)
        chain = AttestedChain.local(clock)
        harness = SoftwareAuthenticator.generate()
        tmp = tempfile.mkdtemp(prefix="gated-expiry-")
        store = ApprovalStore(os.path.join(tmp, "approval.db"))
        port = _free_port()
        url = f"http://localhost:{port}"
        gate = ApprovalGate(chain.deployment.authority_server, store,
                            CredentialSet((harness.credential("harness:eval"),)), clock, origin=url).install()
        surface = ApprovalSurface(gate, ("127.0.0.1", port))
        chain.approvals, chain.harness = ApprovalClient(chain.authority, url), HarnessApprover(url, harness)
        try:
            record = run_expiry(chain, ttl=20, wait=25, sleep=clock.advance, run_id="run-expiry-gated",
                                clock_mode="stepped")
        finally:
            surface.close()
            chain.close()
            store.close()
        self.assertTrue(record["pass"], record)
        steps = [o for o in store_objects(tmp) if o[0] == "step"]
        self.assertEqual(sorted(a for _, a in steps), [0, 1])


def store_objects(tmp):
    """Return (kind, attempt) of every object the gate recorded (read after the run)."""
    import sqlite3
    db = sqlite3.connect(os.path.join(tmp, "approval.db"))
    try:
        return [(k, json.loads(b).get("attempt", 0)) for k, b in db.execute("SELECT kind, body FROM objects")]
    finally:
        db.close()


if __name__ == "__main__":
    unittest.main()
