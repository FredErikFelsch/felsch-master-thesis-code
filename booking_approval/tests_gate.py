"""The approval gate on a real seeded Authority: who can create a run and approve a payment.

Run:
    python3 -m booking_approval.tests_gate

The Authority is the V5 service restored from a seeded store (`service_v5.start_authority`),
reached over its TCP listener in the same way as the controller reaches it. No hardware and
no cluster are needed. The step approval needs an open intervention at the Authority, which
in a deployment only a TD's report creates. Here `intervention_pending` is pinned to True on
the instance. The attestation verifier is a dummy object, since no test reaches it, and the
expiry test advances the fixed clock directly.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v3.fragment import ActionFragment
from booking_v3.policy import p3_with_pay_approval
from booking_v4 import wire
from booking_v4.services import _call
from booking_v5 import service_v5
from booking_v5.tests_v5_fixtures import FREEZE, STAMP

from .credentials import CredentialPinMismatch, CredentialSet, pin
from .gate import ApprovalGate, DecisionRefused
from .softauthn import SoftwareAuthenticator
from .store import ApprovalStore
from .webauthn import b64url_decode

T0 = 1_700_000_010
ORIGIN = "http://localhost:8450"


class GateFixture(unittest.TestCase):
    """A seeded Authority with the gate installed and two enrolled approvers."""

    def setUp(self):
        from booking_v5.binding import PROTOCOL_VERSION
        self.tmp = tempfile.mkdtemp(prefix="approval-gate-")
        freeze = json.loads((FREEZE / f"freeze-{STAMP}.json").read_text())
        freeze["binding_version"] = PROTOCOL_VERSION.decode()
        freeze_path = os.path.join(self.tmp, "freeze.json")
        with open(freeze_path, "w", encoding="utf-8") as fh:
            json.dump(freeze, fh)
        self.a_db, g_db = os.path.join(self.tmp, "authority.db"), os.path.join(self.tmp, "gateway.db")
        service_v5.seed(self.a_db, g_db, freeze_path, FixedClock(T0))
        self.clock = FixedClock(T0)
        self.server, self.a_store = service_v5.start_authority(self.a_db, ("127.0.0.1", 0), self.clock,
                                                               verifier_factory=lambda: object())
        self.person = SoftwareAuthenticator.generate(counting=True)
        self.harness = SoftwareAuthenticator.generate()
        self.creds = CredentialSet((self.person.credential("fred", kind="passkey"),
                                    self.harness.credential("harness:eval", kind="harness")))
        self.store = ApprovalStore(os.path.join(self.tmp, "approval.db"))
        pin(self.store, self.creds)
        self.gate = ApprovalGate(self.server, self.store, self.creds, self.clock, origin=ORIGIN).install()
        self.policy = p3_with_pay_approval()

    def tearDown(self):
        self.server.close()
        self.a_store.close()
        self.store.close()

    # helpers --------------------------------------------------------------------------
    def rpc(self, method, params):
        """Send one RPC over TCP. An error reply comes back as {"error": ...} instead of raising."""
        try:
            return _call(self.server.endpoint, method, params)
        except wire.WireError as exc:
            return {"error": str(exc)}

    def propose(self, run_id="run-1"):
        """Propose the plan for `run_id` through the RPC surface and return its object id."""
        reply = self.rpc("approval.propose_run", {"policy": wire.policy_to_wire(self.policy), "run_id": run_id})
        self.assertIn("object_id", reply, reply)
        return reply["object_id"]

    def sign(self, object_id, decision="approve", who=None, **kw):
        """Fetch a challenge and answer it with an authenticator (by default the person's)."""
        who = who or self.person
        ch = self.gate.issue_challenge(object_id, decision)
        a = who.assertion(b64url_decode(ch["challenge"]), kw.pop("origin", ORIGIN))
        a["challenge"] = ch["challenge"]
        return a

    def decide(self, object_id, decision="approve", who=None, **kw):
        """Sign and submit one decision to the gate."""
        return self.gate.decide(object_id, decision, self.sign(object_id, decision, who, **kw))

    def pay_fragment(self, run_id="run-1"):
        """Build the payment fragment of the approval-bound step."""
        return ActionFragment(run_id=run_id, fragment_index=3, policy_digest=self.policy.digest(),
                              operation="pay", arguments={"order_id": "ord-1", "amount_minor": 45000,
                                                          "currency": "EUR", "action_id": "act-pay"},
                              action_id="act-pay", declared_facts=("booking_order_id",),
                              declared_capability="pay")


class TheControllerCannotApprove(GateFixture):
    """The methods that carry authority are closed on the RPC surface."""

    def test_create_run_is_closed_even_with_a_valid_hmac_approval(self):
        approval = approve(self.policy, approver_id="alice", approval_id="A-x", run_id="run-x",
                           issued_at=T0 - 10, expires_at=T0 + 3600)
        reply = self.rpc("authority.create_run", {"policy": wire.policy_to_wire(self.policy),
                                                  "approval": wire.approval_to_wire(approval), "run_id": "run-x"})
        self.assertIn("requires the approval surface", reply.get("error", ""))
        self.assertIsNone(self.server._dep.authority.status("run-x"))

    def test_decide_intervention_is_closed_even_with_the_human_secret(self):
        from booking_v3.authority import HumanApprovalCredential
        secret = HumanApprovalCredential(secret=self.server._dep.authority._human_secret)
        reply = self.rpc("authority.decide_intervention", {
            "human": wire.human_to_wire(secret), "decision_id": "d", "run_id": "run-1", "step_index": 3,
            "fragment_hash": "0" * 64, "approver_id": "x", "grant": True, "ttl": 60})
        self.assertIn("requires the approval surface", reply.get("error", ""))

    def test_proposing_a_run_does_not_create_it(self):
        self.propose()
        self.assertIsNone(self.server._dep.authority.status("run-1"))
        self.assertEqual(self.rpc("approval.status", {"object_id": self.propose()})["state"], "pending")


class APersonApprovesThePlan(GateFixture):
    """A verified assertion turns a proposed plan into a run."""

    def test_a_verified_approval_creates_the_run(self):
        oid = self.propose()
        out = self.decide(oid)
        self.assertEqual(out["state"], "approved")
        self.assertEqual(out["approver_kind"], "passkey")
        status = self.rpc("approval.status", {"object_id": oid})
        env = wire.envelope_from_wire(status["result"]["envelope"])
        self.assertEqual(env.policy_digest, self.policy.digest())
        self.assertEqual(self.server._dep.authority.status("run-1").value, "ACTIVE")

    def test_a_rejection_creates_nothing(self):
        oid = self.propose()
        self.assertEqual(self.decide(oid, "reject")["state"], "rejected")
        self.assertIsNone(self.server._dep.authority.status("run-1"))

    def test_the_page_shows_the_compiled_policy(self):
        v = self.gate.object_view(self.propose())["view"]
        self.assertEqual(v["digest"], self.policy.digest())
        self.assertEqual([s["tool"] for s in v["steps"]], list(self.policy.allowed_flow))
        self.assertTrue(any(s["approval"] for s in v["steps"]))


class AnAssertionThatDoesNotFitIsRefused(GateFixture):
    """Each way an assertion can fail its challenge, key or ceremony ends in a refusal."""

    def _refused(self, status, why, fn):
        with self.assertRaises(DecisionRefused) as caught:
            fn()
        self.assertEqual(caught.exception.status, status, caught.exception.reason)
        self.assertIn(why, caught.exception.reason)

    def test_an_unpinned_key_is_refused(self):
        oid = self.propose()
        self._refused(403, "not pinned", lambda: self.decide(oid, who=SoftwareAuthenticator.generate()))
        self.assertIsNone(self.server._dep.authority.status("run-1"))

    def test_a_replayed_assertion_is_refused(self):
        oid = self.propose()
        a = self.sign(oid)
        self.gate.decide(oid, "reject", self.sign(oid, "reject"))  # the object is decided meanwhile
        self._refused(409, "no longer pending", lambda: self.gate.decide(oid, "approve", a))
        self._refused(403, "already used", lambda: self.gate.decide(oid, "approve", a))

    def test_a_challenge_for_reject_cannot_approve(self):
        oid = self.propose()
        a = self.sign(oid, "reject")
        self._refused(403, "another object or decision", lambda: self.gate.decide(oid, "approve", a))

    def test_a_challenge_for_another_object_cannot_approve(self):
        a = self.sign(self.propose("run-a"))
        other = self.propose("run-b")
        self._refused(403, "another object or decision", lambda: self.gate.decide(other, "approve", a))

    def test_an_expired_challenge_is_refused(self):
        oid = self.propose()
        a = self.sign(oid)
        self.clock._t = T0 + 200                               # past the challenge TTL
        self._refused(403, "expired", lambda: self.gate.decide(oid, "approve", a))

    def test_another_origin_is_refused(self):
        oid = self.propose()
        self._refused(403, "origin", lambda: self.decide(oid, origin="http://localhost:9999"))

    def test_an_embedded_ceremony_needs_an_allowed_embedder(self):
        oid = self.propose()
        ch = self.gate.issue_challenge(oid, "approve")
        a = self.person.assertion(b64url_decode(ch["challenge"]), ORIGIN, top_origin="http://localhost:8766")
        a["challenge"] = ch["challenge"]
        self._refused(403, "cross-origin", lambda: self.gate.decide(oid, "approve", a))
        self.gate.allowed_top_origins = ("http://localhost:8766",)
        self.assertEqual(self.decide(oid)["state"], "approved")    # the next, unembedded ceremony still passes

    def test_a_person_must_verify(self):
        oid = self.propose()
        self.person.user_verified = False
        self._refused(403, "user verification", lambda: self.decide(oid))

    def test_a_failed_attempt_spends_the_challenge(self):
        oid = self.propose()
        a = self.sign(oid)
        good = dict(a)
        a["signature"] = self.sign(oid)["signature"]          # a signature over another challenge
        self._refused(403, "does not verify", lambda: self.gate.decide(oid, "approve", a))
        self._refused(403, "already used", lambda: self.gate.decide(oid, "approve", good))


class APersonApprovesThePayment(GateFixture):
    """A step approval is bound to the fragment the Authority itself holds."""

    def setUp(self):
        super().setUp()
        self.decide(self.propose())
        self.server._dep.authority.intervention_pending = lambda run, step, h: True    # a TD reported it
        self.fragment = self.pay_fragment()
        self.gate._observe_grant({"params": {"fragment": wire.fragment_to_wire(self.fragment)}},
                                 {"grant": None, "reason": "manual intervention required: no intervention approval presented"})

    def ticket(self, fragment=None):
        """Ask the gate for the page of a step fragment."""
        return self.rpc("approval.step_ticket", {"fragment": wire.fragment_to_wire(fragment or self.fragment)})

    def test_the_page_shows_the_fragment_arguments(self):
        v = self.gate.object_view(self.ticket()["object_id"])["view"]
        self.assertEqual(v["arguments"]["amount_minor"], 45000)
        self.assertEqual(v["fragment_hash"], self.fragment.fragment_hash)

    def test_an_approval_yields_a_signed_fragment_bound_intervention(self):
        oid = self.ticket()["object_id"]
        out = self.decide(oid)
        self.assertEqual(out["state"], "approved")
        approval = wire.intervention_from_wire(self.rpc("approval.status", {"object_id": oid})["result"]["approval"])
        self.assertEqual(approval.fragment_hash, self.fragment.fragment_hash)
        self.assertEqual(approval.approver_id, "fred")
        anchors = self.server._dep.authority.anchors()
        from booking_v1.freeze import canonical_bytes
        self.assertTrue(anchors.intervention_key.verify(approval.signature, canonical_bytes(approval.binding())))

    def test_the_harness_is_recorded_as_harness(self):
        out = self.decide(self.ticket()["object_id"], who=self.harness)
        self.assertEqual((out["approver_id"], out["approver_kind"]), ("harness:eval", "harness"))

    def test_a_fragment_the_authority_does_not_hold_opens_no_page(self):
        self.server._dep.authority.intervention_pending = lambda run, step, h: h == self.fragment.fragment_hash
        other = self.pay_fragment("run-9")
        self.assertIn("no approval pending", self.ticket(other).get("error", ""))

    def test_other_arguments_under_the_pending_hash_are_refused(self):
        w = wire.fragment_to_wire(self.fragment)
        w["arguments"]["amount_minor"] = 1                     # claims the pending hash, other bytes
        reply = self.rpc("approval.step_ticket", {"fragment": w})
        self.assertIn("hash", reply.get("error", ""))

    def test_a_second_attempt_after_a_decision_is_a_new_page(self):
        first = self.ticket()["object_id"]
        self.decide(first)
        again = self.ticket()["object_id"]                    # e.g. the approval expired before use
        self.assertNotEqual(first, again)
        self.assertEqual(self.gate.object_view(again)["view"]["attempt"], 1)

    def test_a_forged_fragment_opens_no_page(self):
        w = wire.fragment_to_wire(self.pay_fragment("run-7"))
        w["arguments"]["amount_minor"] = 1                     # the hash no longer matches
        self.gate._observe_grant({"params": {"fragment": w}},
                                 {"grant": None, "reason": "manual intervention required: x"})
        self.assertIsNone(self.store.find_step("run-7", 3, w["fragment_hash"]))


class TheCredentialSetIsPinned(GateFixture):
    """The approver set is pinned and the gate state survives a restart."""

    def test_a_changed_set_is_refused_without_repin(self):
        other = CredentialSet((SoftwareAuthenticator.generate().credential("mallory", kind="passkey"),))
        with self.assertRaises(CredentialPinMismatch):
            pin(self.store, other)
        pin(self.store, other, repin=True)

    def test_an_empty_set_is_refused(self):
        with self.assertRaises(CredentialPinMismatch):
            pin(self.store, CredentialSet(()))

    def test_decisions_survive_a_restart_of_the_gate_store(self):
        oid = self.propose()
        a = self.sign(oid)
        self.store.close()
        self.store = ApprovalStore(os.path.join(self.tmp, "approval.db"))
        self.gate._store = self.store
        self.gate.decide(oid, "approve", a)
        with self.assertRaises(DecisionRefused):
            self.gate.decide(oid, "approve", a)


if __name__ == "__main__":
    unittest.main()
