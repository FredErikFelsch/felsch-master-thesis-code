"""The approval surface over HTTP and the deployed entry point (`service.start`).

Run:
    python3 -m booking_approval.tests_surface

A seeded Authority is started through `booking_approval.service.start`. The controller side
talks RPC through `ApprovalClient` and the approver talks HTTP through `HarnessApprover`, so
the three parties and paths are those of the cluster, on loopback.
"""
from __future__ import annotations

import json
import os
import pathlib
import socket
import stat
import tempfile
import unittest
import urllib.error
import urllib.request

from booking_v1.clock import FixedClock
from booking_v3.policy import p3_with_pay_approval
from booking_v4 import wire
from booking_v5 import service_v5
from booking_v5.tests_v5_fixtures import FREEZE, STAMP

from . import service
from .client import ApprovalClient, ApprovalUnavailable, HarnessApprover
from .credentials import CredentialSet
from .softauthn import SoftwareAuthenticator

T0 = 1_700_000_010


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SurfaceFixture(unittest.TestCase):
    """A seeded Authority started through `service.start`, with a controller client and a harness approver."""

    def setUp(self):
        from booking_v5.binding import PROTOCOL_VERSION
        self.tmp = tempfile.mkdtemp(prefix="approval-surface-")
        freeze = json.loads((FREEZE / f"freeze-{STAMP}.json").read_text())
        freeze["binding_version"] = PROTOCOL_VERSION.decode()
        fp = os.path.join(self.tmp, "freeze.json")
        with open(fp, "w", encoding="utf-8") as fh:
            json.dump(freeze, fh)
        self.db = os.path.join(self.tmp, "authority.db")
        service_v5.seed(self.db, os.path.join(self.tmp, "gateway.db"), fp, FixedClock(T0))
        self.harness = SoftwareAuthenticator.generate()
        self.cred_path = os.path.join(self.tmp, "approver-credentials.json")
        CredentialSet((self.harness.credential("harness:eval"),)).save(self.cred_path)
        port = _free_port()
        self.url = f"http://localhost:{port}"
        self.server, self.a_store, self.gate, self.surface, self.store = service.start(
            self.db, ("127.0.0.1", 0), ("127.0.0.1", port), self.cred_path, FixedClock(T0),
            origin=self.url, verifier_factory=lambda: object())
        self.client = ApprovalClient(self.server.endpoint, self.url)
        self.approver = HarnessApprover(self.url, self.harness)

    def tearDown(self):
        self.surface.close()
        self.server.close()
        self.a_store.close()
        self.store.close()

    def http(self, path, body=None, headers=None):
        """Send one request and return (status, headers, parsed body or raw bytes)."""
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method="POST" if data else "GET",
                                     headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw, status, hdrs = r.read(), r.status, r.headers
        except urllib.error.HTTPError as err:
            raw, status, hdrs = err.read(), err.code, err.headers
        try:
            return status, hdrs, json.loads(raw)
        except ValueError:
            return status, hdrs, raw


class TheWholePathWorks(SurfaceFixture):
    """Propose, approve and read the result across the real RPC and HTTP paths."""

    def test_propose_approve_and_read_the_envelope(self):
        policy = p3_with_pay_approval()
        ticket = self.client.propose_run(policy, "run-1")
        self.assertTrue(ticket.url.startswith(self.url + "/approve/"))
        self.assertEqual(self.approver.decide(ticket.object_id, "approve")["state"], "approved")
        st = self.client.wait(ticket.object_id, timeout=5)
        self.assertEqual(wire.envelope_from_wire(st["result"]["envelope"]).policy_digest, policy.digest())
        self.assertEqual(st["approver_kind"], "harness")

    def test_the_page_is_served_with_a_strict_policy(self):
        status, hdrs, body = self.http("/approve/" + "0" * 64)
        self.assertEqual(status, 200)
        self.assertIn(b"approve.js", body)
        self.assertIn("script-src 'self'", hdrs["Content-Security-Policy"])
        self.assertEqual(hdrs["Cache-Control"], "no-store")

    def test_pinned_names_the_approvers_without_keys(self):
        pinned = self.client.pinned()
        self.assertEqual([dict(c) for c in pinned["credentials"]], [{"approver_id": "harness:eval", "kind": "harness"}])


class RequestHygiene(SurfaceFixture):
    """The surface refuses requests with the wrong host, origin, content type or key."""

    def setUp(self):
        super().setUp()
        self.oid = self.client.propose_run(p3_with_pay_approval(), "run-1").object_id

    def test_another_host_is_refused(self):
        status, _, _ = self.http("/api/pending", headers={"Host": "attacker.example:8450"})
        self.assertEqual(status, 421)

    def test_a_post_without_origin_is_refused(self):
        status, _, body = self.http("/api/challenge", {"object_id": self.oid, "decision": "approve"},
                                    {"Content-Type": "application/json"})
        self.assertEqual(status, 403, body)

    def test_a_post_that_is_not_json_is_refused(self):
        status, _, _ = self.http("/api/challenge", {"object_id": self.oid, "decision": "approve"},
                                 {"Content-Type": "text/plain", "Origin": self.url})
        self.assertEqual(status, 415)

    def test_an_unknown_object_is_404(self):
        status, _, _ = self.http("/api/object/" + "f" * 64)
        self.assertEqual(status, 404)

    def test_an_unpinned_harness_key_is_refused(self):
        stranger = HarnessApprover(self.url, SoftwareAuthenticator.generate())
        with self.assertRaisesRegex(ApprovalUnavailable, "403"):
            stranger.decide(self.oid, "approve")
        self.assertEqual(self.client.status(self.oid)["state"], "pending")


class TheEntryPointPinsTheApprovers(SurfaceFixture):
    """`service.start` refuses a credential file that differs from the pinned set."""

    def test_a_changed_credential_file_stops_the_start(self):
        self.tearDown()
        CredentialSet((SoftwareAuthenticator.generate().credential("harness:mallory"),)).save(self.cred_path)
        with self.assertRaises(SystemExit):
            service.start(self.db, ("127.0.0.1", 0), ("127.0.0.1", 0), self.cred_path, FixedClock(T0),
                          verifier_factory=lambda: object())
        # reopen what tearDown closes
        self.server, self.a_store, self.gate, self.surface, self.store = service.start(
            self.db, ("127.0.0.1", 0), ("127.0.0.1", 0), self.cred_path, FixedClock(T0), repin=True,
            verifier_factory=lambda: object())


class AnEnrolledHarnessKeyIsAccepted(SurfaceFixture):
    """A harness key written by `enroll_harness` is private to its owner and loads again."""

    def test_enroll_writes_a_private_key_only_the_owner_reads_and_the_gate_accepts_it(self):
        from .enroll import enroll_harness
        key = pathlib.Path(self.tmp) / "keys" / "harness.json"
        creds = pathlib.Path(self.tmp) / "eval-credentials.json"
        enroll_harness("harness:eval2", creds, key)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        loaded = SoftwareAuthenticator.load(key)
        self.assertEqual(CredentialSet.load(creds).credentials[0].public_key,
                         loaded.credential("harness:eval2").public_key)
        with self.assertRaises(SystemExit):
            enroll_harness("harness:eval2", creds, key)            # an existing key is not overwritten

    def test_a_refused_approver_id_leaves_no_key_file(self):
        from .enroll import enroll_harness
        key = pathlib.Path(self.tmp) / "keys" / "unprefixed.json"
        with self.assertRaises(ValueError):
            enroll_harness("eval3", pathlib.Path(self.tmp) / "eval3-credentials.json", key)
        self.assertFalse(key.exists())


class TheEvaluationHarnessGoesThroughTheGate(SurfaceFixture):
    """`gated_call` replaces the closed `create_run` path with a proposal and a harness approval."""

    def test_e2e_live_create_run_is_routed_through_the_gate(self):
        from booking_v1.approval import approve
        from booking_v4.services import _call
        from .harness_e2e import gated_call
        policy = p3_with_pay_approval()
        hmac_approval = approve(policy, approver_id="alice", approval_id="A-e2e", run_id="run-e2e",
                                issued_at=T0 - 10, expires_at=T0 + 3600)
        params = {"policy": wire.policy_to_wire(policy), "approval": wire.approval_to_wire(hmac_approval),
                  "run_id": "run-e2e"}
        with self.assertRaisesRegex(wire.WireError, "requires the approval surface"):
            _call(self.server.endpoint, "authority.create_run", params)          # the direct way is closed
        call = gated_call(_call, self.url, self.approver)
        reply = call(self.server.endpoint, "authority.create_run", params)
        self.assertEqual(wire.envelope_from_wire(reply["envelope"]).policy_digest, policy.digest())
        self.assertEqual(call(self.server.endpoint, "approval.pinned", {})["credentials"][0]["kind"], "harness")


class TheShellMayEmbedThePageAndNobodyElse(unittest.TestCase):
    """The framing headers name the configured embedder origins and no others."""

    def test_without_ancestors_framing_is_refused(self):
        from .surface import security_headers
        h = security_headers()
        self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
        self.assertEqual(h["X-Frame-Options"], "DENY")

    def test_only_the_named_shell_origin_may_embed(self):
        from .surface import security_headers
        h = security_headers(("http://localhost:8766",))
        self.assertIn("frame-ancestors http://localhost:8766;", h["Content-Security-Policy"] + ";")
        self.assertNotIn("X-Frame-Options", h)

    def test_a_wildcard_or_path_is_not_an_origin(self):
        from .surface import security_headers
        for bad in ("*", "http://localhost:8766/x", "localhost:8766", "http://a b"):
            with self.assertRaises(ValueError):
                security_headers((bad,))


if __name__ == "__main__":
    unittest.main()
