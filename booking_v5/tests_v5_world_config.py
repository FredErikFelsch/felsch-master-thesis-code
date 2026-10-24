"""The deployment's counterparty is seeded, checked and fail-closed.

Run:
    python3 -m booking_v5.tests_v5_world_config

The world is a property of the deployment, not of whatever environment a process happened to
start with. It is written into both stores at `init`, so moving a deployment to another
counterparty means seeding again, which is an explicit step and leaves a trace. An environment
variable could differ between two restarts of the same pod and nobody would see it.

What a gateway can check on its own is the world half: that the counterparty is one of the
described ones and that the credential it needs is held. The policy half lives where policies
live. Both are fail-closed, and the failure that matters most is the quiet one: a gateway seeded
for a live counterparty must not come up serving the mock catalogue.

The tests need no hardware and no cluster, and they pass without network access.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v3.policy import p3_with_pay_approval
from booking_v4.durable import DurableStore
from booking_live.policy import pl1_with_pay_approval
from booking_live.startup import PolicyNotAdmitted

from . import service_v5
from .binding import PROTOCOL_VERSION
from .tests_v5_fixtures import FREEZE, STAMP

T0 = 1_700_000_010
TOKEN = "duffel_test_" + "t" * 20


class Call:
    """A tool call as the executor receives it."""

    def __init__(self, tool, args=None):
        self.tool, self.args = tool, dict(args or {})


class SeededWorld(unittest.TestCase):
    """The seeded world decides the gateway executor and the policies the Authority admits."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v5-world-")
        freeze = json.loads((FREEZE / f"freeze-{STAMP}.json").read_text())
        freeze["binding_version"] = PROTOCOL_VERSION.decode()
        self.freeze_path = os.path.join(self.tmp, "freeze.json")
        with open(self.freeze_path, "w", encoding="utf-8") as fh:
            json.dump(freeze, fh)
        self.a_db = os.path.join(self.tmp, "authority.db")
        self.g_db = os.path.join(self.tmp, "gateway.db")
        self._saved = os.environ.get("DUFFEL_TOKEN")
        os.environ.pop("DUFFEL_TOKEN", None)

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("DUFFEL_TOKEN", None)
        else:
            os.environ["DUFFEL_TOKEN"] = self._saved

    def _seed(self, **kwargs):
        """Seed both stores from the fixture freeze."""
        return service_v5.seed(self.a_db, self.g_db, self.freeze_path, FixedClock(T0), **kwargs)

    def _gateway(self):
        """Start the gateway role on the seeded store."""
        return service_v5.start_gateway(self.g_db, ("127.0.0.1", 0), ("127.0.0.1", 0),
                                        FixedClock(T0))

    def _executor_of(self, server):
        """Return the executor the started gateway dispatches to."""
        return server._dep.gateway._executor if hasattr(server._dep.gateway, "_executor") \
            else server._dep.gateway.executor

    def _world_of(self, db):
        """Return the world a store was seeded for."""
        store = DurableStore(db)
        try:
            return store.get_setting(service_v5.SETTING_WORLD)
        finally:
            store.close()

    # The default.

    def test_the_default_deployment_is_the_catalogue(self):
        self._seed()
        store = DurableStore(self.g_db)
        try:
            self.assertEqual(store.get_setting(service_v5.SETTING_WORLD),
                             service_v5.DEFAULT_WORLD)
        finally:
            store.close()

    def test_a_default_gateway_serves_the_catalogue(self):
        self._seed()
        server, store = self._gateway()
        try:
            result = self._executor_of(server)(Call("search", {"to": "FRA"}))
            ids = [o["flight_id"] for o in result.payload["offers"]]
            self.assertEqual(ids, ["LH123", "LH250", "AF456"])
        finally:
            store.close()

    # A live world is seeded into both stores.

    def test_both_stores_carry_the_world(self):
        self._seed(world="duffel")
        for db in (self.a_db, self.g_db):
            store = DurableStore(db)
            try:
                self.assertEqual(store.get_setting(service_v5.SETTING_WORLD), "duffel")
            finally:
                store.close()

    def test_an_unknown_world_is_refused_at_seed(self):
        with self.assertRaises(SystemExit) as caught:
            self._seed(world="aws")
        self.assertIn("unknown world", str(caught.exception))

    def test_a_reseed_cannot_move_the_deployment(self):
        """A re-seed must not move the stores to another world.

        In a deployment the stores hold runs, facts and a ledger of the seeded world by then.
        """
        self._seed(world="duffel")
        with self.assertRaises(SystemExit) as caught:
            self._seed(world="serpapi")
        self.assertIn("refusing to re-seed", str(caught.exception))

    def test_a_reseed_with_the_same_world_is_still_idempotent(self):
        self._seed(world="duffel")
        self._seed(world="duffel")          # must not raise
        self.assertEqual([self._world_of(db) for db in (self.a_db, self.g_db)], ["duffel", "duffel"])

    # The gateway half, fail-closed.

    def test_a_live_gateway_without_its_credential_does_not_start(self):
        self._seed(world="duffel")
        with self.assertRaises(SystemExit) as caught:
            self._gateway()
        message = str(caught.exception)
        self.assertIn("duffel", message)
        self.assertIn("DUFFEL_TOKEN", message)

    def test_a_live_gateway_does_not_come_up_as_the_catalogue(self):
        """The quiet failure this check exists for.

        A gateway that believes it is live while answering from the catalogue would produce runs
        that look clean and prove nothing. The live executor must therefore be the one installed.
        The test shows it by asking for a tool the live world refuses by name and the catalogue
        would confirm.
        """
        os.environ["DUFFEL_TOKEN"] = TOKEN
        self._seed(world="duffel")
        server, store = self._gateway()
        try:
            result = self._executor_of(server)(
                Call("pay", {"amount_minor": 1, "currency": "EUR", "recipient": "x"}))
            self.assertEqual(result.outcome.value, "FAILED")
            self.assertIn("pay_order", result.error or "")
        finally:
            store.close()

    def test_the_live_gateway_does_not_answer_from_the_catalogue(self):
        os.environ["DUFFEL_TOKEN"] = TOKEN
        self._seed(world="duffel")
        server, store = self._gateway()
        try:
            result = self._executor_of(server)(Call("search", {"to": "EWR"}))
            # The test token cannot confirm against the provider, with or without a network.
            # The catalogue would have confirmed three flights.
            self.assertNotEqual(result.outcome.value, "CONFIRMED")
            self.assertIsNone(result.payload, "the catalogue offers came back")
            self.assertIn("search", result.error or "", "the refusal names the live call")
        finally:
            store.close()

    # The Authority half, fail-closed.

    def _authority(self):
        """Start the authority role on the seeded store with an injected verifier."""
        return service_v5.start_authority(self.a_db, ("127.0.0.1", 0), FixedClock(T0),
                                          verifier_factory=lambda: object())

    def _create_run(self, server, policy, run_id):
        """Create a run under `policy` on the started Authority and return S0."""
        approval = approve(policy, approver_id="alice", approval_id=f"A-{run_id}", run_id=run_id,
                           issued_at=T0 - 10, expires_at=T0 + 3600)
        return server._dep.authority.create_run(policy, approval, run_id)

    def test_a_duffel_authority_admits_pl1(self):
        self._seed(world="duffel")
        server, store = self._authority()
        try:
            s0 = self._create_run(server, pl1_with_pay_approval(), "run-pl1")
            self.assertEqual(s0.policy_digest, pl1_with_pay_approval().digest())
        finally:
            store.close()

    def test_a_duffel_authority_refuses_the_catalogue_policy(self):
        """P3 names `pay`, which the Duffel gateway cannot execute, so it is refused before S0."""
        self._seed(world="duffel")
        server, store = self._authority()
        try:
            with self.assertRaises(PolicyNotAdmitted) as caught:
                self._create_run(server, p3_with_pay_approval(), "run-p3")
            self.assertIn("'pay'", str(caught.exception))
        finally:
            store.close()

    def test_a_serpapi_authority_refuses_a_selling_policy(self):
        self._seed(world="serpapi")
        server, store = self._authority()
        try:
            with self.assertRaises(PolicyNotAdmitted):
                self._create_run(server, pl1_with_pay_approval(), "run-pl1")
        finally:
            store.close()

    def test_the_catalogue_authority_stays_unbound(self):
        """The frozen V5 evaluation over the mock binds no admission rule."""
        self._seed()
        server, store = self._authority()
        try:
            self.assertIsNone(server._dep.authority._policy_admission)
            self._create_run(server, p3_with_pay_approval(), "run-p3")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
