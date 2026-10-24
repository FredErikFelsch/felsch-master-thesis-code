"""The effect ledger over the durable gateway of V4, and the V5 role surfaces.

The tests need no hardware, no cluster and no mock gateway. The effect path is the frozen V3
ToolGateway behind the durable two-phase dispatch, driven as `booking_v4.tests_durable` drives
it, including its crash injection. Ledger rows are written with the intent and with the outcome
(PENDING, then COMMITTED). A crash inside the window leaves PENDING, and the delta says
INDETERMINATE, not zero. Idempotent recovery resolves it into one committed effect. The delta is
cursor-based and separates own from foreign rows. A role-bound server does not have the other
role's methods, and the V3 provisioning boundary is not on the V5 surface.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3
from booking_v3.provisioner import create_deployment
from booking_v4 import wire
from booking_v4.durable import (AUTHORITY_SURFACE, GATEWAY_SURFACE, OBSERVATION_SURFACE,
                                DurableDeploymentServer, DurableProcessDeployment, DurableStore,
                                ExternalWorld, _RestoredDeployment)
from booking_v4.services import _call
from booking_v4.tests_recovery_support import RecoveringProcessDeployment, recover_dispatch

from .controller_v5 import RunRecord
from .gateway import COMMITTED, PENDING, DurableLedger, EffectEntry, RemoteLedger, ledger_delta
from .relying_party import Refusal

T0 = 1_700_000_010
ISSUED, EXPIRES = 1_700_000_000, 1_700_003_600


def _deployment(idempotent: bool = False, recovery: bool = False):
    """Return a durable V4 deployment with run-1 created, the harness of `booking_v4.tests_durable`."""
    world = ExternalWorld(idempotent=idempotent)
    policy = default_p3()
    dep = (RecoveringProcessDeployment(FixedClock(T0), executor=world.executor, enable_recovery=True,
                                       downstream_idempotent=idempotent, enable_test_api=True)
           if recovery else
           DurableProcessDeployment(FixedClock(T0), executor=world.executor,
                                    downstream_idempotent=idempotent, enable_test_api=True))
    approval = approve(policy, approver_id="alice", approval_id="A-run-1",
                       run_id="run-1", issued_at=ISSUED, expires_at=EXPIRES)
    s0 = dep.authority.create_run(policy, approval, "run-1")
    return policy, dep, s0, world


def _grant(dep, fragment, state_hash):
    """Establish a runner session for `fragment` and return the execution grant."""
    credential = dep.authority.establish_runner_session(
        dep.bootstrap, fragment.run_id, fragment.fragment_hash, state_hash)
    grant, reason = dep.authority.request_execution_grant(
        credential, fragment, state_hash, {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
    assert grant is not None, reason
    return grant


def _advance(policy, dep, envelope, upto):
    """Run the honest prefix of `upto` steps and return the last envelope."""
    for step, args in enumerate(happy_path_arguments()[:upto]):
        fragment = honest_fragment(policy, envelope.run_id, step, args)
        result = dep.provisioner.spawn(fragment, envelope).execute(policy, envelope, fragment)
        assert result.status == "STEP_COMPLETED", result.reason
        envelope = result.envelope
    return envelope


def _row(seq, gid, run_id, step, state) -> EffectEntry:
    """Return a ledger row with a fixed fragment hash."""
    return EffectEntry(seq, gid, run_id, step, "f" * 64, state)


class LedgerDeltaTests(unittest.TestCase):
    """`ledger_delta` counts own committed and pending effects and names foreign rows."""

    def test_pending_then_committed_is_one_committed_effect(self):
        rows = (_row(3, "g", "r", 2, PENDING), _row(4, "g", "r", 2, COMMITTED))
        d = ledger_delta(rows, "r", 2)
        self.assertEqual((d.own_committed, d.own_pending, d.clean, d.verdict), (1, 0, True, "COMMITTED=1"))

    def test_a_lone_pending_row_is_indeterminate_not_zero(self):
        d = ledger_delta((_row(5, "g", "r", 3, PENDING),), "r", 3)
        self.assertEqual((d.own_committed, d.own_pending, d.verdict), (0, 1, "INDETERMINATE"))

    def test_nothing_after_the_cursor_is_a_clean_zero(self):
        d = ledger_delta((), "r", 9)
        self.assertEqual((d.own_committed, d.own_pending, d.clean), (0, 0, True))

    def test_foreign_rows_are_named_not_counted_away(self):
        rows = (_row(1, "a", "r", 1, PENDING), _row(2, "a", "r", 1, COMMITTED), _row(3, "z", "other", 7, COMMITTED))
        d = ledger_delta(rows, "r", 1)
        self.assertEqual([(r.run_id, r.step) for r in d.foreign], [("other", 7)])
        self.assertEqual(d.verdict, "COMMITTED=1 FOREIGN=1")


class LedgerOverTheDurableGatewayTests(unittest.TestCase):
    """The rows the durable dispatch path writes, read through DurableLedger."""

    def test_a_normal_dispatch_writes_pending_then_committed(self):
        p, dep, s0, world = _deployment()
        with dep:
            ledger = DurableLedger(dep.store)
            cursor = ledger.high_watermark()
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            grant = _grant(dep, fragment, s0.state_hash)
            result = dep.gateway.execute(grant.token, fragment)
            self.assertEqual(result.outcome.value, "CONFIRMED")   # V1 EffectOutcome name
            rows = ledger.entries_after(cursor)
            self.assertEqual([r.state for r in rows], [PENDING, COMMITTED])
            self.assertEqual({r.grant_id for r in rows}, {grant.grant_id})
            self.assertEqual((rows[0].run_id, rows[0].step, rows[0].fragment_hash),
                             ("run-1", 0, fragment.fragment_hash))
            self.assertEqual(ledger_delta(rows, "run-1", 0).verdict, "COMMITTED=1")
            self.assertEqual(world.effect_count("search"), 1)

    def test_a_crash_after_the_effect_leaves_pending_and_the_delta_is_indeterminate(self):
        """The effect happened and the outcome did not become durable (the dual-write window).

        The ledger row is PENDING and the evaluation reports INDETERMINATE, not zero.
        """
        p, dep, s0, world = _deployment()
        with dep:
            ledger = DurableLedger(dep.store)
            cursor = ledger.high_watermark()
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            grant = _grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=False)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("search"), 1)              # the effect happened
            rows = ledger.entries_after(cursor)
            self.assertEqual([r.state for r in rows], [PENDING])
            d = ledger_delta(rows, "run-1", 0)
            self.assertEqual((d.own_committed, d.own_pending, d.verdict), (0, 1, "INDETERMINATE"))

    def test_a_crash_before_the_effect_is_also_pending(self):
        """The symmetric case: the intent is durable and the effect did not run.

        The ledger cannot tell the two cases apart, and no other reader can either. Both read
        PENDING and INDETERMINATE. The world says 0, and the ledger does not claim 0.
        """
        p, dep, s0, world = _deployment()
        with dep:
            ledger = DurableLedger(dep.store)
            cursor = ledger.high_watermark()
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            grant = _grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=True)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("search"), 0)
            self.assertEqual(ledger_delta(ledger.entries_after(cursor), "run-1", 0).verdict, "INDETERMINATE")

    def test_idempotent_recovery_resolves_pending_into_one_committed_effect(self):
        """With a downstream that deduplicates on action_id, recover_dispatch asks again and commits.

        The same grant gains a COMMITTED row, so there is one logical effect and the world counts 1.
        """
        p, dep, s0, world = _deployment(idempotent=True, recovery=True)
        with dep:
            ledger = DurableLedger(dep.store)
            envelope = _advance(p, dep, s0, 2)
            cursor = ledger.high_watermark()
            fragment = honest_fragment(p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            grant = _grant(dep, fragment, envelope.state_hash)
            dep.server.crash_dispatch_once(before_effect=False)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(ledger_delta(ledger.entries_after(cursor), "run-1", 2).verdict, "INDETERMINATE")
            recovered = recover_dispatch(dep, grant.token, fragment)
            self.assertEqual(recovered.outcome.value, "CONFIRMED")
            rows = ledger.entries_after(cursor)
            self.assertEqual([r.state for r in rows], [PENDING, COMMITTED])
            self.assertEqual(ledger_delta(rows, "run-1", 2).verdict, "COMMITTED=1")
            self.assertEqual(world.effect_count("book"), 1)

    def test_a_refused_dispatch_writes_no_row(self):
        """A consumed token presented again is refused by V3 before any intent, so no row is written."""
        p, dep, s0, world = _deployment()
        with dep:
            ledger = DurableLedger(dep.store)
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            grant = _grant(dep, fragment, s0.state_hash)
            dep.gateway.execute(grant.token, fragment)
            cursor = ledger.high_watermark()
            refused = dep.gateway.execute(grant.token, fragment)
            self.assertTrue(hasattr(refused, "reason"))
            self.assertEqual(ledger.entries_after(cursor), ())
            self.assertEqual(world.effect_count("search"), 1)


class MeasurementIsNeverAssumedTests(unittest.TestCase):
    """A run record does not report a ledger it did not read.

    The counters default to zero, so `ledger_measured` decides whether three zeros are a
    measurement. Callers check it before believing them (see `booking_demo.tests_demo`).
    `execute_fragment` raises on a broken run, because a refusal is a result of the experiment and
    an exception is not.
    """

    def test_the_default_counters_do_not_read_as_an_observation(self):
        rec = RunRecord("run-m", 0, "f" * 64, "s" * 64)
        self.assertEqual((rec.effects, rec.pending_effects, rec.foreign_effects), (0, 0, 0))
        self.assertFalse(rec.ledger_measured)
        self.assertFalse(rec.accepted, "three default zeros are not a measured 'no effect'")
        self.assertEqual(rec.outcome, "UNMEASURED")
        rec.ledger_measured, rec.effects = True, 1
        self.assertTrue(rec.accepted)
        self.assertEqual(rec.outcome, "ACCEPTED")

    def test_an_unmeasured_record_does_not_claim_a_refusal_either(self):
        """UNMEASURED comes before the refusal.

        A relying-party refusal means no session existed, but the ledger is read so that the claim
        of no effect does not rest on that.
        """
        rec = RunRecord("run-m", 0, "f" * 64, "s" * 64, refusal=Refusal("binding-mismatch"))
        self.assertEqual(rec.outcome, "UNMEASURED")
        rec.ledger_measured = True
        self.assertEqual(rec.outcome, "REFUSED(binding-mismatch)")

    def test_a_pending_dispatch_is_not_reported_as_no_effect(self):
        rec = RunRecord("run-m", 0, "f" * 64, "s" * 64, pending_effects=1, ledger_measured=True)
        self.assertFalse(rec.accepted)
        self.assertEqual(rec.outcome, "INDETERMINATE")


class RoleSurfaceTests(unittest.TestCase):
    """One artefact, two runtime principals, two exposed interfaces."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="v5-roles-")
        base = create_deployment(FixedClock(T0))
        self.base = base
        self.auth_store = DurableStore(os.path.join(self.tmp, "authority.db"))
        self.gw_store = DurableStore(os.path.join(self.tmp, "gateway.db"))
        # The authority role holds the Authority object and no gateway.
        self.authority = DurableDeploymentServer(
            _RestoredDeployment(base.authority, None), self.auth_store,
            tcp=("127.0.0.1", 0), role="authority")
        # The gateway role holds the gateway with only the verify key, and no Authority object.
        self.gateway = DurableDeploymentServer(
            _RestoredDeployment(None, base.gateway), self.gw_store,
            tcp=("127.0.0.1", 0), role="gateway", observe_tcp=("127.0.0.1", 0))

    def tearDown(self):
        self.authority.close()
        self.gateway.close()
        self.auth_store.close()
        self.gw_store.close()

    def _code(self, endpoint, method, params):
        """Call `method` and return the error text, or "OK" when the call succeeds."""
        try:
            _call(endpoint, method, params)
        except wire.WireError as exc:
            return str(exc)
        return "OK"

    def test_the_surfaces_are_disjoint_and_omit_the_v3_session_call(self):
        self.assertEqual(AUTHORITY_SURFACE & GATEWAY_SURFACE, frozenset())
        self.assertEqual(AUTHORITY_SURFACE & OBSERVATION_SURFACE, frozenset())
        self.assertEqual(GATEWAY_SURFACE & OBSERVATION_SURFACE, frozenset())
        self.assertNotIn("authority.establish_runner_session", AUTHORITY_SURFACE | GATEWAY_SURFACE | OBSERVATION_SURFACE)

    def test_the_v3_provisioning_boundary_does_not_exist_on_the_v5_surface(self):
        """Acceptance test A14 as a property of the API.

        A direct call to the legacy session establishment with the real bootstrap finds no such
        method on the authority role. There is no session, no grant and no effect.
        """
        msg = self._code(self.authority.endpoint, "authority.establish_runner_session",
                         {"bootstrap": wire.bootstrap_to_wire(self.base.bootstrap), "run_id": "run-1",
                          "fragment_hash": "f" * 64, "state_hash": "s" * 64, "nonce": "n"})
        self.assertIn("no such method", msg)
        self.assertEqual(self.auth_store.load_states(), None)          # nothing was persisted

    def test_the_gateway_process_has_no_authority_methods_and_vice_versa(self):
        self.assertIn("no such method", self._code(self.gateway.endpoint, "authority.create_run",
                                                   {"policy": {}, "approval": {}, "run_id": "r"}))
        self.assertIn("no such method", self._code(self.authority.endpoint, "gateway.execute",
                                                   {"token": {}, "fragment": {}}))

    def test_the_ledger_is_readable_only_on_the_observation_port(self):
        """The runner's port (execution surface) cannot read the ledger.

        The controller's port (observation surface) cannot execute. One process serves two
        capabilities on two listeners.
        """
        self.assertIn("no such method", self._code(self.gateway.endpoint, "gateway.ledger_watermark", {}))
        self.assertIn("no such method", self._code(self.gateway.observe_endpoint, "gateway.execute",
                                                   {"token": {}, "fragment": {}}))
        remote = RemoteLedger(self.gateway.observe_endpoint)
        self.assertEqual(remote.high_watermark(), 0)
        self.assertEqual(remote.entries_after(0), ())

    def test_an_unknown_role_is_refused_and_the_observation_port_belongs_to_the_gateway(self):
        with self.assertRaises(ValueError):
            DurableDeploymentServer(_RestoredDeployment(None, None), self.gw_store, role="counterparty")
        with self.assertRaises(ValueError):
            DurableDeploymentServer(_RestoredDeployment(self.base.authority, None), self.auth_store,
                                    tcp=("127.0.0.1", 0), role="authority", observe_tcp=("127.0.0.1", 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
