"""The host on the path between the gateway and the TD.

Every binding across steps ("the recipient of `pay` is the recipient `book` returned") rests on
a value the monitor observed. It observes it in the response of the gateway, and that response
travels over a network the host controls. Nothing authenticates it, neither a signature nor a
pinned channel. A host that rewrites one field of a booking confirmation would therefore give the
monitor a value with legitimate provenance, and the next step would pay the attacker while every
check held.

The countermeasure does not sign the channel. It compares the report against a record the
gateway wrote for itself: the digest of the response, in the COMMITTED row of its effect ledger,
inside the transaction that made the outcome durable. The Authority recomputes that digest from
the effect event the runner reports and refuses to sign a successor when the two differ. A value
therefore reaches the state only if a trusted component recorded it.

The countermeasure belongs to V5 and not to V3, because it is armed by binding a ledger, and V3
and V4 bind none. Their threat model has no hostile host beneath the runner, so the frozen
ablations stay the systems that were measured. The runner attestation follows the same rule for
the same reason.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.effects import EffectOutcome, EffectResult, response_digest
from booking_v1.freeze import thaw
from booking_v1.lifecycle import PolicyState
from booking_v3.authority import Authority
from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3
from booking_v3.runner import EphemeralRunner
from booking_v4.durable import (AUTHORITY_SURFACE, GATEWAY_SURFACE, OBSERVATION_SURFACE,
                                DurableProcessDeployment, ExternalWorld)
from booking_v4.endpoint import ServiceEndpoint
from booking_v4.tests_recovery_support import RecoveringProcessDeployment, recover_dispatch

from . import service_v5
from .binding import PROTOCOL_VERSION
from .e2e_live import _manifest, _observation_check
from .gateway import DurableLedger, RemoteLedger
from .relying_party import FakeVerifier
from .tests_v5_fixtures import FREEZE, STAMP, needs_measured_freeze

T0 = 1_700_000_010
ISSUED, EXPIRES = 1_700_000_000, 1_700_003_600
BOOK_STEP = 2


class _HostOnThePath:
    """An attacker who carries the response from the gateway to the TD.

    It performs no effect of its own and forges nothing. It rewrites one field of a confirmed
    payload on its way back, which is all that the attacker model (Chapter 3) grants a host
    beneath a runner.
    """

    def __init__(self, real, field: str, value) -> None:
        self._real, self._field, self._value = real, field, value
        self.tampered = 0

    def execute(self, token, fragment):
        result = self._real.execute(token, fragment)
        if (isinstance(result, EffectResult) and result.outcome is EffectOutcome.CONFIRMED
                and result.payload is not None and self._field in thaw(result.payload)):
            payload = dict(thaw(result.payload))
            payload[self._field] = self._value
            self.tampered += 1
            return EffectResult(outcome=result.outcome, payload=payload, error=result.error)
        return result

    def __getattr__(self, name):
        return getattr(self._real, name)


class _UnreachableLedger:
    """A ledger whose observation surface does not answer."""

    def effect(self, grant_id):
        raise ConnectionError("gateway observation surface is not answering")


class _EmptyLedger:
    """A ledger that holds no row for any grant."""

    def effect(self, grant_id):
        return None, None


class _PendingLedger:
    """A ledger whose row says the dispatch was recorded and its outcome was not. The check must not pass on it."""

    def __init__(self) -> None:
        self.reads = 0

    def effect(self, grant_id):
        self.reads += 1
        return "PENDING", None


def _deployment():
    """Return a durable process deployment over a fresh world, with run-1 created under P3."""
    world = ExternalWorld()
    policy = default_p3()
    dep = DurableProcessDeployment(FixedClock(T0), executor=world.executor, enable_test_api=True)
    approval = approve(policy, approver_id="alice", approval_id="A-run-1",
                       run_id="run-1", issued_at=ISSUED, expires_at=EXPIRES)
    s0 = dep.authority.create_run(policy, approval, "run-1")
    return policy, dep, s0, world


def _advance(policy, dep, envelope, upto):
    """Run the honest prefix through the ordinary provisioner."""
    for step, args in enumerate(happy_path_arguments()[:upto]):
        fragment = honest_fragment(policy, envelope.run_id, step, args)
        result = dep.provisioner.spawn(fragment, envelope).execute(policy, envelope, fragment)
        assert result.status == "STEP_COMPLETED", result.reason
        envelope = result.envelope
    return envelope


def _run_step_through(dep, gateway, policy, envelope, step):
    """Run one step with the given gateway between the runner and the world."""
    fragment = honest_fragment(policy, envelope.run_id, step, happy_path_arguments()[step])
    credential = dep.authority.establish_runner_session(
        dep.bootstrap, fragment.run_id, fragment.fragment_hash, envelope.state_hash)
    runner = EphemeralRunner(dep.authority, gateway, dep.authority.anchors(), credential)
    return runner.execute(policy, envelope, fragment), fragment


class ResponseDigestTests(unittest.TestCase):
    """The digest both sides compute, on its own."""

    def test_it_is_a_function_of_content_and_not_of_key_order(self):
        self.assertEqual(response_digest("CONFIRMED", {"a": 1, "b": 2}),
                         response_digest("CONFIRMED", {"b": 2, "a": 1}))

    def test_one_changed_field_changes_it(self):
        self.assertNotEqual(response_digest("CONFIRMED", {"booking_ref": "BK-LH123"}),
                            response_digest("CONFIRMED", {"booking_ref": "BK-ATTACKER"}))

    def test_the_outcome_is_covered_too(self):
        self.assertNotEqual(response_digest("CONFIRMED", {"x": 1}),
                            response_digest("FAILED", {"x": 1}))


class ObservationIsCheckedAgainstTheLedgerTests(unittest.TestCase):
    """The whole path, over the durable gateway of V4."""

    def test_an_honest_run_is_unaffected_by_the_check(self):
        """The check raises no false alarm: the digest of an untouched response matches its own row."""
        policy, dep, s0, world = _deployment()
        with dep:
            dep.authority.bind_effect_ledger(DurableLedger(dep.store))
            envelope = _advance(policy, dep, s0, len(happy_path_arguments()))
            self.assertEqual(envelope.step_index, len(happy_path_arguments()))
            self.assertEqual(world.effect_count("pay"), 1)

    def test_a_rewritten_response_is_refused_and_the_run_is_parked(self):
        """The attack, end to end.

        The effect happened, the value does not enter the state, and the run is parked for
        reconciliation, so it cannot be extended.
        """
        policy, dep, s0, world = _deployment()
        with dep:
            dep.authority.bind_effect_ledger(DurableLedger(dep.store))
            envelope = _advance(policy, dep, s0, BOOK_STEP)
            host = _HostOnThePath(dep.gateway, "booking_ref", "BK-ATTACKER")
            result, _fragment = _run_step_through(dep, host, policy, envelope, BOOK_STEP)
            self.assertEqual(host.tampered, 1, "the harness did not actually tamper")
            self.assertNotEqual(result.status, "STEP_COMPLETED")
            self.assertIn("observation-mismatch", result.reason)
            self.assertIsNone(result.envelope, "no successor may be signed")
            self.assertEqual(world.effect_count("book"), 1, "the booking took place")
            self.assertIs(dep.authority.status("run-1"), PolicyState.EFFECT_RECONCILE)

    def test_without_a_bound_ledger_the_same_attack_succeeds(self):
        """The ablation, stated as a measurement rather than as a claim.

        V3 and V4 accept the same attack, which is why the countermeasure belongs to V5.
        """
        policy, dep, s0, world = _deployment()
        with dep:
            envelope = _advance(policy, dep, s0, BOOK_STEP)
            host = _HostOnThePath(dep.gateway, "booking_ref", "BK-ATTACKER")
            result, _fragment = _run_step_through(dep, host, policy, envelope, BOOK_STEP)
            self.assertEqual(host.tampered, 1)
            self.assertEqual(result.status, "STEP_COMPLETED",
                             "without a ledger the rewritten value is accepted")

    def test_an_unreachable_ledger_refuses_rather_than_passes(self):
        """The check fails closed, otherwise an attacker could switch it off by cutting a connection."""
        policy, dep, s0, world = _deployment()
        with dep:
            envelope = _advance(policy, dep, s0, BOOK_STEP)
            dep.authority.bind_effect_ledger(_UnreachableLedger())   # only the measured step sees it
            result, _fragment = _run_step_through(dep, dep.gateway, policy, envelope, BOOK_STEP)
            self.assertNotEqual(result.status, "STEP_COMPLETED")
            self.assertIn("unreachable", result.reason)

    def test_a_pending_row_is_re_read_once_and_then_refused(self):
        """PENDING is neither a pass nor a permanent wait.

        The invariant says a response cannot exist before its committed row, so a PENDING row
        means a crash or a read that overtook a commit. One short re-read covers the second case.
        """
        policy, dep, s0, world = _deployment()
        with dep:
            envelope = _advance(policy, dep, s0, BOOK_STEP)
            pending = _PendingLedger()
            dep.authority.bind_effect_ledger(pending)
            result, _fragment = _run_step_through(dep, dep.gateway, policy, envelope, BOOK_STEP)
            self.assertNotEqual(result.status, "STEP_COMPLETED")
            self.assertIn("observation-pending", result.reason)
            self.assertEqual(pending.reads, 2, "one re-read, not a retry loop")

    def test_the_gateway_commits_its_outcome_before_it_answers(self):
        """Once a caller holds a response, the committed row with its digest is already there.

        This is the invariant the PENDING case rests on, measured here instead of assumed.
        """
        policy, dep, s0, world = _deployment()
        with dep:
            ledger = DurableLedger(dep.store)
            envelope = _advance(policy, dep, s0, BOOK_STEP)
            fragment = honest_fragment(policy, envelope.run_id, BOOK_STEP,
                                       happy_path_arguments()[BOOK_STEP])
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, fragment.run_id, fragment.fragment_hash, envelope.state_hash)
            grant, reason = dep.authority.request_execution_grant(
                credential, fragment, envelope.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIsNotNone(grant, reason)
            result = dep.gateway.execute(grant.token, fragment)
            state, digest = ledger.effect(grant.grant_id)
            self.assertEqual(state, "COMMITTED", "the reply arrived before its ledger row")
            self.assertEqual(digest, response_digest(result.outcome.value, result.payload))

    def test_a_missing_row_refuses_rather_than_passes(self):
        """An effect whose outcome did not become durable has nothing to compare against, so it is refused."""
        policy, dep, s0, world = _deployment()
        with dep:
            envelope = _advance(policy, dep, s0, BOOK_STEP)
            dep.authority.bind_effect_ledger(_EmptyLedger())   # only the measured step sees it
            result, _fragment = _run_step_through(dep, dep.gateway, policy, envelope, BOOK_STEP)
            self.assertNotEqual(result.status, "STEP_COMPLETED")
            self.assertIn("no committed effect recorded", result.reason)


class _RecordingLedger:
    """A ledger that answers like the one it wraps and remembers which grant it was asked about."""

    def __init__(self, inner) -> None:
        self._inner, self.asked = inner, []

    def effect(self, grant_id):
        self.asked.append(grant_id)
        return self._inner.effect(grant_id)


class TheLookupBelongsToTheAuthorityTests(unittest.TestCase):
    """The row is found by the Authority's own grant id."""

    def test_the_ledger_is_asked_about_the_authoritys_grant_id_not_the_reported_one(self):
        """The row is looked up by the grant id the Authority derived for itself.

        The test calls the check directly. The grant id the reported event carries is ignored.
        """
        authority, _b, _h = Authority.create(FixedClock(T0))
        recording = _RecordingLedger(_EmptyLedger())
        authority.bind_effect_ledger(recording)
        ok, why = authority._observation_matches("grant-the-authority-holds", {
            "outcome": "CONFIRMED", "payload": {"x": 1},
            "grant_id": "grant-of-the-attackers-choosing"})
        self.assertFalse(ok)
        self.assertEqual(recording.asked, ["grant-the-authority-holds"])

    def test_the_digest_covers_the_payload_the_report_carries(self):
        """A rewritten payload is refused, and every ledger read during the step asks about the same grant."""
        policy, dep, s0, world = _deployment()
        with dep:
            envelope = _advance(policy, dep, s0, BOOK_STEP)
            recording = _RecordingLedger(DurableLedger(dep.store))
            dep.authority.bind_effect_ledger(recording)
            host = _HostOnThePath(dep.gateway, "booking_ref", "BK-ATTACKER")
            result, _f = _run_step_through(dep, host, policy, envelope, BOOK_STEP)
            self.assertIn("observation-mismatch", result.reason)
            self.assertEqual(len(set(recording.asked)), 1, "every read asked about the same grant")


class TheRecoveryPathRecordsTheSameDigestTests(unittest.TestCase):
    """Idempotent recovery must not write a different digest than the response it returns."""

    def test_recovery_writes_the_digest_of_the_response_it_returns(self):
        world = ExternalWorld(idempotent=True)
        policy = default_p3()
        dep = RecoveringProcessDeployment(FixedClock(T0), executor=world.executor,
                                          downstream_idempotent=True, enable_recovery=True,
                                          enable_test_api=True)
        approval = approve(policy, approver_id="alice", approval_id="A-run-1",
                           run_id="run-1", issued_at=ISSUED, expires_at=EXPIRES)
        s0 = dep.authority.create_run(policy, approval, "run-1")
        with dep:
            ledger = DurableLedger(dep.store)
            fragment = honest_fragment(policy, "run-1", 0, happy_path_arguments()[0])
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, fragment.run_id, fragment.fragment_hash, s0.state_hash)
            grant, reason = dep.authority.request_execution_grant(
                credential, fragment, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIsNotNone(grant, reason)
            dep.server.crash_dispatch_once(before_effect=False)   # effect happens, outcome is lost
            with self.assertRaises(Exception):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(ledger.effect(grant.grant_id)[0], "PENDING")
            recovered = recover_dispatch(dep, grant.token, fragment)
            state, digest = ledger.effect(grant.grant_id)
            self.assertEqual(state, "COMMITTED")
            self.assertEqual(digest, response_digest(recovered.outcome.value, recovered.payload),
                             "recovery recorded a digest that is not the one it returned")


class TheCheckChangesNothingWhenUnboundTests(unittest.TestCase):
    """With no ledger bound the frozen stages stay the systems that were measured."""

    def test_an_honest_run_produces_the_same_statuses_with_and_without_a_ledger(self):
        def statuses(bind: bool):
            policy, dep, s0, world = _deployment()
            with dep:
                if bind:
                    dep.authority.bind_effect_ledger(DurableLedger(dep.store))
                out, envelope = [], s0
                for step, args in enumerate(happy_path_arguments()):
                    fragment = honest_fragment(policy, envelope.run_id, step, args)
                    r = dep.provisioner.spawn(fragment, envelope).execute(policy, envelope, fragment)
                    out.append((r.status, r.reason))
                    envelope = r.envelope
                rows = [(e.state, e.step, e.response_hash)
                        for e in DurableLedger(dep.store).entries_after(0)]
                return out, (envelope.state_hash if envelope else None), rows
        unbound, unbound_hash, unbound_rows = statuses(False)
        bound, bound_hash, bound_rows = statuses(True)
        self.assertEqual(unbound, bound, "binding the ledger changed an honest run")
        self.assertEqual(unbound_hash, bound_hash, "the final state hash differs")
        self.assertEqual(unbound_rows, bound_rows, "the ledger rows differ")


class ObservationCheckIsVisibleTests(unittest.TestCase):
    """A run record must be able to say which system produced it."""

    def test_the_authority_reports_its_own_wiring(self):
        policy, dep, s0, world = _deployment()
        with dep:
            self.assertEqual(dep.authority.observation_check(), "unbound")
            dep.authority.bind_effect_ledger(DurableLedger(dep.store))
            self.assertEqual(dep.authority.observation_check(), "bound")

    def test_a_wired_but_unreachable_ledger_is_not_reported_as_bound(self):
        """A ledger that is wired but unreachable does not count as bound.

        Pointing the Authority at the execution Service on the observation port is such a case.
        That Service publishes only 8443, so every read goes to a ClusterIP with no matching port,
        is not translated, and is lost. Each ledger read blocks for the full 30 s deployment
        timeout and every finalisation fails closed, while the run records would say `bound` the
        whole time if `bound` meant "a ledger object exists". Only a reachable ledger lets a
        finalisation be checked.
        """
        policy, dep, s0, world = _deployment()
        with dep:
            dep.authority.bind_effect_ledger(
                RemoteLedger(ServiceEndpoint.tcp("127.0.0.1", 1)))   # nothing listens there
            self.assertEqual(dep.authority.observation_check(), "unreachable")

    def test_the_question_is_on_the_authority_surface_and_not_on_the_gateway(self):
        self.assertIn("authority.observation_check", AUTHORITY_SURFACE)
        self.assertNotIn("authority.observation_check", GATEWAY_SURFACE | OBSERVATION_SURFACE)

    def test_the_value_reaches_the_run_manifest(self):
        self.assertEqual(_manifest([], "bound")["observation_check"], "bound")
        self.assertEqual(_manifest([])["observation_check"], "unknown")

    def test_an_unanswered_question_is_unknown_not_bound(self):
        """A deployment that cannot be asked is uncounted, not assumed to be checking."""
        self.assertEqual(_observation_check(ServiceEndpoint.tcp("127.0.0.1", 1)), "unknown")

    @needs_measured_freeze
    def test_a_reachable_authority_that_checks_answers_bound_over_the_wire(self):
        """The positive half of the unreachable-endpoint test above.

        A negative test whose expected value is also the value of every failure proves nothing on
        its own. `unknown` is what an endpoint that cannot answer yields, but also what a function
        that raises on every call would record. This test requires the answer `bound`.

        It is wired the way the pods are wired: `seed` then `start_authority`, with the gateway's
        observation endpoint passed in, because that is the deployment whose answer the live run
        records. A hand-built server around the harness facade would test a different object.
        """
        tmp = tempfile.mkdtemp(prefix="v5-observation-rpc-")
        freeze = json.loads((FREEZE / f"freeze-{STAMP}.json").read_text())
        freeze["binding_version"] = PROTOCOL_VERSION.decode()
        freeze_path = os.path.join(tmp, f"freeze-{STAMP}.json")
        with open(freeze_path, "w", encoding="utf-8") as fh:
            json.dump(freeze, fh)
        a_db, g_db = os.path.join(tmp, "authority.db"), os.path.join(tmp, "gateway.db")
        image = _runner_image_for(freeze, "ab")
        service_v5.seed(a_db, g_db, freeze_path, FixedClock(T0), runner_image=image)

        gateway, _ = service_v5.start_gateway(g_db, ("127.0.0.1", 0), ("127.0.0.1", 0),
                                              FixedClock(T0))
        self.addCleanup(gateway.close)
        host, _, port = gateway.observe_endpoint.address.rpartition(":")
        authority, _ = service_v5.start_authority(a_db, ("127.0.0.1", 0), FixedClock(T0),
                                                  verifier_factory=FakeVerifier,
                                                  gateway_observe=(host, int(port)))
        self.addCleanup(authority.close)
        self.assertEqual(_observation_check(authority.endpoint), "bound")

    @needs_measured_freeze
    def test_an_authority_without_the_wiring_answers_unbound_over_the_wire(self):
        """The same deployment without `--gateway-observe` answers, and the answer is not `bound`."""
        tmp = tempfile.mkdtemp(prefix="v5-observation-rpc-unbound-")
        freeze = json.loads((FREEZE / f"freeze-{STAMP}.json").read_text())
        freeze["binding_version"] = PROTOCOL_VERSION.decode()
        freeze_path = os.path.join(tmp, f"freeze-{STAMP}.json")
        with open(freeze_path, "w", encoding="utf-8") as fh:
            json.dump(freeze, fh)
        a_db, g_db = os.path.join(tmp, "authority.db"), os.path.join(tmp, "gateway.db")
        service_v5.seed(a_db, g_db, freeze_path, FixedClock(T0),
                        runner_image=_runner_image_for(freeze, "cd"))
        authority, _ = service_v5.start_authority(a_db, ("127.0.0.1", 0), FixedClock(T0),
                                                  verifier_factory=FakeVerifier)
        self.addCleanup(authority.close)
        self.assertEqual(_observation_check(authority.endpoint), "unbound")


def _runner_image_for(freeze: dict, fill: str) -> str:
    """Return the runner image a seeded test deployment must use for this freeze.

    A freeze of the `run` profile pins the run init-data digest, which contains the runner image,
    so the deployment must render that image. Other profiles accept a placeholder image of the
    given fill byte.
    """
    init = freeze.get("init_data", {})
    if init.get("profile") == "run":
        return init["runner_image"]
    return "eu.gcr.io/x/booking@sha256:" + fill * 32


if __name__ == "__main__":
    unittest.main(verbosity=2)
