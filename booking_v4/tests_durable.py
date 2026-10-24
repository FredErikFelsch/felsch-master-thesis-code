"""Unit tests for the durable services: durability, idempotency and the effect semantics of `durable`.

Run from the repository root:  python3 -m booking_v4.tests_durable
"""

from __future__ import annotations

import json
import os
import functools
import subprocess
import sys
import tempfile
import threading
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.lifecycle import PolicyState

from booking_v3.authority import ProvisionerCredential
from booking_v3.envelope import TrustAnchors, VerifyKey
from booking_v2.world import v2_executor
from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3

from . import wire
from .durable import DurableProcessDeployment, ExternalWorld, expected_grant_id
from .process_backend import ProcessRunnerProvisioner
from .services import AuthorityClient, GatewayClient, _call
from .tests_recovery_support import RecoveringProcessDeployment, recover_dispatch

T0 = 1_700_000_010
ISSUED, EXPIRES = 1_700_000_000, 1_700_003_600
PAY = {"amount_minor": 34900, "currency": "EUR",
       "recipient": "airline:LH", "action_id": "pay-1"}
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _deployment(run_id="run-1", **kwargs):
    """Return (policy, deployment, s0) for a durable deployment with one activated run."""
    policy = default_p3()
    dep = DurableProcessDeployment(FixedClock(T0), enable_test_api=True, **kwargs)
    approval = approve(policy, approver_id="alice", approval_id=f"A-{run_id}",
                       run_id=run_id, issued_at=ISSUED, expires_at=EXPIRES)
    s0 = dep.authority.create_run(policy, approval, run_id)
    return policy, dep, s0


def _advance(policy, dep, envelope, upto):
    """Run the first `upto` happy-path steps and return all envelopes, s0 first."""
    envelopes = [envelope]
    for step, args in enumerate(happy_path_arguments()[:upto]):
        fragment = honest_fragment(policy, envelope.run_id, step, args)
        result = dep.provisioner.spawn(fragment, envelope).execute(policy, envelope, fragment)
        assert result.status == "STEP_COMPLETED", result.reason
        envelope = result.envelope
        envelopes.append(envelope)
    return envelopes


def _harness_grant(dep, fragment, state_hash):
    """Obtain a grant as the trusted runner would, through the durable service."""
    credential = dep.authority.establish_runner_session(
        dep.bootstrap, fragment.run_id, fragment.fragment_hash, state_hash)
    grant, reason = dep.authority.request_execution_grant(
        credential, fragment, state_hash,
        {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
    assert grant is not None, reason
    return credential, grant


class TestDurabilityAcrossRestart(unittest.TestCase):
    """A service crash forgets nothing the guarantees depend on."""

    def test_run_continues_across_service_restart(self):
        p, dep, s0 = _deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            dep.restart_services()
            envelope = envelopes[-1]
            for step, args in enumerate(happy_path_arguments()[2:], start=2):
                fragment = honest_fragment(p, "run-1", step, args)
                result = dep.provisioner.spawn(fragment, envelope).execute(p, envelope, fragment)
                self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
                envelope = result.envelope
            self.assertEqual(envelope.step_index, 4)
            self.assertIs(dep.authority.status("run-1"), PolicyState.COMPLETED)
            self.assertEqual([e["operation"] for e in dep.gateway.executions],
                             ["search", "select", "book", "pay"])

    def test_created_run_survives_restart_without_manual_checkpoint(self):
        """create_run itself passes through the durable service."""
        p, dep, s0 = _deployment()
        with dep:
            dep.restart_services()
            self.assertIs(dep.authority.status("run-1"), PolicyState.ACTIVE)
            envelopes = _advance(p, dep, s0, 1)
            self.assertEqual(envelopes[-1].step_index, 1)

    def test_established_session_survives_restart(self):
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, "run-1", fragment.fragment_hash, s0.state_hash)
            dep.restart_services()
            grant, reason = dep.authority.request_execution_grant(
                credential, fragment, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIsNotNone(grant, reason)

    def test_effect_pending_survives_restart_and_blocks_a_second_grant(self):
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _harness_grant(dep, fragment, s0.state_hash)
            self.assertIs(dep.authority.status("run-1"), PolicyState.EFFECT_PENDING)
            dep.restart_services()
            self.assertIs(dep.authority.status("run-1"), PolicyState.EFFECT_PENDING)
            other = honest_fragment(p, "run-1", 0, {"to": "MUC"})
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, "run-1", other.fragment_hash, s0.state_hash)
            grant, reason = dep.authority.request_execution_grant(
                credential, other, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIsNone(grant)
            self.assertIn("effect in progress", reason)

    def test_duplicate_action_id_survives_restart(self):
        p, dep, s0 = _deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 3)
            dep.restart_services()
            fragment = honest_fragment(p, "run-1", 3, {**PAY, "action_id": "book-1"})
            result = dep.provisioner.spawn(fragment, envelopes[-1]).execute(
                p, envelopes[-1], fragment)
            self.assertEqual(result.status, "GRANT_REFUSED")
            self.assertIn("duplicate action_id", result.reason)

    def test_consumed_token_survives_restart(self):
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            first = dep.gateway.execute(grant.token, fragment)
            self.assertFalse(hasattr(first, "reason"))  # an EffectResult
            dep.restart_services()
            # The durable consumed set: the restored gateway itself refuses.
            refusal = dep._real_gateway.execute(grant.token, fragment)
            self.assertTrue(hasattr(refusal, "reason"))
            self.assertIn("single use", refusal.reason)
            self.assertEqual(len(dep.gateway.executions), 1)

    def test_outcome_recoverable_after_restart(self):
        """After a restart, execute still refuses the consumed token (booking_v3 semantics),
        and the outcome is recovered read-only, without a second dispatch."""
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            first = dep.gateway.execute(grant.token, fragment)
            dep.restart_services()
            refused = dep.gateway.execute(grant.token, fragment)
            self.assertTrue(hasattr(refused, "reason"))
            self.assertIn("single use", refused.reason)
            again = dep.gateway.dispatch_outcome(grant.token, fragment)
            self.assertEqual(first.outcome, again.outcome)
            self.assertEqual(first.payload, again.payload)
            self.assertEqual(len(dep.gateway.executions), 1)


class TestMemoryEqualsDurable(unittest.TestCase):
    """A failed durable commit rolls the live objects back too."""

    def test_commit_failure_rolls_back_memory(self):
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, "run-1", fragment.fragment_hash, s0.state_hash)
            before = dep._real_authority.export_state()
            dep.store.fail_next_commit()
            with self.assertRaises(wire.WireError) as ctx:
                dep.authority.request_execution_grant(
                    credential, fragment, s0.state_hash,
                    {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIn("rolled back", str(ctx.exception))
            # Memory equals the pre-request snapshot equals the durable state.
            self.assertEqual(dep._real_authority.export_state(), before)
            self.assertIs(dep.authority.status("run-1"), PolicyState.ACTIVE)
            # The rolled-back session is open again, so the retry succeeds.
            grant, reason = dep.authority.request_execution_grant(
                credential, fragment, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIsNotNone(grant, reason)


    def test_a_method_that_raises_halfway_leaves_no_partial_state(self):
        """A method that changes the Authority and then raises is stored as an error, not as a change."""
        from unittest import mock
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, "run-1", fragment.fragment_hash, s0.state_hash)
            before = dep._real_authority.export_state()
            real = dep._real_authority.request_execution_grant

            def grant_then_raise(*args, **kwargs):
                real(*args, **kwargs)                 # the run moves to EFFECT_PENDING
                raise RuntimeError("fails after the change")

            with mock.patch.object(dep._real_authority, "request_execution_grant", grant_then_raise):
                with self.assertRaises(wire.WireError):
                    dep.authority.request_execution_grant(
                        credential, fragment, s0.state_hash,
                        {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertEqual(dep._real_authority.export_state(), before)
            self.assertIs(dep.authority.status("run-1"), PolicyState.ACTIVE)
            self.assertEqual(dep.store.load_states()[0], before)

class TestIdempotencyIdentity(unittest.TestCase):
    """Server-derived identities for internal RPCs. Execute keeps the booking_v3 semantics."""

    def test_grant_retry_same_identity_replays(self):
        """An internal RPC (grant) replays its stored reply on an identical retry."""
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, "run-1", fragment.fragment_hash, s0.state_hash)
            g1, _ = dep.authority.request_execution_grant(
                credential, fragment, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "h"})
            g2, _ = dep.authority.request_execution_grant(
                credential, fragment, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "h"})
            self.assertEqual(g1.grant_id, g2.grant_id)  # stored reply, one grant

    def test_attacker_forged_token_cannot_poison_or_dispatch(self):
        """A forged token gets refused and neither dispatches nor blocks the real one."""
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            fake_token = wire.token_to_wire(grant.token)
            fake_token["signature"] = "00" * 64
            attack = _call(dep.server.socket_path, "gateway.execute", {
                "token": fake_token, "fragment": wire.fragment_to_wire(fragment)})
            self.assertEqual(attack["result"]["kind"], "gateway-refusal")
            # No intent was persisted under the real grant, so the legitimate call works.
            result = dep.gateway.execute(grant.token, fragment)
            self.assertFalse(hasattr(result, "reason"))
            self.assertEqual(len(dep.gateway.executions), 1)


class _CountingExecutor:
    """The simulated counterparty's own call counter, independent of the gateway's record."""

    def __init__(self) -> None:
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, call):
        with self._lock:
            self.calls += 1
        return v2_executor(call)


class TestRecoveryClosed(unittest.TestCase):
    """No reachable operation re-submits an authorised request.

    The shipped gateway has no effectful recovery: the method is not in the code,
    `downstream_idempotent` cannot add it, and a client that asks is refused as an unknown
    method. The assertions read the counterparty's own call counter, not the gateway's record.
    """

    def _setup(self):
        provider = _CountingExecutor()
        world = ExternalWorld(idempotent=False, executor=provider)
        policy = default_p3()
        dep = DurableProcessDeployment(
            FixedClock(T0), executor=world.executor,
            downstream_idempotent=True, enable_test_api=True)  # the shipped server: no recovery
        approval = approve(policy, approver_id="alice", approval_id="A-run-1",
                           run_id="run-1", issued_at=ISSUED, expires_at=EXPIRES)
        s0 = dep.authority.create_run(policy, approval, "run-1")
        return policy, dep, s0, provider

    def test_valid_token_fragment_and_open_intent_do_not_enable_recovery(self):
        """All preconditions of the old recovery hold, the call is refused, no dispatch."""
        p, dep, s0, provider = self._setup()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=True)  # intent durable, no effect
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(provider.calls, 0)
            with self.assertRaises(wire.WireError) as ctx:
                recover_dispatch(dep, grant.token, fragment)
            self.assertIn("unknown method", str(ctx.exception))
            self.assertEqual(provider.calls, 0)
            # the read-only query stays available and reports the open intent as uncertain
            result = dep.gateway.dispatch_outcome(grant.token, fragment)
            self.assertEqual(result.outcome.value, "UNCERTAIN")
            self.assertEqual(provider.calls, 0)

    def test_crash_after_counterparty_processed_stays_closed_after_restart(self):
        """The counterparty acted, the gateway has no outcome: neither retry path re-dispatches."""
        p, dep, s0, provider = self._setup()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=False)  # effect ran, outcome not stored
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(provider.calls, 1)
            dep.restart_services()
            refused = dep.gateway.execute(grant.token, fragment)  # token stays consumed
            self.assertTrue(hasattr(refused, "reason"))
            with self.assertRaises(wire.WireError):
                recover_dispatch(dep, grant.token, fragment)
            result = dep.gateway.dispatch_outcome(grant.token, fragment)
            self.assertEqual(result.outcome.value, "UNCERTAIN")
            self.assertEqual(provider.calls, 1)

    def test_concurrent_submissions_cause_one_dispatch(self):
        """Simultaneous execute and recover calls on one grant reach the counterparty once."""
        p, dep, s0, provider = self._setup()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            barrier = threading.Barrier(6)
            outcomes: list[str] = []

            def submit(call) -> None:
                barrier.wait()
                try:
                    result = call(grant.token, fragment)
                    outcomes.append("refused" if hasattr(result, "reason") else "effect")
                except (wire.WireError, OSError):
                    outcomes.append("error")

            calls = [dep.gateway.execute] * 4 + [functools.partial(recover_dispatch, dep)] * 2
            threads = [threading.Thread(target=submit, args=(c,)) for c in calls]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
            self.assertEqual(len(outcomes), 6)
            self.assertEqual(outcomes.count("effect"), 1)
            self.assertEqual(provider.calls, 1)


class TestDispatchWindow(unittest.TestCase):
    """The dual-write window between the durable store and the external world."""

    def _setup(self, idempotent: bool, recovery: bool = False):
        world = ExternalWorld(idempotent=idempotent)
        policy = default_p3()
        # Recovery exists only in the test double. Without it the shipped server is used.
        dep = (RecoveringProcessDeployment(FixedClock(T0), executor=world.executor, enable_recovery=True,
                                           downstream_idempotent=idempotent, enable_test_api=True)
               if recovery else
               DurableProcessDeployment(FixedClock(T0), executor=world.executor,
                                        downstream_idempotent=idempotent, enable_test_api=True))
        approval = approve(policy, approver_id="alice", approval_id="A-run-1",
                           run_id="run-1", issued_at=ISSUED, expires_at=EXPIRES)
        s0 = dep.authority.create_run(policy, approval, "run-1")
        return policy, dep, s0, world

    def test_crash_after_effect_without_downstream_idempotency(self):
        """Effect happened, outcome commit skipped: recovery is UNCERTAIN, one effect."""
        p, dep, s0, world = self._setup(idempotent=False)
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=False)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("search"), 1)  # it did happen
            # execute refuses the consumed token, and recovery does not claim it never happened.
            refused = dep.gateway.execute(grant.token, fragment)
            self.assertTrue(hasattr(refused, "reason"))
            result = dep.gateway.dispatch_outcome(grant.token, fragment)
            self.assertEqual(result.outcome.value, "UNCERTAIN")
            self.assertEqual(world.effect_count("search"), 1)  # not executed again

    def test_crash_before_effect_without_downstream_idempotency(self):
        """The intent is durable and the effect did not run: recovery is UNCERTAIN, with no effect."""
        p, dep, s0, world = self._setup(idempotent=False)
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=True)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("search"), 0)
            result = dep.gateway.dispatch_outcome(grant.token, fragment)
            self.assertEqual(result.outcome.value, "UNCERTAIN")
            self.assertEqual(world.effect_count("search"), 0)

    def test_outcome_commit_failure_leaves_uncertain_one_effect(self):
        """The external effect happened and the phase-two commit fails: UNCERTAIN."""
        p, dep, s0, world = self._setup(idempotent=False)
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            # Phase one commits. The effect runs. The phase-two commit fails.
            dep.store.fail_next_commit_after(1)
            with self.assertRaises(wire.WireError):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("search"), 1)  # effect stands
            # The live gateway is back at the durable phase-one state: the intent stands
            # and the outcome is absent.
            result = dep.gateway.dispatch_outcome(grant.token, fragment)
            self.assertEqual(result.outcome.value, "UNCERTAIN")
            self.assertEqual(world.effect_count("search"), 1)  # not executed again

    def test_crash_with_downstream_idempotency_recovers_one_effect(self):
        """With recovery explicitly enabled, an idempotent downstream makes the window a safe recovery."""
        p, dep, s0, world = self._setup(idempotent=True, recovery=True)
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            fragment = honest_fragment(
                p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            _credential, grant = _harness_grant(dep, fragment, envelopes[-1].state_hash)
            dep.server.crash_dispatch_once(before_effect=False)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("book"), 1)
            result = recover_dispatch(dep, grant.token, fragment)
            self.assertEqual(result.outcome.value, "CONFIRMED")
            self.assertEqual(world.effect_count("book"), 1)  # at most one logical booking

    def test_recover_dispatch_commit_failure_rolls_back_one_effect(self):
        """Recovery performs the effect again and its outcome commit fails.

        The live gateway returns to phase one, the intent stands, and a second recovery
        succeeds with one logical effect in the world.
        """
        p, dep, s0, world = self._setup(idempotent=True, recovery=True)
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            fragment = honest_fragment(
                p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            _credential, grant = _harness_grant(dep, fragment, envelopes[-1].state_hash)
            dep.server.crash_dispatch_once(before_effect=False)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("book"), 1)
            before = dep._real_gateway.export_state()
            dep.store.fail_next_commit()  # the recovery outcome commit fails
            with self.assertRaises(wire.WireError) as ctx:
                recover_dispatch(dep, grant.token, fragment)
            self.assertIn("intent stands", str(ctx.exception))
            self.assertEqual(dep._real_gateway.export_state(), before)  # memory restored
            self.assertEqual(world.effect_count("book"), 1)  # downstream deduped
            result = recover_dispatch(dep, grant.token, fragment)
            self.assertEqual(result.outcome.value, "CONFIRMED")
            self.assertEqual(world.effect_count("book"), 1)  # still one

    def test_read_only_dispatch_outcome_does_not_call_downstream(self):
        """dispatch_outcome stays read-only even with an idempotent downstream."""
        p, dep, s0, world = self._setup(idempotent=True)
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=True)  # the effect does not run
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("search"), 0)
            result = dep.gateway.dispatch_outcome(grant.token, fragment)
            self.assertEqual(result.outcome.value, "UNCERTAIN")
            self.assertEqual(world.effect_count("search"), 0)  # read-only: no call

    def test_dispatch_outcome_rejects_tampered_token(self):
        """Recovery requires a valid token: a tampered one is refused."""
        p, dep, s0, world = self._setup(idempotent=False)
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=False)
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            bad = wire.token_to_wire(grant.token)
            bad["signature"] = "00" * 64
            with self.assertRaises(wire.WireError) as ctx:
                _call(dep.server.socket_path, "gateway.dispatch_outcome", {
                    "token": bad, "fragment": wire.fragment_to_wire(fragment)})
            self.assertIn("refused", str(ctx.exception))


class TestAmbiguousOutcome(unittest.TestCase):
    """A reply lost after the commit yields neither a second effect nor a silent retry."""

    def test_lost_gateway_reply_parks_uncertain_without_retry(self):
        p, dep, s0 = _deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            dep.server.drop_reply_once("gateway.execute")
            fragment = honest_fragment(p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            handle = dep.provisioner.spawn(fragment, envelopes[-1])
            # the reply is lost, the runner reconciles read only and reports UNCERTAIN
            self.assertEqual(handle.execute(p, envelopes[-1], fragment).status, "EFFECT_UNCERTAIN")
            self.assertEqual([e["operation"] for e in dep.gateway.executions],
                             ["search", "select", "book"])
            self.assertIs(dep.authority.status("run-1"), PolicyState.EFFECT_UNCERTAIN)
            retry = honest_fragment(p, "run-1", 2, {"flight": "LH123", "action_id": "book-2"})
            result = dep.provisioner.spawn(retry, envelopes[-1]).execute(
                p, envelopes[-1], retry)
            self.assertEqual(result.status, "GRANT_REFUSED")
            self.assertEqual([e["operation"] for e in dep.gateway.executions],
                             ["search", "select", "book"])  # still one booking

    def test_lost_finalize_reply_recovered_and_run_completes(self):
        p, dep, s0 = _deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            dep.server.drop_reply_once("authority.finalize_transition")
            fragment = honest_fragment(p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            handle = dep.provisioner.spawn(fragment, envelopes[-1])
            with self.assertRaises(RuntimeError):
                handle.execute(p, envelopes[-1], fragment)  # the Authority reply is lost, not the gateway's
            self.assertIs(dep.authority.status("run-1"), PolicyState.ACTIVE)
            self.assertEqual([e["operation"] for e in dep.gateway.executions],
                             ["search", "select", "book"])
            grant_id = expected_grant_id(
                "run-1", 2, fragment.fragment_hash, envelopes[-1].state_hash)
            reply = _call(dep.server.socket_path, "authority.finalize_outcome",
                          {"grant_id": grant_id})
            s3 = wire.envelope_from_wire(reply["envelope"])
            self.assertEqual(s3.step_index, 3)
            pay = honest_fragment(p, "run-1", 3, PAY)
            result = dep.provisioner.spawn(pay, s3).execute(p, s3, pay)
            self.assertEqual(result.status, "STEP_COMPLETED")
            self.assertIs(dep.authority.status("run-1"), PolicyState.COMPLETED)


class TestRecoveryEndpointsLeakNothing(unittest.TestCase):
    """The read-only recovery endpoints carry no identity, so they hand back only what their
    caller would have received anyway.

    The gateway and the Authority each record the same effect. Under one shared primary key,
    `grant_id`, that would have two consequences:

      * `authority.finalize_outcome` takes nothing but a `grant_id`, and `expected_grant_id`
        derives that from run, step, fragment hash and input state, all of which the untrusted
        orchestrator chose itself. On any outcome other than CONFIRMED_VALIDATED the Authority
        writes no row, so the row under that key would be the gateway's, including the
        counterparty payload that the monitor withholds from the agent.
      * On the happy path the Authority's row would replace the gateway's, so
        `gateway.dispatch_outcome` would answer a recovering holder of the token with the
        Authority's envelope instead of the effect it was asking about.

    One key prefix per writer prevents both, and each reader sees only its own rows.
    """

    def test_a_withheld_gateway_record_is_not_readable_through_finalize_outcome(self):
        """The gateway's reply is durable, the runner did not deliver it, and the Authority
        wrote no row for this grant, so the recovery endpoint has nothing to return."""
        p, dep, s0 = _deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            dep.server.drop_reply_once("gateway.execute")
            fragment = honest_fragment(p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            handle = dep.provisioner.spawn(fragment, envelopes[-1])
            # the reply is lost, the runner reconciles read only and reports UNCERTAIN
            self.assertEqual(handle.execute(p, envelopes[-1], fragment).status, "EFFECT_UNCERTAIN")
            self.assertIs(dep.authority.status("run-1"), PolicyState.EFFECT_UNCERTAIN)
            # the counterparty did act, so the gateway's record exists
            self.assertEqual([e["operation"] for e in dep.gateway.executions],
                             ["search", "select", "book"])

            grant_id = expected_grant_id("run-1", 2, fragment.fragment_hash,
                                         envelopes[-1].state_hash)
            with self.assertRaises(wire.WireError) as ctx:
                _call(dep.server.socket_path, "authority.finalize_outcome",
                      {"grant_id": grant_id})
            self.assertIn("no recorded outcome", str(ctx.exception))

    def test_the_gateway_record_survives_the_finalization_of_the_same_grant(self):
        """The Authority's row holds the signed successor and nothing of the counterparty."""
        p, dep, s0 = _deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            fragment = honest_fragment(p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            result = dep.provisioner.spawn(fragment, envelopes[-1]).execute(
                p, envelopes[-1], fragment)
            self.assertEqual(result.status, "STEP_COMPLETED")
            grant_id = expected_grant_id("run-1", 2, fragment.fragment_hash,
                                         envelopes[-1].state_hash)
            # the Authority's row: the signed successor, and nothing of the counterparty
            auth = _call(dep.server.socket_path, "authority.finalize_outcome",
                         {"grant_id": grant_id})
            self.assertIn("envelope", auth)
            self.assertNotIn("result", auth)


class TestIdempotencyIdentityAndHonestReplies(unittest.TestCase):
    """Reports: the identity covers the whole request, and the answer says what the Authority did.

    The idempotency identity is per-method material plus the request content. For the two
    report methods that material is the session secret alone. A retry of `report_denial` is
    the same call, so the material suffices for the honest runner but not against anyone else
    who holds the credential. Without the content, a first call with any other content would
    occupy the identity slot, and the honest report that followed would be refused with
    "identity reused with different content", leaving the run alive with no denial recorded.

    Separately, neither report method answers `{"ok": true}` regardless of what the Authority
    did, because a runner whose report was refused could not then tell.
    """

    def _session(self, dep, s0):
        """Establish a session for the first fragment and return (fragment, credential wire)."""
        fragment = honest_fragment(default_p3(), "run-1", 0, {"to": "FRA"})
        credential = dep.authority.establish_runner_session(
            dep.bootstrap, "run-1", fragment.fragment_hash, s0.state_hash)
        return fragment, wire.credential_to_wire(credential)

    def _deny(self, dep, cw, event):
        """Send one raw report_denial with the given admission event."""
        return _call(dep.server.socket_path, "authority.report_denial",
                     {"credential": cw, "run_id": "run-1", "admission_event": event,
                      "attestation": None})

    def test_a_first_foreign_report_no_longer_locks_out_the_honest_one(self):
        p, dep, s0 = _deployment()
        with dep:
            fragment, cw = self._session(dep, s0)
            # someone else on the channel speaks first, with other content
            foreign = self._deny(dep, cw, {"kind": "admission", "decision": "ALLOW",
                                           "fragment_hash": fragment.fragment_hash})
            # the honest runner's real denial is a different request and is judged on its
            # own merits, not refused as a reused identity
            honest = self._deny(dep, cw, {"kind": "admission", "decision": "DENY",
                                          "reason": "cross-step binding violated",
                                          "fragment_hash": fragment.fragment_hash})
            self.assertIn("ok", foreign)
            self.assertIn("ok", honest, "the honest report must reach the Authority")

    def test_a_report_that_was_not_acted_on_says_so(self):
        p, dep, s0 = _deployment()
        with dep:
            fragment, cw = self._session(dep, s0)
            event = {"kind": "admission", "decision": "DENY", "reason": "x",
                     "fragment_hash": fragment.fragment_hash}
            self.assertTrue(self._deny(dep, cw, event)["ok"], "the first denial is acted on")
            self.assertIs(dep.authority.status("run-1"), PolicyState.TERMINATED)
            # the session is consumed, so a second report changes nothing and says so
            self.assertFalse(self._deny(dep, cw, dict(event, reason="again"))["ok"])

    def test_a_lost_gateway_reply_books_once(self):
        """After a lost gateway reply the runner reconciles read only, so the booking happens once.

        gateway.execute has no reply table: the consumed token and the read-only lookup in the
        runner keep the effect single. `test_grant_retry_same_identity_replays` covers the
        replay of a stored reply.
        """
        p, dep, s0 = _deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 2)
            dep.server.drop_reply_once("gateway.execute")
            fragment = honest_fragment(p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
            handle = dep.provisioner.spawn(fragment, envelopes[-1])
            # the reply is lost, the runner reconciles read only and reports UNCERTAIN
            self.assertEqual(handle.execute(p, envelopes[-1], fragment).status, "EFFECT_UNCERTAIN")
            self.assertEqual([e["operation"] for e in dep.gateway.executions],
                             ["search", "select", "book"], "one booking, not two")


class TestServiceProcessKill(unittest.TestCase):
    """SIGKILL the separate service process and restart it on the same store."""

    def _start_service(self, db, socket_path, world_db=None, idempotent=False):
        """Start `booking_v4.service_process` and return (process, handshake, anchors)."""
        cmd = [sys.executable, "-m", "booking_v4.service_process",
               "--db", db, "--socket", socket_path, "--now", str(T0),
               "--enable-test-api"]
        if world_db:
            cmd += ["--world-db", world_db]
        if idempotent:
            cmd.append("--idempotent")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                cwd=_REPO_ROOT, text=True)
        handshake = json.loads(proc.stdout.readline())
        anchors = TrustAnchors(
            envelope_key=VerifyKey.from_bytes(bytes.fromhex(handshake["envelope_key"])),
            intervention_key=VerifyKey.from_bytes(bytes.fromhex(handshake["intervention_key"])))
        return proc, handshake, anchors

    def _create_run(self, socket_path, policy, run_id="run-1"):
        """Activate a run at the service and return its genesis envelope."""
        approval = approve(policy, approver_id="alice", approval_id=f"A-{run_id}",
                           run_id=run_id, issued_at=ISSUED, expires_at=EXPIRES)
        reply = _call(socket_path, "authority.create_run", {
            "policy": wire.policy_to_wire(policy),
            "approval": wire.approval_to_wire(approval), "run_id": run_id})
        return wire.envelope_from_wire(reply["envelope"])

    def _remote_provisioner(self, socket_path, handshake, anchors):
        """Return a process provisioner that talks to the service process."""
        from .durable import RemoteAuthorityHandle
        return ProcessRunnerProvisioner(
            RemoteAuthorityHandle(socket_path), anchors,
            ProvisionerCredential(secret=handshake["bootstrap"]), socket_path)

    def test_sigkill_mid_run_and_continue(self):
        p = default_p3()
        tmp = tempfile.mkdtemp(prefix="durable-kill-")
        db, sock = os.path.join(tmp, "d.db"), os.path.join(tmp, "svc.sock")
        proc, handshake, anchors = self._start_service(db, sock)
        try:
            s0 = self._create_run(sock, p)
            provisioner = self._remote_provisioner(sock, handshake, anchors)
            envelope = s0
            for step, args in enumerate(happy_path_arguments()[:2]):
                fragment = honest_fragment(p, "run-1", step, args)
                result = provisioner.spawn(fragment, envelope).execute(p, envelope, fragment)
                self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
                envelope = result.envelope
            proc.kill()   # SIGKILL, no cleanup at all
            proc.wait()
            proc, handshake, anchors = self._start_service(db, sock)
            provisioner = self._remote_provisioner(sock, handshake, anchors)
            for step, args in enumerate(happy_path_arguments()[2:], start=2):
                fragment = honest_fragment(p, "run-1", step, args)
                result = provisioner.spawn(fragment, envelope).execute(p, envelope, fragment)
                self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
                envelope = result.envelope
            status = _call(sock, "read.status", {"run_id": "run-1"})["status"]
            self.assertEqual(status, "COMPLETED")
            ops = list(_call(sock, "read.dispatch_ops", {})["operations"])
            self.assertEqual(ops, ["search", "select", "book", "pay"])
        finally:
            proc.kill()
            proc.wait()

    def test_sigkill_while_effect_pending(self):
        p = default_p3()
        tmp = tempfile.mkdtemp(prefix="durable-kill-")
        db, sock = os.path.join(tmp, "d.db"), os.path.join(tmp, "svc.sock")
        proc, handshake, anchors = self._start_service(db, sock)
        try:
            from .durable import RemoteAuthorityHandle
            s0 = self._create_run(sock, p)
            handle = RemoteAuthorityHandle(sock)
            bootstrap = ProvisionerCredential(secret=handshake["bootstrap"])
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            credential = handle.establish_runner_session(
                bootstrap, "run-1", fragment.fragment_hash, s0.state_hash)
            client = AuthorityClient(sock)
            grant, reason = client.request_execution_grant(
                credential, fragment, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIsNotNone(grant, reason)
            proc.kill()
            proc.wait()
            proc, handshake, anchors = self._start_service(db, sock)
            status = _call(sock, "read.status", {"run_id": "run-1"})["status"]
            self.assertEqual(status, "EFFECT_PENDING")
            other = honest_fragment(p, "run-1", 0, {"to": "MUC"})
            credential2 = RemoteAuthorityHandle(sock).establish_runner_session(
                ProvisionerCredential(secret=handshake["bootstrap"]), "run-1",
                other.fragment_hash, s0.state_hash)
            grant2, reason2 = AuthorityClient(sock).request_execution_grant(
                credential2, other, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            self.assertIsNone(grant2)
            self.assertIn("effect in progress", reason2)
        finally:
            proc.kill()
            proc.wait()

    def test_sigkill_inside_dispatch_window(self):
        """The service process dies between the external effect and the durable outcome."""
        p = default_p3()
        tmp = tempfile.mkdtemp(prefix="durable-kill-")
        db, sock = os.path.join(tmp, "d.db"), os.path.join(tmp, "svc.sock")
        world_db = os.path.join(tmp, "airline.db")
        proc, handshake, anchors = self._start_service(db, sock, world_db=world_db)
        try:
            from .durable import RemoteAuthorityHandle
            s0 = self._create_run(sock, p)
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            credential = RemoteAuthorityHandle(sock).establish_runner_session(
                ProvisionerCredential(secret=handshake["bootstrap"]), "run-1",
                fragment.fragment_hash, s0.state_hash)
            grant, _ = AuthorityClient(sock).request_execution_grant(
                credential, fragment, s0.state_hash,
                {"kind": "admission", "decision": "ALLOW", "reason": "harness"})
            _call(sock, "test.crash_dispatch_once", {"before_effect": False, "hard": True})
            with self.assertRaises((wire.WireError, OSError)):
                GatewayClient(sock).execute(grant.token, fragment)
            proc.wait()  # the whole service died mid-request
            airline = ExternalWorld(db_path=world_db)
            self.assertEqual(airline.effect_count("search"), 1)  # the effect did happen
            proc, handshake, anchors = self._start_service(db, sock, world_db=world_db)
            # execute refuses the consumed token, and recovery is read-only.
            refused = GatewayClient(sock).execute(grant.token, fragment)
            self.assertTrue(hasattr(refused, "reason"))
            result = GatewayClient(sock).dispatch_outcome(grant.token, fragment)
            self.assertEqual(result.outcome.value, "UNCERTAIN")  # no retry
            self.assertEqual(ExternalWorld(db_path=world_db).effect_count("search"), 1)
        finally:
            proc.kill()
            proc.wait()


class TestSessionEstablishmentIdempotency(unittest.TestCase):
    """Establishing a session again with the same nonce returns the stored credential."""

    def test_lost_establish_reply_same_nonce_one_session(self):
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            nonce = "fixed-establish-nonce-1"
            dep.server.drop_reply_once("authority.establish_runner_session")
            with self.assertRaises(wire.WireError):
                dep.authority.establish_runner_session(
                    dep.bootstrap, "run-1", fragment.fragment_hash,
                    s0.state_hash, request_nonce=nonce)  # committed, reply lost
            sessions_after_first = len(dep._real_authority.export_state()["sessions"])
            cred = dep.authority.establish_runner_session(
                dep.bootstrap, "run-1", fragment.fragment_hash,
                s0.state_hash, request_nonce=nonce)  # retry, same nonce
            self.assertIsNotNone(cred)
            # No second session was created: the stored credential came back.
            self.assertEqual(len(dep._real_authority.export_state()["sessions"]),
                             sessions_after_first)
            # A different nonce makes a new session.
            other = dep.authority.establish_runner_session(
                dep.bootstrap, "run-1", fragment.fragment_hash,
                s0.state_hash, request_nonce="different-nonce")
            self.assertNotEqual(other.session_id, cred.session_id)


class TestRecoveryIsTtlIndependent(unittest.TestCase):
    """Outcome recovery does not re-check the token TTL."""

    def test_expired_token_still_recoverable(self):
        from booking_v3.authority import TOKEN_TTL
        from booking_v3.gateway import ToolGateway
        p, dep, s0 = _deployment()
        with dep:
            fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
            _credential, grant = _harness_grant(dep, fragment, s0.state_hash)
            # A gateway whose clock is well past the token's expiry.
            late = ToolGateway(dep._real_authority.token_key(),
                               FixedClock(T0 + TOKEN_TTL + 100))
            # A fresh dispatch would be refused as expired ...
            self.assertIsNotNone(late.authorize_dispatch(grant.token, fragment))
            # ... but the holder-proof used for recovery is TTL-independent.
            self.assertIsNone(
                late.verify_dispatch_authorization(grant.token, fragment))


class TestHumanApprovalAuthorization(unittest.TestCase):
    """decide_intervention needs the provisioned human credential and a pending fragment."""

    def _pay_deployment(self):
        """Return (policy, deployment, s0) for a run whose payment step needs approval."""
        from booking_v3.policy import p3_with_pay_approval
        policy = p3_with_pay_approval()
        dep = DurableProcessDeployment(FixedClock(T0), enable_test_api=True)
        approval = approve(policy, approver_id="alice", approval_id="A-run-1",
                           run_id="run-1", issued_at=ISSUED, expires_at=EXPIRES)
        s0 = dep.authority.create_run(policy, approval, "run-1")
        return policy, dep, s0

    def test_untrusted_caller_cannot_grant_intervention(self):
        from booking_v3.authority import HumanApprovalCredential
        p, dep, s0 = self._pay_deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 3)
            pay = honest_fragment(p, "run-1", 3, PAY)
            forged = HumanApprovalCredential(secret="guessed")
            with self.assertRaises(wire.WireError) as ctx:
                _call(dep.server.socket_path, "authority.decide_intervention", {
                    "human": wire.human_to_wire(forged), "decision_id": "d1",
                    "run_id": "run-1", "step_index": 3,
                    "fragment_hash": pay.fragment_hash, "approver_id": "alice",
                    "approver_kind": "passkey", "grant": True, "ttl": 600})
            self.assertIn("invalid", str(ctx.exception))
            result = dep.provisioner.spawn(pay, envelopes[-1]).execute(p, envelopes[-1], pay)
            self.assertEqual(result.status, "REQUIRE_APPROVAL")

    def test_trusted_human_credential_grants_and_completes(self):
        p, dep, s0 = self._pay_deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 3)
            pay = honest_fragment(p, "run-1", 3, PAY)
            first = dep.provisioner.spawn(pay, envelopes[-1]).execute(p, envelopes[-1], pay)
            self.assertEqual(first.status, "REQUIRE_APPROVAL")           # parked, hence pending
            approval = dep.human_interface.decide_intervention(
                "run-1", 3, pay.fragment_hash, approver_id="alice", grant=True)
            result = dep.provisioner.spawn(pay, envelopes[-1]).execute(
                p, envelopes[-1], pay, approval)
            self.assertEqual(result.status, "STEP_COMPLETED")
            self.assertIs(dep.authority.status("run-1"), PolicyState.COMPLETED)

    def test_an_approval_for_a_hash_no_runner_submitted_is_refused_on_the_surface(self):
        """The human credential is necessary but not sufficient.

        A fragment hash the Authority has not parked as pending gets no approval, with a
        named refusal, and a denial of it does not touch the run.
        """
        p, dep, s0 = self._pay_deployment()
        with dep:
            _advance(p, dep, s0, 3)
            pay = honest_fragment(p, "run-1", 3, PAY)
            self.assertFalse(dep.authority.intervention_pending("run-1", 3, pay.fragment_hash))
            with self.assertRaises(wire.WireError) as ctx:
                dep.human_interface.decide_intervention("run-1", 3, pay.fragment_hash, approver_id="alice", grant=True)
            self.assertIn("no pending intervention", str(ctx.exception))
            with self.assertRaises(wire.WireError):
                dep.human_interface.decide_intervention("run-1", 3, "ab" * 32, approver_id="alice", grant=False)
            self.assertIs(dep.authority.status("run-1"), PolicyState.ACTIVE)

    def test_the_decision_surface_types_its_parameters(self):
        """A non-integer ttl or step_index and a non-string or empty decision_id are refused
        on the surface with a named error, before the Authority."""
        p, dep, s0 = self._pay_deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 3)
            pay = honest_fragment(p, "run-1", 3, PAY)
            first = dep.provisioner.spawn(pay, envelopes[-1]).execute(p, envelopes[-1], pay)
            self.assertEqual(first.status, "REQUIRE_APPROVAL")
            base = {"human": wire.human_to_wire(dep.human_interface._human), "decision_id": "d-1",
                    "run_id": "run-1", "step_index": 3, "fragment_hash": pay.fragment_hash,
                    "approver_id": "alice", "approver_kind": "passkey", "grant": True, "ttl": 60}
            cases = (({"ttl": "60"}, "integers"), ({"step_index": "three"}, "integers"),
                     ({"step_index": 3.0}, "integers"), ({"ttl": True}, "integers"),
                     ({"decision_id": 7}, "decision_id"), ({"decision_id": ""}, "decision_id"))
            for n, (bad, needle) in enumerate(cases):
                # each attempt is its own decision. A same-identity retry with other
                # content would be refused as a reuse, which is the replay rule, not this test
                with self.assertRaises(wire.WireError) as ctx:
                    _call(dep.human_interface._socket_path, "authority.decide_intervention",
                          {**base, "decision_id": f"bad-{n}", **bad})
                self.assertIn(needle, str(ctx.exception), bad)
            self.assertTrue(dep.authority.intervention_pending("run-1", 3, pay.fragment_hash))
            reply = _call(dep.human_interface._socket_path, "authority.decide_intervention", base)
            self.assertIsNotNone(reply["approval"])

    def test_pending_is_recorded_when_a_runner_reports_and_consumed_on_grant(self):
        """The Authority's own record of what awaits a decision (used by the continuation gate)."""
        p, dep, s0 = self._pay_deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 3)
            pay = honest_fragment(p, "run-1", 3, PAY)
            first = dep.provisioner.spawn(pay, envelopes[-1]).execute(p, envelopes[-1], pay)
            self.assertEqual(first.status, "REQUIRE_APPROVAL")
            self.assertTrue(dep.authority.intervention_pending("run-1", 3, pay.fragment_hash))
            approval = dep.human_interface.decide_intervention(
                "run-1", 3, pay.fragment_hash, approver_id="alice", grant=True)
            second = dep.provisioner.spawn(pay, envelopes[-1]).execute(p, envelopes[-1], pay, approval)
            self.assertEqual(second.status, "STEP_COMPLETED")
            self.assertFalse(dep.authority.intervention_pending("run-1", 3, pay.fragment_hash))

    def test_human_credential_survives_restart(self):
        p, dep, s0 = self._pay_deployment()
        with dep:
            envelopes = _advance(p, dep, s0, 3)
            pay = honest_fragment(p, "run-1", 3, PAY)
            first = dep.provisioner.spawn(pay, envelopes[-1]).execute(p, envelopes[-1], pay)
            self.assertEqual(first.status, "REQUIRE_APPROVAL")
            dep.restart_services()                                        # the pending record is durable too
            approval = dep.human_interface.decide_intervention(
                "run-1", 3, pay.fragment_hash, approver_id="alice", grant=True)
            self.assertIsNotNone(approval)


class TestTestApiGating(unittest.TestCase):
    """The fault and read-back API is off unless enabled."""

    def test_fault_api_disabled_by_default(self):
        from booking_v3.provisioner import create_deployment
        from booking_v4.durable import DurableDeploymentServer, DurableStore, _RestoredDeployment
        tmp = tempfile.mkdtemp(prefix="durable-gate-")
        store = DurableStore(os.path.join(tmp, "d.db"))
        base = create_deployment(FixedClock(T0))
        server = DurableDeploymentServer(
            _RestoredDeployment(base.authority, base.gateway), store)  # off by default
        try:
            with self.assertRaises(wire.WireError) as ctx:
                _call(server.socket_path, "test.crash_dispatch_once",
                      {"before_effect": False, "hard": True})
            self.assertIn("disabled", str(ctx.exception))
            with self.assertRaises(wire.WireError):
                _call(server.socket_path, "read.status", {"run_id": "x"})
        finally:
            server.close()
            store.close()


class TestSingleWriter(unittest.TestCase):
    """The store enforces a single writer, not only `replicas: 1` in the manifest.

    A second live writer on the same database is refused before it reads a row, in-process
    and across processes. A dead writer's lock is released with it.
    """

    def test_second_store_on_the_same_path_is_refused_while_the_first_lives(self):
        from booking_v4.durable import DurableStore, StoreBusy
        tmp = tempfile.mkdtemp(prefix="durable-writer-")
        path = os.path.join(tmp, "d.db")
        first = DurableStore(path)
        try:
            with self.assertRaises(StoreBusy):
                DurableStore(path)
        finally:
            first.close()
        second = DurableStore(path)          # only a live writer blocks, a closed one does not
        second.close()

    def test_a_second_process_is_refused_and_a_dead_process_releases_the_lock(self):
        from booking_v4.durable import DurableStore
        tmp = tempfile.mkdtemp(prefix="durable-writer-")
        path = os.path.join(tmp, "d.db")
        probe = ("import sys\n"
                 "from booking_v4.durable import DurableStore, StoreBusy\n"
                 "try:\n    DurableStore(sys.argv[1]); print('OPENED')\n"
                 "except StoreBusy:\n    print('BUSY')\n")
        first = DurableStore(path)
        try:
            out = subprocess.run([sys.executable, "-c", probe, path], capture_output=True,
                                 text=True, cwd=os.path.dirname(os.path.dirname(__file__)), timeout=60)
            self.assertEqual(out.stdout.strip(), "BUSY", out.stderr)
        finally:
            first.close()
        # A writer that dies without close(): the OS drops its lock, the successor opens.
        holder = subprocess.Popen(
            [sys.executable, "-c",
             "import sys, time\nfrom booking_v4.durable import DurableStore\n"
             "DurableStore(sys.argv[1]); print('HELD', flush=True); time.sleep(60)\n", path],
            stdout=subprocess.PIPE, text=True, cwd=os.path.dirname(os.path.dirname(__file__)))
        try:
            self.assertEqual(holder.stdout.readline().strip(), "HELD")
            out = subprocess.run([sys.executable, "-c", probe, path], capture_output=True,
                                 text=True, cwd=os.path.dirname(os.path.dirname(__file__)), timeout=60)
            self.assertEqual(out.stdout.strip(), "BUSY", out.stderr)
        finally:
            holder.kill()
            holder.wait()
        successor = DurableStore(path)
        successor.close()

    def test_a_symlink_to_the_same_database_contends_for_the_same_lock(self):
        """The lock is keyed by the database's real path, so a second name for the file
        (symlink, `..` path) does not yield a second writer."""
        from booking_v4.durable import DurableStore, StoreBusy
        tmp = tempfile.mkdtemp(prefix="durable-writer-")
        path = os.path.join(tmp, "d.db")
        link = os.path.join(tmp, "alias.db")
        first = DurableStore(path)
        try:
            os.symlink(path, link)
            with self.assertRaises(StoreBusy):
                DurableStore(link)
            with self.assertRaises(StoreBusy):
                DurableStore(os.path.join(tmp, "sub", "..", "d.db"))
        finally:
            first.close()

    def test_a_removed_lock_file_stops_the_writer_instead_of_duplicating_it(self):
        """Deleting the lock file lets a successor open, but the holder notices at its next
        transaction and refuses to write (`StoreBusy`)."""
        from booking_v4.durable import DurableStore, StoreBusy
        tmp = tempfile.mkdtemp(prefix="durable-writer-")
        path = os.path.join(tmp, "d.db")
        first = DurableStore(path)
        with first.transaction():
            first.put_reply("i1", "h", "r")
        os.unlink(path + ".lock")
        second = DurableStore(path)
        try:
            with self.assertRaises(StoreBusy):
                with first.transaction():
                    first.put_reply("i2", "h", "r")
            with second.transaction():
                second.put_reply("i2", "h", "r")
        finally:
            second.close()
            first.close()


class TestFrozenEvaluationOnDurableBackend(unittest.TestCase):
    """Every scenario, the differential conformance check (P8) and dispatch safety (P9) of
    `booking_v3.experiment` on the durable process backend."""

    def test_every_scenario_p8_p9(self):
        """As on the process backend: the two transport scenarios are expected not to
        match, because this configuration binds no effect ledger either."""
        from booking_v3.scenarios import OBSERVATION_CHECK_SCENARIOS
        from .experiment_durable import run_all
        results, diffs = run_all()
        self.assertEqual([r.name for r in results if not r.matches_prediction],
                         list(OBSERVATION_CHECK_SCENARIOS))
        self.assertEqual([r.name for r in results if not r.effects_exact], [])
        self.assertEqual([d.trace for d in diffs if not d.ok], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
