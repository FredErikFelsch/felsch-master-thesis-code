"""What the gateway and the runner may claim about the past.

Run:
    python3 -m booking_v3.tests_gateway_order

Gateway. A token that was spent and has since expired must still answer "already consumed, a
dispatch was attempted". "token expired, nothing dispatched" would turn an earlier effect into
a certain non-effect. The read-only recovery check ignores the TTL.

Runner. A failure report has no successor envelope, so a missing envelope says nothing. The
runner reports EFFECT_FAILED or EFFECT_UNCERTAIN only when the Authority took the report over,
and then the state the Authority adopted decides, not the runner's own label. A refused
finalisation is FINALIZE_REFUSED.
"""
from __future__ import annotations

import dataclasses
import unittest

from booking_v1.approval import approve
from booking_v1.effects import EffectOutcome, EffectResult, response_digest
from booking_v1.lifecycle import PolicyState

from .authority import adopted_state
from .gateway import GatewayRefusal
from .provisioner import create_deployment
from .runner import EphemeralRunner
from .tests_failure_ledger import _Ledger
from .tests_negative import RUN, T0, _Fixture


class ASpentTokenThatExpiredIsStillSpent(_Fixture):
    """A spent token stays a dispatch attempt after it has expired."""

    def test_spent_then_expired_is_still_a_dispatch_attempt(self):
        credential, fragment, grant, why = self.grant()
        self.assertIsNotNone(grant, why)
        first = self.dep.gateway.execute(grant.token, fragment)
        self.assertNotIsInstance(first, GatewayRefusal)
        self.clock.set(grant.token.expires_at + 1)
        second = self.dep.gateway.execute(grant.token, fragment)
        self.assertIsInstance(second, GatewayRefusal)
        self.assertIn("already consumed", second.reason)
        self.assertTrue(second.dispatch_attempted, "a spent token that expired must still read as a dispatch attempt")
        self.assertEqual(len(self.dep.gateway.executions), 1)

    def test_control_an_unspent_expired_token_is_refused_as_expired_without_a_dispatch(self):
        credential, fragment, grant, why = self.grant()
        self.clock.set(grant.token.expires_at + 1)
        refusal = self.dep.gateway.execute(grant.token, fragment)
        self.assertIn("expired", refusal.reason)
        self.assertFalse(refusal.dispatch_attempted)
        self.assertEqual(self.dep.gateway.executions, [])

    def test_a_spent_token_for_another_request_is_refused_by_its_binding_not_as_spent(self):
        credential, fragment, grant, why = self.grant()
        self.dep.gateway.execute(grant.token, fragment)
        other = self.fragment(arguments={"to": "LIS"})
        refusal = self.dep.gateway.execute(grant.token, other)
        self.assertNotIn("consumed", refusal.reason)
        self.assertFalse(refusal.dispatch_attempted)

    def test_the_read_only_recovery_check_still_ignores_the_ttl(self):
        credential, fragment, grant, why = self.grant()
        self.dep.gateway.execute(grant.token, fragment)
        self.clock.set(grant.token.expires_at + 1)
        self.assertIsNone(self.dep.gateway.verify_dispatch_authorization(grant.token, fragment))


class EveryBindingOfATokenIsCheckedOnItsOwn(_Fixture):
    """Each binding check must refuse alone, on both paths (dispatch and read-only check).

    The fragment hash covers run, step, operation and arguments, so a changed field is normally
    caught twice. Here the fragment hash of a changed fragment is forced back to the authorised
    one (an inconsistent fragment), so only the check of that single field can refuse.
    """

    def _forged(self, fragment, **changes):
        """Return `fragment` with changed fields but the original fragment hash."""
        changed = dataclasses.replace(fragment, **changes)
        object.__setattr__(changed, "fragment_hash", fragment.fragment_hash)
        return changed

    def _cases(self, fragment):
        """Return one forged fragment per binding, with the expected refusal text."""
        return {
            "run": (self._forged(fragment, run_id="other-run"), "different run"),
            "step": (self._forged(fragment, fragment_index=fragment.fragment_index + 1), "different step"),
            "operation": (self._forged(fragment, operation="other_operation"), "operation"),
            "arguments": (self._forged(fragment, arguments={"to": "LIS"}), "authorized request"),
        }

    def test_the_read_only_check_refuses_each_binding_alone(self):
        credential, fragment, grant, why = self.grant()
        self.assertIsNotNone(grant, why)
        for name, (forged, expected) in self._cases(fragment).items():
            with self.subTest(binding=name):
                reason = self.dep.gateway.verify_dispatch_authorization(grant.token, forged)
                self.assertIsNotNone(reason, f"{name} binding not checked by the read-only check")
                self.assertIn(expected, reason)

    def test_the_dispatch_refuses_each_binding_alone_and_does_not_spend_the_token(self):
        credential, fragment, grant, why = self.grant()
        self.assertIsNotNone(grant, why)
        for name, (forged, expected) in self._cases(fragment).items():
            with self.subTest(binding=name):
                refusal = self.dep.gateway.execute(grant.token, forged)
                self.assertIsInstance(refusal, GatewayRefusal, f"{name} binding not checked")
                self.assertIn(expected, refusal.reason)
                self.assertFalse(refusal.dispatch_attempted)
        self.assertEqual(self.dep.gateway.executions, [])
        self.assertNotIsInstance(self.dep.gateway.execute(grant.token, fragment), GatewayRefusal)

    def test_the_fragment_hash_alone_is_checked_too(self):
        credential, fragment, grant, why = self.grant()
        self.assertIsNotNone(grant, why)
        wrong = dataclasses.replace(fragment)
        object.__setattr__(wrong, "fragment_hash", "0" * 64)
        self.assertIn("different fragment", self.dep.gateway.verify_dispatch_authorization(grant.token, wrong))
        refusal = self.dep.gateway.execute(grant.token, wrong)
        self.assertIsInstance(refusal, GatewayRefusal)
        self.assertIn("different fragment", refusal.reason)


class _RefusingFinalization:
    """The real Authority, except that it refuses every finalisation."""

    def __init__(self, real):
        """Wrap the real Authority."""
        self._real = real

    def __getattr__(self, name):
        """Delegate everything except finalize_transition."""
        return getattr(self._real, name)

    def finalize_transition(self, credential, record, attestation=None):
        """Refuse as an unauthenticated channel would."""
        return None, "unauthenticated runner channel (finalization refused)"


class ARunnerReportsWhatTheAuthorityTookOver(_Fixture):
    """The runner's status follows the state the Authority adopted, not its own label."""

    def setUp(self):
        """Rebuild the fixture on a world in which every effect fails."""
        self.failing = lambda call: EffectResult(outcome=EffectOutcome.FAILED, error="boom")
        super().setUp()
        self.dep = create_deployment(self.clock, executor=self.failing)
        self.auth = self.dep.authority
        approval = approve(self.policy, approver_id="alice", approval_id="A-2", run_id=RUN,
                           issued_at=T0 - 1000, expires_at=2_000_000)
        self.s0 = self.auth.create_run(self.policy, approval, RUN)
        self.auth._LEDGER_REREAD_SECONDS = 0

    def run_step(self, authority=None):
        """Run the single step once, optionally against another Authority object."""
        fragment = self.fragment()
        credential = self.auth.establish_runner_session(self.dep.bootstrap, RUN, fragment.fragment_hash,
                                                        self.s0.state_hash)
        runner = EphemeralRunner(authority or self.auth, self.dep.gateway, self.dep.anchors, credential)
        return runner.execute(self.policy, self.s0, fragment)

    def test_an_accepted_failure_is_reported_as_failed_and_adopted(self):
        result = self.run_step()
        self.assertEqual(result.status, "EFFECT_FAILED")
        self.assertIs(self.auth.status(RUN), PolicyState.EFFECT_FAILED)

    def test_a_refused_finalization_is_not_reported_as_a_recorded_failure(self):
        result = self.run_step(_RefusingFinalization(self.auth))
        self.assertEqual(result.status, "FINALIZE_REFUSED", "a refused finalisation must not be reported as a recorded failure")
        self.assertIs(self.auth.status(RUN), PolicyState.EFFECT_PENDING,
                      "the Authority did not take the failure over")

    def test_a_label_the_ledger_contradicts_comes_back_as_uncertain_not_failed(self):
        self.auth.bind_effect_ledger(_Ledger("COMMITTED", response_digest("CONFIRMED", None)))
        result = self.run_step()
        self.assertEqual(result.status, "EFFECT_UNCERTAIN")
        self.assertIn("contradicts the gateway ledger", result.reason)
        self.assertIs(self.auth.status(RUN), PolicyState.EFFECT_RECONCILE)


class AdoptedStateParsing(_Fixture):
    """`adopted_state` names a state only for an adopted note."""

    def test_only_an_adopted_note_names_a_state(self):
        self.assertEqual(adopted_state("adopted EFFECT_FAILED: effect FAILED; run parked fail-closed"),
                         "EFFECT_FAILED")
        self.assertIsNone(adopted_state("unauthenticated runner channel (finalization refused)"))
        self.assertIsNone(adopted_state(None))


if __name__ == "__main__":
    unittest.main()
