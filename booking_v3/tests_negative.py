"""Negative tests for individual Authority checks.

Run:
    python3 -m booking_v3.tests_negative

Each test first runs the same request unmodified and expects success (control), then changes
one property and expects the refusal with the reason that belongs to the checked condition.
A refusal for another reason would mean an earlier check fired and the condition under test
was not reached.

The checked conditions:

    grant      the fragment's policy digest must be the approved run's
    grant      an exhausted consumption budget refuses (reachable via a restored state only,
               because policy validation forbids a budget below the occurrences in the flow)
    grant      no new grant after the plan approval's validity window
    grant      the operation must be the approved one of the step, also for a runner whose
               signed ALLOW is valid (an attested session)
    successor  previous_state_hash must be the last signed state
    successor  audit_head must be the head extended by this transition
    successor  step_index must be the granted step plus one
"""
from __future__ import annotations

import dataclasses
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.freeze import to_canonical

from . import runner_attestation as ra
from .authority import TransitionRecord, request_hash
from .envelope import SigningKey, StateEnvelope, chain_extend
from .fragment import honest_fragment
from .provisioner import create_deployment
from .policy import default_p3

T0 = 1_000_000
T_EXPIRES = 2_000_000
RUN = "run-1"
ADMISSION = {"kind": "admission", "decision": "ALLOW", "reason": "test"}


class _Clock(FixedClock):
    """A fixed clock the test can move."""

    def set(self, t: int) -> None:
        """Move the clock to ``t``."""
        self._t = t


class _Fixture(unittest.TestCase):
    """One fresh Authority with run `run-1` at step 0 (state S0)."""

    def setUp(self):
        """Create the deployment and activate the run."""
        self.policy = default_p3()
        self.clock = _Clock(T0)
        approval = approve(self.policy, approver_id="alice", approval_id=f"A-{RUN}", run_id=RUN,
                           issued_at=T0 - 1000, expires_at=T_EXPIRES)
        self.dep = create_deployment(self.clock)
        self.auth = self.dep.authority
        self.s0 = self.auth.create_run(self.policy, approval, RUN)

    # Helpers.
    def fragment(self, **changes):
        """Return the honest step-0 fragment, optionally with changed fields."""
        return dataclasses.replace(honest_fragment(self.policy, RUN, 0, {"to": "FRA"}), **changes)

    def grant(self, fragment=None):
        """Open a runner session for the fragment and request the grant on it."""
        fragment = fragment or self.fragment()
        credential = self.auth.establish_runner_session(
            self.dep.bootstrap, RUN, fragment.fragment_hash, self.s0.state_hash)
        grant, why = self.auth.request_execution_grant(credential, fragment, self.s0.state_hash,
                                                       ADMISSION, None)
        return credential, fragment, grant, why

    def finalize(self, **successor):
        """Grant step 0, then report CONFIRMED_VALIDATED with a successor built from overrides.

        Returns the pair (signed envelope or None, reason) the Authority answers.
        """
        credential, fragment, grant, why = self.grant()
        self.assertIsNotNone(grant, f"control grant refused: {why}")
        effect = to_canonical({
            "kind": "effect", "run_id": RUN, "step_index": 0, "fragment_hash": fragment.fragment_hash,
            "outcome": "CONFIRMED", "payload": {"ok": True}, "error": None, "produced_facts": []})
        head = chain_extend(self.s0.audit_head, [to_canonical(ADMISSION), effect])
        fields = dict(run_id=RUN, policy_digest=self.s0.policy_digest, approval_id=self.s0.approval_id,
                      step_index=1, facts={}, audit_head=head, previous_state_hash=self.s0.state_hash)
        fields.update(successor)
        record = TransitionRecord(run_id=RUN, grant_id=grant.grant_id, outcome="CONFIRMED_VALIDATED",
                                  admission_event=to_canonical(ADMISSION), effect_event=effect,
                                  proposed=StateEnvelope(**fields))
        return self.auth.finalize_transition(credential, record)


class TheGrantChecksTheRun(_Fixture):
    """Grant-time checks against the Authority's run ledger."""

    def test_a_fragment_under_another_policy_digest_is_refused(self):
        _, _, grant, why = self.grant()
        self.assertIsNotNone(grant, why)                       # control
        self.setUp()
        _, _, grant, why = self.grant(self.fragment(policy_digest="0" * 64))
        self.assertIsNone(grant)
        self.assertIn("policy digest does not match", why)

    def test_an_exhausted_budget_refuses_the_grant(self):
        _, _, grant, why = self.grant()
        self.assertIsNotNone(grant, why)                       # control
        self.setUp()
        state = self.auth.export_state()                       # a restored state with no budget left
        state["runs"][RUN]["remaining"]["search"] = 0
        self.auth.import_state(state)
        _, _, grant, why = self.grant()
        self.assertIsNone(grant)
        self.assertIn("consumption budget", why)

    def test_no_new_grant_after_the_approval_window(self):
        _, _, grant, why = self.grant()
        self.assertIsNotNone(grant, why)                       # control, inside the window
        self.setUp()
        self.clock.set(T_EXPIRES + 1)                          # the Authority's own check, not a token's expiry
        _, _, grant, why = self.grant()
        self.assertIsNone(grant)
        self.assertIn("validity window elapsed", why)


class TheGrantKeepsTheApprovedOperationSequence(_Fixture):
    """Only the operation is wrong. The grant must still be refused.

    The run, the step, the state, the session and the signed ALLOW are valid. The operation
    is another operation of the same policy, one that has budget left and, at this step, no
    approval requirement.
    """

    def setUp(self):
        """Add a runner signing key to the fixture."""
        super().setUp()
        self.key = SigningKey()

    def attested_grant(self, fragment):
        """Request a grant on an attested session, where the runner signs its own ALLOW."""
        credential = self.auth.establish_runner_session(
            self.dep.bootstrap, RUN, fragment.fragment_hash, self.s0.state_hash,
            verify_key=self.key.verify_key().to_bytes())
        admission = {"kind": "admission", "run_id": RUN, "step_index": fragment.fragment_index,
                     "fragment_hash": fragment.fragment_hash, "decision": "ALLOW"}
        attestation = ra.sign(self.key, ra.grant_statement(
            run_id=RUN, step=fragment.fragment_index, state_hash=self.s0.state_hash,
            fragment_hash=fragment.fragment_hash, operation=fragment.operation,
            request_hash=request_hash(fragment.operation, fragment.arguments),
            admission_hash=ra.event_digest(admission)))
        return self.auth.request_execution_grant(credential, fragment, self.s0.state_hash,
                                                 admission, None, attestation)

    def test_control_the_approved_operation_is_granted_on_an_attested_session(self):
        grant, why = self.attested_grant(self.fragment())
        self.assertIsNotNone(grant, why)

    def test_another_operation_of_the_policy_is_refused_at_step_zero(self):
        other = [op for op in self.policy.allowed_flow if op != self.policy.allowed_flow[0]][-1]
        self.assertGreater(self.auth.export_state()["runs"][RUN]["remaining"][other], 0)
        grant, why = self.attested_grant(self.fragment(operation=other))
        self.assertIsNone(grant)
        self.assertIn("not the approved operation of step 0", why)

    def test_every_other_operation_of_the_flow_is_refused_at_step_zero(self):
        for op in set(self.policy.allowed_flow) - {self.policy.allowed_flow[0]}:
            with self.subTest(operation=op):
                self.setUp()
                grant, why = self.attested_grant(self.fragment(operation=op))
                self.assertIsNone(grant)
                self.assertIn("not the approved operation", why)

    def test_an_operation_outside_the_flow_is_refused(self):
        grant, why = self.attested_grant(self.fragment(operation="read_secret"))
        self.assertIsNone(grant)
        self.assertIn("not the approved operation", why)

    def test_the_operation_check_survives_a_restored_state(self):
        state = self.auth.export_state()
        self.assertEqual(state["runs"][RUN]["allowed_flow"], list(self.policy.allowed_flow))
        self.auth.import_state(state)
        other = self.policy.allowed_flow[-1]
        _, _, grant, why = self.grant(self.fragment(operation=other))
        self.assertIsNone(grant)
        self.assertIn("not the approved operation", why)

    def test_a_snapshot_without_the_flow_is_not_restored(self):
        state = self.auth.export_state()
        del state["runs"][RUN]["allowed_flow"]
        with self.assertRaises(KeyError):
            self.auth.import_state(state)


class TheSuccessorIsLinkedToTheGrant(_Fixture):
    """A successor proposal must extend the granted transition by one step."""

    def test_control_an_honest_successor_is_signed(self):
        signed, why = self.finalize()
        self.assertIsNotNone(signed, why)

    def test_a_successor_must_extend_the_last_signed_state(self):
        signed, why = self.finalize(previous_state_hash="0" * 64)
        self.assertIsNone(signed)
        self.assertIn("does not extend the last signed state", why)

    def test_a_successor_must_carry_the_extended_audit_head(self):
        signed, why = self.finalize(audit_head="0" * 64)
        self.assertIsNone(signed)
        self.assertIn("extended audit head", why)

    def test_a_successor_must_advance_one_step(self):
        signed, why = self.finalize(step_index=2)
        self.assertIsNone(signed)
        self.assertIn("wrong step arithmetic", why)


if __name__ == "__main__":
    unittest.main()
