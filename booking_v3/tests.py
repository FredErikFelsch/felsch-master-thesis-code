"""Unit tests for the fragmented pipeline, grouped by component.

Run from the repository root:  python3 -m booking_v3.tests
"""

from __future__ import annotations

import dataclasses
import unittest

from booking_v0.tools import ToolCall
from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.freeze import thaw
from booking_v1.ledger import RunLedger
from booking_v1.lifecycle import PolicyState
from booking_v2.monitor import PolicyMonitor
from booking_v2.policy import default_p2_1

from .authority import (
    ProvisionerCredential, ProvisioningRefused, RunnerCredential, TransitionRecord, TOKEN_TTL,
)
from .envelope import (
    SigningKey, StateEnvelope, chain_extend, genesis_audit_head, verify_envelope,
)
from .experiment import differential_conformance
from .experiment_world import run_backend
from .fragment import ActionFragment, FragmentInvalid, honest_fragment
from .gateway import GatewayRefusal, ToolGateway
from .monitor import V3Decision, check
from .orchestrator import Orchestrator, happy_path_arguments
from .policy import default_p3, p3_with_pay_approval
from .provisioner import create_deployment
from .runner import EphemeralRunner
from .scenarios import make_context, world_scenarios

T0 = 1_000_000
T_EXPIRES = 2_000_000


def _fresh(policy=None, run_id="run-1"):
    """Return (policy, authority, gateway, anchors, s0, deployment) for one test run."""
    policy = policy or default_p3()
    clock = FixedClock(T0)
    approval = approve(policy, approver_id="alice", approval_id=f"A-{run_id}",
                       run_id=run_id, issued_at=T0 - 1000, expires_at=T_EXPIRES)
    dep = create_deployment(clock)
    s0 = dep.authority.create_run(policy, approval, run_id)
    return policy, dep.authority, dep.gateway, dep.anchors, s0, dep


def _advance(policy, dep, envelope, upto):
    """Drive the happy path up to (excluding) step ``upto`` and return the envelopes S0 to S_upto."""
    envelopes = [envelope]
    for step, args in enumerate(happy_path_arguments()[:upto]):
        fragment = honest_fragment(policy, envelope.run_id, step, args)
        result = dep.provisioner.spawn(fragment, envelope).execute(policy, envelope, fragment)
        assert result.status == "STEP_COMPLETED", result.reason
        envelope = result.envelope
        envelopes.append(envelope)
    return envelopes


class TestActionFragment(unittest.TestCase):
    """Canonical hashing and construction guards."""

    def setUp(self):
        self.p = default_p3()

    def test_hash_stable(self):
        f1 = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        f2 = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        self.assertEqual(f1.fragment_hash, f2.fragment_hash)

    def test_argument_change_changes_hash(self):
        f1 = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        f2 = honest_fragment(self.p, "run-1", 0, {"to": "MUC"})
        self.assertNotEqual(f1.fragment_hash, f2.fragment_hash)

    def test_run_change_changes_hash(self):
        f1 = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        f2 = honest_fragment(self.p, "run-2", 0, {"to": "FRA"})
        self.assertNotEqual(f1.fragment_hash, f2.fragment_hash)

    def test_policy_change_changes_hash(self):
        f1 = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        f2 = honest_fragment(p3_with_pay_approval(), "run-1", 0, {"to": "FRA"})
        self.assertNotEqual(f1.fragment_hash, f2.fragment_hash)

    def test_non_canonical_arguments_rejected(self):
        with self.assertRaises(FragmentInvalid):
            ActionFragment(run_id="run-1", fragment_index=0, policy_digest="d",
                           operation="search", arguments={"to": {1, 2}})

    def test_action_id_mismatch_rejected(self):
        with self.assertRaises(FragmentInvalid):
            ActionFragment(run_id="run-1", fragment_index=0, policy_digest="d",
                           operation="book", arguments={"flight": "LH123", "action_id": "a"},
                           action_id="b")


class TestStateEnvelope(unittest.TestCase):
    """Canonical hashing, Ed25519 signing and tamper evidence."""

    def setUp(self):
        self.p, self.auth, self.gw, self.anchors, self.s0, self.dep = _fresh()
        self.s1 = _advance(self.p, self.dep, self.s0, 1)[-1]

    def _tampered(self, **overrides):
        """Rebuild s1 with modified fields, keeping the original signature."""
        fields = dict(
            run_id=self.s1.run_id, policy_digest=self.s1.policy_digest,
            approval_id=self.s1.approval_id, step_index=self.s1.step_index,
            facts=thaw(self.s1.facts), audit_head=self.s1.audit_head,
            previous_state_hash=self.s1.previous_state_hash)
        fields.update(overrides)
        return StateEnvelope(**fields).with_signature(self.s1.signature)

    def test_valid_envelope_accepts(self):
        ok, why = verify_envelope(self.s1, self.anchors.envelope_key)
        self.assertTrue(ok, why)

    def test_changed_fact_rejected(self):
        facts = thaw(self.s1.facts)
        facts["offer_prices"]["value"]["LH123"] = 1
        ok, why = verify_envelope(self._tampered(facts=facts), self.anchors.envelope_key)
        self.assertFalse(ok)

    def test_removed_fact_rejected(self):
        facts = thaw(self.s1.facts)
        del facts["offer_prices"]
        self.assertFalse(verify_envelope(self._tampered(facts=facts), self.anchors.envelope_key)[0])

    def test_added_fact_rejected(self):
        facts = thaw(self.s1.facts)
        facts["selected_flight_id"] = dict(facts["offer_flight_ids"], ftype="str", value="AF456")
        self.assertFalse(verify_envelope(self._tampered(facts=facts), self.anchors.envelope_key)[0])

    def test_changed_run_rejected(self):
        self.assertFalse(verify_envelope(self._tampered(run_id="run-2"), self.anchors.envelope_key)[0])

    def test_changed_policy_rejected(self):
        self.assertFalse(verify_envelope(self._tampered(policy_digest="0" * 64), self.anchors.envelope_key)[0])

    def test_changed_step_rejected(self):
        self.assertFalse(verify_envelope(self._tampered(step_index=3), self.anchors.envelope_key)[0])

    def test_wrong_public_key_rejected(self):
        self.assertFalse(verify_envelope(self.s1, SigningKey().verify_key())[0])

    def test_unsigned_rejected(self):
        unsigned = self._tampered().with_signature("")
        self.assertFalse(verify_envelope(unsigned, self.anchors.envelope_key)[0])


class TestAuthorityFreshness(unittest.TestCase):
    """The pre-effect grant refuses replay, fork, skip and double effects."""

    def setUp(self):
        self.p, self.auth, self.gw, self.anchors, self.s0, self.dep = _fresh()

    def _grant(self, fragment, state_hash, intervention=None):
        """Open a session for ``fragment`` and request a grant with a fixed ALLOW event."""
        event = {"kind": "admission", "decision": "ALLOW", "reason": "test"}
        credential = self.auth.establish_runner_session(
            self.dep.bootstrap, fragment.run_id,
            fragment.fragment_hash, state_hash)
        return self.auth.request_execution_grant(credential, fragment, state_hash, event, intervention)

    def test_old_state_replay_refused_before_effect(self):
        envs = _advance(self.p, self.dep, self.s0, 2)
        effects_before = len(self.gw.executions)
        fragment = honest_fragment(self.p, "run-1", 1, {"flight": "LH123"})
        result = self.dep.provisioner.spawn(fragment, envs[1]).execute(self.p, envs[1], fragment)
        self.assertEqual(result.status, "GRANT_REFUSED")
        self.assertIn("freshness", result.reason)
        self.assertEqual(len(self.gw.executions), effects_before)  # P9: zero effects

    def test_fork_refused(self):
        envs = _advance(self.p, self.dep, self.s0, 2)
        # First extension of S1 already happened (S2 exists). A second runner
        # extending the same S1 loses the compare-and-advance.
        fragment = honest_fragment(self.p, "run-1", 1, {"flight": "LH250"})
        result = self.dep.provisioner.spawn(fragment, envs[1]).execute(self.p, envs[1], fragment)
        self.assertEqual(result.status, "GRANT_REFUSED")

    def test_skipped_step_refused(self):
        fragment = honest_fragment(self.p, "run-1", 2, {"flight": "LH123", "action_id": "book-1"})
        grant, why = self._grant(fragment, self.s0.state_hash)
        self.assertIsNone(grant)
        self.assertIn("step mismatch", why)

    def test_double_grant_refused_while_pending(self):
        fragment = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        grant, _ = self._grant(fragment, self.s0.state_hash)
        self.assertIsNotNone(grant)
        second, why = self._grant(fragment, self.s0.state_hash)
        self.assertIsNone(second)
        self.assertIn("effect in progress", why)

    def test_completed_run_refuses_everything(self):
        envs = _advance(self.p, self.dep, self.s0, 4)
        self.assertIs(self.auth.status("run-1"), PolicyState.COMPLETED)
        fragment = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        grant, why = self._grant(fragment, envs[-1].state_hash)
        self.assertIsNone(grant)
        self.assertIn("COMPLETED", why)

    def test_duplicate_action_id_refused(self):
        envs = _advance(self.p, self.dep, self.s0, 3)
        args = {"amount_minor": 34900, "currency": "EUR", "recipient": "airline:LH", "action_id": "book-1"}
        fragment = honest_fragment(self.p, "run-1", 3, args)
        result = self.dep.provisioner.spawn(fragment, envs[-1]).execute(self.p, envs[-1], fragment)
        self.assertEqual(result.status, "GRANT_REFUSED")
        self.assertIn("duplicate action_id", result.reason)

    def test_denied_run_is_terminated(self):
        fragment = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        bad = ActionFragment(run_id="run-1", fragment_index=0, policy_digest=self.p.digest(),
                             operation="read_secret", arguments={"key": "k"},
                             declared_facts=(), declared_capability="search")
        result = self.dep.provisioner.spawn(bad, self.s0).execute(self.p, self.s0, bad)
        self.assertEqual(result.status, "DENIED")
        self.assertIs(self.auth.status("run-1"), PolicyState.TERMINATED)
        grant, why = self._grant(fragment, self.s0.state_hash)
        self.assertIsNone(grant)


class TestStatelessMonitor(unittest.TestCase):
    """The pure check() reproduces the booking_v2 admission semantics."""

    def setUp(self):
        self.p, self.auth, self.gw, self.anchors, self.s0, self.dep = _fresh()

    def _check(self, envelope, fragment):
        """Run the stateless check with this test's policy and anchors."""
        return check(self.p, envelope, fragment, self.anchors)

    def test_select_not_offered_denied(self):
        s1 = _advance(self.p, self.dep, self.s0, 1)[-1]
        fragment = honest_fragment(self.p, "run-1", 1, {"flight": "ZZZ"})
        outcome = self._check(s1, fragment)
        self.assertIs(outcome.decision, V3Decision.DENY)
        self.assertIn("binding violated", outcome.reason)

    def test_book_mismatch_denied(self):
        s2 = _advance(self.p, self.dep, self.s0, 2)[-1]
        fragment = honest_fragment(self.p, "run-1", 2, {"flight": "LH250", "action_id": "book-1"})
        self.assertIs(self._check(s2, fragment).decision, V3Decision.DENY)

    def test_book_over_budget_denied(self):
        envs = _advance(self.p, self.dep, self.s0, 1)
        select = honest_fragment(self.p, "run-1", 1, {"flight": "AF456"})
        result = self.dep.provisioner.spawn(select, envs[-1]).execute(self.p, envs[-1], select)
        self.assertEqual(result.status, "STEP_COMPLETED")  # AF456 was offered
        book = honest_fragment(self.p, "run-1", 2, {"flight": "AF456", "action_id": "book-1"})
        outcome = self._check(result.envelope, book)
        self.assertIs(outcome.decision, V3Decision.DENY)
        self.assertIn("within", outcome.reason)

    def test_pay_manipulations_denied(self):
        s3 = _advance(self.p, self.dep, self.s0, 3)[-1]
        base = {"amount_minor": 34900, "currency": "EUR", "recipient": "airline:LH", "action_id": "pay-1"}
        for mutation in ({"amount_minor": 1}, {"currency": "USD"}, {"recipient": "attacker:acct-666"}):
            fragment = honest_fragment(self.p, "run-1", 3, {**base, **mutation})
            self.assertIs(self._check(s3, fragment).decision, V3Decision.DENY, mutation)

    def test_off_policy_operation_denied(self):
        fragment = ActionFragment(run_id="run-1", fragment_index=0, policy_digest=self.p.digest(),
                                  operation="read_secret", arguments={"key": "k"},
                                  declared_facts=(), declared_capability="search")
        outcome = self._check(self.s0, fragment)
        self.assertIs(outcome.decision, V3Decision.DENY)
        self.assertIn("out-of-policy", outcome.reason)

    def test_wrong_run_denied(self):
        fragment = honest_fragment(self.p, "run-2", 0, {"to": "FRA"})
        self.assertIs(self._check(self.s0, fragment).decision, V3Decision.DENY)

    def test_step_mismatch_denied(self):
        fragment = honest_fragment(self.p, "run-1", 1, {"flight": "LH123"})
        outcome = self._check(self.s0, fragment)
        self.assertIs(outcome.decision, V3Decision.DENY)
        self.assertIn("does not match envelope step", outcome.reason)

    def test_wrong_declarations_denied(self):
        wrong_facts = ActionFragment(
            run_id="run-1", fragment_index=0, policy_digest=self.p.digest(),
            operation="search", arguments={"to": "FRA"},
            declared_facts=("selected_flight_id",), declared_capability="search")
        self.assertIs(self._check(self.s0, wrong_facts).decision, V3Decision.DENY)
        wrong_cap = ActionFragment(
            run_id="run-1", fragment_index=0, policy_digest=self.p.digest(),
            operation="search", arguments={"to": "FRA"},
            declared_facts=(), declared_capability="pay")
        self.assertIs(self._check(self.s0, wrong_cap).decision, V3Decision.DENY)

    def test_swapped_policy_denied(self):
        other = p3_with_pay_approval()  # different digest than the approved run
        fragment = honest_fragment(other, "run-1", 0, {"to": "FRA"})
        outcome = check(other, self.s0, fragment, self.anchors)
        self.assertIs(outcome.decision, V3Decision.DENY)
        self.assertIn("digest", outcome.reason)

    def test_tampered_envelope_in_transit_denied(self):
        s1 = _advance(self.p, self.dep, self.s0, 1)[-1]
        facts = thaw(s1.facts)
        facts["offer_prices"]["value"]["AF456"] = 1  # make AF456 look affordable
        tampered = StateEnvelope(
            run_id=s1.run_id, policy_digest=s1.policy_digest, approval_id=s1.approval_id,
            step_index=s1.step_index, facts=facts, audit_head=s1.audit_head,
            previous_state_hash=s1.previous_state_hash).with_signature(s1.signature)
        fragment = honest_fragment(self.p, "run-1", 1, {"flight": "AF456"})
        outcome = self._check(tampered, fragment)
        self.assertIs(outcome.decision, V3Decision.DENY)
        self.assertIn("envelope rejected", outcome.reason)


class TestToolGateway(unittest.TestCase):
    """Capability tokens authorise one request, once."""

    def setUp(self):
        self.p, self.auth, self.gw, self.anchors, self.s0, self.dep = _fresh()
        self.fragment = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        event = {"kind": "admission", "decision": "ALLOW", "reason": "test"}
        self.credential = self.auth.establish_runner_session(
            self.dep.bootstrap, "run-1",
            self.fragment.fragment_hash, self.s0.state_hash)
        self.grant, _ = self.auth.request_execution_grant(self.credential, self.fragment, self.s0.state_hash, event)

    def test_correct_token_executes(self):
        result = self.gw.execute(self.grant.token, self.fragment)
        self.assertNotIsInstance(result, GatewayRefusal)
        self.assertEqual(len(self.gw.executions), 1)

    def test_token_reuse_refused(self):
        self.gw.execute(self.grant.token, self.fragment)
        second = self.gw.execute(self.grant.token, self.fragment)
        self.assertIsInstance(second, GatewayRefusal)
        self.assertIn("single use", second.reason)
        self.assertEqual(len(self.gw.executions), 1)

    def test_only_a_spent_token_is_refused_after_a_dispatch_was_started(self):
        """Only the spent-token refusal reports a started dispatch.

        The gateway consumes the token before it calls the counterparty, so one refusal
        reason can only occur after a dispatch intent exists. Every other reason is
        decided before the token is consumed and means zero effects. The caller needs the
        difference to choose between FAILED and UNCERTAIN.
        """
        self.gw.execute(self.grant.token, self.fragment)
        spent = self.gw.execute(self.grant.token, self.fragment)
        self.assertTrue(spent.dispatch_attempted)

        # The expiry case needs an unspent token, because a spent token is reported as
        # spent before its expiry is looked at.
        p, auth, gw, _anchors, s0, dep = _fresh(run_id="run-2")
        fragment = honest_fragment(p, "run-2", 0, {"to": "FRA"})
        credential = auth.establish_runner_session(
            dep.bootstrap, "run-2", fragment.fragment_hash, s0.state_hash)
        grant, _ = auth.request_execution_grant(
            credential, fragment, s0.state_hash,
            {"kind": "admission", "decision": "ALLOW", "reason": "test"})
        other = honest_fragment(p, "run-2", 0, {"to": "LIS"})
        for refusal in (gw.execute(grant.token, other),
                        gw.execute(dataclasses.replace(grant.token, signature="00"), fragment),
                        gw.execute(dataclasses.replace(grant.token, expires_at=T0 - 1), fragment)):
            self.assertIsInstance(refusal, GatewayRefusal)
            self.assertFalse(refusal.dispatch_attempted, refusal.reason)
        self.assertEqual(gw.executions, [], "none of these reached a dispatch")

    def test_a_token_someone_else_spent_parks_the_run_as_uncertain_not_failed(self):
        """A runner that meets a token someone else spent reports UNCERTAIN, not FAILED.

        `booking_v1.lifecycle` defines EFFECT_FAILED as "certain no effect happened" and
        EFFECT_UNCERTAIN as an outcome that needs reconciliation rather than an automatic
        retry, because a blind retry could pay twice.

        The orchestrator transports the grant reply, so it sees the token. If it spends the
        token against the same fragment first, the runner meets "already consumed". Mapping
        every GatewayRefusal to FAILED would park the run as "certainly no effect" while the
        effect stood in the gateway's own execution list.
        """
        p, auth, gw, anchors, s0, dep = _fresh(run_id="run-3")
        real_execute = gw.execute

        def stolen_first(token, fragment):
            gw.execute = real_execute                 # steal once
            real_execute(token, fragment)             # the effect really happens
            return real_execute(token, fragment)      # what the runner then sees
        gw.execute = stolen_first

        fragment = honest_fragment(p, "run-3", 0, {"to": "FRA"})
        credential = auth.establish_runner_session(
            dep.bootstrap, "run-3", fragment.fragment_hash, s0.state_hash)
        result = EphemeralRunner(auth, gw, anchors, credential).execute(p, s0, fragment)

        self.assertEqual(result.status, "EFFECT_UNCERTAIN", result.reason)
        self.assertIs(auth.status("run-3"), PolicyState.EFFECT_UNCERTAIN)
        self.assertEqual([e["operation"] for e in gw.executions], ["search"],
                         "the effect did happen, so FAILED would be wrong")

    def test_changed_arguments_refused(self):
        other = honest_fragment(self.p, "run-1", 0, {"to": "MUC"})
        result = self.gw.execute(self.grant.token, other)
        self.assertIsInstance(result, GatewayRefusal)
        self.assertEqual(len(self.gw.executions), 0)

    def test_wrong_operation_refused(self):
        forged = ActionFragment(
            run_id="run-1", fragment_index=0, policy_digest=self.p.digest(),
            operation="pay", arguments={"amount_minor": 1, "currency": "EUR",
                                        "recipient": "attacker", "action_id": "x"},
            action_id="x", declared_facts=(), declared_capability="pay")
        result = self.gw.execute(self.grant.token, forged)
        self.assertIsInstance(result, GatewayRefusal)
        self.assertEqual(len(self.gw.executions), 0)

    def test_token_from_other_run_refused(self):
        _p, auth2, _gw2, _a, s0b, dep2 = _fresh(run_id="run-2")
        frag2 = honest_fragment(self.p, "run-2", 0, {"to": "FRA"})
        event = {"kind": "admission", "decision": "ALLOW", "reason": "test"}
        cred2 = auth2.establish_runner_session(
            dep2.bootstrap, "run-2", frag2.fragment_hash, s0b.state_hash)
        grant2, _ = auth2.request_execution_grant(cred2, frag2, s0b.state_hash, event)
        # A token minted by another Authority instance fails the signature. The
        # run binding is additionally asserted against a same-key token.
        result = self.gw.execute(grant2.token, self.fragment)
        self.assertIsInstance(result, GatewayRefusal)
        result2 = self.gw.execute(self.grant.token, frag2)
        self.assertIsInstance(result2, GatewayRefusal)
        self.assertEqual(len(self.gw.executions), 0)

    def test_expired_token_refused(self):
        late_gateway = ToolGateway(self.auth.token_key(), FixedClock(T0 + TOKEN_TTL + 1))
        result = late_gateway.execute(self.grant.token, self.fragment)
        self.assertIsInstance(result, GatewayRefusal)
        self.assertIn("expired", result.reason)


class TestManualIntervention(unittest.TestCase):
    """REQUIRE_APPROVAL, fragment-bound approvals, human deny."""

    def setUp(self):
        self.p, self.auth, self.gw, self.anchors, self.s0, self.dep = _fresh(policy=p3_with_pay_approval())
        self.s3 = _advance(self.p, self.dep, self.s0, 3)[-1]
        self.pay_args = {"amount_minor": 34900, "currency": "EUR",
                         "recipient": "airline:LH", "action_id": "pay-1"}

    def _pay_fragment(self, **mutation):
        """Return the step-3 pay fragment with ``mutation`` applied to its arguments."""
        return honest_fragment(self.p, "run-1", 3, {**self.pay_args, **mutation})

    def _park(self, fragment):
        """Submit once without approval: REQUIRE_APPROVAL, recorded as pending."""
        result = self.dep.provisioner.spawn(fragment, self.s3).execute(self.p, self.s3, fragment)
        self.assertEqual(result.status, "REQUIRE_APPROVAL")
        self.assertTrue(self.auth.intervention_pending("run-1", 3, fragment.fragment_hash))

    def test_pay_without_approval_requires_approval_no_effect(self):
        effects = len(self.gw.executions)
        fragment = self._pay_fragment()
        result = self.dep.provisioner.spawn(fragment, self.s3).execute(self.p, self.s3, fragment)
        self.assertEqual(result.status, "REQUIRE_APPROVAL")
        self.assertEqual(len(self.gw.executions), effects)
        self.assertIs(self.auth.status("run-1"), PolicyState.ACTIVE)

    def test_require_then_approve_then_resubmit_completes(self):
        """The full hook sequence must finalise against the unchanged envelope."""
        fragment = self._pay_fragment()
        first = self.dep.provisioner.spawn(fragment, self.s3).execute(self.p, self.s3, fragment)
        self.assertEqual(first.status, "REQUIRE_APPROVAL")
        approval = self.auth.decide_intervention(
            "run-1", 3, fragment.fragment_hash, approver_id="alice", grant=True)
        second = self.dep.provisioner.spawn(fragment, self.s3).execute(
            self.p, self.s3, fragment, intervention_approval=approval)
        self.assertEqual(second.status, "STEP_COMPLETED")
        self.assertIs(self.auth.status("run-1"), PolicyState.COMPLETED)
        self.assertEqual(len(self.auth.notices("run-1")), 1)
        _events, head = self.auth.audit("run-1")
        self.assertEqual(second.envelope.audit_head, head)

    def test_approved_fragment_completes(self):
        fragment = self._pay_fragment()
        self._park(fragment)
        approval = self.auth.decide_intervention(
            "run-1", 3, fragment.fragment_hash, approver_id="alice", grant=True)
        result = self.dep.provisioner.spawn(fragment, self.s3).execute(
            self.p, self.s3, fragment, intervention_approval=approval)
        self.assertEqual(result.status, "STEP_COMPLETED")
        self.assertIs(self.auth.status("run-1"), PolicyState.COMPLETED)

    def test_approval_binds_exact_arguments(self):
        approved = self._pay_fragment()
        self._park(approved)
        approval = self.auth.decide_intervention(
            "run-1", 3, approved.fragment_hash, approver_id="alice", grant=True)
        swapped = self._pay_fragment(recipient="attacker:acct-666")
        result = self.dep.provisioner.spawn(swapped, self.s3).execute(
            self.p, self.s3, swapped, intervention_approval=approval)
        # The swapped arguments fail the recipient binding outright. The point
        # is that the approval cannot carry over. A merely re-argued fragment
        # within policy would come back as REQUIRE_APPROVAL.
        self.assertIn(result.status, ("DENIED", "REQUIRE_APPROVAL"))
        self.assertEqual(len(self.gw.executions), 3)

    def test_expired_approval_refused_at_grant(self):
        fragment = self._pay_fragment()
        self._park(fragment)
        approval = self.auth.decide_intervention(
            "run-1", 3, fragment.fragment_hash, approver_id="alice", grant=True, ttl=-10)
        result = self.dep.provisioner.spawn(fragment, self.s3).execute(
            self.p, self.s3, fragment, intervention_approval=approval)
        self.assertEqual(result.status, "GRANT_REFUSED")
        self.assertIn("validity window", result.reason)
        self.assertEqual(len(self.gw.executions), 3)

    def test_human_denial_terminates_run(self):
        fragment = self._pay_fragment()
        self._park(fragment)
        self.assertIsNone(self.auth.decide_intervention(
            "run-1", 3, fragment.fragment_hash, approver_id="alice", grant=False))
        self.assertIs(self.auth.status("run-1"), PolicyState.TERMINATED)

    def test_denial_of_a_sibling_never_overwrites_effect_pending(self):
        """A human denial of a sibling while an effect is pending leaves EFFECT_PENDING.

        Two pay fragments X and Y are parked and X is granted. While X's effect is in
        flight the human denies Y. The denial must not move the run off EFFECT_PENDING,
        otherwise X's finalisation fails and its effect is lost to the chain. The run
        completes, and the denial does not change the status.
        """
        x = self._pay_fragment()
        y = self._pay_fragment(action_id="pay-2")
        self._park(x)
        self._park(y)
        approval = self.auth.decide_intervention("run-1", 3, x.fragment_hash, approver_id="alice", grant=True)
        real_execute = self.gw.execute

        def execute_with_concurrent_denial(token, fragment):
            self.assertIs(self.auth.status("run-1"), PolicyState.EFFECT_PENDING)
            self.assertIsNone(self.auth.decide_intervention(
                "run-1", 3, y.fragment_hash, approver_id="alice", grant=False))
            self.assertIs(self.auth.status("run-1"), PolicyState.EFFECT_PENDING)
            return real_execute(token, fragment)
        self.gw.execute = execute_with_concurrent_denial
        result = self.dep.provisioner.spawn(x, self.s3).execute(self.p, self.s3, x, intervention_approval=approval)
        self.assertEqual(result.status, "STEP_COMPLETED")
        self.assertIs(self.auth.status("run-1"), PolicyState.COMPLETED)
        events, head = self.auth.audit("run-1")
        self.assertEqual(result.envelope.audit_head, head)
        self.assertEqual(events[-1]["kind"], "effect")
        self.assertEqual(events[-1]["fragment_hash"], x.fragment_hash)

    def test_a_runner_denial_of_a_sibling_never_breaks_the_chain_of_a_pending_effect(self):
        """The same collision as above, but through the runner's denial path.

        The test above covers the human interface, which only touches the status. A runner
        that denies reports through `report_denial`, which must not append the event or
        extend the audit head while an effect is in flight. The holder of the pending grant
        computed its successor over the old head, so a moved head would make the Authority
        refuse the finalisation. The booking would stand, its admission and effect events
        would not enter the chain, and the run would stay in EFFECT_PENDING.
        """
        x = self._pay_fragment()
        self._park(x)
        approval = self.auth.decide_intervention(
            "run-1", 3, x.fragment_hash, approver_id="alice", grant=True)
        # A sibling the monitor refuses: same step, same state, declarations the policy does
        # not derive. Its own session is legitimate, its verdict is DENY.
        sibling = ActionFragment(
            run_id="run-1", fragment_index=3, policy_digest=self.p.digest(), operation="pay",
            arguments=dict(self.pay_args, action_id="pay-sibling"), action_id="pay-sibling",
            declared_facts=(), declared_capability="pay")
        real_execute = self.gw.execute

        def execute_with_concurrent_runner_denial(token, fragment):
            self.assertIs(self.auth.status("run-1"), PolicyState.EFFECT_PENDING)
            denied = self.dep.provisioner.spawn(sibling, self.s3).execute(self.p, self.s3, sibling)
            self.assertEqual(denied.status, "DENIED")
            self.assertIs(self.auth.status("run-1"), PolicyState.EFFECT_PENDING)
            return real_execute(token, fragment)
        self.gw.execute = execute_with_concurrent_runner_denial

        result = self.dep.provisioner.spawn(x, self.s3).execute(
            self.p, self.s3, x, intervention_approval=approval)
        self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
        self.assertIs(self.auth.status("run-1"), PolicyState.COMPLETED)
        events, head = self.auth.audit("run-1")
        self.assertEqual(result.envelope.audit_head, head, "the chain head must stay in sync")
        self.assertEqual(events[-1]["kind"], "effect")
        self.assertEqual(events[-1]["fragment_hash"], x.fragment_hash)
        self.assertNotIn("DENY", [e.get("decision") for e in events],
                         "the sibling denial belongs outside the chain, like a pending notice")
        self.assertTrue(any(n.get("kind") == "denial-while-effect-pending"
                            and n.get("fragment_hash") == sibling.fragment_hash
                            for n in self.auth.notices("run-1")),
                        "and it is recorded, not dropped")

    def test_a_runner_denial_with_no_effect_in_flight_still_terminates_and_chains(self):
        """Without a pending effect, the denial is a chain event and the run is terminated."""
        sibling = ActionFragment(
            run_id="run-1", fragment_index=3, policy_digest=self.p.digest(), operation="pay",
            arguments=dict(self.pay_args, action_id="pay-solo"), action_id="pay-solo",
            declared_facts=(), declared_capability="pay")
        head_before = self.auth.audit("run-1")[1]
        result = self.dep.provisioner.spawn(sibling, self.s3).execute(self.p, self.s3, sibling)
        self.assertEqual(result.status, "DENIED")
        self.assertIs(self.auth.status("run-1"), PolicyState.TERMINATED)
        events, head = self.auth.audit("run-1")
        self.assertNotEqual(head, head_before)
        self.assertEqual(events[-1].get("decision"), "DENY")

    def test_decision_on_an_unsubmitted_fragment_is_a_no_op(self):
        """A decision on a fragment no runner submitted changes nothing.

        The human interface signs only what a runner submitted and the Authority parked.
        An invented hash gets no approval, and a denial of it cannot terminate a live run,
        so whoever reaches the interface has no denial primitive.
        """
        fragment = self._pay_fragment()
        self.assertFalse(self.auth.intervention_pending("run-1", 3, fragment.fragment_hash))
        self.assertIsNone(self.auth.decide_intervention(
            "run-1", 3, fragment.fragment_hash, approver_id="alice", grant=True))
        self.assertIsNone(self.auth.decide_intervention(
            "run-1", 3, "ab" * 32, approver_id="alice", grant=False))
        self.assertIs(self.auth.status("run-1"), PolicyState.ACTIVE)
        # consumed once granted and used: a second decision for the same hash is a no-op too
        self._park(fragment)
        approval = self.auth.decide_intervention("run-1", 3, fragment.fragment_hash, approver_id="alice", grant=True)
        result = self.dep.provisioner.spawn(fragment, self.s3).execute(self.p, self.s3, fragment, intervention_approval=approval)
        self.assertEqual(result.status, "STEP_COMPLETED")
        self.assertIsNone(self.auth.decide_intervention("run-1", 3, fragment.fragment_hash, approver_id="alice", grant=True))


class TestFragmentedFlightMatchesV2(unittest.TestCase):
    """Four separate runners reproduce the booking_v2 outcome (P8, P9)."""

    def _run_v2_reference(self):
        """Run the happy path through the in-process booking_v2 monitor."""
        p2 = default_p2_1()          # the base P3 wraps
        approval = approve(p2, approver_id="alice", approval_id="A-v2", run_id="run-v2",
                           issued_at=T0 - 1000, expires_at=T_EXPIRES)
        monitor = PolicyMonitor(p2, approval, run_id="run-v2",
                                clock=FixedClock(T0), ledger=RunLedger())
        for tool, args in [
            ("search", {"to": "FRA"}), ("select", {"flight": "LH123"}),
            ("book", {"flight": "LH123", "action_id": "book-1"}),
            ("pay", {"amount_minor": 34900, "currency": "EUR",
                     "recipient": "airline:LH", "action_id": "pay-1"}),
        ]:
            monitor.submit(ToolCall(tool, args))
        return monitor

    def test_happy_path_across_four_runners(self):
        p, auth, gw, anchors, s0, dep = _fresh()
        report = Orchestrator(dep.provisioner).run(p, s0, happy_path_arguments())
        self.assertEqual(report.statuses, ["STEP_COMPLETED"] * 4)
        self.assertEqual(len(set(report.runner_nos)), 4)  # four distinct runners
        self.assertEqual(report.final_envelope.step_index, 4)
        self.assertIs(auth.status("run-1"), PolicyState.COMPLETED)

    def test_state_chain_links_every_predecessor(self):
        p, auth, gw, anchors, s0, dep = _fresh()
        envelopes = _advance(p, dep, s0, 4)
        for prev, nxt in zip(envelopes, envelopes[1:]):
            self.assertEqual(nxt.previous_state_hash, prev.state_hash)
            self.assertEqual(nxt.step_index, prev.step_index + 1)
        _events, head = auth.audit("run-1")
        self.assertEqual(envelopes[-1].audit_head, head)

    def test_v3_facts_equal_v2_facts(self):
        p, auth, gw, anchors, s0, dep = _fresh()
        final = Orchestrator(dep.provisioner).run(p, s0, happy_path_arguments()).final_envelope
        v2 = self._run_v2_reference()
        self.assertIs(v2.state, PolicyState.COMPLETED)
        v2_facts = {name: (thaw(f.value), f.ftype) for name, f in v2.facts().items()}
        v3_facts = {name: (rec["value"], rec["ftype"]) for name, rec in thaw(final.facts).items()}
        # thaw turns set facts into sorted lists on both sides, so the two maps compare directly.
        self.assertEqual(v2_facts, v3_facts)

    def test_second_booking_variant_completes(self):
        p, auth, gw, anchors, s0, dep = _fresh()
        args = [
            {"to": "FRA"}, {"flight": "LH250"},
            {"flight": "LH250", "action_id": "book-1"},
            {"amount_minor": 37500, "currency": "EUR", "recipient": "airline:LH", "action_id": "pay-1"},
        ]
        report = Orchestrator(dep.provisioner).run(p, s0, args)
        self.assertEqual(report.statuses, ["STEP_COMPLETED"] * 4)

    def test_rejected_scenarios_execute_zero_further_effects(self):
        p, auth, gw, anchors, s0, dep = _fresh()
        args = [{"to": "FRA"}, {"flight": "ZZZ"}]
        report = Orchestrator(dep.provisioner).run(p, s0, args)
        self.assertEqual(report.statuses, ["STEP_COMPLETED", "DENIED"])
        self.assertEqual([e["operation"] for e in gw.executions], ["search"])  # P9
        self.assertIs(auth.status("run-1"), PolicyState.TERMINATED)


class TestRunnerChannel(unittest.TestCase):
    """Sessions are unobtainable without the bootstrap and bound to one fragment."""

    def setUp(self):
        self.p, self.auth, self.gw, self.anchors, self.s0, self.dep = _fresh()
        self.fragment = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})
        self.fake_allow = {"kind": "admission", "decision": "ALLOW",
                           "reason": "the runner said ALLOW, trust me"}

    def _session(self, fragment=None, state_hash=None):
        """Open a real runner session for ``fragment`` on ``state_hash``."""
        fragment = fragment or self.fragment
        return self.auth.establish_runner_session(
            self.dep.bootstrap, fragment.run_id,
            fragment.fragment_hash, state_hash or self.s0.state_hash)

    def _forged(self):
        """Return a credential for a session the Authority never opened."""
        return RunnerCredential(
            session_id="rs-forged", run_id="run-1",
            fragment_hash=self.fragment.fragment_hash,
            state_hash=self.s0.state_hash, secret="forged")

    def test_session_unobtainable_without_bootstrap(self):
        """An orchestrator cannot acquire a real session, only request runners."""
        with self.assertRaises(ProvisioningRefused):
            self.auth.establish_runner_session(
                ProvisionerCredential(secret="guessed"), "run-1",
                self.fragment.fragment_hash, self.s0.state_hash)
        with self.assertRaises(ProvisioningRefused):
            self.auth.establish_runner_session(
                "not-a-credential", "run-1",
                self.fragment.fragment_hash, self.s0.state_hash)
        self.assertEqual(self.gw.executions, [])

    def test_fabricated_allow_without_credential_gets_no_grant(self):
        grant, why = self.auth.request_execution_grant(
            self._forged(), self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNone(grant)
        self.assertIn("unauthenticated", why)
        self.assertEqual(self.gw.executions, [])  # zero gateway dispatches
        self.assertIs(self.auth.status("run-1"), PolicyState.ACTIVE)

    def test_wrong_secret_gets_no_grant(self):
        real = self._session()
        forged = RunnerCredential(
            session_id=real.session_id, run_id=real.run_id,
            fragment_hash=real.fragment_hash, state_hash=real.state_hash,
            secret="0" * 32)
        grant, why = self.auth.request_execution_grant(
            forged, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNone(grant)
        self.assertIn("unauthenticated", why)

    def test_session_binds_exact_fragment(self):
        """A session provisioned for F0 grants nothing for a different fragment."""
        other = honest_fragment(self.p, "run-1", 0, {"to": "MUC"})
        credential = self._session(fragment=other)
        grant, why = self.auth.request_execution_grant(
            credential, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNone(grant)
        self.assertIn("does not bind", why)

    def test_session_binds_exact_input_state(self):
        credential = self._session(state_hash="0" * 64)
        grant, why = self.auth.request_execution_grant(
            credential, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNone(grant)
        self.assertIn("does not bind", why)

    def test_session_consumed_by_refused_grant(self):
        """A refused grant attempt also closes the session."""
        credential = self._session(state_hash="1" * 64)
        first, _ = self.auth.request_execution_grant(
            credential, self.fragment, "1" * 64, self.fake_allow)
        self.assertIsNone(first)  # refused (stale state), session now closed
        second, why = self.auth.request_execution_grant(
            credential, self.fragment, "1" * 64, self.fake_allow)
        self.assertIsNone(second)
        self.assertIn("unauthenticated", why)

    def test_forged_finalization_refused(self):
        credential = self._session()
        grant, _ = self.auth.request_execution_grant(
            credential, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNotNone(grant)
        record = TransitionRecord(
            run_id="run-1", grant_id=grant.grant_id, outcome="CONFIRMED_VALIDATED",
            admission_event=self.fake_allow, effect_event={"kind": "effect"}, proposed=None)
        signed, why = self.auth.finalize_transition(self._forged(), record)
        self.assertIsNone(signed)
        self.assertIn("unauthenticated", why)

    def test_finalization_must_answer_the_granted_admission(self):
        """The Authority accepts only the admission event it granted."""
        credential = self._session()
        grant, _ = self.auth.request_execution_grant(
            credential, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNotNone(grant)
        swapped = {"kind": "admission", "decision": "ALLOW", "reason": "rewritten"}
        record = TransitionRecord(
            run_id="run-1", grant_id=grant.grant_id, outcome="CONFIRMED_VALIDATED",
            admission_event=swapped,
            effect_event={"kind": "effect", "run_id": "run-1", "step_index": 0,
                          "fragment_hash": self.fragment.fragment_hash},
            proposed=None)
        signed, why = self.auth.finalize_transition(credential, record)
        self.assertIsNone(signed)
        self.assertIn("does not match the granted admission", why)

    def test_effect_event_must_name_the_granted_fragment(self):
        credential = self._session()
        grant, _ = self.auth.request_execution_grant(
            credential, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNotNone(grant)
        record = TransitionRecord(
            run_id="run-1", grant_id=grant.grant_id, outcome="CONFIRMED_VALIDATED",
            admission_event=self.fake_allow,
            effect_event={"kind": "effect", "run_id": "run-1", "step_index": 0,
                          "fragment_hash": "another-fragment"},
            proposed=None)
        signed, why = self.auth.finalize_transition(credential, record)
        self.assertIsNone(signed)
        self.assertIn("does not answer the open grant", why)

    def test_session_is_single_use(self):
        credential = self._session()
        grant, _ = self.auth.request_execution_grant(
            credential, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNotNone(grant)
        second, why = self.auth.request_execution_grant(
            credential, self.fragment, self.s0.state_hash, self.fake_allow)
        self.assertIsNone(second)
        self.assertIn("unauthenticated", why)

    def test_fake_denial_cannot_terminate_run(self):
        self.auth.report_denial(self._forged(), "run-1",
                                {"kind": "admission", "decision": "DENY"})
        self.assertIs(self.auth.status("run-1"), PolicyState.ACTIVE)


class TestProvenance(unittest.TestCase):
    """The provenance fields are transported, bound and tamper-evident."""

    def setUp(self):
        self.p, self.auth, self.gw, self.anchors, self.s0, self.dep = _fresh()
        self.fragments = []
        envelope = self.s0
        for step, args in enumerate(happy_path_arguments()):
            fragment = honest_fragment(self.p, "run-1", step, args)
            self.fragments.append(fragment)
            result = self.dep.provisioner.spawn(fragment, envelope).execute(
                self.p, envelope, fragment)
            self.assertEqual(result.status, "STEP_COMPLETED")
            envelope = result.envelope
        self.final = envelope

    def test_provenance_binds_run_fragment_and_audit(self):
        events, archive_head = self.auth.audit("run-1")
        # Recompute the chain head after each committed step's effect event.
        head = genesis_audit_head("run-1", self.p.digest(), "A-run-1")
        head_after_step = {}
        for i in range(0, len(events), 2):
            head = chain_extend(head, [events[i], events[i + 1]])
            head_after_step[events[i]["step_index"]] = head
        self.assertEqual(head, archive_head)
        facts = thaw(self.final.facts)
        self.assertEqual(len(facts), 9)      # P2.1: 3 offer facts, selected, 4 booking facts, payment_paid
        for name, rec in facts.items():
            # producing_seq keeps the booking_v2 semantics: it indexes the producing
            # effect event in the archived chain (admission at 2i, effect at 2i+1),
            # so the archived event can be dereferenced directly.
            seq = rec["producing_seq"]
            step = (seq - 1) // 2
            effect_event = events[seq]
            self.assertEqual(effect_event["kind"], "effect", name)
            self.assertEqual(effect_event["step_index"], step, name)
            self.assertIn(name, effect_event["produced_facts"])
            self.assertEqual(rec["run_id"], "run-1", name)
            self.assertEqual(rec["source_tool"], self.p.allowed_flow[step], name)
            self.assertEqual(rec["fragment_id"], self.fragments[step].fragment_hash[:16], name)
            self.assertEqual(rec["integrity"], head_after_step[step], name)

    def test_tampered_provenance_invalidates_envelope(self):
        facts = thaw(self.final.facts)
        facts["booking_amount_minor"]["fragment_id"] = "forged-fragment"
        tampered = StateEnvelope(
            run_id=self.final.run_id, policy_digest=self.final.policy_digest,
            approval_id=self.final.approval_id, step_index=self.final.step_index,
            facts=facts, audit_head=self.final.audit_head,
            previous_state_hash=self.final.previous_state_hash).with_signature(self.final.signature)
        self.assertFalse(verify_envelope(tampered, self.anchors.envelope_key)[0])


class TestPolicyObjectTrust(unittest.TestCase):
    """In-process, `check()` trusts the delivered policy object to compute its own digest.

    This is monitor.py step 0. A lying object with the approved digest and a permissive
    flow is admitted, because the process is the boundary in this model. The tests pin
    what that costs. booking_v4 closes it at the wire:
    `booking_v4.tests.TestAdversarialBoundary` shows the same lie cannot cross
    `policy_from_wire`, which reconstructs and re-derives the digest.
    """

    @staticmethod
    def _lying(real):
        """Return a policy object that reports the approved digest and permits everything."""
        class LyingPolicy:
            allowed_flow = ("pay", "select", "book", "pay")
            max_executions = real.max_executions
            approval_required_steps = ()
            def digest(self): return real.digest()
            def local_at(self, s): return None
            def bindings_at(self, s): return ()
            def producers_at(self, s): return ()
            def postconditions_at(self, s): return ()
        return LyingPolicy()

    def test_the_authority_refuses_the_operation_a_lying_object_names_out_of_sequence(self):
        """A lying object cannot name a payment at step 0, even with a valid digest.

        The Authority keeps the approved operation sequence, which the object's
        permissive flow does not change.
        """
        real, _auth, _gw, _anchors, s0, dep = _fresh(run_id="run-lie")
        pay = ActionFragment(run_id="run-lie", fragment_index=0, policy_digest=real.digest(), operation="pay",
                             arguments={"amount_minor": 999999, "currency": "EUR",
                                        "recipient": "attacker:acct-666", "action_id": "x"},
                             action_id="x", declared_facts=(), declared_capability="pay")
        result = dep.provisioner.spawn(pay, s0).execute(self._lying(real), s0, pay)
        self.assertEqual(result.status, "GRANT_REFUSED")
        self.assertIn("approved operation", result.reason)
        self.assertEqual(dep.gateway.executions, [])

    def test_known_limit_a_lying_policy_object_passes_the_in_process_digest_check(self):
        """At the approved operation a lying object still removes constraints and bindings.

        The in-process monitor evaluates them from the object it was given, and the
        Authority does not evaluate them.
        """
        real, _auth, _gw, _anchors, s0, dep = _fresh(run_id="run-lie")
        envelopes = _advance(real, dep, s0, 3)
        state = envelopes[3]
        args = {"amount_minor": 999999, "currency": "EUR", "recipient": "attacker:acct-666", "action_id": "x"}
        pay = ActionFragment(run_id="run-lie", fragment_index=3, policy_digest=real.digest(), operation="pay",
                             arguments=args, action_id="x", declared_facts=(), declared_capability="pay")
        result = dep.provisioner.spawn(pay, state).execute(self._lying(real), state, pay)
        self.assertEqual(result.status, "STEP_COMPLETED")                 # the limit
        self.assertEqual([e["operation"] for e in dep.gateway.executions][-1], "pay")


class TestDifferentialConformance(unittest.TestCase):
    """P8: booking_v2 and booking_v3 agree on decisions, final facts and final state per trace."""

    def test_all_traces_agree(self):
        for d in differential_conformance():
            self.assertTrue(d.decisions_equal, f"{d.trace}: {d.decisions_v2} != {d.decisions_v3}")
            self.assertTrue(d.facts_equal, f"{d.trace}: final facts differ")
            self.assertTrue(d.state_equal, f"{d.trace}: {d.final_v2} != {d.final_v3}")


class TestLyingWorld(unittest.TestCase):
    """The counterparty lies, plausibly and well-typed, on the fragmented plane.

    The table is pinned, so a change here changes the claim.
    """

    PINNED = {
        # (scenario, policy): verdict.  P2.1 = what P3 wraps, P2 = frozen baseline on the fragmented plane.
        ("world-price-drift", "P2.1"): "EFFECT_UNRECONCILED", ("world-price-drift", "P2"): "LEAK_AS_PREDICTED",
        ("world-currency-drift", "P2.1"): "EFFECT_UNRECONCILED", ("world-currency-drift", "P2"): "CALL_BLOCKED",
        ("world-select-swap", "P2.1"): "CALL_BLOCKED", ("world-select-swap", "P2"): "LEAK_AS_PREDICTED",
        ("world-negative-price", "P2.1"): "CALL_BLOCKED", ("world-negative-price", "P2"): "LEAK_AS_PREDICTED",
        ("world-paid-false", "P2.1"): "EFFECT_UNRECONCILED", ("world-paid-false", "P2"): "LEAK_AS_PREDICTED",
        ("world-attacker-recipient", "P2.1"): "LEAK_AS_PREDICTED", ("world-attacker-recipient", "P2"): "LEAK_AS_PREDICTED",
    }

    def test_the_world_table_is_pinned_in_process(self):
        results = run_backend("in-process")
        self.assertEqual({(r.name, r.policy): r.verdict for r in results}, self.PINNED)
        self.assertTrue(all(r.matches_prediction for r in results))
        # the documented limit: one leak under P2.1, five under P2
        self.assertEqual(sorted(r.name for r in results if r.policy == "P2.1" and r.verdict == "LEAK_AS_PREDICTED"),
                         ["world-attacker-recipient"])
        self.assertEqual(len([r for r in results if r.policy == "P2" and r.verdict == "LEAK_AS_PREDICTED"]), 5)

    def test_a_lying_reply_leaves_no_signed_successor(self):
        """A lying reply fails closed after the effect.

        The booking ran and the post-effect check failed. The Authority signed no
        successor, the run parks in EFFECT_UNCERTAIN, the audit chain ends with the
        INTEGRITY_FAILED effect event, and pay has no input state.
        """
        ws = next(w for w in world_scenarios() if w.name == "world-price-drift")
        ctx = make_context(policy=default_p3(), world_overrides=ws.world_overrides)
        report = Orchestrator(ctx.provisioner).run(ctx.policy, ctx.s0, ws.step_arguments)
        self.assertEqual(report.statuses, ["STEP_COMPLETED", "STEP_COMPLETED", "EFFECT_UNCERTAIN"])
        self.assertIsNone(report.results[-1].envelope)
        self.assertIs(ctx.authority.status("run-1"), PolicyState.EFFECT_UNCERTAIN)
        events, _head = ctx.authority.audit("run-1")
        self.assertEqual((events[-1]["kind"], events[-1]["outcome"]), ("effect", "INTEGRITY_FAILED"))
        self.assertEqual([e["operation"] for e in ctx.gateway.executions], ["search", "select", "book"])
        # a pay fragment against the last signed state is refused: that state is at step 2
        # and the run is parked
        pay = honest_fragment(ctx.policy, "run-1", 3, {"amount_minor": 39999, "currency": "EUR",
                                                        "recipient": "airline:LH", "action_id": "pay-1"})
        last_signed = report.results[1].envelope
        result = ctx.provisioner.spawn(pay, last_signed).execute(ctx.policy, last_signed, pay)
        self.assertNotEqual(result.status, "STEP_COMPLETED")
        self.assertEqual([e["operation"] for e in ctx.gateway.executions], ["search", "select", "book"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
