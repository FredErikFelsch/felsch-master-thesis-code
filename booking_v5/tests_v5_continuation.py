"""The continuation gate of the relying party.

A second attested session for (run, step) exists only as the continuation of a session that
ended in REQUIRE_APPROVAL. The tests run over the in-process V5 services of `experiment_v5`
and drive them with the frozen V3 scenario helpers.

The rule is `relying_party._continuation_refused`. The prior session redeemed no effect, the
fragment and the state are the same, and the Authority holds the pending intervention for this
fragment (unconsumed, run not terminal). The gate does not validate the human approval. That
check stays in the frozen V3 grant path.
"""
from __future__ import annotations

import dataclasses
import unittest

from booking_v3 import scenarios as v3s
from booking_v3.fragment import honest_fragment
from booking_v3.policy import p3_with_pay_approval

from .experiment_v5 import ATTESTATION_REFUSED, AttestedInProcessDeployment, create_attested_deployment
from .relying_party import SESSION_ACTIVE, SESSION_SUPERSEDED, AuthorityRelyingParty, FakeVerifier

RULE = "step-already-has-session"


class ContinuationGateTests(unittest.TestCase):
    """A second session for (run, step) is admitted only as the continuation of a pending intervention."""

    def setUp(self):
        self.deployments: list[AttestedInProcessDeployment] = []

        def factory(clock, executor=None):
            dep = create_attested_deployment(clock, executor=executor)
            self.deployments.append(dep)
            return dep

        v3s.set_deployment_factory(factory)

    def tearDown(self):
        v3s.set_deployment_factory(None)
        for dep in self.deployments:
            dep.close()

    def _pending_pay(self):
        """Run steps 0 to 2, then submit pay (step 3) without approval, which ends in REQUIRE_APPROVAL."""
        ctx = v3s.make_context(policy=p3_with_pay_approval())
        outcome = v3s.ScenarioOutcome()
        envelopes = v3s._advance(ctx, outcome, 3)
        pay = honest_fragment(ctx.policy, ctx.run_id, 3, v3s.PAY_ARGS)
        first = v3s._step(ctx, envelopes[-1], pay, outcome)
        self.assertEqual(first.status, "REQUIRE_APPROVAL")
        return ctx, envelopes, pay, outcome

    def _approve(self, ctx, pay):
        return ctx.human_approver.decide_intervention(
            ctx.run_id, 3, pay.fragment_hash, approver_id=v3s.APPROVER_ID, grant=True)

    def _rp(self):
        return self.deployments[-1].rp

    # Admitted.

    def test_approved_resubmission_is_a_second_session_that_supersedes_the_first(self):
        ctx, envelopes, pay, outcome = self._pending_pay()
        rp = self._rp()
        first = rp.session_for(ctx.run_id, 3)
        result = v3s._step(ctx, envelopes[-1], pay, outcome, intervention=self._approve(ctx, pay))
        self.assertEqual(result.status, "STEP_COMPLETED")
        self.assertEqual(ctx.authority.status(ctx.run_id).value, "COMPLETED")
        second = rp.session_for(ctx.run_id, 3)
        self.assertIsNot(first, second)
        self.assertNotEqual(first.td_id, second.td_id, "two attested TDs, not one session rewritten")
        self.assertEqual((first.state, first.superseded_by), (SESSION_SUPERSEDED, second.td_id.hex()))
        self.assertEqual(second.state, SESSION_ACTIVE)
        self.assertEqual(rp._history, [first])
        runs = self.deployments[-1].records
        self.assertEqual([r.effects for r in runs], [1, 1, 1, 0, 1])

    def test_pending_intervention_without_approval_admits_a_session_but_no_effect(self):
        """The documented limit of the gate.

        While the intervention is pending, re-attestation without an approval is admitted at the
        relying party and refused again at the grant. It obtains no authority and causes no effect,
        the run stays ACTIVE and the intervention stays pending.
        """
        ctx, envelopes, pay, outcome = self._pending_pay()
        again = v3s._step(ctx, envelopes[-1], pay, outcome)              # no approval presented
        self.assertEqual(again.status, "REQUIRE_APPROVAL")
        self.assertEqual(ctx.authority.status(ctx.run_id).value, "ACTIVE")
        dep = self.deployments[-1]
        self.assertEqual([r.effects for r in dep.records], [1, 1, 1, 0, 0])
        self.assertEqual(len(dep.rp._history), 1)
        pending = [n for n in dep.base.authority.notices(ctx.run_id)
                   if n["kind"] == "intervention-pending" and n["fragment_hash"] == pay.fragment_hash]
        self.assertTrue(pending, "the intervention is still pending")
        # The approval still completes the run afterwards.
        done = v3s._step(ctx, envelopes[-1], pay, outcome, intervention=self._approve(ctx, pay))
        self.assertEqual(done.status, "STEP_COMPLETED")
        self.assertEqual(len(dep.rp._history), 2)

    def test_the_superseded_credential_cannot_redeem(self):
        ctx, envelopes, pay, outcome = self._pending_pay()
        rp = self._rp()
        old = rp.session_for(ctx.run_id, 3)
        v3s._step(ctx, envelopes[-1], pay, outcome, intervention=self._approve(ctx, pay))
        self.assertEqual(rp.redeem(old.credential, ctx.run_id, 3, "e" * 64).rule, "credential-out-of-scope")
        self.assertEqual(rp.redeem(rp.session_for(ctx.run_id, 3).credential, ctx.run_id, 3, "e" * 64).run_id,
                         ctx.run_id)

    # Refused.

    def _refused(self, ctx, envelope, fragment, outcome, detail_prefix=None, intervention=None,
                 not_at_step=False):
        """Assert that the attempt is refused at the relying party, before any runner and any effect.

        Args:
            ctx: The scenario context.
            envelope: The envelope the attempt presents.
            fragment: The fragment the attempt presents.
            outcome: The scenario outcome to record into.
            detail_prefix: The start of the gate's refusal detail. Required unless `not_at_step`.
            intervention: The approved intervention to present, if any.
            not_at_step: The run is no longer at this step on this state (completed, consumed,
                other state). The read-only check of the Authority's own view then refuses the
                attempt as `run-not-at-step` before the continuation gate is asked, so there is
                no gate detail to compare.
        """
        result = v3s._step(ctx, envelope, fragment, outcome, intervention)
        self.assertEqual(result.status, ATTESTATION_REFUSED)
        rec = self.deployments[-1].records[-1]
        if not_at_step:
            self.assertEqual(rec.refusal.rule, "run-not-at-step")
        else:
            self.assertEqual(rec.refusal.rule, RULE)
            self.assertTrue(rec.refusal.detail.startswith(detail_prefix), rec.refusal.detail)
        self.assertEqual((rec.effects, rec.pending_effects, rec.foreign_effects), (0, 0, 0))

    def test_a_different_fragment_is_not_a_continuation(self):
        ctx, envelopes, pay, outcome = self._pending_pay()
        swapped = honest_fragment(ctx.policy, ctx.run_id, 3,
                                  {**v3s.PAY_ARGS, "recipient": "attacker:acct-666"})
        self._refused(ctx, envelopes[-1], swapped, outcome, "no pending intervention",
                      intervention=self._approve(ctx, pay))

    def test_a_different_state_is_refused_before_the_gate(self):
        """The run is not at step 3 on an older state, so the position check refuses it first."""
        ctx, envelopes, pay, outcome = self._pending_pay()
        self._refused(ctx, envelopes[-2], pay, outcome,
                      intervention=self._approve(ctx, pay), not_at_step=True)

    def test_a_completed_step_admits_no_second_session(self):
        """The run has moved past step 1, so the position check refuses a replay of it first."""
        ctx = v3s.make_context()
        outcome = v3s.ScenarioOutcome()
        envelopes = v3s._advance(ctx, outcome, 2)
        replay = honest_fragment(ctx.policy, ctx.run_id, 1, v3s.happy_path_arguments()[1])
        self._refused(ctx, envelopes[1], replay, outcome, not_at_step=True)

    def test_a_consumed_continuation_admits_no_third_session(self):
        """The run completed with the continuation, so the position check refuses a third attempt."""
        ctx, envelopes, pay, outcome = self._pending_pay()
        approval = self._approve(ctx, pay)
        done = v3s._step(ctx, envelopes[-1], pay, outcome, intervention=approval)
        self.assertEqual(done.status, "STEP_COMPLETED")
        self._refused(ctx, envelopes[-1], pay, outcome, intervention=approval, not_at_step=True)

    def test_the_gate_refuses_a_redeemed_prior_another_fragment_and_another_state(self):
        """The gate's own conditions, asked directly with the pending session as the prior.

        In the deployment the position check answers first for another state, so this test calls
        `_continuation_refused` to show the gate would refuse it as well.
        """
        ctx, envelopes, pay, outcome = self._pending_pay()
        prior = self._rp().session_for(ctx.run_id, 3)
        gate = AuthorityRelyingParty._continuation_refused
        pending = lambda run_id, step, fragment_hash: fragment_hash == pay.fragment_hash  # noqa: E731
        state = prior.scope.state_hash
        self.assertIsNone(gate(prior, ctx.run_id, 3, pay.fragment_hash, state, pending))
        self.assertEqual(gate(prior, ctx.run_id, 3, pay.fragment_hash, "0" * 64, pending),
                         "state differs from the pending one")
        self.assertEqual(gate(prior, ctx.run_id, 3, "f" * 64, state, lambda *a: True),
                         "fragment differs from the pending one")
        self.assertEqual(gate(prior, ctx.run_id, 3, "f" * 64, state, pending),
                         "no pending intervention for this fragment")
        self.assertEqual(gate(prior, ctx.run_id, 3, pay.fragment_hash, state, None),
                         "no pending intervention for this fragment")
        redeemed = dataclasses.replace(prior, effect_id="e" * 64)
        self.assertEqual(gate(redeemed, ctx.run_id, 3, pay.fragment_hash, state, pending),
                         "prior session redeemed an effect")

    # Durability.

    def test_the_history_survives_the_state_round_trip(self):
        ctx, envelopes, pay, outcome = self._pending_pay()
        v3s._step(ctx, envelopes[-1], pay, outcome, intervention=self._approve(ctx, pay))
        rp = self._rp()
        state = rp.export_state()
        self.assertEqual([s["state"] for s in state["sessions"]], [SESSION_ACTIVE] * 4)
        self.assertEqual([(h["state"], h["superseded_by"]) for h in state["history"]],
                         [(SESSION_SUPERSEDED, rp.session_for(ctx.run_id, 3).td_id.hex())])
        copy = AuthorityRelyingParty(FakeVerifier(), rp.reference)
        copy.import_state(state)
        self.assertEqual(copy.export_state(), state)
        self.assertEqual(len(copy._history), 1)


if __name__ == "__main__":
    unittest.main()
