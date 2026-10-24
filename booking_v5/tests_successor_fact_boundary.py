"""Characterisation of a known and accepted limit of the Authority. Not a defence test.

Run:
    python3 -m booking_v5.tests_successor_fact_boundary

The Authority authenticates the proposed successor (it is named by its state hash inside the
runner's signature) and links it (run, policy, approval, predecessor, step, audit head). It also
compares the reported effect event with the gateway's durable record. It does not derive the
facts in the successor from that effect. The facts are the statement of a bound runner, and the
threat model (Chapter 3) states that as a trust assumption: the monitor and state-transition logic
inside the runner is correct. Cryptographic integrity of the state is therefore not the same as
correct derivation of the facts in it.

A green test in this module means that the documented limit was reproduced. It does not mean
that the weakness is prevented. If the third case fails, the Authority has started to derive or
check facts, and the description of the successor state and of the runner in the trust table must
be revised on purpose, not by accident. If the second case fails, the signature binding of the
attested decision is broken, which is a regression of a defence.

The cases run on one run, over the in-process Authority and gateway, with the Authority's effect
ledger bound so that the observation check is in force:

    1  The unchanged proposal with its own attestation is signed.
    2  One fact is changed and the runner's original attestation kept. It is refused (a defence).
    3  The same fact is changed, the proposal rebuilt (new state hash) and attested again with the
       bound runner's own key. It is signed, although the effect result and the gateway record
       are unchanged. This is the characterised limit.
    +  Control: a changed effect payload, attested in the same way, is still refused by the
       observation check. The check is therefore active in this rig, so case 3 passes because of
       what the Authority does not compare and not because a check was switched off.

The key in case 3 models a bound runner that is already compromised. It does not show that a
runner can be compromised. There is no cluster and no payment. The narrow evidence is that the
Authority validly signs the altered fact store.
"""
from __future__ import annotations

import dataclasses
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.effects import response_digest
from booking_v1.freeze import thaw, to_canonical
from booking_v1.lifecycle import PolicyState
from booking_v3 import runner_attestation as ra
from booking_v3.envelope import SigningKey, StateEnvelope, chain_extend
from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3
from booking_v3.provisioner import create_deployment
from booking_v3.runner import EphemeralRunner

from . import tests_v5_attested_decision as base

RUN = base.RUN
BOOK_STEP = 2
#: The fact that the later payment step is bound to, and the value the forgery puts in it.
FACT = "booking_recipient"
FORGED_VALUE = "attacker:acct-42"


class _RecordingGateway:
    """The gateway, plus the digest of every response it returned.

    The ledger view below answers from this record, so the Authority compares the reported effect
    with what the gateway produced, not with a value chosen by the test.
    """

    def __init__(self, real) -> None:
        self._real = real
        self.recorded: dict[str, tuple[str, str]] = {}

    def __getattr__(self, name):
        return getattr(self._real, name)

    def execute(self, token, fragment):
        result = self._real.execute(token, fragment)
        if hasattr(result, "outcome"):
            payload = None if result.payload is None else dict(thaw(result.payload))
            self.recorded[token.grant_id] = ("COMMITTED", response_digest(result.outcome.value, payload))
        return result


class _LedgerView:
    """What `Authority.bind_effect_ledger` expects, backed by the recording gateway."""

    def __init__(self, gateway: _RecordingGateway) -> None:
        self._gateway = gateway
        self.asked: list[str] = []

    def effect(self, grant_id: str):
        self.asked.append(grant_id)
        return self._gateway.recorded.get(grant_id, (None, None))


class TheAuthorityAuthenticatesTheSuccessorNotTheFacts(unittest.TestCase):
    """One run up to the booking step. The booking runner's finalisation is captured, not sent."""

    def setUp(self):
        self.policy = default_p3()
        self.dep = create_deployment(FixedClock(base.T0))
        approval = approve(self.policy, approver_id="alice", approval_id=f"A-{RUN}", run_id=RUN,
                           issued_at=base.ISSUED, expires_at=base.EXPIRES)
        envelope = self.dep.authority.create_run(self.policy, approval, RUN)
        self.gateway = _RecordingGateway(self.dep.gateway)
        self.ledger = _LedgerView(self.gateway)
        self.dep.authority.bind_effect_ledger(self.ledger)       # the observation check is in force
        for step in range(BOOK_STEP):                              # search, select: honest and complete
            result, _signer, _credential = self._run(step, envelope)
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
            envelope = result.envelope
        self.predecessor = envelope
        channel = base._HostileChannel(self.dep.authority, drop=("finalize_transition",))
        _result, self.signer, self.credential = self._run(BOOK_STEP, envelope, authority=channel)
        _name, _credential, self.record, self.attestation = channel.read[0]
        self.honest_recipient = thaw(self.record.proposed.facts)[FACT]["value"]
        self.assertEqual(self.dep.authority.status(RUN), PolicyState.EFFECT_PENDING, "the grant must be open")

    # Helpers.

    def _run(self, step, envelope, authority=None):
        """Run one attested runner step.

        Returns:
            The result, the runner's key and its credential.
        """
        fragment = honest_fragment(self.policy, RUN, step, happy_path_arguments()[step])
        signer = SigningKey()
        credential = self.dep.authority.establish_runner_session(
            self.dep.bootstrap, fragment.run_id, fragment.fragment_hash, envelope.state_hash,
            verify_key=signer.verify_key().to_bytes())
        runner = EphemeralRunner(authority or self.dep.authority, self.gateway, self.dep.anchors,
                                 credential, signer=signer)
        return runner.execute(self.policy, envelope, fragment), signer, credential

    def _with_fact(self, value, audit_head=None) -> StateEnvelope:
        """Return the captured proposal with one type-correct fact value changed.

        Everything else stays equal, the audit head too unless the caller passes another one. The
        state hash is recomputed.
        """
        facts = dict(thaw(self.record.proposed.facts))
        facts[FACT] = {**facts[FACT], "value": value}
        proposed = self.record.proposed
        return StateEnvelope(
            run_id=proposed.run_id, policy_digest=proposed.policy_digest, approval_id=proposed.approval_id,
            step_index=proposed.step_index, facts=facts, audit_head=audit_head or proposed.audit_head,
            previous_state_hash=proposed.previous_state_hash)

    def _attest(self, record):
        """Return the finalize statement for `record`, signed with the bound runner's own key."""
        return ra.sign(self.signer, ra.finalize_statement(
            run_id=record.run_id, grant_id=record.grant_id, outcome=record.outcome,
            admission_hash=ra.event_digest(record.admission_event),
            effect_hash=ra.event_digest(record.effect_event),
            proposed_state_hash=record.proposed.state_hash))

    def _finalize(self, record, attestation):
        """Present `record` and `attestation` to the Authority's finalize path."""
        return self.dep.authority.finalize_transition(self.credential, record, attestation)

    # The three cases.

    def test_1_the_unchanged_proposal_is_signed(self):
        signed, why = self._finalize(self.record, self.attestation)
        self.assertIsNotNone(signed, why)
        self.assertEqual(thaw(signed.facts)[FACT]["value"], self.honest_recipient)

    def test_2_a_changed_fact_under_the_original_attestation_is_refused(self):
        forged = self._with_fact(FORGED_VALUE)
        self.assertNotEqual(forged.state_hash, self.record.proposed.state_hash)
        signed, why = self._finalize(dataclasses.replace(self.record, proposed=forged), self.attestation)
        self.assertIsNone(signed, "regression: a rewritten fact store was signed")
        self.assertIn("does not match the statement", why)
        self.assertIs(self.dep.authority.status(RUN), PolicyState.EFFECT_PENDING, "nothing was adopted")

    def test_3_characterisation_a_bound_runner_can_have_a_changed_fact_signed(self):
        """The known and accepted limit.

        A green result means the documented limit was reproduced, not that the weakness is
        prevented.
        """
        forged = self._with_fact(FORGED_VALUE)
        record = dataclasses.replace(self.record, proposed=forged)
        # Everything the Authority can compare is unchanged and true:
        self.assertEqual(record.effect_event, self.record.effect_event, "the reported effect is the real one")
        self.assertEqual(record.proposed.previous_state_hash, self.record.proposed.previous_state_hash)
        self.assertEqual(record.proposed.audit_head, self.record.proposed.audit_head)
        self.assertEqual(record.proposed.step_index, self.record.proposed.step_index)
        recorded = self.gateway.recorded[self.record.grant_id]
        self.assertEqual(recorded[1], response_digest("CONFIRMED", dict(thaw(self.record.effect_event["payload"]))),
                         "the gateway record matches the true effect")

        signed, why = self._finalize(record, self._attest(record))

        self.assertIsNotNone(signed, f"the limit is no longer reproduced, its description must be revised on purpose: {why}")
        self.assertEqual(thaw(signed.facts)[FACT]["value"], FORGED_VALUE)
        self.assertNotEqual(FORGED_VALUE, self.honest_recipient)
        self.assertEqual(thaw(self.record.effect_event["payload"])["recipient"], self.honest_recipient,
                         "the signed fact contradicts the effect result the gateway recorded")
        self.assertIn(self.record.grant_id, self.ledger.asked, "the observation check ran for this grant")
        self.assertIs(self.dep.authority.status(RUN), PolicyState.ACTIVE)

    # The control.

    def test_control_a_changed_effect_payload_is_still_refused_by_the_observation_check(self):
        """The same forgery with the same key, but with the effect result altered as well.

        The audit head is rebuilt over it so that no linkage check fires first. Only the
        comparison with the gateway's record can refuse it, and it does.
        """
        payload = dict(thaw(self.record.effect_event["payload"]))
        payload["recipient"] = FORGED_VALUE
        effect = to_canonical({**dict(self.record.effect_event), "payload": payload})
        head = chain_extend(self.predecessor.audit_head, [to_canonical(self.record.admission_event), effect])
        record = dataclasses.replace(self.record, effect_event=effect,
                                     proposed=self._with_fact(FORGED_VALUE, audit_head=head))
        signed, why = self._finalize(record, self._attest(record))
        self.assertIsNone(signed)
        self.assertIn("observation-mismatch", why)
        self.assertIs(self.dep.authority.status(RUN), PolicyState.EFFECT_RECONCILE)


if __name__ == "__main__":
    unittest.main()
