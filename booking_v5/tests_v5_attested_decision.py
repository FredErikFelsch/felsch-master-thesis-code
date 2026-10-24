"""The Authority believes a verdict because the measured TD signed it, not because the caller
holds the credential.

The attack in one trace: on a session that records no verdict key, the channel after attestation
carries no authentication, and `report_denial` puts the bearer credential on it in the case where
it must not be usable, because the monitor has just refused the fragment. A hostile host reads
that message, drops it (so the session stays OPEN and the run stays ACTIVE) and states an ALLOW
itself for the fragment that was refused. Every Authority check passes, because all of them are
about identity and freshness and none of them is about meaning: the session binds this fragment
and this state, the step is the expected one, the policy digest matches, the budget is not spent.
The Authority mints a grant whose `authorized_request_hash` names the attacker's own payment, and
the gateway performs it. The host does more than race an effect that was already admitted,
because nothing has been admitted at that point.

The configuration this test runs is the measured one: `default_p3` marks no step for human
approval, so the payment step has nothing in front of it but the monitor's verdict.
`test_the_same_trace_succeeds_without_a_verdict_key` is the control. It is the same trace on a
session that records no key, and it succeeds. The two traces differ only in the recorded verdict
key.

The three refusals the attacker meets:

    grant       the statement is reconstructed by the Authority from the request it is about
                to act on, so a forged ALLOW needs a signature over bytes the forger cannot
                produce
    finalize    the statement names the proposed successor by its state hash, so a rewritten
                fact store is refused before it can be signed into an envelope
    phase       a statement collected on one path is not valid on another, so the DENY the TD
                honestly signed cannot be replayed as an admission
"""
from __future__ import annotations

import dataclasses
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.freeze import thaw, to_canonical
from booking_v1.lifecycle import PolicyState
from booking_v3 import runner_attestation as ra
from booking_v3.authority import request_hash
from booking_v3.envelope import SigningKey, StateEnvelope, VerifyKey
from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3
from booking_v3.provisioner import create_deployment
from booking_v3.runner import EphemeralRunner

from .binding import RunnerIdentity, canonical_binding
from .rtmr_replay import boot_key_content

RUN = "run-h2"
T0, ISSUED, EXPIRES = 1_760_000_000, 1_759_999_000, 1_760_090_000

#: The manipulated payment: the right amount and currency, to the wrong account. The monitor
#: refuses it because `recipient` is bound to the recipient the booking confirmed.
EVIL_PAYMENT = {"amount_minor": 34900, "currency": "EUR",
                "recipient": "attacker:acct-42", "action_id": "pay-1"}


class _HostileChannel:
    """The host between the TD and the Authority.

    It forwards by default, records everything it sees, and drops what it is told to drop. It
    holds no key and no standing of its own. Every call it makes later is made with material it
    read off the wire.
    """

    def __init__(self, authority, drop: tuple[str, ...] = ()):
        self._authority = authority
        self._drop = drop
        self.read: list[tuple] = []

    def __getattr__(self, name):
        return getattr(self._authority, name)

    def report_denial(self, credential, run_id, admission_event, attestation=None):
        self.read.append(("report_denial", credential, admission_event, attestation))
        if "report_denial" in self._drop:
            return None
        return self._authority.report_denial(credential, run_id, admission_event, attestation)

    def finalize_transition(self, credential, record, attestation=None):
        self.read.append(("finalize_transition", credential, record, attestation))
        if "finalize_transition" in self._drop:
            return None, "dropped on the channel"
        return self._authority.finalize_transition(credential, record, attestation)


class AttestedDecisionTests(unittest.TestCase):
    """Forged and replayed verdicts are refused. Honest runs and V3 and V4 sessions are unchanged."""

    def setUp(self):
        self.dep = create_deployment(FixedClock(T0))
        self.policy = default_p3()
        approval = approve(self.policy, approver_id="alice", approval_id=f"A-{RUN}",
                           run_id=RUN, issued_at=ISSUED, expires_at=EXPIRES)
        self.s0 = self.dep.authority.create_run(self.policy, approval, RUN)

    # Helpers.

    def _td(self, fragment, envelope, *, attested: bool = True):
        """Return one modelled TD: its own verdict key, and the session the Authority minted for it.

        `attested=False` is a session without a verdict key: the Authority records no key, so it
        keeps believing whatever arrives on the channel. That is what V3 and V4 still do, and what
        the control test uses to show the attack working.
        """
        signer = SigningKey()
        credential = self.dep.authority.establish_runner_session(
            self.dep.bootstrap, fragment.run_id, fragment.fragment_hash, envelope.state_hash,
            verify_key=signer.verify_key().to_bytes() if attested else None)
        return signer, credential

    def _runner(self, credential, signer, authority=None):
        """Return a V3 runner for the session, talking to `authority` (the real one by default)."""
        return EphemeralRunner(authority or self.dep.authority, self.dep.gateway,
                               self.dep.anchors, credential, signer=signer)

    def _advance(self, envelope, step: int, *, attested: bool = True) -> StateEnvelope:
        """Run one honest step to completion and return the signed successor."""
        fragment = honest_fragment(self.policy, RUN, step, happy_path_arguments()[step])
        signer, credential = self._td(fragment, envelope, attested=attested)
        result = self._runner(credential, signer if attested else None).execute(
            self.policy, envelope, fragment)
        self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
        return result.envelope

    def _up_to_payment(self, *, attested: bool = True) -> StateEnvelope:
        """Run search, select and book, and return the envelope before the payment."""
        envelope = self.s0
        for step in range(3):                      # search, select, book
            envelope = self._advance(envelope, step, attested=attested)
        return envelope

    @staticmethod
    def _forged_allow(fragment) -> dict:
        """Return the admission event a host would write for itself.

        It carries the real fragment and the real arguments, and a decision nobody computed.
        """
        return to_canonical({
            "kind": "admission", "run_id": fragment.run_id,
            "step_index": fragment.fragment_index, "fragment_hash": fragment.fragment_hash,
            "tool": fragment.operation, "args": thaw(fragment.arguments),
            "decision": "allow", "reason": "admitted",
        })

    # The attack.

    def test_a_host_that_reads_the_credential_cannot_state_an_allow(self):
        envelope = self._up_to_payment()
        evil = honest_fragment(self.policy, RUN, 3, EVIL_PAYMENT)
        signer, credential = self._td(evil, envelope)

        channel = _HostileChannel(self.dep.authority, drop=("report_denial",))
        result = self._runner(credential, signer, authority=channel).execute(
            self.policy, envelope, evil)
        self.assertEqual(result.status, "DENIED")
        self.assertIn("recipient", result.reason)

        # The host now holds the credential, and the run is still alive because it dropped the
        # report. Without a verdict key that position is enough to forge an admission.
        self.assertEqual([c[0] for c in channel.read], ["report_denial"])
        stolen = channel.read[0][1]
        self.assertIs(self.dep.authority.status(RUN), PolicyState.ACTIVE)

        grant, why = self.dep.authority.request_execution_grant(
            stolen, evil, envelope.state_hash, self._forged_allow(evil))
        self.assertIsNone(grant, "a host without the TD's verdict key must not obtain a grant")
        self.assertIn("no attested decision presented", why)
        self.assertIs(self.dep.authority.status(RUN), PolicyState.ACTIVE,
                      "a refused grant admits nothing, so no effect is pending")

    def test_the_same_trace_succeeds_without_a_verdict_key(self):
        """The control, which shows that the verdict key fixes an open path.

        The same steps on a session that records no verdict key make the Authority mint a grant
        for the manipulated payment, bound to the attacker's own request hash. V3 and V4 still
        behave this way by design.
        """
        envelope = self._up_to_payment(attested=False)
        evil = honest_fragment(self.policy, RUN, 3, EVIL_PAYMENT)
        _signer, credential = self._td(evil, envelope, attested=False)

        channel = _HostileChannel(self.dep.authority, drop=("report_denial",))
        result = self._runner(credential, None, authority=channel).execute(
            self.policy, envelope, evil)
        self.assertEqual(result.status, "DENIED")

        grant, _why = self.dep.authority.request_execution_grant(
            channel.read[0][1], evil, envelope.state_hash, self._forged_allow(evil))
        self.assertIsNotNone(grant, "without a verdict key the forged ALLOW is believed")
        self.assertEqual(grant.token.authorized_request_hash,
                         request_hash(evil.operation, evil.arguments))

    def test_a_signed_denial_cannot_be_replayed_as_an_admission(self):
        """A statement signed on the denial path is not valid on the grant path.

        The TD did sign something for this fragment, honestly: a DENY. A host that keeps that
        signature and presents it on the grant path is refused, because the statement the grant
        reconstructs is a different object.
        """
        envelope = self._up_to_payment()
        evil = honest_fragment(self.policy, RUN, 3, EVIL_PAYMENT)
        signer, credential = self._td(evil, envelope)

        channel = _HostileChannel(self.dep.authority, drop=("report_denial",))
        self._runner(credential, signer, authority=channel).execute(self.policy, envelope, evil)
        stolen_credential, _event, stolen_attestation = channel.read[0][1:]
        self.assertIsNotNone(stolen_attestation, "the TD signs its denial")

        grant, why = self.dep.authority.request_execution_grant(
            stolen_credential, evil, envelope.state_hash, self._forged_allow(evil),
            None, stolen_attestation)
        self.assertIsNone(grant)
        self.assertIn("does not match the statement", why)

    def test_a_rewritten_successor_is_refused_before_it_is_signed(self):
        """On the finalize path, a rewritten successor is refused before it is signed.

        This path does more damage. The Authority checks the linkage of a proposed successor, not
        its meaning, so whoever can finalize can write the fact store every later step is
        admitted against. The signature names the proposal by its state hash, so the rewrite is
        refused and nothing is signed.
        """
        envelope = self._advance(self.s0, 0)            # the search step produced the offers
        fragment = honest_fragment(self.policy, RUN, 1, happy_path_arguments()[1])
        signer, credential = self._td(fragment, envelope)

        channel = _HostileChannel(self.dep.authority, drop=("finalize_transition",))
        self._runner(credential, signer, authority=channel).execute(self.policy, envelope, fragment)
        _name, stolen_credential, record, attestation = channel.read[0]
        self.assertIsNotNone(record.proposed)

        poisoned = dict(thaw(record.proposed.facts))
        poisoned["injected_by_the_host"] = {"name": "injected_by_the_host", "value": "attacker",
                                            "type": "string"}
        rewritten = StateEnvelope(
            run_id=record.proposed.run_id, policy_digest=record.proposed.policy_digest,
            approval_id=record.proposed.approval_id, step_index=record.proposed.step_index,
            facts=poisoned, audit_head=record.proposed.audit_head,
            previous_state_hash=record.proposed.previous_state_hash)
        self.assertNotEqual(rewritten.state_hash, record.proposed.state_hash)

        signed, why = self.dep.authority.finalize_transition(
            stolen_credential, dataclasses.replace(record, proposed=rewritten), attestation)
        self.assertIsNone(signed, "no envelope may be signed over facts the TD did not produce")
        self.assertIn("does not match the statement", why)

    # What must not have changed.

    def test_the_honest_run_is_untouched(self):
        envelope = self.s0
        for step in range(4):
            envelope = self._advance(envelope, step)
        self.assertEqual(envelope.step_index, 4)
        self.assertIs(self.dep.authority.status(RUN), PolicyState.COMPLETED)

    def test_a_session_without_a_verdict_key_requires_no_attestation(self):
        """V3 and V4 are unchanged.

        Their host is still trusted beneath the runner, so their sessions record no key and their
        calls carry none. The countermeasure belongs to V5, whose threat model has a hostile host.
        """
        envelope = self.s0
        for step in range(4):
            envelope = self._advance(envelope, step, attested=False)
        self.assertIs(self.dep.authority.status(RUN), PolicyState.COMPLETED)

    def test_require_compares_the_whole_statement(self):
        """`require` compares canonical bytes.

        A statement with an added, renamed or dropped field is a mismatch, not an extra the
        verifier ignores.
        """
        key = SigningKey()
        statement = ra.grant_statement(run_id=RUN, step=3, state_hash="s" * 64,
                                       fragment_hash="f" * 64, operation="pay",
                                       request_hash="r" * 64, admission_hash="a" * 64)
        attestation = ra.sign(key, statement)
        verify_key = key.verify_key()
        self.assertEqual(ra.require(verify_key, statement, attestation)[0], True)
        self.assertEqual(ra.require(None, statement, None)[0], True)
        self.assertEqual(ra.require(verify_key, statement, None),
                         (False, "no attested decision presented"))
        widened = dict(statement, extra="whatever")
        self.assertFalse(ra.require(verify_key, widened, attestation)[0])
        dropped = {k: v for k, v in statement.items() if k != "request_hash"}
        self.assertFalse(ra.require(verify_key, dropped, attestation)[0])
        renamed = {("op" if k == "operation" else k): v for k, v in statement.items()}
        self.assertFalse(ra.require(verify_key, renamed, attestation)[0])
        self.assertFalse(ra.require(SigningKey().verify_key(), statement, attestation)[0])


class MeasuredKeyTests(unittest.TestCase):
    """The verdict key is bound into the canonical binding and the measured history."""

    def test_the_verdict_key_is_inside_the_canonical_binding_and_the_measured_history(self):
        seen: list = []
        identity = RunnerIdentity.create(rtmr_extend=lambda op, content: seen.append((op, content)))
        identity.bind(RUN, 3, "f" * 64, "s" * 64)
        nonce = b"\x09" * 32

        self.assertEqual(seen[0], ("boot-key", boot_key_content(identity.pk_boot.hex(),
                                                                identity.pk_sig.hex())))
        self.assertEqual(identity.runtime_data(nonce),
                         canonical_binding(nonce, RUN, 3, "f" * 64, "s" * 64,
                                           identity.pk_boot, identity.pk_sig))
        other = RunnerIdentity.create().pk_sig
        self.assertNotEqual(identity.runtime_data(nonce),
                            canonical_binding(nonce, RUN, 3, "f" * 64, "s" * 64,
                                              identity.pk_boot, other),
                            "a substituted verdict key must change what the hardware signed")

    def test_the_identity_signer_matches_the_announced_verdict_key(self):
        identity = RunnerIdentity.create()
        statement = ra.deny_statement(run_id=RUN, state_hash="s" * 64, fragment_hash="f" * 64,
                                      admission_hash="a" * 64)
        attestation = ra.sign(identity.signer, statement)
        self.assertTrue(ra.require(VerifyKey.from_bytes(identity.pk_sig), statement, attestation)[0])


if __name__ == "__main__":
    unittest.main()
