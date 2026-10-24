"""The session package is sealed to the TD, but nothing authenticates who sealed it.

Run:
    python3 -m booking_v5.tests_session_package_sender

`seal_to(pk_boot, plaintext, aad)` is X25519 ephemeral-static ECDH. It needs only the TD's public
boot key, which the TD announces in `v5-hello`, and the AAD, which is the public bind event of
(run, step, fragment hash, state hash). Anyone who can compose the `v5-session` line can therefore
seal a package of their own, and `runner_main.serve` decrypts it and takes credential and trust
anchors out of it (see the docstring of `booking_v4.wire.session_package_to_wire`).

These tests pin down how far that gap reaches, measured with the packet decoder of the runner
(`runner_main.serve` over pipes) and the in-process Authority:

    accepted            the TD opens a package the Authority did not make and hands the monitor
                        the forged credential and the forged trust anchors (current behaviour)
    local only          the forged credential obtains no grant at the Authority, so no effect,
                        and the run can still be provisioned and completed afterwards
    control             a package from the relying party arrives unchanged

Limit: this is local execution inside the TD against anchors of the attacker's choosing, and
misleading evidence for whoever reads the runner's result line. It is not a grant or effect
bypass. The claim "the runner receives its trust anchors authenticated from the Authority" is
therefore not backed by the mechanism. To keep it, the TD needs an independently anchored
verification value for the Authority (for example a key in the measured init-data), and the
package must be signed under it. Without that the claim is an explicit trust assumption: the
party that composes the session line (the controller) is trusted not to substitute the package.
"""
from __future__ import annotations

import unittest

from booking_v3 import scenarios as v3
from booking_v3.authority import RunnerCredential
from booking_v3.fragment import honest_fragment
from booking_v3.runner import RunnerResult
from booking_v4 import wire

from .binding import bind_event, seal_to
from .relying_party import AuthorityRelyingParty, FakeVerifier
from .runner_bind import Challenge
from . import tests_v5_protocol as base      # module import: its TestCase must not be collected here

RUN, STEP = base.RUN, base.STEP
_credential_octets, _domain_objects = base._credential_octets, base._domain_objects


def key_bytes(anchors) -> tuple[bytes, bytes]:
    """Return the two trust anchors as raw public keys, because the objects compare by identity."""
    return anchors.envelope_key.to_bytes(), anchors.intervention_key.to_bytes()


class SessionPackageSender(unittest.TestCase):
    """Reuses the pipe harness of `tests_v5_protocol` without re-running its tests."""

    setUp = base.ProtocolEndToEnd.setUp
    tearDown = base.ProtocolEndToEnd.tearDown
    _start_runner = base.ProtocolEndToEnd._start_runner
    _transport = base.ProtocolEndToEnd._transport

    def _execute(self, policy, envelope, fragment, intervention, anchors, endpoint, credential,
                 gateway_endpoint=None, signer=None):
        """Record what the monitor was handed, the credential and the anchors."""
        self.handed = (credential, anchors)
        return RunnerResult(status="STEP_COMPLETED", envelope=None, reason="ok",
                            payload={"flights": []}, runner_no=1)

    def _attested_td(self):
        """Return a TD that attested honestly for this binding, with the keys it announced."""
        ctl = self._start_runner()
        rp = AuthorityRelyingParty(FakeVerifier(), self.ref)
        transport = self._transport(ctl)
        keys = transport.boot_keys("td-1")
        nonce = rp.issue_nonce(RUN, STEP, self.frag_hash, self.state_hash, keys.pk_boot)
        evidence = transport.attest("td-1", Challenge(RUN, STEP, self.frag_hash, self.state_hash, nonce))
        return rp, transport, keys, nonce, evidence

    def _forged_sealed(self, keys):
        """Return a package the Authority did not make.

        It carries the attacker's credential and the attacker's own trust anchors, sealed with
        public values only.
        """
        _, _, _, attacker_anchors, _ = _domain_objects()
        self.assertNotEqual(key_bytes(attacker_anchors), key_bytes(self.anchors))
        forged = RunnerCredential(session_id="sess-forged", run_id=RUN, fragment_hash=self.frag_hash,
                                  state_hash=self.state_hash, secret="attacker-chosen")
        octets = wire.encode(wire.session_package_to_wire(forged, attacker_anchors)).encode()
        aad = bind_event(RUN, STEP, self.frag_hash, self.state_hash)
        return forged, attacker_anchors, seal_to(keys.pk_boot, octets, aad)

    def test_the_td_accepts_a_package_the_authority_did_not_make(self):
        """Current behaviour, recorded: forged credential and forged anchors reach the monitor."""
        _, transport, keys, _, _ = self._attested_td()
        forged, attacker_anchors, sealed = self._forged_sealed(keys)
        result = transport.deliver("td-1", sealed, self.frag_octets, self.env_octets)
        self.assertEqual(result.status, "STEP_COMPLETED")
        credential, anchors = self.handed
        self.assertEqual(credential, forged)
        self.assertEqual(key_bytes(anchors), key_bytes(attacker_anchors))
        self.assertNotEqual(key_bytes(anchors), key_bytes(self.anchors),
                            "the monitor verifies against the attacker's keys")

    def test_the_forged_credential_does_not_authenticate_at_the_real_authority(self):
        """The reach is local.

        The forged credential obtains no grant at the Authority, so no effect, and the run can
        still be provisioned and completed afterwards.
        """
        ctx = v3.make_context()
        frag = honest_fragment(ctx.policy, ctx.run_id, 0, {"to": "LIS"})
        forged = RunnerCredential(session_id="sess-forged", run_id=ctx.run_id,
                                  fragment_hash=frag.fragment_hash, state_hash=ctx.s0.state_hash,
                                  secret="attacker-chosen")
        grant, why = ctx.authority.request_execution_grant(forged, frag, ctx.s0.state_hash, {"kind": "admission"})
        self.assertIsNone(grant)
        self.assertIn("unauthenticated runner channel", why)
        # The run is untouched: the honest runner can still be provisioned and granted.
        honest = ctx.provisioner.spawn(frag, ctx.s0)
        self.assertEqual(honest.execute(ctx.policy, ctx.s0, frag).status, "STEP_COMPLETED")

    def test_control_a_package_from_the_relying_party_arrives_unchanged(self):
        rp, transport, keys, nonce, evidence = self._attested_td()
        session = rp.establish_session(evidence, keys.pk_boot, keys.pk_sig, RUN, STEP, self.frag_hash,
                                       self.state_hash, nonce, _credential_octets,
                                       self.ref.substrate_profile_hash)
        self.assertFalse(hasattr(session, "rule"), getattr(session, "detail", ""))
        result = transport.deliver("td-1", session.sealed, self.frag_octets, self.env_octets)
        self.assertEqual(result.status, "STEP_COMPLETED")
        credential, anchors = self.handed
        self.assertEqual(credential.secret, "s3cret")
        self.assertEqual(key_bytes(anchors), key_bytes(self.anchors))


if __name__ == "__main__":
    unittest.main()
