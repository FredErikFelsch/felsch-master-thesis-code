"""Offline tests of the V5 model, without a cluster, hardware or a Kubernetes client.

Tests whose name carries an acceptance label (A10 to A18, see `scripts/gke-v5/attack_catalogue.md`)
specify the live test of that label offline. Only the live suite demonstrates it.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import unittest
import unittest.mock

from .binding import (BINDING_V50, AlreadyBound, BytesMismatch, NotBound, RunnerIdentity, bind_event,
                      canonical_binding, seal_to, td_identity)
from .evidence import FakeAttestationAgent
from .rtmr_replay import expected_rtmr3, replay
from .pool import TdPool
from .profile_v5 import (INIT_DATA_ANNOTATION, RUNTIME_CLASS, SUBSTRATE_PROFILE, build_runner_pod_manifest,
                         init_data_hash, manifest_without_identity, substrate_profile_hash)
from .relying_party import (AuthorityRelyingParty, FakeVerifier, ReferenceValues, Refusal,
                            Session, SessionScope, tdattributes_debug)
from .verifier import VerifiedClaims

RUN, STEP = "run-1", 2
FRAG_BYTES, ENV_BYTES = b'{"fragment":1}', b'{"envelope":1}'
FRAG, STATE = hashlib.sha256(FRAG_BYTES).hexdigest(), hashlib.sha256(ENV_BYTES).hexdigest()
IMG = "reg.example.com/booking@sha256:" + "a" * 64


def _mint(scope: SessionScope) -> bytes:
    """Mint a readable stand-in credential for `scope`."""
    return b"cred:" + scope.run_id.encode() + b":" + str(scope.step).encode()


class IdentityAndBindingTests(unittest.TestCase):
    """The boot key is the TD identity, a TD binds once and the binding covers all fields."""

    def test_boot_key_is_the_td_identity_and_is_generated_once(self):
        ident = RunnerIdentity.create()
        self.assertEqual(ident.td_id, td_identity(ident.pk_boot))
        self.assertNotEqual(RunnerIdentity.create().td_id, ident.td_id)

    def test_a_td_binds_at_most_once_locally(self):
        ident = RunnerIdentity.create()
        ident.bind(RUN, STEP, FRAG, STATE)
        with self.assertRaises(AlreadyBound):
            ident.bind(RUN, STEP + 1, FRAG, STATE)
        with self.assertRaises(NotBound):
            RunnerIdentity.create().runtime_data(b"\0" * 32)

    def test_rtmr_hook_records_the_two_runner_events_as_aael_lines(self):
        """The hook receives the operation and content that `POST /aa/aael` takes and the Authority replays."""
        seen = []
        ident = RunnerIdentity.create(rtmr_extend=lambda op, content: seen.append((op, content)))
        ident.bind(RUN, STEP, FRAG, STATE)
        self.assertEqual(seen, [("boot-key", f"{ident.pk_boot.hex()}.{ident.pk_sig.hex()}"),
                                ("bind", f"{RUN}/{STEP}/{FRAG}/{STATE}")])

    def test_canonical_binding_covers_version_nonce_run_step_hashes_and_keys(self):
        ident = RunnerIdentity.create()
        ident.bind(RUN, STEP, FRAG, STATE)
        n = b"\7" * 32
        fields = (n, RUN, STEP, FRAG, STATE, ident.pk_boot, ident.pk_sig)
        self.assertEqual(ident.runtime_data(n), canonical_binding(*fields))
        others = (b"\x08" * 32, "run-2", STEP + 1, "e" * 64, "t" * 64, b"\1" * 32, b"\2" * 32)
        for i, other in enumerate(others):
            with self.subTest(field=i):
                changed = fields[:i] + (other,) + fields[i + 1:]
                self.assertNotEqual(ident.runtime_data(n), canonical_binding(*changed))
        self.assertNotEqual(ident.runtime_data(n), canonical_binding(*fields, version=BINDING_V50))

    def test_A16_bytes_must_match_the_attested_hashes_before_execution(self):
        ident = RunnerIdentity.create()
        b = ident.bind(RUN, STEP, FRAG, STATE)
        b.verify_bytes(FRAG_BYTES, ENV_BYTES)                       # attested A, fed A: ok
        with self.assertRaises(BytesMismatch):
            b.verify_bytes(b'{"fragment":2}', ENV_BYTES)            # attested A, fed B: refused
        with self.assertRaises(BytesMismatch):
            b.verify_bytes(FRAG_BYTES, b'{"envelope":2}')

    def test_sealed_credential_opens_only_in_the_bound_td_for_that_binding(self):
        ident = _bound_identity()
        box = seal_to(ident.pk_boot, b"secret", aad=bind_event(RUN, STEP, FRAG, STATE))
        self.assertEqual(ident.open_sealed(box), b"secret")
        other = _bound_identity()
        with self.assertRaises(Exception):
            other.open_sealed(box)                                   # other boot key
        rebound = _bound_identity(step=STEP + 1)
        box2 = seal_to(rebound.pk_boot, b"secret", aad=bind_event(RUN, STEP, FRAG, STATE))
        with self.assertRaises(Exception):
            rebound.open_sealed(box2)                                # AAD is another binding


class FreshnessAndVersionTests(unittest.TestCase):
    """What the relying party claims about challenges and the binding version must hold."""

    def setUp(self):
        self.aa = FakeAttestationAgent()
        self.rp = AuthorityRelyingParty(FakeVerifier(), ReferenceValues(require_rtmr3=False))

    def test_every_refused_attempt_burns_the_challenge(self):
        """A challenge is consumed at its first presentation, whatever the outcome.

        A refusal that returned before the consume would leave the same challenge open for another
        try with other evidence.
        """
        ident = _bound_identity()
        for kw in ({"substrate_profile_hash": "wrong"}, {}):          # wrong substrate, no evidence
            rp = AuthorityRelyingParty(FakeVerifier(), ReferenceValues(require_rtmr3=False))
            n = rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
            first = rp.establish_session(None, ident.pk_boot, ident.pk_sig, RUN, STEP, FRAG,
                                         STATE, n, _mint, **kw)
            self.assertIsInstance(first, Refusal)
            again = rp.establish_session(self.aa.get_evidence(ident.runtime_data(n)),
                                         ident.pk_boot, ident.pk_sig, RUN, STEP, FRAG, STATE,
                                         n, _mint)
            self.assertEqual(again.rule, "nonce-reused", f"the challenge stayed open after {first.rule}")

    def test_a_challenge_belongs_to_the_td_that_asked_for_it(self):
        """A challenge issued for one boot key cannot be answered by another machine."""
        ident, other = _bound_identity(), _bound_identity()
        n = self.rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
        res = self.rp.establish_session(self.aa.get_evidence(other.runtime_data(n)),
                                        other.pk_boot, other.pk_sig, RUN, STEP, FRAG, STATE,
                                        n, _mint)
        self.assertEqual(res.rule, "nonce-td-mismatch")

    def test_a_freeze_without_a_binding_version_is_refused_by_default(self):
        """A record that names no version is refused unless the earlier binding is allowed explicitly.

        Without the refusal this would be the only fail-open default among the reference values. A
        record that names no version means the earlier v5.0 binding, in which a TD's verdict key is
        not attested.
        """
        record = {"schema_version": 1, "platform": "tdx", "substrate_profile_hash": "x" * 64,
                  "measurement": {k: "0" * 8 for k in
                                  ("mrtd", "rtmr0", "rtmr1", "rtmr2", "mrseam", "tee_tcb_svn",
                                   "xfam", "tdattributes")},
                  "init_data": {"algorithm": "sha256", "digest": "d" * 64}}
        with self.assertRaises(ValueError) as ctx:
            ReferenceValues.from_freeze_text(json.dumps(record), "<archived>")
        self.assertIn("binding_version", str(ctx.exception))
        old = ReferenceValues.from_freeze_text(json.dumps(record), "<archived>",
                                               allow_pre_h2_binding=True)
        self.assertEqual(old.binding_version, "v5.0")
        record["binding_version"] = "v5.1"
        self.assertEqual(ReferenceValues.from_freeze_text(json.dumps(record)).binding_version, "v5.1")

    def test_the_run_record_says_whether_verdicts_are_attested(self):
        """The record lets a reader tell a session whose verdicts are verified from one whose are not."""
        claims = VerifiedClaims(platform="tdx", measurement="m", runtime_data=b"")
        current = self.rp.appraisal_record(claims)
        self.assertEqual(current["binding_version"], "v5.1")
        self.assertTrue(current["verdicts_attested"])
        legacy = AuthorityRelyingParty(
            FakeVerifier(), ReferenceValues(require_rtmr3=False, binding_version="v5.0"))
        self.assertFalse(legacy.appraisal_record(claims)["verdicts_attested"])


class RelyingPartyTests(unittest.TestCase):
    """Offline analogues of acceptance tests A10 to A18 against the FakeVerifier."""

    def setUp(self):
        self.aa = FakeAttestationAgent()
        # The plain fake AA carries no RTMR3, so the weaker reference is stated, not the default.
        self.rp = AuthorityRelyingParty(FakeVerifier(), ReferenceValues(require_rtmr3=False))

    def _bound_td(self, run=RUN, step=STEP, frag=FRAG, state=STATE, aa=None):
        """Return a bound identity, a nonce issued to it and evidence over its binding."""
        ident = _bound_identity(run, step, frag, state)
        n = self.rp.issue_nonce(run, step, frag, state, ident.pk_boot)
        ev = (aa or self.aa).get_evidence(ident.runtime_data(n))
        return ident, n, ev

    def _establish(self, ident, n, ev, run=RUN, step=STEP, frag=FRAG, state=STATE):
        """Establish a session for `ident` on the relying party under test."""
        return self.rp.establish_session(ev, ident.pk_boot, ident.pk_sig, run, step, frag, state, n, _mint)

    def test_happy_path_session_is_scoped_and_openable_only_in_the_td(self):
        ident, n, ev = self._bound_td()
        res = self._establish(ident, n, ev)
        self.assertIsInstance(res, Session)
        self.assertEqual(res.scope, SessionScope(RUN, STEP, FRAG, STATE, ident.pk_boot, ident.pk_sig))
        self.assertEqual(ident.open_sealed(res.sealed), _mint(res.scope))
        self.assertIs(self.rp.session_for(RUN, STEP), res)
        self.assertIsNone(self.rp.session_for(RUN, STEP + 1))       # A17: the session has a scope

    def test_the_session_records_which_verifier_appraised_it(self):
        """A session carries `{verifier, qv_result}`, and the record survives the durable round trip.

        A run record therefore names the verifier by itself. The offline model says `FakeVerifier`
        and `FAKE`, not `OK`.
        """
        ident, n, ev = self._bound_td()
        res = self._establish(ident, n, ev)
        self.assertIsInstance(res, Session)
        self.assertEqual((res.appraisal["verifier"], res.appraisal["qv_result"]), ("FakeVerifier", "FAKE"))
        self.assertEqual(res.appraisal["advisory_ids"], [])  # the supplemental fields are present and empty offline
        copy = AuthorityRelyingParty(FakeVerifier(), ReferenceValues(require_rtmr3=False))
        copy.import_state(self.rp.export_state())
        self.assertEqual(copy.session_for(RUN, STEP).appraisal, res.appraisal)

    def test_A10_binding_mismatch_is_refused(self):
        ident, n, _ = self._bound_td()
        other = _bound_identity()
        ev = self.aa.get_evidence(other.runtime_data(n))            # evidence over another key
        self.assertEqual(self._establish(ident, n, ev).rule, "binding-mismatch")

    def test_A10_nonce_is_bound_to_the_expected_step_and_single_use(self):
        ident, n, ev = self._bound_td()
        self.assertIsInstance(self._establish(ident, n, ev), Session)
        self.assertEqual(self._establish(ident, n, ev).rule, "nonce-reused")
        self.assertEqual(self._establish(ident, b"\1" * 32, ev).rule, "nonce-unknown")
        n2 = self.rp.issue_nonce(RUN, STEP + 5, FRAG, STATE, ident.pk_boot)   # issued for another step
        self.assertEqual(self._establish(ident, n2, ev).rule, "nonce-step-mismatch")

    def test_A11_same_boot_key_cannot_be_bound_to_a_second_fragment(self):
        ident, n, ev = self._bound_td()
        self.assertIsInstance(self._establish(ident, n, ev), Session)
        # The adversary reuses the TD with a fresh nonce, a correct binding and the same pk_boot.
        frag2, state2 = "e" * 64, "t" * 64
        n2 = self.rp.issue_nonce(RUN, STEP + 1, frag2, state2, ident.pk_boot)
        ev2 = self.aa.get_evidence(canonical_binding(n2, RUN, STEP + 1, frag2, state2, ident.pk_boot, ident.pk_sig))
        self.assertEqual(self.rp.establish_session(ev2, ident.pk_boot, ident.pk_sig, RUN, STEP + 1, frag2, state2, n2, _mint).rule,
                         "td-already-bound")

    def test_A13_platform_measurement_or_policy_downgrade_is_refused(self):
        for aa, rule in ((FakeAttestationAgent(platform="sev-snp"), "platform-mismatch"),
                         (FakeAttestationAgent(measurement="mrtd-other"), "measurement-mismatch"),
                         (FakeAttestationAgent(init_data_hash="policy-with-exec"), "init-data-mismatch")):
            ident, n, ev = self._bound_td(aa=aa)
            self.assertEqual(self._establish(ident, n, ev).rule, rule)

    def test_A15_rtmr3_must_be_the_replay_of_the_expected_history(self):
        """RTMR3 must be the replay of [init-data, boot-key, bind], and one extra event breaks it.

        The Authority recomputes the value, so no event log has to travel from the guest.
        """
        ref = ReferenceValues(require_rtmr3=True)
        ident = _bound_identity()
        good = expected_rtmr3(ref.init_data_digest, ident.pk_boot.hex(), ident.pk_sig.hex(), RUN, STEP, FRAG, STATE)

        rp = self.rp = AuthorityRelyingParty(FakeVerifier(), ref)
        n = rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
        ev = FakeAttestationAgent(rtmr3=good).get_evidence(ident.runtime_data(n))
        self.assertIsInstance(self._establish(ident, n, ev), Session)

        # One extra event (a second bind attempt inside the same TD) changes the value.
        extra = replay([f"v5 bind {RUN}/9/{FRAG}/{STATE}"], good)
        for bad, rule in ((extra, "rtmr3-mismatch"), (None, "rtmr3-missing")):
            rp = self.rp = AuthorityRelyingParty(FakeVerifier(), ref)
            ident2 = _bound_identity()
            n2 = rp.issue_nonce(RUN, STEP, FRAG, STATE, ident2.pk_boot)
            ev2 = FakeAttestationAgent(rtmr3=bad).get_evidence(ident2.runtime_data(n2))
            self.assertEqual(self._establish(ident2, n2, ev2).rule, rule)

    def test_A15_a_td_booted_with_another_init_data_cannot_reach_the_expected_rtmr3(self):
        """On GCE the init-data is not in MRCONFIGID. RTMR3 carries it as event 1."""
        ref = ReferenceValues(require_rtmr3=True)
        ident = _bound_identity()
        permissive = expected_rtmr3("policy-allowing-exec", ident.pk_boot.hex(), ident.pk_sig.hex(), RUN, STEP, FRAG, STATE)
        rp = self.rp = AuthorityRelyingParty(FakeVerifier(), ref)
        n = rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
        ev = FakeAttestationAgent(rtmr3=permissive).get_evidence(ident.runtime_data(n))
        self.assertEqual(self._establish(ident, n, ev).rule, "rtmr3-mismatch")

    def test_A14_the_controller_alone_gets_no_session(self):
        """Bootstrap credentials without hardware evidence buy nothing."""
        ident = _bound_identity()
        n = self.rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
        res = self.rp.establish_session(None, ident.pk_boot, ident.pk_sig, RUN, STEP, FRAG, STATE, n, _mint)
        self.assertEqual(res.rule, "evidence-missing")

    def test_A17a_credential_scope_is_enforced(self):
        """Acceptance test A17a: a credential minted for (run, step) authorises nothing outside that scope.

        Presented for another step it finds no session, and a forged credential is out of scope.
        Neither produces an effect. Live, the V3 runner session bind in `request_execution_grant`
        enforces this property, and `redeem` is the offline model of it.
        """
        ident, n, ev = self._bound_td()
        sess = self._establish(ident, n, ev)
        self.assertEqual(self.rp.redeem(sess.credential, RUN, STEP + 1, "e" * 64).rule, "no-session-for-step")
        self.assertEqual(self.rp.redeem(b"forged", RUN, STEP, "e" * 64).rule, "credential-out-of-scope")

    def test_A17b_one_credential_is_one_logical_effect_idempotent_on_replay(self):
        """Acceptance test A17b: a credential authorises one logical effect.

        This is idempotency, distinct from the scope of A17a. Redeeming the credential again with
        the same effect_id replays the same grant, because a lost reply is not a second effect. A
        different effect_id on the same credential is refused as `credential-already-redeemed`.
        Live, the server-derived idempotency of the durable V4 server provides this, and `redeem`
        is the offline model of it.
        """
        ident, n, ev = self._bound_td()
        sess = self._establish(ident, n, ev)
        first = self.rp.redeem(sess.credential, RUN, STEP, "e" * 64)
        self.assertEqual(first.effect_id, "e" * 64)
        replay = self.rp.redeem(sess.credential, RUN, STEP, "e" * 64)
        self.assertEqual((replay.effect_id, replay.credential_id), (first.effect_id, first.credential_id))
        self.assertEqual(self.rp.redeem(sess.credential, RUN, STEP, "d" * 64).rule, "credential-already-redeemed")

    def test_boot_measurements_are_pinned_but_mrowner_is_not(self):
        ref = ReferenceValues(boot_measurements={"rtmr0": "aa", "xfam": "bb"}, require_rtmr3=False)
        rp = self.rp = AuthorityRelyingParty(FakeVerifier(), ref)
        ident = _bound_identity()
        n = rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
        good = FakeAttestationAgent(boot_measurements={"rtmr0": "aa", "xfam": "bb", "mrowner": "per-instance"})
        self.assertIsInstance(self._establish(ident, n, good.get_evidence(ident.runtime_data(n))), Session)
        rp2 = self.rp = AuthorityRelyingParty(FakeVerifier(), ref)
        ident2 = _bound_identity()
        n2 = rp2.issue_nonce(RUN, STEP, FRAG, STATE, ident2.pk_boot)
        bad = FakeAttestationAgent(boot_measurements={"rtmr0": "aa", "xfam": "changed"})
        res = self._establish(ident2, n2, bad.get_evidence(ident2.runtime_data(n2)))
        self.assertEqual(res.rule, "boot-measurement-mismatch")
        self.assertTrue(res.detail.startswith("xfam got="))

    def test_a_debug_td_is_refused_before_any_pin_and_the_default_requires_rtmr3(self):
        """TDATTRIBUTES.DEBUG (bit 0, little-endian byte 0) refuses the TD before any pin is consulted.

        A freeze therefore cannot be taken from a debug TD unnoticed. The model default
        `ReferenceValues()` demands RTMR3, so the weaker form must be written down.
        """
        self.assertTrue(tdattributes_debug("0100000000000000"))
        self.assertFalse(tdattributes_debug("0000001000000000"))      # SEPT_VE_DISABLE only (the frozen TD)
        self.assertFalse(tdattributes_debug(None))
        debug = FakeAttestationAgent(boot_measurements={"tdattributes": "0100000000000000"})
        ident = _bound_identity()
        n = self.rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
        res = self._establish(ident, n, debug.get_evidence(ident.runtime_data(n)))
        self.assertEqual(res.rule, "debug-td")
        self.assertTrue(ReferenceValues().require_rtmr3)
        strict = AuthorityRelyingParty(FakeVerifier(), ReferenceValues())
        ident2 = _bound_identity()
        n2 = strict.issue_nonce(RUN, STEP, FRAG, STATE, ident2.pk_boot)
        res2 = strict.establish_session(self.aa.get_evidence(ident2.runtime_data(n2)), ident2.pk_boot, ident2.pk_sig,
                                        RUN, STEP, FRAG, STATE, n2, _mint)
        self.assertEqual(res2.rule, "rtmr3-missing")

    def test_the_supplemental_data_is_parsed_for_the_record(self):
        """The QVL's sgx_ql_qv_supplemental_t (DCAP 1.22, version 3) is parsed for the record only.

        The dates sit at offsets 8, 16, 24 and 32, tcb_eval_ref_num at 48, and the advisory ids are
        found by pattern in sa_list.
        """
        # Imported here, because the vendored QVL wrapper is not needed by any other test.
        from .dcap.local_dcap_verify import parse_supplemental
        buf = bytearray(600)
        buf[0:4] = (3).to_bytes(4, "little")
        for off, v in ((8, 1_700_000_000), (16, 1_710_000_000), (24, 1_800_000_000), (32, 1_690_000_000)):
            buf[off:off + 8] = v.to_bytes(8, "little", signed=True)
        buf[48:52] = (17).to_bytes(4, "little")
        buf[300:330] = b"INTEL-SA-00960,INTEL-SA-00837\x00"
        rec = parse_supplemental(bytes(buf))
        self.assertEqual(rec["version"], 3)
        self.assertEqual(rec["tcb_eval_ref_num"], 17)
        self.assertEqual(rec["advisory_ids"], ["INTEL-SA-00837", "INTEL-SA-00960"])
        self.assertEqual(rec["earliest_expiration_date"], "2027-01-15T08:00:00Z")
        self.assertEqual(parse_supplemental(b"\0" * 10)["version"], None)
        # An absurd time_t is recorded as absent and does not raise.
        buf[24:32] = (2 ** 62).to_bytes(8, "little", signed=True)
        rec = parse_supplemental(bytes(buf))
        self.assertIsNone(rec["earliest_expiration_date"])
        self.assertEqual(rec["tcb_eval_ref_num"], 17)

    def test_A18_substrate_half_of_the_profile_is_pinned_too(self):
        ident, n, ev = self._bound_td()
        res = self.rp.establish_session(ev, ident.pk_boot, ident.pk_sig, RUN, STEP, FRAG, STATE, n, _mint,
                                        substrate_profile_hash="firewall-missing")
        self.assertEqual(res.rule, "substrate-profile-mismatch")

    def test_one_step_one_session(self):
        ident, n, ev = self._bound_td()
        self.assertIsInstance(self._establish(ident, n, ev), Session)
        ident2, n2, ev2 = self._bound_td()                          # another TD, same step
        self.assertEqual(self._establish(ident2, n2, ev2).rule, "step-already-has-session")

    def test_A15_a_pool_td_is_unbound_until_it_binds_and_binds_only_once(self):
        """Acceptance test A15 for the warm pool: an idle pool TD can redeem nothing.

        A pre-booted, idle pool TD holds no credential and no session. Its first
        establish_session consumes it by binding pk_boot. A second establish_session for the same
        pk_boot, even for another (run, step), is td-already-bound (A11 from the pool's side).
        The pool's own rule against reuse is covered in PoolTests.
        """
        ident = RunnerIdentity.create()                             # a freshly booted, still-idle pool TD
        self.assertIsNone(self.rp.session_for(RUN, STEP))           # unbound: the Authority knows nothing of it
        self.assertEqual(self.rp.redeem(b"whatever", RUN, STEP, "e" * 64).rule, "no-session-for-step")
        ident.bind(RUN, STEP, FRAG, STATE)                          # first binding consumes the TD
        n = self.rp.issue_nonce(RUN, STEP, FRAG, STATE, ident.pk_boot)
        self.assertIsInstance(self._establish(ident, n, self.aa.get_evidence(ident.runtime_data(n))), Session)
        frag2, state2 = "e" * 64, "t" * 64                          # same pk_boot, another (run, step)
        n2 = self.rp.issue_nonce(RUN, STEP + 1, frag2, state2, ident.pk_boot)
        ev2 = self.aa.get_evidence(canonical_binding(n2, RUN, STEP + 1, frag2, state2, ident.pk_boot, ident.pk_sig))
        self.assertEqual(self.rp.establish_session(ev2, ident.pk_boot, ident.pk_sig, RUN, STEP + 1, frag2, state2, n2, _mint).rule,
                         "td-already-bound")


def _bound_identity(run=RUN, step=STEP, frag=FRAG, state=STATE) -> RunnerIdentity:
    """Return a fresh runner identity bound to (run, step, frag, state)."""
    ident = RunnerIdentity.create()
    ident.bind(run, step, frag, state)
    return ident


class _FakeBackend:
    """TdPool backend whose TDs are names. Every TD is ready at once."""

    def __init__(self):
        self.n = 0
        self.alive = set()
        self.deleted = []

    def create(self):
        self.n += 1
        name = f"td-{self.n}"
        self.alive.add(name)
        return name

    def is_ready(self, name):
        return True

    def delete_and_confirm(self, name):
        self.alive.discard(name)
        self.deleted.append(name)

    def list_managed(self):
        return sorted(self.alive)


class _NotYetReadyBackend(_FakeBackend):
    """A backend whose machines are ready only once the test says so.

    `_FakeBackend` reports every machine ready the instant it exists. That suits the hand-out
    rules but not the timing ones: with an instantly ready replacement the pool cannot run dry,
    so the cold fallback would not be reached.
    """

    def __init__(self):
        super().__init__()
        self.ready = set()

    def is_ready(self, name):
        return name in self.ready

    def mark_ready(self, *names):
        self.ready.update(names)


class _OneDeadBackend(_FakeBackend):
    """A backend whose first machine dies in the pool.

    Its pod hit activeDeadlineSeconds while idle, so is_ready raises for it, as the Kubernetes
    backend does for a terminal pod state.
    """

    def is_ready(self, name: str) -> bool:
        if name.endswith("-1"):
            raise RuntimeError(f"{name} is Failed: DeadlineExceeded")
        return super().is_ready(name)


class PoolTests(unittest.TestCase):
    """The pool hands out each TD once, replaces it at the hand-out and evicts dead machines."""

    def test_a_dead_idle_td_is_evicted_not_offered_again(self):
        # A Failed idle TD must not stay idle and raise out of every later acquire. It is evicted
        # and replaced.
        be = _OneDeadBackend()
        pool = TdPool(be, size=2)
        pool.fill()
        dead = [n for n in pool._idle if n.endswith("-1")]
        self.assertEqual(len(dead), 1)
        name, _ = pool.acquire(("r", 0, "f1", "search"))
        self.assertFalse(name.endswith("-1"))
        self.assertNotIn(dead[0], pool._idle)
        self.assertIn(dead[0], pool._retired)
        name2, _ = pool.acquire(("r", 1, "f2", "select"))       # the dead one does not come back
        self.assertFalse(name2.endswith("-1"))

    def test_pool_hands_out_each_td_once_and_retires_after_use(self):
        be = _FakeBackend()
        pool = TdPool(be, size=2)
        pool.fill()
        a, ra = pool.acquire(("r", 1, "frag-a", "s"))
        b, rb = pool.acquire(("r", 2, "frag-b", "s"))
        c, rc = pool.acquire(("r", 3, "frag-c", "s"))
        self.assertEqual(len({a, b, c}), 3, "no machine is handed out twice")
        self.assertEqual((ra, rb, rc), (0.0, 0.0, 0.0), "every hand-out was warm")
        self.assertEqual(be.n, 5, "each hand-out started its own replacement")
        pool.retire(a)
        self.assertIn(a, be.deleted)
        self.assertNotIn(pool.acquire(("r", 4, "frag-d", "s"))[0], (a, b, c))

    def test_a_hand_out_starts_its_replacement_at_once(self):
        """The refill belongs to the hand-out, not to the end of the fragment.

        Topping the pool up only after the whole run would cost a replacement a full run of head
        start. With a boot time of 87 s and a warm step of 21 s that is the difference between a
        pool of five and a pool of six, and a live series of ten runs can go cold because a
        replacement is a few seconds short.
        """
        be = _FakeBackend()
        pool = TdPool(be, size=2)
        pool.fill()
        self.assertEqual((pool.idle, be.n), (2, 2))
        pool.acquire(("r", 0, "frag-a", "s"))
        self.assertEqual(pool.idle, 2, "the pool is back at size without the caller doing anything")
        self.assertEqual(be.n, 3, "one replacement was asked for")
        pool.fill()
        self.assertEqual(be.n, 3, "a top-up after the run is now a no-op")

    def test_a_replacement_that_is_not_ready_yet_gives_a_cold_hand_off(self):
        """The refill does not promise warmth. An acquire before the boot finishes is cold."""
        be = _NotYetReadyBackend()
        pool = TdPool(be, size=1)
        pool.fill()
        be.mark_ready("td-1")                               # one machine, booted
        first, ready_first = pool.acquire(("r", 0, "frag-a", "s"))
        self.assertEqual((first, ready_first), ("td-1", 0.0))
        self.assertEqual(pool.idle, 1, "td-2 was asked for at the hand-out")
        self.assertFalse(be.is_ready("td-2"), "td-2 is still booting")
        be.mark_ready("td-3")                               # the one the cold path will create
        second, ready_second = pool.acquire(("r", 1, "frag-b", "s"))
        self.assertEqual(second, "td-3")
        self.assertGreater(ready_second, 0.0, "a cold hand-off reports its boot wait")

    def test_a_binding_gets_a_td_at_most_once_but_the_same_fragment_may_recur(self):
        be = _FakeBackend()
        pool = TdPool(be, size=2)
        pool.fill()
        pool.acquire(("r", 1, "frag-a", "s"))
        with self.assertRaises(RuntimeError):
            pool.acquire(("r", 1, "frag-a", "s"))                    # same binding twice
        pool.acquire(("r", 2, "frag-a", "s"))                        # same bytes, other step: fine

    def test_cold_pool_creates_on_demand_and_reports_the_boot_wait(self):
        be = _FakeBackend()
        pool = TdPool(be, size=0)
        pool.fill()
        self.assertEqual(pool.idle, 0)
        name, ready = pool.acquire(("r", 1, "frag-a", "s"))
        self.assertIn(name, be.alive)
        self.assertGreaterEqual(ready, 0.0)

    def test_a_td_that_never_becomes_ready_is_destroyed_and_refused(self):
        class _NeverReady(_FakeBackend):
            def is_ready(self, name):
                return False

        be = _NeverReady()
        pool = TdPool(be, size=0, ready_timeout=0.0)
        with unittest.mock.patch("booking_v5.pool.time.sleep", lambda s: None), self.assertRaises(RuntimeError):
            pool.acquire(("r", 1, "frag-a", "s"))
        self.assertEqual(len(be.deleted), 1)

    def test_drain_deletes_idle_tds_and_the_pool_stays_at_size(self):
        """A warm pool stays at constant size, and `drain()` destroys what was not bound.

        The hand-out boots the replacement. At the end `drain()` destroys the idle machines, which
        makes the idle cost explicit.
        """
        be = _FakeBackend()
        pool = TdPool(be, size=2)
        pool.fill()
        self.assertEqual(pool.idle, 2)
        name, ready = pool.acquire(("r", 0, "f" * 64, "s" * 64))
        self.assertEqual((pool.idle, ready), (2, 0.0))
        pool.retire(name)
        self.assertEqual(pool.drain(), 2)
        self.assertEqual(pool.idle, 0)
        self.assertEqual(len(be.deleted), 3)
        self.assertEqual(TdPool(be, size=0).drain(), 0)

    def test_sweep_on_start_deletes_every_managed_td(self):
        be = _FakeBackend()
        TdPool(be, size=3).fill()
        TdPool(be, size=3).sweep_on_start()
        self.assertEqual(be.alive, set())


class ProfileTests(unittest.TestCase):
    """The runner pod manifest is a pure, measured function of its inputs and stays hardened."""

    def test_profile_is_a_pure_function_and_measured(self):
        m1 = build_runner_pod_manifest(image=IMG, namespace="agent-system", name="runner-1")
        m2 = build_runner_pod_manifest(image=IMG, namespace="agent-system", name="runner-2")
        self.assertEqual(manifest_without_identity(m1), manifest_without_identity(m2))
        self.assertEqual(m1["spec"]["runtimeClassName"], RUNTIME_CLASS)
        doc = gzip.decompress(base64.b64decode(m1["metadata"]["annotations"][INIT_DATA_ANNOTATION])).decode()
        self.assertEqual(m1["metadata"]["annotations"]["v5/init-data-sha256"], init_data_hash(doc))
        self.assertIn(IMG, doc)                                  # digest pin rendered into the guest policy
        self.assertNotIn("${RUNNER_IMAGE}", doc)                 # rego does not expand shell variables
        self.assertIn("default ExecProcessRequest := false", doc)
        self.assertIn("default SetPolicyRequest := false", doc)

    def test_substrate_profile_hash_is_canonical_and_names_both_boundaries(self):
        self.assertEqual(substrate_profile_hash(), substrate_profile_hash(dict(SUBSTRATE_PROFILE)))
        self.assertNotEqual(substrate_profile_hash(), substrate_profile_hash(dict(SUBSTRATE_PROFILE, podvm_subnet_cidr="10.9.9.0/24")))
        self.assertIn("runner-egress", SUBSTRATE_PROFILE["network_policies"])       # A5 (tunnel)
        self.assertIn("v5-runner-td-policy:65000-deny-egress", SUBSTRATE_PROFILE["firewall_rules"])  # A5b (direct NIC)

    def test_profile_rejects_a_mutable_tag(self):
        with self.assertRaises(Exception):
            build_runner_pod_manifest(image="reg.example.com/booking:v5", namespace="agent-system", name="x")

    def test_the_runner_container_is_hardened(self):
        c = build_runner_pod_manifest(image=IMG, namespace="agent-system", name="r")["spec"]["containers"][0]
        self.assertTrue(c["securityContext"]["readOnlyRootFilesystem"])
        self.assertEqual(c["securityContext"]["capabilities"], {"drop": ["ALL"]})


if __name__ == "__main__":
    unittest.main(verbosity=2)
