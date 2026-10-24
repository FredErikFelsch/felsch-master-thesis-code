"""The V5 verification path against recorded TDX evidence, without a cluster.

The main fixture is the frozen run in `results_v5/freeze-candidate/`. Its freeze record is the
reference the Authority reads, its evidence log carries the quote over the canonical binding and
the pre-event quote, its binding file the recorded nonce, run, step and hashes, and its DCAP
report the Intel QVL verdict for that quote. The appraisal pin and the RTMR3 replay therefore test
the same bytes. The secondary line under `results_v5/freeze-ov7-20260905T064641Z/` has the same
MRTD and RTMR0 and other RTMR1 and RTMR2 (another image), so it is the DCAP-verified fixture of
another pod-VM measurement. The pre-overlay runs in `results_v5/probe/` serve where a test needs a
TD with a different RTMR3 history.

The two layers are tested separately, because a signed quote with a changed byte is refused at
the appraisal and does not reach a reference or binding check:

    appraiser layer      raw quote -> QVL / RecordedAppraisal -> VerifiedClaims
                         codes: quote-malformed, reportdata-mismatch, no-appraiser,
                                tcb-rejected, collateral-unavailable, verifier-error
    relying-party layer  VerifiedClaims (qv_result OK, recorded bytes) -> reference, RTMR3,
                         binding, nonce, ledger, scope
                         codes: measurement-mismatch, boot-measurement-mismatch, platform-mismatch,
                                rtmr3-mismatch, rtmr3-missing, binding-mismatch, nonce-unknown,
                                nonce-reused, nonce-td-mismatch, nonce-step-mismatch,
                                td-already-bound, substrate-profile-mismatch, evidence-missing,
                                credential scope

Most relying-party tests replace one verified claim. The freshness, substrate and evidence tests
change the call instead.

These tests cannot re-verify a signature chain on this machine, because Intel's library runs on
x86_64 Linux only. `RecordedAppraisal` accepts only the quote bytes Intel's library verified when
the DCAP record was taken, pinned by SHA-256. Everything downstream runs on the recorded bytes.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import pathlib
import re
import tempfile
import unittest

from .binding import BINDING_V50, BINDING_V51, RunnerIdentity, canonical_binding
from .evidence import Evidence, RecordedEvidence
from .freeze_record import verify_freeze
from .profile_v5 import SUBSTRATE_PROFILE, substrate_profile_hash
from .relying_party import AuthorityRelyingParty, ReferenceValues, Refusal, Session
from .rtmr_replay import expected_history, expected_rtmr3, replay
from .tdx_quote import parse_aa_evidence, parse_quote
from .verifier import (AppraisalRejected, CollateralUnavailable, RecordedAppraisal, TdxVerifier,
                       UnappraisedForTesting, VerificationFailed)

# Archived lines (the secondary line, the pre-overlay image, the first runner image of the primary
# line) predate the verdict key. Those TDs attested under the v5.0 binding, which carries no
# pk_sig. `_binding` falls back to this constant only when the evidence log prints no PK_SIG. A
# current line that lost its verdict key is then read as v5.0 and fails the binding check,
# because the hardware bound a pk_sig.
PRE_H2_PK_SIG = b""

MOCKS = pathlib.Path(__file__).resolve().parents[1]
FREEZE = MOCKS / "results_v5" / "freeze-candidate"
PROBE = MOCKS / "results_v5" / "probe"
STAMP = "20261016T100620Z"           # the frozen run (pinned by pin_freeze.py)
PREV_STAMP = "20261003T073223Z"      # secondary line: the previous freeze
OV9_FIRST_STAMP = "20260905T145032Z"  # same pod-VM line, runner image before the final rebuild
FREEZE_OV7 = MOCKS / "results_v5" / "freeze-ov7-20260905T064641Z"
OV7_STAMP = "20260905T064641Z"  # secondary line: same MRTD/RTMR0, other RTMR1/2
OLD_STAMP = "20260903T170805Z"       # pre-overlay image: RTMR3 extended once, other RTMR1/2

#: The public copy of the recorded data has the cloud project id replaced by a placeholder. The
#: freeze pins digests over the original bytes, so tests that re-derive those digests cannot hold
#: on the copy. They are skipped there and run against the measured data.
SANITISED_FREEZE = any("project-example" in p.read_text(encoding="utf-8")
                       for p in FREEZE.glob("runner-*.yaml"))
needs_measured_freeze = unittest.skipIf(
    SANITISED_FREEZE, "recorded data is the sanitised copy, pinned digests hold for the measured bytes")


def _probe_reference(stamp: str = STAMP, where: pathlib.Path = FREEZE) -> ReferenceValues:
    """Return the reference a recorded quote is judged against.

    A freeze pins the init-data digest of the run profile, the document every production runner is
    launched with. The quote recorded in the freeze is the probe pod's, and it was measured under
    the probe digest, which the freeze keeps as `probe_init_data`. Replayed against the run digest
    that quote would always mismatch, so the tests of the recorded evidence take the probe digest.
    A freeze without the field names one digest only, the quote's.

    Args:
        stamp: The freeze stamp.
        where: The directory that holds the freeze.

    Returns:
        The reference values with the probe digest, where the freeze records one.
    """
    path = where / f"freeze-{stamp}.json"
    ref = ReferenceValues.from_freeze(path)
    probe = json.loads(path.read_text(encoding="utf-8")).get("probe_init_data")
    if probe:
        ref = dataclasses.replace(ref, init_data_digest=probe["digest"], init_data_profile="probe")
    return ref


def _recorded(where: pathlib.Path, stamp: str, marker: str = "EVIDENCE_B64") -> Evidence:
    """Return the evidence recorded under `marker` in the evidence log of `stamp`."""
    return RecordedEvidence.from_probe(where, stamp, marker).get_evidence(b"")


def _binding(stamp: str = STAMP) -> dict:
    """Return the recorded binding fields plus the keys and the protocol version of that line.

    `pk_sig` and `version` come from the evidence log the runner itself wrote. A v5.1 line prints
    PK_SIG next to PK_BOOT, a v5.0 line prints only PK_BOOT. A freeze whose runner stopped
    publishing its verdict key therefore reads back as v5.0 here and fails every binding
    assertion, which is the intended alarm.
    """
    b = json.loads((FREEZE / f"binding-{stamp}.json").read_text())
    log = (FREEZE / f"evidence-{stamp}.log").read_text()
    b["pk_boot"] = bytes.fromhex(re.search(r"^PK_BOOT ([0-9a-f]{64})", log, re.M).group(1))
    sig = re.search(r"^PK_SIG ([0-9a-f]{64})", log, re.M)
    b["pk_sig"] = bytes.fromhex(sig.group(1)) if sig else PRE_H2_PK_SIG
    b["version"] = BINDING_V51 if sig else BINDING_V50
    b["nonce"] = bytes.fromhex(b["nonce"])
    return b


def _appraisal(stamp: str = STAMP) -> RecordedAppraisal:
    """Return the appraisal pinned to the quote Intel's library verified for `stamp`."""
    ev = _recorded(FREEZE, stamp)
    quote = parse_quote(parse_aa_evidence(ev.blob)[0])
    return RecordedAppraisal.from_dcap_report((FREEZE / f"dcap-{stamp}.txt").read_text(), quote.quote_bytes)


class _MutatedClaims:
    """Relying-party layer harness that verifies the recorded bytes and then replaces claims.

    The recorded bytes are verified with the genuine appraisal pin, and the verified claims named
    in `changes` are replaced afterwards. A test reaches a reference, binding or ledger check this
    way with evidence whose appraisal is genuine, which a changed quote would not pass.
    """

    def __init__(self, inner, **changes):
        self.inner, self.changes = inner, changes

    def verify(self, evidence):
        return dataclasses.replace(self.inner.verify(evidence), **self.changes)


def _rewrap(original_blob: bytes, new_quote: bytes) -> bytes:
    """Put modified quote bytes back into the Attestation Agent's evidence JSON."""
    d = json.loads(original_blob)
    d["quote"] = base64.b64encode(new_quote).decode()
    return json.dumps(d).encode()


# The freeze itself.

class FreezeTests(unittest.TestCase):
    """The recorded freeze is intact and is read as pinned."""

    @needs_measured_freeze
    def test_the_freeze_is_intact(self):
        """The TXT file is the rendering of the JSON, and every named artefact still has its hash."""
        self.assertEqual([], verify_freeze(FREEZE, STAMP))

    @needs_measured_freeze
    def test_the_secondary_ov7_line_is_intact_and_differs_only_where_the_image_does(self):
        """The secondary freeze stays verifiable on its own.

        Against the primary line only the image-dependent fields moved: RTMR1 and RTMR2 (kernel,
        verity root hash) and RTMR3 (init-data).
        """
        self.assertEqual([], verify_freeze(FREEZE_OV7, OV7_STAMP))
        a = json.loads((FREEZE_OV7 / f"reference-values-{OV7_STAMP}.json").read_text())["quote"]["fields"]
        b = json.loads((FREEZE / f"reference-values-{STAMP}.json").read_text())["quote"]["fields"]
        same = ("mrtd", "rtmr0", "mrseam", "tee_tcb_svn", "xfam", "tdattributes")
        self.assertEqual({k: a[k] for k in same}, {k: b[k] for k in same})
        self.assertNotEqual((a["rtmr1"], a["rtmr2"]), (b["rtmr1"], b["rtmr2"]))

    def test_from_freeze_reads_the_pinned_fields(self):
        ref = ReferenceValues.from_freeze(FREEZE / f"freeze-{STAMP}.json")
        self.assertEqual(len(ref.measurement), 96)
        self.assertEqual(set(ref.boot_measurements),
                         {"rtmr0", "rtmr1", "rtmr2", "mrseam", "tee_tcb_svn", "xfam", "tdattributes"})
        self.assertTrue(ref.require_rtmr3)
        # The init-data digest of the frozen run, pinned by value. It moves whenever the runner
        # image is rebuilt, because the image digest enters the generated guest policy and the
        # policy enters the init-data. Everything else in the measurement stays put, since the
        # pod-VM image is unchanged.
        self.assertEqual(ref.init_data_digest, "e04cc56d988d1bbae57287e88f489223d3ed5714689314951155810f3815b512")  # 20261016T100620Z (prev e5cbe152…)
        self.assertEqual(ref.substrate_profile_hash, substrate_profile_hash(SUBSTRATE_PROFILE),
                         "the frozen substrate hash must be the one this code computes for the profile")

    def test_from_freeze_refuses_the_raw_reference_values_file(self):
        """The freeze is the one machine-readable source. The raw reference-values file is not a freeze."""
        with self.assertRaises(ValueError):
            ReferenceValues.from_freeze(FREEZE / f"reference-values-{STAMP}.json")

    def test_from_reference_values_follows_the_recorded_init_data_algorithm(self):
        """The raw-file constructor takes the digest of the TOML's own `algorithm`.

        sha384 is the CoCo default. A file that lacks the digest for that algorithm is refused.
        """
        data = json.loads((FREEZE / f"reference-values-{STAMP}.json").read_text())
        data["init_data"]["algorithm"] = "sha384"
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(data, f)
        ref = ReferenceValues.from_reference_values(f.name, "sub")
        self.assertEqual(ref.init_data_digest, data["init_data"]["sha384(toml)"])
        del data["init_data"]["sha384(toml)"]
        with open(f.name, "w") as g:
            json.dump(data, g)
        with self.assertRaises(KeyError):
            ReferenceValues.from_reference_values(f.name, "sub")


# Appraiser layer.

class AppraiserLayerTests(unittest.TestCase):
    """The path from raw quote through `RecordedAppraisal` to `VerifiedClaims`, and each failure code."""

    def setUp(self):
        self.evidence = _recorded(FREEZE, STAMP)
        self.quote = parse_quote(parse_aa_evidence(self.evidence.blob)[0])
        self.appraisal = _appraisal()

    def test_the_frozen_quote_verifies_and_carries_the_binding_and_a_runtime_measurement(self):
        claims = TdxVerifier(self.appraisal).verify(self.evidence)
        self.assertEqual(claims.platform, "tdx")
        self.assertEqual(claims.measurement, self.quote.fields["mrtd"])
        self.assertEqual(self.quote.reportdata, claims.runtime_data.hex().encode())
        self.assertEqual(claims.appraisal["qv_result"], "OK")
        self.assertEqual(claims.appraisal["fmspc"], "00806f050000")
        self.assertIsNone(claims.init_data_hash)  # MRCONFIGID is zero on GCE
        self.assertIsNotNone(claims.rtmr3)  # the overlay ran
        self.assertNotIn("mrowner", claims.boot_measurements)    # per instance, so not pinned

    def _code(self, verifier, evidence) -> str:
        with self.assertRaises(VerificationFailed) as ctx:
            verifier.verify(evidence)
        return ctx.exception.code

    def test_a_flipped_byte_is_a_quote_nobody_verified(self):
        raw = bytearray(self.quote.quote_bytes)
        raw[184] ^= 0x01                                                     # first byte of MRTD
        broken = Evidence("tdx", _rewrap(self.evidence.blob, bytes(raw)), self.evidence.runtime_data)
        self.assertEqual(self._code(TdxVerifier(self.appraisal), broken), "verifier-error")

    def test_evidence_for_another_runtime_data_is_a_reportdata_mismatch(self):
        wrong = Evidence("tdx", self.evidence.blob, bytes(32))
        self.assertEqual(self._code(TdxVerifier(self.appraisal), wrong), "reportdata-mismatch")

    def test_no_appraiser_means_no_verification(self):
        self.assertEqual(self._code(TdxVerifier(), self.evidence), "no-appraiser")

    def test_padding_behind_the_signature_must_be_zero(self):
        buf, _ = parse_aa_evidence(self.evidence.blob)                 # quote + padding
        tampered = bytearray(buf)
        tampered[self.quote.quote_len + 10] = 0x41
        broken = Evidence("tdx", _rewrap(self.evidence.blob, bytes(tampered)), self.evidence.runtime_data)
        self.assertEqual(self._code(TdxVerifier(UnappraisedForTesting(i_know=True)), broken), "quote-malformed")

    def test_a_rejected_tcb_is_tcb_rejected(self):
        """The QVL ran and said no (out-of-date TCB, revoked key), which is a statement about the TD."""
        rejected = RecordedAppraisal({k: dict(v, qv_result="TCB_OUT_OF_DATE") for k, v in self.appraisal.verdicts.items()})
        self.assertEqual(self._code(TdxVerifier(rejected), self.evidence), "tcb-rejected")

    def test_unreachable_collateral_is_collateral_unavailable(self):
        """PCS down or collateral expired is a fault of the verifier's environment, and it still fails closed."""
        def pcs_down(quote_bytes, reportdata):
            raise CollateralUnavailable("PCS unreachable")

        self.assertEqual(self._code(TdxVerifier(pcs_down), self.evidence), "collateral-unavailable")

        class ConnectionError(Exception):                                     # requests' class name
            pass

        def requests_down(quote_bytes, reportdata):
            raise ConnectionError("api.trustedservices.intel.com: connection refused")
        self.assertEqual(self._code(TdxVerifier(requests_down), self.evidence), "collateral-unavailable")

    def test_a_crashing_library_is_verifier_error(self):
        def crash(quote_bytes, reportdata):
            raise RuntimeError("tdx_qv_verify_quote failed: quote3_error_t=0xe002")


        self.assertEqual(self._code(TdxVerifier(crash), self.evidence), "verifier-error")

    def test_the_relying_party_reports_the_verifier_code_as_the_rule(self):
        """Every appraiser-layer failure surfaces as a refusal whose rule is the code.

        Its stage is 'verifier', so the run record separates these refusals from policy refusals.
        """
        b = _binding()
        for appraiser, code in (
                (lambda q, r: (_ for _ in ()).throw(AppraisalRejected("x")), "tcb-rejected"),
                (lambda q, r: (_ for _ in ()).throw(CollateralUnavailable("x")), "collateral-unavailable"),
                (lambda q, r: (_ for _ in ()).throw(RuntimeError("x")), "verifier-error")):
            rp = AuthorityRelyingParty(TdxVerifier(appraiser), _probe_reference())
            rp._nonces[b["nonce"]] = (b["run"], b["step"], b["fragment_hash"], b["state_hash"],
                                      b["pk_boot"], False)
            res = rp.establish_session(self.evidence, b["pk_boot"], b["pk_sig"], b["run"], b["step"],
                                       b["fragment_hash"],
                                       b["state_hash"], b["nonce"], lambda s: b"c", substrate_profile_hash())
            self.assertIsInstance(res, Refusal)
            self.assertEqual((res.rule, res.stage), (code, "verifier"))


# Relying-party layer.

class RelyingPartyLayerTests(unittest.TestCase):
    """The Authority's decision on the verified claims of the frozen quote, with the genuine appraisal pin.

    The positive case comes first, then one refusal per changed claim or changed call.
    """

    def setUp(self):
        self.evidence = _recorded(FREEZE, STAMP)
        self.quote = parse_quote(parse_aa_evidence(self.evidence.blob)[0])
        self.b = _binding()
        self.ref = _probe_reference()
        self.verifier = TdxVerifier(_appraisal())

    def _rp(self, verifier=None, ref=None) -> AuthorityRelyingParty:
        rp = AuthorityRelyingParty(verifier or self.verifier, ref or self.ref)
        self._admit(rp, self.b["nonce"], self.b["step"])
        return rp

    def _admit(self, rp, nonce: bytes, step: int) -> bytes:
        """Admit a nonce to the ledger as if this Authority had issued it for `step`.

        The recorded nonce was drawn by `scripts/gke-v5/18_probe_peer_pod.sh` without an Authority.

        Returns:
            The admitted nonce.
        """
        # The recorded challenge belongs to the recorded TD: a nonce is bound to the boot key that
        # asked for it, not only to the step.
        rp._nonces[nonce] = (self.b["run"], step, self.b["fragment_hash"], self.b["state_hash"],
                             self.b["pk_boot"], False)
        return nonce

    def _establish(self, rp, *, evidence="frozen", pk_boot=None, step=None, nonce=None, substrate=None):
        b = self.b
        return rp.establish_session(self.evidence if evidence == "frozen" else evidence,
                                    pk_boot or b["pk_boot"], b["pk_sig"], b["run"], step or b["step"],
                                    b["fragment_hash"], b["state_hash"], nonce or b["nonce"],
                                    lambda scope: f"cred:{scope.run_id}:{scope.step}".encode(),
                                    substrate or substrate_profile_hash())

    # The positive fixture: the evidence the chain must accept.

    def test_reportdata_is_the_canonical_binding_over_pk_boot(self):
        """The hardware bound H(V5-BIND, version, nonce, run, step, f, s, pk_boot, pk_sig).

        This is checked before any session logic. Both keys are the ones the runner printed and
        recorded as its first AAEL event. The verdict key is part of the binding, so a TD that
        swapped it cannot present this reportdata.
        """
        b = self.b
        want = canonical_binding(b["nonce"], b["run"], b["step"], b["fragment_hash"], b["state_hash"],
                                 b["pk_boot"], b["pk_sig"], b["version"])
        self.assertEqual(self.quote.reportdata, want.hex().encode())

    def test_the_recorded_quote_carries_the_probe_digest_not_the_run_digest(self):
        """Judged against the run digest, the recorded probe quote is refused.

        The freeze pins the run digest for production runners, and the recorded quote is the probe
        pod's, so the refusal shows the pin at work.
        """
        path = FREEZE / f"freeze-{STAMP}.json"
        freeze = json.loads(path.read_text(encoding="utf-8"))
        if not freeze.get("probe_init_data"):
            self.skipTest("a freeze without probe_init_data names the quote's own digest")
        run_ref = ReferenceValues.from_freeze(path)
        self.assertEqual(run_ref.init_data_profile, "run")
        self.assertNotEqual(run_ref.init_data_digest, self.ref.init_data_digest)
        res = self._establish(self._rp(ref=run_ref))
        self.assertIsInstance(res, Refusal)
        self.assertEqual(res.rule, "rtmr3-mismatch")

    def test_the_frozen_td_carries_the_full_rtmr3_history(self):
        """RTMR3 is the replay of [init-data, boot-key, bind] with the frozen init-data digest.

        A TD booted under another policy cannot reach this value.
        """
        b = self.b
        claims = self.verifier.verify(self.evidence)
        self.assertEqual(claims.rtmr3, expected_rtmr3(self.ref.init_data_digest, b["pk_boot"].hex(),
                                                      b["pk_sig"].hex(), b["run"], b["step"],
                                                      b["fragment_hash"], b["state_hash"],
                                                      b["version"].decode()))
        # The pre-event quote of the same TD shows the init-data event alone.
        pre = _recorded(FREEZE, STAMP, marker="EVIDENCE_PRE_B64")
        pre_quote = parse_quote(parse_aa_evidence(pre.blob)[0])
        self.assertEqual(pre_quote.raw_field("rtmr3"),
                         replay(expected_history(self.ref.init_data_digest, b["pk_boot"].hex(),
                                                 b["pk_sig"].hex(), b["run"], b["step"],
                                                 b["fragment_hash"], b["state_hash"],
                                                 b["version"].decode())[:1]))

    def test_the_frozen_evidence_establishes_a_session(self):
        """The main fixture: genuine appraisal, frozen reference and recorded binding give a Session.

        The session is sealed to pk_boot and its credential redeems one effect for this (run, step).
        """
        rp = self._rp()
        res = self._establish(rp)
        self.assertIsInstance(res, Session, getattr(res, "rule", None))
        self.assertEqual(res.scope.pk_boot, self.b["pk_boot"])
        self.assertEqual(res.credential, f"cred:{self.b['run']}:{self.b['step']}".encode())
        self.assertIn("ct", res.sealed)                                   # sealed, not plaintext
        self.assertEqual(rp.refusals, [])                                 # accepted without a detour
        grant = rp.redeem(res.credential, self.b["run"], self.b["step"], "e" * 64)
        self.assertEqual((grant.run_id, grant.step, grant.fragment_hash), (self.b["run"], self.b["step"], self.b["fragment_hash"]))
        self.assertEqual(rp.redeem(res.credential, self.b["run"], self.b["step"], "d" * 64).rule, "credential-already-redeemed")
        self.assertEqual(rp.redeem(res.credential, self.b["run"], self.b["step"] + 1, "e" * 64).rule, "no-session-for-step")

    # One changed claim or call per refusal.

    def _refusal(self, **claim_changes) -> Refusal:
        rp = self._rp(verifier=_MutatedClaims(self.verifier, **claim_changes))
        res = self._establish(rp)
        self.assertIsInstance(res, Refusal, "expected a refusal")
        self.assertEqual(res.stage, "relying-party")
        return res

    def test_another_mrtd_is_measurement_mismatch(self):
        self.assertEqual(self._refusal(measurement="0" * 96).rule, "measurement-mismatch")

    def test_another_boot_measurement_is_boot_measurement_mismatch(self):
        claims = self.verifier.verify(self.evidence)
        other = dict(claims.boot_measurements, rtmr1="1" * 96)
        res = self._refusal(boot_measurements=other)
        self.assertEqual(res.rule, "boot-measurement-mismatch")
        self.assertTrue(res.detail.startswith("rtmr1 got="))

    def test_another_platform_is_platform_mismatch(self):
        self.assertEqual(self._refusal(platform="sev-snp").rule, "platform-mismatch")     # A13

    def test_rtmr3_without_the_init_data_event_is_rtmr3_mismatch_and_says_so(self):
        """A TD whose overlay did not measure the init-data is refused, and the refusal says so."""
        b = self.b
        without = replay(expected_history(self.ref.init_data_digest, b["pk_boot"].hex(),
                                          b["pk_sig"].hex(), b["run"], b["step"], b["fragment_hash"],
                                          b["state_hash"], b["version"].decode())[1:])
        res = self._refusal(rtmr3=without)
        self.assertEqual(res.rule, "rtmr3-mismatch")
        self.assertIn("init-data NOT measured", res.detail)

    def test_a_td_measured_under_another_init_data_is_rtmr3_mismatch(self):
        """Acceptance test A12: with the Authority pinned to another policy, the first event differs."""
        other_ref = dataclasses.replace(self.ref, init_data_digest="ab" * 32)
        rp = self._rp(ref=other_ref)
        res = self._establish(rp)
        self.assertEqual(res.rule, "rtmr3-mismatch")
        self.assertIn("foreign init-data digest", res.detail)

    def test_a_missing_runtime_measurement_is_refused_when_required(self):
        self.assertEqual(self._refusal(rtmr3=None).rule, "rtmr3-missing")

    def test_another_reportdata_is_binding_mismatch(self):
        self.assertEqual(self._refusal(runtime_data=bytes(32)).rule, "binding-mismatch")

    def test_evidence_for_another_boot_key_is_refused_twice_over(self):
        """Acceptance test A10: the transport claims a key the hardware did not bind.

        Two independent checks catch it. A challenge is bound to the boot key that asked for it,
        so a key the Authority did not issue this nonce for is refused at the nonce, before any
        evidence is weighed. The substituted key presented with a challenge issued for it still
        fails at the canonical binding, because that is what the hardware signed. The design rests
        on the second check. The first is the cheaper fence in front of it.
        """
        other = RunnerIdentity.create().pk_boot
        rp = self._rp()
        self.assertEqual(self._establish(rp, pk_boot=other).rule, "nonce-td-mismatch")

        rp2 = self._rp()
        nonce = self._admit(rp2, b"\x0b" * 32, self.b["step"])
        rp2._nonces[nonce] = rp2._nonces[nonce][:4] + (other, False)   # challenge for the other key
        self.assertEqual(self._establish(rp2, pk_boot=other, nonce=nonce).rule, "binding-mismatch")

    def test_no_evidence_is_evidence_missing(self):
        """Acceptance test A14: the controller's own credentials buy nothing."""
        rp = self._rp()
        self.assertEqual(self._establish(rp, evidence=None).rule, "evidence-missing")

    def test_an_unknown_nonce_is_nonce_unknown(self):
        rp = AuthorityRelyingParty(self.verifier, self.ref)                  # nothing admitted
        self.assertEqual(self._establish(rp).rule, "nonce-unknown")

    def test_a_replayed_quote_is_nonce_reused_and_a_refusal_burns_the_nonce(self):
        """Acceptance tests A11 and A12 at the freshness gate.

        The same evidence offered again is refused as `nonce-reused`, whatever the first attempt's
        outcome.
        """
        rp = self._rp()
        self.assertIsInstance(self._establish(rp), Session)
        self.assertEqual(self._establish(rp).rule, "nonce-reused")
        rp2 = self._rp(verifier=_MutatedClaims(self.verifier, measurement="0" * 96))
        self.assertEqual(self._establish(rp2).rule, "measurement-mismatch")
        self.assertEqual(self._establish(rp2).rule, "nonce-reused")

    def test_a_nonce_issued_for_another_step_is_nonce_step_mismatch(self):
        rp = AuthorityRelyingParty(self.verifier, self.ref)
        self._admit(rp, self.b["nonce"], self.b["step"] + 1)
        self.assertEqual(self._establish(rp).rule, "nonce-step-mismatch")

    def test_a_bound_td_cannot_be_bound_to_a_second_fragment(self):
        """Acceptance test A11 at the ledger: one TD binds one fragment.

        The same boot key presents evidence for the next step whose binding and RTMR3 would be
        correct for that step (the claims are changed accordingly). The TD identity is already
        bound to the recorded step, so the refusal is `td-already-bound`.
        """
        b = self.b
        rp = self._rp()
        self.assertIsInstance(self._establish(rp), Session)
        nonce2 = self._admit(rp, b"\x07" * 32, b["step"] + 1)
        rd2 = canonical_binding(nonce2, b["run"], b["step"] + 1, b["fragment_hash"], b["state_hash"],
                                b["pk_boot"], b["pk_sig"], b["version"])
        r3 = expected_rtmr3(self.ref.init_data_digest, b["pk_boot"].hex(), b["pk_sig"].hex(), b["run"],
                            b["step"] + 1, b["fragment_hash"], b["state_hash"], b["version"].decode())
        rp.verifier = _MutatedClaims(self.verifier, runtime_data=rd2, rtmr3=r3)
        res = self._establish(rp, step=b["step"] + 1, nonce=nonce2)
        self.assertEqual(res.rule, "td-already-bound")

    def test_a_foreign_substrate_is_refused(self):
        rp = self._rp()
        self.assertEqual(self._establish(rp, substrate="0" * 64).rule, "substrate-profile-mismatch")

    def test_a_dcap_verified_td_of_the_previous_image_is_refused_on_rtmr1(self):
        """Acceptance test A12 with a quote of the secondary line, refused on RTMR1.

        The TD has the same MRTD and RTMR0 as the primary reference and is refused on the first
        boot measurement that differs. The quote was DCAP-verified when it was recorded. Here the
        appraisal is skipped, because the test is about the reference pin.
        """
        ov7 = _recorded(FREEZE_OV7, OV7_STAMP)
        rp = AuthorityRelyingParty(TdxVerifier(UnappraisedForTesting(i_know=True)), self.ref)
        n = rp.issue_nonce("run-x", 1, "f" * 64, "s" * 64, bytes(32))
        res = rp.establish_session(ov7, bytes(32), bytes(32), "run-x", 1, "f" * 64, "s" * 64, n,
                                   lambda s: b"c", substrate_profile_hash())
        self.assertEqual(res.rule, "boot-measurement-mismatch")
        self.assertTrue(res.detail.startswith("rtmr1 got="))

    def test_a_td_from_the_pre_overlay_image_is_refused_on_its_boot_measurements(self):
        """Acceptance test A12 with another pod-VM measurement, the pre-overlay TD.

        The TD has the same MRTD, other RTMR1 and RTMR2, and an RTMR3 the probe extended once. Its
        quote has no DCAP record in the freeze, so the appraisal is skipped, because the test is
        about the reference pin.
        """
        old = _recorded(PROBE, OLD_STAMP)
        rp = AuthorityRelyingParty(TdxVerifier(UnappraisedForTesting(i_know=True)), self.ref)
        n = rp.issue_nonce("run-x", 1, "f" * 64, "s" * 64, bytes(32))
        res = rp.establish_session(old, bytes(32), bytes(32), "run-x", 1, "f" * 64, "s" * 64, n,
                                   lambda s: b"c", substrate_profile_hash())
        self.assertEqual(res.rule, "boot-measurement-mismatch")
        self.assertTrue(res.detail.startswith("rtmr1 got="))


# The offline end-to-end run (controller, Authority, gateway, runner, one committed effect) is in
# tests_v5_service.py. It runs over the role-bound services and the frozen V3 monitor. This file
# keeps to the hardware evidence.


if __name__ == "__main__":
    unittest.main(verbosity=2)
