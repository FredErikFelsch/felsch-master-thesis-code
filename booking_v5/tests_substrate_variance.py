"""Tests that keep the RTMR0 tolerance of `substrate_variance` from becoming a gap.

A latency series may survive a refusal caused by the provider's RTMR0 field. That is a narrow,
opt-in exception backed by evidence, and an exception of this kind turns into a hole if it is
written loosely. Each condition therefore has a test that shows the exception does not apply when
it should not: another rule, another measurement field, a substituted kernel (RTMR1), any effect
at all, an unmeasured ledger, a missing quote, an unreadable freeze, and a quote that does not
match the refusal it claims to explain.

Two more tests show that the surrounding code widens nothing. The classifier returns no reference
value, and the tolerated run is still not accepted.

The frozen line's own recorded outlier (`results_v5/e2e/.../evidence-runner-td-*`) is used when it
is on disk, so at least one case runs on recorded hardware bytes.

Run from the repository root:  python3 -m booking_v5.tests_substrate_variance
"""
from __future__ import annotations

import base64
import pathlib
import re
import tempfile
import unittest

from . import substrate_variance as sv
from .substrate_variance import PINNED_BESIDES_RTMR0, TOLERATED_RULE, classify

MOCKS = pathlib.Path(__file__).resolve().parents[1]

# The two RTMR0 values: the frozen one and the outlier host's.
FROZEN_RTMR0 = ("c49d22aff6edb37cb6178defb05e0e2b512c26960e6ee73b1ea303365a31def8"
                "07ab2ad71e5874236feca2ca552c6307")
OTHER_RTMR0 = ("5eeb1d573d3aad53a115ac7ccce2d773ced06ff7175038843d98b2bddf786123"
               "ff54094e27878243688bae4e5bd920ce")

_REFERENCE = dict({name: f"{i + 1:02x}" * 48 for i, name in enumerate(PINNED_BESIDES_RTMR0)},
                  rtmr0=FROZEN_RTMR0)
_DETAIL = f"rtmr0 got={OTHER_RTMR0} want={FROZEN_RTMR0}"

#: The refusal that is tolerated, so each test can change one thing.
_CLEAN = dict(rule=TOLERATED_RULE, detail=_DETAIL, effects=0, pending_effects=0,
              foreign_effects=0, ledger_measured=True, stamp="test-stamp")


class _FakeQuote:
    """A quote whose fields are dictated by the test. No parsing, no hardware."""

    def __init__(self, fields: dict):
        self._fields = fields
        self.quote_bytes = b""

    def raw_field(self, name: str):
        """Return the field as bytes, or raise KeyError like the real quote."""
        if name not in self._fields:
            raise KeyError(name)
        return bytes.fromhex(self._fields[name])


class _Patched:
    """Replace the module's three impure edges (freeze on disk, quote parsing, PCK identity) for one test."""

    def __init__(self, *, reference=None, fields=None):
        self.reference, self.fields = reference, fields

    def __enter__(self):
        self._freeze, self._quote, self._pck = sv.frozen_fields, sv._quote_of, sv.pck_identity
        sv.frozen_fields = lambda stamp: self.reference
        sv._quote_of = lambda blob: _FakeQuote(self.fields or {})
        sv.pck_identity = lambda quote: ("0xdeadbeef", "00806f050000")
        self._tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        self._tmp.write(b"quote")
        self._tmp.close()
        return self._tmp.name

    def __exit__(self, *exc):
        sv.frozen_fields, sv._quote_of, sv.pck_identity = self._freeze, self._quote, self._pck
        pathlib.Path(self._tmp.name).unlink(missing_ok=True)
        return False


_UNSET = object()


def _run(*, reference=_REFERENCE, fields=None, path=_UNSET, **changes):
    """Classify one case.

    Args:
        reference: The frozen fields the patched freeze returns.
        fields: The fields of the patched quote. Defaults to a quote that matches the reference
            in everything but RTMR0.
        path: The evidence path. Defaults to a temporary file.
        **changes: Arguments of `classify` that differ from the tolerated refusal.

    Returns:
        The verdict of `classify`.
    """
    fields = fields if fields is not None else dict(_REFERENCE, rtmr0=OTHER_RTMR0)
    arguments = dict(_CLEAN, **changes)
    with _Patched(reference=reference, fields=fields) as evidence:
        return classify(arguments.pop("rule"), arguments.pop("detail"),
                        evidence if path is _UNSET else path, **arguments)


class TheToleratedCase(unittest.TestCase):
    """The one refusal that may be classified: only RTMR0 moved and nothing happened."""

    def test_only_rtmr0_moved_and_nothing_happened(self):
        verdict = _run()
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict.observed_rtmr0, OTHER_RTMR0)
        self.assertEqual(verdict.expected_rtmr0, FROZEN_RTMR0)
        self.assertEqual(verdict.pck_leaf_serial, "0xdeadbeef")

    def test_the_record_says_the_refusal_stands(self):
        """The JSON that lands in summary.json must not read like an admission."""
        record = _run().to_json()
        self.assertEqual(record["kind"], "substrate-rtmr0-variance")
        self.assertIn("refusal stands", record["note"])
        self.assertIn("no effect", record["note"])

    def test_the_classifier_returns_no_reference_value(self):
        """The classifier reports what was observed and hands nobody a value to pin."""
        verdict = _run()
        self.assertFalse(hasattr(verdict, "accept"))
        self.assertNotIn("accepted_rtmr0", verdict.to_json())


class NothingElseIsTolerated(unittest.TestCase):
    """One test per way the exception must not apply."""

    def test_another_rule_is_not_classified(self):
        for rule in ("rtmr3-mismatch", "measurement-mismatch", "nonce-reused",
                     "binding-mismatch", "substrate-profile-mismatch", None):
            with self.subTest(rule=rule):
                self.assertIsNone(_run(rule=rule))

    def test_another_boot_measurement_in_the_detail_is_not_classified(self):
        for field in ("rtmr1", "rtmr2", "mrseam", "mrtd"):
            with self.subTest(field=field):
                detail = f"{field} got={OTHER_RTMR0} want={FROZEN_RTMR0}"
                self.assertIsNone(_run(detail=detail))

    def test_a_substituted_kernel_is_not_tolerated(self):
        """RTMR1 carries the kernel. If it moved too, this is not the provider's field."""
        fields = dict(_REFERENCE, rtmr0=OTHER_RTMR0, rtmr1="ff" * 48)
        self.assertIsNone(_run(fields=fields))

    def test_every_other_pinned_field_is_compared(self):
        for name in PINNED_BESIDES_RTMR0:
            with self.subTest(field=name):
                fields = dict(_REFERENCE, rtmr0=OTHER_RTMR0, **{name: "ab" * 48})
                self.assertIsNone(_run(fields=fields))

    def test_a_missing_field_in_the_quote_is_not_a_match(self):
        fields = dict(_REFERENCE, rtmr0=OTHER_RTMR0)
        fields.pop("rtmr2")
        self.assertIsNone(_run(fields=fields))

    def test_any_effect_makes_it_a_finding(self):
        for change in ({"effects": 1}, {"pending_effects": 1}, {"foreign_effects": 1}):
            with self.subTest(**change):
                self.assertIsNone(_run(**change))

    def test_an_unmeasured_ledger_is_not_a_zero_ledger(self):
        self.assertIsNone(_run(ledger_measured=False))

    def test_without_the_quote_there_is_no_proof(self):
        self.assertIsNone(_run(path="/nonexistent/evidence.bin"))
        self.assertIsNone(_run(path=None))

    def test_an_unreadable_freeze_refuses_to_classify(self):
        self.assertIsNone(_run(reference=None))

    def test_the_quote_must_be_the_one_the_refusal_saw(self):
        """A saved blob from some other TD cannot be used to explain this refusal."""
        fields = dict(_REFERENCE, rtmr0="cc" * 48)
        self.assertIsNone(_run(fields=fields))

    def test_a_detail_naming_the_wrong_expected_value_is_not_classified(self):
        detail = f"rtmr0 got={OTHER_RTMR0} want={'dd' * 48}"
        self.assertIsNone(_run(detail=detail))

    def test_an_unparsable_detail_is_not_classified(self):
        for detail in ("", "rtmr0 mismatch", "rtmr0 got=short want=short", None):
            with self.subTest(detail=detail):
                self.assertIsNone(_run(detail=detail))


class TheRecordedOutlier(unittest.TestCase):
    """The one case that runs on recorded hardware bytes, when they are on disk."""

    def _recorded(self):
        """Return the newest refused evidence blob of the e2e runs, or None."""
        candidates = sorted((MOCKS / "results_v5" / "e2e").glob("*/evidence-runner-td-*.bin"))
        return candidates[-1] if candidates else None

    def test_the_recorded_rtmr0_outlier_classifies_and_names_another_host(self):
        blob = self._recorded()
        if blob is None:
            self.skipTest("no refused evidence recorded on this checkout")
        stamp = sv.frozen_stamp()
        reference = sv.frozen_fields(stamp) if stamp else None
        if not reference:
            self.skipTest("no readable freeze record on this checkout")
        quote = sv._quote_of(blob.read_bytes())
        observed = sv._field(quote, "rtmr0")
        if observed == reference.get("rtmr0"):
            self.skipTest("the recorded evidence is not an RTMR0 outlier")
        detail = f"rtmr0 got={observed} want={reference['rtmr0']}"
        verdict = classify(TOLERATED_RULE, detail, blob, effects=0, pending_effects=0,
                           foreign_effects=0, ledger_measured=True, stamp=stamp)
        self.assertIsNotNone(verdict, "the recorded outlier must classify")
        # Every other pinned field is byte-equal on the recorded bytes.
        for name in PINNED_BESIDES_RTMR0:
            self.assertEqual(sv._field(quote, name), reference[name], name)
        # The PCK leaf, issued per physical package, is a different one.
        serial, fmspc = sv.pck_identity(quote)
        frozen_blob = MOCKS / "results_v5" / "freeze-candidate" / f"evidence-{stamp}.log"
        if serial and frozen_blob.exists():
            b64 = re.search(r"^EVIDENCE_B64 (\S+)", frozen_blob.read_text(), re.M)
            if b64:
                frozen_quote = sv._quote_of(base64.b64decode(b64.group(1)))
                frozen_serial, frozen_fmspc = sv.pck_identity(frozen_quote)
                self.assertNotEqual(serial, frozen_serial, "another host means another PCK leaf")
                self.assertEqual(fmspc, frozen_fmspc, "same platform generation, other package")


class TheHarnessDoesNotAdmitAnything(unittest.TestCase):
    """The tolerance lives in the measurement harness and changes no decision."""

    def test_the_relying_party_knows_nothing_about_this_module(self):
        source = (MOCKS / "booking_v5" / "relying_party.py").read_text()
        for name in ("substrate_variance", "SubstrateVariance", "tolerate_substrate",
                     "TOLERATE_SUBSTRATE"):
            self.assertNotIn(name, source, name)

    def test_the_freeze_record_knows_nothing_about_this_module(self):
        source = (MOCKS / "booking_v5" / "freeze_record.py").read_text()
        self.assertNotIn("substrate_variance", source)

    def test_a_tolerated_run_is_still_not_accepted(self):
        """In e2e_live the run keeps accepted=False. Only the verdict of the series survives."""
        source = (MOCKS / "booking_v5" / "e2e_live.py").read_text()
        self.assertIn('"accepted": ok', source)
        self.assertIn("all_ok = all_ok and (ok or variance is not None)", source)
        self.assertNotIn("rec.accepted = True", source)

    def test_the_flag_is_opt_in_and_only_for_a_series(self):
        source = (MOCKS / "booking_v5" / "e2e_live.py").read_text()
        self.assertIn('getattr(args, "tolerate_substrate_variance", False)) and repeat > 1', source)

    def test_the_security_steps_do_not_set_the_flag(self):
        """The negative, A19 and expiry scripts do not pass the flag, and the fragment script only on request."""
        scripts = MOCKS / "scripts" / "gke-v5"
        for name in ("32_negative_v5.sh", "41_probe_a19.sh", "34_expiry_v5.sh"):
            path = scripts / name
            if path.exists():
                self.assertNotIn("TOLERATE_SUBSTRATE_VARIANCE", path.read_text(), name)
        thirty_one = (scripts / "31_run_fragment_v5.sh").read_text()
        self.assertIn('[ "${TOLERATE_SUBSTRATE_VARIANCE:-0}" = "1" ]', thirty_one,
                      "31_run_fragment_v5.sh must default to off")

    def test_the_summary_separates_the_counts(self):
        source = (MOCKS / "booking_v5" / "e2e_live.py").read_text()
        for key in ('"accepted_runs"', '"refused_runs"', '"substrate_variance_runs"',
                    '"substrate_variance"'):
            self.assertIn(key, source, key)


if __name__ == "__main__":
    unittest.main(verbosity=2)
