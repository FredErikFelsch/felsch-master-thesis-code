"""The freeze names both init-data digests, and the Authority cross-checks the run digest.

Run:
    python3 -m booking_v5.tests_freeze_digests

The probe pod and the run pods are measured under different init-data (their own policy and
pod name), so a freeze that records only the probe digest would pin the wrong value for the
runs. A record built with a runner image carries `init_data.profile == "run"`, renders the run
document into the freeze directory and has `verify` re-derive the digest from it. A deployment
that does not reproduce that digest is refused at seeding and at start.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import pathlib
import shutil
import tempfile
import unittest

from .freeze_record import build_freeze, main as freeze_main, render_freeze_txt, run_document_name, verify_freeze
from .profile_v5 import init_data_document, init_data_hash
from .relying_party import ReferenceValues
from .report_v5 import render_t5
from .service_v5 import _require_deployment_matches_freeze, deployment_init_data_digest

MOCKS = pathlib.Path(__file__).resolve().parents[1]
CAND = MOCKS / "results_v5" / "freeze-candidate"
STAMP = "20260930T155610Z"
RUNNER_IMAGE = ("europe-west1-docker.pkg.dev/project-example/thesis/booking"
                "@sha256:8864e0692a5fbe73135bc255d26a61d638aced26950210338a4bb581b3986a34")
PROBE_DIGEST = json.loads((CAND / f"reference-values-{STAMP}.json").read_text())["init_data"]["sha256(toml)"] if (CAND / f"reference-values-{STAMP}.json").exists() else ""


class TheRunDigestIsTheHashOfTheRenderedRunDocument(unittest.TestCase):
    """The run digest is the hash of the rendered run document.

    Reproducing digests recorded in an older freeze needs the init-data templates as they were
    then, so those digests are evidence kept with the recorded results and not a regression test.
    """

    def test_the_run_digest_is_the_hash_of_the_rendered_run_document(self):
        self.assertEqual(deployment_init_data_digest(RUNNER_IMAGE),
                         init_data_hash(init_data_document(RUNNER_IMAGE)))

    def test_a_probe_policy_gives_another_digest_than_the_run_policy(self):
        probe = init_data_hash(init_data_document(RUNNER_IMAGE, "package agent_policy\n# a probe policy\n"))
        self.assertNotEqual(probe, deployment_init_data_digest(RUNNER_IMAGE))


class _Dir(unittest.TestCase):
    """A scratch freeze directory with the recorded step artefacts of the primary line."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="freeze-digests-"))
        names = (f"reference-values-{STAMP}.json", f"dcap-{STAMP}.txt", f"substrate-40-{STAMP}.txt")
        if not all((CAND / n).exists() for n in names):
            self.skipTest("recorded artefacts not present")
        for n in names:
            shutil.copy(CAND / n, self.dir / n)

    def build(self, **kw):
        """Build the freeze record and its text rendering into the scratch directory."""
        freeze = build_freeze(self.dir, STAMP, **kw)
        (self.dir / f"freeze-{STAMP}.json").write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n")
        (self.dir / f"FREEZE-{STAMP}.txt").write_text(render_freeze_txt(freeze))
        return freeze


class TheRecordNamesBothAndVerifyDerivesThem(_Dir):
    """The record carries run and probe digests and `verify` re-derives each of them."""

    def test_a_run_record_carries_run_and_probe_and_verifies(self):
        f = self.build(runner_image=RUNNER_IMAGE)
        self.assertEqual(f["init_data"]["profile"], "run")
        self.assertEqual(f["init_data"]["digest"], deployment_init_data_digest(RUNNER_IMAGE))
        self.assertEqual(f["probe_init_data"]["digest"], PROBE_DIGEST)
        self.assertEqual(verify_freeze(self.dir, STAMP), [])
        self.assertIn("init_data_profile=run", (self.dir / f"FREEZE-{STAMP}.txt").read_text())

    def test_without_a_runner_image_the_record_says_probe(self):
        f = self.build()
        self.assertEqual(f["init_data"]["profile"], "probe")
        self.assertNotIn("probe_init_data", f)
        self.assertEqual(verify_freeze(self.dir, STAMP), [])

    def test_verify_refuses_a_digest_that_is_not_the_run_documents(self):
        f = self.build(runner_image=RUNNER_IMAGE)
        f["init_data"]["digest"] = "0" * 64
        (self.dir / f"freeze-{STAMP}.json").write_text(json.dumps(f, indent=2, sort_keys=True) + "\n")
        (self.dir / f"FREEZE-{STAMP}.txt").write_text(render_freeze_txt(f))
        self.assertTrue(any("not the SHA-256 of the run document" in p for p in verify_freeze(self.dir, STAMP)))

    def test_verify_refuses_an_edited_run_document(self):
        self.build(runner_image=RUNNER_IMAGE)
        doc = self.dir / run_document_name(STAMP)
        doc.write_text(doc.read_text() + "\n# edited\n")
        problems = verify_freeze(self.dir, STAMP)
        self.assertTrue(any("run document" in p or "artefact changed" in p for p in problems), problems)

    def test_verify_refuses_a_probe_digest_that_is_not_the_reference_values(self):
        f = self.build(runner_image=RUNNER_IMAGE)
        f["probe_init_data"]["digest"] = "1" * 64
        (self.dir / f"freeze-{STAMP}.json").write_text(json.dumps(f, indent=2, sort_keys=True) + "\n")
        (self.dir / f"FREEZE-{STAMP}.txt").write_text(render_freeze_txt(f))
        self.assertTrue(any("probe_init_data.digest" in p for p in verify_freeze(self.dir, STAMP)))


class VerifyDerivesTheRecordFromTheArtefacts(_Dir):
    """A JSON and a text edited together must not pass.

    `verify` re-derives the measurement, the substrate profile hash, the init-data digests and the
    binding version from the artefacts (or from the code that verifies them) and reports files
    added to the record.
    """

    def _rewrite(self, freeze):
        """Write `freeze` and its text rendering back, consistent with each other."""
        (self.dir / f"freeze-{STAMP}.json").write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n")
        (self.dir / f"FREEZE-{STAMP}.txt").write_text(render_freeze_txt(freeze))

    def _tampered(self, edit):
        """Build a verified record, apply `edit` consistently to JSON and text, and return the problems."""
        freeze = self.build(runner_image=RUNNER_IMAGE)
        self.assertEqual(verify_freeze(self.dir, STAMP), [])  # positive control: the untouched record verifies
        edit(freeze)
        self._rewrite(freeze)
        return verify_freeze(self.dir, STAMP)

    def test_a_consistently_edited_measurement_is_refused(self):
        problems = self._tampered(lambda f: f["measurement"].update(mrtd="0" * 96))
        self.assertTrue(any("measurement" in p and "mrtd" in p for p in problems), problems)

    def test_a_consistently_edited_substrate_profile_hash_is_refused(self):
        problems = self._tampered(lambda f: f.update(substrate_profile_hash="0" * 64))
        self.assertTrue(any("substrate_profile_hash" in p for p in problems), problems)

    def test_a_binding_version_the_code_does_not_verify_is_refused(self):
        problems = self._tampered(lambda f: f.update(binding_version="v0.0"))
        self.assertTrue(any("binding_version" in p for p in problems), problems)

    def test_a_probe_record_re_derives_its_init_data_digest_too(self):
        freeze = self.build()
        freeze["init_data"]["digest"] = "2" * 64
        self._rewrite(freeze)
        self.assertTrue(any("init_data" in p for p in verify_freeze(self.dir, STAMP)))

    def test_control_a_record_without_a_binding_version_makes_no_claim_about_it(self):
        freeze = self.build()
        del freeze["binding_version"]
        self._rewrite(freeze)
        self.assertEqual(verify_freeze(self.dir, STAMP), [])

    def test_a_file_added_to_this_freeze_is_reported(self):
        self.build()
        (self.dir / f"extra-{STAMP}.txt").write_text("added later\n")
        self.assertTrue(any(f"extra-{STAMP}.txt" in p and "not listed" in p for p in verify_freeze(self.dir, STAMP)))

    def test_control_a_file_of_another_freeze_in_the_same_directory_is_not_an_addition(self):
        self.build()
        (self.dir / "attach-20250101T000000Z.txt").write_text("another line\n")
        self.assertEqual(verify_freeze(self.dir, STAMP), [])

    def test_verify_changes_nothing_in_the_directory(self):
        self.build(runner_image=RUNNER_IMAGE)
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.dir.iterdir()}
        verify_freeze(self.dir, STAMP)
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.dir.iterdir()}
        self.assertEqual(before, after)

    def test_the_verdict_names_what_it_proved_and_gives_the_digest_to_pin(self):
        self.build(runner_image=RUNNER_IMAGE)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = freeze_main(["verify", str(self.dir), "--stamp", STAMP])
        text = out.getvalue()
        digest = hashlib.sha256((self.dir / f"freeze-{STAMP}.json").read_bytes()).hexdigest()
        self.assertEqual(code, 0)
        self.assertIn("freeze record is consistent with the supplied artefacts", text)
        self.assertIn(digest, text)
        self.assertNotIn("intact", text)
        self.assertNotIn("FREEZE_OK", text)

    def test_a_broken_record_is_not_called_consistent(self):
        freeze = self.build()
        freeze["measurement"]["mrtd"] = "0" * 96
        self._rewrite(freeze)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = freeze_main(["verify", str(self.dir), "--stamp", STAMP])
        self.assertEqual(code, 1)
        self.assertIn("NOT consistent", out.getvalue())


class TheDeploymentMustReproduceTheRunDigest(_Dir):
    """A deployment must reproduce the run digest the freeze names, or it is refused."""

    def reference(self, **kw):
        """Return a reference built from a freshly built freeze record."""
        return ReferenceValues.from_freeze_text(json.dumps(self.build(**kw)))

    def test_the_reference_carries_the_profile(self):
        self.assertEqual(self.reference(runner_image=RUNNER_IMAGE).init_data_profile, "run")
        self.assertEqual(self.reference().init_data_profile, "probe")

    def test_a_matching_deployment_is_accepted_and_a_missing_one_keeps_the_freeze(self):
        ref = self.reference(runner_image=RUNNER_IMAGE)
        _require_deployment_matches_freeze(ref, deployment_init_data_digest(RUNNER_IMAGE))
        _require_deployment_matches_freeze(ref, None)

    def test_a_deployment_with_another_digest_is_refused_for_a_run_freeze(self):
        ref = self.reference(runner_image=RUNNER_IMAGE)
        with self.assertRaisesRegex(SystemExit, "wrong services image"):
            _require_deployment_matches_freeze(ref, "f" * 64)

    def test_a_probe_or_legacy_freeze_still_lets_the_deployment_override(self):
        _require_deployment_matches_freeze(self.reference(), "f" * 64)


class TheTableShowsWhichDigestIsWhich(unittest.TestCase):
    """`report_v5.render_t5` does not print a probe digest as the digest of the runs."""

    def test_legacy_and_run_lines_fill_the_two_rows_differently(self):
        prov = {"image": "x", "a5c": "HARDENED (noop)", "b1": "APPLIED"}
        legacy = {"freeze_stamp": "L", "init_data": {"digest": "a" * 64}, "image": {}, "measurement": {},
                  "dcap": {}, "probe": {}}
        run = {"freeze_stamp": "R", "init_data": {"digest": "b" * 64, "profile": "run"},
               "probe_init_data": {"digest": "c" * 64}, "image": {}, "measurement": {}, "dcap": {}, "probe": {}}
        out = render_t5([("legacy", legacy, prov), ("run", run, prov)])
        rows = {line.split("&")[0].strip(): line for line in out.splitlines() if "init-data digest" in line}
        probe_row, run_row = rows["init-data digest, probe quote"], rows["init-data digest, run policy"]
        self.assertIn("aaaaaaaaaaaa", probe_row)           # legacy: its only digest is the probe's
        self.assertIn("cccccccccccc", probe_row)
        self.assertNotIn("aaaaaaaaaaaa", run_row)
        self.assertIn("not recorded", run_row)
        self.assertIn("bbbbbbbbbbbb", run_row)


if __name__ == "__main__":
    unittest.main()
