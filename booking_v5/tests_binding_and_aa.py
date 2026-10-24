"""The freeze binding version and the attestation agent reply are parsed strictly.

An explicit v5.0 needs the archive opt-in, and an unknown version string is refused. The agent
reply is parsed as JSON and only its top-level `success` decides, so a reply that merely
contains the text `"success":"true"` is not accepted.

Run:
    python3 -m booking_v5.tests_binding_and_aa
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from .relying_party import ReferenceValues
from .runner_bind import AttestationAgent, RunnerError, _aa_reported_success


def _record(**extra) -> str:
    """Return a minimal freeze record as JSON, with `extra` fields set."""
    record = {"schema_version": 1, "platform": "tdx", "substrate_profile_hash": "x" * 64,
              "measurement": {k: "0" * 8 for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "mrseam",
                                                    "tee_tcb_svn", "xfam", "tdattributes")},
              "init_data": {"algorithm": "sha256", "digest": "d" * 64}}
    record.update(extra)
    return json.dumps(record)


class BindingVersionGuard(unittest.TestCase):
    """The binding version of a reference record is validated, whatever path builds it."""

    def test_an_explicit_v50_needs_the_archive_opt_in(self):
        with self.assertRaisesRegex(ValueError, "names binding_version v5.0"):
            ReferenceValues.from_freeze_text(_record(binding_version="v5.0"))
        old = ReferenceValues.from_freeze_text(_record(binding_version="v5.0"), allow_pre_h2_binding=True)
        self.assertEqual(old.binding_version, "v5.0")

    def test_an_unknown_version_is_refused_even_with_the_opt_in(self):
        for bad in ("v5.2", "v6", "", "V5.1", "v5.1 "):
            with self.assertRaisesRegex(ValueError, "unknown binding_version"):
                ReferenceValues.from_freeze_text(_record(binding_version=bad), allow_pre_h2_binding=True)

    def test_the_current_version_needs_no_opt_in(self):
        self.assertEqual(ReferenceValues.from_freeze_text(_record(binding_version="v5.1")).binding_version, "v5.1")

    def test_a_directly_built_reference_with_an_unknown_version_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unknown binding_version"):
            ReferenceValues(binding_version="v9")


class AaReplyIsParsed(unittest.TestCase):
    """The agent reply is judged by its parsed top-level field, not by a substring match."""

    def test_only_a_top_level_success_counts(self):
        self.assertTrue(_aa_reported_success(b'{"success":"true"}'))
        self.assertTrue(_aa_reported_success(b'{"success": "true", "x": 1}'))
        self.assertTrue(_aa_reported_success(b'{"success": true}'))
        for bad in (b'{"success":"false","details":{"success":"true"}}', b'{"success":"false"}',
                    b'{"error":"\\"success\\":\\"true\\""}', b'["success","true"]', b'not json',
                    b'', b'{"success":"True"}'):
            self.assertFalse(_aa_reported_success(bad), bad)

    def test_extend_refuses_a_reply_that_only_contains_the_text(self):
        class _Resp:
            """The shape of a urllib response with a fixed body."""

            def __init__(self, body):
                self.body = body

            def read(self):
                return self.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        aa = AttestationAgent()
        with mock.patch("urllib.request.urlopen", return_value=_Resp(b'{"success":"true"}')):
            aa.extend("op", "content")  # positive control
        with mock.patch("urllib.request.urlopen",
                        return_value=_Resp(b'{"success":"false","details":{"success":"true"}}')):
            with self.assertRaises(RunnerError):
                aa.extend("op", "content")


if __name__ == "__main__":
    unittest.main()
