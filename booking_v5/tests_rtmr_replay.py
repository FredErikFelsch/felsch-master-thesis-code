"""Offline tests for booking_v5.rtmr_replay against a fixture recorded live.

The fixture comes from a probe run (GCE c3-standard-4 TDX, CoCo peer pod, guest-components
f156103). It pins the two facts the relying party depends on: the AAEL TaggedEvent encoding and
the RTMR extend rule. If either drifts upstream, this test fails before any live run.

Run:  python3 -m booking_v5.tests_rtmr_replay
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
import struct
import unittest

from .rtmr_replay import RTMR_ZERO, aael_event_digest, aael_line, extend, init_data_line, replay

PROBE = pathlib.Path(__file__).resolve().parents[1] / "results_v5" / "probe"
STAMP = "20260903T170805Z"
RTMR3_OFF = 520          # offset of RTMR3 in a TDX v4 quote (48-byte header + 472 in the TD report body)


def _rtmr3(quote_b64: str) -> bytes:
    """Return RTMR3 of a base64 quote."""
    q = base64.b64decode(quote_b64)
    return q[RTMR3_OFF:RTMR3_OFF + 48]


class LiveFixture(unittest.TestCase):
    """The probe's single AAEL event replays onto the RTMR3 the live quote showed."""

    @classmethod
    def setUpClass(cls):
        log = (PROBE / f"evidence-{STAMP}.log").read_text()
        before = json.loads(base64.b64decode(re.search(r"^EVIDENCE_B64 (\S+)", log, re.M).group(1)))
        after = json.loads(base64.b64decode(re.search(r"^EVIDENCE_AFTER_EXTEND_B64 (\S+)", log, re.M).group(1)))
        cls.rtmr3_before = _rtmr3(before["quote"])
        cls.rtmr3_after = _rtmr3(after["quote"])
        cls.rd = (PROBE / f"runtime-data-{STAMP}.txt").read_text().strip()

    def test_replay_matches_live_rtmr3(self):
        line = aael_line("p3-extend", self.rd, domain="v5-probe")
        self.assertEqual(replay([line], self.rtmr3_before), self.rtmr3_after)

    def test_probe_started_from_zero(self):
        self.assertEqual(self.rtmr3_before, RTMR_ZERO)

    def test_wrong_content_does_not_replay(self):
        line = aael_line("p3-extend", self.rd[:-1] + ("0" if self.rd[-1] != "0" else "1"), domain="v5-probe")
        self.assertNotEqual(replay([line], self.rtmr3_before), self.rtmr3_after)


class Encoding(unittest.TestCase):
    """The AAEL tagged-event encoding and the RTMR extend rule."""

    def test_tagged_event_layout(self):
        line = "v5 init-data abc"
        expected = hashlib.sha384(struct.pack("<II", 0x4141454C, len(line)) + line.encode()).digest()
        self.assertEqual(aael_event_digest(line), expected)

    def test_extend_is_sha384_of_concatenation(self):
        d = aael_event_digest("v5 x y")
        self.assertEqual(extend(RTMR_ZERO, d), hashlib.sha384(RTMR_ZERO + d).digest())

    def test_order_matters(self):
        a, b = "v5 init-data 00", "v5 boot-key 11"
        self.assertNotEqual(replay([a, b]), replay([b, a]))

    def test_init_data_line_format(self):
        self.assertEqual(init_data_line("ab" * 32), "v5 init-data " + "ab" * 32)

    def test_tokens_without_spaces(self):
        with self.assertRaises(ValueError):
            aael_line("init data", "x")
        with self.assertRaises(ValueError):
            aael_line("ok", "x", domain="v 5")


if __name__ == "__main__":
    unittest.main(verbosity=1)
