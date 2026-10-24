"""The freeze record names the measured image and reads the A5c state from its provenance.

A5c is the acceptance test for the pod VM's metadata server reached over link-local
(`scripts/gke-v5/attack_catalogue.md`). A script must not pass the A5c state in as a label, and
the record must not take the first provenance file it finds. The probe script judges A5c from the
recorded network log instead of only printing it. The fixtures are the recorded provenance files
and logs of a hardened and an unhardened pod-VM image, overlay revisions ov9 and ov13.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest

from .freeze_record import FreezeInconsistent, build_freeze, hardening_from_provenance

MOCKS = pathlib.Path(__file__).resolve().parents[1]
IMAGES = MOCKS / "results_v5" / "podvm-image"
FREEZE = MOCKS / "results_v5" / "freeze-candidate"
STAMP = "20260924T152405Z"
OV9 = "podvm-fedora-tdx-caa-0-21-1-ov9"
OV13 = "podvm-fedora-tdx-caa-0-21-1-ov13"


def _prov(name: str) -> str:
    """Return the recorded provenance text of image `name`."""
    return (IMAGES / f"{name}.provenance.txt").read_text()


class TheHardeningComesFromTheProvenance(unittest.TestCase):
    """The hardening state of an image is read from its provenance record, not assumed."""

    def test_ov9_is_hardened(self):
        self.assertEqual(hardening_from_provenance(_prov(OV9)),
                         {"a5c": "HARDENED (noop)", "b1": "APPLIED"})

    def test_ov13_is_not(self):
        self.assertEqual(hardening_from_provenance(_prov(OV13)),
                         {"a5c": "OPEN (V5_HARDEN_A5C=0)", "b1": "NOT APPLIED"})


class TheRecordNamesTheMeasuredImage(unittest.TestCase):
    """The freeze, rebuilt from its own artefacts in a scratch copy, names the measured image."""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp(prefix="a5c-freeze-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        for name in (f"reference-values-{STAMP}.json", f"dcap-{STAMP}.txt", f"substrate-40-{STAMP}.txt"):
            shutil.copy(FREEZE / name, self.dir / name)
        shutil.copy(IMAGES / f"{OV9}.provenance.txt", self.dir)
        shutil.copy(IMAGES / f"{OV13}.provenance.txt", self.dir)

    def test_the_named_image_decides_and_its_state_is_read(self):
        f = build_freeze(self.dir, STAMP, image=OV13)
        self.assertEqual(f["image"]["name"], OV13)
        self.assertEqual(f["image"]["file"], f"{OV13}.provenance.txt")
        self.assertEqual(f["probe"]["a5c"], "OPEN (V5_HARDEN_A5C=0)")
        self.assertEqual(f["probe"]["b1"], "NOT APPLIED")

    def test_a_contradicting_label_is_refused(self):
        with self.assertRaises(FreezeInconsistent):
            build_freeze(self.dir, STAMP, image=OV13, a5c="HARDENED (V5_HARDEN_A5C=1)")

    def test_two_provenances_without_a_name_are_undecidable(self):
        with self.assertRaises(FreezeInconsistent):
            build_freeze(self.dir, STAMP)

    def test_an_image_without_provenance_is_refused(self):
        with self.assertRaises(FreezeInconsistent):
            build_freeze(self.dir, STAMP, image="podvm-fedora-tdx-caa-0-21-1-ov99")


class TheNetworkProbeJudgesA5cFromItsLog(unittest.TestCase):
    """The awk extraction of `19_probe_network.sh` judges A5c from recorded logs, closed or open."""

    SCRIPT = (MOCKS / "scripts" / "gke-v5" / "19_probe_network.sh").read_text()

    def _verdict(self, log: pathlib.Path) -> str:
        """Run the A5c extraction of the probe script on `log` and return its verdict word."""
        start = self.SCRIPT.index('a5c_line="$(')
        body = self.SCRIPT[start:self.SCRIPT.index("esac", start) + 4]
        out = subprocess.run(["bash", "-c", f'LOG="{log}"\n' + body.replace(' | tee -a "${LOG}"', "")],
                             capture_output=True, text=True, check=True).stdout
        return out.split()[0]

    def test_the_ov9_line_is_closed(self):
        self.assertEqual(self._verdict(MOCKS / "results_v5" / "probe" / "network-20260911T204144Z.txt"),
                         "A5C_CLOSED")

    def test_the_ov13_line_is_open(self):
        self.assertEqual(self._verdict(MOCKS / "results_v5" / "probe" / "network-20260924T152826Z.txt"),
                         "A5C_OPEN")


if __name__ == "__main__":
    unittest.main()
