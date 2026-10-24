"""Dry run of the probe analysis on synthetic evidence.

The tests build the evidence a correct V5 runner TD would produce and let
`scripts/gke-v5/20_verify_evidence_offline.py` judge it. Nothing here is a claim about hardware.
The tests exercise the analysis tooling before any cluster exists. The script must print
V5_BINDING_OK, V5_RTMR3_REPLAY_OK and INITDATA_MEASURED for correct evidence and must go red for
each single mutation.

The quote is a real recorded one with REPORTDATA and RTMR3 rewritten, so the layout and the
surrounding parsing are the real ones. The signature is not valid any more, and the script checks
none. Signature checking is the job of `scripts/gke-v5/21_dcap_verify.sh`.

Run:  python3 -m booking_v5.tests_probe_analysis
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

from .binding import RunnerIdentity, canonical_binding
from .rtmr_replay import expected_rtmr3, init_data_line, replay
from .tdx_quote import BODY

MOCKS = pathlib.Path(__file__).resolve().parents[1]
PROBE = MOCKS / "results_v5" / "probe"
SCRIPT = MOCKS / "scripts" / "gke-v5" / "20_verify_evidence_offline.py"
SOURCE_STAMP = "20260903T170805Z"        # the recorded run whose quote bytes and manifest are reused
STAMP = "SYNTH0000T000000Z"
RUN, STEP = "probe-synth", 1
FRAG, STATE, NONCE = "a1" * 32, "b2" * 32, "c3" * 32


def _patch(quote_buf: bytes, **fields: bytes) -> bytes:
    """Overwrite report-body fields in place. The quote stays structurally valid."""
    buf = bytearray(quote_buf)
    for name, value in fields.items():
        off, ln = BODY[name]
        if len(value) != ln:
            raise ValueError(f"{name} must be {ln} bytes")
        buf[off:off + ln] = value
    return bytes(buf)


class ProbeAnalysisDryRun(unittest.TestCase):
    """One synthetic run in a temporary probe directory, judged by the real script."""

    @classmethod
    def setUpClass(cls):
        cls.identity = RunnerIdentity.create()
        cls.pk = cls.identity.pk_boot
        cls.pk_sig = cls.identity.pk_sig
        cls.identity.bind(RUN, STEP, FRAG, STATE)
        cls.runtime_data = cls.identity.runtime_data(bytes.fromhex(NONCE))
        blob = (PROBE / f"evidence-{SOURCE_STAMP}.log").read_text()
        raw = base64.b64decode(re.search(r"^EVIDENCE_B64 (\S+)", blob, re.M).group(1))
        cls.document = json.loads(raw)
        cls.quote_buf = base64.b64decode(cls.document["quote"])
        # The init-data digest the pod-VM overlay measures is the sha256 of the TOML that was
        # launched (it carries the genpolicy policy), so it is taken from the manifest the run
        # recorded, as 20_verify_evidence_offline.py does.
        cls.init_digest = manifest_init_data_digest(PROBE / f"runner-peer-{SOURCE_STAMP}.yaml")

    def _write_run(self, tmp: pathlib.Path, *, rtmr3: bytes, reportdata: bytes,
                   pre_rtmr3: bytes | None = None, pk_hex: str | None = None,
                   pk_sig_hex: str | None = None) -> None:
        """Write the four files a probe run leaves behind, with the given measurements."""
        def doc(quote: bytes) -> str:
            return base64.b64encode(json.dumps(dict(self.document, quote=base64.b64encode(quote).decode())).encode()).decode()

        main = _patch(self.quote_buf, rtmr3=rtmr3, reportdata=reportdata)
        lines = [f"PROBE_BIND_START {json.dumps({'run': RUN})}", f"PK_BOOT {pk_hex or self.pk.hex()}",
                 f"PK_SIG {pk_sig_hex or self.pk_sig.hex()}",
                 f"RUNTIME_DATA {self.runtime_data.hex()}"]
        if pre_rtmr3 is not None:
            lines.append("EVIDENCE_PRE_B64 " + doc(_patch(self.quote_buf, rtmr3=pre_rtmr3, reportdata=reportdata)))
        lines += ["AAEL_OK boot-key x", "AAEL_OK bind x", f"EVIDENCE_OK {len(main)}",
                  "EVIDENCE_B64 " + doc(main), "PROBE_BIND_DONE"]
        (tmp / f"evidence-{STAMP}.log").write_text("\n".join(lines) + "\n")
        (tmp / f"runtime-data-{STAMP}.txt").write_text(self.runtime_data.hex() + "\n")
        (tmp / f"binding-{STAMP}.json").write_text(json.dumps(
            {"run": RUN, "step": STEP, "fragment_hash": FRAG, "state_hash": STATE, "nonce": NONCE}))
        shutil.copy(PROBE / f"runner-peer-{SOURCE_STAMP}.yaml", tmp / f"runner-peer-{STAMP}.yaml")

    def _run20(self, **kwargs) -> tuple[int, str]:
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            self._write_run(tmp, **kwargs)
            env = dict(os.environ, V5_PROBE_DIR=str(tmp), PYTHONPATH=str(MOCKS))
            proc = subprocess.run([sys.executable, str(SCRIPT), STAMP], capture_output=True, text=True, env=env)
            return proc.returncode, proc.stdout + proc.stderr

    @property
    def _good(self) -> dict:
        return {"rtmr3": expected_rtmr3(self.init_digest, self.pk.hex(), self.pk_sig.hex(),
                                        RUN, STEP, FRAG, STATE),
                "reportdata": self.runtime_data.hex().encode(),
                "pre_rtmr3": replay([init_data_line(self.init_digest)])}

    def test_correct_evidence_passes_every_v5_verdict(self):
        code, out = self._run20(**self._good)
        self.assertIn("V5_BINDING_OK", out)
        self.assertIn("V5_RTMR3_REPLAY_OK", out)
        self.assertIn("INITDATA_MEASURED", out)
        self.assertIn("AAEL_BOTH_RECORDED", out)
        self.assertEqual(code, 0, out)

    def test_a_binding_over_another_step_is_caught(self):
        """The TD attested a different step than the one recorded, and two verdicts catch it.

        The binding verdict sees REPORTDATA that is not the recorded runtime_data. The V5 binding
        verdict recomputes the canonical binding from the recorded fields and compares it with the
        bytes the hardware signed.
        """
        other = canonical_binding(bytes.fromhex(NONCE), RUN, STEP + 1, FRAG, STATE, self.pk, self.pk_sig)
        code, out = self._run20(**dict(self._good, reportdata=other.hex().encode()))
        self.assertIn("VERDICT binding:    BINDING_MISMATCH", out)
        self.assertIn("VERDICT v5-binding: V5_BINDING_MISMATCH", out)
        self.assertNotEqual(code, 0)

    def test_a_missing_bind_event_is_caught(self):
        """RTMR3 carries only the init-data and boot-key events, so the binding was not measured."""
        partial = replay([init_data_line(self.init_digest),
                          f"v5 boot-key {self.pk.hex()}.{self.pk_sig.hex()}"])
        code, out = self._run20(**dict(self._good, rtmr3=partial))
        self.assertIn("V5_RTMR3_MISMATCH", out)
        self.assertNotEqual(code, 0)

    def test_an_unmeasured_init_data_is_caught(self):
        """The overlay did not run. RTMR3 starts from zero, so no expected value can match."""
        no_overlay = replay([f"v5 boot-key {self.pk.hex()}.{self.pk_sig.hex()}",
                             f"v5 bind {RUN}/{STEP}/{FRAG}/{STATE}"])
        code, out = self._run20(**dict(self._good, rtmr3=no_overlay, pre_rtmr3=bytes(48)))
        self.assertIn("V5_RTMR3_MISMATCH", out)
        self.assertIn("INITDATA_NOT_MEASURED", out)
        self.assertNotEqual(code, 0)

    def test_another_tds_boot_key_is_caught(self):
        """Evidence from a TD whose boot key is not the announced one."""
        code, out = self._run20(**dict(self._good, pk_hex=RunnerIdentity.create().pk_boot.hex()))
        self.assertIn("V5_BINDING_MISMATCH", out)
        self.assertNotEqual(code, 0)


def manifest_init_data_digest(manifest: pathlib.Path) -> str:
    """Return the sha256 of the uncompressed init-data TOML in the manifest's annotation."""
    m = yaml.safe_load(manifest.read_text())
    gz = base64.b64decode(m["metadata"]["annotations"]["io.katacontainers.config.hypervisor.cc_init_data"])
    return hashlib.sha256(gzip.decompress(gz)).hexdigest()


if __name__ == "__main__":
    unittest.main(verbosity=2)
