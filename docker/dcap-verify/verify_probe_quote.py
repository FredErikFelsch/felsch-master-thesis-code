#!/usr/bin/env python3
"""Verify a recorded probe quote offline with Intel's DCAP QVL.

The input is mounted at /work (results_v5/probe): evidence-<STAMP>.log with its EVIDENCE_B64
line, and runtime-data-<STAMP>.txt. The output is a set of VERDICT lines. The exit code is 0
only for an accepted qv_result.

What is checked here, and by whom:
  REPORTDATA binding   booking_v5.dcap (constant-time compare against ascii(runtime_data) padded to 64 B)
  signature chain      Intel QVL: quote -> attestation key -> PCK cert -> Intel root, CRLs
  TCB status           Intel QVL against PCS TCB info and QE identity for the quote's FMSPC
  measurements         printed so that they can be pinned, but not judged here. The
                       Authority judges them against the reference values.

    python3 /app/verify_probe_quote.py <STAMP>
"""
import base64
import json
import os
import pathlib
import re
import sys

from booking_v5.dcap.local_dcap_verify import (
    DEFAULT_ACCEPTED_QV_RESULTS, debug_verify_quote, local_dcap_appraiser, parse_tdx_quote,
)

WORK = pathlib.Path("/work")


def load(stamp: str) -> tuple[bytes, bytes]:
    """Load the recorded quote of `stamp`.

    Returns:
        The raw quote buffer and the 64-byte REPORTDATA expected from runtime_data.
    """
    log = (WORK / f"evidence-{stamp}.log").read_text()
    m = re.search(r"^EVIDENCE_B64 (\S+)", log, re.M)
    if not m:
        sys.exit("no EVIDENCE_B64 line in the evidence log (re-run scripts/gke-v5/18_probe_peer_pod.sh)")
    evidence = json.loads(base64.b64decode(m.group(1)))
    rd = (WORK / f"runtime-data-{stamp}.txt").read_text().strip().encode()
    if len(rd) > 64:
        sys.exit("runtime_data longer than 64 bytes: the AA copies it unchanged into REPORTDATA")
    return base64.b64decode(evidence["quote"]), rd.ljust(64, b"\0")


def main() -> int:
    """Verify the quote of the stamp given on the command line and print VERDICT lines."""
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    stamp = sys.argv[1]
    quote, report_data = load(stamp)
    parsed = parse_tdx_quote(quote)
    print(f"VERDICT parse:   quote {len(parsed.quote_bytes)} B, FMSPC {parsed.fmspc}, MRTD {parsed.mr_td.hex()}")
    print(f"VERDICT library: {pathlib.Path('/etc/dcap-versions.txt').read_text().strip().replace(chr(10), ', ')}")
    if os.environ.get("DCAP_DEBUG") == "1":
        debug_verify_quote(quote)
    if "PCS_API_KEY" not in os.environ:
        print("VERDICT dcap:    NOT_VERIFIED (PCS_API_KEY not set, export it and re-run)")
        return 3
    try:
        measurement, evidence_json = local_dcap_appraiser()(quote, report_data)
    except RuntimeError as exc:
        print(f"VERDICT dcap:    REJECTED ({exc})")
        return 1
    ev = json.loads(evidence_json)
    print(f"VERDICT dcap:    VERIFIED qv_result={ev['qv_result']} fmspc={ev['fmspc']} (accepted set: "
          f"{sorted(hex(r) for r in DEFAULT_ACCEPTED_QV_RESULTS)})")
    print("VERDICT binding: REPORTDATA == ascii(runtime_data) (checked constant-time by the appraiser)")
    print(f"VERDICT mrtd:    {measurement}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
