"""RTMR0 outliers: recognise provider substrate variance without admitting anything.

RTMR0 is written by the virtual firmware and measures the boot configuration below the
project's image. In a public cloud it belongs to the provider. MRTD, RTMR1 and RTMR2 are the
project's (firmware image, kernel, initrd), RTMR3 carries the init-data and the runner's
events, and RTMR0 reflects the host GCE happened to place the pod VM on. Across the recorded
runs, 2 of 60 TDs showed an RTMR0 other than the frozen one. A timing series starts 21 TDs and
demands that all of them are accepted, so roughly every second series fails on a property that
has nothing to do with what is being measured.

This module never turns a refusal into an admission. It widens no reference value, adds no
RTMR0 to an accepted set and re-runs nothing. The Authority's decision stays as it was: the TD
was refused, executed no fragment and produced no effect. Neither `relying_party.py` nor the
freeze is touched.

It classifies, from the refused TD's own recorded bytes, whether the refusal was this one known
provider property, so a latency series can report it as a measured platform event instead of
aborting. Five conditions must all hold, and each keeps a real defect a failure:

  1. Opt-in. The caller has to ask for the classification. Only the timing runs do.
  2. The refusal is `boot-measurement-mismatch` and its detail names `rtmr0` and no other field.
  3. The saved quote reproduces that: every other pinned field (MRTD, RTMR1, RTMR2, MRSEAM,
     TEE TCB SVN, XFAM, TD attributes) is byte-equal to the frozen reference, and none is
     missing. A substituted kernel moves RTMR1 and is therefore not tolerated here.
  4. The run is effect-free and that was measured: zero effects, zero pending, zero foreign,
     and the ledger was actually read. An unmeasured ledger is not a zero ledger.
  5. The frozen reference is readable. Without it there is nothing to compare against, so the
     answer is "not classified".

The classification carries its own evidence: the observed RTMR0, the expected one, and the PCK
leaf serial, which is issued per physical package and is what shows this was a different host.

    python3 -m booking_v5.substrate_variance <evidence.bin> [--stamp STAMP]
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import sys

MOCKS = pathlib.Path(__file__).resolve().parents[1]
FREEZE_DIR = MOCKS / "results_v5" / "freeze-candidate"

#: The fields the Authority pins, without RTMR0, the one field this module is about. All of
#: these must match, or the refusal is not substrate variance.
PINNED_BESIDES_RTMR0 = ("mrtd", "rtmr1", "rtmr2", "mrseam", "tee_tcb_svn", "xfam", "tdattributes")

#: The only refusal rule that can be classified. Its detail must name rtmr0 (_RTMR0_DETAIL).
TOLERATED_RULE = "boot-measurement-mismatch"
_RTMR0_DETAIL = re.compile(r"^rtmr0 got=([0-9a-f]{96}) want=([0-9a-f]{96})$")


@dataclasses.dataclass(frozen=True)
class SubstrateVariance:
    """One classified RTMR0 outlier, with the evidence that says it was another host."""

    observed_rtmr0: str
    expected_rtmr0: str
    pck_leaf_serial: str | None
    fmspc: str | None
    freeze_stamp: str
    evidence_path: str

    def to_json(self) -> dict:
        """Return the record a latency series stores for this outlier."""
        return {"kind": "substrate-rtmr0-variance", **dataclasses.asdict(self),
                "note": ("the refusal stands: this TD executed no fragment and produced no "
                         "effect. Only the latency series counts it separately instead of "
                         "aborting, because RTMR0 is the provider's field, not ours.")}


def frozen_stamp() -> str | None:
    """Return the pinned freeze stamp: FREEZE_STAMP if set, else the newest record on disk."""
    stamp = os.environ.get("FREEZE_STAMP")
    if stamp:
        return stamp
    records = sorted(FREEZE_DIR.glob("freeze-*.json")) if FREEZE_DIR.exists() else []
    return records[-1].stem.split("-", 1)[1] if records else None


def frozen_fields(stamp: str) -> dict | None:
    """Return the measurement fields of the pinned freeze, or None when they cannot be read.

    They are read from the freeze record, the same source the Authority is pinned to. An
    unreadable record makes the refusal unclassifiable.
    """
    path = FREEZE_DIR / f"freeze-{stamp}.json"
    if not path.exists():
        return None
    try:
        measurement = json.loads(path.read_text())["measurement"]
    except (ValueError, KeyError):
        return None
    return {k: v for k, v in measurement.items() if isinstance(v, str)}


def _quote_of(blob: bytes):
    """Parse the saved evidence, whether it is the AA envelope or a bare quote.

    Raises:
        QuoteMalformed: the bytes are neither.
    """
    from .tdx_quote import parse_aa_evidence, parse_quote
    try:
        return parse_quote(parse_aa_evidence(blob)[0])
    except Exception:                                                        # noqa: BLE001 (try the bare quote next)
        return parse_quote(blob)


def _field(quote, name: str) -> str | None:
    try:
        value = quote.raw_field(name)
    except Exception:                                                        # noqa: BLE001 (a missing field is not comparable)
        return None
    return value.hex() if isinstance(value, (bytes, bytearray)) else str(value)


def pck_identity(quote) -> tuple[str | None, str | None]:
    """Return (leaf serial, fmspc) of the quote's PCK certificate, or (None, None).

    The leaf is issued per physical package, so a differing serial is what shows the TD ran on
    another machine. It is reported and not required. A missing certificate chain weakens the
    explanation, but the decision does not rest on it.
    """
    try:
        from cryptography import x509
        from .dcap import local_dcap_verify as dcap
        pems = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                          quote.quote_bytes, re.S)
        if not pems:
            return None, None
        leaf = x509.load_pem_x509_certificate(pems[0])
        fmspc = None
        for extension in leaf.extensions:
            if extension.oid.dotted_string == "1.2.840.113741.1.13.1":
                fmspc = dcap._extract_fmspc(extension.value.value)
        return hex(leaf.serial_number), fmspc
    except Exception:                                                        # noqa: BLE001 (reported only)
        return None, None


def classify(rule: str | None, detail: str | None, evidence_path: str | os.PathLike[str] | None,
             *, effects: int, pending_effects: int, foreign_effects: int,
             ledger_measured: bool, stamp: str | None = None) -> SubstrateVariance | None:
    """Return the classification, or None when this refusal is not provider RTMR0 variance.

    None is the safe answer and the default for everything unexpected: another rule, another
    field, a missing or unparsable quote, one differing pinned field, any effect, an unmeasured
    ledger, or an unreadable freeze. The caller must treat None as a plain failure.

    Args:
        rule: the refusal rule.
        detail: the refusal detail, which must read "rtmr0 got=<hex> want=<hex>".
        evidence_path: the refused TD's saved evidence.
        effects: committed effects of the run.
        pending_effects: pending effects of the run.
        foreign_effects: effects of other runs seen meanwhile.
        ledger_measured: whether the ledger was actually read.
        stamp: the freeze stamp, `frozen_stamp()` when None.

    Returns:
        The classified outlier, or None.
    """
    if rule != TOLERATED_RULE:
        return None
    match = _RTMR0_DETAIL.match((detail or "").strip())
    if not match:                       # another boot measurement, or a detail that cannot be parsed
        return None
    if effects or pending_effects or foreign_effects:
        return None                     # a refused run that touched the world is a finding
    if not ledger_measured:
        return None                     # not measured is not zero
    if not evidence_path or not pathlib.Path(evidence_path).exists():
        return None                     # no bytes, no proof
    stamp = stamp or frozen_stamp()
    if not stamp:
        return None
    reference = frozen_fields(stamp)
    if not reference:
        return None

    from .tdx_quote import QuoteMalformed
    try:
        quote = _quote_of(pathlib.Path(evidence_path).read_bytes())
    except QuoteMalformed:
        return None                     # unparsable bytes prove nothing
    for name in PINNED_BESIDES_RTMR0:
        expected, got = reference.get(name), _field(quote, name)
        if not expected or not got or got != expected:
            return None                 # anything but RTMR0 moved, or could not be compared
    observed = _field(quote, "rtmr0")
    if observed != match.group(1) or match.group(2) != reference.get("rtmr0"):
        return None                     # the saved bytes must be the ones the refusal saw

    serial, fmspc = pck_identity(quote)
    return SubstrateVariance(observed_rtmr0=observed, expected_rtmr0=match.group(2),
                             pck_leaf_serial=serial, fmspc=fmspc, freeze_stamp=stamp,
                             evidence_path=str(evidence_path))


def main() -> int:
    """Command line entry point: classify one saved quote and print the field comparison."""
    parser = argparse.ArgumentParser(description="classify a refused TD's evidence as RTMR0 variance")
    parser.add_argument("evidence")
    parser.add_argument("--stamp", default=None, help="freeze stamp, default FREEZE_STAMP or the newest")
    parser.add_argument("--detail", default=None, help="the refusal detail, if it is known")
    args = parser.parse_args()

    stamp = args.stamp or frozen_stamp()
    reference = frozen_fields(stamp) if stamp else None
    if not reference:
        print(f"no readable freeze record for stamp {stamp!r}", file=sys.stderr)
        return 2
    quote = _quote_of(pathlib.Path(args.evidence).read_bytes())
    detail = args.detail or f"rtmr0 got={_field(quote, 'rtmr0')} want={reference.get('rtmr0')}"
    verdict = classify(TOLERATED_RULE, detail, args.evidence, effects=0, pending_effects=0,
                       foreign_effects=0, ledger_measured=True, stamp=stamp)

    print(f"{'field':16} {'frozen':>14}  {'refused':>14}  equal")
    for name in ("rtmr0", *PINNED_BESIDES_RTMR0):
        expected, got = str(reference.get(name, "")), str(_field(quote, name))
        print(f"{name:16} {expected[:14]:>14}  {got[:14]:>14}  {'YES' if got == expected else 'NO'}")
    serial, fmspc = pck_identity(quote)
    print(f"\nPCK leaf serial : {serial}\nFMSPC           : {fmspc}")
    print("\nVERDICT:", "provider RTMR0 variance" if verdict else "NOT classifiable as substrate variance")
    if verdict:
        json.dump(verdict.to_json(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0 if verdict else 1


if __name__ == "__main__":
    raise SystemExit(main())
