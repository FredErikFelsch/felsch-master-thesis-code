"""Evidence verification: establish that the evidence is genuine and read its claims.

Division of labour in the Authority:

    verifier.py       is the evidence genuine? Structure of the TDX quote, signature
                      chain PCK -> Intel root, TCB status, and the hardware binding
                      REPORTDATA == ascii(runtime_data). Extracts claims. Judges no
                      policy and does not decide whether a measurement is the right one.
    relying_party.py  is it the right evidence? Reference values, canonical
                      binding, one-TD-one-fragment ledger, substrate profile, scope.

Keeping the reference pin out of here means there is one place where the Authority's
policy lives, and the verifier can be swapped without moving policy with it (local DCAP
today, a Trustee adapter exists only as an unwired stub in relying_party.py).

The project's own code checks no signature. `TdxVerifier` takes an `appraise` callable
with the signature of `dcap.local_dcap_verify.local_dcap_appraiser()`:

    appraise(quote_bytes, reportdata_64) -> (measurement_hex, appraisal_json)

and fails closed when none is configured. Three appraisers are provided:

    dcap_appraiser()         Intel's QVL in this process (x86_64 Linux + PCS key).
    RecordedAppraisal        a QVL result recorded earlier, pinned to the quote's
                             SHA-256, for fixture tests on a Mac, where the library
                             cannot run. It confirms only the quote bytes it was
                             built for and refuses any other quote. That the recorded
                             verdict belongs to those bytes rests on the caller
                             pairing report and quote correctly.
    UnappraisedForTesting    explicit opt-out, refuses unless `i_know=True`.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from .evidence import Evidence
from .tdx_quote import QuoteMalformed, TdxQuote, parse_aa_evidence, parse_quote

Appraiser = Callable[[bytes, bytes], "tuple[str, str]"]


class VerificationFailed(Exception):
    """The evidence could not be established.

    `code` names the stage, so the relying party's refusal (and the run record) separates the
    verifier's failure modes instead of reporting one "evidence-invalid":

        quote-malformed          structure (not a TDX quote v4, bad lengths, non-zero padding)
        reportdata-mismatch      hardware binding: REPORTDATA != ascii(runtime_data)
        no-appraiser             no DCAP appraisal configured (fail closed)
        tcb-rejected             the QVL ran and its result is not accepted (TCB out of date,
                                 revoked, misconfigured). This is a signed statement that
                                 the platform is not trustworthy
        collateral-unavailable   PCS/PCCS unreachable, collateral expired or inconsistent:
                                 the verifier's environment, not the platform
        verifier-error           the library crashed or a recorded verdict is missing for
                                 these bytes. Nothing is known about the platform

    All of them are refusals. Only the last two are not evidence against the TD.
    """

    def __init__(self, message: str, code: str = "verifier-error"):
        super().__init__(message)
        self.code = code


class AppraisalRejected(Exception):
    """An appraiser's typed signal that the QVL result is not accepted (tcb-rejected)."""


class CollateralUnavailable(Exception):
    """An appraiser's typed signal that collateral could not be obtained (collateral-unavailable)."""


def classify_appraisal_error(exc: BaseException) -> str:
    """Map what an appraiser raised onto a VerificationFailed code.

    Typed exceptions come first. The vendored Intel QVL wrapper (dcap/local_dcap_verify.py)
    raises RuntimeError and ValueError with plain messages, and `requests` exceptions for PCS.
    These are mapped by class name and message, so the vendored error texts need no exception
    types of their own. The German words are matched as well, for messages of the vendored
    module before its translation (see dcap/PROVENANCE.md).

    Returns:
        One of tcb-rejected, collateral-unavailable or verifier-error.
    """
    if isinstance(exc, AppraisalRejected):
        return "tcb-rejected"
    if isinstance(exc, CollateralUnavailable):
        return "collateral-unavailable"
    name = type(exc).__name__
    msg = str(exc)
    if name in ("ConnectionError", "Timeout", "HTTPError", "RequestException", "ReadTimeout",
                "ConnectTimeout") or "collateral" in msg.lower() or "PCS" in msg:
        return "collateral-unavailable"
    if "verification result refused" in msg:
        return "tcb-rejected"
    return "verifier-error"


@dataclass(frozen=True)
class VerifiedClaims:
    """The claims the verifier asserts. None of them is judged good or bad yet."""

    platform: str                       # "tdx" | "fake"
    measurement: str                    # MRTD, hex
    runtime_data: bytes                 # the value the hardware bound in REPORTDATA
    rtmr3: Optional[bytes] = None       # runtime measurement register, None if unavailable
    boot_measurements: dict = field(default_factory=dict)   # rtmr0..2, mrseam, tee_tcb_svn, xfam, tdattributes
    init_data_hash: Optional[str] = None                    # MRCONFIGID where the platform fills it
    appraisal: dict = field(default_factory=dict)           # qv_result, fmspc, source


class Verifier(Protocol):
    """Anything that turns an evidence document into verified claims."""

    def verify(self, evidence: Evidence) -> VerifiedClaims:
        """Return the claims of genuine evidence, or raise VerificationFailed."""
        ...


# --- appraisers ---------------------------------------------------------------

def dcap_appraiser(**kwargs) -> Appraiser:
    """Return Intel's Quote Verification Library as an appraiser in this process.

    It needs x86_64 Linux and PCS_API_KEY. `kwargs` go to `local_dcap_appraiser`.

    Raises:
        VerificationFailed: the library or its dependencies are not available here
            (the usual case on a Mac, where the container of scripts/gke-v5/21_dcap_verify.sh is used).
    """
    try:
        from .dcap.local_dcap_verify import local_dcap_appraiser
    except Exception as exc:                                    # noqa: BLE001
        raise VerificationFailed(f"Intel QVL not available in this process: {exc}") from exc
    return local_dcap_appraiser(**kwargs)


@dataclass(frozen=True)
class RecordedAppraisal:
    """A QVL verdict recorded earlier, pinned to the SHA-256 of the quote bytes.

    It lets the offline test suite use real evidence on a machine that cannot run Intel's
    library. A quote without a recorded verdict is refused.
    """

    verdicts: dict          # sha256(quote_bytes) hex -> {"qv_result": ..., "fmspc": ..., ...}
    accept: frozenset = frozenset({"OK"})

    @classmethod
    def from_dcap_report(cls, report_text: str, quote_bytes: bytes) -> "RecordedAppraisal":
        """Read a `results_v5/probe/dcap-<STAMP>.txt` report for one known quote.

        The report is not checked against the quote. The caller pairs them.

        Args:
            report_text: the text of the recorded DCAP report.
            quote_bytes: the quote the report was produced for.

        Returns:
            An appraisal that knows the verdict for `quote_bytes` only.

        Raises:
            VerificationFailed: the report has no qv_result line.
        """
        qv = re.search(r"qv_result\s*[=:]\s*(\w+)", report_text)
        fmspc = re.search(r"fmspc\s*[=:]\s*([0-9a-fA-F]+)", report_text)
        if not qv:
            raise VerificationFailed("no qv_result line in the recorded DCAP report", "verifier-error")
        return cls({hashlib.sha256(quote_bytes).hexdigest(): {
            "qv_result": qv.group(1), "fmspc": fmspc.group(1) if fmspc else None,
            "source": "recorded-dcap-report"}})

    def __call__(self, quote_bytes: bytes, reportdata_64: bytes) -> tuple[str, str]:
        rec = self.verdicts.get(hashlib.sha256(quote_bytes).hexdigest())
        if rec is None:
            raise VerificationFailed("no recorded DCAP verdict for these quote bytes", "verifier-error")
        if rec["qv_result"] not in self.accept:
            raise AppraisalRejected(f"recorded quote verification result refused: {rec['qv_result']}")
        return parse_quote(quote_bytes).fields["mrtd"], json.dumps(rec, sort_keys=True)


@dataclass(frozen=True)
class UnappraisedForTesting:
    """An appraiser that skips the signature chain, for structural tests. It refuses by default."""

    i_know: bool = False

    def __call__(self, quote_bytes: bytes, reportdata_64: bytes) -> tuple[str, str]:
        if not self.i_know:
            raise VerificationFailed("no DCAP appraisal configured (fail closed)", "no-appraiser")
        return parse_quote(quote_bytes).fields["mrtd"], json.dumps({"qv_result": "NOT_APPRAISED"})


# --- the TDX verifier ---------------------------------------------------------

@dataclass
class TdxVerifier:
    """Establishes a CoCo Attestation Agent evidence document as a genuine TDX quote."""

    appraise: Optional[Appraiser] = None

    def verify(self, evidence: Evidence) -> VerifiedClaims:
        """Check the structure, then the hardware binding, then the DCAP appraisal, and return the claims.

        Raises:
            VerificationFailed: any of the three steps fails. No partial claims are returned.
        """
        if len(evidence.runtime_data) != 32:
            raise VerificationFailed(f"runtime_data must be 32 bytes, got {len(evidence.runtime_data)}",
                                     "quote-malformed")
        try:
            quote_buf, _ccel = parse_aa_evidence(evidence.blob)
            quote = parse_quote(quote_buf)
        except QuoteMalformed as exc:
            raise VerificationFailed(str(exc), "quote-malformed") from exc

        # Hardware binding. The AA copies the runtime_data query string unchanged into
        # REPORTDATA, so the expected bytes are the 64 ASCII characters of its hex form,
        # which fill the 64 bytes REPORTDATA holds.
        expected = evidence.runtime_data.hex().encode()
        if not secrets.compare_digest(quote.reportdata, expected):
            raise VerificationFailed("REPORTDATA does not carry the requested runtime_data", "reportdata-mismatch")

        appraise = self.appraise or UnappraisedForTesting()
        try:
            measurement, appraisal_json = appraise(quote.quote_bytes, quote.reportdata)
        except VerificationFailed:
            raise
        except Exception as exc:                                # noqa: BLE001 (classified and re-raised)
            raise VerificationFailed(f"quote appraisal failed: {exc}", classify_appraisal_error(exc)) from exc
        if measurement != quote.fields["mrtd"]:
            raise VerificationFailed("appraiser and quote disagree about MRTD", "verifier-error")

        return _claims_from_quote(quote, evidence.runtime_data, _as_dict(appraisal_json))


def _as_dict(appraisal_json: str) -> dict:
    try:
        return json.loads(appraisal_json)
    except Exception:                                           # noqa: BLE001 (kept raw for the record)
        return {"raw": appraisal_json}


def _claims_from_quote(quote: TdxQuote, runtime_data: bytes, appraisal: dict) -> VerifiedClaims:
    """Read the claims the Authority pins.

    MROWNER is not among them, because it differs per instance on GCE and pinning it would
    refuse every new pod VM.
    """
    boot = {k: quote.fields[k] for k in ("rtmr0", "rtmr1", "rtmr2", "mrseam",
                                         "tee_tcb_svn", "xfam", "tdattributes")}
    # MRCONFIGID carries the init-data hash where the platform fills it. On GCE it stays
    # zero, which is why the init-data is measured into RTMR3 instead.
    init_data_hash = None if quote.is_zero("mrconfigid") else quote.fields["mrconfigid"]
    rtmr3 = None if quote.is_zero("rtmr3") else quote.raw_field("rtmr3")
    return VerifiedClaims(platform="tdx", measurement=quote.fields["mrtd"], runtime_data=runtime_data,
                          rtmr3=rtmr3, boot_measurements=boot, init_data_hash=init_data_hash,
                          appraisal=dict(appraisal, quote_len=quote.quote_len))
