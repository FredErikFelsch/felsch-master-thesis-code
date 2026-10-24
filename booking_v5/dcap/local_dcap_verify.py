"""Local DCAP quote verification: the appraisal step without Intel Trust Authority.

`local_dcap_appraiser()` builds the appraiser callable. It calls Intel's official DCAP Quote
Verification Library (`libsgx-dcap-quote-verify`, package version 1.27.101.1-noble1) through
ctypes. This file only reads metadata from the quote (measurement, REPORTDATA, FMSPC, the
embedded PCK certificate chain). It checks no signature and no certificate chain itself,
`tdx_qv_verify_quote()` from the Intel library does. This keeps hand-written cryptographic
code out of the security path.

The struct layouts and function signatures below are copied from the headers installed on a
GCP TDX cVM:

    sgx_dcap_quoteverify.h   tdx_qv_verify_quote() signature
    sgx_ql_lib_common.h      sgx_ql_qve_collateral_t / tdx_ql_qv_collateral_t (an alias, see
                             the file), quote3_error_t
    sgx_quote_4.h            sgx_quote4_header_t, sgx_report2_body_t (the field offsets for
                             mr_td and report_data below were cross-checked against a real
                             quote of that cVM)

The one exception is `sgx_ql_qv_result_t` (the result codes). It lives in sgx_qve_header.h,
which was not among the collected headers. The values come from Intel's official public
repository (github.com/intel/SGXDataCenterAttestationPrimitives, tag DCAP_1.22,
QuoteVerification/QvE/Include/sgx_qve_header.h). They are plain integer constants without
struct layouts, so the risk of change is low.

REPORTDATA and the measurement are both read from the raw quote by struct offset, not from
JWT claims (there is no JWT here and no appraisal authority is needed).

QvE versus QVL mode: `p_qve_report_info` is passed as NULL (QVL mode). The
verification then runs entirely in a normal host process, without the verifier itself running
in an SGX enclave. Intel's documentation points out that in this mode the result is not
additionally attested by a QvE report. The quote signature chain and the TCB status are still
checked completely against the collateral data. That is sufficient here, because the binding
to the hardware runs through MRTD and REPORTDATA in the quote itself and not through an
additional QvE report.

Setup (on the cVM):
    sudo apt-get install libsgx-dcap-quote-verify libsgx-dcap-default-qpl
    pip install cryptography pyasn1 requests

    from booking_v5.dcap.local_dcap_verify import local_dcap_appraiser
    appraise = local_dcap_appraiser()    # (quote, report_data_64) -> (measurement_hex, json)

The collateral comes from `local_dcap_collateral.PCSCollateralClient` or, in V5, from the cache
in `booking_v5/collateral_cache.py`. `booking_v5/verifier.py` wraps the appraiser in
`TdxVerifier`.
"""

from __future__ import annotations

import base64
import ctypes
import json
import os
import re
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID

from .local_dcap_collateral import PCSCollateralClient

# --------------------------------------------------------------------------- #
# Quote layout (sgx_quote_4.h, checked against a real quote of this cVM): the header is
# 48 B, report_body 584 B, signature_data_len sits at offset 632, the quote length is
# 636 + signature_data_len, and the rest is ConfigFS zero padding. booking_v5/tdx_quote.py
# holds the project's own copy of these offsets, which agrees with this one.
# --------------------------------------------------------------------------- #
_HEADER_LEN = 48
_MR_TD_OFFSET = _HEADER_LEN + 136
_MR_TD_LEN = 48
_REPORT_DATA_OFFSET = _HEADER_LEN + 520
_REPORT_DATA_LEN = 64
_SIG_LEN_OFFSET = _HEADER_LEN + 584

_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)

# SGX/TDX extension in the PCK certificate (OID 1.2.840.113741.1.13.1). The FMSPC is
# sub-OID .4. Structure: SEQUENCE OF SEQUENCE{OID, ANY}, see the PCK certificate spec.
_FMSPC_OID = "1.2.840.113741.1.13.1.4"


@dataclass(frozen=True)
class ParsedTdxQuote:
    """Only the fields the appraiser itself needs. No cryptographic checking.

    Attributes:
        quote_bytes: Exact quote length (ConfigFS zero padding cut off).
        mr_td: 48-byte SHA-384 measurement of the TD (what gets pinned).
        report_data: The 64 bound REPORTDATA bytes from the quote.
        pck_chain_pem: Embedded PCK certificate chain (leaf, intermediate, root).
        fmspc: 6-byte platform identifier, hex, from the leaf certificate.
    """
    quote_bytes: bytes
    mr_td: bytes
    report_data: bytes
    pck_chain_pem: bytes
    fmspc: str


def _extract_fmspc(sgx_ext_der: bytes) -> str:
    """Read the FMSPC from the composite SGX/TDX certificate extension.

    The extension is itself a SEQUENCE OF SEQUENCE{OID, ANY} with several sub-values (PPID,
    TCB, PCEID, FMSPC, SGX type, ...). Checked empirically against the real PCK certificate
    of this cVM.
    """
    from pyasn1.codec.der.decoder import decode
    from pyasn1.type import univ

    seq, _ = decode(sgx_ext_der, asn1Spec=univ.Sequence())
    for i in range(len(seq)):
        entry = seq[i]
        if str(entry[0]) == _FMSPC_OID:
            return bytes(entry[1]).hex()
    raise ValueError("FMSPC sub-OID (...13.1.4) not found in the SGX extension")


def parse_tdx_quote(raw: bytes) -> ParsedTdxQuote:
    """Parse a TDX ECDSA quote v4 (sgx_quote_4.h), read-only.

    Args:
        raw: The raw quote as generated in the guest. It can be longer than the actual
            quote (ConfigFS buffer padding) and is cut off using ``signature_data_len``.

    Raises:
        ValueError: Wrong quote format, wrong TEE type, or no embedded PCK chain or FMSPC
            can be found.
    """
    version, _att_key_type, tee_type = struct.unpack_from("<HHI", raw, 0)
    if version != 4:
        raise ValueError(f"only TDX ECDSA quote v4 is supported, found version={version}")
    if tee_type != 0x81:
        raise ValueError(f"not a TDX quote (tee_type=0x{tee_type:02x}, expected 0x81)")

    (sig_len,) = struct.unpack_from("<I", raw, _SIG_LEN_OFFSET)
    true_len = _SIG_LEN_OFFSET + 4 + sig_len
    quote = raw[:true_len]

    mr_td = quote[_MR_TD_OFFSET: _MR_TD_OFFSET + _MR_TD_LEN]
    report_data = quote[_REPORT_DATA_OFFSET: _REPORT_DATA_OFFSET + _REPORT_DATA_LEN]

    certs = _PEM_CERT.findall(quote)
    if not certs:
        raise ValueError(
            "no PEM certificate chain found in the quote. "
            "certification_data probably does not embed the full PCK chain "
            "(cert_key_type != PCK_CERT_CHAIN)"
        )
    chain_pem = b"\n".join(certs)

    leaf = x509.load_pem_x509_certificate(certs[0])
    fmspc = None
    for ext in leaf.extensions:
        if ext.oid.dotted_string == "1.2.840.113741.1.13.1":
            fmspc = _extract_fmspc(bytes(ext.value.value))
            break
    if fmspc is None:
        raise ValueError("no SGX/TDX extension (...13.1) found in the PCK leaf certificate")

    return ParsedTdxQuote(quote, mr_td, report_data, chain_pem, fmspc)


def _ca_type_from_chain(chain_pem: bytes) -> str:
    """Determine 'processor' or 'platform' from the real issuer in the quote.

    There is no guessed default. GCP TDX cVMs showed the issuer 'Intel SGX PCK Platform CA',
    other environments can deliver Processor CA certificates, so the type is read from the
    chain instead of being hard-coded.
    """
    leaf = x509.load_pem_x509_certificate(_PEM_CERT.findall(chain_pem)[0])
    issuer_cn = leaf.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if "Platform CA" in issuer_cn:
        return "platform"
    if "Processor CA" in issuer_cn:
        return "processor"
    raise ValueError(f"unknown PCK CA type in the certificate issuer: {issuer_cn!r}")


def _fetch_root_ca_crl(chain_pem: bytes) -> bytes:
    """Fetch the root CA CRL and return it as raw DER.

    The URL is the CRL distribution point of the intermediate certificate, checked against
    `ALLOWED_ROOT_CA_CRL_URLS`. There is no PEM re-encoding. sgx_ql_qve_collateral_t.version
    is set to major_version=3 (see _build_collateral), which according to the struct comment
    in sgx_ql_lib_common.h expects raw binary or base16 DER, no PEM. The ``x509.load_der_x509_crl`` call is only a sanity
    check that the answer really is a valid CRL. Its result is discarded and the raw bytes
    are returned.
    """
    resp = requests.get(_root_ca_crl_url(chain_pem), timeout=20, allow_redirects=False)
    resp.raise_for_status()
    x509.load_der_x509_crl(resp.content)  # sanity check, raises on invalid DER
    return resp.content


#: The pinned URLs the root CA CRL may be fetched from. It is a set so that a second Intel
#: endpoint can be added here. A URL taken from a certificate alone is refused.
ALLOWED_ROOT_CA_CRL_URLS = frozenset({"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"})


def _root_ca_crl_url(chain_pem: bytes) -> str:
    """Return the root CA's CRL distribution point URL from the intermediate certificate.

    V5 modification: split out so that a caching collateral source can use the URL as its key,
    see booking_v5/collateral_cache.py and PROVENANCE.md.

    Raises:
        ValueError: the chain has no intermediate certificate, or the URL is not pinned.
    """
    certs = _PEM_CERT.findall(chain_pem)
    if len(certs) < 2:
        raise ValueError("chain holds no intermediate certificate, so no CRL distribution point is available")
    intermediate = x509.load_pem_x509_certificate(certs[1])
    cdp = intermediate.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    url = cdp.value[0].full_name[0].value
    # The chain comes out of the quote, so this value is chosen by whoever produced the quote
    # and is read before any quote verification. Only the pinned Intel URL may be fetched
    # (V5 modification, see PROVENANCE.md).
    if url not in ALLOWED_ROOT_CA_CRL_URLS:
        raise ValueError(f"CRL distribution point {url!r} is not a pinned Intel URL")
    return url


# --------------------------------------------------------------------------- #
# ctypes binding against libsgx-dcap-quote-verify (sgx_dcap_quoteverify.h,
# sgx_ql_lib_common.h, package version 1.27.101.1-noble1, copied from the headers)
# --------------------------------------------------------------------------- #

class _VersionSplit(ctypes.Structure):
    _fields_ = [("major_version", ctypes.c_uint16), ("minor_version", ctypes.c_uint16)]


class _VersionUnion(ctypes.Union):
    _fields_ = [("version", ctypes.c_uint32), ("split", _VersionSplit)]


class TdxQlQvCollateralT(ctypes.Structure):
    """Matches ``sgx_ql_qve_collateral_t`` == ``tdx_ql_qv_collateral_t`` (an alias,
    sgx_ql_lib_common.h line 270), in the header's field order. It lies outside the
    ``#pragma pack(1)`` region of the header file, so it has natural alignment and no
    ``_pack_`` is given.
    """
    _anonymous_ = ("_version",)
    _fields_ = [
        ("_version", _VersionUnion),
        ("tee_type", ctypes.c_uint32),
        ("pck_crl_issuer_chain", ctypes.c_char_p),
        ("pck_crl_issuer_chain_size", ctypes.c_uint32),
        ("root_ca_crl", ctypes.c_char_p),
        ("root_ca_crl_size", ctypes.c_uint32),
        ("pck_crl", ctypes.c_char_p),
        ("pck_crl_size", ctypes.c_uint32),
        ("tcb_info_issuer_chain", ctypes.c_char_p),
        ("tcb_info_issuer_chain_size", ctypes.c_uint32),
        ("tcb_info", ctypes.c_char_p),
        ("tcb_info_size", ctypes.c_uint32),
        ("qe_identity_issuer_chain", ctypes.c_char_p),
        ("qe_identity_issuer_chain_size", ctypes.c_uint32),
        ("qe_identity", ctypes.c_char_p),
        ("qe_identity_size", ctypes.c_uint32),
    ]


# quote3_error_t (sgx_ql_lib_common.h): TEE_MK_ERROR(x) = 0xE000|x
SGX_QL_SUCCESS = 0x0000

# sgx_ql_qv_result_t (sgx_qve_header.h, Intel GitHub tag DCAP_1.22, not part of the
# locally collected header set): TEE_QV_MK_ERROR(x) = 0xA000|x
SGX_QL_QV_RESULT_OK = 0x0000
SGX_QL_QV_RESULT_CONFIG_NEEDED = 0xA001
SGX_QL_QV_RESULT_OUT_OF_DATE = 0xA002
SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED = 0xA003
SGX_QL_QV_RESULT_INVALID_SIGNATURE = 0xA004
SGX_QL_QV_RESULT_REVOKED = 0xA005
SGX_QL_QV_RESULT_UNSPECIFIED = 0xA006
SGX_QL_QV_RESULT_SW_HARDENING_NEEDED = 0xA007
SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED = 0xA008
SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED = 0xA009
SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED = 0xA00A

_QV_RESULT_NAMES = {
    SGX_QL_QV_RESULT_OK: "OK",
    SGX_QL_QV_RESULT_CONFIG_NEEDED: "CONFIG_NEEDED",
    SGX_QL_QV_RESULT_OUT_OF_DATE: "OUT_OF_DATE",
    SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED: "OUT_OF_DATE_CONFIG_NEEDED",
    SGX_QL_QV_RESULT_INVALID_SIGNATURE: "INVALID_SIGNATURE",
    SGX_QL_QV_RESULT_REVOKED: "REVOKED",
    SGX_QL_QV_RESULT_UNSPECIFIED: "UNSPECIFIED",
    SGX_QL_QV_RESULT_SW_HARDENING_NEEDED: "SW_HARDENING_NEEDED",
    SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED: "CONFIG_AND_SW_HARDENING_NEEDED",
    SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED: "TD_RELAUNCH_ADVISED",
    SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED: "TD_RELAUNCH_ADVISED_CONFIG_NEEDED",
}

# Fail closed by default: only a flawless result is accepted. Whoever wants to allow TCB
# grace periods passes a more permissive `accept_results`.
DEFAULT_ACCEPTED_QV_RESULTS = frozenset({SGX_QL_QV_RESULT_OK})


def _load_library(path: Optional[str] = None) -> ctypes.CDLL:
    """Load libsgx-dcap-quote-verify, with or without an explicit path.

    The real file name was determined with ``dpkg -L libsgx-dcap-quote-verify | grep .so`` on a
    real GCP TDX cVM: ``libsgx_dcap_quoteverify.so.1`` ("quoteverify" as one word, no
    underscore between quote and verify, unlike the package name
    ``libsgx-dcap-quote-verify``). The SONAME candidate comes first (works when ldconfig knows
    the path), the multiarch path is the fallback.
    """
    candidates = [path] if path else [
        "libsgx_dcap_quoteverify.so.1",
        "libsgx_dcap_quoteverify.so",
        "/usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1",
        "/usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so",
    ]
    last_exc: Optional[OSError] = None
    for name in candidates:
        if name is None:
            continue
        try:
            return ctypes.CDLL(name)
        except OSError as exc:
            last_exc = exc
    raise RuntimeError(
        "cannot load libsgx-dcap-quote-verify. Find the real path with "
        "'dpkg -L libsgx-dcap-quote-verify | grep .so' and pass it as lib_path= to "
        "local_dcap_appraiser()."
    ) from last_exc


def _bind_verify_quote(lib: ctypes.CDLL):
    """Set argtypes and restype for tdx_qv_verify_quote (sgx_dcap_quoteverify.h)."""
    lib.tdx_qv_verify_quote.argtypes = [
        ctypes.c_char_p,                          # p_quote
        ctypes.c_uint32,                           # quote_size
        ctypes.POINTER(TdxQlQvCollateralT),        # p_quote_collateral
        ctypes.c_int64,                            # expiration_check_date (time_t)
        ctypes.POINTER(ctypes.c_uint32),           # p_collateral_expiration_status
        ctypes.POINTER(ctypes.c_int),              # p_quote_verification_result
        ctypes.c_void_p,                           # p_qve_report_info (NULL = QVL mode)
        ctypes.c_uint32,                           # supplemental_data_size
        ctypes.c_void_p,                           # p_supplemental_data (optional)
    ]
    lib.tdx_qv_verify_quote.restype = ctypes.c_int
    return lib.tdx_qv_verify_quote


def _bind_supplemental_size(lib: ctypes.CDLL):
    """Bind ``tdx_qv_get_quote_supplemental_data_size(uint32_t*)`` (sgx_dcap_quoteverify.h).

    Returns:
        The bound function, or None if the library does not export it. No supplemental
        data is read then.
    """
    fn = getattr(lib, "tdx_qv_get_quote_supplemental_data_size", None)
    if fn is None:
        return None
    fn.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
    fn.restype = ctypes.c_int
    return fn


_SA_ID = re.compile(rb"INTEL-SA-\d{5}")


def parse_supplemental(buf: bytes) -> dict:
    """Read the fields of ``sgx_ql_qv_supplemental_t`` that go into the run record.

    The struct is that of sgx_qve_header.h, DCAP 1.22, struct version 3. Read are the four
    ``time_t`` dates behind the 4-byte version union (natural alignment, offsets 8, 16, 24
    and 32), ``tcb_eval_ref_num`` (48) and the advisory ids, which are found by pattern in
    ``sa_list`` wherever the tail of the struct puts it. The values are recorded only and
    do not enter the accept decision, which stays ``qv_result == OK``.
    """
    if len(buf) < 52:
        return {"version": None, "raw_len": len(buf)}
    def t(off: int) -> Optional[str]:
        """Return a ``time_t`` as ISO 8601, or None when unset or not renderable.

        Record-only data should not turn an OK quote into a verifier error, so an absurd
        value is recorded as absent instead of raising.
        """
        value = int.from_bytes(buf[off:off + 8], "little", signed=True)
        if value <= 0:
            return None
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OverflowError, OSError, ValueError):
            return None
    return {
        "version": int.from_bytes(buf[0:4], "little"),
        "earliest_issue_date": t(8), "latest_issue_date": t(16),
        "earliest_expiration_date": t(24), "tcb_level_date_tag": t(32),
        "tcb_eval_ref_num": int.from_bytes(buf[48:52], "little"),
        "advisory_ids": sorted({m.decode() for m in _SA_ID.findall(buf)}),
        "raw_len": len(buf),
    }


#: Tolerance for normal clock drift when comparing with ``issueDate``. Large enough for a
#: badly synchronised VM clock, small enough that a rollback attack does not fit into it.
_CLOCK_SKEW_S = 300


def _parse_pcs_date(raw: str) -> float:
    """Convert a PCS timestamp (ISO 8601 with Z) to Unix time."""
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    ).timestamp()


def _assert_collateral_dates(tcb_body: bytes, qe_body: bytes, now: int) -> None:
    """Check issue and expiry of the collateral against the verification time.

    These are two independent checks next to the ``collateral_expired`` flag of the Intel
    library. They do not replace it. The library takes its verification time from the caller,
    so it cannot detect a manipulated clock.

    ``nextUpdate`` in the past
        The collateral has expired, the TCB level in it says nothing about the present.

    ``issueDate`` in the future
        The system time is before the moment at which Intel issued the document that was just
        downloaded. That cannot happen with a correct clock, so this check catches a clock set
        back. On a cVM the host sets the time, so it is not a trustworthy source.

    Limit of the method: an attacker who sets the clock back and also serves matching old,
    correctly signed collateral from that time produces a self-consistent picture. Closing it
    would need a time source outside the attacker's control, for example a signed timestamp
    from the relying party, which this module does not have.

    Args:
        tcb_body: Raw TCB info body from PCS.
        qe_body: Raw QE identity body from PCS.
        now: Verification time, the same one that goes to the library.

    Raises:
        RuntimeError: Collateral expired or system time implausible. The message contains
            "collateral", which `booking_v5.verifier.classify_appraisal_error` maps to
            collateral-unavailable.
    """
    documents = (
        ("TCB Info", json.loads(tcb_body).get("tcbInfo", {})),
        ("QE Identity", json.loads(qe_body).get("enclaveIdentity", {})),
    )
    for label, body in documents:
        next_update = body.get("nextUpdate")
        if next_update and now > _parse_pcs_date(next_update):
            raise RuntimeError(
                f"{label} collateral has expired (nextUpdate {next_update})"
            )

        issue_date = body.get("issueDate")
        if issue_date and now + _CLOCK_SKEW_S < _parse_pcs_date(issue_date):
            raise RuntimeError(
                f"system time is before the issueDate of the {label} collateral "
                f"({issue_date}). The cVM clock was probably set back."
            )


def _nul_terminated(data: bytes) -> bytes:
    """Append a NUL terminator unless one is already present.

    The QVL checks every text collateral field (the three issuer chains, TCB info, QE
    identity) with::

        #define IS_IN_ENCLAVE_POINTER(p, size) \\
            (p && (strnlen(p, size) == size - 1) && sgx_is_within_enclave(p, size))

    (Intel DCAP, ``ae/QvE/qve/qve.cpp``, ``is_collateral_deep_copied``). The size must
    therefore count the terminator. If this one byte is missing, the parameter check fails
    before any check of the content, and ``tdx_qv_verify_quote`` returns the failure seen in
    practice: ``ret=0xe002`` (SGX_QL_ERROR_INVALID_PARAMETER), ``qv_result=0xa006``
    (UNSPECIFIED) and ``collateral_expired=1``. These three values are the defensive defaults
    for the outputs at the start of the function, not the result of a real check.

    The two CRL fields are excluded. They are only checked with ``sgx_is_within_enclave``.
    They are passed as raw DER, which may contain NUL bytes, with their exact size. A counted
    terminator byte would corrupt the DER there.
    """
    return data if data.endswith(b"\x00") else data + b"\x00"


def _build_collateral(
    parsed: ParsedTdxQuote, pcs: PCSCollateralClient, now: Optional[int] = None
) -> tuple[TdxQlQvCollateralT, list]:
    """Fetch the collateral from PCS plus the root CA CRL and fill the ctypes struct.

    Args:
        parsed: The parsed quote, supplies the FMSPC and the PCK chain.
        pcs: Collateral source.
        now: Verification time for the date check. None takes the system time. It must be
            the same time that is later passed to the library, otherwise the clock could
            change between the two checks.

    Returns:
        The struct and the list of referenced bytes objects. ctypes keeps no reference of its
        own to Python bytes assigned through c_char_p. Without the list they would be
        garbage-collected while the C library still accesses the memory.

    Raises:
        RuntimeError: One of the three issuer chains came back empty from PCS. This happens
            when PCS renames the headers and ``_ISSUER_CHAIN_HEADERS`` no longer matches.
            Without this check it would end in ``size == 0`` and thus also in 0xe002, but
            without a hint to the cause. Also raised for expired collateral or an implausible
            system time, see ``_assert_collateral_dates``.
    """
    ca = _ca_type_from_chain(parsed.pck_chain_pem)
    crl = pcs.pck_crl(ca=ca, encoding="der")
    qe = pcs.td_qe_identity()
    tcb = pcs.tcb_info(parsed.fmspc)
    # V5 modification: a collateral source with root_ca_crl(url) (the cache) supplies the
    # root CA CRL itself. Otherwise the original direct fetch runs.
    if hasattr(pcs, "root_ca_crl"):
        root_crl_der = pcs.root_ca_crl(_root_ca_crl_url(parsed.pck_chain_pem))
        x509.load_der_x509_crl(root_crl_der)  # sanity check as in the direct fetch
    else:
        root_crl_der = _fetch_root_ca_crl(parsed.pck_chain_pem)

    for label, chain in (
        ("PCK CRL", crl.issuer_chain_pem),
        ("TCB Info", tcb.issuer_chain_pem),
        ("QE Identity", qe.issuer_chain_pem),
    ):
        if not chain.strip():
            raise RuntimeError(
                f"PCS returned no issuer chain for {label}. "
                f"Compare the header names in _ISSUER_CHAIN_HEADERS with the real "
                f"PCS response."
            )

    _assert_collateral_dates(tcb.body, qe.body,
                             int(time.time()) if now is None else now)

    # Text fields are NUL-terminated, and their size includes the terminator.
    pck_crl_chain = _nul_terminated(crl.issuer_chain_pem.encode())
    tcb_info_chain = _nul_terminated(tcb.issuer_chain_pem.encode())
    tcb_info = _nul_terminated(tcb.body)
    qe_identity_chain = _nul_terminated(qe.issuer_chain_pem.encode())
    qe_identity = _nul_terminated(qe.body)
    # CRL fields are raw DER, and their size has no terminator.
    pck_crl_der = crl.body

    keep_alive = [
        pck_crl_chain, tcb_info_chain, tcb_info,
        qe_identity_chain, qe_identity,
        pck_crl_der, root_crl_der,
    ]

    c = TdxQlQvCollateralT()
    # major_version=3, minor_version=1 == 0x00010003 == QVE_COLLATERAL_VERSOIN31
    # (sic, a typo in Intel's header sgx_qve_def.h). It means CRLs as raw binary DER,
    # matching encoding="der" in the PCS query. The 32-bit value is set by hand instead of
    # through the anonymous union, because only the outer union field is marked anonymous,
    # not its inner split.
    c.version = 3 | (1 << 16)
    c.tee_type = 0x81
    c.pck_crl_issuer_chain = pck_crl_chain
    c.pck_crl_issuer_chain_size = len(pck_crl_chain)
    c.root_ca_crl = root_crl_der
    c.root_ca_crl_size = len(root_crl_der)
    c.pck_crl = pck_crl_der
    c.pck_crl_size = len(pck_crl_der)
    c.tcb_info_issuer_chain = tcb_info_chain
    c.tcb_info_issuer_chain_size = len(tcb_info_chain)
    c.tcb_info = tcb_info
    c.tcb_info_size = len(tcb_info)
    c.qe_identity_issuer_chain = qe_identity_chain
    c.qe_identity_issuer_chain_size = len(qe_identity_chain)
    c.qe_identity = qe_identity
    c.qe_identity_size = len(qe_identity)
    return c, keep_alive


# --------------------------------------------------------------------------- #
# Debug helpers, not part of the production appraiser. They isolate, after a failure,
# whether the cause lies in the self-built collateral struct or elsewhere (basic parameter
# check before the collateral check, see tee_verify_evidence() in the official source). A
# call with p_quote_collateral=NULL lets the library fetch the collateral itself through the
# installed QPL (libsgx-dcap-default-qpl), without the self-built struct.
# --------------------------------------------------------------------------- #

def debug_verify_quote(quote: bytes, lib_path: Optional[str] = None) -> None:
    """Print raw diagnostic values and call tdx_qv_verify_quote twice.

    The first call passes NULL (QPL auto-fetch), the second the self-built collateral struct.
    For troubleshooting only, not part of the appraiser.

    Args:
        quote: Raw TDX quote as generated in the guest.
        lib_path: Explicit path to the QVL, as for `local_dcap_appraiser`.
    """
    parsed = parse_tdx_quote(quote)
    print(f"[debug] quote_bytes len         = {len(parsed.quote_bytes)}")
    print(f"[debug] quote_bytes[:16]        = {parsed.quote_bytes[:16].hex()}")
    print(f"[debug] mr_td                   = {parsed.mr_td.hex()}")
    print(f"[debug] report_data             = {parsed.report_data.hex()}")
    print(f"[debug] fmspc                   = {parsed.fmspc}")
    print(f"[debug] sizeof(TdxQlQvCollateralT) = {ctypes.sizeof(TdxQlQvCollateralT)}")

    verify_fn = _bind_verify_quote(_load_library(lib_path))
    now = int(time.time())
    print(f"[debug] expiration_check_date   = {now}")

    print("\n[debug] --- call 1: p_quote_collateral = NULL (QPL auto-fetch) ---")
    collateral_expired = ctypes.c_uint32()
    qv_result = ctypes.c_int()
    ret = verify_fn(
        parsed.quote_bytes, len(parsed.quote_bytes),
        None, now,
        ctypes.byref(collateral_expired), ctypes.byref(qv_result),
        None, 0, None,
    )
    print(f"[debug] ret (quote3_error_t)    = 0x{ret & 0xFFFFFFFF:04x}")
    print(f"[debug] qv_result               = 0x{qv_result.value & 0xFFFFFFFF:04x}")
    print(f"[debug] collateral_expired      = {collateral_expired.value}")

    print("\n[debug] --- call 2: the self-built collateral struct (PCS) ---")
    pcs = PCSCollateralClient()
    collateral, _keep_alive = _build_collateral(parsed, pcs)
    print(f"[debug] collateral.version      = 0x{collateral.version:08x}")
    print(f"[debug] collateral.tee_type     = 0x{collateral.tee_type:02x}")
    print(f"[debug] pck_crl_size            = {collateral.pck_crl_size} (DER, exact)")
    print(f"[debug] root_ca_crl_size        = {collateral.root_ca_crl_size} (DER, exact)")
    print(f"[debug] pck_crl_issuer_chain    = {collateral.pck_crl_issuer_chain_size} (incl. NUL)")
    print(f"[debug] tcb_info_issuer_chain   = {collateral.tcb_info_issuer_chain_size} (incl. NUL)")
    print(f"[debug] tcb_info_size           = {collateral.tcb_info_size} (incl. NUL)")
    print(f"[debug] qe_identity_issuer_chain= {collateral.qe_identity_issuer_chain_size} (incl. NUL)")
    print(f"[debug] qe_identity_size        = {collateral.qe_identity_size} (incl. NUL)")
    collateral_expired2 = ctypes.c_uint32()
    qv_result2 = ctypes.c_int()
    ret2 = verify_fn(
        parsed.quote_bytes, len(parsed.quote_bytes),
        ctypes.byref(collateral), now,
        ctypes.byref(collateral_expired2), ctypes.byref(qv_result2),
        None, 0, None,
    )
    print(f"[debug] ret (quote3_error_t)    = 0x{ret2 & 0xFFFFFFFF:04x}")
    print(f"[debug] qv_result               = 0x{qv_result2.value & 0xFFFFFFFF:04x}")
    print(f"[debug] collateral_expired      = {collateral_expired2.value}")


def dump_for_c_test(quote: bytes, out_dir: str = "/tmp/dcap_c_test") -> None:
    """Write the quote and all collateral parts as raw files for a small C harness.

    The harness is not part of this repository. It reads these files and calls
    tdx_qv_verify_quote() through Intel's headers, without a ctypes struct replica, which
    separates a ctypes marshalling error from a real data or environment problem. This uses
    the same PCS calls as _build_collateral(), but writes the raw bytes instead of packing
    them into a ctypes struct. ``pck_chain.pem`` is also written for openssl sanity checks.
    The library itself reads the PCK chain from the quote, not from this file.

    Args:
        quote: Raw TDX quote as generated in the guest.
        out_dir: Target directory on the cVM, which the harness reads.
    """
    os.makedirs(out_dir, exist_ok=True)
    parsed = parse_tdx_quote(quote)
    pcs = PCSCollateralClient()

    ca = _ca_type_from_chain(parsed.pck_chain_pem)
    crl = pcs.pck_crl(ca=ca, encoding="der")
    qe = pcs.td_qe_identity()
    tcb = pcs.tcb_info(parsed.fmspc)
    root_crl_der = _fetch_root_ca_crl(parsed.pck_chain_pem)

    files = {
        "quote.bin": parsed.quote_bytes,
        "pck_chain.pem": parsed.pck_chain_pem,
        "pck_crl.bin": crl.body,
        "pck_crl_chain.txt": crl.issuer_chain_pem.encode(),
        "root_ca_crl.bin": root_crl_der,
        "tcb_info.json": tcb.body,
        "tcb_info_chain.txt": tcb.issuer_chain_pem.encode(),
        "qe_identity.json": qe.body,
        "qe_identity_chain.txt": qe.issuer_chain_pem.encode(),
    }
    for name, data in files.items():
        path = os.path.join(out_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"[dump] {path}: {len(data)} bytes")


# --------------------------------------------------------------------------- #
# Appraiser: the callable `TdxVerifier` takes as its `appraise` argument
# --------------------------------------------------------------------------- #

def local_dcap_appraiser(
    pcs: Optional[PCSCollateralClient] = None,
    accept_results: frozenset = DEFAULT_ACCEPTED_QV_RESULTS,
    lib_path: Optional[str] = None,
) -> Callable[[bytes, bytes], tuple[str, str]]:
    """Build the local appraisal step, which needs no Intel Trust Authority.

    It returns a callable ``(quote, report_data_64) -> (measurement_hex, evidence_json)``, the
    signature `booking_v5.verifier.TdxVerifier` expects for `appraise`. Measurement and
    REPORTDATA come directly from the quote, not from JWT claims of an appraisal authority.

    Args:
        pcs: Collateral source. Default: ``PCSCollateralClient()`` (reads
            ``PCS_API_KEY`` and ``PCS_BASE_URL`` from the environment).
        accept_results: Set of accepted ``sgx_ql_qv_result_t`` values. Strict by default:
            only ``SGX_QL_QV_RESULT_OK``.
        lib_path: Explicit path to libsgx_dcap_quoteverify.so.1, if it cannot be found
            through the default load path.

    Returns:
        The callable ``(quote, report_data_64) -> (measurement_hex, evidence_json)``.

    Raises:
        RuntimeError: the library cannot be loaded.
    """
    pcs = pcs or PCSCollateralClient()
    lib = _load_library(lib_path)
    verify_fn = _bind_verify_quote(lib)
    size_fn = _bind_supplemental_size(lib)

    def _appraise(quote: bytes, report_data_64: bytes) -> tuple[str, str]:
        parsed = parse_tdx_quote(quote)

        if not secrets.compare_digest(parsed.report_data, report_data_64):
            raise RuntimeError(
                "quote REPORTDATA does not match the given REPORTDATA, "
                "quote refused"
            )

        # One time for both checks, the date check in _build_collateral and the library. Two
        # separate calls of time.time() would leave a window in which the clock can change.
        now = int(time.time())
        collateral, _keep_alive = _build_collateral(parsed, pcs, now)

        collateral_expired = ctypes.c_uint32()
        qv_result = ctypes.c_int()
        # Supplemental data: sized by the library, parsed for the record only. If the
        # library cannot size it, verify without it. The accept decision is unchanged.
        supp_buf, supp_size = None, 0
        if size_fn is not None:
            size = ctypes.c_uint32()
            if size_fn(ctypes.byref(size)) == SGX_QL_SUCCESS and size.value:
                supp_size = size.value
                supp_buf = ctypes.create_string_buffer(supp_size)
        ret = verify_fn(
            parsed.quote_bytes, len(parsed.quote_bytes),
            ctypes.byref(collateral),
            now,
            ctypes.byref(collateral_expired),
            ctypes.byref(qv_result),
            None, supp_size, ctypes.cast(supp_buf, ctypes.c_void_p) if supp_buf is not None else None,
        )
        if ret != SGX_QL_SUCCESS:
            raise RuntimeError(f"tdx_qv_verify_quote failed: quote3_error_t=0x{ret:04x}")
        if collateral_expired.value:
            raise RuntimeError("verification collateral (CRL/TCB Info) has expired")

        result_name = _QV_RESULT_NAMES.get(qv_result.value, f"0x{qv_result.value:04x}")
        supplemental = parse_supplemental(supp_buf.raw) if supp_buf is not None else None
        if qv_result.value not in accept_results:
            advisories = (supplemental or {}).get("advisory_ids") or []
            raise RuntimeError(f"quote verification result refused: {result_name}"
                               + (f" (advisories: {', '.join(advisories)})" if advisories else ""))

        measurement = parsed.mr_td.hex()
        evidence = json.dumps({
            "qv_result": result_name,
            "fmspc": parsed.fmspc,
            "supplemental": supplemental,
            "quote_b64": base64.b64encode(parsed.quote_bytes).decode(),
        })
        return measurement, evidence

    return _appraise