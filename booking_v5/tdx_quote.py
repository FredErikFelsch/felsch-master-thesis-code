"""TDX quote v4 layout for the project's own code.

The offline probe analysis (`scripts/gke-v5/20_verify_evidence_offline.py`), the Authority's
verifier and the fixture tests import it from here. The vendored DCAP module keeps its own
copy of the few offsets it needs, which agree with these. This module only reads and checks
no signature. The signature chain and the TCB status are established by Intel's DCAP library
through `booking_v5/dcap/local_dcap_verify.py`.

Offsets come from the Intel DCAP Quote Library API (TD report body 1.0, 584 bytes) and were
checked byte for byte against live GCE TDX quotes. The Attestation Agent returns a fixed
8000-byte buffer. The quote ends after the signature and the rest must be zero padding.
"""
from __future__ import annotations

import base64
import json
import struct
from dataclasses import dataclass, field

HDR_LEN = 48
TEE_TYPE_TDX = 0x81
SIGLEN_OFF = 632

#: field name -> (offset from the start of the quote, length in bytes)
BODY: dict[str, tuple[int, int]] = {
    "tee_tcb_svn": (48, 16), "mrseam": (64, 48), "mrsignerseam": (112, 48), "seamattributes": (160, 8),
    "tdattributes": (168, 8), "xfam": (176, 8), "mrtd": (184, 48), "mrconfigid": (232, 48),
    "mrowner": (280, 48), "mrownerconfig": (328, 48), "rtmr0": (376, 48), "rtmr1": (424, 48),
    "rtmr2": (472, 48), "rtmr3": (520, 48), "reportdata": (568, 64),
}

#: TCG digest sizes by TPM_ALG_ID (SHA1, SHA256, SHA384, SHA512), for the CCEL event log.
DIGEST_LEN = {0x4: 20, 0xB: 32, 0xC: 48, 0xD: 64}


class QuoteMalformed(ValueError):
    """The bytes are not a well-formed TDX ECDSA quote v4."""


@dataclass(frozen=True)
class TdxQuote:
    """The verifier-relevant view of one quote. `fields` values are hex strings."""

    version: int
    att_key_type: int
    tee_type: int
    quote_len: int
    buffer_len: int
    fields: dict[str, str]
    raw: bytes = field(repr=False, default=b"")

    def hex(self, name: str) -> str:
        """Return the hex string of one body field."""
        return self.fields[name]

    def raw_field(self, name: str) -> bytes:
        """Return the bytes of one body field."""
        return bytes.fromhex(self.fields[name])

    @property
    def reportdata(self) -> bytes:
        """The 64 REPORTDATA bytes the guest asked the hardware to bind."""
        return self.raw_field("reportdata")

    @property
    def quote_bytes(self) -> bytes:
        """The quote without the Attestation Agent's zero padding (what DCAP verifies)."""
        return self.raw[: self.quote_len]

    def is_zero(self, name: str) -> bool:
        """True when a body field is all zero, i.e. the platform left it unset."""
        return set(self.fields[name]) == {"0"}


def parse_quote(buf: bytes) -> TdxQuote:
    """Parse header and TD10 report body, and truncate the trailing zero padding.

    Raises:
        QuoteMalformed: wrong version, wrong TEE type, signature length outside the
            buffer, or non-zero bytes behind the signature (a hiding place for data).
    """
    if len(buf) < SIGLEN_OFF + 4:
        raise QuoteMalformed(f"buffer too short for a TDX quote v4: {len(buf)} B")
    version, att_key_type, tee_type = struct.unpack_from("<HHI", buf, 0)
    if version != 4 or tee_type != TEE_TYPE_TDX:
        raise QuoteMalformed(f"not a TDX quote v4 (version={version}, tee_type={tee_type:#x})")
    sig_len = struct.unpack_from("<I", buf, SIGLEN_OFF)[0]
    quote_len = SIGLEN_OFF + 4 + sig_len
    if quote_len > len(buf):
        raise QuoteMalformed(f"signature length {sig_len} exceeds buffer {len(buf)}")
    if any(buf[quote_len:]):
        raise QuoteMalformed("bytes after the signature are not zero padding")
    fields = {name: buf[off: off + ln].hex() for name, (off, ln) in BODY.items()}
    return TdxQuote(version, att_key_type, tee_type, quote_len, len(buf), fields, bytes(buf))


def ccel_events(el: bytes) -> list[tuple[int, int, list[bytes], bytes]]:
    """Parse a TCG2 crypto-agile event log into [(mr_index, event_type, digests, data)].

    CCEL index mapping on TDX: 0 = MRTD, 1 = RTMR0, 2 = RTMR1, 3 = RTMR2, 4 = RTMR3.
    The result is informational. The V5 relying party replays RTMR3 instead of trusting a log.
    """
    events = []
    size = struct.unpack_from("<I", el, 28)[0]      # first record: TCG_PCClientPCREvent (SHA1 header)
    off = 32 + size
    while off + 12 <= len(el):
        idx, typ, n = struct.unpack_from("<III", el, off)
        off += 12
        digests = []
        for _ in range(n):
            alg = struct.unpack_from("<H", el, off)[0]
            off += 2
            ln = DIGEST_LEN.get(alg, 32)
            digests.append(el[off: off + ln])
            off += ln
        sz = struct.unpack_from("<I", el, off)[0]
        off += 4
        events.append((idx, typ, digests, el[off: off + sz]))
        off += sz
    return events


def parse_aa_evidence(blob: bytes) -> tuple[bytes, bytes | None]:
    """Split the Attestation Agent's evidence JSON into (quote bytes, CCEL bytes or None).

    Shape observed on CoCo guest-components f156103: {"quote": b64, "cc_eventlog": b64}.

    Raises:
        QuoteMalformed: the blob is not the AA's JSON or carries no quote.
    """
    try:
        d = json.loads(blob)
        quote = base64.b64decode(d["quote"])
    except Exception as exc:                                    # noqa: BLE001 (one refusal reason)
        raise QuoteMalformed(f"not an Attestation Agent evidence document: {exc}") from exc
    log = d.get("cc_eventlog")
    return quote, base64.b64decode(log) if log else None
