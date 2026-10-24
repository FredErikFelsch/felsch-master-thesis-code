"""Evidence documents and their producers: live, fake and recorded.

Inside a CoCo guest the Attestation Agent (AA) serves evidence at
`http://127.0.0.1:8006/aa/evidence?runtime_data=<hex>`. The guest components put
`runtime_data` into the TDX quote's REPORTDATA. The container needs no device and no
privilege for this. The runner does not parse the quote and forwards it as an opaque blob.
The runtime_data itself is the canonical binding of `binding.canonical_binding`.
"""
from __future__ import annotations

import base64
import json
import urllib.request
from dataclasses import dataclass
from typing import Optional, Protocol


@dataclass(frozen=True)
class Evidence:
    """Opaque evidence blob plus the runtime_data it was requested with."""

    platform: str          # "tdx" | "sev-snp" | "fake"  (as reported by the producer)
    blob: bytes            # the quote / report, opaque to the runner
    runtime_data: bytes    # what was requested (the verifier proves it is inside)

    def to_wire(self) -> dict:
        """Return the wire form, used by both the attach line and the Authority RPC.

        The blob (a real TDX quote plus CC event log is about 46 KB) travels as a list of
        base64 parts, each below `booking_v1.freeze.MAX_STR`, so every V1 wire limit stays
        as it is.
        """
        return {"platform": self.platform, "blob_parts": split_blob(self.blob),
                "runtime_data": self.runtime_data.hex()}

    @classmethod
    def from_wire(cls, d: dict) -> "Evidence":
        """Inverse of `to_wire`.

        Raises:
            ValueError: the blob parts or the runtime_data are malformed.
        """
        return cls(d["platform"], join_blob(d["blob_parts"]), bytes.fromhex(d["runtime_data"]))


BLOB_PART_CHARS = 8_000     # < booking_v1.freeze.MAX_STR (10 000)


def split_blob(raw: bytes) -> list[str]:
    """Return the base64 of `raw`, cut into parts of at most BLOB_PART_CHARS characters."""
    b64 = base64.b64encode(raw).decode()
    return [b64[i:i + BLOB_PART_CHARS] for i in range(0, len(b64), BLOB_PART_CHARS)] or [""]


def join_blob(parts: object) -> bytes:
    """Inverse of `split_blob`.

    Raises:
        ValueError: `parts` is not a list of strings, or the base64 is invalid.
    """
    if not isinstance(parts, (list, tuple)) or not all(isinstance(x, str) for x in parts):
        raise ValueError("blob_parts must be a list of strings")
    return base64.b64decode("".join(parts), validate=True)


class EvidenceProducer(Protocol):
    """Anything that can produce evidence bound to a given runtime_data."""

    def get_evidence(self, runtime_data_32: bytes) -> Evidence:
        """Return evidence over `runtime_data_32`."""
        ...


@dataclass
class AttestationAgentClient:
    """Live producer over the CoCo Attestation Agent REST API inside the guest.

    The runner does not use this class. Its client is `runner_bind.AttestationAgent`, which
    also records RTMR3 events and checks that the reply holds a quote.
    """

    base_url: str = "http://127.0.0.1:8006"
    timeout: float = 10.0

    def get_evidence(self, runtime_data_32: bytes) -> Evidence:
        """Fetch evidence from the guest's Attestation Agent over `runtime_data_32`."""
        if len(runtime_data_32) != 32:
            raise ValueError("runtime_data must be 32 bytes")
        url = f"{self.base_url}/aa/evidence?runtime_data={runtime_data_32.hex()}"
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310 (loopback only)
            body = resp.read()
        # AA returns JSON whose shape depends on the TEE. Keep it opaque.
        try:
            platform = json.loads(body).get("tee", "unknown")
        except Exception:                                       # noqa: BLE001 (the platform is a label only)
            platform = "unknown"
        return Evidence(str(platform), body, runtime_data_32)


@dataclass
class FakeAttestationAgent:
    """Offline producer: a deterministic 'quote' the FakeVerifier understands.

    The blob carries the same claims a real TDX quote yields (measurement, boot
    measurements, RTMR3, the bound runtime_data), so the relying party runs unchanged.
    `rtmr3` is a real replay value. Tests build it with `rtmr_replay.replay` over the
    AAEL lines the runner recorded, which exercises the measurement maths offline.
    """

    measurement: str = "mrtd-ref"
    platform: str = "tdx"
    rtmr3: Optional[bytes] = None
    boot_measurements: Optional[dict] = None
    init_data_hash: Optional[str] = None      # MRCONFIGID. None on GCE

    def get_evidence(self, runtime_data_32: bytes) -> Evidence:
        """Build the deterministic fake evidence document for `runtime_data_32`."""
        d = {"measurement": self.measurement, "platform": self.platform,
             "runtime_data": runtime_data_32.hex(),
             "boot_measurements": self.boot_measurements or {},
             "init_data_hash": self.init_data_hash}
        if self.rtmr3 is not None:
            d["rtmr3"] = self.rtmr3.hex()
        blob = json.dumps(d, sort_keys=True).encode()
        return Evidence(self.platform, blob, runtime_data_32)


@dataclass
class RecordedEvidence:
    """A probe run's evidence document, replayed from `results_v5/probe/evidence-<STAMP>.log`.

    The fixture tests use it to run on real bytes from real hardware without a cluster.
    """

    blob: bytes
    runtime_data: bytes

    @classmethod
    def from_probe(cls, probe_dir, stamp: str, marker: str = "EVIDENCE_B64") -> "RecordedEvidence":
        """Read the evidence document and the runtime_data the probe requested it with.

        Args:
            probe_dir: the probe directory, usually `results_v5/probe`.
            stamp: the probe run's stamp.
            marker: the log line prefix that carries the base64 evidence.

        Returns:
            The recorded evidence.

        Raises:
            FileNotFoundError: a file is missing, or the log has no marker line.
        """
        import pathlib
        import re
        probe = pathlib.Path(probe_dir)
        log = (probe / f"evidence-{stamp}.log").read_text()
        m = re.search(rf"^{marker} (\S+)", log, re.M)
        if not m:
            raise FileNotFoundError(f"no {marker} line in evidence-{stamp}.log")
        rd = (probe / f"runtime-data-{stamp}.txt").read_text().strip()
        return cls(base64.b64decode(m.group(1)), bytes.fromhex(rd))

    def get_evidence(self, runtime_data_32: bytes) -> Evidence:
        """Return the recorded evidence and ignore the argument.

        Recorded evidence is bound to the runtime_data of its own run.
        """
        return Evidence("tdx", self.blob, self.runtime_data)
