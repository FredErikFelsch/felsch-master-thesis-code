"""DCAP collateral with a validity-bounded cache: no network in the path of a verdict.

The vendored PCS client (`dcap/local_dcap_collateral.py`) fetches every document fresh. In
V5 the Authority appraises one quote per TD, so every authorisation would depend on DNS and
on Intel's services at that moment. A transient DNS failure in the pod would be enough to
refuse a legitimate payment (`collateral-unavailable`).

This wrapper keeps each collateral document for the validity Intel signed into it:
`nextUpdate` of TCB Info and QE Identity, `nextUpdate` of the two CRLs. No check is
loosened. An expired document is not served, a document within `refresh_margin_s` of its
expiry is refreshed, and when a refresh fails the cached copy is served only while it is
still valid. With nothing valid in the cache and no network, the verdict is
`collateral-unavailable`, as before. `warm()` fills the cache at start (the FMSPC of the
frozen reference, the CA type observed on the platform), so the first TD of a deployment
does not touch the network either.

The class offers the same three methods as `PCSCollateralClient` plus `root_ca_crl(url)`,
which the vendored verifier calls when the collateral source offers it (see
dcap/PROVENANCE.md).
"""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from .verifier import CollateralUnavailable          # the verifier maps it to collateral-unavailable

ROOT_CA_CRL_URL = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
ALLOWED_ROOT_CA_CRL_URLS = frozenset({ROOT_CA_CRL_URL})   # pinned root CA CRL sources, a URL from a quote is refused
_FMSPC = re.compile(r"^[0-9a-fA-F]{12}$")
PLATFORM_CA_OBSERVED = "platform"          # the PCK issuer seen on GCP TDX


def _pcs_date(raw: str) -> float:
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def json_next_update(body: bytes, key: str) -> float:
    """Return `nextUpdate` of a PCS JSON document (`tcbInfo` or `enclaveIdentity`) as Unix time.

    Raises:
        ValueError: the document has no nextUpdate.
    """
    doc = json.loads(body).get(key, {})
    if "nextUpdate" not in doc:
        raise ValueError(f"collateral {key!r} carries no nextUpdate")
    return _pcs_date(doc["nextUpdate"])


def crl_next_update(der: bytes) -> float:
    """Return `nextUpdate` of a DER CRL (the PCK CRL or the root CA CRL) as Unix time.

    Raises:
        ValueError: the CRL has no nextUpdate.
    """
    from cryptography import x509
    crl = x509.load_der_x509_crl(der)
    nxt = getattr(crl, "next_update_utc", None) or crl.next_update
    if nxt is None:
        raise ValueError("CRL carries no nextUpdate")
    if nxt.tzinfo is None:
        nxt = nxt.replace(tzinfo=timezone.utc)
    return nxt.timestamp()


@dataclass
class _Entry:
    value: Any
    valid_until: float
    fetched_at: float


@dataclass
class CachedCollateral:
    """Validity-bounded cache in front of a collateral source (the PCS client)."""

    source: Any                                   # PCSCollateralClient or a test double
    clock: Callable[[], float] = time.time
    refresh_margin_s: float = 6 * 3600            # refresh this long before expiry
    fetch_root: Optional[Callable[[str], bytes]] = None   # GET url -> DER. Default: requests
    allowed_root_urls: frozenset = ALLOWED_ROOT_CA_CRL_URLS
    _entries: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)            # guards `_entries` only, released before I/O
    _key_locks: dict = field(default_factory=dict)                           # one lock per key, serialises fetches of that key
    fetches: int = 0                              # for tests and the log line

    # --- the collateral interface ---------------------------------------------------------
    def td_qe_identity(self):
        """Return the QE identity document, cached."""
        return self._get(("qe",), self.source.td_qe_identity,
                         lambda c: json_next_update(c.body, "enclaveIdentity"))

    def tcb_info(self, fmspc: str):
        """Return the TCB info document for one FMSPC, cached."""
        if not _FMSPC.match(str(fmspc)):
            raise CollateralUnavailable(f"tcb/{str(fmspc)[:16]!r}: FMSPC is not 12 hex digits")
        return self._get(("tcb", fmspc.lower()), lambda: self.source.tcb_info(fmspc),
                         lambda c: json_next_update(c.body, "tcbInfo"))

    def pck_crl(self, ca: str = "processor", encoding: str = "der"):
        """Return the PCK CRL of one CA type, cached. Only DER is supported."""
        if encoding != "der":
            raise ValueError("the cache holds DER CRLs only (what the QVL struct v3.1 expects)")
        return self._get(("pckcrl", ca), lambda: self.source.pck_crl(ca=ca, encoding="der"),
                         lambda c: crl_next_update(c.body))

    def root_ca_crl(self, url: str) -> bytes:
        """Return the Intel root CA CRL. Only pinned Intel URLs are fetched."""
        if url not in self.allowed_root_urls:               # before the cache key and before any I/O
            raise CollateralUnavailable("rootcrl: the URL is not a pinned Intel URL")
        return self._get(("rootcrl", url), lambda: self._fetch_root(url), crl_next_update)

    # --- start-up -----------------------------------------------------------------------
    def warm(self, fmspc: Optional[str], ca: str = PLATFORM_CA_OBSERVED, root_url: str = ROOT_CA_CRL_URL) -> dict:
        """Fill the cache before the first TD.

        Failures are reported and not raised, because a deployment without network at start
        still refuses correctly later.

        Args:
            fmspc: the FMSPC of the frozen reference, or None to skip TCB info.
            ca: the PCK CA type observed on the platform.
            root_url: the pinned root CA CRL URL.

        Returns:
            Per document "ok", "skipped (no fmspc)" or the error.
        """
        report = {}
        for name, fn in (("qe", self.td_qe_identity),
                         ("tcb", (lambda: self.tcb_info(fmspc)) if fmspc else None),
                         ("pckcrl", lambda: self.pck_crl(ca=ca)),
                         ("rootcrl", lambda: self.root_ca_crl(root_url))):
            if fn is None:
                report[name] = "skipped (no fmspc)"
                continue
            try:
                fn()
                report[name] = "ok"
            except Exception as exc:                                   # noqa: BLE001 (reported, see above)
                report[name] = f"{type(exc).__name__}: {str(exc)[:80]}"
        return report

    def status(self) -> dict:
        """Return the remaining validity in seconds of every cached document."""
        now = self.clock()
        return {"/".join(k): {"valid_for_s": int(e.valid_until - now)} for k, e in self._entries.items()}

    # --- internals ----------------------------------------------------------------------
    def _fetch_root(self, url: str) -> bytes:
        if self.fetch_root is not None:
            return self.fetch_root(url)
        import requests
        resp = requests.get(url, timeout=20, allow_redirects=False)    # a redirect could leave the allow-list
        resp.raise_for_status()
        return resp.content

    def _get(self, key: tuple, fetch: Callable[[], Any], validity: Callable[[Any], float]):
        """Serve a valid entry, else fetch it.

        The cache lock covers only dictionary access, so a slow or hanging fetch of one key
        does not block a hit or a fetch of another key. Fetches of the same key are serialised
        by a per-key lock, so one refresh runs at a time and the others re-read its result.

        Raises:
            CollateralUnavailable: the fetch failed and no valid copy is cached, or the
                source delivered expired collateral.
        """
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and self.clock() < entry.valid_until - self.refresh_margin_s:
                return entry.value
            key_lock = self._key_locks.setdefault(key, threading.Lock())
        with key_lock:
            with self._lock:
                now = self.clock()
                entry = self._entries.get(key)
                if entry is not None and now < entry.valid_until - self.refresh_margin_s:
                    return entry.value                                 # another thread refreshed it meanwhile
            try:
                value = fetch()                                        # I/O outside the cache lock
                valid_until = validity(value)
            except Exception as exc:                                   # noqa: BLE001 (re-raised as CollateralUnavailable)
                if entry is not None and now < entry.valid_until:
                    return entry.value                                 # still valid: serve it
                raise CollateralUnavailable(f"{'/'.join(key)}: {type(exc).__name__}: {str(exc)[:200]}") from exc
            if now >= valid_until:
                raise CollateralUnavailable(f"{'/'.join(key)}: the source delivered expired collateral")
            with self._lock:
                self.fetches += 1
                self._entries[key] = _Entry(value, valid_until, now)
            return value
