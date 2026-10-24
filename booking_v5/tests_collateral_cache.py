"""The collateral cache serves documents within their validity and does not extend it.

A transient DNS failure at appraisal time must not cost a verdict while valid collateral is held.
These tests pin what the cache must and must not do. It serves a document for the validity the
issuer signed into it and refreshes before expiry. When a refresh fails it serves the cached copy
only while that copy is still valid, and refuses otherwise. A PCS double (`_Source`) stands in
for the network.
"""
from __future__ import annotations

import datetime as dt
import json
import unittest
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .collateral_cache import ROOT_CA_CRL_URL, CachedCollateral, crl_next_update, json_next_update
from .tdx_quote import parse_aa_evidence, parse_quote
from .tests_v5_fixtures import FREEZE, STAMP, _recorded
from .verifier import CollateralUnavailable, classify_appraisal_error

T0 = 1_800_000_000                     # a fixed "now"
DAY = 86_400


def _iso(t: float) -> str:
    """Return the UTC timestamp `t` in the ISO form the PCS documents use."""
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _crl_der(next_update: float) -> bytes:
    """Return a DER CRL signed by a throwaway key, valid until `next_update`."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test CA")])
    builder = (x509.CertificateRevocationListBuilder().issuer_name(name)
               .last_update(dt.datetime.fromtimestamp(T0 - DAY, dt.timezone.utc))
               .next_update(dt.datetime.fromtimestamp(next_update, dt.timezone.utc)))
    return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


@dataclass
class _Doc:
    """A PCS document as the source returns it."""

    body: bytes
    issuer_chain_pem: str = "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"
    content_type: str = "application/json"


class _Source:
    """A PCS double: counts calls, can be switched off, hands out documents with a validity."""

    def __init__(self, valid_until: float):
        self.valid_until, self.calls, self.down = valid_until, [], False

    def _guard(self, name):
        self.calls.append(name)
        if self.down:
            raise ConnectionError("name resolution failed")

    def td_qe_identity(self):
        self._guard("qe")
        return _Doc(json.dumps({"enclaveIdentity": {"issueDate": _iso(T0 - DAY), "nextUpdate": _iso(self.valid_until)}}).encode())

    def tcb_info(self, fmspc):
        self._guard(f"tcb:{fmspc}")
        return _Doc(json.dumps({"tcbInfo": {"fmspc": fmspc, "issueDate": _iso(T0 - DAY), "nextUpdate": _iso(self.valid_until)}}).encode())

    def pck_crl(self, ca="processor", encoding="der"):
        self._guard(f"pckcrl:{ca}")
        return _Doc(_crl_der(self.valid_until), content_type="application/pkix-crl")

    def root(self, url):
        self._guard(f"root:{url}")
        return _crl_der(self.valid_until)


def _cache(valid_until=T0 + 30 * DAY, now=T0):
    """Return a cache over a fresh PCS double, the double and the mutable clock."""
    src = _Source(valid_until)
    clock = {"t": now}
    c = CachedCollateral(src, clock=lambda: clock["t"], fetch_root=src.root)
    return c, src, clock


class CollateralCacheTests(unittest.TestCase):
    """Validity, refresh and failure behaviour of `CachedCollateral` against a PCS double."""

    def test_validity_comes_from_the_documents_themselves(self):
        self.assertEqual(json_next_update(json.dumps({"tcbInfo": {"nextUpdate": _iso(T0 + 5)}}).encode(), "tcbInfo"), T0 + 5)
        self.assertEqual(crl_next_update(_crl_der(T0 + 7)), T0 + 7)
        with self.assertRaises(ValueError):
            json_next_update(b'{"tcbInfo": {}}', "tcbInfo")

    def test_one_fetch_per_document_while_valid(self):
        c, src, clock = _cache()
        for _ in range(3):
            c.td_qe_identity()
            c.tcb_info("00806F050000")
            c.pck_crl(ca="platform")
            c.root_ca_crl(ROOT_CA_CRL_URL)
        self.assertEqual(src.calls, ["qe", "tcb:00806F050000", "pckcrl:platform", f"root:{ROOT_CA_CRL_URL}"])
        self.assertEqual(c.fetches, 4)
        clock["t"] = T0 + 20 * DAY                       # still valid, outside the refresh margin
        c.tcb_info("00806f050000")                       # key is case-insensitive
        self.assertEqual(c.fetches, 4)

    def test_refreshed_before_expiry_and_served_from_cache_when_the_refresh_fails(self):
        c, src, clock = _cache(valid_until=T0 + 2 * DAY)
        c.td_qe_identity()
        clock["t"] = T0 + 2 * DAY - 3600                 # inside the 6 h margin: refresh
        src.down = True
        c.td_qe_identity()                               # refresh fails, cached copy still valid: served
        self.assertEqual(src.calls, ["qe", "qe"])
        src.down = False
        src.valid_until = T0 + 40 * DAY
        c.td_qe_identity()                               # refresh succeeds: new validity
        self.assertEqual(c.fetches, 2)
        self.assertGreater(c.status()["qe"]["valid_for_s"], 30 * DAY)

    def test_an_expired_document_is_not_served_and_no_network_means_collateral_unavailable(self):
        c, src, clock = _cache(valid_until=T0 + 2 * DAY)
        c.pck_crl(ca="platform")
        clock["t"] = T0 + 2 * DAY + 1
        src.down = True
        with self.assertRaises(CollateralUnavailable) as ctx:
            c.pck_crl(ca="platform")
        self.assertEqual(classify_appraisal_error(ctx.exception), "collateral-unavailable")

    def test_the_source_delivering_expired_collateral_is_refused(self):
        c, src, clock = _cache(valid_until=T0 - 1)
        with self.assertRaises(CollateralUnavailable):
            c.tcb_info("00806F050000")
        self.assertEqual(c.status(), {})

    def test_warm_fills_everything_the_first_td_needs_and_reports_instead_of_raising(self):
        c, src, clock = _cache()
        report = c.warm("00806F050000")
        self.assertEqual(report, {"qe": "ok", "tcb": "ok", "pckcrl": "ok", "rootcrl": "ok"})
        self.assertEqual(c.fetches, 4)
        c2, src2, _ = _cache()
        src2.down = True
        report = c2.warm(None)
        self.assertEqual(report["tcb"], "skipped (no fmspc)")
        self.assertTrue(report["qe"].startswith("CollateralUnavailable"))

    def test_the_cache_holds_der_crls_only(self):
        c, _, _ = _cache()
        with self.assertRaises(ValueError):
            c.pck_crl(ca="platform", encoding="pem")


class VendoredVerifierUsesTheCacheTests(unittest.TestCase):
    """The vendored QVL binding takes every document of a verdict from the cache.

    `_build_collateral` takes every document, the root CA CRL included, from the cache when the
    source offers `root_ca_crl(url)`. No `requests` call remains in the path of a verdict. The
    test uses the frozen quote for the recorded PCK chain and FMSPC.
    """

    def test_every_document_of_a_verdict_comes_from_the_cache(self):
        try:
            from .dcap.local_dcap_verify import _build_collateral, _root_ca_crl_url, parse_tdx_quote
        except Exception as exc:                                       # noqa: BLE001
            self.skipTest(f"vendored verifier not importable here: {exc}")
        quote = parse_quote(parse_aa_evidence(_recorded(FREEZE, STAMP).blob)[0])
        parsed = parse_tdx_quote(quote.quote_bytes)
        url = _root_ca_crl_url(parsed.pck_chain_pem)
        self.assertTrue(url.startswith("https://certificates.trustedservices.intel.com/"), url)
        c, src, clock = _cache()
        c.warm(parsed.fmspc, ca="platform", root_url=url)
        calls_after_warm = list(src.calls)
        collateral, keep = _build_collateral(parsed, c, now=T0)
        self.assertEqual(src.calls, calls_after_warm, "the verdict fetched nothing")
        self.assertGreater(collateral.root_ca_crl_size, 0)
        self.assertGreater(collateral.tcb_info_size, 0)
        src.down = True                                               # DNS gone: the verdict still has its collateral
        _build_collateral(parsed, c, now=T0)


if __name__ == "__main__":
    unittest.main()
