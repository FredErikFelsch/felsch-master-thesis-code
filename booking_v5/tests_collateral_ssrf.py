"""The Root-CA CRL URL comes from the quote's own certificate chain, before any QVL check.

Run:
    python3 -m booking_v5.tests_collateral_ssrf

Only a local dummy target is used: an HTTP server on 127.0.0.1 records the requests. The test
certificates are two unrelated self-signed ones, and the second carries a CRL distribution point
that names the dummy. A URL that is not the pinned Intel one must be refused before any request,
a redirect must not leave the allow-list, and a slow fetch must not block a cache hit for another
key.
"""
from __future__ import annotations

import datetime as dt
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .collateral_cache import CachedCollateral
from .dcap.local_dcap_verify import _root_ca_crl_url
from .verifier import CollateralUnavailable


def _name(cn: str) -> x509.Name:
    """Return an X.509 name with the common name `cn`."""
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _chain_pem(cdp_url: str) -> bytes:
    """Return two unrelated self-signed certificates as PEM.

    The second one stands in for the intermediate and carries the CDP extension.
    `_root_ca_crl_url` reads only that extension and verifies no chain, so this is enough.
    """
    now = dt.datetime.now(dt.timezone.utc)
    pems = []
    for cn, cdp in (("root", None), ("intermediate", cdp_url)):
        key = ec.generate_private_key(ec.SECP256R1())
        b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1)))
        if cdp:
            b = b.add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(cdp)], relative_name=None, reasons=None,
                crl_issuer=None)]), critical=False)
        pems.append(b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    return b"".join(pems)


class _Dummy:
    """A recording HTTP target on 127.0.0.1 with an optional delay (tarpit) or redirect."""

    def __init__(self, delay: float = 0.0, redirect_to: str | None = None) -> None:
        self.hits: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            """Records each requested path and answers with a 404 or a redirect."""

            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802
                outer.hits.append(self.path)
                time.sleep(delay)
                if redirect_to:
                    self.send_response(302)
                    self.send_header("Location", redirect_to)
                else:
                    self.send_response(404)
                self.end_headers()

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/computeMetadata/v1/"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        """Stop the server and release its port."""
        self.httpd.shutdown()
        self.httpd.server_close()


class TheCrlUrlIsNotChosenByTheQuote(unittest.TestCase):
    """An attacker-chosen CRL distribution point does not make the Authority issue a request."""

    def test_a_cdp_url_that_is_not_the_pinned_one_is_refused_before_any_request(self):
        dummy = _Dummy()
        try:
            with self.assertRaises(ValueError):
                _root_ca_crl_url(_chain_pem(dummy.url))
            with self.assertRaises(CollateralUnavailable):
                CachedCollateral(source=None).root_ca_crl(dummy.url)
            self.assertEqual(dummy.hits, [], f"the Authority fetched an attacker chosen URL: {dummy.hits}")
        finally:
            dummy.close()

    def test_the_pinned_url_is_accepted_from_a_chain(self):
        pinned = "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der"
        self.assertEqual(_root_ca_crl_url(_chain_pem(pinned)), pinned)

    def test_a_redirect_from_an_allowed_url_is_not_followed(self):
        target = _Dummy()
        first = _Dummy(redirect_to=target.url)
        try:
            cache = CachedCollateral(source=None, allowed_root_urls=frozenset({first.url}))
            with self.assertRaises(CollateralUnavailable):
                cache.root_ca_crl(first.url)
            self.assertEqual(first.hits, ["/computeMetadata/v1/"])
            self.assertEqual(target.hits, [], "a redirect left the allow-list")
        finally:
            first.close()
            target.close()


class TheCacheRefusesForeignKeysAndHoldsNoLockDuringAFetch(unittest.TestCase):
    """The cache refuses a malformed FMSPC and does not hold its lock while it fetches."""

    def test_an_fmspc_that_is_not_12_hex_digits_is_refused(self):
        with self.assertRaises(CollateralUnavailable):
            CachedCollateral(source=None).tcb_info("00806F050000&x=1")

    def test_a_slow_fetch_does_not_block_a_hit_for_another_key(self):
        tarpit = _Dummy(delay=2.0)
        try:
            cache = CachedCollateral(source=None, allowed_root_urls=frozenset({tarpit.url}),
                                     fetch_root=lambda u: requests.get(u, timeout=5).content)
            cache._entries[("qe",)] = type("E", (), {"value": "cached", "valid_until": time.time() + 10**6,
                                                     "fetched_at": time.time()})()
            threading.Thread(target=lambda: _swallow(cache.root_ca_crl, tarpit.url), daemon=True).start()
            time.sleep(0.3)
            self.assertEqual(tarpit.hits, ["/computeMetadata/v1/"], "the slow fetch is not in flight")
            t0 = time.time()
            self.assertEqual(cache._get(("qe",), lambda: 1 / 0, lambda v: 0), "cached")    # a pure cache hit
            self.assertLess(time.time() - t0, 0.5, "the cache lock is held during the fetch")
        finally:
            tarpit.close()


def _swallow(fn, *args):
    """Run `fn` and ignore its failure (the dummy answers 404)."""
    try:
        fn(*args)
    except Exception:                                      # noqa: BLE001
        pass


if __name__ == "__main__":
    unittest.main()
