"""PCS collateral client: direct queries instead of a PCCS.

This client replaces a full PCCS installation (Provisioning Certificate Caching Service).
PCCS is built for repeated queries from many platforms, with its own database and cache-fill
modes. Here there is one query per collateral type and appraisal, and caching, where wanted,
is done by booking_v5/collateral_cache.py. This client therefore calls Intel's Provisioning
Certification Service (PCS) v4 directly, with no intermediate layer and no storage of its own.

It covers the three collateral types a TDX DCAP quote verification needs:

    TD-QE identity        which quoting enclave version is considered trustworthy. It has
                          no platform reference, so the query is fixed.
    TCB info              which platform patch level (SVN combination) is current, per
                          FMSPC. The FMSPC comes from the PCK certificate in a real quote,
                          so it can only be queried once a real quote from the cVM exists.
    PCK revocation list   revoked platform certificates.

The client does not verify the quote signature or the certificate chain. Intel's official
DCAP Quote Verification Library (``libsgx-dcap-quote-verify``) does that, bound in
local_dcap_verify.py against the real headers.

Setup:
    Create an account at https://api.portal.trustedservices.intel.com, subscribe to the
    product "Intel SGX Provisioning Certification Service" (despite the name it also covers
    the /tdx/ v4 endpoints) and copy the primary key.

    export PCS_API_KEY=...
    export PCS_BASE_URL=https://api.trustedservices.intel.com   # default

    python3 -m booking_v5.dcap.local_dcap_collateral   # demo and self-test
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import unquote

import requests

_ISSUER_CHAIN_HEADERS = (
    "SGX-Enclave-Identity-Issuer-Chain",   # TD-QE identity, QE identity
    "SGX-TCB-Info-Issuer-Chain",           # TCB Info
    "TCB-Info-Issuer-Chain",               # alternative name, checked defensively
    "SGX-PCK-CRL-Issuer-Chain",            # PCK Revocation List
    "SGX-PCK-Certificate-Issuer-Chain",    # PCK certificate, in case it is needed later
)


@dataclass(frozen=True)
class Collateral:
    """A response obtained from PCS: payload plus issuer chain.

    Attributes:
        body: Raw response body. JSON for TCB info and QE identity, DER for the PCK CRL
            unless ``encoding='pem'`` is requested.
        issuer_chain_pem: Issuer certificate chain from the response header, already
            URL-decoded. Empty if the endpoint supplies none or its header name differs
            from ``_ISSUER_CHAIN_HEADERS``.
        content_type: Content-Type header of the response.
    """
    body: bytes
    issuer_chain_pem: str
    content_type: str


@dataclass
class PCSCollateralClient:
    """Thin client for Intel's Provisioning Certification Service (PCS) v4.

    Replaces PCCS with one query per collateral type and appraisal, without caching and
    without a database of its own.

    Args:
        api_key: PCS subscription key, can be set through the env var ``PCS_API_KEY``.
        base_url: PCS base endpoint, can be set through the env var ``PCS_BASE_URL``.
    """
    api_key: str = field(default_factory=lambda: os.environ["PCS_API_KEY"])
    base_url: str = field(
        default_factory=lambda: os.getenv("PCS_BASE_URL", "https://api.trustedservices.intel.com")
    )

    def _get(self, path: str, params: dict | None = None) -> Collateral:
        """Perform a GET against PCS and wrap the body and the issuer chain."""
        resp = requests.get(
            f"{self.base_url}{path}",
            headers={"Ocp-Apim-Subscription-Key": self.api_key},
            params=params or {},
            timeout=20,
        )
        resp.raise_for_status()
        chain = ""
        for name in _ISSUER_CHAIN_HEADERS:
            if name in resp.headers:
                chain = unquote(resp.headers[name])
                break
        return Collateral(
            body=resp.content,
            issuer_chain_pem=chain,
            content_type=resp.headers.get("Content-Type", ""),
        )

    def td_qe_identity(self) -> Collateral:
        """Fetch the TD-QE identity, which says which quoting enclave version is trusted."""
        return self._get("/tdx/certification/v4/qe/identity")

    def tcb_info(self, fmspc: str) -> Collateral:
        """Fetch the TCB info for one platform family.

        Args:
            fmspc: 6-byte hex identifier, found in the PCK certificate of the real quote.
        """
        return self._get("/tdx/certification/v4/tcb", params={"fmspc": fmspc})

    def pck_crl(self, ca: str = "processor", encoding: str = "der") -> Collateral:
        """Fetch the revocation list for the PCK certificate chain.

        Args:
            ca: 'processor' or 'platform', depending on the certificate type in the quote.
            encoding: 'der' (raw binary, the default, matching major_version=3
                minor_version=1 in sgx_ql_qve_collateral_t) or 'pem'. DCAP quote verify
                expects no PEM for major_version=3, see the struct comment in
                sgx_ql_lib_common.h.
        """
        return self._get("/sgx/certification/v4/pckcrl", params={"ca": ca, "encoding": encoding})


if __name__ == "__main__":
    client = PCSCollateralClient()

    qe = client.td_qe_identity()
    print(f"TD-QE identity : {len(qe.body):5} bytes  {qe.content_type}")
    print(f"  issuer chain found: {bool(qe.issuer_chain_pem)}")

    crl = client.pck_crl()
    print(f"PCK CRL        : {len(crl.body):5} bytes  {crl.content_type}")
    print(f"  issuer chain found: {bool(crl.issuer_chain_pem)}")

    print("\nTCB info is not part of the self-test. It needs a real FMSPC from a real")
    print("quote and is exercised in the cVM run.")