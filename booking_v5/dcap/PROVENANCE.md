# Provenance

The two modules in this directory are vendored from the `judgeguard` adapters
(`judgeguard/adapters/` of the archived judgeguard project), without modification apart from
the changes listed below:

    local_dcap_verify.py       ctypes binding of libsgx-dcap-quote-verify (tdx_qv_verify_quote, QVL mode),
                               quote parsing for MRTD / REPORTDATA / FMSPC / PCK chain, collateral struct
    local_dcap_collateral.py   PCSCollateralClient (Intel PCS v4, needs PCS_API_KEY)

Reason for vendoring: the archive may move, and the V5 evaluation must build from this
repository alone. The library runs on x86_64 Linux only (Intel library). `docker/dcap-verify`
provides that environment on other platforms such as macOS.

First modification (V5): `local_dcap_verify.py` gained `_root_ca_crl_url()` (the CRL
distribution point extracted from the chain, split out of `_fetch_root_ca_crl`), and
`_build_collateral` asks the collateral source for the root CA CRL when it offers
`root_ca_crl(url)`. That is what `booking_v5/collateral_cache.CachedCollateral` provides: every
collateral document is cached for the validity Intel signed into it, so no verdict depends on
DNS or PCS at that moment. Without such a source, the original direct fetch runs unchanged.

Second modification: `_root_ca_crl_url()` refuses any distribution point that is not in
`ALLOWED_ROOT_CA_CRL_URLS` (the pinned Intel Root CA CRL URL), because the chain is taken from
the quote and the URL was fetched before any quote verification. `_fetch_root_ca_crl` no
longer follows redirects (`allow_redirects=False`).

Third modification: the error messages and diagnostic output of both modules were translated
from German to English. `booking_v5/verifier.classify_appraisal_error` maps the messages onto
refusal codes, so the translations keep the words it looks for: "collateral" or "PCS" for an
unavailable or expired collateral, "verification result refused" for a rejected TCB. The
mapping of every message is the same as before.
