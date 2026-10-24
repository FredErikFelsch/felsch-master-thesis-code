"""Vendored DCAP quote verification (Intel QVL via ctypes) and its PCS collateral client.

This is the Authority's verifier. `booking_v5.verifier.dcap_appraiser` wraps it, live through
the collateral cache (`booking_v5/collateral_cache.py`). The dcap-verify container
(scripts/gke-v5/21_dcap_verify.sh) runs it on recorded probe quotes. The V5 modifications
are listed in PROVENANCE.md.
"""
