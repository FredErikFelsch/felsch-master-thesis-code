"""Verification of WebAuthn registrations and assertions, server side.

The scope is what the approval gate needs: a credential public key in SPKI form (what
`AuthenticatorAttestationResponse.getPublicKey()` returns in Firefox, Chrome and Safari), the
algorithms ES256 (-7) and EdDSA (-8), and the checks of WebAuthn Level 2, section 7.2
(assertion) and 7.1 (registration) that do not need attestation. Attestation statements are
not verified, because the operator pins the credential at enrolment, so its provenance is
the enrolment ceremony and not a vendor certificate.

Only `cryptography` is used, which the services image already ships.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import load_der_public_key

#: COSE algorithm identifiers the gate accepts.
ES256 = -7
EDDSA = -8
SUPPORTED_ALGORITHMS = (ES256, EDDSA)

#: Authenticator data flags (WebAuthn L2, 6.1).
FLAG_UP = 0x01          # user present
FLAG_UV = 0x04          # user verified (biometric or PIN)
FLAG_AT = 0x40          # attested credential data included (registration only)


class WebAuthnRefused(Exception):
    """A registration or assertion failed one of the checks. The message names the check."""


@dataclass(frozen=True)
class AssertionResult:
    """What a verified assertion tells the relying party."""

    sign_count: int
    user_present: bool
    user_verified: bool


def b64url_encode(raw: bytes) -> str:
    """Encode bytes as base64url without padding, the encoding WebAuthn uses for binary fields."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


_B64URL = re.compile(r"[A-Za-z0-9_-]*={0,2}", re.ASCII)


def b64url_decode(text: str) -> bytes:
    """Decode base64url. Missing padding is accepted, non-strings and foreign characters are not.

    `urlsafe_b64decode` drops every byte outside the alphabet without a word, so two
    different strings could decode to the same bytes. The alphabet is checked first.
    """
    if not isinstance(text, str):
        raise WebAuthnRefused("binary field must be a base64url string")
    if not _B64URL.fullmatch(text):
        raise WebAuthnRefused("invalid base64url: characters outside the alphabet")
    try:
        return base64.urlsafe_b64decode(text.rstrip("=") + "=" * (-len(text.rstrip("=")) % 4))
    except (ValueError, TypeError) as exc:
        raise WebAuthnRefused(f"invalid base64url: {exc}") from None


def _client_data(client_data_json: bytes, *, expected_type: str, challenge: bytes, origin: str,
                 allowed_top_origins: tuple[str, ...] = ()) -> None:
    """Check 7.2 steps 10 to 14: type, challenge, origin and who embedded the page.

    A ceremony inside an iframe reports `crossOrigin: true` (and, per WebAuthn L3, the
    `topOrigin` of the embedding page). It is accepted only when the relying party names
    the embedders it allows, and a reported `topOrigin` must be one of them. Browsers that
    omit `topOrigin` are covered by the page's CSP `frame-ancestors`, which the browser
    enforces with the same list before the page can run at all.
    """
    try:
        data = json.loads(client_data_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WebAuthnRefused("clientDataJSON is not JSON") from None
    if not isinstance(data, dict):
        raise WebAuthnRefused("clientDataJSON is not an object")
    if data.get("type") != expected_type:
        raise WebAuthnRefused(f"clientData type is {data.get('type')!r}, expected {expected_type!r}")
    if not hmac.compare_digest(b64url_decode(data.get("challenge", "")), challenge):
        raise WebAuthnRefused("clientData challenge does not match the issued challenge")
    if data.get("origin") != origin:
        raise WebAuthnRefused(f"clientData origin is {data.get('origin')!r}, expected {origin!r}")
    if data.get("crossOrigin") is True:
        if not allowed_top_origins:
            raise WebAuthnRefused("cross-origin ceremony refused")
        top = data.get("topOrigin")
        if top is not None and top not in allowed_top_origins:
            raise WebAuthnRefused(f"embedded by {top!r}, which may not embed the approval page")


def _authenticator_data(auth_data: bytes, *, rp_id: str, require_uv: bool) -> AssertionResult:
    """Check 7.2 steps 15 to 17: rpIdHash, user present and user verified."""
    if len(auth_data) < 37:
        raise WebAuthnRefused("authenticatorData too short")
    if not hmac.compare_digest(auth_data[:32], hashlib.sha256(rp_id.encode("utf-8")).digest()):
        raise WebAuthnRefused("rpIdHash does not match the relying party")
    flags = auth_data[32]
    if not flags & FLAG_UP:
        raise WebAuthnRefused("user presence flag not set")
    if require_uv and not flags & FLAG_UV:
        raise WebAuthnRefused("user verification flag not set (biometric or PIN required)")
    return AssertionResult(sign_count=int.from_bytes(auth_data[33:37], "big"),
                           user_present=True, user_verified=bool(flags & FLAG_UV))


def load_public_key(spki_der: bytes, algorithm: int):
    """Load a credential public key and check that it fits the declared algorithm.

    Args:
        spki_der: The public key as DER SubjectPublicKeyInfo.
        algorithm: The declared COSE algorithm.

    Returns:
        The loaded key.

    Raises:
        WebAuthnRefused: when the algorithm is unsupported, the key does not parse or does
            not fit the algorithm.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise WebAuthnRefused(f"unsupported COSE algorithm {algorithm}")
    try:
        key = load_der_public_key(spki_der)
    except ValueError:
        raise WebAuthnRefused("public key is not a DER SubjectPublicKeyInfo") from None
    if algorithm == ES256 and not (isinstance(key, ec.EllipticCurvePublicKey)
                                   and isinstance(key.curve, ec.SECP256R1)):
        raise WebAuthnRefused("ES256 requires a P-256 key")
    if algorithm == EDDSA and not isinstance(key, ed25519.Ed25519PublicKey):
        raise WebAuthnRefused("EdDSA requires an Ed25519 key")
    return key


def verify_assertion(*, spki_der: bytes, algorithm: int, rp_id: str, origin: str, challenge: bytes,
                     client_data_json: bytes, authenticator_data: bytes, signature: bytes,
                     require_uv: bool = True, allowed_top_origins: tuple[str, ...] = ()) -> AssertionResult:
    """Verify one `navigator.credentials.get` result against a pinned credential.

    Args:
        spki_der: The pinned credential public key.
        algorithm: Its COSE algorithm.
        rp_id: The relying party id the credential is scoped to (`localhost`).
        origin: The origin the ceremony must have run on (`http://localhost:8450`).
        challenge: The challenge the gate issued for this decision.
        client_data_json: `response.clientDataJSON`, raw bytes.
        authenticator_data: `response.authenticatorData`, raw bytes.
        signature: `response.signature`, raw bytes (DER for ES256).
        require_uv: Whether user verification is mandatory (True for a passkey).
        allowed_top_origins: Pages that may embed the approval page (the operator shell).

    Returns:
        The flags and the signature counter.

    Raises:
        WebAuthnRefused: naming the first check that failed.
    """
    _client_data(client_data_json, expected_type="webauthn.get", challenge=challenge, origin=origin,
                 allowed_top_origins=allowed_top_origins)
    result = _authenticator_data(authenticator_data, rp_id=rp_id, require_uv=require_uv)
    key = load_public_key(spki_der, algorithm)
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    try:
        if algorithm == ES256:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, signed)
    except InvalidSignature:
        raise WebAuthnRefused("assertion signature does not verify") from None
    return result


def _attested_credential_id(auth_data: bytes) -> bytes:
    """Return the credential id inside the attested credential data (WebAuthn L2, 6.5.1)."""
    if not auth_data[32] & FLAG_AT:
        raise WebAuthnRefused("attested credential data flag not set")
    if len(auth_data) < 55:
        raise WebAuthnRefused("attested credential data too short")
    length = int.from_bytes(auth_data[53:55], "big")
    if length == 0 or len(auth_data) <= 55 + length:
        raise WebAuthnRefused("attested credential data is incomplete")
    return auth_data[55:55 + length]


def verify_registration(*, spki_der: bytes, algorithm: int, rp_id: str, origin: str, challenge: bytes,
                        client_data_json: bytes, authenticator_data: bytes | None,
                        credential_id: bytes | None = None) -> None:
    """Check a `navigator.credentials.create` result before its key is pinned.

    The attestation statement is not evaluated (see the module docstring), so nothing here
    proves that a real authenticator produced the data. A caller who knows the challenge can
    build all of it. The checks hold the ceremony to its shape: it answers the issued
    challenge on the expected origin, carries authenticator data for the relying party with
    user presence, user verification and attested credential data, names the credential id
    being pinned (when `credential_id` is given), and its key parses for the algorithm.
    Missing authenticator data is a refusal. The pinned SPKI is not compared with the COSE
    key inside the attested credential data. Who may start a ceremony is decided outside this
    function, by the enrolment code and the operator's confirmation (see `enroll`).

    Args:
        spki_der: The public key the page sent, which is what gets pinned.
        algorithm: Its COSE algorithm.
        rp_id: The relying party id.
        origin: The origin the ceremony must have run on.
        challenge: The challenge the listener issued.
        client_data_json: `response.clientDataJSON`, raw bytes.
        authenticator_data: `response.getAuthenticatorData()`, raw bytes, or None.
        credential_id: The credential id being pinned, raw bytes.

    Raises:
        WebAuthnRefused: naming the first check that failed.
    """
    _client_data(client_data_json, expected_type="webauthn.create", challenge=challenge, origin=origin)
    if authenticator_data is None:
        raise WebAuthnRefused("authenticatorData missing: the browser must expose it")
    _authenticator_data(authenticator_data, rp_id=rp_id, require_uv=True)
    attested = _attested_credential_id(authenticator_data)
    if credential_id is not None and not hmac.compare_digest(attested, credential_id):
        raise WebAuthnRefused("attested credential id differs from the credential id being pinned")
    load_public_key(spki_der, algorithm)
