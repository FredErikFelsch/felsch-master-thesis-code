"""A software WebAuthn authenticator: what a browser and a passkey produce, in Python.

Used by the offline tests and by the unattended evaluation harness (`--approve auto|deny`).
It builds `clientDataJSON` and `authenticatorData` in the WebAuthn L2 layout (the COSE key
of a registration is a placeholder, see `registration_data`) and signs with a P-256 key, so
the gate verifies it with the same code path as a real passkey. A harness key is enrolled
with kind "harness" and every decision it makes is recorded as such, because it is an
automated approver and not evidence of a person.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .credentials import ApproverCredential
from .webauthn import ES256, FLAG_AT, FLAG_UP, FLAG_UV, b64url_encode


@dataclass
class SoftwareAuthenticator:
    """A P-256 credential scoped to one relying party.

    Attributes:
        private_key: The credential's private key.
        credential_id: Its credential id (raw bytes).
        rp_id: The relying party id it answers for.
        user_verified: Whether it claims user verification (tests set False to probe UV).
        sign_count: The counter it reports. A counting authenticator increments it per assertion.
    """

    private_key: ec.EllipticCurvePrivateKey
    credential_id: bytes
    rp_id: str = "localhost"
    user_verified: bool = True
    sign_count: int = 0
    _counting: bool = field(default=False, repr=False)

    @classmethod
    def generate(cls, rp_id: str = "localhost", *, counting: bool = False) -> "SoftwareAuthenticator":
        """Create a random P-256 credential. With `counting` it reports an increasing signature counter."""
        return cls(ec.generate_private_key(ec.SECP256R1()), os.urandom(16), rp_id, _counting=counting)

    @classmethod
    def load(cls, path: str | pathlib.Path, rp_id: str = "localhost") -> "SoftwareAuthenticator":
        """Read a harness key written by `enroll harness` (PEM plus credential id)."""
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        key = serialization.load_pem_private_key(data["private_key_pem"].encode(), password=None)
        return cls(key, bytes.fromhex(data["credential_id_hex"]), rp_id)

    def save(self, path: str | pathlib.Path) -> None:
        """Write the private key, readable by the owner only."""
        pem = self.private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()).decode()
        p = pathlib.Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"private_key_pem": pem, "credential_id_hex": self.credential_id.hex()}, fh)

    def credential(self, approver_id: str, kind: str = "harness") -> ApproverCredential:
        """Return the public half, as it is pinned at the Authority."""
        spki = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return ApproverCredential(approver_id=approver_id, kind=kind,
                                  credential_id=b64url_encode(self.credential_id),
                                  public_key=b64url_encode(spki), algorithm=ES256)

    def registration_data(self, *, user_verified: bool | None = None, attested: bool = True,
                          credential_id: bytes | None = None) -> bytes:
        """Build the `authenticatorData` of a registration: flags, counter and attested credential data.

        The COSE key is a placeholder, because the gate does not read it and a real
        authenticator's encoding is not what the tests are about.

        Args:
            user_verified: Overrides the UV flag of this authenticator.
            attested: False leaves the AT flag and the attested credential data out.
            credential_id: Overrides the attested credential id.

        Returns:
            The raw authenticator data.
        """
        uv = self.user_verified if user_verified is None else user_verified
        flags = FLAG_UP | (FLAG_UV if uv else 0) | (FLAG_AT if attested else 0)
        head = hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + (0).to_bytes(4, "big")
        if not attested:
            return head
        cid = self.credential_id if credential_id is None else credential_id
        return head + bytes(16) + len(cid).to_bytes(2, "big") + cid + b"\xa1\x01\x02"

    def assertion(self, challenge: bytes, origin: str, top_origin: str | None = None) -> dict:
        """Return what `navigator.credentials.get` hands the page, base64url-encoded for the wire.

        Args:
            challenge: The challenge the gate issued.
            origin: The origin the page runs on.
            top_origin: Simulates the page running embedded in another origin's iframe.

        Returns:
            credential_id, client_data_json, authenticator_data and signature.
        """
        data = {"type": "webauthn.get", "challenge": b64url_encode(challenge), "origin": origin,
                "crossOrigin": top_origin is not None}
        if top_origin is not None:
            data["topOrigin"] = top_origin
        client_data = json.dumps(data, separators=(",", ":")).encode()
        if self._counting:
            self.sign_count += 1
        flags = FLAG_UP | (FLAG_UV if self.user_verified else 0)
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags])
                     + self.sign_count.to_bytes(4, "big"))
        signature = self.private_key.sign(auth_data + hashlib.sha256(client_data).digest(),
                                          ec.ECDSA(hashes.SHA256()))
        return {"credential_id": b64url_encode(self.credential_id),
                "client_data_json": b64url_encode(client_data),
                "authenticator_data": b64url_encode(auth_data),
                "signature": b64url_encode(signature)}
