"""WebAuthn verification: the checks a forged, replayed or misdirected assertion fails.

Run:
    python3 -m booking_approval.tests_webauthn

No browser and no network are needed. The software authenticator builds the same bytes a
browser and a passkey would, so the checks of `verify_assertion` run on real signatures. Not
every check has a test of its own: a missing user presence flag, truncated authenticator data
and client data that is not a JSON object are not exercised here.
"""
from __future__ import annotations

import json
import unittest

from .softauthn import SoftwareAuthenticator
from .webauthn import (EDDSA, ES256, WebAuthnRefused, b64url_decode, b64url_encode, load_public_key,
                       verify_assertion, verify_registration)

ORIGIN = "http://localhost:8450"
CHALLENGE = b"\x01" * 32


def _parts(auth: SoftwareAuthenticator, challenge: bytes = CHALLENGE, origin: str = ORIGIN) -> dict:
    a = auth.assertion(challenge, origin)
    return {k: b64url_decode(a[k]) for k in ("client_data_json", "authenticator_data", "signature")}


def _verify(auth: SoftwareAuthenticator, parts: dict, *, challenge: bytes = CHALLENGE, origin: str = ORIGIN,
            rp_id: str = "localhost", require_uv: bool = True, key_of: SoftwareAuthenticator | None = None):
    cred = (key_of or auth).credential("harness:t")
    return verify_assertion(spki_der=b64url_decode(cred.public_key), algorithm=ES256, rp_id=rp_id, origin=origin,
                            challenge=challenge, client_data_json=parts["client_data_json"],
                            authenticator_data=parts["authenticator_data"], signature=parts["signature"],
                            require_uv=require_uv)


class AnAssertionVerifies(unittest.TestCase):
    """A genuine assertion passes and reports its flags and counter."""

    def test_a_genuine_assertion_verifies(self):
        auth = SoftwareAuthenticator.generate()
        result = _verify(auth, _parts(auth))
        self.assertTrue(result.user_verified)

    def test_the_counter_is_reported(self):
        auth = SoftwareAuthenticator.generate(counting=True)
        _verify(auth, _parts(auth))
        self.assertEqual(_verify(auth, _parts(auth)).sign_count, 2)


class AForgedOrMisdirectedAssertionIsRefused(unittest.TestCase):
    """Each altered input of an otherwise genuine assertion is refused with its own reason."""

    def setUp(self):
        self.auth = SoftwareAuthenticator.generate()

    def _refused(self, why: str, **kw):
        parts = kw.pop("parts", None) or _parts(self.auth)
        with self.assertRaisesRegex(WebAuthnRefused, why):
            _verify(self.auth, parts, **kw)

    def test_another_key_is_refused(self):
        self._refused("signature does not verify", key_of=SoftwareAuthenticator.generate())

    def test_another_challenge_is_refused(self):
        self._refused("challenge does not match", challenge=b"\x02" * 32)

    def test_another_origin_is_refused(self):
        self._refused("origin", parts=_parts(self.auth, origin="http://evil.localhost:8450"))

    def test_another_relying_party_is_refused(self):
        self._refused("rpIdHash", rp_id="example.org")

    def test_missing_user_verification_is_refused(self):
        self.auth.user_verified = False
        self._refused("user verification", parts=_parts(self.auth))

    def test_missing_user_verification_passes_only_when_not_required(self):
        self.auth.user_verified = False
        _verify(self.auth, _parts(self.auth), require_uv=False)

    def test_a_tampered_client_data_is_refused(self):
        parts = _parts(self.auth)
        data = json.loads(parts["client_data_json"])
        data["crossOrigin"] = False
        data["extra"] = "x"
        parts["client_data_json"] = json.dumps(data).encode()
        self._refused("signature does not verify", parts=parts)

    def test_a_registration_response_is_not_an_assertion(self):
        parts = _parts(self.auth)
        data = json.loads(parts["client_data_json"])
        data["type"] = "webauthn.create"
        parts["client_data_json"] = json.dumps(data).encode()
        self._refused("type", parts=parts)


class AnEmbeddedCeremony(unittest.TestCase):
    """The page as the operator shell's panel, which reports crossOrigin and topOrigin."""

    SHELL = "http://localhost:8766"

    def setUp(self):
        self.auth = SoftwareAuthenticator.generate()

    def _parts(self, top):
        a = self.auth.assertion(CHALLENGE, ORIGIN, top_origin=top)
        return {k: b64url_decode(a[k]) for k in ("client_data_json", "authenticator_data", "signature")}

    def _verify(self, parts, allowed):
        cred = self.auth.credential("harness:t")
        return verify_assertion(spki_der=b64url_decode(cred.public_key), algorithm=ES256, rp_id="localhost",
                                origin=ORIGIN, challenge=CHALLENGE, allowed_top_origins=allowed, **parts)

    def test_embedded_is_refused_without_allowed_embedders(self):
        with self.assertRaisesRegex(WebAuthnRefused, "cross-origin"):
            self._verify(self._parts(self.SHELL), ())

    def test_the_shell_may_embed(self):
        self._verify(self._parts(self.SHELL), (self.SHELL,))

    def test_another_embedder_is_refused(self):
        with self.assertRaisesRegex(WebAuthnRefused, "may not embed"):
            self._verify(self._parts("http://localhost:3000"), (self.SHELL,))


class KeysAndRegistration(unittest.TestCase):
    """Key loading and the checks on a registration."""

    def test_an_es256_key_must_be_p256(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        der = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaisesRegex(WebAuthnRefused, "P-256"):
            load_public_key(der, ES256)

    def test_an_eddsa_key_is_accepted(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        der = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        load_public_key(der, EDDSA)

    def test_a_registration_for_this_challenge_and_origin_passes(self):
        auth = SoftwareAuthenticator.generate()
        cd = json.dumps({"type": "webauthn.create", "challenge": b64url_encode(CHALLENGE),
                         "origin": ORIGIN}).encode()
        verify_registration(spki_der=b64url_decode(auth.credential("harness:t").public_key), algorithm=ES256,
                            rp_id="localhost", origin=ORIGIN, challenge=CHALLENGE, client_data_json=cd,
                            authenticator_data=auth.registration_data(),
                            credential_id=auth.credential_id)

    def _register(self, auth, **overrides):
        """Verify a registration of `auth`, with one field replaced to probe one check."""
        cd = json.dumps({"type": "webauthn.create", "challenge": b64url_encode(CHALLENGE),
                         "origin": ORIGIN}).encode()
        args = dict(spki_der=b64url_decode(auth.credential("harness:t").public_key), algorithm=ES256,
                    rp_id="localhost", origin=ORIGIN, challenge=CHALLENGE, client_data_json=cd,
                    authenticator_data=auth.registration_data(), credential_id=auth.credential_id)
        args.update(overrides)
        verify_registration(**args)

    def test_a_registration_without_authenticator_data_is_refused(self):
        with self.assertRaisesRegex(WebAuthnRefused, "authenticatorData missing"):
            self._register(SoftwareAuthenticator.generate(), authenticator_data=None)

    def test_a_registration_without_user_verification_is_refused(self):
        auth = SoftwareAuthenticator.generate()
        with self.assertRaisesRegex(WebAuthnRefused, "user verification"):
            self._register(auth, authenticator_data=auth.registration_data(user_verified=False))

    def test_a_registration_without_attested_data_is_refused(self):
        auth = SoftwareAuthenticator.generate()
        with self.assertRaisesRegex(WebAuthnRefused, "attested credential data flag"):
            self._register(auth, authenticator_data=auth.registration_data(attested=False))

    def test_the_attested_credential_id_must_be_the_pinned_one(self):
        auth = SoftwareAuthenticator.generate()
        with self.assertRaisesRegex(WebAuthnRefused, "differs"):
            self._register(auth, authenticator_data=auth.registration_data(credential_id=b"someone-else-id"))

    def test_a_registration_on_another_origin_is_refused(self):
        auth = SoftwareAuthenticator.generate()
        cd = json.dumps({"type": "webauthn.create", "challenge": b64url_encode(CHALLENGE),
                         "origin": "http://localhost:9999"}).encode()
        with self.assertRaisesRegex(WebAuthnRefused, "origin"):
            verify_registration(spki_der=b64url_decode(auth.credential("harness:t").public_key), algorithm=ES256,
                                rp_id="localhost", origin=ORIGIN, challenge=CHALLENGE, client_data_json=cd,
                                authenticator_data=auth.registration_data(),
                                credential_id=auth.credential_id)


if __name__ == "__main__":
    unittest.main()
