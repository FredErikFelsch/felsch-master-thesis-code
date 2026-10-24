"""Who may enrol an approver key, and what the ceremony must prove.

Run:
    python3 -m booking_approval.tests_enroll_rogue

A local process must not be able to fetch the enrolment challenge, post its own software key
without authenticator data and have it pinned as `kind: "passkey"`. The challenge and the
registration need a one-time code that only the operator's terminal shows, the registration
must carry authenticator data with user presence, user verification and attested credential
data for the credential id being pinned, and the operator must confirm the key before
anything is written.

A residual risk remains and is asserted: with `attestation: "none"` a caller who has the code
can forge the authenticator data. That caller is inside the trust boundary (the operator's
terminal), and the operator's confirmation is the last check against it.
"""
from __future__ import annotations

import json
import pathlib
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from .credentials import CredentialSet
from .enroll import enroll_passkey, fingerprint
from .softauthn import SoftwareAuthenticator
from .webauthn import b64url_encode


CODE = "operator-terminal-code"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Ceremony:
    """One enrolment listener on a free port and a caller that talks to it over HTTP."""

    def __init__(self, confirm):
        self.port = _free_port()
        self.base = f"http://localhost:{self.port}"
        self.creds = pathlib.Path(tempfile.mkdtemp(prefix="enroll-")) / "approver-credentials.json"
        self.asked: list = []
        self.done: dict = {}

        def confirmer(credential):
            self.asked.append(fingerprint(credential))
            return confirm(credential)

        self.thread = threading.Thread(daemon=True, target=lambda: self.done.setdefault(
            "c", enroll_passkey("fred", self.creds, self.port, code=CODE, confirm=confirmer)))
        self.thread.start()
        for _ in range(100):                                  # wait for the listener
            try:
                urllib.request.urlopen(f"{self.base}/")
                break
            except OSError:
                time.sleep(0.05)

    def get(self, path, code=CODE):
        """GET `path` with the enrolment code (None sends none) and return (status, JSON body)."""
        headers = {"X-Enroll-Code": code} if code is not None else {}
        try:
            with urllib.request.urlopen(urllib.request.Request(self.base + path, headers=headers)) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def register(self, auth, challenge_b64, *, code=CODE, auth_data="default", cred_id=None,
                 client_type="webauthn.create"):
        """POST a registration of `auth`. With `auth_data` None it is omitted, bytes replace it."""
        cred = auth.credential("fred", kind="passkey")
        client = json.dumps({"type": client_type, "challenge": challenge_b64, "origin": self.base}).encode()
        body = {"public_key": cred.public_key, "credential_id": cred_id or cred.credential_id,
                "algorithm": cred.algorithm, "client_data_json": b64url_encode(client)}
        if auth_data == "default":
            body["authenticator_data"] = b64url_encode(auth.registration_data())
        elif auth_data is not None:
            body["authenticator_data"] = b64url_encode(auth_data)
        headers = {"Origin": self.base, "Content-Type": "application/json"}
        if code is not None:
            headers["X-Enroll-Code"] = code
        req = urllib.request.Request(f"{self.base}/api/register", data=json.dumps(body).encode(), headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def pinned(self, auth):
        """Return the credential of `auth` as pinned in the credential file, or None."""
        cid = b64url_encode(auth.credential_id)
        return CredentialSet.load(self.creds).by_id(cid) if self.creds.exists() else None

    def challenge(self):
        """Return the registration challenge the listener issued."""
        return self.get("/api/options")[1]["challenge"]


class WhoMayEnroll(unittest.TestCase):
    """Only a caller with the code and a well-formed ceremony reaches the operator's confirmation."""

    def test_options_without_the_code_are_refused(self):
        c = _Ceremony(confirm=lambda cred: True)
        self.assertEqual(c.get("/api/options", code=None)[0], 403)
        self.assertEqual(c.get("/api/options", code="guess")[0], 403)

    def test_a_rogue_process_without_the_code_cannot_register(self):
        c, rogue = _Ceremony(confirm=lambda cred: True), SoftwareAuthenticator.generate()
        status, _ = c.register(rogue, challenge_b64="AAAA", code=None)
        self.assertEqual(status, 403)
        self.assertIsNone(c.pinned(rogue))
        self.assertEqual(c.asked, [], "the operator must not even be asked")

    def test_the_code_alone_is_not_enough_without_authenticator_data(self):
        c, rogue = _Ceremony(confirm=lambda cred: True), SoftwareAuthenticator.generate()
        status, reply = c.register(rogue, c.challenge(), auth_data=None)
        self.assertEqual(status, 400)
        self.assertIn("authenticatorData missing", reply["error"])
        self.assertIsNone(c.pinned(rogue))

    def test_user_verification_and_attested_data_are_required(self):
        c, rogue = _Ceremony(confirm=lambda cred: True), SoftwareAuthenticator.generate()
        challenge = c.challenge()
        self.assertIn("user verification", c.register(
            rogue, challenge, auth_data=rogue.registration_data(user_verified=False))[1]["error"])
        self.assertIn("attested credential data", c.register(
            rogue, challenge, auth_data=rogue.registration_data(attested=False))[1]["error"])
        self.assertIn("differs", c.register(
            rogue, challenge, auth_data=rogue.registration_data(credential_id=b"other"))[1]["error"])
        self.assertIsNone(c.pinned(rogue))

    def test_a_ceremony_for_another_purpose_is_refused(self):
        c, rogue = _Ceremony(confirm=lambda cred: True), SoftwareAuthenticator.generate()
        status, reply = c.register(rogue, c.challenge(), client_type="webauthn.get")
        self.assertEqual(status, 400)
        self.assertIsNone(c.pinned(rogue))

    def test_a_forged_but_well_formed_registration_is_stopped_by_the_operator(self):
        """Whoever has the code can forge the data, so the operator's confirmation is the last check.

        The confirmation at the terminal stands between that caller and the credential file.
        """
        c, rogue = _Ceremony(confirm=lambda cred: False), SoftwareAuthenticator.generate()
        status, reply = c.register(rogue, c.challenge())
        self.assertEqual(status, 403)
        self.assertIn("operator did not confirm", reply["error"])
        self.assertEqual(c.asked, [fingerprint(rogue.credential("fred", kind="passkey"))])
        self.assertIsNone(c.pinned(rogue), "a key the operator declined was pinned")

    def test_control_the_confirmed_key_is_pinned_as_a_passkey(self):
        c, key = _Ceremony(confirm=lambda cred: True), SoftwareAuthenticator.generate()
        status, reply = c.register(key, c.challenge())
        self.assertEqual((status, reply.get("ok")), (200, True))
        c.thread.join(timeout=3)
        pinned = c.pinned(key)
        self.assertIsNotNone(pinned)
        self.assertEqual((pinned.approver_id, pinned.kind), ("fred", "passkey"))

    def test_after_one_registration_the_ceremony_is_closed(self):
        c, first = _Ceremony(confirm=lambda cred: True), SoftwareAuthenticator.generate()
        challenge = c.challenge()
        self.assertEqual(c.register(first, challenge)[0], 200)
        c.thread.join(timeout=3)
        self.assertFalse(c.thread.is_alive(), "the listener must have shut down")


if __name__ == "__main__":
    unittest.main()
