"""One-time enrolment of an approver: a passkey in the browser, or a harness key.

    python3 -m booking_approval.enroll passkey --approver fred \\
        --credentials k8s/v5/approver-credentials.json
        # opens no browser itself: visit the printed http://localhost:8450/#code=... link in
        # the browser that holds the passkey (Firefox, Chrome, Safari) and confirm with Touch ID

    python3 -m booking_approval.enroll harness --approver harness:eval \\
        --credentials k8s/v5/approver-credentials.eval.json \\
        --key-out ~/.config/thesis-v5/harness-approver.json

    python3 -m booking_approval.enroll list --credentials k8s/v5/approver-credentials.json

The passkey ceremony runs on the origin the Authority's page is later served on
(`http://localhost:8450`, rp id `localhost`), so the port-forward to the Authority must not
be running during enrolment. The credential file holds public keys only. The harness key's
private half goes to `--key-out`, mode 0600, and must stay off the controller's paths: a
deployment that pins it accepts automated approvals, which its runs then record as such.

Who may enrol: proof of possession of a key is not authorisation, and with
`attestation: "none"` nothing in the ceremony proves a real authenticator was involved. The
static page and its script and stylesheet are served to anyone who reaches the port, since
they hold nothing secret. The challenge (`/api/options`) and the registration
(`/api/register`) are only answered for a request that carries a one-time code shown on the
operator's terminal. The code travels in the URL fragment and an `X-Enroll-Code` header, not
in a request line. A key is pinned only after the operator has compared its fingerprint,
shown by the page and by the terminal, and typed `y`. Anyone who can read the operator's
terminal or acts as the operator's own browser session is inside this trust boundary, which
is the security assumption of enrolment.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable

from booking_v4 import wire

from .credentials import ApproverCredential, CredentialSet
from .softauthn import SoftwareAuthenticator
from .webauthn import WebAuthnRefused, b64url_decode, b64url_encode, verify_registration

STATIC = pathlib.Path(__file__).with_name("static")
_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def _existing(path: pathlib.Path) -> CredentialSet:
    return CredentialSet.load(path) if path.exists() else CredentialSet(())


def fingerprint(credential: ApproverCredential) -> str:
    """Short, human-comparable digest of the public key (the page computes the same value)."""
    digest = hashlib.sha256(b64url_decode(credential.public_key)).hexdigest()[:24]
    return "-".join(digest[i:i + 4] for i in range(0, 24, 4))


def confirm_on_terminal(credential: ApproverCredential) -> bool:
    """Ask the operator at the terminal whether this exact key may be pinned."""
    answer = input(f"Pin key {fingerprint(credential)} for {credential.approver_id!r}? "
                   f"Compare with the page. [y/N] ")
    return answer.strip().lower() == "y"


def enroll_passkey(approver: str, credentials: pathlib.Path, port: int = 8450, rp_id: str = "localhost",
                   *, code: str | None = None,
                   confirm: Callable[[ApproverCredential], bool] = confirm_on_terminal) -> ApproverCredential:
    """Serve the registration page on localhost until one passkey is registered.

    Args:
        approver: The approver id the passkey is pinned for.
        credentials: The credential file to extend (created if missing).
        port: The local port. It fixes the origin `http://localhost:<port>`.
        rp_id: The WebAuthn relying party id.
        code: The one-time enrolment code (default: fresh and random). Both API requests must
            carry it, and it is shown only on the operator's terminal.
        confirm: Called with the verified candidate before anything is written. Only a True
            answer pins the key. The default asks the operator at the terminal.

    Returns:
        The credential that was added to the file.
    """
    code = code or secrets.token_urlsafe(24)
    origin = f"http://localhost:{port}"
    challenge = secrets.token_bytes(32)
    user_id = secrets.token_bytes(16)
    done: dict = {}

    class Handler(BaseHTTPRequestHandler):
        timeout = wire.REQUEST_TIMEOUT_S      # the server is single threaded, so an idle client must not hold it

        def log_message(self, *args):
            pass

        def _send(self, status, body: bytes, ctype: str):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", _CSP)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, payload):
            self._send(status, json.dumps(payload).encode(), "application/json")

        def _coded(self) -> bool:
            """Return whether the request carries the one-time code (compared in constant time)."""
            return hmac.compare_digest(str(self.headers.get("X-Enroll-Code") or "").encode(), code.encode())

        def do_GET(self):  # noqa: N802
            if self.headers.get("Host") != f"localhost:{port}":
                return self._json(421, {"error": f"open http://localhost:{port}/"})
            if self.path == "/":
                return self._send(200, (STATIC / "enroll.html").read_bytes(), "text/html; charset=utf-8")
            if self.path in ("/static/enroll.js", "/static/approve.css"):
                ctype = "text/javascript" if self.path.endswith(".js") else "text/css"
                return self._send(200, (STATIC / self.path.rsplit("/", 1)[1]).read_bytes(), ctype + "; charset=utf-8")
            if self.path == "/api/options":
                if not self._coded():
                    return self._json(403, {"error": "enrolment code missing or wrong"})
                return self._json(200, {"challenge": b64url_encode(challenge), "rp_id": rp_id,
                                        "user_id": b64url_encode(user_id), "approver": approver})
            return self._json(404, {"error": "not found"})

        def do_POST(self):  # noqa: N802
            if (self.path != "/api/register" or self.headers.get("Origin") != origin
                    or self.headers.get("Host") != f"localhost:{port}" or done):
                return self._json(403, {"error": "refused"})
            if not self._coded():
                return self._json(403, {"error": "enrolment code missing or wrong"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)))
                spki, alg = b64url_decode(body["public_key"]), int(body["algorithm"])
                auth_data = b64url_decode(body["authenticator_data"]) if body.get("authenticator_data") else None
                verify_registration(spki_der=spki, algorithm=alg, rp_id=rp_id, origin=origin, challenge=challenge,
                                    client_data_json=b64url_decode(body["client_data_json"]),
                                    authenticator_data=auth_data,
                                    credential_id=b64url_decode(str(body["credential_id"])))
                cred = ApproverCredential(approver_id=approver, kind="passkey",
                                          credential_id=str(body["credential_id"]),
                                          public_key=b64url_encode(spki), algorithm=alg)
            except (KeyError, ValueError, TypeError, WebAuthnRefused) as exc:
                return self._json(400, {"error": str(exc)})
            if not confirm(cred):
                return self._json(403, {"error": "the operator did not confirm this key"})
            _existing(credentials).with_credential(cred).save(credentials)
            done["credential"] = cred
            self._json(200, {"ok": True, "approver_id": approver})
            threading.Thread(target=self.server.shutdown, daemon=True).start()

    httpd = HTTPServer(("127.0.0.1", port), Handler)
    print(f"open {origin}/#code={code} in your browser and register a passkey for {approver!r} "
          f"(Ctrl-C to abort). The code is single-use and must not leave this terminal.")
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
    return done["credential"]


def enroll_harness(approver: str, credentials: pathlib.Path, key_out: pathlib.Path) -> ApproverCredential:
    """Generate a software key, keep its private half at `key_out` (0600) and pin its public half.

    The credential is built before the key file is written, so an approver id that is refused
    leaves no orphaned private key behind.

    Args:
        approver: The approver id, which must carry the harness prefix.
        credentials: The credential file to extend (created if missing).
        key_out: Where the private key is written. An existing file is not overwritten.

    Returns:
        The credential that was added to the file.
    """
    if key_out.exists():
        raise SystemExit(f"{key_out} exists, refusing to overwrite a harness key")
    auth = SoftwareAuthenticator.generate()
    cred = auth.credential(approver, kind="harness")
    auth.save(key_out)
    _existing(credentials).with_credential(cred).save(credentials)
    return cred


def main(argv: list[str] | None = None) -> int:
    """Run the command line: the passkey, harness and list sub-commands."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("passkey")
    p.add_argument("--approver", required=True)
    p.add_argument("--credentials", required=True)
    p.add_argument("--port", type=int, default=8450)
    h = sub.add_parser("harness")
    h.add_argument("--approver", required=True)
    h.add_argument("--credentials", required=True)
    h.add_argument("--key-out", required=True)
    ls = sub.add_parser("list")
    ls.add_argument("--credentials", required=True)
    args = ap.parse_args(argv)
    path = pathlib.Path(args.credentials)
    if args.cmd == "passkey":
        cred = enroll_passkey(args.approver, path, args.port)
    elif args.cmd == "harness":
        cred = enroll_harness(args.approver, path, pathlib.Path(os.path.expanduser(args.key_out)))
    else:
        cs = _existing(path)
        for c in cs.credentials:
            print(f"{c.approver_id:20} {c.kind:8} alg={c.algorithm} id={c.credential_id[:16]}…")
        print(f"digest {cs.digest()}")
        return 0
    print(f"enrolled {cred.approver_id} ({cred.kind}), credential {cred.credential_id[:16]}… -> {path}")
    print(f"credential set digest now {CredentialSet.load(path).digest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
