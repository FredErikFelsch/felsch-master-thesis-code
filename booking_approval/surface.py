"""The approval surface: the page a person approves on, served by the Authority itself.

    GET  /                        pending approvals (links)
    GET  /approve/<object_id>     the approval page for one object
    GET  /static/<file>           the page's script and style (no inline code, strict CSP)
    GET  /api/pending             [view, ...]
    GET  /api/object/<object_id>  one view, rendered from the Authority's own material
    POST /api/challenge           {"object_id", "decision"} -> a challenge bound to both
    POST /api/decide              {"object_id", "decision", "assertion", "ttl"?} -> result

The listener runs in the Authority pod and is reached through `kubectl port-forward` on
`localhost:8450`, which is the WebAuthn origin the passkey is scoped to. What protects a
decision is the assertion, not the transport: the controller can reach this surface too, and
all it can obtain there is a challenge it cannot sign.

Request hygiene: the Host header must name the origin (no DNS rebinding), a POST must be
JSON from that origin, bodies are small, and every answer the handler writes is `no-store`
with a CSP that allows only this origin. Error pages that `http.server` writes itself (a
malformed request line, an unsupported method) do not carry these headers.

Embedding: the page may be shown as the side panel of the operator's shell
(ui/approval-ui/shell.html), but only by the origins passed as `frame_ancestors`. Without
any, framing is refused outright. A permitted embedder cannot read or change the page (other
origin). What it could do is draw over it (clickjacking). That is the same residual class as
the local port: local UI processes are trusted, the controller is not.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from booking_v4 import wire

from .gate import ApprovalGate, DecisionRefused

STATIC = pathlib.Path(__file__).with_name("static")
_FILES = {"approve.js": "text/javascript; charset=utf-8", "approve.css": "text/css; charset=utf-8"}
_OBJECT = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 16 * 1024
_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors {ancestors}")
_ORIGIN = re.compile(r"^https?://[a-z0-9.\-]+(:[0-9]{1,5})?$")


def security_headers(frame_ancestors: tuple[str, ...] = ()) -> dict[str, str]:
    """Return the security headers of every answer the handler writes.

    Args:
        frame_ancestors: The origins allowed to embed the page. With none, framing is refused.

    Returns:
        The header names and values.

    Raises:
        ValueError: when an entry is not a plain origin.
    """
    for o in frame_ancestors:
        if not _ORIGIN.match(o):
            raise ValueError(f"not an origin: {o!r}")
    headers = {"Cache-Control": "no-store",
               "Content-Security-Policy": _CSP.format(ancestors=" ".join(frame_ancestors) or "'none'"),
               "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}
    if not frame_ancestors:
        headers["X-Frame-Options"] = "DENY"          # older browsers. CSP frame-ancestors wins in current ones
    return headers


def _handler(gate: ApprovalGate, frame_ancestors: tuple[str, ...] = ()):
    """Build the request handler class bound to one gate."""
    origin = gate.origin
    host = urlsplit(origin).netloc
    headers = security_headers(frame_ancestors)

    class Handler(BaseHTTPRequestHandler):
        server_version = "approval-surface"
        timeout = wire.REQUEST_TIMEOUT_S      # an idle or stalled connection frees its thread

        def log_message(self, fmt, *args):          # one line per request on stdout, no bodies
            sys.stdout.write(f"[approval-surface] {self.command} {self.path.split('?')[0]} {args[1] if len(args) > 1 else ''}\n")
            sys.stdout.flush()

        # --- responses -----------------------------------------------------------------
        def _send(self, status: int, body: bytes, ctype: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, payload) -> None:
            self._send(status, json.dumps(payload).encode(), "application/json")

        def _host_ok(self) -> bool:
            if self.headers.get("Host") != host:
                self._json(421, {"error": f"this surface answers only for {host}"})
                return False
            return True

        # --- GET -------------------------------------------------------------------------
        def do_GET(self):  # noqa: N802 (http.server naming)
            if not self._host_ok():
                return
            path = urlsplit(self.path).path
            if path == "/" or path.startswith("/approve/"):
                return self._send(200, (STATIC / "approve.html").read_bytes(), "text/html; charset=utf-8")
            if path.startswith("/static/"):
                name = path[len("/static/"):]
                if name in _FILES:
                    return self._send(200, (STATIC / name).read_bytes(), _FILES[name])
                return self._json(404, {"error": "not found"})
            if path == "/api/pending":
                return self._json(200, gate.pending_views())
            if path.startswith("/api/object/"):
                oid = path[len("/api/object/"):]
                view = gate.object_view(oid) if _OBJECT.match(oid) else None
                return self._json(200, view) if view else self._json(404, {"error": "unknown approval object"})
            return self._json(404, {"error": "not found"})

        # --- POST ------------------------------------------------------------------------
        def do_POST(self):  # noqa: N802
            if not self._host_ok():
                return
            if self.headers.get("Origin") != origin:
                return self._json(403, {"error": "cross-origin request refused"})
            if not (self.headers.get("Content-Type") or "").startswith("application/json"):
                return self._json(415, {"error": "application/json required"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._json(400, {"error": "Content-Length is not a number"})
            if length <= 0 or length > MAX_BODY:
                return self._json(413, {"error": "body missing or too large"})
            try:
                body = json.loads(self.rfile.read(length))
                oid, decision = str(body["object_id"]), str(body["decision"])
            except (ValueError, KeyError, TypeError):
                return self._json(400, {"error": "object_id and decision required"})
            if not _OBJECT.match(oid):
                return self._json(404, {"error": "unknown approval object"})
            path = urlsplit(self.path).path
            try:
                if path == "/api/challenge":
                    return self._json(200, gate.issue_challenge(oid, decision))
                if path == "/api/decide":
                    ttl = body.get("ttl")
                    if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool)):
                        return self._json(400, {"error": "ttl must be an integer"})
                    return self._json(200, gate.decide(oid, decision, body.get("assertion") or {}, ttl))
            except DecisionRefused as refused:
                return self._json(refused.status, {"error": refused.reason})
            return self._json(404, {"error": "not found"})

    return Handler


class ApprovalSurface:
    """The HTTP listener of the approval surface.

    It serves from a daemon thread and handles each request on a thread of its own.
    """

    def __init__(self, gate: ApprovalGate, bind: tuple[str, int], frame_ancestors: tuple[str, ...] = ()) -> None:
        self._http = ThreadingHTTPServer(bind, _handler(gate, tuple(frame_ancestors)))
        self._http.daemon_threads = True
        self.address = self._http.server_address
        self._thread = threading.Thread(target=self._http.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        """Stop the listener and release the port."""
        self._http.shutdown()
        self._http.server_close()
