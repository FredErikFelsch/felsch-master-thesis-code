"""The approval facade: what is pending, and the only way to answer it from the local panel.

"Trusted" here means trusted against the conversation. Nothing on this path comes from the
chat, and the chat adapter has no code that writes an answer. It does not mean attested. The
request file is written by the controller, which the threat model treats as untrusted. In the
local panel the human signs the digest, and what the human reads is rendered from that file,
outside the TCB. With the WebAuthn gate the Authority renders the approval page itself
(`booking_approval.surface`), and the shell of this process only embeds it.

    python3 -m ui.approval_api [--port 8766] [--authority-url URL]   then open http://localhost:8766/

GET  /                                  one view: Open WebUI in an iframe, the approval drawer beside it
                                        (approval-ui/shell.html, ?chat=<open webui url>)
GET  /panel                             the local panel alone (approval-ui/index.html), ?controls=1: demo controls only
GET  /api/shell-config                  {"authority_url"}: the Authority's page the shell embeds, "" for the local panel
GET  /api/approvals/pending             [record, ...] (approval_record.pending_record)
POST /api/approvals/<id>/approve        {"policy_hash": "..."} → approval.json {"granted": true, ...}
                                        (every POST: application/json, no foreign Origin, written once)
POST /api/approvals/<id>/reject         {"policy_hash": "..."} → approval.json {"granted": false, ...}
GET  /api/demo/controls, /api/demo/external-input, /api/demo/node-attack
                                        the current demo controls {external_input, node_attack,
                                        foreign_order, injection_text}
POST /api/demo/external-input           {"mode": ...}: what the agent's untrusted input looks like
                                        in the next run (a demo control, not an agent setting)
POST /api/demo/foreign-order            {"order_id": "ord_…" | ""}: the attacker's hold order that the
                                        injected content asks the agent to pay (duffel)
POST /api/demo/node-attack              {"attack": ...}: a throwaway fragment under attack from the
                                        node before the next run (attested modes only)

`approval_id` and `policy_hash` tie an answer to one pending request. They do not identify the
person who gives it. The server loads its own record, and the client's pair must match it. The
id must be unused and the request must be the current one, so an id that is unknown, already
answered or paired with another hash is refused (404 or 409). What is approved is the stored
policy. Amount, tool and order in the body are display fields and are ignored.

Anyone who knows the pair can still post an answer. In the local demo that is acceptable,
because the panel listens on loopback and one person uses the screen. Reachable over a
network, the endpoint needs an identity as well. For the proof of concept, `APPROVAL_TOKEN` in
the environment makes every POST require `Authorization: Bearer <token>` (off when unset). That
is a placeholder for a real approver identity, not a claim about one. This process holds no
credential and knows no chat. The chat adapter (ui/agent_api.py) can see that a request is
pending but cannot write an answer.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from booking_demo.approval_record import pending_record, policy_hash
from booking_demo.http_guard import origins_for, refuse, write_once
from booking_demo.live import ORDER_ID, injection_for
from booking_demo.serve import DEMO_DIR

HERE = pathlib.Path(__file__).resolve().parent
#: The demo control the agent facade reads when it starts a run. It says whether the external
#: content the agent will observe is benign or carries an indirect prompt injection. Request,
#: agent, policy and deployment stay the same, and only the untrusted input differs.
CONTROLS_FILE = "demo-controls.json"
EXTERNAL_INPUT = ("benign", "injection", "injection-combined", "injection-correction")
#: The injection style each switch position starts the next run with (benign has none).
INJECTION_STYLE = {"injection": "naive", "injection-combined": "combined",
                   "injection-correction": "correction"}


#: The attacker on the node beneath the runner (booking_demo/attacks.py, labels as in
#: scripts/gke-v5/attack_catalogue.md). a10 forges the boot key the transport reports, a16
#: delivers a fragment other than the attested one, and a18 asserts a foreign substrate. a16
#: runs as a throwaway run before the real one, a10 and a18 as an extra attempt at the real
#: run's first step. The TD or the relying party refuses each with a ledger delta of 0, which
#: is where the demo shows what the attested path adds over the monitor alone.
NODE_ATTACKS = ("none", "a10", "a16", "a18")
DEFAULTS = {"external_input": "benign", "node_attack": "none", "foreign_order": ""}


def inject_style_of(external_input: str) -> str:
    """The injection style of a switch position, "naive" for benign, which carries no injection."""
    return INJECTION_STYLE.get(external_input, "naive")


def read_controls(demo_dir: pathlib.Path = DEMO_DIR) -> dict:
    """The demo controls, with defaults for anything unset or invalid."""
    p = demo_dir / CONTROLS_FILE
    try:
        data = json.loads(p.read_text()) if p.exists() else {}
    except json.JSONDecodeError:
        data = {}
    ext, atk, order = data.get("external_input"), data.get("node_attack"), str(data.get("foreign_order") or "")
    order = order if ORDER_ID.match(order) else ""
    return {"external_input": ext if ext in EXTERNAL_INPUT else DEFAULTS["external_input"],
            "node_attack": atk if atk in NODE_ATTACKS else DEFAULTS["node_attack"],
            "foreign_order": order,
            # What the agent will read on top of the request when the switch is on (duffel).
            "injection_text": injection_for("duffel", order or None,
                                            inject_style_of(ext)).strip()}


def write_controls(mode: str | None = None, demo_dir: pathlib.Path = DEMO_DIR,
                   node_attack: str | None = None, foreign_order: str | None = None) -> dict:
    """Set one or more controls. The others keep their value.

    Args:
        mode: The external input (one of `EXTERNAL_INPUT`), or None to keep it.
        demo_dir: The directory that holds `CONTROLS_FILE`.
        node_attack: The node attacker (one of `NODE_ATTACKS`), or None to keep it.
        foreign_order: The attacker's Duffel order id, "" to clear it, or None to keep it.

    Returns:
        The controls as `read_controls` returns them after the write.

    Raises:
        ValueError: A value is not one of the allowed ones.
    """
    if mode is not None and mode not in EXTERNAL_INPUT:
        raise ValueError(f"external input is one of {EXTERNAL_INPUT}")
    if node_attack is not None and node_attack not in NODE_ATTACKS:
        raise ValueError(f"node attack is one of {NODE_ATTACKS}")
    if foreign_order is not None and foreign_order != "" and not ORDER_ID.match(foreign_order):
        raise ValueError("the attacker's order id must look like ord_… (a Duffel order id), or be empty")
    current = read_controls(demo_dir)
    if mode is not None:
        current["external_input"] = mode
    if node_attack is not None:
        current["node_attack"] = node_attack
    if foreign_order is not None:
        current["foreign_order"] = foreign_order
    current.pop("injection_text", None)
    demo_dir.mkdir(parents=True, exist_ok=True)
    (demo_dir / CONTROLS_FILE).write_text(json.dumps(current))
    return read_controls(demo_dir)


class ApprovalStore:
    """Pending requests of every run in the demo directory, and the answers given.

    An answered id stays in `decided` for the life of the process, so a second answer for
    the same id is refused even if the request file were still there (the runner unlinks
    it, but a decision must not depend on that).
    """

    def __init__(self, demo_dir: pathlib.Path = DEMO_DIR) -> None:
        self.demo_dir = demo_dir
        self.decided: set[str] = set()
        self._lock = threading.Lock()

    def _run_dirs(self) -> list[pathlib.Path]:
        """Every run directory with a pending request, not only the `latest` ones.

        A run started by hand or by another front end moves `latest`. A request of the run this
        panel was showing must neither vanish nor be confused with the new one. Each request
        names its run through its approval_id (sha256 over run_id and object), so showing all
        of them is unambiguous.
        """
        return sorted(p.parent for p in self.demo_dir.glob("*/approval-request.json"))

    def pending(self) -> list[dict]:
        """Every request currently waiting for a decision, as trusted records."""
        out = []
        for run_dir in self._run_dirs():
            p = run_dir / "approval-request.json"
            if not p.exists():
                continue
            try:
                req = json.loads(p.read_text())
            except json.JSONDecodeError:
                continue                       # the runner is still writing it
            if not req.get("approval_id") or req["approval_id"] in self.decided:
                continue
            out.append(pending_record(run_dir.name, req))
        return out

    def decide(self, approval_id: str, given_hash: str, granted: bool) -> tuple[int, dict]:
        """Answer one request.

        The id, the hash and the choice between approve and reject are all a client
        contributes. What is approved is the server's own pending request, and the answer
        carries the hash of the stored request.

        Args:
            approval_id: The id of the request, from the URL path.
            given_hash: The policy hash the client repeats.
            granted: True to approve, False to reject.

        Returns:
            (http status, response body).
        """
        with self._lock:
            if approval_id in self.decided:
                return 409, {"error": "already decided", "approval_id": approval_id}
            for run_dir in self._run_dirs():
                p = run_dir / "approval-request.json"
                if not p.exists():
                    continue
                try:
                    req = json.loads(p.read_text())
                except json.JSONDecodeError:
                    continue
                if req.get("approval_id") != approval_id:
                    continue
                want = policy_hash(req)
                if not given_hash or given_hash != want:
                    return 409, {"error": "policy hash does not match the pending request",
                                 "approval_id": approval_id}
                # Written once across processes (O_EXCL), whether the answer comes from this
                # panel, the dashboard or a second tab. The runner removes approval.json before
                # it writes a new request, so the first answer to a request wins and every
                # later one is a 409.
                if not write_once(run_dir / "approval.json",
                                  {"granted": bool(granted), "approval_id": approval_id, "policy_hash": want}):
                    self.decided.add(approval_id)
                    return 409, {"error": "already decided", "approval_id": approval_id}
                self.decided.add(approval_id)
                return 200, {"ok": True, "approval_id": approval_id, "granted": bool(granted)}
            # Unknown, expired (the runner removed the request at its timeout) or replaced.
            # Nothing is re-created here, because a new request can only come from the run.
            return 404, {"error": "expired or no longer pending", "approval_id": approval_id}


STORE = ApprovalStore()
#: Origins a browser may POST from: the panel's own (set from --port in main).
ALLOWED_ORIGINS: frozenset[str] = origins_for(8766)
#: The Authority's approval page on the cluster path (booking_approval.surface, reached through
#: the port-forward of scripts/gke-v5/49_approval_page.sh). Pass it with --authority-url.
CLUSTER_AUTHORITY_URL = "http://localhost:8450/"
#: The page the shell embeds, set from --authority-url in main. "" means the local panel.
AUTHORITY_URL = ""


def shell_authority_url() -> str:
    """Return the approval page the shell embeds, or "" for the local panel.

    The choice is explicit. The shell never guesses from what happens to listen on a port,
    because a foreign process on that port would otherwise be embedded as the approval page.
    """
    return AUTHORITY_URL


class Handler(BaseHTTPRequestHandler):
    """The panel, the pending list, the answers and the demo controls."""

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        """Write one complete response."""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:                                  # noqa: N802
        """Serve the pages, the shell config, the pending requests and the controls."""
        path = urlparse(self.path).path
        if path == "/":
            return self._send(200, (HERE / "approval-ui" / "shell.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/panel":
            return self._send(200, (HERE / "approval-ui" / "index.html").read_bytes(), "text/html; charset=utf-8")
        if path == "/api/shell-config":
            # Where the shell loads its approval panel from: the Authority's own page, or
            # "" for a deployment without the gate, which then uses the local panel.
            return self._send(200, json.dumps({"authority_url": shell_authority_url()}).encode())
        if path == "/api/approvals/pending":
            return self._send(200, json.dumps(STORE.pending()).encode())
        if path in ("/api/demo/external-input", "/api/demo/node-attack", "/api/demo/controls"):
            return self._send(200, json.dumps(read_controls(STORE.demo_dir)).encode())
        return self._send(404, b'{"error":"not found"}')

    def _authorized(self) -> bool:
        """The proof-of-concept identity check: a bearer token when APPROVAL_TOKEN is set, else loopback trust."""
        want = os.environ.get("APPROVAL_TOKEN", "")
        if not want:
            return True
        got = self.headers.get("Authorization", "")
        return got.startswith("Bearer ") and secrets.compare_digest(got[7:], want)

    def do_POST(self) -> None:                                 # noqa: N802
        """Answer a pending request or set a demo control. Every other route is a 404."""
        why = refuse(self.headers, ALLOWED_ORIGINS)
        if why:
            return self._send(403, json.dumps({"error": why}).encode())
        parts = urlparse(self.path).path.strip("/").split("/")
        n = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, b'{"error":"bad json"}')
        if not self._authorized():
            return self._send(401, b'{"error":"an approver identity is required"}')
        if parts == ["api", "demo", "external-input"]:
            try:
                return self._send(200, json.dumps(write_controls(str(body.get("mode", "")), STORE.demo_dir)).encode())
            except ValueError as exc:
                return self._send(400, json.dumps({"error": str(exc)}).encode())
        if parts == ["api", "demo", "foreign-order"]:
            try:
                controls = write_controls(None, STORE.demo_dir, foreign_order=str(body.get("order_id", "")).strip())
                return self._send(200, json.dumps(controls).encode())
            except ValueError as exc:
                return self._send(400, json.dumps({"error": str(exc)}).encode())
        if parts == ["api", "demo", "node-attack"]:
            try:
                controls = write_controls(None, STORE.demo_dir, node_attack=str(body.get("attack", "")))
                return self._send(200, json.dumps(controls).encode())
            except ValueError as exc:
                return self._send(400, json.dumps({"error": str(exc)}).encode())
        if len(parts) != 4 or parts[:2] != ["api", "approvals"] or parts[3] not in ("approve", "reject"):
            return self._send(404, b'{"error":"not found"}')
        # Only the hash is read from the body. The id comes from the path, and every other
        # field is ignored.
        code, payload = STORE.decide(parts[2], str(body.get("policy_hash", "")), parts[3] == "approve")
        return self._send(code, json.dumps(payload).encode())

    def log_message(self, *args) -> None:
        """Suppress the default access log."""


def main(argv=None) -> int:
    """Start the approval panel."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--authority-url", default="",
                    help="the Authority's approval page shown in the shell's drawer, for example "
                         f"{CLUSTER_AUTHORITY_URL} on the cluster path (default: '', the local panel)")
    args = ap.parse_args(argv)
    global ALLOWED_ORIGINS, AUTHORITY_URL
    ALLOWED_ORIGINS = origins_for(args.port)
    AUTHORITY_URL = args.authority_url
    print(f"approval panel: http://{args.host}:{args.port}/   (runs under {DEMO_DIR})")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
