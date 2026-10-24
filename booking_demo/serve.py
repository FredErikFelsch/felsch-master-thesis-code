"""A small local server for the dashboard: static page, the latest run's events, approvals.

    python3 -m booking_demo.serve [--port 8765]     then open http://localhost:8765/

GET  /                 dashboard.html (everything at once)
GET  /launcher         the launcher's state (busy, live budget, usable models)
GET  /events.json      events of the latest run (results_v5/demo/latest.json → dir)
GET  /runs             list of recorded runs (for the replay picker)
GET  /events.json?run=<dir>   events of a specific run
POST /approve          {"approval_id", "policy_hash", "granted"} → <run>/approval.json, only for
                       the request the page displayed (same store as ui.approval_api)
POST /chat             {"text": "..."} → <run>/chat.json, the reply to a pending chat-request.json
                       of this server's run (WAITING_FOR_USER_CONTINUATION). The reply continues
                       the conversation. It does not change the approved policy and it is not
                       an approval.
POST /run              {"task": "...", "world": "duffel", "mode": "v3", "model": "anthropic",
                        "inject": bool}
                       starts one run, always with --plan agent --approve wait, because a typed
                       request is an input to the planning phase and not a policy. While a run
                       waits for a continuation, POST /run is treated like POST /chat, so the
                       one chat input resumes the run instead of planning a new one.
                       Mode "v5" runs on the CoCo cluster through
                       `scripts/gke-v5/33_demo_v5.sh` (the deployed world must match, and the
                       Authority refuses a policy it cannot execute), without any provider
                       credential in its environment.

Every POST needs application/json and, when a browser sends an Origin, one of the server's
own (http_guard). Those are `localhost` and `127.0.0.1` on the server's port, whatever
`--host` it binds. A browser on another machine reaches the dashboard through an SSH tunnel
to localhost, see README.md.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = pathlib.Path(__file__).resolve().parent
MOCKS = HERE.parent
DEMO_DIR = MOCKS / "results_v5" / "demo"

MAX_TASK_LEN = 600
WORLDS = ("mock", "serpapi", "duffel")
MODES = ("v0", "v3", "v5-local", "v5")
#: The credentials a v5 (cluster) run must not inherit. The provider credential lives only
#: in the gateway (OpenBao), and the controller does not need it.
PROVIDER_SECRETS = ("DUFFEL_TOKEN", "SERPAPI_KEY")
MODELS = ("scripted", "anthropic", "openai")
#: Which environment variable each model needs. It is checked before launching, because a
#: missing key otherwise surfaces as a run that starts and dies a second later.
MODEL_KEYS = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


class RunLauncher:
    """Starts demo runs on request, one at a time, with a budget per server start.

    A live run spends real quota and creates real hold orders, so the number of live runs
    per server start is capped. Mock runs are not counted.
    """

    def __init__(self, max_live_runs: int, cluster_pool: int = 3) -> None:
        self.max_live_runs = max_live_runs
        self.cluster_pool = cluster_pool
        self.live_used = 0
        self._lock = threading.Lock()
        self._current: subprocess.Popen | None = None
        #: The id this launcher gave its current run (DEMO_LAUNCH_ID). The run writes its
        #: directory under it, so a paused run is found by launch rather than by `latest`.
        self.launch_id: str | None = None

    @property
    def busy(self) -> bool:
        """Return True while the run this launcher started is still alive."""
        return self._current is not None and self._current.poll() is None

    def launched_run(self) -> pathlib.Path | None:
        """Return the run directory of the run this launcher started last, once it announced it."""
        from .continuation import launched_run
        return launched_run(DEMO_DIR, self.launch_id)

    def waiting_run(self) -> pathlib.Path | None:
        """Return this launcher's run if it is alive and paused in WAITING_FOR_USER_CONTINUATION."""
        from .continuation import waiting_request
        run = self.launched_run()
        return run if self.busy and waiting_request(run) is not None else None

    def status(self) -> dict:
        """Return the launcher state for the dashboard: busy flag, live budget and the usable models."""
        return {"busy": self.busy, "live_used": self.live_used,
                "live_left": max(0, self.max_live_runs - self.live_used),
                "models": [m for m in MODELS
                           if m not in MODEL_KEYS or os.environ.get(MODEL_KEYS[m])]}

    def start(self, task: str, world: str, mode: str, inject: bool,
              model: str = "scripted", attack: str = "", foreign_order: str = "",
              inject_style: str = "naive") -> tuple[int, dict]:
        """Validate the request, then launch the run.

        Args:
            task: The typed request.
            world: One of WORLDS.
            mode: One of MODES.
            inject: Whether the injection is added to what the agent reads.
            model: One of MODELS.
            attack: A node attack (a10, a16, a18), or "". a10 and a18 run against step 0 of
                the approved run, a16 in a throwaway run first. An attack needs an attested
                mode, because only the attested path refuses it.
            foreign_order: The attacker's Duffel order id for the injection, or "".
            inject_style: "naive", "combined" or "correction".

        Returns:
            (http status, body).
        """
        task = (task or "").strip()
        if not task:
            return 400, {"error": "a request is required"}
        if len(task) > MAX_TASK_LEN:
            return 400, {"error": f"a request is at most {MAX_TASK_LEN} characters"}
        if world not in WORLDS or mode not in MODES or model not in MODELS:
            return 400, {"error": "unknown world, mode or model"}
        if inject_style not in ("naive", "combined", "correction"):
            return 400, {"error": "unknown injection style"}
        if foreign_order:
            from .live import ORDER_ID
            if not ORDER_ID.match(foreign_order):
                return 400, {"error": "the attacker's order id is not a Duffel order id (ord_...)"}
        if attack and attack not in ("a10", "a16", "a18"):
            return 400, {"error": "unknown node attack"}
        if attack and not mode.startswith("v5"):
            return 400, {"error": f"the node attacker ({attack}) needs the attested path: pick a v5 mode"}
        needed = MODEL_KEYS.get(model)
        if needed and not os.environ.get(needed):
            return 400, {"error": f"{model} needs {needed} in the environment of this "
                                  f"server. Export it and restart the server."}

        with self._lock:
            if self.busy:
                return 409, {"error": "a run is still going"}
            if world != "mock" and self.live_used >= self.max_live_runs:
                return 429, {"error": f"live run budget spent ({self.max_live_runs} per "
                                      f"server start). Restart the server to reset."}
            # --plan agent is not optional here. A typed request has no frozen policy, so the
            # agent proposes one and a human approves it before anything executes.
            self.launch_id = uuid.uuid4().hex
            env = dict(os.environ)
            if mode == "v5":
                # The cluster path: `scripts/gke-v5/33_demo_v5.sh` supplies the controller
                # context, the impersonated controller identity and the admin context of the
                # human's credential.
                argv = ["bash", str(MOCKS / "scripts" / "gke-v5" / "33_demo_v5.sh"),
                        "--world", world, "--model", model, "--plan", "agent",
                        "--approve", "wait", "--pool", str(self.cluster_pool), "--task", task]
                env = {k: v for k, v in os.environ.items() if k not in PROVIDER_SECRETS}
            else:
                argv = [sys.executable, "-m", "booking_demo.run", "--mode", mode,
                        "--world", world, "--model", model, "--plan", "agent",
                        "--approve", "wait", "--task", task]
            if inject:
                argv += ["--inject", "--inject-style", inject_style]
                if foreign_order:
                    argv += ["--foreign-order", foreign_order]
            if attack:
                argv += ["--attack", attack]
            env["DEMO_LAUNCH_ID"] = self.launch_id
            self._current = subprocess.Popen(argv, cwd=str(MOCKS), env=env)   # no shell, argv only
            if world != "mock":
                self.live_used += 1
            return 200, {"started": True, **self.status()}


LAUNCHER = RunLauncher(max_live_runs=5)
#: Origins a browser may POST from (http_guard): this server's own page. Set in main().
ALLOWED_ORIGINS: frozenset[str] = frozenset({"http://localhost:8765", "http://127.0.0.1:8765"})


def _latest_dir(demo: str = "booking") -> pathlib.Path | None:
    name = "latest-devops.json" if demo == "devops" else "latest.json"
    p = DEMO_DIR / name
    if not p.exists():
        return None
    return DEMO_DIR / json.loads(p.read_text())["dir"]


_APPROVALS = None


def _approvals():
    """Return the approval store of ui.approval_api.

    The store checks id and hash against the pending record and writes the answer once. It
    is imported on first use, because that module imports this one.
    """
    global _APPROVALS
    if _APPROVALS is None:
        from ui.approval_api import ApprovalStore
        _APPROVALS = ApprovalStore(DEMO_DIR)
    return _APPROVALS


class Handler(BaseHTTPRequestHandler):
    """The dashboard's HTTP handler. Routes are listed in the module docstring."""

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:                                  # noqa: N802
        """Serve the pages, the run list and the events of a run."""
        url = urlparse(self.path)
        if url.path == "/":
            return self._send(200, (HERE / "dashboard.html").read_bytes(), "text/html; charset=utf-8")
        if url.path == "/launcher":
            return self._send(200, json.dumps(LAUNCHER.status()).encode())
        if url.path == "/runs":
            demo = parse_qs(url.query).get("demo", ["booking"])[0]
            all_dirs = sorted(p.name for p in DEMO_DIR.iterdir() if p.is_dir()) if DEMO_DIR.exists() else []
            runs = [n for n in all_dirs if ("devops" in n) == (demo == "devops")]
            return self._send(200, json.dumps(runs).encode())
        if url.path == "/events.json":
            q = parse_qs(url.query)
            run_dir = DEMO_DIR / q["run"][0] if "run" in q else _latest_dir(q.get("demo", ["booking"])[0])
            if run_dir is None or not (run_dir / "events.json").exists():
                return self._send(200, b"[]")

            def _read_json(path, default):
                # The run process rewrites these files continuously, so a read may catch a
                # partial write. A bad read returns the default instead of crashing, and the
                # dashboard polls again shortly after and gets the whole file.
                try:
                    txt = path.read_text()
                    return json.loads(txt) if txt.strip() else default
                except (json.JSONDecodeError, FileNotFoundError, ValueError):
                    return default
            events = _read_json(run_dir / "events.json", None)
            if events is None:
                return self._send(200, b'{"stale":true}')   # tell the client to keep its current view
            pending = run_dir / "approval-request.json"
            chat = run_dir / "chat-request.json"
            from .approval_record import policy_hash
            from .continuation import is_orphaned
            approval = _read_json(pending, None) if pending.exists() else None
            if approval:
                # What the dashboard must send back: this request's id and its hash.
                approval = {**approval, "policy_hash": policy_hash(approval), "run": run_dir.name}
            ours = LAUNCHER.launched_run() == run_dir
            payload = {"run": run_dir.name, "events": events, "approval_request": approval,
                       "chat_request": (_read_json(chat, None) if chat.exists() and ours and LAUNCHER.busy
                                        else None),
                       "orphaned": is_orphaned(run_dir, LAUNCHER.busy if ours else None)}
            return self._send(200, json.dumps(payload).encode())
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:                                 # noqa: N802
        """Start a run, reply to a paused one, or record an approval decision."""
        from .http_guard import refuse
        why = refuse(self.headers, ALLOWED_ORIGINS)
        if why:
            return self._send(403, json.dumps({"error": why}).encode())
        path = urlparse(self.path).path
        if path == "/run":
            n = int(self.headers.get("Content-Length", "0"))
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, b'{"error":"bad json"}')
            # One chat input, one routing rule. A run waiting for the user's continuation gets
            # the message as a reply to the same execution, and no planning phase or new
            # policy starts while such a run exists.
            waiting = LAUNCHER.waiting_run()
            if waiting is not None:
                return self._reply_to(waiting, str(body.get("task", "")))
            code, payload = LAUNCHER.start(str(body.get("task", "")),
                                           str(body.get("world", "mock")),
                                           str(body.get("mode", "v3")),
                                           bool(body.get("inject")),
                                           str(body.get("model", "scripted")))
            return self._send(code, json.dumps(payload).encode())
        if path == "/chat":
            return self._chat()
        if path != "/approve":
            return self._send(404, b'{"error":"not found"}')
        n = int(self.headers.get("Content-Length", "0"))
        try:
            decision = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, b'{"error":"bad json"}')
        # The dashboard answers the request it displayed, with its approval_id and policy
        # hash. The same store as the approval panel checks them (pending now, unused, hash
        # equal, written once). A request that changed, expired or was answered elsewhere
        # gets 404 or 409 instead of an answer for whatever happens to be pending.
        code, payload = _approvals().decide(str(decision.get("approval_id", "")),
                                            str(decision.get("policy_hash", "")),
                                            bool(decision.get("granted")))
        return self._send(code, json.dumps(payload).encode())

    def _chat(self) -> None:
        """POST /chat: the same routing as /run, for clients that only ever reply."""
        n = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, b'{"error":"bad json"}')
        waiting = LAUNCHER.waiting_run()
        if waiting is None:
            return self._send(409, b'{"error":"no run of this server is waiting for a continuation"}')
        return self._reply_to(waiting, str(body.get("text", "")))

    def _reply_to(self, run_dir: pathlib.Path, text: str) -> None:
        """Resume this server's paused run.

        `continuation.resume` binds the reply to the pending chat_id and writes it once. A
        reply resumes the run and grants nothing.
        """
        from .continuation import resume
        code, payload = resume(run_dir, text)
        return self._send(code, json.dumps(payload).encode())

    def log_message(self, *args) -> None:
        """Silence the default access log."""


def main(argv=None) -> int:
    """Serve the dashboard until interrupted."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to bind (default loopback). The server only accepts POSTs from "
                         "localhost and 127.0.0.1 origins, so a browser on another machine should "
                         "use an SSH tunnel to localhost instead of 0.0.0.0")
    ap.add_argument("--max-live-runs", type=int, default=5,
                    help="live runs allowed per server start (they spend real quota)")
    ap.add_argument("--cluster-pool", type=int, default=3,
                    help="warm TD pool for mode v5 (cluster) runs")
    args = ap.parse_args(argv)
    global ALLOWED_ORIGINS
    from .http_guard import origins_for
    ALLOWED_ORIGINS = origins_for(args.port)
    LAUNCHER.max_live_runs = args.max_live_runs
    LAUNCHER.cluster_pool = args.cluster_pool
    print(f"dashboard: http://{args.host}:{args.port}/   (runs under {DEMO_DIR})")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
