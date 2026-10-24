"""An OpenAI-compatible chat facade in front of the agent run, for Open WebUI.

    python3 -m ui.agent_api [--port 8767]
    Open WebUI: OPENAI_API_BASE_URL=http://host.docker.internal:8767/v1  OPENAI_API_KEY=unused

GET  /v1/models              one "model" per (mode, world) the launcher accepts
POST /v1/chat/completions    the last user message is the task of a single run (booking_demo.run
                             --plan agent --approve wait), started through the launcher the
                             dashboard uses

While a run of this server is paused in WAITING_FOR_USER_CONTINUATION, the next message resumes
that run. It does not plan again, does not change the policy and does not count as an approval.
It resumes the run only from the conversation that started it (X-OpenWebUI-Chat-Id, forwarded
with ENABLE_FORWARD_USER_INFO_HEADERS). Without that header the demo assumes a single local
operator.

The reply streams the run record: the proposed plan, "Waiting for human approval.", the
monitor's decisions and the end. This process only starts runs and relays their record.
Approvals are answered in the local panel (ui/approval_api.py), on the dashboard
(booking_demo.serve) or, with the WebAuthn gate, on the Authority's page. A chat message reaches
none of them.

No OpenBao, gateway or Authority credential lives in this process. Provider tokens are a
different matter. The v5 runs start without `PROVIDER_SECRETS` (booking_demo.serve) in their
environment, but every other mode passes the whole environment of this process to the run, so
a local duffel run takes DUFFEL_TOKEN from here. The brain of the agent (scripted, openai,
anthropic) is AGENT_BRAIN, and its API key comes from the same environment.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from booking_demo.continuation import is_orphaned, resume
from booking_demo.http_guard import refuse
from booking_demo.serve import DEMO_DIR, LAUNCHER, MODEL_KEYS
from .approval_api import inject_style_of, read_controls

#: The Open WebUI header naming the conversation (sent with ENABLE_FORWARD_USER_INFO_HEADERS).
CHAT_HEADER = "X-OpenWebUI-Chat-Id"
#: Run directory name → the conversation that started it (None: the chat sent no id). The
#: binding lives only in this process, and Open WebUI's chat history cannot restore it.
BINDINGS: dict[str, str | None] = {}
_BIND_LOCK = threading.Lock()
#: Browser origins allowed to POST here. Open WebUI calls from its backend and sends none. A
#: page in a browser sends one and is refused unless it is listed (AGENT_API_ALLOWED_ORIGINS).
ALLOWED_ORIGINS = frozenset(o.strip().rstrip("/") for o in
                            os.environ.get("AGENT_API_ALLOWED_ORIGINS", "").split(",") if o.strip())

#: The models Open WebUI can pick, each a mode and a world of the run. Baseline v0 is in the
#: list so the demo can show the damage from the same chat. v5-duffel is the CoCo cluster, with
#: every step in a fresh attested TD and the credential in OpenBao behind the gateway.
MODELS = ("v0-mock", "v3-mock", "v3-duffel", "v5-local-mock", "v5-local-duffel", "v5-duffel")
MODE_LABEL = {"v0": "baseline without monitor", "v3": "monitored", "v5-local": "attested path with local fakes",
              "v5": "attested path on Intel TDX"}
#: How long a cluster run may take to write its first event. The controller connects, waits
#: for the warm pool (up to 300 s, `--warm-wait` in booking_demo/run.py) and only then starts
#: the session.
START_TIMEOUT = {"v5": 720.0}
#: Cached cluster preflight (the kube and gcloud lookups cost a second or two).
_PREFLIGHT: dict = {"t": 0.0, "problems": []}
REFUSED = {"DENIED", "GRANT_REFUSED", "GATEWAY_REFUSED", "FINALIZE_REFUSED", "RUN_TERMINATED",
           "ATTESTATION_REFUSED", "RUNNER_ERROR", "UNCERTAIN"}


def brain() -> str:
    """Which model proposes the plan and the calls: AGENT_BRAIN, else the first with a key."""
    want = os.environ.get("AGENT_BRAIN")
    if want:
        return want
    for name, key in MODEL_KEYS.items():
        if os.environ.get(key):
            return name
    return "scripted"


def cluster_preflight(now: float | None = None) -> list[str]:
    """List what a `v5` run needs before it can start, as human-readable problems.

    scripts/gke-v5/33_demo_v5.sh takes the cluster identities from the shell: the narrow kube
    context `v5-controller`, the admin context as the current one, and the gcloud project. A
    missing piece otherwise surfaces as a run that dies a minute later with nothing in the chat.
    The result is cached for 60 s.

    Args:
        now: The current time in seconds, for tests. Defaults to `time.time()`.

    Returns:
        The problems found, empty when the cluster path looks ready.
    """
    now = now or time.time()
    if now - _PREFLIGHT["t"] < 60:
        return list(_PREFLIGHT["problems"])
    problems: list[str] = []

    def run(argv: list[str]) -> str | None:
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=15).stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            return None
    contexts = run(["kubectl", "config", "get-contexts", "-o", "name"])
    current = run(["kubectl", "config", "current-context"])
    if contexts is None:
        problems.append("kubectl is not available to this process")
    else:
        if "v5-controller" not in contexts.split():
            problems.append("no kube context v5-controller (run 30_deploy_v5.sh or 47_demo_up.sh)")
        if not current:
            problems.append("no current kube context (gcloud container clusters get-credentials ...)")
        elif current == "v5-controller":
            problems.append("the current kube context is the controller, but the human needs the admin context")
    project = os.environ.get("PROJECT") or run(["gcloud", "config", "get-value", "project"])
    if not project:
        problems.append("no gcloud project (PROJECT in the environment, or gcloud config set project)")
    _PREFLIGHT.update(t=now, problems=problems)
    return list(problems)


def split_model(model_id: str) -> tuple[str, str]:
    """Split a model id into mode and world, for example `v5-local-duffel` → ("v5-local", "duffel").

    Raises:
        ValueError: The id is not one of `MODELS`.
    """
    if model_id not in MODELS:
        raise ValueError(f"unknown model {model_id!r}, use one of {', '.join(MODELS)}")
    mode, _, world = model_id.rpartition("-")
    return mode, world


#: How a run's end status reads in the chat. Any other status is shown as it is.
END_LABEL = {
    "COMPLETED": "✅ **Run completed**",
    "ANSWERED": "",
    "TERMINATED": "⛔ **Run stopped**",
    "PLAN_REJECTED": "**Plan not approved**",
    "ATTACKS_ONLY": "**Attack runs finished**",
    "EFFECT_UNCERTAIN": "⚠️ **Run parked: the outcome of a step is uncertain**",
    "EFFECT_FAILED": "⚠️ **Run parked: a step failed at the provider**",
    "ACTIVE": "**Run ended before the plan was done**",
}
#: How a refusal status reads in the chat.
REFUSAL_LABEL = {
    "DENIED": "refused by the monitor",
    "GRANT_REFUSED": "refused by the Authority",
    "GATEWAY_REFUSED": "refused by the gateway",
    "FINALIZE_REFUSED": "result not accepted by the Authority",
    "RUN_TERMINATED": "the run was already stopped",
    "ATTESTATION_REFUSED": "attestation refused",
    "RUNNER_ERROR": "the confidential VM did not answer",
    "UNCERTAIN": "outcome uncertain",
}


def _step(e: dict) -> str:
    """Return "step N" with the 1-based number of an event, or "a step" when it carries none."""
    s = e.get("step")
    try:
        return f"step {int(s) + 1}"
    except (TypeError, ValueError):
        return "a step"


def _seconds(value) -> str:
    """A duration for the chat, whole seconds from ten seconds on."""
    v = float(value or 0)
    return f"{v:.0f} s" if v >= 10 else f"{v:.1f} s"


def _td_detail(att: dict | None) -> str:
    """The attestation detail of a step, or "" when the step ran without a TD."""
    if not att:
        return ""
    after = " after your approval" if att.get("continuation") else ""
    vm = "fresh confidential VM" if after else "confidential VM"
    return f"  \n_{vm} `{att.get('td', '')}`{after} · attestation verified · {_seconds(att.get('total_s'))}_"


class Narration:
    """Turns the events of one run into chat lines.

    A step on the attested path produces two events, the attestation of its TD and the
    decision. They read as one line, so the attestation is held until its decision arrives.
    """

    def __init__(self) -> None:
        self._attested: dict | None = None

    def line(self, e: dict) -> str | None:
        """Return the chat line for one event, or None to stay quiet."""
        k = e.get("kind")
        if k == "attested":
            td, outcome = e.get("td"), str(e.get("outcome", ""))
            if not td and not outcome:
                return None
            if outcome == "ACCEPTED" or outcome.startswith("MONITOR("):
                self._attested = e
                return None
            self._attested = None
            return f"⛔ The confidential VM `{td}` was not accepted: attestation {outcome.lower()}."
        if k == "decision":
            att, self._attested = self._attested, None
            return _decision(e, att)
        line = narrate(e)
        if self._attested is not None:
            # An attestation whose decision never came (the run ended or paused first) is
            # still shown, before the line of the event that ended it.
            att, self._attested = self._attested, None
            held = f"🔒 {_td_detail(att).strip().strip('_')}"
            return held if line is None else f"{held}\n\n{line}"
        return line


def _decision(e: dict, att: dict | None) -> str | None:
    """The line for a monitor decision, with the attestation of its TD if there was one."""
    st, tool, n = e.get("status"), e.get("tool"), _step(e).capitalize()
    if st == "LOCAL":
        return None
    if st == "STEP_COMPLETED":
        return f"✓ **{n}** `{tool}`{_td_detail(att)}"
    if st == "REQUIRE_APPROVAL":
        return f"⏸ **{n}** `{tool}` waits for your approval.{_td_detail(att)}"
    if st in REFUSED:
        why = f": {e['reason']}" if e.get("reason") else ""
        return f"✗ **{n}** `{tool}` {REFUSAL_LABEL.get(st, str(st).lower())}{why}"
    if st == "EXECUTED":
        return f"**{n}** `{tool}` ran without any check (baseline v0, no monitor)."
    return f"**{n}** `{tool}`: {st}"


def narrate(e: dict) -> str | None:
    """Return one event of the run record as a chat line, or None to stay quiet.

    Steps are narrated by `Narration`, which joins a step's attestation and decision.
    """
    k = e.get("kind")
    if k == "start":
        mode = e.get("mode", "")
        domain = str(e.get("domain", ""))
        world = domain.split("-", 1)[1] if "-" in domain else "mock"     # booking-duffel → duffel
        world_label = {"duffel": "Duffel test mode", "mock": "simulated provider"}.get(world, world)
        control = read_controls()["external_input"]
        attacks = ", ".join(e.get("attacks") or []) or "none"
        return (f"**New run** · {MODE_LABEL.get(mode, mode)} · {world_label} · agent {e.get('model_id', '')}  \n"
                f"_Untrusted input: {control} · attacker on the node: {attacks} · run `{e.get('run_id', '')}`_")
    if k == "mail":
        hl = e.get("highlight")
        if hl and hl in str(e.get("text", "")):
            # The injected part of what the agent reads, quoted once so the viewer sees the
            # attack in the same window as its refusal.
            quoted = "\n".join("> " + line for line in str(hl).splitlines() if line.strip())
            return f"📩 **The content the agent reads carries an injection:**\n{quoted}"
        return None
    if k == "stopped":
        return f"Stopped at your request. Not executed: {', '.join(e.get('remaining') or [])}."
    if k == "runner_error":
        return (f"⚠️ `{e.get('tool')}` could not run: {e.get('reason')}. The confidential VM did not answer, "
                "so nothing reached the provider. The agent may propose the step again.")
    if k == "warm_pool":
        if e.get("state") == "waiting":
            return f"Starting {e.get('size')} confidential VMs for the run …"
        return f"{e.get('ready')} of {e.get('size')} confidential VMs ready after {_seconds(e.get('waited_s'))}."
    if k == "attack_start":
        return (f"⚔️ **Attack on the node** `{e.get('attack')}`: before the real run, the host beneath the "
                "runner attacks one throwaway step …")
    if k == "attack":
        where = e.get("blocked_at", "")
        contained = bool(e.get("pass"))
        if not contained:
            return (f"‼️ `{e.get('attack')}` ({e.get('label', '')}): {e.get('status', '')}, ledger delta "
                    f"{e.get('ledger_delta')}. An effect is not ruled out.")
        line = f"⛔ **Blocked** `{e.get('attack')}` ({e.get('label', '')}) at {where}."
        if e.get("attributed") and "monitor" not in where:
            # Only a verdict of the attested path explains the refusal. A harness error with a
            # ledger that did not move is no effect, but it says nothing about why.
            line += " The attested path refused it before the monitor ran."
        return line + " No effect reached the provider."
    if k == "attested":
        return Narration().line(e)
    if k == "decision":
        return _decision(e, None)
    if k == "plan_proposed":
        if e.get("no_steps"):
            return "No tool is needed for this message, so nothing runs and nothing needs approval."
        if e.get("invalid"):
            return f"The plan was refused before it reached you: {e['invalid']}"
        ap = e.get("approved_policy") or {}
        steps = " → ".join(f"{i + 1}. `{s['tool']}`" for i, s in enumerate(ap.get("steps", [])))
        budget = ap.get("budget_minor")
        shown = f"{budget / 100:,.2f}" if isinstance(budget, (int, float)) else "unknown"
        p = ap.get("parameters") or {}
        route = (f" · {p.get('origin')} → {p.get('destination')} · {p.get('date')} · {p.get('cabin')}"
                 if p.get("origin") and p.get("destination") else "")
        return (f"**Proposed plan**{route}  \n{steps}  \n"
                f"_Budget up to {shown} {ap.get('currency', '')} · policy `{ap.get('digest', '')[:12]}`_")
    if k == "approval_request":
        # The decision is made on the Authority's page in the drawer beside the chat. The chat
        # can say that a decision is pending but cannot approve.
        tool = f" `{e['tool']}`" if e.get("tool") else ""
        what = "the plan" if e.get("subject") == "plan" else f"{_step(e)}{tool}"
        return f"🔐 **Your approval is needed** for {what}. Confirm it with your passkey in the approval panel."
    if k == "plan_decision":
        if e.get("approver") == "no-steps":
            return None
        if e.get("granted"):
            who = e.get("approver", "").removeprefix("approver:")
            by = f" by {who} ({e['approver_kind']})" if e.get("approver_kind") else ""
            return f"✅ Plan approved{by}."
        if "in time" in str(e.get("reason", "")):
            return "The plan was not approved in time, so no run was created."
        return "The plan was not approved, so no run was created."
    if k == "paused":
        return (f"{e.get('message', '')}\n\n_The run is paused and waits for your reply. Next approved step: "
                f"`{e.get('next_step', '')}`. Your reply continues the run. It is not an approval, and a step "
                "that needs one still asks in the panel._")
    if k == "resumed":
        return f"Continuing the approved plan. Next step: `{e.get('next_step', '')}`."
    if k == "user_message":
        return "No reply arrived in time, so the run ends here." if e.get("timed_out") else None
    if k == "approval":
        if e.get("granted"):
            who = e.get("approver", "").removeprefix("approver:")
            return f"✅ Approved by {who} ({e['approver_kind']})." if e.get("approver_kind") else "✅ Approved."
        return "Not approved, so the step does not run."
    if k == "end":
        status = e.get("run_status")
        if status == "ANSWERED":
            return f"\n{e.get('message', '')}"
        head = END_LABEL.get(status, f"**{status}**") if status else "**Run finished** (baseline v0, no run record)"
        ledger = e.get("ledger")
        bad = e.get("unauthorized_effects") or 0
        if ledger is None:
            facts = ["No gateway ledger in the baseline"]
        else:
            n = len(ledger)
            facts = [f"Gateway ledger: {n} authorised effect{'s' if n != 1 else ''}",
                     "no unauthorised effect" if not bad else f"**{bad} unauthorised**"]
        for pay in e.get("payments") or []:
            if pay.get("paid") and isinstance(pay.get("amount_minor"), int):
                facts.append(f"paid {pay['amount_minor'] / 100:.2f} {pay.get('currency', '')} "
                             f"for `{pay.get('order_id', '')}`")
        tail = f"\n\n_{' · '.join(facts)}_"
        if e.get("unfinished_steps"):
            tail += (f"\n\nNot executed: {', '.join(e['unfinished_steps'])}. Nothing beyond the completed "
                     "steps happened.")
        body = f"\n\n{e.get('message', '')}" if e.get("message") else ""
        return f"\n{head}{body}{tail}"
    return None


def _latest_run() -> str | None:
    """The run directory name the launcher last announced, or None."""
    p = DEMO_DIR / "latest.json"
    try:
        return json.loads(p.read_text())["dir"] if p.exists() else None
    except (json.JSONDecodeError, KeyError):
        return None


def _events(run_dir: pathlib.Path) -> list[dict] | None:
    """The events of a run so far, or None while the record is missing or half written."""
    try:
        txt = (run_dir / "events.json").read_text()
        return json.loads(txt) if txt.strip() else None
    except (FileNotFoundError, ValueError):            # JSONDecodeError is a ValueError
        return None


def follow_run(mode: str = "v3", timeout: float = 900.0, conversation: str | None = None):
    """Yield the narration of the run the launcher just started, until it ends or pauses.

    The run announces its directory under the launcher's DEMO_LAUNCH_ID, so nothing is guessed
    from `latest`, which another run may move. It writes its first event only once the session
    starts. On the cluster that is minutes later, so a heartbeat line every 30 s shows that the
    run is still being prepared. The run is bound to `conversation` here, server side.

    Args:
        mode: The mode of the run, which sets how long its start may take.
        timeout: How long to follow the run once it has started, in seconds.
        conversation: The Open WebUI chat id that started the run, or None.

    Yields:
        One chat line per narrated event or heartbeat.
    """
    t0 = time.time()
    run_dir = None
    while time.time() - t0 < 30:
        run_dir = LAUNCHER.launched_run()
        if run_dir is not None:
            break
        time.sleep(0.3)
    else:
        yield "The run did not start (no run record appeared)."
        return
    with _BIND_LOCK:
        BINDINGS[run_dir.name] = conversation
    start_limit = START_TIMEOUT.get(mode, 60.0)
    last_beat = time.time()
    if mode == "v5":
        yield "Connecting to the cluster … The plan comes first, and the confidential VMs start once you approve it."
    while not (run_dir / "events.json").exists():
        if not LAUNCHER.busy:
            yield "The run ended before it started (see the agent api log)."
            return
        if time.time() - t0 > start_limit:
            yield f"Gave up waiting for the run to start after {start_limit:.0f} s."
            return
        if time.time() - last_beat >= 30:
            last_beat = time.time()
            yield f"… still preparing ({time.time() - t0:.0f} s)"
        time.sleep(1.0)
    yield from follow_events(run_dir, 0, timeout)


def follow_events(run_dir: pathlib.Path, seen: int, timeout: float = 900.0):
    """Narrate the events of `run_dir` from index `seen` until `end` or `paused`.

    A pause ends the current chat turn but not the run. The session keeps its state and waits
    for the next message of the same conversation.

    Args:
        run_dir: The run directory with `events.json`.
        seen: The number of events already narrated.
        timeout: How long to follow, in seconds.

    Yields:
        One chat line per narrated event or heartbeat.
    """
    t0 = time.time()
    quiet_since = time.time()
    narration = Narration()
    while time.time() - t0 < timeout:
        events = _events(run_dir) or []
        for e in events[seen:]:
            try:
                line = narration.line(e)
            except Exception as exc:                   # noqa: BLE001, one odd event must not end the stream
                print(f"[agent-api] could not narrate a {e.get('kind')!r} event: {exc!r}", file=sys.stderr)
                line = None
            if line:
                yield line
            if e.get("kind") in ("end", "paused"):
                return
        if len(events) > seen:
            quiet_since = time.time()
        elif time.time() - quiet_since >= 45:
            # A warm-up or a slow TD boot. Say that the run is alive rather than go silent.
            quiet_since = time.time()
            yield f"… still running ({time.time() - t0:.0f} s since this turn began)"
        seen = len(events)
        if not LAUNCHER.busy and seen == len(_events(run_dir) or []):
            time.sleep(1.0)                 # let a last write land
            if (_events(run_dir) or [])[seen:] == []:
                yield "The run ended without a record of its end."
                return
        time.sleep(0.5)
    yield "Stopped following the run (timeout)."


def resume_turn(run_dir: pathlib.Path, text: str, conversation: str | None) -> list[str] | None:
    """Answer this server's paused run from `conversation`.

    Args:
        run_dir: The paused run.
        text: The user's message, delivered as the continuation.
        conversation: The chat id of the message, or None.

    Returns:
        Error lines for the chat, or None when the reply was delivered and the caller should
        follow the run.
    """
    with _BIND_LOCK:
        owner = BINDINGS.get(run_dir.name)
    if owner is not None and conversation != owner:
        return [f"The paused run `{run_dir.name}` belongs to another conversation. "
                "This message changed nothing. Continue it from the chat that started it."]
    code, body = resume(run_dir, text)
    if code != 200:
        return [f"Not resumed: {body.get('error')}."]
    return None


def finishing_run() -> pathlib.Path | None:
    """The launched run when it has ended (an `end` event) but its process is still alive.

    On the cluster the controller releases its TDs after the record is complete, which takes
    a while. A new message then waits instead of being refused.
    """
    run_dir = LAUNCHER.launched_run()
    if run_dir is None or not LAUNCHER.busy:
        return None
    events = _events(run_dir) or []
    return run_dir if events and events[-1].get("kind") == "end" else None


def launch(task: str, world: str, mode: str, head: list[str], conversation: str | None):
    """Start one run and narrate it, after waiting for a finished run that is still tearing down.

    Args:
        task: The user's request, the task of the run.
        world: The world of the run (mock or duffel).
        mode: The mode of the run (v0, v3, v5-local or v5).
        head: Lines to send before the narration.
        conversation: The chat id that starts the run, or None.

    Yields:
        The chat lines of the start and of the run.
    """
    fin = finishing_run()
    if fin is not None:
        yield (f"The previous run `{fin.name}` has finished and is releasing its TDs on the cluster. "
               "Yours starts as soon as that is done …")
        t0 = time.time()
        while LAUNCHER.busy and time.time() - t0 < 180:
            time.sleep(1.0)
        if LAUNCHER.busy:
            yield "The previous run is still shutting down after 180 s. Try again in a moment."
            return
    controls = read_controls()
    inject = controls["external_input"].startswith("injection")
    style = inject_style_of(controls["external_input"])
    attack = "" if controls.get("node_attack", "none") == "none" else controls["node_attack"]
    code, payload = LAUNCHER.start(task, world, mode, inject=inject, model=brain(), attack=attack,
                                   foreign_order=controls.get("foreign_order", "") if inject else "",
                                   inject_style=style)
    if code != 200:
        note = busy_note() if code == 409 else ""
        yield f"Not started: {payload.get('error')}.{note}"
        return
    yield from head
    st = LAUNCHER.status()
    if world != "mock":
        yield (f"_Live run {st['live_used']} of {st['live_used'] + st['live_left']} for this server start "
               "(a repeated or regenerated message is a new run, and stopping the stream does not stop the run)._")
    yield from follow_run(mode, conversation=conversation)


def busy_note() -> str:
    """What the running run is doing right now, for a message that cannot start one."""
    run_dir = LAUNCHER.launched_run()
    run = run_dir.name if run_dir else _latest_run()
    pending = run and ((DEMO_DIR / run / "approval-request.json").exists() or _awaits_authority(DEMO_DIR / run))
    state = ("It is waiting for your decision on the approval page." if pending
             else "It is executing, and the chat that started it shows its progress.")
    return (f" A run is in progress ({run}). {state} This message has no effect on it, "
            "because decisions are made on the approval page and not here.")


def _awaits_authority(run_dir) -> bool:
    """Whether the last approval request of a run has no decision event after it yet."""
    try:
        data = json.loads((run_dir / "events.json").read_text())
    except (OSError, ValueError):
        return False
    events = data if isinstance(data, list) else data.get("events", [])
    for e in reversed(events):
        if e.get("kind") in ("plan_decision", "approval", "end"):
            return False
        if e.get("kind") == "approval_request":
            return True
    return False


def last_user_message(messages: list[dict]) -> str:
    """The text of the last user message, or "" when there is none."""
    for m in reversed(messages or []):
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, list):          # Open WebUI may send content parts
                c = " ".join(p.get("text", "") for p in c if isinstance(p, dict))
            return str(c or "")
    return ""


class Handler(BaseHTTPRequestHandler):
    """The two routes of the facade: the model list and the chat completion."""

    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        """Write one complete response."""
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:                                  # noqa: N802
        """Serve the model list."""
        path = urlparse(self.path).path
        if path == "/v1/models":
            body = {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "attested-agent"} for m in MODELS]}
            return self._send(200, json.dumps(body).encode())
        return self._send(404, b'{"error":"not found"}')

    def do_POST(self) -> None:                                 # noqa: N802
        """Start a run, or resume the paused one, and answer with its narration."""
        if urlparse(self.path).path != "/v1/chat/completions":
            return self._send(404, b'{"error":"not found"}')
        why = refuse(self.headers, ALLOWED_ORIGINS)
        if why:
            return self._send(403, json.dumps({"error": why}).encode())
        n = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, b'{"error":"bad json"}')
        conversation = (self.headers.get(CHAT_HEADER) or "").strip() or None
        model_id = str(body.get("model", ""))
        task = last_user_message(body.get("messages", []))
        stream = bool(body.get("stream"))
        try:
            mode, world = split_model(model_id)
        except ValueError as exc:
            return self._reply(model_id, stream, [str(exc)])
        # Open WebUI's own helper prompts (title, tags, follow-ups) must not start runs.
        if task.lstrip().startswith("### Task:"):
            return self._reply(model_id, stream, ["(no run)"])
        # While this server's run waits for the user's continuation, the message resumes that
        # run (bound to its conversation), whichever model is selected. It does not start a new plan.
        waiting = LAUNCHER.waiting_run()
        if waiting is not None:
            seen = len(_events(waiting) or [])
            errors = resume_turn(waiting, task, conversation)
            if errors:
                return self._reply(model_id, stream, errors)
            return self._reply(model_id, stream, follow_events(waiting, seen))
        orphan = LAUNCHER.launched_run()
        head_orphan = ([f"The previous run `{orphan.name}` paused and its controller is gone (PAUSED_ORPHANED). "
                        "It stays ACTIVE at the Authority without a grant and cannot be resumed. "
                        "This message starts a new run."]
                       if is_orphaned(orphan, LAUNCHER.busy) else [])
        if mode == "v5":
            problems = cluster_preflight()
            if problems:
                return self._reply(model_id, stream,
                                   ["Not started, the cluster path is not ready:"] + [f"- {p}" for p in problems])
        # The demo controls (external input, node attacker) are read at launch time inside
        # `launch`, which also waits for a finished run that is still releasing its TDs.
        return self._reply(model_id, stream, launch(task, world, mode, head_orphan, conversation))

    def _reply(self, model_id: str, stream: bool, lines) -> None:
        """One completion, streamed as SSE chunks or returned whole."""
        cid, now = f"chatcmpl-{uuid.uuid4().hex[:12]}", int(time.time())
        if not stream:
            text = "\n\n".join(lines)
            body = {"id": cid, "object": "chat.completion", "created": now, "model": model_id,
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}
            return self._send(200, json.dumps(body).encode())
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def chunk(delta: dict, finish=None):
            data = {"id": cid, "object": "chat.completion.chunk", "created": now, "model": model_id,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
            raw = f"data: {json.dumps(data)}\n\n".encode()
            self.wfile.write(f"{len(raw):x}\r\n".encode() + raw + b"\r\n")
            self.wfile.flush()
        try:
            chunk({"role": "assistant", "content": ""})
            for line in lines:
                chunk({"content": line + "\n\n"})
            chunk({}, "stop")
            raw = b"data: [DONE]\n\n"
            self.wfile.write(f"{len(raw):x}\r\n".encode() + raw + b"\r\n0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass                                # the client left, and the run continues regardless

    def log_message(self, *args) -> None:
        """Suppress the default access log."""


def main(argv=None) -> int:
    """Start the facade."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8767)
    ap.add_argument("--host", default="127.0.0.1", help="0.0.0.0 when Open WebUI runs in a container")
    ap.add_argument("--max-live-runs", type=int, default=5,
                    help="how many live-world runs one start of this server may launch")
    ap.add_argument("--cluster-pool", type=int, default=5,
                    help="warm TD pool for v5 runs: one TD per plan step plus one per approved "
                         "continuation, so 5 keeps a four-step plan with a payment approval warm")
    args = ap.parse_args(argv)
    LAUNCHER.max_live_runs = args.max_live_runs
    LAUNCHER.cluster_pool = args.cluster_pool
    print(f"agent api: http://{args.host}:{args.port}/v1   brain={brain()}   (runs under {DEMO_DIR})")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
