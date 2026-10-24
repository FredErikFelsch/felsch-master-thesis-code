"""Server side of the chat continuation: which run a message may resume.

A run that paused in WAITING_FOR_USER_CONTINUATION (session.py) writes chat-request.json and
waits for chat.json. This module is the only place a front end turns a chat message into
that answer, and it binds each message to one run:

    launch_id (the launcher's own run)  ↔  run directory / run_id
    conversation_id (when the chat sends one)  ↔  that run
    chat_id (the pending request)  ↔  the one answer, written once

The module neither approves nor plans. A reply only lets the paused session continue under
the policy it already has.
"""
from __future__ import annotations

import json
import pathlib
import re
import time

from .http_guard import write_once

LAUNCHES = "launches"
_LAUNCH_ID = re.compile(r"^[0-9a-f]{32}$")
MAX_REPLY_LEN = 600


def record_launch(demo_dir: pathlib.Path, launch_id: str | None, run_dir: pathlib.Path) -> None:
    """Tell the launcher which directory its own run writes to (called by run.py).

    The launcher then does not have to guess by taking the latest run.

    Args:
        demo_dir: The demo directory the launcher watches.
        launch_id: The launcher's id for this run (32 hex characters). Anything else is
            ignored.
        run_dir: The run directory this process writes to.
    """
    if not launch_id or not _LAUNCH_ID.match(launch_id):
        return
    d = demo_dir / LAUNCHES
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{launch_id}.json").write_text(json.dumps({"dir": run_dir.name}))


def launched_run(demo_dir: pathlib.Path, launch_id: str | None) -> pathlib.Path | None:
    """The run directory of one launch, once the run has announced it."""
    if not launch_id or not _LAUNCH_ID.match(launch_id):
        return None
    p = demo_dir / LAUNCHES / f"{launch_id}.json"
    try:
        return demo_dir / json.loads(p.read_text())["dir"]
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return None


def waiting_request(run_dir: pathlib.Path | None) -> dict | None:
    """The pending continuation request of `run_dir`, or None."""
    if run_dir is None:
        return None
    try:
        return json.loads((run_dir / "chat-request.json").read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def last_event_kind(run_dir: pathlib.Path) -> str | None:
    """The kind of the last event in the run's `events.json`, or None."""
    try:
        events = json.loads((run_dir / "events.json").read_text())
        return events[-1]["kind"] if events else None
    except (FileNotFoundError, json.JSONDecodeError, KeyError, IndexError):
        return None


def is_orphaned(run_dir: pathlib.Path | None, process_alive: bool | None = None,
                now: float | None = None) -> bool:
    """Whether a pause can no longer be answered (PAUSED_ORPHANED).

    A pause is orphaned when the record ends in `paused` and the controller is known to be
    gone, or its request file is missing or past its timeout. The run stays ACTIVE at the
    Authority without a grant and cannot be resumed. This is a loss of availability, and
    no effect can follow from it.

    Args:
        run_dir: The run directory.
        process_alive: What the caller knows about the run's process (None: unknown, e.g. a
            run started by another front end or by hand).
        now: The clock, for tests.

    Returns:
        True when nobody can answer the pause any more.
    """
    if run_dir is None or last_event_kind(run_dir) != "paused":
        return False
    if process_alive is False:
        return True
    req = waiting_request(run_dir)
    if req is None:
        return True
    started, limit = req.get("requested_at"), req.get("timeout")
    return bool(started and limit and (now or time.time()) > float(started) + float(limit))


def resume(run_dir: pathlib.Path, text: str) -> tuple[int, dict]:
    """Answer the pending continuation of `run_dir` with `text`, once.

    The answer is written with `write_once`, so a second reply to the same pause is refused.

    Args:
        run_dir: The paused run's directory.
        text: The human's reply.

    Returns:
        (http status, body). 409 when nothing waits or the request was already answered,
        400 for an empty or oversized reply.
    """
    text = (text or "").strip()
    if not text or len(text) > MAX_REPLY_LEN:
        return 400, {"error": f"a reply is 1 to {MAX_REPLY_LEN} characters"}
    req = waiting_request(run_dir)
    if req is None or not req.get("chat_id"):
        return 409, {"error": "the run is not waiting for a continuation"}
    if not write_once(run_dir / "chat.json", {"chat_id": req["chat_id"], "text": text}):
        return 409, {"error": "this pause was already answered"}
    return 200, {"resumed": True, "run": run_dir.name, "run_id": req.get("run_id"),
                 "next_step": req.get("next_step")}
