"""Request hygiene for the local demo servers.

Two rules, shared by the dashboard (booking_demo.serve), the approval facade
(ui.approval_api) and the chat facade (ui.agent_api):

* A state-changing POST must be `Content-Type: application/json`. A browser cannot send
  that cross-origin without a CORS preflight, and none of these servers answers one, so a
  foreign page (or an iframe of the chat) cannot approve, reply or start a run with a
  "simple" `text/plain` form post.
* When the browser names an `Origin`, it must be one of the server's own. Server-to-server
  callers (Open WebUI's backend, curl, the tests) send none and are judged by the first rule
  and by the loopback bind.

Neither rule is an identity. Who may approve is a separate question (APPROVAL_TOKEN in
ui.approval_api, single local operator in the demo).
"""
from __future__ import annotations

import json
import os
from typing import Iterable, Mapping


def origins_for(port: int, extra: Iterable[str] = ()) -> frozenset[str]:
    """Return the origins a server on `port` serves its own pages from, plus `extra`.

    The own origins are `localhost` and `127.0.0.1` on that port, whatever address the
    server binds.
    """
    own = {f"http://{host}:{port}" for host in ("localhost", "127.0.0.1")}
    return frozenset(own | {o.rstrip("/") for o in extra if o})


def refuse(headers: Mapping[str, str], allowed_origins: Iterable[str]) -> str | None:
    """Return why a POST must be refused, or None.

    Args:
        headers: The request headers (any mapping with `.get`).
        allowed_origins: Origins accepted when the browser sends one.

    Returns:
        A short reason for a 403, or None when the request may proceed.
    """
    ctype = (headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if ctype != "application/json":
        return "a state-changing request must be application/json"
    origin = (headers.get("Origin") or "").rstrip("/")
    if origin and origin not in set(allowed_origins):
        return f"origin {origin} is not allowed"
    return None


def write_once(path, payload: dict) -> bool:
    """Create `path` with `payload` once (O_EXCL). Returns False when it already exists.

    With two tabs, a double click, or approve against reject, the first write wins, and every
    later one is refused before it touches the file, across processes as well.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w") as fh:
        fh.write(json.dumps(payload))
    return True
