"""The controller's side of the approval gate, and the unattended harness approver.

`ApprovalClient` is everything a controller can do: register a plan, ask for the page of a
step the Authority refused for approval, and poll for the outcome. None of it carries
authority. The result it finally reads (the genesis envelope, or the signed intervention
approval) was produced by the Authority after a verified assertion.

`HarnessApprover` answers on the approval surface with a software key, for the unattended
evaluation runs (`--approve auto|deny`). It walks the same HTTP path as the page and is
accepted only where a harness credential is pinned. Every decision it makes is recorded
with kind "harness".
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from booking_v4 import wire
# The RPC helper of the runner packages. It is private there, and reused here so the client
# speaks the same wire framing as every other caller of the Authority.
from booking_v4.services import _call

from .softauthn import SoftwareAuthenticator
from .webauthn import b64url_decode

FINAL_STATES = ("approved", "rejected", "failed")


class ApprovalUnavailable(RuntimeError):
    """The gate refused a controller request (unknown run, nothing pending, bad input)."""


@dataclass(frozen=True)
class Ticket:
    """One pending approval: its object id and the page a person opens."""

    object_id: str
    url: str


class ApprovalClient:
    """Controller-side RPC to the gate (over the Authority's port-forward).

    Args:
        authority: The Authority's RPC endpoint (`ServiceEndpoint`).
        surface_url: The approval surface as the person's browser reaches it.
    """

    def __init__(self, authority, surface_url: str = "http://localhost:8450") -> None:
        self._authority, self.surface_url = authority, surface_url.rstrip("/")

    def _rpc(self, method: str, params: Mapping[str, Any]) -> dict:
        try:
            return _call(self._authority, method, params)
        except wire.WireError as exc:
            raise ApprovalUnavailable(str(exc)) from None

    def propose_run(self, policy, run_id: str) -> Ticket:
        """Register the compiled policy for `run_id`. The run is only created once a person approves.

        Args:
            policy: The compiled policy.
            run_id: The run id the plan is proposed for.

        Returns:
            The ticket with the page a person opens.
        """
        reply = self._rpc("approval.propose_run", {"policy": wire.policy_to_wire(policy), "run_id": run_id})
        return Ticket(reply["object_id"], self.surface_url + reply["path"])

    def step_ticket(self, fragment, wait: float = 10.0) -> Ticket:
        """Return the page of a step the Authority holds as pending approval.

        The gate opens it only for the fragment whose hash the TD reported. The report may
        land a moment after the refusal reached this process, hence the short retry.

        Args:
            fragment: The fragment the Authority refused for want of approval.
            wait: Seconds to keep retrying while nothing is pending yet.

        Returns:
            The ticket with the page a person opens.

        Raises:
            ApprovalUnavailable: when nothing is pending for the fragment once `wait` has passed.
        """
        deadline = time.monotonic() + wait
        while True:
            try:
                reply = self._rpc("approval.step_ticket", {"fragment": wire.fragment_to_wire(fragment)})
                return Ticket(reply["object_id"], self.surface_url + reply["path"])
            except ApprovalUnavailable:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.5)

    def status(self, object_id: str) -> dict:
        """Return the Authority's current status record for an approval object."""
        return self._rpc("approval.status", {"object_id": object_id})

    def pinned(self) -> dict:
        """Return who may approve in this deployment (approver ids and kinds, no key material)."""
        return self._rpc("approval.pinned", {})

    def wait(self, object_id: str, timeout: float, poll: float = 1.0,
             stop: Optional[Callable[[], bool]] = None) -> dict:
        """Poll until the object is decided, the timeout passes or `stop()` is true.

        Args:
            object_id: The approval object.
            timeout: Seconds to wait at most.
            poll: Seconds between two status reads.
            stop: Called before each wait. A True answer ends the polling.

        Returns:
            The final status, or {"state": "timeout"} / {"state": "stopped"}.
        """
        deadline = time.monotonic() + timeout
        while True:
            st = self.status(object_id)
            if st.get("state") in FINAL_STATES:
                return st
            if stop is not None and stop():
                return {"state": "stopped", "object_id": object_id}
            if time.monotonic() >= deadline:
                return {"state": "timeout", "object_id": object_id}
            time.sleep(poll)


class HarnessApprover:
    """An automated approver on the approval surface (software key, kind "harness").

    Args:
        surface_url: Where the approval surface is reached.
        authenticator: The harness key.
        origin: The approval origin, if the surface is reached on another URL (default:
            `surface_url`).
    """

    def __init__(self, surface_url: str, authenticator: SoftwareAuthenticator, origin: str | None = None) -> None:
        self.surface_url = surface_url.rstrip("/")
        self.origin = origin or self.surface_url
        self._auth = authenticator

    def _post(self, path: str, body: dict) -> dict:
        # Host and Origin name the approval origin even when the surface is reached through a
        # port-forward on another local port (the evaluation harness): the surface checks both.
        req = urllib.request.Request(self.surface_url + path, data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "Origin": self.origin,
                                              "Host": urllib.parse.urlsplit(self.origin).netloc})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as err:
            try:
                detail = json.loads(err.read() or b"{}").get("error", err.reason)
            except (ValueError, AttributeError):    # not a JSON object, e.g. a proxy's HTML page
                detail = err.reason
            raise ApprovalUnavailable(f"{path}: {err.code} {detail}") from None

    def decide(self, object_id: str, decision: str, ttl: int | None = None) -> dict:
        """Fetch a challenge for this object and decision, sign it and submit it.

        Args:
            object_id: The approval object.
            decision: "approve" or "reject".
            ttl: Optional shorter validity for a step approval.

        Returns:
            The surface's answer: the new state, the approver and the result.

        Raises:
            ApprovalUnavailable: when the surface refuses the challenge or the decision.
        """
        ch = self._post("/api/challenge", {"object_id": object_id, "decision": decision})
        assertion = self._auth.assertion(b64url_decode(ch["challenge"]), self.origin)
        assertion["challenge"] = ch["challenge"]
        body = {"object_id": object_id, "decision": decision, "assertion": assertion}
        if ttl is not None:
            body["ttl"] = int(ttl)
        return self._post("/api/decide", body)
