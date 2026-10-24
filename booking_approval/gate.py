"""The approval gate: the path by which a human decision reaches the Authority.

The gate is installed on the Authority's RPC server by replacing the instance's `_serve_on`,
so no module of the runner packages changes. It does three things:

1. It closes `authority.create_run` and `authority.decide_intervention` on every non-harness
   RPC surface. A controller that holds the HMAC constant of `booking_v1.approval` or the
   human secret can no longer present either. The gate calls both itself, through the
   server's durable `_serve`, after a verified assertion.

2. It opens four controller methods that carry no authority:
       approval.propose_run   register a compiled policy for a run id, get the object id
       approval.status        the state of an object and, once decided, its result
                              (the genesis envelope, or the signed intervention approval)
       approval.step_ticket   the page of a step the Authority holds as pending approval
       approval.pinned        who may approve in this deployment (no key material)

3. It shows a step only as the preimage of a hash the Authority holds. The monitor in the TD
   refuses an approval-bound step before any grant request, and the TD reports only the
   attested fragment hash. `approval.step_ticket` therefore takes the fragment from the
   controller, re-computes its hash on decoding, and opens a page only when that hash is
   pending at the Authority. The controller can deliver the bytes but cannot choose what the
   person reads, since other bytes would have another hash. A grant the Authority refuses for
   want of approval (an expired approval, resubmitted) registers its fragment the same way.

A decision is applied only when the assertion verifies against a pinned credential, over an
unused and unexpired challenge the gate issued for this object and decision.

Locking: the gate's own methods run outside the server's `_serve_lock`. The reads they make
of the live Authority (`status`, `intervention_pending`) are snapshots that decide what a
page shows and whether an object is registered. Every state change goes through
`self._server._serve`, which takes the lock, and the Authority checks again there:
`create_run` refuses a run id it already holds and `decide_intervention` signs only while
`intervention_pending` is true.
"""
from __future__ import annotations

import secrets
import sys
import threading
from typing import Any, Mapping

from booking_v1.approval import LIVE_APPROVAL_WINDOW, approve
from booking_v1.clock import Clock
from booking_v3.authority import INTERVENTION_TTL, HumanApprovalCredential
from booking_v4 import wire
from booking_v4.durable import HARNESS_SURFACE

from .credentials import CredentialSet
from .objects import DECISIONS, PLAN, STEP, ObjectInvalid, challenge_material, plan_object, step_object, view
from .store import APPROVED, FAILED, PENDING, REJECTED, ApprovalStore
from .webauthn import WebAuthnRefused, b64url_decode, b64url_encode, verify_assertion

CLOSED_METHODS = frozenset({"authority.create_run", "authority.decide_intervention"})
GATE_METHODS: dict[str, set[str]] = {
    "approval.propose_run": {"policy", "run_id"},
    "approval.status": {"object_id"},
    "approval.step_ticket": {"fragment"},
    "approval.pinned": set(),
}
CHALLENGE_TTL = 120
INTERVENTION_REFUSAL = "manual intervention required"


class DecisionRefused(Exception):
    """A decision could not be applied.

    Attributes:
        status: The HTTP status the surface answers with.
        reason: The refusal, shown to the person.
    """

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status, self.reason = status, reason


def _log(line: str) -> None:
    sys.stdout.write(f"[approval-gate] {line}\n")
    sys.stdout.flush()


class ApprovalGate:
    """Authority-side enforcement of human approval over WebAuthn.

    Args:
        server: The Authority's `DurableDeploymentServer`.
        store: The gate's `ApprovalStore`.
        credentials: The pinned approver credentials.
        clock: The Authority's clock (system clock in a deployment).
        rp_id: The WebAuthn relying party id.
        origin: The origin the approval page is served on.
        challenge_ttl: Seconds a challenge stays valid.
        allowed_top_origins: Origins that may show the page as a panel (surface frame_ancestors).
    """

    def __init__(self, server, store: ApprovalStore, credentials: CredentialSet, clock: Clock, *,
                 rp_id: str = "localhost", origin: str = "http://localhost:8450",
                 challenge_ttl: int = CHALLENGE_TTL, allowed_top_origins: tuple[str, ...] = ()) -> None:
        self._server, self._store, self._credentials, self._clock = server, store, credentials, clock
        self.rp_id, self.origin, self._ttl = rp_id, origin, int(challenge_ttl)
        #: The pages that may embed the approval page. An embedded ceremony is accepted only for them.
        self.allowed_top_origins = tuple(allowed_top_origins)
        self._inner = None
        self._lock = threading.Lock()

    @property
    def _authority(self):
        return self._server._dep.authority

    # --- RPC side ------------------------------------------------------------------------
    def install(self, require_preclosed: bool = False) -> "ApprovalGate":
        """Put the gate in front of every listener of the server.

        The handlers resolve `_serve_on` per request, so this takes effect for all listeners
        at once.

        Args:
            require_preclosed: Require that the server was built with the closed methods
                (`start_authority(closed_methods=CLOSED_METHODS)`), so no request could have
                reached them between binding the listener and installing the gate.

        Returns:
            The gate itself.

        Raises:
            RuntimeError: when the gate is already installed, or `require_preclosed` is set
                and the server lacks the closed methods.
        """
        if self._inner is not None:
            raise RuntimeError("gate already installed")
        if require_preclosed and not CLOSED_METHODS <= self._server._closed_methods:
            raise RuntimeError("the Authority listener was opened without the closed methods: "
                               "pass closed_methods=CLOSED_METHODS to start_authority")
        self._inner = self._server._serve_on
        self._server._serve_on = self._serve_on
        self._server.approval_gate = self
        _log(f"installed: create_run and decide_intervention closed, {len(self._credentials.credentials)} "
             f"approver credential(s) pinned, origin {self.origin}")
        return self

    def _serve_on(self, surface, message: Mapping[str, Any]) -> dict | None:
        if surface is HARNESS_SURFACE:
            return self._inner(surface, message)
        method = message.get("method") if isinstance(message, Mapping) else None
        if method in CLOSED_METHODS:
            _log(f"refused {method} on the RPC surface")
            return {"v": wire.WIRE_VERSION, "error": f"{method} requires the approval surface",
                    "code": "METHOD_NOT_FOUND"}
        if method in GATE_METHODS:
            try:
                self._server._check_envelope(message)
                params = wire.expect_keys(message["params"], GATE_METHODS[method], f"{method} params")
                return self._rpc(method, params)
            except (wire.WireError, ObjectInvalid, KeyError, TypeError, ValueError) as exc:
                return {"v": wire.WIRE_VERSION, "error": str(exc), "code": "BAD_REQUEST"}
        reply = self._inner(surface, message)
        if method == "authority.request_execution_grant":
            self._observe_grant(message, reply)
        return reply

    def _rpc(self, method: str, params: dict) -> dict:
        now = self._clock.now()
        if method == "approval.propose_run":
            obj = plan_object(params["policy"], params["run_id"])
            # A snapshot without `_serve_lock`. It saves the person a page for a run that already
            # exists. `create_run` refuses a duplicate run id again under the lock.
            if self._authority.status(obj.run_id) is not None:
                raise ObjectInvalid(f"run {obj.run_id!r} already exists")
            if self._store.put_object(obj, now):
                _log(f"plan pending: run={obj.run_id} object={obj.object_id[:12]}")
            return {"v": wire.WIRE_VERSION, "object_id": obj.object_id, "path": f"/approve/{obj.object_id}"}
        if method == "approval.status":
            stored = self._store.get_object(str(params["object_id"]))
            if stored is None:
                raise ObjectInvalid("unknown approval object")
            return {"v": wire.WIRE_VERSION, "object_id": stored.obj.object_id, "kind": stored.obj.kind,
                    "state": stored.state, "approver_id": stored.approver_id,
                    "approver_kind": stored.approver_kind, "result": stored.result}
        if method == "approval.step_ticket":
            first = step_object(params["fragment"])             # hash re-computed here
            if not self._step_pending(first):
                raise ObjectInvalid("no approval pending for this fragment at the Authority")
            stored = self._register_step(params["fragment"])
            return {"v": wire.WIRE_VERSION, "object_id": stored.obj.object_id, "state": stored.state,
                    "path": f"/approve/{stored.obj.object_id}"}
        return {"v": wire.WIRE_VERSION, "credentials": self._credentials.summary(),
                "digest": self._credentials.digest()}

    def _observe_grant(self, message: Mapping[str, Any], reply: Any) -> None:
        """Keep the fragment the Authority refused for want of approval (the page shows it)."""
        if not isinstance(reply, dict) or reply.get("grant") is not None:
            return
        if not str(reply.get("reason", "")).startswith(INTERVENTION_REFUSAL):
            return
        try:
            self._register_step(message["params"]["fragment"])
        except (ObjectInvalid, KeyError, TypeError):
            return

    def _register_step(self, fragment_wire):
        """Return the open approval object for one fragment.

        This is the pending object if there is one, otherwise a new attempt after an earlier
        decision (an expired approval makes the Authority ask again).
        """
        first = step_object(fragment_wire)
        latest = self._store.find_step(first.run_id, first.step_index, first.fragment_hash)
        if latest is not None and latest.state == PENDING:
            return latest
        attempt = self._store.count_steps(first.run_id, first.step_index, first.fragment_hash)
        obj = step_object(fragment_wire, attempt)
        if self._store.put_object(obj, self._clock.now()):
            _log(f"step pending: run={obj.run_id} step={obj.step_index} fragment={obj.fragment_hash[:12]} "
                 f"attempt={attempt}")
        return self._store.get_object(obj.object_id)

    def _step_pending(self, obj) -> bool:
        """Return whether the Authority holds the step as pending approval.

        The read takes no `_serve_lock`, so it is a snapshot for the page and for registering
        objects. `decide_intervention` checks `intervention_pending` again under the lock
        before it signs anything.
        """
        return bool(self._authority.intervention_pending(obj.run_id, obj.step_index, obj.fragment_hash))

    # --- approval surface side -----------------------------------------------------------
    def object_view(self, object_id: str) -> dict | None:
        """Return what the page shows for one object, rendered from the Authority's own material.

        The state of a step object is a snapshot of `intervention_pending` (see `_step_pending`).
        """
        stored = self._store.get_object(object_id)
        if stored is None:
            return None
        state = stored.state
        if state == PENDING and stored.obj.kind == STEP and not self._step_pending(stored.obj):
            state = "not-pending"          # the Authority has no open request for it (any more)
        return {"object_id": object_id, "state": state, "approver_id": stored.approver_id,
                "approver_kind": stored.approver_kind, "view": view(stored.obj)}

    def pending_views(self) -> list[dict]:
        """Return the views of all objects that are still awaiting a decision."""
        out = []
        for stored in self._store.pending():
            v = self.object_view(stored.obj.object_id)
            if v is not None and v["state"] == PENDING:
                out.append(v)
        return out

    def issue_challenge(self, object_id: str, decision: str) -> dict:
        """Issue a fresh challenge bound to one object and one decision.

        Args:
            object_id: The object the page shows.
            decision: "approve" or "reject".

        Returns:
            The challenge, the relying party id, the timeout, the allowed credential ids and
            the expiry, as the page passes them to `navigator.credentials.get`.

        Raises:
            DecisionRefused: when the decision is unknown (400), the object is unknown (404)
                or not pending (409).
        """
        if decision not in DECISIONS:
            raise DecisionRefused(400, f"decision must be one of {DECISIONS}")
        current = self.object_view(object_id)
        if current is None:
            raise DecisionRefused(404, "unknown approval object")
        if current["state"] != PENDING:
            raise DecisionRefused(409, f"object is {current['state']}")
        now = self._clock.now()
        expires = now + self._ttl
        challenge = challenge_material(object_id, decision, secrets.token_hex(16), expires)
        self._store.put_challenge(challenge.hex(), object_id, decision, expires)
        return {"challenge": b64url_encode(challenge), "rp_id": self.rp_id, "timeout_ms": self._ttl * 1000,
                "allow": [c.credential_id for c in self._credentials.credentials], "expires_at": expires}

    def decide(self, object_id: str, decision: str, assertion: Mapping[str, Any],
               ttl: int | None = None) -> dict:
        """Verify one assertion and apply the decision it signs.

        Args:
            object_id: The object the page shows.
            decision: "approve" or "reject".
            assertion: challenge, credential_id, client_data_json, authenticator_data,
                signature (all base64url).
            ttl: Optional validity in seconds for a step approval. It is not covered by the
                assertion and is capped at the Authority's maximum, so it can only shorten
                the approval.

        Returns:
            The object's new state, the approver and the result.

        Raises:
            DecisionRefused: with the HTTP status and the reason.
        """
        if decision not in DECISIONS:
            raise DecisionRefused(400, f"decision must be one of {DECISIONS}")
        try:
            if not isinstance(assertion, Mapping):
                raise TypeError("the assertion is not an object")
            challenge = b64url_decode(str(assertion["challenge"]))
            credential_id = str(assertion["credential_id"])
            fields = {k: b64url_decode(str(assertion[k]))
                      for k in ("client_data_json", "authenticator_data", "signature")}
        except (KeyError, TypeError, WebAuthnRefused) as exc:
            raise DecisionRefused(400, f"malformed assertion: {exc}") from None
        with self._lock:
            now = self._clock.now()
            why = self._store.consume_challenge(challenge.hex(), object_id, decision, now)
            if why is not None:
                raise DecisionRefused(403, why)
            cred = self._credentials.by_id(credential_id)
            if cred is None:
                raise DecisionRefused(403, "credential is not pinned at this Authority")
            try:
                result = verify_assertion(
                    spki_der=b64url_decode(cred.public_key), algorithm=cred.algorithm, rp_id=self.rp_id,
                    origin=self.origin, challenge=challenge, client_data_json=fields["client_data_json"],
                    authenticator_data=fields["authenticator_data"], signature=fields["signature"],
                    require_uv=cred.requires_uv, allowed_top_origins=self.allowed_top_origins)
            except WebAuthnRefused as exc:
                _log(f"assertion refused for object {object_id[:12]}: {exc}")
                raise DecisionRefused(403, str(exc)) from None
            current = self.object_view(object_id)
            if current is None or current["state"] != PENDING:
                raise DecisionRefused(409, "object is no longer pending")
            if not self._store.advance_counter(cred.credential_id, result.sign_count):
                raise DecisionRefused(403, "signature counter did not advance (cloned authenticator?)")
            stored = self._store.get_object(object_id)
            if stored.obj.kind == PLAN:
                state, outcome = self._apply_plan(stored.obj, decision, cred.approver_id, cred.kind)
            else:
                state, outcome = self._apply_step(stored.obj, decision, cred.approver_id, cred.kind, challenge.hex(), ttl)
            if not self._store.decide(object_id, state, now, cred.approver_id, cred.kind, outcome):
                # The object left PENDING while this decision was applied. What the store holds is
                # the record, so no state is reported that it did not take.
                _log(f"decision not recorded for object {object_id[:12]}: no longer pending")
                raise DecisionRefused(409, "object is no longer pending")
            _log(f"{stored.obj.kind} {decision} by {cred.approver_id} ({cred.kind}): run={stored.obj.run_id} "
                 f"object={object_id[:12]} -> {state}")
            return {"object_id": object_id, "state": state, "approver_id": cred.approver_id,
                    "approver_kind": cred.kind, "result": outcome}

    def _apply_plan(self, obj, decision: str, approver_id: str, approver_kind: str) -> tuple[str, dict]:
        """Create the run through the durable server, with the approval minted here."""
        if decision == "reject":
            return REJECTED, {"reason": "the approver rejected the plan"}
        now = self._clock.now()
        approval = approve(obj.policy(), approver_id=approver_id, approver_kind=approver_kind,
                           approval_id=f"appr-{obj.run_id}", run_id=obj.run_id,
                           issued_at=now - 60, expires_at=now + LIVE_APPROVAL_WINDOW)
        reply = self._server._serve({
            "v": wire.WIRE_VERSION, "method": "authority.create_run", "request_id": f"gate:{obj.object_id}",
            "params": {"policy": dict(obj.body["policy"]), "approval": wire.approval_to_wire(approval),
                       "run_id": obj.run_id}}) or {}
        envelope = reply.get("envelope")
        return (APPROVED if envelope else FAILED), {"envelope": envelope,
                                                    "reason": reply.get("reason") or reply.get("error")}

    def _apply_step(self, obj, decision: str, approver_id: str, approver_kind: str, decision_id: str,
                    ttl: int | None) -> tuple[str, dict]:
        """Let the Authority sign (or refuse) the fragment-bound intervention approval."""
        ttl = INTERVENTION_TTL if ttl is None else min(int(ttl), INTERVENTION_TTL)
        # The Authority's own secret, passed in-process to `_serve` and not over a listener.
        human = HumanApprovalCredential(secret=self._authority._human_secret)
        reply = self._server._serve({
            "v": wire.WIRE_VERSION, "method": "authority.decide_intervention", "request_id": f"gate:{decision_id}",
            "params": {"human": wire.human_to_wire(human), "decision_id": f"gate:{decision_id}",
                       "run_id": obj.run_id, "step_index": obj.step_index, "fragment_hash": obj.fragment_hash,
                       "approver_id": approver_id, "approver_kind": approver_kind,
                       "grant": decision == "approve", "ttl": ttl}}) or {}
        approval = reply.get("approval")
        if decision == "reject":
            return REJECTED, {"approval": None, "reason": "the approver rejected the step"}
        return (APPROVED if approval else FAILED), {"approval": approval, "reason": reply.get("error")}
