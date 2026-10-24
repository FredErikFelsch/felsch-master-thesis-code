"""The Authority and gateway service boundary: JSON-RPC over a Unix domain socket or TCP.

The DeploymentServer publishes the booking_v3 Authority and tool gateway of one deployment as a
line-oriented JSON service. The client proxies expose the method signatures the EphemeralRunner
already calls, so the runner code runs unchanged in another process with the proxies duck-typed in
place of the Python objects. Every request and reply crosses the boundary through the strict wire
module. A malformed message is answered with an error, and the client raises `WireError`.

This thin RPC layer lets the backends change where the runner process lives without changing the
programming model. `booking_v4.durable` adds durability on top of it.
"""

from __future__ import annotations

import os
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import uuid
import weakref
from typing import Any, Mapping

from .budgets import RPC_TIMEOUT_S

from . import wire
from .endpoint import ServiceEndpoint

# The parameter key set of each RPC method. A request with any other key set is rejected.
_RPC_PARAMS: dict[str, set[str]] = {
    # `attestation` is always present and may be null: a session that records a runner
    # verdict key refuses a null one, a session without such a key ignores it.
    "authority.request_execution_grant": {
        "credential", "fragment", "input_state_hash", "admission_event", "intervention",
        "attestation"},
    "authority.finalize_transition": {"credential", "record", "attestation"},
    "authority.report_denial": {"credential", "run_id", "admission_event", "attestation"},
    "authority.report_intervention_required": {
        "credential", "run_id", "step_index", "fragment_hash", "attestation"},
    "gateway.execute": {"token", "fragment"},
}


def _read_line(sock: socket.socket) -> str:
    """Read one reply line of at most MAX_WIRE_BYTES from `sock`."""
    chunks, total = [], 0
    while True:
        b = sock.recv(65536)
        if not b:
            break
        total += len(b)
        if total > wire.MAX_WIRE_BYTES + 2:
            raise wire.WireError("reply exceeds MAX_WIRE_BYTES")
        chunks.append(b)
        if b.endswith(b"\n"):
            break
    return b"".join(chunks).decode("utf-8")


# Bounds every deployment RPC (connect, read and write). Over a Kubernetes network a
# vanished pod, a broken service route or a NetworkPolicy then fails the RPC within a bound
# instead of hanging a runner. The runner does not retry an effectful call. The bound is the
# outer stage of the dispatch budgets (booking_v4.budgets): longer than anything the gateway
# may take, so the gateway answers a slow provider with UNCERTAIN before the runner's wait ends.
_DEPLOYMENT_TIMEOUT = RPC_TIMEOUT_S


class _UdsServer(socketserver.UnixStreamServer):
    """UDS listener that serves one connection at a time, as the booking_v3 objects expect."""


class _TcpServer(socketserver.TCPServer):
    """TCP listener that serves one connection at a time and reuses the address on a rebind."""

    allow_reuse_address = True


def _new_uds_server(socket_path: str, handler):
    """Bind a UDS listener at `socket_path`."""
    return _UdsServer(socket_path, handler)


def _new_tcp_server(addr: tuple[str, int], handler):
    """Bind a TCP listener at `addr`."""
    return _TcpServer(addr, handler)


class DeploymentServer:
    """Serves one deployment's Authority and gateway over a UDS or TCP.

    The RPC core (`_serve`, `_dispatch`, strict decoding, error sanitising) and the
    Authority and gateway objects do not depend on the transport, only the
    ``socketserver`` class does. Pass ``socket_path`` (or nothing) for a UDS,
    ``tcp=(host, port)`` for TCP. ``self.endpoint`` is the address a runner connects
    to. For TCP with port 0 it carries the bound port. The bind address and the
    connect address can differ, for example 0.0.0.0 against a Service DNS name.

    Args:
        deployment: The live objects (`authority`, `gateway`).
        socket_path: The UDS path, None for a fresh temporary directory.
        tcp: (host, port) for a TCP listener instead of a UDS.
    """

    def __init__(self, deployment, socket_path: str | None = None, *,
                 tcp: tuple[str, int] | None = None) -> None:
        self._dep = deployment
        handler = self._make_handler()
        if tcp is not None:
            self._server = _new_tcp_server(tcp, handler)
            host, port = self._server.server_address[0], self._server.server_address[1]
            self.socket_path = None
            self.endpoint = ServiceEndpoint.tcp(host, port)
            cleanup_dir = None
        else:
            owns_dir = socket_path is None
            if socket_path is None:
                socket_path = os.path.join(
                    tempfile.mkdtemp(prefix="booking-v4-"), "authority.sock")
            elif os.path.exists(socket_path):
                os.unlink(socket_path)
            self.socket_path = socket_path
            self._server = _new_uds_server(socket_path, handler)
            self.endpoint = ServiceEndpoint.uds(socket_path)
            cleanup_dir = os.path.dirname(socket_path) if owns_dir else None
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._finalizer = weakref.finalize(
            self, DeploymentServer._cleanup, self._server, cleanup_dir)

    def _make_handler(self, surface: "frozenset[str] | None" = None):
        """Build the stream handler, which is the same for every transport.

        `surface` binds the handler to a method subset (a role-bound listener that knows
        only its own methods). None means the full surface.
        """
        outer = self

        class _Handler(socketserver.StreamRequestHandler):
            timeout = wire.REQUEST_TIMEOUT_S

            def handle(self) -> None:
                try:
                    raw = self.rfile.readline(wire.MAX_WIRE_BYTES + 2)
                except OSError:
                    return  # nothing arrived in time (or the peer went away): drop the connection
                try:
                    if not raw.endswith(b"\n"):
                        raise wire.WireError("request exceeds MAX_WIRE_BYTES or is unterminated")
                    reply = outer._serve_on(surface, wire.decode_line(raw.decode("utf-8")))
                except Exception as exc:  # any failure becomes an error reply
                    # The runner can sit across a real isolation boundary, so a
                    # provoked failure must not carry internals back across it.
                    # WireError is protocol-level input validation and safe to
                    # surface. Anything else returns only a generic code, and the
                    # full detail goes to the server's stderr.
                    if isinstance(exc, wire.WireError):
                        reply = {"v": wire.WIRE_VERSION, "error": str(exc), "code": "WIRE"}
                    else:
                        sys.stderr.write(
                            f"[service-audit] {type(exc).__name__}: {exc}\n")
                        sys.stderr.flush()
                        reply = {"v": wire.WIRE_VERSION,
                                 "error": "internal service error", "code": "INTERNAL"}
                if reply is None:
                    return  # reply dropped by fault injection: the commit stands, the answer is lost
                self.wfile.write((wire.encode(reply) + "\n").encode("utf-8"))

        return _Handler

    @staticmethod
    def _cleanup(server, tmpdir) -> None:
        """Stop the listener and remove the temporary socket directory, if there is one."""
        try:
            server.shutdown()
            server.server_close()
        finally:
            if tmpdir is not None:
                shutil.rmtree(tmpdir, ignore_errors=True)

    def close(self) -> None:
        """Stop serving and remove the socket directory."""
        self._finalizer()

    # --- dispatch ---
    def _serve_on(self, surface, message: Mapping[str, Any]) -> dict | None:
        """Surface-aware entry. This server has one surface and ignores the argument."""
        return self._serve(message)

    def _serve(self, message: Mapping[str, Any]) -> dict | None:
        """Handle one validated request. Subclasses add durability around this."""
        self._check_envelope(message)
        return self._dispatch(message)

    @staticmethod
    def _check_envelope(message: Mapping[str, Any]) -> None:
        """Check the request's top-level key set and its request_id, raising WireError."""
        wire.expect_keys(message, {"v", "method", "params", "request_id"}, "rpc request")
        request_id = message["request_id"]
        if not isinstance(request_id, str) or not request_id:
            raise wire.WireError("request_id must be a non-empty string")

    def _dispatch(self, message: Mapping[str, Any]) -> dict:
        """Decode one request of `_RPC_PARAMS`, call the live object and encode its answer."""
        method = message["method"]
        if method not in _RPC_PARAMS:
            raise wire.WireError(f"unknown method {method!r}")
        params = wire.expect_keys(message["params"], _RPC_PARAMS[method], f"{method} params")
        authority, gateway = self._dep.authority, self._dep.gateway

        if method == "authority.request_execution_grant":
            grant, reason = authority.request_execution_grant(
                wire.credential_from_wire(params["credential"]),
                wire.fragment_from_wire(params["fragment"]),
                params["input_state_hash"],
                dict(params["admission_event"]),
                wire.intervention_from_wire(params["intervention"]),
                wire.attestation_from_wire(params["attestation"]))
            return {"v": wire.WIRE_VERSION,
                    "grant": wire.grant_to_wire(grant) if grant else None,
                    "reason": reason}
        if method == "authority.finalize_transition":
            envelope, reason = authority.finalize_transition(
                wire.credential_from_wire(params["credential"]),
                wire.record_from_wire(params["record"]),
                wire.attestation_from_wire(params["attestation"]))
            return {"v": wire.WIRE_VERSION,
                    "envelope": wire.envelope_to_wire(envelope) if envelope else None,
                    "reason": reason}
        # `ok` says what the Authority did, not that the message arrived. Answering `true`
        # unconditionally would leave a runner whose report was refused (wrong session,
        # wrong fragment, missing or invalid attestation) unable to tell.
        if method == "authority.report_denial":
            acted = authority.report_denial(
                wire.credential_from_wire(params["credential"]),
                params["run_id"], dict(params["admission_event"]),
                wire.attestation_from_wire(params["attestation"]))
            return {"v": wire.WIRE_VERSION, "ok": bool(acted)}
        if method == "authority.report_intervention_required":
            acted = authority.report_intervention_required(
                wire.credential_from_wire(params["credential"]),
                params["run_id"], params["step_index"], params["fragment_hash"],
                wire.attestation_from_wire(params["attestation"]))
            return {"v": wire.WIRE_VERSION, "ok": bool(acted)}
        if method == "gateway.execute":
            result = gateway.execute(
                wire.token_from_wire(params["token"]),
                wire.fragment_from_wire(params["fragment"]))
            return {"v": wire.WIRE_VERSION, "result": wire.effect_reply_to_wire(result)}
        raise wire.WireError(f"unhandled method {method!r}")


def _call(endpoint, method: str, params: Mapping[str, Any],
          request_id: str | None = None) -> dict:
    """Send one request to the deployment service and return the reply.

    Args:
        endpoint: A ServiceEndpoint or a bare socket path (a UDS endpoint), so the
            endpoint chooses the transport (UDS locally, TCP for the Kubernetes runner).
        method: The RPC method.
        params: The request parameters.
        request_id: A correlation id for tracing and logs, a fresh one when None. It is
            not the idempotency identity: a durable service derives that on the server
            from authenticated protocol material (session secret, token signature,
            approval signature, provisioner bootstrap, human credential) and the full
            request content, so a client can neither choose nor block another request's
            identity. See booking_v4.durable.request_identity.

    Returns:
        The decoded reply.

    Raises:
        WireError: The reply carries an error or is malformed.
        OSError: The connection failed or timed out.
    """
    with ServiceEndpoint.coerce(endpoint).connect(timeout=_DEPLOYMENT_TIMEOUT) as sock:
        sock.settimeout(_DEPLOYMENT_TIMEOUT)  # bound read and write too, not only connect
        request = {"v": wire.WIRE_VERSION, "method": method, "params": dict(params),
                   "request_id": request_id or uuid.uuid4().hex}
        sock.sendall((wire.encode(request) + "\n").encode("utf-8"))
        # No TCP half-close (shutdown(SHUT_WR)) here. The servers frame a request by
        # its trailing newline (readline), not by EOF, so the half-close adds nothing.
        # Worse, `kubectl port-forward` (the evaluation harness's path to the in-cluster
        # services) does not pass a half-close on. It tears the whole stream down, which
        # races the reply and yields an empty read.
        reply = wire.decode_line(_read_line(sock))
    if "error" in reply:
        raise wire.WireError(f"{method}: {reply['error']}")
    return reply


class AuthorityClient:
    """Runner-side proxy with the method signatures of the booking_v3 Authority."""

    def __init__(self, endpoint) -> None:
        # Accepts a ServiceEndpoint or a bare socket path (coerced to UDS).
        self._endpoint = ServiceEndpoint.coerce(endpoint)

    def request_execution_grant(self, credential, fragment, input_state_hash,
                                admission_event, intervention=None, attestation=None):
        """Request an execution grant and return (grant or None, reason)."""
        reply = _call(self._endpoint, "authority.request_execution_grant", {
            "credential": wire.credential_to_wire(credential),
            "fragment": wire.fragment_to_wire(fragment),
            "input_state_hash": input_state_hash,
            "admission_event": admission_event,
            "intervention": wire.intervention_to_wire(intervention),
            "attestation": wire.attestation_to_wire(attestation)},
            request_id=f"grant:{credential.session_id}")
        grant = wire.grant_from_wire(reply["grant"]) if reply["grant"] is not None else None
        return grant, reply["reason"]

    def finalize_transition(self, credential, record, attestation=None):
        """Report a transition record and return (envelope or None, reason)."""
        reply = _call(self._endpoint, "authority.finalize_transition", {
            "credential": wire.credential_to_wire(credential),
            "record": wire.record_to_wire(record),
            "attestation": wire.attestation_to_wire(attestation)},
            request_id=f"finalize:{record.grant_id}")
        envelope = (wire.envelope_from_wire(reply["envelope"])
                    if reply["envelope"] is not None else None)
        return envelope, reply["reason"]

    def report_denial(self, credential, run_id, admission_event, attestation=None) -> bool:
        """Report a denied admission. Return True when the Authority acted on it."""
        return _call(self._endpoint, "authority.report_denial", {
            "credential": wire.credential_to_wire(credential),
            "run_id": run_id, "admission_event": admission_event,
            "attestation": wire.attestation_to_wire(attestation)},
            request_id=f"deny:{credential.session_id}")["ok"]

    def report_intervention_required(self, credential, run_id, step_index, fragment_hash,
                                     attestation=None) -> bool:
        """Report that a fragment needs human intervention. Return True when the Authority acted on it."""
        return _call(self._endpoint, "authority.report_intervention_required", {
            "credential": wire.credential_to_wire(credential),
            "run_id": run_id, "step_index": step_index, "fragment_hash": fragment_hash,
            "attestation": wire.attestation_to_wire(attestation)},
            request_id=f"intervention:{credential.session_id}")["ok"]


class GatewayClient:
    """Runner-side proxy with the method signatures of the booking_v3 tool gateway."""

    def __init__(self, endpoint) -> None:
        # Accepts a ServiceEndpoint or a bare socket path (coerced to UDS).
        self._endpoint = ServiceEndpoint.coerce(endpoint)

    def execute(self, token, fragment):
        """Dispatch an authorised fragment and return the gateway's reply."""
        reply = _call(self._endpoint, "gateway.execute", {
            "token": wire.token_to_wire(token),
            "fragment": wire.fragment_to_wire(fragment)},
            request_id=f"gateway:{token.grant_id}")
        return wire.effect_reply_from_wire(reply["result"])

    def dispatch_outcome(self, token, fragment):
        """Return the stored outcome of a dispatch, or UNCERTAIN, without calling the counterparty."""
        reply = _call(self._endpoint, "gateway.dispatch_outcome", {
            "token": wire.token_to_wire(token),
            "fragment": wire.fragment_to_wire(fragment)},
            request_id=f"gateway-outcome:{token.grant_id}")
        return wire.effect_reply_from_wire(reply["result"])
