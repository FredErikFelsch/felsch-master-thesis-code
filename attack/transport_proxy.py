"""A transport on the path between the runner and the gateway, which rewrites one field.

It is the live counterpart of `booking_v3.scenarios._TransportOnThePath`, the same attack at
another level of the stack. It differs from `booking_v2.world.lying_executor`. There the
counterparty lies, the gateway receives the false value and records its digest, and report and
record agree, so the case is outside the attacker model. Here the gateway receives the true
value and records the digest of that value, and the rewrite happens afterwards on the way back
to the runner. That is the capability the attacker model (Chapter 3) grants a host beneath a
runner, and the observation check exists to catch it.

The attack needs a network position, not a privilege. The controller tells the machine its
`gateway_endpoint` in the clear, so a party at that address is the attacker of the model. In
the cluster this process is a second container in the gateway pod. It holds the pod's address
but no gateway database, token signing key, world store or credential. It forges nothing,
performs no effect of its own and changes one field of the answers it matches.

Everything else passes through. Every request is forwarded as received. Every reply that is not
a confirmed effect result carrying the named field is passed on unchanged. The framing (one
JSON object per line) is kept, and a rewritten reply is re-serialised as compact JSON.

    python3 -m attack.transport_proxy --listen 0.0.0.0:8443 --upstream 127.0.0.1:18443 \
        --field booking_ref --value FORGED-REF-1
"""

from __future__ import annotations

import argparse
import json
import socket
import socketserver
import threading
from typing import Any

#: Only a reply to this method is rewritten. Everything else is relayed.
TARGET_METHOD = "gateway.execute"

#: The outcome that carries an observation into the fact store. A refusal or a failure
#: has nothing a later binding could read, so rewriting one would prove nothing.
TARGET_OUTCOME = "CONFIRMED"

#: Bound on one line, mirroring booking_v4.wire.MAX_WIRE_BYTES. Without a bound a single peer
#: could make the proxy buffer without limit.
MAX_LINE_BYTES = 1 << 20

#: Generous, because only the caller should time out here. The runner's deployment timeout is
#: `booking_v4.budgets.RPC_TIMEOUT_S` (65 s).
SOCKET_TIMEOUT_SECONDS = 120.0


class Tamper:
    """The rewrite rule and its counter, shared by every connection thread."""

    def __init__(self, field: str, value: Any, limit: int | None = None,
                 insert: bool = False) -> None:
        """Set up the rule.

        `insert` is the live form of the offline scenario `adv-transport-rewrites-unbound-field`.
        In the running world some rule reads every field of a booking, so the only way to
        touch a field that no rule reads is to add one. An attacker on the path owns the bytes
        and may do that. The scenario shows that the digest covers the whole response and not
        a list of selected fields.

        Args:
            field: The payload field to rewrite.
            value: The value to put there.
            limit: The most replies to rewrite. None rewrites every matching one.
            insert: Write the field even when the response does not carry it.
        """
        self.field = field
        self.value = value
        self.limit = limit
        self.insert = insert
        self.count = 0
        self._lock = threading.Lock()

    def apply(self, method: str | None, reply: dict) -> tuple[dict, bool]:
        """Rewrite one reply if it matches the rule.

        Args:
            method: The method of the request this reply answers, or None if unparseable.
            reply: The decoded reply of the gateway.

        Returns:
            The reply to send on, and whether this call rewrote it.
        """
        if method != TARGET_METHOD:
            return reply, False
        result = reply.get("result")
        if not isinstance(result, dict) or result.get("outcome") != TARGET_OUTCOME:
            return reply, False
        payload = result.get("payload")
        if not isinstance(payload, dict):
            return reply, False
        if self.field not in payload and not self.insert:
            # Report the miss. Otherwise a run that targets a field the running world does
            # not produce leaves the proxy passive, and the harness would count the honest run
            # as an attack. The payload's keys are printed so that the next attempt can aim at
            # a field that exists.
            print(json.dumps({"event": "field-absent", "field": self.field,
                              "payload_keys": sorted(payload)}), flush=True)
            return reply, False
        with self._lock:
            if self.limit is not None and self.count >= self.limit:
                return reply, False
            self.count += 1
        tampered = dict(reply)
        tampered["result"] = dict(result, payload=dict(payload, **{self.field: self.value}))
        return tampered, True


def _read_line(sock: socket.socket, buffer: bytearray) -> bytes | None:
    """Read one newline-framed message, or return None at the end of the stream.

    Raises:
        ValueError: The buffered line exceeds `MAX_LINE_BYTES`.
    """
    while b"\n" not in buffer:
        if len(buffer) > MAX_LINE_BYTES:
            raise ValueError("message exceeds MAX_LINE_BYTES")
        chunk = sock.recv(65536)
        if not chunk:
            return None
        buffer.extend(chunk)
    line, _, rest = bytes(buffer).partition(b"\n")
    buffer[:] = rest
    return line


class _Handler(socketserver.BaseRequestHandler):
    """One client connection, relayed to one upstream connection."""

    def handle(self) -> None:
        """Relay one client connection and open the upstream connection only on the first request.

        Opening it late is required, not an optimisation. `booking_v4.services._TcpServer` is a
        plain `socketserver.TCPServer`, so the gateway serves one connection at a time, and its
        handler blocks until its peer sends a line or hangs up. The container's readiness probe
        opens a TCP connection to this proxy every second and sends nothing. A proxy that
        connected upstream on accept would park a silent connection in the gateway once a
        second, and every real request would queue behind it. The runner then hits its own
        deployment timeout after the effect has already happened, which shows as effects=1
        together with RUNNER_ERROR. So a connection that carries no request does not reach the
        gateway.
        """
        client, from_client, from_upstream = self.request, bytearray(), bytearray()
        upstream = None
        seen, relayed, last = 0, 0, None
        try:
            client.settimeout(SOCKET_TIMEOUT_SECONDS)
            while True:
                request_line = _read_line(client, from_client)
                if request_line is None:
                    return
                if upstream is None:              # the first real request opens the upstream
                    upstream = socket.create_connection(self.server.upstream,
                                                        timeout=SOCKET_TIMEOUT_SECONDS)
                method = None
                try:
                    method = json.loads(request_line).get("method")
                except Exception:
                    pass                          # unparseable: relay it and leave it alone
                seen, last = seen + 1, method
                upstream.sendall(request_line + b"\n")

                reply_line = _read_line(upstream, from_upstream)
                if reply_line is None:
                    # The gateway closed without a newline-terminated answer. Log it, because
                    # otherwise the caller sees only a timeout later and cannot tell a lost
                    # answer from a slow one.
                    print(json.dumps({"event": "upstream-closed-without-reply",
                                      "method": method, "buffered": len(from_upstream)}),
                          flush=True)
                    return
                relayed += 1
                try:
                    reply = json.loads(reply_line)
                except Exception:
                    client.sendall(reply_line + b"\n")
                    continue
                reply, tampered = self.server.tamper.apply(method, reply)
                if tampered:
                    out = json.dumps(reply, sort_keys=True, separators=(",", ":")).encode()
                    print(json.dumps({"event": "tampered", "field": self.server.tamper.field,
                                      "n": self.server.tamper.count}), flush=True)
                else:
                    out = reply_line
                client.sendall(out + b"\n")
        except (OSError, ValueError) as exc:
            print(json.dumps({"event": "connection-error", "reason": f"{type(exc).__name__}: {exc}",
                              "requests": seen, "replies": relayed, "last_method": last}),
                  flush=True)
        finally:
            if seen:
                print(json.dumps({"event": "connection-closed", "requests": seen,
                                  "replies": relayed, "last_method": last}), flush=True)
            if upstream is not None:
                upstream.close()


class _Server(socketserver.ThreadingTCPServer):
    """The listening proxy, one thread per client connection."""

    allow_reuse_address = True
    daemon_threads = True


def serve(listen: tuple[str, int], upstream: tuple[str, int], tamper: Tamper) -> _Server:
    """Start the proxy in a background thread.

    Args:
        listen: Where the runner believes the gateway is.
        upstream: The real gateway.
        tamper: The rewrite rule.

    Returns:
        The running server. The caller owns its lifetime.
    """
    server = _Server(listen, _Handler)
    server.upstream = upstream
    server.tamper = tamper
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _endpoint(text: str) -> tuple[str, int]:
    """Parse `host:port`, the same spelling the services take for `--bind`."""
    host, _, port = text.rpartition(":")
    if not host or not port.isdigit():
        raise argparse.ArgumentTypeError(f"expected host:port, got {text!r}")
    return host, int(port)


def main(argv: list[str] | None = None) -> int:
    """Run the proxy in the foreground until the process is signalled."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--listen", required=True, type=_endpoint,
                        help="where the runner believes the gateway is")
    parser.add_argument("--upstream", required=True, type=_endpoint,
                        help="the real gateway, normally on the pod's loopback")
    parser.add_argument("--field", required=True,
                        help="the payload field to rewrite, e.g. booking_ref (bound) or status (unbound)")
    parser.add_argument("--value", required=True, help="what to put there instead")
    parser.add_argument("--limit", type=int, default=None,
                        help="rewrite at most this many replies (default: every matching one)")
    parser.add_argument("--insert", action="store_true",
                        help="write the field even when the response does not carry it "
                             "(the live form of the unbound-field scenario)")
    args = parser.parse_args(argv)

    tamper = Tamper(args.field, args.value, args.limit, insert=args.insert)
    server = serve(args.listen, args.upstream, tamper)
    print(json.dumps({"event": "listening", "listen": f"{args.listen[0]}:{args.listen[1]}",
                      "upstream": f"{args.upstream[0]}:{args.upstream[1]}",
                      "field": args.field, "limit": args.limit,
                      "insert": bool(args.insert)}), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
