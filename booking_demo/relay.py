"""Relay for a network that cannot reach the model APIs directly (OpenAI and Anthropic).

Run on a machine that can (a Raspberry Pi in the LAN). Set the key of every provider the relay
should serve, one or both:

    export OPENAI_API_KEY=sk-...
    export ANTHROPIC_API_KEY=sk-ant-...
    python3 -m booking_demo.relay --host 0.0.0.0 --port 8787

and on the demo machine, per provider (the relay holds the real key, any non-empty value works here):

    # OpenAI, the SDK appends /chat/completions to the base URL
    export OPENAI_API_KEY=relay
    export OPENAI_BASE_URL=http://<pi>:8787/v1

    # Anthropic, the SDK appends /v1/messages to the base URL
    export ANTHROPIC_API_KEY=relay
    export ANTHROPIC_BASE_URL=http://<pi>:8787

Routing is by path. `/v1/messages` and what is below it goes to Anthropic with the key in the
`x-api-key` header, together with the `anthropic-version` and `anthropic-beta` headers of the client
(the version defaults to 2023-06-01). Everything else below `/v1/` goes to OpenAI with the key as a
bearer token. A provider whose key is not set answers 503. The reply is returned as it came, status
included. A response is read completely before it is passed on, so streaming is not supported.
The relay uses the standard library only. It logs one line per request (provider, path,
status, bytes), and neither the payload nor a key.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Mapping

#: Version header the Anthropic API requires when the client sent none.
ANTHROPIC_VERSION = "2023-06-01"
#: Seconds one upstream call may take (a long non streaming completion included).
UPSTREAM_TIMEOUT_S = 180


def _openai_headers(key: str, incoming: Mapping[str, str]) -> dict:
    """Return the OpenAI headers: the relay's key as a bearer token."""
    return {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}


def _anthropic_headers(key: str, incoming: Mapping[str, str]) -> dict:
    """Return the Anthropic headers: the relay's key in `x-api-key`.

    The client's own key is not forwarded. Its version and beta headers are, because the
    request body depends on them.
    """
    headers = {"Content-Type": "application/json", "x-api-key": key,
               "anthropic-version": incoming.get("anthropic-version") or ANTHROPIC_VERSION}
    beta = incoming.get("anthropic-beta")
    if beta:
        headers["anthropic-beta"] = beta
    return headers


@dataclass(frozen=True)
class Provider:
    """One upstream API: where it is, which environment variable holds its key, how it is addressed."""

    name: str
    upstream_env: str
    upstream_default: str
    key_env: str
    headers: Callable[[str, Mapping[str, str]], dict]

    def upstream(self) -> str:
        """Return the base URL (including `/v1`), read when used so a test can point it elsewhere."""
        return os.environ.get(self.upstream_env, self.upstream_default).rstrip("/")

    def key(self) -> str:
        """Return the real API key, empty when this provider is not configured."""
        return os.environ.get(self.key_env, "")


OPENAI = Provider("openai", "OPENAI_UPSTREAM", "https://api.openai.com/v1", "OPENAI_API_KEY", _openai_headers)
ANTHROPIC = Provider("anthropic", "ANTHROPIC_UPSTREAM", "https://api.anthropic.com/v1", "ANTHROPIC_API_KEY",
                     _anthropic_headers)
PROVIDERS = (OPENAI, ANTHROPIC)


def provider_for(path: str) -> Provider:
    """Return the provider a request path belongs to: `/v1/messages...` is Anthropic, the rest OpenAI."""
    bare = path.split("?", 1)[0]
    return ANTHROPIC if bare == "/v1/messages" or bare.startswith("/v1/messages/") else OPENAI


class Relay(BaseHTTPRequestHandler):
    """HTTP handler that forwards POST requests under `/v1/` to the provider they belong to."""

    def _reply(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:                                 # noqa: N802
        """Forward one request upstream and return the reply as it came, status included."""
        if not self.path.startswith("/v1/"):
            return self._reply(404, b'{"error":"only /v1/* is relayed"}')
        provider = provider_for(self.path)
        bare = self.path.split("?", 1)[0]
        key = provider.key()
        if not key:
            sys.stderr.write(f"[relay] {provider.name} {bare} -> 503 (no key configured)\n")
            return self._reply(503, json.dumps({"error": f"{provider.name} is not configured on this relay"}).encode())
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        req = urllib.request.Request(
            provider.upstream() + self.path[len("/v1"):], data=body,
            headers=provider.headers(key, {k.lower(): v for k, v in self.headers.items()}))
        try:
            with urllib.request.urlopen(req, timeout=UPSTREAM_TIMEOUT_S) as resp:
                data = resp.read()
                sys.stderr.write(f"[relay] {provider.name} {bare} -> {resp.status} ({len(data)} B)\n")
                return self._reply(resp.status, data)
        except urllib.error.HTTPError as exc:
            data = exc.read()
            sys.stderr.write(f"[relay] {provider.name} {bare} -> {exc.code}\n")
            return self._reply(exc.code, data)
        except Exception as exc:                                # noqa: BLE001
            sys.stderr.write(f"[relay] {provider.name} {bare} -> upstream error: {exc}\n")
            return self._reply(502, json.dumps({"error": f"upstream: {exc}"}).encode())

    def log_message(self, *args) -> None:
        """Silence the default access log. `do_POST` writes the one line the relay allows itself."""


def build_parser() -> argparse.ArgumentParser:
    """Build the command line. The relay holds the real API keys, so it listens on loopback by default."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1",
                    help="address to listen on, 0.0.0.0 only inside a network you trust (default: loopback)")
    ap.add_argument("--port", type=int, default=8787)
    return ap


def exposure_warning(host: str) -> str | None:
    """Return a warning when the relay is reachable beyond this machine, else None."""
    if host in ("127.0.0.1", "localhost", "::1"):
        return None
    return (f"relay listens on {host}: every host that can reach it may use your API keys "
            f"without authentication")


def main(argv=None) -> int:
    """Start the relay for every provider whose key is set."""
    args = build_parser().parse_args(argv)
    served = [p for p in PROVIDERS if p.key()]
    if not served:
        sys.exit("set OPENAI_API_KEY, ANTHROPIC_API_KEY or both")
    warning = exposure_warning(args.host)
    if warning:
        sys.stderr.write(f"[relay] WARNING: {warning}\n")
    for p in served:
        client_url = f"http://{args.host}:{args.port}" + ("/v1" if p is OPENAI else "")
        print(f"relay {p.name}: {client_url} -> {p.upstream()}")
    for p in PROVIDERS:
        if p not in served:
            print(f"relay {p.name}: not served ({p.key_env} is not set)")
    ThreadingHTTPServer((args.host, args.port), Relay).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
