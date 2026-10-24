"""The trusted runner controller as a separate operating-system process.

This process is the separate trust domain. It receives its trusted provisioning configuration once
on stdin (the durable service endpoint, the provisioner bootstrap, the trust anchors, the fixed
runner image and the socket-mount paths), builds the container lifecycle provisioner, and serves the
narrow controller RPC:

    controller.spawn(fragment, envelope)                 -> {handle_id}
    controller.execute(handle_id, policy, envelope,       -> {result}
                       fragment, intervention)

The RPC transport is neutral. The controller binds a UDS (`--uds PATH`) or TCP (`--tcp HOST:PORT`)
listener and reports its connect ServiceEndpoint on the stdout handshake. Locally the orchestrator
uses the UDS. In a cluster it can use the TCP Service endpoint of a controller in a different pod
without any change to the contract, only the launch backend (Docker or Kubernetes Job) differs.

The orchestrator does not see any provisioning material. It arrives here on stdin, in the
controller's own address space. The container launch backend is constructed only here, the
orchestrator-facing module `controller` builds none. Handles are opaque ids mapped to real
single-use runner handles, and an unknown or reused id is rejected. If this process dies, its
in-memory handle map is lost, every handle becomes unusable and the orchestrator's next call
fails.

Trust assumption: controller initialisation is trusted. Adversarial control begins only after the
controller has been provisioned with its fixed launch configuration on stdin. The Kubernetes
deployment moves this provisioning from the orchestrator to a trusted init Job and to Kubernetes
RBAC (`controller_k8s_process`, `k8s_init`).

Usage:  python3 -m booking_v4.controller_process (--uds S | --tcp HOST:PORT)
        with the config on stdin.
"""

from __future__ import annotations

import argparse
import json
import socketserver
import sys
import threading
import traceback
import uuid
import weakref

from booking_v3.authority import ProvisionerCredential

from . import wire
from .container_backend import ContainerRunnerProvisioner, _resolve_image
from .controller import CONTROLLER_METHODS
from .durable import RemoteAuthorityHandle
from .endpoint import ServiceEndpoint
from .services import _new_tcp_server, _new_uds_server

_MAX = wire.MAX_WIRE_BYTES


def _build_provisioner(config: dict) -> ContainerRunnerProvisioner:
    """Construct the trusted container launch backend from the stdin config.

    The bootstrap and anchors are reconstructed here, in the controller's own
    process, and the image digest is resolved and pinned here. A missing image
    stops the controller. RemoteAuthorityHandle establishes runner sessions over
    the durable service endpoint. This is the launch authority the orchestrator
    does not hold.
    """
    authority = RemoteAuthorityHandle(config["host_service_socket"])
    anchors = wire.anchors_from_wire(config["anchors"])
    bootstrap = ProvisionerCredential(secret=config["bootstrap_secret"])
    image = _resolve_image(config["image"])  # the controller pins the digest itself
    return ContainerRunnerProvisioner(
        authority, anchors, bootstrap,
        config["host_sock_dir"], config["container_socket"], image,
        trace=False)


class _Controller:
    """Serves the narrow controller RPC over a UDS or TCP listener."""

    def __init__(self, provisioner: ContainerRunnerProvisioner,
                 bind: tuple) -> None:
        self._prov = provisioner
        self._handles: dict[str, object] = {}
        handler = self._make_handler()
        kind = bind[0]
        if kind == "uds":
            self._server = _new_uds_server(bind[1], handler)
            self.endpoint = ServiceEndpoint.uds(bind[1])
        else:  # tcp
            self._server = _new_tcp_server((bind[1], bind[2]), handler)
            host, port = self._server.server_address[0], self._server.server_address[1]
            self.endpoint = ServiceEndpoint.tcp(host, port)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._finalizer = weakref.finalize(self, _Controller._cleanup, self._server)

    @staticmethod
    def _cleanup(server) -> None:
        """Stop the listener."""
        server.shutdown()
        server.server_close()

    def _make_handler(self):
        """Build the stream handler that decodes one request line and writes one reply."""
        outer = self

        class _Handler(socketserver.StreamRequestHandler):
            timeout = wire.REQUEST_TIMEOUT_S

            def handle(self) -> None:
                try:
                    raw = self.rfile.readline(_MAX + 2)
                except OSError:
                    return  # nothing arrived in time (or the peer went away): drop the connection
                try:
                    if not raw.endswith(b"\n"):
                        raise wire.WireError("request exceeds MAX_WIRE_BYTES or is unterminated")
                    reply = outer._serve(wire.decode_line(raw.decode("utf-8")))
                except Exception as exc:
                    # Internals do not go back to the untrusted orchestrator. A WireError
                    # (protocol validation) is safe to name. Anything else becomes a
                    # generic code, and the detail is logged in this process only.
                    if isinstance(exc, wire.WireError):
                        reply = {"v": wire.WIRE_VERSION, "error": str(exc), "code": "WIRE"}
                    else:
                        sys.stderr.write("[controller-audit] " + traceback.format_exc())
                        sys.stderr.flush()
                        reply = {"v": wire.WIRE_VERSION,
                                 "error": "internal controller error", "code": "INTERNAL"}
                self.wfile.write((wire.encode(reply) + "\n").encode("utf-8"))

        return _Handler

    def _serve(self, message) -> dict:
        """Serve one controller.spawn or controller.execute request.

        Raises:
            WireError: An unknown method, another key set, or an unknown or used handle id.
        """
        wire.expect_keys(message, {"v", "method", "params", "request_id"}, "controller rpc")
        method = message["method"]
        if method not in CONTROLLER_METHODS:
            raise wire.WireError(f"unknown controller method {method!r}")
        # The strict exact key set rejects any orchestrator attempt to supply an image,
        # endpoint, environment, mounts, bootstrap or credential.
        params = wire.expect_keys(message["params"], CONTROLLER_METHODS[method],
                                  f"{method} params")
        if method == "controller.spawn":
            fragment = wire.fragment_from_wire(params["fragment"])
            envelope = wire.envelope_from_wire(params["envelope"])
            handle = self._prov.spawn(fragment, envelope)
            handle_id = "rh-" + uuid.uuid4().hex
            self._handles[handle_id] = handle
            return {"v": wire.WIRE_VERSION, "handle_id": handle_id}
        # controller.execute
        handle_id = params["handle_id"]
        if not isinstance(handle_id, str) or handle_id not in self._handles:
            raise wire.WireError("unknown or already-used runner handle")
        handle = self._handles.pop(handle_id)  # single use: consumed on execute
        result = handle.execute(
            wire.policy_from_wire(params["policy"]),
            wire.envelope_from_wire(params["envelope"]),
            wire.fragment_from_wire(params["fragment"]),
            wire.intervention_from_wire(params["intervention"]))
        return {"v": wire.WIRE_VERSION, "result": wire.result_to_wire(result)}


def main() -> int:
    """Read the config from stdin, serve the controller RPC and report the endpoint."""
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--uds")
    group.add_argument("--tcp")  # HOST:PORT
    args = parser.parse_args()
    if args.uds:
        bind = ("uds", args.uds)
    else:
        host, port = args.tcp.rsplit(":", 1)
        bind = ("tcp", host, int(port))

    config = json.loads(sys.stdin.readline())
    provisioner = _build_provisioner(config)
    controller = _Controller(provisioner, bind)

    # Handshake: report the actual connect endpoint (for TCP the bound port, which may be
    # ephemeral). The launcher provisions the orchestrator with it.
    sys.stdout.write(json.dumps({"endpoint": controller.endpoint.to_wire()}) + "\n")
    sys.stdout.flush()
    import time
    while True:  # serve until killed
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
