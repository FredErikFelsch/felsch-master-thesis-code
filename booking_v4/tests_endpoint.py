"""Tests for ServiceEndpoint and the TCP service path.

No Docker needed. Covers the wire round trip, strict decoding, TCP address validation, real UDS
and TCP connections, a real Authority and gateway RPC over TCP, the same runner completing a step
over TCP, the provisioning-input trust property (the endpoint is not accepted in the untrusted
execution message), and bounded connection failure. ServiceEndpoint lets a deployment change who
provisions without changing the transport.

Run from the repository root:  python3 -m booking_v4.tests_endpoint
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest

from booking_v1.clock import FixedClock
from booking_v3.authority import Authority
from booking_v3.gateway import ToolGateway
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3
from booking_v3.provisioner import create_deployment
from booking_v3 import scenarios as v3_scenarios

from . import wire
from .durable import (AuthorityFacade, DurableDeploymentServer, DurableStore,
                      _RestoredDeployment)
from .endpoint import ServiceEndpoint
from .process_backend import _REPO_ROOT, _runner_environment
from .services import DeploymentServer, _call


def _run_runner(endpoint, policy, envelope, fragment, credential, anchors):
    """Spawn one fresh runner_process, provisioned to reach ``endpoint``, and run it.

    Returns the parsed RunnerResult. Only the endpoint varies between callers
    (uds or tcp, plain or durable service). The provisioning and execution
    messages are built the same way each time.
    """
    provisioning = wire.encode({
        "v": wire.WIRE_VERSION, "kind": "provisioning",
        "endpoint": endpoint.to_wire(),
        "credential": wire.credential_to_wire(credential),
        "anchors": wire.anchors_to_wire(anchors)}) + "\n"
    execution = wire.encode({
        "v": wire.WIRE_VERSION, "kind": "execution",
        "policy": wire.policy_to_wire(policy),
        "envelope": wire.envelope_to_wire(envelope),
        "fragment": wire.fragment_to_wire(fragment),
        "intervention": wire.intervention_to_wire(None)}) + "\n"
    proc = subprocess.Popen(
        [sys.executable, "-m", "booking_v4.runner_process"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=_REPO_ROOT, env=_runner_environment(), text=True)
    try:
        out, err = proc.communicate(provisioning + execution, timeout=60)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    if proc.returncode != 0:
        raise AssertionError(f"runner exited {proc.returncode}: {err}")
    lines = [ln for ln in out.splitlines() if ln.strip()]
    if len(lines) != 1:
        raise AssertionError(f"expected one result line, got {len(lines)}: {out!r}")
    return wire.result_from_wire(wire.decode_line(lines[0]))


class ServiceEndpointWireTests(unittest.TestCase):
    """The wire form of an endpoint round-trips and is decoded strictly."""

    def test_uds_round_trip(self):
        ep = ServiceEndpoint.uds("/tmp/authority.sock")
        self.assertEqual(ServiceEndpoint.from_wire(ep.to_wire()), ep)

    def test_tcp_round_trip(self):
        ep = ServiceEndpoint.tcp("10.0.0.5", 8443)
        self.assertEqual(ep.to_wire(), {"kind": "tcp", "address": "10.0.0.5:8443"})
        self.assertEqual(ServiceEndpoint.from_wire(ep.to_wire()), ep)

    def test_from_wire_is_strict(self):
        for bad in ({"kind": "uds"}, {"kind": "uds", "address": "/x", "extra": 1},
                    {"kind": "smtp", "address": "h:1"}):
            with self.assertRaises(wire.WireError):
                ServiceEndpoint.from_wire(bad)

    def test_tcp_validation_rejects_malformed_addresses(self):
        ServiceEndpoint.from_wire({"kind": "tcp", "address": "host:8443"})  # valid
        # "8443\u00b2" passes str.isdigit() but not int(), so it checks the ASCII guard
        for bad in ("noport", ":123", "host:abc", "host:0", "host:70000", "host:8443\u00b2"):
            with self.assertRaises(wire.WireError):
                ServiceEndpoint("tcp", bad)

    def test_coerce_bare_path_is_uds(self):
        self.assertEqual(ServiceEndpoint.coerce("/tmp/a.sock"),
                         ServiceEndpoint.uds("/tmp/a.sock"))
        ep = ServiceEndpoint.tcp("h", 1)
        self.assertIs(ServiceEndpoint.coerce(ep), ep)


class ServiceEndpointConnectTests(unittest.TestCase):
    """Endpoints connect over real sockets and reach a real deployment server."""

    @staticmethod
    def _echo_server(family, address):
        """Start a one-shot echo server and return its listening socket."""
        srv = socket.socket(family, socket.SOCK_STREAM)
        srv.bind(address)
        srv.listen(1)

        def serve():
            conn, _ = srv.accept()
            with conn:
                conn.sendall(conn.recv(1024))
        threading.Thread(target=serve, daemon=True).start()
        return srv

    def test_tcp_connect(self):
        srv = self._echo_server(socket.AF_INET, ("127.0.0.1", 0))
        try:
            ep = ServiceEndpoint.tcp("127.0.0.1", srv.getsockname()[1])
            with ep.connect(timeout=5) as s:
                s.sendall(b"ping")
                self.assertEqual(s.recv(16), b"ping")
        finally:
            srv.close()

    def test_uds_rpc_reaches_deployment_server(self):
        dep = create_deployment(FixedClock(1_000))
        server = DeploymentServer(dep)  # UDS
        try:
            with self.assertRaises(wire.WireError):
                _call(server.endpoint, "authority.does_not_exist", {})
        finally:
            server.close()

    def test_tcp_rpc_reaches_real_authority_gateway(self):
        # A request over TCP to a DeploymentServer with real dispatch, not an echo.
        # A real method with the full key set and a malformed credential reaches the
        # credential decoder (WireError), and an unknown method is rejected.
        dep = create_deployment(FixedClock(1_000))
        server = DeploymentServer(dep, tcp=("127.0.0.1", 0))
        try:
            self.assertEqual(server.endpoint.kind, "tcp")
            with self.assertRaises(wire.WireError) as ctx:
                _call(server.endpoint, "authority.request_execution_grant",
                      {"credential": {"bad": True}, "fragment": {"bad": True},
                       "input_state_hash": "x", "admission_event": {"op": "pay"},
                       "intervention": None, "attestation": None})
            self.assertIn("runner-credential", str(ctx.exception))
            with self.assertRaises(wire.WireError):
                _call(server.endpoint, "gateway.does_not_exist", {})
        finally:
            server.close()


class RunnerOverTcpTest(unittest.TestCase):
    """The unchanged runner completes a step against a TCP service."""

    def test_frozen_runner_completes_a_step_over_tcp(self):
        # The same runner_process.py, provisioned with a TCP endpoint, drives the
        # real Authority and gateway over TCP to a completed step, so the runner
        # works over TCP as it does over UDS.
        dep = create_deployment(FixedClock(v3_scenarios.NOW))
        server = DeploymentServer(dep, tcp=("127.0.0.1", 0))
        proc = None
        try:
            policy = default_p3()
            approval = v3_scenarios.approve(
                policy, approver_id=v3_scenarios.APPROVER_ID, approval_id="appr-tcp",
                run_id="run-tcp", issued_at=v3_scenarios.ISSUED_AT,
                expires_at=v3_scenarios.EXPIRES_AT)
            s0 = dep.authority.create_run(policy, approval, "run-tcp")
            frag0 = v3_scenarios.honest_fragment(policy, "run-tcp", 0,
                                                 happy_path_arguments()[0])
            credential = dep.authority.establish_runner_session(
                dep.bootstrap, frag0.run_id, frag0.fragment_hash, s0.state_hash)

            provisioning = wire.encode({
                "v": wire.WIRE_VERSION, "kind": "provisioning",
                "endpoint": server.endpoint.to_wire(),  # kind == tcp
                "credential": wire.credential_to_wire(credential),
                "anchors": wire.anchors_to_wire(dep.anchors)}) + "\n"
            execution = wire.encode({
                "v": wire.WIRE_VERSION, "kind": "execution",
                "policy": wire.policy_to_wire(policy),
                "envelope": wire.envelope_to_wire(s0),
                "fragment": wire.fragment_to_wire(frag0),
                "intervention": wire.intervention_to_wire(None)}) + "\n"

            proc = subprocess.Popen(
                [sys.executable, "-m", "booking_v4.runner_process"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=_REPO_ROOT, env=_runner_environment(), text=True)
            out, err = proc.communicate(provisioning + execution, timeout=60)
            self.assertEqual(proc.returncode, 0, err)
            lines = [ln for ln in out.splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1, out)
            result = wire.result_from_wire(wire.decode_line(lines[0]))
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
        finally:
            if proc and proc.poll() is None:
                proc.kill()
                proc.wait()
            server.close()


class ProvisioningTrustAndBoundsTests(unittest.TestCase):
    """The endpoint comes only from the trusted provisioning input, and a dead one fails fast."""

    def test_endpoint_is_not_accepted_in_execution_input(self):
        # The endpoint belongs to the trusted provisioning input (line 1) only. The
        # untrusted execution message (line 2) has a fixed key set that rejects a
        # smuggled 'endpoint', so a compromised agent cannot redirect the runner to
        # its own "Authority". The endpoint in the provisioning input is accepted.
        good_exec = {"policy": 1, "envelope": 1, "fragment": 1, "intervention": None}
        wire._expect({"v": wire.WIRE_VERSION, "kind": "execution", **good_exec},
                     "execution", {"policy", "envelope", "fragment", "intervention"})
        with self.assertRaises(wire.WireError):
            wire._expect({"v": wire.WIRE_VERSION, "kind": "execution",
                          **good_exec, "endpoint": {"kind": "tcp", "address": "evil:9"}},
                         "execution", {"policy", "envelope", "fragment", "intervention"})

    def test_malformed_provisioning_endpoint_rejected(self):
        with self.assertRaises(wire.WireError):
            ServiceEndpoint.from_wire({"kind": "tcp"})  # missing address
        with self.assertRaises(wire.WireError):
            ServiceEndpoint.from_wire({"kind": "tcp", "address": "host:notaport"})

    def test_connection_failure_is_bounded_not_hung(self):
        # A dead TCP endpoint fails the RPC promptly (refused or timed out) instead
        # of hanging the caller.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            dead_port = probe.getsockname()[1]  # bound, not listening
        ep = ServiceEndpoint.tcp("127.0.0.1", dead_port)
        with self.assertRaises((OSError, wire.WireError)):
            _call(ep, "authority.does_not_exist", {})


class DurableRunnerOverTcpTests(unittest.TestCase):
    """The durable service exposed over TCP, the stack the Kubernetes deployment uses.

    With durability and TCP checked together here, a change of who provisions or of the
    Kubernetes runner lifecycle does not have to touch the Authority and gateway transport.
    """

    def _fresh_durable_tcp(self, db_path):
        """Seed a fresh store and serve it over TCP. Return (clock, store, authority, bootstrap, server)."""
        clock = FixedClock(v3_scenarios.NOW)
        store = DurableStore(db_path)
        authority, bootstrap, _human = Authority.create(clock)
        gateway = ToolGateway(authority.token_key(), clock)
        with store.transaction():
            store.put_states(json.dumps(authority.export_state(), sort_keys=True),
                             json.dumps(gateway.export_state(), sort_keys=True))
        server = DurableDeploymentServer(
            _RestoredDeployment(authority, gateway), store, tcp=("127.0.0.1", 0))
        return clock, store, authority, bootstrap, server

    def _restore_durable_tcp(self, clock, store):
        """Restore Authority and gateway from the store and serve them on a new TCP listener."""
        states = store.load_states()
        authority = Authority.restore(clock, states[0])
        gateway = ToolGateway(authority.token_key(), clock)
        gateway.restore_state(states[1])
        server = DurableDeploymentServer(
            _RestoredDeployment(authority, gateway), store, tcp=("127.0.0.1", 0))
        return authority, server

    def _setup_persisted(self, authority, server, policy, bootstrap):
        # Run activation and session establishment go through the durable service
        # over TCP, so they are persisted and survive a restart.
        auth = AuthorityFacade(authority, server.endpoint)
        approval = v3_scenarios.approve(
            policy, approver_id=v3_scenarios.APPROVER_ID, approval_id="appr-dtcp",
            run_id="run-dtcp", issued_at=v3_scenarios.ISSUED_AT,
            expires_at=v3_scenarios.EXPIRES_AT)
        s0 = auth.create_run(policy, approval, "run-dtcp")
        frag0 = v3_scenarios.honest_fragment(policy, "run-dtcp", 0, happy_path_arguments()[0])
        cred = auth.establish_runner_session(
            bootstrap, frag0.run_id, frag0.fragment_hash, s0.state_hash)
        return s0, frag0, cred

    def test_durable_runner_over_tcp_completes(self):
        with tempfile.TemporaryDirectory() as d:
            clock, store, authority, bootstrap, server = self._fresh_durable_tcp(
                os.path.join(d, "dep.db"))
            try:
                self.assertEqual(server.endpoint.kind, "tcp")
                policy = default_p3()
                s0, frag0, cred = self._setup_persisted(authority, server, policy, bootstrap)
                result = _run_runner(server.endpoint, policy, s0, frag0, cred,
                                     authority.anchors())
                self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
            finally:
                server.close()
                store.close()

    def test_durable_tcp_survives_restart_and_rebind(self):
        with tempfile.TemporaryDirectory() as d:
            clock, store, authority, bootstrap, server = self._fresh_durable_tcp(
                os.path.join(d, "dep.db"))
            policy = default_p3()
            s0, frag0, cred = self._setup_persisted(authority, server, policy, bootstrap)
            anchors = authority.anchors()
            server.close()  # simulate a service crash

            # Restart: rebuild from SQLite alone and bind a fresh TCP listener. Kubernetes
            # needs no identical pod IP, because the stable logical endpoint is the
            # ClusterIP Service, so the new listener may get any port.
            authority2, server2 = self._restore_durable_tcp(clock, store)
            try:
                self.assertEqual(server2.endpoint.kind, "tcp")
                result = _run_runner(server2.endpoint, policy, s0, frag0, cred, anchors)
                self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
            finally:
                server2.close()
                store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
