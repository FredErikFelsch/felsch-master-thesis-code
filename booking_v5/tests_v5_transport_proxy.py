"""The live transport attack, tested where it can be tested offline: the rewrite rule itself.

These tests cover the part that decides whether the live run means anything. The proxy must be
a pure relay for everything except one field of one confirmed effect result, and it must pass
every other reply through byte for byte. A proxy that reshaped an honest reply would make a
refusal ambiguous: the run would stop and nobody could say whether the observation check or the
harness produced it.

The isolation tests keep the attacker outside the measured artefact. The attack package must not
be in the runner image and must not move the runner source hash. Otherwise the guest would have
to be rebuilt for a change to the attacker, and the attacker would be inside the measured
boundary.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import socket
import threading
import time
import unittest

from attack.transport_proxy import TARGET_METHOD, Tamper, serve

MOCKS = pathlib.Path(__file__).resolve().parent.parent


def _confirmed(**payload) -> dict:
    """Return a wire reply with a confirmed effect result carrying `payload`."""
    return {"v": "wire-1", "result": {"kind": "effect-result", "outcome": "CONFIRMED",
                                      "payload": dict(payload), "error": None}}


class TamperRuleTests(unittest.TestCase):
    """The rule, in isolation from the sockets."""

    def test_a_bound_field_of_a_confirmed_result_is_rewritten(self):
        t = Tamper("booking_ref", "FORGED-1")
        out, tampered = t.apply(TARGET_METHOD, _confirmed(booking_ref="REAL-1", amount_minor=34900))
        self.assertTrue(tampered)
        self.assertEqual(out["result"]["payload"]["booking_ref"], "FORGED-1")
        self.assertEqual(out["result"]["payload"]["amount_minor"], 34900, "only one field moves")
        self.assertEqual(t.count, 1)

    def test_a_field_no_binding_reads_is_rewritten_just_the_same(self):
        # The digest covers the whole response, so the check does not depend on a field list an
        # attacker could dodge.
        t = Tamper("status", "SETTLED")
        out, tampered = t.apply(TARGET_METHOD, _confirmed(booking_ref="REAL-1", status="OK"))
        self.assertTrue(tampered)
        self.assertEqual(out["result"]["payload"]["status"], "SETTLED")

    def test_another_method_is_not_touched(self):
        t = Tamper("booking_ref", "FORGED-1")
        _, tampered = t.apply("authority.finalize_transition", _confirmed(booking_ref="REAL-1"))
        self.assertFalse(tampered)
        self.assertEqual(t.count, 0)

    def test_a_refusal_and_a_failure_are_not_touched(self):
        t = Tamper("booking_ref", "FORGED-1")
        refusal = {"v": "wire-1", "result": {"kind": "gateway-refusal", "reason": "token consumed",
                                             "dispatch_attempted": False}}
        self.assertFalse(t.apply(TARGET_METHOD, refusal)[1])
        failed = {"v": "wire-1", "result": {"kind": "effect-result", "outcome": "FAILED",
                                            "payload": {"booking_ref": "REAL-1"}, "error": "x"}}
        self.assertFalse(t.apply(TARGET_METHOD, failed)[1])
        self.assertEqual(t.count, 0)

    def test_an_absent_field_is_not_invented(self):
        t = Tamper("booking_ref", "FORGED-1")
        self.assertFalse(t.apply(TARGET_METHOD, _confirmed(amount_minor=34900))[1])

    def test_an_absent_field_with_insert_is_written_anyway(self):
        """The live form of the unbound-field scenario.

        In the running world every field of a booking is read by some rule, so a field that no
        rule reads has to be added. The attacker owns the bytes on the way back and may do that.
        The claim under test is that the digest covers the whole response and not a list of
        selected fields.
        """
        t = Tamper("status", "confirmed-by-someone-else", insert=True)
        out, tampered = t.apply(TARGET_METHOD, _confirmed(booking_ref="REAL-1"))
        self.assertTrue(tampered)
        self.assertEqual(out["result"]["payload"]["status"], "confirmed-by-someone-else")
        self.assertEqual(out["result"]["payload"]["booking_ref"], "REAL-1")

    def test_an_absent_field_without_insert_is_reported_and_not_invented(self):
        """A run whose target field is absent leaves the transport passive, and the proxy says so.

        A run that targets a field the running world does not produce, such as `status`, leaves
        the transport passive. The proxy reports the fields the response carried, so a harness
        cannot count the honest run as a successful attack.
        """
        t = Tamper("status", "x")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            _, tampered = t.apply(TARGET_METHOD, _confirmed(booking_ref="REAL-1", price_minor=1))
        self.assertFalse(tampered)
        self.assertEqual(t.count, 0)
        event = json.loads(buffer.getvalue().strip())
        self.assertEqual(event["event"], "field-absent")
        self.assertEqual(event["payload_keys"], ["booking_ref", "price_minor"])

    def test_the_limit_caps_how_many_replies_are_rewritten(self):
        t = Tamper("booking_ref", "FORGED-1", limit=1)
        self.assertTrue(t.apply(TARGET_METHOD, _confirmed(booking_ref="A"))[1])
        self.assertFalse(t.apply(TARGET_METHOD, _confirmed(booking_ref="B"))[1])
        self.assertEqual(t.count, 1)


class RelayTests(unittest.TestCase):
    """End to end over real sockets, against a server that answers one canned line."""

    def _upstream(self, reply: dict) -> tuple[str, int]:
        """Start a server that records each request and answers `reply` in canonical JSON."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        host, port = srv.getsockname()

        def run():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                with conn:
                    self.seen.append(conn.recv(65536))
                    conn.sendall(json.dumps(reply, sort_keys=True, separators=(",", ":")).encode() + b"\n")

        self.seen = []
        threading.Thread(target=run, daemon=True).start()
        self.addCleanup(srv.close)
        return host, port

    def _round_trip_raw(self, listen, request: dict) -> bytes:
        """Send `request` through the proxy and return the reply line as bytes."""
        with socket.create_connection(listen, timeout=5) as sock:
            sock.sendall(json.dumps(request, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            return sock.makefile("rb").readline()

    def _round_trip(self, listen, request: dict) -> dict:
        """Send `request` through the proxy and return the parsed reply."""
        return json.loads(self._round_trip_raw(listen, request))

    def test_the_request_reaches_the_gateway_unchanged_and_the_reply_is_rewritten(self):
        up = self._upstream(_confirmed(booking_ref="REAL-1"))
        tamper = Tamper("booking_ref", "FORGED-1")
        server = serve(("127.0.0.1", 0), up, tamper)
        self.addCleanup(server.shutdown)
        request = {"v": "wire-1", "method": TARGET_METHOD, "params": {"token": {"signature": "s"}}}
        reply = self._round_trip(server.server_address, request)
        self.assertEqual(json.loads(self.seen[0]), request, "the gateway sees the real request")
        self.assertEqual(reply["result"]["payload"]["booking_ref"], "FORGED-1")
        self.assertEqual(tamper.count, 1)

    def test_a_connection_that_sends_nothing_does_not_reach_the_gateway(self):
        """A connection that sends nothing must not open an upstream connection.

        `booking_v4.services._TcpServer` is a plain `socketserver.TCPServer`: the gateway serves
        one connection at a time and its handler blocks until the peer speaks or hangs up. The
        container's readiness probe opens a socket every second and says nothing. A proxy that
        dials upstream on accept would park a silent connection in the gateway once a second,
        every real request would queue behind it, and the runner would time out after its effect
        had already happened. Only the first request line opens the upstream connection.
        """
        up = self._upstream(_confirmed(booking_ref="REAL-1"))
        server = serve(("127.0.0.1", 0), up, Tamper("booking_ref", "FORGED-1"))
        self.addCleanup(server.shutdown)
        for _ in range(5):                                   # five "readiness probes"
            socket.create_connection(server.server_address, timeout=5).close()
        time.sleep(0.2)
        self.assertEqual(self.seen, [], "a silent connection reached the gateway")

        reply = self._round_trip(server.server_address,
                                 {"v": "wire-1", "method": TARGET_METHOD, "params": {}})
        self.assertEqual(len(self.seen), 1, "the first real request opens one upstream connection")
        self.assertEqual(reply["result"]["payload"]["booking_ref"], "FORGED-1")

    def test_an_untargeted_reply_comes_back_byte_identical(self):
        original = _confirmed(booking_ref="REAL-1")
        up = self._upstream(original)
        server = serve(("127.0.0.1", 0), up, Tamper("booking_ref", "FORGED-1"))
        self.addCleanup(server.shutdown)
        raw = self._round_trip_raw(server.server_address,
                                   {"v": "wire-1", "method": "gateway.dispatch_outcome", "params": {}})
        self.assertEqual(raw, json.dumps(original, sort_keys=True, separators=(",", ":")).encode() + b"\n")


class IsolationTests(unittest.TestCase):
    """The attacker must sit outside every measured artefact."""

    def test_the_runner_image_does_not_copy_the_attack_package(self):
        text = (MOCKS / "Dockerfile.k8s").read_text()
        self.assertNotIn("attack", text, "the attacker would be inside the measured guest")

    def test_the_services_image_does_copy_it(self):
        self.assertIn("COPY attack /app/attack", (MOCKS / "Dockerfile.services").read_text())

    def test_the_attack_package_is_outside_the_runner_source_hash(self):
        # Otherwise every change to the attacker forces a guest rebuild, and a timing
        # series could no longer come from one image.
        spec = importlib.util.spec_from_file_location(
            "_rsh", MOCKS / "scripts" / "gke" / "_runner_source_hash.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        covered = {p.relative_to(MOCKS).parts[0] for p in module._source_files(MOCKS)}
        self.assertNotIn("attack", covered)


if __name__ == "__main__":
    unittest.main()
