"""The V5 attach protocol, end to end over a pipe: runner and transport against each other.

`runner_main.serve` runs in a thread on one end, and `AttachTransport` drives the other through
`os.pipe()` file objects. Everything the live path does is exercised except the websocket itself:
the same seven lines, the same octets, the same phase order and the same failure modes.

What each test pins down:

    happy path        the seven lines in order, the credential opens only in this TD, and the
                      result comes back as one line
    swapped bytes     a controller that swaps the fragment after attestation gets no effect
    binding           the evidence is over the canonical binding of the challenge it was sent
    ordering          the runner refuses a second challenge (one TD, one fragment)
    hashes            fragment_hash and state_hash are a function of the octets alone, so the
                      side that attests and the side that verifies compute the same values

Run:  python3 -m booking_v5.tests_v5_protocol
"""
from __future__ import annotations

import os
import threading
import unittest

from booking_v1 import freeze
from booking_v3.authority import RunnerCredential
from booking_v3.fragment import ActionFragment
from booking_v3.runner import RunnerResult
from booking_v3 import scenarios as v3_scenarios
from booking_v4 import wire
from booking_v4.endpoint import ServiceEndpoint

from . import protocol, runner_main
from .attach_transport import AttachTransport, LineStream
from .binding import BytesMismatch, canonical_binding, seal_to, bind_event
from .evidence import BLOB_PART_CHARS, Evidence, FakeAttestationAgent
from .relying_party import AuthorityRelyingParty, FakeVerifier, ReferenceValues, SessionScope
from .runner_bind import Challenge, RunnerError
from .rtmr_replay import replay

RUN, STEP = "run-proto", 3


# The anchors the Authority seals with the credential. `setUp` sets them for each test, because
# `_credential_octets` is a plain function and reads them from here. The TD must read them out of
# the sealed box, not off the wire.
_ANCHORS = None


def _credential_octets(scope) -> bytes:
    """Return what the Authority mints and seals: the credential and the trust anchors.

    Both are bound to the scope the session was established for.
    """
    cred = RunnerCredential(session_id=f"sess-{scope.run_id}-{scope.step}", run_id=scope.run_id,
                            fragment_hash=scope.fragment_hash, state_hash=scope.state_hash,
                            secret="s3cret")
    return wire.encode(wire.session_package_to_wire(cred, _ANCHORS)).encode()


class _FakeAA:
    """A stand-in with the Attestation Agent's shape (`extend`, `evidence`).

    It records the AAEL lines it was given and produces evidence whose RTMR3 is the replay of
    those lines.
    """

    def __init__(self, init_data_digest: str):
        self.lines: list[str] = []
        self._init = init_data_digest

    def extend(self, operation: str, content: str) -> None:
        self.lines.append(f"v5 {operation} {content}")

    def evidence(self, runtime_data_32: bytes) -> Evidence:
        rtmr3 = replay([f"v5 init-data {self._init}"] + self.lines)
        return FakeAttestationAgent(rtmr3=rtmr3).get_evidence(runtime_data_32)


class _PipeStream(LineStream):
    """The controller's end of two os.pipe() pairs."""

    def __init__(self, tx, rx):
        self._tx, self._rx = tx, rx

    def write_line(self, line: str) -> None:
        self._tx.write(line + "\n")
        self._tx.flush()

    def read_line(self) -> str:
        line = self._rx.readline()
        if not line:
            raise EOFError("runner closed its stream")
        return line

    def close(self) -> None:
        for f in (self._tx, self._rx):
            try:
                f.close()
            except Exception:
                pass


def _domain_objects():
    """Return a policy, an envelope and a fragment from the frozen V3 scenario helpers."""
    ctx = v3_scenarios.make_context()
    fragment = ActionFragment(run_id=ctx.run_id, fragment_index=0,
                              policy_digest=ctx.policy.digest(), operation="search_flights",
                              arguments={"from": "BER", "to": "LIS"},
                              declared_facts=(), declared_capability="search")
    return ctx.policy, ctx.s0, fragment, ctx.anchors, ctx.provisioner


class ProtocolEndToEnd(unittest.TestCase):
    """Runner and transport over pipes: seven lines, bound bytes and phase order."""

    def setUp(self):
        global _ANCHORS
        self.policy, self.envelope, self.fragment, self.anchors, _ = _domain_objects()
        _ANCHORS = self.anchors            # what `_credential_octets` seals for this test
        self.frag_octets = protocol.fragment_bytes(self.fragment)
        self.env_octets = protocol.envelope_bytes(self.envelope)
        self.frag_hash, self.state_hash = protocol.attested_hashes(self.fragment, self.envelope)
        self.ref = ReferenceValues(require_rtmr3=True)
        self.aa = _FakeAA(self.ref.init_data_digest)
        self.executed: list = []
        self.threads: list = []
        self._open_files: list = []
        self._controller_tx: list = []

    def tearDown(self):
        # Order matters: close the controller's write end first. A test that stops after `attest`
        # leaves the runner thread blocked in readline, and closing the file it is reading from
        # would block with it. An EOF on its stdin ends it immediately.
        for f in self._controller_tx:
            try:
                f.close()
            except Exception:
                pass
        for t in self.threads:
            t.join(timeout=5)
        for f in self._open_files:  # pipes are FDs, and leaking them fails the suite
            try:
                f.close()
            except Exception:
                pass

    # Harness.

    def _start_runner(self, execute=None):
        """Start `runner_main.serve` in a thread and return the controller's end of the pipes."""
        c2r_r, c2r_w = os.pipe()
        r2c_r, r2c_w = os.pipe()
        rx = os.fdopen(c2r_r, "r")
        tx = os.fdopen(r2c_w, "w")
        ctl_tx, ctl_rx = os.fdopen(c2r_w, "w"), os.fdopen(r2c_r, "r")
        ctl = _PipeStream(ctl_tx, ctl_rx)
        self._open_files += [rx, tx, ctl_rx]
        self._controller_tx.append(ctl_tx)
        self.error: BaseException | None = None

        def _run():
            try:
                runner_main.serve(rx, tx, aa=self.aa, execute=execute or self._execute)
            except BaseException as exc:  # noqa: BLE001 (reported to the test)
                self.error = exc
            finally:
                try:
                    tx.close()
                except Exception:
                    pass

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self.threads.append(t)
        return ctl

    def _execute(self, policy, envelope, fragment, intervention, anchors, endpoint, credential,
                 gateway_endpoint=None, signer=None):
        """Stand in for the frozen V3 monitor and record what it was handed.

        The record includes the verdict key the TD hands its monitor.
        """
        self.executed.append((fragment.fragment_hash, credential, signer))
        return RunnerResult(status="STEP_COMPLETED", envelope=None,
                            reason="ok", payload={"flights": []}, runner_no=1)

    def _transport(self, ctl, **kw):
        """Return an `AttachTransport` whose stream is `ctl`."""
        return AttachTransport(open_stream=lambda td: ctl, anchors=self.anchors,
                               endpoint=ServiceEndpoint("uds", "/run/authority.sock"),
                               policy=self.policy, **kw)

    # Tests.

    def test_the_seven_lines_run_through_and_the_effect_happens_once(self):
        ctl = self._start_runner()
        rp = AuthorityRelyingParty(FakeVerifier(), self.ref)
        transport = self._transport(ctl)

        keys = transport.boot_keys("td-1")
        nonce = rp.issue_nonce(RUN, STEP, self.frag_hash, self.state_hash, keys.pk_boot)
        evidence = transport.attest("td-1", Challenge(RUN, STEP, self.frag_hash, self.state_hash, nonce))

        # The Authority's own decision, on the evidence the TD produced.
        session = rp.establish_session(evidence, keys.pk_boot, keys.pk_sig, RUN, STEP,
                                       self.frag_hash, self.state_hash,
                                       nonce, _credential_octets,
                                       self.ref.substrate_profile_hash)
        self.assertFalse(hasattr(session, "rule"), getattr(session, "detail", ""))

        result = transport.deliver("td-1", session.sealed, self.frag_octets, self.env_octets)
        self.assertEqual(result.status, "STEP_COMPLETED")
        self.assertEqual(len(self.executed), 1)
        self.assertEqual(self.executed[0][0], self.fragment.fragment_hash)
        # The monitor inside the TD is handed the TD's own verdict key, and it is the key the
        # Authority bound in the quote it just appraised.
        self.assertEqual(self.executed[0][2].verify_key().to_bytes(), keys.pk_sig)
        self.assertIsNone(self.error)

    def test_a_swapped_fragment_is_refused_inside_the_td(self):
        """The controller attests fragment A and then delivers fragment B."""
        other = ActionFragment(run_id=self.fragment.run_id, fragment_index=0,
                               policy_digest=self.fragment.policy_digest, operation="pay",
                               arguments={"amount": 999999}, declared_facts=(),
                               declared_capability="pay")
        ctl = self._start_runner()
        rp = AuthorityRelyingParty(FakeVerifier(), self.ref)
        transport = self._transport(ctl)
        keys = transport.boot_keys("td-1")
        nonce = rp.issue_nonce(RUN, STEP, self.frag_hash, self.state_hash, keys.pk_boot)
        evidence = transport.attest("td-1", Challenge(RUN, STEP, self.frag_hash, self.state_hash, nonce))
        session = rp.establish_session(evidence, keys.pk_boot, keys.pk_sig, RUN, STEP,
                                       self.frag_hash, self.state_hash,
                                       nonce, _credential_octets,
                                       self.ref.substrate_profile_hash)
        with self.assertRaises(EOFError):
            transport.deliver("td-1", session.sealed, protocol.fragment_bytes(other), self.env_octets)
        self.assertEqual(self.executed, [], "no effect may happen for unattested bytes")
        self.assertIsInstance(self.error, BytesMismatch)

    def test_the_evidence_is_over_the_canonical_binding_of_this_challenge(self):
        ctl = self._start_runner()
        transport = self._transport(ctl)
        keys = transport.boot_keys("td-1")
        nonce = b"\x11" * 32
        evidence = transport.attest("td-1", Challenge(RUN, STEP, self.frag_hash, self.state_hash, nonce))
        self.assertEqual(evidence.runtime_data,
                         canonical_binding(nonce, RUN, STEP, self.frag_hash, self.state_hash,
                                           keys.pk_boot, keys.pk_sig))
        self.assertEqual(len(evidence.runtime_data.hex()), 64, "REPORTDATA holds 64 ASCII bytes")

    def test_a_second_challenge_is_refused(self):
        """One TD, one fragment: the phase guard, over the wire."""
        ctl = self._start_runner()
        transport = self._transport(ctl)
        transport.boot_keys("td-1")
        transport.attest("td-1", Challenge(RUN, STEP, self.frag_hash, self.state_hash, b"\1" * 32))
        with self.assertRaises(EOFError):
            transport.attest("td-1", Challenge(RUN, STEP + 1, self.frag_hash, self.state_hash, b"\2" * 32))
        self.assertIsInstance(self.error, (RunnerError, wire.WireError))

    def test_a_credential_sealed_for_another_binding_does_not_open(self):
        ctl = self._start_runner()
        transport = self._transport(ctl)
        keys = transport.boot_keys("td-1")
        transport.attest("td-1", Challenge(RUN, STEP, self.frag_hash, self.state_hash, b"\3" * 32))
        octets = _credential_octets(SessionScope(RUN, STEP, self.frag_hash, self.state_hash,
                                                 keys.pk_boot, keys.pk_sig))
        wrong = seal_to(keys.pk_boot, octets, aad=bind_event(RUN, STEP + 9, self.frag_hash, self.state_hash))
        with self.assertRaises(EOFError):
            transport.deliver("td-1", wrong, self.frag_octets, self.env_octets)
        self.assertEqual(self.executed, [])
        self.assertIsInstance(self.error, RunnerError)


class AttestedHashTests(unittest.TestCase):
    """The two sides derive the same hashes from the same objects.

    If they derived different hashes, a swapped fragment would pass the check inside the TD.
    """

    def test_hashes_are_v3_identifiers_derived_from_canonical_octets(self):
        """One identifier per object across V3, V4 and V5.

        The attested hashes are the V3 fragment_hash and state_hash. The TD derives them from the
        octets it was handed, after checking that those octets are canonical (decoding and
        re-encoding gives the same octets).
        """
        policy, envelope, fragment, _, _ = _domain_objects()
        octets = protocol.fragment_bytes(fragment)
        env_octets = protocol.envelope_bytes(envelope)
        self.assertEqual(protocol.attested_hashes(fragment, envelope), (fragment.fragment_hash, envelope.state_hash))
        self.assertEqual(protocol.hashes_of_octets(octets, env_octets), (fragment.fragment_hash, envelope.state_hash))
        self.assertEqual(protocol.fragment_bytes(protocol.parse_fragment_octets(octets)), octets)
        # Non-canonical octets (same content, extra whitespace) are refused before any hash.
        padded = octets.replace(b",", b", ", 1)
        with self.assertRaises(protocol.ProtocolError):
            protocol.hashes_of_octets(padded, env_octets)

    def test_a_changed_argument_changes_the_hash(self):
        policy, envelope, fragment, _, _ = _domain_objects()
        other = ActionFragment(run_id=fragment.run_id, fragment_index=0,
                               policy_digest=fragment.policy_digest, operation="search_flights",
                               arguments={"from": "BER", "to": "MAD"}, declared_facts=(),
                               declared_capability="search")
        self.assertNotEqual(protocol.attested_hashes(fragment, envelope)[0],
                            protocol.attested_hashes(other, envelope)[0])


class EvidenceLineTests(unittest.TestCase):
    """A TDX blob of real size (about 46 KB) crosses the wire within V1's string bound."""

    def test_a_real_sized_blob_round_trips_in_parts_below_max_str(self):
        blob = os.urandom(46_253)
        line = protocol.evidence(Evidence("tdx", blob, b"\x11" * 32))
        parts = wire.decode_line(line)["blob_parts"]
        self.assertGreater(len(parts), 1)
        self.assertTrue(all(len(x) <= BLOB_PART_CHARS < freeze.MAX_STR for x in parts))
        ev = protocol.parse_evidence(line)
        self.assertEqual((ev.platform, ev.blob, ev.runtime_data), ("tdx", blob, b"\x11" * 32))

    def test_the_authority_rpc_form_carries_the_same_parts(self):
        blob = os.urandom(46_253)
        ev = Evidence("tdx", blob, b"\x11" * 32)
        d = ev.to_wire()
        self.assertTrue(all(len(x) < 10_000 for x in d["blob_parts"]))
        self.assertEqual(Evidence.from_wire(d).blob, blob)
        self.assertEqual(list(d["blob_parts"]), list(wire.decode_line(protocol.evidence(ev))["blob_parts"]))

    def test_a_single_string_blob_is_refused(self):
        line = wire.encode({"v": wire.WIRE_VERSION, "kind": protocol.KIND_EVIDENCE, "platform": "tdx",
                            "blob_parts": "QUJD", "runtime_data": "11" * 32})
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_evidence(line)


if __name__ == "__main__":
    unittest.main(verbosity=2)
