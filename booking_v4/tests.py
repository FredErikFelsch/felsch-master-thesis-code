"""Unit tests for the process backend: wire contract and fresh-process runner.

Run from the repository root:  python3 -m booking_v4.tests
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.freeze import thaw
from booking_v1.lifecycle import PolicyState

from booking_v3.envelope import chain_extend, genesis_audit_head, verify_envelope
from booking_v3.fragment import honest_fragment
from booking_v3.orchestrator import Orchestrator, happy_path_arguments
from booking_v3.policy import Policy3, default_p3, p3_with_pay_approval
from booking_v3.runner import RunnerResult

from . import wire
from .process_backend import (
    ProcessRunnerHandle, _parse_child_output, _runner_environment,
    create_process_deployment,
)
from .services import _call

T0 = 1_700_000_010
ISSUED, EXPIRES = 1_700_000_000, 1_700_003_600


def _deployment(policy=None, run_id="run-1"):
    """Return (policy, deployment, s0) for a process deployment with one activated run."""
    policy = policy or default_p3()
    dep = create_process_deployment(FixedClock(T0))
    approval = approve(policy, approver_id="alice", approval_id=f"A-{run_id}",
                       run_id=run_id, issued_at=ISSUED, expires_at=EXPIRES)
    s0 = dep.authority.create_run(policy, approval, run_id)
    return policy, dep, s0


class TestWireContract(unittest.TestCase):
    """The wire schemas are strict, versioned and canonical, and reject what they do not know."""

    def setUp(self):
        self.p = default_p3()
        self.fragment = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})

    def _roundtrip(self, message):
        """Encode and decode one message."""
        return wire.decode_line(wire.encode(message))

    def test_fragment_and_policy_round_trip(self):
        f2 = wire.fragment_from_wire(self._roundtrip(wire.fragment_to_wire(self.fragment)))
        self.assertEqual(f2.fragment_hash, self.fragment.fragment_hash)
        for policy in (self.p, p3_with_pay_approval()):
            p2 = wire.policy_from_wire(self._roundtrip(wire.policy_to_wire(policy)))
            self.assertEqual(p2.digest(), policy.digest())

    def test_envelope_round_trip_preserves_verification(self):
        _p, dep, s0 = _deployment()
        e2 = wire.envelope_from_wire(self._roundtrip(wire.envelope_to_wire(s0)))
        self.assertEqual(e2.state_hash, s0.state_hash)
        self.assertTrue(verify_envelope(e2, dep.anchors.envelope_key)[0])

    def test_unknown_field_rejected(self):
        message = wire.fragment_to_wire(self.fragment)
        message["extra"] = "field"
        with self.assertRaises(wire.WireError):
            wire.fragment_from_wire(self._roundtrip(message))

    def test_wrong_version_rejected(self):
        message = wire.fragment_to_wire(self.fragment)
        message["v"] = "wire-0"
        with self.assertRaises(wire.WireError):
            wire.decode_line(wire.encode(message))

    def test_tampered_fragment_hash_rejected(self):
        message = wire.fragment_to_wire(self.fragment)
        message["arguments"] = {"to": "MUC"}
        with self.assertRaises(wire.WireError):
            wire.fragment_from_wire(self._roundtrip(message))

    def test_tampered_envelope_body_rejected(self):
        _p, dep, s0 = _deployment()
        message = wire.envelope_to_wire(s0)
        message["step_index"] = 3  # claimed state_hash no longer matches
        with self.assertRaises(Exception):
            wire.envelope_from_wire(self._roundtrip(message))


class TestProcessBackendMilestone(unittest.TestCase):
    """The booking_v3 protocol across four independent OS-process lifetimes."""

    def test_happy_path_four_distinct_process_lifetimes(self):
        p, dep, s0 = _deployment()
        report = Orchestrator(dep.provisioner).run(p, s0, happy_path_arguments())
        self.assertEqual(report.statuses, ["STEP_COMPLETED"] * 4)
        pids = dep.provisioner.spawned_pids
        self.assertEqual(len(pids), 4)
        self.assertEqual(len(set(pids)), 4)  # four independent processes
        # One lifetime per fragment, not only four PIDs: every runner had exited
        # before the next one was spawned, and all have exited by the end.
        for entry in dep.provisioner.lifecycle:
            self.assertTrue(entry["spawned_after_all_prior_exited"], entry)
        self.assertTrue(all(h.exited for h in dep.provisioner._handles))
        self.assertEqual(report.final_envelope.step_index, 4)
        self.assertIs(dep.authority.status("run-1"), PolicyState.COMPLETED)
        dep.server.close()

    def test_provenance_survives_the_process_boundary(self):
        p, dep, s0 = _deployment()
        envelope, fragments = s0, []
        for step, args in enumerate(happy_path_arguments()):
            fragment = honest_fragment(p, "run-1", step, args)
            fragments.append(fragment)
            result = dep.provisioner.spawn(fragment, envelope).execute(p, envelope, fragment)
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
            envelope = result.envelope
        events, archive_head = dep.authority.audit("run-1")
        head = genesis_audit_head("run-1", p.digest(), "A-run-1")
        head_after_step = {}
        for i in range(0, len(events), 2):
            head = chain_extend(head, [events[i], events[i + 1]])
            head_after_step[events[i]["step_index"]] = head
        self.assertEqual(head, archive_head)
        self.assertEqual(envelope.audit_head, archive_head)
        for name, rec in thaw(envelope.facts).items():
            seq = rec["producing_seq"]
            step = (seq - 1) // 2
            self.assertEqual(events[seq]["kind"], "effect", name)
            self.assertIn(name, events[seq]["produced_facts"])
            self.assertEqual(rec["fragment_id"], fragments[step].fragment_hash[:16], name)
            self.assertEqual(rec["integrity"], head_after_step[step], name)
        dep.server.close()

    def test_full_frozen_evaluation_on_process_backend(self):
        """Every scenario, the differential conformance check (P8) and dispatch safety (P9)
        of `booking_v3.experiment`, one runner process each.

        The two transport scenarios are expected not to match here, and that is the
        measured result: this backend binds no effect ledger, so a rewritten response is
        accepted and the run completes. Their prediction is written for the configuration
        that checks.
        """
        from booking_v3.scenarios import OBSERVATION_CHECK_SCENARIOS
        from .experiment import run_all
        results, diffs = run_all()
        failed = [r.name for r in results if not r.matches_prediction]
        self.assertEqual(failed, list(OBSERVATION_CHECK_SCENARIOS), failed)
        excess = [r.name for r in results if not r.effects_exact]
        self.assertEqual(excess, [], excess)
        broken = [d.trace for d in diffs if not d.ok]
        self.assertEqual(broken, [], broken)


class TestAdversarialBoundary(unittest.TestCase):
    """The serialisation boundary rejects adversarial input."""

    def setUp(self):
        self.p = default_p3()
        self.fragment = honest_fragment(self.p, "run-1", 0, {"to": "FRA"})

    # --- wire-level ---
    def test_malformed_json_rejected(self):
        with self.assertRaises(wire.WireError):
            wire.decode_line("{not json")

    def test_duplicate_json_key_rejected(self):
        with self.assertRaises(wire.WireError):
            wire.decode_line('{"v":"wire-1","kind":"x","run_id":"A","run_id":"B"}')

    def test_oversized_message_rejected(self):
        with self.assertRaises(wire.WireError):
            wire.decode_line('"' + "x" * (wire.MAX_WIRE_BYTES + 1) + '"')

    def test_missing_field_rejected(self):
        message = wire.fragment_to_wire(self.fragment)
        del message["operation"]
        with self.assertRaises(wire.WireError):
            wire.fragment_from_wire(wire.decode_line(wire.encode(message)))

    def test_unknown_nested_policy_field_rejected(self):
        message = wire.policy_to_wire(self.p)
        message["base"] = dict(message["base"], evil="field")
        with self.assertRaises(wire.WireError):
            wire.policy_from_wire(wire.decode_line(wire.encode(message)))

    def test_unknown_nested_spec_field_rejected(self):
        message = wire.policy_to_wire(self.p)
        base = dict(message["base"])
        producers = {k: [dict(d) for d in v] for k, v in base["step_producers"].items()}
        producers["0"][0]["unexpected"] = "hello"
        base["step_producers"] = producers
        message["base"] = base
        with self.assertRaises(wire.WireError):
            wire.policy_from_wire(wire.decode_line(wire.encode(message)))

    def test_a_lying_policy_object_cannot_cross_the_wire(self):
        """The in-process check trusts `policy.digest()` (pinned as a limit in
        booking_v3.tests). On the wire a policy travels as canonical fields plus the
        claimed digest. `policy_from_wire` reconstructs a fresh Policy3 and re-derives
        the digest from the reconstruction, so a permissive body under the approved
        digest yields a WireError and not a Policy3."""
        from dataclasses import replace
        real = self.p
        permissive = Policy3(base=replace(real.base, allowed_flow=("pay",), max_executions={"pay": 1},
                                          step_local={}, step_producers={}, step_bindings={},
                                          step_postconditions={}))        # valid, but not the approved one
        message = wire.policy_to_wire(permissive)
        message["digest"] = real.digest()                        # the lie: the approved digest on a permissive body
        with self.assertRaises(wire.WireError) as ctx:
            wire.policy_from_wire(wire.decode_line(wire.encode(message)))
        self.assertIn("digest", str(ctx.exception))
        # A malformed body does not even reach the digest check: reconstruction fails first.
        broken = wire.policy_to_wire(real)
        broken["base"] = {**dict(broken["base"]), "allowed_flow": ["pay", "select", "book", "pay"]}
        with self.assertRaises(wire.WireError):
            wire.policy_from_wire(wire.decode_line(wire.encode(broken)))

    def test_tampered_policy_digest_rejected(self):
        message = wire.policy_to_wire(self.p)
        message["digest"] = "0" * 64
        with self.assertRaises(wire.WireError):
            wire.policy_from_wire(wire.decode_line(wire.encode(message)))

    def test_malformed_signature_fails_closed_downstream(self):
        _p, dep, s0 = _deployment()
        message = wire.envelope_to_wire(s0)
        message["signature"] = "zz-not-hex"
        envelope = wire.envelope_from_wire(wire.decode_line(wire.encode(message)))
        ok, _why = verify_envelope(envelope, dep.anchors.envelope_key)
        self.assertFalse(ok)
        dep.server.close()

    # --- RPC-level ---
    def test_rpc_extra_param_rejected(self):
        # The request carries every expected key, so only the extra key "evil" can fail it.
        _p, dep, s0 = _deployment()
        with self.assertRaises(wire.WireError) as ctx:
            _call(dep.provisioner._service_socket, "authority.report_denial", {
                "credential": {
                    "v": wire.WIRE_VERSION, "kind": "runner-credential",
                    "session_id": "x", "run_id": "run-1",
                    "fragment_hash": "f", "state_hash": "s", "secret": "n"},
                "run_id": "run-1",
                "admission_event": {"kind": "admission"},
                "attestation": None,
                "evil": "extra"})
        self.assertIn("key set mismatch", str(ctx.exception))
        dep.server.close()

    def test_rpc_unknown_method_rejected(self):
        _p, dep, s0 = _deployment()
        with self.assertRaises(wire.WireError):
            _call(dep.provisioner._service_socket, "authority.mint_capability", {})
        dep.server.close()

    # --- process-channel level ---
    def test_two_stdout_lines_rejected(self):
        _p, dep, s0 = _deployment()
        good = wire.encode(wire.result_to_wire(RunnerResult(
            status="DENIED", envelope=None, reason="x", payload=None, runner_no=1)))
        with self.assertRaises(RuntimeError):
            _parse_child_output("debug noise\n" + good + "\n", "", 0)
        dep.server.close()

    def test_nonzero_exit_rejected_despite_valid_line(self):
        good = wire.encode(wire.result_to_wire(RunnerResult(
            status="DENIED", envelope=None, reason="x", payload=None, runner_no=1)))
        with self.assertRaises(RuntimeError):
            _parse_child_output(good + "\n", "boom", 1)

    def test_timeout_kills_and_reaps(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        handle = ProcessRunnerHandle(process, process.pid, timeout=1)
        _p, dep, s0 = _deployment()
        fragment = honest_fragment(_p, "run-1", 0, {"to": "FRA"})
        with self.assertRaises(RuntimeError):
            handle.execute(_p, s0, fragment)
        self.assertIsNotNone(process.returncode)  # reaped, so no zombie
        dep.server.close()

    def test_handle_is_single_use(self):
        p, dep, s0 = _deployment()
        fragment = honest_fragment(p, "run-1", 0, {"to": "FRA"})
        handle = dep.provisioner.spawn(fragment, s0)
        first = handle.execute(p, s0, fragment)
        self.assertEqual(first.status, "STEP_COMPLETED")
        with self.assertRaises(RuntimeError):
            handle.execute(p, s0, fragment)
        dep.server.close()

    def test_fragment_other_than_provisioned_gets_no_grant(self):
        p, dep, s0 = _deployment()
        provisioned = honest_fragment(p, "run-1", 0, {"to": "FRA"})
        swapped = honest_fragment(p, "run-1", 0, {"to": "MUC"})
        handle = dep.provisioner.spawn(provisioned, s0)
        result = handle.execute(p, s0, swapped)
        self.assertEqual(result.status, "GRANT_REFUSED")
        self.assertIn("does not bind", result.reason)
        self.assertEqual(dep.gateway.executions, [])  # zero dispatches
        dep.server.close()

    def test_runner_environment_is_minimal(self):
        os.environ["V4_CANARY_SECRET"] = "leak-me"
        try:
            env = _runner_environment()
            self.assertEqual(set(env), {"PATH", "PYTHONUNBUFFERED"})
            self.assertNotIn("V4_CANARY_SECRET", env)
        finally:
            del os.environ["V4_CANARY_SECRET"]


if __name__ == "__main__":
    unittest.main(verbosity=2)
