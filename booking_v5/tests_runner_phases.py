"""The runner's ordering invariant, tested with a fake Attestation Agent.

No fragment effect is executable before successful evidence appraisal and session opening. The
phases boot, bind and attest, open and execute each run once and in that order. A phase shortcut
is a RunnerError, bytes other than the attested ones are a BytesMismatch, and neither leaves an
effect.

Run:  python3 -m booking_v5.tests_runner_phases
"""
from __future__ import annotations

import hashlib
import unittest

from .binding import BytesMismatch, bind_event, seal_to
from .evidence import FakeAttestationAgent
from .rtmr_replay import boot_key_content
from .runner_bind import Challenge, RunnerError, V5Runner


class _FakeAA:
    """A stand-in with the two methods of runner_bind.AttestationAgent. It records the AAEL events."""

    def __init__(self):
        self.events = []
        self._aa = FakeAttestationAgent()

    def extend(self, operation: str, content: str) -> None:
        self.events.append((operation, content))

    def evidence(self, runtime_data_32: bytes):
        return self._aa.get_evidence(runtime_data_32)


def _challenge(fragment=b"frag", envelope=b"env"):
    """Return a challenge for run-1, step 1, over the digests of the given octets."""
    return Challenge("run-1", 1, hashlib.sha256(fragment).hexdigest(),
                     hashlib.sha256(envelope).hexdigest(), b"\x11" * 32)


class Ordering(unittest.TestCase):
    """Each phase runs once and in order. Every shortcut is refused and leaves no effect."""

    def setUp(self):
        self.aa = _FakeAA()
        self.runner = V5Runner.boot(self.aa, hashes=None)   # plain-digest model: octets are not V3 objects
        self.effects = []

    def _sealed(self, ch: Challenge, cred=b"credential"):
        """Seal `cred` to this runner's boot key for the binding of `ch`."""
        return seal_to(self.runner.pk_boot, cred, aad=bind_event(ch.run_id, ch.step, ch.fragment_hash, ch.state_hash))

    def _run(self, f, e, c):
        """Stand in for the monitor and record the fragment as an effect."""
        self.effects.append(f)
        return "ok"

    def test_boot_measures_both_public_keys_first(self):
        """Event 1 covers the sealing key and the verdict key.

        A TD that announced a signing key it had not measured would produce another RTMR3 and be
        refused.
        """
        self.assertEqual(self.aa.events[0],
                         ("boot-key", boot_key_content(self.runner.pk_boot.hex(),
                                                       self.runner.pk_sig.hex())))

    def test_happy_path_in_order(self):
        ch = _challenge()
        self.runner.attest(ch)
        self.assertEqual(self.aa.events[1][0], "bind")
        self.runner.open_session(self._sealed(ch))
        self.assertEqual(self.runner.execute(b"frag", b"env", self._run), "ok")
        self.assertEqual(self.effects, [b"frag"])

    def test_execute_before_open_is_refused(self):
        self.runner.attest(_challenge())
        with self.assertRaises(RunnerError):
            self.runner.execute(b"frag", b"env", self._run)
        self.assertEqual(self.effects, [])

    def test_open_before_attest_is_refused(self):
        with self.assertRaises(RunnerError):
            self.runner.open_session(self._sealed(_challenge()))

    def test_execute_before_attest_is_refused(self):
        with self.assertRaises(RunnerError):
            self.runner.execute(b"frag", b"env", self._run)
        self.assertEqual(self.effects, [])

    def test_attest_twice_is_refused(self):
        self.runner.attest(_challenge())
        with self.assertRaises(RunnerError):
            self.runner.attest(_challenge(b"other"))
        self.assertEqual([e[0] for e in self.aa.events], ["boot-key", "bind"])

    def test_execute_twice_is_refused(self):
        ch = _challenge()
        self.runner.attest(ch)
        self.runner.open_session(self._sealed(ch))
        self.runner.execute(b"frag", b"env", self._run)
        with self.assertRaises(RunnerError):
            self.runner.execute(b"frag", b"env", self._run)
        self.assertEqual(len(self.effects), 1)

    def test_credential_sealed_for_another_binding_does_not_open(self):
        ch = _challenge()
        self.runner.attest(ch)
        other = _challenge(b"other-fragment")
        with self.assertRaises(RunnerError):
            self.runner.open_session(self._sealed(other))   # the AAD is another bind event
        with self.assertRaises(RunnerError):                 # phase already consumed: no retry into execute
            self.runner.execute(b"frag", b"env", self._run)

    def test_wrong_bytes_are_not_executed(self):
        ch = _challenge()
        self.runner.attest(ch)
        self.runner.open_session(self._sealed(ch))
        with self.assertRaises(BytesMismatch):
            self.runner.execute(b"tampered", b"env", self._run)
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main(verbosity=1)
