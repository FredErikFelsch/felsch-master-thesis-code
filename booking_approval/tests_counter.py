"""The signature counter of a counting authenticator must strictly increase.

Run:
    python3 -m booking_approval.tests_counter

Defined counter policy: a stored and reported counter of 0 means the authenticator keeps none
(synced passkeys, harness keys) and is accepted. Otherwise a counter that is not above the
stored one is refused as a possible clone. The refused assertion is otherwise valid (right
challenge, origin, rp id, user verification, signature), so the refusal can only come from the
counter check.
"""
from __future__ import annotations

import unittest

from .gate import DecisionRefused
from .tests_gate import GateFixture


class TheSignatureCounterOnlyMovesForward(GateFixture):
    """A repeated or lower counter is refused, a higher or absent one is accepted."""

    def test_a_lower_counter_after_a_higher_one_is_refused(self):
        self.person.sign_count = 4
        self.assertEqual(self.decide(self.propose("run-1"))["state"], "approved")     # counter 5
        self.person.sign_count = 0                                                     # next assertion: 1
        with self.assertRaises(DecisionRefused) as caught:
            self.decide(self.propose("run-2"))
        self.assertIn("counter did not advance", caught.exception.reason)

    def test_the_same_counter_again_is_refused(self):
        self.assertEqual(self.decide(self.propose("run-1"))["state"], "approved")     # counter 1
        self.person.sign_count = 0                                                     # next assertion: 1 again
        with self.assertRaises(DecisionRefused) as caught:
            self.decide(self.propose("run-2"))
        self.assertIn("counter did not advance", caught.exception.reason)

    def test_control_a_higher_counter_is_accepted(self):
        self.assertEqual(self.decide(self.propose("run-1"))["state"], "approved")     # counter 1
        self.assertEqual(self.decide(self.propose("run-2"))["state"], "approved")     # counter 2

    def test_control_a_null_counter_is_accepted_every_time(self):
        for run in ("run-1", "run-2", "run-3"):
            out = self.decide(self.propose(run), who=self.harness)
            self.assertEqual(out["state"], "approved", out)


if __name__ == "__main__":
    unittest.main()
