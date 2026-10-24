"""A runner's failure label must not override what the gateway ledger recorded.

Run:
    python3 -m booking_v3.tests_failure_ledger

With an effect ledger bound, a FAILED report ("certainly no effect") is accepted only when the
gateway has no row for the grant or its committed row is a failure. A pending row or an
unreachable ledger parks the run as UNCERTAIN, a committed confirmation parks it for
reconciliation. UNCERTAIN asserts nothing and is taken as given. Without a ledger the
runner's label is believed.
"""
from __future__ import annotations

import unittest

from booking_v1.effects import response_digest
from booking_v1.freeze import to_canonical
from booking_v1.lifecycle import PolicyState

from .authority import TransitionRecord
from .tests_negative import ADMISSION, RUN, _Fixture

PAYLOAD = {"order_id": "ord-1", "status": "confirmed"}


class _Ledger:
    """A stand-in for the gateway's ledger view: (state, response_hash) or an exception."""

    def __init__(self, state=None, digest=None, error: Exception | None = None):
        """Answer every lookup with (state, digest), or raise ``error``."""
        self.answer, self.error = (state, digest), error

    def effect(self, grant_id):
        """Return the configured answer for any grant."""
        if self.error is not None:
            raise self.error
        return self.answer


class ARunnerLabelNeverOverridesTheLedger(_Fixture):
    """FAILED, INTEGRITY_FAILED and UNCERTAIN reports are checked against the bound ledger."""

    def setUp(self):
        """Disable the ledger re-read delay."""
        super().setUp()
        self.auth._LEDGER_REREAD_SECONDS = 0

    def report(self, outcome: str, ledger=None, payload=PAYLOAD):
        """Grant step 0, then report `outcome` as a failure (no successor).

        Returns the run state and the Authority's note.
        """
        if ledger is not None:
            self.auth.bind_effect_ledger(ledger)
        credential, fragment, grant, why = self.grant()
        self.assertIsNotNone(grant, why)
        effect = to_canonical({"kind": "effect", "run_id": RUN, "step_index": 0,
                               "fragment_hash": fragment.fragment_hash, "outcome": outcome,
                               "payload": payload, "error": "x", "produced_facts": []})
        record = TransitionRecord(run_id=RUN, grant_id=grant.grant_id, outcome=outcome,
                                  admission_event=to_canonical(ADMISSION), effect_event=effect, proposed=None)
        signed, note = self.auth.finalize_transition(credential, record)
        self.assertIsNone(signed)
        return self.auth.status(RUN), note

    def test_without_a_ledger_the_label_is_believed(self):
        self.assertIs(self.report("FAILED")[0], PolicyState.EFFECT_FAILED)

    def test_failed_with_no_row_is_failed(self):
        self.assertIs(self.report("FAILED", _Ledger(None, None))[0], PolicyState.EFFECT_FAILED)

    def test_failed_with_a_committed_failure_is_failed(self):
        ledger = _Ledger("COMMITTED", response_digest("FAILED", PAYLOAD))
        self.assertIs(self.report("FAILED", ledger)[0], PolicyState.EFFECT_FAILED)

    def test_failed_over_a_committed_confirmation_parks_for_reconciliation(self):
        ledger = _Ledger("COMMITTED", response_digest("CONFIRMED", PAYLOAD))
        state, note = self.report("FAILED", ledger)
        self.assertIs(state, PolicyState.EFFECT_RECONCILE)
        self.assertIn("contradicts the gateway ledger", note)

    def test_failed_over_a_committed_row_with_another_payload_parks_for_reconciliation(self):
        ledger = _Ledger("COMMITTED", response_digest("CONFIRMED", {"order_id": "other"}))
        self.assertIs(self.report("FAILED", ledger)[0], PolicyState.EFFECT_RECONCILE)

    def test_failed_with_a_pending_row_is_uncertain_not_failed(self):
        self.assertIs(self.report("FAILED", _Ledger("PENDING", None))[0], PolicyState.EFFECT_UNCERTAIN)

    def test_failed_with_an_unreachable_ledger_is_uncertain_not_failed(self):
        ledger = _Ledger(error=ConnectionRefusedError("down"))
        self.assertIs(self.report("FAILED", ledger)[0], PolicyState.EFFECT_UNCERTAIN)

    def test_integrity_failed_over_a_committed_confirmation_is_uncertain(self):
        ledger = _Ledger("COMMITTED", response_digest("CONFIRMED", PAYLOAD))
        self.assertIs(self.report("INTEGRITY_FAILED", ledger)[0], PolicyState.EFFECT_UNCERTAIN)

    def test_integrity_failed_without_a_committed_confirmation_parks_for_reconciliation(self):
        self.assertIs(self.report("INTEGRITY_FAILED", _Ledger(None, None))[0], PolicyState.EFFECT_RECONCILE)

    def test_uncertain_is_taken_as_given_whatever_the_ledger_says(self):
        for ledger in (_Ledger(None, None), _Ledger("COMMITTED", response_digest("CONFIRMED", PAYLOAD)),
                       _Ledger(error=OSError("down"))):
            self.setUp()
            self.assertIs(self.report("UNCERTAIN", ledger, payload=None)[0], PolicyState.EFFECT_UNCERTAIN)


if __name__ == "__main__":
    unittest.main()
