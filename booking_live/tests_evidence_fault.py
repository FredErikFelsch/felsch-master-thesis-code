"""The uncertain-outcome evidence names its fault explicitly.

The record that `scripts/gke-v5/39_live_evidence.py uncertain` writes carries a `fault`
block derived from the artefacts: fault_injection, fault_type, provider_dispatch,
gateway_response_to_controller and result. It is checked on synthetic counter-cases and,
when the recorded live run is present (with the gateway log and the Duffel state captured
at the time), on that run. The block should neither be missing on the real run nor claim
an injection that did not happen.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import unittest

from .faults import FAULT_TYPES, FAULTS, LOSE_PAYMENT_RESPONSE

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIVE = ROOT / "results_v5" / "live" / "20260924T154447Z"
RUN = ROOT / "results_v5" / "demo" / "20260924T160807Z-v5-clean-scripted-duffel"


def _evidence_module():
    spec = importlib.util.spec_from_file_location("ev39", ROOT / "scripts" / "gke-v5" / "39_live_evidence.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TheFaultVocabulary(unittest.TestCase):
    """Every fault knob maps to a named fault type."""

    def test_every_knob_has_a_type(self):
        self.assertEqual(set(FAULT_TYPES), set(FAULTS))
        self.assertEqual(FAULT_TYPES[LOSE_PAYMENT_RESPONSE], "drop_provider_response_after_dispatch")


@unittest.skipUnless(RUN.is_dir() and LIVE.is_dir(), "recorded live run of 2026-09-24 not present")
class OnTheRecordedLiveRun(unittest.TestCase):
    """The evidence block derived from the recorded live run is the explicit fault block."""

    def test_the_recorded_step_8_yields_the_explicit_fault_block(self):
        ev = _evidence_module()
        events = ev._events(RUN)
        first = [p for p in ev._decisions(events, "pay_order") if p["status"] != "REQUIRE_APPROVAL"][0]
        recorded = json.loads((LIVE / "8-uncertain-evidence-uncertain.json").read_text())
        order = recorded["provider"]["id"]
        lines = [l for l in (LIVE / "8-gateway-ground-truth.txt").read_text().splitlines()
                 if f"FAULT {LOSE_PAYMENT_RESPONSE}" in l and f"order_id={order}" in l]
        fault = ev._fault_record(events, first, recorded["gateway_env"], recorded["provider"], lines)
        self.assertEqual({k: fault[k] for k in ("fault_injection", "fault_type", "provider_dispatch",
                                                "gateway_response_to_controller", "result")},
                         {"fault_injection": True,
                          "fault_type": "drop_provider_response_after_dispatch",
                          "provider_dispatch": "observed",
                          "gateway_response_to_controller": "suppressed",
                          "result": "UNCERTAIN"})


class TheBlockCannotOverclaim(unittest.TestCase):
    """The block claims an injection, a dispatch or a suppression only when the artefacts show it."""

    PAY = {"kind": "decision", "tool": "pay_order", "status": "EFFECT_UNCERTAIN",
           "reason": "pay_order outcome not established: response lost (injected fault lose-payment-response)"}
    PAID = {"id": "ord_x", "paid_at": "2026-09-24T16:13:11Z"}
    LINE = ["[gateway] FAULT lose-payment-response: pay_order ... order_id=ord_x ..."]

    def setUp(self):
        self.ev = _evidence_module()

    def test_no_knob_is_no_injection(self):
        f = self.ev._fault_record([self.PAY], self.PAY, {}, self.PAID, self.LINE)
        self.assertFalse(f["fault_injection"])
        self.assertEqual(f["gateway_response_to_controller"], "delivered")

    def test_no_gateway_line_is_no_observed_dispatch(self):
        f = self.ev._fault_record([self.PAY], self.PAY, {"WORLD_FAULT": LOSE_PAYMENT_RESPONSE}, self.PAID, [])
        self.assertEqual(f["provider_dispatch"], "not observed")

    def test_an_error_result_is_still_suppressed(self):
        seen = [self.PAY, {"kind": "tool_result", "tool": "pay_order",
                           "result": {"error": "EFFECT_UNCERTAIN", "reason": self.PAY["reason"]}}]
        f = self.ev._fault_record(seen, self.PAY, {"WORLD_FAULT": LOSE_PAYMENT_RESPONSE}, self.PAID, self.LINE)
        self.assertEqual(f["gateway_response_to_controller"], "suppressed")

    def test_a_leaked_payment_id_is_not_suppressed(self):
        line = ["[gateway] FAULT lose-payment-response: pay_order order_id=ord_x payment_id=pay_x; withheld"]
        seen = [self.PAY, {"kind": "note", "text": "pay_x"}]
        f = self.ev._fault_record(seen, self.PAY, {"WORLD_FAULT": LOSE_PAYMENT_RESPONSE}, self.PAID, line)
        self.assertEqual(f["gateway_response_to_controller"], "delivered")

    def test_a_payload_the_controller_saw_is_not_suppressed(self):
        seen = [self.PAY, {"kind": "tool_result", "tool": "pay_order", "result": {"payment_id": "p"}}]
        f = self.ev._fault_record(seen, self.PAY, {"WORLD_FAULT": LOSE_PAYMENT_RESPONSE}, self.PAID, self.LINE)
        self.assertEqual(f["gateway_response_to_controller"], "delivered")


if __name__ == "__main__":
    unittest.main()
