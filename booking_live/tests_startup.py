"""The start-up check refuses a half-migrated system.

Run:
    python3 -m booking_live.tests_startup

Four things are configured separately and have to agree: the counterparty, the policy,
the closed tool vocabulary and the credential. Each can be changed alone, so each can be
forgotten alone. These tests pin every disagreement the check is meant to catch, and that
a correct configuration is accepted.

The demo profile and the cluster gateway read the same `WORLDS` table, so a shape the
gateway would refuse cannot be configured on the demo side without being noticed.
"""
from __future__ import annotations

import unittest

from booking_v1.schema import TOOL_SCHEMAS
from booking_v2.policy import default_p2_1
from booking_v3.policy import p3_with_pay_approval

from .policy import pl1, pl1_with_pay_approval, pla1
from .secrets import MappingSecrets
from .startup import (WORLDS, ConfigurationRefused, SELLING_TOOLS, verify_configuration, verify_world,
                      world_configuration)

HELD = MappingSecrets({"DUFFEL_TOKEN": "duffel_test_" + "t" * 20,
                       "SERPAPI_KEY": "k" * 20})
DUFFEL_TOOLS = ("read_inbox", "search", "select", "book", "pay_order")


class ACoherentConfigurationIsAccepted(unittest.TestCase):
    """Each world with its own policy passes the check."""

    def test_world_b_with_its_policy(self):
        cfg = verify_configuration("duffel", pl1_with_pay_approval(), HELD,
                                   offered_tools=DUFFEL_TOOLS)
        self.assertEqual(cfg.world, "duffel")
        self.assertEqual(cfg.flow, ("search", "select", "book", "pay_order"))
        self.assertTrue(callable(cfg.executor))

    def test_world_a_with_its_policy(self):
        cfg = verify_configuration("serpapi", pla1(), HELD)
        self.assertEqual(cfg.flow, ("search", "select"))

    def test_the_descriptor_names_the_counterparty(self):
        """A recorded run whose world is unstated cannot be reproduced."""
        cfg = verify_configuration("duffel", pl1_with_pay_approval(), HELD)
        self.assertEqual(cfg.descriptor["world"], "duffel")
        self.assertEqual(cfg.descriptor["policy_id"], "PL1")
        self.assertEqual(cfg.descriptor["flow"],
                         ["search", "select", "book", "pay_order"])

    def test_both_worlds_name_tools_the_vocabulary_knows(self):
        """The table itself must not drift out of the closed vocabulary."""
        for name, spec in WORLDS.items():
            for tool in spec.flow:
                self.assertIn(tool, TOOL_SCHEMAS, f"{name} names {tool!r}")


class EveryDisagreementIsRefused(unittest.TestCase):
    """Each way the parts can disagree is refused with a message that names it."""

    def _refused(self, *args, **kwargs) -> str:
        with self.assertRaises(ConfigurationRefused) as caught:
            verify_configuration(*args, **kwargs)
        return str(caught.exception)

    def test_an_unknown_world(self):
        self.assertIn("unknown world", self._refused("aws", pl1(), HELD))

    def test_the_policy_of_the_other_world(self):
        self.assertIn("flow", self._refused("duffel", pla1(), HELD))

    def test_the_mock_policy_on_a_live_world(self):
        """P2.1 still names `pay`, which world B does not serve."""
        self.assertIn("flow", self._refused("duffel", default_p2_1(), HELD))

    def test_the_frozen_p3_on_a_live_world(self):
        self.assertIn("flow", self._refused("duffel", p3_with_pay_approval(), HELD))

    def test_a_payment_step_in_a_world_that_sells_nothing(self):
        """World A has no payment endpoint, and the message says so instead of reporting a shape mismatch.

        "The flow does not match" would send someone to edit the table, which is the wrong fix.
        """
        message = self._refused("serpapi", pl1(), HELD)
        self.assertIn("sells nothing", message)
        self.assertIn("pay_order", message)

    def test_the_selling_rule_is_reachable_and_not_dead_code(self):
        """A flow that matches the table is still refused when it pays.

        The table is temporarily made to agree with the offending policy, so the shape
        check passes and only the selling rule can refuse it. Without this test the rule
        could be removed and every other test would stay green.
        """
        object.__setattr__(WORLDS["serpapi"], "flow", ("search", "select", "book", "pay_order"))
        try:
            message = self._refused("serpapi", pl1(), HELD)
        finally:
            object.__setattr__(WORLDS["serpapi"], "flow", ("search", "select"))
        self.assertIn("sells nothing", message)

    def test_a_missing_credential(self):
        message = self._refused("duffel", pl1(), MappingSecrets({}))
        self.assertIn("DUFFEL_TOKEN", message)

    def test_a_step_the_agent_is_never_offered(self):
        message = self._refused("duffel", pl1(), HELD,
                                offered_tools=("search", "select", "book"))
        self.assertIn("pay_order", message)

    def test_a_payment_tool_offered_outside_the_flow(self):
        """The old `pay` left in the agent's schema is the half-migrated case."""
        message = self._refused("duffel", pl1(), HELD,
                                offered_tools=DUFFEL_TOOLS + ("pay",))
        self.assertIn("['pay']", message)


class TheSellingToolsAreNamedOnce(unittest.TestCase):
    """The payment tools are derived once, from the effect maps."""

    def test_both_payment_tools_are_listed(self):
        self.assertIn("pay", SELLING_TOOLS)
        self.assertIn("pay_order", SELLING_TOOLS)

    def test_a_world_that_sells_carries_one(self):
        self.assertTrue(set(WORLDS["duffel"].flow) & SELLING_TOOLS)
        self.assertFalse(set(WORLDS["serpapi"].flow) & SELLING_TOOLS)


class EveryWorldClassifiesItsEffects(unittest.TestCase):
    """The effect map is total over the flow and derives `sells`."""

    def test_each_flow_is_classified(self):
        from .effects import validate_effects
        for spec in WORLDS.values():
            validate_effects(spec.effects, spec.flow)

    def test_sells_follows_from_a_payment_tool(self):
        self.assertTrue(WORLDS["duffel"].sells)
        self.assertFalse(WORLDS["serpapi"].sells)

    def test_an_unknown_kind_is_refused(self):
        from .effects import WorldSpecError, validate_effects
        with self.assertRaises(WorldSpecError):
            validate_effects({"charge_ticket": "money"}, ("charge_ticket",))

    def test_a_new_payment_tool_is_classified_without_naming_it(self):
        from .effects import PAYMENT, classify
        self.assertEqual(classify({"charge_ticket": PAYMENT}, "charge_ticket"), PAYMENT)


class TheGatewayExecutesTheBoundJourney(unittest.TestCase):
    """The executor every gateway gets passes the approved journey unchanged."""

    def test_the_search_leaves_with_the_calls_journey(self):
        seen = []

        class Capture:
            def request(self, method, url, *, headers=None, params=None, json_body=None):
                seen.append(json_body)
                return 422, {"errors": []}

        executor = verify_world("duffel", MappingSecrets({"DUFFEL_TOKEN": "duffel_test_" + "t" * 20}),
                                Capture()).executor
        call = type("Call", (), {"tool": "search", "args": {
            "to": "LHR", "origin": "MUC", "date": "2030-01-02", "cabin": "business"}})()
        executor(call)
        leg = seen[0]["data"]["slices"][0]
        self.assertEqual((leg["origin"], leg["destination"], leg["departure_date"]), ("MUC", "LHR", "2030-01-02"))
        self.assertEqual(seen[0]["data"]["cabin_class"], "business")

    def test_every_holdable_airline_is_reported(self):
        from .duffel import offers

        def offer(oid, carrier, instant):
            return {"id": oid, "total_amount": "10.00", "total_currency": "EUR",
                    "owner": {"iata_code": carrier},
                    "payment_requirements": {"requires_instant_payment": instant}}

        body = {"data": {"offers": [offer("off_ba", "BA", False), offer("off_zz", "ZZ", False),
                                    offer("off_sq", "SQ", True)]}}
        payload, _ = offers(body)
        self.assertEqual(sorted(o["offer_id"] for o in payload["offers"]), ["off_ba", "off_zz"])
        self.assertEqual((payload["offers_total"], payload["offers_bookable"]), (3, 2))

    def test_a_carrier_known_to_refuse_holds_is_not_bookable_despite_its_flag(self):
        """IB claims requires_instant_payment=false, and Duffel refuses its holds."""
        from .duffel import HOLD_UNSUPPORTED_CARRIERS, offer as one_offer, offers
        self.assertIn("IB", HOLD_UNSUPPORTED_CARRIERS)
        ib = {"id": "off_ib", "total_amount": "10.00", "total_currency": "EUR",
              "owner": {"iata_code": "IB"}, "payment_requirements": {"requires_instant_payment": False}}
        payload, missing = one_offer(ib)
        self.assertEqual(missing, ())
        self.assertFalse(payload["holdable"])
        listed, _ = offers({"data": {"offers": [ib]}})
        self.assertEqual((listed["offer_count"], listed["offers_total"], listed["offers_bookable"]), (0, 1, 0))


class ExperimentKnobsAreFailClosed(unittest.TestCase):
    """WORLD_FAULT must name a known fault, or the gateway does not start."""

    SECRETS = {"DUFFEL_TOKEN": "duffel_test_" + "t" * 20}

    def _world(self, **kw):
        return verify_world("duffel", MappingSecrets(self.SECRETS), **kw)

    def test_an_unknown_fault_is_refused(self):
        with self.assertRaises(ConfigurationRefused):
            self._world(fault="drop-everything")

    def test_the_fault_withholds_only_a_confirmed_payment(self):
        from booking_v1.effects import EffectOutcome, EffectResult
        from .faults import with_fault
        answers = {"pay_order": EffectResult(outcome=EffectOutcome.CONFIRMED,
                                             payload={"order_id": "ord_x", "paid": True}),
                   "book": EffectResult(outcome=EffectOutcome.CONFIRMED, payload={"order_id": "ord_x"})}
        logged = []
        execute = with_fault(lambda call: answers[call.tool], "lose-payment-response",
                             WORLDS["duffel"].effects, log=logged.append)
        call = lambda tool: type("Call", (), {"tool": tool, "args": {"action_id": "a"}})()
        self.assertIs(execute(call("pay_order")).outcome, EffectOutcome.UNCERTAIN)
        self.assertIs(execute(call("book")).outcome, EffectOutcome.CONFIRMED, "only the payment kind")
        self.assertIn("ord_x", logged[0])
        answers["pay_order"] = EffectResult(outcome=EffectOutcome.FAILED, error="refused")
        self.assertIs(execute(call("pay_order")).outcome, EffectOutcome.FAILED,
                      "a refused payment crossed nothing and stays FAILED")


class TheGatewayRunsOnlyInTestMode(unittest.TestCase):
    """Duffel Test Mode is enforced, not assumed.

    A live token (or any token without the test prefix) is refused where the executor is
    built, before a transport exists, and the refusal does not repeat the token.
    """

    LIVE = "duffel_live_" + "L" * 20

    def _refusal(self, token: str) -> str:
        class NoNetwork:
            def request(self, *a, **k):
                raise AssertionError("a refused credential reached the transport")

        with self.assertRaises(ConfigurationRefused) as ctx:
            verify_world("duffel", MappingSecrets({"DUFFEL_TOKEN": token}), transport=NoNetwork())
        return str(ctx.exception)

    def test_a_live_token_is_refused(self):
        message = self._refusal(self.LIVE)
        self.assertIn("test-mode", message)
        self.assertNotIn(self.LIVE, message)

    def test_a_token_without_prefix_is_refused(self):
        self.assertIn("duffel_test_", self._refusal("sk_" + "x" * 20))

    def test_a_test_token_is_accepted(self):
        self.assertEqual(verify_world("duffel", HELD).world, "duffel")

    def test_every_executor_is_guarded(self):
        from .duffel import LiveModeRefused
        from .world import Credentials, live_executor
        with self.assertRaises(LiveModeRefused):
            live_executor("duffel", Credentials(duffel_token=self.LIVE))

    def test_the_local_demo_is_guarded_too(self):
        from booking_demo.live import live_world
        with self.assertRaises(SystemExit) as ctx:
            live_world("duffel", MappingSecrets({"DUFFEL_TOKEN": self.LIVE}))
        self.assertIn("test-mode", str(ctx.exception))

    def test_the_dashboard_says_enforced(self):
        self.assertIn("enforced", world_configuration("duffel")["provider"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
