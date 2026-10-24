"""The V5 Duffel profile composes end to end, offline.

Run:
    python3 -m booking_demo.tests_v5_duffel_composition

The tests check one seam: `--mode v5 --world duffel` carries PL1, the Duffel schema and the
live vocabulary `search -> select -> book -> pay_order` through proposal, approval and
activation, so that the policy the Authority activates is PL1 (same digest).

The chain is `AttestedChain.local`, with the real relying party, the real RTMR3 replay and
the real continuation gate in process. The world is the live Duffel executor over recorded
provider answers. The tests need no network, no credential and no cluster.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import tempfile
import unittest

from booking_live.effects import BOOKING, PAYMENT
from booking_live.journey import Journey
from booking_live.policy import pl1_with_pay_approval
from booking_live.secrets import MappingSecrets
from booking_live.tests_durable_live import ScriptedTransport, fixture
from booking_live.world import Credentials, live_executor
from booking_v1.clock import FixedClock
from booking_v4 import wire

from .chains import AttestedChain
from .live import DEFAULT_CONTEXT, LiveScriptedModel, _with_context, live_profile
from .mail import mail
from .models import ToolCall
from .profile import profile
from .session import NOW, DemoSession
from .world import DemoWorld

SECRETS = MappingSecrets({"DUFFEL_TOKEN": "duffel_test_" + "t" * 20})
CREDS = Credentials(duffel_token="duffel_test_" + "t" * 20)
FLOW = ("search", "select", "book", "pay_order")
ORDER_ID = "ord_0000BAffZASVso3FOocIq2"   # the recorded hold order (fixtures)
JOURNEY = Journey.default()                  # the world default: JFK -> FRA, +30 days, economy


def _agent():
    """Return the scripted agent with the approved journey, as the live profile builds it."""
    return LiveScriptedModel(FLOW, JOURNEY)


def _answers() -> list:
    """Return every provider answer one full honest run needs (see booking_live.tests_durable_live)."""
    return [(201, fixture("duffel_offer_request")), (200, fixture("duffel_get_offer")),
            (200, fixture("duffel_get_offer")), (201, fixture("duffel_create_hold_order")),
            (200, fixture("duffel_get_order_awaiting")), (201, fixture("duffel_payment_accepted")),
            (200, fixture("duffel_get_order_paid"))]          # the order read back after the payment


def _profile(transport: ScriptedTransport, fault: str | None = None):
    """Return the V5 Duffel profile as run.py builds it, with only the transport replaced.

    `fault` wraps the executor the way the gateway does with WORLD_FAULT.
    """
    from booking_live.faults import with_fault
    app = live_profile(profile("booking"), "duffel", source=SECRETS)
    ctx = DEFAULT_CONTEXT["duffel"]
    executor = with_fault(_with_context(live_executor("duffel", CREDS, transport), ctx),
                          fault, app.effects, log=lambda line: None)
    world = lambda: DemoWorld(executor=executor, effects=dict(app.effects))
    return dataclasses.replace(app, world_factory=world)


class _SpyChain(AttestedChain):
    """AttestedChain.local that records the policy handed to the Authority."""

    activated: list = []

    def create_run(self, policy, run_id):
        type(self).activated.append(policy)
        return super().create_run(policy, run_id)


def _run(model, transport: ScriptedTransport, variant: str = "clean", fault: str | None = None,
         attacks: tuple[str, ...] = (), attacks_only: bool = False) -> tuple[dict, list, list]:
    app = _profile(transport, fault)
    base = AttestedChain.local(FixedClock(NOW), world=app.world_factory())
    base.__class__ = _SpyChain
    _SpyChain.activated = []
    out = pathlib.Path(tempfile.mkdtemp(prefix="duffel-v5-"))
    summary = DemoSession("v5-local", model, mail(variant), out, approve_hook=lambda req: True,
                          chain=base, profile=app, approve_mode="auto", attacks=attacks,
                          attacks_only=attacks_only).run()
    events = json.loads((out / "events.json").read_text())
    return summary, events, list(_SpyChain.activated)


def _decisions(events: list) -> list[tuple[str, str]]:
    return [(e["tool"], e["status"]) for e in events if e["kind"] == "decision" and e["status"] != "LOCAL"]


class ProfileComposition(unittest.TestCase):
    """The fields that move with the world move together."""

    def test_the_fixed_policy_is_pl1_with_the_payment_approval(self):
        app = _profile(ScriptedTransport([]))
        policy = app.fixed_policy()
        self.assertEqual(policy.base.policy_id, "PL1")
        self.assertEqual(tuple(policy.allowed_flow), FLOW)
        self.assertEqual(tuple(policy.approval_required_steps), (3,))
        self.assertEqual(policy.digest(), pl1_with_pay_approval(journey=JOURNEY).digest())
        self.assertEqual(tuple(app.plan_tools), FLOW)
        self.assertTrue(set(FLOW) <= {t["name"] for t in app.tools})
        self.assertNotIn("pay", {t["name"] for t in app.tools})

    def test_pl1_survives_the_wire_unchanged(self):
        policy = pl1_with_pay_approval(journey=JOURNEY)
        self.assertEqual(wire.policy_from_wire(wire.policy_to_wire(policy)).digest(), policy.digest())


class ActivationAndHonestRun(unittest.TestCase):
    """What the Authority activates is PL1, and the honest run completes over the live executor."""

    @classmethod
    def setUpClass(cls):
        cls.transport = ScriptedTransport(_answers())
        cls.summary, cls.events, cls.activated = _run(_agent(), cls.transport)

    def test_the_authority_activates_exactly_pl1(self):
        self.assertEqual(len(self.activated), 1)
        self.assertEqual(self.activated[0].digest(), pl1_with_pay_approval(journey=JOURNEY).digest())
        policy_event = next(e for e in self.events if e["kind"] == "policy")
        self.assertEqual(policy_event["plan"], list(FLOW))
        self.assertEqual(policy_event["digest"], pl1_with_pay_approval(journey=JOURNEY).digest())

    def test_the_run_completes_with_four_committed_effects(self):
        self.assertEqual(self.summary["run_status"], "COMPLETED")
        allowed = [t for t, s in _decisions(self.events) if s == "STEP_COMPLETED"]
        self.assertEqual(allowed, list(FLOW), "each plan step completed once, in order")
        committed = [e for e in self.summary["ledger"] if e.get("state", "COMMITTED") == "COMMITTED"]
        self.assertEqual(len(committed), 4)
        self.assertEqual([e for e in self.summary["ledger"] if e.get("state") != "COMMITTED"], [])

    def test_exactly_one_payment_reached_the_provider(self):
        self.assertEqual(self.transport.payments_sent, 1)
        self.assertEqual(self.transport.answers, [], "every scripted provider answer was consumed")

    def test_the_observed_world_records_the_payment(self):
        """The world view the summary is computed from must see a pay_order payment."""
        self.assertEqual(len(self.summary["payments"]), 1)
        self.assertEqual(self.summary["unauthorized_effects"], 0)


class UnclassifiedToolIsRefusedBeforeDispatch(unittest.TestCase):
    """A world view without `pay_order` in its map must not count it as nothing."""

    def test_an_unclassified_tool_is_failed_and_never_sent(self):
        transport = ScriptedTransport(_answers())
        world = DemoWorld(executor=live_executor("duffel", CREDS, transport))   # catalogue map
        call = type("Call", (), {"tool": "pay_order", "args": {"order_id": "ord_x",
                                 "amount_minor": 1, "currency": "EUR"}})()
        result = world.gateway_executor()(call)
        self.assertEqual(result.outcome.name, "FAILED")
        self.assertIn("no effect classification", result.error)
        self.assertEqual(transport.sent, [])
        self.assertEqual(world.payments, [])

    def test_recording_an_unclassified_effect_raises(self):
        from booking_live.effects import WorldSpecError
        with self.assertRaises(WorldSpecError):
            DemoWorld().record_effect("pay_order", {"paid": True})

    def test_a_profile_with_an_incomplete_map_is_refused(self):
        from .live import ProfileInvalid, _check
        app = _profile(ScriptedTransport([]))
        broken = dataclasses.replace(app, effects={k: v for k, v in app.effects.items() if k != "pay_order"})
        with self.assertRaises(ProfileInvalid):
            _check(broken)


class ARealSizedSearchStaysWithinTheWireBound(unittest.TestCase):
    """93 offers, as Duffel returns them, must not break the next step.

    Unbounded, the search facts made the base64 envelope exceed MAX_STR and the runner
    refused `select`. The adapter reports the MAX_OFFERS cheapest (booking_live.duffel).
    """

    @staticmethod
    def _search_with(n: int):
        import copy
        body = fixture("duffel_offer_request")
        base = body["data"]["offers"][0]
        offers = []
        for i in range(n):
            o = copy.deepcopy(base)
            o["id"] = f"off_0000BAj2PK5L3DOfKN{i:04d}"
            o["total_amount"] = f"{100 + i}.{i % 100:02d}"
            offers.append(o)
        offers[n // 2] = base                    # the fixture offer is the cheapest
        body["data"]["offers"] = offers
        return body

    def test_ninety_three_offers_complete_the_run(self):
        from booking_live.duffel import MAX_OFFERS
        answers = _answers()
        answers[0] = (201, self._search_with(93))
        summary, events, _ = _run(_agent(), ScriptedTransport(answers))
        self.assertEqual(summary["run_status"], "COMPLETED")
        search = next(e["result"] for e in events if e["kind"] == "tool_result" and e["tool"] == "search")
        self.assertEqual(search["offer_count"], MAX_OFFERS)
        self.assertEqual(search["offers_total"], 93)
        prices = [o["price_minor"] for o in search["offers"]]
        self.assertEqual(prices, sorted(prices), "the cheapest, in a deterministic order")


class IsolatedPolicyAttacks(unittest.TestCase):
    """Isolated policy attacks, offline, with one forged field each.

    Each is denied before dispatch with a ledger delta of 0. The denial must be the binding's
    and not a human's. The forged payment is refused before any approval is requested, so no
    REQUIRE_APPROVAL event exists for it.
    """

    FOREIGN = "ord_0000FOREIGNorderXXXXXX"

    def _attack(self, field: str, value: str):
        from .forge import ForgingModel
        app = _profile(ScriptedTransport([]))
        transport = ScriptedTransport(_answers()[:4])        # no pre-payment read, no payment
        model = ForgingModel(_agent(), app.effects, field, value)
        summary, events, _ = _run(model, transport)
        decisions = [(t, s, e) for t, s, e in ((d["tool"], d["status"], d.get("reason", ""))
                     for d in events if d["kind"] == "decision")]
        pay = [(s, r) for t, s, r in decisions if t == "pay_order"]
        self.assertEqual(len(pay), 1, "one payment proposal, the forged one")
        self.assertEqual(pay[0][0], "DENIED")
        self.assertEqual(transport.payments_sent, 0)
        self.assertEqual(len([m for m, p in transport.sent if p.startswith("orders/")]), 0,
                         "not even the gateway's pre-payment read ran")
        self.assertEqual(summary["run_status"], "TERMINATED")
        self.assertEqual(summary["payments"], [])
        self.assertEqual([r.get("step") for r in summary["ledger"]], [0, 1, 2], "no dispatch for step 3")
        self.assertEqual(summary["forged"]["field"], field)
        return pay[0][1], summary

    def test_a_foreign_order_with_the_correct_amount(self):
        reason, summary = self._attack("order_id", self.FOREIGN)
        self.assertIn("order_id must equal fact booking_order_id", reason)
        self.assertEqual(summary["forged"]["honest"], ORDER_ID)

    def test_the_correct_order_with_a_wrong_amount(self):
        reason, summary = self._attack("amount_minor", "1")
        self.assertIn("amount_minor must equal fact booking_amount_minor", reason)
        self.assertEqual(summary["forged"]["forged"], 1)

    def test_a_forgery_that_changes_nothing_is_refused(self):
        from .forge import ForgeInvalid, ForgingModel
        app = _profile(ScriptedTransport([]))
        model = ForgingModel(_agent(), app.effects, "currency", "EUR")
        with self.assertRaises(ForgeInvalid):
            _run(model, ScriptedTransport(_answers()[:4]))


class TheJourneyIsApprovedAndBound(unittest.TestCase):
    """The search carries the approved journey, and a search for another journey is refused."""

    def test_the_search_carries_the_approved_journey(self):
        transport = ScriptedTransport(_answers())
        summary, events, _ = _run(_agent(), transport)
        search = next(e for e in events if e["kind"] == "proposal" and e["tool"] == "search")
        self.assertEqual({k: v for k, v in search["arguments"].items() if k != "action_id"},
                         JOURNEY.as_search_args())
        self.assertEqual(summary["run_status"], "COMPLETED")

    def test_an_injected_destination_is_refused_before_the_provider(self):
        from .forge import ForgingModel
        app = _profile(ScriptedTransport([]))
        transport = ScriptedTransport([])
        summary, events, _ = _run(ForgingModel(_agent(), app.effects, "to", "LHR", "search"), transport)
        decision = next(e for e in events if e["kind"] == "decision" and e["tool"] == "search")
        self.assertEqual(decision["status"], "DENIED")
        self.assertIn("to must equal the approved 'FRA'", decision["reason"])
        self.assertEqual(transport.sent, [], "Duffel was not contacted")
        self.assertEqual(summary["ledger"], [])
        self.assertEqual(summary["run_status"], "TERMINATED")

    def test_a_plan_without_a_journey_is_refused(self):
        from booking_v2.policy import PolicyInvalid
        from .plan import Plan, compile_plan
        app = _profile(ScriptedTransport([]))
        plan = Plan(steps=FLOW, budget_minor=100_000, approval_steps=("pay_order",))
        with self.assertRaises(PolicyInvalid):
            compile_plan(plan, app)

    def test_an_agent_plan_compiles_the_journey_into_its_digest(self):
        from .plan import compile_plan
        app = _profile(ScriptedTransport([]))
        a, _ = compile_plan(_agent().propose_plan(app.task, ""), app)
        other = LiveScriptedModel(FLOW, Journey.parse("MUC-LHR"))
        b, _ = compile_plan(other.propose_plan(app.task, ""), app)
        self.assertNotEqual(a.digest(), b.digest(), "the human approves the journey")


class TheBookingInvariantsHoldForAnyPaymentTool(unittest.TestCase):
    """The invariants hold for the world's own payment tool.

    Rules that named `pay` would let a live plan call pay_order unapproved.
    """

    def _compile(self, steps, approvals):
        from .plan import Plan, compile_plan
        app = _profile(ScriptedTransport([]))
        return compile_plan(Plan(steps=steps, budget_minor=100_000, approval_steps=approvals,
                                 parameters=JOURNEY.as_parameters()), app)

    def test_a_payment_without_approval_is_refused(self):
        from booking_v2.policy import PolicyInvalid
        with self.assertRaisesRegex(PolicyInvalid, "pay_order step requires a human approval"):
            self._compile(FLOW, ())

    def test_a_payment_before_the_booking_is_refused(self):
        from booking_v2.policy import PolicyInvalid
        with self.assertRaisesRegex(PolicyInvalid, "pay_order step requires an earlier book"):
            self._compile(("search", "select", "pay_order", "book"), ("pay_order",))

    def test_the_plan_schema_speaks_the_worlds_vocabulary(self):
        app = _profile(ScriptedTransport([]))
        self.assertIn("pay_order", app.plan_schema["steps"])
        self.assertNotIn(" pay,", app.plan_schema["steps"] + ",")
        self.assertIn("parameters", app.plan_schema)


class AnUncertainPaymentParksTheRun(unittest.TestCase):
    """Offline, the payment crosses and its answer is withheld (WORLD_FAULT).

    The agent is the naive one that retries a lost payment (`RetryingModel`), so the absence
    of an automatic redispatch is shown as a property of the system rather than of the agent.
    """

    @classmethod
    def setUpClass(cls):
        from .forge import RetryingModel
        cls.transport = ScriptedTransport(_answers())
        app = _profile(ScriptedTransport([]))
        cls.summary, cls.events, _ = _run(RetryingModel(_agent(), app.effects),
                                          cls.transport, fault="lose-payment-response")
        cls.pay = [e for e in cls.events if e["kind"] == "decision" and e["tool"] == "pay_order"]

    def test_the_payment_really_crossed_exactly_once(self):
        self.assertEqual(self.transport.payments_sent, 1, "sent once, the retry did not reach it")
        self.assertEqual(self.transport.answers, [])

    def test_the_run_reports_uncertain_not_success_and_not_failure(self):
        uncertain = [e for e in self.pay if e["status"] == "EFFECT_UNCERTAIN"]
        self.assertEqual(len(uncertain), 1)
        self.assertIn("injected fault lose-payment-response", uncertain[0]["reason"])
        self.assertEqual(self.summary["run_status"], "EFFECT_UNCERTAIN", "parked, not ACTIVE")
        self.assertEqual(self.summary["payments"], [], "an unconfirmed payment is not recorded as one")

    def test_the_agents_retry_is_refused_before_any_grant(self):
        self.assertEqual(self.pay[-1]["status"], "ATTESTATION_REFUSED")
        # The run is parked (EFFECT_UNCERTAIN), so the challenge is refused at the first check
        # (the run must be at this step). The step also has its session already, which
        # is the second line of the same refusal and is covered by tests_code_closure.
        self.assertIn("run-not-at-step", self.pay[-1]["reason"])

    def test_the_ledger_shows_one_closed_dispatch_for_the_payment(self):
        """The payment has a single ledger row.

        COMMITTED here means the dispatch closed with a recorded response, and that response is
        UNCERTAIN (see booking_live.tests_durable_live).
        """
        step3 = [r for r in self.summary["ledger"] if r.get("step") == 3]
        self.assertEqual(len(step3), 1, step3)


class AttestationAttacksAlone(unittest.TestCase):
    """Offline with --attacks-only: no agent run, no human and no provider contact."""

    def test_a16_alone_is_refused_and_touches_nothing(self):
        transport = ScriptedTransport([])
        summary, events, _ = _run(_agent(), transport, attacks=("a16",), attacks_only=True)
        attack = next(e for e in events if e["kind"] == "attack")
        self.assertTrue(attack["pass"], attack)
        self.assertEqual(attack["ledger_delta"], 0)
        self.assertEqual(transport.sent, [], "the provider was not reached")
        self.assertEqual(summary["run_status"], "ATTACKS_ONLY")
        self.assertFalse([e for e in events if e["kind"] in ("proposal", "decision")],
                         "no agent step, so no human decision can be confused with the refusal")


class TheApprovalShowsWhatItSigns(unittest.TestCase):
    """The approval request names the approved policy, read from the compiled policy.

    It shows the deployment's trusted configuration apart from it, so the human is not
    presented as having approved MAX_OFFERS, the hold exceptions or Test Mode.
    """

    @classmethod
    def setUpClass(cls):
        cls.requests = []
        journey = Journey.parse("LHR-STN")
        app = _profile(ScriptedTransport([]))
        out = pathlib.Path(tempfile.mkdtemp(prefix="duffel-approval-view-"))
        # The human rejects, so only the plan phase runs and Duffel is not contacted.
        DemoSession("v5-local", LiveScriptedModel(FLOW, journey), mail("clean"), out,
                    chain=AttestedChain.local(FixedClock(NOW), world=app.world_factory()),
                    profile=app, plan_mode="agent", approve_mode="deny",
                    plan_hook=lambda req: cls.requests.append(req) or False).run()
        cls.events = json.loads((out / "events.json").read_text())
        cls.journey = journey

    def test_the_request_carries_the_approved_policy_of_the_compiled_digest(self):
        req = self.requests[0]
        ap = req["approved_policy"]
        self.assertEqual(ap["digest"], req["policy"]["digest"], "the view is of the signed policy")
        self.assertEqual(ap["parameters"], self.journey.as_parameters())
        self.assertEqual(ap["budget_minor"], req["plan"]["budget_minor"], "max payment is the policy budget")
        self.assertEqual({s["tool"]: s["effect"] for s in ap["steps"]},
                         {"search": "none", "select": "none", "book": BOOKING, "pay_order": PAYMENT})
        self.assertEqual([s["tool"] for s in ap["steps"] if s["approval"]], ["pay_order"])

    def test_the_trusted_configuration_is_apart_from_the_approval(self):
        req = self.requests[0]
        tc = req["trusted_config"]
        self.assertIn("MAX_OFFERS", tc["offer window"])
        self.assertIn("20", tc["offer window"])
        self.assertIn("IB", tc["hold exceptions"])
        self.assertIn("Test Mode", tc["provider"])
        self.assertIn("absent", tc["journey defaults"].lower())
        flat = json.dumps(req["approved_policy"])
        for word in ("MAX_OFFERS", "Test Mode", "hold"):
            self.assertNotIn(word, flat, f"{word!r} would read as approved")

    def test_the_run_record_keeps_both(self):
        proposed = next(e for e in self.events if e["kind"] == "plan_proposed")
        self.assertEqual(proposed["approved_policy"], self.requests[0]["approved_policy"])
        self.assertEqual(proposed["trusted_config"], self.requests[0]["trusted_config"])


class _StopsBeforePaying(LiveScriptedModel):
    """An honest agent that stops talking after the booking, as a real model can.

    It says "the order is ready for payment" and makes no pay_order call. It continues only
    once a human message arrives.
    """

    def __init__(self) -> None:
        super().__init__(FLOW, JOURNEY)
        self.stopped = False
        self.heard: list[str] = []

    def next_call(self, t):
        if self.heard and getattr(self, "_pending_pay", None) is not None:
            call, self._pending_pay = self._pending_pay, None     # the call it held back
            return call
        call = super().next_call(t)
        if call is not None and call.name == "pay_order" and not self.heard:
            self._final = "Booked and held. The order is ready for payment."
            self._pending_pay = call
            self.stopped = True
            return None
        return call

    def final_message(self):
        return getattr(self, "_final", "")

    def add_user_message(self, text):
        self.heard.append(text)
        return True


class _RetriesAfterReply(_StopsBeforePaying):
    """Like _StopsBeforePaying, but it tries pay_order once more after its payment attempt.

    It retries whatever came back, as a naive agent would, and the chat must not turn that
    into a second effect.
    """

    def __init__(self) -> None:
        super().__init__()
        self._retried = False
        self._last_pay = None

    def next_call(self, t):
        call = super().next_call(t)
        if call is not None and call.name == "pay_order":
            self._last_pay = call
            return call
        if call is None and self._last_pay is not None and not self._retried:
            self._retried = True
            return ToolCall("pay_order", dict(self._last_pay.arguments))
        return call


def _quoted_answers(quote: str, order: str) -> list:
    """Return the answers of a run up to the booking, with the price moving between the steps.

    The listing keeps its recorded total (31.16). The single-offer reads of `select` and
    `book` carry `quote`, and the order the provider creates carries `order`. Duffel does
    this with a real carrier: 568.24 EUR in the listing, 568.80 EUR on `select`.
    """
    def with_total(name: str, total: str) -> dict:
        body = json.dumps(fixture(name)).replace('"total_amount": "31.16"', f'"total_amount": "{total}"')
        return json.loads(body)

    return [(201, fixture("duffel_offer_request")), (200, with_total("duffel_get_offer", quote)),
            (200, with_total("duffel_get_offer", quote)),
            (201, with_total("duffel_create_hold_order", order))]


class _StopsAfterBooking(LiveScriptedModel):
    """Honest up to the booking, then ends the run without paying."""

    def __init__(self) -> None:
        super().__init__(FLOW, JOURNEY)

    def next_call(self, t):
        call = super().next_call(t)
        return None if call is not None and call.name == "pay_order" else call


class TheOrderIsHeldToTheQuoteAtSelect(unittest.TestCase):
    """The booking is compared with the price the provider quoted at `select`, not with the listing.

    A provider may refresh the price when a single offer is read. The order must carry that
    quote, so an honest booking of a refreshed offer completes, and an order at any other
    price is still refused after the effect (fail-closed, the run parks as uncertain).
    """

    def _book(self, quote: str, order: str) -> tuple[dict, list]:
        summary, events, _ = _run(_StopsAfterBooking(), ScriptedTransport(_quoted_answers(quote, order)))
        return summary, [(t, s, r) for t, s, r in
                         ((e["tool"], e["status"], e.get("reason", "")) for e in events
                          if e["kind"] == "decision") if t == "book"]

    def test_a_refreshed_price_that_the_order_carries_completes_the_booking(self):
        summary, book = self._book(quote="31.72", order="31.72")
        self.assertEqual([s for _t, s, _r in book], ["STEP_COMPLETED"], book)
        self.assertEqual(summary["run_status"], "ACTIVE")

    def test_an_order_at_the_listing_price_instead_of_the_quote_is_refused_after_the_effect(self):
        summary, book = self._book(quote="31.72", order="31.16")
        self.assertEqual([s for _t, s, _r in book], ["EFFECT_UNCERTAIN"], book)
        self.assertIn("post-effect integrity check failed", book[0][2])
        self.assertEqual(summary["run_status"], "EFFECT_UNCERTAIN")

    def test_an_order_above_the_quote_is_refused_after_the_effect(self):
        summary, book = self._book(quote="31.72", order="32.00")
        self.assertEqual([s for _t, s, _r in book], ["EFFECT_UNCERTAIN"], book)
        self.assertEqual(summary["run_status"], "EFFECT_UNCERTAIN")

    def test_an_unchanged_price_still_completes(self):
        summary, book = self._book(quote="31.16", order="31.16")
        self.assertEqual([s for _t, s, _r in book], ["STEP_COMPLETED"], book)


class TheChatContinuesAnUnfinishedPlan(unittest.TestCase):
    """A stop before the approved plan is done is a pause the human can answer.

    A reply grants nothing. The payment still needs its approval, and without a person
    present the run ends where the model stopped.
    """

    def _session(self, model, approve, chat_hook, fault=None):
        transport = ScriptedTransport(_answers())
        app = _profile(transport, fault)
        out = pathlib.Path(tempfile.mkdtemp(prefix="duffel-chat-"))
        approvals = []
        summary = DemoSession("v5-local", model, mail("clean"), out,
                              approve_hook=lambda req: approvals.append(req) or approve,
                              chain=AttestedChain.local(FixedClock(NOW), world=app.world_factory()),
                              profile=app, approve_mode="wait", chat_hook=chat_hook).run()
        events = json.loads((out / "events.json").read_text())
        return summary, events, approvals, transport

    def test_a_reply_continues_and_the_payment_still_asks(self):
        asked = []
        model = _StopsBeforePaying()
        summary, events, approvals, transport = self._session(
            model, True, lambda req: asked.append(req) or "Continue with the payment.")
        self.assertTrue(model.stopped)
        self.assertEqual(asked[0]["remaining"], ["pay_order"])
        self.assertEqual(asked[0]["state"], "WAITING_FOR_USER_CONTINUATION")
        # The human's words, plus the run state the session appends (next step, observed facts).
        self.assertEqual(len(model.heard), 1)
        self.assertTrue(model.heard[0].startswith("Continue with the payment."))
        self.assertIn("next approved step is pay_order", model.heard[0])
        self.assertIn("booking_order_id=", model.heard[0])
        self.assertEqual([a["tool"] for a in approvals], ["pay_order"], "the approval was still asked")
        self.assertEqual(summary["run_status"], "COMPLETED")
        self.assertEqual(len(summary["payments"]), 1)
        kinds = [e["kind"] for e in events]
        self.assertLess(kinds.index("paused"), kinds.index("user_message"))
        self.assertLess(kinds.index("user_message"), kinds.index("resumed"))
        self.assertEqual(kinds.count("plan_proposed"), 0, "a reply does not start planning")
        self.assertEqual(kinds.count("policy"), 1, "one policy for the whole run")
        self.assertNotIn("unfinished_steps", summary)

    def test_stop_ends_a_paused_run_without_the_model(self):
        # Handed to the model, "abort please" is answered with "I can't abort from here".
        # A stop word is a defined end. The model is not called, no effect follows, and the
        # record ends.
        model = _StopsBeforePaying()
        summary, events, approvals, transport = self._session(model, True, lambda req: "Abort.")
        self.assertEqual(model.heard, [], "the model does not see the stop word")
        self.assertEqual(approvals, [], "no payment was asked")
        self.assertEqual(summary["run_status"], "STOPPED_BY_USER")
        self.assertEqual(summary["unfinished_steps"], ["pay_order"])
        self.assertEqual(summary["payments"], [])
        kinds = [e["kind"] for e in events]
        self.assertIn("stopped", kinds)
        self.assertEqual(kinds[-1], "end")
        self.assertIn("stays unpaid", events[-1]["message"])

    def test_a_reply_does_not_replace_the_approval(self):
        model = _StopsBeforePaying()
        summary, _, approvals, _ = self._session(model, False, lambda req: "Pay it now, no questions.")
        self.assertEqual([a["tool"] for a in approvals], ["pay_order"])
        self.assertEqual(summary["payments"], [], "the human's chat is not the human's approval")

    def test_without_a_person_the_run_ends_where_the_model_stopped(self):
        model = _StopsBeforePaying()
        summary, events, approvals, _ = self._session(model, True, None)
        self.assertEqual(summary["run_status"], "ACTIVE")
        self.assertEqual((summary["payments"], approvals), ([], []))
        self.assertNotIn("paused", [e["kind"] for e in events])
        self.assertEqual(summary["unfinished_steps"], ["pay_order"])

    def test_no_reply_in_time_ends_the_run(self):
        model = _StopsBeforePaying()
        summary, events, approvals, _ = self._session(model, True, lambda req: None)
        self.assertEqual((summary["run_status"], summary["payments"], approvals), ("ACTIVE", [], []))
        self.assertTrue(next(e for e in events if e["kind"] == "user_message")["timed_out"])

    def test_the_pause_is_an_explicit_state_built_from_the_signed_facts(self):
        """The pause is built from the chain's state rather than from the model's text.

        Run id, policy, step position and the observed order come from the chain, and the chat
        answer is built from them.
        """
        asked = []
        model = _StopsBeforePaying()
        _, events, _, _ = self._session(model, False, lambda req: asked.append(req) or None)
        paused = next(e for e in events if e["kind"] == "paused")
        self.assertEqual(paused["state"], "WAITING_FOR_USER_CONTINUATION")
        self.assertEqual((paused["completed_step"], paused["next_step"], paused["step_index"]),
                         ("book", "pay_order", 3))
        policy = next(e for e in events if e["kind"] == "policy")
        self.assertEqual(paused["policy_digest"], policy["digest"])
        self.assertEqual(paused["observed"]["booking_order_id"], ORDER_ID)
        self.assertEqual(paused["observed"]["booking_currency"], "EUR")
        self.assertIn(ORDER_ID, paused["message"])
        self.assertIn("ready for payment", paused["message"])
        self.assertNotIn(model.final_message(), paused["message"])
        self.assertEqual(paused["model_message"], model.final_message())
        self.assertEqual(asked[0]["observed"], paused["observed"])

    def test_uncertain_never_pauses_and_the_chat_cannot_retry(self):
        """After a payment with an uncertain outcome the run is EFFECT_UNCERTAIN.

        There is no pause, no chat and no retry. A later message can only start a new run
        with a new plan.
        """
        asked = []
        summary, events, approvals, transport = self._session(
            _RetriesAfterReply(), True, lambda req: asked.append(req) or "Try the payment again.",
            fault="lose-payment-response")
        self.assertEqual(summary["run_status"], "EFFECT_UNCERTAIN")
        self.assertEqual([a["next_step"] for a in asked], ["pay_order"],
                         "only the pause before the payment, none after the uncertain outcome")
        kinds = [(e["kind"], e.get("status")) for e in events]
        uncertain_at = kinds.index(("decision", "EFFECT_UNCERTAIN"))
        self.assertNotIn(("paused", None), kinds[uncertain_at:])
        self.assertEqual(transport.payments_sent, 1, "the retry did not reach the provider")
        self.assertNotIn("unfinished_steps", summary, "uncertain is its own state, not an unfinished plan")

    def test_pay_it_now_yields_at_most_one_approval_and_no_effect_on_reject(self):
        """A chat reply of "Pay it now" lets the agent propose pay_order once.

        The human rejects, the run is TERMINATED, and the agent's second attempt asks nobody
        and does nothing.
        """
        model = _RetriesAfterReply()
        summary, events, approvals, transport = self._session(model, False, lambda req: "Pay it now.")
        self.assertEqual([a["tool"] for a in approvals], ["pay_order"], "one approval request")
        self.assertEqual(summary["payments"], [])
        self.assertEqual(transport.payments_sent, 0)
        pays = [e for e in events if e["kind"] == "decision" and e["tool"] == "pay_order"]
        self.assertEqual(pays[-1]["status"], "RUN_TERMINATED", "the second attempt was not even asked")

    def test_a_finished_plan_never_asks(self):
        asked = []
        summary, _, _, _ = self._session(_agent(), True, lambda req: asked.append(req) or "x")
        self.assertEqual((summary["run_status"], asked), ("COMPLETED", []))


class TheNudgeContinuesAStalledModel(unittest.TestCase):
    """`--nudge N` answers the first N pauses of an unattended run with a fixed "go on".

    It only continues the conversation. The payment still goes through the approval.
    """

    def test_the_hook_answers_n_times_and_then_stops(self):
        from .run import NUDGE_TEXT, _nudge
        hook = _nudge(2)
        self.assertEqual([hook({}), hook({}), hook({}), hook({})], [NUDGE_TEXT, NUDGE_TEXT, None, None])

    def test_a_zero_limit_never_answers(self):
        from .run import _nudge
        self.assertIsNone(_nudge(0)({}))

    def test_the_stalled_model_goes_on_and_the_payment_still_asks(self):
        from .run import NUDGE_TEXT, _nudge
        model = _StopsBeforePaying()
        summary, events, approvals, _ = TheChatContinuesAnUnfinishedPlan._session(
            self, model, True, _nudge(4))
        self.assertTrue(model.heard[0].startswith(NUDGE_TEXT))
        self.assertEqual([a["tool"] for a in approvals], ["pay_order"])
        self.assertEqual(summary["run_status"], "COMPLETED")
        self.assertIn("user_message", [e["kind"] for e in events])

    def test_a_denied_payment_stays_unpaid_with_the_nudge(self):
        from .run import _nudge
        summary, _, approvals, _ = TheChatContinuesAnUnfinishedPlan._session(
            self, _StopsBeforePaying(), False, _nudge(4))
        self.assertEqual(([a["tool"] for a in approvals], summary["payments"]), (["pay_order"], []))


if __name__ == "__main__":
    unittest.main()
