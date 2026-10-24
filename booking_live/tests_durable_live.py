"""An UNCERTAIN payment outcome survives the durable two-phase dispatch.

Run:
    python3 -m booking_live.tests_durable_live

The live executor produces real uncertain outcomes: a payment request can be answered by
a timeout after the counterparty has already acted. `tests_live` checks that on the
executor itself. These tests check that the outcome is not lost on the way through
`booking_v4.durable`, where a wrong answer would cost money.

The run is driven as `booking_v5.tests_gateway_ledger` drives it, over the durable gateway
of `booking_v4.durable` with the ToolGateway of `booking_v3.gateway` behind it. Only the
world differs: a `booking_live` executor over recorded provider responses, so `search`,
`select` and `book` answer from the recorded fixtures and the payment fails the way a
lost answer fails.

No network, credential or cluster is needed.
"""
from __future__ import annotations

import json
import pathlib
import unittest
from dataclasses import dataclass, field

from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v3.fragment import honest_fragment
from booking_v3.policy import Policy3
from booking_v4.durable import DurableProcessDeployment, ExternalWorld
from booking_v5.gateway import COMMITTED, PENDING, DurableLedger, ledger_delta

from .policy import pl1
from .world import Credentials, live_executor

T0 = 1_700_000_010
ISSUED, EXPIRES = 1_700_000_000, 1_700_003_600
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"

CREDS = Credentials(duffel_token="duffel_test_" + "t" * 20)
OFFER_ID = "off_0000BAffU2NCWAqssFgZP8"
ORDER_ID = "ord_0000BAffZASVso3FOocIq2"
PRICE_MINOR, CURRENCY = 3116, "EUR"


def fixture(name: str):
    """Load a recorded provider answer from `fixtures/`."""
    return json.loads((FIXTURES / f"{name}.json").read_text())


@dataclass
class ScriptedTransport:
    """Replays scripted provider answers in order.

    An exception in the list is raised instead of answered, which is how a lost reply looks
    to the caller.
    """

    answers: list
    sent: list = field(default_factory=list)

    def request(self, method: str, url: str, *, headers=None, params=None, json_body=None):
        """Record the request and return or raise the next scripted answer."""
        self.sent.append((method, url.split("/air/")[-1] if "/air/" in url else url))
        if not self.answers:
            raise AssertionError(f"unscripted call: {method} {url}")
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    @property
    def payments_sent(self) -> int:
        """Count the payment POSTs that reached the transport."""
        return sum(1 for method, path in self.sent if method == "POST" and path == "payments")


def chain_answers(payment):
    """Script every provider answer one full run needs, with the payment's answer injected."""
    answers = [
        (201, fixture("duffel_offer_request")),     # search
        (200, fixture("duffel_get_offer")),         # select
        (200, fixture("duffel_get_offer")),         # book: passenger ids
        (201, fixture("duffel_create_hold_order")),  # book: the hold order
        (200, fixture("duffel_get_order_awaiting")),  # pay_order: the gateway's own read
        payment,                                    # pay_order: the irreversible step
    ]
    if isinstance(payment, tuple) and payment[0] == 201:
        # an accepted payment is read back
        answers.append((200, fixture("duffel_get_order_paid")))
    return answers


PLAN_ARGUMENTS = [
    {"to": "EWR"},
    {"flight": OFFER_ID},
    {"flight": OFFER_ID, "action_id": "book-1"},
    {"order_id": ORDER_ID, "amount_minor": PRICE_MINOR, "currency": CURRENCY,
     "action_id": "pay-1"},
]


def deployment(payment_answer):
    """Build a durable deployment whose world is the live executor over recorded answers."""
    transport = ScriptedTransport(answers=chain_answers(payment_answer))
    world = ExternalWorld(executor=live_executor("duffel", CREDS, transport))
    # PL1 without the human approval on the payment. The approval is tested elsewhere.
    # The effect path is under test here, and a run that stops for a human would not reach
    # the payment.
    policy = Policy3(base=pl1(), approval_required_steps=())
    dep = DurableProcessDeployment(FixedClock(T0), executor=world.executor,
                                   enable_test_api=True)
    approval = approve(policy, approver_id="alice", approval_id="A-run-1",
                       run_id="run-1", issued_at=ISSUED, expires_at=EXPIRES)
    s0 = dep.authority.create_run(policy, approval, "run-1")
    return policy, dep, s0, world, transport


def run_steps(policy, dep, envelope, upto):
    """Drive the run step by step and report what each step ended as."""
    outcomes = []
    for step in range(upto):
        fragment = honest_fragment(policy, envelope.run_id, step, PLAN_ARGUMENTS[step])
        result = dep.provisioner.spawn(fragment, envelope).execute(policy, envelope, fragment)
        outcomes.append((step, result.status, getattr(result, "reason", None)))
        if result.status != "STEP_COMPLETED":
            break
        envelope = result.envelope
    return envelope, outcomes


class TheLiveWorldReachesTheDurableGateway(unittest.TestCase):
    """The steps of a run are answered from the recorded provider answers."""

    def test_the_chain_runs_over_recorded_provider_answers(self):
        policy, dep, s0, world, transport = deployment((201, fixture("duffel_payment_accepted")))
        with dep:
            envelope, outcomes = run_steps(policy, dep, s0, 4)
        self.assertEqual([o[1] for o in outcomes], ["STEP_COMPLETED"] * 4,
                         f"outcomes were {outcomes}")
        # The search went to the provider, and one payment request was sent.
        self.assertIn(("POST", "offer_requests"), transport.sent)
        self.assertEqual(transport.payments_sent, 1)


class UncertainSurvivesTheDurablePath(unittest.TestCase):
    """A lost payment answer stays UNCERTAIN all the way out."""

    def _park_the_payment(self, payment_answer):
        policy, dep, s0, world, transport = deployment(payment_answer)
        with dep:
            envelope, outcomes = run_steps(policy, dep, s0, 4)
        return outcomes, transport

    def test_a_timeout_on_the_payment_is_uncertain_not_failed(self):
        outcomes, transport = self._park_the_payment(TimeoutError("read timed out"))
        step, status, reason = outcomes[-1]
        self.assertEqual(step, 3)
        self.assertNotEqual(status, "STEP_COMPLETED")
        self.assertIn("UNCERTAIN", f"{status} {reason}".upper(),
                      f"the payment ended as {status!r} / {reason!r}")

    def test_a_server_error_on_the_payment_is_uncertain(self):
        outcomes, transport = self._park_the_payment((503, {}))
        step, status, reason = outcomes[-1]
        self.assertEqual(step, 3)
        self.assertIn("UNCERTAIN", f"{status} {reason}".upper(),
                      f"the payment ended as {status!r} / {reason!r}")

    def test_the_run_does_not_advance_past_an_uncertain_payment(self):
        outcomes, _ = self._park_the_payment((503, {}))
        self.assertEqual([o[1] for o in outcomes[:3]], ["STEP_COMPLETED"] * 3)
        self.assertNotEqual(outcomes[3][1], "STEP_COMPLETED")

    def test_no_blind_second_payment_is_sent(self):
        """One payment request was sent, and the gateway does not retry it on its own."""
        _, transport = self._park_the_payment(TimeoutError("read timed out"))
        self.assertEqual(transport.payments_sent, 1)

    def test_a_refused_payment_is_failed_and_not_uncertain(self):
        """A 422 is the counterparty refusing, which is FAILED and not UNCERTAIN."""
        outcomes, transport = self._park_the_payment(
            (422, fixture("duffel_error_wrong_amount")))
        step, status, reason = outcomes[-1]
        self.assertEqual(step, 3)
        self.assertNotIn("UNCERTAIN", f"{status} {reason}".upper())
        self.assertEqual(transport.payments_sent, 1)


class TheLedgerRecordsWhatHappened(unittest.TestCase):
    """What the effect ledger says about a payment whose answer was lost.

    An UNCERTAIN outcome is committed: the gateway completed its dispatch and records that
    the result is unknown. A row that stays PENDING means something else, a crash between
    the two phases, and that case belongs to `booking_v5.tests_gateway_ledger`.

    The ledger therefore does not distinguish a lost payment from a successful one. The
    outcome does, and the run is parked on it, which is why the effect state machine and
    not the ledger stops the flow.
    """

    def _ledger_rows(self, payment_answer):
        policy, dep, s0, world, transport = deployment(payment_answer)
        with dep:
            run_steps(policy, dep, s0, 4)
            rows = DurableLedger(dep.store).entries_after(0)
        return rows

    def test_a_lost_payment_still_closes_its_dispatch(self):
        rows = self._ledger_rows(TimeoutError("read timed out"))
        last_two = [r.state for r in rows if r.step == 3]
        self.assertEqual(last_two, [PENDING, COMMITTED],
                         "the dispatch opens and closes even when the outcome is unknown")

    def test_the_uncertain_step_produced_no_further_effect(self):
        """One dispatch for the payment step, not two, and nothing else alongside it.

        `ledger_delta` is cursor-based, as the controller uses it: the watermark is taken
        before the step, and only what appeared after it is judged. Given the whole
        ledger, it would count the earlier steps as foreign.
        """
        rows = self._ledger_rows(TimeoutError("read timed out"))
        before_payment = max((r.seq for r in rows if r.step < 3), default=0)
        after = tuple(r for r in rows if r.seq > before_payment)
        delta = ledger_delta(after, "run-1", 3)
        self.assertEqual(delta.own_committed, 1)
        self.assertEqual(delta.own_pending, 0)
        self.assertTrue(delta.clean, f"foreign rows appeared: {delta.foreign}")

    def test_every_step_has_exactly_one_dispatch(self):
        rows = self._ledger_rows((201, fixture("duffel_payment_accepted")))
        per_step = {}
        for r in rows:
            per_step.setdefault(r.step, []).append(r.state)
        self.assertEqual(sorted(per_step), [0, 1, 2, 3])
        for step, states in per_step.items():
            self.assertEqual(states, [PENDING, COMMITTED], f"step {step} was {states}")


class TheGatewayReadsBeforeItPays(unittest.TestCase):
    """The pre-payment read happens inside the durable path, not beside it."""

    def test_the_order_is_re_read_before_the_payment(self):
        policy, dep, s0, world, transport = deployment((201, fixture("duffel_payment_accepted")))
        with dep:
            run_steps(policy, dep, s0, 4)
        paths = [p for m, p in transport.sent]
        self.assertIn(f"orders/{ORDER_ID}", paths)
        self.assertLess(paths.index(f"orders/{ORDER_ID}"), paths.index("payments"),
                        "the gateway must read the order before it pays it")


if __name__ == "__main__":
    unittest.main(verbosity=1)
