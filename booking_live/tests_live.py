"""Self-contained tests for the live contract.

Run:
    python3 -m booking_live.tests_live

The table answers one question, because a contract fitted to one observed response tends
to break on the second: does the adapter accept every response that differs only in form,
and refuse, by name, every response that differs in meaning?

The inputs are the real recorded responses in `fixtures/`, taken from the production
SerpApi endpoint and the Duffel test-mode API. Each case mutates one of them and states
the expected outcome up front. Tolerance and strictness are therefore measured rather than
asserted in prose, and the printed table is the evidence for the tolerance claim.

No network and no credential are needed, because the transport is a fixture.
"""
from __future__ import annotations

import copy
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Callable

from booking_v1.effects import EffectOutcome, safe_execute

from .world import Credentials, HostNotAllowed, live_executor

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
CONFIRMED, FAILED, UNCERTAIN = (EffectOutcome.CONFIRMED, EffectOutcome.FAILED,
                                EffectOutcome.UNCERTAIN)


def fixture(name: str) -> Any:
    """Load a recorded provider response from `fixtures/`."""
    return json.loads((FIXTURES / f"{name}.json").read_text())


class Call:
    """The shape the gateway hands an executor."""

    def __init__(self, tool: str, **args: Any) -> None:
        self.tool, self.args = tool, args


@dataclass
class FixtureTransport:
    """Replays a scripted sequence of (status, body) answers, or raises."""

    answers: list
    seen: list = field(default_factory=list)

    def request(self, method: str, url: str, *, headers=None, params=None, json_body=None):
        """Record the request and return or raise the next scripted answer."""
        self.seen.append((method, url))
        if not self.answers:
            raise AssertionError("transport called more often than the case scripted")
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


# --- mutations, each one a single deviation from a real response --------------------

def drop(*path: str) -> Callable[[Any], Any]:
    """Remove a field entirely, as a provider that renames it would."""
    def _m(body):
        node = body
        for key in path[:-1]:
            node = node[key]
        node.pop(path[-1], None)
        return body
    return _m


def put(value: Any, *path: str) -> Callable[[Any], Any]:
    """Replace a field's value, keeping everything else identical."""
    def _m(body):
        node = body
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        return body
    return _m


def add_unknown(body: Any) -> Any:
    """Add fields the adapter does not know, which must change nothing."""
    body["_brand_new_field"] = {"nested": [1, 2, 3]}
    if isinstance(body.get("data"), dict):
        body["data"]["_another_one"] = "surprise"
    return body


def reorder(body: Any) -> Any:
    """Rebuild the body in reverse key order, to show that nothing reads by position."""
    if isinstance(body.get("data"), dict):
        body["data"] = dict(reversed(list(body["data"].items())))
    return dict(reversed(list(body.items())))


def identity(body: Any) -> Any:
    """Return the unmodified response."""
    return body


@dataclass(frozen=True)
class Case:
    """One response, one deviation, one expected outcome."""

    name: str
    world: str
    call: Call
    answers: list
    expect: EffectOutcome
    expect_in_error: str = ""
    check: Callable[[dict], bool] | None = None

    @property
    def kind(self) -> str:
        """Return "form" when the case must be accepted, "meaning" when it must be refused."""
        return "form" if self.expect is CONFIRMED else "meaning"


def _duffel_offer(mutate=identity, status=200):
    return [(status, mutate(copy.deepcopy(fixture("duffel_get_offer"))))]


ORDER_ID = fixture("duffel_get_order_paid")["data"]["id"]


def _duffel_pay(answer=None, after=None):
    """Script the answers of `pay_order`.

    `pay_order` reads the order first (no effect), sends the payment (the effect) and, for
    an accepted payment, reads the order back. `after` is that last answer, only needed by
    cases that get that far.
    """
    answers = [(200, copy.deepcopy(fixture("duffel_get_order_awaiting"))),
               answer if answer is not None else (201, fixture("duffel_payment_accepted"))]
    if after is not None:
        answers.append(after)
    return answers


def _paid_order(mutate=identity):
    """Return the order as the provider shows it once the payment settled it."""
    return (200, mutate(copy.deepcopy(fixture("duffel_get_order_paid"))))


def _payment(mutate=identity, status=201):
    """Return the recorded payment object with one deviation."""
    return (status, mutate(copy.deepcopy(fixture("duffel_payment_accepted"))))


def _duffel_order(mutate=identity, status=201):
    """Script the answers of `book`, which reads the offer first (no effect) and then creates the order (the effect)."""
    return [(200, copy.deepcopy(fixture("duffel_get_offer"))),
            (status, mutate(copy.deepcopy(fixture("duffel_create_hold_order"))))]


def cases() -> list[Case]:
    """Return every case of the table, in the order it is printed."""
    return [
        # --- the recorded reality, unmodified -------------------------------------
        Case("duffel search, as recorded", "duffel", Call("search", origin="JFK",
             destination="EWR", departure_date="2026-10-22"),
             [(201, fixture("duffel_offer_request"))], CONFIRMED,
             check=lambda p: p["offer_count"] == 1 and p["malformed_offers"] == 0),
        Case("duffel select, as recorded", "duffel", Call("select", offer_id="off_x"),
             _duffel_offer(), CONFIRMED,
             check=lambda p: p["price_minor"] == 3116 and p["currency"] == "EUR"
                             and p["carrier"] == "ZZ" and p["holdable"] is True),
        Case("duffel book, as recorded", "duffel", Call("book", offer_id="off_x"),
             _duffel_order(), CONFIRMED,
             check=lambda p: p["awaiting_payment"] is True and p["price_minor"] == 3116
                             and p["booking_ref"] == "3USZ4V"),
        Case("duffel refresh, paid order", "duffel", Call("refresh", order_id="ord_x"),
             [(200, fixture("duffel_get_order_paid"))], CONFIRMED,
             check=lambda p: p["awaiting_payment"] is False and p["documents"] == 1),
        Case("duffel pay, as recorded", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(after=_paid_order()), CONFIRMED,
             check=lambda p: p["paid"] is True and p["amount_minor"] == 3116),
        Case("serpapi search, as recorded", "serpapi", Call("search", origin="MUC",
             destination="LHR", departure_date="2026-10-22"),
             [(200, fixture("serpapi_search"))], CONFIRMED,
             check=lambda p: p["offer_count"] == 29 and p["currency"] == "EUR"
                             and p["offers"][0]["price_minor"] == 12000),

        # --- form: must be accepted -----------------------------------------------
        Case("amount as a number, not a string", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put(31.16, "data", "total_amount")), CONFIRMED,
             check=lambda p: p["price_minor"] == 3116),
        Case("amount as an integer string", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put("31", "data", "total_amount")), CONFIRMED,
             check=lambda p: p["price_minor"] == 3100),
        Case("currency in lower case", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put("eur", "data", "total_currency")), CONFIRMED,
             check=lambda p: p["currency"] == "EUR"),
        Case("unknown fields added", "duffel", Call("select", offer_id="o"),
             _duffel_offer(add_unknown), CONFIRMED,
             check=lambda p: p["price_minor"] == 3116),
        Case("keys in another order", "duffel", Call("select", offer_id="o"),
             _duffel_offer(reorder), CONFIRMED,
             check=lambda p: p["price_minor"] == 3116),
        Case("carrier only on the segment", "duffel", Call("select", offer_id="o"),
             _duffel_offer(drop("data", "owner")), CONFIRMED,
             check=lambda p: p["carrier"] == "ZZ"),
        Case("empty search result", "duffel", Call("search", origin="X", destination="Y"),
             [(201, {"data": {"offers": []}})], CONFIRMED,
             check=lambda p: p["offer_count"] == 0),
        Case("one malformed offer among many", "duffel",
             Call("search", origin="X", destination="Y"),
             [(201, {"data": {"offers": [
                 {"id": "off_1", "total_amount": "10.00", "total_currency": "EUR",
                  "owner": {"iata_code": "ZZ"},
                  "payment_requirements": {"requires_instant_payment": False}},
                 {"id": "off_2", "total_amount": None, "total_currency": "EUR",
                  "owner": {"iata_code": "ZZ"},
                  "payment_requirements": {"requires_instant_payment": False}}]}})], CONFIRMED,
             check=lambda p: p["offer_count"] == 1 and p["malformed_offers"] == 1),
        # The flow is hold-then-pay, so an instant-payment offer is not bookable and is not
        # reported. The count of all well-formed offers stays visible.
        Case("an offer that requires instant payment is not reported", "duffel",
             Call("search", origin="X", destination="Y"),
             [(201, {"data": {"offers": [
                 {"id": "off_1", "total_amount": "10.00", "total_currency": "EUR",
                  "owner": {"iata_code": "ZZ"},
                  "payment_requirements": {"requires_instant_payment": True}}]}})], CONFIRMED,
             check=lambda p: p["offer_count"] == 0 and p["offers_total"] == 1),

        # --- meaning: must be refused, by name ------------------------------------
        Case("amount absent", "duffel", Call("select", offer_id="o"),
             _duffel_offer(drop("data", "total_amount")), FAILED, "offer.total_amount"),
        Case("amount is null", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put(None, "data", "total_amount")), FAILED, "offer.total_amount"),
        Case("sub-cent precision", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put("31.165", "data", "total_amount")), FAILED, "sub-cent"),
        Case("amount not a number", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put("thirty one", "data", "total_amount")), FAILED, "not a plain decimal"),
        Case("negative amount", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put("-31.16", "data", "total_amount")), FAILED, "negative"),
        Case("currency not ISO 4217", "duffel", Call("select", offer_id="o"),
             _duffel_offer(put("Euro", "data", "total_currency")), FAILED, "ISO 4217"),
        Case("identifier absent", "duffel", Call("select", offer_id="o"),
             _duffel_offer(drop("data", "id")), FAILED, "offer.id"),
        Case("carrier absent everywhere", "duffel", Call("select", offer_id="o"),
             _duffel_offer(lambda b: drop("data", "slices")(drop("data", "owner")(b))),
             FAILED, "iata_code"),
        Case("awaiting_payment as a string", "duffel", Call("book", offer_id="o"),
             _duffel_order(put("true", "data", "payment_status", "awaiting_payment")),
             UNCERTAIN, "awaiting_payment"),
        Case("all refusals reported at once", "duffel", Call("select", offer_id="o"),
             _duffel_offer(lambda b: put(None, "data", "total_currency")(
                 drop("data", "total_amount")(b))),
             FAILED, "total_currency"),

        # --- the gateway's own pre-payment observation ----------------------------
        # These do not reach the payment endpoint. The amount the monitor authorised is
        # checked against the order first, so a moved order stops the effect instead of
        # being discovered afterwards. Nothing has been sent when the read fails, so a
        # failed read is FAILED whether the provider refused it or the transport failed.
        Case("the world moved: order costs more now", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3016, currency="EUR"),
             [(200, fixture("duffel_get_order_awaiting"))], FAILED, "the order moved"),
        Case("the world moved: another currency", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3116, currency="USD"),
             [(200, fixture("duffel_get_order_awaiting"))], FAILED, "the order moved"),
        Case("order is no longer awaiting payment", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3116, currency="EUR"),
             [(200, fixture("duffel_get_order_paid"))], FAILED, "not awaiting payment"),
        Case("pre-payment read fails: payment never sent", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3116, currency="EUR"),
             [(404, {"errors": [{"code": "not_found"}]})], FAILED, "pay not attempted"),
        Case("pre-payment read lost: payment never sent", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3116, currency="EUR"),
             [TimeoutError("read timed out")], FAILED, "pay not attempted"),
        Case("offer read before a hold lost: order never created", "duffel",
             Call("book", offer_id="off_x"),
             [TimeoutError("read timed out")], FAILED, "book not attempted"),

        # --- the provider's own refusals, reached only by a race ------------------
        # The order was still 31.16 when the gateway read it and had changed by the time
        # the payment arrived. The window is small but not zero, and the provider's codes
        # have to survive the trip into an effect outcome.
        Case("race: provider refuses the amount", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3116, currency="EUR"),
             _duffel_pay((422, fixture("duffel_error_wrong_amount"))), FAILED,
             "payment_amount_does_not_match_order_amount"),
        Case("race: provider refuses the currency", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3116, currency="EUR"),
             _duffel_pay((422, fixture("duffel_error_wrong_currency"))), FAILED,
             "payment_currency_does_not_match_order_currency"),
        Case("race: provider says already paid", "duffel",
             Call("pay_order", order_id="ord_x", amount_minor=3116, currency="EUR"),
             _duffel_pay((422, fixture("duffel_error_duplicate"))), FAILED,
             "order_type_not_eligible_for_payment"),

        # --- outcome, not content: what the mock could not exercise ----------------
        Case("server error on a read is FAILED", "duffel", Call("refresh", order_id="o"),
             [(503, {"errors": [{"code": "internal"}]})], FAILED, "http 503"),
        Case("server error on pay is UNCERTAIN", "duffel",
             Call("pay_order", order_id="o", amount_minor=3116, currency="EUR"),
             _duffel_pay((503, {})), UNCERTAIN, "http 503"),
        Case("transport fails on pay is UNCERTAIN", "duffel",
             Call("pay_order", order_id="o", amount_minor=3116, currency="EUR"),
             _duffel_pay(TimeoutError("read timed out")), UNCERTAIN, "TimeoutError"),
        Case("transport fails on search is FAILED", "duffel",
             Call("search", origin="X", destination="Y"),
             [TimeoutError("read timed out")], FAILED, "TimeoutError"),
        Case("accepted but undescribable is UNCERTAIN", "duffel",
             Call("pay_order", order_id="o", amount_minor=3116, currency="EUR"),
             _duffel_pay((201, {"data": {"id": "pay_x"}})), UNCERTAIN, "payment.amount"),
        Case("pay with a non-integer amount never reaches the world", "duffel",
             Call("pay_order", order_id="o", amount_minor="3116", currency="EUR"),
             [], FAILED, "not an integer"),
        Case("world B has no payee to name", "duffel",
             Call("pay", amount_minor=3116, currency="EUR", recipient="airline:ZZ"),
             [], FAILED, "use pay_order"),
        Case("world A sells nothing", "serpapi", Call("book", offer_id="o"),
             [], FAILED, "world A is a search service"),
        Case("world A refuses another currency than requested", "serpapi",
             Call("search", origin="MUC", destination="LHR", departure_date="2026-10-22"),
             [(200, put("USD", "search_parameters", "currency")(copy.deepcopy(fixture("serpapi_search"))))],
             FAILED, "the request asked for 'EUR'"),
        Case("world A spends no search on an unknown tool", "serpapi",
             Call("refresh", order_id="o"), [], FAILED, "unknown tool"),

        # --- the payment result itself --------------------------------------------
        # An accepted HTTP request is not a payment. The status, the order, the amount and
        # the currency of the payment object and the order read back afterwards decide.
        Case("payment pending is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment(lambda b: put("pending", "data", "status")(b))),
             UNCERTAIN, "pending"),
        Case("payment failed is FAILED", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment(lambda b: put("failed", "data", "status")(b))),
             FAILED, "failed"),
        Case("payment cancelled is FAILED", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment(lambda b: put("cancelled", "data", "status")(b))),
             FAILED, "cancelled"),
        Case("payment in an unknown state is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment(lambda b: put("reversed", "data", "status")(b))),
             UNCERTAIN, "reversed"),
        Case("payment without a status is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment(lambda b: drop("data", "status")(b))),
             UNCERTAIN, "payment.status"),
        Case("payment for another order is UNCERTAIN", "duffel",
             Call("pay_order", order_id="ord_other", amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment()), UNCERTAIN, "authorised ord_other"),
        Case("payment of another amount is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment(lambda b: put("1.00", "data", "amount")(b))),
             UNCERTAIN, "authorised"),
        Case("payment in another currency is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(_payment(lambda b: put("USD", "data", "currency")(b))),
             UNCERTAIN, "authorised"),
        Case("succeeded, order still awaiting payment is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(after=(200, fixture("duffel_get_order_awaiting"))),
             UNCERTAIN, "awaiting_payment=True"),
        Case("succeeded, order total changed is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(after=_paid_order(lambda b: put("99.00", "data", "total_amount")(b))),
             UNCERTAIN, "order reads"),
        Case("succeeded, post-payment read fails is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(after=(503, {})), UNCERTAIN, "post-payment read"),
        Case("succeeded, post-payment read lost is UNCERTAIN", "duffel",
             Call("pay_order", order_id=ORDER_ID, amount_minor=3116, currency="EUR"),
             _duffel_pay(after=TimeoutError("read timed out")), UNCERTAIN, "post-payment read"),

        # --- the destination, enforced here because the network layer cannot do it
        Case("a redirect is not followed", "duffel", Call("select", offer_id="o"),
             [(302, {"_non_json_body": "moved"})], FAILED, "redirect"),
        Case("a redirect on pay is not followed", "duffel",
             Call("pay_order", order_id="o", amount_minor=3116, currency="EUR"),
             [(200, fixture("duffel_get_order_awaiting")), (301, {})], FAILED, "redirect"),
        Case("a host off the allow-list never opens a connection", "duffel",
             Call("pay_order", order_id="o", amount_minor=3116, currency="EUR"),
             [HostNotAllowed("'evil.example' is not on the gateway allow-list")],
             FAILED, "blocked by the gateway allow-list"),
    ]


def main() -> int:
    """Run every case, print the table and return 1 on any mismatch."""
    creds = Credentials(serpapi_key="k" * 20, duffel_token="duffel_test_" + "t" * 20)
    rows, failures = [], 0

    for case in cases():
        transport = FixtureTransport(answers=list(case.answers))
        execute = live_executor(case.world, creds, transport)
        result = safe_execute(execute, case.call)      # the gateway's own guard

        ok = result.outcome is case.expect
        detail = result.error or ""
        if ok and case.expect_in_error:
            ok = case.expect_in_error in detail
        if ok and case.check is not None:
            ok = bool(result.payload) and case.check(dict(result.payload))
        if not ok:
            failures += 1
        rows.append((case.kind, case.name, case.expect.value, result.outcome.value,
                     (detail or "-")[:64], ok))

    width = max(len(r[1]) for r in rows)
    print(f"{'kind':8} {'case'.ljust(width)}  {'expected':10} {'got':10} detail")
    print("-" * (8 + width + 36))
    for kind, name, expected, got, detail, ok in rows:
        mark = " " if ok else "  <-- MISMATCH"
        print(f"{kind:8} {name.ljust(width)}  {expected:10} {got:10} {detail}{mark}")

    tolerated = sum(1 for r in rows if r[0] == "form" and r[5])
    refused = sum(1 for r in rows if r[0] == "meaning" and r[5])
    print(f"\n{len(rows)} cases: {tolerated} form deviations accepted, "
          f"{refused} meaning deviations refused by name, {failures} mismatches")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
