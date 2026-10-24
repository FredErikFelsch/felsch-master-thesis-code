"""World B: Duffel, the full transactional chain, normalised to the canonical contract.

Every function here is pure: a parsed provider body goes in, a canonical payload or a
tuple of Missing comes out. Nothing does I/O, so the whole contract is testable against
the recorded fixtures without a network and without a credential.

The shape of this module follows what the real test-mode API returns rather than its
documentation:

    offer     id, total_amount as a decimal string, total_currency, owner.iata_code,
              expires_at, payment_requirements.requires_instant_payment
    order     id, booking_reference, offer_id, type, total_amount, total_currency,
              payment_status.awaiting_payment, .payment_required_by, .paid_at, documents
    refusal   errors[].code, e.g. payment_amount_does_not_match_order_amount

A free choice of payee is not modelled, because Duffel pays one order and the counterparty
follows from that order rather than from an argument. A `recipient` invented here to mirror
the mock would create an authorisation surface the real provider does not have. The live
binding is the chain of identifiers below.
"""
from __future__ import annotations

import re
from typing import Any

from .normalize import Missing, collect, currency, flag, items, minor_units, pick, text

#: The refusals the provider raises for the bindings the monitor enforces, as observed in
#: test mode. This set is documentation only and no code reads it: every 4xx is FAILED
#: (`world._result`), and the codes in a refusal are quoted through `refusal_codes`.
VALIDATION_CODES = frozenset({
    "payment_amount_does_not_match_order_amount",
    "payment_currency_does_not_match_order_currency",
    "order_type_not_eligible_for_payment",
})


#: What a provider refusal code looks like. Anything else (a sentence in `title`, a long or
#: multi line string) is free text from outside the trust boundary and reaches the agent
#: through the refusal message, so it is dropped here and the caller falls back to the status.
_REFUSAL_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}", re.ASCII)
_MAX_REFUSAL_CODES = 8


def refusal_codes(body: Any) -> tuple[str, ...]:
    """Return the provider's own codes for why it refused: code-shaped words only, at most 8."""
    codes = []
    for err in items(body, "errors"):
        for candidate in (pick(err, "code"), pick(err, "title")):
            if isinstance(candidate, str) and _REFUSAL_CODE.fullmatch(candidate):
                codes.append(candidate)
                break
        if len(codes) >= _MAX_REFUSAL_CODES:
            break
    return tuple(codes)


def _carrier(offer_or_order: Any) -> Any:
    """Return the operating airline, preferring the owner over the first segment's carrier.

    Both are read because either may be absent, and neither is read by position beyond
    the first segment of the first slice, which is what a one-way single-segment offer
    is. A multi-segment itinerary would carry several, and the policy would then need to
    say which one authorises the payment. That is out of scope while the chain is one
    segment.
    """
    return pick(offer_or_order, "owner", "iata_code") or pick(
        offer_or_order, "slices", 0, "segments", 0, "marketing_carrier", "iata_code")


#: Carriers whose offers claim `requires_instant_payment: false` but whose hold orders
#: Duffel refuses in test mode. The provenance is recorded because the flag itself is
#: wrong for them:
#:
#:   IB  POST /air/orders type=hold -> 422 invalid_order_create_type,
#:       "The specified `type` was incorrect." Observed repeatedly, while BA, AA and ZZ
#:       held on the same route.
#:
#: Without this entry nothing unsafe happens, because the refusal is a clean FAILED with no
#: effect. The entry only stops the adapter from offering a hold it knows will be refused.
HOLD_UNSUPPORTED_CARRIERS = frozenset({"IB"})


def offer(body: Any) -> tuple[dict, tuple[Missing, ...]]:
    """Normalise one offer, as `select` reports it. `body` is the `data` object of the response."""
    payload, missing = collect(
        offer_id=text(pick(body, "id"), "offer.id"),
        price_minor=minor_units(pick(body, "total_amount"), "offer.total_amount"),
        currency=currency(pick(body, "total_currency"), "offer.total_currency"),
        carrier=text(_carrier(body), "offer.owner.iata_code"),
    )
    # Not security-relevant, so absence is recorded rather than refused. These describe
    # the window the provider gives. The policy binds on the values above.
    payload["expires_at"] = pick(body, "expires_at")
    # The provider's flag, and not a carrier known to refuse holds despite it.
    payload["holdable"] = (pick(body, "payment_requirements", "requires_instant_payment") is False
                           and payload.get("carrier") not in HOLD_UNSUPPORTED_CARRIERS)
    payload["payment_required_by"] = pick(body, "payment_requirements", "payment_required_by")
    return payload, missing


#: Duffel's prefix for test-mode access tokens. A live token begins `duffel_live_`.
TEST_TOKEN_PREFIX = "duffel_test_"


class LiveModeRefused(ValueError):
    """A Duffel credential that is not a test-mode token. The adapter does not start."""


def require_test_mode(token: str | None) -> None:
    """Refuse every Duffel credential except a test-mode token.

    The evaluation claims Duffel Test Mode, so the adapter enforces it instead of
    assuming it. A live token in OpenBao would otherwise turn every approved payment
    into real money without any other part of the system noticing. The check runs where
    the executor is built, before any transport exists, so a refused token does not reach
    the network. The message does not contain the token.

    Raises:
        LiveModeRefused: the token is missing its test-mode prefix.
    """
    if not isinstance(token, str) or not token.startswith(TEST_TOKEN_PREFIX):
        raise LiveModeRefused(
            f"the Duffel credential is not a test-mode token (expected prefix "
            f"{TEST_TOKEN_PREFIX!r}), and this deployment only runs against Duffel Test Mode")


#: The most offers one search observes. The search facts (offer ids, prices, currencies)
#: travel in the signed state envelope, and the envelope travels base64-encoded as one
#: string in the runner's execution line, which the canonical wire bounds at
#: `booking_v1.freeze.MAX_STR` (10 000 characters). A real search with 93 offers exceeded it
#: and the runner refused the next step (fail-closed, no effect). 20 offers keep the
#: envelope at roughly a third of the bound. This is a deployment parameter of the trusted
#: adapter, not of the agent and not of the policy.
MAX_OFFERS = 20


def trusted_configuration() -> dict[str, str]:
    """Return the adapter settings a viewer must not mistake for something the human approved.

    Returns:
        Label -> value, shown apart from the approved policy.
    """
    return {
        "provider": (f"Duffel Test Mode, enforced: the gateway refuses any token without the "
                     f"{TEST_TOKEN_PREFIX!r} prefix (no real money)"),
        "offer window": f"cheapest {MAX_OFFERS} holdable offers per search (MAX_OFFERS)",
        "hold exceptions": (", ".join(sorted(HOLD_UNSUPPORTED_CARRIERS))
                            + " never offered: refuse holds in test mode"),
    }


def offers(body: Any) -> tuple[dict, tuple[Missing, ...]]:
    """Normalise the bookable offers of an offer request, as `search` reports them.

    Bookable means what this world's flow can act on: `book` creates a hold order and
    `pay_order` settles it later, so an offer that requires instant payment is not
    reported. Every airline is reported except those in `HOLD_UNSUPPORTED_CARRIERS`.
    Holds were booked on ZZ, AA and BA.

    A malformed individual offer does not invalidate the search. It is dropped and
    counted. Search produces no authorisation-relevant fact on its own, and a partial
    catalogue is still a truthful observation of what was on offer. An empty result is
    reported as such rather than as a refusal, because "no flights" is an answer.

    The observation is bounded deterministically: the bookable offers are ordered by
    `(price_minor, offer_id)` and the first `MAX_OFFERS` are reported. The monitor binds
    `select` to the offers the agent was shown, so what the agent may choose and what it
    saw are one set. `offers_total` counts the well-formed offers, `offers_bookable` those
    that can be held and `malformed_offers` the dropped ones.
    """
    good, dropped = [], []
    for raw in items(body, "data", "offers"):
        payload, missing = offer(raw)
        (good if not missing else dropped).append(payload if not missing else missing)
    bookable = [o for o in good if o.get("holdable") is True]
    shown = sorted(bookable, key=lambda o: (o["price_minor"], o["offer_id"]))[:MAX_OFFERS]
    return {"offers": tuple(shown), "offer_count": len(shown), "offers_total": len(good),
            "offers_bookable": len(bookable), "malformed_offers": len(dropped)}, ()


def order(body: Any) -> tuple[dict, tuple[Missing, ...]]:
    """Normalise an order, as `book` and the pre-payment read report it.

    `awaiting_payment` is strict: it decides whether an irreversible step is still open,
    so a missing or non-boolean value is a refusal rather than an assumption.
    """
    payload, missing = collect(
        order_id=text(pick(body, "id"), "order.id"),
        price_minor=minor_units(pick(body, "total_amount"), "order.total_amount"),
        currency=currency(pick(body, "total_currency"), "order.total_currency"),
        carrier=text(_carrier(body), "order.owner.iata_code"),
        awaiting_payment=flag(pick(body, "payment_status", "awaiting_payment"),
                              "order.payment_status.awaiting_payment"),
    )
    payload["booking_ref"] = pick(body, "booking_reference")
    payload["offer_id"] = pick(body, "offer_id")
    payload["order_type"] = pick(body, "type")
    payload["payment_required_by"] = pick(body, "payment_status", "payment_required_by")
    payload["paid_at"] = pick(body, "payment_status", "paid_at")
    payload["documents"] = len(items(body, "documents"))
    return payload, missing


#: The payment states the provider documents. Only `succeeded` is a payment. `failed` and
#: `cancelled` are known to have moved no money. Anything else (`pending`, a state added
#: later) leaves the outcome open.
PAYMENT_SUCCEEDED = "succeeded"
PAYMENT_NOT_MADE = frozenset({"failed", "cancelled"})


def payment(body: Any, order_id: str, amount_minor: int | None = None,
            currency_code: str | None = None) -> tuple[dict, tuple[Missing, ...]]:
    """Normalise a payment, as `pay_order` reports it.

    Everything is read back from the provider's payment object: its status, the order it
    settles, the amount and the currency. `paid` is True only when the status is `succeeded`
    and the order, the amount and the currency are the ones that were authorised. A payment
    that succeeded for something else is not "paid" in the sense the policy binds, and the
    caller maps it to an uncertain outcome rather than a confirmation. `status` is strict: a
    missing status is a refusal to describe the payment, not an assumption of success.

    Args:
        body: The parsed payment response.
        order_id: The authorised order.
        amount_minor: The authorised amount, or None to leave it unchecked.
        currency_code: The authorised currency, or None to leave it unchecked.

    Returns:
        The canonical payload and the refusals, if any.
    """
    payload, missing = collect(
        amount_minor=minor_units(pick(body, "data", "amount"), "payment.amount"),
        currency=currency(pick(body, "data", "currency"), "payment.currency"),
        status=text(pick(body, "data", "status"), "payment.status"),
        order_id=text(pick(body, "data", "order_id"), "payment.order_id"),
    )
    if not missing:
        payload["paid"] = (payload["status"] == PAYMENT_SUCCEEDED
                           and payload["order_id"] == order_id
                           and (amount_minor is None or payload["amount_minor"] == amount_minor)
                           and (currency_code is None or payload["currency"] == currency_code))
    payload["payment_id"] = pick(body, "data", "id")
    return payload, missing
