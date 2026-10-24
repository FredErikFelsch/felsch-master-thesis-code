"""World A: a production search service, normalised to the canonical contract.

The functions are pure, as in `duffel`, and the shape follows what the real API returns.
Three observations of the API shape this module:

There is no stable identifier. Two identical searches seconds apart returned the same 29
itineraries with the same carriers and the same prices, but a different `booking_token`
each time. The token is an artefact of the search, not the identity of an offer. It is
carried as an opaque `source_handle` and not used as the thing a later step binds to.
Identity in world A is derived from observed values: the first flight number, the price
and the currency. Itineraries that share all three cannot be told apart.

The price is a whole-unit number, not a decimal string. SerpApi answered `120` for 120 EUR,
so `minor_units` alone is the whole conversion. An extra factor of 100 would be a
conversion error that looks like a policy violation from the outside.

There is no IATA code. The carrier arrives as a display name, "Lufthansa". Mapping that to
`LH` would need an invented table, so the name is recorded as it was observed. World A is
evaluated on its own and not against world B, so the two need no common spelling.

World A ends after `select`. Selling a ticket needs a KYC-verified travel agency, which
this work cannot obtain, so there is no `book` and no `pay` here. The attack this world
carries is the misuse of a metered capability, not a forged payment.
"""
from __future__ import annotations

from typing import Any

from .normalize import Missing, collect, currency, items, minor_units, pick, text


def _handle(flight_number: str, price_minor: int, curr: str) -> str:
    """Derive an offer identity from observed values. It is not an identifier from the provider.

    The `observed:` prefix keeps a later reader from mistaking it for something the
    counterparty would recognise. It exists because a policy needs to name the offer the
    human approved, and the provider offers nothing stable to name it by.
    """
    return f"observed:{flight_number.replace(' ', '')}@{price_minor}{curr}"


def offer(raw: Any, echoed_currency: str) -> tuple[dict, tuple[Missing, ...]]:
    """Normalise one itinerary of a search result.

    The currency is not in the itinerary. It is a property of the request, and the one
    passed in is the one the response echoes in `search_parameters`.

    Args:
        raw: One entry of `best_flights` or `other_flights`.
        echoed_currency: The currency the response echoes.

    Returns:
        The canonical payload and the refusals, if any.
    """
    payload, missing = collect(
        price_minor=minor_units(pick(raw, "price"), "offer.price"),
        currency=currency(echoed_currency, "search_parameters.currency"),
        carrier=text(pick(raw, "flights", 0, "airline"), "offer.flights[0].airline"),
        flight_number=text(pick(raw, "flights", 0, "flight_number"),
                           "offer.flights[0].flight_number"),
    )
    if not missing:
        payload["offer_id"] = _handle(payload["flight_number"], payload["price_minor"],
                                      payload["currency"])
    payload["source_handle"] = pick(raw, "booking_token")
    payload["legs"] = len(items(raw, "flights"))
    return payload, missing


def offers(body: Any, requested_currency: str | None = None) -> tuple[dict, tuple[Missing, ...]]:
    """Normalise every itinerary of a search, best and other, as `search` reports it.

    The currency comes from the echoed `search_parameters`. When `requested_currency` is
    given, an echo that names another currency refuses the whole search, because every
    price in it would be in a currency the policy did not bind. A malformed itinerary is
    dropped and counted rather than invalidating the whole observation, as in world B.

    Args:
        body: The parsed search response.
        requested_currency: The currency the request asked for, or None to skip the check.

    Returns:
        The canonical payload and the refusals, if any.
    """
    echoed = pick(body, "search_parameters", "currency")
    curr = currency(echoed, "search_parameters.currency")
    if isinstance(curr, Missing):
        return {}, (curr,)
    if requested_currency is not None:
        wanted = currency(requested_currency, "request.currency")
        if isinstance(wanted, Missing):
            return {}, (wanted,)
        if curr != wanted:
            return {}, (Missing("search_parameters.currency",
                                f"echoes {curr!r}, the request asked for {wanted!r}"),)

    good, dropped = [], 0
    for raw in items(body, "best_flights") + items(body, "other_flights"):
        payload, missing = offer(raw, curr)
        if missing:
            dropped += 1
        else:
            good.append(payload)
    return {"offers": tuple(good), "offer_count": len(good),
            "malformed_offers": dropped, "currency": curr}, ()


def select(body: Any, offer_id: str,
           requested_currency: str | None = None) -> tuple[dict, tuple[Missing, ...]]:
    """Find the offer under `offer_id` in a repeated search.

    World A cannot retrieve a single offer: there is no endpoint and no stable handle to
    retrieve it by. `select` therefore searches again (`world._serpapi`) and looks the
    observed identity up in the fresh result, which costs one more provider request. That
    is weaker than world B, where the provider confirms the offer itself.

    Args:
        body: The parsed response of the repeated search.
        offer_id: The observed identity (`observed:...`) the agent selected.
        requested_currency: Passed on to `offers`.

    Returns:
        The offer and no refusals, or an empty payload and the reason it was not found.
    """
    catalogue, missing = offers(body, requested_currency)
    if missing:
        return {}, missing
    for candidate in catalogue["offers"]:
        if candidate["offer_id"] == offer_id:
            return dict(candidate), ()
    return {}, (Missing("select.offer_id", f"not among the observed offers: {offer_id!r}"),)
