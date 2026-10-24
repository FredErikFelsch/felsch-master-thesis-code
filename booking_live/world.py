"""The live executor: real counterparties behind the executor signature of V2.

`live_executor` returns an executor the gateway calls in place of `v2_executor`. The
monitor, the policy compiler, the Authority and the attestation path are unchanged. Only
what is behind the enforcement boundary differs.

Outcome semantics:

    2xx                       CONFIRMED, if the response also normalises
    2xx, does not normalise   UNCERTAIN for an effectful step: the counterparty acted,
                              but what it did cannot be described, so no fact is recorded
    3xx                       FAILED: a redirect is not followed (`RequestsTransport`)
    4xx                       FAILED: the provider refused before acting. Its refusal
                              codes are quoted (see `duffel.refusal_codes`)
    5xx or transport error    FAILED for a read, UNCERTAIN for an effectful step
    executor raises           UNCERTAIN, enforced by booking_v1.effects.safe_execute

A read cannot have half happened, so it is not UNCERTAIN. `book` and `pay_order` can be:
the request may have arrived and been processed while the answer was lost. The durable
two-phase dispatch of `booking_v4.durable` exists for this case, which against a real
provider is a real possibility rather than a modelling assumption. The reads that
`book` and `pay_order` make before their effect are FAILED when they fail, because
nothing has been sent at that point.

Credentials arrive as a value and this module does not read them from the environment.
The place that holds them stays outside the executor, so OpenBao can take it over without
a change to this file.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from booking_v1.effects import EffectOutcome, EffectResult
from booking_v4.budgets import PROVIDER_REQUEST_TIMEOUT_S

from . import duffel, serpapi
from .normalize import Missing, reason

DUFFEL_BASE = "https://api.duffel.com/air"
SERPAPI_ENDPOINT = "https://serpapi.com/search"
DUFFEL_VERSION = "v2"

#: The hosts the gateway may speak to, enforced here rather than by the network layer.
#: A Kubernetes NetworkPolicy works on addresses and cannot name `api.duffel.com`, so
#: the network can only grant HTTPS egress in general. Provider identity is therefore an
#: application-layer property, and this is where it lives.
ALLOWED_HOSTS = frozenset({"api.duffel.com", "serpapi.com"})


class HostNotAllowed(RuntimeError):
    """A request to a host the gateway may not speak to. Nothing was sent."""


#: Tools without an external effect. A failed read is FAILED, not UNCERTAIN.
READS = ("search", "select", "refresh")
#: Tools the agent may propose. `refresh` is not among them, because it is an observation
#: the gateway makes on its own behalf immediately before the irreversible step. An agent
#: that could schedule or skip it would control the check that binds the payment to the
#: provider's current order.
AGENT_TOOLS = ("search", "select", "book", "pay_order")
EFFECTFUL = ("book", "pay", "pay_order")

# A fictional passenger. Duffel needs contact details to hold a seat. None of this
# belongs to a real person, and it is only sent to the test-mode account.
PASSENGER = {"given_name": "Ada", "family_name": "Tester", "born_on": "1980-07-24",
             "title": "mrs", "gender": "f", "email": "ada.tester@example.com",
             "phone_number": "+442080160508"}


@dataclass(frozen=True)
class Credentials:
    """The provider credentials the gateway holds and the agent does not see.

    They are read from a `SecretSource` (OpenBao in the cluster). `repr` omits both fields.
    """

    serpapi_key: str | None = field(default=None, repr=False)
    duffel_token: str | None = field(default=None, repr=False)


#: The most a provider answer may weigh. A Duffel offer list is a few hundred kilobytes, so
#: this leaves room and still keeps one answer from filling the gateway's memory.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class ResponseTooLarge(RuntimeError):
    """The provider answered with more than `MAX_RESPONSE_BYTES`. The outcome is not established."""


def _read_bounded(response: Any) -> bytes:
    """Read the body of `response` in chunks and refuse it as soon as it passes the bound."""
    chunks, size = [], 0
    for chunk in response.iter_content(65536):
        size += len(chunk)
        if size > MAX_RESPONSE_BYTES:
            raise ResponseTooLarge(f"answer exceeds {MAX_RESPONSE_BYTES} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


class Transport(Protocol):
    """One HTTP exchange. Raising means the outcome could not be established."""

    def request(self, method: str, url: str, *, headers: Mapping[str, str] | None = None,
                params: Mapping[str, Any] | None = None,
                json_body: Any | None = None) -> tuple[int, Any]: ...


@dataclass(frozen=True)
class RequestsTransport:
    """The real transport, with the two controls the network layer cannot provide.

    The destination is checked here. Every request's host must be on the allow-list
    before a connection is opened, because once the cluster grants HTTPS egress in
    general, this is the only place that knows which provider was meant.

    Redirects are not followed. `requests` follows them by default, and a provider (or
    anyone who can answer for it) could then move the request, with its Authorization
    header, to a host the allow-list does not name. A 3xx is returned as it is and
    refused upstream. If a provider legitimately starts redirecting, the fix is a new
    entry on the allow-list.
    """

    timeout_s: float = PROVIDER_REQUEST_TIMEOUT_S
    allowed_hosts: frozenset[str] = ALLOWED_HOSTS

    def _check(self, url: str) -> None:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme != "https":
            raise HostNotAllowed(f"{parts.scheme!r} is not https")
        if host not in self.allowed_hosts:
            raise HostNotAllowed(f"{host!r} is not on the gateway allow-list")

    def request(self, method: str, url: str, *, headers=None, params=None,
                json_body=None) -> tuple[int, Any]:
        """Send one HTTPS request to an allowed host and return the status and the parsed JSON body.

        Raises:
            HostNotAllowed: when the URL is not https or its host is not on the allow-list.
            ResponseTooLarge: when the answer exceeds `MAX_RESPONSE_BYTES`.
        """
        import requests
        self._check(url)
        response = requests.request(method.upper(), url, headers=dict(headers or {}),
                                    params=dict(params or {}), json=json_body,
                                    timeout=self.timeout_s, allow_redirects=False, stream=True)
        try:
            raw = _read_bounded(response)
        finally:
            response.close()
        text = raw.decode(response.encoding or "utf-8", errors="replace")
        try:
            return response.status_code, json.loads(text)
        except ValueError:
            return response.status_code, {"_non_json_body": text[:2000]}


def _confirmed(payload: Mapping[str, Any]) -> EffectResult:
    return EffectResult(outcome=EffectOutcome.CONFIRMED, payload=dict(payload))


def _refused(tool: str, status: int, body: Any) -> EffectResult:
    """Report a provider refusal: no effect, quoted in the provider's own codes."""
    codes = duffel.refusal_codes(body)
    detail = ", ".join(codes) if codes else f"http {status}"
    return EffectResult(outcome=EffectOutcome.FAILED, error=f"{tool} refused: {detail}")


def _unobservable(tool: str, missing: tuple[Missing, ...]) -> EffectResult:
    """Report an answer that cannot be turned into a fact.

    For an effectful step this is UNCERTAIN and not FAILED: the effect may have happened
    but cannot be described, so nothing is recorded and the run is parked for
    reconciliation rather than advanced or declared clean.
    """
    outcome = EffectOutcome.UNCERTAIN if tool in EFFECTFUL else EffectOutcome.FAILED
    return EffectResult(outcome=outcome, error=f"{tool} {reason(missing)}")


def _unreachable(tool: str, detail: str) -> EffectResult:
    """Report a lost or failed exchange: FAILED for a read, UNCERTAIN for an effectful step."""
    outcome = EffectOutcome.UNCERTAIN if tool in EFFECTFUL else EffectOutcome.FAILED
    return EffectResult(outcome=outcome, error=f"{tool} outcome not established: {detail}")


def _result(tool: str, status: int, body: Any,
            normalize: Callable[[Any], tuple[dict, tuple[Missing, ...]]]) -> EffectResult:
    """Map a status and a body to an effect outcome, using `normalize` for an accepted answer."""
    if status >= 500:
        return _unreachable(tool, f"http {status}")
    if status >= 400:
        return _refused(tool, status, body)
    if status >= 300:
        # Not followed, because a redirect would move the request and its Authorization
        # header to a host the allow-list does not name.
        return EffectResult(outcome=EffectOutcome.FAILED,
                            error=f"{tool} refused: redirect ({status}) not followed")
    payload, missing = normalize(body)
    if missing:
        return _unobservable(tool, missing)
    return _confirmed(payload)


def _payment_result(tool: str, status: int, body: Any, order_id: str,
                    amount_minor: int, curr: str) -> EffectResult:
    """Map the provider's payment answer to an outcome.

    HTTP-level answers go through `_result`. For an accepted request the payment state
    decides: only `succeeded` for the authorised order, amount and currency is CONFIRMED.
    `failed` and `cancelled` moved no money (FAILED). `pending`, an unknown state, or a
    succeeded payment that is not the authorised one leave the outcome open (UNCERTAIN, the
    run is parked for reconciliation).
    """
    if status >= 300:
        return _result(tool, status, body, lambda b: duffel.payment(b, order_id, amount_minor, curr))
    payload, missing = duffel.payment(body, order_id, amount_minor, curr)
    if missing:
        return _unobservable(tool, missing)
    state = payload["status"]
    if state in duffel.PAYMENT_NOT_MADE:
        return EffectResult(outcome=EffectOutcome.FAILED, error=f"{tool}: the payment is {state}")
    if state != duffel.PAYMENT_SUCCEEDED:
        return EffectResult(outcome=EffectOutcome.UNCERTAIN,
                            error=f"{tool} outcome not established: the payment is {state!r}")
    if not payload["paid"]:
        return EffectResult(outcome=EffectOutcome.UNCERTAIN, error=(
            f"{tool} outcome not established: the payment succeeded for {payload['order_id']} "
            f"{payload['amount_minor']} {payload['currency']}, authorised {order_id} {amount_minor} {curr}"))
    return _confirmed(payload)


def _verify_settled(transport: Transport, headers: Mapping[str, str], order_id: str,
                    amount_minor: int, curr: str, accepted: EffectResult) -> EffectResult:
    """Read the order back after an accepted payment.

    A payment object that says `succeeded` is the provider's claim about the payment. The
    order is the fact the booking depends on, so it is read once more, on the gateway's own
    behalf, and must show the same order id, the authorised total and currency, and no longer
    be awaiting payment. Any shortfall, including a failed read, leaves the outcome UNCERTAIN,
    because money may have moved. The run is then parked for reconciliation and not reported
    as clean or as "no effect".
    """
    try:
        status, fresh = transport.request("GET", f"{DUFFEL_BASE}/orders/{order_id}",
                                          headers=headers)
    except Exception as exc:  # a lost read after an accepted payment is still not "no effect"
        return _unreachable("pay_order", f"post-payment read failed: {type(exc).__name__}")
    if status >= 300:
        return _unreachable("pay_order", f"post-payment read http {status}")
    observed, missing = duffel.order(fresh.get("data") if isinstance(fresh, dict) else None)
    if missing:
        return _unobservable("pay_order", missing)
    if (observed["order_id"] != order_id or observed["price_minor"] != amount_minor
            or observed["currency"] != curr or observed["awaiting_payment"] is not False):
        return EffectResult(outcome=EffectOutcome.UNCERTAIN, error=(
            f"pay_order outcome not established: the payment succeeded but the order reads "
            f"{observed['order_id']} {observed['price_minor']} {observed['currency']} "
            f"awaiting_payment={observed['awaiting_payment']}"))
    return accepted


def _duffel_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Duffel-Version": DUFFEL_VERSION,
            "Accept": "application/json", "Content-Type": "application/json"}


#: The form of a provider identifier (`off_0000AzVFQ3W8vgQKuHkP7h`, `ord_...`). The agent names
#: an offer or an order and the name becomes a URL path segment, so anything with a separator,
#: dots, a query or an encoded slash is refused before a request exists.
_IDENTIFIER = re.compile(r"[A-Za-z0-9_]{1,64}", re.ASCII)


def _bad_identifier(tool: str, args: Mapping[str, Any]) -> str | None:
    """Return the name of the argument the tool puts into a URL if it is not an identifier, else None."""
    if tool in ("select", "book"):
        name, value = "offer_id", args.get("offer_id") or args.get("flight")
    elif tool in ("refresh", "pay_order"):
        name, value = "order_id", args.get("order_id")
    else:
        return None
    return None if isinstance(value, str) and _IDENTIFIER.fullmatch(value) else name


def _duffel(tool: str, args: Mapping[str, Any], creds: Credentials,
            transport: Transport) -> EffectResult:
    """Execute one tool call in world B (Duffel).

    One tool call is one effect, even where it takes more than one request.
    """
    if not creds.duffel_token:
        return _unreachable(tool, "no duffel credential")
    bad = _bad_identifier(tool, args)
    if bad is not None:
        return EffectResult(outcome=EffectOutcome.FAILED,
                            error=f"{tool} refused locally: {bad} is not an identifier")
    headers = _duffel_headers(creds.duffel_token)

    if tool == "search":
        body = {"data": {
            "slices": [{"origin": args.get("origin"), "destination": args.get("destination"),
                        "departure_date": args.get("departure_date")}],
            "passengers": [{"type": "adult"}], "cabin_class": args.get("cabin", "economy")}}
        status, response = transport.request("POST", f"{DUFFEL_BASE}/offer_requests",
                                             headers=headers, params={"return_offers": "true"},
                                             json_body=body)
        return _result(tool, status, response, duffel.offers)

    if tool == "select":
        offer_id = args.get("offer_id") or args.get("flight")
        status, response = transport.request("GET", f"{DUFFEL_BASE}/offers/{offer_id}",
                                             headers=headers,
                                             params={"return_available_services": "false"})
        return _result(tool, status, response, lambda b: duffel.offer(b.get("data")))

    if tool == "book":
        offer_id = args.get("offer_id") or args.get("flight")
        # The passenger ids belong to the offer, so they are read from it rather than
        # taken from the agent. This GET has no effect. The effect is the POST below, so a
        # failed GET is FAILED.
        try:
            status, offer_body = transport.request("GET", f"{DUFFEL_BASE}/offers/{offer_id}",
                                                   headers=headers)
        except HostNotAllowed:
            raise
        except Exception as exc:
            return EffectResult(outcome=EffectOutcome.FAILED,
                                error=f"book not attempted: offer read failed: {type(exc).__name__}")
        if status >= 400:
            return _refused(tool, status, offer_body)
        offer_data = offer_body.get("data") if isinstance(offer_body, dict) else None
        passengers = offer_data.get("passengers") if isinstance(offer_data, dict) else None
        ids = [p.get("id") for p in (passengers or [])]
        if not ids:
            return _unobservable(tool, (Missing("offer.passengers", "none returned"),))
        body = {"data": {"type": "hold", "selected_offers": [offer_id],
                         "passengers": [{**PASSENGER, "id": pid} for pid in ids]}}
        status, response = transport.request("POST", f"{DUFFEL_BASE}/orders",
                                             headers=headers, json_body=body)
        return _result(tool, status, response, lambda b: duffel.order(b.get("data")))

    if tool == "refresh":
        order_id = args.get("order_id")
        status, response = transport.request("GET", f"{DUFFEL_BASE}/orders/{order_id}",
                                             headers=headers)
        return _result(tool, status, response, lambda b: duffel.order(b.get("data")))

    if tool == "pay":
        # The mock's payment names a payee. This world has none to name, and mapping the
        # call across would hide the difference the live evaluation is about.
        return EffectResult(outcome=EffectOutcome.FAILED, error=(
            "pay unavailable in world B: a payment settles an order here, "
            "use pay_order(order_id, amount_minor, currency)"))

    if tool == "pay_order":
        order_id = args.get("order_id")
        amount_minor = args.get("amount_minor")
        curr = args.get("currency")
        if not isinstance(amount_minor, int) or isinstance(amount_minor, bool):
            return EffectResult(outcome=EffectOutcome.FAILED,
                                error="pay_order refused locally: amount_minor is not an integer")

        # The gateway reads the order once more, on its own behalf, immediately before
        # the irreversible step. The monitor has already bound this amount to the booking
        # it observed, but it cannot know whether the order changed since. The authorised
        # value is therefore checked against the provider here, inside the trusted base,
        # and a payment that no longer matches is not sent.
        #
        # This read is not an agent step. The agent proposes search, select, book and
        # pay_order and cannot schedule, skip or influence it.
        #
        # A failed pre-payment read is FAILED and not UNCERTAIN, whether the provider
        # refused it or the transport failed: the payment has not been sent at this point,
        # so its outcome is known even though the read's is not. Treating it as UNCERTAIN
        # would park a run that is known to be clean. HostNotAllowed is passed on to
        # `live_executor`, which reports it as FAILED with its own message.
        try:
            status, fresh = transport.request("GET", f"{DUFFEL_BASE}/orders/{order_id}",
                                              headers=headers)
        except HostNotAllowed:
            raise
        except Exception as exc:
            return EffectResult(outcome=EffectOutcome.FAILED,
                                error=f"pay not attempted: pre-payment read failed: {type(exc).__name__}")
        if status >= 400:
            detail = ", ".join(duffel.refusal_codes(fresh)) or f"http {status}"
            return EffectResult(outcome=EffectOutcome.FAILED,
                                error=f"pay not attempted: pre-payment read failed: {detail}")
        observed, missing = duffel.order(fresh.get("data") if isinstance(fresh, dict) else None)
        if missing:
            return EffectResult(outcome=EffectOutcome.FAILED, error=(
                f"pay not attempted: pre-payment read {reason(missing)}"))
        if observed["price_minor"] != amount_minor or observed["currency"] != curr:
            return EffectResult(outcome=EffectOutcome.FAILED, error=(
                f"pay refused before the effect: the order moved (authorised "
                f"{amount_minor} {curr}, observed {observed['price_minor']} "
                f"{observed['currency']} on {order_id})"))
        if observed["awaiting_payment"] is not True:
            return EffectResult(outcome=EffectOutcome.FAILED, error=(
                f"pay refused before the effect: {order_id} is not awaiting payment"))

        amount = f"{amount_minor // 100}.{amount_minor % 100:02d}"
        body = {"data": {"order_id": order_id,
                         "payment": {"type": "balance", "amount": amount, "currency": curr}}}
        status, response = transport.request("POST", f"{DUFFEL_BASE}/payments",
                                             headers=headers, json_body=body)
        result = _payment_result(tool, status, response, order_id, amount_minor, curr)
        if result.outcome is not EffectOutcome.CONFIRMED:
            return result
        return _verify_settled(transport, headers, order_id, amount_minor, curr, result)

    return EffectResult(outcome=EffectOutcome.FAILED, error=f"unknown tool {tool!r}")


def _serpapi(tool: str, args: Mapping[str, Any], creds: Credentials,
             transport: Transport) -> EffectResult:
    """Execute one tool call in world A (SerpApi), which offers search and select and sells nothing.

    Both tools send a search, which costs one provider request each. `select` repeats it
    with the origin, destination and date the call carries, or with the deployment defaults
    that `context.with_context` fills in when it carries none. The currency the response
    echoes must be the requested one (EUR unless the call names another), otherwise the
    call is refused.
    """
    if not creds.serpapi_key:
        return _unreachable(tool, "no serpapi credential")
    if tool in ("book", "pay", "pay_order"):
        return EffectResult(outcome=EffectOutcome.FAILED,
                            error=f"{tool} unavailable: world A is a search service")
    if tool not in ("search", "select"):
        # Checked before the request, so an unknown tool does not spend a metered search.
        return EffectResult(outcome=EffectOutcome.FAILED, error=f"unknown tool {tool!r}")

    params = {"engine": "google_flights", "departure_id": args.get("origin"),
              "arrival_id": args.get("destination"),
              "outbound_date": args.get("departure_date"),
              "currency": args.get("currency", "EUR"), "type": "2", "hl": "en", "gl": "de",
              "no_cache": "true", "api_key": creds.serpapi_key}
    status, response = transport.request("GET", SERPAPI_ENDPOINT, params=params)
    requested = params["currency"]

    if tool == "search":
        return _result(tool, status, response, lambda b: serpapi.offers(b, requested))
    offer_id = args.get("offer_id") or args.get("flight")
    return _result(tool, status, response, lambda b: serpapi.select(b, offer_id, requested))


def live_executor(world: str, creds: Credentials,
                  transport: Transport | None = None) -> Callable[[Any], EffectResult]:
    """Build an executor over a real counterparty, with the signature of `v2_executor`.

    Args:
        world: `"duffel"` for the full transactional chain, `"serpapi"` for the
            production search service.
        creds: The credentials the gateway holds. This function does not read the
            environment.
        transport: Injected so the whole contract is testable against the recorded
            fixtures without a network and without a credential.

    Returns:
        The executor, which maps a call to an `EffectResult`.

    Raises:
        ValueError: for an unknown world.
        duffel.LiveModeRefused: for a Duffel credential that is not a test-mode token.
    """
    if world not in ("duffel", "serpapi"):
        raise ValueError(f"unknown world {world!r}")
    if world == "duffel":
        # Every Duffel executor is built here (gateway, local demo, diagnosis), so a
        # non-test token is refused before a transport exists.
        duffel.require_test_mode(creds.duffel_token)
    http = transport or RequestsTransport()
    handler = _duffel if world == "duffel" else _serpapi

    def _execute(call) -> EffectResult:
        tool = getattr(call, "tool", None)
        args = dict(getattr(call, "args", {}) or {})
        try:
            return handler(tool, args, creds, http)
        except HostNotAllowed as blocked:
            # Refused before a connection was opened, so the outcome is known.
            return EffectResult(outcome=EffectOutcome.FAILED,
                                error=f"{tool} blocked by the gateway allow-list: {blocked}")
        except Exception as exc:                      # transport failure, not a refusal
            return _unreachable(tool or "?", type(exc).__name__)

    return _execute
