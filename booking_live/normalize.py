"""Tolerant parsing, strict normalisation, and refusals that carry a name.

The monitor-facing contract is stable. Provider responses are not. This module is where
the two meet, and it keeps three things apart that are easy to confuse:

    parse       tolerant   what is in this response? Unknown fields are ignored, not
                           validated, and nothing is read by position
    normalise   strict     is this a well-formed amount, currency, identifier? A value
                           that is absent, mis-shaped or imprecise yields Missing, not a
                           default and not an exception
    bind        elsewhere  does it agree with what was observed earlier? (the monitor)

Strictness is intended. A silent default for a security-relevant value would bypass the
policy, since `price_minor = 0` passes every budget ceiling. A value is therefore either
observed and well formed, or it is `Missing(field, reason)`, and the caller turns that into
an effect outcome that records no fact.

Format variation is tolerated, variation in meaning is not. `"31.16"` and `31.16` are the
same amount written differently, so both are accepted. `"eur"` is EUR in another case, so
it is accepted and normalised. `"Euro"` is not ISO 4217, so it is refused, because guessing
there would invent a value rather than read one.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

_ISO_4217 = re.compile(r"^[A-Za-z]{3}$")

#: A plain amount: ASCII digits, an optional fraction, each part bounded. No sign other than
#: a leading minus (which is then refused as negative), no exponent, no digit separator, no
#: non-ASCII digit. `Decimal(str(raw))` reads all of these, and `1e5000000` costs memory and time.
_PLAIN_AMOUNT = re.compile(r"-?[0-9]{1,12}(?:\.[0-9]{1,12})?", re.ASCII)


@dataclass(frozen=True)
class Missing:
    """A security-relevant value that could not be read, with the reason why.

    The reason makes a refusal diagnosable and citable: "total_amount: sub-cent precision
    '31.165'" names the field and the cause, where "book denied" names neither.
    """

    field: str
    reason: str

    def __str__(self) -> str:
        return f"{self.field}: {self.reason}"


def pick(source: Any, *path: str | int) -> Any:
    """Walk a path through nested mappings and lists, returning None if it does not exist.

    A provider that adds a level, renames a branch or returns a shorter list yields None
    here rather than an exception. The caller decides whether a
    None matters, because only the caller knows whether the field is security-relevant.
    """
    current = source
    for key in path:
        if isinstance(key, int):
            if not isinstance(current, (list, tuple)) or not -len(current) <= key < len(current):
                return None
            current = current[key]
        else:
            if not isinstance(current, Mapping):
                return None
            current = current.get(key)
        if current is None:
            return None
    return current


def items(source: Any, *path: str | int) -> list:
    """Return every element of the list at `path`, or an empty list."""
    found = pick(source, *path)
    return list(found) if isinstance(found, (list, tuple)) else []


def text(raw: Any, field: str) -> str | Missing:
    """Normalise a non-empty string, for example an identifier or a flight number.

    Surrounding whitespace is stripped.
    """
    if raw is None:
        return Missing(field, "absent")
    if not isinstance(raw, str):
        return Missing(field, f"not a string: {type(raw).__name__}")
    stripped = raw.strip()
    if not stripped:
        return Missing(field, "empty")
    return stripped


def currency(raw: Any, field: str) -> str | Missing:
    """Normalise an ISO 4217 alphabetic code, upper-cased.

    Case and surrounding whitespace are format, so they are normalised. Anything else that
    is not three letters is refused, because a provider writing "Euro" or "EUR€" is not a
    case to guess at.
    """
    value = text(raw, field)
    if isinstance(value, Missing):
        return value
    if not _ISO_4217.match(value):
        return Missing(field, f"not an ISO 4217 code: {value!r}")
    return value.upper()


def minor_units(raw: Any, field: str) -> int | Missing:
    """Normalise an amount to integer minor units, from a decimal string or a number.

    Duffel writes `"31.16"`, SerpApi writes `120`. Both are read, because the difference
    is notation. An amount that cannot be represented exactly in minor units is refused,
    because rounding it would silently change the value the policy is about to authorise.

    This assumes a two-decimal currency. A zero-decimal currency such as JPY would need
    the exponent from the currency, which is out of scope while both worlds quote EUR.
    """
    if raw is None:
        return Missing(field, "absent")
    if isinstance(raw, bool):
        return Missing(field, "boolean is not an amount")
    if not isinstance(raw, (str, int, float, Decimal)):
        return Missing(field, f"not an amount: {type(raw).__name__}")
    # Notation first: floats and decimals are written out in positional form, so that only a
    # plain decimal reaches the parser. Anything else is not an amount.
    written = format(raw, "f") if isinstance(raw, Decimal) else repr(raw) if isinstance(raw, float) else str(raw)
    written = written.strip()
    if not _PLAIN_AMOUNT.fullmatch(written):
        return Missing(field, f"not a plain decimal: {written[:40]!r}")
    try:
        value = Decimal(written)
    except (InvalidOperation, ValueError):
        return Missing(field, f"not a decimal: {written[:40]!r}")
    if not value.is_finite():
        return Missing(field, f"not finite: {raw!r}")
    if value < 0:
        return Missing(field, f"negative: {raw!r}")
    shifted = value.scaleb(2)
    if shifted != shifted.to_integral_value():
        return Missing(field, f"sub-cent precision: {raw!r}")
    return int(shifted)


def flag(raw: Any, field: str) -> bool | Missing:
    """Normalise a strict boolean. `"true"`, `1` and `None` are refused, not coerced.

    `awaiting_payment` decides whether an irreversible step is still open, so a truthy
    string must not silently become True.
    """
    if raw is None:
        return Missing(field, "absent")
    if not isinstance(raw, bool):
        return Missing(field, f"not a boolean: {raw!r}")
    return raw


def collect(**fields: Any) -> tuple[dict, tuple[Missing, ...]]:
    """Split normalised fields into the payload and the refusals.

    The caller reports all refusals at once, so one run shows everything that is wrong
    with a response rather than one problem per attempt.

    Returns:
        The values that were read, and every Missing among them.
    """
    payload = {k: v for k, v in fields.items() if not isinstance(v, Missing)}
    missing = tuple(v for v in fields.values() if isinstance(v, Missing))
    return payload, missing


def reason(missing: tuple[Missing, ...]) -> str:
    """Return one readable line naming every field that could not be observed."""
    return "unobservable: " + ", ".join(str(m) for m in missing)
