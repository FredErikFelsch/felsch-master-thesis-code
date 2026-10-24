"""The canonical effect classification: which tool of a world causes which kind of effect.

A world adapter speaks its provider's vocabulary (`pay_order`, later perhaps
`charge_ticket`). Everything behind it, the observed world view, the run summary and the
policy admission of the Authority, speaks two canonical kinds only:

    Agent / Policy            pay_order(order_id, amount_minor, currency)
          │
    World description         effects["pay_order"] == PAYMENT
          │
    Summary / admission       counts a payment, knows the world can execute it

A new world is therefore one adapter, one policy and one effect map. Nothing downstream
names its tools.

The map is total over the tools a world serves. A tool without an entry is not read as "no
effect", since that reading would turn a forgotten entry into a payment that is not counted.
A tool that causes no effect says so with `None`, and an unclassified tool is
refused with `WorldSpecError`.
"""
from __future__ import annotations

from typing import Mapping, Optional

#: A durable reservation at the counterparty (an order, a hold, a ticket reservation).
BOOKING = "booking"
#: An irreversible transfer of value that settles a booking.
PAYMENT = "payment"
#: Every canonical kind. `None` in a map means: served, but without an external effect.
KINDS = frozenset({BOOKING, PAYMENT})

#: tool name -> canonical kind, or None for a tool without an external effect.
EffectMap = Mapping[str, Optional[str]]

#: The V2 catalogue (the `mock` world). The live worlds carry theirs in `startup.WORLDS`.
CATALOGUE_EFFECTS: EffectMap = {"search": None, "select": None, "book": BOOKING, "pay": PAYMENT}


class WorldSpecError(RuntimeError):
    """A world description that does not classify a tool it is asked about."""


def classify(effects: EffectMap, tool: str) -> Optional[str]:
    """Return the canonical kind of `tool`, or None when it has no external effect.

    Args:
        effects: The world's effect map.
        tool: The tool to classify.

    Returns:
        BOOKING, PAYMENT or None.

    Raises:
        WorldSpecError: when `tool` has no entry, which is not read as "no effect".
    """
    if tool not in effects:
        raise WorldSpecError(f"tool {tool!r} has no effect classification "
                             f"(classified: {sorted(effects)})")
    return effects[tool]


def validate_effects(effects: EffectMap, flow: tuple[str, ...] = ()) -> None:
    """Check that `effects` only uses canonical kinds and classifies every tool of `flow`.

    Args:
        effects: The world's effect map.
        flow: The tools a policy's flow uses.

    Raises:
        WorldSpecError: naming the unknown kind or the unclassified tools.
    """
    unknown = sorted({k for k in effects.values() if k is not None and k not in KINDS})
    if unknown:
        raise WorldSpecError(f"unknown effect kinds {unknown}, expected one of {sorted(KINDS)} or None")
    missing = [t for t in flow if t not in effects]
    if missing:
        raise WorldSpecError(f"tools without effect classification: {missing}")


def tools_of_kind(effects: EffectMap, kind: str) -> frozenset[str]:
    """Return every tool of `effects` classified as `kind`."""
    return frozenset(t for t, k in effects.items() if k == kind)
