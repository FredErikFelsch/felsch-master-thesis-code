"""Deep, canonical immutability helpers.

Freezing only the outer argument dictionary is not enough once parameters are
security input: a nested dictionary or list could be mutated after the check and
before the effect. These helpers freeze a value recursively and produce a
canonical byte serialisation used for hashing and for the audit chain.
"""

from __future__ import annotations

import json
import math
from types import MappingProxyType
from typing import Any, Mapping

# Bounds on any value the monitor will accept from a tool call or an effect.
MAX_DEPTH = 20          # nesting depth (also bounds cycles)
MAX_NODES = 10_000      # total values across the structure
MAX_STR = 10_000        # length of any single string (key or value)
MAX_TOTAL_CHARS = 200_000  # cumulative characters across all strings


class NonCanonical(Exception):
    """Raised when a value is outside the accepted canonical domain."""


def normalize(value: Any, *, _depth: int = 0, _budget: list[int] | None = None, _chars: list[int] | None = None) -> Any:
    """Return a deeply immutable, canonical copy of ``value`` or raise.

    The accepted domain is narrow: None, bool, int, finite float,
    bounded str (exact types, no subclasses), lists/tuples of accepted values, and
    mappings whose keys are all exact strings. Sets, arbitrary objects, non-finite
    floats, non-string keys, cycles and oversized or too-deep structures are
    rejected with NonCanonical.

    Size is bounded on three independent axes so no single value and no cumulative
    total can be used for resource exhaustion: MAX_DEPTH (also bounds cycles, so a
    self-referential structure raises rather than hangs), MAX_NODES (total values),
    and both MAX_STR (any one string, key or value) and MAX_TOTAL_CHARS (the sum of
    all string lengths). The combined limits bound the canonical serialisation to a
    few megabytes. Non-ASCII characters are escaped and take up to 12 bytes each.

    Args:
        value: The value to normalise.

    Returns:
        A canonical copy with read-only mappings and tuples.

    Raises:
        NonCanonical: If the value is outside the accepted domain or over a bound.

    Iterating a hostile custom mapping may raise its own exception. Callers run
    ``normalize`` in a try/except and treat any exception as a rejection.
    """
    if _budget is None:
        _budget = [MAX_NODES]
    if _chars is None:
        _chars = [MAX_TOTAL_CHARS]
    if _depth > MAX_DEPTH:
        raise NonCanonical("structure too deep")
    _budget[0] -= 1
    if _budget[0] < 0:
        raise NonCanonical("structure too large")

    def _account_str(s: str) -> None:
        if len(s) > MAX_STR:
            raise NonCanonical("string too long")
        _chars[0] -= len(s)
        if _chars[0] < 0:
            raise NonCanonical("cumulative string budget exceeded")

    # Exact types only: a subclass of int, float or str can override comparison, hashing or
    # formatting, so the monitor would read one value and the executor another.
    if value is None or type(value) is bool or type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise NonCanonical("non-finite float")
        return value
    if type(value) is str:
        _account_str(value)
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if type(k) is not str:
                raise NonCanonical("non-string mapping key")
            _account_str(k)
            out[k] = normalize(v, _depth=_depth + 1, _budget=_budget, _chars=_chars)
        return MappingProxyType(out)
    if isinstance(value, (list, tuple)):
        return tuple(normalize(v, _depth=_depth + 1, _budget=_budget, _chars=_chars) for v in value)
    raise NonCanonical(f"unsupported type {type(value).__name__}")


def to_canonical(value: Any) -> Any:
    """Normalise a value and check that it serialises. Raise on any deviation.

    This is the gate for values that enter the audit or an effect. It runs
    the normaliser and then a trial canonical serialisation, so a value that
    passes can always be hashed and logged without a later failure.
    """
    normalized = normalize(value)
    canonical_bytes(normalized)  # Trial serialisation, raises if it cannot encode.
    return normalized


def deep_freeze(value: Any) -> Any:
    """Return a recursively immutable view of ``value``.

    Mappings become read-only mappings, sequences become tuples, sets become
    frozensets. Every other value is returned unchanged, so the result is
    immutable at every depth only for values that already passed normalize().
    """
    if isinstance(value, Mapping):
        return MappingProxyType({k: deep_freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(deep_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(deep_freeze(v) for v in value)
    return value


def thaw(value: Any) -> Any:
    """Return a plain, JSON-serialisable copy of a (possibly frozen) value."""
    if isinstance(value, Mapping):
        return {k: thaw(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted(thaw(v) for v in value)
    return value


def canonical_bytes(value: Any) -> bytes:
    """Return a deterministic byte serialisation of ``value`` for hashing."""
    return json.dumps(thaw(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
