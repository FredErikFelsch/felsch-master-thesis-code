"""A trusted clock interface.

Time is a security input: approval expiry depends on it. If the caller of
activation supplied ``now`` freely, untrusted code could choose a time inside the
validity window. Time therefore comes from a Clock that belongs to the trusted
computing base. Tests use a FixedClock for determinism. A real deployment
uses a trusted wall-clock or an anti-rollback secure time source. A plain monotonic
process counter is not sufficient, because expiry is a wall-clock statement and
must resist the clock being set backwards.
"""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    """A source of the current time in epoch seconds."""

    def now(self) -> int:
        """Return the current time in epoch seconds."""


class FixedClock:
    """A deterministic clock for experiments and tests."""

    def __init__(self, t: int) -> None:
        """Create a clock that always returns ``t`` (epoch seconds)."""
        self._t = t

    def now(self) -> int:
        """Return the fixed time."""
        return self._t


class SystemClock:
    """The deployment clock: the host's wall clock, whole epoch seconds.

    Used by the deployed services (booking_v4.service_process_tcp, booking_v5.service_v5).
    A FixedClock would make every validity window vacuous in a live run, so only
    offline fixtures and unit suites keep it for determinism.

    Assumption, stated as such: the clock is not set backwards. On a confidential VM
    the host owns the clock, so an anti-rollback time source is future work. A
    rollback can make an expired approval verify again. It cannot admit an approval
    before its issue time.
    """

    def now(self) -> int:
        """Return the host wall-clock time in whole epoch seconds."""
        return int(time.time())

