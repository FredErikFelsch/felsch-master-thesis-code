"""Gateway, the reading side: the effect ledger as the evaluation sees it.

The gateway that performs effects is the frozen V3 `ToolGateway` behind the V4 durable
two-phase dispatch (`booking_v4.durable.DurableDeploymentServer._serve_gateway`). The gateway
verifies and consumes the token, records a durable dispatch intent, performs the external
effect and then records a durable outcome. A crash between intent and outcome leaves the
effect UNCERTAIN, and the gateway does not retry it. This module re-implements none of that.
V5 adds one read model to that path, the `effect_ledger` table. It is written in the same
transactions as the intent (state PENDING) and the outcome (state COMMITTED), so a crash
cannot separate a ledger row from the record it mirrors. This module reads it:

    DurableLedger(store)     in-process, over the V4 DurableStore (offline suites, tests)
    RemoteLedger(endpoint)   the controller's view of a running gateway, through the
                             observation surface (`gateway.ledger_watermark`,
                             `gateway.ledger_after`), the only surface the controller can reach

`seq` is the monotone cursor and `grant_id` the logical effect (V3's grant, one per token).
`ledger_delta` reduces the rows after a cursor to the latest state per grant, so a normal
effect (PENDING row, then COMMITTED row) counts as one committed effect and zero pending. An
interrupted one stays PENDING and is reported as INDETERMINATE, not as zero.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

PENDING = "PENDING"
COMMITTED = "COMMITTED"


@dataclass(frozen=True)
class EffectEntry:
    """One row of the effect ledger."""

    seq: int
    grant_id: str
    run_id: str
    step: int
    fragment_hash: str
    state: str
    t: float = 0.0
    response_hash: str | None = None

    @classmethod
    def from_row(cls, r: dict) -> "EffectEntry":
        """Build an entry from a ledger row as the gateway returns it."""
        return cls(int(r["seq"]), r["grant_id"], r["run_id"], int(r["step"]), r["fragment_hash"],
                   r["state"], float(r.get("t", 0.0)), r.get("response_hash"))


class EffectLedger(Protocol):
    """Read-only view of the effect ledger. The controller holds only this view of the gateway."""

    def high_watermark(self) -> int:
        """Return the highest `seq` in the ledger."""
        ...

    def entries_after(self, seq: int) -> tuple[EffectEntry, ...]:
        """Return all rows with a `seq` above the cursor, in order."""
        ...

    def effect(self, grant_id: str) -> tuple[str | None, str | None]:
        """Return (state, response_hash) of one grant's effect."""
        ...


@dataclass(frozen=True)
class LedgerDelta:
    """What the ledger gained after a cursor, for one (run, step).

    own_committed  effects the gateway vouches for, for this (run, step)
    own_pending    dispatches for this (run, step) without a durable outcome (INDETERMINATE)
    foreign        latest rows for any other (run, step) that appeared meanwhile (empty in a clean run)
    """

    own_committed: int
    own_pending: int
    foreign: tuple[EffectEntry, ...]

    @property
    def clean(self) -> bool:
        """True when no other (run, step) wrote to the ledger meanwhile."""
        return not self.foreign

    @property
    def indeterminate(self) -> bool:
        """True when a dispatch has no durable outcome, so the effect may or may not have happened."""
        return self.own_pending > 0

    @property
    def verdict(self) -> str:
        """Return the short summary used in run records."""
        if self.indeterminate:
            return "INDETERMINATE"
        return f"COMMITTED={self.own_committed}" + ("" if self.clean else f" FOREIGN={len(self.foreign)}")


def ledger_delta(rows_after_cursor: tuple[EffectEntry, ...], run_id: str, step: int) -> LedgerDelta:
    """Reduce the rows after a cursor to the latest state per grant, for one (run, step).

    PENDING followed by COMMITTED counts as one committed effect.

    Args:
        rows_after_cursor: ledger rows in seq order.
        run_id: the run of interest.
        step: the step of interest.

    Returns:
        The committed and pending counts for (run_id, step) and the foreign rows.
    """
    latest: dict = {}
    for r in rows_after_cursor:                     # rows arrive in seq order
        latest[r.grant_id] = r
    own = [r for r in latest.values() if (r.run_id, r.step) == (run_id, step)]
    foreign = tuple(r for r in latest.values() if (r.run_id, r.step) != (run_id, step))
    return LedgerDelta(sum(1 for r in own if r.state == COMMITTED),
                       sum(1 for r in own if r.state == PENDING), foreign)


@dataclass(frozen=True)
class DurableLedger:
    """The ledger over the V4 DurableStore, in process. It calls only the store's read methods."""

    _store: object          # booking_v4.durable.DurableStore

    def high_watermark(self) -> int:
        """Return the highest `seq` in the ledger."""
        return self._store.ledger_watermark()

    def entries_after(self, seq: int) -> tuple[EffectEntry, ...]:
        """Return all rows with a `seq` above the cursor, in order."""
        return tuple(EffectEntry.from_row(r) for r in self._store.ledger_after(seq))

    def effect(self, grant_id: str) -> tuple[str | None, str | None]:
        """Return (state, response_hash) of one grant's effect."""
        return self._store.ledger_effect(grant_id)


@dataclass(frozen=True)
class RemoteLedger:
    """The controller's ledger view of a running gateway, over its observation endpoint."""

    endpoint: object        # booking_v4.endpoint.ServiceEndpoint of the observation surface

    def high_watermark(self) -> int:
        """Return the highest `seq` in the gateway's ledger."""
        from booking_v4.services import _call
        return int(_call(self.endpoint, "gateway.ledger_watermark", {})["seq"])

    def entries_after(self, seq: int) -> tuple[EffectEntry, ...]:
        """Return all rows with a `seq` above the cursor, in order."""
        from booking_v4.services import _call
        rows = _call(self.endpoint, "gateway.ledger_after", {"seq": int(seq)})["rows"]
        return tuple(EffectEntry.from_row(r) for r in rows)

    def effect(self, grant_id: str) -> tuple[str | None, str | None]:
        """Return (state, response_hash) of one grant's effect."""
        from booking_v4.services import _call
        reply = _call(self.endpoint, "gateway.ledger_response", {"grant_id": str(grant_id)})
        return reply.get("state"), reply.get("response_hash")
