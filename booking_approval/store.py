"""The gate's durable state: approval objects, issued challenges, decisions and counters.

One SQLite file beside the Authority's store (same volume). Everything that must survive a
restart of the Authority lives here: a consumed challenge stays consumed, a decided object
stays decided, and the signature counter of a passkey only moves forward.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Any

from .objects import ApprovalObject

PENDING, APPROVED, REJECTED, FAILED = "pending", "approved", "rejected", "failed"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS objects (
    object_id TEXT PRIMARY KEY, kind TEXT NOT NULL, run_id TEXT NOT NULL,
    step_index INTEGER, fragment_hash TEXT, body TEXT NOT NULL,
    state TEXT NOT NULL, created_at INTEGER NOT NULL,
    decided_at INTEGER, approver_id TEXT, approver_kind TEXT, result TEXT);
CREATE TABLE IF NOT EXISTS challenges (
    challenge TEXT PRIMARY KEY, object_id TEXT NOT NULL, decision TEXT NOT NULL,
    expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS counters (credential_id TEXT PRIMARY KEY, sign_count INTEGER NOT NULL);
"""


@dataclass(frozen=True)
class StoredObject:
    """An approval object with its lifecycle fields."""

    obj: ApprovalObject
    state: str
    created_at: int
    decided_at: int | None
    approver_id: str | None
    approver_kind: str | None
    result: dict | None


class ApprovalStore:
    """Thread-safe access to the gate's SQLite file."""

    def __init__(self, path: str) -> None:
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            self._db.close()

    # settings ---------------------------------------------------------------------------
    def get_setting(self, key: str) -> str | None:
        """Return a stored setting, or None."""
        with self._lock:
            row = self._db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def put_setting(self, key: str, value: str) -> None:
        """Store a setting, replacing an earlier value."""
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)", (key, value))

    # objects ----------------------------------------------------------------------------
    def put_object(self, obj: ApprovalObject, now: int) -> bool:
        """Register an object as pending and return whether it was new.

        The call is idempotent, so an existing object keeps its state.
        """
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO objects(object_id, kind, run_id, step_index, fragment_hash, body, "
                "state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (obj.object_id, obj.kind, obj.run_id, obj.step_index, obj.fragment_hash,
                 json.dumps(dict(obj.body), sort_keys=True), PENDING, int(now)))
            return cur.rowcount == 1

    def get_object(self, object_id: str) -> StoredObject | None:
        """Return the object with this id, or None."""
        with self._lock:
            row = self._db.execute(
                "SELECT kind, run_id, body, state, created_at, decided_at, approver_id, approver_kind, result "
                "FROM objects WHERE object_id=?", (object_id,)).fetchone()
        return self._row(row) if row else None

    def find_step(self, run_id: str, step_index: int, fragment_hash: str) -> StoredObject | None:
        """Return the latest object for one fragment, or None."""
        with self._lock:
            row = self._db.execute(
                "SELECT kind, run_id, body, state, created_at, decided_at, approver_id, approver_kind, result "
                "FROM objects WHERE kind='step' AND run_id=? AND step_index=? AND fragment_hash=? "
                "ORDER BY rowid DESC LIMIT 1", (run_id, int(step_index), fragment_hash)).fetchone()
        return self._row(row) if row else None

    def count_steps(self, run_id: str, step_index: int, fragment_hash: str) -> int:
        """Return how many approval objects exist for one fragment (earlier attempts included)."""
        with self._lock:
            return int(self._db.execute(
                "SELECT COUNT(*) FROM objects WHERE kind='step' AND run_id=? AND step_index=? AND fragment_hash=?",
                (run_id, int(step_index), fragment_hash)).fetchone()[0])

    def pending(self) -> list[StoredObject]:
        """Return all objects still awaiting a decision, oldest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT kind, run_id, body, state, created_at, decided_at, approver_id, approver_kind, result "
                "FROM objects WHERE state=? ORDER BY created_at", (PENDING,)).fetchall()
        return [self._row(r) for r in rows]

    def decide(self, object_id: str, state: str, now: int, approver_id: str, approver_kind: str,
               result: dict[str, Any]) -> bool:
        """Move a pending object to its final state.

        Args:
            object_id: The object.
            state: The final state.
            now: The decision time.
            approver_id: Who decided.
            approver_kind: "passkey" or "harness".
            result: What the Authority answered.

        Returns:
            False when the object was no longer pending.
        """
        with self._lock:
            cur = self._db.execute(
                "UPDATE objects SET state=?, decided_at=?, approver_id=?, approver_kind=?, result=? "
                "WHERE object_id=? AND state=?",
                (state, int(now), approver_id, approver_kind, json.dumps(result, sort_keys=True),
                 object_id, PENDING))
            return cur.rowcount == 1

    @staticmethod
    def _row(row) -> StoredObject:
        kind, run_id, body, state, created, decided, approver, approver_kind, result = row
        return StoredObject(ApprovalObject(kind, run_id, json.loads(body)), state, created, decided,
                            approver, approver_kind, json.loads(result) if result else None)

    # challenges -------------------------------------------------------------------------
    def put_challenge(self, challenge_hex: str, object_id: str, decision: str, expires_at: int) -> None:
        """Record a challenge issued for one object and one decision."""
        with self._lock:
            self._db.execute("INSERT INTO challenges(challenge, object_id, decision, expires_at) VALUES (?, ?, ?, ?)",
                             (challenge_hex, object_id, decision, int(expires_at)))

    def consume_challenge(self, challenge_hex: str, object_id: str, decision: str, now: int) -> str | None:
        """Mark a challenge used.

        The challenge is consumed before the signature is checked, so any attempt spends it
        and a failed assertion cannot be retried against it.

        Args:
            challenge_hex: The challenge, hex-encoded.
            object_id: The object the assertion is for.
            decision: The decision the assertion is for.
            now: The current time.

        Returns:
            None on success, otherwise the reason it cannot be used.
        """
        with self._lock:
            row = self._db.execute("SELECT object_id, decision, expires_at, used FROM challenges WHERE challenge=?",
                                   (challenge_hex,)).fetchone()
            if row is None:
                return "unknown challenge"
            obj, dec, expires, used = row
            if used:
                return "challenge already used"
            self._db.execute("UPDATE challenges SET used=1 WHERE challenge=?", (challenge_hex,))
        if obj != object_id or dec != decision:
            return "challenge was issued for another object or decision"
        if int(now) > int(expires):
            return "challenge expired"
        return None

    # signature counters -----------------------------------------------------------------
    def advance_counter(self, credential_id: str, sign_count: int) -> bool:
        """Accept a signature counter and return whether it was accepted.

        A counter of 0 means the authenticator keeps none (synced passkeys). Otherwise it must
        strictly increase, which detects a cloned authenticator.
        """
        with self._lock:
            row = self._db.execute("SELECT sign_count FROM counters WHERE credential_id=?",
                                   (credential_id,)).fetchone()
            last = row[0] if row else 0
            if sign_count == 0 and last == 0:
                return True
            if sign_count <= last:
                return False
            self._db.execute("INSERT OR REPLACE INTO counters(credential_id, sign_count) VALUES (?, ?)",
                             (credential_id, int(sign_count)))
            return True
