"""Durable Authority and gateway services with explicit effect semantics.

The durable service wraps the booking_v3 objects in an SQLite store and follows three rules.

Rule one, a reply is visible only if its state is persisted: every internal-state RPC commits
the new Authority and gateway snapshots together with its reply in one SQLite transaction and
only then answers. If that commit fails, the in-memory objects return to the pre-request
snapshot, so the live service and its store do not diverge. gateway.execute follows rule two
instead.

Rule two, a durable dispatch intent comes before any external effect. The counterparty is not
part of the transaction (the dual-write problem), so gateway.execute has two phases. Phase one
consumes the token, records the dispatch intent and commits. Only then does the external call
run. Phase two persists the outcome and commits. A crash inside the window leaves a durable
intent without an outcome, and the answer for that request is UNCERTAIN. The server does not
perform the dispatch a second time, whether or not the downstream deduplicates. The three zones:

    before durable intent               =>  no effect
    after intent, no durable outcome    =>  UNCERTAIN, no retry
    after durable outcome               =>  gateway.dispatch_outcome returns the stored outcome

Rule three, server-derived idempotency identities: the server derives the deduplication key of a
request from authenticated protocol material and the full request content, not from the
client-chosen request_id, so no party can pre-seed another request's identity and block it. The
request_id remains for tracing only. gateway.execute needs no reply table: its token is single
use, and a lost reply is answered by gateway.dispatch_outcome. The facades in this module send
every Authority mutation through this boundary, including run activation, session establishment
and revocation and human intervention decisions.
"""

from __future__ import annotations

import hashlib
import threading
import time
import json
import os
import sqlite3
import sys
import tempfile
import uuid
from contextlib import contextmanager
from typing import Any, Callable, Mapping

from booking_v1.approval import ApprovalError, kind_fits
from booking_v1.clock import Clock
from booking_v1.effects import EffectOutcome, EffectResult, response_digest
from booking_v1.freeze import canonical_bytes, thaw
from booking_v2.world import v2_executor

from booking_v3.authority import (INTERVENTION_TTL, Authority, HumanApprovalCredential,
                                  ProvisionerCredential, ProvisioningRefused, grant_id_of)
from booking_v3.gateway import ToolGateway
from booking_v3.provisioner import create_deployment

from . import wire
from .process_backend import ProcessRunnerProvisioner
from .endpoint import ServiceEndpoint
from .services import (AuthorityClient, DeploymentServer, GatewayClient, _RPC_PARAMS, _call,
                       _new_tcp_server)


def expected_grant_id(run_id: str, step_index: int, fragment_hash: str,
                      input_state_hash: str) -> str:
    """Derive the Authority's deterministic grant id on the recovery side.

    A recovery party that knows which fragment was executing on which state
    can re-derive the id of the grant it held and query the stored outcome of
    its finalisation (`authority.finalize_outcome`) without the lost reply. The
    derivation itself is `booking_v3.authority.grant_id_of`.

    Args:
        run_id: The run the grant belongs to.
        step_index: The step of the fragment.
        fragment_hash: The hash of the executing fragment.
        input_state_hash: The state hash the fragment ran on.

    Returns:
        The grant id the Authority issued for this combination.
    """
    return grant_id_of(run_id, step_index, fragment_hash, input_state_hash)


def idempotency_key(call) -> str | None:
    """Return the key the counterparty deduplicates on.

    The gateway-derived effect identity wins whenever it is present. The client's
    action_id is only the fallback for calls that did not pass a gateway, so a
    controller that reuses another run's action_id reaches the provider under its
    own identity instead of replaying that run's stored outcome.

    Args:
        call: The ToolCall about to be executed.

    Returns:
        The idempotency key, or None when the call carries neither.
    """
    identity = getattr(call, "effect_identity", None)
    if isinstance(identity, str) and identity:
        return identity
    action_id = (getattr(call, "args", None) or {}).get("action_id")
    return action_id if isinstance(action_id, str) else None


class ExternalWorld:
    """The counterparty's own state, outside the trust domain of the services.

    It survives crashes of the durable service (optionally in its own SQLite
    file), so experiments can observe whether an external effect happened even
    when the gateway service died mid-dispatch. With ``idempotent=True`` the
    counterparty deduplicates by the downstream idempotency key it already
    receives, modelling an airline or payment API that supports
    Idempotency-Key semantics: the same logical request executes at most one
    logical effect. Behind the booking_v3 gateway that key is the gateway-derived
    ``call.effect_identity`` (run, step, operation, fragment hash). Only a call
    without one (direct use in tests and the earlier harnesses) falls back to the
    action_id in its arguments.
    """

    def __init__(self, db_path: str | None = None, idempotent: bool = False,
                 executor: Callable[[Any], EffectResult] = v2_executor) -> None:
        #: The counterparty behind this world: the booking_v2 catalogue by default, a live
        #: provider such as `booking_live.world.live_executor` otherwise. `executor` below is
        #: its only caller, so a world built for a live provider cannot fall back to the
        #: catalogue.
        self._execute = executor
        self.idempotent = idempotent
        self._mem: list[tuple[str, str | None, str]] = []
        self._db = None
        if db_path is not None:
            self._db = sqlite3.connect(db_path, check_same_thread=False)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS effects ("
                " seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                " tool TEXT NOT NULL, action_id TEXT, result TEXT NOT NULL)")
            self._db.commit()

    def _lookup(self, tool: str, action_id: str) -> str | None:
        if self._db is not None:
            row = self._db.execute(
                "SELECT result FROM effects WHERE tool = ? AND action_id = ?"
                " ORDER BY seq DESC LIMIT 1", (tool, action_id)).fetchone()
            return row[0] if row else None
        for t, a, r in reversed(self._mem):
            if t == tool and a == action_id:
                return r
        return None

    def _record(self, tool: str, action_id: str | None, result: str) -> None:
        if self._db is not None:
            self._db.execute(
                "INSERT INTO effects (tool, action_id, result) VALUES (?, ?, ?)",
                (tool, action_id, result))
            self._db.commit()
        else:
            self._mem.append((tool, action_id, result))

    def effect_count(self, tool: str | None = None) -> int:
        """Return the number of recorded effects, for one tool or for all."""
        if self._db is not None:
            if tool is None:
                return self._db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
            return self._db.execute(
                "SELECT COUNT(*) FROM effects WHERE tool = ?", (tool,)).fetchone()[0]
        return len([e for e in self._mem if tool is None or e[0] == tool])

    def executor(self, call) -> EffectResult:
        """Execute one call against the counterparty. The gateway is configured with this.

        The lookup is the counterparty's own deduplication, so it applies to a live
        provider in the same way as to the catalogue: with `idempotent=True` the same
        `idempotency_key` returns the stored outcome without a second effect. A provider
        that also deduplicates itself (a Duffel order has one payment state) is only
        modelled here.
        """
        key = idempotency_key(call)
        if self.idempotent and key is not None:
            stored = self._lookup(call.tool, key)
            if stored is not None:
                s = json.loads(stored)
                return EffectResult(outcome=EffectOutcome(s["outcome"]),
                                    payload=s["payload"], error=s["error"])
        result = self._execute(call)
        self._record(call.tool, key,
                     json.dumps({"outcome": result.outcome.value,
                                 "payload": thaw(result.payload) if result.payload is not None else None,
                                 "error": result.error}, sort_keys=True))
        return result


# --- the store ----------------------------------------------------------------

class StoreBusy(RuntimeError):
    """A second writer tried to open a DurableStore that another live process holds."""


class DurableStore:
    """Snapshots, a reply table, dispatch intents and finalisation outcomes.

    The store enforces a single writer itself, not only through the deployment: it takes
    an exclusive advisory lock on `<realpath>.lock` for its whole lifetime (`fcntl.flock`,
    non-blocking). A second `DurableStore` on the same database, in another process or
    thread, raises `StoreBusy` before it reads anything. Without this the consumed-token
    set and the dispatch state live per process, and two Authorities on one database
    would each dispatch the same grant once. The kernel releases the lock when the
    process exits, so a crashed writer does not block its successor, while a live one
    does.

    The lock path is the database's `os.path.realpath`, so two names for one file
    (symlink, `..`) contend for one lock, and the lock file is opened `O_NOFOLLOW`. If
    the lock file is removed or replaced, the old writer refuses its next transaction
    (`StoreBusy`), because `transaction()` checks the locked inode against the lock path
    before `BEGIN IMMEDIATE`. The check does not run again before `COMMIT`, so at most
    the one transaction already past it can still commit after a successor opened the
    store. A party who can delete files in the database directory can therefore stop
    the writer, but cannot run two writers side by side for longer than that one
    transaction.
    """

    def __init__(self, path: str, *, readonly: bool = False) -> None:
        """Open the store at `path`.

        With `readonly=True` the database is opened with SQLite `mode=ro`, no writer lock
        is taken and no table is created. This lets a reader run beside a live service,
        for example `booking_v5.service_v5.human_credential` reading the seeded human
        credential. A writer needs the lock.

        Raises:
            StoreBusy: Another live writer holds the lock on this database.
        """
        self._readonly = readonly
        self._lock_path = None if (readonly or path == ":memory:") else os.path.realpath(path) + ".lock"
        self._lock_fd = None if self._lock_path is None else self._acquire_writer_lock(self._lock_path)
        # The listeners serve from their own threads. `DurableDeploymentServer._serve_lock`
        # serialises access, so only SQLite's same-thread guard has to be lifted.
        if readonly:
            self._conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, check_same_thread=False)
        else:
            self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.isolation_level = None  # explicit BEGIN/COMMIT only
        self._fail_next_commit = False
        self._fail_commit_countdown = None
        for ddl in (
            "CREATE TABLE IF NOT EXISTS replies ("
            " identity TEXT PRIMARY KEY, request_hash TEXT NOT NULL, reply TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS intents ("
            " identity TEXT PRIMARY KEY, request_hash TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS outcomes ("
            " grant_id TEXT PRIMARY KEY, reply TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS states ("
            " id INTEGER PRIMARY KEY CHECK (id = 1),"
            " authority TEXT NOT NULL, gateway TEXT NOT NULL)",
            # The effect ledger, a read model of the dispatch state machine. It is written
            # in the same transactions as intents and outcomes, so a row exists iff the
            # corresponding durable transition committed. `seq` is the monotone cursor for
            # the evaluation, `grant_id` the logical effect. `response_hash` is the digest
            # of the response this effect returned, written into the COMMITTED row. It lets
            # the Authority compare the observation a runner reports with the digest the
            # gateway recorded. The ledger read itself is unauthenticated (see the trust
            # assumption in `DurableDeploymentServer._serve_locked`). The column is NULL on
            # PENDING rows and on rows from older stores.
            "CREATE TABLE IF NOT EXISTS effect_ledger ("
            " seq INTEGER PRIMARY KEY AUTOINCREMENT, grant_id TEXT NOT NULL,"
            " run_id TEXT NOT NULL, step INTEGER NOT NULL, fragment_hash TEXT NOT NULL,"
            " state TEXT NOT NULL, t REAL NOT NULL, response_hash TEXT)",
            # The relying party's ledgers (nonces, TD identities, sessions), durable
            # alongside the Authority state and committed in the same transactions.
            "CREATE TABLE IF NOT EXISTS v5_state ("
            " id INTEGER PRIMARY KEY CHECK (id = 1), state TEXT NOT NULL)",
            # Seeded settings a role reads at start and does not change (the gateway's
            # token verify key, the Authority's frozen reference), written by the trusted init.
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        ):
            if not readonly:
                self._conn.execute(ddl)
        # Idempotent migration for stores created before the column existed. The CREATE above
        # does nothing to an existing table, so the column is added here or not at all.
        if not readonly:
            columns = {r[1] for r in self._conn.execute("PRAGMA table_info(effect_ledger)")}
            if "response_hash" not in columns:
                self._conn.execute("ALTER TABLE effect_ledger ADD COLUMN response_hash TEXT")

    @staticmethod
    def _acquire_writer_lock(lock_path: str):
        """Take an exclusive, non-blocking advisory lock beside the database.

        Contention raises `StoreBusy` at once instead of waiting. Once the lock is held,
        the path is checked against the locked inode again, so a lock file removed or
        replaced during acquisition is refused rather than shared.

        Raises:
            StoreBusy: The lock is held elsewhere or the lock file changed.
        """
        import fcntl
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise StoreBusy(f"{lock_path!r} is held by another live writer (single-writer invariant)") from exc
        if not DurableStore._lock_intact(fd, lock_path):
            os.close(fd)
            raise StoreBusy(f"{lock_path!r} changed underneath the writer lock (single-writer invariant)")
        return fd

    @staticmethod
    def _lock_intact(fd, lock_path: str) -> bool:
        """Return True iff the inode locked through `fd` is still the inode at `lock_path`."""
        try:
            held, at_path = os.fstat(fd), os.stat(lock_path)
        except OSError:
            return False
        return (held.st_ino, held.st_dev) == (at_path.st_ino, at_path.st_dev)

    def _check_writer_lock(self) -> None:
        """Refuse to write if the lock file was removed or replaced.

        `transaction()` calls this before `BEGIN IMMEDIATE`, so a writer whose lock file
        changed stops at its next transaction instead of running beside a successor.

        Raises:
            StoreBusy: The lock path no longer names the held lock.
        """
        if self._lock_fd is not None and not self._lock_intact(self._lock_fd, self._lock_path):
            raise StoreBusy(f"{self._lock_path!r} no longer names the held writer lock (single-writer invariant)")

    def fail_next_commit(self) -> None:
        """Test hook: make the next transaction fail at COMMIT time."""
        self._fail_next_commit = True

    def fail_next_commit_after(self, n: int) -> None:
        """Test hook: let the next n commits succeed and fail the one after them."""
        self._fail_commit_countdown = n

    @contextmanager
    def transaction(self):
        """One BEGIN IMMEDIATE transaction: commit on success, roll back on any error."""
        self._check_writer_lock()
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            if self._fail_next_commit:
                self._fail_next_commit = False
                raise RuntimeError("simulated durable commit failure")
            if self._fail_commit_countdown is not None:
                if self._fail_commit_countdown == 0:
                    self._fail_commit_countdown = None
                    raise RuntimeError("simulated durable commit failure")
                self._fail_commit_countdown -= 1
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def get_reply(self, identity: str) -> tuple[str, str] | None:
        """Return the stored (request_hash, reply) of `identity`, or None."""
        row = self._conn.execute(
            "SELECT request_hash, reply FROM replies WHERE identity = ?",
            (identity,)).fetchone()
        return (row[0], row[1]) if row else None

    def put_reply(self, identity: str, request_hash: str, reply: str) -> None:
        """Insert the reply for `identity`. Call inside `transaction()`.

        A second reply for the same identity raises `sqlite3.IntegrityError`.
        """
        self._conn.execute(
            "INSERT INTO replies (identity, request_hash, reply) VALUES (?, ?, ?)",
            (identity, request_hash, reply))

    def get_intent(self, identity: str) -> str | None:
        """Return the request hash of the dispatch intent recorded for `identity`, or None."""
        row = self._conn.execute(
            "SELECT request_hash FROM intents WHERE identity = ?", (identity,)).fetchone()
        return row[0] if row else None

    def put_intent(self, identity: str, request_hash: str) -> None:
        """Insert the dispatch intent for `identity`. Call inside `transaction()`.

        A second intent for the same identity raises `sqlite3.IntegrityError`.
        """
        self._conn.execute(
            "INSERT INTO intents (identity, request_hash) VALUES (?, ?)",
            (identity, request_hash))

    def del_intent(self, identity: str) -> None:
        """Delete the dispatch intent for `identity`, if there is one."""
        self._conn.execute("DELETE FROM intents WHERE identity = ?", (identity,))

    #: Outcome rows carry a prefix per writer. The gateway records what the counterparty
    #: answered and the Authority records the finalisation of the same grant_id. On one
    #: shared primary key the later finalisation would replace the gateway's row, and
    #: `authority.finalize_outcome` would hand out the gateway's row, including a payload
    #: the monitor withholds from the agent. With one prefix per writer each reader sees
    #: only its own rows.
    GATEWAY_OUTCOME = "gw:"
    AUTHORITY_OUTCOME = "auth:"

    def put_outcome(self, grant_id: str, reply: str) -> None:
        """Store the outcome reply of a grant, replacing an earlier row with the same key."""
        self._conn.execute(
            "INSERT OR REPLACE INTO outcomes (grant_id, reply) VALUES (?, ?)",
            (grant_id, reply))

    def get_outcome(self, grant_id: str) -> str | None:
        """Return the stored outcome reply under `grant_id`, or None."""
        row = self._conn.execute(
            "SELECT reply FROM outcomes WHERE grant_id = ?", (grant_id,)).fetchone()
        return row[0] if row else None

    def put_states(self, authority_state: str, gateway_state: str) -> None:
        """Replace the single row of Authority and Gateway snapshots."""
        self._conn.execute(
            "INSERT INTO states (id, authority, gateway) VALUES (1, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET authority = ?, gateway = ?",
            (authority_state, gateway_state, authority_state, gateway_state))

    def load_states(self) -> tuple[dict, dict] | None:
        """Return the stored (authority, gateway) snapshots, or None for a fresh store."""
        row = self._conn.execute("SELECT authority, gateway FROM states WHERE id = 1").fetchone()
        return (json.loads(row[0]), json.loads(row[1])) if row else None

    # --- effect ledger (append-only, read by cursor) ---
    def put_ledger(self, grant_id: str, run_id: str, step: int, fragment_hash: str, state: str,
                   response_hash: str | None = None) -> None:
        """Append one effect ledger row. Call inside the transaction of the transition it records."""
        self._conn.execute(
            "INSERT INTO effect_ledger (grant_id, run_id, step, fragment_hash, state, t, response_hash)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (grant_id, run_id, int(step), fragment_hash, state, time.time(), response_hash))

    def ledger_effect(self, grant_id: str) -> tuple[str | None, str | None]:
        """Return (state, response_hash) of the latest ledger row for one grant.

        There are three answers. ("COMMITTED", digest) is the only one that can lead to a
        pass. (None, None) means there is no row. ("PENDING", None) means the dispatch was
        recorded and its outcome was not. A runner holding a response does not see
        PENDING, because phase two of `_serve_gateway` commits the COMMITTED row before it
        replies. PENDING therefore means a crash between the phases or a read that
        overtook the commit, and neither is a pass.
        """
        row = self._conn.execute(
            "SELECT state, response_hash FROM effect_ledger WHERE grant_id = ?"
            " ORDER BY seq DESC LIMIT 1", (grant_id,)).fetchone()
        return (row[0], row[1]) if row else (None, None)

    def ledger_watermark(self) -> int:
        """Return the highest ledger sequence number, 0 for an empty ledger."""
        row = self._conn.execute("SELECT COALESCE(MAX(seq), 0) FROM effect_ledger").fetchone()
        return int(row[0])

    def ledger_after(self, seq: int) -> list[dict]:
        """Return all ledger rows with a sequence number above `seq`, oldest first."""
        rows = self._conn.execute(
            "SELECT seq, grant_id, run_id, step, fragment_hash, state, t, response_hash"
            " FROM effect_ledger WHERE seq > ? ORDER BY seq", (int(seq),)).fetchall()
        return [{"seq": r[0], "grant_id": r[1], "run_id": r[2], "step": r[3],
                 "fragment_hash": r[4], "state": r[5], "t": r[6], "response_hash": r[7]}
                for r in rows]

    # --- seeded settings ---
    def put_setting(self, key: str, value: str) -> None:
        """Insert or replace one setting."""
        self._conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)"
                           " ON CONFLICT(key) DO UPDATE SET value = ?", (key, value, value))

    def get_setting(self, key: str) -> str | None:
        """Return the value of one setting, or None."""
        row = self._conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    # --- relying-party state ---
    def put_v5_state(self, state_json: str) -> None:
        """Replace the relying party's state snapshot."""
        self._conn.execute(
            "INSERT INTO v5_state (id, state) VALUES (1, ?) ON CONFLICT(id) DO UPDATE SET state = ?",
            (state_json, state_json))

    def load_v5_state(self) -> dict | None:
        """Return the stored relying-party state, or None."""
        row = self._conn.execute("SELECT state FROM v5_state WHERE id = 1").fetchone()
        return json.loads(row[0]) if row else None

    def close(self) -> None:
        """Close the connection and release the writer lock."""
        self._conn.close()
        if self._lock_fd is not None:
            import fcntl
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            os.close(self._lock_fd)
            self._lock_fd = None


# --- idempotency identities ---------------------------------------------------

def _get(params, *keys):
    value = params
    for key in keys:
        value = value.get(key, "") if isinstance(value, Mapping) else ""
    return value if isinstance(value, (str, int, bool)) else ""


def request_identity(method: str, params: Mapping[str, Any]) -> str:
    """Derive the idempotency identity of a request from protocol material and content.

    For the methods a runner, the provisioner or the human interface calls, the identity
    includes a secret or signature that caller already holds (session secret, token
    signature, approval signature, provisioner bootstrap, human credential), so a party
    that cannot make the request at all maps to a different, harmless identity.
    `v5.issue_nonce`, `v5.establish_session` and the methods without a branch of their own
    use public material only.

    The full request also enters the identity. The material per method alone would be too
    coarse: for `report_denial` and `report_intervention_required` it is the session
    secret only. Anyone holding the credential could then occupy the identity slot with
    other content, and the honest report that followed would be refused with "identity
    reused with different content", so the run would keep running with no denial
    recorded. The grant path of an attested session has the same shape: the Authority
    refuses an unsigned request, and that refusal would then be stored as the answer for
    the identity.

    A genuine retry sends the same bytes and therefore keeps its identity, while two
    different requests can no longer share a slot. The content check in
    `DurableDeploymentServer._serve_transactional` stays as a second guard that should
    not be reachable.

    Args:
        method: The RPC method name.
        params: The decoded request parameters.

    Returns:
        The identity as a hex SHA-256 digest.
    """
    if method == "gateway.execute":
        material = ["gw", _get(params, "token", "signature"),
                    _get(params, "fragment", "fragment_hash")]
    elif method == "authority.request_execution_grant":
        material = ["grant", _get(params, "credential", "secret"),
                    _get(params, "fragment", "fragment_hash"),
                    _get(params, "input_state_hash")]
    elif method == "authority.finalize_transition":
        material = ["fin", _get(params, "credential", "secret"),
                    _get(params, "record", "grant_id")]
    elif method == "authority.report_denial":
        material = ["deny", _get(params, "credential", "secret")]
    elif method == "authority.report_intervention_required":
        material = ["intv", _get(params, "credential", "secret")]
    elif method == "authority.create_run":
        material = ["run", _get(params, "run_id"), _get(params, "approval", "signature")]
    elif method == "authority.establish_runner_session":
        material = ["est", _get(params, "bootstrap", "secret"), _get(params, "nonce")]
    elif method == "authority.revoke_runner_session":
        material = ["rev", _get(params, "credential", "secret")]
    elif method == "v5.issue_nonce":
        # One challenge per (step, boot key). A retry of the same TD gets the same nonce
        # and a fresh TD for the same step gets a fresh one.
        material = ["v5nonce", _get(params, "run_id"), str(_get(params, "step")),
                    _get(params, "fragment_hash"), _get(params, "state_hash"), _get(params, "pk_boot")]
    elif method == "v5.establish_session":
        material = ["v5est", _get(params, "nonce"), _get(params, "pk_boot"),
                    _get(params, "pk_sig")]
    elif method == "authority.decide_intervention":
        # The human interface chooses `decision_id` per decision. A retry of one decision
        # replays its reply. A new decision for the same fragment (after an expired
        # window) is a new request and does not replay the stale approval from the reply
        # table.
        material = ["dec", _get(params, "human", "secret"), _get(params, "decision_id"),
                    _get(params, "run_id"), str(_get(params, "step_index")),
                    _get(params, "fragment_hash"), _get(params, "approver_id"),
                    _get(params, "approver_kind"), str(_get(params, "grant")), str(_get(params, "ttl"))]
    else:
        material = ["other", method]
    material = list(material) + ["content", canonical_bytes({
        "method": method, "params": thaw(params)}).hex()]
    return hashlib.sha256(canonical_bytes(material)).hexdigest()


# --- the durable server -------------------------------------------------------

_EXTRA_PARAMS: dict[str, set[str]] = {
    "authority.create_run": {"policy", "approval", "run_id"},
    "authority.establish_runner_session": {
        "bootstrap", "run_id", "fragment_hash", "state_hash", "nonce"},
    "authority.revoke_runner_session": {"credential"},
    "authority.decide_intervention": {
        "human", "decision_id", "run_id", "step_index", "fragment_hash", "approver_id", "approver_kind",
        "grant", "ttl"},
    # Read-only: whether this Authority verifies reported observations against the
    # gateway's effect ledger. It changes nothing and reveals only a deployment setting,
    # so a run record can state which configuration produced it.
    "authority.observation_check": set(),
}


def _error(reason: str, code: str = "ERROR") -> dict:
    """Build a protocol error reply with a fixed reason and an error code.

    ``reason`` is a fixed, non-sensitive protocol message. For an internal
    exception use ``_internal_error``, which writes the detail to the server's
    stderr and returns only a code.
    """
    return {"v": wire.WIRE_VERSION, "error": reason, "code": code}


def _audit(where: str, exc: Exception) -> None:
    """Write the full failure detail to the server's stderr.

    The client receives only a code and a fixed reason, because the runner
    sits across an isolation boundary and a provoked failure must not carry
    internal state or tracebacks back across it.
    """
    sys.stderr.write(f"[durable-audit] {where}: {type(exc).__name__}: {exc}\n")
    sys.stderr.flush()


def _internal_error(where: str, exc: Exception, prefix: str | None = None,
                    code: str = "INTERNAL") -> dict:
    """Build a sanitised error reply for an internal exception.

    WireError is protocol-level input validation and safe to surface, so its
    message is kept (and still written to stderr). Any other exception yields
    only `prefix` (or a generic message) plus `code`. Its text goes to stderr
    and not into the reply.

    Args:
        where: A short label for the stderr line.
        exc: The exception.
        prefix: The reason sent to the client instead of the exception text.
        code: The error code for a non-wire exception.

    Returns:
        The error reply.
    """
    _audit(where, exc)
    if isinstance(exc, wire.WireError):
        return {"v": wire.WIRE_VERSION, "error": str(exc), "code": "WIRE"}
    return {"v": wire.WIRE_VERSION, "error": prefix or "internal service error",
            "code": code}


# --- roles: one artefact, distinct runtime principals, distinct exposed interfaces ---
#
# The server without a role exposes everything on one listener, as the process,
# container and controller deployments do. A role-bound server serves only its own
# methods: the gateway process has no `authority.*` method and the Authority process has
# no `gateway.*`. Two surfaces belong to the gateway, bound to different listeners: the
# execution surface (the runner's port) and the observation surface (the controller's
# port, ledger reads only).
#
# `authority.establish_runner_session` (the provisioning boundary of booking_v3) is on no
# role surface. On a role-bound Authority a runner session therefore comes only from
# `v5.establish_session`, that is after evidence appraisal.
AUTHORITY_SURFACE = frozenset({
    "authority.request_execution_grant", "authority.finalize_transition",
    "authority.report_denial", "authority.report_intervention_required",
    "authority.finalize_outcome", "authority.create_run", "authority.revoke_runner_session",
    "authority.decide_intervention", "authority.observation_check",
    "v5.issue_nonce", "v5.establish_session"})
#: The gateway's execution surface. It has no effectful recovery: no method the gateway
#: serves submits an authorised request a second time. A lost reply is answered by the
#: read-only `gateway.dispatch_outcome`, which does not call the counterparty.
GATEWAY_SURFACE = frozenset({"gateway.execute", "gateway.dispatch_outcome"})
OBSERVATION_SURFACE = frozenset({"gateway.ledger_watermark", "gateway.ledger_after",
                                 "gateway.ledger_response"})
#: The harness surface: fault injection and read-back (`test.*`, `read.*`). A deployed
#: service offers it only on its own listener (`harness_tcp`), not on the surface a
#: runner or orchestrator can reach. The set is a sentinel, the methods are matched by
#: prefix.
HARNESS_SURFACE = frozenset({"test.*", "read.*"})
ROLE_SURFACES = {"authority": AUTHORITY_SURFACE, "gateway": GATEWAY_SURFACE}

_V5_PARAMS: dict[str, set[str]] = {
    "v5.issue_nonce": {"run_id", "step", "fragment_hash", "state_hash", "pk_boot"},
    "v5.establish_session": {"evidence", "pk_boot", "pk_sig", "run_id", "step", "fragment_hash",
                             "state_hash", "nonce", "substrate_profile_hash"},
}


class DurableDeploymentServer(DeploymentServer):
    """The deployment server with the three durable-effect rules of this module.

    Args:
        deployment: The live objects (`authority`, `gateway`, optionally `relying_party`).
        store: The durable store this server writes.
        socket_path: The UDS path of the main listener (ignored with `tcp`).
        tcp: (host, port) for a TCP main listener.
        downstream_idempotent: Stored only. The shipped server does not read it, the test
            double in `tests_recovery_support` does.
        enable_test_api: Serve `test.*` and `read.*` on the main listener (in-process
            tests only).
        role: None, "authority" or "gateway". A role limits the main listener to the
            methods of `ROLE_SURFACES[role]`.
        observe_tcp: (host, port) for the gateway's observation listener.
        harness_tcp: (host, port) for the harness listener.
        closed_methods: Methods refused on every non-harness listener from the start.

    Raises:
        ValueError: An unknown role, or an observation listener for the Authority role.
    """

    def __init__(self, deployment, store: DurableStore, *,
                 socket_path: str | None = None,
                 tcp: tuple[str, int] | None = None,
                 downstream_idempotent: bool = False,
                 enable_test_api: bool = False,
                 role: str | None = None,
                 observe_tcp: tuple[str, int] | None = None,
                 harness_tcp: tuple[str, int] | None = None,
                 closed_methods: frozenset[str] = frozenset()) -> None:
        self._store = store
        # One lock for every request that reaches the live objects and the store through
        # `_serve_on` or `_serve`: the main, observation and harness listeners and the
        # decisions of the approval gate (booking_approval.gate), which call `_serve`. It is
        # reentrant because `_serve_on` calls `_serve`. Without it two requests share one
        # SQLite connection and one set of live objects, and the failing one rolls the live
        # objects back to a snapshot taken before the other one committed. The approval
        # gate also reads the Authority outside the lock (`status`, `intervention_pending`
        # for its page and its tickets). Those reads are snapshots, and each decision is
        # checked again by the Authority under the lock (`_dispatch_extra`).
        self._serve_lock = threading.RLock()
        # Methods that do not exist on any non-harness listener of this server. They are in
        # force before the base constructor binds and starts the listener. The approval gate
        # passes its closed methods here, so no request is served between "listening" and
        # "filtered".
        self._closed_methods = frozenset(closed_methods)
        self._downstream_idempotent = downstream_idempotent    # read only by tests_recovery_support
        self._enable_test_api = enable_test_api
        self._drop_next: list[str] = []
        self._crash_dispatch: dict | None = None
        if role is not None and role not in ROLE_SURFACES:
            raise ValueError(f"unknown role {role!r}")
        self._role = role
        self._surface = ROLE_SURFACES[role] if role else None
        # The base server chooses the listener, so the durable service runs over UDS or TCP
        # with the same effect semantics.
        super().__init__(deployment, socket_path=socket_path, tcp=tcp)
        # The observation surface on its own listener (gateway role, or legacy).
        self._observer = None
        self.observe_endpoint = None
        if observe_tcp is not None:
            if role == "authority":
                raise ValueError("the observation surface belongs to the gateway")
            self._observer = _new_tcp_server(observe_tcp, self._make_handler(OBSERVATION_SURFACE))
            h, pt = self._observer.server_address[0], self._observer.server_address[1]
            self.observe_endpoint = ServiceEndpoint.tcp(h, pt)
            threading.Thread(target=self._observer.serve_forever, daemon=True).start()
        # The harness surface on its own listener. The main listener of a deployed service
        # does not serve test. or read. methods (enable_test_api is the in-process test hook).
        self._harness = None
        self.harness_endpoint = None
        if harness_tcp is not None:
            self._harness = _new_tcp_server(harness_tcp, self._make_handler(HARNESS_SURFACE))
            h, pt = self._harness.server_address[0], self._harness.server_address[1]
            self.harness_endpoint = ServiceEndpoint.tcp(h, pt)
            threading.Thread(target=self._harness.serve_forever, daemon=True).start()

    def close(self) -> None:
        """Shut down the observation and harness listeners, then the main one."""
        if self._observer is not None:
            self._observer.shutdown()
            self._observer.server_close()
        if self._harness is not None:
            self._harness.shutdown()
            self._harness.server_close()
        super().close()

    # --- role helpers ---
    def _put_states(self) -> None:
        """Write the snapshots of the objects this role holds. Call inside a transaction.

        A missing object is stored as "{}": the gateway process has no Authority object
        (only the verify key) and the Authority process has no gateway.
        """
        authority = getattr(self._dep, "authority", None)
        gateway = getattr(self._dep, "gateway", None)
        self._store.put_states(
            json.dumps(authority.export_state(), sort_keys=True) if authority is not None else "{}",
            json.dumps(gateway.export_state(), sort_keys=True) if gateway is not None else "{}")
        rp = getattr(self._dep, "relying_party", None)
        if rp is not None:
            self._store.put_v5_state(json.dumps(rp.export_state(), sort_keys=True))

    def _serve_on(self, surface, message: Mapping[str, Any]) -> dict | None:
        """Serve one request on the listener bound to `surface`.

        The listener's surface takes precedence. A main listener without its own surface
        uses the role's. A method outside the surface is answered with METHOD_NOT_FOUND
        and changes no state.
        """
        self._check_envelope(message)
        method = message["method"]
        is_harness_method = method.startswith("test.") or method.startswith("read.")
        with self._serve_lock:
            if surface is HARNESS_SURFACE:
                if not is_harness_method:
                    return {"v": wire.WIRE_VERSION, "error": f"no such method {method!r} on this surface",
                            "code": "METHOD_NOT_FOUND"}
                return self._serve_test_api(method, message["params"])
            if method in self._closed_methods:
                return {"v": wire.WIRE_VERSION, "error": f"{method} requires the approval surface",
                        "code": "METHOD_NOT_FOUND"}
            bound = surface if surface is not None else self._surface
            if bound is not None and method not in bound and not (self._enable_test_api and is_harness_method):
                return {"v": wire.WIRE_VERSION, "error": f"no such method {method!r} on this surface",
                        "code": "METHOD_NOT_FOUND"}
            return self._serve(message)

    # --- fault injection ---
    def drop_reply_once(self, method: str) -> None:
        """Commit the next matching request, then lose its reply."""
        self._drop_next.append(method)

    def crash_dispatch_once(self, *, before_effect: bool, hard: bool = False) -> None:
        """Crash inside the next gateway dispatch window.

        before_effect selects which side of the external call the crash hits.
        ``hard`` kills the whole service process (for the SIGKILL experiments),
        otherwise the request is abandoned replyless with the server alive.
        """
        self._crash_dispatch = {"before_effect": before_effect, "hard": hard}

    def _simulate_crash(self) -> None:
        """Consume the armed crash. A hard crash exits the process, otherwise return no reply."""
        crash = self._crash_dispatch
        self._crash_dispatch = None
        if crash and crash.get("hard"):
            os._exit(137)  # the whole service dies mid-request
        return None  # request abandoned, the connection closes without a reply

    # --- serving ---
    def _serve(self, message: Mapping[str, Any]) -> dict | None:
        """Serve one request under the server-wide lock (see `_serve_lock`)."""
        with self._serve_lock:
            return self._serve_locked(message)

    def _serve_locked(self, message: Mapping[str, Any]) -> dict | None:
        self._check_envelope(message)
        method = message["method"]
        params = message["params"]

        # The fault-injection and read-back methods (test.*, read.*) are off unless
        # enable_test_api is set, so a deployed service cannot be told to call os._exit.
        if method.startswith("test.") or method.startswith("read."):
            if not self._enable_test_api:
                return _error("test API disabled")
            return self._serve_test_api(method, params)

        # Read-only recovery endpoints: no identity, no state change. They answer a party
        # that lost a reply, and the untrusted orchestrator can reach them, so they return
        # only what that party would have received anyway. `finalize_outcome` reads the
        # Authority's row and not the gateway's. The gateway's row carries the counterparty
        # payload, which the monitor withholds from the agent on every outcome except
        # CONFIRMED_VALIDATED. `gateway.dispatch_outcome` serves that row against proof of
        # token possession.
        if method == "authority.finalize_outcome":
            p = wire.expect_keys(params, {"grant_id"}, "finalize_outcome params")
            stored = self._store.get_outcome(DurableStore.AUTHORITY_OUTCOME + p["grant_id"])
            if stored is None:
                return _error("no recorded outcome for this grant")
            return json.loads(stored)
        if method == "gateway.dispatch_outcome":
            return self._serve_dispatch_outcome(params)
        # The observation surface: read-only, no identity, no state change.
        #
        # Trust assumption: the channels from the Authority to the gateway (this surface)
        # and from the gateway to OpenBao are plaintext and carry no identity. The answer is
        # believed because it comes from the pod behind the `gateway-observe` Service, so
        # whoever can place a pod behind that Service (the controller, a trusted
        # provisioner) can answer with a ledger row of its choosing. Authenticating the
        # gateway (a signature over (grant_id, state, response_hash) under a key pinned at
        # the Authority, or mTLS) is not implemented.
        if method == "gateway.ledger_watermark":
            wire.expect_keys(params, set(), "ledger_watermark params")
            return {"v": wire.WIRE_VERSION, "seq": self._store.ledger_watermark()}
        if method == "gateway.ledger_after":
            p = wire.expect_keys(params, {"seq"}, "ledger_after params")
            return {"v": wire.WIRE_VERSION, "rows": self._store.ledger_after(int(p["seq"]))}
        if method == "gateway.ledger_response":
            p = wire.expect_keys(params, {"grant_id"}, "ledger_response params")
            state, digest = self._store.ledger_effect(str(p["grant_id"]))
            return {"v": wire.WIRE_VERSION, "state": state, "response_hash": digest}

        identity = request_identity(method, params)
        request_hash = hashlib.sha256(canonical_bytes(
            {"method": method, "params": thaw(params)})).hexdigest()
        if method == "gateway.execute":
            reply = self._serve_gateway(identity, request_hash, message)
        else:
            reply = self._serve_transactional(identity, request_hash, message)
        if reply is not None and self._drop_next and self._drop_next[0] == method:
            self._drop_next.pop(0)
            return None  # the commit stands, the answer is lost on the wire
        return reply

    def _serve_test_api(self, method, params) -> dict:
        """Serve one fault-injection (test.*) or read-back (read.*) method."""
        if method == "test.drop_reply_once":
            p = wire.expect_keys(params, {"method"}, "test params")
            self.drop_reply_once(p["method"])
            return {"v": wire.WIRE_VERSION, "ok": True}
        if method == "test.crash_dispatch_once":
            p = wire.expect_keys(params, {"before_effect", "hard"}, "test params")
            self.crash_dispatch_once(before_effect=bool(p["before_effect"]),
                                     hard=bool(p["hard"]))
            return {"v": wire.WIRE_VERSION, "ok": True}
        if method == "test.fail_next_commit":
            wire.expect_keys(params, set(), "test params")
            self._store.fail_next_commit()
            return {"v": wire.WIRE_VERSION, "ok": True}
        if method == "read.status":
            p = wire.expect_keys(params, {"run_id"}, "read params")
            status = self._dep.authority.status(p["run_id"])
            return {"v": wire.WIRE_VERSION, "status": status.value if status else None}
        if method == "read.dispatch_ops":
            wire.expect_keys(params, set(), "read params")
            return {"v": wire.WIRE_VERSION,
                    "operations": [e["operation"] for e in self._dep.gateway.executions]}
        return _error(f"unknown test method {method!r}")

    def _serve_transactional(self, identity, request_hash, message) -> dict:
        """Serve an internal-state RPC (every method except gateway.execute) in one transaction.

        A stored reply for the identity is replayed if the content matches. Otherwise the
        method runs, and its reply, the outcome row of a finalisation and the new snapshots
        commit together. If the commit fails, the live objects return to their state before
        the request.
        """
        method = message["method"]
        params = message["params"]
        authority = getattr(self._dep, "authority", None)
        gateway = getattr(self._dep, "gateway", None)
        rp = getattr(self._dep, "relying_party", None)
        authority_before = authority.export_state() if authority is not None else None
        gateway_before = gateway.export_state() if gateway is not None else None
        rp_before = rp.export_state() if rp is not None else None
        try:
            with self._store.transaction():
                row = self._store.get_reply(identity)
                if row is not None:
                    stored_hash, stored_reply = row
                    if stored_hash != request_hash:
                        return _error("idempotency identity reused with different content")
                    return json.loads(stored_reply)  # idempotent replay
                try:
                    if method in _RPC_PARAMS:
                        reply = self._dispatch(message)
                    elif method in _EXTRA_PARAMS:
                        wire.expect_keys(params, _EXTRA_PARAMS[method], f"{method} params")
                        reply = self._dispatch_extra(method, dict(params))
                    elif method in _V5_PARAMS:
                        wire.expect_keys(params, _V5_PARAMS[method], f"{method} params")
                        reply = self._dispatch_v5(method, dict(params))
                    else:
                        raise wire.WireError(f"unknown method {method!r}")
                except Exception as exc:
                    # A method that raised may have changed the live objects halfway. The
                    # error reply is stored with the state from before the request, so a
                    # partial change never becomes durable.
                    self._restore(authority, authority_before, gateway, gateway_before, rp, rp_before)
                    reply = _internal_error("transactional", exc)
                self._store.put_reply(identity, request_hash,
                                      json.dumps(thaw(reply), sort_keys=True))
                if (method == "authority.finalize_transition"
                        and reply.get("envelope") is not None):
                    self._store.put_outcome(
                        DurableStore.AUTHORITY_OUTCOME + _get(params, "record", "grant_id"),
                        json.dumps(thaw(reply), sort_keys=True))
                self._put_states()
                return reply
        except Exception as exc:
            # The durable commit failed: return the live objects to the pre-request
            # snapshot so memory and store agree.
            self._restore(authority, authority_before, gateway, gateway_before, rp, rp_before)
            return _internal_error("durable_commit", exc,
                                   prefix="durable commit failed; state rolled back",
                                   code="COMMIT_FAILED")

    @staticmethod
    def _restore(authority, authority_before, gateway, gateway_before, rp, rp_before) -> None:
        """Return the live Authority, gateway and relying party to their pre-request snapshots."""
        if authority is not None:
            authority.import_state(authority_before)
        if gateway is not None:
            gateway.restore_state(gateway_before)
        if rp is not None:
            rp.import_state(rp_before)

    def _serve_gateway(self, identity, request_hash, message) -> dict | None:
        """Serve gateway.execute as the two-phase dispatch of rule two.

        A consumed token is refused here as in booking_v3. A lost outcome is recovered
        read-only through gateway.dispatch_outcome, and execute does not answer the same
        token twice. The token is verified and consumed before any intent is persisted,
        so a caller without a valid token cannot pre-seed a grant's intent or outcome.
        `identity` is computed by the caller for every method and not used here, since
        the single-use token already deduplicates.
        """
        params = message["params"]
        gateway = self._dep.gateway
        try:
            token = wire.token_from_wire(params["token"])
            fragment = wire.fragment_from_wire(params["fragment"])
        except Exception as exc:
            return _internal_error("param_validation", exc)

        gateway_before = gateway.export_state()
        refusal = gateway.authorize_dispatch(token, fragment)
        if refusal is not None:
            # This includes "already consumed" on a genuine replay. As in booking_v3,
            # nothing changed and nothing is persisted.
            return {"v": wire.WIRE_VERSION, "result": wire.effect_reply_to_wire(refusal)}

        # Phase one: the dispatch intent (token consumed, dispatch recorded) becomes
        # durable before the external effect.
        try:
            with self._store.transaction():
                self._store.put_intent(token.grant_id, request_hash)
                self._store.put_ledger(token.grant_id, token.run_id, token.step_index,
                                       token.fragment_hash, "PENDING")
                self._put_states()
        except Exception as exc:
            gateway.restore_state(gateway_before)  # the token counts as unspent again
            return _internal_error("durable_commit", exc,
                                   prefix="durable commit failed; state rolled back",
                                   code="COMMIT_FAILED")
        phase1_gateway_state = gateway.export_state()

        if self._crash_dispatch is not None and self._crash_dispatch["before_effect"]:
            return self._simulate_crash()

        result = gateway.perform_dispatch(fragment)  # the counterparty call, outside any transaction

        if self._crash_dispatch is not None and not self._crash_dispatch["before_effect"]:
            return self._simulate_crash()

        # Phase two: the outcome becomes durable, and only then is it returned.
        reply = {"v": wire.WIRE_VERSION, "result": wire.effect_reply_to_wire(result)}
        try:
            with self._store.transaction():
                self._store.put_outcome(DurableStore.GATEWAY_OUTCOME + token.grant_id,
                                        json.dumps(thaw(reply), sort_keys=True))
                self._store.del_intent(token.grant_id)
                self._store.put_ledger(token.grant_id, token.run_id, token.step_index,
                                       token.fragment_hash, "COMMITTED",
                                       response_digest(result.outcome.value, result.payload))
                self._put_states()
        except Exception as exc:
            # The external effect has happened and cannot be undone. Restore the live
            # gateway to the durable phase-one state and leave the intent standing
            # without an outcome, so the next lookup answers UNCERTAIN and the effect
            # is not executed again.
            gateway.restore_state(phase1_gateway_state)
            return _internal_error("outcome_commit", exc,
                                   prefix="outcome commit failed; effect stands, run UNCERTAIN",
                                   code="OUTCOME_COMMIT_FAILED")
        return reply

    def _recover_token(self, params, what: str):
        """Validate the params of a recovery request and check the token holder.

        Returns:
            (token, fragment) from the request.

        Raises:
            WireError: Malformed params, or the gateway refuses the token for this fragment.
        """
        gateway = self._dep.gateway
        wire.expect_keys(params, {"token", "fragment"}, f"{what} params")
        token = wire.token_from_wire(params["token"])
        fragment = wire.fragment_from_wire(params["fragment"])
        why = gateway.verify_dispatch_authorization(token, fragment)
        if why is not None:
            raise wire.WireError(f"{what} refused: {why}")
        return token, fragment

    def _serve_dispatch_outcome(self, params) -> dict:
        """Answer a lost gateway reply from the store.

        Requires the token as proof of possession but does not consume it. Returns the
        stored outcome if one exists, UNCERTAIN if only the intent stands, and an error
        if there was no dispatch. It does not call the counterparty.
        """
        try:
            token, _fragment = self._recover_token(params, "dispatch_outcome")
        except Exception as exc:
            return _internal_error("param_validation", exc)
        stored = self._store.get_outcome(DurableStore.GATEWAY_OUTCOME + token.grant_id)
        if stored is not None:
            return json.loads(stored)  # the gateway's stored reply, unchanged
        if self._store.get_intent(token.grant_id) is None:
            return _error("no dispatch intent for this grant")
        result = EffectResult(
            outcome=EffectOutcome.UNCERTAIN, payload=None,
            error="dispatch window interrupted; external outcome unknown (fail-closed)")
        return {"v": wire.WIRE_VERSION, "result": wire.effect_reply_to_wire(result)}

    def _dispatch_v5(self, method: str, params: dict) -> dict:
        """Serve a relying-party method in front of the Authority (Authority role only).

        On the Authority role surface `v5.establish_session` is the only way to obtain a
        runner session. Its `mint` callback calls the provisioning boundary of booking_v3
        with the bootstrap this process holds, after the evidence was appraised. The
        controller does not receive a bootstrap, and `authority.establish_runner_session`
        is not on the surface.
        """
        from booking_v5.relying_party import ChallengeRefused, Refusal
        rp = getattr(self._dep, "relying_party", None)
        authority = self._dep.authority
        if rp is None:
            raise wire.WireError("this deployment has no V5 relying party")
        if method == "v5.issue_nonce":
            try:
                nonce = rp.issue_nonce(params["run_id"], int(params["step"]),
                                       params["fragment_hash"], params["state_hash"],
                                       bytes.fromhex(params["pk_boot"]),
                                       run_is_at=authority.run_is_at)
            except ChallengeRefused as exc:
                # Read-only refusal: no nonce exists, so no state was written for it.
                r = exc.refusal
                return {"v": wire.WIRE_VERSION, "nonce": None,
                        "refusal": {"rule": r.rule, "detail": r.detail, "stage": r.stage}}
            return {"v": wire.WIRE_VERSION, "nonce": nonce.hex(), "refusal": None}
        if method == "v5.establish_session":
            from booking_v5.evidence import Evidence
            evidence = Evidence.from_wire(params["evidence"]) if params["evidence"] is not None else None

            def mint(scope):
                # The session records the TD's verdict key, so from here on the Authority
                # believes a decision on this session only when that key signed it.
                # An empty pk_sig means the reference values pin an older binding, where
                # the verdict key is not covered by the quote. The session then records no
                # key and keeps the older semantics, rather than trusting an unattested one.
                cred = authority.establish_runner_session(
                    ProvisionerCredential(secret=authority._bootstrap_secret),     # held here, not sent
                    scope.run_id, scope.fragment_hash, scope.state_hash,
                    verify_key=scope.pk_sig or None)
                # The trust anchors are sealed with the credential. They are the keys the
                # monitor verifies the envelope and a human approval with, so they do not
                # travel in the clear on the line the controller composes.
                return wire.encode(wire.session_package_to_wire(
                    cred, authority.anchors())).encode("utf-8")

            # The two callbacks read the Authority's own state: whether an intervention for
            # this fragment is still pending and whether the run is still at this step. The
            # approval itself is checked later, on the grant path.
            outcome = rp.establish_session(
                evidence, bytes.fromhex(params["pk_boot"]), bytes.fromhex(params["pk_sig"]),
                params["run_id"], int(params["step"]),
                params["fragment_hash"], params["state_hash"], bytes.fromhex(params["nonce"]),
                mint, params["substrate_profile_hash"], continuation_pending=authority.intervention_pending,
                run_is_at=authority.run_is_at)
            if isinstance(outcome, Refusal):
                # Every refusal goes to stdout so `kubectl logs authority` answers an RTMR0
                # outlier without a second boot. The line carries rule, stage, run, step and
                # detail (detail carries got= and want= for boot-measurement-mismatch).
                sys.stdout.write(
                    "[v5-authority] REFUSAL rule={rule} stage={stage} run={run} step={step} detail={detail}\n".format(
                        rule=outcome.rule, stage=outcome.stage, run=params["run_id"],
                        step=int(params["step"]), detail=outcome.detail or ""))
                sys.stdout.flush()
                return {"v": wire.WIRE_VERSION, "session": None,
                        "refusal": {"rule": outcome.rule, "detail": outcome.detail, "stage": outcome.stage}}
            return {"v": wire.WIRE_VERSION, "refusal": None,
                    "session": {"sealed": outcome.sealed, "td_id": outcome.td_id.hex(),
                                "run_id": outcome.scope.run_id, "step": outcome.scope.step,
                                "appraisal": dict(outcome.appraisal)}}
        raise wire.WireError(f"unhandled method {method!r}")

    def _dispatch_extra(self, method: str, params: dict) -> dict:
        """Serve the Authority methods listed in `_EXTRA_PARAMS`."""
        if method == "authority.observation_check":
            return {"v": wire.WIRE_VERSION,
                    "observation_check": self._dep.authority.observation_check()}
        authority = self._dep.authority
        if method == "authority.create_run":
            policy = wire.policy_from_wire(params["policy"])
            approval = wire.approval_from_wire(params["approval"])
            try:
                envelope = authority.create_run(policy, approval, params["run_id"])
            except (ApprovalError, ValueError) as exc:
                # A classified domain or policy refusal, whose reason is safe to return.
                return {"v": wire.WIRE_VERSION, "envelope": None,
                        "reason": f"{type(exc).__name__}: {exc}"}
            except Exception as exc:  # unexpected: the detail goes to stderr only
                _audit("create_run", exc)
                return {"v": wire.WIRE_VERSION, "envelope": None,
                        "reason": "internal error", "code": "INTERNAL"}
            return {"v": wire.WIRE_VERSION,
                    "envelope": wire.envelope_to_wire(envelope), "reason": "created"}
        if method == "authority.establish_runner_session":
            try:
                credential = authority.establish_runner_session(
                    wire.bootstrap_from_wire(params["bootstrap"]),
                    params["run_id"], params["fragment_hash"], params["state_hash"])
            except ProvisioningRefused as exc:
                return {"v": wire.WIRE_VERSION, "credential": None, "reason": str(exc)}
            return {"v": wire.WIRE_VERSION,
                    "credential": wire.credential_to_wire(credential),
                    "reason": "established"}
        if method == "authority.revoke_runner_session":
            authority.revoke_runner_session(wire.credential_from_wire(params["credential"]))
            return {"v": wire.WIRE_VERSION, "ok": True}
        if method == "authority.decide_intervention":
            human = wire.human_from_wire(params["human"])
            if not authority.verify_human(human):
                return {"v": wire.WIRE_VERSION, "approval": None,
                        "error": "human approval credential invalid"}
            # The surface checks the types of its own parameters: `step_index` and `ttl` are
            # integers, `decision_id` is a non-empty string, so the Authority receives the
            # types its signature binds. A negative ttl is accepted. It only shortens the
            # window (an already elapsed approval, the offline stand-in for a late
            # resubmission), and the Authority clamps any ttl to its maximum.
            if not isinstance(params.get("step_index"), int) or isinstance(params.get("step_index"), bool) \
                    or not isinstance(params.get("ttl"), int) or isinstance(params.get("ttl"), bool):
                return {"v": wire.WIRE_VERSION, "approval": None, "error": "step_index and ttl must be integers"}
            step_index, ttl = params["step_index"], params["ttl"]
            if not isinstance(params.get("decision_id"), str) or not params["decision_id"]:
                return {"v": wire.WIRE_VERSION, "approval": None, "error": "decision_id must be a non-empty string"}
            # A grant is the JSON boolean `true` or `false`. `bool("false")` is True, so the
            # decision is not read through truthiness.
            if not isinstance(params.get("grant"), bool):
                return {"v": wire.WIRE_VERSION, "approval": None, "error": "grant must be true or false"}
            # The kind of key is signed with the approval and fits the approver id.
            if not kind_fits(params.get("approver_kind"), params.get("approver_id")):
                return {"v": wire.WIRE_VERSION, "approval": None,
                        "error": "approver_kind must be passkey or harness and fit the approver id"}
            # The Authority signs only a fragment it has recorded as pending. This check runs
            # under `_serve_lock`, so it also covers a snapshot the approval gate read earlier.
            # The surface names the refusal.
            if not authority.intervention_pending(params["run_id"], step_index, params["fragment_hash"]):
                return {"v": wire.WIRE_VERSION, "approval": None,
                        "error": "no pending intervention for this fragment"}
            approval = authority.decide_intervention(
                params["run_id"], step_index, params["fragment_hash"],
                approver_id=str(params["approver_id"]), approver_kind=params["approver_kind"],
                grant=params["grant"], ttl=ttl)
            return {"v": wire.WIRE_VERSION,
                    "approval": wire.intervention_to_wire(approval)}
        raise wire.WireError(f"unhandled method {method!r}")


# --- facades: every mutation passes through the durable service ---------------

class AuthorityFacade:
    """The harness and provisioner view of the Authority.

    Every mutation it offers (run activation, sessions, grants, finalisations,
    reports) goes through the durable service. Intervention decisions go through
    `HumanApprovalClient`. Reads (status, audit, notices, anchors) come from the
    live object.

    Args:
        real: The live Authority object.
        socket_path: The service address, a socket path or a `ServiceEndpoint`.
    """

    def __init__(self, real: Authority, socket_path: str) -> None:
        self._real = real
        self._socket_path = socket_path
        self._client = AuthorityClient(socket_path)

    def observation_check(self) -> str:
        """Return whether the live Authority verifies reported observations against the ledger."""
        return self._real.observation_check()

    def bind_effect_ledger(self, ledger) -> None:
        """Bind the gateway's effect ledger to the live object (deployment wiring).

        This changes no run state and therefore does not pass through the durable
        service: the ledger is a connection to the gateway, held for the lifetime of the
        process and absent from `export_state`. Whoever restarts the service wires it
        again, in the same way as its verifier and its clock.
        """
        self._real.bind_effect_ledger(ledger)

    def bind_policy_admission(self, admit) -> None:
        """Bind a policy admission check to the live object (deployment wiring).

        See `booking_v3.authority.Authority.bind_policy_admission`.
        """
        self._real.bind_policy_admission(admit)

    # mutations, through the durable service
    def create_run(self, policy, approval, run_id: str):
        """Activate a run through the durable service and return its genesis envelope.

        Raises:
            RuntimeError: The Authority refused the run, with its reason.
        """
        reply = _call(self._socket_path, "authority.create_run", {
            "policy": wire.policy_to_wire(policy),
            "approval": wire.approval_to_wire(approval), "run_id": run_id})
        if reply["envelope"] is None:
            raise RuntimeError(reply["reason"])
        return wire.envelope_from_wire(reply["envelope"])

    def establish_runner_session(self, bootstrap, run_id, fragment_hash, state_hash,
                                 request_nonce=None):
        """Establish a fragment-bound runner session through the durable service.

        `request_nonce` makes a retry of the same request replay its reply. Without it a
        fresh nonce is drawn.

        Raises:
            ProvisioningRefused: The Authority refused the session.
        """
        reply = _call(self._socket_path, "authority.establish_runner_session", {
            "bootstrap": wire.bootstrap_to_wire(bootstrap), "run_id": run_id,
            "fragment_hash": fragment_hash, "state_hash": state_hash,
            "nonce": request_nonce or uuid.uuid4().hex})
        if reply["credential"] is None:
            raise ProvisioningRefused(reply["reason"])
        return wire.credential_from_wire(reply["credential"])

    def revoke_runner_session(self, credential) -> None:
        """Revoke a runner session through the durable service."""
        _call(self._socket_path, "authority.revoke_runner_session",
              {"credential": wire.credential_to_wire(credential)})

    def request_execution_grant(self, *args, **kwargs):
        """Request an execution grant over the service, as `AuthorityClient.request_execution_grant`."""
        return self._client.request_execution_grant(*args, **kwargs)

    def finalize_transition(self, *args, **kwargs):
        """Report a transition record over the service, as `AuthorityClient.finalize_transition`."""
        return self._client.finalize_transition(*args, **kwargs)

    def report_denial(self, *args, **kwargs):
        """Report a denied admission over the service, as `AuthorityClient.report_denial`."""
        return self._client.report_denial(*args, **kwargs)

    def report_intervention_required(self, *args, **kwargs):
        """Report a required intervention, as `AuthorityClient.report_intervention_required`."""
        return self._client.report_intervention_required(*args, **kwargs)

    # reads, from the live object
    def status(self, run_id):
        """Return the run status from the live object."""
        return self._real.status(run_id)

    def audit(self, run_id):
        """Return the audit events and head of a run from the live object."""
        return self._real.audit(run_id)

    def intervention_pending(self, run_id, step_index, fragment_hash) -> bool:
        """Return whether the live Authority holds a pending intervention for this fragment."""
        return self._real.intervention_pending(run_id, step_index, fragment_hash)

    def notices(self, run_id):
        """Return the notices of a run from the live object."""
        return self._real.notices(run_id)

    def anchors(self):
        """Return the trust anchors of the live Authority."""
        return self._real.anchors()

    def token_key(self):
        """Return the token verification key of the live Authority."""
        return self._real.token_key()


def new_decision_id() -> str:
    """Return a fresh id for one human decision (milliseconds plus four random bytes).

    A caller that retries the same decision must send the same id again.
    """
    import secrets
    return f"{int(time.time() * 1000)}-{secrets.token_hex(4)}"


class HumanApprovalClient:
    """The client for human intervention decisions.

    Of the clients a deployment hands out, only this one carries the human
    credential. The general `AuthorityFacade` has none, so an ordinary Authority
    client cannot mint an intervention approval. The deployment object itself
    also keeps the credential (`DurableProcessDeployment.human`), and the
    Authority snapshot in the store contains the secret.

    Args:
        socket_path: The service address, a socket path or a `ServiceEndpoint`.
        human: The human approval credential.
    """

    def __init__(self, socket_path: str, human) -> None:
        self._socket_path = socket_path
        self._human = human

    def decide_intervention(self, run_id, step_index, fragment_hash, *,
                            approver_id, grant, ttl=INTERVENTION_TTL, approver_kind="passkey"):
        """Record one human decision through the durable service and return the approval.

        Each call draws a new decision id, so a repeated call is a new decision.

        Returns:
            The intervention approval, or None if the Authority signed nothing.

        Raises:
            WireError: The service refused the decision, with its reason.
        """
        reply = _call(self._socket_path, "authority.decide_intervention", {
            "human": wire.human_to_wire(self._human), "decision_id": new_decision_id(),
            "run_id": run_id, "step_index": step_index,
            "fragment_hash": fragment_hash, "approver_id": approver_id,
            "approver_kind": approver_kind, "grant": grant, "ttl": ttl})
        return wire.intervention_from_wire(reply["approval"])


class GatewayFacade:
    """The harness view of the gateway: dispatches go through the service, reads use the live object."""

    def __init__(self, real: ToolGateway, socket_path: str) -> None:
        self._real = real
        self._client = GatewayClient(socket_path)

    def execute(self, token, fragment):
        """Dispatch an authorised fragment through the durable service."""
        return self._client.execute(token, fragment)

    def dispatch_outcome(self, token, fragment):
        """Read the recorded outcome of a dispatch without calling the counterparty."""
        return self._client.dispatch_outcome(token, fragment)

    @property
    def executions(self):
        """Return the dispatches the live gateway performed."""
        return self._real.executions

    def export_state(self):
        """Return the live gateway's state snapshot."""
        return self._real.export_state()


class RemoteAuthorityHandle:
    """Provisioner-side handle on an Authority in another process.

    Args:
        socket_path: The service address, a socket path or a `ServiceEndpoint`.
    """

    def __init__(self, socket_path: str) -> None:
        self._socket_path = socket_path

    def establish_runner_session(self, bootstrap, run_id, fragment_hash, state_hash,
                                 request_nonce=None):
        """Establish a fragment-bound runner session at the remote Authority.

        Raises:
            ProvisioningRefused: The Authority refused the session.
        """
        reply = _call(self._socket_path, "authority.establish_runner_session", {
            "bootstrap": wire.bootstrap_to_wire(bootstrap), "run_id": run_id,
            "fragment_hash": fragment_hash, "state_hash": state_hash,
            "nonce": request_nonce or uuid.uuid4().hex})
        if reply["credential"] is None:
            raise ProvisioningRefused(reply["reason"])
        return wire.credential_from_wire(reply["credential"])

    def revoke_runner_session(self, credential) -> None:
        """Revoke a runner session at the remote Authority."""
        _call(self._socket_path, "authority.revoke_runner_session",
              {"credential": wire.credential_to_wire(credential)})


# --- the deployment -----------------------------------------------------------

class DurableProcessDeployment:
    """Process backend over durable services, with a simulated service restart.

    Args:
        clock: The clock of Authority and gateway.
        executor: The counterparty executor, None for the booking_v2 catalogue.
        db_path: The store path, None for a fresh temporary directory.
        downstream_idempotent: Passed to the server, which stores it only.
        enable_test_api: Serve `test.*` and `read.*` on the main listener.
    """

    def __init__(self, clock: Clock, executor=None, db_path: str | None = None,
                 downstream_idempotent: bool = False,
                 enable_test_api: bool = False) -> None:
        self.clock = clock
        self._executor = executor
        self._downstream_idempotent = downstream_idempotent
        self._enable_test_api = enable_test_api
        if db_path is None:
            db_path = os.path.join(tempfile.mkdtemp(prefix="booking-durable-"), "deployment.db")
        self.db_path = db_path
        self.store = DurableStore(db_path)
        base = create_deployment(clock, executor=executor)
        self.human = base.human
        self._wire_up(base.authority, base.gateway, base.bootstrap)

    def _make_server(self, deployment) -> DurableDeploymentServer:
        """Build the server for this deployment.

        Test doubles override this to add what the shipped server does not have (see
        `tests_recovery_support`).
        """
        return DurableDeploymentServer(
            deployment, self.store, downstream_idempotent=self._downstream_idempotent,
            enable_test_api=self._enable_test_api)

    def _wire_up(self, authority: Authority, gateway: ToolGateway, bootstrap) -> None:
        self._real_authority = authority
        self._real_gateway = gateway
        self.bootstrap = bootstrap
        self.anchors = authority.anchors()
        self.server = self._make_server(_RestoredDeployment(authority, gateway))
        self.authority = AuthorityFacade(authority, self.server.socket_path)
        # Of the clients, only this one receives the human credential.
        self.human_interface = HumanApprovalClient(self.server.socket_path, self.human)
        self.gateway = GatewayFacade(gateway, self.server.socket_path)
        self.provisioner = ProcessRunnerProvisioner(
            self.authority, self.anchors, self.bootstrap, self.server.socket_path)

    def restart_services(self) -> None:
        """Simulate a service crash and restart: rebuild Authority and gateway from the store alone."""
        self.server.close()
        states = self.store.load_states()
        assert states is not None, "no persisted state to restart from"
        authority_state, gateway_state = states
        authority = Authority.restore(self.clock, authority_state)
        gateway = (ToolGateway(authority.token_key(), self.clock, executor=self._executor)
                   if self._executor is not None
                   else ToolGateway(authority.token_key(), self.clock))
        gateway.restore_state(gateway_state)
        self.human = HumanApprovalCredential(secret=authority_state["human_secret"])
        self._wire_up(authority, gateway,
                      ProvisionerCredential(secret=authority_state["bootstrap_secret"]))

    def close(self) -> None:
        """Stop the service and close the store."""
        self.server.close()
        self.store.close()

    def __enter__(self) -> "DurableProcessDeployment":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class _RestoredDeployment:
    """The live objects a server holds. A role holds only its part.

    The Authority role has `authority` and `relying_party` and no gateway. The gateway
    role has the gateway (with the verify key only) and no Authority.
    """

    def __init__(self, authority, gateway, relying_party=None) -> None:
        self.authority = authority
        self.gateway = gateway
        self.relying_party = relying_party


def create_durable_process_deployment(clock: Clock, executor=None) -> DurableProcessDeployment:
    """Build a durable process deployment (fits the booking_v3 scenario hook)."""
    return DurableProcessDeployment(clock, executor=executor)
