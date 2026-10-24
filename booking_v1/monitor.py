"""The V1.2 reference monitor: atomic, effect-aware, replay-resistant.

Concurrency and atomicity are handled as follows.

- The state EFFECT_PENDING is actually entered. submit() proceeds only when the
  state is ACTIVE, so no call is accepted while an effect is in flight,
  and a concurrent or nested call is denied without disturbing the state.
- submit() is serialised by a lock. The decision, the grant and the admission
  record are committed under the lock and before the external effect runs. The
  effect runs with the lock released. Its outcome is committed under the lock
  again. A denial during EFFECT_PENDING does not terminate the instance, so a
  returning effect cannot overwrite a terminal state.
- The executor is wrapped so a raising or invalid executor becomes an UNCERTAIN
  outcome. No exception escapes into the monitor, and every grant is audited.
- Admission and effect are one append-only, hash-chained event log. The genesis
  hash is bound to the run, the policy digest and the approval id. Effect
  payloads are deep-frozen. Altering or removing an event breaks the chain.
  Dropping the trailing events is caught only against an external head (see
  verify_chain).
- Replay is resisted through a RunLedger: a run activates at most once, and a
  (run_id, action_id) is consumed at most once. Time comes from a trusted Clock.

Trusted computing base assumption: the agent cannot call the executor or the
tools directly, cannot reach effectful resources except through this monitor, and
cannot patch this module or the constraint registry. In a single process these
are assumptions, not enforced boundaries. booking_v4 provides the isolation and
booking_v5 attests it.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Mapping

from booking_v0.tools import ToolCall, ToolResult

from . import constraints
from .approval import Approval, verify as verify_approval
from .clock import Clock
from .effects import EffectOutcome, safe_execute, default_executor, Executor
from .freeze import NonCanonical, canonical_bytes, thaw, to_canonical
from .ledger import RunLedger
from .lifecycle import Decision, PolicyState, TERMINAL_STATES
from .policy import Policy
from .schema import validate_args


@dataclass(frozen=True)
class AdmissionEvent:
    """A frozen, chained admission decision event."""

    seq: int
    run_id: str
    policy_digest: str
    approval_id: str
    tool: str
    args: Mapping[str, Any]
    expected: str | None
    decision: Decision
    reason: str
    state_after: PolicyState
    prev_hash: str
    record_hash: str

    kind: str = "admission"

    def chain_payload(self) -> dict:
        """Return the canonical fields the chain hash covers."""
        return {
            "kind": "admission",
            "seq": self.seq,
            "run_id": self.run_id,
            "policy_digest": self.policy_digest,
            "approval_id": self.approval_id,
            "tool": self.tool,
            "args": thaw(self.args),
            "expected": self.expected,
            "decision": self.decision.value,
            "reason": self.reason,
            "state_after": self.state_after.value,
        }


@dataclass(frozen=True)
class EffectEvent:
    """A frozen, chained effect-outcome event."""

    seq: int
    run_id: str
    policy_digest: str
    approval_id: str
    tool: str
    outcome: EffectOutcome
    payload: Mapping[str, Any] | None
    error: str | None
    state_after: PolicyState
    admission_seq: int
    action_id: str | None
    prev_hash: str
    record_hash: str

    kind: str = "effect"

    def chain_payload(self) -> dict:
        """Return the canonical fields the chain hash covers."""
        return {
            "kind": "effect",
            "seq": self.seq,
            "run_id": self.run_id,
            "policy_digest": self.policy_digest,
            "approval_id": self.approval_id,
            "tool": self.tool,
            "outcome": self.outcome.value,
            "payload": thaw(self.payload) if self.payload is not None else None,
            "error": self.error,
            "state_after": self.state_after.value,
            "admission_seq": self.admission_seq,
            "action_id": self.action_id,
        }


def _snapshot(call: ToolCall) -> ToolCall:
    """Return a deeply immutable, canonical snapshot of a call.

    The tool name must be a string and the arguments must actually be a Mapping (a
    pair-list is not silently coerced). Tool name and arguments are normalised
    together under one size budget, so the tool name is length-bounded too. Any
    deviation raises. The caller turns it into a safe DENY with a minimal audit
    event, so a malformed call cannot crash the monitor.
    """
    if not isinstance(call.tool, str):
        raise NonCanonical("tool name is not a string")
    if not isinstance(call.args, Mapping):
        raise NonCanonical("call arguments are not a mapping")
    combined = to_canonical({"tool": call.tool, "args": dict(call.args)})
    return ToolCall(tool=combined["tool"], args=combined["args"])


def _hash(prev_hash: str, payload: dict) -> str:
    """Compute a chained hash from the previous hash and a canonical payload."""
    return hashlib.sha256(prev_hash.encode() + canonical_bytes(payload)).hexdigest()


class PolicyMonitor:
    """A single-instance, lock-serialised, effect-aware reference monitor."""

    def __init__(
        self,
        policy: Policy,
        approval: Approval,
        *,
        run_id: str,
        clock: Clock,
        ledger: RunLedger,
        executor: Executor = default_executor,
    ) -> None:
        """Activate the monitor against a signed approval for a specific run.

        Verifies the approval (signature, grant, digest, versions, run, window)
        via the trusted clock, then records the activation in the ledger, which
        refuses a second activation of the same run.

        Args:
            policy: The policy to enforce.
            approval: The signed approval for this run.
            run_id: The run being activated.
            clock: The trusted clock for the validity window.
            ledger: The run ledger shared by all monitors of a deployment.
            executor: Runs an admitted call and reports its outcome.

        Raises:
            approval.ApprovalError: on any approval verification failure.
            ledger.RunAlreadyActivated: if this run was already activated.
        """
        verify_approval(approval, policy, run_id=run_id, clock=clock)
        ledger.activate(run_id)  # single activation per run (replay resistance)
        self._policy = policy
        self._run_id = run_id
        self._approval_id = approval.approval_id
        self._policy_digest = policy.digest()
        self._expires_at = approval.expires_at
        self._clock = clock
        self._ledger = ledger
        self._executor = executor
        self._cursor = 0
        self._remaining = dict(policy.max_executions)
        self._state = PolicyState.ACTIVE
        self._lock = threading.Lock()
        self._events: list[AdmissionEvent | EffectEvent] = []
        # Canonical genesis: an unambiguous serialisation, not a delimiter-joined
        # string (an id could itself contain the delimiter). It also binds a
        # digest of the full signed approval binding, not just the approval id.
        approval_binding_digest = hashlib.sha256(canonical_bytes(approval.binding())).hexdigest()
        self._genesis = hashlib.sha256(canonical_bytes({
            "kind": "genesis",
            "run_id": run_id,
            "policy_digest": self._policy_digest,
            "approval_id": self._approval_id,
            "approval_binding_digest": approval_binding_digest,
        })).hexdigest()

    # Read-only views.

    @property
    def state(self) -> PolicyState:
        """Return the current lifecycle state of the instance."""
        return self._state

    @property
    def run_id(self) -> str:
        """Return the run id this monitor was activated for."""
        return self._run_id

    @property
    def approval_id(self) -> str:
        """Return the approval id bound to this run."""
        return self._approval_id

    @property
    def genesis(self) -> str:
        """Return the genesis hash the event chain starts from."""
        return self._genesis

    @property
    def events(self) -> list[AdmissionEvent | EffectEvent]:
        """Return the append-only, hash-chained event log (frozen records)."""
        return list(self._events)

    @property
    def admissions(self) -> list[AdmissionEvent]:
        """Return only the admission events."""
        return [e for e in self._events if isinstance(e, AdmissionEvent)]

    @property
    def effects(self) -> list[EffectEvent]:
        """Return only the effect events."""
        return [e for e in self._events if isinstance(e, EffectEvent)]

    @property
    def chain_head(self) -> str:
        """Return the current head of the audit chain (genesis if empty)."""
        return self._events[-1].record_hash if self._events else self._genesis

    def verify_chain(self, expected_head: str | None = None) -> bool:
        """Return whether the event chain is intact from the bound genesis.

        Continuity from the genesis shows that no event in the middle was altered or
        removed. It does not detect truncation: dropping the last events leaves a
        shorter chain that still verifies. A verifier holding the head from an
        external anchor (the exported record, the envelope in booking_v3) passes it
        as ``expected_head``, and the chain must then end at that head.

        Args:
            expected_head: The head from an external anchor, or None.

        Returns:
            True if every link verifies and, when given, the chain ends at
            ``expected_head``.
        """
        prev = self._genesis
        for e in self._events:
            if e.prev_hash != prev:
                return False
            if e.record_hash != _hash(prev, e.chain_payload()):
                return False
            prev = e.record_hash
        if expected_head is not None and prev != expected_head:
            return False
        return True

    # Internals.

    def _expected_tool(self) -> str | None:
        flow = self._policy.allowed_flow
        return flow[self._cursor] if self._cursor < len(flow) else None

    def _describe_constraint(self, spec) -> str:
        try:
            return constraints.describe(spec, self._policy)
        except Exception:
            return "constraint"

    def _append_admission(self, snap: ToolCall, expected: str | None, decision: Decision, reason: str) -> None:
        seq = len(self._events)
        prev = self.chain_head
        payload = {
            "kind": "admission", "seq": seq, "run_id": self._run_id,
            "policy_digest": self._policy_digest, "approval_id": self._approval_id,
            "tool": snap.tool, "args": thaw(snap.args), "expected": expected,
            "decision": decision.value, "reason": reason, "state_after": self._state.value,
        }
        self._events.append(AdmissionEvent(
            seq=seq, run_id=self._run_id, policy_digest=self._policy_digest,
            approval_id=self._approval_id, tool=snap.tool, args=snap.args,
            expected=expected, decision=decision, reason=reason,
            state_after=self._state, prev_hash=prev, record_hash=_hash(prev, payload),
        ))

    def _append_effect(self, tool: str, outcome: EffectOutcome, payload, error: str | None, admission_seq: int, action_id: str | None) -> None:
        # payload is already normalised and canonical by safe_execute.
        seq = len(self._events)
        prev = self.chain_head
        frozen_payload = payload
        chain_payload = {
            "kind": "effect", "seq": seq, "run_id": self._run_id,
            "policy_digest": self._policy_digest, "approval_id": self._approval_id,
            "tool": tool, "outcome": outcome.value,
            "payload": thaw(frozen_payload) if frozen_payload is not None else None,
            "error": error, "state_after": self._state.value,
            "admission_seq": admission_seq, "action_id": action_id,
        }
        self._events.append(EffectEvent(
            seq=seq, run_id=self._run_id, policy_digest=self._policy_digest,
            approval_id=self._approval_id, tool=tool, outcome=outcome,
            payload=frozen_payload, error=error, state_after=self._state,
            admission_seq=admission_seq, action_id=action_id,
            prev_hash=prev, record_hash=_hash(prev, chain_payload),
        ))

    # The mediation entry point.

    def submit(self, call: ToolCall) -> tuple[Decision, str, ToolResult | None]:
        """Mediate one attempted tool call.

        The decision and the grant are committed under the lock before the
        effect runs. The effect runs with the lock released, and its outcome is
        committed under the lock again.

        Args:
            call: The action the untrusted agent attempts.

        Returns:
            The decision, a short reason and the tool result. The result is
            None on DENY and when the effect produced no payload.
        """
        # Normalise the call into a canonical snapshot. A malformed call (cyclic,
        # oversized, non-string keys, bad tool name) takes a safe DENY path with a
        # minimal canonical audit event instead of raising.
        try:
            snap = _snapshot(call)
        except Exception:
            with self._lock:
                minimal = ToolCall(tool="<malformed>", args=to_canonical({}))
                return self._deny_locked(minimal, self._expected_tool(), "malformed call arguments (non-canonical)", terminal=True)

        # Phase A: decide and grant under the lock, before any external effect.
        with self._lock:
            # 1. The instance must be ACTIVE.
            if self._state is not PolicyState.ACTIVE:
                detail = "effect in progress" if self._state is PolicyState.EFFECT_PENDING else f"instance is {self._state.value}"
                return self._deny_locked(snap, self._expected_tool(), f"not ACTIVE: {detail}", terminal=False)

            # 1b. Validity window applies to every grant decision, not only to
            #     activation: an instance activated in-window may not act after it.
            if self._clock.now() > self._expires_at:
                return self._deny_locked(snap, self._expected_tool(), "approval validity window elapsed", terminal=True)

            expected = self._expected_tool()

            # 2. Tool identity.
            if snap.tool != expected:
                return self._deny_locked(snap, expected, f"out-of-policy action: expected {expected!r}, got {snap.tool!r}", terminal=True)

            # 3. Argument schema (extra = forbid, action_id required for effectful tools).
            ok, why = validate_args(snap.tool, snap.args)
            if not ok:
                return self._deny_locked(snap, expected, f"argument schema violated: {why}", terminal=True)

            # 4. Local constraint, fail-closed.
            spec = self._policy.constraint_at(self._cursor)
            if spec is not None:
                try:
                    satisfied = constraints.evaluate(spec, snap.args, self._policy)
                except Exception:
                    return self._deny_locked(snap, expected, "constraint evaluation error (fail-closed)", terminal=True)
                if not satisfied:
                    return self._deny_locked(snap, expected, f"parameter constraint violated at step {self._cursor}: {self._describe_constraint(spec)}", terminal=True)

            # 5. Consumption budget.
            if self._remaining.get(snap.tool, 0) <= 0:
                return self._deny_locked(snap, expected, f"consumption budget for {snap.tool!r} exhausted", terminal=True)

            # 6. Idempotency: atomically consume the action_id at the grant point.
            action_id = snap.args.get("action_id")
            if isinstance(action_id, str):
                if not self._ledger.consume_action(self._run_id, action_id):
                    return self._deny_locked(snap, expected, f"duplicate action_id {action_id!r} (idempotency)", terminal=True)

            # 7. Grant: consume the right, enter EFFECT_PENDING and commit the
            #    admission before the external effect. If a crash happens after this and
            #    before the effect, the audit shows a granted-but-unconfirmed step.
            self._remaining[snap.tool] = self._remaining.get(snap.tool, 0) - 1
            self._state = PolicyState.EFFECT_PENDING
            reason = "matches approved flow and local constraint; grant committed"
            self._append_admission(snap, expected, Decision.ALLOW, reason)
            admission_seq = self._events[-1].seq  # correlate the effect to this grant

        # Phase B: execute the effect with the lock released.
        result = safe_execute(self._executor, snap)

        # Phase C: commit the outcome under the lock.
        with self._lock:
            if result.outcome is EffectOutcome.CONFIRMED:
                self._cursor += 1
                self._state = PolicyState.COMPLETED if self._cursor >= len(self._policy.allowed_flow) else PolicyState.ACTIVE
            elif result.outcome is EffectOutcome.FAILED:
                self._state = PolicyState.EFFECT_FAILED
            else:
                self._state = PolicyState.EFFECT_UNCERTAIN
            self._append_effect(snap.tool, result.outcome, result.payload, result.error, admission_seq, action_id)
            out_reason = f"{reason}; effect {result.outcome.value}"

        tool_result = ToolResult(tool=snap.tool, payload=dict(result.payload)) if result.payload is not None else None
        return Decision.ALLOW, out_reason, tool_result

    def _deny_locked(self, snap: ToolCall, expected: str | None, reason: str, terminal: bool) -> tuple[Decision, str, None]:
        """Deny under the lock. Terminal denials terminate the instance, others leave the state."""
        if terminal and self._state not in TERMINAL_STATES and self._state is not PolicyState.EFFECT_PENDING:
            self._state = PolicyState.TERMINATED
        self._append_admission(snap, expected, Decision.DENY, reason)
        return Decision.DENY, reason, None
