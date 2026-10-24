"""The V2 reference monitor: V1.2 plus cross-step bindings and provenanced facts.

The monitor keeps the full V1.2 machinery: a lock-serialised submit, the same
admission order, the effect-aware lifecycle, the append-only hash-chained event
log, the run ledger and the trusted clock. It adds two things.

Before admitting a step (rule 4b) it evaluates the step's bindings against the
fact store. A binding compares an agent-supplied argument to a fact the monitor
observed earlier. A missing or wrong-run fact makes the binding fail, so the
admission is denied fail-closed. This is V2a, cross-step consistency.

After a confirmed effect the monitor runs the step's producers and records the
resulting facts, each anchored to the effect event that produced it. A value is
admitted to the store only here, only from a confirmed result, and only for the
current run. Agent-supplied values may become facts, but only after passing the
policy checks for their step, and the authorisation-relevant environmental
attributes (price, currency, recipient) are derived from the tool result rather
than from an agent argument. This is V2b, monitor-originated and run-scoped
provenance: the agent can neither forge, alter nor replay a recorded value.

    alpha_2(a) = ( tool(a), local_constraint_ok(a), bindings_satisfied(a, facts) )
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Mapping

from booking_v0.tools import ToolCall, ToolResult

from booking_v1 import constraints
from booking_v1.approval import Approval, verify as verify_approval
from booking_v1.clock import Clock
from booking_v1.effects import EffectOutcome, safe_execute, Executor
from booking_v1.freeze import NonCanonical, canonical_bytes, thaw, to_canonical
from booking_v1.ledger import RunLedger
from booking_v1.lifecycle import Decision, PolicyState, TERMINAL_STATES
from booking_v1.schema import validate_args

from . import facts as facts_mod
from .facts import FactStore, ObservedFact
from .policy import Policy
from .world import v2_executor


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
            "kind": "admission", "seq": self.seq, "run_id": self.run_id,
            "policy_digest": self.policy_digest, "approval_id": self.approval_id,
            "tool": self.tool, "args": thaw(self.args), "expected": self.expected,
            "decision": self.decision.value, "reason": self.reason, "state_after": self.state_after.value,
        }


@dataclass(frozen=True)
class EffectEvent:
    """A frozen, chained effect-outcome event, naming the facts it produced."""

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
    produced_facts: tuple[str, ...]
    prev_hash: str
    record_hash: str
    kind: str = "effect"

    def chain_payload(self) -> dict:
        """Return the canonical fields the chain hash covers."""
        return {
            "kind": "effect", "seq": self.seq, "run_id": self.run_id,
            "policy_digest": self.policy_digest, "approval_id": self.approval_id,
            "tool": self.tool, "outcome": self.outcome.value,
            "payload": thaw(self.payload) if self.payload is not None else None,
            "error": self.error, "state_after": self.state_after.value,
            "admission_seq": self.admission_seq, "action_id": self.action_id,
            "produced_facts": list(self.produced_facts),
        }


def _snapshot(call: ToolCall) -> ToolCall:
    """Return a deeply immutable, canonical snapshot of a call, as in booking_v1.monitor."""
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
    """A single-instance V2 reference monitor with a provenanced fact store."""

    def __init__(self, policy: Policy, approval: Approval, *, run_id: str, clock: Clock, ledger: RunLedger, executor: Executor = v2_executor) -> None:
        """Activate the monitor against a signed approval for a specific run.

        Args:
            policy: The P2 policy to enforce.
            approval: The signed approval for this run.
            run_id: The run being activated.
            clock: The trusted clock for the validity window.
            ledger: The run ledger shared by all monitors of a deployment.
            executor: Runs an admitted call against the world.

        Raises:
            booking_v1.approval.ApprovalError: On any approval verification failure.
            booking_v1.ledger.RunAlreadyActivated: If this run was already activated.
        """
        verify_approval(approval, policy, run_id=run_id, clock=clock)
        ledger.activate(run_id)
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
        self._facts = FactStore(run_id)
        approval_binding_digest = hashlib.sha256(canonical_bytes(approval.binding())).hexdigest()
        self._genesis = hashlib.sha256(canonical_bytes({
            "kind": "genesis", "run_id": run_id, "policy_digest": self._policy_digest,
            "approval_id": self._approval_id, "approval_binding_digest": approval_binding_digest,
        })).hexdigest()

    # Views.
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
    def events(self):
        """Return the append-only, hash-chained event log."""
        return list(self._events)

    @property
    def admissions(self):
        """Return only the admission events."""
        return [e for e in self._events if isinstance(e, AdmissionEvent)]

    @property
    def effects(self):
        """Return only the effect events."""
        return [e for e in self._events if isinstance(e, EffectEvent)]

    @property
    def chain_head(self) -> str:
        """Return the current head of the audit chain (genesis if empty)."""
        return self._events[-1].record_hash if self._events else self._genesis

    def facts(self) -> dict[str, ObservedFact]:
        """Return the recorded facts by name."""
        return {name: self._facts.get(name) for name in self._facts.names()}

    def verify_chain(self) -> bool:
        """Return whether the event chain is intact from the bound genesis.

        Unlike booking_v1, this check takes no expected head and therefore cannot
        detect truncation.
        """
        prev = self._genesis
        for e in self._events:
            if e.prev_hash != prev or e.record_hash != _hash(prev, e.chain_payload()):
                return False
            prev = e.record_hash
        return True

    # Internals.
    def _expected_tool(self) -> str | None:
        flow = self._policy.allowed_flow
        return flow[self._cursor] if self._cursor < len(flow) else None

    def _append_admission(self, snap, expected, decision, reason) -> None:
        """Append a chained admission event with the current state."""
        seq = len(self._events)
        prev = self.chain_head
        payload = {
            "kind": "admission", "seq": seq, "run_id": self._run_id,
            "policy_digest": self._policy_digest, "approval_id": self._approval_id,
            "tool": snap.tool, "args": thaw(snap.args), "expected": expected,
            "decision": decision.value, "reason": reason, "state_after": self._state.value,
        }
        self._events.append(AdmissionEvent(
            seq=seq, run_id=self._run_id, policy_digest=self._policy_digest, approval_id=self._approval_id,
            tool=snap.tool, args=snap.args, expected=expected, decision=decision, reason=reason,
            state_after=self._state, prev_hash=prev, record_hash=_hash(prev, payload)))

    def _append_effect(self, tool, outcome, payload, error, admission_seq, action_id, produced) -> tuple[int, str]:
        """Append a chained effect event and return its sequence number and record hash."""
        seq = len(self._events)
        prev = self.chain_head
        cp = {
            "kind": "effect", "seq": seq, "run_id": self._run_id, "policy_digest": self._policy_digest,
            "approval_id": self._approval_id, "tool": tool, "outcome": outcome.value,
            "payload": thaw(payload) if payload is not None else None, "error": error,
            "state_after": self._state.value, "admission_seq": admission_seq, "action_id": action_id,
            "produced_facts": list(produced),
        }
        rec = _hash(prev, cp)
        self._events.append(EffectEvent(
            seq=seq, run_id=self._run_id, policy_digest=self._policy_digest, approval_id=self._approval_id,
            tool=tool, outcome=outcome, payload=payload, error=error, state_after=self._state,
            admission_seq=admission_seq, action_id=action_id, produced_facts=tuple(produced),
            prev_hash=prev, record_hash=rec))
        return seq, rec

    def _extract_facts(self, step: int, payload, args: Mapping[str, Any]) -> tuple[list[tuple[str, Any, str]], bool]:
        """Run the step's producers on a confirmed payload, without storing yet.

        The producers see the payload and the admitted argument snapshot. Every
        declared producer must yield a value of its declared type. A missing
        field, a wrong type or a non-canonical value makes the whole step fail its
        post-effect check, so a confirmed effect whose result the monitor cannot
        validate does not advance the flow and produces no facts (fail-closed).

        Returns:
            A pair ``(outputs, ok)``. ``ok`` is False if any producer could not
            deliver a valid typed value, in which case ``outputs`` is empty.
        """
        specs = self._policy.producers_at(step)
        if not specs:
            return [], True
        if payload is None:
            return [], False
        outputs: list[tuple[str, Any, str]] = []
        for spec in specs:
            try:
                name, value, ftype = facts_mod.run_producer(spec, payload, args)
                frozen = facts_mod.build_value(value, ftype)
            except Exception:
                return [], False
            outputs.append((name, frozen, ftype))
        return outputs, True

    def _postconditions_hold(self, step: int, produced: Mapping[str, Any]) -> bool:
        """Check the step's postconditions against produced and earlier facts."""
        for spec in self._policy.postconditions_at(step):
            try:
                ok, _desc = facts_mod.eval_postcondition(spec, produced, self._facts)
            except Exception:
                return False
            if not ok:
                return False
        return True

    def submit(self, call: ToolCall) -> tuple[Decision, str, ToolResult | None]:
        """Mediate one attempted tool call, binding-aware and effect-aware.

        Args:
            call: The action the untrusted agent attempts.

        Returns:
            The decision, a short reason and the tool result. The result is
            None unless the effect is confirmed and passes the post-effect check.
        """
        try:
            snap = _snapshot(call)
        except Exception:
            with self._lock:
                minimal = ToolCall(tool="<malformed>", args=to_canonical({}))
                return self._deny(minimal, self._expected_tool(), "malformed call arguments (non-canonical)", terminal=True)

        with self._lock:
            if self._state is not PolicyState.ACTIVE:
                detail = "effect in progress" if self._state is PolicyState.EFFECT_PENDING else f"instance is {self._state.value}"
                return self._deny(snap, self._expected_tool(), f"not ACTIVE: {detail}", terminal=False)
            if self._clock.now() > self._expires_at:
                return self._deny(snap, self._expected_tool(), "approval validity window elapsed", terminal=True)

            step = self._cursor
            expected = self._expected_tool()

            if snap.tool != expected:
                return self._deny(snap, expected, f"out-of-policy action: expected {expected!r}, got {snap.tool!r}", terminal=True)

            ok, why = validate_args(snap.tool, snap.args)
            if not ok:
                return self._deny(snap, expected, f"argument schema violated: {why}", terminal=True)

            # 4. local constraint, fail-closed
            local = self._policy.local_at(step)
            if local is not None:
                try:
                    if not constraints.evaluate(local, snap.args, self._policy):
                        return self._deny(snap, expected, f"parameter constraint violated at step {step}: {constraints.describe(local, self._policy)}", terminal=True)
                except Exception:
                    return self._deny(snap, expected, "constraint evaluation error (fail-closed)", terminal=True)

            # 4b. cross-step bindings, fail-closed (V2)
            for b in self._policy.bindings_at(step):
                try:
                    passed, desc = facts_mod.eval_binding(b, snap.args, self._facts)
                except Exception:
                    return self._deny(snap, expected, "binding evaluation error (fail-closed)", terminal=True)
                if not passed:
                    return self._deny(snap, expected, f"cross-step binding violated at step {step}: {desc}", terminal=True)

            if self._remaining.get(snap.tool, 0) <= 0:
                return self._deny(snap, expected, f"consumption budget for {snap.tool!r} exhausted", terminal=True)

            action_id = snap.args.get("action_id")
            if isinstance(action_id, str):
                if not self._ledger.consume_action(self._run_id, action_id):
                    return self._deny(snap, expected, f"duplicate action_id {action_id!r} (idempotency)", terminal=True)

            self._remaining[snap.tool] = self._remaining.get(snap.tool, 0) - 1
            self._state = PolicyState.EFFECT_PENDING
            reason = "matches approved flow, local constraint and cross-step bindings; grant committed"
            self._append_admission(snap, expected, Decision.ALLOW, reason)
            admission_seq = self._events[-1].seq

        result = safe_execute(self._executor, snap)

        with self._lock:
            integrity_failed = False
            if result.outcome is EffectOutcome.CONFIRMED:
                # Extract facts first, so the effect event can name them and the
                # facts can be anchored to that single event's final hash. A
                # confirmed result that fails producer extraction or a
                # postcondition is treated as unreconciled: the world claims
                # success but the monitor cannot validate it, so the flow stops
                # fail-closed and no fact is recorded.
                outputs, extract_ok = self._extract_facts(step, result.payload, snap.args)
                produced_map = {name: value for name, value, _ft in outputs}
                if extract_ok and self._postconditions_hold(step, produced_map):
                    produced_names = tuple(o[0] for o in outputs)
                    self._cursor += 1
                    self._state = PolicyState.COMPLETED if self._cursor >= len(self._policy.allowed_flow) else PolicyState.ACTIVE
                    effect_seq, effect_hash = self._append_effect(snap.tool, result.outcome, result.payload, result.error, admission_seq, action_id, produced_names)
                    for name, value, ftype in outputs:
                        self._facts.put(ObservedFact(
                            name=name, value=value, ftype=ftype, source_tool=snap.tool, producing_seq=effect_seq,
                            run_id=self._run_id, fragment_id=f"fragment_{effect_seq}", timestamp=self._clock.now(),
                            integrity=effect_hash))
                else:
                    integrity_failed = True
                    self._state = PolicyState.EFFECT_UNCERTAIN
                    self._append_effect(snap.tool, result.outcome, result.payload,
                                        "post-effect integrity check failed (fail-closed)", admission_seq, action_id, ())
            elif result.outcome is EffectOutcome.FAILED:
                self._state = PolicyState.EFFECT_FAILED
                self._append_effect(snap.tool, result.outcome, result.payload, result.error, admission_seq, action_id, ())
            else:
                self._state = PolicyState.EFFECT_UNCERTAIN
                self._append_effect(snap.tool, result.outcome, result.payload, result.error, admission_seq, action_id, ())
            if integrity_failed:
                out_reason = f"{reason}; effect CONFIRMED, but post-effect integrity validation failed"
            else:
                out_reason = f"{reason}; effect {result.outcome.value}"

        # Only a confirmed and validated result is handed back to the agent. A
        # failed, uncertain or integrity-failed effect returns no payload, so the
        # agent can neither observe nor reuse a result the monitor did not validate.
        if result.outcome is EffectOutcome.CONFIRMED and not integrity_failed and result.payload is not None:
            tool_result = ToolResult(tool=snap.tool, payload=dict(result.payload))
        else:
            tool_result = None
        return Decision.ALLOW, out_reason, tool_result

    def _deny(self, snap, expected, reason, terminal) -> tuple[Decision, str, None]:
        """Deny under the lock, as booking_v1.monitor.PolicyMonitor._deny_locked does."""
        if terminal and self._state not in TERMINAL_STATES and self._state is not PolicyState.EFFECT_PENDING:
            self._state = PolicyState.TERMINATED
        self._append_admission(snap, expected, Decision.DENY, reason)
        return Decision.DENY, reason, None
