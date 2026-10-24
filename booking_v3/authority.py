"""The Authority: the minimal persistent trusted core.

The Authority runs no tool and evaluates no policy predicate (constraint,
binding, producer or postcondition). It keeps a small set of approval-bound
global invariants, among them the approved operation sequence (allowed_flow):
the operation of step i must be the one the approval named for step i. It
guards the global, order-sensitive properties no stateless component can
decide, and it does so before any effect runs:

    create_run                verifies the signed initial approval and mints
                              the signed genesis envelope S0
    request_execution_grant   the pre-effect atomic check, in this order:
                              runner channel and signature, session binding,
                              run status, freshness (latest state), step, policy
                              digest, the approved operation of that step,
                              approval window, intervention approval if the step
                              requires one, consumable right, unused action_id.
                              On success the run moves to EFFECT_PENDING and a
                              one-shot capability token is issued
    finalize_transition       verifies chain linkage and audit extension of
                              the proposed successor, archives the events,
                              signs S_{i+1} and advances the ledger

The per-run ledger holds hashes, counters, status and the archived admission and
effect events. It does not hold the fact store, which travels only inside the
signed envelope. Here the Authority trusts that a runner requesting a grant
established ALLOW (trusted-runner assumption). The attested deployments replace
that trust with attestation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from booking_v1.approval import Approval, kind_fits, verify as verify_approval
from booking_v1.clock import Clock
from booking_v1.effects import response_digest
from booking_v1.freeze import canonical_bytes, thaw, to_canonical
from booking_v1.lifecycle import PolicyState, TERMINAL_STATES

from .envelope import (
    SigningKey, TrustAnchors, StateEnvelope, VerifyKey, chain_extend,
    genesis_audit_head, genesis_previous_hash,
)
from .fragment import ActionFragment
from . import runner_attestation as ra

# Stand-in for the human approver's intervention signing key. In a real system
# this is the approver's own key and the Authority holds only the public half. The
# mock co-locates the approval interface with the Authority, so the Authority also
# carries the signing half (see Authority.__init__). This mirrors the approver-key
# mock of booking_v1.
_INTERVENTION_KEY = SigningKey()

# Validity windows, in seconds past issuance. A capability token that is not
# redeemed within TOKEN_TTL, and an intervention approval not resubmitted within
# INTERVENTION_TTL, are refused at the gateway and at the grant respectively.
# Both are demonstrable against a live clock.
TOKEN_TTL = 120
INTERVENTION_TTL = 300

#: Prefix of the note `finalize_transition` returns when it took over a terminal failure report
#: (no successor exists then). It is followed by the run state the Authority adopted. A refusal
#: does not carry it, so a caller can tell "taken over" from "refused".
ADOPTED_PREFIX = "adopted "


def adopted_state(note: str) -> str | None:
    """Return the run state the Authority adopted, from a `finalize_transition` note.

    Returns None for a note without ADOPTED_PREFIX, which is a refusal.
    """
    if not isinstance(note, str) or not note.startswith(ADOPTED_PREFIX):
        return None
    return note[len(ADOPTED_PREFIX):].split(":", 1)[0].strip() or None


@dataclass(frozen=True)
class CapabilityToken:
    """A single-use right to perform one request, minted per grant.

    Bound to the run, the step, the fragment (arguments included, via
    fragment_hash and authorized_request_hash) and one operation. The Tool
    Gateway verifies the signature, the binding and single use. Possession of
    a token is therefore worth one pre-authorised request.
    """

    run_id: str
    step_index: int
    fragment_hash: str
    operation: str
    authorized_request_hash: str
    grant_id: str
    expires_at: int
    signature: str

    def binding(self) -> dict:
        """Return the canonical content the token signature covers."""
        return {
            "kind": "capability-token",
            "run_id": self.run_id, "step_index": self.step_index,
            "fragment_hash": self.fragment_hash, "operation": self.operation,
            "authorized_request_hash": self.authorized_request_hash,
            "grant_id": self.grant_id, "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class ExecutionGrant:
    """The Authority's pre-effect admission commitment for one fragment."""

    grant_id: str
    run_id: str
    step_index: int
    fragment_hash: str
    issued_at: int
    token: CapabilityToken


@dataclass(frozen=True)
class InterventionApproval:
    """A human's mid-run authorisation of one fragment, time-bounded."""

    run_id: str
    step_index: int
    fragment_hash: str
    approver_id: str
    issued_at: int
    expires_at: int
    signature: str
    approver_kind: str = "passkey"

    def binding(self) -> dict:
        """Return the canonical content the approval signature covers."""
        return {
            "kind": "intervention-approval",
            "run_id": self.run_id, "step_index": self.step_index,
            "fragment_hash": self.fragment_hash, "approver_id": self.approver_id,
            "approver_kind": self.approver_kind,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
        }


def grant_id_of(run_id: str, step_index: int, fragment_hash: str, input_state_hash: str) -> str:
    """Return the deterministic id of the grant for one fragment on one state.

    This is the only place the derivation lives. The Authority issues the grant under this
    id. Every party that knows which fragment ran on which state (a recovery helper, the
    controller that checks what it shows) re-derives it here instead of taking it from a
    record it was handed.

    Args:
        run_id: The run.
        step_index: The step of the fragment.
        fragment_hash: The fragment's hash.
        input_state_hash: The state hash the fragment runs on.

    Returns:
        ``"grant-"`` followed by 24 hex characters.
    """
    return "grant-" + hashlib.sha256(canonical_bytes({
        "run_id": run_id, "step": step_index,
        "fragment_hash": fragment_hash, "state": input_state_hash,
    })).hexdigest()[:24]


def request_hash(operation: str, arguments: Mapping[str, Any]) -> str:
    """Return the canonical hash of one tool request.

    Args:
        operation: The tool name.
        arguments: The tool arguments.

    Returns:
        The SHA-256 hex digest over operation and thawed arguments.
    """
    return hashlib.sha256(canonical_bytes({
        "operation": operation, "arguments": thaw(arguments),
    })).hexdigest()


@dataclass(frozen=True)
class HumanApprovalCredential:
    """The bootstrap secret of the trusted human-approval interface.

    Held only by the component that fronts a real human approver. A durable
    deployment requires it on every decide_intervention call, so a party that
    can merely reach the service cannot mint additional authority by asking
    for grant=true. The attested deployments turn this into an attested
    admin/human channel. The mock models it as a construction-time secret.
    """

    secret: str = field(repr=False)


@dataclass(frozen=True)
class ProvisionerCredential:
    """The bootstrap secret of the trusted runner provisioner.

    Handed to one component, the RunnerProvisioner, at deployment time.
    Establishing a runner session requires it, so the untrusted orchestrator
    can ask the provisioner to start a runner but cannot obtain a
    RunnerCredential itself. The attested deployments replace this
    bootstrap by attestation evidence: a session is established only over
    attested TLS.
    """

    secret: str = field(repr=False)


class ProvisioningRefused(Exception):
    """Raised when a runner session is requested without the bootstrap."""


@dataclass(frozen=True)
class RunnerCredential:
    """The mock authenticated runner channel, bound to one fragment.

    Provisioned through the RunnerProvisioner to one trusted runner. The
    orchestrator does not receive it. The binding fields state what the session
    means: this runner was provisioned for fragment ``fragment_hash`` of run
    ``run_id`` on input state ``state_hash``. Every Authority interaction of the
    runner (grant, finalisation, denial and intervention reports) must present
    it and match the binding. A session is consumed by its first grant attempt
    (successful or not) or by one terminal report, so it serves one fragment.
    It stands in for the attested TLS session of booking_v5, which takes the
    same place in the protocol.
    """

    session_id: str
    run_id: str
    fragment_hash: str
    state_hash: str
    secret: str = field(repr=False)


@dataclass
class _RunnerSession:
    """The Authority's record of one runner session."""

    secret: str = field(repr=False)
    run_id: str
    fragment_hash: str
    state_hash: str
    state: str = "OPEN"          # OPEN -> (GRANTED ->) CLOSED
    grant_id: str | None = None
    #: Raw Ed25519 public key of the runner that owns this session, hex, or None.
    #: Set only where the runner can prove which key it holds, which means the attested
    #: booking_v5 TD (the key is covered by the quote and by RTMR3). When it is set,
    #: every state-changing call on this session must carry a signature by it. When it
    #: is None the session keeps the plain semantics. See runner_attestation.
    verify_key: str | None = None


@dataclass(frozen=True)
class TransitionRecord:
    """What a runner reports back after the effect phase."""

    run_id: str
    grant_id: str
    outcome: str            # CONFIRMED_VALIDATED | INTEGRITY_FAILED | FAILED | UNCERTAIN
    admission_event: Mapping[str, Any]
    effect_event: Mapping[str, Any]
    proposed: StateEnvelope | None   # unsigned successor. None unless CONFIRMED_VALIDATED


@dataclass
class _PendingGrant:
    """The grant a run is waiting to finalise, with its admission event."""

    grant_id: str
    fragment_hash: str
    step_index: int
    admission_event: Mapping[str, Any]


@dataclass
class _RunEntry:
    """The ledger entry of one run.

    ``events`` archives the chained admission and effect events, with arguments
    and payloads. ``notices`` holds the unchained notices.
    """

    policy_digest: str
    approval_id: str
    expires_at: int
    n_steps: int
    allowed_flow: tuple[str, ...]
    approval_required_steps: tuple[int, ...]
    remaining: dict[str, int]
    last_state_hash: str
    next_step: int = 0
    status: PolicyState = PolicyState.ACTIVE
    used_action_ids: set = field(default_factory=set)
    used_interventions: set = field(default_factory=set)
    pending: _PendingGrant | None = None
    audit_head: str = ""
    events: list = field(default_factory=list)
    notices: list = field(default_factory=list)


class Authority:
    """The persistent trusted core: signer, freshness ledger, audit archive."""

    def __init__(self, clock: Clock, bootstrap_secret: str) -> None:
        """Do not call directly at runtime. Construct via ``Authority.create``.

        The constructor takes the bootstrap secret so that it exists only in
        the deployment wiring that also hands it to the RunnerProvisioner.
        The runtime API of a constructed Authority offers no way to read it.

        The intervention verify key is instance configuration (defaulting to
        the module approver mock), not a module global read at verification
        time. A restarted Authority process must carry the same verification
        key, or existing human approvals would become invalid. The approver
        signing key belongs outside the Authority in a real system. The mock
        co-locates the human approval interface, so this instance holds the
        signing key too, signs approvals with it in ``decide_intervention`` and
        exports it in ``export_state``.

        Args:
            clock: The trusted clock.
            bootstrap_secret: The provisioner bootstrap secret.
        """
        self._clock = clock
        self._envelope_key = SigningKey()
        self._bootstrap_secret = bootstrap_secret
        self._human_secret = secrets.token_hex(16)
        self._intervention_verify_key = _INTERVENTION_KEY.verify_key()
        self._approver_key = _INTERVENTION_KEY
        self._runs: dict[str, _RunEntry] = {}
        self._sessions: dict[str, _RunnerSession] = {}
        self._lock = threading.Lock()
        # Wiring, not state: a read-only view of the gateway's effect ledger, bound by the
        # deployment (`bind_effect_ledger`). It is absent from `export_state`, because it is
        # a connection to another service and not something to restore.
        self._effect_ledger = None
        # Wiring, not state, like the ledger above: the admission rule of the world this
        # deployment serves (`bind_policy_admission`). Absent from `export_state`.
        self._policy_admission = None

    def bind_policy_admission(self, admit) -> None:
        """Refuse to activate policies the deployed world cannot execute.

        `admit(policy)` raises a `ValueError` for a policy outside the world, and
        `create_run` calls it before any envelope exists. The rule itself belongs to the
        world description (`booking_live.startup.admit_policy`), so this class names no
        tool. When nothing is bound, behaviour is unchanged, which keeps the frozen ablations
        over the catalogue comparable. The check applies where a live world is deployed.
        """
        self._policy_admission = admit

    def bind_effect_ledger(self, ledger) -> None:
        """Give this Authority a read-only view of the gateway's effect ledger.

        With a ledger bound, `finalize_transition` checks that the response a runner reports
        is the response the gateway recorded for that grant, and refuses the transition
        otherwise. Without one, that path is unchanged, which keeps the frozen ablations
        comparable. The check is bound on the stage whose threat model introduces a hostile
        host beneath the runner. The runner attestation follows the same rule.
        """
        self._effect_ledger = ledger

    def observation_check(self) -> str:
        """Report whether reported observations can be checked against the effect ledger.

        Returns "unbound" when no ledger is wired, "unreachable" when it is wired but does
        not answer, and "bound" when it answers. Only in the "bound" state can a
        finalisation be checked. A wired but unreachable ledger is reported separately,
        because every read would then hang and every finalisation would fail closed after
        a timeout while the run records claimed "bound". The probe is the cheapest read on
        the observation surface and touches no run state.
        """
        if self._effect_ledger is None:
            return "unbound"
        try:
            self._effect_ledger.high_watermark()
        except Exception:
            return "unreachable"
        return "bound"

    #: Delay before the single re-read when the ledger answers PENDING. Under the
    #: invariant in `booking_v4.durable.DurableStore.ledger_effect` a response cannot exist
    #: before its COMMITTED row, so the re-read only covers a read that overtook a commit
    #: across two processes. A row that is still PENDING afterwards is a refusal.
    _LEDGER_REREAD_SECONDS = 0.05

    def _observation_matches(self, grant_id: str, effect: Mapping[str, Any]) -> tuple[bool, str]:
        """Check whether the reported effect is the one the gateway recorded.

        `grant_id` is the Authority's own pending grant, not a field of the record, because
        a record naming its own grant could point at any row with a matching digest. The
        attested verdicts follow the same rule and are reconstructed here rather than read
        out of the request.

        Both sides compute `booking_v1.effects.response_digest` over outcome and payload.
        The gateway wrote its digest into the COMMITTED row of its ledger inside the
        transaction that made the outcome durable, so the value did not travel over the
        network the host controls.

        The check fails closed. A missing row, a row still PENDING after one short re-read
        and an unreachable ledger all refuse, so cutting the connection to the ledger does
        not disable the check.

        Args:
            grant_id: The Authority's pending grant.
            effect: The canonical effect event the runner reported.

        Returns:
            A pair (ok, reason).
        """
        if self._effect_ledger is None:
            return True, "no effect ledger bound for this stage"
        for attempt in (0, 1):
            try:
                state, recorded = self._effect_ledger.effect(grant_id)
            except Exception as exc:
                return False, f"effect ledger unreachable ({type(exc).__name__})"
            if state == "COMMITTED" and recorded is not None:
                break
            if state == "PENDING" and attempt == 0:
                time.sleep(self._LEDGER_REREAD_SECONDS)
                continue
            if state == "PENDING":
                return False, "observation-pending: the gateway recorded no outcome for this grant"
            return False, "no committed effect recorded for this grant"
        reported = response_digest(effect.get("outcome"), effect.get("payload"))
        if not hmac.compare_digest(recorded, reported):
            return False, "observation-mismatch"
        return True, "observation matches the recorded effect"

    def _parked_state(self, outcome: str, grant_id: str, effect: Mapping[str, Any]) -> tuple[PolicyState, str]:
        """Return the fail-closed state for a report that is not a validated confirmation.

        Without a bound effect ledger the runner's label is believed. With one, a label
        that asserts something the ledger can contradict is checked against it, and the
        runner's label does not override what the gateway recorded:

          UNCERTAIN         asserts nothing, so it is taken as given (EFFECT_UNCERTAIN).
          FAILED            asserts that no effect happened. Accepted only when the gateway
                            has no row for this grant, or its committed row is a failure. A
                            pending row, an unreachable ledger or a row of a different
                            outcome do not yield FAILED, because missing or uncertain
                            evidence shows neither "no effect" nor success.
          INTEGRITY_FAILED  asserts a confirmed but invalid effect. Accepted only when the
                            committed row is a confirmation of the reported payload.

        A committed row that the report contradicts parks the run for reconciliation
        (EFFECT_RECONCILE).

        Args:
            outcome: The runner's label.
            grant_id: The Authority's pending grant.
            effect: The canonical effect event the runner reported.

        Returns:
            The state to adopt and a note for the caller.
        """
        plain = f"effect {outcome}; run parked fail-closed"
        if outcome == "UNCERTAIN" or self._effect_ledger is None:
            return (PolicyState.EFFECT_FAILED if outcome == "FAILED" else PolicyState.EFFECT_UNCERTAIN), plain
        state, recorded = None, None
        for attempt in (0, 1):
            try:
                state, recorded = self._effect_ledger.effect(grant_id)
            except Exception as exc:
                return (PolicyState.EFFECT_UNCERTAIN,
                        f"effect ledger unreachable ({type(exc).__name__}): no evidence, outcome unknown; "
                        "run parked fail-closed")
            if state == "PENDING" and attempt == 0:
                time.sleep(self._LEDGER_REREAD_SECONDS)
                continue
            break
        if state == "PENDING":
            return (PolicyState.EFFECT_UNCERTAIN,
                    "the gateway recorded a dispatch without an outcome: outcome unknown; run parked fail-closed")
        verified = None
        if state == "COMMITTED" and recorded is not None:
            for candidate in ("CONFIRMED", "FAILED", "UNCERTAIN"):
                if hmac.compare_digest(response_digest(candidate, effect.get("payload")), recorded):
                    verified = candidate
                    break
        reconcile = (PolicyState.EFFECT_RECONCILE,
                     "reported outcome contradicts the gateway ledger; run parked for reconciliation")
        if outcome == "FAILED":
            if state is None or verified == "FAILED":
                return PolicyState.EFFECT_FAILED, plain
            return reconcile
        # INTEGRITY_FAILED (and any other label): a confirmed effect that the runner could not validate
        if verified == "CONFIRMED":
            return PolicyState.EFFECT_UNCERTAIN, plain
        return reconcile

    def verify_human(self, credential) -> bool:
        """Return whether a presented human-approval credential is the provisioned one."""
        return (isinstance(credential, HumanApprovalCredential)
                and isinstance(credential.secret, str)
                and hmac.compare_digest(self._human_secret, credential.secret))

    @classmethod
    def create(cls, clock: Clock) -> tuple["Authority", ProvisionerCredential, HumanApprovalCredential]:
        """Construct an Authority with its provisioner bootstrap and human-approval credential.

        The bootstrap credential is returned once, here, to the deployment wiring that
        constructs the RunnerProvisioner (see provisioner.create_deployment). The
        runtime API offers no call that returns it, so a party holding an Authority
        reference, the untrusted orchestrator included, cannot obtain it. The human
        credential goes to the component that fronts the human approver. The attested
        deployments replace the construction-time bootstrap by attestation evidence.

        Args:
            clock: The trusted clock.

        Returns:
            The Authority, the ProvisionerCredential and the HumanApprovalCredential.
        """
        secret = secrets.token_hex(16)
        authority = cls(clock, secret)
        return (authority, ProvisionerCredential(secret=secret),
                HumanApprovalCredential(secret=authority._human_secret))

    # Provisioning.
    def anchors(self) -> TrustAnchors:
        """Return the public keys runners are provisioned with."""
        return TrustAnchors(
            envelope_key=self._envelope_key.verify_key(),
            intervention_key=self._intervention_verify_key)

    def establish_runner_session(
        self, bootstrap: ProvisionerCredential, run_id: str,
        fragment_hash: str, state_hash: str, verify_key: bytes | None = None,
    ) -> RunnerCredential:
        """Provision the authenticated channel of one trusted runner.

        Requires the provisioner bootstrap and binds the session to one fragment on
        one input state, so a session does not mean "this party may request grants"
        but only "this runner was provisioned for F_i on S_i". booking_v5 fills this
        seam with attested TLS.

        With a key recorded, possession of the credential alone does not move this run:
        every state-changing call must also carry a signature over the statement the
        Authority itself reconstructs.

        Args:
            bootstrap: The provisioner bootstrap credential.
            run_id: The run the session serves.
            fragment_hash: The fragment the runner was provisioned for.
            state_hash: The input state the fragment runs on.
            verify_key: The raw Ed25519 public key of the runner that will use this
                session, where the provisioning path can establish which key that is.
                booking_v5 passes the pk_sig the hardware quote covers. booking_v3 and
                booking_v4 pass nothing and keep the plain semantics.

        Returns:
            The RunnerCredential for the runner.

        Raises:
            ProvisioningRefused: Without a valid bootstrap or for an unknown
                run.
        """
        with self._lock:
            if (not isinstance(bootstrap, ProvisionerCredential)
                    or not isinstance(bootstrap.secret, str)
                    or not hmac.compare_digest(self._bootstrap_secret, bootstrap.secret)):
                raise ProvisioningRefused("runner provisioning requires the provisioner bootstrap")
            if run_id not in self._runs:
                raise ProvisioningRefused(f"unknown run {run_id!r}")
            session_id = f"rs-{len(self._sessions)}-{secrets.token_hex(4)}"
            secret = secrets.token_hex(16)
            self._sessions[session_id] = _RunnerSession(
                secret=secret, run_id=run_id, fragment_hash=fragment_hash,
                state_hash=state_hash,
                verify_key=None if verify_key is None else bytes(verify_key).hex())
            return RunnerCredential(
                session_id=session_id, run_id=run_id, fragment_hash=fragment_hash,
                state_hash=state_hash, secret=secret)

    @staticmethod
    def _verdict_key(session: _RunnerSession) -> VerifyKey | None:
        """Return the runner key this session's calls must be signed with.

        Returns None for a session without attested decisions.
        """
        if session.verify_key is None:
            return None
        return VerifyKey.from_bytes(bytes.fromhex(session.verify_key))

    def _attested(self, session: _RunnerSession, expected: Mapping[str, Any],
                  attestation) -> tuple[bool, str]:
        """Check whether this call carries the runner's own signature over `expected`.

        `expected` is built by the caller in this class, from the Authority's ledger and
        from the request it is about to act on. No field is taken from the presented
        attestation, so an attacker who holds the credential still cannot state a verdict
        without the runner's key.
        """
        return ra.require(self._verdict_key(session), expected, attestation)

    def _session(self, credential) -> _RunnerSession | None:
        """Authenticate a presented credential. None means unauthenticated."""
        if not isinstance(credential, RunnerCredential):
            return None
        session = self._sessions.get(credential.session_id)
        if session is None or not isinstance(credential.secret, str):
            return None
        if not hmac.compare_digest(session.secret, credential.secret):
            return None
        return session

    # Views.
    def status(self, run_id: str) -> PolicyState | None:
        """Return the lifecycle state of a run, or None if the run is unknown."""
        entry = self._runs.get(run_id)
        return entry.status if entry else None

    def audit(self, run_id: str) -> tuple[tuple[Mapping[str, Any], ...], str]:
        """Return the chained event payloads and the current audit head."""
        entry = self._runs[run_id]
        return tuple(entry.events), entry.audit_head

    def notices(self, run_id: str) -> tuple[Mapping[str, Any], ...]:
        """Return the unchained notices (e.g. pending interventions)."""
        return tuple(self._runs[run_id].notices)

    def run_is_at(self, run_id: str, step_index: int, state_hash: str) -> bool:
        """Return whether the run is active, at `step_index` and holding `state_hash`.

        Read only: nothing is booked and nothing is consumed. booking_v5 asks this before it
        issues a challenge and again before it appraises evidence, so hardware evidence is
        not spent on a step the Authority would refuse anyway. The atomic claim of the step
        stays in the grant path.

        Args:
            run_id: The run.
            step_index: The step the caller is about to act on.
            state_hash: The state hash the caller holds.

        Returns:
            True if the run is ACTIVE at that step and state.
        """
        with self._lock:
            entry = self._runs.get(run_id)
            return (entry is not None and entry.status is PolicyState.ACTIVE
                    and step_index == entry.next_step
                    and state_hash == entry.last_state_hash)

    def intervention_pending(self, run_id: str, step_index: int, fragment_hash: str) -> bool:
        """Return whether this fragment awaits a human decision.

        True if and only if a runner reported it (`report_intervention_required` recorded
        the notice, so the Authority itself has seen the fragment hash), the approval for
        it has not been consumed, and the run is not terminal. This is the Authority's
        own, persisted answer. `decide_intervention` and the booking_v5 continuation
        session are gated on it.

        Args:
            run_id: The run.
            step_index: The step that needs approval.
            fragment_hash: The fragment awaiting the decision.

        Returns:
            Whether the fragment awaits a human decision.
        """
        with self._lock:
            entry = self._runs.get(run_id)
            if entry is None or entry.status in TERMINAL_STATES:
                return False
            if fragment_hash in entry.used_interventions:
                return False
            return any(n.get("kind") == "intervention-pending" and n.get("step_index") == step_index
                       and n.get("fragment_hash") == fragment_hash for n in entry.notices)

    # Lifecycle.
    def create_run(self, policy, approval: Approval, run_id: str) -> StateEnvelope:
        """Verify the initial approval and mint the signed genesis envelope S0.

        Args:
            policy: The approved policy.
            approval: The signed initial approval.
            run_id: The run to activate.

        Returns:
            The signed genesis envelope.

        Raises:
            booking_v1.approval.ApprovalError: On a bad approval.
            ValueError: On a duplicate run activation, or from the bound policy
                admission rule.
        """
        verify_approval(approval, policy, run_id=run_id, clock=self._clock)
        if self._policy_admission is not None:
            self._policy_admission(policy)
        digest = policy.digest()
        binding_digest = hashlib.sha256(canonical_bytes(approval.binding())).hexdigest()
        with self._lock:
            if run_id in self._runs:
                raise ValueError(f"run {run_id!r} was already activated")
            head = genesis_audit_head(run_id, digest, approval.approval_id)
            s0 = StateEnvelope(
                run_id=run_id, policy_digest=digest, approval_id=approval.approval_id,
                step_index=0, facts={}, audit_head=head,
                previous_state_hash=genesis_previous_hash(run_id, digest, binding_digest))
            s0 = s0.with_signature(self._envelope_key.sign(s0.state_hash.encode()))
            self._runs[run_id] = _RunEntry(
                policy_digest=digest, approval_id=approval.approval_id,
                expires_at=approval.expires_at, n_steps=len(policy.allowed_flow),
                allowed_flow=tuple(policy.allowed_flow),
                approval_required_steps=tuple(getattr(policy, "approval_required_steps", ())),
                remaining=dict(policy.max_executions),
                last_state_hash=s0.state_hash, audit_head=head)
            return s0

    def request_execution_grant(
        self,
        credential: RunnerCredential,
        fragment: ActionFragment,
        input_state_hash: str,
        admission_event: Mapping[str, Any],
        intervention: InterventionApproval | None = None,
        attestation: "ra.RunnerAttestation | None" = None,
    ) -> tuple[ExecutionGrant | None, str]:
        """Run the atomic pre-effect check. A refusal means no effect was executed.

        The checks run in this order under one lock: channel and runner signature,
        session binding, run status, freshness, step, policy digest, approved operation,
        approval window, intervention, consumable right, action_id. All are decided
        against one consistent ledger state before any capability exists.

        On a session that records a runner verdict key, the Authority requires the
        runner's own signature over the admission it is asked to act on: this fragment,
        these arguments, this request hash, this audit event. The Authority still does
        not evaluate policy constraints, but holding the credential is not enough for an
        ALLOW. On a session without such a key the ALLOW is trusted because it arrives on
        a provisioned session.

        Args:
            credential: The runner's session credential.
            fragment: The fragment the runner admitted.
            input_state_hash: The state hash the fragment runs on.
            admission_event: The runner's admission event for the fragment.
            intervention: The human approval, for a step that requires one.
            attestation: The runner's signature, for a session with a verdict key.

        Returns:
            The grant and "granted", or None and the refusal reason.
        """
        with self._lock:
            session = self._session(credential)
            if session is None or session.state != "OPEN":
                return None, "unauthenticated runner channel (grant refused)"
            # The runner's signature is checked before the session is consumed, so a
            # forged or unsigned request cannot spend the honest runner's one attempt.
            authorized_request_hash = request_hash(fragment.operation, fragment.arguments)
            ok, why = self._attested(session, ra.grant_statement(
                run_id=fragment.run_id, step=fragment.fragment_index,
                state_hash=input_state_hash, fragment_hash=fragment.fragment_hash,
                operation=fragment.operation, request_hash=authorized_request_hash,
                admission_hash=ra.event_digest(admission_event)), attestation)
            if not ok:
                return None, f"{why} (grant refused)"
            # Every grant attempt consumes the session. Only a successful grant
            # re-opens it as GRANTED, for the single finalisation that answers it.
            session.state = "CLOSED"
            if (session.run_id != fragment.run_id
                    or session.fragment_hash != fragment.fragment_hash
                    or session.state_hash != input_state_hash):
                return None, "runner session does not bind this fragment and input state"
            entry = self._runs.get(fragment.run_id)
            if entry is None:
                return None, "unknown run"
            if entry.status in TERMINAL_STATES:
                return None, f"run is {entry.status.value}"
            if entry.status is PolicyState.EFFECT_PENDING:
                return None, "effect in progress (concurrent grant refused)"
            if input_state_hash != entry.last_state_hash:
                return None, "stale or unknown input state (freshness)"
            if fragment.fragment_index != entry.next_step:
                return None, f"step mismatch: expected {entry.next_step}, got {fragment.fragment_index}"
            if fragment.policy_digest != entry.policy_digest:
                return None, "policy digest does not match the approved run"
            # The approved operation sequence. The runner's signed ALLOW covers the
            # runner's own decision. It does not tell the Authority which operation the approval
            # named for this step, and the approval requirement and the consumption budget are
            # keyed by step and by operation separately, so without this check a bound runner could
            # name a payment at a step that needs no approval.
            if (fragment.fragment_index >= len(entry.allowed_flow)
                    or fragment.operation != entry.allowed_flow[fragment.fragment_index]):
                return None, (f"operation {fragment.operation!r} is not the approved operation "
                              f"of step {fragment.fragment_index}")
            now = self._clock.now()
            if now > entry.expires_at:
                entry.status = PolicyState.TERMINATED
                return None, "approval validity window elapsed"
            if fragment.fragment_index in entry.approval_required_steps:
                ok, why = self._intervention_valid(entry, fragment, intervention, now)
                if not ok:
                    return None, f"manual intervention required: {why}"
            if entry.remaining.get(fragment.operation, 0) <= 0:
                return None, f"consumption budget for {fragment.operation!r} exhausted"
            if fragment.action_id is not None:
                if fragment.action_id in entry.used_action_ids:
                    return None, f"duplicate action_id {fragment.action_id!r} (idempotency)"
                entry.used_action_ids.add(fragment.action_id)
            if fragment.fragment_index in entry.approval_required_steps:
                entry.used_interventions.add(fragment.fragment_hash)
            entry.remaining[fragment.operation] -= 1
            entry.status = PolicyState.EFFECT_PENDING
            grant_id = grant_id_of(fragment.run_id, fragment.fragment_index,
                                   fragment.fragment_hash, input_state_hash)
            # Same layout as CapabilityToken.binding(), which the gateway verifies.
            token_binding = {
                "kind": "capability-token",
                "run_id": fragment.run_id, "step_index": fragment.fragment_index,
                "fragment_hash": fragment.fragment_hash, "operation": fragment.operation,
                "authorized_request_hash": authorized_request_hash,
                "grant_id": grant_id, "expires_at": now + TOKEN_TTL,
            }
            token = CapabilityToken(
                signature=self._envelope_key.sign(canonical_bytes(token_binding)),
                **{k: v for k, v in token_binding.items() if k != "kind"})
            entry.pending = _PendingGrant(
                grant_id=grant_id, fragment_hash=fragment.fragment_hash,
                step_index=fragment.fragment_index,
                admission_event=to_canonical(dict(admission_event)))
            session.state = "GRANTED"
            session.grant_id = grant_id
            return ExecutionGrant(
                grant_id=grant_id, run_id=fragment.run_id,
                step_index=fragment.fragment_index,
                fragment_hash=fragment.fragment_hash, issued_at=now, token=token), "granted"

    def export_state(self) -> dict:
        """Return a canonical snapshot of all durable state.

        Everything the freshness, idempotency and session guarantees depend on is
        captured: the envelope signing key, the bootstrap and human secrets, the
        intervention verify and signing keys, every run entry (ledger, counters,
        pending grant, audit chain, events, notices) and every runner session.
        Restoring this snapshot reproduces the decision state.
        """
        with self._lock:
            runs = {}
            for run_id, entry in self._runs.items():
                runs[run_id] = {
                    "policy_digest": entry.policy_digest,
                    "approval_id": entry.approval_id,
                    "expires_at": entry.expires_at,
                    "n_steps": entry.n_steps,
                    "allowed_flow": list(entry.allowed_flow),
                    "approval_required_steps": list(entry.approval_required_steps),
                    "remaining": dict(entry.remaining),
                    "last_state_hash": entry.last_state_hash,
                    "next_step": entry.next_step,
                    "status": entry.status.value,
                    "used_action_ids": sorted(entry.used_action_ids),
                    "used_interventions": sorted(entry.used_interventions),
                    "pending": None if entry.pending is None else {
                        "grant_id": entry.pending.grant_id,
                        "fragment_hash": entry.pending.fragment_hash,
                        "step_index": entry.pending.step_index,
                        "admission_event": thaw(entry.pending.admission_event)},
                    "audit_head": entry.audit_head,
                    "events": [thaw(event) for event in entry.events],
                    "notices": [thaw(notice) for notice in entry.notices]}
            sessions = {sid: {
                "secret": s.secret, "run_id": s.run_id,
                "fragment_hash": s.fragment_hash, "state_hash": s.state_hash,
                "state": s.state, "grant_id": s.grant_id,
                "verify_key": s.verify_key}
                for sid, s in self._sessions.items()}
            return {"bootstrap_secret": self._bootstrap_secret,
                    "human_secret": self._human_secret,
                    "signing_key": self._envelope_key.to_bytes().hex(),
                    "intervention_verify_key": self._intervention_verify_key.to_bytes().hex(),
                    "approver_key": self._approver_key.to_bytes().hex(),
                    "runs": runs, "sessions": sessions}

    @classmethod
    def restore(cls, clock: Clock, state: Mapping[str, Any]) -> "Authority":
        """Rebuild an Authority from a snapshot taken by ``export_state``.

        Args:
            clock: The trusted clock for the restored instance.
            state: The snapshot.

        Returns:
            The restored Authority.

        Raises:
            KeyError: If the snapshot lacks a required field.
        """
        authority = cls(clock, state["bootstrap_secret"])
        authority._human_secret = state["human_secret"]
        authority._envelope_key = SigningKey.from_bytes(bytes.fromhex(state["signing_key"]))
        authority._intervention_verify_key = VerifyKey.from_bytes(
            bytes.fromhex(state["intervention_verify_key"]))
        authority._approver_key = SigningKey.from_bytes(bytes.fromhex(state["approver_key"]))
        for run_id, r in state["runs"].items():
            entry = _RunEntry(
                policy_digest=r["policy_digest"], approval_id=r["approval_id"],
                expires_at=r["expires_at"], n_steps=r["n_steps"],
                allowed_flow=tuple(r["allowed_flow"]),
                approval_required_steps=tuple(r["approval_required_steps"]),
                remaining=dict(r["remaining"]),
                last_state_hash=r["last_state_hash"])
            entry.next_step = r["next_step"]
            entry.status = PolicyState(r["status"])
            entry.used_action_ids = set(r["used_action_ids"])
            entry.used_interventions = set(r["used_interventions"])
            if r["pending"] is not None:
                entry.pending = _PendingGrant(
                    grant_id=r["pending"]["grant_id"],
                    fragment_hash=r["pending"]["fragment_hash"],
                    step_index=r["pending"]["step_index"],
                    admission_event=to_canonical(dict(r["pending"]["admission_event"])))
            entry.audit_head = r["audit_head"]
            entry.events = [to_canonical(dict(event)) for event in r["events"]]
            entry.notices = [to_canonical(dict(notice)) for notice in r["notices"]]
            authority._runs[run_id] = entry
        for sid, s in state["sessions"].items():
            authority._sessions[sid] = _RunnerSession(
                secret=s["secret"], run_id=s["run_id"],
                fragment_hash=s["fragment_hash"], state_hash=s["state_hash"],
                state=s["state"], grant_id=s["grant_id"],
                verify_key=s.get("verify_key"))
        return authority

    def import_state(self, state: Mapping[str, Any]) -> None:
        """Load a snapshot into this instance.

        Used for in-memory rollback when a durable commit fails. The memory state is
        reset to the last durable snapshot, so it matches the store again.
        """
        restored = Authority.restore(self._clock, state)
        with self._lock:
            self._bootstrap_secret = restored._bootstrap_secret
            self._human_secret = restored._human_secret
            self._envelope_key = restored._envelope_key
            self._intervention_verify_key = restored._intervention_verify_key
            self._approver_key = restored._approver_key
            self._runs = restored._runs
            self._sessions = restored._sessions

    def revoke_runner_session(self, credential: RunnerCredential) -> None:
        """Close a session whose runner never started.

        Closing a still-OPEN session early can only remove authority, so this
        changes no protocol semantics. It keeps the session lifecycle clean when
        provisioning fails between session establishment and a successful runner
        bootstrap, and in the deployed versions after a pod scheduling failure, an
        eviction, a failed attestation or aborted provisioning.
        """
        with self._lock:
            session = self._session(credential)
            if session is not None and session.state == "OPEN":
                session.state = "CLOSED"

    def token_key(self):
        """Return the verification key the Tool Gateway checks tokens with."""
        return self._envelope_key.verify_key()

    def finalize_transition(self, credential: RunnerCredential, record: TransitionRecord,
                            attestation: "ra.RunnerAttestation | None" = None) -> tuple[StateEnvelope | None, str]:
        """Verify and sign the successor state, or record the failed effect.

        Only a CONFIRMED_VALIDATED outcome yields a signed successor. Every
        other outcome parks the run in its fail-closed terminal state, so no
        later step can build on an unvalidated result.

        The successor is composed by the runner and signed here, and the Authority checks
        its linkage rather than its meaning. That is only sound while the proposal comes
        from the runner: the facts inside it are what every later step is admitted
        against. On a session with a verdict key the proposal is therefore named by its
        state hash inside the runner's signature, so a party on the channel cannot have an
        invented fact store signed into a successor envelope.

        Trust boundary. What the Authority guarantees is the cryptographic
        integrity of the state, not the correct derivation of the facts in it. It
        authenticates the proposal, links it to the open grant and compares the reported
        effect (`outcome`, `payload`) with the gateway's record. It does not recompute
        `proposed.facts` from that effect, and does not check them against the producers of
        the policy. A bound runner that is already compromised can therefore have a fact it
        invented signed, although the effect it reports is the true one.
        `booking_v5.tests_successor_fact_boundary` reproduces this boundary. It is stated
        as an assumption: the monitor and state-transition logic inside the bound runner
        is correct.

        Args:
            credential: The runner's session credential, in state GRANTED.
            record: The runner's report for the open grant.
            attestation: The runner's signature, for a session with a verdict key.

        Returns:
            The signed successor and "successor signed", or None and a note. A note
            starting with ADOPTED_PREFIX means the report was accepted and the run
            parked. Any other note is a refusal.
        """
        with self._lock:
            session = self._session(credential)
            if session is None or session.state != "GRANTED" or session.grant_id != record.grant_id:
                return None, "unauthenticated runner channel (finalization refused)"
            ok, why = self._attested(session, ra.finalize_statement(
                run_id=record.run_id, grant_id=record.grant_id, outcome=record.outcome,
                admission_hash=ra.event_digest(record.admission_event),
                effect_hash=ra.event_digest(record.effect_event),
                proposed_state_hash="" if record.proposed is None else record.proposed.state_hash,
            ), attestation)
            if not ok:
                return None, f"{why} (finalization refused)"
            session.state = "CLOSED"
            entry = self._runs.get(record.run_id)
            if entry is None:
                return None, "unknown run"
            if entry.status is not PolicyState.EFFECT_PENDING or entry.pending is None:
                return None, "no effect is pending for this run"
            if record.grant_id != entry.pending.grant_id:
                return None, "record does not answer the open grant"
            pending = entry.pending
            try:
                admission = to_canonical(dict(record.admission_event))
                effect = to_canonical(dict(record.effect_event))
            except Exception:
                return None, "events do not canonicalise"
            # The finalisation must answer the grant the Authority opened: the
            # same admission event, and an effect event naming the granted run,
            # step and fragment. This is identity checking, not policy evaluation.
            if canonical_bytes(admission) != canonical_bytes(pending.admission_event):
                return None, "admission event does not match the granted admission"
            if (effect.get("kind") != "effect"
                    or effect.get("run_id") != record.run_id
                    or effect.get("step_index") != pending.step_index
                    or effect.get("fragment_hash") != pending.fragment_hash):
                return None, "effect event does not answer the open grant"
            new_head = chain_extend(entry.audit_head, [admission, effect])

            if record.outcome == "CONFIRMED_VALIDATED":
                # The values inside the proposal become the facts every later step is
                # admitted against, and they were read out of a response that travelled
                # from the gateway to the runner over a network the host controls. This
                # comparison ties them to the response the gateway recorded.
                ok, why = self._observation_matches(pending.grant_id, effect)
                if not ok:
                    # EFFECT_RECONCILE, not EFFECT_UNCERTAIN: the outcome is known and
                    # committed, but the run may not follow the report. A person has to
                    # reconcile the two rather than retry.
                    entry.events.extend([admission, effect])
                    entry.audit_head = new_head
                    entry.pending = None
                    entry.status = PolicyState.EFFECT_RECONCILE
                    return None, f"{ADOPTED_PREFIX}{PolicyState.EFFECT_RECONCILE.value}: {why}; run parked for reconciliation"
                proposed = record.proposed
                if proposed is None:
                    return None, "confirmed outcome without a proposed successor"
                if (proposed.run_id != record.run_id
                        or proposed.policy_digest != entry.policy_digest
                        or proposed.approval_id != entry.approval_id):
                    return None, "proposed successor is bound to different run material"
                if proposed.previous_state_hash != entry.last_state_hash:
                    return None, "proposed successor does not extend the last signed state"
                if proposed.step_index != pending.step_index + 1:
                    return None, "proposed successor has wrong step arithmetic"
                if proposed.audit_head != new_head:
                    return None, "proposed successor does not carry the extended audit head"
                # StateEnvelope construction recomputed and checked state_hash.
                # Nothing above or below derives `proposed.facts` from the effect: they are the
                # bound runner's statement, vouched for by its signature over the state hash
                # (trust boundary, see the docstring).
                signed = proposed.with_signature(self._envelope_key.sign(proposed.state_hash.encode()))
                entry.events.extend([admission, effect])
                entry.audit_head = new_head
                entry.last_state_hash = signed.state_hash
                entry.next_step = pending.step_index + 1
                entry.status = PolicyState.COMPLETED if entry.next_step >= entry.n_steps else PolicyState.ACTIVE
                entry.pending = None
                return signed, "successor signed"

            status, note = self._parked_state(record.outcome, pending.grant_id, effect)
            entry.events.extend([admission, effect])
            entry.audit_head = new_head
            entry.pending = None
            entry.status = status
            # An accepted terminal report has no successor either, so `None` alone cannot say
            # "taken over" from "refused". The note carries the state the Authority adopted, and
            # only an accepted report does.
            return None, f"{ADOPTED_PREFIX}{status.value}: {note}"

    def report_denial(self, credential: RunnerCredential, run_id: str,
                      admission_event: Mapping[str, Any],
                      attestation: "ra.RunnerAttestation | None" = None) -> bool:
        """Archive a runner's DENY and terminate the run (booking_v2 terminal semantics).

        Only an authenticated runner session can terminate a run this way, so
        a party without a credential cannot kill runs with fake denials.

        The report travels over a channel a hostile host reads. With a verdict key on the
        session the report must be signed, and the signature is over a DENY statement, so
        it can neither be turned into an ALLOW nor replayed onto the grant path.

        Args:
            credential: The runner's session credential, in state OPEN.
            run_id: The run.
            admission_event: The runner's DENY admission event.
            attestation: The runner's signature, for a session with a verdict key.

        Returns:
            Whether the report was acted on, so a runner whose report was refused
            can tell.
        """
        with self._lock:
            session = self._session(credential)
            if (session is None or session.state != "OPEN" or session.run_id != run_id
                    or session.fragment_hash != admission_event.get("fragment_hash")):
                return False
            ok, _why = self._attested(session, ra.deny_statement(
                run_id=run_id, state_hash=session.state_hash,
                fragment_hash=session.fragment_hash,
                admission_hash=ra.event_digest(admission_event)), attestation)
            if not ok:
                return False
            session.state = "CLOSED"
            entry = self._runs.get(run_id)
            if entry is None:
                return False
            try:
                event = to_canonical(dict(admission_event))
            except Exception:
                event = to_canonical({"kind": "admission", "decision": "DENY", "reason": "malformed event"})
            if entry.status is PolicyState.EFFECT_PENDING:
                # An effect of another fragment is in flight. Extending the chain here would
                # move the head the pending runner built its successor on, so its finalisation
                # would be refused and the effect would not enter the chain. The run would
                # then stay in EFFECT_PENDING with no further grant and no finalisation.
                # The denial is therefore recorded as a notice outside the chain, like a
                # pending intervention. The denied fragment could not run anyway: its
                # session is consumed and its step belongs to the effect in flight.
                entry.notices.append(to_canonical({
                    "kind": "denial-while-effect-pending", "run_id": run_id,
                    "fragment_hash": session.fragment_hash, "admission": thaw(event)}))
                return True
            entry.events.append(event)
            entry.audit_head = chain_extend(entry.audit_head, [event])
            if entry.status not in TERMINAL_STATES:
                entry.status = PolicyState.TERMINATED
            return True

    def report_intervention_required(self, credential: RunnerCredential, run_id: str,
                                     step_index: int, fragment_hash: str,
                                     attestation: "ra.RunnerAttestation | None" = None) -> bool:
        """Archive a pending manual intervention (no state change, no effect).

        Recorded as a notice outside the hash chain. The chain covers only the
        admission and effect events of committed transitions, so the head the
        envelope carries stays in sync with the ledger head, and the approved
        resubmission can still finalise against the same envelope.

        The report must describe a step that can need a human: the run is active, the
        step is the one it is at, and the policy requires an approval there. Anything
        else is refused before the attestation is checked and before the session is
        closed, so a wrong report cannot consume the runner session.

        Args:
            credential: The runner's session credential, in state OPEN.
            run_id: The run.
            step_index: The step that needs approval.
            fragment_hash: The fragment awaiting the decision.
            attestation: The runner's signature, for a session with a verdict key.

        Returns:
            Whether the notice was recorded.
        """
        with self._lock:
            session = self._session(credential)
            if (session is None or session.state != "OPEN"
                    or session.run_id != run_id or session.fragment_hash != fragment_hash):
                return False
            entry = self._runs.get(run_id)
            if (entry is None or entry.status is not PolicyState.ACTIVE
                    or step_index != entry.next_step
                    or step_index not in entry.approval_required_steps):
                return False
            ok, _why = self._attested(session, ra.intervention_statement(
                run_id=run_id, step=step_index, state_hash=session.state_hash,
                fragment_hash=fragment_hash), attestation)
            if not ok:
                return False
            session.state = "CLOSED"
            entry.notices.append(to_canonical({
                "kind": "intervention-pending", "run_id": run_id,
                "step_index": step_index, "fragment_hash": fragment_hash}))
            return True

    def decide_intervention(
        self, run_id: str, step_index: int, fragment_hash: str,
        *, approver_id: str, grant: bool, ttl: int = INTERVENTION_TTL,
        approver_kind: str = "passkey",
    ) -> InterventionApproval | None:
        """Record a human decision. A grant yields a signed, fragment-bound artefact.

        Gated on the Authority's own record: a decision binds only a fragment a runner
        has submitted and the Authority has refused for want of approval
        (`intervention_pending`). A hash nobody submitted is neither approved nor, on a
        denial, allowed to terminate the run, so the human interface cannot be used to
        sign an invented fragment or as a denial primitive against a live run. What the
        human reads is still rendered outside the Authority (known limit).

        Args:
            run_id: The run.
            step_index: The step awaiting approval.
            fragment_hash: The fragment awaiting approval.
            approver_id: Who decides.
            grant: The human decision.
            ttl: The approval window in seconds, capped at INTERVENTION_TTL.
            approver_kind: "passkey" or "harness". It must fit ``approver_id``.

        Returns:
            The signed InterventionApproval on a grant, else None. A denial
            terminates the run unless an effect is pending.
        """
        if not self.intervention_pending(run_id, step_index, fragment_hash):
            return None
        if not kind_fits(approver_kind, approver_id):
            return None                              # fail closed: no signature for a kind that does not fit
        ttl = min(int(ttl), INTERVENTION_TTL)        # the human may shorten the window, not lengthen it
        now = self._clock.now()
        if not grant:
            # Same guard as `report_denial`: a denial does not overwrite EFFECT_PENDING.
            # If a sibling fragment's effect is in flight, the run must stay
            # finalisable, otherwise that effect would be lost to the chain.
            with self._lock:
                entry = self._runs.get(run_id)
                if (entry is not None and entry.status not in TERMINAL_STATES
                        and entry.status is not PolicyState.EFFECT_PENDING):
                    entry.status = PolicyState.TERMINATED
            return None
        # Same layout as InterventionApproval.binding(), which _intervention_valid verifies.
        binding = {
            "kind": "intervention-approval",
            "run_id": run_id, "step_index": step_index, "fragment_hash": fragment_hash,
            "approver_id": approver_id, "approver_kind": approver_kind,
            "issued_at": now, "expires_at": now + ttl,
        }
        return InterventionApproval(
            signature=self._approver_key.sign(canonical_bytes(binding)),
            **{k: v for k, v in binding.items() if k != "kind"})

    # Internals.
    def _intervention_valid(self, entry, fragment, intervention, now) -> tuple[bool, str]:
        """Check an intervention approval against the fragment, the ledger and the clock."""
        if intervention is None:
            return False, "no intervention approval presented"
        if fragment.fragment_hash in entry.used_interventions:
            return False, "intervention approval for this fragment already consumed"
        expected = dict(intervention.binding())
        signature_ok = self._intervention_verify_key.verify(
            intervention.signature, canonical_bytes(expected))
        if not signature_ok:
            return False, "intervention signature does not verify"
        if not kind_fits(intervention.approver_kind, intervention.approver_id):
            return False, "intervention approver kind is unknown or does not fit the approver id"
        if (intervention.run_id != fragment.run_id
                or intervention.step_index != fragment.fragment_index
                or intervention.fragment_hash != fragment.fragment_hash):
            return False, "intervention approval binds a different fragment"
        if not (intervention.issued_at <= now <= intervention.expires_at):
            return False, "intervention approval outside its validity window"
        return True, "intervention approval valid"
