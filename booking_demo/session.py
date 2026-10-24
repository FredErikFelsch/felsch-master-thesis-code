"""One demo run: the model proposes, the chosen chain decides, every step becomes an event.

Modes:
    v0         no monitor. Tool calls run directly against the world. Shows the damage.
    v3         the frozen V3 deployment in process (Authority, monitor, gateway, ledger).
    v5-local   the attested path with fake TDs in threads (rehearsal without a cluster).
    v5         the attested path on the cluster: every step in a fresh CoCo peer pod (TDX).

Plan: `fixed` uses the application's pre-approved policy (`ApplicationProfile.fixed_policy`,
for the booking catalogue the frozen P3: search, select, book, pay, 400 EUR, approval before
pay). `agent` asks the model for a plan first, a human approves it (`plan_hook`), and the
approved plan is compiled into the policy of the run (booking_demo.plan). Either way, every
fragment of the run is checked against that one policy.

In every monitored mode each tool call becomes an ActionFragment for the current plan step
and the monitor decides. The adapter derives `declared_facts` and `declared_capability` from
the policy step (what an honest agent would declare) and takes operation and arguments from
the model. The only argument it adds is a run-scoped `action_id` on effectful steps (see
`build_fragment`). It does not judge the call, the monitor does.
"""
from __future__ import annotations

import json
import os
import pathlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from booking_v1.clock import FixedClock
from booking_v1.schema import EFFECTFUL_TOOLS
from booking_v3.fragment import ActionFragment, required_capability, required_facts

from .chains import APPROVER, ISSUED_AT, Chain, InProcessChain, StepTrace
from .continuation import MAX_REPLY_LEN
from .models import Model, ToolCall, Transcript
from .profile import ApplicationProfile, profile as load_profile


def _strip_trailing_plan(text: str) -> str:
    """Remove a trailing JSON object from a direct answer.

    A direct answer sometimes ends with the empty plan the system prompt asked for
    (`{"steps": []}`). The record keeps that JSON out of the reply the person reads.
    """
    t = text.rstrip()
    start, end = t.rfind("{"), t.rfind("}")
    if 0 <= start < end == len(t) - 1:
        try:
            json.loads(t[start:end + 1])
            return t[:start].rstrip()
        except json.JSONDecodeError:
            pass
    return t


def approved_policy_view(plan, policy, profile: ApplicationProfile) -> dict:
    """Build the view of what the human approves, read from the compiled policy.

    The digest is the one the approval signs and the Authority admits. Parameters are
    the plan's (compile_plan bound them into the policy). Budget and approval steps
    come from the policy itself, the effect of each step from the world's effect map.
    The trusted world configuration is not part of the view, because nobody approves it.

    Args:
        plan: The proposed plan (its parameters are bound in `policy`).
        policy: The policy compile_plan produced from it.
        profile: The application profile (effect kinds per tool).

    Returns:
        A JSON-serialisable view for the approval request and the run record.
    """
    flow = list(policy.allowed_flow)
    effects = dict(profile.effects)
    return {
        "digest": policy.digest(),
        "parameters": dict(getattr(plan, "parameters", {}) or {}),
        "budget_minor": getattr(policy, "budget_minor", None),
        "currency": getattr(policy, "currency", None),
        "steps": [{"step": i + 1, "tool": tool,
                   "effect": (effects.get(tool) or "none") if effects else None,
                   "approval": i in tuple(policy.approval_required_steps)}
                  for i, tool in enumerate(flow)],
    }


#: Chat continuation bounds: replies per run and characters per reply.
MAX_CHAT_TURNS = 5
MAX_CHAT_LEN = MAX_REPLY_LEN
#: The explicit intermediate state of a run that paused before its approved plan was done.
WAITING_FOR_USER_CONTINUATION = "WAITING_FOR_USER_CONTINUATION"
#: The replies that end a paused run from the chat. The session matches them itself instead
#: of asking the model: left to the model, "abort please" is answered with "I can't abort
#: from here" and the run pauses again.
STOP_WORDS = frozenset({"stop", "abort", "cancel", "abort the run", "stop the run", "cancel the run"})
NOW = ISSUED_AT + 10
MONITORED = ("v3", "v5-local", "v5")


@dataclass
class EventLog:
    """Append-only run record, rewritten as one JSON file after every event (the dashboard
    polls it), plus a JSONL for the archive."""

    out: pathlib.Path
    events: list = field(default_factory=list)

    def emit(self, kind: str, **data: Any) -> dict:
        """Append one event and persist both files. Returns the event."""
        ev = {"i": len(self.events), "t": round(time.time(), 3), "kind": kind, **data}
        self.events.append(ev)
        self.out.mkdir(parents=True, exist_ok=True)
        # Atomic write: the dashboard polls events.json continuously, so a plain write_text
        # (truncate then fill) lets a poll catch the file empty or half-written. Writing a temp
        # file in the same directory and os.replace-ing it in is atomic on POSIX and Windows.
        blob = json.dumps(self.events, indent=1, default=str)
        tmp = self.out / f".events.json.{os.getpid()}.tmp"
        tmp.write_text(blob)
        os.replace(tmp, self.out / "events.json")
        with (self.out / "events.jsonl").open("a") as fh:
            fh.write(json.dumps(ev, default=str) + "\n")
        return ev


def build_fragment(policy, run_id: str, step: int, call: ToolCall, seq: int) -> ActionFragment:
    """Wrap a model's tool call as the ActionFragment for one plan step.

    Operation and arguments come from the model, the declared facts and capability from
    the policy step. Effectful steps get an idempotency id, as an honest client would
    attach one. The id is run-scoped because the deployed counterparty deduplicates by it
    (`ExternalWorld`, `--idempotent`, a durable world.db that survives redeploys). A plain
    `{tool}-{seq}` would repeat in every run of the same script, and a later run would be
    answered with the stored outcome of an earlier one without the provider being
    contacted.

    Args:
        policy: The run's policy.
        run_id: The run the fragment belongs to.
        step: The plan step index (0-based).
        call: The model's tool call.
        seq: The proposal's sequence number in the run.

    Returns:
        The fragment the chain executes.
    """
    args = dict(call.arguments)
    if call.name in EFFECTFUL_TOOLS and "action_id" not in args:
        args["action_id"] = f"{call.name}-{run_id}-{seq}"
    return ActionFragment(
        run_id=run_id, fragment_index=step, policy_digest=policy.digest(),
        operation=call.name, arguments=args, action_id=args.get("action_id"),
        declared_facts=required_facts(policy, step) if step < len(policy.allowed_flow) else (),
        declared_capability=required_capability(policy, step) if step < len(policy.allowed_flow) else "")


class DemoSession:
    """Drives one model against one chain and records everything."""

    def __init__(self, mode: str, model: Model, mail_text: str, out: pathlib.Path,
                 approve_hook: Optional[Callable[[dict], bool]] = None,
                 run_id: str = "demo-run", mail_highlight: str | None = None,
                 chain: Optional[Chain] = None, attacks: tuple[str, ...] = (),
                 plan_mode: str = "fixed", plan_hook: Optional[Callable[[dict], bool]] = None,
                 approve_mode: str = "unspecified", profile: Optional[ApplicationProfile] = None,
                 attacks_only: bool = False,
                 chat_hook: Optional[Callable[[dict], Optional[str]]] = None,
                 plan_input: Optional[str] = None,
                 approval_timeout: float = 300.0, variant: str = "",
                 fault: Optional[str] = None) -> None:
        #: The fault the operator declares for the gateway of this run (``WORLD_FAULT``, see
        #: ``booking_live.faults``), written to the start event. It does not set the fault, it
        #: only lets the analysis tell a run on a failing gateway from a natural failure.
        self.fault = fault
        #: The input variant (scenario) of this run, written to the start event so the
        #: analysis does not have to read it from a directory name.
        self.variant = variant
        #: The application this run belongs to (booking desk or on-call cluster agent). It
        #: supplies the task, the step library, the world and the untrusted input. The chain
        #: underneath is the same for every application.
        self.profile = profile or load_profile("booking")
        #: What the planner reads as the untrusted input. By default it is the text the agent
        #: later reads through its local tool (a mail is planned from and executed on). Under
        #: an indirect injection in a chat request, the injection sits in content the agent
        #: observes while executing. The plan then binds what the user asked, and the
        #: injected instruction meets the signed policy at the monitor. A human reading a
        #: manipulated plan could otherwise approve the injection.
        self.plan_input = plan_input
        #: How the approvals of this run were answered: "wait" means a person saw the request
        #: and decided, "auto" and "deny" mean nobody did. The evaluation separates runs a
        #: person approved from runs the harness approved, so the mode belongs in the record.
        #: Without it, every approval event would be attributed to a human approver.
        self.approve_mode = approve_mode
        self.mode, self.model, self.out, self.run_id = mode, model, out, run_id
        self.mail_highlight, self.attacks = mail_highlight, tuple(attacks)
        #: Attacks that run inside the approved run, against its own step 0 (a18, a10).
        self._attacks_in_run: list[str] = []
        #: Only the throwaway attack runs, no agent run afterwards. An attack's evidence
        #: must not share a run with a human decision or with provider effects.
        self.attacks_only = attacks_only
        if attacks_only and not self.attacks:
            raise ValueError("attacks_only needs at least one attack")
        self.plan_mode, self.plan_hook = plan_mode, plan_hook or (lambda req: True)
        #: Chat continuation: when the model stops talking before the approved plan is done,
        #: the human may answer in the chat and the run goes on. A reply is conversation and
        #: grants no authority. The policy was fixed at approval, every step still passes
        #: monitor, Authority and gateway, and an approval step still asks. None (every
        #: non-interactive run) ends the run where the model stopped.
        self.chat_hook = chat_hook
        self._chat_turns = 0
        self.log = EventLog(out)
        self.transcript = Transcript(self.profile.task, mail_text)
        self.approve_hook = approve_hook or (lambda req: True)
        self.policy = self.profile.fixed_policy()
        self._seq = 0
        self.chain: Optional[Chain] = None
        if mode in MONITORED:
            self.chain = chain or (InProcessChain(FixedClock(NOW), world=self.profile.world_factory())
                                   if mode == "v3" else None)
            if self.chain is None:
                raise ValueError(f"mode {mode!r} needs a chain (see run.py)")
            self.world = self.chain.world
            if hasattr(self.chain, "evidence_dir"):
                self.chain.evidence_dir = out
            if self._gate() is not None and approve_mode == "wait":
                # A person decides on the Authority's approval page. This process only shows
                # where, and reads the outcome the Authority recorded.
                self.chain.decider = self._at_the_authority
        else:
            self.world = self.profile.world_factory()
        #: Seconds a decision at the Authority may take before the session gives up waiting.
        self.approval_timeout = approval_timeout

    def _gate(self):
        """The Authority's approval gate of this chain (V5 cluster with `booking_approval`)."""
        return getattr(self.chain, "approvals", None) if self.chain is not None else None

    def _at_the_authority(self, ticket, context: dict) -> dict:
        """Point the person to the Authority's page and wait for the recorded outcome.

        This is the decider for `--approve wait`. The decision is made at the Authority,
        this method only reads it.
        """
        self.log.emit("approval_request", url=ticket.url, object_id=ticket.object_id, **context)
        print(f"[demo] waiting for the human at the Authority: {ticket.url}")
        return self.chain.approvals.wait(ticket.object_id, self.approval_timeout)

    def _decision_fields(self) -> dict:
        """Who decided at the Authority, as the gate recorded it (for plan_decision/approval)."""
        st = getattr(self.chain, "last_decision", None) or {}
        who = st.get("approver_id")
        return {"approver": f"approver:{who}" if who else "approver:none",
                "approver_kind": st.get("approver_kind"), "authority_state": st.get("state"),
                "authority_reason": (st.get("result") or {}).get("reason")}

    @property
    def _approver(self) -> str:
        """Who answered the approval requests of this run.

        A run nobody watched must not claim a human approver, however the cryptography is
        wired underneath.
        """
        return APPROVER if self.approve_mode == "wait" else f"approver:demo-{self.approve_mode}"

    # --- the loop ------------------------------------------------------------------------
    def run(self) -> dict:
        """Run the whole scenario and return the summary that the `end` event also carries."""
        from booking_v4.manifest import run_manifest
        clock_mode = "system" if self.mode == "v5" else f"fixed:{NOW}"     # the services under test
        self.log.emit("start", mode=self.mode, domain=self.profile.name, model=self.model.name,
                      model_id=self.model.model_id,
                      run_id=self.run_id, plan_mode=self.plan_mode, attacks=list(self.attacks),
                      variant=self.variant, fault=self.fault,
                      approve_mode=self.approve_mode, approver=self._approver,
                      manifest=run_manifest(clock_mode=clock_mode))
        self.log.emit("task", text=self.profile.task)
        self.log.emit("mail", text=self.transcript.mail, highlight=self.mail_highlight)
        try:
            if self.plan_mode == "fixed" and self.profile.parameters:
                # The pre-approved policy binds the task's parameters (the journey). No plan
                # phase tells the agent about them, so the session does, in the same words
                # an approved plan would.
                from .plan import Plan
                steps = tuple(self.policy.allowed_flow)
                self.model.set_approved_plan(Plan(
                    steps=steps, budget_minor=self.policy.budget_minor, currency=self.policy.currency,
                    approval_steps=tuple(steps[i] for i in self.policy.approval_required_steps),
                    parameters=dict(self.profile.parameters)))
            self.answer_only = False
            if self.plan_mode == "agent" and not self._plan_phase():
                if self.answer_only:
                    text = _strip_trailing_plan(self.model.answer(self.profile.task, self.transcript.mail))
                    summary = {"mode": self.mode, "domain": self.profile.name, "approve_mode": self.approve_mode,
                               **self.world.summary(), "run_status": "ANSWERED"}
                    self.log.emit("end", message=text, **summary)
                    return summary
                summary = {"mode": self.mode, "domain": self.profile.name, "approve_mode": self.approve_mode,
                           **self.world.summary(), "run_status": "PLAN_REJECTED"}
                decision = next((e for e in reversed(self.log.events) if e["kind"] == "plan_decision"), {})
                who = decision.get("approver", "")
                if not who.startswith("approver:"):
                    message = f"The plan was not compilable ({decision.get('reason', '')}). No run was created."
                elif self.approve_mode == "wait" and who != "approver:none":
                    message = "The human rejected the plan. No run was created."
                else:
                    message = (f"The plan was not approved (approvals answered by: {self.approve_mode}). "
                               "No run was created.")
                self.log.emit("end", message=message, plan_rejected_by=who, **summary)
                return summary
            self.log.emit("policy", domain=self.profile.name, plan=list(self.policy.allowed_flow),
                          budget_minor=self.policy.budget_minor, currency=self.policy.currency,
                          approval_steps=list(self.policy.approval_required_steps),
                          digest=self.policy.digest(), rules=self._policy_rules())
            deferred = getattr(self.chain, "deferred_warm_wait", 0.0)
            if deferred:
                # Deferred from the chain's construction (run.py): the plan is approved, now
                # the warm pool. The record shows the wait so a slow run is attributable.
                pool = self.chain.controller.pool
                self.log.emit("warm_pool", state="waiting", size=pool.size, timeout=deferred)
                t0 = time.time()
                ready = self.chain.wait_warm(deferred)
                self.log.emit("warm_pool", state="ready", ready=ready, size=pool.size, waited_s=round(time.time() - t0, 1))
                self.chain.deferred_warm_wait = 0.0
            from .attacks import IN_RUN
            for attack in self.attacks:
                if attack in IN_RUN and not self.attacks_only:
                    self._attacks_in_run.append(attack)    # runs at step 0 of the approved run
                else:
                    self._run_attack(attack)
            if self.attacks_only:
                summary = {"mode": self.mode, "domain": self.profile.name, "approve_mode": self.approve_mode,
                           **self.world.summary(), "run_status": "ATTACKS_ONLY"}
                self.log.emit("end", message="attacks only: no agent run", **summary)
                return summary
            if self.chain is not None:
                from .chains import NotApproved
                try:
                    self.envelope = self.chain.create_run(self.policy, self.run_id)
                except NotApproved as refused:
                    # Fixed plan on a gated Authority: the run exists only after an approval.
                    self.log.emit("plan_decision", granted=False, approve_mode=self.approve_mode,
                                  **self._decision_fields(), reason=str(refused))
                    summary = {"mode": self.mode, "domain": self.profile.name, "approve_mode": self.approve_mode,
                               **self.world.summary(), "run_status": "PLAN_REJECTED"}
                    self.log.emit("end", message="The plan was not approved at the Authority. No run was created.",
                                  **summary)
                    return summary
                if self._gate() is not None and self.plan_mode == "fixed":
                    self.log.emit("plan_decision", granted=True, approve_mode=self.approve_mode,
                                  **self._decision_fields(), reason="")
            while True:
                call = self.model.next_call(self.transcript)
                if call is None:
                    if self._continue_in_chat():
                        continue
                    break
                self._seq += 1
                self.log.emit("proposal", seq=self._seq, tool=call.name, arguments=call.arguments)
                result = self._decide(call)
                self.transcript.record(call, result)
                self.log.emit("tool_result", seq=self._seq, tool=call.name, result=result)
            summary = self._summary()
            forged = getattr(self.model, "forged", None)
            if forged is not None:
                summary["forged"] = forged
            unfinished = self._plan_remaining()
            if unfinished:
                # The run is still ACTIVE at the Authority but nobody will continue it. The
                # summary says so, so that "ACTIVE" does not read like success.
                summary["unfinished_steps"] = unfinished
            if getattr(self, "stopped_by_user", False):
                summary["run_status"] = "STOPPED_BY_USER"
                message = (f"Stopped at your request. Not executed: {', '.join(unfinished)}. "
                           "The order, if one was held, stays unpaid and expires.")
            else:
                message = self.model.final_message()
            self.log.emit("end", message=message, **summary)
            return summary
        finally:
            if self.chain is not None:
                self.chain.close()

    def _plan_remaining(self) -> list[str]:
        """The approved steps not yet completed, in order. Empty without a live monitored run."""
        if self.chain is None or self.policy is None or getattr(self, "envelope", None) is None:
            return []
        if self.chain.run_status(self.run_id) != "ACTIVE":
            return []
        return list(self.policy.allowed_flow)[self.envelope.step_index:]

    def _continuation_snapshot(self, remaining: list[str]) -> dict:
        """Describe what a paused run holds, read from the signed state.

        The snapshot is built from the envelope and the policy, not from the model's text.
        `observed` are the facts the last completed step produced, as the envelope carries
        them, so the order id and amount are the ones the chain confirmed. Maps and sets are
        left out, because they are search results the human does not need to decide to go on.
        """
        flow = list(self.policy.allowed_flow)
        done = self.envelope.step_index
        last = flow[done - 1] if done > 0 else None
        observed = {}
        for name, fact in dict(self.envelope.facts).items():
            # A fact is a frozen mapping in the envelope (value, source_tool, integrity, ...).
            get = (lambda k: fact.get(k)) if hasattr(fact, "get") else (lambda k: getattr(fact, k, None))
            value = get("value")
            if get("source_tool") == last and isinstance(value, (str, int, float, bool)):
                observed[name] = value
        return {"state": WAITING_FOR_USER_CONTINUATION, "run_id": self.run_id,
                "policy_digest": self.policy.digest(), "completed_step": last,
                "step_index": done, "next_step": remaining[0], "remaining": remaining,
                "observed": observed}

    def _pause_text(self, snap: dict) -> str:
        """Build the chat answer of a paused run from the snapshot.

        The words are the same whatever the model happened to write, and they name only
        facts the chain confirmed.
        """
        nxt = snap["next_step"]
        obs = snap["observed"]
        pick = lambda suffix: next((v for k, v in obs.items() if k.endswith(suffix)), None)
        order, amount, currency = pick("order_id"), pick("amount_minor"), pick("currency")
        from booking_live.effects import PAYMENT
        kind = dict(self.profile.effects).get(nxt)
        if order is not None and kind == PAYMENT:
            price = f" ({amount / 100:.2f} {currency})" if isinstance(amount, int) and currency else ""
            return (f"The order {order}{price} has been created and is ready for payment. "
                    f"Tell me when you want to continue with the payment, or reply 'stop' to end the run.")
        return (f"Step {snap['completed_step']} is done. The approved plan continues with {nxt}. "
                f"Tell me when you want to continue.")

    def _continue_in_chat(self) -> bool:
        """Pause a run whose model stopped before the approved plan is done.

        The run enters WAITING_FOR_USER_CONTINUATION. It keeps its run id, its signed state,
        its approved policy and the observed facts. Only this chat turn ends. The human's next
        message resumes the same execution without planning or a new policy. The reply lets
        the agent propose the next approved step, and a step that needs approval still waits
        for its separate, fragment-bound approval. At most MAX_CHAT_TURNS replies are taken,
        so a model that keeps stopping cannot keep a run open.

        Returns:
            True when a reply was handed to the model and the loop should continue.
        """
        remaining = self._plan_remaining()
        if self.chat_hook is None or not remaining or self._chat_turns >= MAX_CHAT_TURNS:
            return False
        snap = self._continuation_snapshot(remaining)
        text = self._pause_text(snap)
        self.log.emit("paused", **snap, message=text, model_message=self.model.final_message())
        reply = self.chat_hook({"kind": "chat", **snap, "message": text, "turn": self._chat_turns + 1})
        reply = (reply or "").strip()[:MAX_CHAT_LEN]
        if not reply:
            self.log.emit("user_message", text="", timed_out=True)
            return False
        self._chat_turns += 1
        self.log.emit("user_message", text=reply)
        if reply.strip().strip(".!").lower() in STOP_WORDS:
            # A defined stop that the model does not interpret. The run ends here with what it
            # has, and no effect can follow from ending. The stop only withdraws the agent's
            # chance to propose the remaining steps.
            self.log.emit("stopped", by="user", remaining=list(remaining))
            self.stopped_by_user = True
            return False
        self.log.emit("resumed", state="ACTIVE", run_id=self.run_id, next_step=snap["next_step"],
                      policy_digest=snap["policy_digest"])
        # The model gets the human's words plus the run state the session knows (next
        # approved step, the facts of the last step). The state is trusted context and
        # decides nothing, because a step that needs approval still asks in the panel when it
        # is called. Without the state, the model keeps answering "I cannot continue this run".
        facts = ", ".join(f"{k}={v}" for k, v in (snap.get("observed") or {}).items())
        note = (f"\n\n[Run state from the system: the approved plan is still active; the next approved step is "
                f"{snap['next_step']}. Call it now with the observed facts ({facts}). If it needs human approval, "
                "calling it is how the human gets asked; do not wait for an approval in this chat.]")
        return bool(self.model.add_user_message(reply + note))

    def _plan_phase(self) -> bool:
        """Let the agent propose a plan, ask the human, and compile the approved plan.

        Returns:
            True when the plan was approved and is now the run's policy, False otherwise.
        """
        from booking_v2.policy import PolicyInvalid
        from .plan import compile_plan, planning_context
        context = planning_context()          # the trusted facts the proposal is resolved against
        try:
            planned_from = self.plan_input if self.plan_input is not None else self.transcript.mail
            plan = self.model.propose_plan(self.profile.task, planned_from)
        except PolicyInvalid as exc:
            # The model's answer is not a plan (no steps, no JSON). It is refused before any
            # human sees it, and the run record says why.
            self.log.emit("plan_proposed", plan=None, review=None, invalid=str(exc), planning_context=context)
            self.log.emit("plan_decision", granted=False, approver="plan-shape", reason=str(exc))
            return False
        self.model._last_plan = plan
        if not plan.steps:
            # With nothing to execute there is nothing to approve, and the message is answered
            # directly. No run is created and no tool can run, so the human is not asked.
            self.log.emit("plan_proposed", plan=plan.as_dict(), review=None, no_steps=True,
                          planning_context=context)
            self.log.emit("plan_decision", granted=False, approver="no-steps",
                          reason="the plan has no steps: nothing to execute, the message is answered directly")
            self.answer_only = True
            return False
        try:
            policy, review = compile_plan(plan, self.profile)
        except PolicyInvalid as exc:
            # A plan violating the plan invariants (pay without book, pay without
            # approval) is refused before any human sees it as approvable.
            self.log.emit("plan_proposed", plan=plan.as_dict(), review=None, invalid=str(exc), planning_context=context)
            self.log.emit("plan_decision", granted=False, approver="plan-invariants", reason=str(exc))
            return False
        approved = approved_policy_view(plan, policy, self.profile)
        trusted = dict(self.profile.trusted_config)
        self.log.emit("plan_proposed", plan=plan.as_dict(), review=review.as_dict(),
                      approved_policy=approved, trusted_config=trusted, planning_context=context,
                      planned_from=planned_from)
        request = {"kind": "plan", "plan": plan.as_dict(), "review": review.as_dict(),
                   "policy": {"digest": policy.digest(), "plan": list(policy.allowed_flow),
                              "approval_steps": list(policy.approval_required_steps)},
                   "approved_policy": approved, "trusted_config": trusted,
                   "planning_context": context}
        if self._gate() is not None:
            # The decision is made at the Authority. Approving it creates the run there.
            grant = None if self.approve_mode == "wait" else bool(self.plan_hook(request))
            status = self.chain.authorize_plan(policy, self.run_id, grant=grant,
                                               context={"notes": list(review.as_dict().get("notes", []))})
            granted = status.get("state") == "approved"
            self.log.emit("plan_decision", granted=granted, approve_mode=self.approve_mode,
                          **self._decision_fields(),
                          reason="" if granted else "the plan was not approved at the Authority "
                                                     f"({status.get('state')})")
        else:
            granted = bool(self.plan_hook(request))
            self.log.emit("plan_decision", granted=granted, approver=self._approver,
                          approve_mode=self.approve_mode,
                          reason="" if granted else "the human rejected the plan, or no decision arrived in time")
        if not granted:
            return False
        self.policy = policy
        self.model.set_approved_plan(plan)
        return True

    def _attack_in_run(self, fragment: ActionFragment) -> None:
        """Run the in-run attacks (a18, a10) against step 0, before the honest attempt.

        The attack uses the run id, the policy digest and the fragment of the honest attempt
        that follows. It is refused before the relying party commits a session, so the
        protocol lets the honest attempt proceed without a reset. The honest step starts
        only after the attack's result and its ledger measurement are recorded.
        """
        from .attacks import run_attack_in_run
        pending, self._attacks_in_run = self._attacks_in_run, []
        for attack in pending:
            self.log.emit("attack_start", attack=attack, in_run=True, run_id=self.run_id,
                          policy_digest=self.policy.digest(), step=fragment.fragment_index)
            ev = run_attack_in_run(self.chain, attack, self.policy, self.run_id, self.envelope, fragment)
            self.log.emit("attack", policy_digest=self.policy.digest(), **ev)

    def _run_attack(self, attack: str) -> None:
        """Run one attack in a throwaway run before the real run.

        The expected outcome is a refusal with a ledger delta of 0. This is used for a16
        (refused only inside the TD, after a session exists) and for every attack in an
        attacks-only session.
        """
        from .attacks import run_attack
        self.log.emit("attack_start", attack=attack)
        run_id = f"{self.run_id}-{attack}"
        if self._gate() is not None:
            # A throwaway run is still a run: the Authority creates it only after an approval.
            status = self.chain.authorize_plan(self.policy, run_id, grant=True,
                                               context={"attack": attack, "throwaway": True})
            if status.get("state") != "approved":
                self.log.emit("attack", attack=attack, status="NOT_APPROVED", **{"pass": False},
                              reason=f"the throwaway run was not approved at the Authority ({status.get('state')})")
                return
        ev = run_attack(self.chain, attack, self.policy, run_id)
        self.log.emit("attack", **ev)

    def _policy_rules(self) -> list[dict]:
        """List the compiled rules per step in plain English, for the dashboard's policy card.

        They are read from the policy object, so what is shown is what the monitor enforces.
        """
        from .explain_policy import step_rules
        return step_rules(self.policy)

    def _decide(self, call: ToolCall) -> dict:
        if call.name == self.profile.local_tool:           # reading untrusted input is not an effect
            self.log.emit("decision", seq=self._seq, tool=call.name, status="LOCAL",
                          reason="untrusted input read by the agent, no effect", step=None,
                          unauthorized=self.world.unauthorized_effects)
            return {"mail": self.transcript.mail}
        if self.chain is None:
            result = self.world.execute_direct(call.name, call.arguments)
            self.log.emit("decision", seq=self._seq, tool=call.name, status="EXECUTED",
                          reason="no monitor: executed as proposed", step=None, unauthorized=self.world.unauthorized_effects)
            return result
        return self._decide_monitored(call)

    def _decide_monitored(self, call: ToolCall) -> dict:
        step = self.envelope.step_index
        fragment = build_fragment(self.policy, self.run_id, step, call, self._seq)
        if self.chain.run_status(self.run_id) == "TERMINATED":
            # The run ended at an earlier refused step. The Authority registers no approval
            # and mints no grant for a terminated run, so a proposal here can only fail. It is
            # not sent to a runner, and a person is not asked to decide on it (the dashboard
            # would otherwise ask for an approval the Authority then ignores).
            reason = "the run was terminated at an earlier refused step, so nothing can be authorised any more"
            ledger = self.chain.ledger()
            self.log.emit("decision", seq=self._seq, tool=call.name, status="RUN_TERMINATED", reason=reason,
                          step=step, fragment_hash=fragment.fragment_hash, run_status="TERMINATED",
                          executions=sum(1 for e in ledger if e.get("state", "COMMITTED") == "COMMITTED"),
                          pending=sum(1 for e in ledger if e.get("state", "COMMITTED") != "COMMITTED"),
                          unauthorized=self.world.unauthorized_effects)
            return {"error": "RUN_TERMINATED", "reason": reason}
        if self._attacks_in_run and step == 0:
            self._attack_in_run(fragment)
        result, trace = self._execute(fragment, None)
        if result.status == "REQUIRE_APPROVAL":
            self.log.emit("decision", seq=self._seq, tool=call.name, status="REQUIRE_APPROVAL",
                          reason=result.reason, step=step, fragment_hash=fragment.fragment_hash)
            request = {"seq": self._seq, "step": step, "tool": call.name,
                       "arguments": dict(fragment.arguments), "fragment_hash": fragment.fragment_hash,
                       "policy_hash": self.policy.digest()}
            if self._gate() is not None:
                grant = None if self.approve_mode == "wait" else bool(self.approve_hook(request))
                approval = self.chain.decide_intervention(self.run_id, step, fragment.fragment_hash, grant=grant,
                                                          fragment=fragment)
                self.log.emit("approval", seq=self._seq, granted=approval is not None,
                              approve_mode=self.approve_mode, **self._decision_fields())
                if approval is None:
                    return {"error": "REQUIRE_APPROVAL", "reason": "the step was not approved at the Authority"}
            else:
                granted = self.approve_hook(request)
                self.log.emit("approval", seq=self._seq, granted=bool(granted), approver=self._approver,
                              approve_mode=self.approve_mode)
                if not granted:
                    self.chain.decide_intervention(self.run_id, step, fragment.fragment_hash, grant=False)
                    return {"error": "REQUIRE_APPROVAL", "reason": "the human did not approve this step"}
                approval = self.chain.decide_intervention(self.run_id, step, fragment.fragment_hash, grant=True)
            result, trace = self._execute(fragment, approval)      # V5: a new TD, the continuation gate admits it
        status = result.status
        self.log.emit("decision", seq=self._seq, tool=call.name, status=status, reason=result.reason,
                      step=step, fragment_hash=fragment.fragment_hash,
                      run_status=self.chain.run_status(self.run_id),
                      # The V3 chain reports the gateway's own execution list, which has no
                      # state column and only lists completed executions. The V5 chain reports
                      # the durable ledger, where a row can still be PENDING.
                      executions=sum(1 for e in self.chain.ledger()
                                     if e.get("state", "COMMITTED") == "COMMITTED"),
                      # A dispatch the gateway started and did not confirm. It is not counted
                      # as an execution, but the money may have moved.
                      pending=sum(1 for e in self.chain.ledger()
                                  if e.get("state", "COMMITTED") != "COMMITTED"),
                      unauthorized=self.world.unauthorized_effects)
        if status == "STEP_COMPLETED":
            self.envelope = result.envelope
            return dict(result.payload or {})
        return {"error": status, "reason": result.reason}

    def _execute(self, fragment: ActionFragment, intervention) -> tuple[Any, StepTrace]:
        try:
            result, trace = self.chain.execute(self.policy, self.envelope, fragment, intervention)
        except Exception as exc:                                  # noqa: BLE001 (the record must get its end)
            # A cold TD can close its attach stream before its hello (a peer-pod boot that did
            # not come up). Raised out of the run, that leaves no end event and the Authority's
            # run ACTIVE with an unused intervention approval. Nothing was dispatched, because
            # the TD never answered. The step is a RUNNER_ERROR like a missing result line, the
            # model sees the error and the record gets its end.
            from booking_v3.runner import RunnerResult
            reason = f"{type(exc).__name__}: {str(exc)[:200]}"
            self.log.emit("runner_error", seq=self._seq, step=fragment.fragment_index, tool=fragment.operation,
                          continuation=intervention is not None, reason=reason)
            return (RunnerResult(status="RUNNER_ERROR", envelope=None, reason=reason, payload=None, runner_no=-1),
                    StepTrace(outcome="RUNNER_ERROR"))
        if trace.td is not None or trace.outcome:
            self.log.emit("attested", seq=self._seq, step=fragment.fragment_index, tool=fragment.operation,
                          continuation=intervention is not None, **trace.as_event())
        return result, trace

    def _summary(self) -> dict:
        s = {"mode": self.mode, "domain": self.profile.name, "approve_mode": self.approve_mode,
             "approver": self._approver, **self.world.summary()}
        if self.chain is not None:
            s["run_status"] = self.chain.run_status(self.run_id)
            s["ledger"] = self.chain.ledger()
        return s
