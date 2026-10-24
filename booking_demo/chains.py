"""The decision chains a demo session can run against, behind a common interface.

    InProcessChain   V3: the frozen deployment in this process.
    AttestedChain    V5: every fragment runs in a fresh attested TD. Two constructions:
                       `AttestedChain.local(...)`   fake TDs in threads (the experiment_v5
                                                    harness), for rehearsals without a cluster
                       `AttestedChain.cluster(...)` CoCo peer pods on GKE, the same plumbing
                                                    as `scripts/gke-v5/31_run_fragment_v5.sh`
                                                    and `32_negative_v5.sh` (`e2e_live`)

A chain creates the run, executes one fragment against the current envelope, turns a human
decision into the Authority's fragment-bound approval and exposes the ledger. The chain
itself decides nothing. The monitor inside the runner (V3) or inside the TD (V5) does.

The human approval on the cluster path: when the Authority runs the approval gate
(`booking_approval`), no approval passes through this process. The chain registers the plan
(`approval.propose_run`) or asks for the page of a refused step (`approval.step_ticket`), a
`decider` obtains the decision at the Authority (the person on the approval page, or the
harness key for unattended evaluation runs), and the chain reads the result the Authority
produced: the genesis envelope, or the signed intervention approval. `create_run` and
`decide_intervention` are closed on the Authority's RPC surface.

Without the gate (older deployments) the chain uses the human's credential (V3
`HumanApprovalCredential`) from the Secret `human-approver`, read under the admin context.
"""
from __future__ import annotations

import base64
import json
import pathlib
import socket
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Protocol

from booking_v1.approval import approve
from booking_v3.authority import INTERVENTION_TTL, HumanApprovalCredential
from booking_v3.fragment import ActionFragment
from booking_v3.runner import RunnerResult
from booking_v4 import wire
from booking_v4.services import _call

from .world import DemoWorld

#: Obtains one decision at the Authority: (ticket, context) -> the gate's final status. The
#: context names the subject ("plan" or "step"), the run and, for a step, its index and hash.
Decider = Callable[[Any, dict], dict]


class NotApproved(RuntimeError):
    """The Authority did not approve (rejected, failed, timed out). `status` is the gate's answer."""

    def __init__(self, status: Mapping[str, Any]) -> None:
        super().__init__(f"not approved at the Authority: {status.get('state')} "
                         f"{(status.get('result') or {}).get('reason') or ''}".strip())
        self.status = dict(status)


APPROVER = "approver:demo-human"
ISSUED_AT = 1_700_000_000
ATTESTATION_REFUSED = "ATTESTATION_REFUSED"


@dataclass
class StepTrace:
    """What the attested path reports about one fragment execution (empty for V3)."""

    td: Optional[str] = None
    outcome: str = ""
    refusal: Optional[dict] = None
    timings: dict = field(default_factory=dict)
    total_s: float = 0.0
    handoff: str = ""
    effects: int = 0
    pending_effects: int = 0
    foreign_effects: int = 0
    #: False means the three counters above were not read from the gateway ledger, so they
    #: are defaults and not an observation. A caller must not read them as "nothing happened".
    ledger_measured: bool = False
    evidence_path: Optional[str] = None     # the raw quote of a REFUSED attempt, for offline re-appraisal
    #: What the controller's check of the shown result found. The run state is a separate
    #: question: RESULT_UNVERIFIED here is EFFECT_UNCERTAIN there, and neither drops the other.
    result_status: str = ""                 # the status of the result the controller shows
    result_check: str = ""                  # "verified", "not applicable", or why it was not backed
    reported_status: str = ""               # the runner's own status, when the controller replaced the line

    def as_event(self) -> dict:
        """Return the trace as a plain dict for the event stream."""
        return {k: v for k, v in vars(self).items()}


class Chain(Protocol):
    """The interface a session drives, implemented by both chains below."""

    name: str
    world: DemoWorld

    def create_run(self, policy, run_id: str): ...
    def execute(self, policy, envelope, fragment: ActionFragment, intervention) -> tuple[RunnerResult, StepTrace]: ...
    def decide_intervention(self, run_id: str, step: int, fragment_hash: str, grant: bool, ttl: Optional[int] = None,
                            fragment: Optional[ActionFragment] = None): ...
    def run_status(self, run_id: str) -> str: ...
    def ledger(self) -> list: ...
    def close(self) -> None: ...


# --- V3 -------------------------------------------------------------------------------------

class InProcessChain:
    """The frozen V3 deployment in process. The demo world is its gateway executor."""

    name = "v3"

    def __init__(self, clock, world=None) -> None:
        from booking_v3.provisioner import create_deployment
        self.world = world if world is not None else DemoWorld()
        self.dep = create_deployment(clock, executor=self.world.gateway_executor())

    def create_run(self, policy, run_id: str):
        """Approve the policy with the demo human and open the run at the Authority."""
        approval = approve(policy, approver_id=APPROVER, approval_id=f"appr-{run_id}",
                           run_id=run_id, issued_at=ISSUED_AT, expires_at=ISSUED_AT + 3600)
        return self.dep.authority.create_run(policy, approval, run_id)

    def execute(self, policy, envelope, fragment, intervention):
        """Run one fragment in a spawned in-process runner. The trace is empty for V3."""
        runner = self.dep.provisioner.spawn(fragment, envelope)
        return runner.execute(policy, envelope, fragment, intervention), StepTrace()

    def decide_intervention(self, run_id, step, fragment_hash, grant, ttl=None, fragment=None):
        """Turn the demo human's decision into the Authority's fragment-bound approval."""
        human = getattr(self.dep, "human_interface", self.dep.authority)
        return human.decide_intervention(run_id, step, fragment_hash, approver_id=APPROVER, grant=grant,
                                         ttl=INTERVENTION_TTL if ttl is None else ttl)

    def run_status(self, run_id):
        """Return the Authority's status of the run."""
        return self.dep.authority.status(run_id).value

    def ledger(self):
        """Return the gateway's executions (only completed ones, there is no state column)."""
        return list(self.dep.gateway.executions)

    def close(self) -> None:
        """Release nothing, since the in-process deployment holds no outside resources."""


# --- V5 -------------------------------------------------------------------------------------

def _trace(rec) -> StepTrace:
    """Convert the controller's run record into a `StepTrace`.

    `outcome` is the e2e word (ACCEPTED / REFUSED(rule)) when the attested path itself
    decided. A monitor verdict inside the TD is named as such.
    """
    status = getattr(rec.result, "status", None)
    outcome = rec.outcome
    # An unmeasured ledger stays unmeasured. A monitor verdict inside the TD says nothing
    # about whether the gateway ledger moved, and only the ledger can say that.
    if rec.ledger_measured and rec.refusal is None and status == "RESULT_UNVERIFIED":
        outcome = "UNVERIFIED_RESULT"                   # the runner line is not backed by the gateway
    elif rec.ledger_measured and rec.refusal is None and status not in (None, "STEP_COMPLETED"):
        outcome = f"MONITOR({status})"
    reported = getattr(rec, "reported_result", None)
    return StepTrace(td=rec.td, outcome=outcome,
                     result_status=status or "", result_check=getattr(rec, "result_check", "") or "",
                     reported_status=getattr(reported, "status", "") or "",
                     refusal=({"rule": rec.refusal.rule, "detail": rec.refusal.detail, "stage": rec.refusal.stage}
                              if rec.refusal else None),
                     timings={k: round(v, 3) for k, v in vars(rec.timings).items() if isinstance(v, float)},
                     total_s=round(rec.timings.total, 3),
                     handoff="warm" if rec.timings.ready == 0.0 else "cold",
                     effects=rec.effects, pending_effects=rec.pending_effects,
                     foreign_effects=rec.foreign_effects, ledger_measured=rec.ledger_measured)


class AttestedChain:
    """Run each fragment in a fresh attested TD, over the V5 controller.

    `controller` and `transport` are the objects `scripts/gke-v5/31_run_fragment_v5.sh` and
    `32_negative_v5.sh` drive. `authority` is the Authority's endpoint (create_run,
    decide_intervention). `ledger` is the gateway ledger this chain reads. `human` is the
    human's credential or None. Without a credential and without an approval gate
    (`approvals`), no approval can be given and an approval step stays REQUIRE_APPROVAL.
    `world` is the demo world when the gateway executes in process (local), else a view
    rebuilt from results, which classifies effects by `effects`. `approvals` is the
    Authority's approval gate and `harness` the software approver that answers there for
    unattended runs. `on_close` releases what the construction acquired.
    """

    name = "v5"

    def __init__(self, controller, transport, authority, ledger, human: Optional[HumanApprovalCredential],
                 world: Optional[DemoWorld] = None, on_close=None,
                 effects: Optional[Mapping[str, Optional[str]]] = None,
                 approvals=None, harness=None) -> None:
        self.controller, self.transport, self.authority = controller, transport, authority
        self._ledger, self.human, self._on_close = ledger, human, on_close
        #: The Authority's approval gate (`booking_approval.client.ApprovalClient`), None on
        #: a deployment without it. `harness` answers there with a software key (auto/deny).
        #: `decider`, when set by the session, obtains decisions from a person instead.
        self.approvals, self.harness = approvals, harness
        self.decider: Optional[Decider] = None
        self.last_decision: Optional[dict] = None
        self._approved: dict[str, Any] = {}
        # The observed view of a cluster gateway's world classifies by the application's
        # effect map, so `pay_order` is recorded as the payment it is.
        self.world = world or (DemoWorld(effects=dict(effects)) if effects is not None else DemoWorld())
        self._remote_world = world is None      # the gateway's world is in the cluster: observe it via payloads
        self._status: dict[str, str] = {}
        self.records: list = []
        self._cursor = ledger.high_watermark()
        self.evidence_dir = None                 # set by the session: where refused evidence is kept
        from booking_v1.approval import live_window
        self.approval_window = live_window       # the deployed Authority runs the system clock

    # construction ---------------------------------------------------------------------------
    @classmethod
    def local(cls, clock, world: Optional[DemoWorld] = None) -> "AttestedChain":
        """Build a chain with fake TDs (runner threads), real services on loopback and real RTMR3 replay."""
        from booking_v5.experiment_v5 import AttestedInProcessDeployment
        world = world or DemoWorld()
        dep = AttestedInProcessDeployment(clock, executor=world.gateway_executor())
        chain = cls(dep.controller, dep.transport, dep.authority_server.endpoint, dep.ledger,
                    dep.base.human, world=world, on_close=dep.close)
        chain.approval_window = lambda: (clock.now() - 60, clock.now() + 3600)   # the offline clock
        chain.deployment = dep                  # the in-process services (tests install the approval gate here)
        return chain

    @classmethod
    def cluster(cls, context: str, admin_context: Optional[str], project: str, zone: str, registry: str,
                impersonate: Optional[str], controller_config: str, pool: int = 0,
                cr_grace: float = 0.0,
                effects: Optional[Mapping[str, Optional[str]]] = None,
                approval_url: str = "http://localhost:8450",
                harness_key: Optional[str] = None) -> "AttestedChain":
        """Build a chain over CoCo peer pods on GKE.

        This is the plumbing of `e2e_live._setup` without the run, plus the Authority's
        approval gate when it runs one. `effects` is the application's effect map
        (`ApplicationProfile.effects`). The world itself stays in the cluster, only its
        observed view is built here. `approval_url` is the approval page as a browser
        reaches it, `harness_key` the key of the harness approver for unattended runs.
        """
        from booking_v3.policy import p3_with_pay_approval
        from booking_v4.endpoint import ServiceEndpoint
        from booking_v5 import e2e_live
        from booking_v5.attach_transport import AttachTransport, kubernetes_attach
        from booking_v5.controller_v5 import AttestedFragmentController, PeerPodBackend, RemoteAuthority
        from booking_v5.gateway import RemoteLedger
        from booking_v5.pool import TdPool
        ns = e2e_live.NS
        e2e_live._kube(context)
        digests_file = pathlib.Path(e2e_live.MOCKS) / "scripts" / "gke" / ".digests"
        digests = dict(line.strip().split("=", 1) for line in digests_file.read_text().splitlines()
                       if "=" in line and not line.startswith("#"))
        anchors = wire.anchors_from_wire(json.loads(pathlib.Path(controller_config).read_text())["anchors"])
        pf_auth = e2e_live.PortForward(context, "authority", 8443).__enter__()
        pf_obs = e2e_live.PortForward(context, "gateway", 8444).__enter__()
        backend = PeerPodBackend(namespace=ns, image=digests["RUNNER_IMAGE"],
                                 instances=e2e_live._gce_probe(project, zone, impersonate),
                                 python=digests.get("RUNNER_PYTHON", "/usr/local/bin/python3"),
                                 registry=registry, pull_token=e2e_live._pull_token, cr_grace=cr_grace)
        transport = AttachTransport(open_stream=kubernetes_attach(ns), anchors=anchors,
                                    endpoint=ServiceEndpoint.tcp(f"authority.{ns}.svc.cluster.local", 8443),
                                    gateway_endpoint=ServiceEndpoint.tcp(f"gateway.{ns}.svc.cluster.local", 8443),
                                    policy=p3_with_pay_approval())
        td_pool = TdPool(backend, size=pool)
        if pool:
            td_pool.fill()
        ledger = RemoteLedger(pf_obs.endpoint)
        controller = AttestedFragmentController(td_pool, RemoteAuthority(pf_auth.endpoint), transport, ledger=ledger)
        # The harness answers on the approval surface (port 8450, no Service, no NetworkPolicy
        # opening, `scripts/gke-v5/49_approval_page.sh` forwards it for a person). An
        # unattended run has no such script, so the chain forwards the port itself when
        # nothing listens on the page's address.
        # Host and Origin stay the page's, the harness sets them (HarnessApprover), so the
        # gate's origin check holds through the forward.
        pf_page = None
        surface_url = approval_url
        if harness_key and not _listening(approval_url):
            pf_page = e2e_live.PortForward(admin_context or context, "authority", 8450).__enter__()
            surface_url = f"http://127.0.0.1:{pf_page.local}"
            print(f"[demo] approval page forwarded for the harness: {surface_url} (origin {approval_url})")
        approvals, harness = _gate_of(pf_auth.endpoint, approval_url, harness_key, surface_url)
        # With the gate, the human secret is neither needed nor read (it stays in the Authority).
        human = read_human_credential(admin_context, ns) if admin_context and approvals is None else None

        def _close():
            drained = td_pool.drain()
            if drained:
                print(f"[demo] pool: {drained} idle TD(s) destroyed")
            for pf in (pf_auth, pf_obs, pf_page):
                if pf is not None:
                    pf.__exit__(None, None, None)
        return cls(controller, transport, pf_auth.endpoint, ledger, human, on_close=_close,
                   effects=effects, approvals=approvals, harness=harness)

    # the interface --------------------------------------------------------------------------
    def create_run(self, policy, run_id: str):
        """Open the run: through the approval gate when there is one, else with the human credential."""
        if self.approvals is not None:
            envelope = self._approved.pop(run_id, None)
            if envelope is None:
                status = self.authorize_plan(policy, run_id, grant=True)
                if status.get("state") != "approved":
                    raise NotApproved(status)
                envelope = self._approved.pop(run_id)
            self._status[run_id] = "ACTIVE"
            return envelope
        issued, expires = self.approval_window()
        approval = approve(policy, approver_id=APPROVER, approval_id=f"appr-{run_id}",
                           run_id=run_id, issued_at=issued, expires_at=expires)
        reply = _call(self.authority, "authority.create_run",
                      {"policy": wire.policy_to_wire(policy), "approval": wire.approval_to_wire(approval),
                       "run_id": run_id})
        if reply.get("envelope") is None:
            raise RuntimeError(f"create_run refused: {reply}")
        self._status[run_id] = "ACTIVE"
        return wire.envelope_from_wire(reply["envelope"])

    def execute(self, policy, envelope, fragment, intervention):
        """Run one fragment in a fresh attested TD and return its result and trace."""
        from booking_v5 import protocol
        self.transport.policy = policy
        self.transport.intervention = intervention
        rec = self.controller.execute_fragment(fragment.run_id, fragment.fragment_index,
                                               protocol.fragment_bytes(fragment), protocol.envelope_bytes(envelope))
        self.records.append(rec)
        if rec.td is not None:
            self.transport.close(rec.td)
        self.controller.pool.fill()                     # top-up, `acquire` already started the replacement
        if rec.refusal is not None:
            result = RunnerResult(status=ATTESTATION_REFUSED, envelope=None, reason=rec.outcome,
                                  payload=None, runner_no=-1)
        elif rec.result is None:
            result = RunnerResult(status="RUNNER_ERROR", envelope=None, reason="no result line from the TD",
                                  payload=None, runner_no=-1)
        else:
            result = rec.result
        self._track(fragment, result)
        trace = _trace(rec)
        trace.evidence_path = self._save_refused_evidence(rec)
        return result, trace

    def _save_refused_evidence(self, rec) -> Optional[str]:
        """Persist the raw quote of a refused attempt, as `e2e_live` does.

        An RTMR0 outlier can then be re-appraised offline
        (`scripts/gke-v5/20_verify_evidence_offline.py`, `21_dcap_verify.sh`) instead of being
        lost with the TD.
        """
        blob = getattr(rec, "evidence_blob", None)
        if rec.refusal is None or not blob or rec.td is None or self.evidence_dir is None:
            return None
        path = pathlib.Path(self.evidence_dir) / f"evidence-{rec.td}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        print(f"[demo] refused evidence saved: {path}  (rule {rec.refusal.rule}, re-appraise with "
              "scripts/gke-v5/20_verify_evidence_offline.py or 21_dcap_verify.sh)")
        return str(path)

    def _track(self, fragment, result) -> None:
        """Track the run status and, on the cluster path, the observed world.

        The status is the one the V3 lifecycle implies, because the V5 surface has no status
        read. On the cluster path a confirmed effect is recorded as the TD reported it.
        """
        if result.status == "DENIED":
            self._status[fragment.run_id] = "TERMINATED"
        elif result.status in ("EFFECT_UNCERTAIN", "EFFECT_FAILED"):
            # The Authority parks the run in this state (`booking_v1.lifecycle.PolicyState`).
            # Reporting ACTIVE here would make a parked run look resumable.
            self._status[fragment.run_id] = result.status
        elif result.status == "RESULT_UNVERIFIED":
            # No successor reached the harness and the outcome is unknown: the run is not
            # resumable, so it is reported like an uncertain outcome.
            self._status[fragment.run_id] = "EFFECT_UNCERTAIN"
        elif (result.status == "STEP_COMPLETED" and result.envelope is not None
              and result.envelope.step_index >= len(self.transport.policy.allowed_flow)):
            self._status[fragment.run_id] = "COMPLETED"
        if self._remote_world and result.status == "STEP_COMPLETED" and result.payload:
            self.world.record_effect(fragment.operation, result.payload)

    def wait_warm(self, timeout: float = 300.0, log=print) -> int:
        """Block until every idle TD of the warm pool is READY or the timeout passes.

        The demo's first steps are then warm hand-offs.

        Args:
            timeout: Seconds to wait at most.
            log: Where progress lines go.

        Returns:
            The number of ready TDs.
        """
        pool = self.controller.pool
        t0 = time.time()
        while True:
            ready = sum(1 for name in list(pool._idle) if pool.backend.is_ready(name))
            if ready >= pool.size or time.time() - t0 > timeout:
                log(f"[demo] warm pool: {ready}/{pool.size} TD(s) ready after {time.time() - t0:.0f} s")
                return ready
            log(f"[demo] warm pool: {ready}/{pool.size} ready, waiting ...")
            time.sleep(10)

    # the approval gate ----------------------------------------------------------------------
    def _decide(self, ticket, context: dict, grant: Optional[bool], ttl: Optional[int] = None) -> dict:
        """Obtain one decision at the Authority from the decider (a person), else the harness key."""
        if self.decider is not None:
            status = self.decider(ticket, context)
        elif self.harness is not None and grant is not None:
            self.harness.decide(ticket.object_id, "approve" if grant else "reject", ttl=ttl)
            status = self.approvals.wait(ticket.object_id, timeout=30)
        else:
            raise RuntimeError(f"nobody can decide the {context.get('subject')} of {context.get('run_id')} at the "
                               f"Authority: use --approve wait (a person on the approval page) or pass "
                               f"--harness-approver-key for a deployment that pins a harness key")
        self.last_decision = dict(status)
        return status

    def authorize_plan(self, policy, run_id: str, grant: Optional[bool] = None, context: Optional[dict] = None) -> dict:
        """Register the plan at the Authority and obtain its decision.

        An approved plan's genesis envelope is kept for `create_run`.

        Args:
            policy: The compiled policy.
            run_id: The run the plan is for.
            grant: The harness's answer (None: a person decides through `decider`).
            context: Extra fields for the decider.

        Returns:
            The gate's final status.
        """
        ticket = self.approvals.propose_run(policy, run_id)
        status = self._decide(ticket, {"subject": "plan", "run_id": run_id, **(context or {})}, grant)
        if status.get("state") == "approved":
            self._approved[run_id] = wire.envelope_from_wire(status["result"]["envelope"])
        return status

    def decide_intervention(self, run_id, step, fragment_hash, grant, ttl=None, fragment=None):
        """Obtain the Authority's fragment-bound approval for a refused step, or None if rejected."""
        if self.approvals is not None:
            if fragment is None or fragment.fragment_hash != fragment_hash:
                raise ValueError("a gated Authority shows the fragment itself: pass fragment=")
            ticket = self.approvals.step_ticket(fragment)
            status = self._decide(ticket, {"subject": "step", "run_id": run_id, "step": step,
                                           "fragment_hash": fragment_hash}, grant, ttl)
            approval = (status.get("result") or {}).get("approval")
            if status.get("state") == "rejected":
                self._status[run_id] = "TERMINATED"
            return wire.intervention_from_wire(approval) if approval else None
        if self.human is None:
            raise RuntimeError("no human credential on this chain (pass --admin-context)")
        from booking_v4.durable import new_decision_id
        reply = _call(self.authority, "authority.decide_intervention", {
            "human": wire.human_to_wire(self.human), "decision_id": new_decision_id(),
            "run_id": run_id, "step_index": step,
            "fragment_hash": fragment_hash, "approver_id": APPROVER, "approver_kind": "passkey", "grant": grant,
            "ttl": INTERVENTION_TTL if ttl is None else ttl})
        if reply.get("approval") is None:
            if reply.get("error"):
                raise RuntimeError(reply["error"])
            self._status[run_id] = "TERMINATED"
            return None
        return wire.intervention_from_wire(reply["approval"])

    def run_status(self, run_id):
        """Return the run status as tracked by this chain, "UNKNOWN" for a run it has not seen."""
        return self._status.get(run_id, "UNKNOWN")

    def ledger(self):
        """Return one row per dispatch since this chain was opened, in its latest state.

        PENDING rows are kept. The gateway consumes the token and records the intent before it
        calls the counterparty, so a dispatch whose row did not reach COMMITTED means the money
        may have moved without anybody knowing. `booking_v5/gateway.py` reports such a row as
        indeterminate, and dropping it here would report it as zero.

        The reduction is the one `gateway.ledger_delta` uses. Rows arrive in sequence order and
        the last state per grant wins, so a normal dispatch (PENDING then COMMITTED) is a single
        committed row and an unconfirmed one stays visible as a single PENDING row. Callers
        that mean "confirmed effects" filter on `state == "COMMITTED"`.
        """
        latest: dict = {}
        for e in self._ledger.entries_after(self._cursor):
            latest[e.grant_id] = e
        return [vars(e) for e in latest.values()]

    def close(self) -> None:
        """Release what the chain holds (port forwards, idle TDs, in-process services)."""
        if self._on_close:
            self._on_close()


def _listening(url: str) -> bool:
    """Return True when something accepts connections at the host and port of `url`."""
    parts = urllib.parse.urlsplit(url)
    try:
        with socket.create_connection((parts.hostname or "127.0.0.1", parts.port or 80), timeout=0.5):
            return True
    except OSError:
        return False


def _gate_of(authority_endpoint, approval_url: str, harness_key: Optional[str],
             surface_url: Optional[str] = None):
    """Return the Authority's approval gate, if this deployment runs one, and the harness approver.

    Args:
        authority_endpoint: The Authority's protocol endpoint (approval.* methods).
        approval_url: The approval page as the person's browser reaches it, which is the
            WebAuthn origin.
        harness_key: Path of the harness authenticator's key, or None.
        surface_url: Where the harness reaches the page (a private forward), default approval_url.

    Returns:
        (ApprovalClient or None, HarnessApprover or None)
    """
    from booking_approval.client import ApprovalClient, ApprovalUnavailable, HarnessApprover
    client = ApprovalClient(authority_endpoint, approval_url)
    try:
        pinned = client.pinned()
    except ApprovalUnavailable:
        if harness_key:
            raise SystemExit("--harness-approver-key given, but the Authority runs no approval gate")
        return None, None
    who = ", ".join(f"{c['approver_id']} ({c['kind']})" for c in pinned["credentials"])
    print(f"[demo] approval gate at the Authority: approvers {who}; page {approval_url}")
    harness = None
    if harness_key:
        from booking_approval.softauthn import SoftwareAuthenticator
        harness = HarnessApprover(surface_url or approval_url, SoftwareAuthenticator.load(harness_key),
                                  origin=approval_url)
    return client, harness


def read_human_credential(admin_context: str, namespace: str, secret: str = "human-approver") -> HumanApprovalCredential:
    """Read the human's credential under the admin kube context.

    The controller's Role cannot read this Secret. The credential is presented to the
    Authority, which signs the approval.

    Args:
        admin_context: The admin kube context.
        namespace: The namespace of the Secret.
        secret: The name of the Secret.

    Returns:
        The credential.

    Raises:
        RuntimeError: The Secret is empty.
    """
    raw = subprocess.check_output(["kubectl", "--context", admin_context, "-n", namespace, "get", "secret", secret,
                                   "-o", "jsonpath={.data.human-credential\\.json}"]).decode()
    if not raw:
        raise RuntimeError(f"Secret {namespace}/{secret} is empty: run scripts/gke-v5/30_deploy_v5.sh "
                           "(trusted init publishes it)")
    return wire.human_from_wire(json.loads(base64.b64decode(raw)))
