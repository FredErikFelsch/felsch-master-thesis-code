"""Controller: trusted launch of one attested TD per fragment.

The controller is trusted to produce the environment (a peer pod from the measured
profile, on the pinned substrate) and to relay three messages (challenge, evidence,
sealed credential). It is not trusted to authorise anything. It cannot read the
credential, cannot make the Authority accept a TD, and cannot substitute the bytes
after attestation (the TD checks the delivered octets against the attested hashes).

    execute_fragment()
        1  hash fragment and envelope                      -> the two hashes that get attested
        2  pool.acquire((run, step, f, s))                 -> one unbound, READY TD, not reused
                                                              (cold: created now, wait in Timings.ready)
        3  transport.boot_keys(td)                         -> pk_boot and pk_sig of that TD
        4  authority.issue_nonce(run, step, f, s, pk_boot) -> challenge for this step and this TD
        5  transport.attest(td, challenge)                 -> evidence over the canonical binding
        6  authority.establish_session(..., substrate)     -> Session or a named Refusal
        7  transport.deliver(td, sealed, bytes)            -> result, or nothing on refusal
        8  pool.retire(td)                                 -> destroyed on every path, refusal included

Step 8 runs in a `finally`, so a TD that saw a fragment is destroyed even when the run
failed, and the rule that no TD is reused does not depend on the happy path.

Timings for the evaluation are taken at the phase boundaries and returned with the
result. `RunRecord.effects` is not the controller's own claim. It is a delta on the tool
gateway's append-only ledger (`gateway.EffectLedger`), read after a cursor taken before the
run and again after the TD is destroyed. Committed effects for this (run, step) are
`effects`. Pending attempts for it are `pending_effects` (the counterparty did not confirm,
so the outcome is indeterminate and not zero). Rows for any other key are `foreign_effects`.
An accepted run shows one committed effect and no pending or foreign ones. A refused run
shows none, because the refusal happened before any attempt. The controller's code cannot
invent any of these counts, because it holds a read-only handle, and the gateway writes
PENDING only after a Grant and COMMITTED only after the counterparty confirmed. That is a
property of this code, not a restriction of the controller's Kubernetes identity, which is a
privileged provisioner credential and a trust assumption.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from booking_v1.effects import response_digest
from booking_v3.authority import grant_id_of
from booking_v3.runner import RunnerResult

from .evidence import Evidence
from .gateway import EffectLedger, ledger_delta
from .pool import TdPool
from .profile_v5 import RUNNER_GENERATE_NAME, SUBSTRATE_PROFILE, build_runner_pod_manifest, substrate_profile_hash
from .relying_party import AuthorityRelyingParty, ChallengeRefused, Refusal, SessionScope
from .runner_bind import Challenge

_DELETE_TIMEOUT = 180      # seconds to confirm a peer pod and its PeerPod CR are gone

#: The status the controller gives a runner line it cannot back with the gateway's own record.
#: It carries no payload and no successor, so nothing downstream can show it as a provider
#: effect.
RESULT_UNVERIFIED = "RESULT_UNVERIFIED"


class SessionHandle(Protocol):
    """What the controller gets back from the Authority: the sealed box.

    The credential is inside the box, sealed to the TD's boot key, so the controller cannot
    use it itself.
    """

    sealed: dict


class V5Authority(Protocol):
    """The Authority as the controller sees it: challenge, then decision.

    The V3 runner credential is minted inside the Authority after appraisal. The controller
    has no mint function and no bootstrap.
    """

    def issue_nonce(self, run_id: str, step: int, fragment_hash: str, state_hash: str, pk_boot: bytes) -> bytes:
        """Open this step for this TD and return the challenge nonce, or raise ChallengeRefused."""
        ...

    def establish_session(self, evidence: Optional[Evidence], pk_boot: bytes, pk_sig: bytes,
                          run_id: str, step: int,
                          fragment_hash: str, state_hash: str, nonce: bytes,
                          substrate_profile_hash: str) -> "SessionHandle | Refusal":
        """Appraise the evidence and return the sealed credential, or a named Refusal."""
        ...


@dataclass
class LocalAuthority:
    """In-process adapter: the relying party plus the mint it would call in the service."""

    rp: AuthorityRelyingParty
    mint: Callable[[SessionScope], bytes]
    #: The Authority's read-only "is the run at this step on this state?". None means no check,
    #: as in the offline model without a ledger behind it.
    run_is_at: Optional[Callable[[str, int, str], bool]] = None

    def issue_nonce(self, run_id, step, fragment_hash, state_hash, pk_boot):
        """Ask the relying party for the challenge nonce of this step and TD."""
        return self.rp.issue_nonce(run_id, step, fragment_hash, state_hash, pk_boot,
                                   run_is_at=self.run_is_at)

    def establish_session(self, evidence, pk_boot, pk_sig, run_id, step, fragment_hash, state_hash,
                          nonce, substrate_profile_hash):
        """Appraise the evidence in-process and mint the credential on acceptance."""
        return self.rp.establish_session(evidence, pk_boot, pk_sig, run_id, step, fragment_hash,
                                         state_hash, nonce, self.mint, substrate_profile_hash,
                                         run_is_at=self.run_is_at)


@dataclass
class RemoteAuthority:
    """The controller's client of the authority role's V5 surface.

    It calls `v5.issue_nonce` and `v5.establish_session`. The V3 methods are not reachable
    through this object.
    """

    endpoint: object        # booking_v4.endpoint.ServiceEndpoint of the authority role

    def issue_nonce(self, run_id, step, fragment_hash, state_hash, pk_boot):
        """Call `v5.issue_nonce` on the authority role. Raises ChallengeRefused on a refusal."""
        from booking_v4.services import _call
        reply = _call(self.endpoint, "v5.issue_nonce", {
            "run_id": run_id, "step": int(step), "fragment_hash": fragment_hash,
            "state_hash": state_hash, "pk_boot": pk_boot.hex()})
        if reply.get("refusal") is not None:
            r = reply["refusal"]
            raise ChallengeRefused(Refusal(r["rule"], r.get("detail", ""), r.get("stage", "relying-party")))
        return bytes.fromhex(reply["nonce"])

    def establish_session(self, evidence, pk_boot, pk_sig, run_id, step, fragment_hash, state_hash,
                          nonce, substrate_profile_hash):
        """Call `v5.establish_session` on the authority role. Returns a session or a Refusal."""
        from booking_v4.services import _call
        reply = _call(self.endpoint, "v5.establish_session", {
            "evidence": evidence.to_wire() if evidence is not None else None,
            "pk_boot": pk_boot.hex(), "pk_sig": pk_sig.hex(),
            "run_id": run_id, "step": int(step),
            "fragment_hash": fragment_hash, "state_hash": state_hash, "nonce": nonce.hex(),
            "substrate_profile_hash": substrate_profile_hash})
        if reply.get("refusal") is not None:
            r = reply["refusal"]
            return Refusal(r["rule"], r.get("detail", ""), r.get("stage", "relying-party"))
        return _RemoteSession(reply["session"]["sealed"], bytes.fromhex(reply["session"]["td_id"]),
                              dict(reply["session"].get("appraisal", {})))


@dataclass
class _RemoteSession:
    sealed: dict
    td_id: bytes
    appraisal: dict = field(default_factory=dict)   # the Authority's appraisal record (relying_party.appraisal_record)


class TdTransport(Protocol):
    """How the controller talks to a runner inside a TD. Carries messages, no authority."""

    def boot_keys(self, td: str):
        """Return the TD's boot keys (`binding.RunnerKeys`: pk_boot and pk_sig)."""
        ...

    def attest(self, td: str, challenge: Challenge) -> Evidence:
        """Have the TD produce evidence over the canonical binding of the challenge."""
        ...

    def deliver(self, td: str, sealed: dict, fragment_bytes: bytes, envelope_bytes: bytes):
        """Hand the sealed credential, fragment and envelope to the runner and return its result."""
        ...


@dataclass
class Timings:
    """Wall-clock durations of the phases, in seconds. `None` means the phase was not reached.

    `spawn` is the pool hand-out including any cold boot. `ready` is the part of it spent
    waiting for the TD to become READY (0.0 for a warm hand-off). `total` therefore counts
    the boot for the cold path and not for the warm pool. That difference, plus the warm
    pool's idle count, is what the cold-versus-warm evaluation reports.

    There is no `session` phase. The Authority seals the credential inside
    `establish_session`, so sealing is counted in `verification`.
    """

    spawn: Optional[float] = None
    ready: Optional[float] = None
    boot_key: Optional[float] = None
    evidence: Optional[float] = None
    verification: Optional[float] = None
    execution: Optional[float] = None
    destroy: Optional[float] = None

    @property
    def total(self) -> float:
        """Return the sum of the phases (`ready` is already inside `spawn`, so it is not added twice)."""
        return sum(v for k, v in vars(self).items() if isinstance(v, float) and k != "ready")


@dataclass
class RunRecord:
    """Everything one fragment execution produces for the run record."""

    run_id: str
    step: int
    fragment_hash: str
    state_hash: str
    td: Optional[str] = None
    result: object = None
    refusal: Optional[Refusal] = None
    effects: int = 0                 # committed effects for this (run, step), from the ledger
    pending_effects: int = 0         # pending attempts for (run, step), the counterparty did not confirm
    foreign_effects: int = 0         # rows for any other key during this run (0 in a clean run)
    indeterminate: Optional[str] = None   # set when the ledger shows a PENDING dispatch for this step
    evidence_blob: Optional[bytes] = None # the raw quote of this run, kept so a refusal can be re-appraised
    appraisal: dict = field(default_factory=dict)   # the Authority's appraisal record for the session
    timings: Timings = field(default_factory=Timings)
    #: Whether the three counters above were actually read from the gateway ledger. They are
    #: plain integers, so a record that never reached the ledger would otherwise report three
    #: zeros that look like a measured "no effect happened". Every claim of this experiment is
    #: "refused and the ledger did not move", and the second half holds only while this is
    #: True.
    ledger_measured: bool = False
    ledger_error: Optional[str] = None    # why the ledger could not be read, if it could not
    cleanup_error: Optional[str] = None   # the TD could not be confirmed gone (does not hide the measurement)
    #: The grant id the controller derived from (run, step, fragment, input state), not one
    #: read out of the runner line, and what the check of the shown result found: "verified",
    #: "not applicable" (a result that claims no effect), or the reason it failed.
    grant_id: Optional[str] = None
    result_check: str = ""
    #: The runner line as it arrived, kept when `result` was replaced because it could not be
    #: backed by the gateway's record.
    reported_result: object = None

    @property
    def accepted(self) -> bool:
        """True for a measured run with one committed effect and nothing pending or foreign."""
        return (self.ledger_measured and self.refusal is None and self.effects == 1
                and self.pending_effects == 0 and self.foreign_effects == 0)

    @property
    def outcome(self) -> str:
        """Return the outcome word for the run record.

        It is one of UNMEASURED, ACCEPTED, REFUSED(<rule>), INDETERMINATE or ANOMALOUS.

        UNMEASURED comes first, before the refusal. A refusal at the relying party means no
        session existed and therefore no effect was possible, but the point of reading the
        ledger is not to rest the claim on that reasoning. A run whose ledger was never read
        is not evidence of anything, whatever else is known about it.
        """
        if not self.ledger_measured:
            return "UNMEASURED"
        if self.refusal is not None:
            return f"REFUSED({self.refusal.rule})"
        if self.pending_effects:
            return "INDETERMINATE"
        if self.accepted:
            return "ACCEPTED"
        return "ANOMALOUS"


@dataclass
class AttestedFragmentController:
    """One controller per deployment. It holds the pool, the Authority handle and the substrate pin."""

    pool: TdPool
    authority: V5Authority               # LocalAuthority offline, RemoteAuthority live
    transport: TdTransport
    ledger: EffectLedger                 # read-only handle on the gateway's ledger (observation surface)
    substrate_profile: dict = field(default_factory=lambda: dict(SUBSTRATE_PROFILE))

    def execute_fragment(self, run_id: str, step: int, fragment_bytes: bytes,
                         envelope_bytes: bytes) -> RunRecord:
        """Run one fragment in one fresh TD.

        A refusal is returned in the record and not raised, because a refusal is a result of
        the experiment and an exception is a broken run.

        Args:
            run_id: the run.
            step: the step.
            fragment_bytes: canonical fragment octets.
            envelope_bytes: canonical envelope octets.

        Returns:
            The run record with timings, refusal or result, and the ledger delta.
        """
        from . import protocol
        fragment_hash, state_hash = protocol.hashes_of_octets(fragment_bytes, envelope_bytes)
        rec = RunRecord(run_id, step, fragment_hash, state_hash)
        clock = _Clock(rec.timings)
        td = None
        try:
            cursor = self.ledger.high_watermark()       # cursor before anything can happen
        except Exception as exc:                        # noqa: BLE001 (the run is unmeasurable)
            cursor, rec.ledger_error = None, f"cursor: {type(exc).__name__}: {exc}"
        try:
            with clock("spawn"):
                td, ready_seconds = self.pool.acquire((run_id, step, fragment_hash, state_hash))
            rec.timings.ready = ready_seconds           # 0.0 for a warm hand-off, the boot wait when cold
            rec.td = td
            with clock("boot_key"):
                keys = self.transport.boot_keys(td)
            try:
                challenge = Challenge(run_id, step, fragment_hash, state_hash,
                                      self.authority.issue_nonce(run_id, step, fragment_hash, state_hash,
                                                                 keys.pk_boot))
            except ChallengeRefused as exc:             # the Authority will not open this step
                rec.refusal = exc.refusal
                return rec
            with clock("evidence"):
                evidence = self.transport.attest(td, challenge)
            rec.evidence_blob = getattr(evidence, "blob", None)   # kept for offline re-appraisal on a refusal
            with clock("verification"):
                outcome = self.authority.establish_session(
                    evidence, keys.pk_boot, keys.pk_sig, run_id, step, fragment_hash, state_hash,
                    challenge.nonce, substrate_profile_hash(self.substrate_profile))
            if isinstance(outcome, Refusal):
                rec.refusal = outcome
                return rec
            rec.appraisal = dict(getattr(outcome, "appraisal", {}) or {})
            with clock("execution"):
                rec.result = self.transport.deliver(td, outcome.sealed, fragment_bytes, envelope_bytes)
            return rec
        finally:
            # Order and guards both matter here. The TD is retired first, because a TD that is
            # still alive could still redeem its one token, and the measurement must come after
            # the last moment an effect can appear. But a failing cleanup must not swallow the
            # measurement: if `pool.retire` raises (a pod VM that will not confirm gone), the
            # ledger is still read, so no caller reports a delta of 0 that was never measured.
            if td is not None:
                try:
                    with clock("destroy"):
                        self.pool.retire(td)                # destroyed on every path
                except Exception as exc:                    # noqa: BLE001 (recorded, not hidden)
                    rec.cleanup_error = f"{type(exc).__name__}: {exc}"
            self._vouch_for_result(rec)
            if cursor is not None:
                try:
                    delta = ledger_delta(self.ledger.entries_after(cursor), run_id, step)
                    rec.effects, rec.pending_effects = delta.own_committed, delta.own_pending
                    rec.foreign_effects = len(delta.foreign)
                    rec.ledger_measured = True
                    if delta.indeterminate:
                        rec.indeterminate = ("dispatch intent without durable outcome "
                                             "(gateway ledger PENDING)")
                except Exception as exc:                    # noqa: BLE001 (recorded, not hidden)
                    rec.ledger_error = f"read: {type(exc).__name__}: {exc}"

    def _vouch_for_result(self, rec: RunRecord) -> None:
        """Show a confirmed step only when the gateway recorded that same response.

        The runner line is unsigned and crosses a stream the host can see, so on its own it proves
        nothing about the provider. The expected grant id is derived here from the run, the
        step, the fragment hash and the input state hash (`grant_id_of`, the Authority's own
        derivation), and the gateway's ledger row for that grant is read after the TD is gone.

            COMMITTED with the digest of the shown payload   the line is shown as it is
            COMMITTED with another digest                     RESULT_UNVERIFIED (payload dropped)
            PENDING                                           EFFECT_UNCERTAIN, not a success
            no row, or a ledger that cannot be read           RESULT_UNVERIFIED, no provider effect claimed

        Only a line that claims a confirmed effect (STEP_COMPLETED) is checked. A monitor verdict
        or a failure report claims no provider effect and passes through unchanged.
        """
        result = getattr(rec, "result", None)
        if result is None or getattr(result, "status", None) != "STEP_COMPLETED":
            rec.result_check = "not applicable"
            return
        rec.grant_id = grant_id_of(rec.run_id, rec.step, rec.fragment_hash, rec.state_hash)
        try:
            state, recorded = self.ledger.effect(rec.grant_id)
        except Exception as exc:                        # noqa: BLE001 (an unreadable ledger must not count as verified)
            self._replace_result(rec, RESULT_UNVERIFIED,
                                 f"the gateway ledger is unreadable ({type(exc).__name__}): "
                                 "no provider effect is claimed")
            return
        if state == "PENDING":
            self._replace_result(rec, "EFFECT_UNCERTAIN",
                                 "the gateway recorded the dispatch but no outcome for this grant")
        elif state != "COMMITTED" or recorded is None:
            self._replace_result(rec, RESULT_UNVERIFIED,
                                 "no committed gateway record for this grant: no provider effect is claimed")
        elif recorded != response_digest("CONFIRMED", result.payload):
            self._replace_result(rec, RESULT_UNVERIFIED,
                                 "the reported payload differs from the response the gateway recorded")
        else:
            rec.result_check = "verified"

    @staticmethod
    def _replace_result(rec: RunRecord, status: str, reason: str) -> None:
        """Keep the runner line in `reported_result` and put a result without payload in its place."""
        rec.reported_result = rec.result
        rec.result_check = reason
        rec.result = RunnerResult(status=status, envelope=None, reason=reason, payload=None,
                                  runner_no=getattr(rec.reported_result, "runner_no", -1))


class _Clock:
    """Context manager that writes the elapsed seconds of a phase into `Timings`."""

    def __init__(self, timings: Timings):
        self._t = timings
        self._name = None
        self._start = 0.0

    def __call__(self, name: str) -> "_Clock":
        self._name = name
        return self

    def __enter__(self) -> "_Clock":
        self._start = time.monotonic()
        return self

    def __exit__(self, *exc) -> bool:
        setattr(self._t, self._name, time.monotonic() - self._start)
        return False


# --- live substrate backend ---------------------------------------------------

class TdBootFailed(Exception):
    """The TD will not become READY (terminal container state). The pool destroys it at once."""


class InstanceProbe(Protocol):
    """Answers whether the cloud instance behind a TD still exists.

    It is injected, so the backend is testable and the GCE call sits in one place.
    """

    def exists(self, instance_id: str) -> bool:
        """True while the cloud still knows the instance."""
        ...


@dataclass
class GceInstanceProbe:
    """GCE instances.get with Application Default Credentials (the node service account in-cluster).

    A 404 is the only answer that proves absence. Every other error is raised.
    """

    project: str
    zone: str

    def exists(self, instance_id: str) -> bool:
        """Ask the Compute API whether the instance exists."""
        import os
        import google.auth
        import google.auth.transport.requests
        import requests
        scopes = ["https://www.googleapis.com/auth/compute.readonly"]
        creds, _ = google.auth.default(scopes=scopes)
        # On an operator machine, act as the narrow v5-controller service account by
        # impersonation, not with the operator's own rights and not with a key file.
        target = os.environ.get("V5_IMPERSONATE_SA")
        if target:
            from google.auth import impersonated_credentials
            creds = impersonated_credentials.Credentials(creds, target_principal=target, target_scopes=scopes)
        creds.refresh(google.auth.transport.requests.Request())
        url = (f"https://compute.googleapis.com/compute/v1/projects/{self.project}"
               f"/zones/{self.zone}/instances/{instance_id}")
        r = requests.get(url, headers={"Authorization": f"Bearer {creds.token}"}, timeout=20)
        if r.status_code == 404:
            return False
        r.raise_for_status()
        return True


#: Matches a credential written as key, separator and value, for example `secret=...`,
#: `token: ...`, `Authorization: Bearer ...` or `api_key="..."`. Prose that only mentions the
#: word ("the session token expired") has no separator and is left alone.
_CREDENTIAL_IN_LOG = re.compile(
    r"""(?ix)
    (?P<key>\b(?:secret|token|signature|password|passwd|api[_-]?key|authorization)\b["']?\s*[:=]\s*["']?
        (?:bearer\s+)?)
    (?P<value>[^\s"',;}]+)
    """)
_BEARER_IN_LOG = re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+/=-]{8,})")


def mask_log(text: str) -> str:
    """Return `text` with the value of every keyed credential masked, for what leaves a dead TD's log.

    The tail of a runner's stderr is put into an error message and from there into the run
    record. A hash of a fragment is not a credential and stays, because it is what a diagnosis
    needs.
    """
    text = _CREDENTIAL_IN_LOG.sub(lambda m: m.group("key") + "<masked>", text)
    return _BEARER_IN_LOG.sub(lambda m: m.group(1) + "<masked>", text)


@dataclass
class PeerPodBackend:
    """`TdBackend` for pool.py: one CoCo peer pod (one TDX VM) per TD.

    Deletion is fail-closed and GCP-specific. "Destroyed" means the VM is gone, not the
    pod object. After the pod's real 404 the backend waits until GCE no longer knows the
    instance named in the PeerPod custom resource, and only then removes that CR's
    `peer.pod/finalizer`. Upstream `peerpod-ctrl` (CAA 0.21.1) registers no gcp provider,
    so it does not remove the finalizer itself and the namespace would stay Terminating.
    `scripts/gke-v5/91_cleanup_probe.sh` does the same for probe namespaces.
    CRs are named `<pod>-resource-<random>`, so they are matched by `spec.instanceID` and not
    by the pod name. `destroyed_at[name]` is the timestamp for the measurements.
    """

    namespace: str
    image: str
    instances: InstanceProbe
    policy_rego: Optional[str] = None
    label: str = "trusted-runner-controller-v5"
    python: str = "/usr/local/bin/python3"                # RUNNER_PYTHON from .digests
    registry: Optional[str] = None                        # AR host for the guest-pull secret
    pull_token: Optional[Callable[[], str]] = None        # mints a short-lived registry token per spawn
    # Default 0 on GCP. peerpod-ctrl in CAA 0.21.1 registers no gcp provider (its controllers
    # blank-import aws, azure, ibmcloud, libvirt, alibabacloud and byom only), so its reconcile
    # cannot delete the instance and does not drop the finalizer. The CAA StopVM to
    # ReleasePeerPod path did not clear the CR within 30 s either. On GCP the
    # confirmed-finalizer cleanup below is therefore the expected path, not an error recovery,
    # and waiting a grace period first only pads every destroy. Raise this for a substrate
    # whose controller removes the CR itself, to let it take the coco_native path.
    cr_grace: float = 0.0                                 # seconds to let CoCo remove the PeerPod CR itself first
    destroyed_at: dict = field(default_factory=dict)      # td name -> monotonic time the VM was gone
    cleanup_mode: dict = field(default_factory=dict)      # td name -> how the CR was cleared (see _confirm_...)

    def _api(self):
        from kubernetes import client
        return client.CoreV1Api(), client.CustomObjectsApi()

    def create(self) -> str:
        """Create one runner pod from the measured manifest and return its name."""
        core, _ = self._api()
        if self.pull_token is not None:
            self._mint_pull_secret(core)
        # generateName: the API server assigns runner-td-<5 chars>, which is what the measured
        # policy allows as the sandbox name (scripts/gke-v5/13_genpolicy.sh uses the same manifest function).
        manifest = build_runner_pod_manifest(image=self.image, namespace=self.namespace,
                                             generate_name=RUNNER_GENERATE_NAME,
                                             policy_rego=self.policy_rego, python=self.python)
        created = core.create_namespaced_pod(self.namespace, manifest)
        return created.metadata.name

    def _mint_pull_secret(self, core) -> None:
        """Write the guest-pull secret for the next spawn.

        The guest pulls the runner image itself (image_guest_pull) and CAA hands it the
        dockerconfig of `ar-pull` as auth.json. The secret is minted per spawn from the
        controller's own identity (a short-lived token) instead of a long-lived key in a Secret.
        """
        import base64
        import json as _json
        from kubernetes import client
        from kubernetes.client.rest import ApiException
        from .profile_v5 import PULL_SECRET
        auth = base64.b64encode(f"oauth2accesstoken:{self.pull_token()}".encode()).decode()
        dockercfg = _json.dumps({"auths": {self.registry: {"auth": auth}}})
        body = client.V1Secret(metadata=client.V1ObjectMeta(name=PULL_SECRET, namespace=self.namespace),
                               type="kubernetes.io/dockerconfigjson",
                               string_data={".dockerconfigjson": dockercfg})
        try:
            core.replace_namespaced_secret(PULL_SECRET, self.namespace, body)
        except ApiException as exc:
            if exc.status != 404:
                raise
            core.create_namespaced_secret(self.namespace, body)

    #: Waiting reasons that waiting does not resolve. They fail the spawn now, not after the timeout.
    TERMINAL_WAITING = ("CreateContainerError", "CreateContainerConfigError", "ErrImagePull",
                        "ImagePullBackOff", "InvalidImageName", "CrashLoopBackOff")

    def is_ready(self, name: str) -> bool:
        """Whether the pod is Ready.

        Raises:
            TdBootFailed: the pod is in a state waiting cannot fix (a policy denial shows as
                CreateContainerError with the agent's message).
        """
        core, _ = self._api()
        pod = core.read_namespaced_pod(name, self.namespace)
        if pod.status.phase in ("Failed", "Succeeded"):
            raise TdBootFailed(f"{name} is {pod.status.phase}: {pod.status.reason or ''} "
                               f"{pod.status.message or ''}\n{self.diagnose(name, pod)}")
        for cs in (pod.status.container_statuses or []):
            w = cs.state.waiting if cs.state else None
            if w is not None and w.reason in self.TERMINAL_WAITING:
                raise TdBootFailed(f"{name} {w.reason}: {(w.message or '')[:400]}\n{self.diagnose(name, pod)}")
        conditions = {c.type: c.status for c in (pod.status.conditions or [])}
        return conditions.get("Ready") == "True"

    def diagnose(self, name: str, pod=None) -> str:
        """Return what the controller may read about a dead TD, before it is destroyed.

        That is the container's terminal state (exit code, reason) and the tail of its log
        (stderr of the runner: the audit lines and the reason of a RUNNER_ERROR). pods/log is
        in the Role.
        """
        core, _ = self._api()
        lines = []
        try:
            pod = pod or core.read_namespaced_pod(name, self.namespace)
            for cs in (pod.status.container_statuses or []):
                t = cs.state.terminated if cs.state else None
                if t is not None:
                    lines.append(mask_log(f"container {cs.name}: exit {t.exit_code} reason={t.reason} {(t.message or '')[:300]}"))
        except Exception as exc:                                    # noqa: BLE001 (diagnosis is best effort)
            lines.append(f"(status unreadable: {exc})")
        try:
            log = core.read_namespaced_pod_log(name, self.namespace, container="runner", tail_lines=40)
            lines.append("--- runner log (tail) ---")
            lines.append(mask_log(log.rstrip()))
        except Exception as exc:                                    # noqa: BLE001 (diagnosis is best effort)
            lines.append(f"(log unreadable: {exc})")
        return "\n".join(lines)

    def delete_and_confirm(self, name: str) -> None:
        """Delete the pod, wait for its real 404, then record how the PeerPod CR was cleared.

        The mode lands in `cleanup_mode[name]`:

        coco_native                      the CR is gone within `cr_grace` (CoCo cleared it
                                         itself). On GCP this does not happen (see cr_grace).
        gce_confirmed_finalizer_cleanup  the CR is still there: confirm with the cloud that the
                                         VM is gone, then drop the finalizer. This is the
                                         expected path on GCP, not an error recovery.
        leaked_vm_failure                the VM does not disappear before the deadline: the
                                         finalizer stays and the run fails (fail-closed). This is
                                         the only real fault.

        Raises:
            RuntimeError: the pod or its VM is not confirmed gone within `_DELETE_TIMEOUT`.
        """
        from kubernetes import client
        from kubernetes.client.rest import ApiException
        core, custom = self._api()
        try:
            core.delete_namespaced_pod(name, self.namespace,
                                       body=client.V1DeleteOptions(grace_period_seconds=0))
        except ApiException as exc:
            if exc.status != 404:
                raise
        deadline = time.monotonic() + _DELETE_TIMEOUT
        while True:
            try:
                core.read_namespaced_pod(name, self.namespace)
            except ApiException as exc:
                if exc.status == 404:                       # only a real 404 proves absence
                    break
                raise
            if time.monotonic() > deadline:
                raise RuntimeError(f"peer pod {name} not confirmed deleted (fail-closed)")
            time.sleep(0.5)
        self._confirm_vm_gone_and_clear_crs(custom, name, deadline)
        self.destroyed_at[name] = time.monotonic()

    def _peerpod_crs(self, custom, name: str) -> list:
        """Return the PeerPod CRs of this pod, matched by instanceID `podvm-<pod>-<hash>`."""
        from kubernetes.client.rest import ApiException
        try:
            items = custom.list_namespaced_custom_object(
                "confidentialcontainers.org", "v1alpha1", self.namespace, "peerpods").get("items", [])
        except ApiException as exc:
            if exc.status == 404:                           # CRD absent: nothing to clear
                return []
            raise
        prefix = f"podvm-{name}-"
        return [it for it in items if str(it.get("spec", {}).get("instanceID", "")).startswith(prefix)]

    def _confirm_vm_gone_and_clear_crs(self, custom, name: str, deadline: float) -> None:
        """Clear the pod's PeerPod CRs once the cloud confirms each VM is gone.

        CoCo first gets `cr_grace` seconds to remove the CR itself (coco_native). On GCP that
        grace is 0 because peerpod-ctrl does not clear it. For every CR still present, wait
        until the cloud reports the instance gone, drop the finalizer and record the cleanup
        mode: `gce_confirmed_finalizer_cleanup` (the expected GCP path) or, if the VM does not
        disappear before the deadline, `leaked_vm_failure` (fail-closed, the finalizer is kept).
        """
        grace_end = time.monotonic() + self.cr_grace
        while self._peerpod_crs(custom, name) and time.monotonic() < grace_end:
            time.sleep(1)
        crs = self._peerpod_crs(custom, name)
        if not crs:
            self.cleanup_mode[name] = "coco_native"          # CoCo cleared the CR within the grace
            return
        for cr in crs:                                       # confirmed-finalizer cleanup (GCP)
            instance = cr["spec"]["instanceID"]
            while self.instances.exists(instance):
                if time.monotonic() > deadline:
                    self.cleanup_mode[name] = "leaked_vm_failure"
                    raise RuntimeError(f"pod VM {instance} still exists after pod deletion "
                                       f"(LEAK: fail-closed, finalizer kept, run failed)")
                time.sleep(2)
            custom.patch_namespaced_custom_object(
                "confidentialcontainers.org", "v1alpha1", self.namespace, "peerpods",
                cr["metadata"]["name"], {"metadata": {"finalizers": None}})
        self.cleanup_mode[name] = "gce_confirmed_finalizer_cleanup"

    def list_managed(self) -> list:
        """Return the sorted names of the pods in the namespace that carry this backend's label."""
        core, _ = self._api()
        pods = core.list_namespaced_pod(self.namespace, label_selector=f"managed-by={self.label}")
        return sorted(p.metadata.name for p in pods.items)
