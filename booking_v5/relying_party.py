"""The Authority as RATS relying party: the second half of verification, where policy lives.

The verifier (verifier.py with local DCAP, or the offline fake) says only that the evidence
is genuine and what it claims. Everything that decides whether those claims are acceptable is
here. Each check fails closed, and each refusal has a name that appears in the run record:

    (a) reference values      platform, MRTD, RTMR0..2, MRSEAM, TCB SVN, XFAM, TD attributes.
                              MROWNER is not pinned, because it differs per pod-VM instance
                              on GCE.
    (b) canonical binding     the attested runtime_data equals the canonical binding
                              (`binding.canonical_binding`) over version, nonce, run, step,
                              fragment and state hash, pk_boot and pk_sig, for a nonce this
                              Authority issued for this step. pk_sig is the key the TD signs
                              its own verdicts with, so the Authority verifies decisions
                              against a key the hardware vouched for, not one the channel
                              offered.
    (c) one TD, one fragment  the TD identity H(pk_boot) is bound to no other fragment
                              (ledger), and RTMR3 equals the replay of the expected history
                              [init-data, boot-key, bind]. No event log is needed, and one
                              extra event anywhere changes the value.
    (d) substrate profile     the half of the Fixed Execution Profile that hardware cannot
                              attest (RuntimeClass, pod-VM type, subnet, firewall, network
                              policies), asserted by the trusted controller as a hash. This
                              is a self-asserted profile binding, not attestation: it pins
                              the configuration the controller claims to have deployed and
                              refuses a session under any other claim. By design it cannot
                              detect a controller that lies.

The nonce is consumed before the appraisal and stays consumed on every path. Only after all
checks succeed is a credential scoped to (run, step, fragment_hash, state_hash, pk_boot)
minted and sealed to pk_boot. Sealing keeps the credential unreadable on its way into the TD
(controller, kubelet and attach stream carry ciphertext). Scoping keeps it useless for any
other step even inside the TD. `redeem` enforces that scope again at the grant path (attack
A17). Attack labels in this module (A14, A17) refer to scripts/gke-v5/attack_catalogue.md.

The binding carries pk_sig for the following reason. Sealing to pk_boot keeps the credential
confidential only until its first use, and the channel after that carries no transport
authentication. A host that read the credential off the DENY report could drop the report,
keep the session open and state an ALLOW itself, for the fragment the monitor had refused.
The Authority does not recompute policy, so it would mint a grant whose request hash named
the attacker's own payment. The binding identifies a request. It does not show that the
monitor admitted it.

`pk_sig` closes this. The TD signs every verdict it reports (see
`booking_v3.runner_attestation`), the Authority reconstructs the statement it expects from
its own ledger and requires a signature over that statement, and pk_sig is inside the
canonical binding, so the key belongs to the measured instance. An attacker who reads the
credential can still drop messages and race the legitimate TD for the one effect this TD has
already signed for, but it cannot issue a verdict of its own.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import secrets
from dataclasses import dataclass, field
from typing import Callable, Optional

from .binding import BINDING_V50, bind_event, canonical_binding, seal_to, td_identity
from .evidence import Evidence
from .rtmr_replay import diagnose_rtmr3, expected_rtmr3
from .verifier import VerifiedClaims, Verifier, VerificationFailed

#: Claims that are pinned when present in the reference. MROWNER is left out (see (a) above).
PINNED_BOOT_FIELDS = ("rtmr0", "rtmr1", "rtmr2", "mrseam", "tee_tcb_svn", "xfam", "tdattributes")


def tdattributes_debug(tdattributes) -> bool:
    """Whether TDATTRIBUTES has the DEBUG bit (bit 0) set.

    The field is 8 bytes, little-endian, as the quote carries it, given as the hex string of
    the quote field or as raw bytes. An absent value is not debug (the pins decide what may be
    absent).
    """
    if tdattributes is None:
        return False
    raw = bytes.fromhex(tdattributes) if isinstance(tdattributes, str) else bytes(tdattributes)
    return bool(raw) and bool(raw[0] & 0x01)


#: The canonical bindings this code knows. Any other version is refused.
KNOWN_BINDING_VERSIONS = (BINDING_V50.decode(), "v5.1")


@dataclass
class ReferenceValues:
    """One frozen runner image plus its substrate.

    The trusted deploy step builds it from `freeze-<STAMP>.json` (see `from_freeze`). For
    analysis it can also be built from the raw reference values (`from_reference_values`).

    MRTD and the boot RTMRs are read from a quote of the podvm image this repository builds
    (`scripts/gke-v5/11_build_podvm_image.sh`, recorded in the freeze with the image's
    digests). That is trust on first use against the project's own build, not against a quote
    a third party presented. The value pinned here is what the project's pipeline produced,
    and every later TD is compared to it. What remains open is an MRTD computed
    independently from the image (a reproducible measured-boot calculation). For a custom
    Fedora podvm there is no established tooling for that today.

    An empty `boot_measurements` means those fields are not pinned. That is the offline
    model default only. `from_freeze` builds the pinned form used against real hardware.
    """

    platform: str = "tdx"
    measurement: str = "mrtd-ref"                       # MRTD
    boot_measurements: dict = field(default_factory=dict)
    init_data_digest: str = "initdata-ref"              # sha256 of the init-data TOML
    substrate_profile_hash: str = "substrate-ref"       # self-asserted profile binding
    #: RTMR3 must carry the expected history. A reference that tolerates a missing RTMR3
    #: would accept a TD that never measured its init-data, so an offline model that wants the
    #: weaker form must say so explicitly.
    require_rtmr3: bool = True
    #: Which canonical binding the image of this freeze attests under. "v5.0" is the earlier
    #: binding, which carries no verdict key. A session established under it records none, and
    #: the Authority then believes a decision because of the channel it arrived on.
    #:
    #: The measurement pins do not refuse an older binding directly. MRTD and RTMR0..2 measure
    #: the pod-VM image, while the binding version is a property of the runner container image.
    #: That image is pinned through `init_data_digest` (the genpolicy policy names the image
    #: digest) and measured as the first RTMR3 event. The coupling is real but it runs through
    #: the init-data, and in a deployed Authority that digest comes from
    #: `service_v5 init --runner-image`, not from the freeze record.
    #:
    #: The default is therefore not permissive. `from_freeze_text` refuses a record without the
    #: field unless the caller says explicitly that it is reading an archived one. A deployment
    #: cannot silently end up on the weaker binding, and only the offline re-appraisal of
    #: archived evidence can ask for it.
    binding_version: str = "v5.1"
    #: Which init-data digest `init_data_digest` is. "run" is the digest of the document every
    #: production runner is launched with, rendered into the freeze, so the deployment's own
    #: digest must equal it. "probe" is the digest of the probe pod's quote, which is not what
    #: runs are measured under, so a deployment has to supply its own. "unspecified" marks a
    #: record written before the profile was named and is treated like "probe".
    init_data_profile: str = "unspecified"

    def __post_init__(self) -> None:
        """Refuse an unknown binding version however the object was built.

        Raises:
            ValueError: `binding_version` is not in KNOWN_BINDING_VERSIONS.
        """
        if self.binding_version not in KNOWN_BINDING_VERSIONS:
            raise ValueError(f"unknown binding_version {self.binding_version!r}, "
                             f"this code knows {', '.join(KNOWN_BINDING_VERSIONS)}")

    @classmethod
    def from_freeze(cls, freeze_json: str | pathlib.Path,
                    allow_pre_h2_binding: bool = False) -> "ReferenceValues":
        """Build the pinned reference from `freeze-<STAMP>.json` (booking_v5.freeze_record).

        The substrate hash, the measurements and the init-data digest all come from this one
        file, which also names the artefacts it was built from, so there is no second argument
        that could disagree with it. The raw output of
        scripts/gke-v5/20_verify_evidence_offline.py is not accepted here.

        Args:
            freeze_json: path of the freeze record.
            allow_pre_h2_binding: admit a v5.0 record (see `from_freeze_text`).

        Returns:
            The pinned reference values.

        Raises:
            ValueError: the file is not a freeze record, or names a binding that is refused.
        """
        return cls.from_freeze_text(pathlib.Path(freeze_json).read_text(), str(freeze_json),
                                    allow_pre_h2_binding)

    @classmethod
    def from_freeze_text(cls, text: str, name: str = "<freeze>",
                         allow_pre_h2_binding: bool = False) -> "ReferenceValues":
        """Same as `from_freeze`, from the JSON text (the seeded setting of the authority store).

        Args:
            text: the freeze record as JSON text.
            name: how the record is named in error messages.
            allow_pre_h2_binding: admit a record that names "v5.0", or names no
                `binding_version` and therefore means "v5.0". This is the binding before the
                verdict key was attested, so a host could state an ALLOW for a refused
                fragment (see the module docstring).
                Only the offline re-appraisal of archived evidence passes it. Every other
                caller, a deployment above all, gets a refusal instead of the weaker binding.

        Returns:
            The pinned reference values.

        Raises:
            ValueError: the text is not a freeze record of schema 1, names an unknown binding
                version, or names v5.0 without `allow_pre_h2_binding`.
        """
        data = json.loads(text)
        if data.get("schema_version") != 1 or "measurement" not in data:
            raise ValueError(f"{name} is not a freeze-<STAMP>.json (schema_version 1). "
                             "build it with `python3 -m booking_v5.freeze_record build`")
        version = data.get("binding_version", BINDING_V50.decode())
        if version not in KNOWN_BINDING_VERSIONS:
            raise ValueError(f"{name} names the unknown binding_version {version!r}, "
                             f"this code knows {', '.join(KNOWN_BINDING_VERSIONS)}")
        # An explicit "v5.0" is the same weaker binding as a missing field. It is admitted only
        # for the offline re-appraisal of archived evidence.
        if version == BINDING_V50.decode() and not allow_pre_h2_binding:
            raise ValueError(
                f"{name} {'names binding_version v5.0' if 'binding_version' in data else 'names no binding_version'}"
                f", so it means the v5.0 binding, "
                f"in which a TD's verdict key is not attested and its "
                f"decisions are therefore not verified. Rebuild the freeze with the current "
                f"code, or pass allow_pre_h2_binding=True to re-appraise archived evidence.")
        m = data["measurement"]
        return cls(platform=data["platform"], measurement=m["mrtd"],
                   boot_measurements={k: m[k] for k in PINNED_BOOT_FIELDS},
                   init_data_digest=data["init_data"]["digest"],
                   substrate_profile_hash=data["substrate_profile_hash"], require_rtmr3=True,
                   binding_version=version,
                   init_data_profile=data["init_data"].get("profile", "unspecified"))

    @classmethod
    def from_reference_values(cls, reference_values_json: str | pathlib.Path, substrate_profile_hash: str,
                              init_data_digest: Optional[str] = None) -> "ReferenceValues":
        """Build the pin from a raw `reference-values-<STAMP>.json` plus a substrate hash.

        The file is the output of scripts/gke-v5/20_verify_evidence_offline.py. This is for
        analysis and tests of a run that is not frozen yet. The deployed Authority uses
        `from_freeze`.

        Args:
            reference_values_json: path of the reference values file.
            substrate_profile_hash: the substrate hash to pin.
            init_data_digest: overrides the recorded init-data digest.

        Returns:
            The pinned reference values.

        Raises:
            KeyError: the file carries no digest for its init-data algorithm and none is given.
        """
        data = json.loads(pathlib.Path(reference_values_json).read_text())
        f = data["quote"]["fields"]
        # The init-data digest process-user-data measures is <algorithm>(raw TOML), and the
        # algorithm is the TOML's own field (sha256 here, sha384 is the CoCo default). Take
        # the key from the recorded algorithm instead of a fixed name.
        algo = data["init_data"]["algorithm"]
        key = f"{algo}(toml)"
        if init_data_digest is None and key not in data["init_data"]:
            raise KeyError(f"reference values carry no {key} digest for init-data algorithm {algo}")
        return cls(platform="tdx", measurement=f["mrtd"],
                   boot_measurements={k: f[k] for k in PINNED_BOOT_FIELDS},
                   init_data_digest=init_data_digest or data["init_data"][key],
                   substrate_profile_hash=substrate_profile_hash, require_rtmr3=True)


@dataclass
class Refusal:
    """A named refusal. `rule` is stable and can be quoted in the evaluation.

    `stage` says which layer refused: "verifier" (the evidence could not be established:
    quote-malformed, reportdata-mismatch, no-appraiser, tcb-rejected, collateral-unavailable,
    verifier-error, see verifier.VerificationFailed) or "relying-party" (genuine evidence that
    is not the right evidence: reference, binding, nonce, ledger, RTMR3, scope). Only
    `collateral-unavailable` and `verifier-error` say nothing about the TD itself.
    """

    rule: str
    detail: str = ""
    stage: str = "relying-party"


@dataclass(frozen=True)
class SessionScope:
    """What a minted credential is valid for: one run, step, fragment and input state on one TD."""

    run_id: str
    step: int
    fragment_hash: str
    state_hash: str
    pk_boot: bytes          # the TD's boot key, one name everywhere (binding, RTMR3, scope)
    pk_sig: bytes           # the TD's verdict key, which the Authority verifies its decisions with


@dataclass(frozen=True)
class Grant:
    """What the Authority asserts at the grant path.

    The credential authorises one logical effect, `effect_id`, on these run, step, fragment
    and state hashes. The gateway compares the bytes it was handed against these four fields
    before it performs anything. This content binding at the effect is the last check that
    the executed fragment is the attested one.
    """

    run_id: str
    step: int
    fragment_hash: str
    state_hash: str
    credential_id: str
    effect_id: str


SESSION_ACTIVE = "ACTIVE"
SESSION_SUPERSEDED = "SUPERSEDED"


@dataclass
class Session:
    """One attested TD session: its scope, the minted credential and the box it was sealed in."""

    scope: SessionScope
    td_id: bytes
    credential: bytes
    sealed: dict
    effect_id: Optional[str] = None   # set at the first redemption, because a credential authorises one effect
    state: str = SESSION_ACTIVE       # ACTIVE, or SUPERSEDED by the continuation of a pending intervention
    superseded_by: Optional[str] = None   # td_id (hex) of the continuation session
    #: Which verifier appraised the evidence this session rests on, and its verdict. Part of
    #: the durable record: a session whose appraisal says `FakeVerifier` is not a measured one.
    appraisal: dict = field(default_factory=dict)

    @property
    def redeemed(self) -> bool:
        """Whether the credential has already been bound to an effect."""
        return self.effect_id is not None


class ChallengeRefused(Exception):
    """The Authority refuses a challenge for this (run, step, state).

    The run is not active, not at that step or not on that state. The exception carries the
    named `Refusal`.
    """

    def __init__(self, refusal: "Refusal") -> None:
        super().__init__(f"{refusal.rule}: {refusal.detail}")
        self.refusal = refusal


@dataclass
class AuthorityRelyingParty:
    """The relying party's decision logic and its in-memory ledger.

    The durable Authority stores `export_state()` (nonces, TD bindings, active sessions and
    the superseded history) as one JSON document in the `v5_state` table of its SQLite store.
    """

    verifier: Verifier
    reference: ReferenceValues
    _nonces: dict = field(default_factory=dict)      # nonce -> (run, step, frag, state, pk_boot, used)
    _td_bound_to: dict = field(default_factory=dict) # td_id -> (run, step, frag, state)
    _sessions: dict = field(default_factory=dict)    # (run, step) -> the ACTIVE Session
    _history: list = field(default_factory=list)     # every SUPERSEDED Session, in order (audit)
    refusals: list = field(default_factory=list)     # every Refusal, for the run record

    # --- durability (V4 durable server persists this alongside the Authority) ---
    @staticmethod
    def _session_to_wire(sess: "Session") -> dict:
        return {
            "run_id": sess.scope.run_id, "step": sess.scope.step,
            "scope": {"run_id": sess.scope.run_id, "step": sess.scope.step,
                      "fragment_hash": sess.scope.fragment_hash, "state_hash": sess.scope.state_hash,
                      "pk_boot": sess.scope.pk_boot.hex(), "pk_sig": sess.scope.pk_sig.hex()},
            "td_id": sess.td_id.hex(), "credential": sess.credential.hex(),
            "sealed": sess.sealed, "effect_id": sess.effect_id,
            "state": sess.state, "superseded_by": sess.superseded_by,
            "appraisal": dict(sess.appraisal),
        }

    @staticmethod
    def _session_from_wire(d: dict) -> "Session":
        sc = d["scope"]
        scope = SessionScope(sc["run_id"], sc["step"], sc["fragment_hash"], sc["state_hash"],
                             bytes.fromhex(sc["pk_boot"]), bytes.fromhex(sc["pk_sig"]))
        return Session(scope, bytes.fromhex(d["td_id"]), bytes.fromhex(d["credential"]), d["sealed"],
                       d["effect_id"], d.get("state", SESSION_ACTIVE), d.get("superseded_by"),
                       dict(d.get("appraisal", {})))

    def export_state(self) -> dict:
        """Return the three ledgers plus the session history, JSON-safe.

        `refusals` are the run record, not state. `sessions` holds the active session per
        (run, step) and `history` every session a continuation superseded. After a
        continuation the durable record therefore shows two attested TD sessions, the second
        an explicit continuation of the first, and not one session whose content changed.
        """
        return {
            "nonces": {n.hex(): [v[0], v[1], v[2], v[3], v[4].hex(), v[5]]
                       for n, v in self._nonces.items()},
            "td_bound_to": {t.hex(): list(v) for t, v in self._td_bound_to.items()},
            "sessions": [self._session_to_wire(sess) for sess in self._sessions.values()],
            "history": [self._session_to_wire(sess) for sess in self._history],
        }

    def import_state(self, state: Optional[dict]) -> None:
        """Restore what `export_state` wrote. `None` (a fresh store) leaves the ledger empty."""
        if state is None:
            return
        self._nonces = {bytes.fromhex(n): (v[0], v[1], v[2], v[3], bytes.fromhex(v[4]), v[5])
                        for n, v in state["nonces"].items()}
        self._td_bound_to = {bytes.fromhex(t): tuple(v) for t, v in state["td_bound_to"].items()}
        self._sessions = {}
        for d in state["sessions"]:
            sess = self._session_from_wire(d)
            self._sessions[(sess.scope.run_id, sess.scope.step)] = sess
        self._history = [self._session_from_wire(d) for d in state.get("history", [])]

    # --- challenge -----------------------------------------------------------
    def issue_nonce(self, run_id: str, step: int, fragment_hash: str, state_hash: str,
                    pk_boot: bytes,
                    run_is_at: Optional[Callable[[str, int, str], bool]] = None) -> bytes:
        """Issue a fresh nonce, bound to this expected step and to the TD that asked.

        A nonce bound to the step alone can be presented by any TD, so a challenge issued for
        one machine could be answered by another. Binding it to `pk_boot` closes that and
        costs nothing, because the controller already sends the key it just read from the
        TD's hello.

        What this does not establish: which fragment a TD is challenged for remains the
        controller's choice, and the controller is a trusted component for this choice. A
        party on the path can still cause a TD to be bound to any fragment the Authority would
        accept, and that set is bounded by what the monitor and the freshness check then
        allow, not by this nonce.

        Args:
            run_id: the run.
            step: the step the run is expected at.
            fragment_hash: the fragment the TD is to bind to.
            state_hash: the state the step runs on.
            pk_boot: the boot key from the TD's hello.
            run_is_at: the Authority's own read-only answer to "is the run active, at this
                step, on this state?", called as `run_is_at(run_id, step, state_hash)`. When
                it says no, no nonce is issued and nothing is recorded, so a refused challenge
                cannot block the step.

        Returns:
            The 32-byte nonce.

        Raises:
            ChallengeRefused: the run is not active at this step on this state.
        """
        if run_is_at is not None and not run_is_at(run_id, step, state_hash):
            raise ChallengeRefused(self._refuse(
                "run-not-at-step", "the run is not active at this step on this state"))
        n = secrets.token_bytes(32)
        self._nonces[n] = (run_id, step, fragment_hash, state_hash, bytes(pk_boot), False)
        return n

    # --- appraisal and scoped session ------------------------------------------
    def establish_session(self, evidence: Optional[Evidence], pk_boot: bytes, pk_sig: bytes,
                          run_id: str, step: int,
                          fragment_hash: str, state_hash: str, nonce: bytes,
                          mint_credential: Callable[[SessionScope], bytes],
                          substrate_profile_hash: str = "substrate-ref",
                          continuation_pending: Optional[Callable[[str, int, str], bool]] = None,
                          run_is_at: Optional[Callable[[str, int, str], bool]] = None,
                          ) -> "Session | Refusal":
        """Make the whole session decision, in refusal order.

        Args:
            evidence: the TD's evidence, or None (refused as evidence-missing).
            pk_boot: the TD's boot key.
            pk_sig: the TD's verdict key.
            run_id: the run.
            step: the step.
            fragment_hash: the fragment the TD is bound to.
            state_hash: the state the step runs on.
            nonce: the nonce this Authority issued for the challenge.
            mint_credential: mints the credential for the scope.
            substrate_profile_hash: the substrate hash the controller asserts.
            continuation_pending: the Authority's own answer to "is a manual intervention
                pending for this fragment, unconsumed, on a live run?", called as
                `continuation_pending(run_id, step, fragment_hash)`. Without it a (run, step)
                admits one session only.
            run_is_at: as for `issue_nonce`, read again after the nonce was spent.

        Returns:
            The new Session, or the Refusal.
        """
        # The nonce comes first, before every other check. It is consumed at its first
        # presentation whatever the outcome. A refusal above it would leave the same challenge
        # open for another try with other evidence. A nonce has to be spent by its first use,
        # so its check precedes every other one.
        rec = self._nonces.get(nonce)
        if rec is None:
            return self._refuse("nonce-unknown")
        if rec[5]:
            return self._refuse("nonce-reused")
        self._nonces[nonce] = rec[:5] + (True,)
        if rec[:4] != (run_id, step, fragment_hash, state_hash):
            return self._refuse("nonce-step-mismatch")
        if not secrets.compare_digest(rec[4], bytes(pk_boot)):
            return self._refuse("nonce-td-mismatch",
                                "this challenge was issued for another boot key")

        # Keys of a fixed size. Under the current binding the verdict key is inside the quote and
        # the session requires signed statements from it, so an empty or odd sized key must not
        # make a session. The v5.0 binding carries none, and its scope records none.
        if len(pk_boot) != 32 or (self.reference.binding_version.encode() != BINDING_V50 and len(pk_sig) != 32):
            return self._refuse("key-length", "the boot key and the verdict key are 32 bytes each")

        # The Authority's own view, read again after the nonce was spent: the step may have
        # closed since the challenge was issued. This check adds no state of its own.
        if run_is_at is not None and not run_is_at(run_id, step, state_hash):
            return self._refuse("run-not-at-step", "the run is not active at this step on this state")

        # (d) substrate half of the profile, asserted by the trusted controller and pinned here.
        if substrate_profile_hash != self.reference.substrate_profile_hash:
            return self._refuse("substrate-profile-mismatch")
        # A14: the controller's own credentials give nothing without hardware evidence.
        if evidence is None:
            return self._refuse("evidence-missing", "no evidence presented")

        # (a) genuine evidence, then reference values
        try:
            claims = self.verifier.verify(evidence)
        except VerificationFailed as exc:
            return self._refuse(exc.code, str(exc), stage="verifier")
        ref_refusal = self._check_reference(claims)
        if ref_refusal is not None:
            return ref_refusal

        # (b) canonical binding, attested by the hardware in runtime_data
        version = self.reference.binding_version.encode()
        if not secrets.compare_digest(
                claims.runtime_data,
                canonical_binding(nonce, run_id, step, fragment_hash, state_hash, pk_boot, pk_sig,
                                  version)):
            return self._refuse("binding-mismatch")

        # (c) core invariant: one boot key, at most one fragment.
        tid = td_identity(pk_boot)
        prior = self._td_bound_to.get(tid)
        if prior is not None and prior != (run_id, step, fragment_hash, state_hash):
            return self._refuse("td-already-bound", f"{prior}")
        prior = self._sessions.get((run_id, step))
        if prior is not None:
            why = self._continuation_refused(prior, run_id, step, fragment_hash, state_hash,
                                             continuation_pending)
            if why is not None:
                return self._refuse("step-already-has-session", why)
        rtmr_refusal = self._check_rtmr3(claims, pk_boot, pk_sig, run_id, step, fragment_hash, state_hash)
        if rtmr_refusal is not None:
            return rtmr_refusal

        # Commit: record the binding, then mint and seal the scoped credential (the nonce is
        # already consumed). If minting fails the TD stays bound without a session, which only
        # retires this single-use TD.
        self._td_bound_to[tid] = (run_id, step, fragment_hash, state_hash)
        # Under the v5.0 binding the verdict key is not covered by the quote, so the session
        # records none, because an unattested key would make a signature look like evidence.
        # The scope carries no key and the Authority requires no signature, which is the
        # guarantee that freeze was measured under.
        scope = SessionScope(run_id, step, fragment_hash, state_hash, pk_boot,
                             b"" if version == BINDING_V50 else pk_sig)
        aad = bind_event(run_id, step, fragment_hash, state_hash)
        credential = mint_credential(scope)
        sess = Session(scope, tid, credential, seal_to(pk_boot, credential, aad=aad),
                       appraisal=self.appraisal_record(claims))
        if prior is not None:                         # an explicit continuation: keep both
            prior.state = SESSION_SUPERSEDED
            prior.superseded_by = tid.hex()
            self._history.append(prior)
        self._sessions[(run_id, step)] = sess
        return sess

    @staticmethod
    def _continuation_refused(prior: "Session", run_id: str, step: int, fragment_hash: str,
                              state_hash: str, continuation_pending) -> Optional[str]:
        """Decide whether a second session for (run, step) is an admissible continuation.

        A second session exists only as the continuation of a session that ended in
        REQUIRE_APPROVAL. The prior session redeemed no effect, the fragment and the state are
        the same, and the Authority holds the pending intervention for this fragment. Returns
        why the continuation is refused, or None to admit it.

        The gate does not validate the human approval. That stays in the frozen V3 grant path.
        While the intervention is pending, a party able to trigger repeated re-attestation can
        consume execution resources (fresh TDs that end in REQUIRE_APPROVAL again) but obtains
        no authority and causes no effect.
        """
        if prior.redeemed:
            return "prior session redeemed an effect"
        if continuation_pending is None or not continuation_pending(run_id, step, fragment_hash):
            return "no pending intervention for this fragment"
        if prior.scope.fragment_hash != fragment_hash:
            return "fragment differs from the pending one"
        if prior.scope.state_hash != state_hash:
            return "state differs from the pending one"
        return None

    # --- grant path ----------------------------------------------------------
    def redeem(self, credential: bytes, run_id: str, step: int, effect_id: str) -> "Grant | Refusal":
        """Redeem a credential at the grant path (attack A17), idempotent per logical effect.

        A credential is valid only for the (run, step) it was minted for and authorises one
        logical effect, named by `effect_id` (the gateway's idempotency key, derived from the
        credential itself so a runner cannot mint two):

            first redemption with effect_id X            -> Grant, credential bound to X
            retry: same credential, same effect_id X     -> the same Grant (a lost reply on the
                                                            gateway-to-Authority hop is not a
                                                            second effect)
            same credential, different effect_id Y       -> credential-already-redeemed

        Args:
            credential: the credential the runner presents.
            run_id: the run.
            step: the step.
            effect_id: the gateway's idempotency key for the effect.

        Returns:
            The Grant, or the Refusal.
        """
        sess = self._sessions.get((run_id, step))
        if sess is None:
            return self._refuse("no-session-for-step")
        if not secrets.compare_digest(sess.credential, credential):
            return self._refuse("credential-out-of-scope")
        if sess.effect_id is not None and sess.effect_id != effect_id:
            return self._refuse("credential-already-redeemed", f"bound to effect {sess.effect_id[:16]}…")
        sess.effect_id = effect_id
        sc = sess.scope
        return Grant(sc.run_id, sc.step, sc.fragment_hash, sc.state_hash,
                     hashlib.sha256(credential).hexdigest(), effect_id)

    def session_for(self, run_id: str, step: int) -> Optional[Session]:
        """Return the active session of (run, step) for the controller. It carries no authorisation."""
        return self._sessions.get((run_id, step))

    # --- checks ---------------------------------------------------------------
    def _check_reference(self, claims: VerifiedClaims) -> Optional[Refusal]:
        """Check the reference values (a). Every mismatch has its own name so the corpus can cite it."""
        if claims.platform != self.reference.platform:
            return self._refuse("platform-mismatch", f"{claims.platform} != {self.reference.platform}")
        # A debug-enabled TD (TDATTRIBUTES.DEBUG, bit 0) is refused before the pins are
        # consulted, because a freeze taken from a debug TD would otherwise pin the debug bit.
        if tdattributes_debug(claims.boot_measurements.get("tdattributes")):
            return self._refuse("debug-td", "TDATTRIBUTES.DEBUG is set")
        if claims.measurement != self.reference.measurement:
            return self._refuse("measurement-mismatch")
        for name, want in self.reference.boot_measurements.items():
            got = claims.boot_measurements.get(name)
            if got != want:
                # Measurements are public: naming both values lets a live refusal be diagnosed
                # (substrate drift versus a wrong reference) without a second boot.
                return self._refuse("boot-measurement-mismatch",
                                    f"{name} got={_hex(got)} want={_hex(want)}")
        # MRCONFIGID carries the init-data hash only where the platform fills it. On GCE it
        # is zero and RTMR3 carries it instead (checked below).
        if claims.init_data_hash is not None and \
                not claims.init_data_hash.startswith(self.reference.init_data_digest):
            return self._refuse("init-data-mismatch")
        return None

    def _check_rtmr3(self, claims: VerifiedClaims, pk_boot: bytes, pk_sig: bytes, run_id: str,
                     step: int, fragment_hash: str, state_hash: str) -> Optional[Refusal]:
        """Check invariant (c): RTMR3 must be the replay of the expected history.

        This is also what proves the init-data on GCE: the first expected event is the
        init-data digest, so a TD booted with a permissive policy cannot reach this value.
        """
        if claims.rtmr3 is None:
            return self._refuse("rtmr3-missing") if self.reference.require_rtmr3 else None
        version = self.reference.binding_version
        want = expected_rtmr3(self.reference.init_data_digest, pk_boot.hex(), pk_sig.hex(),
                              run_id, step, fragment_hash, state_hash, version)
        if not secrets.compare_digest(claims.rtmr3, want):
            return self._refuse("rtmr3-mismatch", diagnose_rtmr3(
                claims.rtmr3.hex(), self.reference.init_data_digest, pk_boot.hex(), pk_sig.hex(),
                run_id, step, fragment_hash, state_hash, version))
        return None

    def appraisal_record(self, claims: VerifiedClaims) -> dict:
        """Return who appraised the evidence and what it said.

        `verifier` is the class name of the configured verifier (`TdxVerifier` for DCAP,
        `FakeVerifier` for the offline model), `qv_result` the appraiser's verdict. It is
        recorded on every Session so a run record names, by itself, which verifier stood behind
        a measured run. It is the service's own report, not evidence. What proves the verifier
        is the service binary accepting `dcap` only, plus the image digest in the run manifest.
        """
        appraisal = claims.appraisal if isinstance(claims.appraisal, dict) else {}
        # The binding version belongs in the run record: without it a reader cannot tell a
        # session whose verdicts are verified from one whose are not.
        supp = appraisal.get("supplemental") if isinstance(appraisal.get("supplemental"), dict) else {}
        # The QVL's supplemental data is for the record only. The decision stays qv_result.
        return {"verifier": type(self.verifier).__name__,
                "binding_version": self.reference.binding_version,
                "verdicts_attested": self.reference.binding_version != BINDING_V50.decode(),
                "qv_result": appraisal.get("qv_result"),
                "fmspc": appraisal.get("fmspc"),
                "advisory_ids": list(supp.get("advisory_ids") or []),
                "tcb_level_date_tag": supp.get("tcb_level_date_tag"),
                "tcb_eval_ref_num": supp.get("tcb_eval_ref_num"),
                "collateral_earliest_expiration": supp.get("earliest_expiration_date")}

    def _refuse(self, rule: str, detail: str = "", stage: str = "relying-party") -> Refusal:
        r = Refusal(rule, detail, stage)
        self.refusals.append(r)
        return r


# --- verifiers for the offline model ------------------------------------------

@dataclass
class FakeVerifier:
    """Offline verifier for `FakeAttestationAgent` blobs.

    It returns the same claim shape as TdxVerifier, so every relying-party branch is exercised
    without hardware.
    """

    def verify(self, evidence: Evidence) -> VerifiedClaims:
        """Parse the fake blob and check that its runtime_data matches the request."""
        try:
            d = json.loads(evidence.blob)
        except Exception as exc:                                # noqa: BLE001 (any parse error refuses)
            raise VerificationFailed(f"unparseable evidence: {exc}") from exc
        if bytes.fromhex(d["runtime_data"]) != evidence.runtime_data:
            raise VerificationFailed("REPORTDATA does not carry the requested runtime_data")
        return VerifiedClaims(platform=d["platform"], measurement=d["measurement"],
                              runtime_data=evidence.runtime_data,
                              rtmr3=bytes.fromhex(d["rtmr3"]) if d.get("rtmr3") else None,
                              boot_measurements=d.get("boot_measurements", {}),
                              init_data_hash=d.get("init_data_hash"),
                              appraisal={"qv_result": "FAKE"})


@dataclass
class TrusteeVerifier:
    """Unwired stub for the Trustee Attestation Service, which would return JWT claims.

    V5 verifies locally, so the Authority holds the reference values itself.
    """

    base_url: str
    jwks_url: Optional[str] = None

    def verify(self, evidence: Evidence) -> VerifiedClaims:
        """Raise VerificationFailed, because this verifier is not wired."""
        raise VerificationFailed("TrusteeVerifier not wired (V5 appraises locally, see verifier.py)")


def _hex(value) -> str:
    """Return the hex of a measurement for refusal details. `None` becomes "absent", strings pass through."""
    if value is None:
        return "absent"
    return value.hex() if isinstance(value, (bytes, bytearray)) else str(value)
