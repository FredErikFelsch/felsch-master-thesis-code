"""Runner: the sequence that runs inside the confidential VM, in order, once.

    boot     derive the sealing and verdict keys, record "v5 boot-key <pk_boot>.<pk_sig>"
             into RTMR3
    bind     freeze the single binding, record "v5 bind <run>/<step>/<f>/<s>" into RTMR3
    attest   ask the Attestation Agent for evidence over the canonical binding
    open     decrypt the session credential sealed to the boot key
    execute  check the bytes offered against the attested hashes, then run

The runner does not rely on its caller for these checks. The controller transports bytes and
messages. It cannot make the runner attest to a fragment it was not bound to (`bind` happens
once), read the credential (sealed to a key that stays in the TD), or swap the fragment after
attestation (`Binding.verify_bytes`).

A phase guard in the runner, and not only the Authority, enforces the order. No fragment
effect can run before the evidence has been appraised and the session opened.

    boot -> bind -> attest -> open -> execute, each phase once, in this order.
    `open_session` refuses before `attest`, `execute` refuses before `open_session`,
    `attest` refuses a second time. The credential exists only after the Authority has
    appraised the evidence, so a successful open shows on the runner side that the
    appraisal happened.

Two constraints of the Attestation Agent are enforced here:
  * runtime_data is copied unchanged into REPORTDATA, which is 64 bytes, so the request
    carries the 64-character hex of a 32-byte value.
  * the Attestation Agent answers HTTP 200 with `"success":"false"` when it refuses an
    event, so `extend` decides on the parsed body and not on the status code alone.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from .binding import Binding, RunnerIdentity, RunnerKeys
from .evidence import Evidence
from .rtmr_replay import DOMAIN

AA_BASE_URL = "http://127.0.0.1:8006"


class RunnerError(Exception):
    """The runner refuses to continue, and nothing is executed after this error."""


def _aa_reported_success(answer: bytes) -> bool:
    """Whether the AA's reply is a JSON object whose top-level `success` is "true" (or true).

    The reply is parsed as JSON, because a substring test would accept
    `{"success":"false","details":{"success":"true"}}` and any reply that merely contains the
    text.
    """
    try:
        data = json.loads(answer)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(data, dict) and data.get("success") in ("true", True)


@dataclass
class AttestationAgent:
    """The CoCo Attestation Agent REST API inside the guest (loopback, unprivileged).

    `POST /aa/aael` records one AAEL event into RTMR3 (needs `enable_eventlog = true`
    in aa.toml). `GET /aa/evidence` returns the quote with the requested runtime_data in REPORTDATA.
    """

    base_url: str = AA_BASE_URL
    timeout: float = 20.0
    domain: str = DOMAIN

    def extend(self, operation: str, content: str) -> None:
        """Record one event. Raises RunnerError unless the AA reports success."""
        body = json.dumps({"domain": self.domain, "operation": operation, "content": content}).encode()
        req = urllib.request.Request(f"{self.base_url}/aa/aael", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:   # noqa: S310 (loopback)
                answer = resp.read()
        except urllib.error.URLError as exc:
            raise RunnerError(f"attestation agent unreachable for {operation}: {exc}") from exc
        if not _aa_reported_success(answer):
            raise RunnerError(f"attestation agent refused the {operation} event: {answer[:200]!r}")

    def evidence(self, runtime_data_32: bytes) -> Evidence:
        """Fetch evidence bound to `runtime_data_32` (sent as 64 hex characters).

        The reply is only checked to mention a quote. The Authority's verifier parses it.

        Raises:
            RunnerError: the value is not 32 bytes, the agent is unreachable or answers with
                a non-2xx status, or the reply holds no quote.
        """
        if len(runtime_data_32) != 32:
            raise RunnerError("runtime_data must be 32 bytes: REPORTDATA holds 64 ASCII characters")
        url = f"{self.base_url}/aa/evidence?runtime_data={runtime_data_32.hex()}"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:   # noqa: S310 (loopback)
                blob = resp.read()
        except urllib.error.URLError as exc:
            raise RunnerError(f"attestation agent unreachable for evidence: {exc}") from exc
        if not blob or b'"quote"' not in blob:
            raise RunnerError(f"attestation agent returned no quote: {blob[:200]!r}")
        return Evidence("tdx", blob, runtime_data_32)


@dataclass(frozen=True)
class Challenge:
    """The challenge the controller relays from the Authority. It carries no authority of its own."""

    run_id: str
    step: int
    fragment_hash: str
    state_hash: str
    nonce: bytes


@dataclass
class V5Runner:
    """The runner of one TD, with one boot key, for one fragment.

    Create one instance per pod VM. The phase guard refuses a second pass through any phase.
    """

    aa: AttestationAgent
    identity: RunnerIdentity = None                 # set by boot()
    _credential: Optional[bytes] = field(default=None, repr=False)
    # created -> booted -> attested -> opened -> executed, or failed when the credential does not open
    _phase: str = field(default="created", repr=False)
    #: How the attested identifiers are derived from octets. The production runner uses
    #: V3's identifiers over canonical octets. The phase-order model tests use a plain digest.
    hashes: object = field(default=None, repr=False)

    def _advance(self, expect: str, to: str) -> None:
        """Phase guard: allow each phase once and only from its predecessor."""
        if self._phase != expect:
            raise RunnerError(f"phase '{to}' refused in phase '{self._phase}' (expected '{expect}')")
        self._phase = to

    @classmethod
    def boot(cls, aa: Optional[AttestationAgent] = None, hashes: object = "v3") -> "V5Runner":
        """Boot: generate the keys in the TD and measure them into RTMR3 at once.

        Args:
            aa: the Attestation Agent client, the loopback default when None.
            hashes: "v3" in production, which derives V3's identifiers from canonical
                octets (`protocol.hashes_of_octets`). None uses the plain digest of the
                octets (model tests).

        Returns:
            The booted runner.
        """
        aa = aa or AttestationAgent()
        runner = cls(aa)
        runner.identity = RunnerIdentity.create(rtmr_extend=aa.extend)
        runner._phase = "booted"
        if hashes == "v3":
            from . import protocol
            hashes = protocol.hashes_of_octets
        runner.hashes = hashes
        return runner

    @property
    def pk_boot(self) -> bytes:
        """Public sealing key of this TD."""
        return self.identity.pk_boot

    @property
    def pk_sig(self) -> bytes:
        """Public verdict key of this TD."""
        return self.identity.pk_sig

    @property
    def keys(self) -> RunnerKeys:
        """What the TD announces in v5-hello and what the Authority binds in the quote."""
        return RunnerKeys(self.identity.pk_boot, self.identity.pk_sig)

    @property
    def signer(self):
        """The key the V3 monitor signs its verdicts with (booking_v3.runner_attestation)."""
        return self.identity.signer

    def attest(self, challenge: Challenge) -> Evidence:
        """Bind and attest: bind once (measured), then get evidence over the canonical binding.

        Raises:
            RunnerError: the runner is not in the booted phase, or the agent fails.
        """
        self._advance("booted", "attested")
        self.identity.bind(challenge.run_id, challenge.step, challenge.fragment_hash, challenge.state_hash)
        return self.aa.evidence(self.identity.runtime_data(challenge.nonce))

    def open_session(self, sealed: dict) -> bytes:
        """Open: decrypt the session package, which only this TD can do for this binding.

        Returns:
            The decrypted package octets.

        Raises:
            RunnerError: the runner is not in the attested phase, or the box does not open.
        """
        self._advance("attested", "opened")
        try:
            self._credential = self.identity.open_sealed(sealed)
        except Exception as exc:                                # noqa: BLE001 (one refusal reason)
            self._phase = "failed"                              # no later phase is reachable from here
            raise RunnerError(f"sealed session credential does not open in this TD: {exc}") from exc
        return self._credential

    @property
    def binding(self) -> Binding:
        """The binding frozen onto this TD. Raises RunnerError before `attest`."""
        if self.identity is None or self.identity.binding is None:
            raise RunnerError("runner is not bound")
        return self.identity.binding

    def execute(self, fragment_bytes: bytes, envelope_bytes: bytes,
                run_fragment: Callable[[bytes, bytes, bytes], object]) -> object:
        """Execute: run the fragment once the octets match the attested hashes.

        Args:
            fragment_bytes: the fragment octets from the execution line.
            envelope_bytes: the envelope octets from the execution line.
            run_fragment: called as `run_fragment(fragment_bytes, envelope_bytes, package)`
                with the package this TD decrypted in `open_session`. It is reached only
                after the hash check.

        Returns:
            Whatever `run_fragment` returns.

        Raises:
            RunnerError: the runner is not in the opened phase.
            BytesMismatch: the octets are not the attested objects.
        """
        self._advance("opened", "executed")
        if self._credential is None:
            raise RunnerError("no session credential: nothing may be executed")
        self.binding.verify_bytes(fragment_bytes, envelope_bytes, hashes=self.hashes)   # raises BytesMismatch
        return run_fragment(fragment_bytes, envelope_bytes, self._credential)
