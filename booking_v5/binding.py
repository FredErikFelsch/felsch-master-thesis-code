"""Binding of one TD: one seed, two key pairs, at most one fragment.

Lifecycle inside the TD:

    boot  -> RunnerIdentity.create()      one seed generated in the TD. From it the X25519
                                          sealing key and the Ed25519 verdict key. td_id = H(pk_boot)
          -> [RTMR3 <- AAEL "v5 boot-key <pk_boot>.<pk_sig>"]         (strengthened invariant)
    bind  -> identity.bind(run_id, step, fragment_hash, state_hash) frozen onto the boot key
          -> [RTMR3 <- AAEL "v5 bind <run>/<step>/<f>/<s>"]           (strengthened invariant)
    exec  -> binding.verify_bytes(fragment_bytes, envelope_bytes)     the attested hashes must
                                                                      match the bytes actually fed
          -> identity.signer signs every verdict the TD reports       (booking_v3.runner_attestation)
    end   -> TD destroyed, both keys gone

Why two keys and not one. The sealing key is X25519, which cannot sign. The verdict key is
Ed25519, which cannot do key agreement. Both are derived from the same seed with distinct
HKDF info strings, so there is still one secret in the TD and one moment at which it comes
into existence, before any fragment is known. Both public halves are covered by the
canonical binding and by RTMR3, so a TD cannot announce a verdict key it did not measure.

Core invariant (enforced by the Authority ledger, hardware-independent):
    a boot key is bound to at most one (run_id, step, fragment_hash, state_hash).
Strengthened invariant (where the guest can extend RTMR3):
    that binding, and both public keys, are anchored in the TD's attested measurement history.

Only `cryptography` is used (already in the runner image).
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from booking_v3.envelope import SigningKey

from .rtmr_replay import OP_BIND, OP_BOOT_KEY, boot_key_content

#: v5.1 adds pk_sig to the canonical binding. A TD and an Authority on different versions
#: compute different runtime_data and the session is refused. There is no negotiation.
#:
#: v5.0 is kept only so that evidence recorded under the older binding can still be appraised
#: and replayed offline. A runner of this code always attests under PROTOCOL_VERSION, so an
#: Authority pinned to v5.0 refuses it with binding-mismatch. The older binding is reachable
#: only through an older runner image, and that image is pinned through the init-data digest
#: (the first RTMR3 event), not through MRTD or RTMR0..2.
BINDING_V50 = b"v5.0"
BINDING_V51 = b"v5.1"
PROTOCOL_VERSION = BINDING_V51
SEAL_INFO = b"v5-session-credential"
SEAL_KEY_INFO = b"v5-td-seal-key"
SIGN_KEY_INFO = b"v5-td-verdict-key"


def _h(*parts: bytes) -> bytes:
    """Length-prefixed SHA-256 over the parts (no ambiguity between fields)."""
    h = hashlib.sha256()
    for p in parts:
        h.update(len(p).to_bytes(2, "big"))
        h.update(p)
    return h.digest()


def _derive(seed: bytes, info: bytes) -> bytes:
    """One 32-byte private key from the TD's single seed. Distinct `info` per purpose, so
    the sealing key and the verdict key are independent even though one seed produces both."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(seed)


def td_identity(pk_boot: bytes) -> bytes:
    """Logical identity of one TD instance for its whole lifetime: H(pk_boot)."""
    return _h(b"v5-td-id", pk_boot)


def boot_key_event(pk_boot: bytes) -> bytes:
    """Domain-separated digest of the boot key.

    This is not the RTMR3 encoding (that is an AAEL line, see rtmr_replay). It is used where a
    fixed-length label is needed.
    """
    return _h(b"boot-key", pk_boot)


def bind_event(run_id: str, step: int, fragment_hash: str, state_hash: str) -> bytes:
    """Digest of the single binding.

    It is the AAD of the sealed session credential, so a box sealed for one binding cannot be
    opened for another even inside the same TD.
    """
    return _h(b"fragment-bind", run_id.encode(), str(step).encode(), fragment_hash.encode(), state_hash.encode())


def canonical_binding(nonce: bytes, run_id: str, step: int, fragment_hash: str, state_hash: str,
                      pk_boot: bytes, pk_sig: bytes,
                      version: bytes = PROTOCOL_VERSION) -> bytes:
    """Return the canonical binding that a TD requests evidence over.

    The value is SHA-256 over the length-prefixed parts "V5-BIND", version, nonce, run_id,
    step, fragment_hash, state_hash, pk_boot and, from v5.1 on, pk_sig (see `_h`). It is
    requested as runtime_data (REPORTDATA) and recomputed by the Authority for condition (b).
    `pk_sig` is included because the Authority later verifies this TD's signed verdicts
    against it. An attacker could substitute a key that is not attested, and the signature
    would then prove nothing about the measured code.

    Args:
        nonce: the Authority's challenge nonce.
        run_id: the run the TD is bound to.
        step: the step within the run.
        fragment_hash: V3 identifier of the fragment.
        state_hash: V3 identifier of the state envelope.
        pk_boot: the TD's public sealing key.
        pk_sig: the TD's public verdict key, ignored under v5.0.
        version: the binding version, `PROTOCOL_VERSION` unless archived evidence is replayed.

    Returns:
        The 32-byte digest.
    """
    parts = [b"V5-BIND", version, nonce, run_id.encode(), str(step).encode(),
             fragment_hash.encode(), state_hash.encode(), pk_boot]
    if version != BINDING_V50:
        parts.append(pk_sig)
    return _h(*parts)


@dataclass(frozen=True)
class RunnerKeys:
    """The two public keys one TD announces.

    `pk_boot` is the key its session credential is sealed to, `pk_sig` the key it signs its
    verdicts with. They travel and are measured together, so no call site can carry one
    without the other.
    """

    pk_boot: bytes
    pk_sig: bytes


@dataclass(frozen=True)
class Binding:
    """The one (run, step, fragment, state) tuple a TD is bound to."""

    run_id: str
    step: int
    fragment_hash: str
    state_hash: str

    def verify_bytes(self, fragment_bytes: bytes, envelope_bytes: bytes,
                     hashes: Optional[Callable[[bytes, bytes], tuple[str, str]]] = None) -> None:
        """Check that the octets offered for execution are the attested objects.

        Called inside the TD immediately before execution. Whoever transports the bytes
        (controller, kubelet, attach stream) cannot substitute fragment B for attested
        fragment A, because the hashes would not match.

        Args:
            fragment_bytes: the fragment octets from the execution line.
            envelope_bytes: the envelope octets from the execution line.
            hashes: derives the identifiers the binding names from the octets. The runner
                passes `protocol.hashes_of_octets` (V3 identifiers over canonical octets).
                The default is the plain SHA-256 of the octets, used by the model tests.

        Raises:
            BytesMismatch: the octets cannot be decoded, or their identifiers differ from
                the bound ones.
        """
        try:
            f, s = hashes(fragment_bytes, envelope_bytes) if hashes else (
                hashlib.sha256(fragment_bytes).hexdigest(), hashlib.sha256(envelope_bytes).hexdigest())
        except Exception as exc:                                # noqa: BLE001 (the octets may be neither canonical nor parseable)
            raise BytesMismatch(f"octets are not the attested objects: {exc}") from exc
        if f != self.fragment_hash:
            raise BytesMismatch("fragment bytes do not match the attested fragment_hash")
        if s != self.state_hash:
            raise BytesMismatch("envelope bytes do not match the attested state_hash")


class BytesMismatch(Exception):
    """The bytes offered for execution are not the ones that were attested."""


@dataclass
class RunnerIdentity:
    """The TD's seed, from which both keys are derived, and its binding.

    The seed is created in the TD and is not exported by any method of this class.
    """

    _seed: bytes
    binding: Optional[Binding] = None
    _rtmr_extend: Optional[Callable[[str, str], None]] = None

    @classmethod
    def create(cls, rtmr_extend: Optional[Callable[[str, str], None]] = None) -> "RunnerIdentity":
        """Boot: derive both keys from a fresh seed and record them in RTMR3 if possible.

        `rtmr_extend` takes one AAEL event as (operation, content). This is the shape the
        Attestation Agent's `POST /aa/aael` takes and the Authority replays
        (`rtmr_replay.expected_history`). Fake and live share one encoding, so the offline
        tests exercise the measurement maths that runs on the hardware.
        """
        ident = cls(os.urandom(32), None, rtmr_extend)
        if rtmr_extend is not None:
            rtmr_extend(OP_BOOT_KEY, boot_key_content(ident.pk_boot.hex(), ident.pk_sig.hex()))
        return ident

    @classmethod
    def from_seed(cls, seed: bytes, rtmr_extend: Optional[Callable[[str, str], None]] = None) -> "RunnerIdentity":
        """Build a TD identity from a fixed seed, for tests and offline models.

        The production path takes a fresh seed from the guest's own entropy in `create`.

        Raises:
            ValueError: the seed is not 32 bytes.
        """
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        return cls(bytes(seed), None, rtmr_extend)

    # --- keys ---------------------------------------------------------------
    @property
    def _priv(self) -> X25519PrivateKey:
        return X25519PrivateKey.from_private_bytes(_derive(self._seed, SEAL_KEY_INFO))

    @property
    def signer(self) -> SigningKey:
        """The Ed25519 key this TD signs its own verdicts with (booking_v3.runner_attestation)."""
        return SigningKey.from_bytes(_derive(self._seed, SIGN_KEY_INFO))

    @property
    def pk_boot(self) -> bytes:
        """Public X25519 half of the sealing key."""
        return self._priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def pk_sig(self) -> bytes:
        """Public Ed25519 half of the verdict key."""
        return self.signer.verify_key().to_bytes()

    @property
    def td_id(self) -> bytes:
        """Identity of this TD instance, H(pk_boot)."""
        return td_identity(self.pk_boot)

    # --- lifecycle ----------------------------------------------------------
    def bind(self, run_id: str, step: int, fragment_hash: str, state_hash: str) -> Binding:
        """Bind: freeze one binding onto the boot key and record it in RTMR3.

        A second bind is refused here and, independently, by the Authority ledger.

        Raises:
            AlreadyBound: the TD already carries a binding.
        """
        if self.binding is not None:
            raise AlreadyBound("this TD is already bound to a fragment")
        self.binding = Binding(run_id, step, fragment_hash, state_hash)
        if self._rtmr_extend is not None:
            self._rtmr_extend(OP_BIND, f"{run_id}/{step}/{fragment_hash}/{state_hash}")
        return self.binding

    def runtime_data(self, nonce: bytes, version: bytes = PROTOCOL_VERSION) -> bytes:
        """Attest: the canonical binding to request evidence over.

        `version` exists for the offline replay of archived evidence. `V5Runner.attest` calls
        this without it, so a live runner cannot be talked down to a binding that omits its
        verdict key.
        """
        b = self._require_bound()
        return canonical_binding(nonce, b.run_id, b.step, b.fragment_hash, b.state_hash,
                                 self.pk_boot, self.pk_sig, version)

    def open_sealed(self, box: dict) -> bytes:
        """Decrypt the session credential sealed to pk_boot (AAD = the bind event)."""
        b = self._require_bound()
        eph_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(box["eph_pub"]))
        key = _seal_key(self._priv.exchange(eph_pub), bytes.fromhex(box["eph_pub"]), self.pk_boot)
        aad = bind_event(b.run_id, b.step, b.fragment_hash, b.state_hash)
        return ChaCha20Poly1305(key).decrypt(bytes.fromhex(box["nonce"]), bytes.fromhex(box["ct"]), aad)

    def _require_bound(self) -> Binding:
        if self.binding is None:
            raise NotBound("TD is not bound to a fragment")
        return self.binding


class AlreadyBound(Exception):
    """A second bind was attempted on a TD that already carries a binding."""
    ...


class NotBound(Exception):
    """A bound-only operation was attempted before the TD was bound."""
    ...


def seal_to(pk_boot: bytes, plaintext: bytes, aad: bytes) -> dict:
    """Seal `plaintext` to a TD's boot key on the Authority side.

    The box uses X25519 ephemeral-static ECDH, HKDF-SHA256 and ChaCha20-Poly1305. `aad` is
    the bind event, so a box sealed for one binding cannot be opened for another even inside
    the same TD. Sealing gives confidentiality and binds the AAD, but does not authenticate
    the sender.

    Args:
        pk_boot: the TD's public sealing key.
        plaintext: the session package.
        aad: the bind event of the TD's binding.

    Returns:
        The box as hex fields `eph_pub`, `nonce` and `ct`.
    """
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _seal_key(eph.exchange(X25519PublicKey.from_public_bytes(pk_boot)), eph_pub, pk_boot)
    nonce = os.urandom(12)
    return {"eph_pub": eph_pub.hex(), "nonce": nonce.hex(),
            "ct": ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad).hex()}


def _seal_key(shared: bytes, eph_pub: bytes, pk_boot: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub + pk_boot, info=SEAL_INFO).derive(shared)
