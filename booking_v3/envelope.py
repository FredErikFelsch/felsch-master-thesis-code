"""StateEnvelope: the entire inter-fragment state, signed by the Authority.

Nothing survives an ephemeral runner except this envelope (and the events the
Authority archives). The envelope carries the run binding, the next authorised
step, the canonical fact store with full provenance, the audit chain head
and the predecessor's state hash. Its state_hash covers all of that
canonically, and the Authority's Ed25519 signature over the state_hash makes
the envelope self-authenticating: a runner verifies with the public key alone,
holds no secret, and gains no ability to mint envelopes.

The signature shows who authorised this state. Freshness, that this is the
latest state, is not an envelope property. The Authority's ledger establishes
it inside the pre-effect execution grant (see authority.py).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from booking_v1.freeze import canonical_bytes, thaw, to_canonical
from booking_v2.facts import FactStore, ObservedFact


class EnvelopeInvalid(Exception):
    """Raised when an envelope is structurally invalid at construction."""


# Ed25519 key wrappers.

class SigningKey:
    """An Ed25519 private key (Authority-side only)."""

    def __init__(self) -> None:
        """Generate a fresh key."""
        self._sk = Ed25519PrivateKey.generate()

    def sign(self, data: bytes) -> str:
        """Return the hex signature over ``data``."""
        return self._sk.sign(data).hex()

    def verify_key(self) -> "VerifyKey":
        """Return the matching public verification key."""
        return VerifyKey(self._sk.public_key())

    # Serialisation helpers: a durable Authority must persist its signing key
    # across restarts.
    def to_bytes(self) -> bytes:
        """Return the raw 32-byte private key (Authority-side persistence only)."""
        return self._sk.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())

    @classmethod
    def from_bytes(cls, raw: bytes) -> "SigningKey":
        """Rebuild a signing key from its raw 32 bytes."""
        key = cls.__new__(cls)
        key._sk = Ed25519PrivateKey.from_private_bytes(raw)
        return key


class VerifyKey:
    """An Ed25519 public key. Holding it allows verification but not signing."""

    def __init__(self, pk) -> None:
        """Wrap a cryptography Ed25519PublicKey."""
        self._pk = pk

    def verify(self, signature_hex: str, data: bytes) -> bool:
        """Return whether ``signature_hex`` is a valid signature over ``data``.

        Args:
            signature_hex: The signature as hex.
            data: The signed bytes.

        Returns:
            True if the signature verifies. Malformed input returns False.
        """
        try:
            self._pk.verify(bytes.fromhex(signature_hex), data)
            return True
        except Exception:
            return False

    # Serialisation helpers: a public key crosses the process boundary as raw
    # bytes, not as a Python object.
    def to_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        return self._pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @classmethod
    def from_bytes(cls, raw: bytes) -> "VerifyKey":
        """Rebuild a verification key from its raw 32 bytes."""
        return cls(Ed25519PublicKey.from_public_bytes(raw))


@dataclass(frozen=True)
class TrustAnchors:
    """The public keys a runner is provisioned with (baked into its image)."""

    envelope_key: VerifyKey
    intervention_key: VerifyKey


# Audit chain.

def chain_extend(head: str, payloads: Iterable[Mapping[str, Any]]) -> str:
    """Extend an audit chain head over canonical event payloads, in the booking_v1 chain style.

    Args:
        head: The current head.
        payloads: The canonical event payloads, in order.

    Returns:
        The new head.
    """
    for payload in payloads:
        head = hashlib.sha256(head.encode() + canonical_bytes(payload)).hexdigest()
    return head


# Fact serialisation.

def serialize_facts(store: FactStore) -> dict[str, Any]:
    """Serialise a FactStore into the canonical envelope representation.

    Every field of every ObservedFact is kept, so provenance survives the
    handoff. Set values thaw to sorted lists. The ftype tag restores them.
    """
    out: dict[str, Any] = {}
    for name in store.names():
        fact = store.get(name)
        out[name] = {
            "value": thaw(fact.value),
            "ftype": fact.ftype,
            "source_tool": fact.source_tool,
            "producing_seq": fact.producing_seq,
            "run_id": fact.run_id,
            "fragment_id": fact.fragment_id,
            "timestamp": fact.timestamp,
            "integrity": fact.integrity,
        }
    return out


def deserialize_facts(run_id: str, facts: Mapping[str, Any]) -> FactStore:
    """Rebuild a FactStore from canonical envelope facts, type-checked, fail-closed.

    Every value passes through ObservedFact's construction gate again (freeze
    plus ftype check), so a record that does not round-trip raises rather than
    entering the store. A fact of another run raises via the store's own guard.

    Args:
        run_id: The run the store belongs to.
        facts: The envelope's serialised facts.

    Returns:
        The rebuilt FactStore.
    """
    store = FactStore(run_id)
    for name in sorted(facts):
        rec = facts[name]
        value = rec["value"]
        if rec["ftype"] == "set":
            value = frozenset(value)
        store.put(ObservedFact(
            name=name, value=value, ftype=rec["ftype"], source_tool=rec["source_tool"],
            producing_seq=rec["producing_seq"], run_id=rec["run_id"],
            fragment_id=rec["fragment_id"], timestamp=rec["timestamp"], integrity=rec["integrity"]))
    return store


# The envelope.

def body_hash(body: Mapping[str, Any]) -> str:
    """Return the SHA-256 state hash over a canonical envelope body."""
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


@dataclass(frozen=True)
class StateEnvelope:
    """The signed inter-fragment state S_i.

    ``signature`` is empty while an envelope is a runner's unsigned proposal
    on its way to the Authority. Every envelope a runner accepts as
    input must carry a verifying signature.
    """

    run_id: str
    policy_digest: str
    approval_id: str
    step_index: int
    facts: Mapping[str, Any]
    audit_head: str
    previous_state_hash: str
    state_hash: str = field(default="")
    signature: str = field(default="")

    def __post_init__(self) -> None:
        """Validate the fields, canonicalise the facts and compute ``state_hash``."""
        for name in ("run_id", "policy_digest", "approval_id", "audit_head", "previous_state_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise EnvelopeInvalid(f"{name} must be a non-empty string")
        if isinstance(self.step_index, bool) or not isinstance(self.step_index, int) or self.step_index < 0:
            raise EnvelopeInvalid("step_index must be a non-negative integer")
        try:
            facts = to_canonical(dict(self.facts))
        except Exception as exc:
            raise EnvelopeInvalid(f"non-canonical facts: {exc}")
        object.__setattr__(self, "facts", facts)
        computed = body_hash(self.body())
        if self.state_hash and self.state_hash != computed:
            # A caller may pass a claimed hash (for example a deserialised one). It must match.
            raise EnvelopeInvalid("state_hash does not match the body")
        object.__setattr__(self, "state_hash", computed)

    def body(self) -> dict:
        """Return the canonical content the state_hash covers."""
        return {
            "kind": "state-envelope",
            "run_id": self.run_id,
            "policy_digest": self.policy_digest,
            "approval_id": self.approval_id,
            "step_index": self.step_index,
            "facts": thaw(self.facts),
            "audit_head": self.audit_head,
            "previous_state_hash": self.previous_state_hash,
        }

    def with_signature(self, signature: str) -> "StateEnvelope":
        """Return a copy carrying the Authority's signature."""
        return StateEnvelope(
            run_id=self.run_id, policy_digest=self.policy_digest, approval_id=self.approval_id,
            step_index=self.step_index, facts=self.facts, audit_head=self.audit_head,
            previous_state_hash=self.previous_state_hash, state_hash=self.state_hash,
            signature=signature)


def verify_envelope(envelope: StateEnvelope, envelope_key: VerifyKey) -> tuple[bool, str]:
    """Verify an envelope's hash integrity and Authority signature, fail-closed.

    Args:
        envelope: The envelope to verify.
        envelope_key: The Authority's envelope verification key.

    Returns:
        A pair (ok, reason).
    """
    try:
        computed = body_hash(envelope.body())
    except Exception:
        return False, "envelope body does not canonicalise"
    if computed != envelope.state_hash:
        return False, "state hash does not match the body"
    if not envelope.signature:
        return False, "envelope is unsigned"
    if not envelope_key.verify(envelope.signature, envelope.state_hash.encode()):
        return False, "envelope signature does not verify"
    return True, "envelope verified"


def genesis_previous_hash(run_id: str, policy_digest: str, approval_binding_digest: str) -> str:
    """Return the genesis constant that S0.previous_state_hash is set to.

    Args:
        run_id: The run.
        policy_digest: The approved policy digest.
        approval_binding_digest: The digest of the signed approval binding.

    Returns:
        The SHA-256 hex digest.
    """
    return hashlib.sha256(canonical_bytes({
        "kind": "genesis", "run_id": run_id, "policy_digest": policy_digest,
        "approval_binding_digest": approval_binding_digest,
    })).hexdigest()


def genesis_audit_head(run_id: str, policy_digest: str, approval_id: str) -> str:
    """Return the audit chain genesis for a run.

    Args:
        run_id: The run.
        policy_digest: The approved policy digest.
        approval_id: The approval id.

    Returns:
        The SHA-256 hex digest.
    """
    return hashlib.sha256(canonical_bytes({
        "kind": "audit-genesis", "run_id": run_id, "policy_digest": policy_digest,
        "approval_id": approval_id,
    })).hexdigest()
