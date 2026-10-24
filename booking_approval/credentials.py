"""The pinned approver credentials: public keys only, one entry per approver.

A credential file is written by `enroll` and handed to the Authority at deployment. It holds
no secret. On its first start the gate pins the file's digest into its own store, and a later
start with a different file is refused unless the operator re-pins explicitly. A credential
set that changed silently between two restarts would otherwise change who may approve.

Two kinds exist and every decision records which one answered:

    passkey   a WebAuthn credential of a person, user verification required (Touch ID)
    harness   a software key for unattended evaluation runs. It proves nothing about
              a person and is pinned only into deployments that run such an evaluation.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
from dataclasses import dataclass
from typing import Iterable

# Shared with the signed approval, so both use one definition of the kinds.
from booking_v1.approval import HARNESS_PREFIX, KINDS, kind_fits
from booking_v1.freeze import canonical_bytes

from .webauthn import SUPPORTED_ALGORITHMS, WebAuthnRefused, b64url_decode, load_public_key


FILE_VERSION = "approver-credentials-1"


class CredentialPinMismatch(Exception):
    """The credential file differs from the set this Authority pinned on its first start."""


@dataclass(frozen=True)
class ApproverCredential:
    """One enrolled approver key.

    Attributes:
        approver_id: Who answers with this key (recorded in every approval it signs).
        kind: "passkey" or "harness".
        credential_id: The WebAuthn credential id, base64url.
        public_key: The SPKI DER public key, base64url.
        algorithm: The COSE algorithm (-7 ES256 or -8 EdDSA).
    """

    approver_id: str
    kind: str
    credential_id: str
    public_key: str
    algorithm: int

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown credential kind {self.kind!r}")
        if not self.approver_id or not isinstance(self.approver_id, str):
            raise ValueError("approver_id must be a non-empty string")
        # The signed approval carries the kind, and the kind must fit the id. A harness key,
        # which has no person behind it, is always `harness:...` and a passkey is not.
        if not kind_fits(self.kind, self.approver_id):
            raise ValueError(f"approver_id {self.approver_id!r} does not match kind {self.kind!r}: "
                             f"harness keys are {HARNESS_PREFIX!r}-prefixed and passkeys are not")
        if self.algorithm not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"unsupported algorithm {self.algorithm}")
        try:
            b64url_decode(self.credential_id)
            load_public_key(b64url_decode(self.public_key), self.algorithm)
        except WebAuthnRefused as exc:
            raise ValueError(f"credential {self.approver_id!r}: {exc}") from None

    @property
    def requires_uv(self) -> bool:
        """Whether a person must verify (biometric or PIN). The harness key has no person behind it."""
        return self.kind == "passkey"

    def as_dict(self) -> dict:
        """Return the credential as a plain mapping, the form stored in the credential file."""
        return {"approver_id": self.approver_id, "kind": self.kind, "credential_id": self.credential_id,
                "public_key": self.public_key, "algorithm": self.algorithm}


@dataclass(frozen=True)
class CredentialSet:
    """The approvers one deployment accepts."""

    credentials: tuple[ApproverCredential, ...]

    def __post_init__(self) -> None:
        ids = [c.credential_id for c in self.credentials]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate credential id in the credential set")

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "CredentialSet":
        """Read a credential file written by `enroll`."""
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        if data.get("version") != FILE_VERSION:
            raise ValueError(f"{path}: not an approver credential file ({data.get('version')!r})")
        return cls(tuple(ApproverCredential(**c) for c in data.get("credentials", [])))

    def save(self, path: str | pathlib.Path) -> None:
        """Write the set (public keys only, safe to commit)."""
        pathlib.Path(path).write_text(json.dumps(
            {"version": FILE_VERSION, "credentials": [c.as_dict() for c in self.credentials]},
            indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def with_credential(self, credential: ApproverCredential) -> "CredentialSet":
        """Return a new set with one credential added (an approver id may hold several keys)."""
        return CredentialSet(self.credentials + (credential,))

    def by_id(self, credential_id: str) -> ApproverCredential | None:
        """Return the credential with this id, or None."""
        return next((c for c in self.credentials if c.credential_id == credential_id), None)

    def of_kinds(self, kinds: Iterable[str]) -> "CredentialSet":
        """Return the subset whose kind is one of `kinds`."""
        wanted = set(kinds)
        return CredentialSet(tuple(c for c in self.credentials if c.kind in wanted))

    def digest(self) -> str:
        """Return the SHA-256 over the canonical set, independent of the order."""
        return hashlib.sha256(canonical_bytes(sorted(
            (c.as_dict() for c in self.credentials), key=lambda c: c["credential_id"]))).hexdigest()

    def summary(self) -> list[dict]:
        """Return who may approve, without key material (for run records)."""
        return [{"approver_id": c.approver_id, "kind": c.kind} for c in self.credentials]


def pin(store, credentials: CredentialSet, *, repin: bool = False) -> str:
    """Pin the credential set into the gate's store, or check it against the pinned one.

    Args:
        store: The gate's `ApprovalStore`.
        credentials: The set this process was started with.
        repin: Replace a different pinned set (an explicit operator decision).

    Returns:
        The pinned digest.

    Raises:
        CredentialPinMismatch: when the set is empty, or differs from the pinned one and
            `repin` is False.
    """
    if not credentials.credentials:
        raise CredentialPinMismatch("no approver credential: nobody could approve (fail-closed)")
    digest = credentials.digest()
    pinned = store.get_setting("credentials_digest")
    if pinned is not None and pinned != digest and not repin:
        raise CredentialPinMismatch(
            f"approver credentials changed since they were pinned ({pinned[:12]} -> {digest[:12]}). "
            f"Start with --repin to accept the new set")
    if pinned is not None and pinned != digest:
        # `--repin` replaces the keys the gate trusts. The replacement stays visible afterwards,
        # digest to digest, in the gate's own store.
        try:
            trace = json.loads(store.get_setting("credentials_repin_log") or "[]")
        except json.JSONDecodeError:
            trace = []
        trace.append({"from": pinned, "to": digest})
        store.put_setting("credentials_repin_log", json.dumps(trace, sort_keys=True))
    store.put_setting("credentials_digest", digest)
    return digest
