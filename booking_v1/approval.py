"""A signed approval, bound to the full approved artefact.

A hash of the policy data alone is not enough: it does not bind the constraint
semantics version, the tool contract, or the run it authorises, and a bare hash is
not an authenticity proof. The approval therefore binds a complete artefact and
signs it.

The signature here is an HMAC under a single trusted key. That is a stand-in for
real asymmetric signing by an approver's key. Authenticity in a real deployment
depends on protecting the approver's private key and on a verifier that is part
of the trusted computing base. Building that PKI is out of scope. The model
relies on the binding and on the points where it is verified.

The approved binding covers:
    policy_digest                 the policy content
    policy_schema_version         the policy structure
    constraint_registry_version   the constraint semantics
    tool_manifest_hash            the tool argument contracts
    approver_id, approval_id      who approved, and a unique approval identity
    approver_kind                 passkey or harness, must fit approver_id
    run_id                        the single run this approval authorises
    issued_at, expires_at         the validity window (epoch seconds)
    granted                       the human decision
"""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass

from .constraints import CONSTRAINT_REGISTRY_VERSION
from .freeze import canonical_bytes
from .policy import POLICY_SCHEMA_VERSION
from .schema import tool_manifest_hash

# Stand-in for the approver's signing key (HMAC). In a real system this is an asymmetric
# private key held by the approver, and the monitor holds only the public key.
#
# Who holds it, per version (a documented limit):
#   V1 to V3  the same process plays approver and monitor. The key is a constant here.
#   V4/V5     the constant ships in every image (services, runner, controller, harness),
#             so a runner or controller that could execute code of its own choosing could
#             mint an initial approval. That path is closed by the deployment, not by
#             cryptography. The runner image is measured (V5) or pinned by digest (V4).
#             NetworkPolicy and RBAC leave no principal other than the trusted init a way
#             to present a fabricated approval to the Authority. From V4 on, the
#             unforgeability of the initial approval rests on those boundaries. Replacing
#             the HMAC by an asymmetric key is future work (image, freeze and
#             re-measurement).
_TRUSTED_APPROVER_KEY = b"trusted-approver-key-v1-mock"


#: The kinds of key an approval can come from. A passkey has a person behind it, a harness
#: key (unattended evaluation) has none, and its approver id is always `harness:...`.
KINDS = ("passkey", "harness")
HARNESS_PREFIX = "harness:"


def kind_fits(kind: object, approver_id: object) -> bool:
    """Return whether `kind` is a known kind and agrees with the approver id's prefix.

    The check fails closed: a harness id is not accepted as a person's approval, and a
    person's id cannot carry the harness kind.

    Args:
        kind: The claimed kind of key.
        approver_id: The approver id the kind must fit.

    Returns:
        True if the kind is in KINDS and matches the id's prefix.
    """
    return (kind in KINDS and isinstance(approver_id, str)
            and (kind == "harness") == approver_id.startswith(HARNESS_PREFIX))


class ApprovalError(Exception):
    """Base class for approval verification failures."""


class ApprovalRejected(ApprovalError):
    """The human rejected the policy."""


class InvalidApprovalSignature(ApprovalError):
    """The approval signature does not verify."""


class ApprovalExpired(ApprovalError):
    """The approval is outside its validity window."""


class ApprovalVersionMismatch(ApprovalError):
    """The approval was issued for a different schema, registry or tool manifest."""


class ApproverKindMismatch(ApprovalError):
    """The approval's kind of key is unknown or does not fit its approver id."""


class RunMismatch(ApprovalError):
    """The approval authorises a different run than the one being activated."""


class PolicyDigestMismatch(ApprovalError):
    """The policy presented does not match the approved digest."""


@dataclass(frozen=True)
class Approval:
    """A signed approval binding a policy artefact to one run."""

    policy_digest: str
    policy_schema_version: str
    constraint_registry_version: str
    tool_manifest_hash: str
    approver_id: str
    approval_id: str
    run_id: str
    issued_at: int
    expires_at: int
    granted: bool
    signature: str
    approver_kind: str = "passkey"

    def binding(self) -> dict:
        """Return the canonical binding that the signature covers.

    Every field except ``signature`` is included.
    """
        return {
            "policy_digest": self.policy_digest,
            "policy_schema_version": self.policy_schema_version,
            "constraint_registry_version": self.constraint_registry_version,
            "tool_manifest_hash": self.tool_manifest_hash,
            "approver_id": self.approver_id,
            "approver_kind": self.approver_kind,
            "approval_id": self.approval_id,
            "run_id": self.run_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "granted": self.granted,
        }


def _sign(binding: dict) -> str:
    """Return the HMAC-SHA256 signature over a binding."""
    return hmac.new(_TRUSTED_APPROVER_KEY, canonical_bytes(binding), hashlib.sha256).hexdigest()


def approve(
    policy,
    *,
    approver_id: str,
    approval_id: str,
    run_id: str,
    issued_at: int,
    expires_at: int,
    grant: bool = True,
    approver_kind: str = "passkey",
) -> Approval:
    """Produce a signed approval for a policy and a specific run.

    The versions and the tool manifest hash are read from the current trusted
    code, so an approval is tied to the declared versions in force when it was
    issued (under the immutable-runtime assumption, see constraints.py).

    Args:
        policy: The policy to approve. Its ``digest()`` is signed.
        approver_id: Who approves.
        approval_id: A unique identity for this approval.
        run_id: The single run the approval authorises.
        issued_at: Start of the validity window, in epoch seconds.
        expires_at: End of the validity window, in epoch seconds.
        grant: The human decision.
        approver_kind: "passkey" or "harness". It is signed and must fit
            ``approver_id``.

    Returns:
        The signed Approval.

    Raises:
        ValueError: If ``approver_kind`` does not fit ``approver_id``.
    """
    if not kind_fits(approver_kind, approver_id):
        raise ValueError(f"approver kind {approver_kind!r} does not fit approver id {approver_id!r}: "
                         f"harness keys are {HARNESS_PREFIX!r}-prefixed and passkeys are not")
    binding = {
        "policy_digest": policy.digest(),
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "constraint_registry_version": CONSTRAINT_REGISTRY_VERSION,
        "tool_manifest_hash": tool_manifest_hash(),
        "approver_id": approver_id,
        "approver_kind": approver_kind,
        "approval_id": approval_id,
        "run_id": run_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "granted": grant,
    }
    signature = _sign(binding)
    return Approval(signature=signature, **binding)


def verify(approval: Approval, policy, *, run_id: str, clock) -> None:
    """Verify an approval for a policy, a run and the trusted clock's time.

    All checks are fail-closed. The monitor calls this at activation. Time comes
    from the trusted ``clock``, not from caller input.

    Args:
        approval: The approval to verify.
        policy: The policy presented for activation.
        run_id: The run being activated.
        clock: The trusted Clock.

    Raises:
        ApprovalError: The subclass for the first check that fails.
    """
    now = clock.now()
    # Authenticity first: the signature must cover this binding.
    expected = _sign(approval.binding())
    if not hmac.compare_digest(expected, approval.signature):
        raise InvalidApprovalSignature("approval signature does not verify")

    if not kind_fits(approval.approver_kind, approval.approver_id):
        raise ApproverKindMismatch("approval's kind of key is unknown or does not fit its approver id")

    if not approval.granted:
        raise ApprovalRejected("approval was rejected")

    if approval.policy_digest != policy.digest():
        raise PolicyDigestMismatch("policy does not match the approved digest")

    if (
        approval.policy_schema_version != POLICY_SCHEMA_VERSION
        or approval.constraint_registry_version != CONSTRAINT_REGISTRY_VERSION
        or approval.tool_manifest_hash != tool_manifest_hash()
    ):
        raise ApprovalVersionMismatch("approval was issued for different declared versions (schema, registry or tool manifest)")

    if approval.run_id != run_id:
        raise RunMismatch("approval authorizes a different run")

    if not (approval.issued_at <= now <= approval.expires_at):
        raise ApprovalExpired("approval is outside its validity window")


#: Validity of a workflow approval presented to a deployed service, in seconds.
#: Used by the harnesses and services that present approvals to a deployed Authority.
LIVE_APPROVAL_WINDOW = 3600


def live_window(skew: int = 60) -> tuple[int, int]:
    """Return (issued_at, expires_at) for an approval presented to a deployed service.

    The service runs the system clock. `skew` tolerates a harness clock slightly
    ahead of the service's.
    """
    now = int(time.time())
    return now - skew, now + LIVE_APPROVAL_WINDOW

