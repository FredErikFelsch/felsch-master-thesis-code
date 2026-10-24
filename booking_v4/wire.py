"""The wire contract: canonical JSON for everything that crosses a boundary.

Every artefact that leaves a trust domain travels as canonical JSON derived from the freeze
module's canonical form, framed one message per line. The module uses no pickle: the
orchestrator is adversarial, and a trusted party that deserialises attacker-reachable pickle
has built code execution into its own boundary. Decoding is strict and versioned. The schema
version must match and the key set must match exactly. Fragments, envelopes and policies
re-derive their hash or digest on decoding and reject a mismatch. The other artefacts are
checked for their exact key set here and verified by the party that uses them (the Authority,
the gateway or the monitor). A transport bug or a tampered field therefore surfaces as a
WireError or a failed verification, not as a different object.

Each artefact has a `*_to_wire` and a `*_from_wire` function.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from booking_v1.constraints import ConstraintSpec
from booking_v1.effects import EffectOutcome, EffectResult
from booking_v1.freeze import thaw, to_canonical
from booking_v2.facts import BindingSpec, PostconditionSpec, ProducerSpec
from booking_v2.policy import Policy

from booking_v1.approval import Approval

from booking_v3.authority import (
    CapabilityToken, ExecutionGrant, HumanApprovalCredential, InterventionApproval,
    ProvisionerCredential, RunnerCredential, TransitionRecord,
)
from booking_v3.envelope import StateEnvelope, TrustAnchors, VerifyKey
from booking_v3.fragment import ActionFragment
from booking_v3.gateway import GatewayRefusal
from booking_v3.policy import POLICY3_SCHEMA_VERSION, Policy3
from booking_v3.runner import RunnerResult
from booking_v3.runner_attestation import RunnerAttestation

WIRE_VERSION = "wire-1"

# Upper bound on the size of one wire message in bytes. `decode_line` and the socket readers
# in `booking_v4.services` enforce it, so a peer cannot make a service read without limit.
MAX_WIRE_BYTES = 1_048_576

#: How long a service waits for the bytes of one request. Each listener answers one connection
#: at a time, so a client that connects and sends nothing would otherwise hold it for as long
#: as it likes. The reply of a long dispatch is not a read and is not affected. The budget of
#: the dispatch itself is in `booking_v4.budgets`.
REQUEST_TIMEOUT_S = 10.0


class WireError(Exception):
    """Raised when a message fails strict decoding."""


def _no_duplicate_pairs(pairs):
    """Build a mapping from JSON pairs and reject duplicate keys (an object_pairs_hook).

    Plain json.loads keeps the last of {"a":1,"a":2}. A canonical wire accepts
    one serialisation per message, so a duplicate key is a protocol violation.
    """
    out = {}
    for key, value in pairs:
        if key in out:
            raise WireError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def encode(message: Mapping[str, Any]) -> str:
    """Serialise one wire message as a single compact JSON line (without the newline)."""
    return json.dumps(thaw(message), sort_keys=True, separators=(",", ":"))


def decode_line(line: str) -> dict:
    """Parse one line into a canonical message.

    Raises:
        WireError: The line exceeds MAX_WIRE_BYTES, is not canonical JSON, has a
            duplicate key or carries another wire version.
    """
    if len(line.encode("utf-8")) > MAX_WIRE_BYTES:
        raise WireError("message exceeds MAX_WIRE_BYTES")
    try:
        message = to_canonical(json.loads(line, object_pairs_hook=_no_duplicate_pairs))
    except WireError:
        raise
    except Exception as exc:
        raise WireError(f"message is not canonical JSON: {exc}")
    if not isinstance(message, Mapping) or message.get("v") != WIRE_VERSION:
        raise WireError("unknown or missing wire version")
    return dict(message)


def expect_keys(mapping: Mapping[str, Any], keys: set[str], what: str) -> dict:
    """Return `mapping` as a dict if its key set is exactly `keys`.

    Raises:
        WireError: `mapping` is not a mapping or has other keys, named by `what`.
    """
    if not isinstance(mapping, Mapping) or set(mapping) != keys:
        raise WireError(f"{what}: key set mismatch")
    return dict(mapping)


def _expect(message: Mapping[str, Any], kind: str, keys: set[str]) -> dict:
    """Return `message` as a dict if it has kind `kind` and exactly `keys` besides `v` and `kind`.

    Raises:
        WireError: Another kind or another key set.
    """
    if message.get("kind") != kind:
        raise WireError(f"expected kind {kind!r}, got {message.get('kind')!r}")
    actual = set(message) - {"v"}
    expected = keys | {"kind"}
    if actual != expected:
        raise WireError(f"{kind}: key set mismatch, got {sorted(actual)}")
    return dict(message)


def _tag(kind: str, fields: Mapping[str, Any]) -> dict:
    """Return `fields` as a message of kind `kind` with the wire version."""
    return {"v": WIRE_VERSION, "kind": kind, **thaw(fields)}


# --- fragment -----------------------------------------------------------------

def fragment_to_wire(fragment: ActionFragment) -> dict:
    """Encode an action fragment. The hash travels along and is re-derived on decoding."""
    body = fragment.binding()
    body.pop("kind")
    return _tag("fragment", {**body, "fragment_hash": fragment.fragment_hash})


def fragment_from_wire(message: Mapping[str, Any]) -> ActionFragment:
    """Decode an action fragment and re-derive its hash, rejecting any mismatch."""
    w = _expect(message, "fragment", {
        "run_id", "fragment_index", "policy_digest", "operation", "arguments",
        "action_id", "declared_facts", "declared_capability", "fragment_hash"})
    fragment = ActionFragment(
        run_id=w["run_id"], fragment_index=w["fragment_index"],
        policy_digest=w["policy_digest"], operation=w["operation"],
        arguments=thaw(w["arguments"]), action_id=w["action_id"],
        declared_facts=tuple(w["declared_facts"]),
        declared_capability=w["declared_capability"])
    if fragment.fragment_hash != w["fragment_hash"]:
        raise WireError("fragment hash does not match the reconstruction")
    return fragment


# --- envelope -----------------------------------------------------------------

def envelope_to_wire(envelope: StateEnvelope) -> dict:
    """Encode a state envelope with its state hash and signature."""
    body = envelope.body()
    body.pop("kind")
    return _tag("envelope", {**body, "state_hash": envelope.state_hash,
                             "signature": envelope.signature})


def envelope_from_wire(message: Mapping[str, Any]) -> StateEnvelope:
    """Decode a state envelope. The constructor re-checks the state hash."""
    w = _expect(message, "envelope", {
        "run_id", "policy_digest", "approval_id", "step_index", "facts",
        "audit_head", "previous_state_hash", "state_hash", "signature"})
    # The constructor recomputes and checks state_hash against the body.
    return StateEnvelope(
        run_id=w["run_id"], policy_digest=w["policy_digest"],
        approval_id=w["approval_id"], step_index=w["step_index"],
        facts=thaw(w["facts"]), audit_head=w["audit_head"],
        previous_state_hash=w["previous_state_hash"],
        state_hash=w["state_hash"], signature=w["signature"])


# --- policy -------------------------------------------------------------------

def policy_to_wire(policy: Policy3) -> dict:
    """Encode a policy with its digest, which `policy_from_wire` re-derives."""
    return _tag("policy3", {
        "policy3_schema_version": POLICY3_SCHEMA_VERSION,
        "approval_required_steps": list(policy.approval_required_steps),
        "base": policy.base._canonical(),
        "digest": policy.digest()})


def policy_from_wire(message: Mapping[str, Any]) -> Policy3:
    """Decode a policy and re-derive its digest, rejecting any mismatch."""
    w = _expect(message, "policy3", {
        "policy3_schema_version", "approval_required_steps", "base", "digest"})
    if w["policy3_schema_version"] != POLICY3_SCHEMA_VERSION:
        raise WireError("policy3 schema version mismatch")
    b = expect_keys(thaw(w["base"]), {
        "policy_id", "task", "allowed_flow", "max_executions", "budget_minor",
        "currency", "step_local", "step_producers", "step_bindings",
        "step_postconditions", "policy_schema_version",
        "constraint_registry_version", "fact_registry_version"}, "policy base")

    # Every nested spec must be exactly {kind, params}. The policy's registered-spec
    # validators then check the params' own keys at construction and reject unknown
    # ones, so every level of the policy serialisation is strict.
    def _spec(cls, d, what):
        s = expect_keys(d, {"kind", "params"}, what)
        return cls(s["kind"], s["params"])

    def _specs(cls, entries):
        return {int(i): tuple(_spec(cls, d, f"{cls.__name__} spec") for d in specs)
                for i, specs in entries.items()}

    try:
        base = Policy(
            policy_id=b["policy_id"], task=b["task"],
            allowed_flow=tuple(b["allowed_flow"]),
            max_executions=b["max_executions"],
            budget_minor=b["budget_minor"], currency=b["currency"],
            step_local={int(i): _spec(ConstraintSpec, d, "ConstraintSpec")
                        for i, d in b["step_local"].items()},
            step_producers=_specs(ProducerSpec, b["step_producers"]),
            step_bindings=_specs(BindingSpec, b["step_bindings"]),
            step_postconditions=_specs(PostconditionSpec, b["step_postconditions"]))
        policy = Policy3(base=base,
                         approval_required_steps=tuple(w["approval_required_steps"]))
    except WireError:
        raise
    except Exception as exc:
        raise WireError(f"policy does not reconstruct: {exc}")
    # The digest also covers the schema and registry version fields inside
    # base._canonical, so a policy from another code version does not decode.
    if policy.digest() != w["digest"]:
        raise WireError("policy digest does not match the reconstruction")
    return policy


# --- trusted provisioning material -------------------------------------------

def credential_to_wire(credential: RunnerCredential) -> dict:
    """Encode a runner credential, including its session secret."""
    return _tag("runner-credential", {
        "session_id": credential.session_id, "run_id": credential.run_id,
        "fragment_hash": credential.fragment_hash,
        "state_hash": credential.state_hash, "secret": credential.secret})


def credential_from_wire(message: Mapping[str, Any]) -> RunnerCredential:
    """Decode a runner credential, rejecting unknown or missing keys. The Authority checks the secret."""
    w = _expect(message, "runner-credential",
                {"session_id", "run_id", "fragment_hash", "state_hash", "secret"})
    return RunnerCredential(**{k: w[k] for k in
                               ("session_id", "run_id", "fragment_hash", "state_hash", "secret")})


_APPROVAL_FIELDS = (
    "policy_digest", "policy_schema_version", "constraint_registry_version",
    "tool_manifest_hash", "approver_id", "approver_kind", "approval_id", "run_id",
    "issued_at", "expires_at", "granted", "signature")


def approval_to_wire(approval: Approval) -> dict:
    """Encode a workflow approval with its signature."""
    return _tag("approval", {name: getattr(approval, name) for name in _APPROVAL_FIELDS})


def approval_from_wire(message: Mapping[str, Any]) -> Approval:
    """Decode a workflow approval, rejecting unknown or missing keys. The Authority verifies the signature."""
    w = _expect(message, "approval", set(_APPROVAL_FIELDS))
    return Approval(**{name: w[name] for name in _APPROVAL_FIELDS})


def bootstrap_to_wire(bootstrap: ProvisionerCredential) -> dict:
    """Encode a provisioner bootstrap credential, including its secret."""
    return _tag("provisioner-credential", {"secret": bootstrap.secret})


def bootstrap_from_wire(message: Mapping[str, Any]) -> ProvisionerCredential:
    """Decode a provisioner bootstrap credential, rejecting unknown or missing keys."""
    w = _expect(message, "provisioner-credential", {"secret"})
    return ProvisionerCredential(secret=w["secret"])


def human_to_wire(human: HumanApprovalCredential) -> dict:
    """Encode a human approval credential, including its secret."""
    return _tag("human-credential", {"secret": human.secret})


def human_from_wire(message: Mapping[str, Any]) -> HumanApprovalCredential:
    """Decode a human approval credential, rejecting unknown or missing keys."""
    w = _expect(message, "human-credential", {"secret"})
    return HumanApprovalCredential(secret=w["secret"])


def anchors_to_wire(anchors: TrustAnchors) -> dict:
    """Encode the trust anchors as hex-encoded public keys."""
    return _tag("trust-anchors", {
        "envelope_key": anchors.envelope_key.to_bytes().hex(),
        "intervention_key": anchors.intervention_key.to_bytes().hex()})


def anchors_from_wire(message: Mapping[str, Any]) -> TrustAnchors:
    """Decode the trust anchors, rejecting unknown or missing keys and malformed keys."""
    w = _expect(message, "trust-anchors", {"envelope_key", "intervention_key"})
    return TrustAnchors(
        envelope_key=VerifyKey.from_bytes(bytes.fromhex(w["envelope_key"])),
        intervention_key=VerifyKey.from_bytes(bytes.fromhex(w["intervention_key"])))


# --- grants, tokens, approvals ------------------------------------------------

def token_to_wire(token: CapabilityToken) -> dict:
    """Encode a capability token with its signature."""
    body = token.binding()
    body.pop("kind")
    return _tag("capability-token", {**body, "signature": token.signature})


def token_from_wire(message: Mapping[str, Any]) -> CapabilityToken:
    """Decode a capability token, rejecting unknown or missing keys. The gateway verifies the signature."""
    w = _expect(message, "capability-token", {
        "run_id", "step_index", "fragment_hash", "operation",
        "authorized_request_hash", "grant_id", "expires_at", "signature"})
    return CapabilityToken(**{k: w[k] for k in (
        "run_id", "step_index", "fragment_hash", "operation",
        "authorized_request_hash", "grant_id", "expires_at", "signature")})


def grant_to_wire(grant: ExecutionGrant) -> dict:
    """Encode an execution grant together with its capability token."""
    return _tag("execution-grant", {
        "grant_id": grant.grant_id, "run_id": grant.run_id,
        "step_index": grant.step_index, "fragment_hash": grant.fragment_hash,
        "issued_at": grant.issued_at, "token": token_to_wire(grant.token)})


def grant_from_wire(message: Mapping[str, Any]) -> ExecutionGrant:
    """Decode an execution grant and its token, rejecting unknown or missing keys."""
    w = _expect(message, "execution-grant", {
        "grant_id", "run_id", "step_index", "fragment_hash", "issued_at", "token"})
    return ExecutionGrant(
        grant_id=w["grant_id"], run_id=w["run_id"], step_index=w["step_index"],
        fragment_hash=w["fragment_hash"], issued_at=w["issued_at"],
        token=token_from_wire(w["token"]))


def intervention_to_wire(approval: InterventionApproval | None) -> dict | None:
    """Encode an intervention approval with its signature. None stays None."""
    if approval is None:
        return None
    body = approval.binding()
    body.pop("kind")
    return _tag("intervention-approval", {**body, "signature": approval.signature})


def intervention_from_wire(message: Mapping[str, Any] | None) -> InterventionApproval | None:
    """Decode an intervention approval, rejecting unknown or missing keys. None stays None."""
    if message is None:
        return None
    w = _expect(message, "intervention-approval", {
        "run_id", "step_index", "fragment_hash", "approver_id", "approver_kind",
        "issued_at", "expires_at", "signature"})
    return InterventionApproval(**{k: w[k] for k in (
        "run_id", "step_index", "fragment_hash", "approver_id", "approver_kind",
        "issued_at", "expires_at", "signature")})


def session_package_to_wire(credential: RunnerCredential, anchors: TrustAnchors) -> dict:
    """Build the package the Authority seals to the TD's boot key: credential and trust anchors.

    The anchors are the public keys the monitor verifies the state envelope and a human
    intervention approval with. Sealing keeps the package confidential and binds it to this
    TD and this binding (AAD). It does not authenticate the sender, because boot key and AAD
    are public: whoever composes the `v5-session` line could seal a package of its own. Such
    a substitution yields at most a local run in the TD against foreign anchors and a
    misleading result line. It yields no grant and no effect, because the Authority refuses
    a credential it did not mint and a session that does not bind the fragment and input
    state (`booking_v5.tests_session_package_sender`). Authenticated anchors would need a
    signature under a key pinned independently, for example in the measured init-data.
    Without it, the controller that composes the session line is trusted not to substitute
    the package.

    The service endpoints stay in the clear. Substituting one sends the runner's grant
    request to a machine that cannot issue a token any real gateway accepts, which denies
    service (out of scope) but grants no authority.

    Args:
        credential: The runner credential the Authority minted for this session.
        anchors: The Authority's trust anchors.

    Returns:
        The package as a wire message.
    """
    return _tag("session-package", {"credential": credential_to_wire(credential),
                                    "anchors": anchors_to_wire(anchors)})


def session_package_from_wire(message: Mapping[str, Any]):
    """Decode an unsealed session package into (credential, anchors)."""
    w = _expect(message, "session-package", {"credential", "anchors"})
    return credential_from_wire(w["credential"]), anchors_from_wire(w["anchors"])


# --- the runner's own signature over its verdict ------------------------------

def attestation_to_wire(attestation) -> dict | None:
    """Encode a `booking_v3.runner_attestation.RunnerAttestation`, or None for a session that requires none.

    The statement travels as its plain canonical mapping. The receiving side reads no field
    out of it and only compares it with the statement it reconstructed itself, so it is not
    validated field by field here.
    """
    if attestation is None:
        return None
    return _tag("runner-attestation", {
        "statement": thaw(attestation.statement), "signature": attestation.signature})


def attestation_from_wire(message: Mapping[str, Any] | None):
    """Decode a runner attestation, or None. The Authority verifies the signature."""
    if message is None:
        return None
    w = _expect(message, "runner-attestation", {"statement", "signature"})
    if not isinstance(w["statement"], Mapping) or not isinstance(w["signature"], str):
        raise WireError("runner-attestation: statement must be an object and signature a string")
    return RunnerAttestation(statement=thaw(w["statement"]), signature=w["signature"])


# --- transition record and results -------------------------------------------

def record_to_wire(record: TransitionRecord) -> dict:
    """Encode a transition record, with the proposed envelope if there is one."""
    return _tag("transition-record", {
        "run_id": record.run_id, "grant_id": record.grant_id,
        "outcome": record.outcome,
        "admission_event": thaw(record.admission_event),
        "effect_event": thaw(record.effect_event),
        "proposed": envelope_to_wire(record.proposed) if record.proposed is not None else None})


def record_from_wire(message: Mapping[str, Any]) -> TransitionRecord:
    """Decode a transition record, rejecting unknown or missing keys. A proposed envelope re-checks its state hash."""
    w = _expect(message, "transition-record", {
        "run_id", "grant_id", "outcome", "admission_event", "effect_event", "proposed"})
    proposed = envelope_from_wire(w["proposed"]) if w["proposed"] is not None else None
    return TransitionRecord(
        run_id=w["run_id"], grant_id=w["grant_id"], outcome=w["outcome"],
        admission_event=thaw(w["admission_event"]),
        effect_event=thaw(w["effect_event"]), proposed=proposed)


def effect_reply_to_wire(result) -> dict:
    """Encode an effect reply, either an effect result or a gateway refusal."""
    if isinstance(result, GatewayRefusal):
        return _tag("gateway-refusal", {"reason": result.reason,
                                        "dispatch_attempted": bool(result.dispatch_attempted)})
    return _tag("effect-result", {
        "outcome": result.outcome.value,
        "payload": thaw(result.payload) if result.payload is not None else None,
        "error": result.error})


def effect_reply_from_wire(message: Mapping[str, Any]):
    """Decode an effect reply (an effect result or a gateway refusal), rejecting unknown or missing keys."""
    if message.get("kind") == "gateway-refusal":
        w = _expect(message, "gateway-refusal", {"reason", "dispatch_attempted"})
        if not isinstance(w["dispatch_attempted"], bool):
            raise WireError("gateway-refusal: dispatch_attempted must be a boolean")
        return GatewayRefusal(reason=w["reason"], dispatch_attempted=w["dispatch_attempted"])
    w = _expect(message, "effect-result", {"outcome", "payload", "error"})
    return EffectResult(outcome=EffectOutcome(w["outcome"]),
                        payload=thaw(w["payload"]) if w["payload"] is not None else None,
                        error=w["error"])


def result_to_wire(result: RunnerResult) -> dict:
    """Encode a runner result, with its envelope if there is one."""
    return _tag("runner-result", {
        "status": result.status, "reason": result.reason,
        "payload": thaw(result.payload) if result.payload is not None else None,
        "envelope": envelope_to_wire(result.envelope) if result.envelope is not None else None,
        "runner_no": result.runner_no})


def result_from_wire(message: Mapping[str, Any]) -> RunnerResult:
    """Decode a runner result, rejecting unknown or missing keys. An envelope re-checks its state hash."""
    w = _expect(message, "runner-result",
                {"status", "reason", "payload", "envelope", "runner_no"})
    envelope = envelope_from_wire(w["envelope"]) if w["envelope"] is not None else None
    return RunnerResult(status=w["status"], envelope=envelope, reason=w["reason"],
                        payload=thaw(w["payload"]) if w["payload"] is not None else None,
                        runner_no=w["runner_no"])
