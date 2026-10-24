"""The Tool Gateway: the capability enforcement point.

Real counterparties do not accept a homemade capability token, so this is the
component that holds the real API credentials and stands between every runner
and the world. It accepts an operation only against a valid, unspent token
minted by the Authority for this request: same run, same fragment (arguments
included, via authorized_request_hash), same operation, within the token's
window, once. Only then does it call the "real" API, which in the
mock is the booking_v2 world executor behind the credential boundary.

The gateway also records every authorised dispatch. The entry is written when the token is
consumed, before the counterparty is called, so an experiment can assert that a rejected
scenario authorised zero dispatches. An entry is a reservation, not proof that the effect
ran. What happened at the counterparty is established by the ledger and the provider, not
by this list.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping

from booking_v0.tools import ToolCall
from booking_v1.clock import Clock
from booking_v1.effects import EffectResult, safe_execute, Executor
from booking_v1.freeze import canonical_bytes, thaw
from booking_v2.world import v2_executor

from .authority import CapabilityToken, request_hash
from .envelope import VerifyKey
from .fragment import ActionFragment


def effect_identity(fragment: ActionFragment) -> str:
    """Return the server-derived identity of one authorised effect.

    Every component is checked against the capability token in authorize_dispatch
    (run, step, fragment hash, which covers operation, arguments and policy digest),
    so a controller cannot choose it. Recovery of the same grant re-dispatches the
    same fragment and therefore meets the same identity. Another run or another step
    yields a different identity. This function only builds the string. Whether a second dispatch is
    deduplicated against a stored outcome is decided by the dispatch and recovery code
    that uses it, not here.

    Args:
        fragment: The verified fragment about to be dispatched.

    Returns:
        "<operation>:<run_id>:<fragment_index>:<fragment_hash>".
    """
    return f"{fragment.operation}:{fragment.run_id}:{fragment.fragment_index}:{fragment.fragment_hash}"


# Stand-in for the real API credential only the gateway possesses. No method returns
# it. Its presence marks the credential boundary.
_REAL_API_CREDENTIAL = "sk_live_GATEWAY_ONLY_MOCK"


@dataclass(frozen=True)
class GatewayRefusal:
    """A refused invocation.

    `dispatch_attempted` separates "no effect happened" from "an effect may have happened
    and this caller cannot know". The gateway consumes the token before it calls the
    counterparty, so a re-entrant or duplicated invocation cannot run the effect twice. As a
    consequence one refusal reason, an already consumed token, can only occur after a
    dispatch intent exists. Every other reason is decided before the consumed set is touched
    and means zero effects.

    The caller must keep the two apart. `booking_v1.lifecycle` defines EFFECT_FAILED as
    "certain no effect happened" and EFFECT_UNCERTAIN as an outcome that needs reconciliation
    rather than an automatic retry, because a blind retry could pay twice. Reporting a spent
    token as FAILED would claim a certainty nobody has.
    """

    reason: str
    dispatch_attempted: bool = False


class ToolGateway:
    """Verifies capability tokens and executes each admitted request at most once."""

    def __init__(self, token_key: VerifyKey, clock: Clock, executor: Executor = v2_executor) -> None:
        """Create a gateway.

        Args:
            token_key: The Authority's key for capability-token signatures.
            clock: The clock for token expiry.
            executor: The world executor behind the credential boundary.
        """
        self._token_key = token_key
        self._clock = clock
        self._executor = executor
        self._consumed: set[str] = set()
        self._executions: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    @property
    def executions(self) -> list[dict[str, Any]]:
        """Return every authorised dispatch, recorded when its token was consumed.

        An entry is a reservation made before the counterparty is called, not proof that the
        effect ran. The ledger and the provider establish what happened.
        """
        return list(self._executions)

    def export_state(self) -> dict:
        """Return the gateway's durable state.

        The consumed-token set is what single use depends on. The dispatch
        log is the zero-dispatch evidence. Both must survive a service restart.
        """
        with self._lock:
            return {"consumed": sorted(self._consumed),
                    "executions": [dict(entry) for entry in self._executions]}

    def restore_state(self, state: Mapping[str, Any]) -> None:
        """Reload the durable state after a restart."""
        with self._lock:
            self._consumed = set(state["consumed"])
            self._executions = [dict(entry) for entry in state["executions"]]

    def authorize_dispatch(self, token: CapabilityToken, fragment: ActionFragment) -> GatewayRefusal | None:
        """Run the pre-effect half of execute(), without an external call.

        All checks, token consumption and the dispatch record happen here, so
        a durable deployment can persist the dispatch intent (token consumed,
        dispatch recorded) before the external effect runs.

        Args:
            token: The capability token the caller presents.
            fragment: The fragment to dispatch.

        Returns:
            None on success, otherwise a GatewayRefusal. A refusal means zero
            effects unless its ``dispatch_attempted`` is set.
        """
        with self._lock:
            if not self._token_key.verify(token.signature, canonical_bytes(token.binding())):
                return GatewayRefusal("token signature does not verify")
            # Order matters. The token is first tied to this request, then a
            # previous use is looked for, and only then does expiry count. A token that was
            # spent and has since expired must still answer "already consumed, a dispatch was
            # attempted". Reporting "expired, nothing dispatched" for it would turn a past
            # effect into a certain non-effect.
            if token.run_id != fragment.run_id:
                return GatewayRefusal("token was minted for a different run")
            if token.step_index != fragment.fragment_index:
                return GatewayRefusal("token was minted for a different step")
            if token.fragment_hash != fragment.fragment_hash:
                return GatewayRefusal("token was minted for a different fragment")
            if token.operation != fragment.operation:
                return GatewayRefusal("token does not authorize this operation")
            if token.authorized_request_hash != request_hash(fragment.operation, fragment.arguments):
                return GatewayRefusal("request differs from the authorized request")
            if token.grant_id in self._consumed:
                # This token was spent, so a dispatch was started. Whether the counterparty
                # acted is not known here.
                return GatewayRefusal("token already consumed (single use)", dispatch_attempted=True)
            if self._clock.now() > token.expires_at:
                return GatewayRefusal("token expired")
            # All checks passed. Consume before executing so a re-entrant or
            # duplicated invocation cannot run the effect twice.
            self._consumed.add(token.grant_id)
            self._executions.append({
                "operation": fragment.operation, "arguments": thaw(fragment.arguments),
                "run_id": fragment.run_id, "step_index": fragment.fragment_index,
            })
        return None

    def verify_dispatch_authorization(self, token: CapabilityToken, fragment: ActionFragment) -> str | None:
        """Verify the token without consuming it, as read-only holder proof for recovery.

        Unlike authorize_dispatch it does not touch the consumed set, so it is
        safe to call for a grant whose token is already spent. It does not
        re-check the token TTL: outcome recovery derives its authority from a
        valid signature and fragment binding plus an existing durable intent or
        outcome, and the grant validity was enforced before the intent was
        created. A long crash must not make an authorised dispatch unrecoverable.

        Args:
            token: The capability token of the grant.
            fragment: The fragment the grant was for.

        Returns:
            None if the token authorises this request, otherwise a reason.
        """
        with self._lock:
            if not self._token_key.verify(token.signature, canonical_bytes(token.binding())):
                return "token signature does not verify"
            if token.run_id != fragment.run_id:
                return "token was minted for a different run"
            if token.step_index != fragment.fragment_index:
                return "token was minted for a different step"
            if token.fragment_hash != fragment.fragment_hash:
                return "token was minted for a different fragment"
            if token.operation != fragment.operation:
                return "token does not authorize this operation"
            if token.authorized_request_hash != request_hash(fragment.operation, fragment.arguments):
                return "request differs from the authorized request"
        return None

    def perform_dispatch(self, fragment: ActionFragment) -> EffectResult:
        """Run the external effect only. Call after authorize_dispatch.

        The downstream idempotency key is derived here, from the fragment the token
        was verified against, not from the controller's action_id. The controller may
        still transport an action_id, but it does not decide which stored outcome a
        dispatch is deduplicated against.
        """
        # The gateway, holding _REAL_API_CREDENTIAL, calls the real counterparty.
        call = ToolCall(tool=fragment.operation, args=dict(thaw(fragment.arguments)),
                        effect_identity=effect_identity(fragment))
        return safe_execute(self._executor, call)

    def execute(self, token: CapabilityToken, fragment: ActionFragment) -> EffectResult | GatewayRefusal:
        """Execute one request under one token, or refuse.

        Args:
            token: The capability token the caller presents.
            fragment: The fragment to execute.

        Returns:
            The effect result, or a GatewayRefusal. A refusal means zero effects
            unless its ``dispatch_attempted`` is set.
        """
        refusal = self.authorize_dispatch(token, fragment)
        if refusal is not None:
            return refusal
        return self.perform_dispatch(fragment)
