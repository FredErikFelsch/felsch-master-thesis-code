"""Tests that the gateway derives the downstream idempotency key.

If ExternalWorld deduplicated on the client's `action_id`, the controller would choose the key,
and it is run-scoped only by the controller's own convention. A compromised controller could then
send run A's key in run B and receive run A's stored outcome for run B: no provider call, but a
record that claims one. So the gateway derives the key from the verified fragment (operation, run,
step, fragment hash), all of which the capability token binds. The controller still transports an
action_id, but it does not decide against which stored outcome a dispatch is replayed.

What the tests show:
  * Run B reusing run A's action_id gets no stale replay: run A's outcome is not returned
    to run B, and run B reaches the provider under its own identity.
  * The same logical effect (the same authorised fragment, as a recovery dispatches it
    again) meets the same server-derived key, so the stored outcome comes back and the
    provider sees no further call.
  * The identity is a pure function of token-bound fields.
  * A call that did not pass a gateway keeps the action_id behaviour.
"""
from __future__ import annotations

import unittest

from booking_v0.tools import ToolCall
from booking_v1.approval import approve
from booking_v1.clock import FixedClock
from booking_v1.effects import EffectOutcome, EffectResult
from booking_v2.world import v2_executor
from booking_v3.fragment import honest_fragment
from booking_v3.gateway import ToolGateway, effect_identity
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3

from .durable import DurableProcessDeployment, ExternalWorld, idempotency_key

T0 = 1_700_000_010
ISSUED, EXPIRES = 1_700_000_000, 1_700_003_600
BOOK_STEP, PAY_STEP = 2, 3


class CountingProvider:
    """A provider that counts every call it serves.

    Without `inner` it confirms with a payload naming the call's serial number, so a
    replayed outcome is recognisable. With `inner` (the booking_v2 catalogue) it answers as
    the real counterparty would, so the booking_v2 postconditions hold end to end.
    """

    def __init__(self, inner=None) -> None:
        self.calls: list[ToolCall] = []
        self._inner = inner

    def __call__(self, call) -> EffectResult:
        self.calls.append(call)
        if self._inner is not None:
            return self._inner(call)
        return EffectResult(outcome=EffectOutcome.CONFIRMED,
                            payload={"tool": call.tool, "served": len(self.calls)})

    def count(self, tool: str) -> int:
        """Return the number of calls served for `tool`."""
        return sum(1 for c in self.calls if c.tool == tool)


def _gateway(provider: CountingProvider) -> tuple[ToolGateway, ExternalWorld]:
    """Return the booking_v3 gateway in front of an idempotent counterparty, and that counterparty."""
    world = ExternalWorld(idempotent=True, executor=provider)
    return ToolGateway(token_key=None, clock=FixedClock(T0), executor=world.executor), world


def _fragment(run_id: str, step: int, action_id: str | None = None):
    """Return the honest happy-path fragment of `step`, optionally with another action_id."""
    args = dict(happy_path_arguments()[step])
    if action_id is not None:
        args["action_id"] = action_id
    return honest_fragment(default_p3(), run_id, step, args)


class TheGatewayDerivesTheKey(unittest.TestCase):
    """The deduplication key comes from the verified fragment, not from the client's action_id."""

    def test_run_b_reusing_run_a_key_gets_no_stale_replay(self):
        """Run A / pay / seq 3 -> key A. Run B sends key A: run A's outcome is not replayed."""
        provider = CountingProvider()
        gateway, world = _gateway(provider)
        a = gateway.perform_dispatch(_fragment("run-A", PAY_STEP, action_id="pay-run-A-3"))
        b = gateway.perform_dispatch(_fragment("run-B", PAY_STEP, action_id="pay-run-A-3"))
        self.assertEqual(provider.count("pay"), 2, "run B reached the provider itself")
        self.assertNotEqual(a.payload, b.payload, "run A's stored outcome was replayed into run B")
        self.assertEqual(b.payload["served"], 2)
        self.assertEqual(world.effect_count("pay"), 2, "one record per run, none shared")

    def test_same_logical_effect_meets_the_same_server_key(self):
        """A recovery dispatches the authorised fragment again and gets the stored outcome."""
        provider = CountingProvider()
        gateway, world = _gateway(provider)
        fragment = _fragment("run-A", PAY_STEP)
        first = gateway.perform_dispatch(fragment)
        again = gateway.perform_dispatch(fragment)
        self.assertEqual(provider.count("pay"), 1, "a second provider call for one effect")
        self.assertEqual(first, again)
        self.assertEqual(world.effect_count("pay"), 1)

    def test_the_key_is_a_function_of_token_bound_fields_only(self):
        fragment = _fragment("run-A", PAY_STEP, action_id="anything-the-controller-likes")
        self.assertEqual(effect_identity(fragment),
                         f"pay:run-A:{PAY_STEP}:{fragment.fragment_hash}")
        seen = []
        _gateway_with = ToolGateway(token_key=None, clock=FixedClock(T0), executor=lambda c: (
            seen.append(c) or EffectResult(outcome=EffectOutcome.CONFIRMED, payload={})))
        _gateway_with.perform_dispatch(fragment)
        self.assertEqual(seen[0].effect_identity, effect_identity(fragment))
        self.assertEqual(idempotency_key(seen[0]), effect_identity(fragment),
                         "the client's action_id decided the key")

    def test_other_steps_and_runs_do_not_share_a_key(self):
        keys = {effect_identity(_fragment(run, step, action_id="k"))
                for run in ("run-A", "run-B") for step in (BOOK_STEP, PAY_STEP)}
        self.assertEqual(len(keys), 4)


class TheHarnessFallbackIsUnchanged(unittest.TestCase):
    """A call without a gateway-derived identity still deduplicates on its action_id."""

    def test_a_call_without_identity_still_dedupes_on_action_id(self):
        provider = CountingProvider()
        world = ExternalWorld(idempotent=True, executor=provider)
        call = ToolCall(tool="pay", args={"action_id": "pay-1"})
        world.executor(call)
        world.executor(ToolCall(tool="pay", args={"action_id": "pay-1"}))
        self.assertEqual(provider.count("pay"), 1)


class OverTheDurableDeployment(unittest.TestCase):
    """The same property end to end: Authority grant, durable two-phase dispatch, world."""

    def _run(self, dep, policy, run_id: str) -> None:
        """Activate `run_id` and run its steps up to and including the booking."""
        approval = approve(policy, approver_id="alice", approval_id=f"A-{run_id}",
                           run_id=run_id, issued_at=ISSUED, expires_at=EXPIRES)
        envelope = dep.authority.create_run(policy, approval, run_id)
        for step, args in enumerate(happy_path_arguments()[:BOOK_STEP + 1]):
            fragment = honest_fragment(policy, run_id, step, args)   # same "book-1" in both runs
            result = dep.provisioner.spawn(fragment, envelope).execute(policy, envelope, fragment)
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
            envelope = result.envelope

    def test_two_runs_with_the_same_client_key_book_twice_not_once(self):
        provider = CountingProvider(inner=v2_executor)
        world = ExternalWorld(idempotent=True, executor=provider)
        policy = default_p3()
        dep = DurableProcessDeployment(FixedClock(T0), executor=world.executor,
                                       downstream_idempotent=True, enable_test_api=True)
        self._run(dep, policy, "run-1")
        self._run(dep, policy, "run-2")
        booked = [c for c in provider.calls if c.tool == "book"]
        self.assertEqual(len(booked), 2, "run-2 was answered with run-1's stored booking")
        self.assertEqual({c.args["action_id"] for c in booked}, {"book-1"})
        self.assertEqual(len({c.effect_identity for c in booked}), 2)


if __name__ == "__main__":
    unittest.main()
