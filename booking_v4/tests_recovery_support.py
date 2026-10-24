"""Test support: the effectful gateway recovery, which the shipped server does not have.

`gateway.recover_dispatch` re-performs an external operation for an idempotent downstream. The
service code has no such method, no option that adds it and no client call for it. The recovery
tests still need the mechanism, because they show what it would do (one logical effect, the same
digest in the ledger, nothing after a crash). They get it from this module. Its name starts with
`tests_`, so it is outside the runner source hash. The images copy it with the rest of
booking_v4, but no service entry point imports it.

    RecoveringServer              the durable server plus `gateway.recover_dispatch`
    RecoveringProcessDeployment   a durable process deployment that serves it
    recover_dispatch(dep, ...)    the client call
"""
from __future__ import annotations

import json
import unittest

from booking_v1.approval import approve
from booking_v1.effects import response_digest
from booking_v1.freeze import thaw
from booking_v4 import wire
from booking_v4.durable import (DurableDeploymentServer, DurableProcessDeployment, DurableStore,
                                _error, _internal_error)
from booking_v4.services import _call
from booking_v3.fragment import honest_fragment
from booking_v3.policy import default_p3


class RecoveringServer(DurableDeploymentServer):
    """The durable server plus the effectful recovery method."""

    def __init__(self, deployment, store, *, enable_recovery: bool = False, **kwargs) -> None:
        self._enable_recovery = enable_recovery      # before the base class starts its listener
        super().__init__(deployment, store, **kwargs)

    def _serve_locked(self, message):
        if message.get("method") == "gateway.recover_dispatch":
            self._check_envelope(message)
            return self._serve_recover_dispatch(message["params"])
        return super()._serve_locked(message)

    def _serve_recover_dispatch(self, params) -> dict:
        """Effectful recovery for an idempotent downstream.

        It has a name of its own, apart from dispatch_outcome, because it may call the
        counterparty. It requires downstream idempotency, the token holder and a standing
        intent without a durable outcome. It then performs the effect again (deduplicated
        downstream, so at most one logical result) and commits the outcome under the same
        rollback guard as phase two: if that commit fails, the live gateway returns to its
        state before the recovery and the intent stands.
        """
        gateway = self._dep.gateway
        if not self._enable_recovery:
            return _error("recover_dispatch is disabled on this gateway")
        try:
            token, fragment = self._recover_token(params, "recover_dispatch")
        except Exception as exc:
            return _internal_error("param_validation", exc)
        if not self._downstream_idempotent:
            return _error("recover_dispatch requires an idempotent downstream")
        stored = self._store.get_outcome(DurableStore.GATEWAY_OUTCOME + token.grant_id)
        if stored is not None:
            return json.loads(stored)  # already recovered: return the stored outcome
        if self._store.get_intent(token.grant_id) is None:
            return _error("no dispatch intent for this grant")

        gateway_before = gateway.export_state()
        result = gateway.perform_dispatch(fragment)  # safe: downstream dedupes
        reply = {"v": wire.WIRE_VERSION, "result": wire.effect_reply_to_wire(result)}
        try:
            with self._store.transaction():
                self._store.put_outcome(DurableStore.GATEWAY_OUTCOME + token.grant_id,
                                        json.dumps(thaw(reply), sort_keys=True))
                self._store.del_intent(token.grant_id)
                self._store.put_ledger(token.grant_id, token.run_id, token.step_index,
                                       token.fragment_hash, "COMMITTED",
                                       response_digest(result.outcome.value, result.payload))
                self._put_states()
        except Exception as exc:
            # As in phase two: the effect stands (or was a downstream no-op), the live
            # gateway returns to its state before the recovery and the intent remains, so
            # the next recovery still yields one effect.
            gateway.restore_state(gateway_before)
            return _internal_error("recovery_commit", exc,
                                   prefix="recovery outcome commit failed; intent stands",
                                   code="RECOVERY_COMMIT_FAILED")
        return reply


class RecoveringProcessDeployment(DurableProcessDeployment):
    """A durable process deployment whose gateway also serves `gateway.recover_dispatch`."""

    def __init__(self, *args, enable_recovery: bool = False, **kwargs) -> None:
        self._enable_recovery = enable_recovery      # `_wire_up` runs inside the base constructor
        super().__init__(*args, **kwargs)

    def _make_server(self, deployment) -> DurableDeploymentServer:
        """Serve the deployment with the recovering server."""
        return RecoveringServer(
            deployment, self.store, downstream_idempotent=self._downstream_idempotent,
            enable_test_api=self._enable_test_api, enable_recovery=self._enable_recovery)


def recover_dispatch(dep, token, fragment):
    """Ask the gateway for the effectful recovery of one grant, which may perform the effect again."""
    reply = _call(dep.server.endpoint, "gateway.recover_dispatch", {
        "token": wire.token_to_wire(token),
        "fragment": wire.fragment_to_wire(fragment)},
        request_id=f"gateway-recover:{token.grant_id}")
    return wire.effect_reply_from_wire(reply["result"])


class TheDoubleRecoversOneEffect(unittest.TestCase):
    """Control for the recovery tests: the double does what the removed method did, so a test
    that shows the shipped server refusing it is not refusing something that never existed."""

    def test_a_crash_after_the_effect_is_recovered_with_one_logical_effect(self):
        from . import tests_durable as td
        world = td.ExternalWorld(idempotent=True)
        policy = default_p3()
        dep = RecoveringProcessDeployment(td.FixedClock(td.T0), executor=world.executor,
                                          downstream_idempotent=True, enable_test_api=True,
                                          enable_recovery=True)
        approval = approve(policy, approver_id="alice", approval_id="A-run-1", run_id="run-1",
                           issued_at=td.ISSUED, expires_at=td.EXPIRES)
        s0 = dep.authority.create_run(policy, approval, "run-1")
        with dep:
            fragment = honest_fragment(policy, "run-1", 0, {"to": "FRA"})
            _credential, grant = td._harness_grant(dep, fragment, s0.state_hash)
            dep.server.crash_dispatch_once(before_effect=False)     # the effect runs, the outcome is lost
            with self.assertRaises((wire.WireError, OSError)):
                dep.gateway.execute(grant.token, fragment)
            self.assertEqual(world.effect_count("search"), 1)
            result = recover_dispatch(dep, grant.token, fragment)
            self.assertEqual(result.outcome.value, "CONFIRMED")
            self.assertEqual(world.effect_count("search"), 1)       # at most one logical effect


if __name__ == "__main__":
    unittest.main()
