"""Trust-boundary tests for the runner controller: a compromised orchestrator gains no provisioning.

The orchestrator's whole interface is the narrow controller RPC, and these tests attack it
directly. They show the structural separation of the launch mechanism, not enforcement against a
fully compromised orchestrator with ambient host privileges (Kubernetes RBAC provides that). The
narrow contract names no image, endpoint, environment, mount, bootstrap, credential or capability
(strict key set), an unknown or reused handle is rejected, a handle bound to one fragment cannot be
run for another, the orchestrator-side module contains no Docker invocation and constructs no
ContainerRunnerProvisioner, the controller runs in a separate process, and after the controller is
killed its handles fail. The Docker-based classes are skipped when Docker or the runner image is
unavailable.

Run from the repository root:  python3 -m booking_v4.tests_controller
"""

from __future__ import annotations

import os
import unittest

from booking_v1.clock import FixedClock
from booking_v3 import scenarios as v3_scenarios
from booking_v3.orchestrator import happy_path_arguments
from booking_v3.policy import default_p3

from . import container_env, wire
from .controller import (ControllerRunnerProvisioner, create_controller_deployment)
from .services import _call


#: Same three measured preconditions as the container suite: docker, the image, and a
#: bind-mounted unix socket a container can connect to. See booking_v4.container_env.
_ENV = container_env.probe()
_SKIP = not _ENV.usable
_REASON = _ENV.skip_reason


def _spawn_params(**extra):
    """Return minimal spawn params (dummy values) plus the extra keys under test.

    The strict key-set decoding rejects an unknown key before the fragment is
    parsed, so dummy values suffice to show that the surface is narrow.
    """
    p = {"fragment": {"dummy": True}, "envelope": {"dummy": True}}
    p.update(extra)
    return p


@unittest.skipIf(_SKIP, _REASON)
class ControllerContractTests(unittest.TestCase):
    """The narrow contract rejects every provisioning field an orchestrator
    might try to smuggle."""

    def setUp(self):
        self._created = []

        def factory(clock, executor=None):
            dep = create_controller_deployment(clock, executor=executor)
            self._created.append(dep)
            return dep

        v3_scenarios.set_deployment_factory(factory)
        self.ctx = v3_scenarios.make_context()
        self.dep = self._created[-1]
        self.ep = self.dep.provisioner._endpoint  # the controller RPC endpoint

    def tearDown(self):
        v3_scenarios.set_deployment_factory(None)
        for dep in self._created:
            dep.close()

    def _reject(self, method, params):
        """Assert that the controller refuses one raw request."""
        with self.assertRaises(wire.WireError):
            _call(self.ep, method, params)

    def test_orchestrator_cannot_supply_image(self):
        self._reject("controller.spawn", _spawn_params(image="evil:latest"))

    def test_orchestrator_cannot_supply_endpoint(self):
        self._reject("controller.spawn", _spawn_params(endpoint={"kind": "tcp", "address": "evil:9"}))

    def test_orchestrator_cannot_supply_environment(self):
        self._reject("controller.spawn", _spawn_params(environment={"SECRET": "x"}))

    def test_orchestrator_cannot_supply_mount(self):
        self._reject("controller.spawn", _spawn_params(mount="/host:/inside"))

    def test_orchestrator_cannot_supply_bootstrap(self):
        self._reject("controller.spawn", _spawn_params(bootstrap="stolen-secret"))

    def test_orchestrator_cannot_supply_credential(self):
        self._reject("controller.spawn", _spawn_params(credential={"forged": True}))

    def test_orchestrator_cannot_supply_capabilities_or_command(self):
        self._reject("controller.spawn", _spawn_params(capabilities=["SYS_ADMIN"]))
        self._reject("controller.spawn", _spawn_params(command=["/bin/sh"]))

    def test_unknown_method_rejected(self):
        self._reject("controller.docker_run", {"image": "evil"})

    def test_malformed_rpc_rejected(self):
        # an unknown params key fails the strict decoding
        with self.assertRaises(wire.WireError):
            _call(self.ep, "controller.spawn", {"fragment": {}, "envelope": {}, "x": 1})

    def test_unknown_handle_rejected(self):
        with self.assertRaises(wire.WireError):
            _call(self.ep, "controller.execute", {
                "handle_id": "rh-does-not-exist",
                "policy": {}, "envelope": {}, "fragment": {}, "intervention": None})


@unittest.skipIf(_SKIP, _REASON)
class ControllerHandleAndCrashTests(unittest.TestCase):
    """Opaque handles are single use, bound to their fragment and die with the controller."""

    def _dep(self):
        """Install a controller deployment and return (created, context, deployment)."""
        created = []

        def factory(clock, executor=None):
            dep = create_controller_deployment(clock, executor=executor)
            created.append(dep)
            return dep

        v3_scenarios.set_deployment_factory(factory)
        ctx = v3_scenarios.make_context()
        return created, ctx, created[-1]

    def test_opaque_handle_and_single_use(self):
        created, ctx, dep = self._dep()
        try:
            frag0 = v3_scenarios.honest_fragment(ctx.policy, ctx.run_id, 0,
                                                 happy_path_arguments()[0])
            handle = dep.provisioner.spawn(frag0, ctx.s0)
            self.assertTrue(handle.handle_id.startswith("rh-"))  # opaque id
            # the handle exposes no container id / credential / provisioning field
            self.assertFalse(any(k for k in vars(handle)
                                 if "cred" in k or "container" in k or "bootstrap" in k))
            result = handle.execute(ctx.policy, ctx.s0, frag0)
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
            # reuse of the same handle id is refused by the controller (consumed)
            with self.assertRaises(wire.WireError):
                _call(dep.provisioner._endpoint, "controller.execute", {
                    "handle_id": handle.handle_id,
                    "policy": {}, "envelope": {}, "fragment": {}, "intervention": None})
        finally:
            v3_scenarios.set_deployment_factory(None)
            for d in created:
                d.close()

    def test_handle_bound_to_one_fragment_cannot_run_another(self):
        # A handle provisioned for fragment A cannot run a different fragment B:
        # the runner's credential is bound to A's fragment_hash and state_hash, so
        # B is refused.
        created, ctx, dep = self._dep()
        try:
            args = happy_path_arguments()
            frag_a = v3_scenarios.honest_fragment(ctx.policy, ctx.run_id, 0, args[0])
            frag_b = v3_scenarios.honest_fragment(ctx.policy, ctx.run_id, 1, args[1])
            handle = dep.provisioner.spawn(frag_a, ctx.s0)
            result = handle.execute(ctx.policy, ctx.s0, frag_b)  # wrong fragment
            self.assertNotEqual(result.status, "STEP_COMPLETED", result.reason)
        finally:
            v3_scenarios.set_deployment_factory(None)
            for d in created:
                d.close()

    def test_handles_fail_after_the_controller_dies(self):
        created, ctx, dep = self._dep()
        try:
            frag0 = v3_scenarios.honest_fragment(ctx.policy, ctx.run_id, 0,
                                                 happy_path_arguments()[0])
            handle = dep.provisioner.spawn(frag0, ctx.s0)
            dep.controller.kill()  # the controller process dies and its handle map is lost
            # execute over the dead controller raises instead of hanging
            with self.assertRaises((OSError, wire.WireError, RuntimeError)):
                handle.execute(ctx.policy, ctx.s0, frag0)
        finally:
            v3_scenarios.set_deployment_factory(None)
            for d in created:
                d.close()


class ControllerStructureTests(unittest.TestCase):
    """Structural checks without Docker: the orchestrator side holds no provisioning
    authority and makes no Docker call."""

    def test_orchestrator_side_has_no_docker_call(self):
        import booking_v4.controller as controller_mod
        with open(controller_mod.__file__) as fh:
            src = fh.read()
        # The orchestrator-facing module does not invoke Docker and does not construct
        # the launch backend. That happens only in controller_process.py and
        # controller_k8s_process.py, in the separate controller process.
        self.assertNotIn('"docker"', src)
        self.assertNotIn("'docker'", src)
        self.assertNotIn("ContainerRunnerProvisioner(", src)

    def test_orchestrator_provisioner_holds_no_secret(self):
        prov = ControllerRunnerProvisioner("/tmp/nonexistent-controller.sock")
        held = set(vars(prov))
        for forbidden in ("bootstrap", "image", "credential", "anchors", "endpoint_secret"):
            self.assertFalse(any(forbidden in k for k in held),
                             f"provisioner must not hold {forbidden}: {held}")


@unittest.skipIf(_SKIP, _REASON)
class ControllerTrustDomainTests(unittest.TestCase):
    """The launch mechanism (provisioning authority) is not in the orchestrator's process.

    It lives only in the separate controller process.
    """

    def _dep(self):
        """Install a controller deployment and return (created, context, deployment)."""
        created = []

        def factory(clock, executor=None):
            dep = create_controller_deployment(clock, executor=executor)
            created.append(dep)
            return dep

        v3_scenarios.set_deployment_factory(factory)
        ctx = v3_scenarios.make_context()
        return created, ctx, created[-1]

    def test_harness_holds_no_launch_mechanism(self):
        created, ctx, dep = self._dep()
        try:
            # The harness-side service has no runner provisioner, so this process
            # cannot launch a runner. The only provisioner the orchestrator holds is
            # the narrow controller client.
            self.assertIsNone(dep._inner.provisioner)
            self.assertIsInstance(dep.provisioner, ControllerRunnerProvisioner)
            # That client can request a fixed-profile runner.
            frag0 = v3_scenarios.honest_fragment(ctx.policy, ctx.run_id, 0,
                                                 happy_path_arguments()[0])
            result = dep.provisioner.spawn(frag0, ctx.s0).execute(ctx.policy, ctx.s0, frag0)
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
        finally:
            v3_scenarios.set_deployment_factory(None)
            for d in created:
                d.close()

    def test_controller_runs_in_a_separate_process(self):
        created, ctx, dep = self._dep()
        try:
            self.assertTrue(dep.controller.alive)
            self.assertNotEqual(dep.controller.pid, os.getpid())  # a separate address space
        finally:
            v3_scenarios.set_deployment_factory(None)
            for d in created:
                d.close()

    def test_controller_rpc_is_transport_neutral_over_tcp(self):
        # Driving the controller over a TCP endpoint shows that the Kubernetes
        # deployment only swaps the launch backend (Docker for Kubernetes Job) and
        # points the orchestrator at a TCP Service endpoint. The controller contract
        # and RPC semantics stay the same.
        dep = create_controller_deployment(
            FixedClock(v3_scenarios.NOW), controller_bind=("tcp", "127.0.0.1", 0))
        try:
            self.assertEqual(dep.provisioner._endpoint.kind, "tcp")
            policy = default_p3()
            approval = v3_scenarios.approve(
                policy, approver_id=v3_scenarios.APPROVER_ID, approval_id="appr-ctcp",
                run_id="run-ctcp", issued_at=v3_scenarios.ISSUED_AT,
                expires_at=v3_scenarios.EXPIRES_AT)
            s0 = dep.authority.create_run(policy, approval, "run-ctcp")
            frag0 = v3_scenarios.honest_fragment(policy, "run-ctcp", 0,
                                                 happy_path_arguments()[0])
            result = dep.provisioner.spawn(frag0, s0).execute(policy, s0, frag0)
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
        finally:
            dep.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
