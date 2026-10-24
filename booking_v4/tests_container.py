"""Container isolation tests: check that the runner container is configured as documented.

The scenario matrix plus differential conformance and dispatch safety show that the protocol
semantics are unchanged on the container backend. They do not show that the container is
hardened. This suite inspects a live runner container and its runtime configuration, and it
exercises the lifecycle guarantees of the provisioner. Every test is skipped
cleanly when Docker or the runner image is unavailable, and when the host cannot pass a unix socket
through a bind mount, so the suite is safe to run anywhere. `container_env` measures those three
preconditions instead of assuming them, and records what it measured.

Run from the repository root:  python3 -m booking_v4.tests_container
"""

from __future__ import annotations

import os
import socket
import subprocess
import tempfile
import unittest

from booking_v3 import scenarios as v3_scenarios

from . import container_env, wire
from .container_backend import (_DEFAULT_IMAGE, _hardening_flags, _inspect_running,
                                _resolve_image,
                                _remove_container,
                                create_container_deployment,
                                create_durable_container_deployment)


#: Measured once per interpreter: docker, the image, and whether a bind-mounted unix socket
#: can be connected to from inside a container. The socket is the isolation channel of this
#: backend, so a host without it cannot run these tests at all. See booking_v4.container_env.
_ENV = container_env.probe()
_SKIP = not _ENV.usable
_REASON = _ENV.skip_reason
_IMAGE = _ENV.image or ""


def _new_sock_dir() -> str:
    """Create a socket directory the container UID can traverse."""
    d = tempfile.mkdtemp(prefix="ctr-test-sock-")
    os.chmod(d, 0o755)
    return d


def _probe(pyscript: str, sock_dir: str | None = None) -> subprocess.CompletedProcess:
    """Run a python probe inside the hardened runner image and return the result.

    Uses the hardening flags of the provisioner and overrides only the entrypoint,
    so the probe can report the container's own configuration.
    """
    sd = sock_dir or _new_sock_dir()
    cmd = (["docker", "run", "--rm", "-i", "--entrypoint", "/usr/bin/python3"]
           + _hardening_flags(sd, trace=False) + [_IMAGE, "-c", pyscript])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def _inspect_created(fmt: str) -> str:
    """Create (not start) a container with the full hardening profile and inspect it.

    Inspecting the runtime configuration is stronger than an in-container write
    attempt: a write can fail merely because root owns the path with mode 0755, so
    it would pass even if --read-only or :ro had been dropped.
    """
    name = "ctr-test-cfg-" + os.urandom(4).hex()
    sd = _new_sock_dir()
    create = (["docker", "create", "--name", name]
              + _hardening_flags(sd, trace=False) + [_IMAGE])
    try:
        subprocess.run(create, capture_output=True, text=True, check=True)
        out = subprocess.run(["docker", "inspect", "-f", fmt, name],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    finally:
        _remove_container(name)


@unittest.skipIf(_SKIP, _REASON)
class ContainerHardeningTests(unittest.TestCase):
    """Inspect the runtime configuration of a live runner container."""

    def test_uid_is_non_root(self):
        r = _probe("import os; print(os.getuid())")
        self.assertEqual(r.stdout.strip(), "65532", r.stderr)

    def test_rootfs_read_only_configured(self):
        # The runtime flag itself, not only a failed write.
        self.assertEqual(_inspect_created("{{.HostConfig.ReadonlyRootfs}}"), "true")

    def test_sock_mount_read_only_configured(self):
        # Every bind mount's RW flag must be false (the UDS is connect-only).
        mounts = _inspect_created("{{range .Mounts}}{{.Destination}}={{.RW}};{{end}}")
        self.assertIn("/sock=false", mounts, mounts)

    def test_rootfs_is_read_only(self):
        # Additional in-container evidence, kept alongside the config check.
        r = _probe(
            "try:\n"
            "  open('/rootfs_canary','w').write('x'); print('WRITABLE')\n"
            "except OSError: print('READONLY')\n")
        self.assertEqual(r.stdout.strip(), "READONLY", r.stderr)

    def test_all_capabilities_dropped(self):
        r = _probe(
            "print([l.split()[1] for l in open('/proc/self/status') "
            "if l.startswith('CapEff:')][0])")
        self.assertEqual(r.stdout.strip(), "0000000000000000", r.stderr)

    def test_no_new_privileges(self):
        r = _probe(
            "print([l.split()[1] for l in open('/proc/self/status') "
            "if l.startswith('NoNewPrivs:')][0])")
        self.assertEqual(r.stdout.strip(), "1", r.stderr)

    def test_no_docker_socket_visible(self):
        r = _probe("import os; print(os.path.exists('/var/run/docker.sock'))")
        self.assertEqual(r.stdout.strip(), "False", r.stderr)

    def test_host_environment_canary_not_leaked(self):
        # A secret set in the provisioner's environment must not reach the runner.
        os.environ["HOST_SECRET_CANARY"] = "top-secret-42"
        try:
            r = _probe("import os; print('HOST_SECRET_CANARY' in os.environ)")
        finally:
            os.environ.pop("HOST_SECRET_CANARY", None)
        self.assertEqual(r.stdout.strip(), "False", r.stderr)

    def test_host_file_canary_not_visible(self):
        fd, path = tempfile.mkstemp(prefix="host_canary_")
        os.write(fd, b"secret")
        os.close(fd)
        try:
            r = _probe(f"import os; print(os.path.exists({path!r}))")
            self.assertEqual(r.stdout.strip(), "False", r.stderr)
        finally:
            os.unlink(path)

    def test_sock_mount_is_not_writable(self):
        # The UDS is bind-mounted read-only: the runner may connect() but not create files.
        sd = _new_sock_dir()
        r = _probe(
            "import sys\n"
            "try:\n"
            "  open('/sock/newfile','w').write('x'); print('WRITABLE')\n"
            "except OSError: print('READONLY')\n", sock_dir=sd)
        self.assertEqual(r.stdout.strip(), "READONLY", r.stderr)

    def test_network_mode_is_none(self):
        name = "ctr-test-net-" + os.urandom(4).hex()
        sd = _new_sock_dir()
        cmd = (["docker", "create", "--name", name]
               + _hardening_flags(sd, trace=False) + [_IMAGE])
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=True)
            out = subprocess.run(
                ["docker", "inspect", "-f", "{{.HostConfig.NetworkMode}}", name],
                capture_output=True, text=True, check=True)
            self.assertEqual(out.stdout.strip(), "none")
        finally:
            _remove_container(name)


@unittest.skipIf(_SKIP, _REASON)
class ContainerLifecycleTests(unittest.TestCase):
    """Exercise the provisioner's per-fragment container lifecycle guarantees."""

    def test_one_container_per_fragment_all_removed_on_success(self):
        created = []

        def factory(clock, executor=None):
            dep = create_durable_container_deployment(clock, executor=executor)
            created.append(dep)
            return dep

        v3_scenarios.set_deployment_factory(factory)
        try:
            out = v3_scenarios.benign_happy_path()
        finally:
            v3_scenarios.set_deployment_factory(None)
        self.assertEqual(out.final_status, "COMPLETED")
        dep = created[-1]
        prov = dep.provisioner
        try:
            self.assertEqual(len(prov.spawned_names), 4)  # one per fragment
            self.assertTrue(all(h.removed for h in prov._handles))
            for name in prov.spawned_names:  # verified gone from the daemon
                self.assertIsNone(_inspect_running(name))
        finally:
            dep.close()

    def test_container_removed_on_failure_path(self):
        # Force the timeout branch on a live handle: execute() raises RuntimeError
        # and still removes the container on the finally path.
        from booking_v3.orchestrator import happy_path_arguments
        created = []

        def factory(clock, executor=None):
            dep = create_durable_container_deployment(clock, executor=executor)
            created.append(dep)
            return dep

        v3_scenarios.set_deployment_factory(factory)
        try:
            ctx = v3_scenarios.make_context()
            frag = v3_scenarios.honest_fragment(
                ctx.policy, ctx.run_id, 0, happy_path_arguments()[0])
            handle = ctx.provisioner.spawn(frag, ctx.s0)
            name = ctx.provisioner.spawned_names[-1]
            handle._timeout = 0.05  # force a deterministic timeout failure
            with self.assertRaises(RuntimeError):
                handle.execute(ctx.policy, ctx.s0, frag)
            self.assertTrue(handle.removed)
            self.assertIsNone(_inspect_running(name))
        finally:
            v3_scenarios.set_deployment_factory(None)
            for dep in created:
                dep.close()

    def test_remove_container_is_idempotent(self):
        # Tearing down a container that is already gone is not an error
        # (docker rm -f exits 0 for a missing one, or reports "No such container").
        self.assertIn(_remove_container("definitely-not-a-real-container-xyz"),
                      ("removed", "absent"))

    def test_image_pinning_refuses_a_missing_image(self):
        digest = _resolve_image(os.environ.get("RUNNER_IMAGE", _DEFAULT_IMAGE))
        self.assertTrue(digest.startswith("sha256:"))
        with self.assertRaises(RuntimeError):
            _resolve_image("thesis/does-not-exist:nope")


@unittest.skipIf(_SKIP, _REASON)
class ContainerInvarianceAndAuthTests(unittest.TestCase):
    """Timing must not change results, and an open socket must not grant authority."""

    def test_timing_on_off_result_invariance(self):
        def run_once() -> tuple:
            created = []

            def factory(clock, executor=None):
                dep = create_durable_container_deployment(clock, executor=executor)
                created.append(dep)
                return dep

            v3_scenarios.set_deployment_factory(factory)
            try:
                out = v3_scenarios.benign_happy_path()
            finally:
                v3_scenarios.set_deployment_factory(None)
                for dep in created:
                    dep.close()
            return out.final_status, tuple(out.statuses), tuple(out.executed_ops)

        os.environ.pop("CONTAINER_RUNNER_TRACE", None)
        off = run_once()
        os.environ["CONTAINER_RUNNER_TRACE"] = "1"
        try:
            on = run_once()
        finally:
            os.environ.pop("CONTAINER_RUNNER_TRACE", None)
        self.assertEqual(off, on)  # tracing is non-semantic

    def test_open_socket_without_credential_grants_no_authority(self):
        # Any local user may connect to the socket (mode 0666). The RunnerCredential,
        # not the connect permission, is the boundary: a connector with a forged
        # credential obtains no grant. The request carries the full key set, so it
        # reaches the credential decoder instead of failing on the key set.
        from booking_v1.clock import FixedClock
        dep = create_container_deployment(FixedClock(1_000))
        try:
            sock_path = dep.server.socket_path
            request = {
                "v": wire.WIRE_VERSION, "method": "authority.request_execution_grant",
                "request_id": "attacker-1",
                "params": {
                    "credential": {"forged": True}, "fragment": {"forged": True},
                    "input_state_hash": "deadbeef",
                    "admission_event": {"op": "pay"}, "intervention": None,
                    "attestation": None}}
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                s.connect(sock_path)
                s.sendall((wire.encode(request) + "\n").encode())
                s.shutdown(socket.SHUT_WR)
                raw = b""
                while not raw.endswith(b"\n"):
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    raw += chunk
            reply = wire.decode_line(raw.decode())
            # The strict decoder refuses the forged credential, so there is no grant.
            self.assertIsNone(reply.get("grant"))
            self.assertIn("runner-credential", reply.get("error", ""), reply)
        finally:
            dep.close()


@unittest.skipIf(_SKIP, _REASON)
class ContainerServiceRestartTests(unittest.TestCase):
    """A running container keeps its socket address across a durable service restart."""

    def test_running_container_survives_service_restart(self):
        # Spawn a container and complete its provisioning, restart Authority and
        # gateway, then execute over the same running container. Both happen on the
        # same /sock/authority.sock.
        from booking_v3.orchestrator import happy_path_arguments
        created = []

        def factory(clock, executor=None):
            dep = create_durable_container_deployment(clock, executor=executor)
            created.append(dep)
            return dep

        v3_scenarios.set_deployment_factory(factory)
        try:
            ctx = v3_scenarios.make_context()
            dep = created[-1]
            frag0 = v3_scenarios.honest_fragment(
                ctx.policy, ctx.run_id, 0, happy_path_arguments()[0])
            handle = ctx.provisioner.spawn(frag0, ctx.s0)  # running + provisioned
            name = ctx.provisioner.spawned_names[-1]
            self.assertEqual(_inspect_running(name), "running")

            dep.restart_services()  # rebuild from the store and bind the same socket again

            result = handle.execute(ctx.policy, ctx.s0, frag0)  # same container
            self.assertEqual(result.status, "STEP_COMPLETED", result.reason)
            self.assertIsNone(_inspect_running(name))  # torn down after execute
        finally:
            v3_scenarios.set_deployment_factory(None)
            for dep in created:
                dep.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
