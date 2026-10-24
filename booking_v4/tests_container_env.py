"""Tests that the environment probe does not turn real failures into skips.

`container_env` lets the container suites skip on a host that cannot pass a unix socket through a
bind mount. That is a legitimate environment limit, and a check of this kind hides regressions if
it is written loosely. These tests pin the narrow reading: EOPNOTSUPP is the only unsupported
verdict, every other outcome raises, and a record of what was measured is written next to the
results.

They need no docker daemon, because the probe's one external call is replaced.

Run from the repository root:  python3 -m booking_v4.tests_container_env
"""
from __future__ import annotations

import errno
import json
import subprocess
import tempfile
import unittest
from unittest import mock

from . import container_env
from .container_env import _UDS_UNSUPPORTED, ContainerEnvironment

#: Errno values that are not the container's EOPNOTSUPP and therefore have to raise. macOS
#: numbers EOPNOTSUPP 102 and Linux numbers it 95, so the host's own symbol is the wrong value
#: to compare with a number a Linux container printed. 102 is in this list for that reason:
#: on a macOS host it is what `errno.EOPNOTSUPP` would have yielded.
_OTHER_ERRNOS = (errno.EACCES, errno.ENOENT, errno.ECONNREFUSED, 102)


def _completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    """Return a fake result of the docker probe."""
    return subprocess.CompletedProcess(args=["docker"], returncode=returncode, stdout=stdout, stderr=stderr)


def _environment(**changes) -> ContainerEnvironment:
    """Return a usable environment with the given fields changed."""
    base = dict(docker_version="29.0.0", storage_driver="overlayfs", image="sha256:" + "a" * 64,
                uds_bind_mount=True, uds_detail="probed", host_platform="Linux",
                host_release="6.0", host_machine="x86_64", python="3.11.0")
    base.update(changes)
    return ContainerEnvironment(**base)


class UnsupportedIsExactlyOneErrno(unittest.TestCase):
    """The skip verdict is reachable by one errno and by nothing else."""

    def test_a_connecting_container_is_supported(self):
        with mock.patch.object(subprocess, "run", return_value=_completed(0, "CONNECTED\n")):
            supported, detail = container_env.uds_bind_mount_supported("img")
        self.assertTrue(supported)
        self.assertIn("connected", detail)

    def test_eopnotsupp_is_the_unsupported_verdict(self):
        out = _completed(1, f"ERRNO {_UDS_UNSUPPORTED}\n")
        with mock.patch.object(subprocess, "run", return_value=out):
            supported, detail = container_env.uds_bind_mount_supported("img")
        self.assertFalse(supported)
        self.assertIn(str(_UDS_UNSUPPORTED), detail)

    def test_the_sentinel_is_the_containers_errno_not_the_hosts(self):
        """The number is printed inside a Linux container, so it is 95 on every host. Taking it
        from the host libc would make the check wrong on the host it exists for: macOS numbers
        EOPNOTSUPP 102, so the real refusal would raise instead of skipping."""
        self.assertEqual(_UDS_UNSUPPORTED, 95)

    def test_another_errno_raises_instead_of_skipping(self):
        """A permission problem or a missing mount is a defect, not an environment limit."""
        for code in _OTHER_ERRNOS:
            with self.subTest(errno=code):
                out = _completed(1, f"ERRNO {code}\n")
                with mock.patch.object(subprocess, "run", return_value=out):
                    with self.assertRaises(RuntimeError):
                        container_env.uds_bind_mount_supported("img")

    def test_a_container_that_did_not_start_raises(self):
        out = _completed(125, "", "docker: Error response from daemon: no such image\n")
        with mock.patch.object(subprocess, "run", return_value=out):
            with self.assertRaises(RuntimeError):
                container_env.uds_bind_mount_supported("img")

    def test_a_silent_success_is_not_a_success(self):
        """Exit code 0 without the word the probe prints says nothing about the socket."""
        with mock.patch.object(subprocess, "run", return_value=_completed(0, "")):
            with self.assertRaises(RuntimeError):
                container_env.uds_bind_mount_supported("img")


class SkipReasonNamesTheCause(unittest.TestCase):
    """A skipped suite has to say which of the three preconditions failed."""

    def test_a_usable_host_has_no_reason(self):
        env = _environment()
        self.assertTrue(env.usable)
        self.assertEqual(env.skip_reason, "")

    def test_no_daemon_says_so(self):
        env = _environment(docker_version=None, image=None, uds_bind_mount=None)
        self.assertFalse(env.usable)
        self.assertIn("docker daemon", env.skip_reason)

    def test_an_unresolvable_image_says_so(self):
        env = _environment(image=None, uds_bind_mount=None)
        self.assertFalse(env.usable)
        self.assertIn("does not resolve", env.skip_reason)

    def test_a_host_without_socket_bind_mounts_names_the_file_sharing_driver(self):
        env = _environment(uds_bind_mount=False, uds_detail="connect() returned EOPNOTSUPP",
                           host_platform="Darwin")
        self.assertFalse(env.usable)
        self.assertIn("unix socket", env.skip_reason)
        self.assertIn("gRPC FUSE", env.skip_reason)
        self.assertIn("Darwin", env.skip_reason)


class TheRecordSaysWhereItRan(unittest.TestCase):
    """environment.json is provenance: it carries the verdict and the host that gave it."""

    def test_the_record_round_trips_and_carries_the_verdict(self):
        env = _environment()
        with tempfile.TemporaryDirectory() as directory:
            path = container_env.write_record(directory, env)
            data = json.loads(path.read_text())
        self.assertEqual(path.name, "environment.json")
        self.assertEqual(data["environment_version"], 1)
        self.assertTrue(data["usable"])
        self.assertEqual(data["skip_reason"], "")
        for key in ("docker_version", "storage_driver", "image", "uds_bind_mount",
                    "host_platform", "host_release", "host_machine", "python", "recorded_at"):
            self.assertIn(key, data, key)

    def test_an_unusable_host_is_recorded_as_unusable_not_omitted(self):
        """The record exists so that 'not verified here' is readable and not missing."""
        env = _environment(uds_bind_mount=False, uds_detail="EOPNOTSUPP", host_platform="Darwin")
        with tempfile.TemporaryDirectory() as directory:
            data = json.loads(container_env.write_record(directory, env).read_text())
        self.assertFalse(data["usable"])
        self.assertFalse(data["uds_bind_mount"])
        self.assertNotEqual(data["skip_reason"], "")


class ProbeDoesNotProbeWhatItCannotReach(unittest.TestCase):
    """Without a daemon the socket probe is not attempted."""

    def test_without_a_daemon_the_socket_is_not_probed(self):
        with mock.patch.object(container_env, "docker_version", return_value=(None, None)), \
             mock.patch.object(container_env, "uds_bind_mount_supported") as probe:
            env = container_env.probe()
        probe.assert_not_called()
        self.assertIsNone(env.uds_bind_mount)
        self.assertEqual(env.uds_detail, "not probed")
        self.assertFalse(env.usable)


if __name__ == "__main__":
    unittest.main(verbosity=2)
