"""Container backend preconditions, probed rather than assumed.

Three things have to hold before the container suites mean anything: a reachable Docker
daemon, a runner image that resolves to a content digest, and a bind-mounted directory whose
filesystem carries Unix domain sockets. The third one is the reason this module exists.

The provisioner hands the runner its deployment socket as a read-only bind mount, and the
runner connects to it from inside the container. The container runs with `--network none`, so
besides stdin and stdout this socket is the runner's only channel to the outside, and the
isolation argument rests on there being no second one. On Linux the bind mount is a real
kernel filesystem and the connect succeeds. Docker Desktop on macOS passes the directory
through a file-sharing driver instead, and VirtioFS refuses `connect()` on an AF_UNIX socket
with `EOPNOTSUPP` (errno 95). The suites then fail on every test that starts a runner, while
the ones that only read `docker inspect` stay green, which reads like a protocol regression
and is not one.

So the precondition is probed, and only `EOPNOTSUPP` on the connect counts as an
environment limit. Every other failure stays a failure, because a skip that swallowed
arbitrary errors would hide the regressions these suites are meant to catch.

The probe result is also a record. `write_record` writes `environment.json` next to the
container results, so a reader can see on which host the container boundary was verified.

    python3 -m booking_v4.container_env            # print the probe, write nothing
"""
from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import platform
import socket
import subprocess
import sys
import tempfile
import threading
import time

from .container_backend import _DEFAULT_IMAGE, _resolve_image

#: EOPNOTSUPP as the Linux container reports it (95). The probe runs inside the runner image,
#: so the number is Linux's whatever the host is. The host's own `errno.EOPNOTSUPP` would be
#: 102 on macOS, the host this check exists for, so the value is written out.
_UDS_UNSUPPORTED = 95

#: The script the probe container runs: connect to the mounted socket and report the result.
_PROBE_SCRIPT = (
    "import socket, sys\n"
    "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
    "try:\n"
    "    s.connect('/sock/probe.sock')\n"
    "except OSError as exc:\n"
    "    print('ERRNO', exc.errno)\n"
    "    sys.exit(1)\n"
    "print('CONNECTED')\n"
)


@dataclasses.dataclass(frozen=True)
class ContainerEnvironment:
    """What the host can do, as measured, plus the reason a suite would not run here."""

    docker_version: str | None
    storage_driver: str | None
    image: str | None
    uds_bind_mount: bool | None          # None: not probed, because docker or the image is missing
    uds_detail: str
    host_platform: str
    host_release: str
    host_machine: str
    python: str

    @property
    def usable(self) -> bool:
        """Return True when a container suite can run here, so a red test means a real defect."""
        return bool(self.docker_version and self.image and self.uds_bind_mount)

    @property
    def skip_reason(self) -> str:
        """Return an empty string when usable, otherwise the reason a skipped test carries."""
        if not self.docker_version:
            return "no reachable docker daemon"
        if not self.image:
            return f"runner image {os.environ.get('RUNNER_IMAGE', _DEFAULT_IMAGE)} does not resolve to a digest"
        if self.uds_bind_mount is False:
            return (f"this host cannot pass a unix socket through a bind mount ({self.uds_detail}). "
                    "The container backend needs a docker host whose bind mounts lie on a "
                    f"filesystem that carries AF_UNIX, which on {self.host_platform} Docker Desktop "
                    "means the gRPC FUSE file sharing implementation, not VirtioFS")
        return ""

    def to_json(self) -> dict:
        """Return the record written to `environment.json`, with a timestamp."""
        return {"environment_version": 1, "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                **dataclasses.asdict(self), "usable": self.usable, "skip_reason": self.skip_reason}


def docker_version() -> tuple[str | None, str | None]:
    """Return (server version, storage driver) of a reachable daemon, (None, None) otherwise."""
    try:
        out = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}\t{{.Driver}}"],
                             capture_output=True, text=True, timeout=15)
    except Exception:                                                        # noqa: BLE001
        return None, None
    if out.returncode != 0 or not out.stdout.strip():
        return None, None
    parts = (out.stdout.strip().split("\t") + [""])[:2]
    return parts[0] or None, parts[1] or None


def resolved_image() -> str | None:
    """Return the runner image pinned to its content digest, or None if it does not resolve."""
    try:
        return _resolve_image(os.environ.get("RUNNER_IMAGE", _DEFAULT_IMAGE))
    except Exception:                                                        # noqa: BLE001
        return None


def uds_bind_mount_supported(image: str) -> tuple[bool, str]:
    """Bind-mount a directory holding a live unix socket and connect to it from a container.

    Returns:
        (supported, detail). `supported` is False only when the container's connect fails
        with EOPNOTSUPP, which is the file-sharing driver refusing AF_UNIX.

    Raises:
        RuntimeError: Any other failure, because an unexplained failure here must not read
            as an environment limit.
    """
    directory = tempfile.mkdtemp(prefix="uds-probe-")
    os.chmod(directory, 0o755)
    path = os.path.join(directory, "probe.sock")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(path)
        server.listen(1)
        os.chmod(path, 0o666)
        accepted = threading.Thread(target=_accept_once, args=(server,), daemon=True)
        accepted.start()
        out = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "-v", f"{directory}:/sock:ro",
             "--entrypoint", "/usr/bin/python3", image, "-c", _PROBE_SCRIPT],
            capture_output=True, text=True, timeout=120)
        text = (out.stdout + out.stderr).strip()
        if out.returncode == 0 and "CONNECTED" in out.stdout:
            return True, "a container connected to a bind-mounted unix socket"
        if f"ERRNO {_UDS_UNSUPPORTED}" in out.stdout:
            return False, f"connect() returned EOPNOTSUPP (errno {_UDS_UNSUPPORTED}) inside the container"
        raise RuntimeError(f"unix socket probe failed for an unexpected reason (rc={out.returncode}): {text[-400:]}")
    finally:
        server.close()
        try:
            os.unlink(path)
        except OSError:
            pass
        try:
            os.rmdir(directory)
        except OSError:
            pass


def _accept_once(server: socket.socket) -> None:
    """Accept a single probe connection and drop it. The probe itself judges a failure."""
    try:
        connection, _ = server.accept()
        connection.close()
    except OSError:
        pass


def probe() -> ContainerEnvironment:
    """Measure the host once. The probe is cheap enough to run when a test module is imported."""
    version, driver = docker_version()
    image = resolved_image() if version else None
    supported: bool | None = None
    detail = "not probed"
    if version and image:
        supported, detail = uds_bind_mount_supported(image)
    return ContainerEnvironment(
        docker_version=version, storage_driver=driver, image=image,
        uds_bind_mount=supported, uds_detail=detail,
        host_platform=platform.system(), host_release=platform.release(),
        host_machine=platform.machine(), python=platform.python_version())


def write_record(out_dir: str | os.PathLike[str], environment: ContainerEnvironment | None = None) -> pathlib.Path:
    """Write `environment.json` into `out_dir` and return its path."""
    environment = environment or probe()
    directory = pathlib.Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "environment.json"
    path.write_text(json.dumps(environment.to_json(), indent=2) + "\n", encoding="utf-8")
    return path


def main() -> int:
    """Print the probe as JSON. Exit status 0 when a container suite can run here."""
    environment = probe()
    json.dump(environment.to_json(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if environment.usable else 1


if __name__ == "__main__":
    raise SystemExit(main())
