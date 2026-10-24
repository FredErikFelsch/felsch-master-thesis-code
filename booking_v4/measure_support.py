"""Shared measurement helpers for the process and container backends.

The module imports no backend, so `process_backend` and `container_backend` can both use it
without an import cycle. Everything here serves measurement only and does not affect results.
"""

from __future__ import annotations

import select
import time

READY_MARKER = "TRACE ready"


def parse_trace(stderr: str) -> dict[str, int]:
    """Return the runner's monotonic phase markers from stderr, skipping malformed lines."""
    marks: dict[str, int] = {}
    for line in stderr.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "TRACE":
            try:
                marks[parts[1]] = int(parts[2])
            except ValueError:
                pass
    return marks


def phases(t0: int, t4: int, t5: int, marks: dict[str, int]) -> dict | None:
    """Compute the four-phase breakdown in nanoseconds, or None if a marker is missing.

    Boundaries (host-wide CLOCK_MONOTONIC):
        T0 parent begins runner creation      T3 execute() returned (postcall)
        T1 runner up and imported (ready)      T4 parent holds a valid result
        T2 inputs reconstructed (precall)      T5 runner removed or reaped

        cold_start = T1-T0   execution = T3-T2
        handoff    = (T2-T1)+(T4-T3)   teardown = T5-T4

    A clock inversion (a sign of a virtualised CLOCK_MONOTONIC) is returned as
    `{"clock_inversion": True, ...}` instead of a negative phase, and the
    callers drop that sample.
    """
    if not {"ready", "precall", "postcall"} <= marks.keys():
        return None
    t1, t2, t3 = marks["ready"], marks["precall"], marks["postcall"]
    if not (t0 <= t1 <= t2 <= t3 <= t4 <= t5):
        return {"clock_inversion": True,
                "t0": t0, "t1": t1, "t2": t2, "t3": t3, "t4": t4, "t5": t5}
    return {
        "cold_start_ns": t1 - t0,
        "handoff_in_ns": t2 - t1,
        "execution_ns": t3 - t2,
        "handoff_out_ns": t4 - t3,
        "handoff_ns": (t2 - t1) + (t4 - t3),
        "teardown_ns": t5 - t4,
        "total_ns": t5 - t0,
    }


def await_ready(process, timeout: float) -> str:
    """Block until the child writes its ``ready`` marker on stderr, at most `timeout` seconds.

    Session establishment and provisioning run only after the child is up, so
    in measurement mode they fall in handoff-in (T2-T1) and not in cold start
    (T1-T0). `select` sees only data that has not yet reached the text
    buffer, so this relies on the runner writing the ready marker as its first
    stderr line (`runner_process._trace`), with nothing behind it until it has
    read its input.

    Returns:
        The stderr text consumed up to and including the ready line, which the
        caller prepends to what the later collection reads.

    Raises:
        RuntimeError: The timeout passed, or the child exited before signalling ready.
    """
    buf: list[str] = []
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("runner did not signal ready within timeout")
        readable, _, _ = select.select([process.stderr], [], [], remaining)
        if not readable:
            continue
        line = process.stderr.readline()
        if line == "":
            raise RuntimeError("runner exited before signalling ready")
        buf.append(line)
        if READY_MARKER in line:
            return "".join(buf)
