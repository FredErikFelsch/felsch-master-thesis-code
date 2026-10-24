"""Harness for the durable process backend: the booking_v3 evaluation on the durable service.

Besides the scenarios it records one negative result, acceptance label A21 (listed in
ENVIRONMENT.md): a second service process on a live store is refused.

Run from the repository root:  python3 -m booking_v4.experiment_durable
"""

from __future__ import annotations

import json
import os

from booking_v3 import scenarios as v3_scenarios
from booking_v3 import experiment as v3_experiment
from booking_v3.policy import default_p3

from .durable import DurableStore, create_durable_process_deployment


def run_all():
    """Run the booking_v3 evaluation with the durable process backend installed."""
    v3_scenarios.set_deployment_factory(create_durable_process_deployment)
    try:
        return v3_experiment.run_all()
    finally:
        v3_scenarios.set_deployment_factory(None)


def second_writer_refused() -> dict:
    """Start two service processes on one store and record what happens.

    The second has to stop before it reads a row (exit 3, StoreBusy), the first has to
    keep serving, and after the first dies the store has to be free again.

    Returns:
        The record, stored as a negative result next to the scenarios.
    """
    import subprocess
    import sys
    import tempfile
    from booking_v4.services import _call
    repo_root = os.path.dirname(os.path.dirname(__file__))
    tmp = tempfile.mkdtemp(prefix="durable-two-writers-")
    db = os.path.join(tmp, "deployment.db")

    def start(sock):
        """Start one service process on the shared store."""
        return subprocess.Popen([sys.executable, "-m", "booking_v4.service_process", "--db", db,
                                 "--socket", sock, "--now", str(v3_scenarios.NOW)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=repo_root, text=True)
    first = start(os.path.join(tmp, "a.sock"))
    handshake = json.loads(first.stdout.readline())
    second = start(os.path.join(tmp, "b.sock"))
    try:
        second_rc = second.wait(timeout=30)
        # The refusal names the lock file inside the temporary directory. The directory differs
        # per machine (and /var against /private/var on macOS), so the record keeps a placeholder.
        second_err = second.stderr.read().strip()
        for local in sorted({os.path.realpath(tmp), tmp}, key=len, reverse=True):
            second_err = second_err.replace(local, "<tmp>")
        # the first still answers on its socket (a read-only, identity-free call)
        alive = first.poll() is None
        try:
            reply = _call(handshake["socket"], "gateway.ledger_watermark", {})
            first_serves = "seq" in reply
        except Exception as exc:                                       # noqa: BLE001
            first_serves, reply = False, str(exc)
    finally:
        first.kill()
        first.wait()
        if second.poll() is None:
            second.kill()
            second.wait()
    released = False
    try:
        DurableStore(db).close()
        released = True
    except Exception:                                                  # noqa: BLE001
        pass
    record = {"name": "A21-second-writer-refused", "second_exit_code": second_rc,
              "second_stderr": second_err[:200], "first_alive_meanwhile": alive,
              "first_served_meanwhile": first_serves, "store_released_after_first_died": released}
    record["pass"] = second_rc == 3 and "single-writer" in second_err and alive and first_serves and released
    return record


def main():
    """Run the evaluation, add the second-writer record and write the results."""
    policy = default_p3()
    results, diffs = run_all()
    print("BACKEND: durable fresh-process (SQLite-backed Authority and gateway service,")
    print("         reply-iff-persisted, deterministic idempotency identities)")
    v3_experiment._print(policy, results, diffs)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v4_durable")
    v3_experiment._write(policy, results, diffs, out_dir)
    negative = second_writer_refused()
    print(f"\nA21 second writer refused: {negative['pass']}  (exit {negative['second_exit_code']}, "
          f"first served meanwhile: {negative['first_served_meanwhile']})")
    path = os.path.join(out_dir, "results.json")
    with open(path, encoding="utf-8") as fh:
        record = json.load(fh)
    record["negative"] = [negative]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, default=str)
    print(f"\nWrote results to {out_dir}/results.json and results.md")


if __name__ == "__main__":
    main()
