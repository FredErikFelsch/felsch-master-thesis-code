"""Harness for the process backend: the booking_v3 evaluation with one OS process per fragment.

Runs the booking_v3 evaluation (scenario matrix, differential conformance against the in-process
monitor, dispatch safety) with every runner executing as a fresh, exec-started OS process. The
trusted process provisioner starts it, and it speaks canonical JSON over stdin and stdout and the
local service socket. Nothing in the evaluation is backend-specific. Equality is semantic
(decisions, rejection points, facts, lifecycle states, provenance, dispatch discipline), not byte
or PID identity.

Run from the repository root:  python3 -m booking_v4.experiment
"""

from __future__ import annotations

import os

from booking_v3 import scenarios as v3_scenarios
from booking_v3 import experiment as v3_experiment
from booking_v3.policy import default_p3

from .process_backend import create_process_deployment


def run_all():
    """Run the booking_v3 evaluation with the process backend installed."""
    v3_scenarios.set_deployment_factory(create_process_deployment)
    try:
        return v3_experiment.run_all()
    finally:
        v3_scenarios.set_deployment_factory(None)


def main():
    """Run the evaluation and write the results to results_v4_process/ in the repository root."""
    policy = default_p3()
    results, diffs = run_all()
    print("BACKEND: fresh-process (one exec-started interpreter per fragment,")
    print("         wire-1 JSON over stdin/stdout and a local UDS service)")
    v3_experiment._print(policy, results, diffs)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v4_process")
    v3_experiment._write(policy, results, diffs, out_dir)
    print(f"\nWrote results to {out_dir}/results.json and results.md")


if __name__ == "__main__":
    main()
