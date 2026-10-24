"""Harness for the separated runner controller: the booking_v3 evaluation with a controller process.

Runs the booking_v3 evaluation (scenario matrix, differential conformance, dispatch safety) with
provisioning moved into a separate trusted controller process. The orchestrator drives the
narrow controller client as it drove any provisioner, and only the party that provisions
changed. The semantics are unchanged, so the results have to compare equal to those of the
container, durable and process backends.

Run from the repository root:  python3 -m booking_v4.experiment_controller
"""

from __future__ import annotations

import os

from booking_v3 import scenarios as v3_scenarios
from booking_v3 import experiment as v3_experiment
from booking_v3.policy import default_p3

from .controller import create_controller_deployment


def run_all():
    """Run the booking_v3 evaluation with the controller backend installed."""
    v3_scenarios.set_deployment_factory(create_controller_deployment)
    try:
        return v3_experiment.run_all()
    finally:
        v3_scenarios.set_deployment_factory(None)


def main():
    """Run the evaluation and write the results to results_v4_controller/ in the repository root."""
    policy = default_p3()
    results, diffs = run_all()
    print("BACKEND: separated trusted runner controller (provisioning in its own")
    print("         OS process, the orchestrator holds only a narrow spawn/execute RPC")
    print("         returning an opaque handle, container lifecycle underneath)")
    v3_experiment._print(policy, results, diffs)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v4_controller")
    v3_experiment._write(policy, results, diffs, out_dir)
    print(f"\nWrote results to {out_dir}/results.json and results.md")


if __name__ == "__main__":
    main()
