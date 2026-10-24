r"""Harness for the Kubernetes backend: the booking_v3 evaluation with one Job per fragment.

Runs the booking_v3 evaluation (scenario matrix, differential conformance against the in-process
monitor, dispatch safety) with every runner executing as one fresh, short-lived Kubernetes Job per
fragment, on the durable Authority and gateway service reached over TCP. The runner
(`runner_process.py`), the wire protocol, the controller contract and the service semantics are
unchanged. Only the launch substrate (Docker container or Kubernetes Job) differs. Equality is
semantic (decisions, rejection points, facts, lifecycle states, provenance, dispatch discipline),
not byte, PID, container or pod identity.

This run needs a real cluster, the `kubernetes` client and `RUNNER_IMAGE` and
`K8S_AUTHORITY_ADVERTISE` set. It is invoked by the cluster scripts under `scripts/gke`, not
offline. See `k8s_deployment.py` for the boundary between this semantic-equivalence run and the
enforcement suite in `tests_k8s.py`.

Run (live, from the repository root, with the cluster reachable):
    RUNNER_IMAGE=REG/runner@sha256:... K8S_AUTHORITY_ADVERTISE=HOST:PORT \
        python3 -m booking_v4.experiment_k8s
"""

from __future__ import annotations

import os

from booking_v3 import scenarios as v3_scenarios
from booking_v3 import experiment as v3_experiment
from booking_v3.policy import default_p3

from .k8s_deployment import create_k8s_deployment


def run_all():
    """Run the booking_v3 evaluation with the Kubernetes launch backend installed."""
    v3_scenarios.set_deployment_factory(create_k8s_deployment)
    try:
        return v3_experiment.run_all()
    finally:
        v3_scenarios.set_deployment_factory(None)


def _load_kube_config() -> str:
    """Load the in-cluster ServiceAccount config (the eval Job), else the local kubeconfig. Return which."""
    from kubernetes import config as kconfig
    try:
        kconfig.load_incluster_config()
        return "in-cluster"
    except kconfig.ConfigException:
        kconfig.load_kube_config()
        return "kubeconfig"


def main():
    """Load the cluster config, run the evaluation and write the results."""
    where = _load_kube_config()
    print(f"kubernetes client config: {where}")
    policy = default_p3()
    results, diffs = run_all()
    print("BACKEND: Kubernetes Job (one fresh, hardened, short-lived Job per")
    print("         fragment, fixed launch profile independent of the fragment,")
    print("         stdin/stdout over pods/attach, durable Authority and gateway")
    print("         over TCP, runner-sa without an API token, network-confined)")
    image = os.environ.get("RUNNER_IMAGE", "<unset>")
    print(f"         runner image {image}")
    v3_experiment._print(policy, results, diffs)
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v4_k8s")
    v3_experiment._write(policy, results, diffs, out_dir)
    print(f"\nWrote results to {out_dir}/results.json and results.md")


if __name__ == "__main__":
    main()
