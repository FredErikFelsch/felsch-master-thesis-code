"""Harness for the durable container backend: the booking_v3 evaluation in hardened containers.

Runs the booking_v3 evaluation (scenario matrix, differential conformance against the in-process
monitor, dispatch safety) with every runner executing in one fresh, hardened OCI container per
fragment, on the durable Authority and gateway service stack. The runner speaks the wire protocol
over stdin and stdout and the bind-mounted deployment UDS. Equality is semantic (decisions,
rejection points, facts, lifecycle states, provenance, dispatch discipline), not byte, PID or
container identity.

Run from the repository root:  python3 -m booking_v4.experiment_container
"""

from __future__ import annotations

import hashlib
import json
import os

from booking_v3 import scenarios as v3_scenarios
from booking_v3 import experiment as v3_experiment
from booking_v3.policy import default_p3

from . import container_env
from .container_backend import (create_durable_container_deployment,
                                _resolve_image, _DEFAULT_IMAGE)


def run_all():
    """Run the booking_v3 evaluation with the durable container backend installed."""
    v3_scenarios.set_deployment_factory(create_durable_container_deployment)
    try:
        return v3_experiment.run_all()
    finally:
        v3_scenarios.set_deployment_factory(None)


def _link_environment(out_dir: str) -> None:
    """Name environment.json and its hash inside results.json, so a changed file is detectable.

    The record then states on its own which host verified the container boundary. This
    stays out of `run_manifest()`: the manifest describes the code and the policies of every
    record, while the host's ability to carry a unix socket through a bind mount is a
    property of this backend alone.
    """
    results_path = os.path.join(out_dir, "results.json")
    environment_path = os.path.join(out_dir, "environment.json")
    digest = hashlib.sha256(open(environment_path, "rb").read()).hexdigest()
    with open(results_path, encoding="utf-8") as fh:
        record = json.load(fh)
    record["environment"] = {"file": "environment.json", "sha256": digest}
    with open(results_path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, default=str)


def main():
    """Measure the host, refuse a host that cannot run this backend, then run and record.

    The environment is probed before the evaluation, not after: a record produced on a host
    whose bind mounts cannot carry a unix socket would be a record of a broken channel, not of
    the container backend. `environment.json` lands next to the results either way, so a reader
    can see which host verified this boundary.
    """
    policy = default_p3()
    environment = container_env.probe()
    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v4_container")
    container_env.write_record(out_dir, environment)
    if not environment.usable:
        raise SystemExit(f"refusing to record a container-backend run on this host: {environment.skip_reason}")
    image = _resolve_image(os.environ.get("RUNNER_IMAGE", _DEFAULT_IMAGE))
    results, diffs = run_all()
    print("BACKEND: durable hardened container (one clean OCI container per")
    print("         fragment on the durable Authority and gateway service,")
    print("         read-only rootfs, cap-drop ALL, --network none, non-root,")
    print("         the wire-1 protocol over stdin/stdout and a")
    print(f"         read-only bind-mounted deployment UDS)\n         image {image}")
    v3_experiment._print(policy, results, diffs)
    v3_experiment._write(policy, results, diffs, out_dir)
    _link_environment(out_dir)
    print(f"\nWrote results to {out_dir}/results.json, results.md and environment.json")
    print(f"HOST: {environment.host_platform} {environment.host_machine}, "
          f"docker {environment.docker_version} ({environment.storage_driver}), "
          f"unix socket over a bind mount: {environment.uds_bind_mount}")


if __name__ == "__main__":
    main()
