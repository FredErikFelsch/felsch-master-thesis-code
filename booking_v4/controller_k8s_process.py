r"""The trusted controller entrypoint with the Kubernetes backend.

Same narrow RPC and contract as the Docker controller. It reuses the `_Controller` server from
`controller_process.py`, but the launch backend is the `KubernetesRunnerProvisioner` (one
short-lived Job per fragment) instead of Docker. It runs inside the controller pod under
controller-sa, the only ServiceAccount in agent-system with Job verbs, and the orchestrator reaches
it only through the controller ClusterIP Service.

Initialisation is trusted: the fixed launch configuration is not supplied by the orchestrator. It is
read from a mounted Secret file that a trusted init step produced (bootstrap and anchors), plus
Deployment arguments set by the trusted deploy step (namespace, expected runner image digest,
Authority endpoint). The orchestrator has no access to any of these.

The module needs a real cluster and the `kubernetes` client, so it is exercised by the cluster
scripts and not offline.

Usage (see k8s/apply/controller.yaml):
    python3 -m booking_v4.controller_k8s_process --tcp 0.0.0.0:9443 \
        --namespace agent-system --runner-image REG/runner@sha256:... \
        --authority-endpoint authority.agent-system.svc.cluster.local:8443 \
        --config-file /secrets/controller-config.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from booking_v3.authority import ProvisionerCredential

from . import wire
from .controller_process import _Controller
from .durable import RemoteAuthorityHandle
from .endpoint import ServiceEndpoint
from .k8s_backend import KubernetesRunnerProvisioner


def main() -> int:
    """Build the Kubernetes provisioner from the mounted config and serve the controller RPC."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--tcp", required=True)                 # HOST:PORT to bind
    ap.add_argument("--namespace", required=True)
    ap.add_argument("--runner-image", required=True)         # expected repo digest
    ap.add_argument("--authority-endpoint", required=True)   # host:port (ClusterIP DNS)
    ap.add_argument("--config-file", required=True)          # {bootstrap_secret, anchors}
    args = ap.parse_args()

    with open(args.config_file) as fh:
        cfg = json.load(fh)

    from kubernetes import config as kconfig
    kconfig.load_incluster_config()  # controller-sa token, mounted by Kubernetes

    a_host, a_port = args.authority_endpoint.rsplit(":", 1)
    authority_endpoint = ServiceEndpoint.tcp(a_host, int(a_port))
    provisioner = KubernetesRunnerProvisioner(
        namespace=args.namespace,
        image=args.runner_image,
        authority=RemoteAuthorityHandle(authority_endpoint),
        anchors=wire.anchors_from_wire(cfg["anchors"]),
        bootstrap=ProvisionerCredential(secret=cfg["bootstrap_secret"]),
        authority_endpoint=authority_endpoint.to_wire())

    # After a start or restart no valid handle exists for any surviving Job, so delete them
    # before serving. cleanup_orphans raises if a deletion cannot be confirmed.
    provisioner.cleanup_orphans()

    host, port = args.tcp.rsplit(":", 1)
    _Controller(provisioner, ("tcp", host, int(port)))
    sys.stderr.write(f"controller-k8s serving on {args.tcp}\n")
    sys.stderr.flush()
    while True:  # serve until the pod is terminated
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
