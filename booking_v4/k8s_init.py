r"""The trusted initialisation step of the Kubernetes deployment.

It takes the fixed launch configuration and the authority material away from the orchestrator and
creates them in a trusted, one-shot step that runs before any adversarial component exists. It
runs as a short Kubernetes Job (`k8s/apply/init.yaml`) under a dedicated `init-sa`, mounting the
same PersistentVolume the Authority pod will use, and it does two things.

  1. Seed the Authority PVC database. On an empty store it mints the trust anchors, the provisioner
     bootstrap and the human secret once (`Authority.create`) and persists the Authority and
     gateway state, like the fresh-database branch of `service_process.py`. The Authority pod then
     restores from this store and does not create its own (`service_process_tcp`). The step is
     idempotent: a store that is already seeded is left untouched.

  2. Publish one pre-created Kubernetes Secret by PATCH. The trusted deploy step creates it empty
     first, so init-sa needs no `create` and no resourceVersion handling. The Secret
     `deployment-bootstrap` (key `controller-config.json` = `{bootstrap_secret, anchors}`) is
     mounted read-only by the controller. It leaves out the human secret, because the controller
     launches runners and does not approve interventions. The human secret stays in the PVC store.
     No live test against the deployed Authority needs it (run activation uses the shared approver
     key), so this step does not export it.

No key or service-account secret is written to the repository. Every secret value is minted here,
at deploy time, inside the cluster, and lives only in the PVC and this Kubernetes Secret.
`--config-out` (a file) exists only for a local dry run without a cluster, and its output must not
be committed.

Usage (from k8s/apply/init.yaml, in-cluster):
    python3 -m booking_v4.k8s_init --db /data/deployment.db \
        --namespace agent-system --secret-name deployment-bootstrap \
        --now 1000 --publish-secret
Local dry run (no cluster, writes the controller config to a file):
    python3 -m booking_v4.k8s_init --db ./deployment.db --now 1000 \
        --config-out ./controller-config.json
"""

from __future__ import annotations

import argparse
import json
import sys

from booking_v1.clock import Clock, FixedClock, SystemClock

from booking_v3.authority import Authority
from booking_v3.gateway import ToolGateway

from . import wire
from .durable import DurableStore


def _seed_store(store: DurableStore, clock: Clock) -> dict:
    """Seed the store if it is empty and return the controller config either way.

    Returns:
        ``{bootstrap_secret, anchors}`` taken from the store, so the published
        Secret matches what the Authority pod will restore, whether this run
        created the deployment or found it already seeded.
    """
    states = store.load_states()
    if states is None:
        authority, bootstrap, _human = Authority.create(clock)
        gateway = ToolGateway(authority.token_key(), clock)
        with store.transaction():
            store.put_states(
                json.dumps(authority.export_state(), sort_keys=True),
                json.dumps(gateway.export_state(), sort_keys=True))
        anchors = authority.anchors()
        bootstrap_secret = bootstrap.secret
    else:
        authority = Authority.restore(clock, states[0])
        anchors = authority.anchors()
        bootstrap_secret = states[0]["bootstrap_secret"]
    return {"bootstrap_secret": bootstrap_secret, "anchors": wire.anchors_to_wire(anchors)}


def _publish_secret(namespace: str, secret_name: str, config: dict) -> None:
    """Patch the key controller-config.json of the pre-created controller Secret.

    The trusted deploy step creates the Secret empty, so init-sa needs only get
    and patch on it by name. A strategic-merge patch of ``stringData`` sets the
    key and needs no resourceVersion, so a re-run does not conflict.
    """
    from kubernetes import client, config as kconfig
    kconfig.load_incluster_config()
    core = client.CoreV1Api()
    core.patch_namespaced_secret(
        secret_name, namespace,
        {"stringData": {"controller-config.json": json.dumps(config, sort_keys=True)}})


def main() -> int:
    """Seed the store and publish the controller config as a Secret or a local file."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)               # PVC path
    ap.add_argument("--now", type=int, default=None,
                    help="pin the seeding clock (offline only). Default: the system clock")
    ap.add_argument("--namespace", default="agent-system")
    ap.add_argument("--secret-name", default="deployment-bootstrap")
    ap.add_argument("--publish-secret", action="store_true",
                    help="patch the pre-created controller Secret in-cluster")
    ap.add_argument("--config-out", default=None,
                    help="local dry run only: write the controller config to this "
                         "file (do not commit it)")
    args = ap.parse_args()

    store = DurableStore(args.db)
    try:
        config = _seed_store(store, FixedClock(args.now) if args.now is not None else SystemClock())
    finally:
        store.close()

    if args.publish_secret:
        _publish_secret(args.namespace, args.secret_name, config)
        sys.stderr.write(
            f"seeded {args.db} and patched Secret {args.namespace}/{args.secret_name}\n")
    if args.config_out:
        with open(args.config_out, "w") as fh:
            json.dump(config, fh, sort_keys=True)
        sys.stderr.write(f"seeded {args.db} and wrote config to {args.config_out}\n")
    if not args.publish_secret and not args.config_out:
        sys.stderr.write(
            "nothing published: pass --publish-secret (in-cluster) or "
            "--config-out FILE (local dry run)\n")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
