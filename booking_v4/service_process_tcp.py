r"""The durable Authority and gateway service over TCP.

This is the TCP, restore-only variant of `service_process.py`, run as the Authority pod
(`k8s/apply/authority.yaml`) on a PersistentVolume. It differs from the UDS `service_process` in
two ways.

  * Transport. It binds a TCP listener (``--bind HOST:PORT``) instead of a Unix socket, so
    in-cluster peers (the runner Jobs, the controller pod) reach it over a ClusterIP Service. The
    Authority and gateway objects and every durable rule are the same, only the listener changes.

  * Restore-only. It does not create a fresh deployment. The trusted init step (`k8s_init.py`)
    mints the trust anchors, the provisioner bootstrap and the human secret once and seeds this
    PVC database. A pod that created its own would mint authority material on an empty volume
    that does not match the controller's Secret, so the process refuses an unseeded database.
    The bootstrap secret is not printed here. It stays in the store and the controller Secret.

The module needs a real PVC and is started by `k8s/apply/authority.yaml`, not offline.

Usage (from k8s/apply/authority.yaml):
    python3 -m booking_v4.service_process_tcp --db /data/deployment.db \
        --bind 0.0.0.0:8443 [--now 1000] [--world-db W] [--idempotent]
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from booking_v1.clock import FixedClock, SystemClock

from booking_v3.authority import Authority
from booking_v3.gateway import ToolGateway

from .durable import StoreBusy, DurableDeploymentServer, DurableStore, _RestoredDeployment
from .service_world import DEFAULT_WORLD, WorldRefused, gateway_executor


def _hostport(spec: str) -> tuple[str, int]:
    """Split a HOST:PORT string at the last colon and return (host, port)."""
    host, port = spec.rsplit(":", 1)
    return host, int(port)


def main() -> int:
    """Open the seeded store, restore the deployment, serve over TCP and print the endpoint."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--bind", required=True)              # HOST:PORT
    parser.add_argument("--now", type=int, default=None,
                        help="pin the clock to this instant (offline fixtures only). Default: the system clock")
    parser.add_argument("--world", default=DEFAULT_WORLD,
                        help=f"the counterparty to reach: {DEFAULT_WORLD} (the recorded booking_v2 catalogue) "
                             "or a live world from booking_live.startup.WORLDS. A live world without a "
                             "credential refuses to start")
    parser.add_argument("--world-db", default=None)
    parser.add_argument("--idempotent", action="store_true")
    parser.add_argument("--harness-bind", default=None,
                        help="HOST:PORT of a separate listener for the harness surface (test.*, read.*), "
                             "and is not served on --bind")
    args = parser.parse_args()

    clock = FixedClock(args.now) if args.now is not None else SystemClock()
    try:
        store = DurableStore(args.db)
    except StoreBusy as exc:
        # Single writer: a second service on a live store stops here, before it reads
        # a row or answers a request. Exit 3 is the code the two-writer scenario expects.
        sys.stderr.write(f"refusing to start: {exc}\n")
        sys.stderr.flush()
        return 3
    # Both booking_v4 entry points wire their world through booking_v4.service_world. A
    # world that is not the catalogue yields a live executor, or this process does not
    # start, so a service configured for a real counterparty does not serve recorded data.
    try:
        executor = gateway_executor(args.world, args.world_db, args.idempotent)
    except WorldRefused as refused:
        sys.stderr.write(f"refusing to start: {refused}\n")
        sys.stderr.flush()
        return 4

    states = store.load_states()
    if states is None:
        # Restore-only: refuse to mint authority material on an unseeded volume.
        sys.stderr.write(
            f"authority store {args.db!r} is not seeded. Run the trusted init "
            "(booking_v4.k8s_init) first. Refusing to create authority material on an unseeded volume\n")
        return 2

    authority = Authority.restore(clock, states[0])
    gateway = (ToolGateway(authority.token_key(), clock, executor=executor)
               if executor else ToolGateway(authority.token_key(), clock))
    gateway.restore_state(states[1])

    server = DurableDeploymentServer(
        _RestoredDeployment(authority, gateway), store,
        tcp=_hostport(args.bind), downstream_idempotent=args.idempotent,
        harness_tcp=_hostport(args.harness_bind) if args.harness_bind else None)
    # Report only the endpoints, not the bootstrap or the human secret.
    out = {"endpoint": server.endpoint.to_wire()}
    if server.harness_endpoint is not None:
        out["harness_endpoint"] = server.harness_endpoint.to_wire()
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
    while True:  # serve until the pod is terminated
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
