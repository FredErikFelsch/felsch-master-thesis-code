r"""The durable Authority and gateway service as a separate operating-system process.

Entry point for the crash experiments. The service hosts the Authority and the
tool gateway behind the durable server on a fixed socket address, backed by a
SQLite file. On a fresh database it creates the deployment, on an existing one
it restores from the store alone. The parent reads one handshake line (socket,
bootstrap, public anchors) and may then SIGKILL this process at any point. A
successor started on the same database and socket continues from the state the
store holds.

The external world has its own database (the counterparty's state is not part
of the service and must survive the death of the service process), optionally
with downstream idempotency on the gateway-derived effect identity (see
`durable.idempotency_key`).

Usage:
    python3 -m booking_v4.service_process --db D --socket S --now T \
        [--world-db W] [--idempotent]
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


def main() -> int:
    """Open the store, restore or create the deployment, serve and print the handshake."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--now", type=int, default=None,
                        help="pin the clock to this instant (offline fixtures only). Default: the system clock")
    parser.add_argument("--world", default=DEFAULT_WORLD,
                        help=f"the counterparty to reach: {DEFAULT_WORLD} (the recorded booking_v2 catalogue) "
                             "or a live world from booking_live.startup.WORLDS. A live world without a "
                             "credential refuses to start")
    parser.add_argument("--world-db", default=None)
    parser.add_argument("--idempotent", action="store_true")
    parser.add_argument("--enable-test-api", action="store_true")
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
    if states is not None:
        authority = Authority.restore(clock, states[0])
        gateway = (ToolGateway(authority.token_key(), clock, executor=executor)
                   if executor else ToolGateway(authority.token_key(), clock))
        gateway.restore_state(states[1])
        bootstrap_secret = states[0]["bootstrap_secret"]
    else:
        authority, bootstrap, human = Authority.create(clock)
        gateway = (ToolGateway(authority.token_key(), clock, executor=executor)
                   if executor else ToolGateway(authority.token_key(), clock))
        bootstrap_secret = bootstrap.secret
        with store.transaction():
            store.put_states(
                json.dumps(authority.export_state(), sort_keys=True),
                json.dumps(gateway.export_state(), sort_keys=True))

    server = DurableDeploymentServer(
        _RestoredDeployment(authority, gateway), store,
        socket_path=args.socket, downstream_idempotent=args.idempotent,
        enable_test_api=args.enable_test_api)
    anchors = authority.anchors()
    sys.stdout.write(json.dumps({
        "socket": server.socket_path,
        "bootstrap": bootstrap_secret,
        "envelope_key": anchors.envelope_key.to_bytes().hex(),
        "intervention_key": anchors.intervention_key.to_bytes().hex(),
    }) + "\n")
    sys.stdout.flush()
    while True:  # serve until killed
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
