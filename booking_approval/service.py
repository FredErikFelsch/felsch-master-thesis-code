"""The Authority with the approval gate: the deployed entry point of the authority role.

    python3 -m booking_approval.service --db /data/authority.db --bind 0.0.0.0:8443 \\
        --credentials /etc/approver/approver-credentials.json [--approval-bind 0.0.0.0:8450] \\
        [--origin http://localhost:8450] [--gateway-observe gateway:8444] [--harness-bind ...]

It restores the Authority in the same way as `booking_v5.service_v5 serve --role authority`
(`start_authority`, same store, same verifier, same world admission), with the gate's closed
methods refused from the moment the listener is bound. It then installs the gate on that
server and starts the approval surface, both before it prints its ready line. The gate's
store lives beside the Authority's (`approval.db` on the same volume).

`init` and the gateway role are unchanged and stay on `booking_v5.service_v5`.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

from booking_v1.clock import FixedClock, SystemClock
from booking_v5 import service_v5

from .credentials import CredentialPinMismatch, CredentialSet, pin
from .gate import CLOSED_METHODS, ApprovalGate
from .store import ApprovalStore
from .surface import ApprovalSurface


def start(db: str, bind: tuple[str, int], approval_bind: tuple[str, int], credentials_path: str, clock, *,
          origin: str = "http://localhost:8450", rp_id: str = "localhost", repin: bool = False,
          verifier: str = "dcap", harness: tuple[str, int] | None = None,
          gateway_observe: tuple[str, int] | None = None, verifier_factory=None,
          frame_ancestors: tuple[str, ...] = ()):
    """Restore the Authority, pin the approvers, install the gate and open the surface.

    Args:
        db: The Authority's SQLite file. The gate's store is `approval.db` beside it.
        bind: Host and port of the Authority's RPC listener.
        approval_bind: Host and port of the approval surface.
        credentials_path: The approver credential file.
        clock: The Authority's clock.
        origin: The WebAuthn origin of the approval page.
        rp_id: The WebAuthn relying party id.
        repin: Accept a credential set that differs from the pinned one.
        verifier: The attestation verifier (`booking_v5.service_v5.start_authority`).
        harness: Host and port of the harness listener, or None.
        gateway_observe: The gateway's observation endpoint, or None.
        verifier_factory: Injected verifier constructor for tests, or None.
        frame_ancestors: Origins that may show the approval page as a panel.

    Returns:
        (server, authority_store, gate, surface, approval_store)

    Raises:
        SystemExit: when the credential set does not match the pinned one (fail-closed).
    """
    credentials = CredentialSet.load(credentials_path)
    approval_store = ApprovalStore(str(pathlib.Path(db).with_name("approval.db")))
    try:
        digest = pin(approval_store, credentials, repin=repin)
    except CredentialPinMismatch as exc:
        approval_store.close()
        raise SystemExit(f"approval gate: {exc}")
    server, store = service_v5.start_authority(db, bind, clock, verifier, harness,
                                               gateway_observe=gateway_observe, verifier_factory=verifier_factory,
                                               closed_methods=CLOSED_METHODS)
    gate = ApprovalGate(server, approval_store, credentials, clock, rp_id=rp_id, origin=origin,
                        allowed_top_origins=tuple(frame_ancestors)).install(require_preclosed=True)
    surface = ApprovalSurface(gate, approval_bind, frame_ancestors)
    sys.stdout.write(f"[approval-gate] credentials {digest[:16]}: "
                     + ", ".join(f"{c['approver_id']} ({c['kind']})" for c in credentials.summary()) + "\n")
    return server, store, gate, surface, approval_store


def main(argv: list[str] | None = None) -> int:
    """Run the authority role from the command line. It serves until the process is stopped."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True)
    ap.add_argument("--bind", required=True)
    ap.add_argument("--credentials", required=True, help="approver credential file (public keys only)")
    ap.add_argument("--approval-bind", default="0.0.0.0:8450")
    ap.add_argument("--origin", default="http://localhost:8450", help="the WebAuthn origin of the approval page")
    ap.add_argument("--rp-id", default="localhost")
    ap.add_argument("--repin", action="store_true", help="accept a credential set that differs from the pinned one")
    ap.add_argument("--frame-ancestor", action="append", default=[],
                    help="an origin that may show the approval page as a panel (the operator shell), may be repeated")
    ap.add_argument("--now", type=int, default=None)
    ap.add_argument("--verifier", default="dcap", choices=("dcap",))
    ap.add_argument("--gateway-observe", default=None)
    ap.add_argument("--harness-bind", default=None)
    args = ap.parse_args(argv)
    service_v5.refuse_test_flags(args)
    clock = FixedClock(args.now) if args.now is not None else SystemClock()
    hp = service_v5._hostport
    server, _, gate, surface, _ = start(
        args.db, hp(args.bind), hp(args.approval_bind), args.credentials, clock, origin=args.origin,
        rp_id=args.rp_id, repin=args.repin, verifier=args.verifier,
        harness=hp(args.harness_bind) if args.harness_bind else None,
        gateway_observe=hp(args.gateway_observe) if args.gateway_observe else None,
        frame_ancestors=tuple(args.frame_ancestor))
    sys.stdout.write(json.dumps({
        "role": "authority", "endpoint": server.endpoint.to_wire(), "verifier": args.verifier,
        "observation_check": args.gateway_observe or "off", "approval_gate": "on",
        "approval_surface": f"{surface.address[0]}:{surface.address[1]}", "origin": gate.origin,
        "clock": "system" if args.now is None else f"fixed:{args.now}"}) + "\n")
    sys.stdout.flush()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main())
