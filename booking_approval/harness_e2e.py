"""The cluster evaluation harness (`booking_v5.e2e_live`) on a gated Authority.

    python3 -m booking_approval.harness_e2e run --context v5-controller ...   (e2e_live's arguments)

`e2e_live` creates its runs with `authority.create_run` and an HMAC approval, which the gate
closes. This entry point leaves `e2e_live` untouched (it is part of the runner image's source
and of the frozen measurement) and routes only that call through the gate: the run is
proposed, the harness key approves it on the approval surface, and `e2e_live` receives the
genesis envelope the Authority produced. Every other call passes unchanged.
On an Authority without the gate nothing is routed and `e2e_live` runs as before.

The harness key is read from HARNESS_APPROVER_KEY (default ~/.config/thesis-v5/harness-approver.json)
and is accepted only by a deployment that pins it (APPROVER_CREDENTIALS=...eval.json at deployment).
"""
from __future__ import annotations

import os
import pathlib
import sys

from booking_v4 import services, wire

from .client import ApprovalClient, ApprovalUnavailable, HarnessApprover
from .softauthn import SoftwareAuthenticator

DEFAULT_KEY = "~/.config/thesis-v5/harness-approver.json"
ORIGIN = "http://localhost:8450"


def gated_call(real_call, surface_url: str, harness: HarnessApprover):
    """Wrap `services._call` so that `authority.create_run` is answered through the gate.

    Args:
        real_call: The original `services._call`.
        surface_url: Where the approval surface is reached.
        harness: The approver that signs the plan.

    Returns:
        A drop-in replacement for `services._call`.
    """
    def call(endpoint, method, params, request_id=None):
        if method != "authority.create_run":
            return real_call(endpoint, method, params, request_id)
        client = ApprovalClient(endpoint, surface_url)
        ticket = client.propose_run(wire.policy_from_wire(params["policy"]), params["run_id"])
        harness.decide(ticket.object_id, "approve")
        status = client.wait(ticket.object_id, timeout=30)
        envelope = (status.get("result") or {}).get("envelope") if status.get("state") == "approved" else None
        return {"v": wire.WIRE_VERSION, "envelope": envelope,
                "reason": "created via the approval gate (harness)" if envelope else f"not approved: {status}"}
    return call


def _context(argv: list[str]) -> str:
    return argv[argv.index("--context") + 1] if "--context" in argv else "v5-controller"


def main(argv: list[str] | None = None) -> int:
    """Run `e2e_live`, routing run creation through the approval gate when the Authority has one."""
    from booking_v5 import e2e_live
    argv = list(sys.argv[1:] if argv is None else argv)
    ctx = _context(argv)
    with e2e_live.PortForward(ctx, "authority", 8443) as rpc:
        try:
            ApprovalClient(rpc.endpoint).pinned()
            gated = True
        except ApprovalUnavailable:
            gated = False
    if not gated:
        print("[harness] the Authority runs no approval gate: e2e_live unchanged")
        return e2e_live.main(argv)
    key = pathlib.Path(os.path.expanduser(os.environ.get("HARNESS_APPROVER_KEY", DEFAULT_KEY)))
    if not key.exists():
        raise SystemExit(f"gated Authority, but no harness key at {key} "
                         f"(python3 -m booking_approval.enroll harness ...)")
    with e2e_live.PortForward(ctx, "authority", 8450) as page:
        surface = f"http://127.0.0.1:{page.local}"
        harness = HarnessApprover(surface, SoftwareAuthenticator.load(key), origin=ORIGIN)
        services._call = gated_call(services._call, surface, harness)
        print(f"[harness] gated Authority: create_run goes through the approval gate (harness key {key.name})")
        return e2e_live.main(argv)


if __name__ == "__main__":
    sys.exit(main())
