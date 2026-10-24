"""What the controller can do against the approval gate, from its own position.

    python3 -m booking_approval.probe_controller --context v5-controller

Runs under the controller's kube context, through its own port-forwards to the Authority
(8443 RPC and 8450 approval surface), with everything a compromised controller holds: the
HMAC constant of `booking_v1.approval` (it ships in every image) and the policy of a run.
It reads no secret and prints one JSON object {case: observed}.

    create_run with the HMAC constant       expected "refused"
    decide_intervention                     expected "refused"
    forged assertion on the approval page   expected "refused" and the object still pending
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request

from booking_v1.approval import approve, live_window
from booking_live.policy import pl1_with_pay_approval
from booking_v4 import wire
from booking_v4.durable import new_decision_id
from booking_v4.services import _call
from booking_v5.e2e_live import PortForward

from .softauthn import SoftwareAuthenticator
from .webauthn import b64url_decode

ORIGIN = "http://localhost:8450"


def _rpc(endpoint, method: str, params: dict) -> str:
    """Call one RPC method and return "refused" when the gate closed it, otherwise what came back."""
    try:
        reply = _call(endpoint, method, params)
    except wire.WireError as exc:
        return "refused" if "requires the approval surface" in str(exc) else f"error: {exc}"
    return f"answered: {json.dumps(reply)[:120]}"


def _post(base: str, path: str, body: dict) -> tuple[int, dict]:
    """Send a POST as the page would (Host and Origin of the approval origin) and return status and body."""
    req = urllib.request.Request(base + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Origin": ORIGIN,
                                          "Host": "localhost:8450"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"{}")


def probe(context: str) -> dict:
    """Run the three attempts under `context` and return what each one observed."""
    policy = pl1_with_pay_approval()
    out: dict[str, str] = {}
    with PortForward(context, "authority", 8443) as rpc, PortForward(context, "authority", 8450) as page:
        ep = rpc.endpoint
        issued, expires = live_window()
        run_id = f"probe-{secrets.token_hex(6)}"
        forged = approve(policy, approver_id="controller", approval_id=f"appr-{run_id}", run_id=run_id,
                         issued_at=issued, expires_at=expires)
        out["create_run with the HMAC constant"] = _rpc(ep, "authority.create_run", {
            "policy": wire.policy_to_wire(policy), "approval": wire.approval_to_wire(forged), "run_id": run_id})
        out["decide_intervention"] = _rpc(ep, "authority.decide_intervention", {
            "human": {"v": wire.WIRE_VERSION, "kind": "human-credential", "secret": "0" * 32},
            "decision_id": new_decision_id(), "run_id": run_id, "step_index": 3, "fragment_hash": "0" * 64,
            "approver_id": "controller", "approver_kind": "passkey", "grant": True, "ttl": 60})
        oid = _call(ep, "approval.propose_run", {"policy": wire.policy_to_wire(policy), "run_id": run_id})["object_id"]
        base = f"http://127.0.0.1:{page.local}"
        status, ch = _post(base, "/api/challenge", {"object_id": oid, "decision": "approve"})
        if status != 200:
            out["forged assertion on the approval page"] = f"no challenge: {status} {ch.get('error')}"
        else:
            a = SoftwareAuthenticator.generate().assertion(b64url_decode(ch["challenge"]), ORIGIN)
            a["challenge"] = ch["challenge"]
            status, body = _post(base, "/api/decide", {"object_id": oid, "decision": "approve", "assertion": a})
            state = _call(ep, "approval.status", {"object_id": oid})["state"]
            out["forged assertion on the approval page"] = (
                "refused" if status == 403 and state == "pending" else f"{status} {body.get('error')} state={state}")
    return out


def main(argv: list[str] | None = None) -> int:
    """Run the probe from the command line and print the result as JSON."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--context", default="v5-controller")
    args = ap.parse_args(argv)
    print(json.dumps(probe(args.context)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
