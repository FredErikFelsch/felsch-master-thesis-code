"""Live check: the deployed gateway has no effectful recovery path.

    python3 -m booking_v5.probe_recovery_closed [--context CTX] [--out FILE]

`gateway.recover_dispatch` would re-perform an external operation. The production modules
have no such method, no option that adds it and no client call for it. The mechanism lives only
in the test support module `booking_v4/tests_recovery_support.py`, which the image contains but
the gateway does not import. This probe asks the deployed gateway, through a port-forward to
its execution surface, and records two observations:

    source   the gateway pod's `durable.py` and `services.py` do not mention `recover_dispatch`
             or `enable_recovery`
    refusal  `gateway.recover_dispatch` is answered as an unknown method, not with a token or
             parameter error (which would mean the path exists)

The call carries no token and no fragment. On a gateway that had the path it would fail at
parameter validation before reaching the provider, so the probe itself cannot cause an
effect. It does not read a secret. Run it with the admin context while the cluster is up.
Exit code 0 only if both observations hold.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone

from booking_v4 import wire
from booking_v4.services import _call

from .e2e_live import NS, PortForward

#: What a gateway answers for a method it does not have: the surface filter of a deployed role
#: ("no such method ... on this surface") or the dispatcher of a server without roles.
ABSENT_REPLIES = ("no such method", "unknown method")
SOURCE_FILES = ("/app/booking_v4/durable.py", "/app/booking_v4/services.py")
SOURCE_PATTERN = "recover_dispatch\\|enable_recovery"


def classify(error_text: str | None, answered: bool) -> str:
    """Return 'closed' only for an unknown-method reply. Anything else is an open or unknown path."""
    if answered:
        return "OPEN: the gateway answered the call"
    if error_text and any(reply in error_text for reply in ABSENT_REPLIES):
        return "closed"
    return f"UNEXPECTED: {error_text}"


def current_context() -> str:
    """Return the kube context kubectl uses now (the admin context during an evaluation)."""
    return subprocess.check_output(["kubectl", "config", "current-context"]).decode().strip()


def source_mentions(context: str) -> int:
    """Count the lines mentioning the recovery method or its option in the gateway pod's sources.

    Raises:
        RuntimeError: a source file cannot be read in the pod.
    """
    total = 0
    for path in SOURCE_FILES:
        out = subprocess.run(["kubectl", "--context", context, "-n", NS, "exec", "deploy/gateway", "--",
                              "grep", "-c", SOURCE_PATTERN, path], capture_output=True, text=True)
        if out.returncode not in (0, 1):            # 1 is grep's "no match", the wanted answer
            raise RuntimeError(f"cannot read {path} in the gateway pod: {out.stderr.strip()}")
        total += int(out.stdout.strip() or 0)
    return total


def gateway_image(context: str) -> str:
    """Return the image reference(s) the deployed gateway runs."""
    return subprocess.check_output(["kubectl", "--context", context, "-n", NS, "get", "deploy", "gateway", "-o",
                                    "jsonpath={.spec.template.spec.containers[*].image}"]).decode()


def probe(context: str) -> dict:
    """Ask the deployed gateway's execution surface and record both observations."""
    answered, error_text = False, None
    with PortForward(context, "gateway", 8443) as pf:
        try:
            _call(pf.endpoint, "gateway.recover_dispatch", {})
            answered = True
        except wire.WireError as exc:
            error_text = str(exc)
    mentions = source_mentions(context)
    verdict = classify(error_text, answered)
    return {"checked_at": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), "context": context,
            "gateway_image": gateway_image(context), "surface": "execution (8443)",
            "source_mentions_recovery": mentions, "reply": error_text, "result": verdict,
            "pass": verdict == "closed" and mentions == 0}


def main(argv: list[str] | None = None) -> int:
    """Run the probe, print the record as JSON and return 0 only if both observations hold."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--context", default=None, help="kube context, default: the current one")
    ap.add_argument("--out", default=None, help="also write the record to this file")
    args = ap.parse_args(argv)
    record = probe(args.context or current_context())
    text = json.dumps(record, indent=1)
    print(text)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 0 if record["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
