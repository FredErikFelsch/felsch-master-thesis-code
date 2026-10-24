"""Probe entry point: record the V5 runner's RTMR3 events inside a peer pod and print a fixture.

It runs as the initial command of the probe pod (`scripts/gke-v5/18_probe_peer_pod.sh`),
because the measured guest policy forbids exec. It records the same RTMR3 events in the same
order as `runner_bind.V5Runner` and requests evidence over the same canonical binding. It drives
these steps by hand instead of through V5Runner (no phase guard, no open or execute) and adds
one step, marked below: an extra evidence fetch before the runner's own events. The offline
analysis can then separate two questions that would otherwise arrive as one answer:

    did the pod-VM overlay measure the init-data?   RTMR3 before the events == replay([init-data])
    did the two runner events land?                 RTMR3 after  the events == replay([init-data, boot-key, bind])

There is no Authority in the probe, so the nonce and the binding fields come from the
command line and are recorded next to the evidence. The offline verification recomputes the
canonical binding from that file and checks REPORTDATA against it. Every step prints one line
and no step is fatal, so a failed step still leaves the pod alive and its reason in the log.

Usage (as the container command):
    python3 -m booking_v5.probe_bind --run <id> --step <n> --fragment <hex> --state <hex>
                                     --nonce <hex> [--idle 1800]
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time

from .binding import RunnerIdentity
from .rtmr_replay import boot_key_content
from .runner_bind import AttestationAgent, RunnerError


def _emit(marker: str, *parts: object) -> None:
    """Print one line per event, flushed at once, because the log is the fixture."""
    print(marker, *parts, flush=True)


def main(argv: list[str] | None = None) -> int:
    """Run the probe sequence, print one marker line per step, then idle for log collection."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--run", required=True)
    ap.add_argument("--step", type=int, required=True)
    ap.add_argument("--fragment", required=True, help="fragment_hash, hex")
    ap.add_argument("--state", required=True, help="state_hash, hex")
    ap.add_argument("--nonce", required=True, help="nonce the Authority would have issued, hex")
    ap.add_argument("--idle", type=int, default=1800, help="seconds to stay alive for log collection")
    ap.add_argument("--base-url", default="http://127.0.0.1:8006")
    args = ap.parse_args(argv)

    aa = AttestationAgent(base_url=args.base_url)
    nonce = bytes.fromhex(args.nonce)
    params = {"run": args.run, "step": args.step, "fragment_hash": args.fragment,
              "state_hash": args.state, "nonce": args.nonce}
    _emit("PROBE_BIND_START", json.dumps(params, sort_keys=True))

    try:
        _emit("AA_INFO", _get(aa, "/info")[:400])
    except Exception as exc:                                    # noqa: BLE001 (a probe step is not fatal)
        _emit("AA_INFO_FAIL", repr(exc))

    # Boot: the keys exist before anything is measured or requested.
    identity = RunnerIdentity.create()                          # no hook yet: the pre-fetch comes first
    _emit("PK_BOOT", identity.pk_boot.hex())
    _emit("PK_SIG", identity.pk_sig.hex())                      # the verdict key, measured with it

    # Bind locally so the canonical binding can be computed. Nothing is measured by this call.
    # The bind event is recorded explicitly below, in the order the Authority expects.
    identity.bind(args.run, args.step, args.fragment, args.state)
    runtime_data = identity.runtime_data(nonce)
    _emit("RUNTIME_DATA", runtime_data.hex())                   # 32 B -> 64 ASCII characters

    # Probe only: evidence before the runner events, to isolate the overlay's init-data measurement.
    try:
        _emit("EVIDENCE_PRE_B64", _b64(aa.evidence(runtime_data).blob))
    except RunnerError as exc:
        _emit("EVIDENCE_PRE_FAIL", repr(exc))

    for operation, content in (("boot-key", boot_key_content(identity.pk_boot.hex(), identity.pk_sig.hex())),
                               ("bind", f"{args.run}/{args.step}/{args.fragment}/{args.state}")):
        try:
            aa.extend(operation, content)
            _emit("AAEL_OK", operation, content[:32] + ("…" if len(content) > 32 else ""))
        except RunnerError as exc:
            _emit("AAEL_FAIL", operation, repr(exc))

    # The evidence the Authority would appraise: REPORTDATA == ascii(canonical binding),
    # RTMR3 == replay([init-data, boot-key, bind]).
    try:
        evidence = aa.evidence(runtime_data)
        _emit("EVIDENCE_OK", len(evidence.blob))
        _emit("EVIDENCE_B64", _b64(evidence.blob))
    except RunnerError as exc:
        _emit("EVIDENCE_FAIL", repr(exc))

    _emit("PROBE_BIND_DONE")
    if args.idle > 0:
        time.sleep(args.idle)
    return 0


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _get(aa: AttestationAgent, path: str) -> str:
    import urllib.request
    with urllib.request.urlopen(f"{aa.base_url}{path}", timeout=10) as resp:   # noqa: S310 (loopback)
        return resp.read().decode(errors="replace")


if __name__ == "__main__":
    sys.exit(main())
