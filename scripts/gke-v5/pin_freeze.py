"""pin_freeze.py: pins a verified freeze candidate in _config.sh and tests_v5_fixtures.py.

Needs:  A freeze candidate from 98a under results_v5/freeze-candidate/, python3, and the booking_v5
        package for the verification and the fixture suite.
Usage:  python3 scripts/gke-v5/pin_freeze.py <STAMP>
Result: The stamp pinned in both files, and the fixture suite re-run. Exit code 1 if the pin's
        fixtures fail, so the caller stops.

What an operator does by hand after 98a, done the same way every time:

    _config.sh              FREEZE_STAMP -> <STAMP>, the old line recorded in a comment
    tests_v5_fixtures.py    STAMP -> <STAMP>, PREV_STAMP -> the old STAMP,
                            the pinned init-data digest -> the one the freeze records

It refuses unless `freeze_record verify` accepts the candidate, and it re-runs the fixture
suite afterwards. A candidate that does not verify is not pinned.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

MOCKS = pathlib.Path(__file__).resolve().parents[2]
CONFIG = MOCKS / "scripts" / "gke-v5" / "_config.sh"
FIXTURES = MOCKS / "booking_v5" / "tests_v5_fixtures.py"
CAND = MOCKS / "results_v5" / "freeze-candidate"


def _run(*cmd: str) -> int:
    """Run `cmd` in the repository root, echoing it first, and return its exit code."""
    print("[pin] $", " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=MOCKS).returncode


def main(argv: list[str]) -> int:
    """Pin the freeze candidate named in `argv` and re-run the fixture suite.

    Args:
        argv: one UTC stamp of the form YYYYMMDDTHHMMSSZ.

    Returns:
        The exit code of the fixture suite. A wrong argument, a missing candidate or a refused
        verification exits with a message instead.
    """
    if len(argv) != 1 or not re.fullmatch(r"\d{8}T\d{6}Z", argv[0]):
        raise SystemExit(__doc__)
    stamp = argv[0]
    txt = CAND / f"FREEZE-{stamp}.txt"
    if not txt.exists():
        raise SystemExit(f"[pin] no freeze candidate {txt}")
    if _run(sys.executable, "-m", "booking_v5.freeze_record", "verify", "results_v5/freeze-candidate",
            "--stamp", stamp) != 0:
        raise SystemExit(f"[pin] freeze_record verify refused {stamp}, nothing pinned")
    digest = re.search(r"^init_data_digest=([0-9a-f]{64})$", txt.read_text(), re.M)
    if not digest:
        raise SystemExit(f"[pin] {txt.name} records no init_data_digest")
    digest = digest.group(1)

    cfg = CONFIG.read_text()
    old = re.search(r'^FREEZE_STAMP="\$\{FREEZE_STAMP:-(\d{8}T\d{6}Z)\}"$', cfg, re.M)
    if not old:
        raise SystemExit("[pin] FREEZE_STAMP line not found in _config.sh")
    if old.group(1) == stamp:
        print(f"[pin] {stamp} is already pinned")
    else:
        cfg = cfg.replace(old.group(0),
                          f"# pinned by pin_freeze.py: {stamp} (previous line: {old.group(1)})\n"
                          f'FREEZE_STAMP="${{FREEZE_STAMP:-{stamp}}}"')
        CONFIG.write_text(cfg)

        fx = FIXTURES.read_text()
        cur = re.search(r'^STAMP = "(\d{8}T\d{6}Z)".*$', fx, re.M)
        prev = re.search(r'^PREV_STAMP = "(\d{8}T\d{6}Z)".*$', fx, re.M)
        dig = re.search(r'(self\.assertEqual\(ref\.init_data_digest, ")([0-9a-f]{64})("\).*)$', fx, re.M)
        if not (cur and prev and dig):
            raise SystemExit("[pin] STAMP / PREV_STAMP / init-data pin not found in tests_v5_fixtures.py")
        fx = fx.replace(cur.group(0), f'STAMP = "{stamp}"           # the frozen run (pinned by pin_freeze.py)')
        fx = fx.replace(prev.group(0), f'PREV_STAMP = "{cur.group(1)}"      # secondary line: the previous freeze')
        fx = fx.replace(dig.group(0), f'{dig.group(1)}{digest}")  # {stamp} (prev {dig.group(2)[:8]}…)')
        FIXTURES.write_text(fx)
        print(f"[pin] pinned {stamp} (was {old.group(1)}), init-data {digest[:12]}")

    return _run(sys.executable, "-m", "booking_v5.tests_v5_fixtures")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
