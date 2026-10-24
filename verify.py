#!/usr/bin/env python3
"""One command for the whole offline suite, with a diff against the previous run.

    python3 verify.py                  every test module, full report
    python3 verify.py --quick          skip the slow service and durable modules
    python3 verify.py -k v5            only modules whose name contains "v5"
    python3 verify.py --list           show what would run, run nothing

The suite is spread over ten packages and a run takes minutes. After a change the useful
question is what differs from the last run, and this script answers it. It stores the outcome
of each module in `.verify-state.json` and prints what moved. A pre-existing environment failure (the
x86_64 `opa` binary on an arm64 machine, for one) stays visible as unchanged instead of
being re-read as a regression on every run.

Each module runs in its own interpreter, so a crash costs one module and not the whole run,
and the per-module timings are comparable across runs. The exit code is 0 only when every
module that ran reported OK.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent
STATE = ROOT / ".verify-state.json"

#: Packages searched for test modules, in the order a failure is most cheaply understood:
#: the lower layers first, so a break in V2 is reported before the V5 tests that rest on it.
PACKAGES = ("booking_v0", "booking_v1", "booking_v2", "booking_v3", "booking_v4",
            "booking_v5", "booking_demo", "booking_live", "booking_approval", "ui")

#: Modules that take tens of seconds because they start real services or subprocesses.
#: `--quick` leaves them out, and a full run before a commit includes them.
SLOW = ("booking_v4.tests_durable", "booking_v4.tests", "booking_v5.tests_v5_service",
        "booking_v5.tests_v5_protocol", "booking_v5.tests_v5_experiment")

_SUMMARY = re.compile(r"^Ran (\d+) tests? in ([\d.]+)s", re.M)
_COUNTS = re.compile(r"(failures|errors|skipped)=(\d+)")
#: The V0 to V2 modules are plain functions run by a `main()`, not unittest cases. They are
#: detected rather than listed: unittest collects nothing from them, and that is the signal to
#: run them as scripts. Keeping the detection means a module that is later converted to
#: unittest needs no change here.
_SCRIPT_SUMMARY = re.compile(r"^All (\d+) tests passed\.", re.M)
#: `booking_live.tests_live` is a table runner, not unittest: it ends with "59 cases: ..., 0 mismatches"
#: and exits non-zero on any mismatch. A run with mismatches matches nothing here and is FAILED.
_CASES_SUMMARY = re.compile(r"^(\d+) cases: .*, 0 mismatches$", re.M)
#: Python 3.12 and later report "unittest collected nothing" as an ERROR with a non-zero exit
#: code and this banner. The V0 to V2 modules are scripts, so unittest legitimately collects
#: nothing from them. The script fallback therefore keys on the collection result and not on
#: exit code 0, which would differ between 3.10 and 3.12+ interpreters.
_NO_TESTS_RAN = re.compile(r"^NO TESTS RAN", re.M)


def discover() -> list[str]:
    """Every test module (`tests*.py`) in the source packages, as dotted names."""
    found = []
    for package in PACKAGES:
        directory = ROOT / package
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("tests*.py")):
            found.append(f"{package}.{path.stem}")
    return found


def _invoke(argv: list[str], timeout: float) -> tuple[str, int | None, float]:
    """Run a command from the repository root.

    Args:
        argv: The command and its arguments.
        timeout: The limit in seconds.

    Returns:
        The combined output, the exit code (None on timeout) and the elapsed seconds.
    """
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return proc.stdout + proc.stderr, proc.returncode, time.monotonic() - started
    except subprocess.TimeoutExpired as exc:
        raw = exc.output or ""
        text = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        return text, None, time.monotonic() - started


def run_module(module: str, timeout: float) -> dict:
    """Run one module in its own interpreter and reduce its output to a record.

    Two shapes are supported. A unittest module is run through `-m unittest`. A module that
    unittest collects nothing from is run again as a script (`-m <module>`), which is how the
    V0 to V2 suites are written, and its summary line is parsed instead.

    Args:
        module: The dotted module name.
        timeout: The limit per interpreter run, in seconds.

    Returns:
        The record with status, kind, test counts, seconds and the first problem.
    """
    output, code, elapsed = _invoke([sys.executable, "-W", "ignore", "-m", "unittest", module], timeout)
    summary = _SUMMARY.search(output)
    kind = "unittest"
    # Unittest collected nothing, so its exit code says nothing about this module's tests, and
    # the module runs as the script it is. Both spellings mean the same on different interpreters.
    collected_nothing = bool(_NO_TESTS_RAN.search(output)) or (summary is not None and summary.group(1) == "0")
    if collected_nothing:
        output, code, script_elapsed = _invoke([sys.executable, "-W", "ignore", "-m", module], timeout)
        elapsed += script_elapsed
        summary = _SCRIPT_SUMMARY.search(output) or _CASES_SUMMARY.search(output)
        kind = "script"

    counts = {name: int(value) for name, value in _COUNTS.findall(output)} if kind == "unittest" else {}
    status = "TIMEOUT" if code is None else ("OK" if code == 0 else "FAILED")
    if kind == "script" and status == "OK" and summary is None:
        status = "FAILED"                      # exited 0 without claiming the tests passed
    return {
        "status": status,
        "kind": kind,
        "tests": int(summary.group(1)) if summary else 0,
        "failures": counts.get("failures", 0),
        "errors": counts.get("errors", 0),
        "skipped": counts.get("skipped", 0),
        "seconds": round(elapsed, 1),
        "first_problem": _first_problem(output) if status != "OK" else "",
    }


def _first_problem(output: str) -> str:
    """The first FAIL or ERROR header with its assertion line.

    That is enough to recognise a known failure without scrolling, but it does not replace
    reading the real output.
    """
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(("FAIL:", "ERROR:", "Traceback")):
            detail = next((x.strip() for x in lines[i:i + 24]
                           if x.strip().startswith(("AssertionError", "TypeError", "ValueError",
                                                    "AttributeError", "OSError", "KeyError",
                                                    "RuntimeError"))), "")
            return f"{line.strip()} | {detail}"[:240]
    tail = [x for x in lines[-6:] if x.strip()]
    return (tail[-1][:240] if tail else "no output at all")


def load_previous() -> dict:
    """The recorded outcome of the previous run, or an empty dict when there is none."""
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {}


def report(current: dict, previous: dict, *, partial: bool) -> bool:
    """Print the per-module table and the diff.

    A filtered or `--quick` run compares only the modules it ran. Calling a module "no longer
    run" because `-k` excluded it would make the diff useless when it is used most, which is
    while working on one package.

    Args:
        current: The record of this run.
        previous: The record of the previous run, or an empty dict.
        partial: Whether this run covered only part of the modules.

    Returns:
        Whether every module that ran was green.
    """
    modules = current["modules"]
    old = previous.get("modules", {})
    width = max(len(name) for name in modules)

    print()
    for name, record in modules.items():
        mark = {"OK": "ok  ", "FAILED": "FAIL", "TIMEOUT": "TIME"}[record["status"]]
        counts = f"{record['tests']:>4} tests"
        if record["skipped"]:
            counts += f", {record['skipped']} skipped"
        if record["failures"] or record["errors"]:
            counts += f", {record['failures']} failures, {record['errors']} errors"
        print(f"  {mark}  {name:<{width}}  {counts:<42} {record['seconds']:>6.1f}s")
        if record["first_problem"]:
            print(f"        {record['first_problem']}")

    green = [n for n, r in modules.items() if r["status"] == "OK"]
    red = [n for n, r in modules.items() if r["status"] != "OK"]
    total_tests = sum(r["tests"] for r in modules.values())
    total_time = sum(r["seconds"] for r in modules.values())
    print(f"\n  {len(green)}/{len(modules)} modules green, {total_tests} tests, {total_time:.0f}s total")

    if old:
        broke = [n for n in modules if modules[n]["status"] != "OK"
                 and old.get(n, {}).get("status") == "OK"]
        fixed = [n for n in modules if modules[n]["status"] == "OK"
                 and old.get(n, {}).get("status") not in (None, "OK")]
        still = [n for n in red if old.get(n, {}).get("status") not in (None, "OK")]
        fresh = [n for n in modules if n not in old]
        gone = [] if partial else [n for n in old if n not in modules]
        covered = f"{len(modules)} module" + ("" if len(modules) == 1 else "s")
        scope = "" if not partial else f" (over the {covered} this run covered)"
        print(f"  since {previous.get('finished', 'the last run')}{scope}:")
        for label, names in (("BROKE", broke), ("fixed", fixed), ("still red", still),
                             ("new module", fresh), ("no longer run", gone)):
            if names:
                print(f"    {label}: {', '.join(sorted(names))}")
        if not (broke or fixed or still or fresh or gone):
            print("    nothing changed")
    else:
        print("  no previous run recorded, so this one becomes the baseline")

    return not red


def main() -> int:
    """Parse the options, run the selected modules, print the report and return the exit code."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-k", dest="filter", action="append", default=[], metavar="TEXT",
                        help="only modules containing this substring (repeatable, any match counts)")
    parser.add_argument("--quick", action="store_true", help="skip the slow service and durable modules")
    parser.add_argument("--list", action="store_true", help="print the module list and exit")
    parser.add_argument("--timeout", type=float, default=600.0, help="per-module timeout in seconds")
    args = parser.parse_args()

    modules = [m for m in discover()
               if not args.filter or any(text in m for text in args.filter)]
    if args.quick:
        modules = [m for m in modules if m not in SLOW]
    if not modules:
        print("no test modules match", file=sys.stderr)
        return 2
    if args.list:
        print("\n".join(modules))
        return 0

    results: dict = {}
    for index, module in enumerate(modules, 1):
        print(f"[{index}/{len(modules)}] {module}", flush=True)
        results[module] = run_module(module, args.timeout)

    partial = bool(args.filter) or args.quick
    previous = load_previous()
    current = {"finished": time.strftime("%Y-%m-%d %H:%M"), "modules": results}
    green = report(current, previous, partial=partial)

    # The state is written whether or not the run was green, because the diff should show a
    # failure staying a failure rather than the last green run forever. A partial run
    # updates only what it ran, so the next full run still diffs against real results for the
    # modules this one skipped.
    merged = dict(previous.get("modules", {})) if partial else {}
    merged.update(results)
    STATE.write_text(json.dumps({"finished": current["finished"], "partial": partial,
                                 "modules": merged}, indent=2, sort_keys=True) + "\n")
    return 0 if green else 1


if __name__ == "__main__":
    sys.exit(main())
