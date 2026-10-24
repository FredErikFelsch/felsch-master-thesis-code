"""V5 evaluation report: regenerate every thesis table from the recorded files.

Reads ``results_v5/`` (no cluster, no network) and writes booktabs tables as
standalone ``.tex`` files plus a macro file with the headline numbers, so that
every number in chapter 7 (Evaluation) is regenerable::

    python3 -m booking_v5.report_v5                      # defaults below
    python3 -m booking_v5.report_v5 --price-per-hour 0.2 --price-source "GCE list price, europe-west4, 2026-09-08"

Outputs (``--out``, default ``../thesis/tables``):

    t1-security-compact.tex  A10..A19, A5, A5c: attack, refusing component, kind of evidence
    t1-scenarios.tex         the scenarios by group (attested protocol, offline)
    t2-equivalence.tex       the scenarios whose refusal moves or that have no baseline, against the frozen baseline
    t3-latency.tex           per-phase statistics, cold and warm
    t4-cost-ops.tex          VM lifetime, cost per fragment, idle pool cost and pool sizing
    t5-freeze.tex            the pinned fields of the freeze lines that differ (ov7, ov9, primary)
    t6b-llm.tex              the demo agent runs: attempted / took effect / honest done (booking_demo.report_llm)
    t6c-llm-models.tex       the same per model id, guarded runs (booking_demo.report_llm)
    v5-numbers.tex           \\newcommand macros for the prose

and ``results_v5/README.md`` as the index of the result directories.

Architecture: ``load_*`` functions read files into plain dicts, ``compute_*``
functions derive numbers, ``render_*`` functions turn them into LaTeX. No code
here interprets scenario semantics. The catalogue of attacks (``ATTACKS``) only
names what each recorded artefact demonstrates and which file it comes from. The
attack labels are those of scripts/gke-v5/attack_catalogue.md.
"""

from __future__ import annotations

import argparse
import pathlib
import glob
import json
import os
import re
import statistics
from dataclasses import dataclass
from typing import Any, Iterable

# ----------------------------------------------------------------------------
# Constants: the two freeze lines and the attack catalogue
# ----------------------------------------------------------------------------

OV7_FREEZE = "20260905T064641Z"
OV9_FREEZE = "20260911T133722Z"


@dataclass(frozen=True)
class FreezeLine:
    """One pod-VM image line: from which stamp on it ran, which image, which freeze.

    The lines are separated by time because every live record carries a stamp and none
    carries its image. `start` is the first stamp that belongs to the line (the freeze of
    the line, or for ov13 the upload of the first image built without the ov9 hardening).
    The image, not the freeze record, names what ran: some ov13 records call their image
    ov9 while their RTMR1 and RTMR2 are those of ov13.
    """

    name: str
    start: str
    image: str
    freeze: str | None


def _primary_freeze() -> str:
    """Return the pinned freeze stamp, read from scripts/gke-v5/_config.sh, where pin_freeze.py writes it."""
    cfg = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "gke-v5" / "_config.sh"
    m = re.search(r'FREEZE_STAMP="\$\{FREEZE_STAMP:-(\d{8}T\d{6}Z)\}"', cfg.read_text())
    if not m:
        raise SystemExit(f"no pinned FREEZE_STAMP in {cfg}")
    return m.group(1)


PRIMARY_FREEZE = _primary_freeze()

#: In time order. ov10 to ov12 were built but no live record ran on them before ov13
#: replaced them, so the unhardened stretch is one line, ov13.
LINES: tuple[FreezeLine, ...] = (
    FreezeLine("ov7", "", "podvm-fedora-tdx-caa-0-21-1-ov7", OV7_FREEZE),
    FreezeLine("ov9", "20260905T145032Z", "podvm-fedora-tdx-caa-0-21-1-ov9", OV9_FREEZE),
    FreezeLine("ov13", "20260923T150632Z", "podvm-fedora-tdx-caa-0-21-1-ov13", "20260924T152405Z"),
    FreezeLine("ov14", "20260925T084140Z", "podvm-fedora-tdx-caa-0-21-1-ov14", PRIMARY_FREEZE),
)
PRIMARY = LINES[-1]
IMAGE_PREFIX = "podvm-fedora-tdx-"

PHASES = ["spawn", "boot_key", "evidence", "verification", "execution", "destroy"]
PHASE_LABEL = {
    "spawn": r"spawn (VM creation, \gls{cvm} boot)",
    "boot_key": "boot key exchange",
    "evidence": r"evidence (quote in the \gls{cvm}, transfer)",
    "verification": "verification (DCAP, references, binding)",
    "execution": "execution (monitor, grant, gateway call)",
    "destroy": "destroy (deletion, confirmed by GCE)",
    "total": "total",
}

EVIDENCE_LIVE_E2E = "cluster run"
EVIDENCE_LIVE_TD = r"cluster run, inside the \gls{cvm}"
EVIDENCE_MEASURED_POLICY = "offline policy check"
EVIDENCE_OFFLINE_FIXTURE = "recorded quotes"
EVIDENCE_OFFLINE_DET = "offline test"
EVIDENCE_LIVE_PROBE = "cluster probe"


@dataclass(frozen=True)
class Attack:
    """One row of the table of attacks on the attested execution.

    ``key`` is the key in ``negative.json`` or in the network probe when the attack was run live,
    ``source`` names the file or test suite the result comes from, and ``compact`` is False for
    a row that does not apply to the evaluated setup (A5b only exists in external-networking mode).
    """

    ident: str
    title: str
    layer: str
    evidence: str
    source: str
    key: str | None = None
    compact: bool = True


ATTACKS: tuple[Attack, ...] = (
    Attack("A10", "evidence missing, or runtime data not bound to nonce, fragment, state and key",
           "relying party (binding)", EVIDENCE_LIVE_E2E, "e2e/<stamp>/negative.json", key="A10"),
    Attack("A11", r"evidence replayed for a second fragment on the same \gls{cvm}",
           r"the \gls{cvm} binds once, the nonce is used once", EVIDENCE_LIVE_TD, "e2e/<stamp>/negative.json", key="A11"),
    Attack("A12", r"\gls{cvm} with another init-data or image measurement",
           "relying party (reference values)", EVIDENCE_OFFLINE_FIXTURE, "tests_v5_fixtures.py"),
    Attack("A13", "platform downgrade to another hardware or to software evidence",
           "relying party (platform pin)", EVIDENCE_OFFLINE_FIXTURE, "tests_v5_fixtures.py"),
    Attack("A14", "controller as relay, bootstrap credential without evidence",
           "Authority", EVIDENCE_LIVE_E2E, "e2e/<stamp>/negative.json", key="A14"),
    Attack("A15", r"unbound pooled \gls{cvm} requests a grant, or is bound twice",
           "relying party (ledger)", EVIDENCE_OFFLINE_DET, "tests_v5_offline.py, tests_v5_protocol.py"),
    Attack("A16", r"bytes delivered to the \gls{cvm} differ from the attested hashes",
           "the runner, before the monitor runs", EVIDENCE_LIVE_TD, "e2e/<stamp>/negative.json", key="A16"),
    Attack("A17", "credential of one step used for another step",
           "Authority grant path (scope)", EVIDENCE_OFFLINE_DET, "tests_v5_service.py"),
    Attack("A18", "environment hash differs from the pinned one",
           "relying party (environment pin)", EVIDENCE_LIVE_E2E, "e2e/<stamp>/negative.json", key="A18"),
    Attack("A19", r"host writes onto the init-data inside the \gls{cvm}",
           "guest policy of the Kata agent", EVIDENCE_MEASURED_POLICY, "41_probe_a19.sh (OPA over the frozen policy)"),
    Attack("A5", r"\gls{cvm} egress to anything but the Authority, the execution port of the gateway and the resolver",
           "cluster network policy", EVIDENCE_LIVE_PROBE, "freeze-*/network-<stamp>.txt", key="A5"),
    Attack("A5b", "direct pod-VM NIC egress (only in external-networking mode)",
           "VPC firewall on the pod-VM tag", EVIDENCE_LIVE_PROBE, "freeze-*/network-<stamp>.txt", key="A5b", compact=False),
    Attack("A5c", r"\gls{cvm} reaches the instance metadata service",
           "pod-VM image (path closed)", EVIDENCE_LIVE_PROBE, "freeze-*/network-<stamp>.txt", key="A5c"),
)

# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------


def tex(s: Any) -> str:
    """Escape a string for LaTeX text mode."""
    s = str(s)
    for a, b in (("\\", r"\textbackslash{}"), ("&", r"\&"), ("%", r"\%"), ("_", r"\_"),
                 ("#", r"\#"), ("{", r"\{"), ("}", r"\}"), ("$", r"\$")):
        s = s.replace(a, b)
    return s


def fmt(x: float | None, nd: int = 1) -> str:
    """Format `x` with `nd` decimals, or as "--" when it is missing."""
    return "--" if x is None else f"{x:.{nd}f}"


def read_json(path: str) -> Any:
    """Parse a UTF-8 JSON file."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def stamp_of(path: str) -> str:
    """Return the first UTC stamp (YYYYMMDDTHHMMSSZ) in a path, or an empty string."""
    m = re.search(r"(\d{8}T\d{6}Z)", path)
    return m.group(1) if m else ""


def line_of(stamp: str) -> str:
    """Return the freeze line a stamp belongs to, which is the last line that had started by then."""
    return [ln.name for ln in LINES if stamp >= ln.start][-1]


def stats(xs: list[float]) -> dict[str, float | int]:
    """Return mean, stdev, median, quartiles, p95, min and max of a non-empty sample."""
    xs = sorted(xs)
    n = len(xs)
    q = statistics.quantiles(xs, n=4, method="inclusive") if n >= 2 else [xs[0]] * 3
    p95 = statistics.quantiles(xs, n=20, method="inclusive")[18] if n >= 2 else xs[0]
    return {
        "n": n, "mean": statistics.fmean(xs), "stdev": statistics.stdev(xs) if n >= 2 else 0.0,
        "median": statistics.median(xs), "q1": q[0], "q3": q[2], "p95": p95, "min": xs[0], "max": xs[-1],
    }


def write(path: str, text: str) -> None:
    """Write `text` to `path`, creating the directory, and say so."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote", path)


def table(caption: str, label: str, colspec: str, header: list[str], rows: Iterable[str | list[str]],
          size: str = r"\footnotesize", note: str | None = None, tabularx: bool = False,
          short_caption: str | None = None) -> str:
    """Render one booktabs table. Cells arrive already escaped.

    Args:
        caption: the table caption.
        label: the LaTeX label.
        colspec: the column specification.
        header: the header cells.
        rows: the body rows. A string is copied as a rule or a spanning row, a list is joined with ``&``.
        size: the font size command.
        note: a note under the table, set flush left in a small font.
        tabularx: use ``tabularx`` over the text width, so that ``X`` columns fill the line.
        short_caption: the entry of the list of tables, when it should differ from the caption.

    Returns:
        The LaTeX source.
    """
    head = " & ".join(header) + r" \\"
    body = "\n".join("    " + (r if isinstance(r, str) else " & ".join(r) + r" \\") for r in rows)
    env = r"tabularx}{\textwidth" if tabularx else "tabular"
    cap = rf"\caption[{short_caption}]{{{caption}}}" if short_caption else rf"\caption{{{caption}}}"
    out = [r"\begin{table}[!htb]", r"  \centering", "  " + size, "  " + cap,
           rf"  \label{{{label}}}", rf"  \begin{{{env}}}{{{colspec}}}", r"    \toprule",
           "    " + head, r"    \midrule", body, r"    \bottomrule",
           rf"  \end{{{'tabularx' if tabularx else 'tabular'}}}"]
    if note:
        out.append(rf"  \par\vspace{{4pt}}{{\footnotesize\raggedright {note}\par}}")
    out.append(r"\end{table}")
    return "% generated by booking_v5/report_v5.py, do not edit\n" + "\n".join(out) + "\n"


# ----------------------------------------------------------------------------
# Loading
# ----------------------------------------------------------------------------


def load_freeze(results: str, dirname: str, stamp: str) -> dict:
    """Return the freeze record `freeze-<stamp>.json` of a result directory."""
    return read_json(os.path.join(results, dirname, f"freeze-{stamp}.json"))


def line_hardening(results: str, line: FreezeLine) -> dict:
    """Return the image name plus the a5c and b1 hardening of a line, read from its image provenance.

    The freeze record is not consulted, because some records name the wrong image (see FreezeLine).
    """
    from .freeze_record import hardening_from_provenance
    prov = os.path.join(results, "podvm-image", f"{line.image}.provenance.txt")
    if not os.path.exists(prov):
        return {"image": line.image, "a5c": "no provenance", "b1": "no provenance"}
    with open(prov, encoding="utf-8") as fh:
        return {"image": line.image, **hardening_from_provenance(fh.read())}


def load_summaries(results: str) -> list[dict]:
    """Return the summary.json of every repeated live series, tagged with its stamp and directory."""
    out = []
    for p in sorted(glob.glob(os.path.join(results, "e2e", "*", "summary.json"))):
        d = read_json(p)
        d["_stamp"] = stamp_of(p)
        d["_dir"] = os.path.dirname(p)
        out.append(d)
    return out


def load_rep_steps(e2e_dir: str) -> list[dict]:
    """Return all step records of one repeated series (rep-*.json)."""
    steps = []
    for p in sorted(glob.glob(os.path.join(e2e_dir, "rep-*.json")),
                    key=lambda q: int(re.search(r"rep-(\d+)", q).group(1))):
        steps.extend(read_json(p).get("steps", []))
    return steps


def load_all_live_steps(results: str) -> list[dict]:
    """Return every live step record in e2e/ (run.json, rep-*.json, negative.json rows)."""
    steps = []
    for p in glob.glob(os.path.join(results, "e2e", "*", "*.json")):
        d = read_json(p)
        stamp = stamp_of(p)
        if isinstance(d, dict) and isinstance(d.get("steps"), list):
            for s in d["steps"]:
                s["_stamp"] = stamp
                steps.append(s)
        elif isinstance(d, dict) and isinstance(d.get("results"), dict):
            for s in d["results"].values():
                if isinstance(s, dict) and "td" in s:
                    s["_stamp"] = stamp
                    steps.append(s)
    return steps


def load_negative(results: str, stamp: str | None) -> tuple[str, dict]:
    """Return (stamp, results) of the live negative run with the given stamp, else of the latest one."""
    paths = sorted(glob.glob(os.path.join(results, "e2e", "*", "negative.json")))
    if stamp:
        paths = [p for p in paths if stamp_of(p) == stamp]
    if not paths:
        raise SystemExit("no negative.json found")
    p = paths[-1]
    return stamp_of(p), read_json(p)["results"]


def load_network(results: str, freeze_dir: str) -> dict[str, str]:
    """Return the A5, A5b and A5c verdicts from the network probe of a freeze directory, plus the probe file name."""
    paths = sorted(glob.glob(os.path.join(results, freeze_dir, "network-*.txt")))
    if not paths:
        return {"A5": "no probe recorded", "A5b": "no probe recorded"}
    text = open(paths[-1], encoding="utf-8").read()
    a5 = "no A5 block"
    m = re.search(r"== peer pod, tunnelled networking \(A5\) ==(.*?)(?:\n== |\Z)", text, re.S)
    if m:
        blocked = re.findall(r"^BLOCKED\s+(\S+)", m.group(1), re.M)
        opened = re.findall(r"^OPEN\s+(\S+)", m.group(1), re.M)
        a5 = f"{len(blocked)} targets blocked, open only: {', '.join(opened) or 'none'}"
    a5b = "NOT\\_APPLICABLE (tunnelled mode)" if "A5b NOT_APPLICABLE" in text else "see probe"
    v = re.search(r"^(A5C_(?:CLOSED|OPEN|UNDECIDED))", text, re.M)
    a5c = {"A5C_CLOSED": "BLOCKED (A5C\\_CLOSED)", "A5C_OPEN": "\\textbf{OPEN} (A5C\\_OPEN)",
           "A5C_UNDECIDED": "undecided"}.get(v.group(1) if v else "", "not judged by this probe")
    return {"A5": a5, "A5b": a5b, "A5c": a5c, "_file": os.path.basename(paths[-1])}


def load_equivalence(results: str) -> dict:
    """Return the raw equivalence record of the scenario matrix."""
    return read_json(os.path.join(results, "experiment", "equivalence.json"))


def load_experiment_results(results: str) -> dict:
    """Return the raw results of the scenario matrix on the attested protocol."""
    return read_json(os.path.join(results, "experiment", "results.json"))


# ----------------------------------------------------------------------------
# Equivalence evaluation: a derived layer over the unchanged raw record
# ----------------------------------------------------------------------------
#
# ``experiment/equivalence.json`` is the raw output of the comparator and is not edited.
# Its ``cause`` field is a placeholder and its verdict labels are the baseline's. This layer
# reads that file and the baseline file, derives the comparison sets from the scenario ids,
# checks the counts against each other and explains every invariant scenario from the
# recorded attested runs. The result is written to ``equivalence-evaluation.json`` with the
# sha256 of both inputs, so the evaluation is reproducible and cannot be mistaken for the raw record.

EQUIVALENCE_EVALUATION_VERSION = 1

# The scenarios added on purpose after the baseline was frozen. A scenario that is absent from
# the baseline and not in this set is an error, not a "new" scenario.
EXPECTED_NEW_SCENARIOS = frozenset({"benign-transport-untouched",
                                    "adv-transport-rewrites-bound-field",
                                    "adv-transport-rewrites-unbound-field"})

#: The relying party refuses before any runner under one of two rules. `run-not-at-step` is the
#: read only check of the Authority's own state (the run must be active at this step on this
#: state), `step-already-has-session` the later check that the step has no session yet. Both
#: leave no machine bound for the attempt, and the record must show it.
EARLY_REFUSAL_RULES = frozenset({"run-not-at-step", "step-already-has-session"})
EARLY_REFUSAL_STATUS = "ATTESTATION_REFUSED"


def file_sha256(path: str) -> str:
    """Return the sha256 of a file's bytes, the reference to an input that must not change."""
    import hashlib
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def evaluate_invariant(sc: dict) -> dict:
    """Explain one invariant scenario from its recorded attested runs.

    The attempt that was refused is the last attested run of the scenario. It is corroborated
    only if the record shows the early refusal rule, no runner result, a measured ledger and a
    ledger delta of zero (no pending, no foreign effect). An unmeasured ledger is not a zero.
    """
    last = (sc.get("attested_runs") or [{}])[-1]
    differing = list(sc.get("differing_fields", []))
    v5, base = sc.get("v5", {}), sc.get("baseline", {})
    v5_last = (v5.get("statuses") or [None])[-1]
    base_last = (base.get("statuses") or [None])[-1]
    corroborated = (v5_last == EARLY_REFUSAL_STATUS
                    and last.get("refusal") in EARLY_REFUSAL_RULES
                    and last.get("status") is None
                    and last.get("ledger_measured") is True
                    and last.get("effects") == 0
                    and last.get("pending_effects") == 0
                    and last.get("foreign_effects") == 0)
    lifecycle = "final_status" in differing
    differences = {"refusal_stage": "statuses" in differing,
                   "verdict_label": "verdict" in differing or "matches_prediction" in differing,
                   "lifecycle_status": lifecycle}
    lifecycle_text = (f"Run status {base.get('final_status')} in the baseline, {v5.get('final_status')} in the attested execution"
                      if lifecycle else "Run status equal in both")
    cause = (f"Baseline: {base_last}. Attested: {v5_last} at the relying party under "
             f"'{last.get('refusal')}' ({last.get('refusal_detail')}), no machine bound for the attempt, "
             f"ledger delta {last.get('effects')} (measured: {last.get('ledger_measured')}). "
             f"{lifecycle_text}. Raw labels retained in the input: verdict "
             f"{base.get('verdict')} (baseline), {v5.get('verdict')} (attested).")
    return {"name": sc["name"], "raw_level": sc["level"], "differences": differences,
            "refusal_rule": last.get("refusal"), "refusal_layer": "relying party, before a session",
            "attempt_ledger_delta": last.get("effects"), "ledger_measured": last.get("ledger_measured"),
            "corroborated_by_records": corroborated, "cause": cause}


def evaluate_equivalence(eq: dict, baseline_ids: list[str], eq_sha: str, baseline_sha: str) -> dict:
    """Derive the comparison sets, check the counts and explain the invariant scenarios.

    Args:
        eq: the raw equivalence record.
        baseline_ids: the scenario names of the baseline.
        eq_sha: sha256 of the raw record.
        baseline_sha: sha256 of the baseline file.

    Returns:
        The derived evaluation.
    """
    v5_ids = [s["name"] for s in eq["scenarios"]]
    base = set(baseline_ids)
    compared = [n for n in v5_ids if n in base]
    new = [n for n in v5_ids if n not in base]
    sets = {"total": len(v5_ids), "compared": len(compared), "new": len(new), "new_ids": new,
            "missing_from_v5": sorted(base - set(v5_ids)),
            "unexpected_new": sorted(set(new) - EXPECTED_NEW_SCENARIOS),
            "expected_new_found_in_baseline": sorted(EXPECTED_NEW_SCENARIOS & base)}
    n_levels = {k: eq[f"scenarios_{k}"] for k in ("exact", "invariant", "divergent")}
    consistent = (sets["compared"] == sum(n_levels.values())
                  and sets["total"] == sets["compared"] + sets["new"]
                  and sets["total"] == eq["scenarios_total"]
                  and sets["new"] == eq["scenarios_new"]
                  and not sets["missing_from_v5"] and not sets["unexpected_new"]
                  and not sets["expected_new_found_in_baseline"])
    invariants = [evaluate_invariant(s) for s in eq["scenarios"] if s["level"] == "invariant"]
    return {"evaluation_version": EQUIVALENCE_EVALUATION_VERSION,
            "input": {"file": "experiment/equivalence.json", "sha256": eq_sha,
                      "baseline": eq["baseline"], "baseline_sha256": baseline_sha},
            "note": "Derived layer. The input is the unchanged raw record. Its verdict labels and its "
                    "`cause` placeholder are retained there and explained here.",
            "sets": sets, "levels": n_levels, "counts_consistent": consistent,
            "lifecycle_differs": sum(1 for i in invariants if i["differences"]["lifecycle_status"]),
            "all_invariants_corroborated": all(i["corroborated_by_records"] for i in invariants),
            "invariants": invariants}


def load_equivalence_evaluation(results: str, eq: dict) -> dict:
    """Evaluate the raw record against the baseline file it names and write the derived file.

    Raises:
        SystemExit: the counts are inconsistent or an invariant scenario is not corroborated.
    """
    raw = os.path.join(results, "experiment", "equivalence.json")
    baseline = os.path.join(os.path.dirname(results), eq["baseline"])
    ev = evaluate_equivalence(eq, [r["name"] for r in read_json(baseline)["results"]],
                              file_sha256(raw), file_sha256(baseline))
    if not (ev["counts_consistent"] and ev["all_invariants_corroborated"]):
        raise SystemExit(f"equivalence evaluation is inconsistent: {json.dumps(ev['sets'])}, "
                         f"levels {ev['levels']}, corroborated {ev['all_invariants_corroborated']}")
    with open(os.path.join(results, "experiment", "equivalence-evaluation.json"), "w", encoding="utf-8") as fh:
        json.dump(ev, fh, indent=1)
    return ev


def load_world(results: str) -> dict:
    """Return the lying-world records of V2 (`results_v2_1`) and V3 (`results_v3/world`)."""
    mocks = os.path.dirname(results)
    v2 = read_json(os.path.join(mocks, "results_v2_1", "results.json"))
    v3 = read_json(os.path.join(mocks, "results_v3", "world", "results.json"))
    cells: dict[tuple[str, str, str], str] = {}
    for r in v2.get("results", []):
        m = re.match(r"(world-[a-z-]+) \[(P2(?:\.1)?)\]$", r.get("name", ""))
        if m:
            cells[(m.group(1), "V2", m.group(2))] = r.get("verdict", "?")
    for r in v3.get("results", []):
        if r.get("backend") == "in-process":
            cells[(r["name"], "V3", r["policy"])] = r.get("verdict", "?")
    names = [n for n in dict.fromkeys(k[0] for k in cells)]
    return {"cells": cells, "names": names, "v3": v3,
            "leaks_p2": sorted(n for n in names if cells.get((n, "V3", "P2")) == "LEAK_AS_PREDICTED"),
            "leaks_p21": sorted(n for n in names if cells.get((n, "V3", "P2.1")) == "LEAK_AS_PREDICTED"),
            "backends_agree": bool(v3.get("backends_agree")), "all_as_predicted": bool(v3.get("all_as_predicted"))}


def load_demo_runs(results: str) -> list[dict]:
    """Return one record per demo directory that reached an ``end`` event."""
    runs = []
    for p in sorted(glob.glob(os.path.join(results, "demo", "*", "events.json"))):
        ev = read_json(p)
        kinds = [e["kind"] for e in ev]
        if "end" not in kinds:
            continue
        start = next(e for e in ev if e["kind"] == "start")
        end = next(e for e in ev if e["kind"] == "end")
        name = os.path.basename(os.path.dirname(p))
        # T6 reports the catalogue world. Runs against a live world (domain `booking-duffel`,
        # `booking-serpapi`) are evidence of the live chapter and are checked there by
        # 39_live_evidence.py, not tabulated with the mock runs.
        if str(end.get("domain", start.get("domain", "booking"))).startswith("booking-"):
            continue
        mode = end.get("mode", start.get("mode"))
        m = re.match(rf"(\d{{8}}T\d{{6}}Z)-(?:devops-)?{re.escape(str(mode))}-([a-z-]+)-(scripted|openai)$", name)
        decisions = [(e.get("tool"), e.get("status")) for e in ev if e["kind"] == "decision"]
        attacks = [(e.get("attack"), e.get("blocked_at"), e.get("pass")) for e in ev if e["kind"] == "attack"]
        runs.append({
            "dir": name, "stamp": m.group(1) if m else stamp_of(name),
            "mode": mode, "scenario": m.group(2) if m else "?",
            "model": m.group(3) if m else start.get("model", "?"),
            "plan_phase": "plan_proposed" in kinds, "approval": "approval" in kinds,
            "attacks": attacks, "decisions": decisions,
            "payments": end.get("payments", []), "unauthorized": end.get("unauthorized_effects", 0),
            "secret_reads": end.get("secret_reads", 0), "sends": end.get("sends", 0),
            "run_status": end.get("run_status", "--"), "message": end.get("message", ""),
        })
    return runs


# ----------------------------------------------------------------------------
# Computing
# ----------------------------------------------------------------------------


def pick_series(summaries: list[dict], pool: bool, stamp: str | None) -> dict:
    """Return the cold (pool 0) or warm (pool > 0) series with the given stamp, else the largest on the primary line."""
    cands = [s for s in summaries if (s.get("pool_size", 0) > 0) == pool]
    if stamp:
        cands = [s for s in cands if s["_stamp"] == stamp]
    else:
        cands = [s for s in cands if line_of(s["_stamp"]) == PRIMARY.name]
    if not cands:
        raise SystemExit(f"no {'warm' if pool else 'cold'} series found")
    return max(cands, key=lambda s: (s["summary"]["repetitions"], s["_stamp"]))


def compute_phase_stats(steps: list[dict], handoff: str | None) -> dict[str, dict]:
    """Return per-phase statistics over accepted steps, optionally filtered by hand-off kind."""
    sel = [s for s in steps if s.get("accepted") and (handoff is None or s.get("handoff") == handoff)]
    out: dict[str, dict] = {}
    for ph in PHASES:
        xs = [s["timings"][ph] for s in sel if s.get("timings", {}).get(ph) is not None]
        if xs:
            out[ph] = stats(xs)
    out["total"] = stats([s["total_s"] for s in sel])
    out["_n"] = len(sel)
    out["_accepted"] = sum(1 for s in sel if s.get("accepted"))
    out["_effects"] = sum(s.get("effects", 0) for s in sel)
    out["_foreign"] = sum(s.get("foreign_effects", 0) for s in sel)
    out["_pending"] = sum(s.get("pending_effects", 0) for s in sel)
    return out


def derived(cold: dict, warm: dict) -> dict[str, float]:
    """Return the headline numbers: attestation share, teardown share, pool sizing rule."""
    def med(d: dict, ph: str) -> float:
        return d[ph]["median"] if ph in d else 0.0
    att_c = med(cold, "boot_key") + med(cold, "evidence") + med(cold, "verification")
    att_w = med(warm, "boot_key") + med(warm, "evidence") + med(warm, "verification")
    t_boot = med(cold, "spawn")
    t_warm = med(warm, "total")
    return {
        "att_cold_s": att_c, "att_cold_share": 100 * att_c / med(cold, "total"),
        "att_warm_s": att_w, "att_warm_share": 100 * att_w / t_warm,
        "teardown_warm_share": 100 * med(warm, "destroy") / t_warm,
        "lifecycle_cold_share": 100 * (t_boot + med(cold, "destroy")) / med(cold, "total"),
        "speedup": med(cold, "total") / t_warm,
        "pool_min": -(-t_boot // t_warm),  # ceil
        "t_boot": t_boot, "t_warm": t_warm, "t_cold": med(cold, "total"),
    }


def compute_ops(all_steps: list[dict]) -> dict[str, dict[str, int]]:
    """Count per freeze line the boots, the boot-measurement refusals and the confirmed cleanups.

    The `rtmr0` count takes every `boot-measurement-mismatch` refusal, whichever pinned boot
    field it names. In the recorded runs every such refusal names RTMR0.
    """
    out = {ln.name: {"boots": 0, "rtmr0": 0, "confirmed": 0} for ln in LINES}
    for s in all_steps:
        ln = line_of(s["_stamp"])
        out[ln]["boots"] += 1
        ref = s.get("refusal")
        if isinstance(ref, dict) and ref.get("rule") == "boot-measurement-mismatch":
            out[ln]["rtmr0"] += 1
        if s.get("cleanup_mode") == "gce_confirmed_finalizer_cleanup":
            out[ln]["confirmed"] += 1
    return out


def scenario_groups(results: dict, early: frozenset[str] = frozenset()) -> list[tuple[str, str, int, list[str]]]:
    """Return the scenarios grouped by the component that refuses them.

    The group is the verdict that the frozen baseline predicts (``expected``), except for the scenarios
    in ``early``. In the attested execution the relying party refuses these before any runner exists,
    so they form their own group instead of standing under the monitor or the grant.
    """
    groups = {
        "REFUSED_BY_RELYING_PARTY": ("refused by the relying party before the runner starts",
                                     "relying party (rule run-not-at-step or step-already-has-session)"),
        "RUN_COMPLETES": ("benign, run completes", "none (accepted)"),
        "APPROVAL_THEN_COMPLETES": ("step approval granted, run completes", "none (approval, continuation session)"),
        "DENIED_BY_MONITOR": ("denied by the monitor", "runner (monitor)"),
        "REFUSED_AT_GRANT": ("refused at grant", "authority grant path / relying party"),
        "REFUSED_AT_GATEWAY": ("refused at the gateway", "tool gateway (single-use token)"),
        "INTERVENTION_BLOCKED": ("step approval blocked", "authority (fragment-bound approval)"),
        "ACTIVATION_REFUSED": ("activation refused", "authority (approval verification, no genesis)"),
        "EFFECT_FAILED": ("effect fails, run parked fail-closed", "authority (no successor signed)"),
        "EFFECT_UNRECONCILED": ("effect ran, observation rewritten in transit, run parked",
                                "authority, successor-state check at finalisation (the call itself had happened)"),
    }
    by: dict[str, list[str]] = {}
    for sc in results.get("results", []):
        key = "REFUSED_BY_RELYING_PARTY" if sc.get("name") in early else sc.get("expected", "?")
        by.setdefault(key, []).append(sc.get("name", "?"))
    rows = []
    for key, names in by.items():
        title, layer = groups.get(key, (key, "?"))
        rows.append((title, layer, len(names), names))
    return rows


# ----------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------


def _attack_passes(a: Attack, neg: dict, net: dict[str, str]) -> bool:
    """Return whether the record of an attack shows the refusal, so that a failure cannot appear as a pass."""
    if a.key in ("A5", "A5b", "A5c"):
        return a.key != "A5c" or net.get("A5c", "").startswith("BLOCKED")
    if a.key:
        return bool(neg.get(a.key, {}).get("pass"))
    return True


def render_t1(neg_stamp: str, neg: dict, net: dict[str, str]) -> str:
    """Render the attacks on the attested execution: attack, refusing component and kind of evidence.

    The recorded verdicts are only checked here. A live row whose record does not show the
    refusal is marked, and the verdict texts stay in the result files named in the note.
    """
    rows = []
    for a in ATTACKS:
        if not a.compact:
            continue
        mark = "" if _attack_passes(a, neg, net) else r" \textbf{(FAIL)}"
        rows.append([a.ident, a.title, a.layer, a.evidence + mark])
    note = (f"Cluster rows come from the negative run \\texttt{{e2e/{neg_stamp}/}} and from the network probe "
            f"\\texttt{{{tex(net.get('_file', '?'))}}} of the {PRIMARY.name} freeze. The offline rows come from "
            "the test suites \\texttt{tests\\_v5\\_fixtures}, \\texttt{tests\\_v5\\_offline}, "
            "\\texttt{tests\\_v5\\_protocol} and \\texttt{tests\\_v5\\_service} and from "
            "\\texttt{41\\_probe\\_a19.sh}, which evaluates the measured policy.")
    ragged = r">{\raggedright\arraybackslash}"
    return table("The attacks on the attested execution, the component that refuses each and the kind of evidence",
                 "tab:security-compact", rf"@{{}}l {ragged}X {ragged}p{{3.9cm}} {ragged}p{{2.9cm}}@{{}}",
                 ["ID", "Attack", "Refused by", "Evidence"], rows, note=note, tabularx=True,
                 short_caption="Attacks on the attested execution")


def render_t1_scenarios(results: dict, early: frozenset[str] = frozenset()) -> str:
    """Render the scenarios of the matrix by refusing component, with their names.

    ``early`` names the scenarios that the relying party refuses before a cVM is bound (the invariant
    scenarios of the equivalence evaluation). They are shown as one group, as in the equivalence table.
    """
    groups = scenario_groups(results, early)
    rows = [[tex(t), str(n), ", ".join(r"\texttt{" + tex(x).replace("-", r"-\allowbreak{}") + "}" for x in names)]
            for t, _layer, n, names in groups]
    # The count comes from the data, not from a literal, because it is the kind of number a
    # reader checks.
    total = sum(n for _t, _l, n, _names in groups)
    ragged = r">{\raggedright\arraybackslash}"
    return table(f"All {total} protocol scenarios by group (offline tests with simulated attestation)",
                 "tab:t1-scenarios", rf"{ragged}p{{4.2cm}} r {ragged}p{{8.6cm}}",
                 ["Group", "n", "Scenarios"], rows, size=r"\footnotesize",
                 note=("The groups name the component that refuses in the attested execution. The scenarios of the "
                       "relying party group are listed in \\Cref{tab:t2-equivalence}. The local-container baseline refused "
                       "them later, in the monitor or at the grant."))


def render_t2(eq: dict, ev: dict) -> str:
    """Render the scenarios whose refusal differs from the baseline, and the scenarios without a baseline.

    The counts are in the table of the chapter. Here every invariant scenario shows what the
    baseline did, where the attested execution refused instead, and whether the run status differs.
    """
    rule_of = {i["name"]: i["refusal_rule"] for i in ev["invariants"]}
    rows = []
    for sc in eq["scenarios"]:
        if sc["level"] != "invariant":
            continue
        base, v5 = sc.get("baseline", {}), sc.get("v5", {})
        rule = tex(str(rule_of.get(sc["name"]))).replace("-", r"-\allowbreak{}")
        status = ("equal" if base.get("final_status") == v5.get("final_status")
                  else f"{tex(base.get('final_status'))} / {tex(v5.get('final_status'))}")
        rows.append([r"\texttt{" + tex(sc["name"]).replace("-", r"-\allowbreak{}") + "}",
                     tex((base.get("statuses") or ["?"])[-1]),
                     r"before a \gls{cvm} is bound, rule \texttt{" + rule + "}", status])
    rows.append(r"\midrule")
    for n in ev["sets"]["new_ids"]:
        rows.append([r"\texttt{" + tex(n).replace("-", r"-\allowbreak{}") + "}",
                     r"\multicolumn{3}{l}{new, no baseline counterpart}"])
    sets = ev["sets"]
    note = (f"Baseline: \\texttt{{{tex(eq.get('baseline', ''))}}}. In the {len(ev['invariants'])} scenarios above, "
            "the relying party refuses the attempt before any \\gls{cvm} is bound, and the ledger shows no "
            f"effect at the provider (measured). The other {eq['scenarios_exact']} of the {sets['compared']} compared "
            "scenarios have equal result fields. The run status column gives the status in the baseline and in the "
            "attested execution.")
    ragged = r">{\raggedright\arraybackslash}"
    return table("The scenarios in which the attested execution refuses at another point than the baseline, "
                 "and the scenarios without a baseline",
                 "tab:t2-equivalence", rf"{ragged}p{{4.4cm}} l {ragged}p{{4.0cm}} {ragged}p{{3.1cm}}",
                 ["Scenario", "Baseline", "Attested execution refuses", "Run status"], rows, note=note,
                 short_caption="Scenarios that differ from the baseline")


def _variance_note(series: dict) -> str:
    """Return the sentences naming the provider RTMR0 refusals of a series, or "" when there were none.

    A latency series may survive a refusal that is provably the provider's RTMR0 field
    (booking_v5.substrate_variance). If one occurred, the table has to say so, because the
    blanket sentence "all runs accepted" would otherwise be false, and the reader could not
    tell that the platform produced a measurement the pinned reference correctly rejected.
    """
    summary = series.get("summary", {}) if isinstance(series, dict) else {}
    count = summary.get("substrate_variance_runs", 0)
    if not count:
        return ""
    observed = {v.get("observed_rtmr0", "")[:16] for v in summary.get("substrate_variance", [])}
    one = count == 1
    return (f" {count} further {'run' if one else 'runs'} of this series "
            f"{'was' if one else 'were'} refused because the pod VM booted on "
            f"another host of the same platform generation, whose virtual firmware writes a "
            f"different RTMR0 ({', '.join(sorted(o for o in observed if o))}\\ldots). Every other "
            f"pinned measurement was byte-equal to the freeze and no effect was produced. "
            f"{'That run is' if one else 'Those runs are'} excluded from the statistics above, "
            f"so N counts admitted runs only.")


def render_t3(cold: dict, warm: dict, cold_stamp: str, warm_stamp: str, warm_pool: int,
              cold_series: dict | None = None, warm_series: dict | None = None) -> str:
    """Render the per-phase latency statistics, cold and warm, with a note on provider RTMR0 refusals."""
    def block(d: dict, title: str) -> list[list[str] | str]:
        """One block of phase rows under a spanning title row."""
        rows: list[list[str] | str] = [r"\multicolumn{7}{l}{\textit{" + tex(title) + r"}} \\"]
        for ph in PHASES + ["total"]:
            if ph not in d:
                continue
            s = d[ph]
            rows.append([PHASE_LABEL[ph], fmt(s["median"]), fmt(s["q1"]), fmt(s["q3"]), fmt(s["p95"]),
                         fmt(s["min"]), fmt(s["max"])])
        return rows
    fixed = block(cold, f"cold, N={cold['_n']} (pool 0, series {cold_stamp})")
    fixed.append(r"\addlinespace")
    fixed += block(warm, f"warm hand-off, N={warm['_n']} (pool {warm_pool}, series {warm_stamp})")
    note = ("Seconds per fragment, one fragment per run. Every counted run was accepted, with one effect and no "
            "pending or foreign effect. The distributions are not normal, so the table gives the median, "
            "the quartiles, the 95th percentile and the extremes.")
    note += _variance_note(cold_series or {}) + _variance_note(warm_series or {})
    ragged = r">{\raggedright\arraybackslash}"
    return table("Latency per phase of one attested fragment, cold and warm", "tab:t3-latency",
                 rf"{ragged}p{{5.9cm}} r r r r r r",
                 ["Phase", "median", "q1", "q3", "p95", "min", "max"], fixed, note=note,
                 short_caption="Latency per phase")


def _currency(price_src: str | None) -> str:
    """Return the currency named in the price source (USD, EUR, ...), defaulting to USD."""
    m = re.search(r"\b(USD|EUR|GBP|CHF)\b", price_src or "")
    return m.group(1) if m else "USD"


def render_t4(d: dict, cold: dict, warm: dict, ops: dict, price: float | None, price_src: str | None,
              warm_pool: int) -> str:
    """Render the cost table: VM lifetime, estimated cost per fragment, idle pool cost and pool sizing.

    `cold`, `warm` and `ops` are accepted for the call site and not read. The table takes its
    numbers from `d` (see `derived`).
    """
    def cost(seconds: float) -> str:
        if price is None:
            return r"$\approx$ " + fmt(seconds / 3600, 4) + r" $\times$ hourly price"
        return f"{seconds / 3600 * price:.4f} {currency}"

    currency = _currency(price_src)
    rows = [
        ["VM lifetime per fragment, cold (median total)", fmt(d["t_cold"]) + " s"],
        ["VM lifetime per fragment, warm (median total, excluding the earlier pre-boot)", fmt(d["t_warm"]) + " s"],
        [r"pre-boot of a warm \gls{cvm} (median spawn, cold)", fmt(d["t_boot"]) + " s"],
        ["estimated infrastructure cost per fragment, cold", cost(d["t_cold"])],
        ["estimated infrastructure cost per fragment, warm (lifetime incl. pre-boot)", cost(d["t_warm"] + d["t_boot"])],
        ["idle cost of the warm pool", f"pool size $\\times$ hourly price (pool {warm_pool} in the warm series)"
                                       + (f", {warm_pool * price:.2f} {currency} per hour" if price else "")],
        ["estimated minimum pool for the measured hand-off rate, $\\lceil T_{boot}/T_{warm} \\rceil$", str(int(d["pool_min"]))],
    ]
    # The latency shares and the per-line cleanup and RTMR0 counts are not rows here. The
    # text carries them through v5-numbers.tex, and four ratios in one cell were unreadable
    # in print.
    note = ("Cost is an estimate under the measured VM lifetime" +
            (f" at {price:.4f} {currency} per hour (c3-standard-4, {tex(price_src or 'source to add')})." if price
             else ". The hourly list price of c3-standard-4 (europe-west4) and its source are to be added."))
    ragged = r">{\raggedright\arraybackslash}"
    return table("Cost of per-step confidential execution", "tab:t4-cost", rf"{ragged}p{{8cm}} {ragged}p{{6cm}}",
                 ["Measure", "Value"], rows, size=r"\small", note=note)


def render_t5(columns: list[tuple[str, dict, dict]]) -> str:
    """Render the pinned fields per line.

    `columns` holds (header, freeze record, hardening from the image provenance). Image name,
    A5c and B1 come from the line, not from the record. A field with the same value in every
    line is not a row. It is named in the note, so that the rows show only what differs.
    """
    def g(f: dict, *ks: str) -> str:
        v: Any = f
        for k in ks:
            v = v.get(k, {}) if isinstance(v, dict) else {}
        return "" if v == {} else str(v)
    def short(h: str, n: int = 16) -> str:
        return tex(h[:n]) + r"\ldots" if len(h) > n else tex(h)
    fields = [
        ("freeze stamp", ("freeze_stamp",)), ("pod-VM image", ("image", "name")), ("overlay revision", ("image", "overlay_rev")),
        ("overlay sha256", ("image", "overlay_sha256")), ("CAA / Kata", None), ("MRTD", ("measurement", "mrtd")),
        ("RTMR0", ("measurement", "rtmr0")), ("RTMR1", ("measurement", "rtmr1")), ("RTMR2", ("measurement", "rtmr2")),
        ("init-data digest, probe quote", None), ("init-data digest, run policy", None),
        ("environment hash", ("substrate_profile_hash",)),
        ("DCAP verdict", ("dcap", "qv_result")), ("FMSPC", ("dcap", "fmspc")),
        ("probe checks 1 / 2 / 3", None), ("A5c", None), ("B1", None), ("attach", ("probe", "attach", "verdict")),
    ]
    rows, same = [], []
    for label, ks in fields:
        if label == "pod-VM image":
            vals = [h["image"].removeprefix(IMAGE_PREFIX) for _, _, h in columns]
        elif label in ("A5c", "B1"):
            vals = [h[label.lower()] for _, _, h in columns]
        elif label.startswith("init-data digest"):
            # Two digests exist: the probe pod's quote and the policy production runners are
            # measured under. A legacy record holds only the probe's.
            def init_digest(f: dict, want: str) -> str:
                init = f.get("init_data", {})
                if want == "probe":
                    return str((f.get("probe_init_data") or init).get("digest", "")) if (
                        f.get("probe_init_data") or init.get("profile") in (None, "probe")) else ""
                return str(init.get("digest", "")) if init.get("profile") == "run" else "not recorded"
            want = "probe" if "probe" in label else "run"
            vals = [init_digest(f, want) for _, f, _ in columns]
        elif label == "CAA / Kata":
            vals = [f"{g(f, 'image', 'caa')} / {g(f, 'image', 'kata')}" for _, f, _ in columns]
        elif label.startswith("probe checks"):
            vals = [f"{g(f, 'probe', 'p1')} / {g(f, 'probe', 'p2')} / {g(f, 'probe', 'p3')}" for _, f, _ in columns]
        else:
            vals = [g(f, *ks) for _, f, _ in columns]
        # Only hashes are truncated, words wrap at their spaces.
        vals = [short(v, 12) if re.fullmatch(r"[0-9a-f]{25,}", v) else tex(v) for v in vals]
        if len(set(vals)) == 1:
            same.append(f"{tex(label)} \\texttt{{{vals[0]}}}")
            continue
        rows.append([label] + [r"\scriptsize\texttt{" + v + "}" for v in vals])
    note = ("Every line verifies offline with \\texttt{freeze\\_record verify}. Long hashes are truncated here "
            "and complete in the freeze files. Image names without the common prefix \\texttt{"
            + tex(IMAGE_PREFIX) + "}. Image, A5c and B1 are read from the provenance of the image the "
            "line ran on. A5c replaces the setup of the metadata path in the image with an empty script. "
            "B1 removes the mount unit that blocks the boot of the sandbox. Identical in all lines: " + ", ".join(same) + ". "
            "The records of 24 September (ov13, superseded) name ov9 and a hardened A5c while their "
            "RTMR1/2 are those of ov13. They stay in the archive and are not used for the reported results.")
    ragged = r">{\raggedright\arraybackslash}"
    return table("Pinned values per freeze line", "tab:t5-freeze",
                 rf"{ragged}p{{3.2cm}} " + " ".join([rf"{ragged}p{{3.5cm}}"] * len(columns)),
                 ["Field"] + [c[0] for c in columns], rows, note=note)


def render_numbers(d: dict, cold: dict, warm: dict, eq: dict, ev: dict, ops: dict, neg_stamp: str,
                   cold_stamp: str, warm_stamp: str, world: dict | None = None, llm: dict | None = None) -> str:
    """Render the macros for the prose.

    Names are camel-cased with a vFive prefix. The lying world and the real-LLM block get their
    own prefixes.
    """
    m = {
        "vFiveColdN": cold["_n"], "vFiveWarmN": warm["_n"],
        "vFiveColdMedian": fmt(d["t_cold"]), "vFiveWarmMedian": fmt(d["t_warm"]),
        "vFiveBootMedian": fmt(d["t_boot"]), "vFiveSpeedup": fmt(d["speedup"]),
        "vFiveAttCold": fmt(d["att_cold_s"]), "vFiveAttColdShare": fmt(d["att_cold_share"]),
        "vFiveAttWarm": fmt(d["att_warm_s"]), "vFiveAttWarmShare": fmt(d["att_warm_share"]),
        "vFiveTeardownWarmShare": fmt(d["teardown_warm_share"]),
        "vFiveLifecycleColdShare": fmt(d["lifecycle_cold_share"]),
        "vFiveDestroyMedian": fmt(cold["destroy"]["median"]), "vFivePoolMin": int(d["pool_min"]),
        "vFiveExecMedian": fmt(cold["execution"]["median"], 2),
        "vFiveScenariosTotal": eq["scenarios_total"], "vFiveScenariosExact": eq["scenarios_exact"],
        "vFiveScenariosInvariant": eq["scenarios_invariant"], "vFiveScenariosDivergent": eq["scenarios_divergent"],
        "vFiveScenariosCompared": ev["sets"]["compared"], "vFiveScenariosNew": ev["sets"]["new"],
        "vFiveScenariosLifecycle": ev["lifecycle_differs"],
        "vFiveBootsOvNine": ops["ov9"]["boots"], "vFiveRtmrZeroOvNine": ops["ov9"]["rtmr0"],
        "vFiveBootsOvSeven": ops["ov7"]["boots"], "vFiveRtmrZeroOvSeven": ops["ov7"]["rtmr0"],
        "vFiveConfirmedOvNine": ops["ov9"]["confirmed"], "vFiveConfirmedOvSeven": ops["ov7"]["confirmed"],
        "vFiveNegativeStamp": neg_stamp, "vFiveColdStamp": cold_stamp, "vFiveWarmStamp": warm_stamp,
        "vFiveFreezeOvNine": OV9_FREEZE, "vFiveFreezeOvSeven": OV7_FREEZE,
        # The primary line: the pinned freeze and its image, whatever its name.
        "vFiveFreezePrimary": PRIMARY.freeze, "vFiveLinePrimary": PRIMARY.name,
        "vFiveBootsPrimary": ops[PRIMARY.name]["boots"], "vFiveRtmrZeroPrimary": ops[PRIMARY.name]["rtmr0"],
        "vFiveConfirmedPrimary": ops[PRIMARY.name]["confirmed"],
        "vFiveBootsOvThirteen": ops["ov13"]["boots"], "vFiveRtmrZeroOvThirteen": ops["ov13"]["rtmr0"],
        "vFiveConfirmedOvThirteen": ops["ov13"]["confirmed"],
        "vFiveBootsAll": sum(o["boots"] for o in ops.values()),
        "vFiveRtmrZeroAll": sum(o["rtmr0"] for o in ops.values()),
        "vFiveConfirmedAll": sum(o["confirmed"] for o in ops.values()),
    }
    if world:
        m.update({
            "worldScenarios": len(world["names"]),
            "worldLeaksPTwo": len(world["leaks_p2"]), "worldLeaksPTwoOne": len(world["leaks_p21"]),
            "worldAllAsPredicted": "true" if world["all_as_predicted"] else "false",
            "worldBackendsAgree": "true" if world["backends_agree"] else "false",
        })
    if llm:
        from booking_demo import report_llm
        m.update(report_llm.llm_macros(llm))      # counts per population, no intervals, no pooling
    lines = ["% generated by booking_v5/report_v5.py, do not edit"]
    lines += [rf"\newcommand{{\{k}}}{{{v}}}" for k, v in m.items()]
    return "\n".join(lines) + "\n"


def render_readme(results: str, cold_stamp: str, warm_stamp: str, neg_stamp: str, summaries: list[dict]) -> str:
    """Return the index text written to results_v5/README.md."""
    series = "\n".join(f"- `e2e/{s['_stamp']}/` pool {s.get('pool_size', 0)}, {s['summary']['repetitions']} runs, "
                       f"{s['summary']['accepted_runs']} accepted, line {line_of(s['_stamp'])}" for s in summaries)
    return f"""# results_v5 index

Generated by `booking_v5/report_v5.py`. Nothing here is edited by hand.

## Freeze lines

- `freeze-candidate/` = **{PRIMARY.name}, primary line**, freeze `{PRIMARY.freeze}` (image `{PRIMARY.image}`, B1 + A5c as no-op).
  The same directory keeps the earlier freezes: ov9 `{OV9_FREEZE}` (5 to 23 September 2026) and the ov13 records of
  24 September 2026 (`20260924T*`), whose `image`/`a5c` fields wrongly name ov9 and HARDENED (their RTMR1/2 are ov13's).
- `freeze-ov7-{OV7_FREEZE}/` = **ov7, secondary line** (accidental boot via the IMDS unit, A5c open), kept verifiable.

Re-verify offline: `python3 -m booking_v5.freeze_record verify <dir>`, `scripts/gke-v5/40_verify_v5.sh --offline`,
`python3 -m booking_v5.experiment_v5` (the scenario matrix, writes `experiment/`).

## Timed series (table T3)

- cold: `e2e/{cold_stamp}/` (pool 0)
- warm: `e2e/{warm_stamp}/` (pool refilled after every hand-out, and the `handoff` field of each step says cold or warm)

All series:
{series}

## Negative runs (table of the attacks on the attested execution)

- `e2e/{neg_stamp}/negative.json` is the {line_of(neg_stamp)} run behind that table (A10, A11, A14, A16, A18 live).
- earlier `negative.json` files are the ov7 line and the earlier rehearsal runs.
- A12, A13, A15, A17: offline (`tests_v5_fixtures.py`, `tests_v5_offline.py`, `tests_v5_service.py`).
- A19: `scripts/gke-v5/41_probe_a19.sh` (OPA over the frozen policy).
- A5, A5b, A5c: `freeze-*/network-*.txt` (A5c is judged by `scripts/gke-v5/19_probe_network.sh` since 25 September 2026).

## Equivalence (T2)

`experiment/equivalence.json` (raw), `experiment/equivalence-evaluation.json` (derived, versioned), `experiment/results.json`, `experiment/results.md`.

## Demo runs

`demo/<stamp>-<mode>-<scenario>-<model>/events.json`, `latest.json` points to the last run.
`booking_demo/report_llm.py` classifies the runs (tables t6b and t6c, and `demo/llm-summary.json`).

## Other directories

- `probe/`: every probe output of the bring-up runs (boot times, bindings, evidence, network, attach, reference values).
- `podvm-image/`: overlay tarballs, provenance and remote build logs of ov1 to ov14.
- `environment/`: the destroyed-cluster records.
- `genpolicy-3.31.0/`, `opa/`: pinned tools for the offline policy checks.
- `caa-src/`: the cloud-api-adaptor source at the pinned commit.
"""


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------


def main() -> None:
    """Regenerate every table and the macro file, and the results index unless --no-readme is given."""
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", default=os.path.join(here, "..", "results_v5"))
    ap.add_argument("--out", default=os.path.join(here, "..", "..", "thesis", "tables"))
    ap.add_argument("--cold-stamp", default=None)
    ap.add_argument("--warm-stamp", default=None)
    ap.add_argument("--negative-stamp", default=None)
    ap.add_argument("--price-per-hour", type=float, default=None)
    ap.add_argument("--price-source", default=None)
    ap.add_argument("--no-readme", action="store_true")
    a = ap.parse_args()
    results = os.path.normpath(a.results)
    out = os.path.normpath(a.out)

    summaries = load_summaries(results)
    cold_s = pick_series(summaries, pool=False, stamp=a.cold_stamp)
    warm_s = pick_series(summaries, pool=True, stamp=a.warm_stamp)
    cold = compute_phase_stats(load_rep_steps(cold_s["_dir"]), handoff=None)
    warm = compute_phase_stats(load_rep_steps(warm_s["_dir"]), handoff="warm")
    d = derived(cold, warm)
    ops = compute_ops(load_all_live_steps(results))
    neg_stamp, neg = load_negative(results, a.negative_stamp)
    net = load_network(results, "freeze-candidate")
    eq = load_equivalence(results)
    ev = load_equivalence_evaluation(results, eq)
    exp = load_experiment_results(results)
    t5_columns = []
    for ln, header in ((LINES[0], "ov7 (secondary)"), (LINES[1], "ov9"),
                       (PRIMARY, f"{PRIMARY.name} (primary)")):
        where = f"freeze-ov7-{OV7_FREEZE}" if ln.name == "ov7" else "freeze-candidate"
        t5_columns.append((header, load_freeze(results, where, ln.freeze), line_hardening(results, ln)))
    world = load_world(results)

    write(os.path.join(out, "t1-security-compact.tex"), render_t1(neg_stamp, neg, net))
    write(os.path.join(out, "t1-scenarios.tex"), render_t1_scenarios(exp, frozenset(i["name"] for i in ev["invariants"])))
    write(os.path.join(out, "t2-equivalence.tex"), render_t2(eq, ev))
    write(os.path.join(out, "t3-latency.tex"),
          render_t3(cold, warm, cold_s["_stamp"], warm_s["_stamp"], warm_s.get("pool_size", 0),
                    cold_series=cold_s, warm_series=warm_s))
    write(os.path.join(out, "t4-cost-ops.tex"), render_t4(d, cold, warm, ops, a.price_per_hour, a.price_source, warm_s.get("pool_size", 0)))
    write(os.path.join(out, "t5-freeze.tex"), render_t5(t5_columns))
    # The agent-run block, counts per population: booking_demo.report_llm.
    from booking_demo import report_llm
    llm = report_llm.summarize(report_llm.load_runs(results))
    with open(os.path.join(results, "demo", "llm-summary.json"), "w", encoding="utf-8") as fh:
        json.dump(llm, fh, indent=1, default=str)
    write(os.path.join(out, "t6b-llm.tex"), report_llm.render_t6b(llm))
    write(os.path.join(out, "t6c-llm-models.tex"), report_llm.render_models_table(llm))
    write(os.path.join(out, "v5-numbers.tex"), render_numbers(d, cold, warm, eq, ev, ops, neg_stamp, cold_s["_stamp"], warm_s["_stamp"], world, llm))
    if not a.no_readme:
        write(os.path.join(results, "README.md"), render_readme(results, cold_s["_stamp"], warm_s["_stamp"], neg_stamp, summaries))

    print(json.dumps({"cold": cold_s["_stamp"], "warm": warm_s["_stamp"], "negative": neg_stamp,
                      "derived": {k: round(v, 3) for k, v in d.items()}, "ops": ops,
                      "cold_n": cold["_n"], "warm_n": warm["_n"],
                      "world": {"leaks_p2": world["leaks_p2"], "leaks_p21": world["leaks_p21"],
                                "all_as_predicted": world["all_as_predicted"], "backends_agree": world["backends_agree"]},
                      "llm": {"by_status": llm["by_status"],
                              "populations": {k: {"n": c["n"], "m1": c["m1_unauthorized_runs"], "m2": c["m2_malicious_attempted"],
                                                  "clean_n": c["m3_clean_n"], "clean_done": c["m3_honest_completed"]}
                                              for k, c in llm["populations"].items()},
                              "unclassified": len(llm["unclassified"])}}, indent=1))


if __name__ == "__main__":
    main()
