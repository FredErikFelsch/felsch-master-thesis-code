"""V5 driver for the frozen scenario matrix (booking_v3.scenarios): semantic equivalence, offline.

The matrix has 31 scenarios, three of which were added after the V4 baseline was frozen
(`report_v5.EXPECTED_NEW_SCENARIOS`). The frozen booking_v3 evaluation (the scenario matrix,
the P8 differential conformance and the P9 dispatch safety properties) runs unchanged and only
the deployment backend is substituted, as in V4. Here the backend is the V5 attested fragment
path over the real in-process services:

    scenario  ->  fragment/envelope octets  ->  AttestedFragmentController.execute_fragment
              ->  (attest, establish session, octet check inside the "TD")
              ->  the frozen V3 EphemeralRunner behind the V5 protocol  ->  runner result

The adapter interprets no scenario semantics. It serialises what the scenario hands it,
drives the attested path and returns the runner result unchanged. Where the relying party
refuses before any runner exists (no V3 outcome), the adapter returns the V5 run record in
the frozen result shape: status `ATTESTATION_REFUSED`, and as reason the run record's
outcome word (`REFUSED(<rule>)`, or `UNMEASURED` when the ledger could not be read), as the
live e2e records it. No code maps such a refusal onto a V3 status, so a scenario that V5
refuses earlier than V3 surfaces as a divergence in `statuses`, and the equivalence report
then falls back to the P8 and P9 invariants for that scenario.

The services are the same objects the cluster runs (two role-bound DurableDeploymentServers
on loopback, the V5 relying party in front of the frozen Authority, the effect ledger on the
gateway's observation surface). Evidence is the fake AA with the real RTMR3 replay. The
hardware path is covered separately by tests_v5_fixtures on recorded quotes. The fake AA and
the pipe stream are imported from the test module tests_v5_protocol.

Run from the repository root with `python3 -m booking_v5.experiment_v5`. It writes
results_v5/experiment/{results.json,results.md,equivalence.json}. The equivalence is reported
against results_v4_container/results.json at two levels: exact per scenario, else the P8 and
P9 invariants with the differing fields named.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any

from booking_v3 import experiment as v3_experiment
from booking_v3 import scenarios as v3_scenarios
from booking_v3.policy import default_p3
from booking_v3.provisioner import create_deployment
from booking_v3.runner import RunnerResult
from booking_v4.durable import (AuthorityFacade, DurableDeploymentServer, DurableStore,
                                GatewayFacade, HumanApprovalClient, _RestoredDeployment)

from . import protocol, runner_main
from .attach_transport import AttachTransport
from .controller_v5 import AttestedFragmentController, RemoteAuthority, RunRecord
from .gateway import DurableLedger, RemoteLedger
from .pool import TdPool
from .profile_v5 import substrate_profile_hash
from .relying_party import AuthorityRelyingParty, FakeVerifier, ReferenceValues
from .tests_v5_protocol import _FakeAA, _PipeStream

BASELINE = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "results_v4_container", "results.json")
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v5", "experiment")

# The fields of one ScenarioResult that the primary (exact) check compares, which are all of them.
RESULT_FIELDS = ("name", "description", "expected", "statuses", "final_status", "verdict",
                 "matches_prediction", "effects_exact", "chain_ok", "reasons",
                 "executed_ops", "note")


# The status under which a relying-party refusal (no runner, no V3 result) is recorded.
ATTESTATION_REFUSED = "ATTESTATION_REFUSED"
# Statuses that end a step without executing it, in V3 and (with the V5 one added) in V5.
_REJECTING = {"DENIED", "GRANT_REFUSED", "GATEWAY_REFUSED", "REQUIRE_APPROVAL",
              "ACTIVATION_REFUSED", "FINALIZE_REFUSED", ATTESTATION_REFUSED}


# --- the TD substitute: one runner thread per spawned TD ------------------------------------

class _ThreadTdBackend:
    """TdPool backend whose "TDs" are runner threads over pipes (the tests_v5_service shape)."""

    def __init__(self) -> None:
        self.n = 0
        self.alive: set[str] = set()
        self.deleted: list[str] = []

    def create(self) -> str:
        """Name a new thread TD. The thread starts when the transport opens its stream."""
        self.n += 1
        name = f"td-{self.n}"
        self.alive.add(name)
        return name

    def is_ready(self, name: str) -> bool:
        """A thread TD is ready at once."""
        return True

    def delete_and_confirm(self, name: str) -> None:
        """Forget the TD. Its stream is closed by the caller."""
        self.alive.discard(name)
        self.deleted.append(name)

    def list_managed(self) -> list[str]:
        """Return the names of the live thread TDs."""
        return sorted(self.alive)


class _V5AuthorityFacade(AuthorityFacade):
    """AuthorityFacade over the V5 authority role.

    The V5 service surface has no `authority.establish_runner_session`, because a runner
    credential exists only sealed to an attested boot key (`v5.establish_session`). The three
    scenarios that play the trusted runner directly (bootstrap in hand) therefore call the
    frozen Authority in process, as the V3 in-process backend did. This is harness plumbing,
    not a scenario decision, and it is named in the equivalence report.
    """

    def establish_runner_session(self, bootstrap, run_id, fragment_hash, state_hash,
                                 request_nonce=None):
        """Call the frozen Authority in process. `request_nonce` is not used on this path."""
        return self._real.establish_runner_session(bootstrap, run_id, fragment_hash, state_hash)


@dataclass
class _AttestedRunnerHandle:
    """Single-use handle: one spawned TD, one fragment, one attested execution."""

    deployment: "AttestedInProcessDeployment"
    fragment: Any
    envelope: Any
    _used: bool = False

    def execute(self, policy, envelope, fragment, intervention_approval=None):
        """Serialise what the scenario hands over, run the attested path and return the result.

        Raises:
            RuntimeError: the handle was already used, or the path produced neither a refusal
                nor a result.
        """
        if self._used:
            raise RuntimeError("this attested runner was already used (single use)")
        self._used = True
        dep = self.deployment
        dep.transport.policy = policy
        dep.transport.intervention = intervention_approval
        rec = dep.controller.execute_fragment(
            fragment.run_id, fragment.fragment_index,
            protocol.fragment_bytes(fragment), protocol.envelope_bytes(envelope))
        dep.records.append(rec)
        if rec.td is not None:
            dep.transport.close(rec.td)          # the TD is gone and its stream goes with it
        if rec.refusal is not None:
            return RunnerResult(status=ATTESTATION_REFUSED, envelope=None, reason=rec.outcome,
                                payload=None, runner_no=-1)
        if rec.result is None:
            raise RuntimeError("attested path produced neither a refusal nor a result")
        return rec.result


class _AttestedProvisioner:
    """The V3 RunnerProvisioner interface (spawn(fragment, envelope)) on the attested path."""

    def __init__(self, deployment: "AttestedInProcessDeployment") -> None:
        self._deployment = deployment

    def spawn(self, fragment, envelope) -> _AttestedRunnerHandle:
        """Return a single-use handle for one fragment on the attested path."""
        return _AttestedRunnerHandle(self._deployment, fragment, envelope)


class AttestedInProcessDeployment:
    """One fresh V5 deployment per scenario: services on loopback, attested runner path.

    Exposes what `booking_v3.scenarios.make_context` needs (authority, gateway, anchors,
    provisioner, bootstrap, human_interface). Mutations reach the frozen Authority and gateway
    through the durable, role-bound service boundary. Reads come from the live objects.
    """

    def __init__(self, clock, executor=None) -> None:
        self.tmp = tempfile.mkdtemp(prefix="v5-exp-")
        base = create_deployment(clock, executor=executor)
        self.base = base
        self.bootstrap = base.bootstrap
        self.anchors = base.anchors
        self.records: list[RunRecord] = []
        self.runner_errors: list[BaseException] = []
        self._threads: list[threading.Thread] = []
        self._files: list = []

        self.ref = ReferenceValues(require_rtmr3=True,
                                   substrate_profile_hash=substrate_profile_hash())
        rp = AuthorityRelyingParty(FakeVerifier(), self.ref)
        self.rp = rp
        self.auth_store = DurableStore(os.path.join(self.tmp, "authority.db"))
        self.gw_store = DurableStore(os.path.join(self.tmp, "gateway.db"))
        self.authority_server = DurableDeploymentServer(
            _RestoredDeployment(base.authority, None, rp), self.auth_store,
            tcp=("127.0.0.1", 0), role="authority")
        self.gateway_server = DurableDeploymentServer(
            _RestoredDeployment(None, base.gateway), self.gw_store,
            tcp=("127.0.0.1", 0), role="gateway", observe_tcp=("127.0.0.1", 0))

        # This makes this stage check observations at all. V3 and V4 bind no ledger and
        # therefore behave as they were measured. The countermeasure appears on
        # the stage whose threat model has a hostile host beneath the runner.
        base.authority.bind_effect_ledger(DurableLedger(self.gw_store))
        self.authority = _V5AuthorityFacade(base.authority, self.authority_server.endpoint)
        self.gateway = GatewayFacade(base.gateway, self.gateway_server.endpoint)
        self.human_interface = HumanApprovalClient(self.authority_server.endpoint, base.human)

        self.backend = _ThreadTdBackend()
        self.pool = TdPool(self.backend, size=0)                           # cold path
        self.transport = AttachTransport(
            open_stream=lambda td: self._start_runner(), anchors=self.anchors,
            endpoint=self.authority_server.endpoint,
            gateway_endpoint=self.gateway_server.endpoint, policy=None)
        self.ledger = RemoteLedger(self.gateway_server.observe_endpoint)
        self.controller = AttestedFragmentController(
            self.pool, RemoteAuthority(self.authority_server.endpoint), self.transport,
            ledger=self.ledger)
        self.provisioner = _AttestedProvisioner(self)

    def _start_runner(self) -> _PipeStream:
        """Start one runner thread as one TD (runner_main.serve with the frozen V3 monitor)."""
        c2r_r, c2r_w = os.pipe()
        r2c_r, r2c_w = os.pipe()
        rx, tx = os.fdopen(c2r_r, "r"), os.fdopen(r2c_w, "w")
        ctl_tx, ctl_rx = os.fdopen(c2r_w, "w"), os.fdopen(r2c_r, "r")
        self._files += [rx, tx, ctl_tx, ctl_rx]
        aa = _FakeAA(self.ref.init_data_digest)

        def _run() -> None:
            try:
                runner_main.serve(rx, tx, aa=aa)
            except BaseException as exc:                                   # noqa: BLE001 (reported per scenario)
                self.runner_errors.append(exc)
            finally:
                try:
                    tx.close()
                except Exception:                                          # noqa: BLE001 (already closed)
                    pass

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        self._threads.append(thread)
        return _PipeStream(ctl_tx, ctl_rx)

    def close(self) -> None:
        """Release listeners, stores, pipes and threads. Idempotent.

        The run records (`self.records`) stay, so a closed deployment still reports.
        """
        if getattr(self, "_closed", False):
            return
        self._closed = True
        self.transport.close()
        for f in self._files:
            try:
                f.close()
            except Exception:                                              # noqa: BLE001 (already closed)
                pass
        for t in self._threads:
            t.join(timeout=5)
        self.authority_server.close()
        self.gateway_server.close()
        self.auth_store.close()
        self.gw_store.close()


_DEPLOYMENTS: list[AttestedInProcessDeployment] = []
_CURRENT_SCENARIO: list[str] = [""]


def create_attested_deployment(clock, executor=None) -> AttestedInProcessDeployment:
    """Deployment factory for `booking_v3.scenarios.set_deployment_factory`.

    A scenario may build several contexts (cross-run), so each deployment is tagged with the
    scenario name.
    """
    # Release the previous scenario's listeners, stores and pipes before opening new ones.
    # The matrix would otherwise hold one deployment per scenario open at once, which exceeds
    # the default file-descriptor limit on macOS (256). Records survive.
    for prev in _DEPLOYMENTS:
        if prev.scenario != _CURRENT_SCENARIO[0]:      # a scenario may build several contexts
            prev.close()
    dep = AttestedInProcessDeployment(clock, executor=executor)
    dep.scenario = _CURRENT_SCENARIO[0]
    _DEPLOYMENTS.append(dep)
    return dep


def _tagged_scenarios():
    """Return the frozen matrix, each `run` wrapped only to name the current scenario for tagging."""
    def _wrap(scenario):
        def run():
            _CURRENT_SCENARIO[0] = scenario.name
            return scenario.run()
        return v3_scenarios.Scenario(scenario.name, scenario.description, scenario.expected, run)
    return [_wrap(s) for s in v3_scenarios.all_scenarios()]


# --- the run -------------------------------------------------------------------------------

@dataclass
class RunReport:
    """The frozen evaluation's output plus the per-scenario attested run records."""

    results: list
    diffs: list
    deployments: list[AttestedInProcessDeployment] = field(default_factory=list)


def run_all() -> RunReport:
    """Run the frozen evaluation with the attested in-process backend installed."""
    _DEPLOYMENTS.clear()
    v3_scenarios.set_deployment_factory(create_attested_deployment)
    original_all = v3_experiment.all_scenarios
    v3_experiment.all_scenarios = _tagged_scenarios
    try:
        results, diffs = v3_experiment.run_all()
        return RunReport(results, diffs, list(_DEPLOYMENTS))
    finally:
        v3_experiment.all_scenarios = original_all
        v3_scenarios.set_deployment_factory(None)
        for dep in _DEPLOYMENTS:
            dep.close()
        _DEPLOYMENTS.clear()


def v5_run_rows(report: RunReport) -> list[dict]:
    """Return one row per scenario with every attested execution its deployments made."""
    rows: dict[str, dict] = {}
    for dep in report.deployments:
        row = rows.setdefault(dep.scenario, {"scenario": dep.scenario, "runs": [],
                                             "runner_errors": []})
        row["runs"] += [{"run_id": r.run_id, "step": r.step, "td": r.td,
                         "status": getattr(r.result, "status", None),
                         "refusal": r.refusal.rule if r.refusal else None,
                         "refusal_detail": r.refusal.detail if r.refusal else None,
                         "effects": r.effects, "pending_effects": r.pending_effects,
                         "foreign_effects": r.foreign_effects,
                         "ledger_measured": r.ledger_measured} for r in dep.records]
        row["runner_errors"] += [f"{type(e).__name__}: {e}" for e in dep.runner_errors]
    return list(rows.values())


# --- the equivalence -----------------------------------------------------------------------

def _rejected(record: dict) -> bool:
    """Whether a scenario ended in a refusal or denial, that is its last step status is a rejecting one."""
    return bool(record["statuses"]) and record["statuses"][-1] in _REJECTING


_UNTOUCHED = ("ACTIVE", "COMPLETED")


def _invariants(v5: dict, base: dict) -> dict:
    """Return the P8 and P9 invariants for a scenario whose exact record diverged.

    They are: identical legitimately executed operations, zero unauthorised effects,
    "rejected in V3 implies rejected in V5", and the final run state.

    The final-state invariant has one named exception. Where V5 refuses at the relying
    party before any runner (`ATTESTATION_REFUSED`), the run is untouched by the attempt
    (ACTIVE or COMPLETED, as before it), even where V3 let the attempt reach the monitor and a
    DENY terminated the run. Refusing earlier and leaving the legitimate run alive is the
    stronger outcome, not a regression. The invariant then asks for "untouched", not for
    "equal to V3".
    """
    earlier = bool(v5["statuses"]) and v5["statuses"][-1] == ATTESTATION_REFUSED
    if earlier:
        final_ok = v5["final_status"] in _UNTOUCHED
    else:
        final_ok = v5["final_status"] == base["final_status"]
    return {
        "same_executed_ops": v5["executed_ops"] == base["executed_ops"],
        "p9_effects_exact": bool(v5["effects_exact"]),
        "same_final_status_or_untouched_by_earlier_refusal": final_ok,
        "rejected_in_v3_implies_rejected_in_v5": (not _rejected(base)) or _rejected(v5),
    }


def compare(v5_record: dict, baseline_record: dict, run_rows: list[dict] | None = None) -> dict:
    """Compare the V5 results with the baseline at two levels.

    The comparison is exact per scenario, else it uses the invariants plus the differing
    fields. The primary check is not weakened globally. A scenario is `exact` only if every
    ScenarioResult field is equal. Otherwise it is `invariant` (all invariants hold, cause to
    be documented) or `divergent` (an invariant fails, which is a regression and not a
    reporting change). A scenario absent from the baseline is `new`.

    Args:
        v5_record: the V5 results.json.
        baseline_record: the frozen V4 container results.json.
        run_rows: the attested run rows from `v5_run_rows`.

    Returns:
        The equivalence report.
    """
    base_by_name = {r["name"]: r for r in baseline_record["results"]}
    rows_by_name = {r["scenario"]: r for r in (run_rows or [])}
    scenarios = []
    for r in v5_record["results"]:
        base = base_by_name.get(r["name"])
        entry = {"name": r["name"]}
        if base is None:
            # Not a divergence. Divergent means an invariant of the frozen matrix failed, which
            # is a regression. A scenario the baseline never ran cannot fail such an invariant,
            # and counting it as one would spend the zero that carries the equivalence claim on
            # a scenario that has nothing to be equivalent to. It is reported on its own and
            # the run still fails if any real invariant breaks.
            entry.update(level="new", cause="scenario absent from the baseline, added after it was frozen")
        else:
            differing = [f for f in RESULT_FIELDS if r.get(f) != base.get(f)]
            if not differing:
                entry["level"] = "exact"
            else:
                inv = _invariants(r, base)
                entry.update(level="invariant" if all(inv.values()) else "divergent",
                             differing_fields=differing, invariants=inv,
                             v5={f: r.get(f) for f in differing},
                             baseline={f: base.get(f) for f in differing},
                             cause="TO BE DOCUMENTED")
        row = rows_by_name.get(r["name"])
        # An invariant over nothing is not satisfied but unobserved. `all([])` is True, so
        # a scenario with no attested execution would "have no foreign effects", and a
        # scenario missing from `rows_by_name` would get no key and be read as True by the
        # reader's default. Both must say so explicitly.
        runs = row["runs"] if row is not None else []
        measured = [x for x in runs if x.get("ledger_measured")]
        if row is not None:
            entry["attested_runs"] = runs
            entry["runner_errors"] = row["runner_errors"]
        entry["attested_runs_total"] = len(runs)
        entry["attested_runs_measured"] = len(measured)
        # Three outcomes, not two:
        #   True   every attested run reached the ledger and none showed a foreign effect
        #   False  a foreign effect was recorded
        #   None   the invariant was not observed, and `foreign_effects_status` says why
        if runs and len(measured) == len(runs):
            entry["foreign_effects_zero"] = all(x["foreign_effects"] == 0 for x in measured)
            entry["foreign_effects_status"] = "measured"
        elif not runs:
            # Legitimately vacuous: several adversarial scenarios attack the Authority or the
            # gateway directly, or end before any fragment runs, so no TD is ever bound. That
            # is not a gap in the measurement, but it is also not evidence, so it is named.
            entry["foreign_effects_zero"] = None
            entry["foreign_effects_status"] = "no-attested-runs"
        else:
            entry["foreign_effects_zero"] = None
            entry["foreign_effects_status"] = "unmeasured"
        # A foreign effect (an effect the ledger attributes to no attested session) is a P9
        # violation whatever the V3 comparison says. It is an invariant of the level, not a
        # side note, so the scenario is divergent. A run that happened but never reached the
        # ledger is divergent too.
        if entry["foreign_effects_zero"] is False:
            entry.setdefault("invariants", {})["foreign_effects_zero"] = False
            entry.update(level="divergent", cause="foreign effect recorded on the attested ledger")
        elif entry["foreign_effects_status"] == "unmeasured":
            entry.setdefault("invariants", {})["foreign_effects_zero"] = None
            entry.update(level="divergent",
                         cause=f"foreign_effects_zero unobserved: {len(measured)} of {len(runs)} "
                               f"attested runs reached the ledger")
        scenarios.append(entry)
    levels = [s["level"] for s in scenarios]
    whole = {k: v5_record.get(k) == baseline_record.get(k)
             for k in ("policy_digest", "p8_differential_conformance",
                       "p9_all_dispatches_authorized", "differential")}
    return {
        "baseline": os.path.relpath(BASELINE, os.path.dirname(os.path.dirname(__file__))),
        "exact_results_json_equal": v5_record == baseline_record,
        "scenarios_total": len(scenarios),
        "scenarios_exact": levels.count("exact"),
        "scenarios_invariant": levels.count("invariant"),
        "scenarios_divergent": levels.count("divergent"),
        "scenarios_new": levels.count("new"),
        "whole_record_fields_equal": whole,
        "harness_notes": [
            "authority.establish_runner_session is not on the V5 service surface. The scenarios "
            "that play the trusted runner with the bootstrap in hand call the frozen Authority "
            "in process (as the V3 in-process backend did).",
            "evidence: fake AA over the real RTMR3 replay. DCAP on recorded quotes is tests_v5_fixtures.",
        ],
        "scenarios": scenarios,
    }


def load_baseline() -> dict:
    """Return the frozen V4 container results that the equivalence is measured against."""
    with open(BASELINE, encoding="utf-8") as fh:
        return json.load(fh)


def _print_equivalence(eq: dict) -> None:
    print("\nEquivalence against", eq["baseline"])
    print(f"  exact results.json ==   : {eq['exact_results_json_equal']}")
    print(f"  scenarios exact/invariant/divergent/new: {eq['scenarios_exact']}/"
          f"{eq['scenarios_invariant']}/{eq['scenarios_divergent']}/{eq['scenarios_new']}"
          f" of {eq['scenarios_total']}")
    for s in eq["scenarios"]:
        if s["level"] != "exact":
            print(f"  [{s['level']}] {s['name']}: differing {s.get('differing_fields')}")
            print(f"      v5={s.get('v5')}\n      baseline={s.get('baseline')}")
        if s.get("foreign_effects_zero") is False:
            print(f"  [FOREIGN EFFECTS] {s['name']}")
        elif s.get("foreign_effects_status") == "unmeasured":
            print(f"  [UNOBSERVED] {s['name']}: {s.get('attested_runs_measured')} of "
                  f"{s.get('attested_runs_total')} attested runs reached the ledger")
        elif s.get("foreign_effects_status") == "no-attested-runs":
            print(f"  [no attested run] {s['name']}: this scenario binds no TD, so the ledger "
                  f"invariant is vacuous rather than satisfied")
        if s.get("runner_errors"):
            print(f"  [runner errors] {s['name']}: {s['runner_errors']}")


def main() -> int:
    """Run the matrix on the attested backend, write the results and print the equivalence.

    Returns 0 when no scenario is divergent, else 1.
    """
    policy = default_p3()
    report = run_all()
    print("BACKEND: V5 attested fragment path over the in-process V5 services (two role-bound")
    print("         durable servers on loopback, V5 relying party, fake AA with real RTMR3")
    print("         replay, runner_main.serve with the frozen V3 EphemeralRunner per TD)")
    v3_experiment._print(policy, report.results, report.diffs)
    v3_experiment._write(policy, report.results, report.diffs, OUT_DIR)
    with open(os.path.join(OUT_DIR, "results.json"), encoding="utf-8") as fh:
        v5_record = json.load(fh)
    eq = compare(v5_record, load_baseline(), v5_run_rows(report))
    with open(os.path.join(OUT_DIR, "equivalence.json"), "w", encoding="utf-8") as fh:
        json.dump(eq, fh, indent=2)
    _print_equivalence(eq)
    print(f"\nWrote {OUT_DIR}/results.json, results.md and equivalence.json")
    return 0 if eq["scenarios_divergent"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
