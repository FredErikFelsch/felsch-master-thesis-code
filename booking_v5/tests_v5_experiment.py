"""Semantic equivalence of the attested path against the V4 container baseline.

The tests run `experiment_v5.run_all` once (about 40 s) and pin the equivalence at two levels:
exact per scenario where it holds, and the invariants P8 (differential conformance) and P9 (every
dispatch authorised) where V5 refuses earlier, at the relying party before any runner, with the
cause named.

The pinned numbers are the finding: 20 exact, 8 invariant, 0 divergent. The eight invariant
scenarios are refused at the relying party before any runner, under `run-not-at-step` (the
Authority's read-only answer to "is the run active at this step on this state") or under
`step-already-has-session`. Three of them are the replay, fork and completed-run family, which V3
refused at the grant for freshness or completion. The fourth is the intervention arg-swap, which
V3 let reach the monitor, where the recipient binding DENIED it and terminated the run. In V5 the
swapped fragment was not parked as pending, so the continuation gate refuses it and the
legitimate run stays ACTIVE with its parked payment. The other four are the envelope attacks
(fact tamper, re-signed forgery, skipped step, envelope of another run). V3 DENIED each at the
Authority and terminated the run. Since the challenge is checked read-only against the
Authority's own state, V5 refuses them before a session exists and the run stays ACTIVE.

Configuration: P3 wraps P2.1, and the approval is gated on the pending record. The 28 baseline
scenarios are compared, and the scenarios added later are counted as new. The baseline
`results_v4_container/results.json` must have been measured on this configuration (same policy
digest). Against a stale baseline the equivalence tests are skipped with the reason, so no
comparison spans two configurations.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest

from booking_v3.scenarios import all_scenarios

from booking_v3 import experiment as v3_experiment
from booking_v3.policy import default_p3

from . import experiment_v5, report_v5

EARLIER_REFUSED = {"adv-state-replay", "adv-state-fork", "adv-replay-completed-run",
                   "adv-intervention-arg-swap", "adv-envelope-fact-tamper", "adv-envelope-resign-forge",
                   "adv-skip-step", "adv-cross-run-envelope"}
#: Where V3 refused with a terminal DENIED and the V5 run survives the refused attempt.
TERMINAL_IN_THE_BASELINE = {"adv-intervention-arg-swap", "adv-envelope-fact-tamper",
                            "adv-envelope-resign-forge", "adv-skip-step", "adv-cross-run-envelope"}


class SemanticEquivalenceTests(unittest.TestCase):
    """The attested path matches the baseline exactly or refuses earlier, with the cause named."""

    @classmethod
    def setUpClass(cls):
        report = experiment_v5.run_all()
        out = tempfile.mkdtemp(prefix="v5-experiment-")
        v3_experiment._write(default_p3(), report.results, report.diffs, out)
        with open(os.path.join(out, "results.json"), encoding="utf-8") as fh:
            cls.record = json.load(fh)
        cls.rows = experiment_v5.v5_run_rows(report)
        cls.baseline = experiment_v5.load_baseline()
        cls.stale = cls.baseline.get("policy_digest") != cls.record["policy_digest"]
        cls.eq = None if cls.stale else experiment_v5.compare(cls.record, cls.baseline, cls.rows)

    def _need_baseline(self):
        """Skip the test when the baseline was measured on another policy digest."""
        if self.stale:
            self.skipTest("results_v4_container/results.json was measured on policy digest "
                          f"{self.baseline.get('policy_digest', '?')[:16]}..., this configuration is "
                          f"{self.record['policy_digest'][:16]}...: re-run booking_v4.experiment_container first")

    def test_the_frozen_evaluation_still_holds_on_the_attested_path(self):
        self.assertTrue(self.record["p8_differential_conformance"])
        self.assertTrue(self.record["p9_all_dispatches_authorized"])
        # Not a literal: the matrix grows when a scenario is added.
        self.assertEqual(len(self.record["results"]), len(all_scenarios()))

    def test_equivalence_levels_are_the_pinned_finding(self):
        self._need_baseline()
        eq = self.eq
        # Exact and invariant are pinned findings about the frozen matrix. Divergent must stay zero.
        # New counts what was added after the baseline was frozen.
        self.assertEqual((eq["scenarios_exact"], eq["scenarios_invariant"], eq["scenarios_divergent"]),
                         (20, 8, 0), [s for s in eq["scenarios"] if s["level"] not in ("exact", "new")])
        self.assertEqual(eq["scenarios_new"],
                         len(all_scenarios()) - eq["scenarios_exact"] - eq["scenarios_invariant"])
        self.assertTrue(all(eq["whole_record_fields_equal"].values()), eq["whole_record_fields_equal"])
        self.assertEqual({s["name"] for s in eq["scenarios"] if s["level"] == "invariant"}, EARLIER_REFUSED)

    def test_every_earlier_refusal_is_the_relying_party_before_any_runner(self):
        self._need_baseline()
        for s in self.eq["scenarios"]:
            if s["level"] != "invariant":
                continue
            self.assertTrue(all(s["invariants"].values()), (s["name"], s["invariants"]))
            self.assertLessEqual(set(s["differing_fields"]),
                                 {"statuses", "final_status", "verdict", "matches_prediction", "reasons"})
            last = s["attested_runs"][-1]
            self.assertEqual((last["status"], last["effects"]), (None, 0), s["name"])
            self.assertIn(last["refusal"], report_v5.EARLY_REFUSAL_RULES, s["name"])
            self.assertEqual(s["v5"]["statuses"][-1], experiment_v5.ATTESTATION_REFUSED)
            if s["name"] in TERMINAL_IN_THE_BASELINE:
                self.assertEqual(s["baseline"]["statuses"][-1], "DENIED")        # V3: the monitor, terminal
                self.assertEqual(s["v5"]["final_status"], "ACTIVE")               # V5: the run survives
            else:
                self.assertEqual(s["baseline"]["statuses"][-1], "GRANT_REFUSED")

    def test_no_foreign_or_pending_effect_in_any_scenario(self):
        for row in self.rows:
            for r in row["runs"]:
                self.assertEqual((r["foreign_effects"], r["pending_effects"]), (0, 0), (row["scenario"], r))

    def test_a_foreign_effect_makes_an_otherwise_exact_scenario_divergent(self):
        """`foreign_effects_zero` is a level invariant, not a note."""
        if self.stale:
            self.skipTest("baseline stale")
        rows = copy.deepcopy(self.rows)
        row = next(r for r in rows if r["scenario"] == "intervention-approved")
        row["runs"][-1]["foreign_effects"] = 1
        eq = experiment_v5.compare(self.record, self.baseline, rows)
        s = next(s for s in eq["scenarios"] if s["name"] == "intervention-approved")
        self.assertEqual(s["level"], "divergent")
        self.assertFalse(s["invariants"]["foreign_effects_zero"])
        self.assertEqual(eq["scenarios_divergent"], 1)

    def test_intervention_flow_is_exact_with_a_continuation_session(self):
        row = next(r for r in self.rows if r["scenario"] == "intervention-approved")
        if not self.stale:
            s = next(s for s in self.eq["scenarios"] if s["name"] == "intervention-approved")
            self.assertEqual(s["level"], "exact")
        self.assertEqual([(r["step"], r["status"], r["effects"]) for r in row["runs"]],
                         [(0, "STEP_COMPLETED", 1), (1, "STEP_COMPLETED", 1), (2, "STEP_COMPLETED", 1),
                          (3, "REQUIRE_APPROVAL", 0), (3, "STEP_COMPLETED", 1)])


if __name__ == "__main__":
    unittest.main()
