"""Tests for the derived equivalence evaluation of report_v5 (no cluster, no experiment run).

The evaluation reads the recorded raw comparator output and the baseline file. These tests pin
what it derives from them and that it refuses what the raw record cannot support: a missing
baseline scenario, an unexpected new scenario, a count that does not add up, an invariant
scenario whose attempt was not measured at the ledger.
"""

from __future__ import annotations

import copy
import json
import os
import unittest

from . import report_v5

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESULTS = os.path.normpath(os.path.join(_HERE, "..", "results_v5"))


def _load():
    """Return the recorded raw comparator output and the scenario names of its baseline."""
    eq = report_v5.read_json(os.path.join(_RESULTS, "experiment", "equivalence.json"))
    baseline = os.path.join(os.path.dirname(_RESULTS), eq["baseline"])
    ids = [r["name"] for r in report_v5.read_json(baseline)["results"]]
    return eq, ids


class EquivalenceEvaluationTests(unittest.TestCase):
    """The derived evaluation counts what the raw record supports and refuses what it cannot."""

    @classmethod
    def setUpClass(cls):
        cls.eq, cls.ids = _load()

    def _evaluate(self, eq=None, ids=None):
        """Evaluate the recorded or the given raw record against the baseline names."""
        return report_v5.evaluate_equivalence(eq or self.eq, ids or self.ids, "raw-sha", "base-sha")

    def test_sets_are_derived_from_ids_and_add_up(self):
        ev = self._evaluate()
        self.assertTrue(ev["counts_consistent"], ev["sets"])
        self.assertEqual(set(ev["sets"]["new_ids"]), report_v5.EXPECTED_NEW_SCENARIOS)
        self.assertEqual(ev["sets"]["total"], ev["sets"]["compared"] + ev["sets"]["new"])
        self.assertEqual(ev["sets"]["compared"], sum(ev["levels"].values()))

    def test_every_invariant_attempt_is_corroborated_by_the_records(self):
        ev = self._evaluate()
        # The run position is read at the challenge, so four envelope attacks are refused before a
        # session exists and leave the run ACTIVE, where the baseline ends it. They join the
        # argument swap among the lifecycle differences.
        self.assertEqual(len(ev["invariants"]), 8)
        self.assertTrue(ev["all_invariants_corroborated"])
        self.assertEqual(ev["lifecycle_differs"], 5)
        only = [i["name"] for i in ev["invariants"] if i["differences"]["lifecycle_status"]]
        self.assertEqual(sorted(only), sorted(["adv-envelope-fact-tamper", "adv-envelope-resign-forge",
                                               "adv-skip-step", "adv-cross-run-envelope",
                                               "adv-intervention-arg-swap"]))

    def test_the_raw_record_is_not_modified(self):
        before = copy.deepcopy(self.eq)
        self._evaluate()
        self.assertEqual(self.eq, before)
        # The placeholder stays in the raw record. The explanation lives in the derived layer.
        self.assertTrue(all(s["cause"] == "TO BE DOCUMENTED" for s in self.eq["scenarios"]
                            if s["level"] == "invariant"))

    def test_a_baseline_scenario_missing_from_v5_is_not_called_new(self):
        ev = self._evaluate(ids=self.ids + ["adv-invented-baseline-case"])
        self.assertFalse(ev["counts_consistent"])
        self.assertEqual(ev["sets"]["missing_from_v5"], ["adv-invented-baseline-case"])

    def test_an_unexpected_new_scenario_is_not_accepted(self):
        eq = copy.deepcopy(self.eq)
        eq["scenarios"].append({"name": "adv-unannounced", "level": "new"})
        eq["scenarios_total"] += 1
        eq["scenarios_new"] += 1
        ev = self._evaluate(eq=eq)
        self.assertFalse(ev["counts_consistent"])
        self.assertEqual(ev["sets"]["unexpected_new"], ["adv-unannounced"])

    def test_a_count_that_does_not_add_up_is_refused(self):
        eq = copy.deepcopy(self.eq)
        eq["scenarios_total"] += 1
        self.assertFalse(self._evaluate(eq=eq)["counts_consistent"])

    def test_an_unmeasured_ledger_is_not_a_corroborated_zero(self):
        eq = copy.deepcopy(self.eq)
        sc = next(s for s in eq["scenarios"] if s["level"] == "invariant")
        sc["attested_runs"][-1]["ledger_measured"] = False
        ev = self._evaluate(eq=eq)
        self.assertFalse(ev["all_invariants_corroborated"])

    def test_a_different_refusal_rule_is_not_explained_as_the_early_refusal(self):
        eq = copy.deepcopy(self.eq)
        sc = next(s for s in eq["scenarios"] if s["level"] == "invariant")
        sc["attested_runs"][-1]["refusal"] = "binding-mismatch"
        self.assertFalse(self._evaluate(eq=eq)["all_invariants_corroborated"])

    def test_the_written_evaluation_references_both_inputs(self):
        path = os.path.join(_RESULTS, "experiment", "equivalence-evaluation.json")
        if not os.path.exists(path):
            self.skipTest("run `python3 -m booking_v5.report_v5` once to write the evaluation")
        with open(path, encoding="utf-8") as fh:
            ev = json.load(fh)
        raw = os.path.join(_RESULTS, "experiment", "equivalence.json")
        self.assertEqual(ev["input"]["sha256"], report_v5.file_sha256(raw),
                         "equivalence.json changed after the evaluation was written")
        baseline = os.path.join(os.path.dirname(_RESULTS), ev["input"]["baseline"])
        self.assertEqual(ev["input"]["baseline_sha256"], report_v5.file_sha256(baseline),
                         "the baseline changed after the evaluation was written")


if __name__ == "__main__":
    unittest.main()
