"""Offline tests for `scripts/gke-v5/12_create_cluster_v5.sh`: order, reconcile, abort.

The script builds the substrate half of the Fixed Execution Profile, so its failure modes are
security failure modes, and every one of them is expensive to discover on a real cluster. A fake
gcloud and kubectl (`testdata/fake_cloud.py`) answer from a scenario and record every call, so
three questions can be asked without a cloud project:

    order      Is the firewall policy associated with the network only after all its rules
               exist? Otherwise a rerun denies everything to running pod VMs for a moment.
    reconcile  Is an existing resource updated to the pinned state, or silently kept? A stale
               allow list that kept only tcp breaks the VXLAN tunnel.
    abort      Does a drift that cannot be repaired in place stop the run?

Run:  python3 -m booking_v5.tests_substrate_script
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest

MOCKS = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = MOCKS / "scripts" / "gke-v5" / "12_create_cluster_v5.sh"
FAKE = pathlib.Path(__file__).resolve().parent / "testdata" / "fake_cloud.py"

FRESH = {
    "project": "test-project", "network": "default", "node_subnet": "default",
    "node_cidr": "10.164.0.0/20", "subnet": None, "fw_rules": {}, "policy": False,
    "policy_rules": {}, "associations": [], "zones": {}, "records": {},
}
GOOD_SUBNET = {"cidr": "192.168.200.0/24", "network": "projects/p/global/networks/default", "pga": "True"}

GOOD_ASSOCIATION = {
    "name": "v5-runner-td-policy-default",
    "attachmentTarget": (
        "https://www.googleapis.com/compute/v1/"
        "projects/test-project/global/networks/default"
    ),
}


class Run:
    """One scripted run: the scenario, the exit code and the ordered call log."""

    def __init__(self, state: dict, env: dict | None = None):
        with tempfile.TemporaryDirectory() as d:
            tmp = pathlib.Path(d)
            binding = tmp / "bin"
            binding.mkdir()
            for name in ("gcloud", "kubectl"):
                dst = binding / name
                shutil.copy(FAKE, dst)
                dst.chmod(dst.stat().st_mode | stat.S_IEXEC)
            (tmp / "state.json").write_text(json.dumps(state))
            log = tmp / "calls.log"
            log.touch()
            environ = dict(os.environ, PATH=f"{binding}:{os.environ['PATH']}",
                           FAKE_STATE=str(tmp / "state.json"), FAKE_LOG=str(log),
                           PROJECT="test-project", V5_MAINTENANCE_EXCLUSION="0")
            environ.update(env or {})
            proc = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, env=environ)
            self.code = proc.returncode
            self.output = proc.stdout + proc.stderr
            self.calls = [line.split("\t") for line in log.read_text().splitlines()]

    def index_of(self, *needles: str) -> int:
        """Return the position of the first call that contains every needle, or -1 if there is none."""
        for i, call in enumerate(self.calls):
            joined = " ".join(call)
            if all(n in joined for n in needles):
                return i
        return -1

    def happened(self, *needles: str) -> bool:
        """Return whether a recorded call contains every needle."""
        return self.index_of(*needles) >= 0


class OrderTests(unittest.TestCase):
    """The firewall policy is associated with the network only after all its rules exist."""

    def test_the_policy_is_associated_only_after_all_its_rules_exist(self):
        """A rerun must not leave a running pod VM with a deny and no allows."""
        run = Run(dict(FRESH))
        self.assertEqual(run.code, 0, run.output)
        assoc = run.index_of("network-firewall-policies", "associations", "create")
        self.assertGreaterEqual(assoc, 0, "the policy was not associated")
        for prio in ("65000", "1000", "1001"):
            rule = run.index_of("network-firewall-policies", "rules", "create", prio)
            self.assertGreaterEqual(rule, 0, f"rule {prio} was not created")
            self.assertLess(rule, assoc, f"rule {prio} was created after the association")

    def test_an_existing_association_is_not_created_again(self):
        run = Run(
            dict(
                FRESH,
                policy=True,
                associations=[GOOD_ASSOCIATION],
            )
        )

        self.assertEqual(run.code, 0, run.output)
        self.assertFalse(
            run.happened("associations", "create"),
            "an existing correct association must not be created again",
        )


class ReconcileTests(unittest.TestCase):
    """An existing resource is updated to the pinned state and not silently kept."""

    def test_an_existing_tunnel_rule_is_updated_to_the_pinned_allow_list(self):
        """A `describe || create` would keep a stale rule that allowed only tcp and break the tunnel."""
        state = dict(FRESH, subnet=GOOD_SUBNET,
                     fw_rules={"v5-allow-peerpod-tunnel": {"direction": "INGRESS"}})
        run = Run(state)
        self.assertEqual(run.code, 0, run.output)
        i = run.index_of("firewall-rules", "update", "v5-allow-peerpod-tunnel")
        self.assertGreaterEqual(i, 0, "the existing rule was kept instead of reconciled")
        self.assertIn("tcp:15150,udp:4789", " ".join(run.calls[i]))

    def test_an_existing_return_rule_is_reconciled_too(self):
        state = dict(FRESH, subnet=GOOD_SUBNET,
                     fw_rules={"v5-allow-peerpod-tunnel-return": {"direction": "INGRESS"}})
        run = Run(state)
        self.assertEqual(run.code, 0, run.output)
        self.assertTrue(run.happened("firewall-rules", "update", "v5-allow-peerpod-tunnel-return"))

    def test_a_drifted_policy_rule_is_updated_not_kept(self):
        state = dict(FRESH, subnet=GOOD_SUBNET, policy=True,
                     policy_rules={"1001": {"direction": "EGRESS"}})
        run = Run(state)
        self.assertEqual(run.code, 0, run.output)
        i = run.index_of("network-firewall-policies", "rules", "update", "1001")
        self.assertGreaterEqual(i, 0, "the existing policy rule was kept instead of reconciled")
        self.assertIn("udp:4789", " ".join(run.calls[i]))

    def test_private_google_access_is_switched_back_on(self):
        """Without it the guest pull cannot reach the API VIP and every peer pod stalls."""
        run = Run(dict(FRESH, subnet=dict(GOOD_SUBNET, pga="False")))
        self.assertEqual(run.code, 0, run.output)
        self.assertTrue(run.happened("subnets", "update", "--enable-private-ip-google-access"))

    def test_a_dns_zone_not_attached_to_the_network_is_attached(self):
        state = dict(FRESH, subnet=GOOD_SUBNET,
                     zones={"v5-googleapis": {"networks": ["projects/p/global/networks/other"]}})
        run = Run(state)
        self.assertEqual(run.code, 0, run.output)
        self.assertTrue(run.happened("managed-zones", "update", "v5-googleapis"))

    def test_a_correct_environment_creates_nothing(self):
        """A full reconcile run creates nothing that already exists."""
        state = dict(FRESH, subnet=GOOD_SUBNET, policy=True,
                     associations=[GOOD_ASSOCIATION],
                     fw_rules={"v5-allow-peerpod-tunnel": {"direction": "INGRESS"},
                               "v5-allow-peerpod-tunnel-return": {"direction": "INGRESS"}},
                     policy_rules={p: {"direction": "EGRESS"} for p in ("65000", "1000", "1001")})
        run = Run(state)
        self.assertEqual(run.code, 0, run.output)
        self.assertFalse(run.happened("firewall-rules", "create"))
        self.assertFalse(run.happened("network-firewall-policies", "rules", "create"))
        self.assertFalse(run.happened("subnets", "create"))
        self.assertFalse(run.happened("associations", "create"))


class AbortTests(unittest.TestCase):
    """Drift that cannot be repaired in place aborts the run."""

    def test_an_association_to_the_wrong_network_aborts(self):
        wrong = {
            "name": "v5-runner-td-policy-default",
            "attachmentTarget": (
                "https://www.googleapis.com/compute/v1/"
                "projects/test-project/global/networks/other"
            ),
        }

        run = Run(
            dict(
                FRESH,
                policy=True,
                associations=[wrong],
            )
        )

        self.assertNotEqual(run.code, 0)
        self.assertIn("association", run.output.lower())

    def test_a_subnet_with_another_cidr_aborts(self):
        """Every rule of acceptance test A5b keys on this range, so a different one voids the confinement."""
        run = Run(dict(FRESH, subnet=dict(GOOD_SUBNET, cidr="10.9.9.0/24")))
        self.assertNotEqual(run.code, 0)
        self.assertIn("immutable", run.output)

    def test_a_subnet_in_another_network_aborts(self):
        run = Run(dict(FRESH, subnet=dict(GOOD_SUBNET, network="projects/p/global/networks/other")))
        self.assertNotEqual(run.code, 0)
        self.assertIn("network", run.output)

    def test_a_firewall_rule_with_the_wrong_direction_aborts(self):
        """Direction cannot be updated in place, so keeping it would be a silent hole."""
        run = Run(dict(FRESH, subnet=GOOD_SUBNET,
                       fw_rules={"v5-allow-peerpod-tunnel": {"direction": "EGRESS"}}))
        self.assertNotEqual(run.code, 0)
        self.assertIn("direction", run.output)

    def test_an_allow_priority_that_does_not_beat_the_deny_aborts(self):
        """ALLOW=1000 with DENY=1001 leaves the second allow (1001) at the deny's priority."""
        run = Run(dict(FRESH), env={"FW_PRIO_DENY": "1001"})
        self.assertNotEqual(run.code, 0)
        self.assertIn("must be smaller than FW_PRIO_DENY", run.output)
        self.assertFalse(run.happened("compute", "firewall-rules"),
                         "validation must run before any resource is touched")

    def test_duplicate_allow_priorities_abort(self):
        run = Run(dict(FRESH), env={"FW_PRIO_ALLOW_VXLAN": "1000"})
        self.assertNotEqual(run.code, 0)
        self.assertIn("duplicate allow priorities", run.output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
