"""Probe scripts and manifests must not assume the world before the V5 pod-VM overlay.

The script tests guard against defects that share one root cause: a script that still assumes
the world before the overlay, or before booking_v5 existed. Each would cost a cluster run. Among
them:

  * The container command must not hardcode /usr/bin/python3. The GKE image is built on
    python:3.11-slim, where the interpreter is /usr/local/bin/python3. The failure arrives
    inside the guest as "CreateContainer: the file was not found", after a full TD boot and
    guest pull.
  * Dockerfile.k8s, the image the GKE path builds and the peer pods run, must copy booking_v5.
    A COPY only in the local Dockerfile.runner is not enough.
  * Probe P1 of `scripts/gke-v5/18_probe_peer_pod.sh` must be overlay-aware. A peer pod
    launched without init-data behaves differently on an overlay image, because init-data is on
    the measured boot path.
  * 19_probe_network.sh must launch its peer-pod probes with init-data too. Otherwise on an
    overlay image every A5 and A5c verdict comes back UNDECIDED.

There are three kinds of test below. The permissive-policy tests and the A19 tests check
behaviour (the A labels are listed in `scripts/gke-v5/attack_catalogue.md`). The script tests
read the scripts as text, which is shallow by nature. They keep these specific mistakes from
returning unnoticed.

Run:  python3 -m booking_v5.tests_probe_manifests
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

from . import probe_a19
from .permissive_policy import permissive_policy, request_names
from .profile_v5 import init_data_annotation_value, init_data_document, init_data_hash

MOCKS = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = MOCKS / "scripts" / "gke-v5"
RULES = MOCKS / "results_v5" / "genpolicy-3.31.0" / "rules.patched.rego"
PROBE_IMAGE = "mirror.gcr.io/library/busybox:1.36"
PINNED_IMAGE = "reg.example.com/booking@sha256:" + "a" * 64


class PermissivePolicyTests(unittest.TestCase):
    """The probe policy must be bootable, complete, and unmistakable for the runner policy."""

    @classmethod
    def setUpClass(cls):
        cls.rules = RULES.read_text()

    def test_every_request_the_pinned_rules_name_is_allowed(self):
        """Every request the pinned rules name is allowed by default.

        A request the agent asks about and the policy does not define is DENIED, which would fail
        a network probe for a reason that has nothing to do with the network.
        """
        policy = permissive_policy(self.rules)
        names = request_names(self.rules)
        self.assertGreater(len(names), 20)
        for name in names:
            self.assertIn(f"default {name} := true", policy)
        self.assertEqual(sorted(request_names(policy)), sorted(names))

    def test_the_policy_is_standalone(self):
        """The policy has only defaults and no rule bodies.

        Nothing consults policy_data, so a probe pod needs no per-manifest generation step.
        """
        policy = permissive_policy(self.rules)
        self.assertIn("package agent_policy", policy)
        self.assertNotIn("policy_data", policy)
        for line in policy.splitlines():
            self.assertTrue(line.startswith(("#", "package ", "default ")) or not line.strip(), line)

    def test_it_names_itself_as_permissive(self):
        self.assertIn("ALLOWS EVERYTHING", permissive_policy(self.rules))

    def test_a_probe_td_cannot_be_taken_for_a_runner_td(self):
        """The permissive init-data document has another digest than the runner's.

        The init-data digest is measured into RTMR3, so the permissive TD reaches another RTMR3
        than a runner TD and its evidence is refused by the reference pin.
        """
        probe_doc = init_data_document(PROBE_IMAGE, policy_rego=permissive_policy(self.rules))
        runner_doc = init_data_document(PINNED_IMAGE)
        self.assertNotEqual(init_data_hash(probe_doc), init_data_hash(runner_doc))
        self.assertIn("ALLOWS EVERYTHING", probe_doc)
        self.assertNotIn("ALLOWS EVERYTHING", runner_doc)

    def test_the_annotation_round_trips(self):
        doc = init_data_document(PROBE_IMAGE, policy_rego=permissive_policy(self.rules))
        value = init_data_annotation_value(doc)
        self.assertEqual(gzip.decompress(base64.b64decode(value)).decode(), doc)
        self.assertLess(len(value), 200_000, "annotation must stay well under the 256 KB limit")

    def test_a_file_that_is_not_a_rules_rego_is_refused(self):
        with self.assertRaises(ValueError):
            permissive_policy("package agent_policy\n# nothing here\n")


class ProbeScriptTests(unittest.TestCase):
    """Text assertions on the scripts, each narrow and tied to one defect."""

    @classmethod
    def setUpClass(cls):
        cls.p18 = (SCRIPTS / "18_probe_peer_pod.sh").read_text()
        cls.p19 = (SCRIPTS / "19_probe_network.sh").read_text()
        cls.dockerfile = (MOCKS / "Dockerfile.k8s").read_text()
        cls.build = (MOCKS / "scripts" / "gke" / "20_build_push_images.sh").read_text()
        cls.p14 = (SCRIPTS / "14_install_coco.sh").read_text()
        cls.p11 = (SCRIPTS / "11_build_podvm_image.sh").read_text()

    @staticmethod
    def _code(text: str) -> str:
        """Return the script without its comment lines, because a path named in a comment is documentation."""
        return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))

    def test_no_script_hardcodes_an_interpreter_path(self):
        for name, text in (("18_probe_peer_pod.sh", self.p18), ("19_probe_network.sh", self.p19)):
            self.assertNotIn("/usr/bin/python3", self._code(text),
                             f"{name} hardcodes an interpreter path the GKE image does not have")
        self.assertIn("RUNNER_PYTHON", self.p18, "18_probe_peer_pod.sh must take the interpreter from .digests")

    def test_the_build_step_records_the_interpreter_from_the_image(self):
        self.assertIn("command -v python3", self.build)
        self.assertIn("RUNNER_PYTHON=${RUNNER_PYTHON}", self.build)

    def test_the_image_the_cluster_runs_carries_booking_v5(self):
        self.assertIn("COPY booking_v5 /app/booking_v5", self.dockerfile)
        self.assertIn("import booking_v4.runner_process, booking_v5.probe_bind, booking_v5.runner_main", self.build,
                      "the build step must prove the modules import before the digest is pinned")

    def test_p1_is_overlay_aware(self):
        """Probe P1 expects a pod without init-data to become Ready on an overlay image.

        The agents do not depend on initdata-measure, so the pod still becomes Ready. P1 checks
        that a failed measurement does not break the boot, and still tells a missing pod VM apart
        from a boot failure.
        """
        self.assertIn("OVERLAY_IMAGE", self.p18)
        self.assertIn("READY_UNMEASURED_OK", self.p18)
        self.assertIn("NOT_READY", self.p18)
        self.assertIn("NO_PODVM", self.p18, "a missing pod VM must be told apart from a boot failure")
        self.assertNotIn("FAILCLOSED_OK\"", self.p18, "the expectation that the guest fails closed must be gone")

    def test_install_coco_clears_the_peerpod_finalizer_instead_of_waiting_for_a_controller(self):
        """`14_install_coco.sh` clears the PeerPod finalizer itself, for CRs whose VM is gone.

        Only CRs whose pod VM GCE reports as gone qualify, otherwise a running c3 TDX instance is
        orphaned. peerpod-ctrl of CAA 0.21.1 registers no gcp provider, so it does not remove its
        finalizer and a stale PeerPod CR stays. Waiting for the controller would refuse the rollout
        on every rerun.
        """
        self.assertIn("finalizers", self.p14, "14_install_coco.sh must clear the finalizer itself")
        self.assertIn("instanceID", self.p14, "the decision must be made per CR, by its VM")
        self.assertIn("compute instances list", self.p14,
                      "a finalizer may be cleared only once GCE confirms the VM is gone")
        self.assertIn("still exists, leaving the finalizer alone", self.p14)

    def test_the_p1_teardown_deletes_the_pod_the_vm_and_the_finalizer_itself(self):
        """The pod of probe P1 gets no sandbox, so `18_probe_peer_pod.sh` tears it down itself.

        Without a sandbox the pod stays Terminating, the CAA does not delete its VM and the
        PeerPod finalizer is not cleared. The script does all three, and the VM goes before the
        finalizer so a failure cannot orphan a running c3 TDX instance.
        """
        block = self.p18[self.p18.index("P1 complete"):self.p18.index("p1_clean=0")]
        self.assertIn("--grace-period=0 --force", block)
        self.assertIn("instances delete", block)
        self.assertIn("finalizers", block)
        self.assertLess(block.index("instances delete"), block.index('"finalizers":null'),
                        "the VM must be deleted before its CR's finalizer is cleared")

    def test_the_podvm_build_gates_only_on_the_fixes_it_was_asked_for(self):
        """`11_build_podvm_image.sh` checks the mount fix only when `V5_HARDEN_B1` turned it on.

        A5c and the mount fix can be switched off. An unconditional gate would then demand the
        success of a step the build skipped, and stop after `make binaries` with
        'run-kata-containers.mount survived the hardening step'.
        """
        gate = self.p11[self.p11.index("survived the hardening step") - 400:
                        self.p11.index("survived the hardening step")]
        self.assertIn("V5_HARDEN_B1", gate, "the mount gate must be conditional on V5_HARDEN_B1")
        self.assertIn("initdata-measure missing from the tree", self.p11,
                      "every V5 image must be gated on the one thing it always carries")
        self.assertIn("enablement entries are regular files", self.p11,
                      "a .wants entry that stopped being a symlink must not be shipped")

    def test_every_peer_pod_probe_carries_init_data(self):
        calls = re.findall(r'^\s*probe "([^"]+)" "([^"]+)"', self.p19, re.M)
        self.assertGreaterEqual(len(calls), 4, "the four probe calls were not found")
        for label, overrides in calls:
            if "peer pod" in label:
                self.assertEqual(overrides, "${OV_PEER}", f"{label} does not carry init-data")
            else:
                self.assertEqual(overrides, "${OV_REGULAR}", label)
        self.assertNotIn('\\"runtimeClassName\\":\\"kata-remote\\",', self.p19,
                         "a raw runtimeClass fragment means the pod has no init-data annotation")
        self.assertIn("permissive_policy", self.p19)


class A19CopyFileDenial(unittest.TestCase):
    """Acceptance test A19 offline: the measured runner policy denies a host CopyFileRequest onto /run/peerpod/*.

    The test evaluates the enforced policy with OPA (its digest is in the freeze, and the
    kata-agent runs this rego) instead of a live CopyFile, because the agent is reachable only
    over the forwarder's mutual-TLS ttrpc.
    """

    FROZEN_POLICY = MOCKS / "results_v5" / "freeze-candidate" / "runner-peer-20260905T145032Z.policy.rego"

    @classmethod
    def setUpClass(cls):
        cls.rules = RULES.read_text()

    @staticmethod
    def _opa() -> "str | None":
        """Return the first OPA binary that runs on this machine, else None.

        The cached `results_v5/opa/opa` is the binary 41_probe_a19.sh downloaded for the machine
        it ran on (a Mac binary does not execute on Linux), so its existence alone proves nothing.
        """
        cached = MOCKS / "results_v5" / "opa" / "opa"
        for cand in (os.environ.get("OPA_BIN"), str(cached) if cached.exists() else None, shutil.which("opa")):
            if not cand:
                continue
            try:
                if subprocess.run([cand, "version"], capture_output=True, timeout=20).returncode == 0:
                    return cand
            except (OSError, subprocess.SubprocessError):
                continue
        return None

    # The policy contract the probe relies on.
    def test_copyfile_defaults_to_false_and_is_only_path_restricted_to_the_share_dir(self):
        """CopyFileRequest is allowed only for a path matching sfprefix.

        It is not denied outright, because peer pods need it for /etc/hosts and similar files.
        /run/peerpod/* does not match sfprefix and is therefore denied by default.
        """
        self.assertIn("default CopyFileRequest := false", self.rules)
        self.assertIn("allow_copy_file_path(input.path", self.rules)

    def test_the_measured_settings_allow_copyfile_only_under_the_sandbox_share_prefix(self):
        settings = json.loads((MOCKS / "k8s" / "v5" / "genpolicy-settings.json").read_text())
        allowed = settings["request_defaults"]["CopyFileRequest"]
        self.assertEqual(allowed, ["$(sfprefix)"])                # the sandbox share dir only
        sfprefix = settings["common"]["sfprefix"]
        self.assertTrue(sfprefix.startswith("^$(cpath)/"))        # under /run/kata-containers/shared
        for path in probe_a19.A19_TARGET_PATHS:                   # none of the init-data files is under it
            self.assertTrue(path.startswith("/run/peerpod/"), path)

    def test_every_a19_target_is_a_measured_initdata_file(self):
        self.assertEqual(set(probe_a19.A19_TARGET_PATHS),
                         {"/run/peerpod/initdata.digest", "/run/peerpod/initdata.toml",
                          "/run/peerpod/aa.toml", "/run/peerpod/cdh.toml"})
        self.assertTrue(probe_a19.A19_ALLOWED_CONTROL.startswith("/run/kata-containers/shared/"))

    # The pure probe logic.
    def test_copyfile_input_and_opa_argv_query_the_agent_rule(self):
        self.assertEqual(probe_a19.copyfile_input("/run/peerpod/initdata.digest"),
                         {"path": "/run/peerpod/initdata.digest", "file_type": "Regular"})
        argv = probe_a19.opa_eval_argv("opa", "policy.rego", "in.json")
        self.assertEqual(argv[:3], ["opa", "eval", "-d"])
        self.assertIn("data.agent_policy.CopyFileRequest", argv)
        self.assertIn("--format", argv)

    def test_parse_opa_bool_reads_the_rule_value(self):
        j = '{"result":[{"expressions":[{"value":%s}]}]}'
        self.assertIs(probe_a19.parse_opa_bool(j % "false"), False)
        self.assertIs(probe_a19.parse_opa_bool(j % "true"), True)
        self.assertIsNone(probe_a19.parse_opa_bool('{"result":[]}'))     # rule/query error
        self.assertIsNone(probe_a19.parse_opa_bool("not json"))

    def test_target_verdicts_map_deny_to_pass_and_allow_to_leak(self):
        self.assertEqual(probe_a19.verdict_for_target("/run/peerpod/x", False).verdict, probe_a19.A19_DENIED)
        self.assertTrue(probe_a19.verdict_for_target("/run/peerpod/x", False).passed)
        self.assertEqual(probe_a19.verdict_for_target("/run/peerpod/x", True).verdict, probe_a19.A19_LEAKED)
        self.assertEqual(probe_a19.verdict_for_target("/run/peerpod/x", None).verdict, probe_a19.A19_INCONCLUSIVE)

    def test_control_must_be_allowed_or_the_probe_proves_nothing(self):
        self.assertEqual(probe_a19.verdict_for_control("c", True).verdict, probe_a19.A19_CONTROL_OK)
        self.assertTrue(probe_a19.verdict_for_control("c", True).passed)
        self.assertEqual(probe_a19.verdict_for_control("c", False).verdict, probe_a19.A19_CONTROL_FAILED)

    # The real evaluation, when opa and the frozen policy are present.
    def test_opa_denies_every_target_and_allows_the_control_on_the_frozen_policy(self):
        opa = self._opa()
        if opa is None or not self.FROZEN_POLICY.exists():
            self.skipTest("opa binary or frozen policy not available (run 41_probe_a19.sh once)")

        def allowed(path: str) -> "bool | None":
            """Return the policy verdict for a CopyFile of `path`."""
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(probe_a19.copyfile_input(path), f)
                inp = f.name
            out = subprocess.run(probe_a19.opa_eval_argv(opa, str(self.FROZEN_POLICY), inp),
                                 capture_output=True, text=True).stdout
            return probe_a19.parse_opa_bool(out)

        for path in probe_a19.A19_TARGET_PATHS:
            self.assertIs(allowed(path), False, f"{path} was not denied by the measured policy")
        self.assertIs(allowed(probe_a19.A19_ALLOWED_CONTROL), True, "the sfprefix control was not allowed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
