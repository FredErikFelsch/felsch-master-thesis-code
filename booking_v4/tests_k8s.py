"""The live enforcement suite for the Kubernetes deployment (needs a real cluster).

It runs only against a cluster whose CNI enforces NetworkPolicy and whose RBAC is applied.
Gating rule:

  * K8S_LIVE unset: every test is skipped, so the file is safe offline and cannot pass
    without a cluster.
  * K8S_LIVE=1 but the cluster is unreachable: the import raises, so a live run cannot pass
    by skipping everything.

`scripts/gke/50_run_security_suite.sh` sets K8S_LIVE=1 after `scripts/gke/30_deploy.sh`.

The semantic equivalence run is a separate artefact (`experiment_k8s.py`). This file checks
what the offline profile tests (`tests_k8s_offline.py`) cannot: the enforced launch boundary,
network confinement, teardown and the behaviour after a crash. The acceptance labels A1 to A9
of the Kubernetes enforcement run (`scripts/gke/RUNBOOK.md`) map to the classes as follows:

  A1 to A3  RbacBoundaryTests: RBAC checked with `kubectl auth can-i --as`. The orchestrator
            is denied every Job and pod-mutation verb, the controller holds the Job lifecycle
            plus pods/attach, the runner holds nothing.
  A5        NetworkConfinementTests: a runner reaches the Authority (positive control) and not
            an in-cluster canary (negative control), so a blocked connection is the policy and
            not broken connectivity.
  A6        JobLifecycleTests: a spawn through the controller RPC uses the fixed profile that
            reached the API server, and leaves no orphan.
  A7, A8    ControllerCrashTests: a lost controller invalidates outstanding handles, and its
            restart sweeps orphaned Jobs.
  A9        CrashAfterGrantTests: a lost gateway reply after the effect parks the run in
            EFFECT_UNCERTAIN, with no replacement Job and no second dispatch. The fault is a
            dropped gateway.execute reply, not a sleep.

Run (live):  K8S_LIVE=1 python3 -m booking_v4.tests_k8s
"""

from __future__ import annotations

import json
import os
import subprocess
import time
import unittest

NS = os.environ.get("K8S_NAMESPACE", "agent-system")
_SA = f"system:serviceaccount:{NS}"
_MANAGED_BY = "trusted-runner-controller"


def _kubectl(*args: str, check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["kubectl", "-n", NS, *args],
                          capture_output=True, text=True, check=check, timeout=timeout)


def _can_i(verb: str, resource: str, sa: str) -> bool:
    """Ask the API server whether ``sa`` may ``verb`` ``resource``.

    ``resource`` may name a subresource as ``pods/attach``. kubectl reads a bare
    ``pods/attach`` as the Pod named ``attach`` (TYPE/NAME syntax), which is always
    denied and proves nothing, so a subresource is passed via ``--subresource``.
    """
    args = ["kubectl", "-n", NS, "auth", "can-i", verb]
    if "/" in resource:
        base, sub = resource.split("/", 1)
        args += [base, "--subresource", sub]
    else:
        args += [resource]
    proc = subprocess.run(args + ["--as", f"{_SA}:{sa}"],
                          capture_output=True, text=True, check=False, timeout=60)
    return proc.stdout.strip() == "yes"


def _cluster_reachable() -> bool:
    """Return True if kubectl can read the namespace."""
    try:
        _kubectl("get", "namespace", NS, "-o", "name", timeout=20)
        return True
    except Exception:
        return False


_LIVE = os.environ.get("K8S_LIVE") == "1"
if _LIVE and not _cluster_reachable():
    # A live run that cannot reach the cluster fails instead of skipping.
    raise RuntimeError(
        f"K8S_LIVE=1 but namespace {NS!r} is unreachable via kubectl. Refusing to "
        "report a passing security run without a cluster")
_SKIP = "live cluster not available (set K8S_LIVE=1 and apply k8s/apply to run)"


@unittest.skipUnless(_LIVE, _SKIP)
class RbacBoundaryTests(unittest.TestCase):
    """A1 to A3: the enforced control-plane boundary, under which only the controller may launch."""

    def test_service_accounts_exist(self):
        # A can-i --as check accepts any syntactic principal, so confirm that the
        # service accounts exist before trusting the matrix below.
        out = _kubectl("get", "sa", "orchestrator-sa", "controller-sa",
                       "runner-sa", "authority-sa", "-o", "name").stdout
        for sa in ("orchestrator-sa", "controller-sa", "runner-sa", "authority-sa"):
            self.assertIn(sa, out)

    def test_orchestrator_cannot_touch_runner_workloads(self):
        for verb, resource in (("create", "jobs"), ("delete", "jobs"),
                               ("patch", "jobs"), ("update", "jobs"),
                               ("create", "pods"), ("create", "pods/attach"),
                               ("get", "pods/attach"), ("create", "pods/exec"),
                               ("get", "secrets")):
            self.assertFalse(_can_i(verb, resource, "orchestrator-sa"),
                             f"orchestrator-sa must NOT {verb} {resource}")

    def test_controller_holds_the_launch_lifecycle_and_not_other_verbs(self):
        for verb, resource in (("create", "jobs"), ("delete", "jobs"),
                               ("get", "jobs"), ("list", "jobs"),
                               ("create", "pods/attach"), ("get", "pods/attach")):
            self.assertTrue(_can_i(verb, resource, "controller-sa"),
                            f"controller-sa must {verb} {resource}")
        for verb, resource in (("update", "jobs"), ("patch", "jobs"),
                               ("create", "pods"), ("create", "pods/exec"),
                               ("get", "secrets"), ("create", "configmaps"),
                               ("patch", "deployments"), ("create", "roles"),
                               ("create", "rolebindings")):
            self.assertFalse(_can_i(verb, resource, "controller-sa"),
                             f"controller-sa must NOT {verb} {resource}")

    def test_runner_sa_is_powerless(self):
        for verb, resource in (("create", "jobs"), ("get", "secrets"),
                               ("create", "pods/attach"), ("get", "pods/attach"),
                               ("list", "pods")):
            self.assertFalse(_can_i(verb, resource, "runner-sa"),
                             f"runner-sa must NOT {verb} {resource}")


@unittest.skipUnless(_LIVE, _SKIP)
class JobLifecycleTests(unittest.TestCase):
    """A6: one spawn and execute through the controller uses the fixed profile and leaves no orphan."""

    def _managed_jobs(self):
        out = _kubectl("get", "jobs", "-l", f"managed-by={_MANAGED_BY}", "-o", "json").stdout
        return json.loads(out).get("items", [])

    def test_spawn_execute_uses_fixed_profile_and_leaves_no_orphan(self):
        from .k8s_client_probe import spawn_execute_once
        before = len(self._managed_jobs())
        result, job = spawn_execute_once()
        self.assertIsNotNone(result)
        # The profile that reached the API server (not only what the builder would
        # produce) is the fixed one, independent of the fragment.
        spec, tmpl = job["spec"], job["spec"]["template"]["spec"]
        c = tmpl["containers"][0]
        self.assertEqual(spec["backoffLimit"], 0)
        self.assertEqual(tmpl["restartPolicy"], "Never")
        self.assertEqual(tmpl["serviceAccountName"], "runner-sa")
        self.assertIs(tmpl["automountServiceAccountToken"], False)
        self.assertEqual(tmpl["securityContext"]["runAsUser"], 65532)
        self.assertEqual(tmpl["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
        self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True)
        self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
        self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertNotIn("command", c)  # image ENTRYPOINT runs the runner
        vol = tmpl["volumes"][0]["emptyDir"]
        self.assertEqual(vol.get("medium"), "Memory")
        self.assertEqual(vol.get("sizeLimit"), "16Mi")
        expected = os.environ.get("EXPECTED_RUNNER_IMAGE")
        if expected:
            self.assertEqual(c["image"], expected)  # the digest that was deployed
        self.assertRegex(c["image"], r"@sha256:[0-9a-f]{64}$")  # digest-pinned
        # No surviving managed Job (deleted and confirmed absent after execute).
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and len(self._managed_jobs()) > before:
            time.sleep(1)
        self.assertLessEqual(len(self._managed_jobs()), before)


@unittest.skipUnless(_LIVE, _SKIP)
class NetworkConfinementTests(unittest.TestCase):
    """A5: a runner reaches the Authority (positive control) but not an in-cluster canary."""

    CANARY = "netcanary"

    @classmethod
    def setUpClass(cls):
        cls._probe_image = os.environ.get("PROBE_IMAGE")
        if not cls._probe_image:
            return
        # A reachable in-cluster listener that the runner egress policy does not
        # allow. If runner->authority works but runner->canary does not, the
        # NetworkPolicy blocks it, not missing connectivity.
        manifest = {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": cls.CANARY, "namespace": NS,
                         "labels": {"app": cls.CANARY}},
            "spec": {"replicas": 1, "selector": {"matchLabels": {"app": cls.CANARY}},
                     "template": {"metadata": {"labels": {"app": cls.CANARY}},
                                  "spec": {"automountServiceAccountToken": False,
                                           "containers": [{
                                               "name": "canary", "image": cls._probe_image,
                                               "command": ["sh", "-c",
                                                           "while true; do nc -lk -p 9000; done"]}]}}}}
        svc = {"apiVersion": "v1", "kind": "Service",
               "metadata": {"name": cls.CANARY, "namespace": NS},
               "spec": {"selector": {"app": cls.CANARY},
                        "ports": [{"port": 9000, "targetPort": 9000}]}}
        # An explicit ingress allow on the canary from app=runner makes the negative
        # control unambiguous. With it, a blocked runner->canary can only be the
        # runner egress policy, not a missing ingress allow on the canary and not
        # broken connectivity, which the positive runner->authority control rules out.
        ingress = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": "netcanary-ingress", "namespace": NS},
            "spec": {"podSelector": {"matchLabels": {"app": cls.CANARY}},
                     "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "runner"}}}],
                                  "ports": [{"protocol": "TCP", "port": 9000}]}]}}
        for m in (manifest, svc, ingress):
            subprocess.run(["kubectl", "-n", NS, "apply", "-f", "-"],
                           input=json.dumps(m), text=True, capture_output=True,
                           check=True, timeout=30)
        _kubectl("rollout", "status", f"deploy/{cls.CANARY}", "--timeout=60s", check=False)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "_probe_image", None):
            _kubectl("delete", "networkpolicy", "netcanary-ingress", "--ignore-not-found", check=False)
            _kubectl("delete", "deploy", cls.CANARY, "--ignore-not-found", check=False)
            _kubectl("delete", "svc", cls.CANARY, "--ignore-not-found", check=False)

    def _probe(self, host: str, port: int) -> bool:
        """Return True iff a runner-labelled pod can open TCP host:port within the timeout."""
        name = f"netprobe-{int(time.time()*1000)}"
        manifest = {
            "apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": NS, "labels": {"app": "runner"}},
            "spec": {"restartPolicy": "Never", "serviceAccountName": "runner-sa",
                     "automountServiceAccountToken": False, "activeDeadlineSeconds": 30,
                     "containers": [{"name": "probe", "image": self._probe_image,
                                     "command": ["sh", "-c",
                                                 f"nc -z -w 3 {host} {port} && echo OPEN || echo BLOCKED"]}]}}
        try:
            subprocess.run(["kubectl", "-n", NS, "apply", "-f", "-"],
                           input=json.dumps(manifest), text=True, capture_output=True,
                           check=True, timeout=30)
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                phase = _kubectl("get", "pod", name, "-o",
                                 "jsonpath={.status.phase}", check=False).stdout.strip()
                if phase in ("Succeeded", "Failed"):
                    break
                time.sleep(1)
            return "OPEN" in _kubectl("logs", name, check=False).stdout
        finally:
            _kubectl("delete", "pod", name, "--ignore-not-found", check=False)

    def test_runner_reaches_authority_only(self):
        if not self._probe_image:
            self.skipTest("PROBE_IMAGE (tiny image with nc) not set")
        self.assertTrue(self._probe("authority", 8443),
                        "positive control: runner must reach the Authority service")
        self.assertFalse(self._probe(self.CANARY, 9000),
                         "runner must not reach an in-cluster canary (policy denies)")


@unittest.skipUnless(_LIVE, _SKIP)
class ControllerCrashTests(unittest.TestCase):
    """A7 and A8: a lost controller invalidates its handles, and its restart sweeps orphaned Jobs."""

    def test_restart_sweeps_orphans_and_invalidates_handles(self):
        from .k8s_client_probe import spawn_only, execute_handle, restart_controller
        handle, policy, fragment, envelope = spawn_only()  # live rh-... handle
        restart_controller()                                # kill controller, Recreate
        # The in-memory handle map died with the pod, so the handle is unusable.
        with self.assertRaises(Exception):
            execute_handle(handle, policy, fragment, envelope)
        # The restarted controller swept the orphaned managed Job. cleanup_orphans would
        # have kept the controller from serving if it could not confirm the deletion.
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            out = _kubectl("get", "jobs", "-l", f"managed-by={_MANAGED_BY}", "-o", "json").stdout
            if not json.loads(out).get("items"):
                return
            time.sleep(2)
        self.fail("orphaned runner Jobs were not swept on controller restart")


@unittest.skipUnless(_LIVE, _SKIP)
class CrashAfterGrantTests(unittest.TestCase):
    """A9: a lost gateway reply after the effect parks the run in EFFECT_UNCERTAIN, without a retry.

    The run enters EFFECT_PENDING when the grant is issued and leaves it only through
    finalize, so the fault has to fall after the gateway committed the effect and before the
    runner can finalise a confirmed outcome. The test arms the durable service to drop the
    next `gateway.execute` reply: the effect commits once and the answer is lost. The runner
    (`booking_v3.runner.EphemeralRunner._lost_transport`) then asks `gateway.dispatch_outcome`
    read only, does not send the request again and finalises the step as UNCERTAIN. The
    Authority adopts EFFECT_UNCERTAIN for that report (`Authority._parked_state`),
    so `handle.execute` returns a result with that status instead of raising. Dropping the
    finalize reply instead would be the wrong fault, because the durable finalize would
    commit and the run would advance normally.

    The test checks the result status, the parked run state, a single dispatch of the
    operation and that no replacement Job was created (backoffLimit 0, restartPolicy Never).
    """

    @staticmethod
    def _managed_job_uids() -> set:
        out = _kubectl("get", "jobs", "-l", f"managed-by={_MANAGED_BY}", "-o", "json").stdout
        return {j["metadata"]["uid"] for j in json.loads(out).get("items", [])}

    def test_lost_gateway_reply_parks_uncertain_without_retry_or_double_dispatch(self):
        from .k8s_client_probe import activate_run, _first_fragment, _port_forward
        from .controller import ControllerRunnerProvisioner
        from .services import _call
        auth_port = int(os.environ.get("AUTHORITY_LOCAL_PORT", "8443"))
        harness_port = int(os.environ.get("AUTHORITY_HARNESS_LOCAL_PORT", "8445"))
        ctrl_port = int(os.environ.get("CONTROLLER_LOCAL_PORT", "9443"))
        run_id = f"k8s-a9-{int(time.time())}"
        policy, s0 = activate_run(run_id)
        fragment, envelope = _first_fragment(policy, run_id, s0)

        # Arm the fault after the effect commits and before finalize: drop the next
        # gateway.execute reply (the commit stands, the answer is lost).
        # The harness surface is the Authority's own listener (8445, not in the Service and
        # unreachable by NetworkPolicy from any pod), so the test port-forwards the
        # Deployment. The application surface (8443) has to refuse these methods.
        with _port_forward("authority", auth_port, 8443) as aep:
            with self.assertRaises(Exception):
                _call(aep, "test.drop_reply_once", {"method": "gateway.execute"})
        with _port_forward("authority", harness_port, 8445, kind="deploy") as hep:
            _call(hep, "test.drop_reply_once", {"method": "gateway.execute"})
        uids_before = self._managed_job_uids()

        with _port_forward("controller", ctrl_port, 9443) as cep:
            provisioner = ControllerRunnerProvisioner(cep)
            handle = provisioner.spawn(fragment, envelope)
            new_uids = self._managed_job_uids() - uids_before
            # The runner reconciles the lost reply read only and reports UNCERTAIN.
            result = handle.execute(policy, envelope, fragment, None)
        self.assertEqual(result.status, "EFFECT_UNCERTAIN", result.reason)

        # One runner Job was created for this run (by UID), the spawn, and the fault
        # produced no replacement. The test watches for a while, because backoffLimit 0
        # and restartPolicy Never are what keep a dead runner Job from being re-created.
        self.assertEqual(len(new_uids), 1, f"expected one runner Job, got {new_uids}")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            self.assertEqual(self._managed_job_uids() - uids_before - new_uids, set(),
                             "a replacement runner Job was created")
            time.sleep(3)

        with _port_forward("authority", harness_port, 8445, kind="deploy") as hep:
            status = _call(hep, "read.status", {"run_id": run_id}).get("status")
            ops = _call(hep, "read.dispatch_ops", {}).get("operations", [])
        self.assertEqual(status, "EFFECT_UNCERTAIN")             # parked for reconciliation
        self.assertEqual(ops.count(fragment.operation), 1)       # dispatched once, no double


if __name__ == "__main__":
    unittest.main(verbosity=2)
