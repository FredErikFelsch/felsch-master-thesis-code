"""Offline tests of the launch profile and the manifests (no cluster).

These run without a Kubernetes cluster or the `kubernetes` client. They check the central
property of the launch design that needs no cluster: the untrusted execution input (fragment,
envelope, policy) has no influence on the runner launch profile, so the Pod template is the same
for every fragment, and that profile matches the hardening of the container backend and the
canonical YAML. They also check that the manifests parse and encode the intended RBAC matrix.

The enforced boundary (RBAC, NetworkPolicy) is shown only live, in `tests_k8s.py`.

Run from the repository root:  python3 -m booking_v4.tests_k8s_offline
"""

from __future__ import annotations

import inspect
import os
import unittest

import yaml

from .k8s_backend import (FIXED_PROFILE, build_runner_job_manifest, pod_template_of,
                          require_pinned_image, _START_TIMEOUT, _EXEC_TIMEOUT)
from .controller import CONTROLLER_METHODS

_K8S_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "k8s")
_APPLY_DIR = os.path.join(_K8S_DIR, "apply")
_REF_DIR = os.path.join(_K8S_DIR, "reference")

_PINNED = "reg.example.com/runner@sha256:" + ("a" * 64)


def _load(name: str):
    """Return the YAML documents of one manifest under k8s/apply."""
    with open(os.path.join(_APPLY_DIR, name)) as fh:
        return list(yaml.safe_load_all(fh))


def _load_ref(name: str):
    """Return the YAML documents of one reference manifest under k8s/reference."""
    with open(os.path.join(_REF_DIR, name)) as fh:
        return list(yaml.safe_load_all(fh))


class LaunchProfileIntegrityTests(unittest.TestCase):
    """The untrusted execution input cannot influence the launch profile."""

    def test_builder_takes_no_execution_input(self):
        params = set(inspect.signature(build_runner_job_manifest).parameters)
        for forbidden in ("fragment", "envelope", "policy", "intervention", "credential"):
            self.assertNotIn(forbidden, params,
                             f"the launch-profile builder must not take {forbidden}")

    def test_pod_template_is_fragment_invariant(self):
        # The controller builds one Job per fragment, and only the name varies. The
        # Pod template (image, service account, securityContext, mounts, the whole
        # launch profile) has to compare equal whatever the fragment.
        a = build_runner_job_manifest(image="REG/runner@sha256:abc",
                                      namespace="agent-system", name="runner-a")
        b = build_runner_job_manifest(image="REG/runner@sha256:abc",
                                      namespace="agent-system", name="runner-b")
        self.assertNotEqual(a["metadata"]["name"], b["metadata"]["name"])
        self.assertEqual(pod_template_of(a), pod_template_of(b))

    def test_fixed_profile_matches_frozen_hardening(self):
        m = build_runner_job_manifest(image="REG/runner@sha256:abc",
                                      namespace="agent-system", name="runner-x")
        job, tmpl = m["spec"], m["spec"]["template"]["spec"]
        c = tmpl["containers"][0]
        self.assertEqual(job["backoffLimit"], 0)                      # no retry
        self.assertEqual(job["completions"], 1)
        self.assertEqual(job["parallelism"], 1)
        self.assertIn("activeDeadlineSeconds", job)                    # bounded
        self.assertEqual(tmpl["restartPolicy"], "Never")
        self.assertIs(tmpl["automountServiceAccountToken"], False)     # no API token
        self.assertEqual(tmpl["serviceAccountName"], "runner-sa")
        self.assertIs(tmpl["securityContext"]["runAsNonRoot"], True)
        self.assertEqual(tmpl["securityContext"]["runAsUser"], 65532)
        self.assertEqual(tmpl["securityContext"]["seccompProfile"]["type"], "RuntimeDefault")
        self.assertIs(c["securityContext"]["readOnlyRootFilesystem"], True)
        self.assertIs(c["securityContext"]["allowPrivilegeEscalation"], False)
        self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertEqual(c["resources"]["limits"]["memory"], "512Mi")
        self.assertEqual(tmpl["volumes"][0]["emptyDir"],
                         {"medium": "Memory", "sizeLimit": "16Mi"})
        self.assertNotIn("command", c)  # image ENTRYPOINT runs the runner
        for host in ("hostNetwork", "hostPID", "hostIPC"):
            self.assertNotIn(host, tmpl)
        self.assertTrue(all("hostPath" not in v for v in tmpl["volumes"]))

    def test_active_deadline_covers_controller_budget(self):
        # activeDeadlineSeconds bounds the whole Job, so it has to exceed the
        # controller's own start and execution budget. Otherwise Kubernetes could kill
        # a runner the controller still expects to finish, which would look like a
        # runner crash.
        self.assertGreaterEqual(FIXED_PROFILE["active_deadline_seconds"],
                                _START_TIMEOUT + _EXEC_TIMEOUT)

    def test_builder_matches_canonical_yaml(self):
        built = build_runner_job_manifest(
            image="RUNNER_IMAGE_DIGEST", namespace="agent-system", name="runner-CANONICAL")
        canonical = _load_ref("runner-job-template.yaml")[0]
        self.assertEqual(built, canonical)

    def test_runner_image_must_be_digest_pinned(self):
        # The code enforces this, not only the deployment convention: a mutable tag is
        # rejected, and only repo@sha256:<64 hex> is accepted.
        for bad in ("runner:latest", "reg/runner:v4.4c", "reg/runner",
                    "reg/runner@sha256:abc", "reg/runner@sha256:" + "g" * 64):
            with self.assertRaises(ValueError):
                require_pinned_image(bad)
        self.assertEqual(require_pinned_image(_PINNED), _PINNED)


class ManifestTests(unittest.TestCase):
    """The manifests parse and encode the intended matrix of RBAC rules and service accounts."""

    def test_container_commands_use_path_python_not_absolute(self):
        # The image is python:3.11-slim, where python3 is /usr/local/bin/python3.
        # A hard-coded /usr/bin/python3 command override fails at container start
        # ("no such file or directory"), so every command invokes a bare "python3"
        # (resolved via PATH), as the Dockerfile ENTRYPOINT does.
        for name in ("init.yaml", "authority.yaml", "controller.yaml"):
            for doc in _load(name):
                spec = doc.get("spec", {})
                tmpl = spec.get("template", {}).get("spec") or \
                    spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec")
                if not tmpl:
                    continue
                for c in tmpl.get("containers", []):
                    cmd = c.get("command")
                    if cmd:
                        self.assertEqual(cmd[0], "python3",
                                         f"{name}: command must be bare python3, got {cmd[0]!r}")

    def test_all_manifests_parse(self):
        for name in ("namespace.yaml", "serviceaccounts.yaml", "rbac.yaml",
                     "storage.yaml", "init.yaml", "authority.yaml",
                     "controller.yaml", "networkpolicy.yaml"):
            docs = _load(name)
            self.assertTrue(docs and all(isinstance(d, dict) for d in docs), name)
        for name in ("runner-job-template.yaml", "rbac-model-v4.4b.yaml"):
            docs = _load_ref(name)
            self.assertTrue(docs and all(isinstance(d, dict) for d in docs), name)

    def test_untrusted_sas_get_no_token(self):
        sas = {d["metadata"]["name"]: d for d in _load("serviceaccounts.yaml")}
        self.assertIs(sas["orchestrator-sa"]["automountServiceAccountToken"], False)
        self.assertIs(sas["runner-sa"]["automountServiceAccountToken"], False)

    def test_rbac_binds_only_controller_and_narrowly(self):
        docs = _load("rbac.yaml")
        role = next(d for d in docs if d["kind"] == "Role")
        binding = next(d for d in docs if d["kind"] == "RoleBinding")
        # Only controller-sa is a subject, and orchestrator-sa and runner-sa are not.
        subjects = {(s["kind"], s["name"]) for s in binding["subjects"]}
        self.assertEqual(subjects, {("ServiceAccount", "controller-sa")})
        # The Role grants the Job lifecycle and pods/attach and nothing else that is
        # dangerous: no pod creation, no secrets, no deployments, no roles.
        resources = {res for r in role["rules"] for res in r["resources"]}
        self.assertIn("jobs", resources)
        self.assertIn("pods/attach", resources)
        for forbidden in ("secrets", "deployments", "roles", "rolebindings", "configmaps"):
            self.assertNotIn(forbidden, resources)
        # Jobs may be created and deleted. Pods may only be observed, not created.
        job_rule = next(r for r in role["rules"] if r["resources"] == ["jobs"])
        self.assertIn("create", job_rule["verbs"])
        self.assertIn("delete", job_rule["verbs"])
        pods_rule = next(r for r in role["rules"] if r["resources"] == ["pods"])
        self.assertNotIn("create", pods_rule["verbs"])

    def test_init_sa_may_only_patch_named_secrets(self):
        # init-sa patches the one pre-created Secret by name. It cannot create
        # arbitrary Secrets (Kubernetes cannot restrict `create` by name, so the Role
        # grants no create at all), and it has no other resource or escalation.
        docs = _load("init.yaml")
        role = next(d for d in docs if d["kind"] == "Role")
        binding = next(d for d in docs if d["kind"] == "RoleBinding")
        subjects = {(s["kind"], s["name"]) for s in binding["subjects"]}
        self.assertEqual(subjects, {("ServiceAccount", "init-sa")})
        resources = {res for r in role["rules"] for res in r["resources"]}
        self.assertEqual(resources, {"secrets"})
        secret_rule = next(r for r in role["rules"] if "secrets" in r["resources"])
        self.assertNotIn("create", secret_rule["verbs"])          # no create at all
        self.assertEqual(set(secret_rule["verbs"]), {"get", "update", "patch"})
        self.assertEqual(set(secret_rule["resourceNames"]), {"deployment-bootstrap"})
        # The controller Role (rbac.yaml) grants no verbs on secrets at all.
        ctrl_role = next(d for d in _load("rbac.yaml") if d["kind"] == "Role")
        ctrl_resources = {res for r in ctrl_role["rules"] for res in r["resources"]}
        self.assertNotIn("secrets", ctrl_resources)

    def test_networkpolicy_default_denies_and_confines_runner(self):
        pols = {d["metadata"]["name"]: d for d in _load("networkpolicy.yaml")}
        # namespace-wide default-deny exists for both directions
        dd = pols["default-deny-all"]
        self.assertEqual(dd["spec"]["podSelector"], {})
        self.assertEqual(set(dd["spec"]["policyTypes"]), {"Ingress", "Egress"})
        # the runner has no ingress rules, and egress only to the Authority and DNS
        runner = pols["runner-egress"]
        self.assertNotIn("ingress", runner["spec"])
        egress_targets = []
        for rule in runner["spec"]["egress"]:
            for to in rule["to"]:
                if "podSelector" in to:
                    egress_targets.append(to["podSelector"].get("matchLabels"))
        self.assertIn({"app": "authority"}, egress_targets)  # authority reachable
        # No egress rule opens the controller or the wider world to the runner: there
        # is no ipBlock, and the only cross-namespace target is kube-system on port 53
        # (DNS, selected by namespace only, see networkpolicy.yaml).
        for rule in runner["spec"]["egress"]:
            ports = {(p.get("protocol", "TCP"), p["port"]) for p in rule.get("ports", [])}
            for to in rule["to"]:
                self.assertNotIn(to.get("podSelector", {}).get("matchLabels"),
                                 [{"app": "controller"}])
                self.assertNotIn("ipBlock", to)
                if "namespaceSelector" in to:
                    self.assertEqual(to["namespaceSelector"]["matchLabels"],
                                     {"kubernetes.io/metadata.name": "kube-system"})
                    self.assertEqual(ports, {("UDP", 53), ("TCP", 53)})

    def test_orchestrator_has_no_path_to_authority(self):
        # The orchestrator holds only the narrow controller RPC: its egress reaches
        # the controller and DNS but not the Authority, and the Authority accepts
        # ingress only from the controller and the runner, and only on 8443 (the
        # harness listener 8445 is admitted to no pod, see HarnessSurfaceTests).
        pols = {d["metadata"]["name"]: d for d in _load("networkpolicy.yaml")}
        orch = pols["orchestrator-egress"]
        orch_targets = [to.get("podSelector", {}).get("matchLabels")
                        for rule in orch["spec"]["egress"] for to in rule["to"]]
        self.assertIn({"app": "controller"}, orch_targets)       # controller reachable
        self.assertNotIn({"app": "authority"}, orch_targets)     # the Authority is not
        authority_ingress = [f.get("podSelector", {}).get("matchLabels")
                             for rule in pols["authority-policy"]["spec"]["ingress"]
                             for f in rule["from"]]
        self.assertNotIn({"app": "orchestrator"}, authority_ingress)


class HarnessSurfaceTests(unittest.TestCase):
    """The fault-injection and read-back surface is the Authority's own listener (8445).

    It is not in the Service, the NetworkPolicy admits no pod to it, and the application
    listener refuses those methods.
    """

    def test_authority_serves_the_harness_on_its_own_port_only(self):
        docs = _load("authority.yaml")
        deploy = next(d for d in docs if d["kind"] == "Deployment")
        svc = next(d for d in docs if d["kind"] == "Service")
        c = deploy["spec"]["template"]["spec"]["containers"][0]
        self.assertIn("--harness-bind", c["args"])
        self.assertEqual(c["args"][c["args"].index("--harness-bind") + 1], "0.0.0.0:8445")
        self.assertNotIn("--enable-test-api", c["args"])
        self.assertEqual({p["containerPort"] for p in c["ports"]}, {8443, 8445})
        self.assertEqual({p["port"] for p in svc["spec"]["ports"]}, {8443})     # 8445 is not advertised
        pols = {d["metadata"]["name"]: d for d in _load("networkpolicy.yaml")}
        admitted = {p["port"] for rule in pols["authority-policy"]["spec"]["ingress"] for p in rule["ports"]}
        self.assertEqual(admitted, {8443})

    def test_the_application_listener_refuses_test_and_read_methods(self):
        """In-process: the main listener of a server without enable_test_api refuses test.
        and read. methods as disabled, and a harness listener serves only those methods."""
        import tempfile
        from booking_v1.clock import FixedClock
        from booking_v3.provisioner import create_deployment
        from booking_v4 import wire
        from booking_v4.durable import DurableDeploymentServer, DurableStore, _RestoredDeployment
        from booking_v4.services import _call
        tmp = tempfile.mkdtemp(prefix="k8s-harness-")
        store = DurableStore(os.path.join(tmp, "d.db"))
        base = create_deployment(FixedClock(1_700_000_010))
        server = DurableDeploymentServer(_RestoredDeployment(base.authority, base.gateway), store,
                                         tcp=("127.0.0.1", 0), harness_tcp=("127.0.0.1", 0))
        try:
            with self.assertRaises(wire.WireError) as ctx:
                _call(server.endpoint, "read.status", {"run_id": "x"})
            self.assertIn("disabled", str(ctx.exception))
            reply = _call(server.harness_endpoint, "read.dispatch_ops", {})
            self.assertIn("operations", reply)
            with self.assertRaises(wire.WireError) as ctx:
                _call(server.harness_endpoint, "authority.create_run", {"policy": {}, "approval": {}, "run_id": "x"})
            self.assertIn("no such method", str(ctx.exception))
        finally:
            server.close()
            store.close()


class EvalTopologyTests(unittest.TestCase):
    """The in-cluster harness topology of the equivalence run (k8s/apply/eval.yaml).

    It keeps the runner side equal to agent-system and gives the harness only the
    controller role's verbs. scripts/gke/60_run_freeze_eval.sh applies it,
    scripts/gke/30_deploy.sh does not.
    """

    def setUp(self):
        self.docs = _load("eval.yaml")
        self.by = {(d["kind"], d["metadata"]["name"]): d for d in self.docs}

    def test_everything_lives_in_agent_eval(self):
        for d in self.docs:
            if d["kind"] != "Namespace":
                self.assertEqual(d["metadata"]["namespace"], "agent-eval", d["kind"])
        self.assertIn(("Namespace", "agent-eval"), self.by)

    def test_runner_egress_equals_production(self):
        prod = {d["metadata"]["name"]: d for d in _load("networkpolicy.yaml")}
        self.assertEqual(self.by[("NetworkPolicy", "runner-egress")]["spec"],
                         prod["runner-egress"]["spec"])
        self.assertEqual(self.by[("NetworkPolicy", "default-deny-all")]["spec"],
                         prod["default-deny-all"]["spec"])

    def test_runner_sa_has_no_token(self):
        self.assertIs(self.by[("ServiceAccount", "runner-sa")]["automountServiceAccountToken"], False)

    def test_harness_role_is_the_controller_role(self):
        prod = next(d for d in _load("rbac.yaml") if d["kind"] == "Role")
        role = self.by[("Role", "eval-harness")]
        def norm(r):
            return sorted((tuple(x["apiGroups"]), tuple(x["resources"]), tuple(sorted(x["verbs"])))
                          for x in r["rules"])
        self.assertEqual(norm(role), norm(prod))
        binding = self.by[("RoleBinding", "eval-can-manage-runners")]
        self.assertEqual({(x["kind"], x["name"]) for x in binding["subjects"]},
                         {("ServiceAccount", "eval-sa")})

    def test_harness_presents_as_authority_on_8443_and_binds_there(self):
        job = self.by[("Job", "eval-harness")]
        tpl = job["spec"]["template"]
        self.assertEqual(tpl["metadata"]["labels"], {"app": "authority"})
        svc = self.by[("Service", "authority")]
        self.assertEqual(svc["spec"]["selector"], {"app": "authority"})
        self.assertEqual(svc["spec"]["ports"][0]["port"], 8443)
        env = {e["name"]: e["value"] for e in tpl["spec"]["containers"][0]["env"]}
        self.assertEqual(env["K8S_NAMESPACE"], "agent-eval")
        self.assertEqual(env["K8S_AUTHORITY_BIND"], "0.0.0.0:8443")
        self.assertEqual(env["K8S_AUTHORITY_ADVERTISE"], "authority.agent-eval.svc.cluster.local:8443")
        self.assertEqual(env["RUNNER_IMAGE"], "${RUNNER_IMAGE}")   # rendered from .digests
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(tpl["spec"]["serviceAccountName"], "eval-sa")
        sc = tpl["spec"]["containers"][0]["securityContext"]
        self.assertTrue(sc["readOnlyRootFilesystem"])
        self.assertEqual(sc["capabilities"], {"drop": ["ALL"]})


class ContractUnchangedTests(unittest.TestCase):
    """The Kubernetes deployment reuses the controller contract unchanged."""

    def test_controller_methods_unchanged(self):
        self.assertEqual(set(CONTROLLER_METHODS), {"controller.spawn", "controller.execute"})
        self.assertEqual(CONTROLLER_METHODS["controller.spawn"], {"fragment", "envelope"})
        self.assertEqual(CONTROLLER_METHODS["controller.execute"],
                         {"handle_id", "policy", "envelope", "fragment", "intervention"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
