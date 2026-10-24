"""Dry run of the deployment artefacts checked in the repository, without a cluster.

The manifests are rendered with placeholders, parsed and checked against the trust cut. One
image runs as two Deployments selected by --role, with separate PVCs and ServiceAccounts. The
gateway serves two ports on two Services, and only the Authority may reach the observation port.
The runner may reach authority:8443, gateway:8443 and DNS, and no other destination. The init job
publishes only the anchors.

The controller Role may spawn, attach, port-forward, read logs, use the ar-pull secret and patch
PeerPods, and it holds nothing that could rewrite the Authority, the gateway or the reference.
The deployment scripts reference files and commands that exist. Dockerfile.services carries the
QVL, the code, the init-data templates and the service entry point. The runner manifest pins
`runner_main` as the command and the pull secret.
"""
from __future__ import annotations

import ast
import contextlib
import io
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

import yaml

from . import service_v5
from .profile_v5 import PULL_SECRET, RUNNER_GENERATE_NAME, build_runner_pod_manifest

MOCKS = pathlib.Path(__file__).resolve().parents[1]
SVC = MOCKS / "k8s" / "v5" / "services"
SCRIPTS = MOCKS / "scripts" / "gke-v5"
IMG = "eu.gcr.io/x/booking@sha256:" + "ab" * 32
SVC_IMG = "eu.gcr.io/x/booking-services@sha256:" + "cd" * 32
#: The counterparty a rendered manifest is seeded for. "mock" is the default of
#: 30_deploy_v5.sh and of the seeder, so the rendered form here is the one every
#: recorded deployment used.
WORLD = "mock"


def _render(name: str, world: str = WORLD) -> list[dict]:
    """Render a services manifest with test values for its placeholders and parse its documents."""
    s = (SVC / name).read_text()
    s = (s.replace("${SERVICES_IMAGE}", SVC_IMG).replace("${RUNNER_IMAGE}", IMG)
          .replace("${BOOKING_WORLD}", world))
    assert "${" not in s, "unreplaced placeholder"
    return [d for d in yaml.safe_load_all(s) if d]


def _by(docs, kind, name):
    """Return the document of `kind` named `name`."""
    return next(d for d in docs if d["kind"] == kind and d["metadata"]["name"] == name)


class TheSeededWorldTests(unittest.TestCase):
    """The init job carries the world, and it defaults to the catalogue.

    The world is seeded into both stores instead of being read from a process's environment, so a
    pod that restarts cannot come up against a different counterparty than the one its stores
    were built for. `booking_v5.tests_v5_world_config` covers the refusals themselves.
    """

    def test_the_init_job_seeds_a_world(self):
        job = _by(_render("services.yaml"), "Job", "trusted-init-v5")
        args = job["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--world", args)
        self.assertEqual(args[args.index("--world") + 1], "mock")

    def test_a_live_world_renders_into_the_same_argument(self):
        job = _by(_render("services.yaml", world="duffel"), "Job", "trusted-init-v5")
        args = job["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertEqual(args[args.index("--world") + 1], "duffel")

    def test_the_gateway_still_automounts_no_service_account_token(self):
        """The live patch adds a projected token. It must not turn the automount back on."""
        dep = _by(_render("services.yaml"), "Deployment", "gateway")
        self.assertIs(dep["spec"]["template"]["spec"]["automountServiceAccountToken"], False)


class ServicesManifestTests(unittest.TestCase):
    """The services manifest pins roles, stores, principals and ports of the trust cut."""

    def setUp(self):
        self.docs = _render("services.yaml")

    def test_one_image_two_roles_two_stores_two_principals(self):
        auth = _by(self.docs, "Deployment", "authority")["spec"]["template"]["spec"]
        gw = _by(self.docs, "Deployment", "gateway")["spec"]["template"]["spec"]
        self.assertEqual(auth["containers"][0]["image"], SVC_IMG)
        self.assertEqual(gw["containers"][0]["image"], SVC_IMG)
        # The Authority runs behind the approval gate: same restore, other entry.
        self.assertEqual(auth["containers"][0]["command"], ["python3", "-m", "booking_approval.service"])
        self.assertIn("--credentials", auth["containers"][0]["args"])
        self.assertEqual(gw["containers"][0]["args"][:3], ["serve", "--role", "gateway"])
        self.assertNotEqual(auth["serviceAccountName"], gw["serviceAccountName"])
        self.assertEqual(auth["volumes"][0]["persistentVolumeClaim"]["claimName"], "authority-db")
        self.assertEqual(gw["volumes"][0]["persistentVolumeClaim"]["claimName"], "gateway-db")
        self.assertFalse(auth["automountServiceAccountToken"])
        self.assertFalse(gw["automountServiceAccountToken"])
        for spec in (auth, gw):
            self.assertEqual(spec["containers"][0]["securityContext"]["capabilities"], {"drop": ["ALL"]})
            self.assertTrue(spec["containers"][0]["securityContext"]["readOnlyRootFilesystem"])

    def test_the_gateway_exposes_two_ports_on_two_services_and_the_authority_one(self):
        gw_args = _by(self.docs, "Deployment", "gateway")["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--observe", gw_args)
        self.assertIn("0.0.0.0:8444", gw_args)
        execute = _by(self.docs, "Service", "gateway")["spec"]["ports"]
        observe = _by(self.docs, "Service", "gateway-observe")["spec"]["ports"]
        self.assertEqual([p["port"] for p in execute], [8443])
        self.assertEqual([p["port"] for p in observe], [8444])
        self.assertEqual([p["port"] for p in _by(self.docs, "Service", "authority")["spec"]["ports"]], [8443])

    def test_the_init_seeds_both_stores_from_the_freeze_and_the_runner_image(self):
        job = _by(self.docs, "Job", "trusted-init-v5")["spec"]["template"]["spec"]
        args = job["containers"][0]["args"]
        self.assertEqual(args[0], "init")
        self.assertIn("--runner-image", args)
        self.assertIn(IMG, args)
        self.assertIn("--publish-secret", args)
        mounts = {m["name"]: m["mountPath"] for m in job["containers"][0]["volumeMounts"]}
        self.assertEqual(set(mounts), {"authority-db", "gateway-db", "freeze"})
        self.assertEqual(job["serviceAccountName"], "init-sa")
        role = _by(self.docs, "Role", "trusted-init")["rules"][0]
        # The human secret is not published: the gate uses it inside the Authority.
        self.assertEqual(role["resourceNames"], ["deployment-bootstrap"])
        self.assertNotIn("create", role["verbs"])
        self.assertNotIn("--human-secret-name", args)

    def test_the_verifier_is_dcap_and_not_a_placeholder(self):
        """The manifest pins `--verifier dcap` literally.

        There is no `${V5_VERIFIER}` placeholder, so no environment variable at deploy time can
        put a non-appraising verifier behind the Authority.
        """
        raw = (SVC / "services.yaml").read_text()
        self.assertNotIn("V5_VERIFIER", raw)
        args = _by(self.docs, "Deployment", "authority")["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertEqual(args[args.index("--verifier") + 1], "dcap")

    def test_the_attested_configuration_has_no_harness_listener(self):
        """No V5 service carries the harness listener.

        The test. and read. harness surface exists only in the V4 manifest (for acceptance test
        A9). In the V5 services no container carries `--harness-bind` and none exposes 8445, so
        `pods/portforward` in the controller Role reaches no harness.
        """
        raw = (SVC / "services.yaml").read_text()
        self.assertNotIn("--harness-bind", raw)
        for app in ("authority", "gateway"):
            spec = _by(self.docs, "Deployment", app)["spec"]["template"]["spec"]
            for c in spec["containers"]:
                self.assertNotIn("--harness-bind", c.get("args", []))
                self.assertNotIn(8445, [p["containerPort"] for p in c.get("ports", [])])
        self.assertIn("v5 no harness listener", (SCRIPTS / "40_verify_v5.sh").read_text())

    def test_the_service_binary_offers_no_fake_verifier(self):
        """`service_v5 serve --verifier` accepts only `dcap`. `FakeVerifier` stays in the model."""
        self.assertFalse(hasattr(service_v5, "FakeVerifier"))
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            service_v5.main(["serve", "--role", "authority", "--db", "x", "--bind", "0:1",
                             "--verifier", "fake"])
        with self.assertRaises(SystemExit):
            service_v5._verifier("fake")


class NetworkPolicyTests(unittest.TestCase):
    """The NetworkPolicies allow the pod-to-pod paths of the trust cut and deny the rest."""

    def setUp(self):
        self.docs = [d for d in yaml.safe_load_all((SVC / "networkpolicy.yaml").read_text()) if d]

    def _pol(self, name):
        return _by(self.docs, "NetworkPolicy", name)["spec"]

    def test_default_deny_exists(self):
        p = self._pol("default-deny-all")
        self.assertEqual(p["podSelector"], {})
        self.assertEqual(set(p["policyTypes"]), {"Ingress", "Egress"})

    def test_the_runner_reaches_exactly_authority_gateway_and_dns(self):
        p = self._pol("runner-egress")
        self.assertNotIn("ingress", p)
        targets = []
        for rule in p["egress"]:
            for to in rule["to"]:
                if "podSelector" in to:
                    targets.append((to["podSelector"]["matchLabels"]["app"], [x["port"] for x in rule["ports"]]))
                else:
                    self.assertEqual(to["namespaceSelector"]["matchLabels"], {"kubernetes.io/metadata.name": "kube-system"})
                    self.assertEqual({x["port"] for x in rule["ports"]}, {53})
        self.assertEqual(sorted(targets), [("authority", [8443]), ("gateway", [8443])])

    def test_each_gateway_port_admits_exactly_one_principal(self):
        """Who may reach which gateway port is checked as pairs, not as a set of ports.

        The observation port 8444 admits the Authority, for the effect-ledger check, and no other
        pod. The execution surface stays reachable only by a runner and the observation surface
        only by the Authority. A swap of the two ports therefore fails the test, where a set of
        allowed ports would still match.
        """
        p = self._pol("gateway-policy")
        pairs = sorted((to["podSelector"]["matchLabels"]["app"], x["port"])
                       for rule in p["ingress"] for to in rule["from"] for x in rule["ports"])
        self.assertEqual(pairs, [("authority", 8444), ("runner", 8443)])
        for rule in p["egress"]:
            for to in rule["to"]:
                self.assertNotIn("podSelector", to, "the gateway talks to no pod (verify key, no redeem)")

    def test_the_authority_reaches_only_the_observation_surface_of_the_gateway(self):
        """The Authority may talk to one pod, the gateway, and only on the observation port.

        The execution surface 8443 has to stay closed to it. The Authority issues grants and does
        not perform effects, and a path to that port would let a compromised Authority spend a
        token instead of only minting one. Port 8444 gives it reads of an append-only ledger,
        which is what the observation check needs.
        """
        p = self._pol("authority-policy")
        pairs = sorted((to["podSelector"]["matchLabels"]["app"], x["port"])
                       for rule in p["egress"] for to in rule["to"] if "podSelector" in to
                       for x in rule["ports"])
        self.assertEqual(pairs, [("gateway", 8444)])
        froms = {to["podSelector"]["matchLabels"]["app"] for rule in p["ingress"] for to in rule["from"]}
        self.assertEqual(froms, {"runner"})


class ControllerIdentityTests(unittest.TestCase):
    """The controller Role can spawn and observe runners and rewrite nothing of the trust base."""

    def setUp(self):
        docs = [d for d in yaml.safe_load_all((SVC / "controller-identity.yaml").read_text()) if d]
        self.rules = _by(docs, "Role", "v5-controller")["rules"]
        binding = _by(docs, "RoleBinding", "v5-controller")
        self.assertEqual(binding["subjects"][0]["name"], "v5-controller")

    def _verbs(self, resource, group=""):
        out = set()
        for r in self.rules:
            if group in r["apiGroups"] and resource in r["resources"]:
                out |= set(r["verbs"])
        return out

    def test_spawn_attach_portforward_log_and_recovery_are_granted(self):
        self.assertEqual(self._verbs("pods"), {"create", "get", "list", "watch", "delete"})
        self.assertEqual(self._verbs("pods/attach"), {"get", "create"})
        self.assertEqual(self._verbs("pods/portforward"), {"get", "create"})
        self.assertEqual(self._verbs("pods/log"), {"get"})
        self.assertEqual(self._verbs("peerpods", "confidentialcontainers.org"), {"get", "list", "patch"})

    def test_nothing_that_could_rewrite_authority_gateway_or_reference(self):
        resources = {res for r in self.rules for res in r["resources"]}
        for forbidden in ("deployments", "configmaps", "persistentvolumeclaims", "services", "networkpolicies",
                          "roles", "rolebindings", "serviceaccounts", "pods/exec"):
            self.assertNotIn(forbidden, resources, forbidden)
        secret_rules = [r for r in self.rules if "secrets" in r["resources"]]
        named = [r for r in secret_rules if r.get("resourceNames")]
        self.assertEqual(named[0]["resourceNames"], ["ar-pull"])
        for r in secret_rules:
            if not r.get("resourceNames"):
                self.assertEqual(r["verbs"], ["create"], "unnamed secret access is create only")


class ScriptsAndImageTests(unittest.TestCase):
    """Scripts and the services image reference the files, commands and packages they need."""

    def test_scripts_reference_existing_files_and_commands(self):
        s30 = (SCRIPTS / "30_deploy_v5.sh").read_text()
        for needle in ("services.yaml", "networkpolicy.yaml", "controller-identity.yaml", "v5-freeze",
                       "trusted-init-v5", "create token v5-controller", "auth can-i create deployments",
                       "v5ControllerProbe", "controller-config.json"):
            self.assertIn(needle, s30, needle)
        for name in ("services.yaml", "networkpolicy.yaml", "controller-identity.yaml"):
            self.assertTrue((SVC / name).is_file(), name)
        for name in ("31_run_fragment_v5.sh", "32_negative_v5.sh"):
            # e2e_live, entered through the approval gate's harness wrapper
            self.assertIn("booking_approval.harness_e2e", (SCRIPTS / name).read_text())
        self.assertIn("e2e_live.main(argv)", (MOCKS / "booking_approval" / "harness_e2e.py").read_text())
        self.assertIn("SERVICES_IMAGE=", (SCRIPTS / "23_build_services_image.sh").read_text())
        ast.parse((MOCKS / "booking_v5" / "e2e_live.py").read_text())

    def test_the_services_image_carries_the_qvl_the_code_and_the_templates(self):
        df = (MOCKS / "Dockerfile.services").read_text()
        for needle in ("libsgx-dcap-quote-verify", "libsgx-dcap-default-qpl", "COPY booking_v5", "COPY booking_v4",
                       "COPY booking_live", "COPY k8s/v5/init-data", "booking_v5.service_v5", "USER 65532"):
            self.assertIn(needle, df, needle)

    def test_the_freeze_preparation_rebuilds_the_services_image_after_genpolicy(self):
        """`98a_freeze_prepare.sh` rebuilds the services image after genpolicy.

        The preparation rebuilds the runner and re-renders the init-data, so the services image
        has to be rebuilt too. It carries its own copy of k8s/v5/init-data, which the Authority
        pins, while the controller renders from the tree. `scripts/gke/20_build_push_images.sh`
        also rewrites .digests and drops SERVICES_IMAGE. Without `23_build_services_image.sh` the
        init-data check in `40_verify_v5.sh` has nothing to compare, and the preparation fails at
        its last step, after the full probe chain.
        """
        sh = (SCRIPTS / "98a_freeze_prepare.sh").read_text()
        self.assertIn("23_build_services_image.sh", sh)
        self.assertLess(sh.index("13_genpolicy.sh"), sh.index("23_build_services_image.sh"))
        self.assertLess(sh.index("23_build_services_image.sh"), sh.index("40_verify_v5.sh"))

    def test_the_chain_deploys_the_world_once_and_the_live_evaluation_does_not_deploy_again(self):
        """`100_final_chain.sh` deploys once and runs `45_live_evaluation.sh` with SKIP_DEPLOY=1.

        The live evaluation would otherwise build and deploy the services itself. The chain
        deploys in its `deploy` phase for the live evaluation and the model runs.
        `36_assert_observation_v5.sh` and `38_negative_live_v5.sh` run there too, because the live
        evaluation does not contain them.
        """
        chain = (SCRIPTS / "100_final_chain.sh").read_text()
        self.assertRegex(chain, r'if want deploy; then\n\s+hard "23 build services"')
        self.assertIn("SKIP_DEPLOY=1", re.search(r'soft "45 live evaluation"[^\n]*', chain).group(0))
        for name in ("36 observation check", "38 network and gate proofs"):
            self.assertIn(name, chain)

    def test_the_live_evaluation_has_a_central_run_with_a_completed_verdict(self):
        """The central row of the live table needs a run of its own on the frozen configuration."""
        text = (SCRIPTS / "45_live_evaluation.sh").read_text()
        self.assertRegex(text, r'demo "5-central" --mail clean --approve auto[^\n]*\\\n\s+&& evidence "5-central" completed')

    def _find_opa(self, version_output_script: str) -> str:
        """Run the `find_opa` function of `40_verify_v5.sh` against a fake `opa` and return what it prints."""
        sh = (SCRIPTS / "40_verify_v5.sh").read_text()
        func = re.search(r'^OPA_VERSION=.*?^\}\n', sh, re.S | re.M)
        self.assertIsNotNone(func, "find_opa not found in 40_verify_v5.sh")
        with tempfile.TemporaryDirectory() as tmp:
            opa = pathlib.Path(tmp, "results_v5", "opa", "opa")
            opa.parent.mkdir(parents=True)
            opa.write_text("#!/bin/sh\n" + version_output_script)
            opa.chmod(0o755)
            # A real opa on PATH would answer instead of the fake, so PATH holds only the system tools.
            env = {k: v for k, v in os.environ.items() if k != "OPA_BIN"}
            env["PATH"] = "/usr/bin:/bin"
            out = subprocess.run(["bash", "-c", "set -uo pipefail; MOCKS_DIR=\"$1\"\n" + func.group(0) + "\nfind_opa",
                                  "bash", tmp], capture_output=True, text=True, env=env, timeout=30)
            return out.stdout.strip()

    def test_find_opa_accepts_a_version_that_arrives_in_pieces(self):
        """`find_opa` accepts an `opa version` output that arrives in pieces.

        Under pipefail, `opa version | grep -q` lets grep leave after the first line. The rest of
        the output hits a closed pipe, opa dies of SIGPIPE and the pipeline counts as failed, so a
        present binary is reported as "OPA 0.68.0 not found". Whether that happens is a race, so
        the fake opa makes it certain.
        """
        out = self._find_opa('echo "Version: 0.68.0"\nsleep 0.5\necho "Build Commit: x"\n')
        self.assertTrue(out.endswith("/results_v5/opa/opa"), out)

    def test_find_opa_still_refuses_another_version(self):
        """`find_opa` reports nothing for an opa of another version."""
        self.assertEqual(self._find_opa('echo "Version: 0.69.0"\necho "Build Commit: x"\n'), "")

    def test_the_deploy_refuses_a_world_change_and_names_the_way_out(self):
        """A deploy onto stores seeded for another world is refused, not re-seeded.

        The stores sit on PVCs that outlive a redeploy, so `BOOKING_WORLD=duffel` onto a cluster
        last seeded as "mock" is a refusal. `30_deploy_v5.sh` makes that refusal cheap, and
        `seed()` in service_v5 is the check that enforces it.
        """
        sh = (SCRIPTS / "30_deploy_v5.sh").read_text()
        self.assertIn("RESEED_WORLD", sh)
        self.assertIn("world mismatch", sh)
        self.assertIn("delete pvc authority-db gateway-db", sh)
        # The marker is written only after a successful seed, and it is only a marker.
        self.assertIn("v5.world=${BOOKING_WORLD}", sh)
        self.assertLess(sh.index("wait_job trusted-init-v5"), sh.index("v5.world=${BOOKING_WORLD}"))
        # The guard inside the store is still in place.
        src = (MOCKS / "booking_v5" / "service_v5.py").read_text()
        self.assertIn("refusing to re-seed it as", src)

    def test_the_deploy_does_not_wait_for_a_gateway_that_has_no_credential_yet(self):
        """With a live world the deploy waits for the Authority alone.

        `37_install_openbao.sh` needs the Deployment before it can patch it, and the gateway
        refuses to start before that script has stored the credential. With a live world,
        `30_deploy_v5.sh` therefore waits for the Authority alone, and `37_install_openbao.sh`
        waits for the gateway after the patch.
        """
        sh = (SCRIPTS / "30_deploy_v5.sh").read_text()
        self.assertIn('if [ "${BOOKING_WORLD}" = "mock" ]; then\n'
                      '  kubectl -n "${NAMESPACE}" rollout status deployment/gateway', sh)
        self.assertIn("rollout status deploy/gateway", (SCRIPTS / "37_install_openbao.sh").read_text())

    def test_the_live_package_is_in_the_services_image_and_not_in_the_guest(self):
        """`booking_live` is copied into the services image and not into the runner image.

        `seed()` imports booking_live.startup, so an init without it fails before it writes a row.
        The guest must stay without it, because a COPY in Dockerfile.k8s would move
        RUNNER_SOURCE_SHA256 and invalidate every measurement of V0 to V5.
        """
        self.assertIn("COPY booking_live /app/booking_live", (MOCKS / "Dockerfile.services").read_text())
        self.assertNotIn("booking_live", (MOCKS / "Dockerfile.k8s").read_text())

    def test_the_runner_manifest_pins_runner_main_and_the_pull_secret(self):
        m = build_runner_pod_manifest(image=IMG, namespace="agent-system", name="r", python="/usr/local/bin/python3")
        c = m["spec"]["containers"][0]
        self.assertEqual(c["command"], ["/usr/local/bin/python3", "-m", "booking_v5.runner_main"])
        self.assertEqual(m["spec"]["imagePullSecrets"], [{"name": PULL_SECRET}])
        self.assertTrue(c["stdin"])

    def test_the_controller_manifest_uses_generate_name_and_the_policy_template_a_placeholder(self):
        """The runner manifest uses generateName, and the tracked policy is a template.

        genpolicy pins the sandbox name. With generateName it pins the regex the API server's
        names satisfy, so one policy covers every runner-td-<x> pod. The tracked policy.rego is a
        template with ${RUNNER_IMAGE}, and `13_genpolicy.sh` restores the placeholder after
        generation.
        """
        m = build_runner_pod_manifest(image=IMG, namespace="agent-system", generate_name=RUNNER_GENERATE_NAME)
        self.assertEqual(m["metadata"]["generateName"], "runner-td-")
        self.assertNotIn("name", m["metadata"])
        with self.assertRaises(ValueError):
            build_runner_pod_manifest(image=IMG, namespace="agent-system")
        s13 = (SCRIPTS / "13_genpolicy.sh").read_text()
        self.assertIn("generate_name=RUNNER_GENERATE_NAME", s13)
        self.assertIn('replace(image, "${RUNNER_IMAGE}")', s13)


if __name__ == "__main__":
    unittest.main(verbosity=2)
