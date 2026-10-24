"""The credential store's manifests and the gateway patch, pinned before they reach a cluster.

Run:
    python3 -m booking_v5.tests_v5_openbao

A mistake in a manifest shows up as a pod that will not start, twenty minutes into a cluster
run, with a message about a role. These tests are cheap and run in a second, so the things that
are easy to get wrong are checked here instead.

The most valuable check is `test_every_variable_is_one_the_code_actually_reads`: the environment
variable names in the gateway patch are compared against the names `booking_live.secrets` reads.
Renaming one in Python without touching the manifest would otherwise be found in the cluster.
"""
from __future__ import annotations

import pathlib
import unittest

import yaml

MOCKS = pathlib.Path(__file__).resolve().parents[1]
BAO = MOCKS / "k8s" / "v5" / "openbao"
IMAGE = "docker.io/openbao/openbao:2.4.1"
MASTER = "172.16.0.0/28"

PRIVATE_RANGES = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                  "127.0.0.0/8"}


def render(name: str, **subs) -> list[dict]:
    """Render a manifest with its `${NAME}` placeholders substituted and none left over.

    Args:
        name: The manifest file under k8s/v5/openbao.
        **subs: The value for each placeholder name.

    Returns:
        The parsed YAML documents.
    """
    s = (BAO / name).read_text()
    for placeholder, value in subs.items():
        s = s.replace("${" + placeholder + "}", value)
    assert "${" not in s, f"unreplaced placeholder in {name}"
    return [d for d in yaml.safe_load_all(s) if d]


def by(docs, kind, name=None):
    """Return the first document of `kind`, and of `name` if given.

    Args:
        docs: The parsed documents.
        kind: The Kubernetes kind.
        name: The metadata name, or None for any.

    Returns:
        The matching document.

    Raises:
        AssertionError: No document matches.
    """
    for d in docs:
        if d["kind"] == kind and (name is None or d["metadata"]["name"] == name):
            return d
    raise AssertionError(f"no {kind} {name} in the manifest")


class TheStoreItself(unittest.TestCase):
    """The store runs unprivileged, keeps its root token in a Secret and stays in the cluster."""

    def setUp(self):
        self.docs = render("openbao.yaml", OPENBAO_IMAGE=IMAGE)

    def test_it_can_call_tokenreview_and_nothing_else(self):
        """Kubernetes auth fails with a confusing message without this binding."""
        crb = by(self.docs, "ClusterRoleBinding")
        self.assertEqual(crb["roleRef"]["name"], "system:auth-delegator")
        self.assertEqual(crb["subjects"][0]["name"], "openbao-sa")
        self.assertEqual(crb["subjects"][0]["namespace"], "agent-system")
        self.assertEqual([d["kind"] for d in self.docs if d["kind"].endswith(("Role", "RoleBinding"))],
                         ["ClusterRoleBinding"], "the store holds no other role or binding")

    def test_the_store_runs_unprivileged(self):
        c = by(self.docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["securityContext"]["capabilities"]["drop"], ["ALL"])
        self.assertTrue(c["securityContext"]["readOnlyRootFilesystem"])
        self.assertFalse(c["securityContext"]["allowPrivilegeEscalation"])

    def test_the_root_token_comes_from_a_secret_not_from_the_manifest(self):
        c = by(self.docs, "Deployment")["spec"]["template"]["spec"]["containers"][0]
        root = next(e for e in c["env"] if e["name"] == "BAO_DEV_ROOT_TOKEN_ID")
        self.assertIn("secretKeyRef", root["valueFrom"])
        self.assertNotIn("value", root)

    def test_it_is_reachable_only_inside_the_cluster(self):
        self.assertEqual(by(self.docs, "Service")["spec"]["type"], "ClusterIP")


class TheNetworkRules(unittest.TestCase):
    """The gateway reaches the store and public HTTPS only, and the runner appears in no policy."""

    def setUp(self):
        self.docs = render("networkpolicy-live.yaml", MASTER_CIDR=MASTER)
        self.gateway = by(self.docs, "NetworkPolicy", "gateway-live-egress")
        self.store = by(self.docs, "NetworkPolicy", "openbao-policy")

    def _public_https(self):
        """Return the egress rule to 0.0.0.0/0 and its ipBlock."""
        for rule in self.gateway["spec"]["egress"]:
            for target in rule["to"]:
                if target.get("ipBlock", {}).get("cidr") == "0.0.0.0/0":
                    return rule, target["ipBlock"]
        raise AssertionError("no public HTTPS rule")

    def test_the_gateway_reaches_the_store_by_label(self):
        rule = self.gateway["spec"]["egress"][0]
        self.assertEqual(rule["to"][0]["podSelector"]["matchLabels"]["app"], "openbao")
        self.assertEqual(rule["ports"][0]["port"], 8200)

    def test_public_https_excludes_every_private_range(self):
        """The same grant must not also open other workloads or the metadata server."""
        rule, block = self._public_https()
        self.assertEqual(rule["ports"][0]["port"], 443)
        self.assertEqual(set(block["except"]), PRIVATE_RANGES)

    def test_the_metadata_range_is_excluded_explicitly(self):
        """The metadata range stays excluded even if the private ranges change.

        On GKE the metadata server at 169.254.169.254 hands out node credentials.
        """
        _rule, block = self._public_https()
        self.assertIn("169.254.0.0/16", block["except"])

    def test_the_gateway_gets_no_other_port(self):
        ports = {p["port"] for rule in self.gateway["spec"]["egress"] for p in rule["ports"]}
        self.assertEqual(ports, {8200, 443})

    def test_only_the_gateway_may_talk_to_the_store(self):
        ingress = self.store["spec"]["ingress"]
        self.assertEqual(len(ingress), 1)
        self.assertEqual(ingress[0]["from"][0]["podSelector"]["matchLabels"]["app"], "gateway")

    def test_the_store_reaches_the_api_server_for_tokenreview(self):
        """The edge most easily forgotten, and the one whose absence looks like RBAC."""
        blocks = [t["ipBlock"]["cidr"] for rule in self.store["spec"]["egress"]
                  for t in rule["to"] if "ipBlock" in t]
        self.assertEqual(blocks, [MASTER])

    def test_the_runner_appears_nowhere(self):
        """No policy selects the runner or names it as a peer, so the live layer grants it nothing."""
        apps = []
        for d in self.docs:
            spec = d["spec"]
            peers = [spec.get("podSelector", {})]
            peers += [p.get("podSelector", {}) for rule in spec.get("ingress", []) for p in rule.get("from", [])]
            peers += [p.get("podSelector", {}) for rule in spec.get("egress", []) for p in rule.get("to", [])]
            apps += [sel.get("matchLabels", {}).get("app") for sel in peers]
        self.assertIn("gateway", apps, "the collection found no peers at all")
        self.assertNotIn("runner", apps)


class TheGatewayPatch(unittest.TestCase):
    """The gateway patch projects a bound token and sets only variables the code reads."""

    def setUp(self):
        self.patch = render("gateway-live-patch.yaml")[0]
        self.spec = self.patch["spec"]["template"]["spec"]
        self.container = self.spec["containers"][0]
        self.env = {e["name"]: e["value"] for e in self.container["env"]}

    def test_the_token_is_projected_and_audience_bound(self):
        source = self.spec["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"]
        self.assertEqual(source["audience"], "openbao")
        self.assertLessEqual(source["expirationSeconds"], 3600)

    def test_it_does_not_turn_automounting_back_on(self):
        """A general-purpose API token would grant more than the projected one."""
        self.assertNotIn("automountServiceAccountToken", self.spec)

    def test_the_token_is_mounted_read_only_where_the_code_looks(self):
        mount = next(m for m in self.container["volumeMounts"] if m["name"] == "bao-token")
        self.assertTrue(mount["readOnly"])
        self.assertTrue(self.env["BAO_SA_TOKEN_PATH"].startswith(mount["mountPath"]))

    def test_the_store_is_addressed_inside_the_cluster(self):
        self.assertIn("openbao.agent-system.svc", self.env["BAO_ADDR"])

    def test_every_variable_is_one_the_code_actually_reads(self):
        """The check that would otherwise fail twenty minutes into a cluster run."""
        source = (MOCKS / "booking_live" / "secrets.py").read_text()
        for name in self.env:
            self.assertIn(f'"{name}"', source,
                          f"{name} is set in the manifest but read nowhere in secrets.py")

    def test_the_role_matches_what_the_install_script_creates(self):
        script = (MOCKS / "scripts" / "gke-v5" / "37_install_openbao.sh").read_text()
        self.assertIn(f'BAO_ROLE_NAME:-{self.env["BAO_ROLE"]}', script)
        self.assertIn('BAO_AUDIENCE:-openbao', script)

    def test_the_kv_path_matches_what_the_install_script_writes(self):
        script = (MOCKS / "scripts" / "gke-v5" / "37_install_openbao.sh").read_text()
        self.assertIn(f'bao kv put {self.env["BAO_MOUNT"]}/{self.env["BAO_PATH"]}', script)
        self.assertIn(f'path "{self.env["BAO_MOUNT"]}/data/{self.env["BAO_PATH"]}"', script)


if __name__ == "__main__":
    unittest.main(verbosity=1)
