"""The Kata agent policy must bind the image a guest pull loads.

Run:
    python3 -m booking_v5.tests_kata_policy_image

The tests evaluate `CreateContainerRequest` of the policy template `k8s/v5/init-data/policy.rego`
(rendered with a digest-pinned runner image) with OPA 0.68.0, the version
`scripts/gke-v5/41_probe_a19.sh` pins. The OPA binary is taken from `$OPA_BIN`, from
`results_v5/opa/opa` or from the PATH. The suite is skipped with the reason in the skip message
when none of them is that version, so a missing tool does not pass silently.

The request is built from the policy's own `policy_data` for the container named `runner`, with
the fields the agent adds. The control case must be allowed, otherwise the input is not a
faithful request and every refusal below would prove nothing.

Two facts come from requests the host sent (probe log `results_v5/probe/boot-times-
20260903T140328Z.txt`, three CreateContainerRequests of the pause container). The pause
container carries one `image_guest_pull` storage with `source: "pause"`, and its single driver
option is `image_guest_pull={"metadata": <the OCI annotations>}`. The agent (kata-agent 3.31.0)
pulls `storage.source` for an application container, and unpacks the guest's pause bundle when
the metadata says "sandbox". The runner request is modelled on that shape. Whether the runner
request on a cluster has this form is a live check (the A19 probe run on the final freeze, see
`scripts/gke-v5/attack_catalogue.md`).

A template without the image-source rule (`allow_image_source`, added by `_rules_backport.py`)
is tolerated. The test that documents the missing rule then runs and the tests that need the rule
are skipped, and not the other way round.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = pathlib.Path(os.environ.get("KATA_POLICY_TEMPLATE")
                        or ROOT / "k8s" / "v5" / "init-data" / "policy.rego")
OPA_VERSION = "0.68.0"
IMAGE = ("europe-west1-docker.pkg.dev/project-example/thesis/booking@sha256:"
         "8864e0692a5fbe73135bc255d26a61d638aced26950210338a4bb581b3986a34")
ATTACKER = "ghcr.io/attacker/evil@sha256:" + "0" * 64
IMG_KEY = "io.kubernetes.cri.image-name"
CID, SANDBOX, SNAME = "b" * 64, "a" * 64, "runner-td-bcdfg"
SFPREFIX = f"/run/kata-containers/shared/containers/{CID}-0123456789abcdef-"


def pull_option(annotations: dict) -> str:
    """Return the single driver option the host sends, the OCI annotations as pull metadata."""
    return "image_guest_pull=" + json.dumps({"metadata": annotations}, separators=(",", ":"))


def find_opa() -> str | None:
    """Return the OPA binary of the pinned version, or None."""
    for cand in (os.environ.get("OPA_BIN"), str(ROOT / "results_v5" / "opa" / "opa"), shutil.which("opa")):
        if not cand or not os.path.isfile(cand):
            continue
        try:
            out = subprocess.run([cand, "version"], capture_output=True, text=True, timeout=20).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if re.search(rf"Version:\s*{re.escape(OPA_VERSION)}", out):
            return cand
    return None


def _concrete(v):
    """Replace the policy's placeholders and regexes by values that match them."""
    if not isinstance(v, str):
        return v
    v = v.replace("$(bundle-id)", CID).replace("$(root_path)", f"/run/kata-containers/{CID}/rootfs")
    if v.startswith("$(sfprefix)"):
        return SFPREFIX + v[len("$(sfprefix)"):].rstrip("$")
    if v == "^[a-z0-9]{64}$":
        return SANDBOX
    if v.startswith("^runner"):
        return SNAME
    if v == "^/run/kata-containers/sandbox/ephemeral/tmp$":
        return v[1:-1]
    if v.startswith("^/var/run/netns/cni-"):
        return "/var/run/netns/cni-e18555e0-5582-e9a8-a18f-7bd08e5bf776"
    return v


def _walk(o):
    """Apply `_concrete` to every string of a nested structure."""
    if isinstance(o, dict):
        return {k: _walk(x) for k, x in o.items()}
    if isinstance(o, list):
        return [_walk(x) for x in o]
    return _concrete(o)


@unittest.skipIf(find_opa() is None, f"SKIPPED: OPA {OPA_VERSION} not found (set OPA_BIN or run 41_probe_a19.sh)")
class TheImageSourceIsBoundByThePolicy(unittest.TestCase):
    """A guest pull that would load another image than the pinned runner image is refused."""

    @classmethod
    def setUpClass(cls):
        cls.opa = find_opa()
        cls.dir = tempfile.mkdtemp(prefix="kata-policy-")
        text = TEMPLATE.read_text(encoding="utf-8").replace("${RUNNER_IMAGE}", IMAGE)
        cls.policy_text = text
        cls.policy = os.path.join(cls.dir, "policy.rego")
        pathlib.Path(cls.policy).write_text(text, encoding="utf-8")
        cls.has_rule = "allow_image_source" in text
        pathlib.Path(cls.dir, "state.json").write_text('{"pstate": {}}')
        data = json.loads(cls._opa("data.agent_policy.policy_data", raw=False))
        cls.base = cls._request(data)
        cls.pause = cls._pause_request(data)

    @classmethod
    def _opa(cls, query: str, inp: dict | None = None, raw: bool = True) -> str:
        """Evaluate `query` with OPA on the rendered policy.

        Args:
            query: The OPA query.
            inp: The input document, if any.
            raw: Return OPA's raw output. Otherwise return the query's value as JSON.

        Returns:
            The output of the evaluation.
        """
        args = [cls.opa, "eval", "-d", cls.policy, "-d", os.path.join(cls.dir, "state.json"),
                "-f", "raw" if raw else "json"]
        if inp is not None:
            args += ["-i", "/dev/stdin"]
        out = subprocess.run(args + [query], input=json.dumps(inp) if inp is not None else None,
                             capture_output=True, text=True, timeout=120)
        if not raw:
            return json.dumps(json.loads(out.stdout)["result"][0]["expressions"][0]["value"])
        return out.stdout.strip()

    @staticmethod
    def _request(policy_data: dict) -> dict:
        """Return a CreateContainerRequest for the `runner` container, built from its policy entry."""
        c = [x for x in policy_data["containers"]
             if x["OCI"]["Annotations"].get("io.kubernetes.cri.container-name") == "runner"][0]
        oci = _walk(copy.deepcopy(c["OCI"]))
        a = oci["Annotations"]
        a["io.kubernetes.cri.sandbox-id"] = SANDBOX
        a["io.katacontainers.pkg.oci.bundle_path"] = f"/run/containerd/io.containerd.runtime.v2.task/k8s.io/{CID}"
        a["io.kubernetes.container.terminationMessagePath"] = "/dev/termination-log"
        a["io.kubernetes.container.terminationMessagePolicy"] = "File"
        oci.update(Hooks=None, Solaris=None, Windows=None)
        lin = oci["Linux"]
        lin.update(GIDMappings=[], UIDMappings=[], MountLabel="", RootfsPropagation="", IntelRdt=None, Seccomp=None,
                   Resources={**(lin.get("Resources") or {}), "Devices": [], "BlockIO": None, "Network": None,
                              "Pids": None})
        oci["Process"]["SelinuxLabel"] = ""
        storages = _walk(copy.deepcopy(c["storages"]))
        storages.append({"driver": "image_guest_pull", "driver_options": [pull_option(a)],
                         "source": a[IMG_KEY], "fstype": "overlay", "options": [],
                         "mount_point": f"/run/kata-containers/{CID}/rootfs", "fs_group": None, "shared": False})
        return {"OCI": oci, "storages": storages, "devices": [], "sandbox_pidns": False, "container_id": CID,
                "shared_mounts": [], "string_user": None}

    @staticmethod
    def _pause_request(policy_data: dict) -> dict:
        """Return the pause (sandbox) CreateContainerRequest in the shape of the captured host requests."""
        c = [x for x in policy_data["containers"]
             if x["OCI"]["Annotations"].get("io.kubernetes.cri.container-type") == "sandbox"][0]
        oci = _walk(copy.deepcopy(c["OCI"]))
        a = oci["Annotations"]
        a["io.kubernetes.cri.sandbox-id"] = SANDBOX
        a["io.katacontainers.pkg.oci.bundle_path"] = f"/run/containerd/io.containerd.runtime.v2.task/k8s.io/{CID}"
        a["io.kubernetes.cri.podsandbox.image-name"] = "registry.example/pause:3.8@sha256:" + "8" * 64
        a["io.kubernetes.cri.sandbox-log-directory"] = (
            f"/var/log/pods/{a['io.kubernetes.cri.sandbox-namespace']}_{a['io.kubernetes.cri.sandbox-name']}_"
            "28f561c0-ed34-4499-800a-977397baba55")
        oci.update(Hooks=None, Solaris=None, Windows=None)
        lin = oci["Linux"]
        lin.update(GIDMappings=[], UIDMappings=[], MountLabel="", RootfsPropagation="", IntelRdt=None, Seccomp=None,
                   Resources={**(lin.get("Resources") or {}), "Devices": [], "BlockIO": None, "Network": None,
                              "Pids": None})
        oci["Process"]["SelinuxLabel"] = ""
        storages = _walk(copy.deepcopy(c["storages"]))
        storages.append({"driver": "image_guest_pull", "driver_options": [pull_option(a)], "source": "pause",
                         "fstype": "overlay", "options": [], "mount_point": f"/run/kata-containers/{CID}/rootfs",
                         "fs_group": None, "shared": False})
        return {"OCI": oci, "storages": storages, "devices": [], "sandbox_pidns": False, "container_id": CID,
                "shared_mounts": [], "string_user": None}

    def allowed(self, mutate=lambda i: None, base=None) -> bool:
        """Return whether the policy allows the request after `mutate` has been applied to a copy."""
        inp = copy.deepcopy(base or self.base)
        mutate(inp)
        return self._opa("data.agent_policy.CreateContainerRequest.allowed", inp) == "true"

    @staticmethod
    def _pull(i):
        """Return the guest-pull storage of request `i`."""
        return [s for s in i["storages"] if s["driver"] == "image_guest_pull"][0]

    # The control, and the gap of a template without the rule.

    def test_control_the_expected_image_is_allowed(self):
        self.assertTrue(self.allowed(), "the baseline request is refused: the input is not faithful")

    @unittest.skipIf("allow_image_source" in TEMPLATE.read_text(encoding="utf-8"), "template already has the rule")
    def test_without_the_rule_the_template_accepts_a_foreign_image_source(self):
        self.assertTrue(self.allowed(lambda i: self._pull(i).update(source=ATTACKER)),
                        "the template refuses a foreign source: regenerate the expectations")

    # The image-source rules.

    def _needs_rule(self):
        """Skip the test when the template does not carry the image-source rules."""
        if not self.has_rule:
            self.skipTest("the template does not carry the image-source rules yet (regenerate with 13_genpolicy.sh)")

    def test_a_foreign_storage_source_is_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: self._pull(i).update(source=ATTACKER)))

    def test_an_empty_storage_source_is_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: self._pull(i).update(source="")))

    def test_a_foreign_image_name_annotation_is_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: i["OCI"]["Annotations"].update({IMG_KEY: ATTACKER})))

    def test_both_foreign_is_refused(self):
        self._needs_rule()
        def both(i):
            i["OCI"]["Annotations"][IMG_KEY] = ATTACKER
            self._pull(i)["source"] = ATTACKER
        self.assertFalse(self.allowed(both))

    def test_a_missing_image_name_annotation_is_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: i["OCI"]["Annotations"].pop(IMG_KEY)))

    def test_a_missing_guest_pull_storage_is_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: i["storages"].remove(self._pull(i))))

    def test_a_second_guest_pull_storage_is_refused(self):
        self._needs_rule()
        def two(i, mount_suffix=""):
            extra = copy.deepcopy(self._pull(i))
            extra["source"] = ATTACKER
            extra["mount_point"] += mount_suffix
            i["storages"].append(extra)
        self.assertFalse(self.allowed(two), "a second pull for the same mount point and a foreign source")
        self.assertFalse(self.allowed(lambda i: two(i, "/x")), "a second pull for another mount point")
        self.assertFalse(self.allowed(lambda i: i["storages"].append(copy.deepcopy(self._pull(i)))),
                         "an identical duplicate")

    # The pull metadata (driver options).

    def test_metadata_that_marks_the_runner_as_a_sandbox_is_refused(self):
        """The agent unpacks the guest's pause bundle for such a pull instead of the image."""
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: self._meta_key(i, "io.kubernetes.cri.container-type", "sandbox")))
        self.assertFalse(self.allowed(lambda i: self._meta_key(i, "io.kubernetes.cri-o.ContainerType", "sandbox")))

    @staticmethod
    def _meta_key(i, key, value):
        """Set `key` to `value` in the pull metadata of request `i`."""
        s = TheImageSourceIsBoundByThePolicy._pull(i)
        m = json.loads(s["driver_options"][0].split("=", 1)[1])["metadata"]
        m[key] = value
        s["driver_options"] = [pull_option(m)]

    def test_two_driver_options_are_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: self._pull(i)["driver_options"].append(pull_option({}))))

    def test_driver_options_that_are_not_the_pull_metadata_are_refused(self):
        self._needs_rule()
        for bad in (["image_guest_pull=true"], ["image_guest_pull={not json"], [], ["other=1"],
                    [f"image_guest_pull={ATTACKER}"]):
            with self.subTest(bad=bad):
                self.assertFalse(self.allowed(lambda i: self._pull(i).update(driver_options=bad)))

    def _allowed_under(self, policy_text: str, inp: dict) -> bool:
        """Return whether a modified copy of the policy allows `inp`."""
        path = os.path.join(self.dir, "variant.rego")
        pathlib.Path(path).write_text(policy_text, encoding="utf-8")
        out = subprocess.run([self.opa, "eval", "-d", path, "-d", os.path.join(self.dir, "state.json"), "-f", "raw",
                              "-i", "/dev/stdin", "data.agent_policy.CreateContainerRequest.allowed"],
                             input=json.dumps(inp), capture_output=True, text=True, timeout=120).stdout.strip()
        return out == "true"

    def test_an_option_with_a_foreign_key_is_refused_even_if_its_tail_is_valid_metadata(self):
        """The agent reads only `image_guest_pull=<json>`. The policy must not cut at a fixed offset."""
        self._needs_rule()
        def rekey(i):
            s = self._pull(i)
            s["driver_options"] = ["x" * len("image_guest_pull=") + s["driver_options"][0].split("=", 1)[1]]
        self.assertFalse(self.allowed(rekey))

    def test_a_tag_instead_of_a_digest_is_refused(self):
        """A policy whose image reference is not digest-pinned is not accepted.

        The image rule needs `@sha256:<64 hex>` at the end. The policy is modified, not the request.
        """
        self._needs_rule()
        tag = IMAGE.split("@")[0] + ":latest"
        weak = self.policy_text.replace(IMAGE, tag)
        self.assertNotEqual(weak, self.policy_text)
        inp = copy.deepcopy(self.base)
        inp["OCI"]["Annotations"][IMG_KEY] = tag
        self._pull(inp)["source"] = tag
        self._pull(inp)["driver_options"] = [pull_option(inp["OCI"]["Annotations"])]
        self.assertFalse(self._allowed_under(weak, inp))

    def test_a_container_that_names_no_image_may_not_pull(self):
        """When the policy entry of the container carries no image name, every pull is refused."""
        self._needs_rule()
        marker = f'"{IMG_KEY}": "{IMAGE}",'
        self.assertIn(marker, self.policy_text)
        nameless = self.policy_text.replace(marker, "")
        no_pull = copy.deepcopy(self.base)
        no_pull["storages"].remove(self._pull(no_pull))
        no_pull["OCI"]["Annotations"].pop(IMG_KEY)
        self.assertFalse(self._allowed_under(nameless, copy.deepcopy(self.base)), "a pull must be refused")
        self.assertTrue(self._allowed_under(nameless, no_pull), "control: without a pull the same entry is allowed")

    # The pause container, with the request shape captured from the host.

    def test_pause_control_the_real_shaped_pause_request_is_allowed(self):
        self._needs_rule()
        self.assertTrue(self.allowed(base=self.pause), "the rule refuses the pause container the host really sends")

    def test_the_runner_cannot_be_turned_into_a_pause_pull(self):
        """For the runner, the source `pause` and the sandbox flag are refused, whatever the pause rule says.

        Source `pause` plus a sandbox flag makes the agent unpack the guest's pause bundle.
        """
        self._needs_rule()
        def as_pause(i):
            self._pull(i)["source"] = "pause"
            self._meta_key(i, "io.kubernetes.cri.container-type", "sandbox")
        self.assertFalse(self.allowed(as_pause))

    def test_pause_without_a_pull_storage_is_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: i["storages"].remove(self._pull(i)), base=self.pause))

    def test_pause_pull_with_a_foreign_source_is_refused(self):
        """Without the sandbox flag the agent would pull `source`."""
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: self._pull(i).update(source=ATTACKER), base=self.pause))
        self.assertFalse(self.allowed(lambda i: self._pull(i).update(source="pause2"), base=self.pause))

    def test_pause_whose_metadata_does_not_say_sandbox_is_refused(self):
        """Source "pause" without the flag would make the agent pull an image called `pause`."""
        self._needs_rule()
        def unflag(i):
            self._meta_key(i, "io.kubernetes.cri.container-type", "container")
        self.assertFalse(self.allowed(unflag, base=self.pause))

    def test_pause_with_two_pull_storages_is_refused(self):
        self._needs_rule()
        self.assertFalse(self.allowed(lambda i: i["storages"].append(copy.deepcopy(self._pull(i))), base=self.pause))


class TheTemplateAndTheGeneratorCarryTheSameRule(unittest.TestCase):
    """The template and the backport carry the same image-source rule.

    The rule lives twice: in the template `policy.rego` (run policy) and in `_rules_backport.py`
    (genpolicy output of the probe and attach pods). They must not drift, and the pin of the
    patched upstream rules in `_genpolicy.sh` must be the hash of what the backport produces.
    """

    BACKPORT = ROOT / "scripts" / "gke-v5" / "_rules_backport.py"
    GENPOLICY = ROOT / "scripts" / "gke-v5" / "_genpolicy.sh"
    UPSTREAM = ROOT / "results_v5" / "genpolicy-3.31.0" / "rules.rego"
    START = "# What a guest pull loads (audit F-039)."
    END = "allow_anno_key_value(i_key, i_value, p_container) if {"

    @classmethod
    def _backport(cls):
        """Load `_rules_backport.py` as a module."""
        spec = importlib.util.spec_from_file_location("_rules_backport", cls.BACKPORT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def _block(self, text: str) -> str:
        """Return the image-source block of a policy text."""
        return text[text.index(self.START):text.index(self.END)].strip()

    def test_the_rule_text_is_identical(self):
        new = [n for name, _old, n in self._backport().EDITS if name == "allow_image_source: rule"][0]
        self.assertEqual(self._block(new), self._block(TEMPLATE.read_text(encoding="utf-8")))

    @unittest.skipUnless(UPSTREAM.is_file(), "the pinned upstream rules.rego is not downloaded (results_v5/genpolicy-3.31.0)")
    def test_the_pin_is_the_hash_of_the_backport_output(self):
        text = self.UPSTREAM.read_text()
        mod = self._backport()
        for name, old, new in mod.EDITS:
            self.assertEqual(text.count(old), 1, name)
            text = text.replace(old, new)
        header = ("# rules.rego from Kata 3.31.0 with the GHSA-fmg6-v47x-52wr (CVE-2026-77176) mount-source\n"
                  "# fix backported by scripts/gke-v5/_rules_backport.py (three edits) plus the image-source\n"
                  "# binding of audit F-039 (two edits), see that file.\n")
        digest = hashlib.sha256((header + text).encode()).hexdigest()
        pin = re.search(r'RULES_PATCHED_SHA256="\$\{RULES_PATCHED_SHA256:-([0-9a-f]{64})\}"',
                        self.GENPOLICY.read_text()).group(1)
        self.assertEqual(digest, pin)


if __name__ == "__main__":
    unittest.main()
