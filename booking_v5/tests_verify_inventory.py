"""The test inventory of the repository is complete and pinned.

Run:
    python3 -m booking_v5.tests_verify_inventory

A freeze run is valid only after `scripts/gke-v5/40_verify_v5.sh` passed, and that pass means
something only if the script runs every test module there is. This suite fails when a
`tests*.py` module exists that the script does not run, when the script names a module that
does not exist, when a module is listed twice, or when `verify.py` does not search a package
that contains tests.
"""
from __future__ import annotations

import pathlib
import re
import unittest

import verify

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gke-v5" / "40_verify_v5.sh"


def existing_modules() -> set[str]:
    """Return the dotted name of every `tests*.py` in a top-level package (a directory with an __init__.py)."""
    found = set()
    for package in sorted(p for p in ROOT.iterdir() if (p / "__init__.py").is_file()):
        for path in package.glob("tests*.py"):
            found.add(f"{package.name}.{path.stem}")
    return found


def scripted_modules() -> list[str]:
    """Return the modules `40_verify_v5.sh` runs through its `suite` helper, in order."""
    return re.findall(r"^\s*suite\s+(\S+)", SCRIPT.read_text(encoding="utf-8"), re.M)


class TheVerifyInventoryIsComplete(unittest.TestCase):
    """The verification script runs every test module once and lists no module that does not exist."""

    def test_the_script_runs_every_test_module(self):
        missing = sorted(existing_modules() - set(scripted_modules()))
        self.assertEqual(missing, [], "40_verify_v5.sh does not run these test modules")

    def test_the_script_names_no_module_that_does_not_exist(self):
        unknown = sorted(set(scripted_modules()) - existing_modules())
        self.assertEqual(unknown, [], "40_verify_v5.sh runs modules that are not in the tree")

    def test_no_module_is_listed_twice(self):
        modules = scripted_modules()
        self.assertEqual(sorted(m for m in set(modules) if modules.count(m) > 1), [])

    def test_the_script_pins_opa_and_runs_the_opa_suite(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('OPA_VERSION="0.68.0"', text)
        self.assertIn("booking_v5.tests_kata_policy_image", text)
        self.assertRegex(text, r'check "OPA \$\{OPA_VERSION\}" 1')

    def test_verify_py_searches_every_package_that_has_tests(self):
        packages = {m.split(".")[0] for m in existing_modules()}
        self.assertEqual(sorted(packages - set(verify.PACKAGES)), [])
        self.assertEqual(sorted(set(verify.discover())), sorted(existing_modules()))


if __name__ == "__main__":
    unittest.main()
