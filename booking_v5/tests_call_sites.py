"""Every call site of the protocol-shaped methods matches the signature it calls.

Some call sites need a live cluster (for example `e2e_live`) and are reached by no other test.
A parameter added to a protocol method would break them unnoticed, and Python cannot catch this
at import time. The check is therefore static. For a small set of methods whose parameter list is
the protocol, every call in the source tree must supply at least as many arguments as the
implementations require. A method that gains a parameter fails here until every caller has been
updated.

The check counts arguments only. It does not know which object a call is made on, so it takes the
smallest requirement among the implementations of that name, and it catches a caller that
supplies fewer arguments than any of them needs. Keyword-only parameters are not counted, and
optional keywords count as supplied.
"""
from __future__ import annotations

import ast
import importlib
import inspect
import pathlib
import unittest

MOCKS = pathlib.Path(__file__).resolve().parents[1]

#: Packages whose call sites are checked. Vendored sources and recorded runs are left out.
PACKAGES = ("booking_v0", "booking_v1", "booking_v2", "booking_v3", "booking_v4", "booking_v5",
            "booking_demo")

#: Methods whose parameter list is part of a protocol rather than an implementation detail.
#: Each entry names the implementations that define what a caller has to supply.
WATCHED: dict[str, tuple[str, ...]] = {
    "establish_session": ("booking_v5.relying_party:AuthorityRelyingParty.establish_session",
                          "booking_v5.controller_v5:RemoteAuthority.establish_session",
                          "booking_v5.controller_v5:LocalAuthority.establish_session"),
    # All three implementations require the boot key, because a challenge is bound to the TD
    # that asked for it.
    "issue_nonce": ("booking_v5.relying_party:AuthorityRelyingParty.issue_nonce",
                    "booking_v5.controller_v5:RemoteAuthority.issue_nonce",
                    "booking_v5.controller_v5:LocalAuthority.issue_nonce"),
    "execute_fragment": ("booking_v5.controller_v5:AttestedFragmentController.execute_fragment",),
    "establish_runner_session": ("booking_v3.authority:Authority.establish_runner_session",),
    "request_execution_grant": ("booking_v3.authority:Authority.request_execution_grant",),
    "canonical_binding": ("booking_v5.binding:canonical_binding",),
    "expected_rtmr3": ("booking_v5.rtmr_replay:expected_rtmr3",),
}


def _resolve(path: str):
    """Return the object a `module:dotted.name` path names."""
    module_name, _, dotted = path.partition(":")
    obj = importlib.import_module(module_name)
    for part in dotted.split("."):
        obj = getattr(obj, part)
    return obj


def _required(func) -> int:
    """Return how many positional arguments a caller must supply, excluding `self`."""
    params = list(inspect.signature(func).parameters.values())
    if params and params[0].name == "self":
        params = params[1:]
    return sum(1 for p in params
               if p.default is inspect.Parameter.empty
               and p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                              inspect.Parameter.POSITIONAL_OR_KEYWORD))


def _call_sites(tree: ast.AST):
    """Yield the name and node of every call of a watched method in `tree`."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (node.func.attr if isinstance(node.func, ast.Attribute)
                else node.func.id if isinstance(node.func, ast.Name) else None)
        if name in WATCHED:
            yield name, node


class CallSitesMatchTheirSignatures(unittest.TestCase):
    """Calls of the watched methods supply every argument their implementations require."""

    def test_every_call_supplies_what_the_signature_requires(self):
        minimum = {name: min(_required(_resolve(p)) for p in paths)
                   for name, paths in WATCHED.items()}
        problems = []
        for package in PACKAGES:
            for path in sorted((MOCKS / package).rglob("*.py")):
                if "__pycache__" in path.parts:
                    continue
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
                for name, node in _call_sites(tree):
                    if any(isinstance(a, ast.Starred) for a in node.args) or \
                            any(k.arg is None for k in node.keywords):
                        continue  # forwarded *args or **kwargs cannot be counted
                    supplied = len(node.args) + len(node.keywords)
                    if supplied < minimum[name]:
                        problems.append(
                            f"{path.relative_to(MOCKS)}:{node.lineno}: {name}() got {supplied} "
                            f"argument(s), the signature requires {minimum[name]}")
        self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_the_check_flags_an_establish_session_call_without_the_verdict_key(self):
        """Positive control: a call site that lacks the verdict key is reported as too short."""
        source = ('auth.establish_session(None, pk, run_id, 0, fragment.fragment_hash, '
                  's0.state_hash, nonce, substrate_profile_hash())')
        tree = ast.parse(source)
        sites = list(_call_sites(tree))
        self.assertEqual(len(sites), 1)
        name, node = sites[0]
        minimum = min(_required(_resolve(p)) for p in WATCHED[name])
        self.assertLess(len(node.args) + len(node.keywords), minimum,
                        "the call without pk_sig must be recognised as too short")

    def test_the_watched_implementations_all_exist(self):
        for name, paths in WATCHED.items():
            for path in paths:
                obj = _resolve(path)
                self.assertTrue(callable(obj), f"{path} is not callable")
                self.assertGreater(_required(obj), 0, f"{path} takes no required argument")


if __name__ == "__main__":
    unittest.main()
