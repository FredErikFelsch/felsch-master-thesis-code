"""Attack A19: after the init-data is measured, the host cannot replace it through the agent.

The label A19 comes from scripts/gke-v5/attack_catalogue.md. The init-data measurement
argument rests on three things together, not on TDX alone. process-user-data writes
`/run/peerpod/initdata*` once inside the TD and `initdata-measure` reads the same file into
RTMR3. The measured genpolicy policy denies `SetPolicyRequest`. And it denies the agent's
host-facing write path onto those files, `CopyFileRequest`. This module checks the third.

On CAA/kata-remote the kata-agent is reachable only over the agent-protocol-forwarder's
mutual-TLS ttrpc channel on the pod VM (`:15150`). There is no local agent unix socket and
`kata-agent-ctl` cannot speak TLS-TCP, so a live CopyFile would need CAA's own client
identity and a bespoke TLS client. Instead the property is shown deterministically against
the policy the TD enforces. The runner's genpolicy policy is measured into RTMR3 (its digest
is in the freeze, and the substrate check compares the ConfigMap with the freeze). Evaluating
that `rules.rego` with OPA for a `CopyFileRequest` on each `/run/peerpod/*` path therefore
answers, for the enforced policy itself, whether the agent would allow the write. It does
not, because the paths are outside the CopyFile `sfprefix`. A path inside the sandbox share
dir is allowed (positive control). This covers every target path instead of one live attempt
and is reproducible offline from the pinned policy.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

#: The measured init-data files a host must not be able to replace after RTMR3 is extended.
A19_TARGET_PATHS = (
    "/run/peerpod/initdata.digest",     # the hex digest initdata-measure read into RTMR3
    "/run/peerpod/initdata.toml",       # the raw init-data (genpolicy policy, aa.toml, cdh.toml)
    "/run/peerpod/aa.toml",
    "/run/peerpod/cdh.toml",
)

#: A path inside the sandbox share dir (sfprefix): <cpath>/<64-hex bundle-id>-<16-hex>-<name>.
#: The policy allows CopyFile here, so it is the positive control that shows the probe would
#: have seen an allow if the policy granted one.
A19_ALLOWED_CONTROL = ("/run/kata-containers/shared/containers/"
                       + "a" * 64 + "-0123456789abcdef-hostname")

#: The rule the kata-agent consults before performing a CopyFileRequest.
A19_QUERY = "data.agent_policy.CopyFileRequest"

# Verdicts
A19_DENIED = "A19_DENIED"              # the policy refuses the write: the property holds
A19_LEAKED = "A19_LEAKED"             # the policy allows it: the init-data is replaceable (FAIL)
A19_INCONCLUSIVE = "A19_INCONCLUSIVE"  # OPA gave no boolean (policy/query error)
A19_CONTROL_OK = "A19_CONTROL_OK"     # the allowed control path is indeed allowed
A19_CONTROL_FAILED = "A19_CONTROL_FAILED"  # the control was not allowed, so the probe proves nothing


@dataclass(frozen=True)
class A19Result:
    """The verdict for one path, with a human-readable reason."""

    verdict: str
    path: str
    detail: str = ""

    @property
    def passed(self) -> bool:
        """Whether this verdict is the desired one (denied target or allowed control)."""
        return self.verdict in (A19_DENIED, A19_CONTROL_OK)


def copyfile_input(path: str, file_type: str = "Regular") -> dict:
    """Return the OPA input document for a host CopyFileRequest of a regular file to `path`.

    The rule checks `input.file_type` and `input.path` only. The file content does not enter
    the decision.
    """
    return {"path": path, "file_type": file_type}


def opa_eval_argv(opa: str, policy_file: str, input_file: str, query: str = A19_QUERY) -> list[str]:
    """Return the `opa eval` command line for one CopyFileRequest input, with JSON output.

    The policy is self-contained (it carries its own policy_data), so no data file is needed.

    Args:
        opa: the opa binary.
        policy_file: the measured runner policy.
        input_file: the input document from `copyfile_input`.
        query: the rule to evaluate.

    Returns:
        The argument vector.
    """
    return [opa, "eval", "-d", policy_file, "-i", input_file, query, "--format", "json"]


def parse_opa_bool(opa_json_text: str) -> "bool | None":
    """Return the rule's value from `opa eval --format json`.

    Returns None if the query produced no boolean (a policy or query error, or a value of
    another type). A caller must not read None as a denial.
    """
    try:
        d = json.loads(opa_json_text)
        value = d["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError, TypeError):
        return None
    return value if isinstance(value, bool) else None


def verdict_for_target(path: str, allowed: "bool | None") -> A19Result:
    """Judge a target under /run/peerpod.

    An allowed write is the failure (A19_LEAKED), a denied one (False) the pass, and no
    boolean is inconclusive.
    """
    if allowed is None:
        return A19Result(A19_INCONCLUSIVE, path, "OPA returned no boolean for the rule")
    if allowed:
        return A19Result(A19_LEAKED, path, "policy allows host CopyFile: init-data is replaceable")
    return A19Result(A19_DENIED, path, "policy denies host CopyFile onto this path")


def verdict_for_control(path: str, allowed: "bool | None") -> A19Result:
    """Judge the sfprefix control, which must be allowed.

    Otherwise the probe would deny everything trivially and prove nothing about /run/peerpod.
    """
    if allowed:
        return A19Result(A19_CONTROL_OK, path, "sandbox-share path is allowed (probe is meaningful)")
    return A19Result(A19_CONTROL_FAILED, path, "the control was not allowed: the probe is not discriminating")


def main(argv: "list[str] | None" = None) -> int:
    """Evaluate the measured runner policy for every A19 target plus the positive control.

    Prints one verdict per path.

    Returns:
        0 if every target is denied and the control allowed, else 1.
    """
    import argparse
    import subprocess
    import tempfile
    ap = argparse.ArgumentParser(description="A19: the measured policy denies host CopyFile onto /run/peerpod/*")
    ap.add_argument("--opa", default="opa", help="path to the opa binary")
    ap.add_argument("--policy", required=True, help="the measured runner policy.rego (digest in RTMR3)")
    args = ap.parse_args(argv)

    def evaluate(path: str) -> "bool | None":
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(copyfile_input(path), f)
            input_file = f.name
        try:
            proc = subprocess.run(opa_eval_argv(args.opa, args.policy, input_file),
                                  capture_output=True, text=True)
        finally:
            os.unlink(input_file)
        return parse_opa_bool(proc.stdout)

    ok = True
    for path in A19_TARGET_PATHS:
        res = verdict_for_target(path, evaluate(path))
        print(f"{res.verdict}  {path}  {res.detail}")
        ok = ok and res.passed
    ctrl = verdict_for_control(A19_ALLOWED_CONTROL, evaluate(A19_ALLOWED_CONTROL))
    print(f"{ctrl.verdict}  {ctrl.path}  {ctrl.detail}")
    ok = ok and ctrl.passed
    print("A19", "DENIED (all targets, control allowed)" if ok else "CHECK: a target was not denied or the control failed")
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    import sys
    sys.exit(main())
