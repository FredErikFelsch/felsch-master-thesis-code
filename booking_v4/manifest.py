"""The run manifest: what configuration produced a record.

Every record writer (the booking_v3 experiment and its re-measurements, the live runs, the demo
sessions) embeds `run_manifest()`, so every recorded number names the code, policies, verifier,
clock mode, images and freeze it came from.

    {
      "manifest_version": 1,
      "recorded_at": "2026-09-10T12:00:00Z",
      "git": {"commit": "...", "dirty": true|false, "branch": "..."},
      "policies": {"P2": "<digest>", "P2.1": "<digest>", "P3": "<digest>", "P3+pay-approval": "<digest>"},
      "registry": {"policy_schema": "ps-3", "constraint": "cr-1", "fact": "fr-2", "fact_extension": "fr-2.1"},
      "ttl": {"token_s": 120, "intervention_s": 300},
      "clock_mode": "system" | "fixed:<epoch>" | "stepped",
      "verifier": "TdxVerifier" | "FakeVerifier" | null,
      "images": {"RUNNER_IMAGE": "...@sha256:...", ...}        (scripts/gke/.digests, when present)
      "freeze": {"stamp": "...", "sha256": "..."}               (results_v5/freeze-candidate, when present)
                or {"stamp": "...", "sha256": null, "missing": true}  (the requested stamp has no file)
      "python": "3.x.y", "platform": "..."
    }
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import platform
import subprocess
import sys
import time
from typing import Optional

MANIFEST_VERSION = 1
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _git() -> dict:
    """Return commit, dirty flag and branch of the checkout, or None values outside git."""
    def run(*args):
        try:
            return subprocess.run(["git", *args], cwd=str(REPO_ROOT), capture_output=True, text=True,
                                  timeout=10).stdout.strip()
        except Exception:                                       # noqa: BLE001
            return ""
    commit = run("rev-parse", "HEAD")
    if not commit:
        return {"commit": None, "dirty": None, "branch": None}
    return {"commit": commit, "dirty": bool(run("status", "--porcelain")), "branch": run("rev-parse", "--abbrev-ref", "HEAD")}


def _policies() -> dict:
    """Return the digests of the default policies."""
    from booking_v2.policy import default_p2, default_p2_1
    from booking_v3.policy import default_p3, p3_with_pay_approval
    return {"P2": default_p2().digest(), "P2.1": default_p2_1().digest(),
            "P3": default_p3().digest(), "P3+pay-approval": p3_with_pay_approval().digest()}


def _registry() -> dict:
    """Return the schema and registry versions the policies are built against."""
    from booking_v2 import facts
    from booking_v2.policy import CONSTRAINT_REGISTRY_VERSION, POLICY_SCHEMA_VERSION
    return {"policy_schema": POLICY_SCHEMA_VERSION, "constraint": CONSTRAINT_REGISTRY_VERSION,
            "fact": facts.FACT_REGISTRY_VERSION, "fact_extension": facts.FACT_REGISTRY_EXTENSION}


def _images() -> Optional[dict]:
    """Return the image digests from scripts/gke/.digests, or None without that file."""
    path = REPO_ROOT / "scripts" / "gke" / ".digests"
    if not path.exists():
        return None
    out = {}
    for line in path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _freeze(stamp: Optional[str] = None) -> Optional[dict]:
    """Return stamp and SHA-256 of the freeze file the record belongs to.

    With a stamp (argument or FREEZE_STAMP) only `freeze-<stamp>.json` counts. If that file
    is missing, the result names the requested stamp with `"sha256": None` and
    `"missing": True` instead of recording another freeze. Without a stamp the newest file
    in results_v5/freeze-candidate is used.

    Returns:
        The freeze entry, or None if no stamp is requested and no freeze file exists.
    """
    stamp = stamp or os.environ.get("FREEZE_STAMP")
    directory = REPO_ROOT / "results_v5" / "freeze-candidate"
    candidates = sorted(directory.glob("freeze-*.json")) if directory.exists() else []
    if stamp:
        candidates = [c for c in candidates if c.name == f"freeze-{stamp}.json"]
        if not candidates:
            return {"stamp": stamp, "sha256": None, "missing": True}
    if not candidates:
        return None
    path = candidates[-1]
    return {"stamp": path.name[len("freeze-"):-len(".json")],
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def run_manifest(*, clock_mode: str, verifier: Optional[str] = None, freeze_stamp: Optional[str] = None,
                 extra: Optional[dict] = None) -> dict:
    """Build the manifest for one record.

    Args:
        clock_mode: The clock the services under test ran: `system` live,
            `fixed:<epoch>` for the harness clock, `stepped` for the offline expiry
            scenario.
        verifier: The Authority's verifier class, None where no attestation is involved.
        freeze_stamp: The freeze the record belongs to, FREEZE_STAMP by default.
        extra: Further top-level fields, merged in last.

    Returns:
        The manifest as a JSON-serialisable dict.
    """
    from booking_v3.authority import INTERVENTION_TTL, TOKEN_TTL
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "git": _git(),
        "policies": _policies(),
        "registry": _registry(),
        "ttl": {"token_s": TOKEN_TTL, "intervention_s": INTERVENTION_TTL},
        "clock_mode": clock_mode,
        "verifier": verifier,
        "images": _images(),
        "freeze": _freeze(freeze_stamp),
        "python": platform.python_version(),
        "platform": platform.platform(),
    }
    if extra:
        manifest.update(extra)
    return manifest


if __name__ == "__main__":
    import json
    json.dump(run_manifest(clock_mode="system"), sys.stdout, indent=2)
    print()
