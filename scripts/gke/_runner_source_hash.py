#!/usr/bin/env python3
"""_runner_source_hash.py: content hash over the source that Dockerfile.k8s puts into the runner image.

Needs:  python3 and the repository root as the single argument.
Usage:  python3 scripts/gke/_runner_source_hash.py <mocks-dir>
Result: The hex SHA-256 on stdout. Exit code 2 on a wrong argument count.

One definition, two readers. ``20_build_push_images.sh`` records the value next to the
image digest it has just pushed, and ``99_full_run_v5.sh`` recomputes it before a run and
refuses to start when the pinned image is older than the code it would measure.

The check exists because ``99`` restores ``scripts/gke/.digests`` from
``results_v4_k8s/environment/image-digests.env`` at the start of every run, and that
archive is written by a teardown, so it can be older than the code. The guest then
answers the ``v5-hello`` with ``pk_boot`` alone while the services already require
``pk_sig`` as well, and the run dies in step 31 after a full cluster bring-up.
A measurement against a guest of a different protocol version would be invalid, so this
is fail-closed: a missing record counts as a mismatch.

Scope: the ``.py`` files of the packages the Dockerfile COPYs, plus the Dockerfile
itself. Test modules named ``tests_*.py`` are excluded on purpose. They do travel into the
image, so the image digest changes with them, but they cannot run inside the TD, and forcing
a rebuild for a test edit would make the check expensive enough to be switched off. The
script-style ``tests.py`` of V0 to V4 does not match that pattern and is hashed like any
other module. What the image digest
pins is a separate question and is answered by the freeze record.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

# The packages Dockerfile.k8s copies, in the order it copies them.
PACKAGES = ("booking_v0", "booking_v1", "booking_v2", "booking_v3", "booking_v4", "booking_v5")

# Build inputs outside the packages. The Dockerfile decides what is in the image at all.
EXTRA_FILES = ("Dockerfile.k8s",)


def _source_files(mocks_dir: Path) -> list[Path]:
    """Every hashed file, sorted: the package sources without ``tests_*.py`` and caches, plus EXTRA_FILES."""
    files: list[Path] = []
    for package in PACKAGES:
        for path in (mocks_dir / package).rglob("*.py"):
            if "__pycache__" in path.parts or path.name.startswith("tests_"):
                continue
            files.append(path)
    files.extend(mocks_dir / name for name in EXTRA_FILES)
    return sorted(files)


def runner_source_digest(mocks_dir: Path) -> str:
    """SHA-256 over path and bytes of every source file, so a rename counts as a change."""
    digest = hashlib.sha256()
    for path in _source_files(mocks_dir):
        digest.update(str(path.relative_to(mocks_dir)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main(argv: list[str]) -> int:
    """Print the digest for the mocks directory given as the single argument."""
    if len(argv) != 2:
        print(f"usage: {argv[0]} <mocks-dir>", file=sys.stderr)
        return 2
    print(runner_source_digest(Path(argv[1]).resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
