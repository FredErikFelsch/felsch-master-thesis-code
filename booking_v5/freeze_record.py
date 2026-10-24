"""Freeze record: one machine-readable source for the Authority's reference values.

`freeze-<STAMP>.json` is the only input `ReferenceValues.from_freeze` reads. It is built once
from the recorded artefacts of a cluster run (the reference values, the DCAP report, the
substrate hash, the image provenance and the probe verdicts) and carries the SHA-256 of every
artefact it was built from. `FREEZE-<STAMP>.txt` is the human record, rendered deterministically
from the JSON. `verify` checks that the two have not drifted apart and that the artefacts on
disk are still the ones the freeze names. It also re-derives what the record pins: the
measurement, the substrate profile hash, the init-data digests and the binding version. It can
only report consistency. The record carries no signature, so its digest must be pinned outside
the directory.

    python3 -m booking_v5.freeze_record build  results_v5/freeze-candidate --stamp <STAMP> \
        --network <STAMP> --attach <STAMP> --image <image-name> \
        --runner-image <registry>/booking@sha256:<digest>

Two init-data digests exist and the freeze names both. The probe digest is the one the probe
pod's quote carried (sandbox `runner-peer`, its own genpolicy policy). The run digest is the one
every production runner is measured under (generateName `runner-td-`, the run policy) and the
one the Authority pins at deployment. `init_data` is the run digest, rendered from the sources
into `init-data-run-<STAMP>.toml`, an artefact whose SHA-256 is the digest. `probe_init_data`
is the probe digest, taken from `reference-values-<STAMP>.json`.

    python3 -m booking_v5.freeze_record verify results_v5/freeze-candidate --stamp <STAMP>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

from .binding import PROTOCOL_VERSION
from .profile_v5 import init_data_document, init_data_hash, require_pinned_image

SCHEMA_VERSION = 1
#: Quote fields the Authority pins (MROWNER differs per instance and is not among them).
MEASUREMENT_FIELDS = ("mrtd", "rtmr0", "rtmr1", "rtmr2", "mrseam", "tee_tcb_svn", "xfam", "tdattributes")
_DERIVED = ("FREEZE-{stamp}.txt", "freeze-{stamp}.json", "SHA256SUMS")


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _grep(text: str, pattern: str, group: int = 1, default: str | None = None) -> str | None:
    m = re.search(pattern, text, re.M)
    return m.group(group) if m else default


class FreezeInconsistent(ValueError):
    """The freeze would describe an image other than the one it measured.

    It is also raised when the record would claim a hardening that the image does not carry.
    """


def hardening_from_provenance(ptxt: str) -> dict:
    """Read what the image build recorded about two hardening steps.

    The steps are the IMDS-NAT hardening against attack A5c (scripts/gke-v5/attack_catalogue.md)
    and the removal of the kata mount unit, recorded as `b1`. The result is what the build
    wrote, not what a caller asserts. The lines are written into the provenance by
    k8s/v5/podvm-overlay/apply-hardening.sh.

    Args:
        ptxt: The image's provenance text.

    Returns:
        {"a5c": "HARDENED (noop)" | "HARDENED (masked)" | "OPEN (V5_HARDEN_A5C=0)",
         "b1": "APPLIED" | "NOT APPLIED"}
    """
    if "neutralised (A5c noop)" in ptxt:
        a5c = "HARDENED (noop)"
    elif re.search(r"setup-nat-for-imds\.service masked", ptxt):
        a5c = "HARDENED (masked)"
    else:
        a5c = "OPEN (V5_HARDEN_A5C=0)"
    b1 = "APPLIED" if "run-kata-containers.mount removed (B1)" in ptxt else "NOT APPLIED"
    return {"a5c": a5c, "b1": b1}


def run_document_name(stamp: str) -> str:
    """Return the file name of the rendered run init-data document inside the freeze directory."""
    return f"init-data-run-{stamp}.toml"


def build_freeze(freeze_dir: pathlib.Path, stamp: str, network_stamp: str | None = None,
                 attach_stamp: str | None = None, image: str | None = None, a5c: str | None = None,
                 caa: str = "0.21.1", kata: str = "3.31.0", runner_image: str | None = None) -> dict:
    """Assemble the freeze from the artefacts in `freeze_dir`.

    The image's provenance is the one named `image`, not the first one in the directory, and
    the `a5c` and `b1` hardening state is read from it. An explicit `a5c` label is accepted only
    when it agrees with the provenance. Without an image name a single provenance in the
    directory is used, more than one is refused, and with none the record carries no
    hardening claim.

    `runner_image` (digest-pinned) makes `init_data` the run digest. The init-data document the
    production runners are launched with is rendered into `init-data-run-<STAMP>.toml` and its
    SHA-256 is recorded. The probe digest moves to `probe_init_data`. Without it the record says
    `profile: probe`. The deployed Authority refuses such a record (service_v5.start_authority),
    so only offline fixtures use it.

    Args:
        freeze_dir: the directory with the recorded artefacts.
        stamp: the stamp of the probe run that is frozen.
        network_stamp: the stamp of the network probe, if any.
        attach_stamp: the stamp of the attach probe, if any.
        image: the name of the measured pod-VM image.
        a5c: an optional a5c label to check against the provenance.
        caa: the CAA version recorded in the image block.
        kata: the Kata version recorded in the image block.
        runner_image: the digest-pinned runner image, see above.

    Returns:
        The freeze record as a dict.

    Raises:
        FileNotFoundError: a required artefact is missing.
        KeyError: the reference values carry no digest for their init-data algorithm.
        ValueError: the substrate output has no PASS hash.
        FreezeInconsistent: `image` has no provenance in `freeze_dir`, the image is not
            decidable, `a5c` contradicts the provenance, or the probe digest is not sha256.
    """
    ref = json.loads((freeze_dir / f"reference-values-{stamp}.json").read_text())
    fields = ref["quote"]["fields"]
    algo = ref["init_data"]["algorithm"]
    digest_key = f"{algo}(toml)"
    if digest_key not in ref["init_data"]:
        raise KeyError(f"reference values carry no {digest_key} digest for init-data algorithm {algo}")

    dcap_txt = (freeze_dir / f"dcap-{stamp}.txt").read_text()
    substrate_txt = (freeze_dir / f"substrate-40-{stamp}.txt").read_text()
    substrate_hash = _grep(substrate_txt, r"substrate profile hash:\s+PASS\s+([0-9a-f]{64})")
    if not substrate_hash:
        raise ValueError("no PASS substrate profile hash in the recorded output of 40_verify_v5.sh. "
                         "A freeze needs a green substrate")

    provenance = {}
    hardening = {"a5c": a5c or "UNKNOWN (no image provenance)", "b1": "UNKNOWN (no image provenance)"}
    prov_files = sorted(freeze_dir.glob("*.provenance.txt"))
    if image is not None:
        named = freeze_dir / f"{image}.provenance.txt"
        if not named.exists():
            raise FreezeInconsistent(f"no provenance for the measured image {image!r} in {freeze_dir}")
        prov_files = [named]
    elif len(prov_files) > 1:
        raise FreezeInconsistent(f"{len(prov_files)} image provenances in {freeze_dir} and no --image: "
                                 "which one was measured is not decidable")
    if prov_files:
        ptxt = prov_files[0].read_text()
        provenance = {"file": prov_files[0].name,
                      "system_raw_sha256": _grep(ptxt, r"^([0-9a-f]{64})\s+system\.raw"),
                      "overlay_sha256": _grep(ptxt, r"overlay_sha256=([0-9a-f]{64})"),
                      "overlay_rev": int(_grep(ptxt, r"overlay_rev=(\d+)", default="0") or 0),
                      "caa_commit": _grep(ptxt, r"^([0-9a-f]{40})$")}
        if image is None:
            image = prov_files[0].name.replace(".provenance.txt", "")
        hardening = hardening_from_provenance(ptxt)
        if a5c is not None and a5c.split()[0] != hardening["a5c"].split()[0]:
            raise FreezeInconsistent(f"a5c label {a5c!r} contradicts the provenance of {image}: "
                                     f"{hardening['a5c']}")

    verdict_path = freeze_dir / f"verdict-{stamp}.txt"
    probe = {}
    if verdict_path.exists():
        vtxt = verdict_path.read_text()
        probe = {"p1": _grep(vtxt, r"^P1 [^:]+:\s+(\S+)"), "p2": _grep(vtxt, r"^P2 [^:]+:\s+(\S+)"),
                 "p3": _grep(vtxt, r"^P3 [^:]+:\s+(\S+)")}
    attach = {}
    if attach_stamp:
        atxt = (freeze_dir / f"attach-{attach_stamp}.txt").read_text()
        summary = next((json.loads(l) for l in atxt.splitlines() if l.startswith("{")), {})
        attach = {"stamp": attach_stamp, "verdict": summary.get("verdict"),
                  "rounds": summary.get("rounds"), "rtt_ms": summary.get("rtt_ms")}

    probe_digest = ref["init_data"][digest_key]
    init_data = {"algorithm": algo, "digest": probe_digest, "profile": "probe"}
    probe_init_data = None
    if runner_image is not None:
        if algo != "sha256":
            raise FreezeInconsistent(f"the run document is hashed with sha256, the probe used {algo}")
        runner_image = require_pinned_image(runner_image)
        document = init_data_document(runner_image)
        (freeze_dir / run_document_name(stamp)).write_text(document)
        probe_init_data = {"algorithm": algo, "digest": probe_digest, "profile": "probe",
                           "source": f"reference-values-{stamp}.json"}
        init_data = {"algorithm": "sha256", "digest": init_data_hash(document), "profile": "run",
                     "runner_image": runner_image, "document": run_document_name(stamp)}

    artefacts = {p.name: _sha256(p) for p in sorted(freeze_dir.iterdir())
                 if p.is_file() and p.name not in tuple(d.format(stamp=stamp) for d in _DERIVED)}

    return {
        "schema_version": SCHEMA_VERSION,
        "freeze_stamp": stamp,
        "platform": "tdx",
        # The canonical binding the runner code of this tree attests under, recorded next to
        # the measurements so the Authority pins both together. The runner image is tied to it
        # through the init-data digest.
        "binding_version": PROTOCOL_VERSION.decode(),
        "substrate_profile_hash": substrate_hash,
        "measurement": {k: fields[k] for k in MEASUREMENT_FIELDS},
        "init_data": init_data,
        **({"probe_init_data": probe_init_data} if probe_init_data else {}),
        "image": {"name": image, "caa": caa, "kata": kata, **provenance},
        "dcap": {"qv_result": _grep(dcap_txt, r"qv_result\s*[=:]\s*(\w+)"),
                 "fmspc": _grep(dcap_txt, r"fmspc\s*[=:]\s*([0-9a-fA-F]+)"),
                 "library": _grep(dcap_txt, r"VERDICT library:\s+(.+)$")},
        "probe": {**probe, "network_stamp": network_stamp, "a5c": hardening["a5c"],
                  "b1": hardening["b1"], "attach": attach},
        "artefacts": artefacts,
    }


def render_freeze_txt(freeze: dict) -> str:
    """Render the human record, derived entirely and deterministically from the JSON."""
    f = freeze
    out = [f"freeze_stamp={f['freeze_stamp']}  schema_version={f['schema_version']}  platform={f['platform']}",
           f"image={f['image'].get('name')}  caa={f['image'].get('caa')}  kata={f['image'].get('kata')}"
           f"  overlay_rev={f['image'].get('overlay_rev')}",
           f"system_raw_sha256={f['image'].get('system_raw_sha256')}",
           f"overlay_sha256={f['image'].get('overlay_sha256')}",
           f"substrate_profile_hash={f['substrate_profile_hash']}"]
    out += [f"{k}={f['measurement'][k]}" for k in MEASUREMENT_FIELDS]   # fixed order, not dict order
    out += [f"init_data_algorithm={f['init_data']['algorithm']}", f"init_data_digest={f['init_data']['digest']}"]
    if f["init_data"].get("profile"):              # absent in legacy records: their rendering stays as it was
        out += [f"init_data_profile={f['init_data']['profile']}"]
    if f["init_data"].get("runner_image"):
        out += [f"init_data_runner_image={f['init_data']['runner_image']}"]
    if f.get("probe_init_data"):
        out += [f"probe_init_data_digest={f['probe_init_data']['digest']}"]
    out += [f"dcap={f['dcap'].get('qv_result')} fmspc={f['dcap'].get('fmspc')} ({f['dcap'].get('library')})"]
    p = f["probe"]
    a = p.get("attach") or {}
    out += [f"probe: P1={p.get('p1')} P2={p.get('p2')} P3={p.get('p3')} network={p.get('network_stamp')}",
            f"a5c={p.get('a5c')}" + (f"  b1={p['b1']}" if p.get("b1") else ""),
            f"attach={a.get('verdict')} {a.get('stamp')} rounds={a.get('rounds')} rtt_ms={a.get('rtt_ms')}",
            "artefacts (sha256):"]
    out += [f"  {h}  {name}" for name, h in sorted(f["artefacts"].items())]
    return "\n".join(out) + "\n"


def _init_data_problems(freeze_dir: pathlib.Path, stamp: str, freeze: dict) -> list[str]:
    """Re-derive what the record claims about its init-data digests.

    A record with `profile: run` must carry the rendered run document, the digest must be that
    document's SHA-256, and the document must name the runner image. The probe digest must be the
    one in `reference-values-<STAMP>.json`. A record without a profile is a legacy one and says
    so. Nothing is derived for it.
    """
    init = freeze.get("init_data", {})
    profile = init.get("profile")
    problems = []
    if profile in (None, "probe"):
        # A legacy or probe record names the probe digest: it is the one in the reference values.
        ref_path = freeze_dir / f"reference-values-{stamp}.json"
        if ref_path.is_file():
            ref_init = json.loads(ref_path.read_text())["init_data"]
            if ref_init.get(f"{init.get('algorithm')}(toml)") != init.get("digest"):
                problems.append("init_data.digest is not the digest in the reference values")
        return problems
    if profile == "run":
        doc = freeze_dir / str(init.get("document", ""))
        if not doc.is_file():
            return [f"run init-data document missing: {init.get('document')}"]
        text = doc.read_text()
        if init_data_hash(text) != init.get("digest"):
            problems.append("init_data.digest is not the SHA-256 of the run document")
        if init.get("runner_image") not in text:
            problems.append("the run document does not name the runner image the record claims")
        probe = freeze.get("probe_init_data") or {}
        ref_path = freeze_dir / probe.get("source", f"reference-values-{stamp}.json")
        if not ref_path.is_file():
            problems.append(f"probe source missing: {ref_path.name}")
        else:
            ref_digest = json.loads(ref_path.read_text())["init_data"].get(f"{probe.get('algorithm')}(toml)")
            if ref_digest != probe.get("digest"):
                problems.append("probe_init_data.digest is not the one in the reference values")
        if init.get("digest") == probe.get("digest"):
            problems.append("run and probe init-data digests are identical: one of them is not what it says")
    else:
        problems.append(f"unknown init_data.profile {profile!r}")
    return problems


def _derivation_problems(freeze_dir: pathlib.Path, stamp: str, freeze: dict) -> list[str]:
    """Re-derive what the record pins and compare.

    The record is only as good as the match between what it says and what the artefacts it names
    say. The measurement comes from the reference values, the substrate profile hash from the
    recorded output of the substrate check, and the binding version from the code that
    verifies the binding (a record pinned to another version would not be accepted by this
    verifier). A record that predates `binding_version` makes no claim about it.
    """
    problems = []
    ref_path = freeze_dir / f"reference-values-{stamp}.json"
    if ref_path.is_file():
        fields = json.loads(ref_path.read_text())["quote"]["fields"]
        recorded = freeze.get("measurement", {})
        problems += [f"measurement.{k} is not the value in {ref_path.name}"
                     for k in MEASUREMENT_FIELDS if recorded.get(k) != fields.get(k)]
    else:
        problems.append(f"reference values missing: {ref_path.name}")
    substrate_path = freeze_dir / f"substrate-40-{stamp}.txt"
    if substrate_path.is_file():
        derived = _grep(substrate_path.read_text(), r"substrate profile hash:\s+PASS\s+([0-9a-f]{64})")
        if derived != freeze.get("substrate_profile_hash"):
            problems.append(f"substrate_profile_hash is not the PASS hash in {substrate_path.name}")
    else:
        problems.append(f"substrate output missing: {substrate_path.name}")
    if "binding_version" in freeze and freeze["binding_version"] != PROTOCOL_VERSION.decode():
        problems.append(f"binding_version {freeze['binding_version']!r} is not the version this code "
                        f"verifies ({PROTOCOL_VERSION.decode()!r})")
    return problems


def _unlisted_files(freeze_dir: pathlib.Path, stamp: str, freeze: dict) -> list[str]:
    """Return the files of this freeze (their name carries the stamp) that the record does not list.

    One directory can hold several freezes, so a file of another stamp is not an addition. A file
    named for this stamp that is neither an artefact nor one of the derived records was added
    after the record was built.
    """
    known = set(freeze.get("artefacts", {})) | {d.format(stamp=stamp) for d in _DERIVED}
    return sorted(p.name for p in freeze_dir.iterdir() if p.is_file() and stamp in p.name and p.name not in known)


def verify_freeze(freeze_dir: pathlib.Path, stamp: str) -> list[str]:
    """Return the problems between the record and the artefacts it was supplied with.

    An empty list means the record is consistent with those artefacts. It does not make the
    record authentic: nothing in the directory signs it, so the digest of `freeze-<STAMP>.json`
    has to be pinned somewhere the directory cannot reach (`main` prints it).
    """
    problems = []
    jpath = freeze_dir / f"freeze-{stamp}.json"
    tpath = freeze_dir / f"FREEZE-{stamp}.txt"
    if not jpath.exists():
        return [f"missing {jpath.name}"]
    freeze = json.loads(jpath.read_text())
    if freeze.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"schema_version {freeze.get('schema_version')} != {SCHEMA_VERSION}")
    if not tpath.exists():
        problems.append(f"missing {tpath.name}")
    elif tpath.read_text() != render_freeze_txt(freeze):
        problems.append(f"{tpath.name} is not the rendering of {jpath.name}")
    problems += _init_data_problems(freeze_dir, stamp, freeze)
    problems += _derivation_problems(freeze_dir, stamp, freeze)
    problems += [f"file not listed in the record: {name}" for name in _unlisted_files(freeze_dir, stamp, freeze)]
    for name, want in freeze.get("artefacts", {}).items():
        p = freeze_dir / name
        if not p.exists():
            problems.append(f"artefact missing: {name}")
        elif _sha256(p) != want:
            problems.append(f"artefact changed: {name}")
    return problems


def main(argv: list[str] | None = None) -> int:
    """Command line entry point: `build` writes the record, `verify` checks it. Returns the exit status."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("dir")
    b.add_argument("--stamp", required=True)
    b.add_argument("--network")
    b.add_argument("--attach")
    b.add_argument("--image")
    b.add_argument("--runner-image", default=None,
                   help="digest-pinned runner image: makes init_data the run digest")
    b.add_argument("--a5c", default=None,
                   help="optional, must agree with the image provenance, which is the source")
    v = sub.add_parser("verify")
    v.add_argument("dir")
    v.add_argument("--stamp", required=True)
    args = ap.parse_args(argv)
    d = pathlib.Path(args.dir)
    if args.cmd == "build":
        freeze = build_freeze(d, args.stamp, args.network, args.attach, args.image, args.a5c,
                              runner_image=args.runner_image)
        (d / f"freeze-{args.stamp}.json").write_text(json.dumps(freeze, indent=2, sort_keys=True) + "\n")
        (d / f"FREEZE-{args.stamp}.txt").write_text(render_freeze_txt(freeze))
        print(render_freeze_txt(freeze), end="")
        print(f"written: freeze-{args.stamp}.json, FREEZE-{args.stamp}.txt")
        return 0
    problems = verify_freeze(d, args.stamp)
    for p in problems:
        print(f"FREEZE PROBLEM: {p}")
    if problems:
        print("freeze record is NOT consistent with the supplied artefacts")
        return 1
    digest = _sha256(d / f"freeze-{args.stamp}.json")
    print("freeze record is consistent with the supplied artefacts")
    print(f"freeze-{args.stamp}.json sha256 {digest}")
    print("(a record cannot vouch for itself: pin this digest outside the directory)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
