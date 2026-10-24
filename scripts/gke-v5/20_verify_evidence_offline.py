#!/usr/bin/env python3
"""20_verify_evidence_offline.py: analyses the TDX evidence a probe run recorded, without a cluster.

Needs:  A probe run recorded by 18_probe_peer_pod.sh under results_v5/probe/ (evidence log,
        runtime-data and runner-peer manifest, and binding-<STAMP>.json for production-sequence
        runs), python3 with pyyaml, and the booking_v5 package. V5_PROBE_DIR points the script
        at another directory, which the dry-run tests use.
Usage:  20_verify_evidence_offline.py <STAMP>            e.g. 20260903T145942Z
Result: results_v5/probe/reference-values-<STAMP>.json and VERDICT lines on stdout. Exit code 0
        only if REPORTDATA carries our value and, for a production-sequence run, both V5
        verdicts are OK. Exit code 2 on a missing evidence line or wrong arguments.

It answers, from the recorded bytes alone and in this order:
  1. Structure   is the AA's `quote` a well-formed TDX quote v4 (layout: booking_v5.tdx_quote):
                 header, TD10 report body, consistent signature length? The AA returns a fixed
                 8000-byte buffer. The real quote ends after the signature, the rest is zero padding.
  2. Binding     does REPORTDATA carry our runtime_data? (The AA copies the runtime_data query
                 string as bytes, without hashing. Our 64-char hex string is 64 ASCII bytes, so
                 runtime_data has to stay within 64 bytes.)
  3. Init-data   is the init-data (genpolicy policy, aa.toml, cdh.toml) measured anywhere the
                 verifier can see it: MRCONFIGID, RTMR3, or an event in the CCEL event log?
                 The probe also records evidence before its own events, so this question is
                 answered on the pre-event quote and stays separable from step 3c.
  3c. V5 bind    (only for runs with a binding-<STAMP>.json, that is the production sequence)
                 does REPORTDATA carry the canonical binding recomputed from the recorded
                 fields and PK_BOOT, and is RTMR3 the replay of [init-data, boot-key, bind]?
                 That is the Authority's decision, reproduced from recorded bytes alone.
  4. Reference   write MRTD, RTMR0..2, MRCONFIGID, MROWNER, TCB SVN, XFAM, TD attributes as the
                 reference-value candidates of this run (input for the Authority pin).
  5. DCAP        not done here: the signature chain (PCK -> Intel root) and the TCB status need
                 the DCAP verifier and its collateral (21_dcap_verify.sh). This script only
                 reports that the check is outstanding.
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
import pathlib
import os
import re
import sys

import yaml

MOCKS = pathlib.Path(__file__).resolve().parents[2]
# V5_PROBE_DIR lets the dry-run tests point this script at a synthetic run without writing
# anything into the recorded probe results under results_v5/probe.
PROBE = pathlib.Path(os.environ.get("V5_PROBE_DIR", MOCKS / "results_v5" / "probe"))
sys.path.insert(0, str(MOCKS))
from booking_v5.binding import canonical_binding  # noqa: E402
from booking_v5.rtmr_replay import BINDING_V50, BINDING_V51  # noqa: E402
from booking_v5.rtmr_replay import (RTMR_ZERO, aael_line, diagnose_rtmr3,  # noqa: E402
                                    expected_rtmr3, init_data_line, replay)

from booking_v5.tdx_quote import ccel_events, parse_quote  # noqa: E402


def init_data_bytes(manifest: pathlib.Path) -> tuple[bytes, bytes]:
    """Return (gzip bytes, decoded TOML bytes) of the cc_init_data annotation."""
    m = yaml.safe_load(manifest.read_text())
    gz = base64.b64decode(m["metadata"]["annotations"]["io.katacontainers.config.hypervisor.cc_init_data"])
    return gz, gzip.decompress(gz)


def main(stamp: str) -> int:
    """Analyse the probe run `stamp`, print the VERDICT lines and write its reference values.

    Args:
        stamp: the UTC stamp of the probe run, as in evidence-<stamp>.log.

    Returns:
        0 if REPORTDATA carries our value and every V5 verdict is OK, 1 otherwise, and 2 if the
        evidence log has no EVIDENCE_B64 line.
    """
    log = (PROBE / f"evidence-{stamp}.log").read_text()
    m = re.search(r"^EVIDENCE_B64 (\S+)", log, re.M)
    if not m:
        print("VERDICT evidence: NO_FULL_EVIDENCE (log has no EVIDENCE_B64 line, re-run 18)")
        return 2
    evidence = json.loads(base64.b64decode(m.group(1)))
    quote = parse_quote(base64.b64decode(evidence["quote"]))
    print(f"VERDICT structure:  STRUCTURE_OK  (TDX quote v4, {quote.quote_len} B real + {quote.buffer_len - quote.quote_len} B padding)")

    # The production sequence (booking_v5.probe_bind) records evidence before its own two AAEL
    # events. Where it exists, that quote answers the init-data question on its own, so "the
    # overlay measured the init-data" and "our events landed" do not have to share one verdict.
    m_pre = re.search(r"^EVIDENCE_PRE_B64 (\S+)", log, re.M)
    pre_quote = parse_quote(base64.b64decode(json.loads(base64.b64decode(m_pre.group(1)))["quote"])) if m_pre else None
    binding_file = PROBE / f"binding-{stamp}.json"
    binding = json.loads(binding_file.read_text()) if binding_file.exists() else None
    m_pk = re.search(r"^PK_BOOT (\S+)", log, re.M)
    pk_boot_hex = m_pk.group(1) if m_pk else None
    # A run recorded with an older pod-VM image has no PK_SIG line: the TD of that image had
    # one key and attested under the v5.0 binding. The version is read from the recording
    # rather than assumed, so the archived probe fixtures stay verifiable with this script.
    m_sig = re.search(r"^PK_SIG (\S+)", log, re.M)
    pk_sig_hex = m_sig.group(1) if m_sig else ""
    binding_version = BINDING_V51 if m_sig else BINDING_V50

    # 2. binding: REPORTDATA vs. the runtime_data the probe passed to the AA
    rd = (PROBE / f"runtime-data-{stamp}.txt").read_text().strip()
    reportdata = bytes.fromhex(quote.fields["reportdata"])
    forms = {"ascii(runtime_data)": rd.encode().ljust(64, b"\0"), "raw(runtime_data)": bytes.fromhex(rd).ljust(64, b"\0"),
             "sha384(ascii)": hashlib.sha384(rd.encode()).digest().ljust(64, b"\0"), "sha512(ascii)": hashlib.sha512(rd.encode()).digest()}
    hit = [k for k, v in forms.items() if v == reportdata]
    print(f"VERDICT binding:    {'BINDING_OK  REPORTDATA == ' + hit[0] if hit else 'BINDING_MISMATCH (REPORTDATA matches no known form of runtime_data)'}")

    # 3. init-data: where is the policy hash?
    gz, toml = init_data_bytes(PROBE / f"runner-peer-{stamp}.yaml")
    algo = re.search(r'^algorithm\s*=\s*"(\w+)"', toml.decode(), re.M).group(1)
    digests = {f"{a}({src})": getattr(hashlib, a)(b).hexdigest() for a in ("sha256", "sha384") for src, b in (("toml", toml), ("gzip", gz))}
    initdata_quote = pre_quote or quote      # before our own events, where the probe recorded it
    where = []
    for reg in ("mrconfigid", "rtmr3"):
        for name, dg in digests.items():
            if initdata_quote.fields[reg].startswith(dg):   # sha256 zero-padded to 48 B, sha384 exact
                where.append(f"{reg} = {name}")
    events = ccel_events(base64.b64decode(evidence["cc_eventlog"]))
    per_index = {i: sum(1 for e in events if e[0] == i) for i in range(5)}
    ev_hit = [f"CCEL idx{e[0]} type={e[1]:#x}" for e in events for d in e[2] if d.hex() in digests.values()]
    where += ev_hit

    def _zero(reg: str) -> bool:
        return set(initdata_quote.fields[reg]) == {"0"}

    # Overlay images measure the init-data digest into RTMR3 as the first AAEL event
    # (k8s/v5/podvm-overlay). Process-user-data's digest is hex(<algorithm>(raw TOML)).
    initdata_digest_hex = getattr(hashlib, algo)(toml).hexdigest()
    initdata_rtmr3 = replay([init_data_line(initdata_digest_hex)], RTMR_ZERO).hex()
    if initdata_quote.fields["rtmr3"] == initdata_rtmr3:
        where.append(f"rtmr3{' (pre-event quote)' if pre_quote else ''} = replay([v5 init-data <digest>])")
    if where:
        print(f"VERDICT init-data:  INITDATA_MEASURED  ({', '.join(where)})")
    else:
        print(f"VERDICT init-data:  INITDATA_NOT_MEASURED  (init-data algorithm={algo}, {len(toml)} B TOML; "
              f"MRCONFIGID {'zero' if _zero('mrconfigid') else 'non-zero but no match'}, RTMR3 {'zero' if _zero('rtmr3') else 'non-zero but no match'}, "
              f"CCEL events per MR index {per_index}, no event digest equals the init-data hash)")
        print("        -> the genpolicy policy is enforced in the guest (P2 needed it) but not attested: a verifier cannot tell this")
        print("           init-data from a permissive one. The guest must extend the init-data digest into RTMR3 before the agent")
        print("           starts (podvm image / CAA process-user-data), or the attestation claim covers only MRTD and RTMR0 to 2.")

    # 3b/3c. The runtime measurement. Two shapes of probe run:
    #   binding-<STAMP>.json present -> the production sequence: REPORTDATA must be the canonical
    #     binding and RTMR3 the replay of [init-data, boot-key, bind]. This is the Authority's
    #     decision, reproduced from recorded bytes.
    #   otherwise -> the earlier single-extend probe, kept so its fixtures stay verifiable.
    v5_verdicts = {}
    if binding is not None and pk_boot_hex:
        want_rd = canonical_binding(bytes.fromhex(binding["nonce"]), binding["run"], binding["step"],
                                    binding["fragment_hash"], binding["state_hash"],
                                    bytes.fromhex(pk_boot_hex),
                                    bytes.fromhex(pk_sig_hex) if pk_sig_hex else b"",
                                    binding_version.encode())
        # Compare against the bytes in the quote, not against the recorded runtime-data file:
        # the file is written by the probe script, the REPORTDATA is written by the hardware.
        rd_ok = want_rd.hex().encode() == reportdata
        v5_verdicts["binding"] = "V5_BINDING_OK" if rd_ok else "V5_BINDING_MISMATCH"
        detail = "" if rd_ok else f"; recomputed {want_rd.hex()[:32]}…, REPORTDATA {reportdata[:32].decode(errors='replace')}…"
        print(f"VERDICT v5-binding: {v5_verdicts['binding']}  "
              f"(runtime_data == H(V5-BIND | nonce | run | step | f | s | pk_boot"
              f"{' | pk_sig' if pk_sig_hex else ''}) [{binding_version}]{detail})")
        want_rtmr3 = expected_rtmr3(initdata_digest_hex, pk_boot_hex, pk_sig_hex, binding["run"],
                                    binding["step"], binding["fragment_hash"], binding["state_hash"],
                                    binding_version).hex()
        got_rtmr3 = quote.fields["rtmr3"]
        r3_ok = got_rtmr3 == want_rtmr3
        v5_verdicts["rtmr3"] = "V5_RTMR3_REPLAY_OK" if r3_ok else "V5_RTMR3_MISMATCH"
        detail = "" if r3_ok else f"; expected {want_rtmr3[:32]}…, quote has {got_rtmr3[:32]}…"
        print(f"VERDICT v5-rtmr3:   {v5_verdicts['rtmr3']}  (replay of [init-data, boot-key, bind]{detail})")
        if not r3_ok:
            print("        -> " + diagnose_rtmr3(got_rtmr3, initdata_digest_hex, pk_boot_hex, pk_sig_hex,
                                                 binding["run"], binding["step"],
                                                 binding["fragment_hash"], binding["state_hash"],
                                                 binding_version))
        n_events = len(re.findall(r"^AAEL_OK ", log, re.M))
        events_verdict = "AAEL_BOTH_RECORDED" if n_events == 2 else f"AAEL_INCOMPLETE ({n_events}/2)"
        print(f"VERDICT v5-events:  {events_verdict}  "
              f"(pre-event quote {'present' if pre_quote else 'MISSING'})")
    else:
        m2 = re.search(r"^EVIDENCE_AFTER_EXTEND_B64 (\S+)", log, re.M)
        if m2:
            ev2 = json.loads(base64.b64decode(m2.group(1)))
            q2 = parse_quote(base64.b64decode(ev2["quote"]))
            moved = q2.fields["rtmr3"] != quote.fields["rtmr3"]
            new_keys = sorted(set(ev2) - set(evidence))
            # Replay (verified against a live quote): the AA writes the AAEL line
            # "<domain> <operation> <content>" as a TCG EV_EVENT_TAG (0x6) TaggedEvent with id
            # "AAEL" = 0x4141454c, digest = SHA-384(TaggedEvent bytes), RTMR3' = SHA-384(RTMR3 || digest).
            expected = replay([aael_line("p3-extend", rd, domain="v5-probe")], bytes.fromhex(quote.fields["rtmr3"]))
            replay_verdict = "REPLAY_OK" if expected.hex() == q2.fields["rtmr3"] else "REPLAY_MISMATCH"
            print(f"VERDICT p3-extend:  {'RTMR3_EXTENDED ' + replay_verdict if moved else 'RTMR3_UNCHANGED'}  (RTMR3 after: {q2.fields['rtmr3'][:32]}…; "
                  f"new evidence keys: {new_keys or 'none'})")
        else:
            print("VERDICT p3-extend:  NOT_PROBED  (no EVIDENCE_AFTER_EXTEND_B64 line: run 18 again with the /aa/aael probe)")

    # 4. reference values
    quote_json = {"version": quote.version, "att_key_type": quote.att_key_type, "tee_type": quote.tee_type,
                  "quote_len": quote.quote_len, "buffer_len": quote.buffer_len, "fields": quote.fields}
    ref = {"stamp": stamp, "quote": quote_json, "init_data": {"algorithm": algo, **digests, "toml_bytes": len(toml)},
           "runtime_data": rd, "reportdata_form": hit[0] if hit else None,
           "v5": {**v5_verdicts, "binding_file": binding, "pk_boot": pk_boot_hex,
                  "pk_sig": pk_sig_hex or None, "binding_version": binding_version,
                  "pre_event_rtmr3": pre_quote.fields["rtmr3"] if pre_quote else None},
           "ccel": {"events": len(events), "per_mr_index": per_index}}
    out = PROBE / f"reference-values-{stamp}.json"
    out.write_text(json.dumps(ref, indent=2))
    f = quote.fields
    try:
        shown = out.relative_to(MOCKS)
    except ValueError:                      # V5_PROBE_DIR outside the repo (dry-run tests)
        shown = out
    print(f"VERDICT reference:  written {shown}")
    print(f"        MRTD       {f['mrtd']}")
    for i in range(3):
        print(f"        RTMR{i}      {f[f'rtmr{i}']}")
    print(f"        MRCONFIGID {f['mrconfigid'][:16]}…  MROWNER {f['mrowner'][:16]}…  TCB_SVN {f['tee_tcb_svn']}  XFAM {f['xfam']}  TDATTR {f['tdattributes']}")
    print("VERDICT dcap:       NOT_CHECKED_HERE  (signature chain and TCB status: 21_dcap_verify.sh)")
    # Exit code: the run is only usable as a V5 fixture when REPORTDATA carries our value and,
    # for a production-sequence run, both V5 verdicts are OK.
    ok = bool(hit) and all(v.endswith("_OK") for v in v5_verdicts.values())
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
