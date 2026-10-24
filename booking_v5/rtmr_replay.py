"""RTMR3 replay: the Authority recomputes the TD's runtime measurement itself.

No event log travels from the guest. The relying party knows which events a correct
V5 runner TD must record, in which order, and recomputes RTMR3 from them. A TD that
recorded anything else, in another order, or one event too many, yields another value
and is refused. That is the strengthened invariant of the binding (see `binding.py`).

Encoding (checked bit for bit against a live GCE TDX quote):
the Attestation Agent (guest-components f156103) records an AAEL line
``"<domain> <operation> <content>"`` as a TCG EV_EVENT_TAG TaggedEvent with id
0x4141454c ("AAEL"). The kernel extends RTMR3 with SHA-384 over those bytes:

    tagged        = LE32(0x4141454c) || LE32(len(line)) || line
    event_digest  = SHA-384(tagged)
    RTMR3'        = SHA-384(RTMR3 || event_digest)

The expected history of one V5 runner TD, in this order:

    1. ``v5 init-data <sha256 of the init-data TOML>``   pod-VM overlay, before the agent
       (`k8s/v5/podvm-overlay/usr/local/bin/initdata-measure`), closes the gap that the
       genpolicy policy is not in MRCONFIGID on GCE.
    2. ``v5 boot-key <pk_boot hex>.<pk_sig hex>``        runner, once, right after boot.
       Both public keys of the TD are measured: the X25519 key the session credential is
       sealed to, and the Ed25519 key that signs the TD's own verdicts.
       A TD that announced a signing key it did not measure yields another RTMR3.
    3. ``v5 bind <run>/<step>/<fragment_hash>/<state_hash>``  runner, once, at bind.

A second bind event, a second boot key, or a missing init-data event changes RTMR3.
"""
from __future__ import annotations

import hashlib
import struct

AAEL_TAG_ID = 0x4141454C
RTMR_ZERO = bytes(48)
DOMAIN = "v5"

OP_INIT_DATA = "init-data"
OP_BOOT_KEY = "boot-key"
OP_BIND = "bind"


def aael_line(operation: str, content: str, domain: str = DOMAIN) -> str:
    """Return the line the AA (or the pod-VM overlay) records for one event.

    Raises:
        ValueError: domain or operation empty or containing a space (they are the
            first two whitespace-separated tokens of the line and must stay unambiguous),
            or content containing a newline.
    """
    for part, name in ((domain, "domain"), (operation, "operation")):
        if not part or " " in part:
            raise ValueError(f"{name} must be a non-empty token without spaces: {part!r}")
    if "\n" in content:
        raise ValueError("content must not contain a newline")
    return f"{domain} {operation} {content}"


def aael_event_digest(line: str) -> bytes:
    """Return SHA-384 over the TCG TaggedEvent bytes of one AAEL line."""
    data = line.encode()
    return hashlib.sha384(struct.pack("<II", AAEL_TAG_ID, len(data)) + data).digest()


def extend(register: bytes, event_digest: bytes) -> bytes:
    """Perform one RTMR extend step as the TDX module does (SHA-384 register).

    Raises:
        ValueError: the register or the digest is not 48 bytes.
    """
    if len(register) != 48 or len(event_digest) != 48:
        raise ValueError("RTMR and event digest must be 48 bytes")
    return hashlib.sha384(register + event_digest).digest()


def replay(lines: list[str], start: bytes = RTMR_ZERO) -> bytes:
    """Return the expected RTMR3 after extending `lines` in order, starting from `start`."""
    value = start
    for line in lines:
        value = extend(value, aael_event_digest(line))
    return value


# --- the three V5 events ------------------------------------------------------

def init_data_line(init_data_digest_hex: str) -> str:
    """Return event 1, the init-data digest, as the pod-VM overlay writes it before the agent."""
    return aael_line(OP_INIT_DATA, init_data_digest_hex)


BINDING_V50 = "v5.0"
BINDING_V51 = "v5.1"


def boot_key_content(pk_boot_hex: str, pk_sig_hex: str, version: str = BINDING_V51) -> str:
    """Return the measured content of event 2: both public keys of this TD, in a fixed order.

    `version` exists only so that evidence recorded under the older binding, when the runner
    had one key, can still be replayed offline. See `booking_v5.binding.PROTOCOL_VERSION`.

    Raises:
        ValueError: a key contains the separator '.' or a space, which would let two
            different key pairs collide in one measurement.
    """
    if version == BINDING_V50:
        return pk_boot_hex
    for part in (pk_boot_hex, pk_sig_hex):
        if not part or "." in part or " " in part:
            raise ValueError(f"key hex must be non-empty and free of '.' and ' ': {part!r}")
    return f"{pk_boot_hex}.{pk_sig_hex}"


def boot_key_line(pk_boot_hex: str, pk_sig_hex: str, version: str = BINDING_V51) -> str:
    """Return event 2, the TD's public keys, recorded once by the runner right after boot."""
    return aael_line(OP_BOOT_KEY, boot_key_content(pk_boot_hex, pk_sig_hex, version))


def bind_line(run_id: str, step: int, fragment_hash: str, state_hash: str) -> str:
    """Return event 3, the single binding of this TD.

    Raises:
        ValueError: a field contains the separator '/' or a space, which would make the
            line ambiguous and two different bindings collide in one measurement.
    """
    parts = (run_id, str(step), fragment_hash, state_hash)
    for p in parts:
        if "/" in p or " " in p or not p:
            raise ValueError(f"binding field must be non-empty and free of '/' and ' ': {p!r}")
    return aael_line(OP_BIND, "/".join(parts))


def expected_history(init_data_digest_hex: str, pk_boot_hex: str, pk_sig_hex: str, run_id: str,
                     step: int, fragment_hash: str, state_hash: str,
                     version: str = BINDING_V51) -> list[str]:
    """Return the complete AAEL history a correct V5 runner TD has recorded."""
    return [init_data_line(init_data_digest_hex),
            boot_key_line(pk_boot_hex, pk_sig_hex, version),
            bind_line(run_id, step, fragment_hash, state_hash)]


def expected_rtmr3(init_data_digest_hex: str, pk_boot_hex: str, pk_sig_hex: str, run_id: str,
                   step: int, fragment_hash: str, state_hash: str,
                   version: str = BINDING_V51) -> bytes:
    """Return the RTMR3 the Authority expects in the quote of a correctly bound TD."""
    return replay(expected_history(init_data_digest_hex, pk_boot_hex, pk_sig_hex, run_id, step,
                                   fragment_hash, state_hash, version))


def diagnose_rtmr3(got_rtmr3_hex: str, init_data_digest_hex: str, pk_boot_hex: str,
                   pk_sig_hex: str, run_id: str,
                   step: int, fragment_hash: str, state_hash: str,
                   version: str = BINDING_V51) -> str:
    """Name the history a mismatching RTMR3 has, so a refusal says which link broke.

    A bare "mismatch" verdict cannot tell two different defects apart. Each alternative below
    is the failure of one component. An RTMR3 matching none of them points at foreign inputs
    (another init-data digest, another boot key, other binding fields, an extra event).
    """
    full = expected_history(init_data_digest_hex, pk_boot_hex, pk_sig_hex, run_id, step,
                            fragment_hash, state_hash, version)
    alternatives = {
        "[boot-key, bind] (init-data NOT measured: initdata-measure.service did not run)": full[1:],
        "[init-data] (runner recorded no event)": full[:1],
        "[init-data, boot-key] (bind event missing)": full[:2],
        "[] (RTMR3 never extended)": [],
    }
    for name, hist in alternatives.items():
        if replay(hist).hex() == got_rtmr3_hex:
            return f"quote RTMR3 == replay({name})"
    return ("quote RTMR3 matches none of the single-defect histories: foreign init-data digest, "
            "foreign boot key, wrong binding fields, or an extra event")
