"""The three live attacks, as switches on an AttestedChain.

Each one is the manipulation `booking_v5.e2e_live.cmd_negative` performs, applied to a
single fragment execution and then removed. The labels follow the attack catalogue
(`scripts/gke-v5/attack_catalogue.md`). They model a controller or transport that was taken
over, that is the party that spawns TDs and carries bytes. The TD, the Authority and the
gateway are not attacked. Every attack must end with a ledger delta of 0.

    a16   tampered fragment: attest fragment A, deliver fragment B. Refused inside the TD,
          before the monitor runs, because the delivered octets do not hash to the attested
          fragment.
    a10   forged boot key: the transport reports a key the TD does not hold. Refused at the
          relying party with binding-mismatch (the hardware signed a different binding).
    a18   wrong substrate: the controller reports a pod-VM subnet that does not match the
          pinned profile for one attempt. Refused at the relying party with
          substrate-profile-mismatch before any evidence is weighed. This tests the
          comparison of the substrate profile the controller reports with the pinned one. It
          does not place a TD in another subnet, and a controller that reports the expected
          profile is not caught by this check.

Where an attack may run: a18 and a10 are refused before the relying party commits a
session, so the approved run stays usable. They run inside the approved run against its own
step 0 (`run_attack_in_run`), and the honest attempt follows under the same run, policy and
predecessor state. a16 is refused only inside the TD, after the relying party has accepted a
session for (run, step), and a second session for that step is refused
(`step-already-has-session`). It therefore keeps its own throwaway run.
"""
from __future__ import annotations

import contextlib
from typing import Iterator

from booking_v3.fragment import honest_fragment
from booking_v5 import protocol

#: Attacks refused before the relying party commits a session for (run, step).
IN_RUN = ("a18", "a10")

ATTACKS = {
    "a16": ("tampered fragment", "TD (hash check of the delivered octets, before the monitor)"),
    "a10": ("forged boot key", "relying party: binding-mismatch"),
    "a18": ("wrong substrate", "relying party: substrate-profile-mismatch"),
}


@contextlib.contextmanager
def armed(chain, attack: str, policy, run_id: str) -> Iterator[None]:
    """Apply one attack to the chain for the duration of the block."""
    if attack == "a16":
        other = honest_fragment(policy, run_id, 0, {"to": "LIS"})
        real = chain.transport.deliver
        chain.transport.deliver = lambda td, sealed, fb, eb: real(td, sealed, protocol.fragment_bytes(other), eb)
        try:
            yield
        finally:
            chain.transport.deliver = real
    elif attack == "a10":
        from booking_v5.binding import RunnerIdentity, RunnerKeys
        real = chain.transport.boot_keys

        def lying(td):
            real(td)                                  # consume the TD's hello
            other = RunnerIdentity.create()           # report keys the TD does not hold
            return RunnerKeys(other.pk_boot, other.pk_sig)
        chain.transport.boot_keys = lying
        try:
            yield
        finally:
            chain.transport.boot_keys = real
    elif attack == "a18":
        real = chain.controller.substrate_profile
        chain.controller.substrate_profile = dict(real, podvm_subnet_cidr="10.9.9.0/24")
        try:
            yield
        finally:
            chain.controller.substrate_profile = real
    else:
        raise ValueError(f"unknown attack {attack!r}")


def run_attack(chain, attack: str, policy, run_id: str) -> dict:
    """Run step 0 with the honest fragment in a throwaway run under attack.

    An attack passes (`pass`) when both conditions are observed: the attempt did not
    complete, and the gateway ledger did not move for it.

    An exception out of `chain.execute` is not attributed to the defence. A pod VM that
    does not confirm gone, a pool that times out while booting, an unreachable observation
    endpoint or a typo in the attack would otherwise read as a defence that fired. The
    legitimate refusal of a16 surfaces as a dead stream, so the two cannot be told apart by
    the exception alone. A refusal that the attested path itself decided carries a measured
    trace and is `attributed`. An exception is recorded as HARNESS_ERROR. It can still show
    that no effect happened, but it is not attributed. The ledger is read from the chain
    independently of the trace, so the delta exists even when the run record does not.

    Args:
        chain: The attested chain.
        attack: One of ATTACKS.
        policy: The approved policy.
        run_id: The id of the throwaway run.

    Returns:
        The attack event (see `_measure`).
    """
    envelope = chain.create_run(policy, run_id)
    fragment = honest_fragment(policy, run_id, 0, {"to": "FRA"})
    return _measure(chain, attack, policy, run_id, envelope, fragment)


def run_attack_in_run(chain, attack: str, policy, run_id: str, envelope, fragment) -> dict:
    """Run one attempt under attack against step `fragment.fragment_index` of the approved run.

    This is only for attacks in `IN_RUN`. They are refused before a session is committed, so
    the approved run is untouched and the honest attempt can follow. Nothing is created here,
    because the run, the policy and the envelope are the approved ones. The measured ledger
    delta belongs to this attempt alone, since the honest step has not started yet.

    Args:
        chain: The attested chain.
        attack: One of IN_RUN.
        policy: The approved policy.
        run_id: The approved run.
        envelope: The run's current envelope.
        fragment: The honest fragment of the step.

    Returns:
        The attack event, with the run status before and after the attempt.

    Raises:
        ValueError: The attack is not one of IN_RUN.
    """
    if attack not in IN_RUN:
        raise ValueError(f"{attack} is refused only after a session exists and runs as a throwaway run")
    status_before = chain.run_status(run_id)
    ev = _measure(chain, attack, policy, run_id, envelope, fragment)
    ev["in_run"] = True
    ev["run_status_before"], ev["run_status_after"] = status_before, chain.run_status(run_id)
    # A refusal that left the run in another status is not a contained attempt.
    ev["pass"] = bool(ev["pass"] and ev["run_status_after"] == status_before)
    return ev


def _measure(chain, attack: str, policy, run_id: str, envelope, fragment) -> dict:
    """Apply the attack to one fragment execution and measure refusal and ledger delta."""
    label, blocked_at = ATTACKS[attack]
    before = _ledger_rows(chain)
    trace, harness_error = None, None
    try:
        with armed(chain, attack, policy, run_id):
            result, trace = chain.execute(policy, envelope, fragment, None)
        status, reason = result.status, result.reason
    except Exception as exc:                                       # noqa: BLE001 (not attributed)
        status = "HARNESS_ERROR"
        reason = harness_error = f"{type(exc).__name__}: {str(exc)[:160]}"
    after = _ledger_rows(chain)

    # The delta the chain itself can see, independent of whether a run record survived.
    rows = None if (before is None or after is None) else len(after) - len(before)
    measured = bool(trace and trace.ledger_measured) or rows is not None
    ledger_delta = (trace.effects + trace.pending_effects + trace.foreign_effects) if trace else rows
    completed = status == "STEP_COMPLETED"
    no_effect = bool(measured and ledger_delta == 0 and rows in (0, None))
    # Two questions, answered separately, because collapsing them would let a broken harness
    # read as a working defence. `pass` is the claim of the experiment: the attack produced no
    # effect. `attributed` is whether this run also shows why, which needs a verdict from the
    # attested path itself. An exception plus a ledger that did not move is evidence for the
    # first and none for the second, so a pod VM that would not boot does not look like a
    # defence that fired.
    attributed = bool(trace is not None and status in ("ATTESTATION_REFUSED", "DENIED", "RUNNER_ERROR"))
    return {"attack": attack, "label": label, "blocked_at": blocked_at, "run_id": run_id,
            "status": status, "reason": reason, "trace": trace.as_event() if trace else None,
            "harness_error": harness_error,
            "ledger_measured": measured, "ledger_delta": ledger_delta, "ledger_rows_delta": rows,
            "attributed": attributed,
            "pass": bool(no_effect and not completed)}


def _ledger_rows(chain):
    """Return the chain's own view of the gateway ledger, or None if it could not be read.

    It is read directly rather than through the run record, so a broken run still has a
    measurement.
    """
    try:
        return list(chain.ledger())
    except Exception:                                              # noqa: BLE001 (unmeasurable)
        return None
