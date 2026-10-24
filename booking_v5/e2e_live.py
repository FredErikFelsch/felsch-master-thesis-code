"""The live V5 end to end, driven from the operator machine under the narrow controller identity.

    python3 -m booking_v5.e2e_live run      --context v5-controller [--steps 1]
    python3 -m booking_v5.e2e_live negative --context v5-controller

scripts/gke-v5/31_run_fragment_v5.sh and scripts/gke-v5/32_negative_v5.sh run these two
commands through booking_approval.harness_e2e. The module creates one V3 run through the
Authority surface, spawns runner peer pods from the frozen profile (`PeerPodBackend`),
attaches (`pods/attach`), lets the Authority appraise and the gateway execute, reads the
effect ledger through the observation port (`pods/portforward`, not a pod-to-pod path),
destroys every TD and writes the run record (timings, outcome, ledger delta, refusal code,
cleanup mode) under results_v5/e2e/<STAMP>/. The controller mints no credential and touches
no bootstrap, because both are inside the authority pod.

Access from the operator machine: the Kubernetes API through the `v5-controller` context, the
Authority and the gateway observation port through port-forwards to the pods (the only
in-cluster paths the controller has), and the GCE instance probe by impersonating the
`v5-controller@` service account (no key file). The runners reach the services by their
in-cluster names. Those endpoints travel to the TD in the `v5-session` line.

Attack labels (A10, A11, A14, A16, A17, A18) refer to scripts/gke-v5/attack_catalogue.md.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

MOCKS = pathlib.Path(__file__).resolve().parents[1]
OUT = MOCKS / "results_v5" / "e2e"
# The deployed Authority runs the system clock, so the harness issues every workflow
# approval "now" and the validity windows are live.
from booking_v1.approval import live_window  # noqa: E402
NS = "agent-system"


# --- plumbing ------------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class PortForward:
    """`kubectl port-forward pod/<pod> local:remote` under the controller context."""

    def __init__(self, context: str, app: str, remote: int):
        self.context, self.app, self.remote = context, app, remote
        self.local = _free_port()
        self.proc = None

    def __enter__(self):
        pod = subprocess.check_output(["kubectl", "--context", self.context, "-n", NS, "get", "pods",
                                       "-l", f"app={self.app}", "-o", "jsonpath={.items[0].metadata.name}"]).decode()
        self.proc = subprocess.Popen(["kubectl", "--context", self.context, "-n", NS, "port-forward",
                                      f"pod/{pod}", f"{self.local}:{self.remote}"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", self.local), timeout=0.5):
                    return self
            except OSError:
                time.sleep(0.2)
        raise RuntimeError(f"port-forward to {self.app}:{self.remote} did not come up")

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()

    @property
    def endpoint(self):
        """The forwarded local port as a service endpoint."""
        from booking_v4.endpoint import ServiceEndpoint
        return ServiceEndpoint.tcp("127.0.0.1", self.local)


def _kube(context: str) -> None:
    from kubernetes import config
    config.load_kube_config(context=context)


def _gce_probe(project: str, zone: str, impersonate: str | None):
    from .controller_v5 import GceInstanceProbe
    probe = GceInstanceProbe(project, zone)
    if impersonate:
        os.environ["V5_IMPERSONATE_SA"] = impersonate
    return probe


def _pull_token() -> str:
    return subprocess.check_output(["gcloud", "auth", "print-access-token"]).decode().strip()


# --- the run --------------------------------------------------------------------------------

def _setup(args):
    from booking_v1.approval import approve
    from booking_v3.policy import default_p3
    from booking_v4 import wire
    from booking_v4.endpoint import ServiceEndpoint
    from booking_v4.services import _call
    from .attach_transport import AttachTransport, kubernetes_attach
    from .controller_v5 import AttestedFragmentController, PeerPodBackend, RemoteAuthority
    from .gateway import RemoteLedger
    from .pool import TdPool

    _kube(args.context)
    digests = dict(l.strip().split("=", 1) for l in open(MOCKS / "scripts" / "gke" / ".digests")
                   if "=" in l and not l.startswith("#"))
    anchors = wire.anchors_from_wire(json.load(open(args.controller_config))["anchors"])
    policy = default_p3()

    pf_auth = PortForward(args.context, "authority", 8443).__enter__()
    pf_obs = PortForward(args.context, "gateway", 8444).__enter__()
    forwards = (pf_auth, pf_obs)

    run_id = args.run_id or f"run-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    issued, expires = live_window()
    approval = approve(policy, approver_id="alice", approval_id=f"A-{run_id}", run_id=run_id,
                       issued_at=issued, expires_at=expires)
    reply = _call(pf_auth.endpoint, "authority.create_run",
                  {"policy": wire.policy_to_wire(policy), "approval": wire.approval_to_wire(approval), "run_id": run_id})
    if reply.get("envelope") is None:
        raise SystemExit(f"create_run refused: {reply}")
    s0 = wire.envelope_from_wire(reply["envelope"])

    backend = PeerPodBackend(namespace=NS, image=digests["RUNNER_IMAGE"],
                             instances=_gce_probe(args.project, args.zone, args.impersonate),
                             python=digests.get("RUNNER_PYTHON", "/usr/local/bin/python3"),
                             registry=args.registry, pull_token=_pull_token, cr_grace=args.cr_grace)
    transport = AttachTransport(open_stream=kubernetes_attach(NS), anchors=anchors,
                                endpoint=ServiceEndpoint.tcp(f"authority.{NS}.svc.cluster.local", 8443),
                                gateway_endpoint=ServiceEndpoint.tcp(f"gateway.{NS}.svc.cluster.local", 8443),
                                policy=policy)
    pool_size = int(getattr(args, "pool", 0))
    pool = TdPool(backend, size=pool_size)
    if pool_size:
        pool.fill()                                # pre-boot N unbound TDs, which warm up in the background
    controller = AttestedFragmentController(pool, RemoteAuthority(pf_auth.endpoint),
                                            transport, ledger=RemoteLedger(pf_obs.endpoint))
    return dict(policy=policy, run_id=run_id, s0=s0, backend=backend, transport=transport,
                controller=controller, authority=pf_auth.endpoint, forwards=forwards,
                observation_check=_observation_check(pf_auth.endpoint))


def _observation_check(authority_endpoint) -> str:
    """Ask the deployed Authority whether it verifies observations against the ledger.

    Asked here, while the forwards are still open, because the manifests are written in a
    finally block after they are closed. An unanswered question is recorded as `unknown`
    and not as `bound`, because the evaluation counts a property only where the system said it
    has it. A deployment whose manifest lost the flag then shows up as uncounted rather than as
    passing.

    The reason is printed rather than swallowed. A bare `unknown` does not say whether the
    call timed out, was refused or answered something unexpected, and finding out would cost
    another cluster bring-up. So the value stays fail-closed and the reason goes to the
    operator.
    """
    from booking_v4.services import _call          # local, like every import in `_setup`
    try:
        reply = _call(authority_endpoint, "authority.observation_check", {})
    except Exception as exc:                       # noqa: BLE001 (recorded as unknown, reason printed)
        print(f"observation_check: call failed, recording 'unknown' ({type(exc).__name__}: {exc})")
        return "unknown"
    answer = reply.get("observation_check")
    if answer is None:
        print(f"observation_check: no such key in the reply, recording 'unknown' (reply={reply})")
        return "unknown"
    return str(answer)


def _manifest(runs: list, observation_check: str = "unknown") -> dict:
    """Return the run manifest of a live run.

    It records the system clock, the verifier as the Authority recorded it on the accepted
    sessions (not as the deploy script claims it), and whether that Authority was wired to
    check observations against the gateway's effect ledger.
    """
    from booking_v4.manifest import run_manifest
    observed = sorted({s["appraisal"].get("verifier") for r in runs for s in r.get("steps", [])
                       if s.get("appraisal", {}).get("verifier")})
    return run_manifest(clock_mode="system",
                        verifier=observed[0] if len(observed) == 1 else (observed or None),
                        extra={"observation_check": observation_check})


def _record(rec, backend, extra: dict | None = None) -> dict:
    d = {"run_id": rec.run_id, "step": rec.step, "td": rec.td, "outcome": rec.outcome,
         "accepted": rec.accepted, "effects": rec.effects, "pending_effects": rec.pending_effects,
         "foreign_effects": rec.foreign_effects, "fragment_hash": rec.fragment_hash, "state_hash": rec.state_hash,
         "refusal": ({"rule": rec.refusal.rule, "detail": rec.refusal.detail, "stage": rec.refusal.stage}
                     if rec.refusal else None),
         "result_status": getattr(rec.result, "status", None),
         # Why a step ended as it did. Without this a FINALIZE_REFUSED is a bare status and
         # the reason lives only in a pod log that is gone with the cluster.
         "result_reason": getattr(rec.result, "reason", None),
         "has_successor": getattr(rec.result, "envelope", None) is not None,
         # The Authority's appraisal record (verifier, binding version, qv_result, fmspc,
         # advisories and more), which says which verifier stood behind this run.
         "appraisal": dict(rec.appraisal),
         "timings": {k: v for k, v in vars(rec.timings).items()}, "total_s": rec.timings.total,
         "handoff": "warm" if rec.timings.ready == 0.0 else "cold",   # warm = pre-booted, unbound TD
         "cleanup_mode": backend.cleanup_mode.get(rec.td), "indeterminate": rec.indeterminate,
         # Whether the three counters above were read or are just their defaults.
         "ledger_measured": rec.ledger_measured, "ledger_error": rec.ledger_error,
         "cleanup_error": rec.cleanup_error}
    d.update(extra or {})
    return d


def _save_refused_evidence(out: pathlib.Path, rec) -> str | None:
    """Save the raw quote of a refused run so it can be re-appraised offline.

    The re-appraisal uses scripts/gke-v5/20_verify_evidence_offline.py. Only refusals that
    reached the evidence stage carry a blob.

    Returns:
        The path of the saved file, or None when nothing was saved.
    """
    blob = getattr(rec, "evidence_blob", None)
    if rec.refusal is None or not blob or rec.td is None:
        return None
    path = out / f"evidence-{rec.td}.bin"
    path.write_bytes(blob)
    print(f"  refused evidence saved: {path}  (re-appraise: python3 scripts/gke-v5/20_verify_evidence_offline.py ...)")
    return str(path)


def _create_run(env, run_id: str):
    """Create one V3 run through the Authority surface and return its S0 envelope.

    Each repetition of a `--repeat` series needs its own run. The Authority binds a session
    per (run, step), so re-using a run_id would refuse the second repetition at step 0.
    """
    from booking_v1.approval import approve
    from booking_v4 import wire
    from booking_v4.services import _call
    issued, expires = env.get("approval_window", live_window)()   # offline suites pass their fixed clock's window
    approval = approve(env["policy"], approver_id="alice", approval_id=f"A-{run_id}",
                       run_id=run_id, issued_at=issued, expires_at=expires)
    reply = _call(env["authority"], "authority.create_run",
                  {"policy": wire.policy_to_wire(env["policy"]),
                   "approval": wire.approval_to_wire(approval), "run_id": run_id})
    if reply.get("envelope") is None:
        raise SystemExit(f"create_run refused: {reply}")
    return wire.envelope_from_wire(reply["envelope"])


def _run_once(env, steps: int, run_id: str, s0, out: pathlib.Path,
              tolerate_substrate: bool = False) -> tuple[list, bool, dict | None]:
    """Run `steps` fragments end to end, one fresh TD each (cold or from the warm pool).

    The steps are chained on the envelope. Refused-run evidence is saved under `out`.

    `tolerate_substrate` changes no decision. The refusal stands, the run still counts as not
    accepted, its timings do not enter the statistics and no reference value is widened. It
    only lets the caller learn that this particular refusal was the provider's RTMR0 field, so
    a latency series can report it instead of aborting. See booking_v5.substrate_variance for
    the five conditions that must hold.

    Returns:
        (records, accepted, substrate_variance). A harness failure ends the run with a record
        `{"step", "harness_error"}`, which has no timings.
    """
    from booking_v3.fragment import honest_fragment
    from booking_v3.orchestrator import happy_path_arguments
    from . import protocol
    records, envelope, ok, variance = [], s0, True, None
    for step in range(steps):
        fragment = honest_fragment(env["policy"], run_id, step, happy_path_arguments()[step])
        if envelope is None:
            # The previous step produced no successor, which happens whenever the Authority
            # refused to finalise it. Continuing would raise inside the wire encoder and the
            # traceback would escape `cmd_run`, taking every record collected so far with it
            # (run.json with `steps: []` and the refusal reason lost). The reason for the stop
            # is already in the record of the step above, so stopping here loses nothing.
            print(f"[{run_id}] step {step}: no envelope from the previous step, stopping")
            ok = False
            break
        try:
            rec = env["controller"].execute_fragment(run_id, step, protocol.fragment_bytes(fragment),
                                                     protocol.envelope_bytes(envelope))
        except Exception as exc:                   # noqa: BLE001 (the harness failed, which is a finding)
            import traceback
            traceback.print_exc()
            records.append({"step": step, "harness_error": f"{type(exc).__name__}: {exc}"})
            return records, False, variance
        d = _record(rec, env["backend"])
        saved = _save_refused_evidence(out, rec)
        if saved:
            d["evidence_bin"] = saved
        records.append(d)
        print(f"[{run_id}] step {step}: {rec.outcome}  effects={rec.effects} "
              f"pending={rec.pending_effects} foreign={rec.foreign_effects}  "
              f"total={rec.timings.total:.1f}s  td={rec.td}  cleanup={d['cleanup_mode']}")
        if not rec.accepted:
            ok = False
            if tolerate_substrate and variance is None:
                variance = _classify_substrate(rec, saved)
                if variance is not None:
                    d["substrate_variance"] = variance
                    print(f"  classified as provider substrate variance (RTMR0 only, effect-free): "
                          f"observed {variance['observed_rtmr0'][:16]}…, "
                          f"PCK leaf {variance['pck_leaf_serial']}")
            break
        envelope = rec.result.envelope if rec.result is not None else None
    return records, ok, variance


def _classify_substrate(rec, evidence_path: str | None) -> dict | None:
    """Ask booking_v5.substrate_variance whether this refusal is the provider's RTMR0 field.

    Everything the classifier needs is passed explicitly, including the measured effect
    counts, because a refused run that touched the world, or one whose ledger was never read,
    is a finding and is not classified. None means "treat this as a plain failure".
    """
    from .substrate_variance import classify
    refusal = getattr(rec, "refusal", None)
    verdict = classify(getattr(refusal, "rule", None), getattr(refusal, "detail", None),
                       evidence_path, effects=rec.effects, pending_effects=rec.pending_effects,
                       foreign_effects=rec.foreign_effects,
                       ledger_measured=bool(getattr(rec, "ledger_measured", False)))
    return verdict.to_json() if verdict else None


def _quantile(sorted_vals: list, q: float) -> float:
    """Return the q-quantile by linear interpolation between order statistics (numpy's default).

    `sorted_vals` must be sorted and non-empty.
    """
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = q * (len(sorted_vals) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return float(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo))


def _stat(values: list) -> dict | None:
    """Return mean and stdev plus the order statistics (median, q1, q3, iqr, p95, min, max).

    Cold TDX boot times are not normally distributed, so the report carries both and not only
    mean and stdev. Returns None when `values` holds no number.
    """
    import statistics
    vals = sorted(v for v in values if isinstance(v, (int, float)))
    if not vals:
        return None
    q1, q3 = _quantile(vals, 0.25), _quantile(vals, 0.75)
    return {"n": len(vals), "mean": statistics.fmean(vals),
            "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0,
            "min": vals[0], "max": vals[-1], "median": _quantile(vals, 0.5),
            "q1": q1, "q3": q3, "iqr": q3 - q1, "p95": _quantile(vals, 0.95)}


def _summarize(runs: list) -> dict:
    """Summarise a repeated series.

    The statistics cover every step with timings and without a refusal, which in a clean
    series are the accepted steps. Harness failures carry no timings and are counted
    separately in `harness_errors`.

    Args:
        runs: a list of {run_id, accepted, steps: [record, ...], substrate_variance}.

    Returns:
        Mean, stdev and order statistics per phase, the cleanup_mode counts and the
        accepted and refused tally.
    """
    PHASES = ("spawn", "ready", "boot_key", "evidence", "verification", "execution", "destroy")
    steps = [st for r in runs for st in r["steps"] if st.get("refusal") is None and "timings" in st]
    harness_errors = sum(1 for r in runs for st in r["steps"] if "harness_error" in st)
    stat = _stat
    phase_stats = {ph: stat([st["timings"].get(ph) for st in steps]) for ph in PHASES}
    cleanup = {}
    for st in steps:
        cleanup[st.get("cleanup_mode")] = cleanup.get(st.get("cleanup_mode"), 0) + 1
    warm = [st for st in steps if st.get("handoff") == "warm"]
    cold = [st for st in steps if st.get("handoff") != "warm"]
    # A run refused for provider RTMR0 variance is counted on its own. It is not accepted and
    # its steps are not in `steps`, so no timing of it reaches any statistic. The count exists
    # so the series reports the platform event instead of hiding it behind a smaller n.
    variance_runs = [r for r in runs if r.get("substrate_variance")]
    return {
        "repetitions": len(runs),
        "accepted_runs": sum(1 for r in runs if r["accepted"]),
        "refused_runs": sum(1 for r in runs if not r["accepted"]),
        "substrate_variance_runs": len(variance_runs),
        "substrate_variance": [r["substrate_variance"] for r in variance_runs],
        "accepted_steps": len(steps),
        "harness_errors": harness_errors,
        "phases": phase_stats,
        "total_s": stat([st["total_s"] for st in steps]),
        # a mixed series (warm pool exhausted, cold fallback) must not blur the two populations
        "handoff_counts": {"warm": len(warm), "cold": len(cold)},
        "total_s_warm": stat([st["total_s"] for st in warm]),
        "total_s_cold": stat([st["total_s"] for st in cold]),
        "phases_warm": {ph: stat([st["timings"].get(ph) for st in warm]) for ph in PHASES},
        "cleanup_mode_counts": cleanup,
    }


def cmd_run(args) -> int:
    """Run one fragment chain, or with --repeat N, N of them.

    A single run writes run.json. A repeated run writes rep-<i>.json per repetition and
    summary.json (mean and spread per phase, cleanup_mode counts) under one stamp directory.

    Returns:
        0 when every run was accepted (or refused for tolerated substrate variance), else 1.
    """
    env = _setup(args)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = OUT / stamp
    out.mkdir(parents=True, exist_ok=True)
    repeat = max(1, int(getattr(args, "repeat", 1)))
    # Opt-in, and only for a repeated series. A single run is a security run, where a refusal
    # is the result and not something to classify away.
    tolerate = bool(getattr(args, "tolerate_substrate_variance", False)) and repeat > 1
    runs, all_ok = [], True
    try:
        for i in range(repeat):
            run_id = env["run_id"] if i == 0 else f"{env['run_id']}-r{i}"
            s0 = env["s0"] if i == 0 else _create_run(env, run_id)
            records, ok, variance = _run_once(env, args.steps, run_id, s0, out,
                                              tolerate_substrate=tolerate)
            all_ok = all_ok and (ok or variance is not None)
            runs.append({"run_id": run_id, "accepted": ok, "steps": records,
                         "substrate_variance": variance})
            # Top-up only: `acquire` starts the replacement at the hand-out, so this is a
            # no-op whenever the pool is already at size. It is the safety net for a run that
            # ended without a hand-out at all.
            env["controller"].pool.fill()
    finally:
        drained = env["controller"].pool.drain()   # idle TDs are ours to destroy, like bound ones
        if drained:
            print(f"pool: {drained} idle TD(s) destroyed at the end (warm pool idle cost)")
        for pf in env["forwards"]:
            pf.__exit__(None, None, None)
        manifest = _manifest(runs, env.get("observation_check", "unknown"))
        if repeat == 1:
            (out / "run.json").write_text(json.dumps(
                {"stamp": stamp, "run_id": env["run_id"], "manifest": manifest,
                 "steps": runs[0]["steps"] if runs else []}, indent=2))
            print(f"recorded: {out / 'run.json'}")
        else:
            for i, r in enumerate(runs):
                (out / f"rep-{i}.json").write_text(json.dumps(
                    {"stamp": stamp, "run_id": r["run_id"], "manifest": manifest, "steps": r["steps"]}, indent=2))
            summary = {"stamp": stamp, "steps_per_run": args.steps, "pool_size": int(getattr(args, "pool", 0)),
                       "manifest": manifest,
                       "tolerate_substrate_variance": tolerate,
                       "runs": [{"run_id": r["run_id"], "accepted": r["accepted"],
                                 "substrate_variance": bool(r.get("substrate_variance"))} for r in runs],
                       "summary": _summarize(runs)}
            (out / "summary.json").write_text(json.dumps(summary, indent=2))
            print(f"recorded: {out} ({repeat} repetitions, summary.json)")
    tolerated = sum(1 for r in runs if r.get("substrate_variance"))
    verdict = "ACCEPTED" if all_ok else "NOT ACCEPTED"
    if tolerated:
        verdict += (f" ({tolerated} run(s) refused for provider RTMR0 variance, effect-free, "
                    f"excluded from the statistics and recorded in summary.json)")
    print("VERDICT e2e:", verdict)
    return 0 if all_ok else 1


def second_challenge_nonce(first: bytes) -> bytes:
    """Return a nonce for the second challenge of A11, as long as the first and not equal to it.

    It does not come from the Authority, because the Authority issues challenges only for the
    step the run stands at, and A11 needs a second challenge on a TD that has already bound
    once, which no honest controller would send.
    """
    while True:
        nonce = os.urandom(len(first))
        if nonce != first:
            return nonce


def cmd_negative(args) -> int:
    """Run the live negative cases A14, A10, A16, A11 and A18.

    Each case must refuse and leave the ledger delta at zero. A11 is the TD-side property: a runner
    binds once, and a second challenge on the live stream is refused inside the TD. A18 is the
    substrate half of the profile: a controller asserting a wrong substrate hash is refused at
    the relying party before evidence, ledger 0. The Authority-side td-already-bound and A17
    (scope and idempotency) are enforced live by the existing V3 and V4 mechanisms and shown
    as offline fixtures (tests_v5_offline, tests_v5_fixtures). The V5 relying_party.redeem is
    offline only.

    Returns:
        0 when every case passed, else 1.
    """
    from booking_v3.fragment import honest_fragment
    from booking_v4 import wire
    from booking_v4.services import _call
    from . import protocol
    from .binding import RunnerIdentity
    from .controller_v5 import RemoteAuthority
    from .profile_v5 import substrate_profile_hash
    from .runner_bind import Challenge
    env = _setup(args)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = OUT / stamp
    out.mkdir(parents=True, exist_ok=True)
    policy, run_id, s0 = env["policy"], env["run_id"], env["s0"]
    fragment = honest_fragment(policy, run_id, 0, {"to": "FRA"})
    f_octets, e_octets = protocol.fragment_bytes(fragment), protocol.envelope_bytes(s0)
    results = {}
    try:
        # A14: no evidence, and the legacy provisioning call does not exist on the surface.
        auth = RemoteAuthority(env["authority"])
        nonce = auth.issue_nonce(run_id, 0, fragment.fragment_hash, s0.state_hash, b"\1" * 32)
        r = auth.establish_session(None, b"\1" * 32, b"\2" * 32, run_id, 0, fragment.fragment_hash,
                                   s0.state_hash, nonce, substrate_profile_hash())
        try:
            _call(env["authority"], "authority.establish_runner_session",
                  {"bootstrap": {"kind": "provisioner-credential", "secret": "x"}, "run_id": run_id,
                   "fragment_hash": fragment.fragment_hash, "state_hash": s0.state_hash, "nonce": "n"})
            legacy = "REACHABLE"
        except wire.WireError as exc:
            legacy = "METHOD_NOT_FOUND" if "no such method" in str(exc) else str(exc)
        results["A14"] = {"refusal": getattr(r, "rule", None), "legacy_establish": legacy,
                          "pass": getattr(r, "rule", None) == "evidence-missing" and legacy == "METHOD_NOT_FOUND"}
        print("A14:", results["A14"])

        # A10: the transport lies about the boot key. The binding the hardware signed is then
        # not the one the Authority recomputes: binding-mismatch, no session, no effect.
        transport = env["transport"]
        real_boot_keys = transport.boot_keys
        def lying_boot_keys(td):
            real_boot_keys(td)                           # consume the TD's hello line ...
            other = RunnerIdentity.create()              # ... and report keys the TD does not hold
            from .binding import RunnerKeys
            return RunnerKeys(other.pk_boot, other.pk_sig)
        transport.boot_keys = lying_boot_keys
        rec = env["controller"].execute_fragment(run_id, 0, f_octets, e_octets)
        transport.boot_keys = real_boot_keys
        results["A10"] = _record(rec, env["backend"], {"pass": rec.ledger_measured
                                                        and rec.refusal is not None
                                                        and rec.refusal.rule == "binding-mismatch"
                                                        and rec.effects == 0 and rec.foreign_effects == 0})
        _save_refused_evidence(out, rec)
        print("A10:", rec.outcome, "ledger", rec.effects, rec.pending_effects, rec.foreign_effects)

        # A16: attest fragment A, deliver fragment B. The TD refuses before the monitor
        # (BytesMismatch) and the ledger delta stays 0. The same refusal has two observable
        # shapes. Over pods/attach the runner reports one RUNNER_ERROR line and exits. Over the
        # in-memory pipe of the offline tests the stream simply ends.
        # The ledger is read here, from the controller's own handle, before and after, as A11
        # does below. The legitimate refusal of A16 surfaces as a dead stream, so the
        # `except` branch must not pass without that read. The one claim the test exists to
        # make ("and no effect happened") needs a measurement behind it.
        other = honest_fragment(policy, run_id, 0, {"to": "LIS"})
        real_deliver = transport.deliver
        transport.deliver = lambda td, sealed, fb, eb: real_deliver(td, sealed, protocol.fragment_bytes(other), eb)
        a16_ledger = env["controller"].ledger
        a16_cursor = a16_ledger.high_watermark()
        try:
            rec = env["controller"].execute_fragment(run_id, 0, f_octets, e_octets)
            refused_in_td = (getattr(rec.result, "status", None) == "RUNNER_ERROR" and rec.refusal is None
                             and rec.ledger_measured
                             and rec.effects == 0 and rec.pending_effects == 0 and rec.foreign_effects == 0)
            a16 = _record(rec, env["backend"], {"pass": refused_in_td,
                                                "note": "the TD refused the swapped fragment (RUNNER_ERROR, ledger 0)"
                                                if refused_in_td else "the runner answered a swapped fragment"})
        except Exception as exc:                                       # noqa: BLE001 (the stream ends: expected)
            a16 = {"pass": False, "error": f"{type(exc).__name__}: {str(exc)[:120]}",
                   "note": "no run record: the claim rests on the independent ledger read"}
        finally:
            transport.deliver = real_deliver
        try:
            rows_after = len(a16_ledger.entries_after(a16_cursor))
        except Exception as exc:                                       # noqa: BLE001 (unmeasurable)
            rows_after, a16["ledger_read_error"] = None, f"{type(exc).__name__}: {exc}"
        a16["ledger_rows_after"] = rows_after
        # Whatever happened to the run record, the refusal is only proven while the ledger
        # stayed still. An exception alone proves nothing and must not pass on its own, and an
        # unreadable ledger proves nothing either.
        a16["pass"] = bool(a16.get("pass") or a16.get("error")) and rows_after == 0
        results["A16"] = a16
        print("A16:", a16)

        # A11 (TD side): a TD binds once. On one live stream do boot_key and attest, then send
        # a second v5-challenge where the runner now expects the session line. The runner reads
        # the session line next, so the second challenge fails its line check and the runner
        # ends with RUNNER_ERROR. No session is established and no effect happens. On hardware
        # this protocol order is the defence that fires. Bind-once, the phase guard and the
        # Authority-side td-already-bound (same pk_boot, second (run, step)) are defence in
        # depth, shown offline.
        # The second challenge carries a nonce the Authority never issued. The Authority
        # refuses to issue a challenge for a step the run does not stand at
        # (`run-not-at-step`), so asking it for one at step 1 of a run that is at step 0 would
        # end the test before the TD is reached. The claim is about the TD, which refuses the
        # line before it looks at the nonce, so any nonce serves.
        auth11 = RemoteAuthority(env["authority"])
        ledger = env["controller"].ledger
        cursor = ledger.high_watermark()
        td = None
        try:
            td, _ = env["controller"].pool.acquire((run_id, 0, fragment.fragment_hash, s0.state_hash))
            keys = transport.boot_keys(td)
            n1 = auth11.issue_nonce(run_id, 0, fragment.fragment_hash, s0.state_hash, keys.pk_boot)
            transport.attest(td, Challenge(run_id, 0, fragment.fragment_hash, s0.state_hash, n1))
            n2 = second_challenge_nonce(n1)
            refused, detail = False, ""
            try:
                transport.attest(td, Challenge(run_id, 1, fragment.fragment_hash, s0.state_hash, n2))
            except Exception as exc:                                   # noqa: BLE001 (refusal is the pass)
                refused, detail = True, f"{type(exc).__name__}: {str(exc)[:160]}"
            rows = ledger.entries_after(cursor)
            a11 = {"pass": refused and len(rows) == 0, "refused_in_td": refused,
                   "ledger_rows": len(rows), "detail": detail,
                   "note": "the runner bound once, and a second challenge was refused in the TD (ledger 0)"}
        finally:
            if td is not None:
                env["controller"].pool.retire(td)
                transport.close(td)
        results["A11"] = a11
        print("A11:", a11)

        # A18: the controller asserts the substrate half of the Fixed Execution Profile
        # (RuntimeClass, pod-VM type, subnet, firewall) to the Authority as a hash. A
        # controller on the wrong substrate (here a foreign pod-VM subnet) is refused at the
        # relying party before any evidence is weighed: substrate-profile-mismatch, ledger
        # delta 0. A controller that asserts another substrate is refused. A controller that
        # lies about its substrate is not detected, see relying_party (d).
        real_profile = env["controller"].substrate_profile
        env["controller"].substrate_profile = dict(real_profile, podvm_subnet_cidr="10.9.9.0/24")
        try:
            rec = env["controller"].execute_fragment(run_id, 0, f_octets, e_octets)
        finally:
            env["controller"].substrate_profile = real_profile
        results["A18"] = _record(rec, env["backend"], {"pass": rec.ledger_measured
                                                        and rec.refusal is not None
                                                        and rec.refusal.rule == "substrate-profile-mismatch"
                                                        and rec.effects == 0 and rec.foreign_effects == 0})
        _save_refused_evidence(out, rec)
        print("A18:", rec.outcome, "ledger", rec.effects, rec.pending_effects, rec.foreign_effects)
    finally:
        for pf in env["forwards"]:
            pf.__exit__(None, None, None)
        (out / "negative.json").write_text(json.dumps({"stamp": stamp, "run_id": run_id,
                                                       "manifest": _manifest([], env.get("observation_check", "unknown")),
                                                       "results": results},
                                                      indent=2, default=str))
        print(f"recorded: {out / 'negative.json'}")
    all_pass = all(v.get("pass") for v in results.values())
    print("VERDICT negative:", "ALL RED AS EXPECTED" if all_pass else "CHECK negative.json")
    return 0 if all_pass else 1


def main(argv=None) -> int:
    """Command line entry point: `run` or `negative`. Returns the process exit code."""
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "negative"):
        p = sub.add_parser(name)
        p.add_argument("--context", default="v5-controller")
        p.add_argument("--project", required=True)
        p.add_argument("--zone", required=True)
        p.add_argument("--registry", required=True)
        p.add_argument("--impersonate", default=None, help="v5-controller@<project>.iam.gserviceaccount.com")
        p.add_argument("--controller-config", default=str(OUT / "controller-config.json"))
        # cr-grace default 0: on GCP peerpod-ctrl does not clear the CR itself (see PeerPodBackend).
        p.add_argument("--run-id", default=None)
        p.add_argument("--cr-grace", type=float, default=0.0)
        if name == "run":
            p.add_argument("--steps", type=int, default=1)
            p.add_argument("--repeat", type=int, default=1, help="N cold-path repetitions, one summary.json")
            p.add_argument("--pool", type=int, default=0, help="warm pool size (0 = cold path)")
            p.add_argument("--tolerate-substrate-variance", action="store_true",
                           help="latency series only, and only with --repeat > 1: a refusal that "
                                "is provably the provider's RTMR0 field (every other pinned "
                                "measurement byte-equal, zero measured effects) does not abort "
                                "the series. The refusal itself stands and is recorded.")
    args = ap.parse_args(argv)
    return cmd_run(args) if args.cmd == "run" else cmd_negative(args)


if __name__ == "__main__":
    sys.exit(main())
