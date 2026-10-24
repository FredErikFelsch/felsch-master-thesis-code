"""Deployment-cost measurement: process baseline against hardened container.

Measures cold start, execution, handoff and teardown separately, so the security benefit of
per-fragment container isolation can be set against its deployment cost. Both backends run the
same benign happy path (four ephemeral runners: search, select, book, pay) on the same host and
interpreter, so the isolation technology is the only variable. Both use the non-durable
service, so durability cost is not folded in. Each fragment reports the same four-phase breakdown
on the shared CLOCK_MONOTONIC. In measurement mode the provisioner waits for the runner's ready
marker before establishing the session and provisioning, so those costs fall in handoff-in and not
in cold start.

Only the execution phase is protocol work and should match across backends. Cold start, handoff and
teardown are the containerisation tax. Warm-up runs are discarded before sampling. The report
records median, mean, p95 and IQR, plus kernel, docker, runtime, CPU and interpreter metadata for
reproducibility.

Run from the repository root:  python3 -m booking_v4.measure_backends
Environment: MEASURE_REPS (default 30), MEASURE_WARMUP (default 5),
RUNNER_IMAGE (container image).
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import subprocess
import time

from booking_v3 import scenarios as v3_scenarios

from .process_backend import create_process_deployment
from .container_backend import create_container_deployment, _resolve_image, _DEFAULT_IMAGE

_PHASES = ["cold_start_ns", "handoff_in_ns", "execution_ns",
           "handoff_out_ns", "handoff_ns", "teardown_ns", "total_ns"]


def _run_backend(factory, reps: int, warmup: int) -> tuple[list[dict], list[int]]:
    """Run the benign happy path, discard ``warmup`` runs, then sample ``reps``."""
    created: list = []

    def wrap(clock, executor=None):
        dep = factory(clock, executor=executor)
        created.append(dep)
        return dep

    per_fragment: list[dict] = []
    happy_wall_ns: list[int] = []
    v3_scenarios.set_deployment_factory(wrap)
    try:
        for i in range(warmup + reps):
            created.clear()
            t = time.monotonic_ns()
            out = v3_scenarios.benign_happy_path()
            wall = time.monotonic_ns() - t
            dep = created[-1]
            if out.final_status != "COMPLETED":
                dep.close()
                raise RuntimeError(f"happy path did not complete: {out.final_status}")
            if i >= warmup:  # discard warm-up runs
                happy_wall_ns.append(wall)
                for h in dep.provisioner._handles:
                    if h.timings and not h.timings.get("clock_inversion"):
                        per_fragment.append(h.timings)
            dep.close()
    finally:
        v3_scenarios.set_deployment_factory(None)
    return per_fragment, happy_wall_ns


def _stats_ms(values_ns: list[int]) -> dict:
    """Return median, mean, min and max in milliseconds, plus p95 and IQR from two samples on."""
    vals = sorted(v / 1e6 for v in values_ns)
    out = {
        "median": round(statistics.median(vals), 3),
        "mean": round(statistics.fmean(vals), 3),
        "min": round(vals[0], 3),
        "max": round(vals[-1], 3),
    }
    if len(vals) >= 2:
        q = statistics.quantiles(vals, n=100, method="inclusive")
        out["p95"] = round(q[94], 3)
        quart = statistics.quantiles(vals, n=4, method="inclusive")
        out["iqr"] = round(quart[2] - quart[0], 3)
    return out


def _summary(samples: list[dict]) -> dict:
    """Return the sample count and the millisecond statistics of every phase."""
    out: dict = {"n": len(samples)}
    for key in _PHASES:
        vals = [s[key] for s in samples if key in s]
        if vals:
            out[key.replace("_ns", "_ms")] = _stats_ms(vals)
    return out


def _host_metadata(image: str) -> dict:
    """Return kernel, docker, runtime, CPU and interpreter facts for reproducibility."""
    def _sh(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
        except Exception:
            return None

    cpu_model = None
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass
    return {
        "image": image,
        "python": platform.python_version(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_model": cpu_model,
        "cpu_count": os.cpu_count(),
        "docker_version": _sh(["docker", "version", "--format", "{{.Server.Version}}"]),
        "docker_runtime": _sh(["docker", "info", "--format", "{{.DefaultRuntime}}"]),
        "docker_storage_driver": _sh(["docker", "info", "--format", "{{.Driver}}"]),
    }


def _fmt(label: str, s: dict) -> str:
    """Format the phase medians of one backend as one summary line."""
    def med(k):
        return f"{s[k]['median']:.2f}" if k in s else "  -  "
    return (f"{label:<12} cold={med('cold_start_ms'):>7}  hin={med('handoff_in_ms'):>6}  "
            f"exec={med('execution_ms'):>6}  hout={med('handoff_out_ms'):>6}  "
            f"tear={med('teardown_ms'):>7}  total={med('total_ms'):>7}  (n={s.get('n')})")


def main():
    """Measure both backends, write `measurements.json` and print a summary."""
    reps = int(os.environ.get("MEASURE_REPS", "30"))
    warmup = int(os.environ.get("MEASURE_WARMUP", "5"))
    image = _resolve_image(os.environ.get("RUNNER_IMAGE", _DEFAULT_IMAGE))

    # Measurement-only tracing, switched on for both backends alike.
    os.environ["PROCESS_RUNNER_TRACE"] = "1"
    os.environ["CONTAINER_RUNNER_TRACE"] = "1"
    proc_frags, proc_wall = _run_backend(create_process_deployment, reps, warmup)
    ctr_frags, ctr_wall = _run_backend(create_container_deployment, reps, warmup)

    proc_sum, ctr_sum = _summary(proc_frags), _summary(ctr_frags)
    report = {
        "reps": reps,
        "warmup": warmup,
        "fragments_per_run": 4,
        "host": _host_metadata(image),
        "clock": "CLOCK_MONOTONIC (host-wide, no time namespace)",
        "phase_definition": {
            "cold_start": "T1-T0 container/interpreter up and imported",
            "handoff": "(T2-T1)+(T4-T3) session+provisioning+input in, result out",
            "execution": "T3-T2 EphemeralRunner.execute (protocol work)",
            "teardown": "T5-T4 container removed / process reaped",
            "note": ("measurement mode waits for the ready marker before "
                     "session/provisioning, so those costs fall in handoff-in, "
                     "not cold start; phases are observed critical-path intervals"),
        },
        "process_baseline": proc_sum,
        "hardened_container": ctr_sum,
        "happy_path_wall_ms": {
            "process": _stats_ms(proc_wall),
            "container": _stats_ms(ctr_wall),
        },
    }
    if "total_ms" in proc_sum and "total_ms" in ctr_sum:
        report["container_overhead_ms_median"] = round(
            ctr_sum["total_ms"]["median"] - proc_sum["total_ms"]["median"], 3)

    out_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "results_v4_container")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "measurements.json"), "w") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)

    print("DEPLOYMENT-COST MEASUREMENT (median ms per fragment)")
    print(f"image {image}   reps={reps} warmup={warmup}   4 fragments/run")
    print(f"host: python {report['host']['python']}, kernel {report['host']['kernel']}, "
          f"docker {report['host']['docker_version']} runtime={report['host']['docker_runtime']}\n")
    print(_fmt("process", proc_sum))
    print(_fmt("container", ctr_sum))
    print(f"\nHappy-path wall (median): process "
          f"{report['happy_path_wall_ms']['process']['median']:.1f} ms   "
          f"container {report['happy_path_wall_ms']['container']['median']:.1f} ms")
    if "container_overhead_ms_median" in report:
        print(f"Container overhead per fragment (median total): "
              f"{report['container_overhead_ms_median']:.1f} ms")
    print(f"\nWrote {out_dir}/measurements.json")


if __name__ == "__main__":
    main()
