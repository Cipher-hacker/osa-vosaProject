"""Same-host computation rerun with auditable serial client samples."""
from collections import defaultdict
from dataclasses import asdict
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shutil
import statistics
import sys

import instrument
import resources
import dependency_locks

ROOT = Path(__file__).resolve().parent
PROTOCOLS = ("osa", "opa", "willow", "tacita")
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("computation_base_suite", ROOT / "support/suite.py")
S = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = S
spec.loader.exec_module(S)


def check_package():
    manifest = S.read_json(ROOT / "package_manifest.json")
    for name, digest in manifest["files"].items():
        S.require(S.sha(ROOT / name), digest, "addon source " + name)
    return S.sha(ROOT / "package_manifest.json")


def binaries():
    return {p: ROOT / "bin" / p for p in (*PROTOCOLS, "kahe")}


def plan(smoke=False):
    if smoke:
        return [S.Job(p, 20, 16, 20, 32, 1) for p in PROTOCOLS] + [S.Job("tacita", 20, 16, 20, 10000, 1)]
    jobs = []
    for repeat in (1, 2, 3):
        drops = [10, 20, 30, 40]
        drops = drops[repeat-1:] + drops[:repeat-1]
        for i, dropout in enumerate(drops):
            offset = (i + repeat-1) % 4
            for protocol in PROTOCOLS[offset:] + PROTOCOLS[:offset]:
                jobs.append(S.Job(protocol, 1000, 1000-10*dropout, 50, 10000, repeat))
    return jobs


def config(smoke=False):
    return dict(version=instrument.VERSION, threads=32, repeats=1 if smoke else 3,
        client_warmup=1 if smoke else 3, client_samples=2 if smoke else 20,
        timeout_seconds=43200, resource_interval_seconds=2, min_free_disk_gib=20,
        client_timing_scope="serial operation and serialization after same-process warmup; setup excluded",
        tacita_client_scope="mean(STE samples) + mean(KAHE samples); not fused wall time")


def load_timing(path, stage, c):
    timing = S.read_json(path)
    S.require(timing["schema"], "serial-client-timing-v1", "timing schema")
    S.require(timing["stage"], stage, "timing stage")
    S.require(timing["serial"], True, "serial client samples")
    S.require(timing["setup_included"], False, "setup excluded")
    for field, count in (("warmup_s", c["client_warmup"]), ("samples_s", c["client_samples"])):
        values = timing[field]
        S.require(len(values), count, field + " count")
        if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
            raise ValueError("Invalid client sample")
    if not math.isclose(timing["mean_s"], statistics.mean(timing["samples_s"]), rel_tol=1e-13, abs_tol=1e-15):
        raise ValueError("Client mean does not match recorded samples")
    return timing


def evidence(attempt):
    return {p.relative_to(attempt).as_posix(): S.sha(p) for p in sorted(attempt.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts}


def normalize(attempt, job, c, host, elapsed, smoke):
    raw = S.read_json(attempt / "ste/metrics.json") if job.protocol == "tacita" else S.parse_line((attempt / "process.log").read_text())
    row = S.normalize(raw, job, ["dropout_computation_retest"], c["threads"], elapsed)
    stages = ("ste", "kahe") if job.protocol == "tacita" else ("native",)
    timings = {s: load_timing(attempt / "client_samples" / (s + ".json"), s, c) for s in stages}
    mean = sum(t["mean_s"] for t in timings.values())
    if not math.isclose(row["client_compute_s"], mean, rel_tol=1e-12, abs_tol=0.00000051):
        raise ValueError("Native metric does not match warmed serial samples")
    row.update(client_compute_s=mean, host=host, client_samples_per_stage=c["client_samples"],
        client_warmups_per_stage=c["client_warmup"], measurement_version=instrument.VERSION)
    if not smoke:
        reference = S.read_json(ROOT / "communication_reference.json")[f"{job.protocol}_A{job.active}"]
        for field in (*S.HOPS, "total_bytes", "client_send_bytes_mean", "committee_send_bytes_mean"):
            S.require(row[field], reference[field], "communication changed during timer rerun: " + field)
    return row


def verify_case(run, job):
    c = S.read_json(run / "manifest.json")["contract"]
    directory = run / "raw" / job.id
    state = S.read_json(directory / "status.json")
    S.require(state["status"], "completed", "measurement completion")
    attempt = (directory / state["attempt"]).resolve()
    if attempt.parent != directory.resolve():
        raise ValueError("Invalid attempt directory")
    S.require(evidence(attempt), state["evidence_sha256"], "raw evidence hashes")
    command = S.read_json(attempt / "command.json")
    S.require(command["job"], asdict(job), "job parameters")
    S.require(S.read_json(attempt / "resource_summary.json")["exit_code"], 0, "process success")
    row = normalize(attempt, job, c["config"], c["host"]["host"], state["driver_wall_s"], c["smoke"])
    row["source"] = attempt.relative_to(run).as_posix()
    S.require(row, S.read_json(attempt / "row.json"), "recorded measurement")
    return row


def verify_run(run):
    contract = S.read_json(run / "manifest.json")["contract"]
    S.require(contract["config"], config(contract["smoke"]), "measurement configuration")
    jobs = plan(contract["smoke"])
    S.require(contract["jobs"], [asdict(j) for j in jobs], "exact experiment plan")
    S.require(S.read_json(run / "status.json")["status"], "completed", "full run completion")
    return [verify_case(run, job) for job in jobs]


def host_record(base):
    if not sys.platform.startswith("linux") or platform.machine() != "x86_64":
        raise RuntimeError("Native experiments require the existing Linux x86_64 server")
    available = len(os.sched_getaffinity(0))
    if available < 32:
        raise RuntimeError(f"Need original 32-thread allocation; only {available} CPUs available")
    instrument.check_base(base)
    dependency_locks.verify(ROOT / "work", S.read_json(ROOT / "dependency_locks.json"))
    inventory = S.read_json(ROOT / "instrumented_sources.json")
    for name, digest in inventory.items():
        if not name.endswith("MODULE.bazel.lock"):
            S.require(S.sha(ROOT / "work" / name), digest, "instrumented source changed: " + name)
    for name, binary in binaries().items():
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f"Missing instrumented binary {name}: run prepare.sh")
    cpu = next((x.split(":", 1)[1].strip() for x in Path("/proc/cpuinfo").read_text().splitlines() if x.startswith("model name")), "unknown")
    return dict(host=platform.node(), cpu_model=cpu, available_cpus=available,
        platform=platform.platform(), python=platform.python_version(), base=str(base),
        addon_sha256=check_package(), base_inventory_sha256=S.sha(ROOT / "base_files.json"),
        instrumented_inventory_sha256=S.sha(ROOT / "instrumented_sources.json"),
        dependency_lock_manifest_sha256=S.sha(ROOT / "dependency_locks.json"),
        binary_sha256={name: S.sha(p) for name, p in binaries().items()},
        instrumentation_diff_sha256=S.sha(ROOT / "work/client_timing_changes.diff"))


def commands(job, c, attempt, base):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BENCH_", "OPA_", "VOSA_", "MPVAS_"))}
    env.update(BENCH_N_CLIENTS=str(job.n), BENCH_ACTIVE_CLIENTS=str(job.active), BENCH_COMMITTEE_SIZE=str(job.m),
        BENCH_THRESHOLD=str(job.t), BENCH_VECTOR_LEN=str(job.length), BENCH_THREADS=str(c["threads"]),
        BENCH_CLIENT_WARMUP=str(c["client_warmup"]), BENCH_CLIENT_SAMPLES=str(c["client_samples"]),
        BENCH_CLIENT_TIMING_DIR=str(attempt / "client_samples"), TMPDIR=str(base / ".runtime/tmp"),
        PYTHONUNBUFFERED="1", PYTHONDONTWRITEBYTECODE="1", OMP_NUM_THREADS="1", MKL_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1")
    if job.protocol == "osa":
        env.update(BENCH_OSA_PROFILE="compact_seeded", BENCH_RSS_SECRET_DIM=str(job.rss),
            BENCH_OSA_DIGEST_MASK_MODE="shake256_xof", BENCH_OSA_AUX_ENCRYPTION_MODE="ind_cpa_shake256")
    if job.protocol != "tacita":
        return [str(binaries()[job.protocol])], env
    return [sys.executable, "-u", str(ROOT / "tacita_worker.py"), "--work", str(ROOT / "work"),
        "--binary", str(binaries()["tacita"]), "--bridge", str(binaries()["kahe"]), "--output", str(attempt / "ste"),
        "--n", str(job.n), "--active", str(job.active), "--m", str(job.m), "--threshold", str(job.t),
        "--length", str(job.length), "--threads", str(c["threads"])], env


def execute(base, smoke=False, resume=None):
    c, jobs, host = config(smoke), plan(smoke), host_record(base)
    contract = dict(config=c, jobs=[asdict(j) for j in jobs], smoke=smoke, host=host)
    if not smoke:
        gate = S.read_json(ROOT / "validation/latest.json")
        S.require(gate["status"], "passed", "instrumented validation")
        S.require(gate["host"], host, "validated host and binaries")
        verify_run(ROOT / gate["run"])
    run = resume.resolve() if resume else ROOT / ("validation" if smoke else "runs") / (("smoke_" if smoke else "computation_") + S.stamp())
    with S.Lock(base / ".suite.lock"), S.Lock(ROOT / ".retest.lock"):
        if resume:
            S.require(S.read_json(run / "manifest.json")["contract"], contract, "resume configuration and binaries")
        else:
            run.mkdir(parents=True, exist_ok=False)
            S.write_json(run / "manifest.json", dict(contract=contract, utc_started=S.now()))
        state = dict(status="running", expected_jobs=len(jobs), completed_jobs=0, utc_started=S.read_json(run / "manifest.json")["utc_started"], pid=os.getpid())
        print(f"RESULTS={run}", flush=True)
        rows = []
        try:
            for job in jobs:
                if (run / "raw" / job.id / "status.json").is_file() and S.read_json(run / "raw" / job.id / "status.json")["status"] == "completed":
                    rows.append(verify_case(run, job))
                    continue
                if shutil.disk_usage(ROOT).free < c["min_free_disk_gib"] * 2**30:
                    raise RuntimeError("Need at least 20 GiB free before continuing")
                directory = run / "raw" / job.id
                attempt = directory / ("attempt_" + S.stamp())
                attempt.mkdir(parents=True, exist_ok=False)
                command, env = commands(job, c, attempt, base)
                S.write_json(attempt / "command.json", dict(command=command, job=asdict(job), config=c, utc_started=S.now(),
                    controlled_env={k:v for k,v in env.items() if k.startswith("BENCH_")}))
                S.write_json(directory / "status.json", dict(status="running", attempt=attempt.name))
                state.update(completed_jobs=len(rows), current_job=job.id, current_log=str(attempt / "process.log"), utc_updated=S.now())
                S.write_json(run / "status.json", state)
                S.write_json(ROOT / "current.json", dict(run=str(run), **state))
                print(f"[{len(rows)+1}/{len(jobs)}] {job.id} started {S.now()}\nlog={attempt / 'process.log'}", flush=True)
                try:
                    elapsed = resources.run(command, env, base, attempt, c["timeout_seconds"], c["resource_interval_seconds"])
                    row = normalize(attempt, job, c, host["host"], elapsed, smoke)
                    row["source"] = attempt.relative_to(run).as_posix()
                    S.write_json(attempt / "row.json", row)
                    S.write_json(directory / "status.json", dict(status="completed", attempt=attempt.name, utc_finished=S.now(),
                        driver_wall_s=elapsed, evidence_sha256=evidence(attempt)))
                except BaseException as exc:
                    S.write_json(directory / "status.json", dict(status="failed", attempt=attempt.name, error=str(exc)))
                    raise
                rows.append(row)
                S.write_csv(run / "measurements.csv", rows)
                print(f"[{job.id}] PASS client_mean_s={row['client_compute_s']:.6f} samples_per_stage={c['client_samples']} driver_wall_s={elapsed:.3f}", flush=True)
            S.require(host_record(base), host, "code and binaries changed during measurement")
            state.update(status="completed", completed_jobs=len(rows), utc_finished=S.now(), current_job="", current_log="")
            S.write_json(run / "status.json", state)
            S.write_json(ROOT / "current.json", dict(run=str(run), **state))
        except BaseException as exc:
            state.update(status="failed", completed_jobs=len(rows), error=str(exc), utc_updated=S.now())
            S.write_json(run / "status.json", state)
            S.write_json(ROOT / "current.json", dict(run=str(run), **state))
            raise
    verify_run(run)
    if smoke:
        scripts = ROOT / "work/tacita/scripts"
        sys.path.insert(0, str(scripts))
        from fig7_validation import check_pair
        pair = [S.read_json(run / r["source"] / "ste/metrics.json") for r in rows if r["protocol"] == "tacita"]
        check_pair(pair)
        S.write_json(ROOT / "validation/latest.json", dict(status="passed", run=run.relative_to(ROOT).as_posix(), host=host))
        print("COMPUTATION_VALIDATION_PASS", flush=True)
    else:
        from plot_results import plot
        plot(run, rows)
        print("COMPUTATION_RETEST_COMPLETE", flush=True)
    print(f"RESULTS={run}", flush=True)
    return run


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    for mode in ("validate", "run"):
        c = sub.add_parser(mode)
        c.add_argument("--base", type=Path, required=True)
        c.add_argument("--resume", type=Path)
    for mode in ("plot", "verify", "export"):
        c = sub.add_parser(mode)
        c.add_argument("--run", type=Path, required=True)
    sub.add_parser("status")
    a = p.parse_args()
    if a.mode in ("validate", "run"):
        execute(a.base.resolve(), a.mode == "validate", a.resume)
    elif a.mode == "status":
        s = S.read_json(ROOT / "current.json")
        print(json.dumps(s, indent=2))
        file = Path(s.get("current_log") or "__absent__")
        if file.is_file():
            print("\n".join(file.read_text(errors="replace").splitlines()[-6:]))
        csv = Path(s["run"]) / "measurements.csv"
        if csv.is_file():
            print("Latest three completed measurements:")
            print("\n".join(csv.read_text().splitlines()[-3:]))
    else:
        run = a.run.resolve()
        rows = verify_run(run)
        if a.mode == "plot":
            from plot_results import plot
            plot(run, rows)
        elif a.mode == "export":
            import tarfile
            target = ROOT.parent / ("four_protocol_computation_results_" + S.stamp() + ".tar.gz")
            with tarfile.open(target, "w:gz") as archive:
                archive.add(run, arcname=run.name)
                for name in ("package_manifest.json", "base_files.json", "communication_reference.json", "dependency_locks.json", "dependency_locks.py", "locked_dependencies", "README_CN.md", "client_timing.rs", "instrument.py", "runner.py", "tacita_worker.py", "plot_results.py", "resources.py", "support", "plotting"):
                    archive.add(ROOT / name, arcname="code/" + name)
                for repository, record in S.read_json(ROOT / "dependency_locks.json").items():
                    archive.add(ROOT / "work" / record["target"], arcname="code/used_dependency_locks/" + repository + ".MODULE.bazel.lock")
                    for name in record.get("config_files", {}):
                        archive.add(ROOT / "work" / name, arcname="code/used_dependency_config/" + name)
                archive.add(ROOT / "work/client_timing_changes.diff", arcname="code/client_timing_changes.diff")
            print(f"ARCHIVE={target}", flush=True)
        else:
            print(f"VERIFY_PASS measurements={len(rows)}")


if __name__ == "__main__":
    main()
