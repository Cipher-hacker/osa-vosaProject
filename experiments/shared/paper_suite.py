#!/usr/bin/env python3
"""Fresh CPU experiments, sender-only accounting, same-host resumable execution."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
VERSION = "paper-cpu-v1"
AGG = ("osa", "opa", "willow", "tacita")
LABELS = dict(osa="OSA", opa="OPA", willow="Willow", tacita="TACITA-STE",
              vosa="VOSA", mpvas="mPVAS")
EXPECTED = dict(osa="OSA-SeededDigest-RSS31-full-online", opa="OPA-LWR-full-online",
                willow="Willow-paper-full-online", tacita="TACITA-STE-Fig7-v2",
                vosa="VOSA-verification-only-faithful",
                mpvas="mPVAS-UD-verification-only-real-pairing-vector")
HOPS = ("client_to_server_bytes", "client_to_committee_bytes", "client_to_verifier_bytes",
        "server_to_committee_bytes", "server_to_verifier_bytes",
        "verifier_to_committee_bytes", "committee_to_server_bytes")
REQUIRED_HOPS = {
    "osa": {HOPS[0], HOPS[3], HOPS[6]}, "opa": {HOPS[0], HOPS[3], HOPS[6]},
    "tacita": {HOPS[0], HOPS[3], HOPS[6]},
    "willow": {HOPS[0], HOPS[4], HOPS[5], HOPS[6]},
    "vosa": {HOPS[0], HOPS[2], HOPS[4]}, "mpvas": {HOPS[0], HOPS[4]},
}
LIMITATIONS = [
    "No real FL training, datasets, global model download or accuracy plots.",
    "OSA is the existing Compact/SeededDigest/RSS31 benchmark, not silently changed to faithful mode.",
    "TACITA is an independent Fig7-batched-v2 STE+KAHE ablation without MKLHTS/input soundness, not author code.",
    "Native security parameters, input encodings and message framing differ. No equal-security certification.",
    "All communication counts sent messages once per directed online hop; received bytes are not added.",
    "Server forwarding is a separate transmitted hop. The existing routing is retained.",
    "Setup distribution/public parameters and transport headers/retransmissions are excluded.",
    "Client metric is mean sent bytes per active client; committee metric is mean per actual responder.",
    "mPVAS dropouts still send recovery messages; include these in system total, not in active-client mean.",
    "Willow verifier sends are included in system total even if not a standalone plotted role.",
    "VOSA/mPVAS plots are verification-only increments, not full aggregation comparisons.",
    "mPVAS uses real MNT224 pairing at recorded 112-bit security; not equal to the VOSA security target.",
    "mPVAS vector extension executes the released scalar verification equation separately per coordinate.",
    "STE online_wall_s is a stage sum with serial KAHE clients. Do not compare it as a fused parallel wall time.",
    "Times are native role computation in seconds, not network latency. Repeats are independent executions.",
    "Functional correctness and selected negative tests are not a security proof.",
]


def now():
    return datetime.now(timezone.utc).isoformat()


def stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def write_csv(path, rows):
    if not rows:
        return
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(path)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require(value, expected, context):
    if value != expected:
        raise ValueError(f"{context}: got {value!r}, expected {expected!r}")


def validate_config(c):
    require(c["schema"], VERSION, "configuration version")
    for k in ("threads", "repeats", "timeout_seconds"):
        if type(c[k]) is not int or c[k] < 1:
            raise ValueError(f"{k} must be a positive integer")
    for k, low, high in (("n_values", 1, 1000), ("m_values", 20, 100),
                         ("lengths", 10000, 100000), ("dropout_values", 0, 99)):
        v = c[k]
        if not v or v != sorted(set(v)) or any(type(x) is not int or not low <= x <= high for x in v):
            raise ValueError(f"Invalid {k}")
    require(c["n_clients"], 1000, "fixed N")
    require(c["committee_size"], 50, "fixed m")
    require(c["dropout_percent"], 20, "fixed dropout")
    require(c["vector_len"], 10000, "fixed L")
    if c["plot_y_scale"] not in ("linear", "log"):
        raise ValueError("plot_y_scale must be linear or log")
    if not isinstance(c["min_free_disk_gib"], (float, int)) or c["min_free_disk_gib"] < 1:
        raise ValueError("min_free_disk_gib must be positive")


@dataclass(frozen=True)
class Job:
    protocol: str
    n: int
    active: int
    m: int
    length: int
    repeat: int

    @property
    def t(self):
        return max(17, (68 * self.m + 50) // 100) if self.protocol == "opa" else (80 * self.m + 50) // 100

    @property
    def rss(self):
        return (80 * self.m + 50) // 100 - 10

    @property
    def id(self):
        return f"{self.protocol}_N{self.n}_A{self.active}_M{self.m}_L{self.length}_R{self.repeat}"


def plan(c, scope="all", smoke=False):
    jobs = {}

    def add(group, protocols, n, m, length, d):
        if n * (100 - d) % 100:
            raise ValueError("Dropout setting does not produce an integer active population")
        for r in range(1, (1 if smoke else c["repeats"]) + 1):
            for protocol in protocols:
                job = Job(protocol, n, n * (100 - d) // 100, m, length, r)
                groups = jobs.setdefault(job, [])
                if group not in groups:
                    groups.append(group)

    if smoke:
        if scope in ("all", "aggregation"):
            add("smoke", AGG, 20, 20, 32, 20)
        if scope in ("all", "verification"):
            add("smoke", ("vosa", "mpvas"), 20, 20, 32, 20)
        return jobs
    if scope in ("all", "aggregation"):
        add("main", AGG, 1000, 50, 10000, 20)
        for n in c["n_values"]:
            add("n", AGG, n, 50, 10000, 20)
        for m in c["m_values"]:
            add("m", AGG, 1000, m, 10000, 20)
        for length in c["lengths"]:
            add("length", AGG, 1000, 50, length, 20)
        for d in c["dropout_values"]:
            add("osa_dropout", ("osa",), 1000, 50, 10000, d)
            for n in c["n_values"]:
                add("osa_grid", ("osa",), n, 50, 10000, d)
    if scope in ("all", "verification"):
        add("verification_main", ("vosa", "mpvas"), 1000, 50, 10000, 20)
        for n in c["n_values"]:
            add("verification_n", ("vosa", "mpvas"), n, 50, 10000, 20)
        for d in c["dropout_values"]:
            for n in c["n_values"]:
                add("vosa_grid", ("vosa",), n, 50, 10000, d)
    return jobs


def parse_line(log):
    lines = [x for x in log.splitlines() if x.strip().startswith("protocol=")]
    if len(lines) != 1:
        raise ValueError(f"Expected one protocol metric record, got {len(lines)}")
    return dict(token.split("=", 1) for token in shlex.split(lines[0]) if "=" in token)


def numeric(raw, key, integer=False):
    value = int(raw[key]) if integer else float(raw[key])
    if not math.isfinite(value) or value < 0:
        raise ValueError(f"Invalid {key}: {value}")
    return value


def normalize(raw, job, groups, threads, driver_wall_s):
    p = job.protocol
    require(raw["protocol"], EXPECTED[p], "protocol")
    if p in AGG:
        require(raw["correctness"], "pass", "aggregation correctness")
    else:
        require(raw["honest_correctness"], "pass", "honest verification")
        require(raw["forged_server_rejection"], "pass", "negative test")
        require(raw["timing_scope"], "verification_increment_only", "verification scope")
    cfg = raw["config"] if p == "tacita" else raw
    for key, value in (("n_clients", job.n), ("active_clients", job.active)):
        require(int(cfg[key]), value, key)
    require(int(raw["input_vector_len"] if p == "tacita" else raw["vector_len"]), job.length, "L")
    if p != "mpvas":
        require(int(cfg["committee_size"]), job.m, "m")
        threshold_key = "threshold" if p == "tacita" else "threshold_r" if p == "opa" else "threshold_t"
        require(int(cfg[threshold_key]), job.t, "threshold")
    thread_key = "threads" if p in ("tacita", "vosa") else "client_threads" if p == "mpvas" else "bench_threads"
    expected_threads = min(threads, job.active) if p == "vosa" else min(threads, job.n) if p == "mpvas" else threads
    require(int(cfg[thread_key]), expected_threads, "threads")
    if p == "osa":
        for key, value in dict(benchmark_profile="compact_seeded", rss_field_mode="compact31",
                               digest_sharing_mode="seeded_prg_digest").items():
            require(raw[key], value, key)
        require(int(raw["rss_secret_dim"]), job.rss, "RSS dimension")
    if p == "tacita":
        for key, value in dict(implementation_version="fig7-batched-v2", mklhts_enabled=False,
                               input_soundness=False, ste_share_proofs=True, key_coordinates=8192,
                               seed_bytes=32, main_ciphertexts_per_client=1, main_headers_per_client=1,
                               bound_shares_per_member=1, tag_shares_per_member=1).items():
            require(raw[key], value, key)
        require(raw["kahe_stage"]["correctness"], "pass", "KAHE correctness")
        require(raw["kahe_stage"]["profile"], "fixed-upstream-100k", "KAHE profile")
        require(int(raw["kahe_stage"]["log_n"]), 13, "KAHE log_n")
        require(int(raw["kahe_stage"]["log_t"]), 168, "KAHE log_t")
        require(int(cfg["slots"]), 8192, "STE key dimensions")
        require(int(cfg["input_bound"]), 37, "STE key bound")
        require(cfg["mask_inputs"], False, "KAHE-key masking mode")
    if p == "mpvas":
        require(raw["curve"], "MNT224", "pairing curve")
        require(int(raw["security_bits"]), 112, "recorded security")
    hops = {}
    for key in HOPS:
        value = numeric(raw, key, True) if key in REQUIRED_HOPS[p] else int(raw.get(key, 0))
        if value < 0 or (key not in REQUIRED_HOPS[p] and value != 0):
            raise ValueError(f"Unexpected traffic: {key}")
        hops[key] = value
    total = numeric(raw, "total_bytes", True)
    require(sum(hops.values()), total, "sum of sent hops (never add receive counters)")
    client_sent = sum(hops[k] for k in HOPS[:3])
    dropout_sent = numeric(raw, "dropout_client_to_server_bytes", True) if p == "mpvas" else 0
    active_sent = numeric(raw, "active_client_to_server_bytes", True) if p == "mpvas" else client_sent
    require(active_sent + dropout_sent, client_sent, "active/dropout client accounting")
    if p == "mpvas" and job.active == job.n and dropout_sent:
        raise ValueError("No dropout clients but nonzero dropout traffic")
    server_sent = hops[HOPS[3]] + hops[HOPS[4]]
    committee_sent = hops[HOPS[6]]
    verifier_sent = hops[HOPS[5]]
    require(client_sent + server_sent + committee_sent + verifier_sent, total, "sender totals")
    responders = job.t if p in AGG else 0
    client_key = "client_compute_mean_s" if p == "vosa" else "active_client_compute_mean_s" if p == "mpvas" else "client_compute_s"
    times = dict(client_compute_s=numeric(raw, client_key), server_compute_s=numeric(raw, "server_compute_s"),
                 verifier_compute_s=0.0 if p == "tacita" else numeric(raw, "verifier_compute_s"),
                 committee_compute_s=numeric(raw, "committee_compute_s") if p in AGG else 0.0)
    return dict(job_id=job.id, protocol=p, display_name=LABELS[p], groups=";".join(groups),
                n_clients=job.n, active_clients=job.active, committee_size=job.m, responding_members=responders,
                vector_len=job.length, dropout_percent=100 * (job.n-job.active) / job.n, repeat=job.repeat,
                threads=threads, host=platform.node(), correctness="pass", **hops,
                client_sent_bytes=client_sent, active_client_sent_bytes=active_sent,
                dropout_client_sent_bytes=dropout_sent, server_sent_bytes=server_sent,
                committee_sent_bytes=committee_sent, verifier_sent_bytes=verifier_sent, total_bytes=total,
                client_send_bytes_mean=active_sent / job.active,
                committee_send_bytes_mean=committee_sent / responders if responders else 0.0,
                **times, server_and_verifier_s=times["server_compute_s"] + times["verifier_compute_s"],
                driver_wall_s=driver_wall_s, reported_online_s=raw.get("online_wall_s", ""),
                timing_scope="verification_increment_only" if p not in AGG else "native_role_compute",
                source="")


def paths(root=ROOT):
    runtime = root / ".runtime"
    return {**{p: root / "bin" / p for p in ("osa", "opa", "willow", "vosa")},
            "tacita": root / "tacita/target/release/tacita-ste-comparison",
            "kahe": root / "tacita/bin/kahe_stage_fig7_v2",
            "mpvas": runtime / "mpvas-real/venv/bin/python"}


def commands(job, c, attempt, root=ROOT):
    p = job.protocol
    bins = paths(root)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BENCH_", "OPA_", "VOSA_", "MPVAS_"))}
    env.update(OMP_NUM_THREADS="1", MKL_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1",
               TMPDIR=str(root / ".runtime/tmp"), PYTHONUNBUFFERED="1")
    if p in ("osa", "opa", "willow"):
        env.update(BENCH_N_CLIENTS=str(job.n), BENCH_ACTIVE_CLIENTS=str(job.active), BENCH_VECTOR_LEN=str(job.length),
                   BENCH_COMMITTEE_SIZE=str(job.m), BENCH_THRESHOLD=str(job.t), BENCH_THREADS=str(c["threads"]))
        if p == "osa":
            env.update(BENCH_OSA_PROFILE="compact_seeded", BENCH_RSS_SECRET_DIM=str(job.rss),
                       BENCH_OSA_DIGEST_MASK_MODE="shake256_xof", BENCH_OSA_AUX_ENCRYPTION_MODE="ind_cpa_shake256")
        return [str(bins[p])], env, root
    if p == "vosa":
        env.update(VOSA_N_CLIENTS=str(job.n), VOSA_ACTIVE_CLIENTS=str(job.active), VOSA_VECTOR_LEN=str(job.length),
                   VOSA_COMMITTEE_SIZE=str(job.m), VOSA_THRESHOLD=str(job.t), VOSA_THREADS=str(c["threads"]))
        return [str(bins[p])], env, root
    if p == "mpvas":
        runtime = root / ".runtime/mpvas-real"
        env.update(PYTHONPATH=os.pathsep.join(map(str, (runtime / "src/charm", root / "project/source/mpvas-experiments/src"))),
                   LD_LIBRARY_PATH=str(runtime / "pbc/lib") + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else ""),
                   MPVAS_VECTOR_LEN=str(job.length), MPVAS_THREADS=str(c["threads"]), MPVAS_PROGRESS_EVERY="25")
        return [str(bins[p]), "-m", "testrun.bench_ud_vector", "-p", "ud", "-n", str(job.n), "-m", "0",
                "--dropout-ratio", str((job.n-job.active) / job.n), "--suppress-writes"], env, root / "project/source/mpvas-experiments/src"
    return [sys.executable, "-u", str(root / "tacita/scripts/run.py"), "formal", "--implementation", "fig7-batched-v2",
            "--n-clients", str(job.n), "--active-clients", str(job.active), "--committee-size", str(job.m),
            "--threshold", str(job.t), "--vector-len", str(job.length), "--threads", str(c["threads"]),
            "--slots", "1", "--repeats", "1", "--output-root", str(attempt / "ste"),
            "--kahe-bridge", str(bins["kahe"])], env, root / "tacita"


def run_process(command, env, cwd, log, timeout):
    start = time.monotonic()
    with log.open("w", encoding="utf-8") as handle:
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT,
                                start_new_session=os.name != "nt")
        try:
            code = proc.wait(timeout=timeout)
        except BaseException:
            if proc.poll() is None:
                if os.name == "nt":
                    proc.terminate()
                else:
                    os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    if os.name == "nt":
                        proc.kill()
                    else:
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
            raise
    elapsed = time.monotonic() - start
    if code:
        tail = "\n".join(log.read_text(encoding="utf-8", errors="replace").splitlines()[-40:])
        raise RuntimeError(f"Exit {code}: {log}\n{tail}")
    return elapsed


def read_raw(attempt, job):
    if job.protocol != "tacita":
        return parse_line((attempt / "process.log").read_text(encoding="utf-8")), [attempt / "process.log"]
    candidates = list((attempt / "ste").glob("formal_*/*/metrics.json"))
    if len(candidates) != 1:
        raise ValueError("Expected exactly one fresh STE metrics.json")
    file = candidates[0]
    status = file.parent / "status.json"
    manifest = file.parent.parent / "manifest.json"
    require(read_json(status)["status"], "completed", "STE completion")
    require(read_json(manifest)["hostname"], platform.node(), "STE host")
    return read_json(file), [attempt / "process.log", file, status, manifest]


def verify_job(run, job, groups, threads):
    run = run.resolve()
    directory = run / "raw" / job.id
    status = read_json(directory / "status.json")
    require(status["status"], "completed", job.id)
    attempt = (directory / status["attempt"]).resolve()
    if attempt.parent != directory.resolve():
        raise ValueError("Invalid attempt path")
    for relative, digest in status["evidence_sha256"].items():
        file = (attempt / relative).resolve()
        if not file.is_relative_to(attempt) or sha(file) != digest:
            raise ValueError(f"Altered or invalid evidence: {relative}")
    raw, evidence = read_raw(attempt, job)
    mandatory = {p.relative_to(attempt).as_posix() for p in evidence}
    mandatory.update(("row.json", "command.json"))
    if set(status["evidence_sha256"]) != mandatory:
        raise ValueError("Incomplete evidence hash inventory")
    row = normalize(raw, job, groups, threads, status["driver_wall_s"])
    row["source"] = attempt.relative_to(run).as_posix()
    require(read_json(attempt / "row.json"), row, "recorded result")
    return row


def source_signature(root):
    entries = {}
    for base in (root / "scripts", root / "project/source", root / "tacita/src", root / "tacita/scripts",
                 root / "tacita/bridge", root / "tacita/upstream"):
        for directory, dirs, names in os.walk(base, followlinks=False):
            dirs[:] = [d for d in dirs if d not in ("target", ".git", "__pycache__")
                       and not d.startswith("bazel-") and not Path(directory, d).is_symlink()]
            for name in names:
                file = Path(directory, name)
                if not file.is_file() or file.is_symlink():
                    continue
                if file.suffix in (".py", ".rs", ".cc", ".h", ".bzl", ".proto", ".toml") or file.name == "BUILD":
                    entries[file.relative_to(root).as_posix()] = sha(file)
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()


def preflight(c, jobs, root=ROOT):
    if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("Native runs require Linux x86_64; plan and tests are cross-platform")
    used = {j.protocol for j in jobs}
    bins = paths(root)
    if "tacita" in used:
        used.add("kahe")
    for p in used:
        if not bins[p].is_file() or not os.access(bins[p], os.X_OK):
            raise RuntimeError(f"Missing executable {bins[p]}; run setup/build first")
    if "tacita" in used:
        sys.path.insert(0, str(root / "tacita/scripts"))
        from fig7_validation import require_validation
        require_validation(root / "tacita", bins["tacita"], bins["kahe"])
    free = shutil.disk_usage(root).free / 2**30
    if free < c["min_free_disk_gib"]:
        raise RuntimeError(f"Only {free:.1f} GiB free. Need {c['min_free_disk_gib']} GiB")
    available = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
    if available < c["threads"]:
        raise RuntimeError(f"Requested {c['threads']} threads, only {available} CPUs available; configure before running")
    check = [str(root / ".runtime/mpvas-real/venv/bin/python"), "-c", "from charm.toolbox.pairinggroup import PairingGroup; PairingGroup('MNT224'); print('PAIRING_IMPORT_PASS')"]
    if "mpvas" in used:
        job = next(j for j in jobs if j.protocol == "mpvas")
        _, env, cwd = commands(job, c, root, root)
        subprocess.run(check, env=env, cwd=cwd, check=True)
    cpuinfo = Path("/proc/cpuinfo").read_text()
    cpu_model = next((x.split(":", 1)[1].strip() for x in cpuinfo.splitlines() if x.startswith("model name")), "unknown")
    runtime_files = {}
    if "mpvas" in used:
        for base in (root / ".runtime/mpvas-real/src/charm", root / ".runtime/mpvas-real/pbc/lib"):
            for file in base.rglob("*.so*"):
                if file.is_file():
                    runtime_files[file.relative_to(root).as_posix()] = sha(file)
        if not runtime_files:
            raise RuntimeError("Pairing runtime shared libraries not found")
    return dict(host=platform.node(), platform=platform.platform(), cpu_model=cpu_model, available_cpus=available,
                python=platform.python_version(), source_sha256=source_signature(root),
                binary_sha256={p: sha(bins[p]) for p in sorted(used)},
                runtime_sha256=runtime_files,
                mem_total_kib=next((x.split()[1] for x in Path("/proc/meminfo").read_text().splitlines() if x.startswith("MemTotal:")), ""))


class Lock:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        import fcntl
        self.file = self.path.open("a+")
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.file.close()
            raise RuntimeError("Another suite is running in this package; do not run timing jobs concurrently")
        return self

    def __exit__(self, *args):
        self.file.close()


def execute(c, scope, smoke, resume, root=ROOT):
    jobs = plan(c, scope, smoke)
    host = preflight(c, jobs, root)
    contract = dict(version=VERSION, config=c, scope=scope, smoke=smoke, host=host,
                    jobs=[dict(**asdict(j), groups=g) for j, g in jobs.items()])
    run = resume.resolve() if resume else root / "runs" / (("smoke_" if smoke else "paper_") + stamp())
    if resume:
        require(read_json(run / "manifest.json")["contract"], contract, "resume contract (host, code, binaries, parameters)")
    else:
        run.mkdir(parents=True, exist_ok=False)
        write_json(run / "manifest.json", dict(contract=contract, utc_started=now(), limitations=LIMITATIONS))
    rows = []
    state = dict(status="running", utc_started=read_json(run / "manifest.json")["utc_started"], pid=os.getpid(),
                 expected_jobs=len(jobs), completed_jobs=0, current_job="", current_log="", utc_updated=now())
    print(f"RESULTS={run}", flush=True)
    with Lock(root / ".suite.lock"):
        try:
            for job, groups in jobs.items():
                directory = run / "raw" / job.id
                status_file = directory / "status.json"
                if status_file.is_file() and read_json(status_file).get("status") == "completed":
                    rows.append(verify_job(run, job, groups, c["threads"]))
                    state.update(completed_jobs=len(rows), utc_updated=now())
                    write_json(run / "status.json", state)
                    continue
                if shutil.disk_usage(root).free < c["min_free_disk_gib"] * 2**30:
                    raise RuntimeError("Free disk below configured minimum; free space before resume")
                attempt = directory / ("attempt_" + stamp())
                attempt.mkdir(parents=True, exist_ok=False)
                command, env, cwd = commands(job, c, attempt, root)
                log = attempt / "process.log"
                state.update(current_job=job.id, current_log=str(log.relative_to(run)), utc_updated=now())
                write_json(run / "status.json", state)
                write_json(status_file, dict(status="running", attempt=attempt.name, utc_started=now()))
                metadata = dict(command=command, cwd=str(cwd), job=asdict(job), utc_started=now(),
                                controlled_env={k:v for k,v in env.items() if k.startswith(("BENCH_", "VOSA_", "MPVAS_"))})
                write_json(attempt / "command.json", metadata)
                print(f"[{len(rows)+1}/{len(jobs)}] {job.id} started {metadata['utc_started']}\nlog={log}", flush=True)
                elapsed = run_process(command, env, cwd, log, c["timeout_seconds"])
                raw, evidence = read_raw(attempt, job)
                row = normalize(raw, job, groups, c["threads"], elapsed)
                row["source"] = attempt.relative_to(run).as_posix()
                write_json(attempt / "row.json", row)
                evidence += [attempt / "row.json", attempt / "command.json"]
                write_json(status_file, dict(status="completed", attempt=attempt.name, utc_finished=now(),
                                             driver_wall_s=elapsed, evidence_sha256={p.relative_to(attempt).as_posix():sha(p) for p in evidence}))
                rows.append(row)
                state.update(completed_jobs=len(rows), utc_updated=now())
                write_csv(run / "measurements.csv", rows)
                write_json(run / "status.json", state)
                print(f"[{job.id}] PASS driver_wall_s={elapsed:.3f} total_sent_bytes={row['total_bytes']}", flush=True)
            require(source_signature(root), host["source_sha256"], "source changed while running")
            for p, digest in host["binary_sha256"].items():
                require(sha(paths(root)[p]), digest, "binary changed while running")
            for name, digest in host["runtime_sha256"].items():
                require(sha(root / name), digest, "pairing runtime changed while running")
            write_csv(run / "measurements.csv", rows)
            state.update(status="completed", current_job="", current_log="", utc_finished=now(), utc_updated=now())
            write_json(run / "status.json", state)
        except BaseException as exc:
            state.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=str(exc), utc_updated=now())
            write_json(run / "status.json", state)
            print(f"FAILED; results preserved at {run}; resume this directory after fixing the cause", file=sys.stderr)
            raise
    print(f"SUITE_COMPLETE\nRESULTS={run}", flush=True)
    return run


def verify_run(run):
    run = run.resolve()
    manifest = read_json(run / "manifest.json")
    contract = manifest["contract"]
    validate_config(contract["config"])
    require(contract["version"], VERSION, "run contract version")
    expected = [dict(**asdict(j), groups=g) for j, g in plan(contract["config"], contract["scope"], contract["smoke"]).items()]
    require(contract["jobs"], expected, "full expected job coverage")
    require(read_json(run / "status.json")["status"], "completed", "full suite status")
    rows = []
    # Parsing must preserve the recorded host when done on a different plotting machine.
    original_node = platform.node
    platform.node = lambda: contract["host"]["host"]
    try:
        for spec in contract["jobs"]:
            job = Job(**{k:v for k,v in spec.items() if k != "groups"})
            rows.append(verify_job(run, job, spec["groups"], contract["config"]["threads"]))
    finally:
        platform.node = original_node
    require(len(rows), read_json(run / "status.json")["expected_jobs"], "job coverage")
    require(len(rows), read_json(run / "status.json")["completed_jobs"], "completed coverage")
    return rows, manifest


def verify_package(root=ROOT):
    manifest = read_json(root / "package_manifest.json")
    for name, expected in manifest["files"].items():
        if name in manifest.get("bazel_generated_lockfiles", []):
            continue
        file = (root / name).resolve()
        if not file.is_relative_to(root.resolve()) or sha(file) != expected:
            raise ValueError(f"Missing or altered package file: {name}")
    print(f"PACKAGE_HASH_PASS files={len(manifest['files'])}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("plan", "check", "run", "verify", "status", "verify-package"))
    p.add_argument("--config", type=Path, default=ROOT / "config.json")
    p.add_argument("--scope", choices=("all", "aggregation", "verification"), default="all")
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--resume", type=Path)
    p.add_argument("--run", type=Path)
    p.add_argument("--plots", action="store_true", help="generate figures after a successful full non-smoke run")
    a = p.parse_args()
    if a.action == "verify-package":
        verify_package()
        return
    if a.action in ("status", "verify"):
        if not a.run:
            p.error("--run is required")
        if a.action == "verify":
            rows, _ = verify_run(a.run.resolve())
            print(f"RESULTS_VERIFIED jobs={len(rows)}")
        else:
            state = read_json(a.run / "status.json")
            print(json.dumps(state, indent=2))
            if state.get("current_log"):
                file = a.run / state["current_log"]
                if file.is_file():
                    print("\n".join(file.read_text(encoding="utf-8", errors="replace").splitlines()[-3:]))
        return
    c = read_json(a.config)
    validate_config(c)
    jobs = plan(c, a.scope, a.smoke)
    if a.action == "plan":
        print(json.dumps(dict(config=c, scope=a.scope, unique_protocol_runs=len(jobs),
                              per_protocol=dict(Counter(j.protocol for j in jobs)),
                              groups=dict(Counter(g for groups in jobs.values() for g in groups)),
                              limitations=LIMITATIONS), indent=2))
    elif a.action == "check":
        print(json.dumps(preflight(c, jobs), indent=2))
        print("PREFLIGHT_PASS")
    else:
        def interrupted(signum, frame):
            raise KeyboardInterrupt(f"Received signal {signum}")
        if os.name != "nt":
            signal.signal(signal.SIGTERM, interrupted)
            signal.signal(signal.SIGHUP, interrupted)
        run = execute(c, a.scope, a.smoke, a.resume)
        if a.plots and not a.smoke:
            import plot
            rows, _ = verify_run(run)
            out = run / ("figures_" + stamp())
            index = plot.generate(rows, c, out, a.scope)
            write_json(out / "source.json", dict(run=str(run), manifest_sha256=sha(run / "manifest.json")))
            print(f"FIGURES_PASS count={len(index)}\nFIGURES={out}")


if __name__ == "__main__":
    main()
