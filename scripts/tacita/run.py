#!/usr/bin/env python3
"""Fresh CPU experiments. No reuse of old timing data or model training."""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from fig7_validation import require_validation

ROOT = Path(__file__).resolve().parents[1]
FIG7 = "fig7-batched-v2"

def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))

def write_json(path, obj):
    path.write_text(json.dumps(obj, indent=2), encoding="utf-8")

def csv_rows(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

def run_logged(command, log):
    print("running:", " ".join(map(str, command)), flush=True)
    with log.open("w", encoding="utf-8") as f:
        subprocess.run(list(map(str, command)), stdout=f, stderr=subprocess.STDOUT, check=True)

def marker(process, prefix, log):
    for line in process.stdout:
        log.write(line)
        log.flush()
        if line.startswith(prefix + " "):
            return dict(token.split("=", 1) for token in line.split()[1:])
    raise RuntimeError(f"KAHE bridge exited before {prefix}; inspect bridge.log")

def vector_prepare(args, binary, out, log):
    seed_file = out / "seeds.json"
    new = args.implementation == FIG7
    run_logged([binary, "seeds", "--clients", args.active_clients, "--output", seed_file] + (["--fig7"] if new else []), out / "seed-generation.log")
    seeds = read_json(seed_file)
    mask_file = out / "mask-seeds.txt"
    mask_file.write_text("\n".join(" ".join(map(str, s)) for s in seeds["mask_seeds"]) + "\n", encoding="ascii")
    key_file = out / "client-keys.txt"
    command = [str(args.kahe_bridge), str(args.n_clients), str(args.active_clients), str(args.vector_len), str(args.committee_size), str(args.threshold), str(mask_file), str(key_file)]
    if new:
        command.append("--fixed-profile")
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, bufsize=1)
    try:
        ready = marker(proc, "ready", log)
        keys = [[int(x) for x in line.split()] for line in key_file.read_text().splitlines()]
        if len(keys) != args.active_clients:
            raise ValueError("KAHE bridge returned wrong client key count")
        if new and (ready.get("profile") != "fixed-upstream-100k" or
                    any(len(key) != 8192 for key in keys)):
            raise ValueError("wrong KAHE profile/key dimension; rebuild the v2 bridge")
        fixture = out / "client-fixture.json"
        write_json(fixture, {"values": keys, "seeds": seeds["seeds"]})
        return proc, ready, fixture
    except BaseException:
        proc.kill()
        proc.wait()
        raise

def one(args, binary, out):
    out.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    write_json(out / "status.json", {"status": "running", "utc_started": started,
                                    "implementation": args.implementation, "driver_pid": os.getpid()})
    command = [binary, "bench", "--n-clients", args.n_clients, "--active-clients", args.active_clients,
               "--committee-size", args.committee_size, "--threshold", args.threshold,
               "--threads", args.threads, "--slots", args.slots, "--output", out / "metrics.json"]
    proc = None
    with (out / "bridge.log").open("w", encoding="utf-8") as bridge_log:
        try:
            if args.vector_len > 1 or args.implementation == FIG7:
                proc, ready, fixture = vector_prepare(args, binary, out, bridge_log)
                command += ["--input-json", fixture, "--unmasked-key-inputs", "--input-bound", 37]
            if args.implementation == FIG7:
                command += ["--fig7"]
            run_logged(command, out / "training-free-benchmark.log")
            metrics = read_json(out / "metrics.json")
            if metrics["correctness"] != "pass":
                raise RuntimeError("STE correctness failed")
            if args.implementation == FIG7 and metrics.get("implementation_version") != FIG7:
                raise RuntimeError("wrong Rust binary version")
            if proc is not None:
                proc.stdin.write(" ".join(map(str, metrics["decoded_sum"])) + "\n")
                for seed in metrics["recovered_mask_seeds"]:
                    proc.stdin.write(" ".join(map(str, seed)) + "\n")
                proc.stdin.close()
                done = marker(proc, "done", bridge_log)
                if proc.wait() != 0 or done.get("correctness") != "pass":
                    raise RuntimeError("KAHE vector correctness failed")
                metrics["kahe_stage"] = {**ready, **done}
                metrics["setup_s"] += float(ready["setup_s"])
                metrics["client_compute_s"] += float(ready["client_mean_s"])
                metrics["client_observed_mean_s"] += float(ready["client_mean_s"])
                metrics["client_batch_wall_s"] += float(ready["client_serial_wall_s"])
                metrics["server_compute_s"] += float(ready["server_pre_s"]) + float(done["server_finalize_s"])
                metrics["online_wall_s"] += float(ready["client_serial_wall_s"]) + float(ready["server_pre_s"]) + float(done["server_finalize_s"])
                metrics["client_to_server_bytes"] += int(ready["client_bytes"])
                metrics["total_bytes"] += int(ready["client_bytes"])
                metrics["implementation_scope"] = ("Figure7_fixed_KAHE_batched_STE_no_MKLHTS"
                    if args.implementation == FIG7 else "KAHE_plus_STE_blocks_no_MKLHTS")
                metrics["kahe_client_schedule"] = "serial; STE clients use requested thread pool"
                metrics["timing_note"] = "sum of measured stages; IPC and fixture disk IO excluded; not a fused parallel wall-time comparison"
            metrics["input_vector_len"] = args.vector_len
            metrics["utc_started"] = started
            metrics["driver_wall_s"] = time.monotonic() - start
            write_json(out / "metrics.json", metrics)
            if not args.keep_fixtures:
                for name in ("seeds.json", "mask-seeds.txt", "client-keys.txt", "client-fixture.json"):
                    (out / name).unlink(missing_ok=True)
            write_json(out / "status.json", {"status": "completed", "utc_finished": datetime.now(timezone.utc).isoformat()})
            return metrics
        except BaseException as exc:
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()
            write_json(out / "status.json", {"status": "failed", "error": str(exc)})
            raise

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=["smoke", "formal", "n-sweep", "m-sweep", "dropout"])
    p.add_argument("--threads", type=int, default=32)
    p.add_argument("--implementation", choices=["legacy", FIG7], default="legacy")
    p.add_argument("--n-clients", type=int, default=1000)
    p.add_argument("--active-clients", type=int, default=800)
    p.add_argument("--committee-size", type=int, default=50)
    p.add_argument("--threshold", type=int, default=40)
    p.add_argument("--vector-len", type=int, default=1)
    p.add_argument("--slots", type=int, default=1)
    p.add_argument("--repeats", type=int, default=None)
    p.add_argument("--output-root", type=Path)
    p.add_argument("--kahe-bridge", type=Path)
    p.add_argument("--keep-fixtures", action="store_true")
    a = p.parse_args()
    if a.kahe_bridge is None:
        a.kahe_bridge = ROOT / "bin" / ("kahe_stage_fig7_v2" if a.implementation == FIG7 else "kahe_stage")
    if a.output_root is None:
        a.output_root = ROOT / "results" / "fig7_v2" if a.implementation == FIG7 else ROOT / "results"
    if a.implementation == FIG7 and (a.slots != 1 or a.vector_len > 100000):
        p.error("fig7 uses slots=1 whole-key ciphertext and fixed-profile vector-len<=100000")
    if a.vector_len < 1 or a.threads < 1 or (a.repeats is not None and a.repeats < 1):
        p.error("vector length, threads and repeats must be positive")
    binary = ROOT / "target/release" / ("tacita-ste-comparison.exe" if os.name == "nt" else "tacita-ste-comparison")
    if not binary.is_file():
        p.error("build the Rust executable first")
    if (a.vector_len > 1 or a.implementation == FIG7) and not a.kahe_bridge.is_file():
        p.error("vector mode requires scripts/build_kahe_bridge.sh")
    if a.implementation == FIG7 and a.mode != "smoke":
        try:
            require_validation(ROOT, binary, a.kahe_bridge)
        except ValueError as exc:
            p.error(str(exc))
    out = a.output_root.resolve() / (a.mode + "_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ"))
    out.mkdir(parents=True, exist_ok=False)
    cfg = vars(a).copy()
    write_json(out / "manifest.json", {"args": {k: str(v) if isinstance(v, Path) else v for k,v in cfg.items()},
        "hostname": platform.node(), "platform": platform.platform(), "cpu_count": os.cpu_count(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "bridge_sha256": hashlib.sha256(a.kahe_bridge.read_bytes()).hexdigest() if a.kahe_bridge.is_file() else None,
        "upstream_commit": "c1a82f02a9fa2faeffa6589628c67e6e85a27ce9",
        "mklhts_enabled": False, "input_soundness": False,
        "traffic_contract": "canonical compressed cryptographic payload bytes; excludes transport framing, IDs of input clients, and setup distribution",
        "security_profile": "honest-client research ablation; setup dealer and key hints trusted"})
    points = [(a.n_clients, a.active_clients, a.committee_size, a.threshold)]
    if a.mode == "smoke":
        points = [(4, 3, 3, 2)]
    elif a.mode == "n-sweep":
        points = [(n, max(1, n*4//5), a.committee_size, a.threshold) for n in [32,64,128,256,512,1000]]
    elif a.mode == "m-sweep":
        points = [(a.n_clients,a.active_clients,m,max(1,m*4//5)) for m in
                  ([20,40,60,80,100] if a.implementation == FIG7 else [16,32,50,64,128])]
    elif a.mode == "dropout":
        points = [(a.n_clients,a.n_clients*(100-d)//100,a.committee_size,a.threshold) for d in [0,10,20,30,40]]
    rows = []
    for n,active,m,t in points:
        a.n_clients,a.active_clients,a.committee_size,a.threshold = n,active,m,t
        for repeat in range(a.repeats or (1 if a.mode == "smoke" else 3)):
            name=f"n{n}_a{active}_m{m}_t{t}_r{repeat+1}"
            print(f"[{name}] started {datetime.now(timezone.utc).isoformat()}", flush=True)
            metrics=one(a,binary,out/name)
            row={"protocol":metrics["protocol"],"n_clients":n,"active_clients":active,"committee_size":m,"threshold":t,"vector_len":a.vector_len,"repeat":repeat+1,"slots":metrics["config"]["slots"]}
            for key in ["setup_s","client_compute_s","committee_compute_s","server_compute_s","server_dlog_s","online_wall_s","client_to_server_bytes","server_to_committee_bytes","committee_to_server_bytes","total_bytes"]:
                row[key]=metrics[key]
            rows.append(row)
            csv_rows(out/"runs.csv",rows)
            print(f"[{name}] correctness=pass online_s={metrics['online_wall_s']:.3f}",flush=True)
    groups={}
    for row in rows:
        k=tuple(row[x] for x in ["n_clients","active_clients","committee_size","threshold","vector_len"])
        groups.setdefault(k,[]).append(row)
    summaries=[]
    for key,group in groups.items():
        s=dict(zip(["n_clients","active_clients","committee_size","threshold","vector_len"],key))
        s["repeats"]=len(group)
        for metric in ["client_compute_s","committee_compute_s","server_compute_s","online_wall_s","total_bytes"]:
            values=[r[metric] for r in group]
            s[metric+"_mean"]=statistics.mean(values)
            s[metric+"_stdev"]=statistics.stdev(values) if len(values)>1 else 0
        summaries.append(s)
    csv_rows(out/"summary.csv",summaries)
    print(f"results={out}")

if __name__ == "__main__":
    main()
