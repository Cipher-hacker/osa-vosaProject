#!/usr/bin/env python3
"""Run fresh baselines and a TACITA STE-only vector ablation."""
import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from fig7_validation import require_validation

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project", type=Path, required=True)
    p.add_argument("--threads", type=int, default=32)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--vector-len", type=int, default=10000)
    p.add_argument("--slots", type=int, default=16)
    p.add_argument("--implementation", choices=["legacy", "fig7-batched-v2"], default="legacy")
    a = p.parse_args()
    if a.vector_len <= 1 or a.repeats < 1 or a.threads < 1:
        p.error("comparison needs vector-len > 1 and positive repeats/threads")
    project = a.project.resolve()
    new = a.implementation == "fig7-batched-v2"
    if new:
        try:
            require_validation(ROOT, ROOT/"target/release/tacita-ste-comparison", ROOT/"bin/kahe_stage_fig7_v2")
        except ValueError as exc:
            p.error(str(exc))
    out = ROOT / "results" / (("comparison_fig7_v2_" if new else "comparison_") + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ"))
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    for repeat in range(1,a.repeats+1):
        baseline = out / f"baseline_r{repeat}"
        subprocess.run([sys.executable, str(project/"drivers/run_full_unified_comparison.py"),
            "--secure-root", str(project/"source/secure-aggregation-main"), "--opa-root", str(project/"source/opa-secure-aggregation"),
            "--output-dir", str(baseline), "--threads", str(a.threads), "--vector-len", str(a.vector_len)], check=True)
        manifest = json.loads((baseline/"manifest.json").read_text())
        cfg = manifest["standard_configuration"]
        for key,value in {"n_clients":1000,"active_clients":800,"committee_size":50,"osa_threshold":40,"willow_threshold":40,"opa_threshold":34,"vector_len":a.vector_len}.items():
            if cfg[key] != value: raise RuntimeError(f"baseline mismatch: {key}")
        with (baseline/"protocol_summary.csv").open(newline="") as f:
            for row in csv.DictReader(f):
                rows.append({"protocol":row["protocol"], "repeat":repeat, "vector_len":a.vector_len,
                    **{k:row[k] for k in ["client_compute_s","committee_compute_s","server_compute_s","online_wall_s","total_bytes"]},
                    "traffic_scope":"existing driver serialization including envelope", "wall_scope":"existing driver parallel client batch"})
        stage = out/f"tacita_r{repeat}"
        subprocess.run([sys.executable,str(ROOT/"scripts/run.py"),"formal","--threads",str(a.threads),"--vector-len",str(a.vector_len),"--slots",str(1 if new else a.slots),"--implementation",a.implementation,"--repeats","1","--output-root",str(stage)],check=True)
        paths=list(stage.glob("formal_*/n1000_a800_m50_t40_r1/metrics.json"))
        if len(paths)!=1: raise RuntimeError("expected exactly one fresh TACITA result")
        m=json.loads(paths[0].read_text())
        if m["input_vector_len"]!=a.vector_len or m["correctness"]!="pass": raise RuntimeError("TACITA result mismatch")
        if new and m.get("implementation_version") != "fig7-batched-v2": raise RuntimeError("wrong TACITA implementation version")
        rows.append({"protocol":m["protocol"], "repeat":repeat,"vector_len":a.vector_len,
            **{k:m[k] for k in ["client_compute_s","committee_compute_s","server_compute_s","online_wall_s","total_bytes"]},
            "traffic_scope":"compressed crypto payload; envelope excluded", "wall_scope":"sum of stages; KAHE clients serial, STE clients parallel"})
        with (out/"comparison.csv").open("w",newline="") as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    (out/"NOTES.txt").write_text("TACITA-STE-only excludes MKLHTS and input soundness. Role times are useful for investigation. Do not publish wall-time speedups or exact wire-byte ratios without normalizing the documented stage schedules and envelope serialization. No old benchmark results were reused.\n")
    print(f"results={out}")

if __name__=="__main__":
    main()
