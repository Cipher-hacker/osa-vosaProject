#!/usr/bin/env python3
"""Build and validate the real Linux KAHE+STE path before accepting v2 formal runs."""
import argparse
from collections import deque
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from fig7_validation import VERSION, check_pair, sha256

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--project", type=Path, required=True)
    p.add_argument("--threads", type=int, default=32)
    a = p.parse_args()
    if not sys.platform.startswith("linux") or a.threads < 1:
        p.error("run on Linux with positive threads; this tests the real Bazel bridge")
    out = ROOT / "validation" / ("fig7_check_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ"))
    out.mkdir(parents=True, exist_ok=False)
    # No permission to reuse an older gate while a new validation is in progress.
    gate = ROOT / "validation/fig7_linux.json"
    gate.write_text(json.dumps({"status":"running", "details":str(out)}), encoding="utf-8")
    def command(argv, name, env=None):
        print("running:", " ".join(map(str, argv)), flush=True)
        log_path = out / name
        print(f"log: {log_path}", flush=True)
        try:
            with log_path.open("w", encoding="utf-8") as log:
                subprocess.run(list(map(str, argv)), cwd=ROOT, env=env,
                               stdout=log, stderr=subprocess.STDOUT, check=True)
        except (OSError, subprocess.CalledProcessError):
            print(f"Stage failed; last 80 log lines from {log_path}:", file=sys.stderr, flush=True)
            if log_path.is_file():
                with log_path.open(encoding="utf-8", errors="replace") as log:
                    sys.stderr.writelines(deque(log, maxlen=80))
                sys.stderr.flush()
            raise
    try:
        command(["cargo", "build", "--release", "--locked"], "build.log")
        command(["cargo", "test", "--release", "--locked"], "rust-tests.log")
        command([sys.executable,"-m","unittest","discover","-s","tests","-p","test_fig7_*.py"],"python-tests.log")
        env = os.environ.copy()
        env["JOBS"] = str(a.threads)
        command(["bash", "scripts/build_fig7_bridge.sh", str(a.project.resolve())],
                "bridge-build.log", env=env)
        metrics = []
        paths = []
        for length in [32,10000]:
            stage = out / f"L{length}"
            command([sys.executable, "scripts/run.py", "smoke", "--implementation", VERSION,
                     "--vector-len",length,"--threads",a.threads,"--repeats",1,"--output-root",stage],f"L{length}.log")
            found = list(stage.glob("smoke_*/n4_a3_m3_t2_r1/metrics.json"))
            if len(found) != 1:
                raise RuntimeError("expected exactly one fresh vector smoke result")
            status = json.loads((found[0].parent/"status.json").read_text())
            if status["status"] != "completed": raise RuntimeError("incomplete vector smoke")
            metrics.append(json.loads(found[0].read_text()))
            paths.append(str(found[0]))
        check_pair(metrics)
        record = {"status":"passed", "implementation":VERSION,
                  "utc_finished":datetime.now(timezone.utc).isoformat(),
                  "binary_sha256":sha256(ROOT/"target/release/tacita-ste-comparison"),
                  "bridge_sha256":sha256(ROOT/"bin/kahe_stage_fig7_v2"),
                  "smoke_metrics":paths,"details":str(out),
                  "claim":"functional and structural validation only; not a security proof"}
        gate.write_text(json.dumps(record,indent=2),encoding="utf-8")
        print("FIG7_END_TO_END_VALIDATION_PASS",flush=True)
        print(f"results={out}")
    except BaseException as exc:
        gate.write_text(json.dumps({"status":"failed","error":str(exc),"details":str(out)},indent=2),encoding="utf-8")
        print(f"validation failed; logs={out}",file=sys.stderr)
        raise

if __name__ == "__main__":
    main()
