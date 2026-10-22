"""Execute the existing end-to-end TACITA driver with the instrumented binaries."""
import argparse
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--bridge", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    for name in ("n", "active", "m", "threshold", "length", "threads"):
        p.add_argument("--" + name, type=int, required=True)
    a = p.parse_args()
    scripts = a.work / "tacita/scripts"
    sys.path.insert(0, str(scripts))
    spec = importlib.util.spec_from_file_location("instrumented_tacita_driver", scripts / "run.py")
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    args = SimpleNamespace(implementation="fig7-batched-v2", n_clients=a.n, active_clients=a.active,
        committee_size=a.m, threshold=a.threshold, threads=a.threads, slots=1,
        vector_len=a.length, kahe_bridge=a.bridge, keep_fixtures=False)
    metrics = driver.one(args, a.binary, a.output)
    if metrics["correctness"] != "pass" or metrics["kahe_stage"]["correctness"] != "pass":
        raise ValueError("TACITA end-to-end correctness failed")
    print(f"TACITA_CORRECTNESS_PASS metrics={a.output / 'metrics.json'}", flush=True)


if __name__ == "__main__":
    main()
