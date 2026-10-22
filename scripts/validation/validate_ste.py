#!/usr/bin/env python3
"""Run the existing Fig7 structural gate against freshly built exact binaries."""
import sys
from pathlib import Path
import suite

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tacita/scripts"))
from fig7_validation import check_pair


def main():
    root = ROOT / "tacita"
    out = root / "validation" / ("suite_" + suite.stamp())
    out.mkdir(parents=True, exist_ok=False)
    gate = root / "validation/fig7_linux.json"
    suite.write_json(gate, dict(status="running", details=str(out)))
    metrics = []
    paths = []
    try:
        for length in (32, 10000):
            stage = out / f"L{length}"
            command = [sys.executable, "-u", str(root / "scripts/run.py"), "smoke", "--implementation", "fig7-batched-v2",
                       "--vector-len", str(length), "--threads", "2", "--repeats", "1", "--output-root", str(stage)]
            import os
            suite.run_process(command, os.environ.copy(), root, out / f"L{length}.log", 7200)
            found = list(stage.glob("smoke_*/*/metrics.json"))
            if len(found) != 1:
                raise ValueError("Expected one new validation result")
            suite.require(suite.read_json(found[0].parent / "status.json")["status"], "completed", "smoke status")
            metrics.append(suite.read_json(found[0]))
            paths.append(str(found[0]))
        check_pair(metrics)
        suite.write_json(gate, dict(status="passed", implementation="fig7-batched-v2", utc_finished=suite.now(),
                                   binary_sha256=suite.sha(root / "target/release/tacita-ste-comparison"),
                                   bridge_sha256=suite.sha(root / "bin/kahe_stage_fig7_v2"), smoke_metrics=paths,
                                   claim="Functional/structural check only; not a security proof"))
        print("FIG7_END_TO_END_VALIDATION_PASS")
    except BaseException as exc:
        suite.write_json(gate, dict(status="failed", details=str(out), error=str(exc)))
        raise


if __name__ == "__main__":
    main()
