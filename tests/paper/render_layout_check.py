"""Synthetic layout QA only. Never produces accepted experimental results."""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import suite
import plot
from test_suite import fixture


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if "layout_test_only" not in a.output.name:
        p.error("Output folder must include layout_test_only; these are NOT measurements")
    c = suite.read_json(Path(__file__).resolve().parents[1] / "config.json")
    rows = []
    for job, groups in suite.plan(c).items():
        raw = fixture(job.protocol, job)
        row = suite.normalize(raw, job, groups, c["threads"], 1)
        factor = dict(osa=1, opa=8, willow=20, tacita=1000, vosa=1, mpvas=300)[job.protocol]
        scale = (1 + job.n / 1000) * (1 + job.length / 100000) * (1 + job.m / 100)
        for key in ("client_compute_s", "committee_compute_s", "server_compute_s", "verifier_compute_s", "server_and_verifier_s"):
            row[key] *= factor * scale * (1 + .01 * job.repeat)
        for key in ("client_send_bytes_mean", "committee_send_bytes_mean", "server_sent_bytes", "total_bytes"):
            row[key] *= scale * max(1, factor/100)
        row["source"] = "SYNTHETIC_LAYOUT_TEST_NOT_EXPERIMENTAL_DATA"
        rows.append(row)
    index = plot.generate(rows, c, a.output.resolve())
    suite.require(len(index), 64, "full figure coverage")
    suite.write_json(a.output / "TEST_ONLY.json", dict(synthetic=True, not_for_paper=True, figures=64))
    print(f"LAYOUT_TEST_ONLY_PASS figures={len(index)} output={a.output}")


if __name__ == "__main__":
    main()
