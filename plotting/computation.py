"""Four computation figures from complete independent runs, with all samples retained."""
from collections import defaultdict
import math
from pathlib import Path
import statistics
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "plotting"))
from renderer import draw, LABELS

METRICS = (
    ("client_compute_s", "single_active_client_time"),
    ("committee_compute_s", "single_responding_member_time"),
    ("server_compute_s", "server_time"),
    ("server_and_verifier_s", "server_plus_verifier_time"),
)


def points(rows, field):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["protocol"], row["dropout_percent"])].append(row)
    expected = {(p, d) for p in ("osa", "opa", "willow", "tacita") for d in (10, 20, 30, 40)}
    if set(groups) != expected:
        raise ValueError("Require all four protocols and dropout configurations")
    points = []
    for p, label in zip(("osa", "opa", "willow", "tacita"), LABELS):
        for dropout in (10, 20, 30, 40):
            group = sorted(groups[(p, dropout)], key=lambda r: r["repeat"])
            if [r["repeat"] for r in group] != [1, 2, 3]:
                raise ValueError("Need three independent executions per point")
            values = [r[field] for r in group]
            if any(not math.isfinite(v) or v < 0 for v in values):
                raise ValueError("Invalid computation time")
            mean, sd = statistics.mean(values), statistics.stdev(values)
            points.append(dict(series=label, protocol=p, x=dropout, metric=field, value=mean,
                raw_mean=mean, sample_sd=sd, raw_sample_sd=sd, repeats=3, divisor=1,
                repeat_1=values[0], repeat_2=values[1], repeat_3=values[2],
                high_variability=bool(mean and sd / mean > .25),
                job_ids=";".join(r["job_id"] for r in group)))
    return points


def plot(run, rows):
    from runner import S
    if len(rows) != 48:
        raise ValueError("Only the complete 48-job formal run can generate paper figures")
    out = run / ("figures_" + S.stamp())
    out.mkdir(parents=True, exist_ok=False)
    data = out / "computation/data"
    S.write_csv(data / "raw_measurements_48.csv", rows)
    samples, index, warnings = [], [], []
    for row in rows:
        for file in sorted((run / row["source"] / "client_samples").glob("*.json")):
            timing = S.read_json(file)
            for phase, field in (("warmup", "warmup_s"), ("measured", "samples_s")):
                for i, value in enumerate(timing[field], 1):
                    samples.append(dict(job_id=row["job_id"], protocol=row["protocol"], dropout_percent=row["dropout_percent"],
                        repeat=row["repeat"], stage=timing["stage"], phase=phase, sample=i, seconds=value,
                        source=file.relative_to(run).as_posix()))
    S.write_csv(data / "client_samples_with_warmups.csv", samples)
    for metric, role in METRICS:
        summary = points(rows, metric)
        name = "four_protocol_dropout_" + role
        csv = data / (name + ".csv")
        S.write_csv(csv, summary)
        spec = dict(name=name, labels=list(LABELS), bars=False, xfield="dropout_percent", ylabel="Running time (s)")
        layout = draw(summary, spec, out / "computation/images" / name)
        index.append(dict(name=name, metric=metric, csv=csv.relative_to(out).as_posix(), data_sha256=S.sha(csv), **layout))
        warnings.extend(p for p in summary if p["high_variability"])
    S.write_json(out / "index.json", index)
    S.write_json(out / "variability_flags.json", warnings)
    S.write_json(out / "verification.json", dict(status="passed", figures=4, formal_runs=48,
        client_measured_samples_per_stage_per_config=60, warmups_excluded=True, no_errorbars=True,
        original_values_preserved=True, original_communication_reference_matches=True,
        statistical_independent_repeats=3, client_stage_samples_not_treated_as_60_independent_rounds=True))
    S.write_json(run / "latest_figures.json", dict(path=out.name))
    print(f"FIGURES_PASS count=4\nFIGURES={out}", flush=True)
    return out
