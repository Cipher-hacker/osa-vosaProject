#!/usr/bin/env python3
"""Standalone paper figures from a completely verified fresh run, never old data."""
from __future__ import annotations

import argparse
from collections import defaultdict
import math
from pathlib import Path
import statistics

import suite
from renderer import draw as render_figure

COMM = (
    ("client_send_bytes_mean", "active_client_sent", "Communication (KB)", 1000),
    ("committee_send_bytes_mean", "committee_responder_sent", "Communication (KB)", 1000),
    ("server_sent_bytes", "server_sent", "Communication (MB)", 1000000),
    ("total_bytes", "total_sent", "Communication (MB)", 1000000),
)
TIMES = (
    ("client_compute_s", "active_client_computation", "Running time (s)", 1),
    ("committee_compute_s", "committee_responder_computation", "Running time (s)", 1),
    ("server_compute_s", "server_computation", "Running time (s)", 1),
    ("server_and_verifier_s", "server_plus_verifier_computation", "Running time (s)", 1),
)
VERIFY_TIME = (TIMES[0], TIMES[2], ("verifier_compute_s", "verifier_computation", "Running time (s)", 1))
VERIFY_COMM = (COMM[0], COMM[2], COMM[3])
COLORS = ("#D55E00", "#0072B2", "#666666", "#9C4DCC")
MARKERS = ("o", "x", "D", "^")
STYLES = ("-", "--", "-.", ":")


def mean_and_sd(rows, field, repeats):
    if sorted(r["repeat"] for r in rows) != list(range(1, repeats+1)):
        raise ValueError(f"Missing/duplicate repeats for {field}")
    v = [r[field] for r in rows]
    if not all(math.isfinite(x) and x >= 0 for x in v):
        raise ValueError("Invalid figure data")
    return statistics.mean(v), statistics.stdev(v) if len(v) > 1 else 0.0


def select(rows, group):
    return [r for r in rows if group in r["groups"].split(";")]


def captions():
    return """# Figure definitions (put these in the manuscript, not inside the images)

Each role/metric is a separate figure. Lines connect measured means only.
No error bars are drawn; sample standard deviations remain in the accompanying CSV.
When TACITA's maximum is at least twice the other protocols' maximum, the main axes
show OSA, OPA and Willow, with all four protocols retained in an inset inside the
main axes. Both axes use linear scales starting at zero. Each has its own legend.
Otherwise all protocols remain in the main axes. No measured values are changed.
Times are seconds (s); KB=1000 bytes, MB=1000000 bytes. No millisecond relabeling.
Communication is sent bytes only, with each directed online hop counted once.
Client sends include its ciphertexts, encrypted shares and applicable commitments.
An upload received by a server is not counted again as receive traffic. Forwarding
that message to a committee is another transmitted hop and is counted once.
Setup/public parameters and global model download are excluded. Native protocol
envelopes are included for baselines, while TACITA counts compressed crypto payload
and explicit tags. These are not normalized packet-level byte comparisons.

Four-protocol plots use the existing OSA-Compact, OPA, Willow and independent
TACITA-STE+KAHE Fig7-batched-v2 without MKLHTS. This does not certify equal security
parameters or full paper equivalence. OSA's compact/seeded RSS31 extension is kept.
N scans fix L=10000, m=50, client dropout=20%. Committee scans fix N=1000,
L=10000, dropout=20%. Length scans fix N=1000, m=50, dropout=20%, start at L=10000.
The fixed-config bars use N=1000, m=50, L=10000, dropout=20%.

m is configured membership, not response count. OSA/Willow/TACITA respond with
t=round(0.8*m), OPA with max(17, round(0.68*m)), exactly as the existing benchmark.
OSA RSS dimension=t-10. At m=50, response counts are 40 and 34 respectively.
Per-client communication is total active-client sends divided by active clients;
per-committee-member is total returns divided by actual responders, not m.
Willow verifier sends remain in total communication. Role means are not additive
unless multiplied by participant counts. Client dropout is separate from fixed
committee participation. System total also includes mPVAS dropout recovery sends.

OSA dropout-only and N-by-dropout plots retain fixed L=10000, m=50, t=40.
VOSA/mPVAS are verification-only overheads, not full aggregation or model training.
mPVAS uses real MNT224 pairing (recorded 112-bit); this is not equal to VOSA's
security target. The mPVAS vector extension runs the scalar equation per coordinate.
The active-client metric excludes dropout clients; system total includes both.

Each point uses the configured independent repeats. CSV standard deviations are
sample deviations, not confidence intervals. Values are not smoothed or fitted.
All runs in one delivery use the same recorded host and artifacts. Shared points
are measured once per repeat and referenced by multiple figures, not treated as
additional independent samples. See measurements.csv and manifest.json for details.
Native role timers differ in implementation; server+verifier is an arithmetic sum,
not an end-to-end latency. STE's reported online stage sum is intentionally not
plotted against the baselines' parallel wall timers. No simulated network delays.
"""


class Figures:
    def __init__(self, out, c):
        self.out = out
        self.config = c
        self.index = []

    def draw(self, rows, group, metric, series, xfield, expected_x, category, prefix, bars=False):
        field, role, ylabel, divisor = metric
        data = []
        for i, (label, filtered) in enumerate(series):
            values = defaultdict(list)
            for r in filtered:
                values[r[xfield] if not bars else 0].append(r)
            if sorted(values) != ([0] if bars else expected_x):
                raise ValueError(f"Incomplete x coverage: {prefix} {label}: {sorted(values)}")
            for x, point_rows in sorted(values.items()):
                mean, sd = mean_and_sd(point_rows, field, self.config["repeats"])
                data.append(dict(series=label, x=x if not bars else label, metric=field,
                                 raw_mean=mean, raw_sample_sd=sd, value=mean/divisor,
                                 sample_sd=sd/divisor, divisor=divisor, repeats=len(point_rows),
                                 job_ids=";".join(r["job_id"] for r in point_rows)))
        stem = f"{prefix}_{role}"
        folder = Path(category) / ("computation" if divisor == 1 else "communication")
        image = self.out / "paper_figures" / folder / stem
        spec = dict(name=stem, labels=[s[0] for s in series], bars=bars,
                    xfield=xfield, ylabel=ylabel, repeats=self.config["repeats"])
        layout = render_figure(data, spec, image)
        layout = dict(headroom=None, axes_fraction=None, data_occlusion=False,
                      decorated_inset_inside_main=None) | layout
        suite.write_csv(self.out / "plot_data" / folder / (stem + ".csv"), data)
        self.index.append(dict(category=str(folder), name=stem, metric=field, y_axis=ylabel,
                               x_scale="linear", y_scale="linear", **layout,
                               legend=";".join(s[0] for s in series),
                               png=image.with_suffix(".png").relative_to(self.out).as_posix(),
                               pdf=image.with_suffix(".pdf").relative_to(self.out).as_posix(),
                               data=(Path("plot_data")/folder/(stem+".csv")).as_posix()))


def generate(rows, c, out, scope="all"):
    out.mkdir(parents=True, exist_ok=False)
    maker = Figures(out, c)
    if scope in ("all", "aggregation"):
        for group, field, xs, category in (
            ("main", "n_clients", [1000], "four_protocols/fixed_configuration"),
            ("n", "n_clients", c["n_values"], "four_protocols/client_count"),
            ("m", "committee_size", c["m_values"], "four_protocols/committee_size"),
            ("length", "vector_len", c["lengths"], "four_protocols/vector_length"),
        ):
            selected = select(rows, group)
            series = [(suite.LABELS[p], [r for r in selected if r["protocol"] == p]) for p in suite.AGG]
            for metric in (*TIMES, *COMM):
                maker.draw(selected, group, metric, series, field, xs, category, "four_protocols_" + group, group == "main")
        for group, field, xs, category in (
            ("osa_dropout", "dropout_percent", c["dropout_values"], "independent/OSA_dropout"),
            ("osa_grid", "n_clients", c["n_values"], "independent/OSA_clients_by_dropout"),
        ):
            selected = select(rows, group)
            series = [("OSA", selected)] if group == "osa_dropout" else [
                (f"k = {d}%", [r for r in selected if r["dropout_percent"] == d]) for d in c["dropout_values"]]
            for metric in (*TIMES[:3], *COMM):
                maker.draw(selected, group, metric, series, field, xs, category, group)
    if scope in ("all", "verification"):
        for group, bars in (("verification_main", True), ("verification_n", False)):
            selected = select(rows, group)
            series = [(suite.LABELS[p], [r for r in selected if r["protocol"] == p]) for p in ("vosa", "mpvas")]
            for metric in (*VERIFY_TIME, *VERIFY_COMM):
                maker.draw(selected, group, metric, series, "n_clients", [1000] if bars else c["n_values"],
                           "independent/" + group, group, bars)
        selected = select(rows, "vosa_grid")
        series = [(f"k = {d}%", [r for r in selected if r["dropout_percent"] == d]) for d in c["dropout_values"]]
        for metric in (*VERIFY_TIME, *VERIFY_COMM):
            maker.draw(selected, "vosa_grid", metric, series, "n_clients", c["n_values"],
                       "independent/VOSA_verification_clients_by_dropout", "vosa_verification_grid")
    suite.write_csv(out / "figure_index.csv", maker.index)
    suite.write_csv(out / "measurements.csv", rows)
    (out / "CAPTIONS.md").write_text(captions(), encoding="utf-8")
    suite.write_json(out / "figure_audit.json", dict(status="passed", figures=len(maker.index),
                      expected_series_checked=True, each_figure_has_legend=True, titles_and_notes_outside=True,
                      units="seconds; decimal KB/MB", traffic="sent_only_no_receive_double_counting",
                      no_errorbars=True, original_means_preserved=True,
                      inset_figures=sum(x["axes"] == 2 for x in maker.index)))
    return maker.index


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, required=True)
    a = p.parse_args()
    rows, manifest = suite.verify_run(a.run.resolve())
    contract = manifest["contract"]
    if contract["smoke"]:
        p.error("Smoke results cannot be used as formal paper figures")
    out = a.run.resolve() / ("figures_" + suite.stamp())
    index = generate(rows, contract["config"], out, contract["scope"])
    suite.write_json(out / "source.json", dict(run=str(a.run.resolve()), manifest_sha256=suite.sha(a.run / "manifest.json")))
    print(f"FIGURES_PASS count={len(index)}\nFIGURES={out}")


if __name__ == "__main__":
    main()
