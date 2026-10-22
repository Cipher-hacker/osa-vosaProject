"""Scientific mean-only figures; an inset retains the complete protocol comparison."""
from __future__ import annotations

from collections import defaultdict
import csv
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.path import Path as MplPath
from matplotlib.ticker import MaxNLocator
from matplotlib.transforms import Bbox

LABELS = ("OSA", "OPA", "Willow", "TACITA-STE")
COLORS = ("#D55E00", "#0072B2", "#666666", "#9C4DCC")
MARKERS = ("o", "x", "D", "^")
STYLES = ("-", "--", "-.", ":")
XLABELS = {"n_clients": "Total number of clients N", "committee_size": "Committee size m",
           "vector_len": "Input vector length L", "dropout_percent": "Client dropout rate (%)"}


def read_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def inspect_data(points, labels, bars=False, repeats=3):
    data = defaultdict(list)
    for p in points:
        value = float(p["value"])
        if not math.isfinite(value) or value < 0:
            raise ValueError("Invalid plotted measurement")
        if int(p["repeats"]) != repeats:
            raise ValueError("Every point must retain all configured measurements")
        data[p["series"]].append((p["x"] if bars else float(p["x"]), value))
    if set(data) != set(labels):
        raise ValueError("Legend and data series differ")
    for label in labels:
        data[label].sort(key=lambda p: p[0])
        xs = [p[0] for p in data[label]]
        if len(xs) != len(set(xs)) or (bars and len(xs) != 1):
            raise ValueError("Duplicate x coordinates")
        if not bars and xs != [p[0] for p in data[labels[0]]]:
            raise ValueError("Series have different x coverage")
    return data


def scale_ratio(data):
    if set(data) != set(LABELS):
        return None
    baseline_max = max(y for p in LABELS[:3] for _, y in data[p])
    tacita_max = max(y for _, y in data[LABELS[3]])
    return tacita_max / baseline_max if baseline_max else (float("inf") if tacita_max else 1.0)


def style_for(label, labels):
    i = LABELS.index(label) if label in LABELS else labels.index(label)
    return COLORS[i], MARKERS[i], STYLES[i]


def draw_axis(ax, data, labels, spec, small=False):
    bars = spec["bars"]
    for i, label in enumerate(labels):
        color, marker, style = style_for(label, spec["labels"])
        xs = [p[0] for p in data[label]]
        ys = [p[1] for p in data[label]]
        if bars:
            ax.bar(i, ys[0], width=.52, color=color, edgecolor="#444444", linewidth=.5, label=label)
        else:
            ax.plot(xs, ys, color=color, marker=marker, linestyle=style, markerfacecolor="white",
                    markersize=3.5 if small else 6, linewidth=1.1 if small else 1.7, label=label)
    ax.set_xscale("linear")
    ax.set_yscale("linear")
    if bars:
        ax.set_xticks([] if small else range(len(labels)), [] if small else labels, fontsize=6.5 if small else 10)
        ax.set_xlim(-.6, len(labels)-.4)
    else:
        xs = [p[0] for p in data[labels[0]]]
        span = max(xs)-min(xs)
        ax.set_xlim(min(xs)-.05*max(1, span), max(xs)+.05*max(1, span))
        if small:
            ticks = xs if len(xs) <= 4 else [xs[0], xs[len(xs)//2], xs[-1]]
        else:
            ticks = list(range(10000, 100001, 10000)) if spec["xfield"] == "vector_len" else xs
        ax.set_xticks(ticks, [f"{int(x)}" for x in ticks])
        if not small:
            ax.set_xlabel(XLABELS[spec["xfield"]], fontsize=12, labelpad=5)
        if spec["xfield"] == "vector_len" and not small:
            ax.tick_params(axis="x", labelrotation=30, labelsize=9)
    ax.set_ylabel(spec["ylabel"], fontsize=7.2 if small else 12, labelpad=2 if small else 7)
    maximum = max(y for label in labels for _, y in data[label])
    ax.set_ylim(0, maximum * 1.10 if maximum else 1)
    ax.tick_params(axis="both", labelsize=7 if small else 10.5, pad=2 if small else 4)
    if spec["xfield"] == "vector_len" and not small:
        ax.tick_params(axis="x", labelsize=9)
    ax.yaxis.set_major_locator(MaxNLocator(nbins=3 if small else 6, prune="upper"))
    ax.ticklabel_format(axis="y", style="plain", useOffset=False)
    ax.grid(axis="y", linestyle="--", color="#d1d1d1", linewidth=.4 if small else .6)
    ax.set_axisbelow(True)
    legend = ax.legend(loc="lower left", bbox_to_anchor=(0, 1.015), borderaxespad=0,
                      ncol=2 if small or len(labels) == 4 else len(labels),
                      fontsize=6.6 if small else 10.5, handlelength=2.3 if small else 2.8,
                      columnspacing=.9 if small else 1.5, labelspacing=.2 if small else .5)
    if small:
        ax.set_facecolor("white")
        for spine in ax.spines.values():
            spine.set_color("#777777")
            spine.set_linewidth(.65)
    return legend


def text_artists(ax, legend):
    artists = [legend, ax.xaxis.label, ax.yaxis.label]
    xmin, xmax = ax.get_xlim()
    ymin, ymax = ax.get_ylim()
    artists.extend(t.label1 for t in ax.xaxis.get_major_ticks() if xmin <= t.get_loc() <= xmax)
    artists.extend(t.label1 for t in ax.yaxis.get_major_ticks() if ymin <= t.get_loc() <= ymax)
    return [a for a in artists if a.get_visible() and (a.get_text() if hasattr(a, "get_text") else True)]


def decorated_bbox(ax, legend, renderer):
    return Bbox.union([ax.bbox, *[a.get_window_extent(renderer) for a in text_artists(ax, legend)]])


def collides_with_data(ax, box):
    for line in ax.lines:
        path = MplPath(line.get_xydata()).transformed(ax.transData)
        if path.intersects_bbox(box, filled=False):
            return True
        if any(box.contains(x, y) for x, y in ax.transData.transform(line.get_xydata())):
            return True
    return any(p.get_window_extent().overlaps(box) for p in ax.patches)


def place_inset(fig, ax, data, spec):
    maximum = max(y for p in LABELS[:3] for _, y in data[p])
    inset = fig.add_axes([.5, .5, .3, .25], zorder=5)
    legend = draw_axis(inset, data, list(LABELS), spec, small=True)
    # Test the full decorated inset, including labels and legend, against all main curves.
    for headroom in (1.12, 1.35, 1.65, 1.95, 2.25):
        ax.set_ylim(0, maximum*headroom if maximum else 1)
        for x, y in ((.53, .55), (.12, .55), (.32, .55), (.53, .25), (.12, .25)):
            main = ax.get_position()
            inset.set_position([main.x0+x*main.width, main.y0+y*main.height,
                                .43*main.width, .32*main.height])
            fig.canvas.draw()
            box = decorated_bbox(inset, legend, fig.canvas.get_renderer()).padded(7)
            if not (ax.bbox.contains(box.x0, box.y0) and ax.bbox.contains(box.x1, box.y1)):
                continue
            if not collides_with_data(ax, box):
                return inset, legend, dict(headroom=headroom, axes_fraction=[x, y, .43, .32],
                                          data_occlusion=False, decorated_inset_inside_main=True)
    raise ValueError(f"No clear inset position: {spec['name']}")


def draw(points, spec, output_stem):
    data = inspect_data(points, spec["labels"], spec["bars"], spec.get("repeats", 3))
    ratio = scale_ratio(data)
    use_inset = ratio is not None and ratio >= 2
    main_labels = list(LABELS[:3]) if use_inset else spec["labels"]
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11,
                         "pdf.fonttype": 42, "ps.fonttype": 42})
    fig, ax = plt.subplots(figsize=(8.4, 5.4))
    fig.subplots_adjust(left=.145, right=.97, bottom=.20 if spec["xfield"] == "vector_len" else .16, top=.82)
    try:
        main_legend = draw_axis(ax, data, main_labels, spec)
        inset_info = {}
        axes = [(ax, main_legend, main_labels)]
        if use_inset:
            inset, legend, inset_info = place_inset(fig, ax, data, spec)
            axes.append((inset, legend, list(LABELS)))
        fig.canvas.draw()
        renderer = fig.canvas.get_renderer()
        for axis, legend, labels in axes:
            if [t.get_text() for t in legend.get_texts()] != list(labels):
                raise ValueError("Missing legend")
            if axis.get_yscale() != "linear" or axis.get_ylim()[0] != 0:
                raise ValueError("Unexpected axis scaling")
            if axis.collections or axis.get_title() or axis.texts or fig.texts:
                raise ValueError("Error bars or in-plot annotations are not allowed")
            actual = [[p.get_height()] for p in axis.patches] if spec["bars"] else [list(line.get_ydata()) for line in axis.lines]
            expected = [[y for _, y in data[label]] for label in labels]
            if actual != expected:
                raise ValueError("Plotted values differ from recorded means")
            for artist in text_artists(axis, legend):
                box = artist.get_window_extent(renderer)
                if not fig.bbox.contains(box.x0, box.y0) or not fig.bbox.contains(box.x1, box.y1):
                    raise ValueError(f"Clipped text in {spec['name']}: {artist}")
        output_stem = Path(output_stem)
        output_stem.parent.mkdir(parents=True, exist_ok=True)
        for extension in ("png", "pdf"):
            fig.savefig(output_stem.with_suffix("."+extension), dpi=240)
        return dict(layout="three_protocol_main_with_four_protocol_inset" if use_inset else "full_comparison",
                    axes=len(axes), tacita_to_other_max_ratio=ratio,
                    means_unchanged=True, no_errorbars=True, **inset_info)
    finally:
        plt.close(fig)
