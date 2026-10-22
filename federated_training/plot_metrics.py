"""Plot recipient-generated loss and accuracy CSVs without rerunning training."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib.pyplot as plt


COLORS = {
    "plain": "#4C78A8",
    "quantized-plain": "#72B7B2",
    "opa": "#F58518",
    "willow": "#E45756",
    "osa": "#54A24B",
    "vosa": "#B279A2",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, default=Path("results/federated_training"))
    parser.add_argument(
        "--dataset-model",
        choices=("mnist_lenet5", "cifar10_alexnet_bn"),
        required=True,
    )
    parser.add_argument("--output", type=Path, default=None)
    return parser.parse_args()


def read_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> None:
    args = parse_args()
    output = args.output or args.results_root / args.dataset_model / "training_curves.pdf"
    fig, axes = plt.subplots(1, 2, figsize=(7.2, 2.8))
    found = 0
    for protocol, color in COLORS.items():
        path = args.results_root / args.dataset_model / protocol / "metrics.csv"
        if not path.exists():
            continue
        rows = read_rows(path)
        if not rows:
            continue
        rounds = [int(row["round"]) for row in rows]
        axes[0].plot(rounds, [float(row["test_loss"]) for row in rows], label=protocol, color=color)
        axes[1].plot(rounds, [float(row["test_accuracy"]) for row in rows], label=protocol, color=color)
        found += 1
    if found == 0:
        raise FileNotFoundError(f"no metrics.csv files found under {args.results_root / args.dataset_model}")
    axes[0].set(xlabel="Communication round", ylabel="Test loss")
    axes[1].set(xlabel="Communication round", ylabel="Test accuracy (%)")
    for axis in axes:
        axis.grid(True, linestyle="--", linewidth=0.5, alpha=0.55)
        axis.spines[["top", "right"]].set_visible(False)
    handles, labels = axes[1].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=min(found, 3), frameon=False)
    fig.tight_layout(rect=(0, 0.15, 1, 1))
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, bbox_inches="tight")
    print(f"saved_figure={output}")


if __name__ == "__main__":
    main()
