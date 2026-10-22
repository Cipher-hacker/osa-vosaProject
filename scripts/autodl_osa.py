#!/usr/bin/env python3
"""CPU-only OSA checks and fresh MNIST/CIFAR-10 runs. Never resumes a run."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIGS = ("mnist_lenet5", "cifar10_alexnet_bn")
MNIST_MD5 = {
    "train-images-idx3-ubyte": "f68b3c2dcbeaaa9fbdd348bbdeb94873",
    "train-labels-idx1-ubyte": "d53e105ee54ea40749a09fcbcd1e9432",
    "t10k-images-idx3-ubyte": "9fb629c4189551a2d022fa330f9573f3",
    "t10k-labels-idx1-ubyte": "ec29112dd5afa0611ce80d1b7f02629c",
}
CIFAR_MD5 = {
    "data_batch_1": "c99cafc152244af753f735de768cd75f",
    "data_batch_2": "d4bba439e000b95fd0a9bffe97cbabec",
    "data_batch_3": "54ebc095f3ab1f0389bbae665268c751",
    "data_batch_4": "634d18415352ddfa80567beed471001a",
    "data_batch_5": "482c414d41f54cd18b22e5b47cb7c3cb",
    "test_batch": "40351d587109b95175f43aff81a1287e",
    "batches.meta": "5ff9c542aee3614f3951f8cda6e48888",
}


def file_hash(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_data(root: Path = ROOT) -> dict:
    fingerprints = {}
    raw = root / "datasets/MNIST/raw"
    for name, expected in MNIST_MD5.items():
        packed_path, raw_path = raw / (name + ".gz"), raw / name
        if file_hash(packed_path, "md5") != expected:
            raise RuntimeError(f"MNIST checksum mismatch: {packed_path}")
        if gzip.decompress(packed_path.read_bytes()) != raw_path.read_bytes():
            raise RuntimeError(f"MNIST raw/gzip mismatch: {raw_path}")
        for path in (packed_path, raw_path):
            fingerprints[path.relative_to(root).as_posix()] = file_hash(path)
    for name, expected in CIFAR_MD5.items():
        path = root / "datasets/cifar-10-batches-py" / name
        if file_hash(path, "md5") != expected:
            raise RuntimeError(f"CIFAR-10 checksum mismatch: {path}")
        fingerprints[path.relative_to(root).as_posix()] = file_hash(path)
    # torchvision prefers a legacy processed MNIST cache if it exists.
    if (root / "datasets/MNIST/processed").exists():
        raise RuntimeError("Unexpected MNIST/processed cache; use the clean upload bundle.")
    print("data=PASS: MNIST 60000/10000; CIFAR-10 50000/10000; canonical checksums match", flush=True)
    return fingerprints


def cpu_environment() -> dict:
    settings = {
        "OMP_NUM_THREADS": "4",
        "MKL_NUM_THREADS": "4",
        "OPENBLAS_NUM_THREADS": "1",
        "OSA_PARALLEL_CHUNKS": "8",
    }
    for key, default in settings.items():
        value = os.environ.get(key, default)
        if not value.isdecimal() or int(value) < 1:
            raise ValueError(f"{key} must be a positive integer")
        os.environ[key] = settings[key] = value
    os.environ["PYTHONUNBUFFERED"] = "1"
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    return settings


def check_runtime() -> dict:
    import numpy as np
    import torch
    import torchvision
    from torch.utils.data import Subset

    sys.path.insert(0, str(ROOT))
    from federated_training import train
    from federated_training.codec import flatten_delta
    from federated_training.config import ExperimentConfig
    from federated_training.data import build_schedule, load_datasets, partition_indices

    torch.set_num_threads(int(os.environ["OMP_NUM_THREADS"]))
    report = {
        "python": sys.version, "executable": sys.executable, "platform": platform.platform(),
        "cpu_count": os.cpu_count(), "torch": torch.__version__,
        "torchvision": torchvision.__version__, "numpy": np.__version__, "device": "cpu",
        "models": {},
    }
    try:
        report["torch_musa_installed"] = importlib.metadata.version("torch-musa")
    except importlib.metadata.PackageNotFoundError:
        report["torch_musa_installed"] = None
    for name in CONFIGS:
        config = ExperimentConfig.load(ROOT / "federated_training/configs" / (name + ".json"))
        train_data, test_data = load_datasets(ROOT / "datasets", config.dataset, download=False)
        expected_train = 60000 if config.dataset == "mnist" else 50000
        if (len(train_data), len(test_data)) != (expected_train, 10000):
            raise RuntimeError(f"Unexpected dataset sizes for {name}")
        partitions = partition_indices(train_data, config.num_clients, config.data_split, config.seed)
        assigned = [index for part in partitions for index in part]
        if sorted(assigned) != list(range(len(train_data))) or any(not part for part in partitions):
            raise RuntimeError(f"Missing/duplicate data or empty clients for {name}")
        schedule = build_schedule(config.seed, config.rounds, config.num_clients, config.active_clients)
        covered = {client for selected in schedule for client in selected}
        if covered != set(range(config.num_clients)):
            raise RuntimeError(f"Some clients never participate for {name}")
        train.set_seed(config.seed)
        model = train.build_model(config.dataset, config.model).cpu()
        initial = {key: value.detach().clone() for key, value in model.state_dict().items()}
        client = schedule[0][0]
        state, loss, examples = train.train_local(
            initial, train_data, partitions[client], config, torch.device("cpu"), 1, client,
        )
        delta, _ = flatten_delta(state, initial)
        if not math.isfinite(loss) or not np.isfinite(delta).all() or not np.any(delta):
            raise RuntimeError(f"Nonfinite loss/update or unchanged model for {name}")
        if examples != len(partitions[client]):
            raise RuntimeError(f"Client sample count mismatch for {name}")
        model.load_state_dict(state)
        test_loss, accuracy = train.evaluate(
            model, Subset(test_data, range(64)), config, torch.device("cpu"),
        )
        if not math.isfinite(test_loss):
            raise RuntimeError(f"Nonfinite evaluation loss for {name}")
        report["models"][name] = {
            "train_samples": len(train_data), "test_samples": len(test_data),
            "assigned_samples": len(assigned), "clients_covered": len(covered),
            "round_1_samples": sum(len(partitions[c]) for c in schedule[0]),
            "local_smoke_samples": examples, "local_smoke_loss": loss,
            "evaluation_smoke_accuracy": accuracy, "vector_length": int(delta.size),
            "config_sha256": file_hash(ROOT / "federated_training/configs" / (name + ".json")),
        }
        print(f"cpu_training=PASS: {name}; one real client trained; partition has no missing/duplicate samples", flush=True)
    return report


def run_logged(command: list[str], log: Path) -> None:
    print("RUN: " + " ".join(command), flush=True)
    with log.open("x", encoding="utf-8") as handle:
        process = subprocess.Popen(
            command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding="utf-8", errors="replace",
        )
        try:
            for line in process.stdout:
                print(line, end="", flush=True)
                handle.write(line)
                handle.flush()
            if process.wait():
                raise RuntimeError(f"Command failed; see {log}")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def training_command(name: str, output: Path, smoke: bool) -> list[str]:
    return [sys.executable, "-u", "-m", "federated_training.train", "--config",
            str(ROOT / "federated_training/configs" / (name + ".json")),
            "--protocol", "osa", "--device", "cpu", "--data-root", str(ROOT / "datasets"),
            "--output-root", str(output), "--rounds", "1" if smoke else "300"]


def validate_run(output: Path, name: str, rounds: int) -> dict:
    path = output / name / "osa/metrics.csv"
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if [int(row["round"]) for row in rows] != list(range(1, rounds + 1)):
        raise RuntimeError(f"Missing/duplicate rounds: {path}")
    for row in rows:
        expected_examples = 48000 if name == "mnist_lenet5" else 40000
        if (row["protocol"] != "osa" or row["device"] != "cpu"
                or row["real_protocol_execution"] != "True"
                or row["verification_enabled"] != "False"
                or int(row["online_clients"]) != 800 or int(row["examples"]) != expected_examples
                or float(row["max_abs_sum_error"]) != 0 or row["round_aborted"] != "False"
                or not all(math.isfinite(float(row[key])) for key in ("train_loss", "test_loss", "test_accuracy"))):
            raise RuntimeError(f"Unexpected training metrics: {path}, round {row['round']}")
    print(f"metrics=PASS: {name}, {rounds} new rounds, accuracy={rows[-1]['test_accuracy']}%", flush=True)
    return {"rounds": rounds, "last_accuracy": float(rows[-1]["test_accuracy"])}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("data", "check", "prepare", "smoke", "run"))
    args = parser.parse_args()
    settings = cpu_environment()
    fingerprints = check_data()
    if args.action == "data":
        return
    if sys.version_info < (3, 10):
        raise RuntimeError("Python 3.10 or later is required")
    report = check_runtime()
    report.update({"thread_settings": settings, "dataset_sha256": fingerprints})
    if args.action == "check":
        print(json.dumps(report, indent=2))
        return
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise RuntimeError("Run prepare/smoke/run on the Linux x86_64 server")
    free_gib = shutil.disk_usage(ROOT).free / (1024 ** 3)
    if free_gib < 20:
        raise RuntimeError(f"Only {free_gib:.1f} GiB free on project disk; free at least 20 GiB first")
    output_parent = ROOT / "results_fresh"
    output_parent.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = Path(tempfile.mkdtemp(prefix=f"{args.action}_{stamp}_", dir=output_parent))
    print(f"FRESH_OUTPUT={output}", flush=True)
    (output / "preflight.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    manifest = ROOT / "UPLOAD_SHA256SUMS"
    if manifest.exists():
        shutil.copyfile(manifest, output / manifest.name)
    if args.action == "prepare":
        run_logged(["bash", str(ROOT / "scripts/build_osa_fl.sh")], output / "build.log")
    run_logged([sys.executable, "-u", str(ROOT / "scripts/smoke_federated_bridges.py"),
                "--protocol", "osa"], output / "bridge_smoke.log")
    if args.action == "prepare":
        print("PREPARE=PASS. Next: python scripts/autodl_osa.py smoke", flush=True)
        return
    results = {}
    for name in CONFIGS:
        run_logged(training_command(name, output, args.action == "smoke"), output / (name + ".log"))
        results[name] = validate_run(output, name, 1 if args.action == "smoke" else 300)
    (output / "completed.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"COMPLETE: {output}", flush=True)


if __name__ == "__main__":
    main()
