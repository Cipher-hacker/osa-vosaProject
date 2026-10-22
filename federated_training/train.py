"""End-to-end logical-client FedAvg with selectable real aggregation backends."""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import random
import shutil
import time
from pathlib import Path
from typing import Any

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, Subset

from .codec import apply_delta, dequantize_sum, flatten_delta, quantize_weighted
from .config import ExperimentConfig
from .data import build_schedule, load_datasets, partition_indices, schedule_hash
from .models import build_model
from .protocol_bridge import aggregate_quantized_plain, aggregate_secure


PROTOCOLS = ("plain", "quantized-plain", "opa", "willow", "osa", "vosa")
CSV_FIELDS = [
    "dataset", "model", "protocol", "round", "num_clients", "active_clients",
    "online_clients", "examples", "data_split", "local_epochs", "batch_size",
    "learning_rate", "seed", "vector_length", "quant_scale", "clip_value",
    "committee_size", "reconstruction_threshold", "opa_reconstruction_threshold",
    "rss_secret_dim", "protocol_display_name", "protocol_variant",
    "initial_state_hash", "schedule_hash",
    "config_hash", "train_loss", "test_loss", "test_accuracy", "local_training_s",
    "aggregation_wall_s", "round_wall_s", "total_wall_s", "device",
    "real_protocol_execution", "verification_enabled", "verification_accepted",
    "client_time_ms", "committee_time_ms", "server_time_ms", "verifier_time_ms",
    "end_to_end_time_ms", "client_upload_bytes", "server_received_bytes",
    "committee_received_bytes", "verifier_received_bytes", "max_abs_sum_error",
    "round_aborted", "checkpoint",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--protocol", choices=(*PROTOCOLS, "all"), required=True)
    parser.add_argument("--data-root", type=Path, default=Path("datasets"))
    parser.add_argument("--output-root", type=Path, default=Path("results/federated_training"))
    parser.add_argument("--device", default="auto", help="auto, cpu, cuda, or cuda:N")
    parser.add_argument("--rounds", type=int, default=None, help="optional short-run override")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args()


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def select_device(value: str) -> torch.device:
    if value == "auto":
        value = "cuda" if torch.cuda.is_available() else "cpu"
    device = torch.device(value)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA was requested but torch.cuda.is_available() is false")
    return device


def state_hash(state: dict[str, torch.Tensor]) -> str:
    digest = hashlib.sha256()
    for key in sorted(state):
        value = state[key].detach().cpu().contiguous()
        digest.update(key.encode("utf-8"))
        digest.update(str(value.dtype).encode("ascii"))
        digest.update(np.asarray(value).tobytes())
    return digest.hexdigest()


def train_local(
    global_state: dict[str, torch.Tensor],
    dataset,
    indices: list[int],
    config: ExperimentConfig,
    device: torch.device,
    round_idx: int,
    client_id: int,
) -> tuple[dict[str, torch.Tensor], float, int]:
    local_seed = config.seed + round_idx * 1_000_003 + client_id
    set_seed(local_seed)
    model = build_model(config.dataset, config.model).to(device)
    model.load_state_dict(global_state)
    model.train()
    loader_generator = torch.Generator().manual_seed(local_seed)
    loader = DataLoader(
        Subset(dataset, indices),
        batch_size=config.batch_size,
        shuffle=True,
        num_workers=config.num_workers,
        generator=loader_generator,
    )
    optimizer = torch.optim.SGD(
        model.parameters(),
        lr=config.learning_rate,
        momentum=config.momentum,
        weight_decay=config.weight_decay,
    )
    criterion = nn.NLLLoss(reduction="mean")
    loss_sum = 0.0
    seen = 0
    for _ in range(config.local_epochs):
        for inputs, labels in loader:
            inputs, labels = inputs.to(device), labels.to(device)
            optimizer.zero_grad(set_to_none=True)
            loss = criterion(model(inputs), labels)
            loss.backward()
            optimizer.step()
            batch_examples = int(labels.numel())
            loss_sum += float(loss.item()) * batch_examples
            seen += batch_examples
    state = {key: value.detach().cpu() for key, value in model.state_dict().items()}
    del model
    return state, loss_sum / max(seen, 1), len(indices)


@torch.no_grad()
def evaluate(model: nn.Module, dataset, config: ExperimentConfig, device: torch.device) -> tuple[float, float]:
    model.eval()
    loader = DataLoader(
        dataset,
        batch_size=config.test_batch_size,
        shuffle=False,
        num_workers=config.num_workers,
    )
    criterion = nn.NLLLoss(reduction="sum")
    loss_sum = 0.0
    correct = 0
    seen = 0
    for inputs, labels in loader:
        inputs, labels = inputs.to(device), labels.to(device)
        output = model(inputs)
        loss_sum += float(criterion(output, labels).item())
        correct += int(output.argmax(dim=1).eq(labels).sum().item())
        seen += int(labels.numel())
    return loss_sum / max(seen, 1), 100.0 * correct / max(seen, 1)


def run_protocol(
    protocol: str,
    config: ExperimentConfig,
    train_dataset,
    test_dataset,
    partitions: list[list[int]],
    schedule: list[list[int]],
    device: torch.device,
    output_root: Path,
    resume: bool,
) -> Path:
    set_seed(config.seed)
    model = build_model(config.dataset, config.model).to(device)
    initial_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
    initial_digest = state_hash(initial_state)
    schedule_digest = schedule_hash(schedule)
    run_dir = output_root / f"{config.dataset}_{config.model}" / protocol
    work_dir = run_dir / "bridge_work"
    run_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = run_dir / "checkpoint_latest.pt"
    metrics_path = run_dir / "metrics.csv"
    start_round = 1
    total_wall_s = 0.0
    if resume:
        if not checkpoint_path.exists() or not metrics_path.exists():
            raise FileNotFoundError("--resume requires checkpoint_latest.pt and metrics.csv")
        checkpoint = torch.load(checkpoint_path, map_location="cpu")
        if checkpoint["config_hash"] != config.digest() or checkpoint["schedule_hash"] != schedule_digest:
            raise RuntimeError("checkpoint configuration or client schedule does not match")
        if checkpoint["initial_state_hash"] != initial_digest or checkpoint["protocol"] != protocol:
            raise RuntimeError("checkpoint initialization or protocol does not match")
        model.load_state_dict(checkpoint["model_state"])
        start_round = int(checkpoint["round"]) + 1
        total_wall_s = float(checkpoint.get("total_wall_s", 0.0))
    elif metrics_path.exists():
        raise FileExistsError(f"{metrics_path} exists; remove it or pass --resume")

    work_dir.mkdir(parents=True, exist_ok=True)
    config.save(run_dir / "config.json")
    (run_dir / "run_identity.json").write_text(
        json.dumps(
            {
                "config_hash": config.digest(),
                "initial_state_hash": initial_digest,
                "schedule_hash": schedule_digest,
                "protocol": protocol,
            },
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )

    write_header = not metrics_path.exists()
    with metrics_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        for round_idx in range(start_round, config.rounds + 1):
            round_started = time.perf_counter()
            global_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
            selected = schedule[round_idx - 1]
            active = [client_id for client_id in selected if partitions[client_id]]
            if not active:
                raise RuntimeError("selected round has no non-empty clients")
            exact_accumulator: np.ndarray | None = None
            metadata = None
            matrix_path = work_dir / f"round_{round_idx:04d}_client_updates.i64le"
            matrix = None
            weighted_loss = 0.0
            total_examples = 0
            local_started = time.perf_counter()

            for row_idx, client_id in enumerate(active):
                local_state, local_loss, examples = train_local(
                    global_state,
                    train_dataset,
                    partitions[client_id],
                    config,
                    device,
                    round_idx,
                    client_id,
                )
                delta, current_metadata = flatten_delta(local_state, global_state)
                metadata = current_metadata if metadata is None else metadata
                if protocol == "plain":
                    if exact_accumulator is None:
                        exact_accumulator = np.zeros(delta.size, dtype=np.float64)
                    exact_accumulator += delta * examples
                else:
                    clipped = np.clip(delta, -config.clip_value, config.clip_value)
                    if matrix is None:
                        matrix = np.memmap(
                            matrix_path,
                            dtype="<i8",
                            mode="w+",
                            shape=(len(active), delta.size),
                        )
                    matrix[row_idx, :] = quantize_weighted(clipped, examples, config.quant_scale)
                weighted_loss += local_loss * examples
                total_examples += examples

            local_training_s = time.perf_counter() - local_started
            if metadata is None:
                raise RuntimeError("no model update metadata was produced")
            vector_length = sum(metadata.numels.values())
            aggregation_started = time.perf_counter()
            protocol_metrics: dict[str, Any]
            if protocol == "plain":
                assert exact_accumulator is not None
                aggregate_delta = exact_accumulator / total_examples
                protocol_metrics = {
                    "protocol_display_name": "Plain-FedAvg",
                    "protocol_variant": "exact-float32-client-upload",
                    "real_protocol_execution": False,
                    "verification_enabled": False,
                    "verification_accepted": None,
                    "client_time_ms": 0.0,
                    "committee_time_ms": 0.0,
                    "server_time_ms": 0.0,
                    "verifier_time_ms": 0.0,
                    "end_to_end_time_ms": 0.0,
                    "client_upload_bytes": vector_length * len(active) * 4,
                    "server_received_bytes": vector_length * len(active) * 4,
                    "committee_received_bytes": 0,
                    "verifier_received_bytes": 0,
                    "max_abs_sum_error": 0,
                    "round_aborted": False,
                }
            else:
                assert matrix is not None
                matrix.flush()
                del matrix
                shape = (len(active), vector_length)
                round_bridge_dir = work_dir / f"round_{round_idx:04d}"
                round_bridge_dir.mkdir(parents=True, exist_ok=True)
                if protocol == "quantized-plain":
                    aggregate_i64, protocol_metrics = aggregate_quantized_plain(matrix_path, shape)
                else:
                    aggregate_i64, protocol_metrics = aggregate_secure(
                        protocol,
                        matrix_path,
                        shape,
                        round_idx,
                        round_bridge_dir,
                        config,
                        max(len(indices) for indices in partitions),
                    )
                if protocol_metrics.get("round_aborted"):
                    raise RuntimeError(f"{protocol} aborted in round {round_idx}")
                aggregate_delta = dequantize_sum(aggregate_i64, total_examples, config.quant_scale)
                if not config.keep_bridge_artifacts:
                    matrix_path.unlink(missing_ok=True)
                    if round_bridge_dir.exists() and not any(round_bridge_dir.iterdir()):
                        round_bridge_dir.rmdir()

            aggregation_wall_s = time.perf_counter() - aggregation_started
            new_state = apply_delta(global_state, aggregate_delta, metadata)
            model.load_state_dict(new_state)
            model.to(device)
            test_loss, test_accuracy = evaluate(model, test_dataset, config, device)
            round_wall_s = time.perf_counter() - round_started
            total_wall_s += round_wall_s
            checkpoint_name = ""
            if round_idx % config.checkpoint_every == 0 or round_idx == config.rounds:
                checkpoint_payload = {
                    "round": round_idx,
                    "model_state": {k: v.detach().cpu() for k, v in model.state_dict().items()},
                    "config_hash": config.digest(),
                    "initial_state_hash": initial_digest,
                    "schedule_hash": schedule_digest,
                    "protocol": protocol,
                    "total_wall_s": total_wall_s,
                }
                temporary_checkpoint = checkpoint_path.with_suffix(".tmp")
                torch.save(checkpoint_payload, temporary_checkpoint)
                temporary_checkpoint.replace(checkpoint_path)
                checkpoint_name = checkpoint_path.name
            row = {
                "dataset": config.dataset,
                "model": config.model,
                "protocol": protocol,
                "round": round_idx,
                "num_clients": config.num_clients,
                "active_clients": config.active_clients,
                "online_clients": len(active),
                "examples": total_examples,
                "data_split": config.data_split,
                "local_epochs": config.local_epochs,
                "batch_size": config.batch_size,
                "learning_rate": config.learning_rate,
                "seed": config.seed,
                "vector_length": vector_length,
                "quant_scale": config.quant_scale if protocol != "plain" else "",
                "clip_value": config.clip_value if protocol != "plain" else "",
                "committee_size": config.committee_size if protocol not in {"plain", "quantized-plain"} else "",
                "reconstruction_threshold": config.reconstruction_threshold if protocol in {"willow", "osa", "vosa"} else "",
                "opa_reconstruction_threshold": config.opa_reconstruction_threshold if protocol == "opa" else "",
                "rss_secret_dim": config.rss_secret_dim if protocol in {"osa", "vosa"} else "",
                "protocol_display_name": protocol_metrics.get("protocol_display_name", protocol),
                "protocol_variant": protocol_metrics.get("protocol_variant", protocol),
                "initial_state_hash": initial_digest,
                "schedule_hash": schedule_digest,
                "config_hash": config.digest(),
                "train_loss": weighted_loss / total_examples,
                "test_loss": test_loss,
                "test_accuracy": test_accuracy,
                "local_training_s": local_training_s,
                "aggregation_wall_s": aggregation_wall_s,
                "round_wall_s": round_wall_s,
                "total_wall_s": total_wall_s,
                "device": str(device),
                "real_protocol_execution": protocol_metrics.get("real_protocol_execution", False),
                "verification_enabled": protocol_metrics.get("verification_enabled", False),
                "verification_accepted": protocol_metrics.get("verification_accepted"),
                "client_time_ms": protocol_metrics.get("client_time_ms", 0.0),
                "committee_time_ms": protocol_metrics.get("committee_time_ms", 0.0),
                "server_time_ms": protocol_metrics.get("server_time_ms", 0.0),
                "verifier_time_ms": protocol_metrics.get("verifier_time_ms", 0.0),
                "end_to_end_time_ms": protocol_metrics.get("end_to_end_time_ms", 0.0),
                "client_upload_bytes": protocol_metrics.get("client_upload_bytes", 0),
                "server_received_bytes": protocol_metrics.get("server_received_bytes", 0),
                "committee_received_bytes": protocol_metrics.get("committee_received_bytes", 0),
                "verifier_received_bytes": protocol_metrics.get("verifier_received_bytes", 0),
                "max_abs_sum_error": protocol_metrics.get("max_abs_sum_error", 0),
                "round_aborted": protocol_metrics.get("round_aborted", False),
                "checkpoint": checkpoint_name,
            }
            writer.writerow(row)
            handle.flush()
            print(
                f"protocol={protocol} round={round_idx}/{config.rounds} "
                f"clients={len(active)} train_loss={row['train_loss']:.6f} "
                f"test_loss={test_loss:.6f} accuracy={test_accuracy:.4f}% "
                f"wall_s={round_wall_s:.3f}",
                flush=True,
            )
    return metrics_path


def main() -> None:
    args = parse_args()
    config = ExperimentConfig.load(args.config).with_overrides(rounds=args.rounds)
    device = select_device(args.device)
    set_seed(config.seed)
    train_dataset, test_dataset = load_datasets(args.data_root, config.dataset, args.download)
    partitions = partition_indices(train_dataset, config.num_clients, config.data_split, config.seed)
    schedule = build_schedule(config.seed, config.rounds, config.num_clients, config.active_clients)
    protocols = PROTOCOLS if args.protocol == "all" else (args.protocol,)
    for protocol in protocols:
        path = run_protocol(
            protocol,
            config,
            train_dataset,
            test_dataset,
            partitions,
            schedule,
            device,
            args.output_root,
            args.resume,
        )
        print(f"saved_metrics={path}")


if __name__ == "__main__":
    main()
