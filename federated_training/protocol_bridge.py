"""Block-wise execution of the packaged Rust secure-aggregation bridges."""

from __future__ import annotations

import concurrent.futures
import json
import math
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import numpy as np

from .config import ExperimentConfig


PACKAGE_ROOT = Path(__file__).resolve().parents[1]


def _resolve_protocol_root(name: str) -> Path:
    for candidate in ("protocols", "source"):
        p = PACKAGE_ROOT / candidate / name
        if p.exists():
            return p
    return PACKAGE_ROOT / "protocols" / name


BRIDGES = {
    "opa": (
        _resolve_protocol_root("opa-secure-aggregation"),
        "opa/real_fl_bridge_optimized",
    ),
    "willow": (
        _resolve_protocol_root("secure-aggregation-main"),
        "willow/benches/real_fl_bridge",
    ),
    "osa": (
        _resolve_protocol_root("secure-aggregation-main"),
        "willow/benches/osa_vosa_shell_kahe_real_fl_bridge",
    ),
    "vosa": (
        _resolve_protocol_root("secure-aggregation-main"),
        "willow/benches/osa_vosa_shell_kahe_real_fl_bridge",
    ),
}

SUM_FIELDS = {
    "client_time_ms",
    "committee_time_ms",
    "server_time_ms",
    "verifier_time_ms",
    "end_to_end_time_ms",
    "client_upload_bytes",
    "server_received_bytes",
    "committee_received_bytes",
    "verifier_received_bytes",
    "ciphertext_bytes",
    "encrypted_key_share_bytes",
    "encrypted_aux_share_bytes",
    "committee_to_server_bytes",
    "server_to_committee_bytes",
    "server_to_verifier_bytes",
    "client_commitment_bytes",
    "client_randomness_bytes",
}


def public_weighted_update_bound(config: ExperimentConfig, max_client_samples: int) -> int:
    return max(1, math.ceil(config.clip_value * config.quant_scale * max_client_samples))


def limb_count_for_bound(bound: int, base: int = 1 << 31) -> int:
    count = 1
    capacity = base
    while 2 * bound >= capacity:
        count += 1
        capacity *= base
    return count


def aggregate_quantized_plain(matrix_path: Path, shape: tuple[int, int]) -> tuple[np.ndarray, dict[str, Any]]:
    started = time.perf_counter()
    matrix = np.memmap(matrix_path, dtype="<i8", mode="r", shape=shape)
    aggregate = np.sum(matrix, axis=0, dtype=np.int64)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return np.asarray(aggregate), {
        "protocol": "Quantized-Plain-FedAvg",
        "protocol_display_name": "Quantized-Plain-FedAvg",
        "real_protocol_execution": False,
        "verification_enabled": False,
        "verification_accepted": None,
        "client_time_ms": 0.0,
        "committee_time_ms": 0.0,
        "server_time_ms": elapsed_ms,
        "verifier_time_ms": 0.0,
        "end_to_end_time_ms": elapsed_ms,
        "client_upload_bytes": int(matrix.size * 8),
        "server_received_bytes": int(matrix.size * 8),
        "committee_received_bytes": 0,
        "verifier_received_bytes": 0,
        "max_abs_sum_error": 0,
        "round_aborted": False,
    }


def _run_bridge_chunk(
    binary: Path,
    repo_cwd: Path,
    round_dir: Path,
    chunk_index: int,
    start: int,
    end: int,
    source: np.ndarray,
    rows: int,
    round_idx: int,
    config: ExperimentConfig,
    protocol: str,
    public_bound: int,
    limb_count: int,
    keep_artifacts: bool,
) -> tuple[int, int, np.ndarray, dict[str, Any], float]:
    """Run one independent protocol chunk and return (start, end, aggregate, metrics, wall_s)."""
    chunk_dir = round_dir / f"chunk_{chunk_index:06d}"
    chunk_dir.mkdir(parents=True, exist_ok=True)
    chunk_matrix = np.ascontiguousarray(source[:, start:end], dtype="<i8")
    matrix_file = chunk_dir / "client_updates.i64le"
    chunk_matrix.tofile(matrix_file)
    manifest = {
        "protocol": protocol,
        "round_idx": round_idx * 1_000_000 + chunk_index,
        "num_clients": rows,
        "vector_length": end - start,
        "client_vector_file": matrix_file.name,
        "result_sum_file": "aggregate.i64le",
        "metrics_file": "metrics.json",
        "chunk_size": end - start,
        "committee_size": config.committee_size,
        "threshold": (
            config.opa_reconstruction_threshold
            if protocol == "opa"
            else config.reconstruction_threshold
        ),
        "rss_secret_dim": config.rss_secret_dim,
        "input_offset": public_bound,
        "limb_count": limb_count,
        "allow_plaintext_parameter_derivation": False,
        "enable_vosa_verification": protocol == "vosa",
        "attack_type": "none",
        "rng_mode": config.rng_mode,
    }
    manifest_path = (chunk_dir / "manifest.json").resolve()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    command = [str(binary), "--manifest", str(manifest_path)]
    if protocol == "vosa":
        command.append("--enable_vosa_verification")
    started = time.perf_counter()
    process = subprocess.run(
        command,
        cwd=repo_cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    wall_s = time.perf_counter() - started
    (chunk_dir / "bridge.log").write_text(process.stdout, encoding="utf-8")
    if process.returncode != 0:
        raise RuntimeError(
            f"{protocol} bridge failed for chunk {chunk_index}; see {chunk_dir / 'bridge.log'}"
        )
    chunk_result = np.fromfile(chunk_dir / "aggregate.i64le", dtype="<i8")
    if chunk_result.size != end - start:
        raise RuntimeError(f"{protocol} bridge returned a malformed aggregate")
    metrics = json.loads((chunk_dir / "metrics.json").read_text(encoding="utf-8"))
    if not keep_artifacts:
        shutil.rmtree(chunk_dir)
    return start, end, chunk_result, metrics, wall_s


def aggregate_secure(
    protocol: str,
    matrix_path: Path,
    shape: tuple[int, int],
    round_idx: int,
    round_dir: Path,
    config: ExperimentConfig,
    max_client_samples: int,
) -> tuple[np.ndarray, dict[str, Any]]:
    protocol = protocol.lower()
    if protocol not in BRIDGES:
        raise ValueError(f"unsupported secure protocol: {protocol}")
    binary = bridge_binary(protocol)
    if not binary.exists():
        raise FileNotFoundError(
            f"missing bridge binary {binary}; run scripts/build_federated_bridges.sh first"
        )

    rows, cols = shape
    source = np.memmap(matrix_path, dtype="<i8", mode="r", shape=shape)
    aggregate = np.empty(cols, dtype="<i8")
    merged: dict[str, Any] = {
        "protocol": protocol.upper(),
        "real_protocol_execution": True,
        "verification_enabled": protocol == "vosa",
        "verification_accepted": True if protocol == "vosa" else None,
        "round_aborted": False,
        "max_abs_sum_error": 0,
        "chunks": 0,
    }
    chunk_size = config.opa_chunk_size if protocol == "opa" else config.protocol_chunk_size
    public_bound = public_weighted_update_bound(config, max_client_samples)
    limb_count = limb_count_for_bound(public_bound)
    repo_cwd = BRIDGES[protocol][0]
    chunk_starts = list(range(0, cols, chunk_size))
    parallel_chunks = max(
        1,
        min(int(os.environ.get("OSA_PARALLEL_CHUNKS", "1")), len(chunk_starts)),
    )

    phase_started = time.perf_counter()
    results: list[tuple[int, int, np.ndarray, dict[str, Any], float]] = []
    if parallel_chunks == 1:
        for chunk_index, start in enumerate(chunk_starts):
            results.append(
                _run_bridge_chunk(
                    binary,
                    repo_cwd,
                    round_dir,
                    chunk_index,
                    start,
                    min(start + chunk_size, cols),
                    source,
                    rows,
                    round_idx,
                    config,
                    protocol,
                    public_bound,
                    limb_count,
                    config.keep_bridge_artifacts,
                )
            )
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel_chunks) as pool:
            futures = [
                pool.submit(
                    _run_bridge_chunk,
                    binary,
                    repo_cwd,
                    round_dir,
                    chunk_index,
                    start,
                    min(start + chunk_size, cols),
                    source,
                    rows,
                    round_idx,
                    config,
                    protocol,
                    public_bound,
                    limb_count,
                    config.keep_bridge_artifacts,
                )
                for chunk_index, start in enumerate(chunk_starts)
            ]
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
    phase_elapsed = time.perf_counter() - phase_started

    for start, end, chunk_result, metrics, _wall_s in results:
        aggregate[start:end] = chunk_result
        merge_metrics(merged, metrics)
        merged["chunks"] = int(merged["chunks"]) + 1

    merged["secure_aggregation_subprocess_wall_clock_s"] = phase_elapsed
    merged_path = round_dir / "merged_protocol_metrics.json"
    merged_path.write_text(json.dumps(merged, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return aggregate, merged


def bridge_binary(protocol: str) -> Path:
    repo, relative = BRIDGES[protocol]
    suffix = ".exe" if os.name == "nt" else ""
    return repo / "bazel-bin" / f"{relative}{suffix}"


def merge_metrics(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key in SUM_FIELDS:
        value = source.get(key)
        if isinstance(value, (int, float)):
            target[key] = target.get(key, 0) + value
    target["max_abs_sum_error"] = max(
        int(target.get("max_abs_sum_error", 0)), int(source.get("max_abs_sum_error", 0))
    )
    target["round_aborted"] = bool(target.get("round_aborted", False)) or bool(
        source.get("round_aborted", False)
    )
    if source.get("abort_reason"):
        target["abort_reason"] = source["abort_reason"]
    if target.get("verification_enabled"):
        target["verification_accepted"] = bool(target.get("verification_accepted", True)) and bool(
            source.get("verification_accepted", False)
        )
    for key in (
        "protocol_display_name",
        "protocol_variant",
        "threat_model",
        "kahe_backend",
        "rss_field_mode",
        "digest_sharing_mode",
        "p",
        "q",
        "seed_dim",
    ):
        if key in source:
            target[key] = source[key]
