#!/usr/bin/env python3
"""Tiny no-dataset runtime smoke test for every real FL aggregation bridge."""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = [[1, -2, 3, 0], [4, 5, -6, 7]]
EXPECTED = [5, 3, -3, 7]


def _resolve_target(protocol_dir: str, rel_path: str):
    for candidate in ("protocols", "source"):
        base = ROOT / candidate / protocol_dir
        if base.exists():
            return base, base / "bazel-bin" / rel_path
    return ROOT / "protocols" / protocol_dir, ROOT / "protocols" / protocol_dir / "bazel-bin" / rel_path


TARGETS = {
    "opa": _resolve_target("opa-secure-aggregation", "opa/real_fl_bridge_optimized"),
    "willow": _resolve_target("secure-aggregation-main", "willow/benches/real_fl_bridge"),
    "osa": _resolve_target("secure-aggregation-main", "willow/benches/osa_vosa_shell_kahe_real_fl_bridge"),
    "vosa": _resolve_target("secure-aggregation-main", "willow/benches/osa_vosa_shell_kahe_real_fl_bridge"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", choices=(*TARGETS, "all"), default="all")
    return parser.parse_args()


def write_i64(path: Path, rows: list[list[int]]) -> None:
    with path.open("wb") as handle:
        for row in rows:
            for value in row:
                handle.write(struct.pack("<q", value))


def read_i64(path: Path) -> list[int]:
    raw = path.read_bytes()
    if len(raw) % 8:
        raise RuntimeError(f"invalid i64 file length: {path}")
    return [value[0] for value in struct.iter_unpack("<q", raw)]


def run(protocol: str, parent: Path) -> None:
    repo, binary = TARGETS[protocol]
    if not binary.exists():
        raise FileNotFoundError(f"missing {binary}; run scripts/build_federated_bridges.sh")
    work = parent / protocol
    work.mkdir()
    write_i64(work / "clients.i64le", MATRIX)
    manifest = {
        "protocol": protocol,
        "round_idx": 1,
        "num_clients": len(MATRIX),
        "vector_length": len(MATRIX[0]),
        "client_vector_file": "clients.i64le",
        "result_sum_file": "aggregate.i64le",
        "metrics_file": "metrics.json",
        "chunk_size": len(MATRIX[0]),
        "committee_size": 50,
        "threshold": 34 if protocol == "opa" else 40,
        "rss_secret_dim": 30,
        "input_offset": 10,
        "limb_count": 1,
        "allow_plaintext_parameter_derivation": False,
        "enable_vosa_verification": protocol == "vosa",
        "attack_type": "none",
        "rng_mode": "deterministic_benchmark",
    }
    manifest_path = work / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    command = [str(binary), "--manifest", str(manifest_path)]
    if protocol == "vosa":
        command.append("--enable_vosa_verification")
    completed = subprocess.run(command, cwd=repo, text=True, capture_output=True, check=False)
    (work / "bridge.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    if completed.returncode:
        raise RuntimeError(f"{protocol} bridge failed:\n{completed.stdout}{completed.stderr}")
    actual = read_i64(work / "aggregate.i64le")
    metrics = json.loads((work / "metrics.json").read_text(encoding="utf-8"))
    if actual != EXPECTED or metrics.get("max_abs_sum_error") != 0:
        raise RuntimeError(f"{protocol} aggregate mismatch: {actual} != {EXPECTED}")
    if protocol == "vosa" and metrics.get("verification_accepted") is not True:
        raise RuntimeError("VOSA verifier did not accept the honest aggregate")
    print(f"{protocol}_fl_bridge_smoke=pass")


def main() -> None:
    args = parse_args()
    protocols = TARGETS if args.protocol == "all" else (args.protocol,)
    with tempfile.TemporaryDirectory(prefix="osa-vosa-fl-bridge-") as temporary:
        for protocol in protocols:
            run(protocol, Path(temporary))
    print("all_fl_bridge_smoke=pass")


if __name__ == "__main__":
    main()
