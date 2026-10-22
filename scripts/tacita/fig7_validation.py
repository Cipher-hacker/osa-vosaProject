"""Fail-closed validation contract for the new binary and its actual KAHE bridge."""
import hashlib
import json
from pathlib import Path

VERSION = "fig7-batched-v2"

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def require_validation(root, binary, bridge):
    path = root / "validation/fig7_linux.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        if (record["status"] != "passed" or record["implementation"] != VERSION or
                record["binary_sha256"] != sha256(binary) or
                record["bridge_sha256"] != sha256(bridge)):
            raise ValueError("validation does not match current executable files")
    except (OSError, ValueError, KeyError) as exc:
        raise ValueError("Run scripts/validate_fig7.py on this Linux host before formal v2 experiments: " + str(exc)) from exc

def check_pair(metrics):
    if len(metrics) != 2 or {m["input_vector_len"] for m in metrics} != {32, 10000}:
        raise ValueError("validation needs both L=32 and L=10000")
    for m in metrics:
        if (m["correctness"] != "pass" or m["kahe_stage"]["correctness"] != "pass" or
                m["implementation_version"] != VERSION or m["mklhts_enabled"] or m["input_soundness"] or
                not m["ste_share_proofs"] or m["key_coordinates"] != 8192 or m["seed_bytes"] != 32 or
                m["bound_shares_per_member"] != 1 or m["tag_shares_per_member"] != 1 or
                m["main_headers_per_client"] != 1 or m["main_ciphertexts_per_client"] != 1 or
                m["kahe_stage"]["profile"] != "fixed-upstream-100k"):
            raise ValueError("Figure 7 structural or end-to-end validation failed")
    for key in ["server_to_committee_bytes", "committee_to_server_bytes", "key_coordinates"]:
        if metrics[0][key] != metrics[1][key]:
            raise ValueError(f"committee contract changes with application vector length: {key}")
    for key in ["log_n", "log_t", "moduli"]:
        if metrics[0]["kahe_stage"][key] != metrics[1]["kahe_stage"][key]:
            raise ValueError(f"KAHE security parameter changes with vector length: {key}")
