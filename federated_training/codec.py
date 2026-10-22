"""Conversion between PyTorch model deltas and protocol integer vectors."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch


@dataclass(frozen=True)
class StateVectorMetadata:
    float_keys: list[str]
    shapes: dict[str, tuple[int, ...]]
    numels: dict[str, int]


def flatten_delta(
    local_state: dict[str, torch.Tensor],
    global_state: dict[str, torch.Tensor],
) -> tuple[np.ndarray, StateVectorMetadata]:
    keys: list[str] = []
    shapes: dict[str, tuple[int, ...]] = {}
    numels: dict[str, int] = {}
    parts: list[np.ndarray] = []
    for key, global_value in global_state.items():
        if not torch.is_floating_point(global_value):
            continue
        keys.append(key)
        shapes[key] = tuple(global_value.shape)
        numels[key] = int(global_value.numel())
        delta = local_state[key].detach().cpu().to(torch.float64) - global_value.detach().cpu().to(torch.float64)
        parts.append(delta.reshape(-1).numpy())
    vector = np.concatenate(parts).astype(np.float64, copy=False)
    return vector, StateVectorMetadata(keys, shapes, numels)


def apply_delta(
    global_state: dict[str, torch.Tensor],
    delta: np.ndarray,
    metadata: StateVectorMetadata,
) -> dict[str, torch.Tensor]:
    result = {key: value.detach().cpu().clone() for key, value in global_state.items()}
    offset = 0
    for key in metadata.float_keys:
        count = metadata.numels[key]
        values = delta[offset : offset + count]
        if len(values) != count:
            raise ValueError(f"delta is too short while restoring {key}")
        offset += count
        tensor = torch.from_numpy(values.reshape(metadata.shapes[key])).to(global_state[key].dtype)
        result[key] = global_state[key].detach().cpu() + tensor
    if offset != len(delta):
        raise ValueError("delta contains trailing values")
    return result


def quantize_weighted(delta: np.ndarray, samples: int, scale: float) -> np.ndarray:
    weighted = np.rint(delta * float(samples) * float(scale))
    info = np.iinfo(np.int64)
    if np.any(weighted < info.min) or np.any(weighted > info.max):
        raise OverflowError("quantized weighted update does not fit int64")
    return weighted.astype("<i8")


def dequantize_sum(values: np.ndarray, total_samples: int, scale: float) -> np.ndarray:
    if total_samples <= 0:
        raise ValueError("total_samples must be positive")
    return values.astype(np.float64) / (float(total_samples) * float(scale))

