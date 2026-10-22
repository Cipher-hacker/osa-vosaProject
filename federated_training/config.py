"""Typed experiment configuration shared by all aggregation backends."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from pathlib import Path


@dataclass(frozen=True)
class ExperimentConfig:
    dataset: str
    model: str
    num_clients: int = 1000
    active_clients: int = 800
    rounds: int = 300
    data_split: str = "iid"
    local_epochs: int = 1
    batch_size: int = 32
    test_batch_size: int = 256
    learning_rate: float = 0.01
    momentum: float = 0.9
    weight_decay: float = 0.0
    seed: int = 2026
    num_workers: int = 0
    quant_scale: float = 1_000_000.0
    clip_value: float = 0.1
    committee_size: int = 50
    reconstruction_threshold: int = 40
    opa_reconstruction_threshold: int = 34
    rss_secret_dim: int = 30
    protocol_chunk_size: int = 4096
    opa_chunk_size: int = 64
    rng_mode: str = "os_rng_security"
    checkpoint_every: int = 1
    keep_bridge_artifacts: bool = False

    @classmethod
    def load(cls, path: Path) -> "ExperimentConfig":
        values = json.loads(path.read_text(encoding="utf-8"))
        config = cls(**values)
        config.validate()
        return config

    def validate(self) -> None:
        if (self.dataset.lower(), self.model.lower()) not in {
            ("mnist", "lenet5"),
            ("mnist", "mlp"),
            ("cifar10", "alexnet_bn"),
            ("cifar10", "alexnet"),
            ("cifar10", "lenet5_paper"),
        }:
            raise ValueError(f"unsupported dataset/model pair: {self.dataset}/{self.model}")
        if not 0 < self.active_clients <= self.num_clients:
            raise ValueError("active_clients must be in 1..num_clients")
        for name in ("rounds", "local_epochs", "batch_size", "test_batch_size"):
            if int(getattr(self, name)) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.learning_rate <= 0 or self.quant_scale <= 0 or self.clip_value <= 0:
            raise ValueError("learning_rate, quant_scale, and clip_value must be positive")
        if not 0 < self.reconstruction_threshold <= self.committee_size:
            raise ValueError("reconstruction_threshold must be in 1..committee_size")
        if self.opa_reconstruction_threshold != 34 or self.committee_size != 50:
            raise ValueError("the packaged OPA-FL target fixes committee_size=50 and threshold=34")
        if not 0 < self.rss_secret_dim < self.reconstruction_threshold:
            raise ValueError("rss_secret_dim must be in 1..reconstruction_threshold-1")
        if self.protocol_chunk_size <= 0 or self.opa_chunk_size <= 0:
            raise ValueError("protocol chunk sizes must be positive")
        if self.rng_mode not in {"deterministic_benchmark", "os_rng_security"}:
            raise ValueError("unsupported rng_mode")

    def with_overrides(self, *, rounds: int | None = None) -> "ExperimentConfig":
        config = replace(self, rounds=self.rounds if rounds is None else rounds)
        config.validate()
        return config

    def canonical_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2, sort_keys=True) + "\n", encoding="utf-8")
