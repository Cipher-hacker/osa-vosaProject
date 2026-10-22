"""Dataset loading, partitioning, and deterministic client schedules."""

from __future__ import annotations

import hashlib
import random
from pathlib import Path

import numpy as np
from torchvision import datasets, transforms


def load_datasets(data_root: Path, dataset: str, download: bool):
    dataset = dataset.lower()
    if dataset == "mnist":
        transform = transforms.Compose(
            [transforms.ToTensor(), transforms.Normalize((0.1307,), (0.3081,))]
        )
        train = datasets.MNIST(str(data_root), train=True, transform=transform, download=download)
        test = datasets.MNIST(str(data_root), train=False, transform=transform, download=download)
        return train, test
    if dataset == "cifar10":
        train_transform = transforms.Compose(
            [
                transforms.RandomCrop(32, padding=4),
                transforms.RandomHorizontalFlip(),
                transforms.ToTensor(),
                transforms.Normalize((0.4914, 0.4822, 0.4465), (0.2023, 0.1994, 0.2010)),
            ]
        )
        test_transform = transforms.Compose(
            [
                transforms.ToTensor(),
                transforms.Normalize((0.4914, 0.4822, 0.4465), (0.2023, 0.1994, 0.2010)),
            ]
        )
        train = datasets.CIFAR10(str(data_root), train=True, transform=train_transform, download=download)
        test = datasets.CIFAR10(str(data_root), train=False, transform=test_transform, download=download)
        return train, test
    raise ValueError(f"unsupported dataset: {dataset}")


def partition_indices(dataset, num_clients: int, split: str, seed: int) -> list[list[int]]:
    if num_clients <= 0:
        raise ValueError("num_clients must be positive")
    rng = np.random.default_rng(seed)
    all_indices = np.arange(len(dataset))
    if split == "iid":
        rng.shuffle(all_indices)
        return [chunk.tolist() for chunk in np.array_split(all_indices, num_clients)]
    if split.startswith("dirichlet_alpha_"):
        alpha = float(split.removeprefix("dirichlet_alpha_"))
        if alpha <= 0:
            raise ValueError("Dirichlet alpha must be positive")
        targets = np.asarray(dataset.targets)
        bins: list[list[int]] = [[] for _ in range(num_clients)]
        for class_id in np.unique(targets):
            class_indices = all_indices[targets == class_id]
            rng.shuffle(class_indices)
            proportions = rng.dirichlet(np.full(num_clients, alpha))
            boundaries = (np.cumsum(proportions) * len(class_indices)).astype(int)
            for client_id, chunk in enumerate(np.split(class_indices, boundaries[:-1])):
                bins[client_id].extend(chunk.tolist())
        for chunk in bins:
            rng.shuffle(chunk)
        return bins
    raise ValueError(f"unsupported data split: {split}")


def build_schedule(seed: int, rounds: int, num_clients: int, active_clients: int) -> list[list[int]]:
    if not 0 < active_clients <= num_clients:
        raise ValueError("active_clients must be in 1..num_clients")
    rng = random.Random(seed + 17)
    return [rng.sample(range(num_clients), active_clients) for _ in range(rounds)]


def schedule_hash(schedule: list[list[int]]) -> str:
    digest = hashlib.sha256()
    for selected in schedule:
        for client_id in selected:
            digest.update(int(client_id).to_bytes(8, "little", signed=False))
        digest.update(b"|")
    return digest.hexdigest()

