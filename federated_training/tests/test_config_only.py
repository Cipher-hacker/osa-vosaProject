from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATCHED_KEYS = {
    "num_clients": 1000,
    "active_clients": 800,
    "rounds": 300,
    "data_split": "iid",
    "local_epochs": 1,
    "batch_size": 32,
    "test_batch_size": 256,
    "learning_rate": 0.01,
    "momentum": 0.9,
    "seed": 2026,
    "quant_scale": 1_000_000.0,
    "clip_value": 0.1,
    "committee_size": 50,
    "reconstruction_threshold": 40,
    "opa_reconstruction_threshold": 34,
    "rss_secret_dim": 30,
    "rng_mode": "os_rng_security",
}


class ConfigOnlyTests(unittest.TestCase):
    def test_dataset_configs_share_the_fairness_boundary(self) -> None:
        paths = [
            ROOT / "configs" / "mnist_lenet5.json",
            ROOT / "configs" / "cifar10_alexnet_bn.json",
        ]
        configs = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
        for key, expected in MATCHED_KEYS.items():
            self.assertEqual(configs[0][key], expected, key)
            self.assertEqual(configs[1][key], expected, key)
        self.assertEqual((configs[0]["dataset"], configs[0]["model"]), ("mnist", "lenet5"))
        self.assertEqual((configs[1]["dataset"], configs[1]["model"]), ("cifar10", "alexnet_bn"))


if __name__ == "__main__":
    unittest.main()
