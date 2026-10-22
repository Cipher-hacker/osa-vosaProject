from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import numpy as np
import torch

from federated_training.codec import apply_delta, dequantize_sum, flatten_delta, quantize_weighted
from federated_training.config import ExperimentConfig
from federated_training.data import build_schedule, schedule_hash
from federated_training.models import build_model, model_vector_length
from federated_training.protocol_bridge import aggregate_quantized_plain, limb_count_for_bound


class CoreTests(unittest.TestCase):
    def test_default_config_and_schedule_are_deterministic(self) -> None:
        config = ExperimentConfig(dataset="mnist", model="lenet5")
        config.validate()
        first = build_schedule(config.seed, 3, config.num_clients, config.active_clients)
        second = build_schedule(config.seed, 3, config.num_clients, config.active_clients)
        self.assertEqual(schedule_hash(first), schedule_hash(second))
        self.assertEqual(len(first[0]), 800)

    def test_state_delta_roundtrip(self) -> None:
        model = build_model("mnist", "lenet5")
        global_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
        local_state = {key: value.detach().cpu().clone() for key, value in global_state.items()}
        for key, value in local_state.items():
            if torch.is_floating_point(value):
                local_state[key] = value + 0.125
        delta, metadata = flatten_delta(local_state, global_state)
        restored = apply_delta(global_state, delta, metadata)
        for key in metadata.float_keys:
            self.assertTrue(torch.allclose(restored[key], local_state[key]))
        self.assertEqual(delta.size, model_vector_length(model))

    def test_quantized_plain_sum(self) -> None:
        matrix = np.asarray([[1, -2, 3], [4, 5, -6]], dtype="<i8")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "matrix.i64le"
            matrix.tofile(path)
            aggregate, metrics = aggregate_quantized_plain(path, matrix.shape)
        np.testing.assert_array_equal(aggregate, np.asarray([5, 3, -3]))
        self.assertEqual(metrics["max_abs_sum_error"], 0)

    def test_quantization_and_limb_count(self) -> None:
        quantized = quantize_weighted(np.asarray([0.1, -0.1]), 60, 1_000_000.0)
        restored = dequantize_sum(quantized, 60, 1_000_000.0)
        np.testing.assert_allclose(restored, np.asarray([0.1, -0.1]))
        self.assertEqual(limb_count_for_bound(6_000_000), 1)


if __name__ == "__main__":
    unittest.main()
