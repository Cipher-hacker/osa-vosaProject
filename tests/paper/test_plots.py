from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import plot
import renderer


class PlotContractTests(unittest.TestCase):
    def test_units_and_metrics(self):
        self.assertTrue(all(m[3] == 1 and "(s)" in m[2] for m in (*plot.TIMES, *plot.VERIFY_TIME)))
        self.assertTrue(all("receive" not in m[0] for m in plot.COMM))
        self.assertTrue(all(m[3] in (1000, 1000000) for m in plot.COMM))

    def test_measured_repeats_required(self):
        with self.assertRaises(ValueError):
            plot.mean_and_sd([dict(repeat=1, value=1), dict(repeat=1, value=2)], "value", 2)
        mean, sd = plot.mean_and_sd([dict(repeat=1, value=1), dict(repeat=2, value=3)], "value", 2)
        self.assertEqual(mean, 2)
        self.assertGreater(sd, 0)

    def test_four_protocols_not_three_or_vosa_substitution(self):
        self.assertEqual(plot.suite.AGG, ("osa", "opa", "willow", "tacita"))
        self.assertEqual(len(set(plot.COLORS)), 4)

    def render_case(self, factors, bars=False, xfield="n_clients", repeats=3):
        xs = [1000] if bars else [100, 200, 400, 600, 800, 1000]
        if xfield == "vector_len":
            xs = [10000, 20000, 40000, 60000, 80000, 100000]
        points = [dict(series=label, x=label if bars else x, value=factor*(1+x/max(xs)),
                       repeats=repeats, sample_sd=999)
                  for label, factor in factors.items() for x in xs]
        spec = dict(name="test_only", labels=list(factors), bars=bars, xfield=xfield,
                    ylabel="Running time (s)", repeats=repeats)
        with tempfile.TemporaryDirectory() as folder:
            with patch("matplotlib.figure.Figure.savefig"):
                info = renderer.draw(points, spec, Path(folder)/"test_only")
        self.assertTrue(info["means_unchanged"])
        self.assertTrue(info["no_errorbars"])
        return info

    def test_tacita_outlier_uses_full_comparison_inset(self):
        info = self.render_case(dict(zip(renderer.LABELS, (1, 8, 20, 1000))))
        self.assertEqual(info["axes"], 2)
        self.assertTrue(info["decorated_inset_inside_main"])
        self.assertFalse(info["data_occlusion"])

    def test_similar_scales_keep_all_four_in_main_axes(self):
        info = self.render_case(dict(zip(renderer.LABELS, (1, 2, 3, 4))))
        self.assertEqual(info["axes"], 1)

    def test_fixed_configuration_bars_can_use_inset(self):
        info = self.render_case(dict(zip(renderer.LABELS, (1, 8, 20, 1000))), bars=True)
        self.assertEqual(info["axes"], 2)

    def test_vector_length_layout_uses_true_values(self):
        self.render_case(dict(zip(renderer.LABELS, (1, 8, 20, 1000))), xfield="vector_len")

    def test_independent_figures_do_not_get_a_tacita_inset(self):
        for labels in (("VOSA", "mPVAS"), ("k = 0%", "k = 10%", "k = 20%", "k = 30%")):
            info = self.render_case({label: i+1 for i, label in enumerate(labels)})
            self.assertEqual(info["axes"], 1)

    def test_renderer_respects_configured_repeats(self):
        self.render_case(dict(zip(renderer.LABELS, (1, 2, 3, 4))), repeats=2)
        with self.assertRaises(ValueError):
            renderer.inspect_data([dict(series="OSA", x=100, value=1, repeats=2)], ["OSA"])


if __name__ == "__main__":
    unittest.main()
