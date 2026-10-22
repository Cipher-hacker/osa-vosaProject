import importlib.util
import json
import math
import os
from pathlib import Path
import statistics
import sys
import tempfile
import unittest
import re
import ast
import shutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import instrument
import runner
from plot_results import points
import dependency_locks


class MeasurementContractTests(unittest.TestCase):
    def lock_workspace(self, folder, original=True):
        base, work = folder / "base", folder / "work"
        for repository in dependency_locks.REPOSITORIES:
            target = work / "project/source" / repository
            target.mkdir(parents=True)
            (target / "MODULE.bazel").write_text('module(name="test_fixture")\n')
            if original:
                source = base / "project/source" / repository
                source.mkdir(parents=True)
                shutil.copyfile(ROOT / "locked_dependencies" / (repository + ".MODULE.bazel.lock"), source / "MODULE.bazel.lock")
        return base, work

    def test_working_snapshots_use_syn2_with_linux_full(self):
        for repository in dependency_locks.REPOSITORIES:
            snapshot = ROOT / "locked_dependencies" / (repository + ".MODULE.bazel.lock")
            profile = dependency_locks.syn_profile(snapshot)
            self.assertTrue(any(p["major"] == 2 and p["full"] for p in profile))
            self.assertFalse(any(p["major"] >= 3 for p in profile))

    def test_dependency_restore_preserves_wrong_lock_and_original(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            base, work = self.lock_workspace(folder)
            before = {}
            for repository in dependency_locks.REPOSITORIES:
                source = base / "project/source" / repository / "MODULE.bazel.lock"
                before[repository] = source.read_bytes()
                (work / "project/source" / repository / "MODULE.bazel.lock").write_text('{"resolver":"incompatible syn 3"}')
            backups = folder / "backups"
            records = dependency_locks.restore(base, work, folder / "records.json", backups)
            dependency_locks.verify(work, records)
            self.assertEqual(len(list(backups.glob("*.lock"))), 2)
            for repository in dependency_locks.REPOSITORIES:
                self.assertEqual((base / "project/source" / repository / "MODULE.bazel.lock").read_bytes(), before[repository])
                self.assertEqual(records[repository]["origin"], "original_package")
            dependency_locks.restore(base, work, folder / "records.json", backups)
            self.assertEqual(len(list(backups.glob("*.lock"))), 2)

    def test_dependency_restore_can_use_bundled_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            base, work = self.lock_workspace(folder, original=False)
            records = dependency_locks.restore(base, work, folder / "records.json", folder / "backups")
            self.assertTrue(all(p["origin"] == "bundled_working_snapshot" for p in records.values()))
            dependency_locks.verify(work, records)

    def test_dependency_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            base, work = self.lock_workspace(folder)
            records = dependency_locks.restore(base, work, folder / "records.json", folder / "backups")
            (work / records[dependency_locks.REPOSITORIES[0]]["target"]).write_text('{"resolver":"changed"}')
            with self.assertRaisesRegex(ValueError, "dependency graph changed"):
                dependency_locks.verify(work, records)

    def test_exact_version_constraints_preserve_existing_features(self):
        base = Path(os.environ["RETEST_TEST_BASE"])
        for repository in dependency_locks.REPOSITORIES:
            module = (base / "project/source" / repository / "MODULE.bazel").read_text()
            snapshot = ROOT / "locked_dependencies" / (repository + ".MODULE.bazel.lock")
            packages = dependency_locks.crate_graph(snapshot)[dependency_locks.APP_EXTENSION]
            fixed = dependency_locks.pinned_specs(module, packages)
            original_specs = {}
            fixed_specs = {}
            for text, target in ((module, original_specs), (fixed, fixed_specs)):
                for node in ast.parse(text).body:
                    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                        continue
                    call = node.value
                    if isinstance(call.func, ast.Attribute) and call.func.attr == "spec":
                        attrs = {k.arg: ast.literal_eval(k.value) for k in call.keywords}
                        target[attrs["package"]] = attrs
            self.assertEqual(set(fixed_specs), set(packages))
            for name, attrs in fixed_specs.items():
                self.assertEqual(attrs["version"], "=" + packages[name]["version"])
                if name in original_specs:
                    self.assertEqual({k: v for k, v in attrs.items() if k != "version"},
                                     {k: v for k, v in original_specs[name].items() if k != "version"})
                else:
                    self.assertFalse(attrs["default_features"])
            self.assertIn('crate_features = ["full"]', fixed)

    def dependency_configuration_fixture(self, folder):
        base = Path(os.environ["RETEST_TEST_BASE"])
        work = folder / "work"
        for repository in dependency_locks.REPOSITORIES:
            directory = work / "project/source" / repository
            directory.mkdir(parents=True)
            for name in ("MODULE.bazel", "BUILD"):
                shutil.copyfile(base / "project/source" / repository / name, directory / name)
        records = dependency_locks.restore(base, work, folder / "records.json", folder / "backups")
        changed = dependency_locks.configure(base, work, records)
        return base, work, records, changed

    def test_snapshot_helper_feature_annotations_match_original_graph(self):
        base = Path(os.environ["RETEST_TEST_BASE"])
        for repository in dependency_locks.REPOSITORIES:
            module = (base / "project/source" / repository / "MODULE.bazel").read_text()
            packages = dependency_locks.crate_graph(ROOT / "locked_dependencies" / (repository + ".MODULE.bazel.lock"))[dependency_locks.APP_EXTENSION]
            annotations = {}
            for node in ast.parse(dependency_locks.pinned_specs(module, packages)).body:
                if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                    continue
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == "annotation":
                    attrs = {k.arg: ast.literal_eval(k.value) for k in call.keywords}
                    annotations[attrs["crate"]] = attrs
            for name in dependency_locks.SNAPSHOT_HELPER_FEATURES:
                self.assertIn(name, packages)
                self.assertEqual(annotations[name]["version"], "=" + packages[name]["version"])
                self.assertEqual(annotations[name]["crate_features"], packages[name]["linux_features"])
            self.assertEqual(annotations["errno"]["crate_features"], ["std"])
            self.assertEqual(annotations["once_cell_polyfill"]["crate_features"], ["default"])
            self.assertIn("Win32_System_Console", annotations["windows-sys"]["crate_features"])

    def test_reported_missing_helper_features_remain_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            _, work, records, _ = self.dependency_configuration_fixture(folder)
            repository = dependency_locks.REPOSITORIES[0]
            target = work / records[repository]["target"]
            data = json.loads(target.read_text())
            restored = target.read_bytes()
            for name in dependency_locks.SNAPSHOT_HELPER_FEATURES:
                changed = json.loads(json.dumps(data))
                found = False
                for result in changed["moduleExtensions"][dependency_locks.APP_EXTENSION].values():
                    for spec in result["generatedRepoSpecs"].values():
                        attrs = spec.get("attributes", {})
                        if attrs.get("strip_prefix", "").startswith(name + "-"):
                            attrs["build_file_content"] = 'rust_library(name="fixture", crate_features=[])\n'
                            found = True
                self.assertTrue(found)
                target.write_text(json.dumps(changed))
                with self.assertRaisesRegex(ValueError, "versions, checksums or Linux features differ"):
                    dependency_locks.capture(work, records, folder / "records.json", repository)
                mismatch = json.loads((folder / ("dependency_resolution_mismatch_" + repository + ".json")).read_text())
                self.assertEqual(mismatch["missing"], [])
                self.assertEqual(mismatch["extra"], [])
                self.assertEqual(set(mismatch["changed"]), {name})
            target.write_bytes(restored)
            dependency_locks.capture(work, records, folder / "records.json", repository)
            dependency_locks.verify(work, records)

    def test_configuration_is_idempotent_and_preserves_originals(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            base, work, records, changed = self.dependency_configuration_fixture(folder)
            self.assertEqual(len(changed), 6)
            self.assertEqual(dependency_locks.configure(base, work, records), [])
            for repository in dependency_locks.REPOSITORIES:
                repo = work / "project/source" / repository
                text = (repo / "MODULE.bazel").read_text()
                self.assertEqual(text.count('patch_args = ["-p1"]'), 1)
                self.assertIn('version = "=2.0.117"', text)
                patch = (repo / dependency_locks.PATCH_NAME).read_text()
                self.assertIn('-    version = ">=2",', patch)
                self.assertIn('+    version = "=2.0.117",', patch)
            instrument.check_base(base)

    def test_native_metadata_can_refresh_without_changing_crates(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            base, work, records, _ = self.dependency_configuration_fixture(folder)
            for repository in dependency_locks.REPOSITORIES:
                target = work / records[repository]["target"]
                data = json.loads(target.read_text())
                for result in data["moduleExtensions"][dependency_locks.APP_EXTENSION].values():
                    result["usagesDigest"] = "test-host-refreshed-metadata"
                target.write_text(json.dumps(data))
                dependency_locks.capture(work, records, folder / "records.json", repository)
            dependency_locks.verify(work, records)
            self.assertTrue(all(r["resolution"] == "native_analysis_validated" for r in records.values()))
            instrument.check_base(base)

    def test_native_resolution_rejects_crate_version_or_feature_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            _, work, records, _ = self.dependency_configuration_fixture(folder)
            repository = dependency_locks.REPOSITORIES[0]
            target = work / records[repository]["target"]
            text = target.read_text()
            for before, after in (("syn-2.0.117", "syn-3.0.9"), ('\\"alloc\\"', '\\"unexpected_feature\\"')):
                self.assertIn(before, text)
                target.write_text(text.replace(before, after))
                with self.assertRaisesRegex(ValueError, "versions, checksums or Linux features differ"):
                    dependency_locks.capture(work, records, folder / "records.json", repository)

    def test_changed_patch_configuration_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            _, work, records, _ = self.dependency_configuration_fixture(folder)
            dependency_locks.verify(work, records)
            record = records[dependency_locks.REPOSITORIES[0]]
            patch = next(name for name in record["config_files"] if name.endswith(".patch"))
            (work / patch).write_text("changed")
            with self.assertRaisesRegex(ValueError, "pin configuration changed"):
                dependency_locks.verify(work, records)

    def test_explicit_root_resolves_compact_osa_shared_source(self):
        original = '''rust_binary(
    name = "run_osa_compact_seeded_unified",
    srcs = ["run_osa_full_unified.rs", "client_timing.rs"],
)
'''
        fixed = instrument.add_crate_roots(original, {"run_osa_compact_seeded_unified": "run_osa_full_unified.rs"})
        attrs = {k.arg: ast.literal_eval(k.value) for k in ast.parse(fixed).body[0].value.keywords}
        self.assertEqual(attrs["crate_root"], "run_osa_full_unified.rs")
        self.assertIn(attrs["crate_root"], attrs["srcs"])
        self.assertEqual(instrument.add_crate_roots(fixed, {attrs["name"]: attrs["crate_root"]}), fixed)

    def test_conflicting_crate_root_is_not_silently_overwritten(self):
        text = '''rust_binary(
    name = "kahe_stage",
    crate_root = "wrong.rs",
    srcs = ["kahe_stage.rs", "client_timing.rs"],
)
'''
        with self.assertRaisesRegex(ValueError, "Conflicting crate_root"):
            instrument.add_crate_roots(text, {"kahe_stage": "kahe_stage.rs"})

    def test_every_instrumented_target_has_a_valid_explicit_root(self):
        base = Path(os.environ["RETEST_TEST_BASE"])
        for relative, targets in instrument.CRATE_ROOTS.items():
            original = (base / relative).read_text()
            fixed = instrument.add_crate_roots(original, targets)
            for node in ast.parse(fixed).body:
                if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
                    continue
                call = node.value
                if not isinstance(call.func, ast.Name) or call.func.id != "rust_binary":
                    continue
                attrs = {k.arg: k.value for k in call.keywords}
                name = ast.literal_eval(attrs["name"])
                if name in targets:
                    self.assertEqual(ast.literal_eval(attrs["crate_root"]), targets[name])
                    self.assertIn(targets[name], ast.literal_eval(attrs["srcs"]))

    def write_timing_fixture(self, folder, stage, value):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / (stage + ".json")).write_text(json.dumps(dict(schema="serial-client-timing-v1", stage=stage,
            warmup_s=[9, 8, 7], samples_s=[value] * 20, mean_s=value, serial=True, setup_included=False)))

    def test_raw_protocol_metrics_match_samples_without_changing_communication(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for protocol in runner.PROTOCOLS:
                attempt = root / protocol
                attempt.mkdir()
                job = runner.S.Job(protocol, 1000, 800, 50, 10000, 1)
                if protocol == "tacita":
                    raw = json.loads((ROOT / "support/fixtures/tacita.json").read_text())
                    raw["client_compute_s"] = .1 + .2
                    (attempt / "ste").mkdir()
                    (attempt / "ste/metrics.json").write_text(json.dumps(raw))
                    self.write_timing_fixture(attempt / "client_samples", "ste", .1)
                    self.write_timing_fixture(attempt / "client_samples", "kahe", .2)
                else:
                    text = (ROOT / "support/fixtures" / (protocol + ".log")).read_text()
                    text = re.sub(r"client_compute_s=[0-9.]+", "client_compute_s=0.123456", text)
                    (attempt / "process.log").write_text(text)
                    self.write_timing_fixture(attempt / "client_samples", "native", .123456)
                row = runner.normalize(attempt, job, runner.config(), "test-only-fixture", 1.0, False)
                self.assertTrue(math.isclose(row["client_compute_s"], .3 if protocol == "tacita" else .123456))
                reference = json.loads((ROOT / "communication_reference.json").read_text())[protocol + "_A800"]
                self.assertEqual(row["total_bytes"], reference["total_bytes"])

    def test_evidence_tampering_is_rejected_before_plotting(self):
        with tempfile.TemporaryDirectory() as folder:
            run = Path(folder)
            job = runner.S.Job("osa", 1000, 800, 50, 10000, 1)
            runner.S.write_json(run / "manifest.json", dict(contract=dict(config=runner.config(), smoke=False, host=dict(host="test"))))
            attempt = run / "raw" / job.id / "attempt_test"
            attempt.mkdir(parents=True)
            file = attempt / "evidence.txt"
            file.write_text("original")
            runner.S.write_json(attempt.parent / "status.json", dict(status="completed", attempt=attempt.name,
                evidence_sha256=runner.evidence(attempt), driver_wall_s=1))
            file.write_text("tampered")
            with self.assertRaisesRegex(ValueError, "raw evidence hashes"):
                runner.verify_case(run, job)

    def test_formal_plan_has_three_independent_runs_per_configuration(self):
        jobs = runner.plan()
        self.assertEqual(len(jobs), 48)
        self.assertEqual(len({j.id for j in jobs}), 48)
        for p in runner.PROTOCOLS:
            for active in (900, 800, 700, 600):
                group = [j for j in jobs if j.protocol == p and j.active == active]
                self.assertEqual([j.repeat for j in group], [1, 2, 3])
                self.assertTrue(all(j.n == 1000 and j.m == 50 and j.length == 10000 for j in group))

    def test_warmups_are_not_used_in_the_client_mean(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "samples.json"
            record = dict(schema="serial-client-timing-v1", stage="native", warmup_s=[9, 8, 7],
                samples_s=[.1] * 20, mean_s=.1, serial=True, setup_included=False)
            path.write_text(json.dumps(record))
            result = runner.load_timing(path, "native", runner.config())
            self.assertEqual(result["mean_s"], .1)
            record["mean_s"] = statistics.mean(record["warmup_s"] + record["samples_s"])
            path.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                runner.load_timing(path, "native", runner.config())

    def test_missing_sample_and_parallel_sample_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "samples.json"
            record = dict(schema="serial-client-timing-v1", stage="native", warmup_s=[1] * 3,
                samples_s=[.1] * 19, mean_s=.1, serial=True, setup_included=False)
            path.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                runner.load_timing(path, "native", runner.config())
            record.update(samples_s=[.1] * 20, serial=False)
            path.write_text(json.dumps(record))
            with self.assertRaises(ValueError):
                runner.load_timing(path, "native", runner.config())

    def test_plot_preserves_run_means_and_requires_complete_coverage(self):
        rows = [dict(protocol=j.protocol, dropout_percent=100*(j.n-j.active)/j.n, repeat=j.repeat,
            job_id=j.id, client_compute_s=j.repeat*.2) for j in runner.plan()]
        summary = points(rows, "client_compute_s")
        self.assertEqual(len(summary), 16)
        self.assertTrue(all(math.isclose(p["value"], .4) and p["repeats"] == 3 for p in summary))
        with self.assertRaises(ValueError):
            points(rows[:-1], "client_compute_s")

    def test_original_full_aggregation_remains_unchanged(self):
        base = Path(os.environ["RETEST_TEST_BASE"])
        cases = {
            "osa": "project/source/secure-aggregation-main/willow/benches/run_osa_full_unified.rs",
            "opa": "project/source/opa-secure-aggregation/opa/bench_opalwr_common.rs",
            "willow": "project/source/secure-aggregation-main/willow/benches/run_willow_paper_full_unified.rs",
        }
        for label, file in cases.items():
            original = (base / file).read_text()
            changed = instrument.instrument_source(label, original)
            start = "    let online_start = Instant::now();\n"
            self.assertEqual(original[original.index(start):], changed[changed.index(start):], label)
            self.assertIn("client_timing.mean_s()", changed)
        text = (base / "tacita/src/fig7_benchmark.rs").read_text()
        changed = instrument.instrument_source("ste", text)
        start = '        eprintln!("[fig7] client batch starting; setup_s={setup_s:.3}");'
        self.assertEqual(text[text.index(start):], changed[changed.index(start):])
        text = (base / "tacita/bridge/kahe_stage.rs").read_text()
        changed = instrument.instrument_source("kahe", text)
        start, end = "    let mut messages = Vec::new();", '    println!("ready '
        self.assertEqual(text[text.index(start):text.index(end)], changed[changed.index(start):changed.index(end)])

    def test_opa_nested_module_path_is_explicit(self):
        base = Path(os.environ["RETEST_TEST_BASE"])
        text = (base / "project/source/opa-secure-aggregation/opa/bench_opalwr_common.rs").read_text()
        changed = instrument.instrument_source("opa", text)
        self.assertTrue(changed.startswith('#[path = "client_timing.rs"]'))

    def test_package_and_original_sources_match_recorded_hashes(self):
        runner.check_package()
        instrument.check_base(Path(os.environ["RETEST_TEST_BASE"]))


if __name__ == "__main__":
    unittest.main()
