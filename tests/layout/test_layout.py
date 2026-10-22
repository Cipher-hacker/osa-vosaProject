import importlib.util
import csv
import json
from pathlib import Path, PurePosixPath
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import project


class LayoutTests(unittest.TestCase):
    def small_project(self, root):
        content = root / 'experiments/shared.py'
        content.parent.mkdir()
        content.write_bytes(b'original experiment source\n')
        entry = {'original': 'scripts/runner.py', 'source': 'experiments/shared.py', 'sha256': project.sha(content)}
        layout = {'schema': 1, 'packages': {k: {'original_name': k, 'files': [dict(entry)]} for k in project.KINDS}}
        (root / 'layout.json').write_text(json.dumps(layout))
        return layout

    def test_all_original_sources_and_manifests(self):
        layout = project.verify(ROOT)
        paper = {r['original']: r for r in layout['packages']['paper']['files']}
        for kind, package in layout['packages'].items():
            records = {r['original']: r for r in package['files']}
            manifest = json.loads((ROOT / records['package_manifest.json']['source']).read_text(encoding='utf-8'))
            for name, expected in manifest['files'].items():
                self.assertIn(name, records)
                self.assertEqual(records[name]['sha256'], expected, (kind, name))
            if kind != 'paper':
                base = json.loads((ROOT / records['base_files.json']['source']).read_text(encoding='utf-8'))
                for name, expected in base['files'].items():
                    self.assertEqual(paper[name]['sha256'], expected)

    def test_expected_shared_files_are_deduplicated(self):
        layout = project.load_layout(ROOT)
        selected = []
        for kind, package in layout['packages'].items():
            original = 'scripts/suite.py' if kind == 'paper' else 'support/suite.py'
            selected.append(next(r['source'] for r in package['files'] if r['original'] == original))
        self.assertEqual(len(set(selected)), 1)

    def test_tacita_keeps_original_parallel_pool(self):
        text = (ROOT / 'protocols/tacita/src/fig7_benchmark.rs').read_text()
        self.assertIn('.num_threads(config.threads)', text)
        self.assertNotIn('role_threads', text)
        self.assertNotIn('let client_pool', text)

    def test_preparation_copies_exact_bytes_and_does_not_overwrite_build_state(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.small_project(root)
            paths = project.prepare(root)
            copied = paths['paper'] / 'scripts/runner.py'
            self.assertEqual(copied.read_bytes(), (root / 'experiments/shared.py').read_bytes())
            copied.write_bytes(b'existing build-generated content')
            result = paths['paper'] / 'runs/retained.json'
            result.parent.mkdir()
            result.write_text('do not overwrite')
            project.prepare(root)
            self.assertEqual(copied.read_bytes(), b'existing build-generated content')
            self.assertEqual(result.read_text(), 'do not overwrite')

    def test_preparation_rejects_changed_source(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.small_project(root)
            (root / 'experiments/shared.py').write_text('changed source')
            with self.assertRaisesRegex(ValueError, 'Original file changed'):
                project.prepare(root)

    def test_preparation_rejects_collision_and_missing_work_file(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            layout = self.small_project(root)
            file = project.working_paths(layout, root)['paper'] / 'scripts/runner.py'
            file.parent.mkdir(parents=True)
            file.write_text('unrelated file')
            with self.assertRaisesRegex(ValueError, 'Refusing to overwrite'):
                project.prepare(root)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.small_project(root)
            paths = project.prepare(root)
            (paths['paper'] / 'scripts/runner.py').unlink()
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                project.prepare(root)

    def test_path_traversal_is_rejected(self):
        for name in ('../escape', '/absolute', 'C:/absolute', 'a\\..\\escape'):
            with self.assertRaises(ValueError):
                project.contained(ROOT, name)

    def test_original_run_commands_preserve_arguments_and_pass_base(self):
        paths = {k: PurePosixPath('/example') / k for k in project.KINDS}
        cmd, cwd = project.command('paper', ['--scope', 'aggregation', '--resume', '/results'], paths)
        self.assertEqual(list(map(str, cmd)), ['bash', '/example/paper/scripts/run_all.sh', '--scope', 'aggregation', '--resume', '/results'])
        for kind in ('computation',):
            cmd, cwd = project.command(kind, ['--resume', '/results'], paths)
            self.assertEqual(list(map(str, cmd)), ['bash', f'/example/{kind}/run.sh', '/example/paper', '--resume', '/results'])
            self.assertEqual(cwd, paths[kind])
            cmd, _ = project.command(kind + '-prepare', [], paths)
            self.assertEqual(list(map(str, cmd)), ['bash', f'/example/{kind}/prepare.sh', '/example/paper'])

    def test_setup_build_and_smoke_delegate_to_original_scripts(self):
        paths = {k: PurePosixPath('/example') / k for k in project.KINDS}
        for action, script in (('setup', 'setup.sh'), ('build', 'build.sh')):
            cmd, _ = project.command(action, [], paths)
            self.assertEqual(list(map(str, cmd)), ['bash', '/example/paper/scripts/' + script])
        cmd, _ = project.command('smoke', [], paths)
        self.assertEqual(list(map(str, cmd)), ['bash', '/example/paper/scripts/run_all.sh', '--smoke'])

    def test_old_experiment_counts_are_preserved(self):
        path = ROOT / 'experiments/shared/paper_suite.py'
        spec = importlib.util.spec_from_file_location('original_suite_for_layout_test', path)
        suite = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = suite
        spec.loader.exec_module(suite)
        config = json.loads((ROOT / 'config/paper.json').read_text())
        jobs = suite.plan(config)
        self.assertEqual(len(jobs), 336)
        self.assertEqual({j.length for j in jobs}, {10000, 20000, 40000, 60000, 80000, 100000})
        self.assertEqual(len(suite.plan(config, smoke=True)), 6)

    def test_obsolete_dropout_entry_and_files_are_removed(self):
        self.assertEqual(set(project.KINDS), {'paper', 'computation'})
        paths = {k: PurePosixPath('/example') / k for k in project.KINDS}
        for action in ('dropout', 'dropout-prepare'):
            with self.assertRaisesRegex(ValueError, 'Unknown action'):
                project.command(action, [], paths)
        for action in ('status', 'plot', 'verify-run'):
            with self.assertRaises(ValueError):
                project.command(action, ['dropout', str(ROOT)], paths)
        for name in ('experiments/dropout.py', 'config/dropout.json', 'plotting/dropout.py',
                     'manifests/dropout.json', 'scripts/run/dropout.sh',
                     'scripts/build/dropout_prepare.sh'):
            self.assertFalse((ROOT / name).exists(), name)
        for name in ('tests/dropout', 'docs/dropout'):
            self.assertFalse(any(p.is_file() for p in (ROOT / name).rglob('*')), name)

    def test_computation_keeps_warmup_and_sampling(self):
        layout = project.load_layout(ROOT)
        records = {r['original']: r for r in layout['packages']['computation']['files']}
        text = (ROOT / records['runner.py']['source']).read_text()
        self.assertIn('client_warmup=1 if smoke else 3', text)
        self.assertIn('client_samples=2 if smoke else 20', text)
        self.assertIn('1000, 1000-10*dropout, 50, 10000, repeat', text)

    def test_release_keeps_original_32_thread_settings(self):
        config = json.loads((ROOT / 'config/paper.json').read_text())
        self.assertEqual(config['threads'], 32)
        self.assertEqual(config['repeats'], 3)
        environment = (ROOT / 'scripts/environment/paper_env.sh').read_text()
        self.assertIn('export OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1', environment)
        self.assertIn('if (( JOBS > 32 )); then JOBS=32; fi', environment)
        computation = (ROOT / 'experiments/computation.py').read_text()
        self.assertIn('threads=32, repeats=1 if smoke else 3', computation)

    def test_bundled_history_contains_complete_formal_records(self):
        for kind, count in (('paper', 336), ('computation', 48)):
            run = ROOT / 'data' / kind
            with (run / 'measurements.csv').open(encoding='utf-8-sig', newline='') as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), count)
            self.assertEqual(len({r['job_id'] for r in rows}), count)
            self.assertEqual({int(r['threads']) for r in rows}, {32})
            self.assertTrue((run / 'manifest.json').is_file())
            self.assertTrue((run / 'raw').is_dir())

    def test_revision_only_changes_plotting_tests_and_inventories(self):
        layout = project.load_layout(ROOT)
        allowed = {'plotting/paper.py', 'plotting/renderer.py', 'tests/paper/test_plots.py',
                   'manifests/paper.json', 'manifests/computation.json', 'manifests/base_files.json'}
        changed = {r['source'] for p in layout['packages'].values() for r in p['files']
                   if 'original_sha256' in r or 'added_for' in r}
        self.assertEqual(changed, allowed)
        for p in layout['packages'].values():
            for r in p['files']:
                if r['source'].startswith(('protocols/', 'experiments/', 'scripts/build/', 'scripts/run/')):
                    self.assertNotIn('original_sha256', r)
        paper = layout['packages']['paper']['files']
        self.assertIn('scripts/renderer.py', [r['original'] for r in paper])

    @unittest.skipUnless(project.os.name == 'nt', 'Windows plotting entry point')
    def test_windows_plot_waits_and_propagates_exit_status(self):
        layout = project.load_layout(ROOT)
        argv = [sys.executable, 'plot.py', '--run', str(ROOT)]
        with patch.object(sys, 'argv', ['project.py', 'plot', 'paper', str(ROOT)]), \
             patch.object(project, 'verify', return_value=layout), \
             patch.object(project, 'prepare') as prepare, \
             patch.object(project, 'command', return_value=(argv, ROOT)), \
             patch.object(project.os, 'chdir'), \
             patch.object(project.subprocess, 'call', return_value=7) as call, \
             patch.object(project.os, 'execvp') as execvp:
            with self.assertRaises(SystemExit) as result:
                project.main()
            self.assertEqual(result.exception.code, 7)
            prepare.assert_called_once_with()
            call.assert_called_once_with(argv)
            execvp.assert_not_called()


if __name__ == '__main__':
    unittest.main()
