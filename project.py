#!/usr/bin/env python3
"""Path adapter for unchanged, functionally organized experiment sources."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
KINDS = ('paper', 'computation')


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def contained(root, name):
    relative = PurePosixPath(name)
    if relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name:
        raise ValueError('Unsafe layout path: ' + name)
    path = root.joinpath(*relative.parts)
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Layout path escapes project: ' + name)
    return path


def load_layout(root=ROOT):
    layout = json.loads((root / 'layout.json').read_text(encoding='utf-8'))
    if layout.get('schema') != 1 or set(layout['packages']) != set(KINDS):
        raise ValueError('Unexpected layout schema or experiment packages')
    names = set()
    for package in layout['packages'].values():
        name = package['original_name']
        if len(PurePosixPath(name).parts) != 1:
            raise ValueError('Invalid working directory name')
        contained(root, name)
        if name in names:
            raise ValueError('Duplicate working directory name')
        names.add(name)
        originals = set()
        for record in package['files']:
            contained(root, record['source'])
            contained(root, record['original'])
            if record['original'] in originals:
                raise ValueError('Duplicate original path: ' + record['original'])
            originals.add(record['original'])
    return layout


def verify(root=ROOT):
    layout = load_layout(root)
    checked = {}
    for package in layout['packages'].values():
        for record in package['files']:
            path = contained(root, record['source'])
            actual = checked.setdefault(record['source'], None)
            if actual is None:
                actual = checked[record['source']] = sha(path)
            if actual != record['sha256']:
                raise ValueError('Original file changed: ' + record['source'])
    revision = layout.get('plot_revision', {}).get('id', 'original')
    print(f'SOURCE_HASH_PASS files={len(checked)} plotting_revision={revision}', flush=True)
    return layout


@contextmanager
def layout_lock(work):
    work.mkdir(parents=True, exist_ok=True)
    with (work / 'layout.lock').open('a+b') as handle:
        if os.name == 'nt':
            import msvcrt
            if handle.tell() == 0:
                handle.write(b'0')
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == 'nt':
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def working_paths(layout, root=ROOT):
    return {kind: contained(root / '.work', package['original_name'])
            for kind, package in layout['packages'].items()}


def prepare(root=ROOT):
    layout = verify(root)
    paths = working_paths(layout, root)
    work = root / '.work'
    receipt_path = work / 'layout-receipt.json'
    expected = {'schema': 1, 'layout_sha256': sha(root / 'layout.json'), 'root': str(root.resolve())}
    with layout_lock(work):
        if receipt_path.exists():
            if json.loads(receipt_path.read_text()) != expected:
                raise ValueError('Working directory belongs to another layout/path; use a clean project copy, not an old .work directory')
            # Never overwrite build-generated lockfiles, existing measurements or a live run.
            for kind, package in layout['packages'].items():
                for record in package['files']:
                    if not contained(paths[kind], record['original']).is_file():
                        raise ValueError('Working copy is incomplete: ' + record['original'])
            return paths
        for kind, package in layout['packages'].items():
            for record in package['files']:
                source = contained(root, record['source'])
                target = contained(paths[kind], record['original'])
                if target.exists():
                    if sha(target) != record['sha256']:
                        raise ValueError('Refusing to overwrite an existing working file: ' + str(target))
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                if sha(target) != record['sha256']:
                    raise ValueError('Working copy checksum mismatch: ' + str(target))
        temporary = work / 'layout-receipt.tmp'
        temporary.write_text(json.dumps(expected, indent=2) + '\n', encoding='utf-8')
        temporary.replace(receipt_path)
    print('LAYOUT_READY; protocol, timing and parameters unchanged; plotting revision applied', flush=True)
    return paths


def command(action, args, paths):
    paper, computation = (paths[k] for k in KINDS)
    python = sys.executable if os.name == 'nt' else paper / '.runtime/python/bin/python'
    if action == 'setup':
        return ['bash', paper / 'scripts/setup.sh', *args], paper
    if action == 'build':
        return ['bash', paper / 'scripts/build.sh', *args], paper
    if action in ('paper', 'smoke'):
        return ['bash', paper / 'scripts/run_all.sh', *(['--smoke'] if action == 'smoke' else []), *args], paper
    if action in ('computation-prepare', 'computation'):
        script = 'prepare.sh' if action.endswith('-prepare') else 'run.sh'
        return ['bash', computation / script, paper, *args], computation
    if action == 'plan':
        return [sys.executable, paper / 'scripts/suite.py', 'plan', *args], paper
    if action == 'status':
        if not args or args[0] not in KINDS:
            raise ValueError('status requires paper RUN or computation')
        kind, rest = args[0], args[1:]
        if kind == 'paper':
            if not rest:
                raise ValueError('status paper requires the printed RESULTS directory')
            return ['bash', paper / 'scripts/status.sh', *rest], paper
        if kind == 'computation':
            if rest:
                raise ValueError('status computation does not accept extra arguments')
            return ['bash', computation / 'status.sh', paper], computation
    if action in ('plot', 'verify-run'):
        if len(args) != 2 or args[0] not in KINDS:
            raise ValueError(action + ' requires a kind and absolute RESULTS directory')
        kind, run = args
        if not Path(run).is_absolute():
            raise ValueError('Use an absolute RESULTS directory')
        mode = 'plot' if action == 'plot' else 'verify'
        if kind == 'paper':
            target = paper / 'scripts' / ('plot.py' if mode == 'plot' else 'suite.py')
            return [python, target, *([] if mode == 'plot' else ['verify']), '--run', run], paper
        return [python, paths[kind] / 'runner.py', mode, '--run', run], paths[kind]
    raise ValueError('Unknown action: ' + action)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dry-run', action='store_true', help='Print the unchanged original command without copying or running')
    parser.add_argument('action', choices=('verify', 'prepare', 'paths', 'setup', 'build', 'smoke',
        'paper', 'computation-prepare', 'computation',
        'status', 'plot', 'verify-run', 'plan'))
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.action == 'verify':
        verify()
        return
    if args.action == 'paths':
        print(json.dumps({k: str(v) for k, v in working_paths(load_layout()).items()}, indent=2))
        return
    if args.action == 'prepare':
        if args.dry_run:
            print('Would prepare byte-identical working files; no compiler or experiment is started')
        else:
            prepare()
        return
    layout = verify()
    paths = working_paths(layout)
    argv, cwd = command(args.action, args.arguments, paths)
    argv = list(map(str, argv))
    print('COMMAND=' + shlex.join(argv), flush=True)
    if args.dry_run:
        print('CWD=' + str(cwd), flush=True)
        return
    if os.name == 'nt' and args.action not in ('plot', 'verify-run'):
        raise RuntimeError('Run native experiments on Linux x86_64; verify/prepare/plot/verify-run/dry-run work on Windows')
    prepare()
    os.chdir(cwd)
    if os.name == 'nt':
        raise SystemExit(subprocess.call(argv))
    os.execvp(argv[0], argv)


if __name__ == '__main__':
    main()
