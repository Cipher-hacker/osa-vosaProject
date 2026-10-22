"""Launcher tests with a fake build tool; these do NOT validate KAHE compilation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = os.environ.get("FIG7_TEST_BASH") or shutil.which("bash")
STUB = """#!/usr/bin/env bash
set -eu
printf '%s\\n' "$0" > "$FIG7_TEST_TOOL_LOG"
printf '%s\\n' "$@" > "$FIG7_TEST_ARGS_LOG"
mkdir -p bazel-bin/tacita_ste_bridge_fig7_v2
printf 'launcher-test-only' > bazel-bin/tacita_ste_bridge_fig7_v2/kahe_stage
"""

@unittest.skipUnless(BASH, "Bash required for launcher tests")
class BridgeLauncherTests(unittest.TestCase):
    def run_launcher(self, explicit=False, missing=False, overrides=False, archives=True):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            root = temp / "tacita"
            project = temp / "original project"
            (root / "scripts").mkdir(parents=True)
            (root / "bridge").mkdir()
            (project / "third_party").mkdir(parents=True)
            (project / "source/secure-aggregation-main").mkdir(parents=True)
            if archives:
                (project / "third_party/bazel-distdir").mkdir()
                (project / "rust_mirror.cfg").write_text("# launcher fixture\n", encoding="utf-8")
            script = root / "scripts/build_fig7_bridge.sh"
            shutil.copyfile(ROOT / "scripts/build_fig7_bridge.sh", script)
            for name in ["BUILD", "kahe_stage.rs"]:
                (root / "bridge" / name).write_text("launcher-test-fixture\n", encoding="utf-8")
            bundled = project / "third_party/bazel-8.1.1-linux-x86_64"
            bundled.write_text(STUB, encoding="utf-8", newline="\n")
            env = os.environ.copy()
            for key in ["BAZEL", "BAZEL_CACHE_ROOT", "BAZEL_USER_ROOT", "BAZEL_REPOSITORY_CACHE", "DISTDIR", "JOBS"]:
                env.pop(key, None)
            env["FIG7_TEST_TOOL_LOG"] = (temp / "tool.log").as_posix()
            env["FIG7_TEST_ARGS_LOG"] = (temp / "args.log").as_posix()
            if overrides:
                # Ask Bash for its path spelling (including MSYS mounts).
                prefix = subprocess.check_output([BASH, "-c", "pwd"], cwd=temp,
                                                 env=env, text=True, encoding="utf-8").strip()
                for key, name in [("BAZEL_CACHE_ROOT", "selected cache"),
                                  ("BAZEL_USER_ROOT", "selected user root"),
                                  ("BAZEL_REPOSITORY_CACHE", "selected repository cache"),
                                  ("DISTDIR", "selected archives")]:
                    path = temp / name
                    path.mkdir()
                    env[key] = prefix + "/" + name
                env["JOBS"] = "7"
            if explicit:
                override = temp / "selected-bazel"
                if not missing:
                    override.write_text(STUB, encoding="utf-8", newline="\n")
                    override.chmod(0o755)
                env["BAZEL"] = override.as_posix()
            result = subprocess.run([BASH, script.as_posix(), project.as_posix()],
                                    env=env, text=True, encoding="utf-8", errors="replace", capture_output=True)
            if missing:
                self.assertEqual(result.returncode, 127)
                self.assertIn("Bazel not found", result.stderr)
                self.assertFalse((root / "bin/kahe_stage_fig7_v2").exists())
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                selected = (temp / "tool.log").read_text().strip()
                self.assertTrue(selected.endswith("selected-bazel" if explicit else bundled.name))
                self.assertEqual((root / "bin/kahe_stage_fig7_v2").read_text(), "launcher-test-only")
                # Git Bash rewrites path prefixes on Windows; suffixes still test
                # spaces, option boundaries and which directory was selected.
                args = (temp / "args.log").read_text().splitlines()
                def option(name, suffix):
                    values = [arg for arg in args if arg.startswith(name + "=")]
                    self.assertEqual(len(values), 1, args)
                    self.assertTrue(values[0].replace("\\", "/").endswith(suffix), values)
                option("--output_user_root", "/selected user root" if overrides else "/tacita/.runtime/bazel-cache")
                option("--repository_cache", "/selected repository cache" if overrides else "/tacita/.runtime/bazel-cache/repository-cache")
                self.assertIn("--jobs=7" if overrides else "--jobs=32", args)
                self.assertIn("--force_pic", args)
                self.assertNotIn("--noforce_pic", args)
                self.assertFalse(any("no-pie" in arg for arg in args))
                if archives or overrides:
                    option("--distdir", "/selected archives" if overrides else "/original project/third_party/bazel-distdir")
                else:
                    self.assertFalse(any(arg.startswith("--distdir=") for arg in args))
                    self.assertIn("dependency archive directory missing", result.stderr)
                if archives:
                    option("--experimental_downloader_config", "/original project/rust_mirror.cfg")
                else:
                    self.assertFalse(any(arg.startswith("--experimental_downloader_config=") for arg in args))

    def test_uses_project_bundled_bazel(self):
        self.run_launcher()

    def test_respects_explicit_bazel(self):
        self.run_launcher(explicit=True)

    def test_missing_explicit_bazel_fails_before_build(self):
        self.run_launcher(explicit=True, missing=True)

    def test_respects_cache_and_archive_overrides(self):
        self.run_launcher(overrides=True)

    def test_missing_optional_archives_warns_without_invalid_flags(self):
        self.run_launcher(archives=False)

if __name__ == "__main__":
    unittest.main()
