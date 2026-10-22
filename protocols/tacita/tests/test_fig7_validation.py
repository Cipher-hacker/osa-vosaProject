import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
from fig7_validation import VERSION, check_pair, require_validation, sha256
import validate_fig7

class ValidationTests(unittest.TestCase):
    def pair(self):
        sample = dict(correctness="pass",implementation_version=VERSION,mklhts_enabled=False,
            input_soundness=False,ste_share_proofs=True,key_coordinates=8192,seed_bytes=32,
            bound_shares_per_member=1,tag_shares_per_member=1,main_headers_per_client=1,
            main_ciphertexts_per_client=1,server_to_committee_bytes=100,committee_to_server_bytes=50,
            kahe_stage=dict(correctness="pass",profile="fixed-upstream-100k",log_n="13",log_t="168",moduli="test"))
        return [dict(copy.deepcopy(sample),input_vector_len=length) for length in [32,10000]]

    def test_pair_and_reject_structural_mismatches(self):
        check_pair(self.pair())
        for key,value in [("key_coordinates",4096),("main_headers_per_client",512),
                          ("correctness","fail"),("mklhts_enabled",True),("committee_to_server_bytes",999)]:
            pair=self.pair();pair[0][key]=value
            with self.assertRaises(ValueError):check_pair(pair)
        pair=self.pair();pair[0]["kahe_stage"]["log_t"]="56"
        with self.assertRaises(ValueError):check_pair(pair)

    def test_gate_requires_success_and_exact_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/"validation").mkdir()
            binary=root/"binary";bridge=root/"bridge"
            binary.write_bytes(b"test-binary");bridge.write_bytes(b"test-bridge")
            with self.assertRaises(ValueError):require_validation(root,binary,bridge)
            gate=root/"validation/fig7_linux.json"
            gate.write_text(json.dumps(dict(status="passed",implementation=VERSION,
                binary_sha256=sha256(binary),bridge_sha256=sha256(bridge))))
            require_validation(root,binary,bridge)
            bridge.write_bytes(b"changed")
            with self.assertRaises(ValueError):require_validation(root,binary,bridge)

    def test_bridge_failure_prints_real_error_and_keeps_gate_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            marker = "ld.lld: error: relocation R_X86_64_32; recompile with -fPIC"
            def fake_run(argv, **kwargs):
                calls.append(argv)
                if argv[0] == "bash":
                    self.assertEqual(kwargs["env"]["JOBS"], "3")
                    kwargs["stdout"].write(marker + "\n")
                    raise subprocess.CalledProcessError(1, argv)
                return subprocess.CompletedProcess(argv, 0)
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(validate_fig7, "ROOT", root), \
                 patch.object(sys, "platform", "linux"), \
                 patch.object(sys, "argv", ["validate_fig7.py", "--project", str(root), "--threads", "3"]), \
                 patch.object(validate_fig7.subprocess, "run", side_effect=fake_run), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                with self.assertRaises(subprocess.CalledProcessError):
                    validate_fig7.main()
            self.assertEqual(len(calls), 4)
            self.assertIn("running: bash scripts/build_fig7_bridge.sh", stdout.getvalue())
            self.assertIn("bridge-build.log", stdout.getvalue())
            self.assertIn(marker, stderr.getvalue())
            self.assertNotIn("FIG7_END_TO_END_VALIDATION_PASS", stdout.getvalue())
            gate = json.loads((root / "validation/fig7_linux.json").read_text())
            self.assertEqual(gate["status"], "failed")
            log = Path(gate["details"]) / "bridge-build.log"
            self.assertEqual(log.read_text().strip(), marker)

if __name__ == "__main__":unittest.main()
