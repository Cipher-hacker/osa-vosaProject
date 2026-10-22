from pathlib import Path
import copy
import json
import os
import sys
import tempfile
import unittest
from contextlib import nullcontext, redirect_stdout
import io
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import suite

ROOT = Path(__file__).resolve().parents[1]


def fixture(protocol, job=None):
    job = job or suite.Job(protocol, 1000, 800, 50, 10000, 1)
    raw = dict(protocol=suite.EXPECTED[protocol], correctness="pass", honest_correctness="pass",
               forged_server_rejection="pass", timing_scope="verification_increment_only",
               n_clients=job.n, active_clients=job.active, committee_size=job.m, vector_len=job.length,
               threshold_t=job.t, threshold_r=job.t, bench_threads=32, threads=32, client_threads=32,
               client_compute_s=.03, client_compute_mean_s=.03, active_client_compute_mean_s=.03,
               committee_compute_s=.02, server_compute_s=2.0, verifier_compute_s=.1,
               benchmark_profile="compact_seeded", rss_field_mode="compact31", digest_sharing_mode="seeded_prg_digest",
               rss_secret_dim=job.rss, curve="MNT224", security_bits=112)
    for key in suite.REQUIRED_HOPS[protocol]:
        raw[key] = 800 if key == "client_to_server_bytes" else 40
    raw["total_bytes"] = sum(raw[k] for k in suite.REQUIRED_HOPS[protocol])
    if protocol == "mpvas":
        raw.update(active_client_to_server_bytes=600, dropout_client_to_server_bytes=200)
    if protocol == "tacita":
        raw.update(config=dict(n_clients=job.n, active_clients=job.active, committee_size=job.m, threshold=job.t,
                               threads=32, slots=8192, input_bound=37, mask_inputs=False),
                   input_vector_len=job.length, implementation_version="fig7-batched-v2", mklhts_enabled=False,
                   input_soundness=False, ste_share_proofs=True, key_coordinates=8192, seed_bytes=32,
                   main_ciphertexts_per_client=1, main_headers_per_client=1, bound_shares_per_member=1,
                   tag_shares_per_member=1, kahe_stage=dict(correctness="pass", profile="fixed-upstream-100k", log_n="13", log_t="168"))
    return raw


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.c = suite.read_json(ROOT / "config.json")

    def test_configuration_and_complete_deduplicated_plan(self):
        suite.validate_config(self.c)
        jobs = suite.plan(self.c)
        self.assertEqual(len(jobs), 336)
        self.assertEqual({j.protocol for j in jobs}, set(suite.LABELS))
        self.assertEqual({j.length for j in jobs if "length" in jobs[j]}, set(self.c["lengths"]))
        main = suite.Job("osa", 1000, 800, 50, 10000, 1)
        self.assertEqual(set(jobs[main]), {"main", "n", "length", "osa_dropout", "osa_grid"})
        self.assertEqual(len(suite.plan(self.c, smoke=True)), 6)

    def test_counts_never_round_dropout_population(self):
        self.c["n_values"] = [101]
        with self.assertRaises(ValueError):
            suite.plan(self.c)

    def test_config_rejects_reversed_or_small_lengths(self):
        for lengths in ([100, 10000], [100000, 10000], [10000, 10000]):
            c = copy.deepcopy(self.c)
            c["lengths"] = lengths
            with self.assertRaises(ValueError):
                suite.validate_config(c)

    def test_role_sends_reconcile_all_protocols(self):
        for p in suite.LABELS:
            raw = fixture(p)
            job = suite.Job(p, 1000, 800, 50, 10000, 1)
            row = suite.normalize(raw, job, ["test"], 32, 3.0)
            self.assertEqual(row["total_bytes"], sum(row[k] for k in suite.HOPS))
            self.assertEqual(row["total_bytes"], sum(row[k] for k in ("client_sent_bytes", "server_sent_bytes", "committee_sent_bytes", "verifier_sent_bytes")))
            self.assertEqual(row["server_compute_s"], 2.0)

    def test_receives_are_not_added(self):
        raw = fixture("osa")
        raw.update(server_receive_bytes=10**12, committee_received_bytes=10**13)
        row = suite.normalize(raw, suite.Job("osa", 1000, 800, 50, 10000, 1), [], 32, 1)
        self.assertEqual(row["total_bytes"], 880)
        self.assertEqual(row["committee_send_bytes_mean"], 1)
        raw["total_bytes"] *= 2
        with self.assertRaises(ValueError):
            suite.normalize(raw, suite.Job("osa", 1000, 800, 50, 10000, 1), [], 32, 1)

    def test_client_commitments_and_verifier_sends_included(self):
        job = suite.Job("vosa", 1000, 800, 50, 10000, 1)
        row = suite.normalize(fixture("vosa"), job, [], 32, 1)
        self.assertEqual(row["client_send_bytes_mean"], 840/800)
        job = suite.Job("willow", 1000, 800, 50, 10000, 1)
        row = suite.normalize(fixture("willow"), job, [], 32, 1)
        self.assertEqual(row["verifier_sent_bytes"], 40)

    def test_mpvas_active_mean_excludes_dropout_recovery(self):
        job = suite.Job("mpvas", 1000, 800, 50, 10000, 1)
        row = suite.normalize(fixture("mpvas"), job, [], 32, 1)
        self.assertEqual(row["client_send_bytes_mean"], .75)
        self.assertEqual(row["client_sent_bytes"], 800)
        self.assertEqual(row["total_bytes"], 840)

    def test_fail_closed_for_missing_or_wrong_metrics(self):
        job = suite.Job("osa", 1000, 800, 50, 10000, 1)
        for key, val in (("active_clients", 999), ("protocol", "old"), ("rss_secret_dim", 29),
                         ("correctness", "fail"), ("client_compute_s", float("nan")),
                         ("client_to_committee_bytes", 1)):
            raw = fixture("osa")
            raw[key] = val
            with self.assertRaises(ValueError):
                suite.normalize(raw, job, [], 32, 1)
        raw = fixture("osa")
        del raw["committee_to_server_bytes"]
        with self.assertRaises(KeyError):
            suite.normalize(raw, job, [], 32, 1)

    def test_fig7_gate_excludes_legacy_and_mklhts(self):
        job = suite.Job("tacita", 1000, 800, 50, 10000, 1)
        for key, val in (("mklhts_enabled", True), ("key_coordinates", 4096), ("main_headers_per_client", 512)):
            raw = fixture("tacita")
            raw[key] = val
            with self.assertRaises(ValueError):
                suite.normalize(raw, job, [], 32, 1)

    def test_external_overrides_do_not_leak(self):
        with patch.dict(os.environ, {"BENCH_OSA_RSS_FIELD_MODE": "paper61", "OPA_FOO": "bad", "VOSA_N_CLIENTS": "4"}):
            cmd, env, cwd = suite.commands(suite.Job("osa", 1000, 800, 50, 10000, 1), self.c, ROOT)
        self.assertNotIn("BENCH_OSA_RSS_FIELD_MODE", env)
        self.assertNotIn("OPA_FOO", env)
        self.assertNotIn("VOSA_N_CLIENTS", env)
        self.assertEqual(env["BENCH_N_CLIENTS"], "1000")

    def test_exact_raw_record_and_changed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            job = suite.Job("osa", 1000, 800, 50, 10000, 1)
            attempt = run / "raw" / job.id / "attempt_test"
            attempt.mkdir(parents=True)
            raw = fixture("osa")
            raw["protocol"] = suite.EXPECTED["osa"]
            (attempt / "process.log").write_text(" ".join(f"{k}={v}" for k,v in raw.items()))
            row = suite.normalize(raw, job, [], 32, 1)
            row["source"] = attempt.relative_to(run).as_posix()
            suite.write_json(attempt / "row.json", row)
            suite.write_json(attempt / "command.json", {"test_only": True})
            hashes = {p.name:suite.sha(p) for p in attempt.iterdir()}
            suite.write_json(attempt.parent / "status.json", dict(status="completed", attempt=attempt.name,
                                                                 evidence_sha256=hashes, driver_wall_s=1))
            self.assertEqual(suite.verify_job(run, job, [], 32), row)
            (attempt / "process.log").write_text("changed")
            with self.assertRaises(ValueError):
                suite.verify_job(run, job, [], 32)

    def test_runner_resume_does_not_rerun_completed_jobs(self):
        c = dict(self.c, repeats=1)
        jobs = {suite.Job(p, 1000, 800, 50, 10000, 1):["main"] for p in ("osa", "opa")}
        host = dict(host=suite.platform.node(), source_sha256="test", binary_sha256={}, runtime_sha256={})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            def process(command, env, cwd, log, timeout):
                p = Path(command[0]).name
                raw = fixture(p)
                log.write_text(" ".join(f"{k}={v}" for k,v in raw.items()), encoding="utf-8")
                return 1.0
            with patch.object(suite, "plan", return_value=jobs), patch.object(suite, "preflight", return_value=host), \
                 patch.object(suite, "Lock", side_effect=lambda p:nullcontext()), \
                 patch.object(suite, "source_signature", return_value="test"), \
                 patch.object(suite, "run_process", side_effect=process) as runner, redirect_stdout(io.StringIO()):
                run = suite.execute(c, "all", False, None, root)
                self.assertEqual(runner.call_count, 2)
                self.assertEqual(len(suite.verify_run(run)[0]), 2)
                suite.execute(c, "all", False, run, root)
                self.assertEqual(runner.call_count, 2)
                with self.assertRaises(ValueError):
                    suite.execute(dict(c, repeats=2), "all", False, run, root)

    def test_bundled_actual_records_parse(self):
        fixtures = ROOT / "tests/fixtures"
        if not fixtures.is_dir():
            self.skipTest("Real parser fixtures are included by the packaging step")
        for p in suite.LABELS:
            file = fixtures / (p + (".json" if p == "tacita" else ".log"))
            raw = suite.read_json(file) if p == "tacita" else suite.parse_line(file.read_text(encoding="utf-8"))
            cfg = raw["config"] if p == "tacita" else raw
            n, active = int(cfg["n_clients"]), int(cfg["active_clients"])
            thread_key = "threads" if p in ("vosa", "tacita") else "client_threads" if p == "mpvas" else "bench_threads"
            threads = int(cfg[thread_key])
            job = suite.Job(p, n, active, int(cfg.get("committee_size", 50)), 10000, 1)
            suite.normalize(raw, job, [], threads, 1)


if __name__ == "__main__":
    unittest.main()
