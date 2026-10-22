# Willow Benchmarks

These benchmarks are using simple loops for now.

Get information with:
```
bazel run -c opt //willow/benches:run_shell_benchmark -- --help
```

For example:

```
bazel run -c opt //willow/benches:run_shell_benchmark -- -l 10000 -n 10 --handler server_handle_client_message --n-iterations 10
```

You can also use the `shell_benchmarks` crate in another binary, e.g., to loop through multiple configurations.

## Paper-Facing Unified Targets

The current one-round comparison uses these distinct targets:

- `//willow/benches:run_willow_paper_full_unified`: Willow Figures 3-5 with PRG seed masking and auxiliary threshold-key recovery.
- `//willow/benches:run_osa_full_unified`: faithful OSA with full ring digest and 61-bit RSS.
- `//willow/benches:run_osa_compact_seeded_unified`: separately labelled OSA extension using a secret-shared 256-bit digest seed and bounded 31-bit RSS field.

Build once with `-c opt`, then execute `bazel-bin/willow/benches/<target>` directly so Bazel startup and compilation are not included in protocol timing. The frozen configuration, security boundary, exact commands, source hashes, and 2026-08-06 raw results are recorded in:

```text
../../../experiments_vosa/results/2026-08-06_osa_efficiency_goal/README.md
```

Do not substitute the older `run_willow_full_unified` target for the paper-full Willow baseline, and do not report the compact OSA target as unchanged faithful OSA.
