# Secure Aggregation

This repository contains implementations of secure aggregation protocols.
It includes the copied Willow baseline ([paper](https://eprint.iacr.org/2024/936)) and a first
`OPALWR`-style prototype in [`opa/`](opa/README.md), derived from the OPA paper.

## Dependencies

The codebase is built using [Bazel](https://bazel.build). All other dependencies are built from source.
We use [SHELL](https://github.com/google/shell-encryption) for homomorphic encryption,
and [Curve25519-Dalek](https://crates.io/crates/curve25519-dalek) for elliptic curve operations.
The library itself is written in Rust.

## Build & Test

To build the library (with performance optimizations enabled), run

```
bazel build -c opt //...
```

To run tests:

```
bazel test -c opt //...
```

Usage examples can be found in [willow/tests/willow_v1_shell.rs](willow/tests/willow_v1_shell.rs).

The new OPA prototype test target is:

```
bazel test -c opt //opa:opalwr_test
```

## Benchmarks

Benchmarks, and information how to run them, can be found in the [benches](willow/benches) folder.

## Security
To report a security issue, please read [SECURITY.md](SECURITY.md).

## Disclaimer

This is not an officially supported Google product. The code is provided as-is,
with no guarantees of correctness or security.

## Local Run Notes

These notes record the run process that was actually verified in this workspace.
For the full cross-repo runbook, see [../README.md](../README.md).

### Verified Targets

The following targets were verified here:

- OPA prototype: `//opa:opalwr_test`
- Willow baseline sanity check target available in the same repo: `//willow/tests:willow_v1_shell`

The OPA target passed successfully in this workspace.

### Environment That Actually Worked

The successful runs used WSL, not plain Windows PowerShell.

Important details:

- Windows PowerShell did not have working `bazel`, `rustc`, or `cargo` on `PATH`.
- WSL had `bazelisk`, `rustc`, `cargo`, `gcc`, and `g++`.
- WSL did not have `clang`.
- This repo pins Bazel `8.1.1` via `.bazelversion`.
- The shared dependency cache lives in `../bazel-distdir`.

Because `.bazelrc` asks for `clang/clang++`, successful local runs explicitly overrode the compiler to `gcc/g++`.

### Recommended Commands

From WSL inside this repository, run the OPA test with:

```bash
USE_BAZEL_VERSION=8.1.1 bazelisk test -c opt \
  --distdir="../bazel-distdir" \
  --action_env=CC=gcc \
  --action_env=CXX=g++ \
  --repo_env=CC=gcc \
  --repo_env=CXX=g++ \
  //opa:opalwr_test
```

If you also want to rerun the Willow baseline from this repo, use:

```bash
USE_BAZEL_VERSION=8.1.1 bazelisk test -c opt \
  --distdir="../bazel-distdir" \
  --action_env=CC=gcc \
  --action_env=CXX=g++ \
  --repo_env=CC=gcc \
  --repo_env=CXX=g++ \
  //willow/tests:willow_v1_shell
```

From the workspace root in Windows PowerShell, the preferred entry point is:

```powershell
powershell.exe -ExecutionPolicy Bypass -File "<workspace-root>\run_secure_agg_tests.ps1" -Scheme OPA
```

From the workspace root in WSL, the wrapper entry point is:

```bash
bash ./run_secure_agg_tests.sh OPA
```

### First Run Expectation

The first OPA repository run in this workspace took about 973 seconds.
After the cache was warm, reruns were fast.

### Common Gotchas

- If `bazelisk` tries to resolve `latest` online, make sure `.bazelversion` exists and still says `8.1.1`.
- If the build complains about `clang`, keep the `gcc/g++` overrides shown above.
- If Codex reports `Wsl/Service/CreateInstance/E_ACCESSDENIED`, that is usually a sandbox or permission problem, not a repo bug.
- A `rules_cc@0.2.16` vs `0.2.17` warning was observed, but it did not block this repo from passing.

### Benchmark Command Used In This Workspace

The current one-round secure-aggregation comparison uses the paper-sized `F_q` path and the fixed-`q` optimized target. The generic `U256` target remains available as a reference.

First build once in optimized mode:

```bash
USE_BAZEL_VERSION=8.1.1 bazelisk build -c opt \
  --distdir="../bazel-distdir" \
  --action_env=CC=gcc \
  --action_env=CXX=g++ \
  --repo_env=CC=gcc \
  --repo_env=CXX=g++ \
  //opa:bench_opalwr_optimized
```

Then run:

```bash
./bazel-bin/opa/bench_opalwr_optimized
```

Notes:

- the active performance target uses `lambda=2048`, `rho=16`, `p=2^53`, `q=2^128-159`, `m=50`, and `r=34`
- `//opa:bench_opalwr` is the slower generic-`U256` reference and is not used for primary performance figures
- do not treat `bazel run` wall-clock time as protocol time
- after one successful `-c opt` build, direct reruns should not need a full rebuild
