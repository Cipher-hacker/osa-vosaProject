# Final Code Package Run Guide

## 1. Version Scope

This package reorganizes the previously confirmed `OSA_Final_Experiments` version. It does not switch to the later, slower `osaexp` implementation or rewrite the runner, parallel execution model, or cryptographic protocols. The reorganization affects file locations, non-executable documentation, the corresponding manifests, and run instructions. Previously confirmed plotting revisions are retained.

The package includes:

| Experiment | Scope | Formal Measurements |
|---|---|---:|
| Main suite | OSA/OPA/Willow/TACITA-STE comparisons at a fixed configuration and across client counts, committee sizes, and vector lengths; separate OSA dropout and client-count grid experiments; VOSA/mPVAS verification experiments | 336 |
| Computation retest | Fixed N=1000, m=50, L=10000; four protocols at client dropout rates of 10%, 20%, 30%, and 40%; three runs per configuration | 48 |

Historical CSV files are not used as new experimental results. `data/` explicitly stores historical raw records; new execution results go to `runs/` under `.work/`. To run real federated learning training (MNIST/CIFAR-10), see the instructions in root `README.md` and `README/AUTODL_CPU_ZH.md`; cryptographic protocol benchmarks generate their inputs using the original code.

## 2. CPU and Threads: Original Settings Retained

| Item | Original Setting, Unchanged |
|---|---|
| Formal main suite | `threads=32` in `config/paper.json` |
| Formal computation retest | `threads=32` in the original runner |
| Build parallelism | The original scripts cap `JOBS` at 32; commands below explicitly use `JOBS=32` |
| Underlying library threads | `OMP_NUM_THREADS=1`, `MKL_NUM_THREADS=1`, `OPENBLAS_NUM_THREADS=1` |
| TACITA thread pool | Original implementation and 32-thread configuration retained; no new per-role threading strategy |
| Client sampling in the computation retest | Original three serial warmups and 20 serial samples; the full protocol's batch phase retains its original execution settings |
| Repetitions | Three independent runs for both the main suite and the formal retest |

The value 32 is an experiment thread setting. It does not mean that every stage simultaneously occupies 32 cores, nor does it turn the 20 serial timing samples into parallel samples. Setting the library environment variables above to 1 does not make the entire experiment single-core.

Use a Linux x86_64 server with at least 32 available logical CPUs. To retain the original hardware allocation, continue using the original 32-core rental configuration. The code does not automatically treat a machine with fewer than 32 CPUs as equivalent. Reserve ample space on the data disk: the original program requires at least 20 GiB of free space, and initial compilation and dependency caches require additional space. Do not run another performance experiment or a large build concurrently.

This package does not set CPU affinity, change container CPU quotas, or alter the original thread settings to accommodate smaller machines. Different CPU models, frequencies, and system loads can still produce different timings. Exact agreement with historical timing values is not guaranteed.

## 3. File Structure

| Path | Purpose |
|---|---|
| `run.sh` | Thin entry point that delegates to `project.py`; does not introduce new thread settings |
| `project.py` | Validates manifests, restores original relative paths, and invokes the old scripts; does not implement protocols or timing |
| `layout.json` | Mapping from reorganized files to original working paths, with SHA-256 hashes |
| `config/paper.json` | Original main-suite parameters: 32 threads and three repetitions |
| `config/communication_reference.json` | Sent-byte consistency reference for the computation retest; not a new measurement |
| `config/rust_mirror.cfg` | Original Bazel download rules |
| `protocols/secure-aggregation-main/` | Original OSA, Willow, VOSA, and KAHE implementations, BUILD files, and dependency locks |
| `protocols/opa-secure-aggregation/` | Original OPA implementation, BUILD files, and dependency locks |
| `protocols/tacita/` | Original STE+KAHE reproduction, bridge code, Cargo lockfile, and upstream source; excludes MKLHTS |
| `protocols/mpvas-experiments/` | Original mPVAS protocol and real pairing benchmark |
| `experiments/shared/paper_suite.py` | Main-suite planning, execution, normalization, evidence validation, and resumption |
| `experiments/shared/resources.py` | Process resource recording for the retest |
| `experiments/computation.py` | Original computation-retest planning, sample validation, status, and export |
| `experiments/tacita_worker.py` | Original TACITA bridge execution for the retest |
| `plotting/paper.py` | Main-suite grouping, means, and generation of 64 figures |
| `plotting/computation.py` | Four computation-retest figures and sampling CSV files |
| `plotting/renderer.py` | Shared styling, legends, linear axes, and inset plots |
| `scripts/setup/paper.sh` | Original system-tool, Python virtual-environment, and Rust installation workflow |
| `scripts/environment/paper_env.sh` | Original cache, temporary-directory, and thread environment settings |
| `scripts/build/paper.sh` | Original main-suite build and native tests |
| `scripts/build/bazel.sh` | Original Bazel launch adapter |
| `scripts/build/pairing/` | Original PBC/Charm build and environment checks |
| `scripts/build/computation_prepare.sh` | Original retest preparation workflow |
| `scripts/build/computation/build.py` | Original build of the isolated retest source copy |
| `scripts/build/computation/instrument.py` | Confirmed timing instrumentation; does not write into the original main-suite source |
| `scripts/build/computation/dependency_locks.py` | Original dependency-lock restoration and strict validation |
| `scripts/build/computation/client_timing.rs` | Original client warmup and sampling implementation |
| `scripts/run/` | Original main-suite and retest launch scripts |
| `scripts/monitor/` | Original status and process inspection scripts |
| `scripts/export/` | Original retest export scripts |
| `scripts/plot/` | Original plotting shell entry points |
| `scripts/validation/` | Original STE end-to-end validation |
| `scripts/tacita/` | Original TACITA build, execution, and validation helpers |
| `tests/` | Original build-gate, data-parsing, plotting, and path tests; test fixtures must not be presented as formal measurements |
| `manifests/` | File manifests for the main package, retest, and main-package dependencies; required for execution, not review reports |
| `third_party/` | Bundled dependency archives, Bazel, working lock snapshots, and licenses |
| `data/paper/` | 336 historical measurements and the complete downloaded raw evidence |
| `data/computation/` | 48 historical retest measurements, warmup/sampling records, and raw evidence |
| `README/` | This guide and the computation timing guide |

The first `prepare` step only copies files. It creates `.work/OSA_Paper_Experiments_CPU_20261008/` and `.work/OSA_Computation_Retest_20261013/`, restoring the relative directory structure required by the old scripts. Do not run the original scripts directly from their reorganized locations: they still use their original relative paths. Use the entry point or the restored `.work` paths shown below.

## 4. Installation and Build After Upload

Upload the entire `OSA_Final_Code` folder to the data disk. The commands below assume `/root/autodl-tmp/OSA_Final_Code`. On another Linux machine, replace only this directory, not the protocol parameters. Execute commands one at a time. Stop if a step fails; do not bypass validation gates and continue.

```bash
cd /root/autodl-tmp/OSA_Final_Code
python3 project.py verify
python3 project.py prepare
ROOT="$PWD"
P="$ROOT/.work/OSA_Paper_Experiments_CPU_20261008"
C="$ROOT/.work/OSA_Computation_Retest_20261013"
python3 --version
nproc
df -h .

export PYTHON_SOURCE="$(command -v python3)"
"$PYTHON_SOURCE" -c 'import sys; assert sys.version_info[:2] == (3, 10), "Use Python 3.10.x"'
JOBS=32 bash "$P/scripts/setup.sh" --install-system
JOBS=32 bash "$P/scripts/build.sh"
bash "$P/scripts/run_all.sh" --smoke
```

If the current `python3` is not version 3.10, first make Python 3.10 available, then set `PYTHON_SOURCE` to that interpreter's absolute path. Do not simply remove the version check. On Ubuntu/Debian, `--install-system` installs system packages and requires root or sudo. Omit this option if the system dependencies are already installed.

Expect `SETUP_PASS`, then `BUILD_PASS`, and finally `SUITE_COMPLETE` for the smoke run. The main smoke suite includes six protocol/verification benchmarks, not real model training. Native builds run on the Linux server; local data validation is not a substitute.

## 5. Formal Experiments Using the Original Workflow

Use tmux to keep a terminal disconnection from interrupting the task:

```bash
tmux new -s osa_final
```

Inside tmux, set the paths again and execute the commands in order:

```bash
cd /root/autodl-tmp/OSA_Final_Code
P="$PWD/.work/OSA_Paper_Experiments_CPU_20261008"
C="$PWD/.work/OSA_Computation_Retest_20261013"

bash "$P/scripts/run_all.sh"
JOBS=32 bash "$C/prepare.sh" "$P"
bash "$C/run.sh" "$P"
```

Wait for each command to succeed before executing the next; do not start them in parallel. Main-suite completion requires `SUITE_COMPLETE` and `FIGURES_PASS count=64`. The retest first requires `COMPUTATION_PREPARE_PASS`; its formal completion requires `COMPUTATION_RETEST_COMPLETE` and `FIGURES_PASS count=4`.

The equivalent consolidated entry-point commands remain `bash run.sh paper`, `JOBS=32 bash run.sh computation-prepare`, and `bash run.sh computation`. They only delegate to the original scripts above, with unchanged parameters.

To detach from tmux, press Ctrl+b, then d. To return, run `tmux attach -t osa_final`. Do not launch duplicate copies of the same experiment.

## 6. Results, Logs, and Resumption

New main-suite results are written to `$P/runs/paper_TIMESTAMP/`; new retest results go to `$C/runs/computation_TIMESTAMP/`. Use the exact path printed after `RESULTS=` in the terminal. Build and run logs are stored in `logs/` within the respective working directories. Each individual task's log is under `raw/` in its result directory.

```bash
# Replace RUN with the full main-suite RESULTS path printed in the terminal.
RUN="$P/runs/paper_ACTUAL_TIMESTAMP"
bash "$P/scripts/status.sh" "$RUN"
tail -n 3 "$RUN/measurements.csv"

# Retest status.
bash "$C/status.sh" "$P"

# Resume only after interruption, on the same host with the same configuration and binaries.
bash "$P/scripts/run_all.sh" --resume "$RUN"
# For the retest, use its own RESULTS path.
bash "$C/run.sh" "$P" --resume "$C/runs/computation_ACTUAL_TIMESTAMP"
```

Do not use historical results in `data/` as the resume directory for a new experiment on the current machine. Those records came from the original server and are provided only for validation and replotting. Do not copy another machine's Python virtual environment or overlay an old `.work` directory onto this package. The entry point rejects an existing working directory associated with a different manifest.

## 7. Replot Bundled Data Without Rerunning Experiments

After completing installation on Linux, execute the following from the package root:

```bash
bash run.sh verify-run paper "$PWD/data/paper"
bash run.sh verify-run computation "$PWD/data/computation"
bash run.sh plot paper "$PWD/data/paper"
bash run.sh plot computation "$PWD/data/computation"
```

For plotting only on Windows, use a Python interpreter with matplotlib and numpy installed. Bazel, Rust, and Charm are not required:

```powershell
cd "$HOME\Desktop\OSA_Final_Code"
python -m pip install -r requirements.txt
python project.py verify
python project.py verify-run paper "$PWD\data\paper"
python project.py verify-run computation "$PWD\data\computation"
python project.py plot paper "$PWD\data\paper"
python project.py plot computation "$PWD\data\computation"
```

Python 3.10 is recommended for the pinned plotting dependencies. A local interpreter that already has the plotting libraries can also be used to try validation and plotting. Each plotting invocation creates a new `figures_TIMESTAMP/` directory under the relevant data directory without overwriting the raw measurements. Main-suite output includes category-organized `paper_figures/` and `plot_data/` directories; retest output uses `computation/images/` and `computation/data/`.

Figures show measured arithmetic means without error bars; standard deviations remain in the CSV files. Where TACITA has a substantially larger scale, a three-protocol main plot is accompanied by an inset containing all four protocols. Both plots have legends. Axes are linear, y-axes start at zero, and units are (s)/(KB)/(MB). Parameter descriptions are not placed inside the figures. Values are neither replaced nor smoothed. Captions are saved separately in the output directory, not embedded in the images.

## 8. Communication and Timing Definitions

This reorganization does not change the statistics code. Per-client communication is the amount sent by one online client. System-wide communication is the sum of bytes sent by all parties; received bytes are not added again. Global model downloads and one-time public parameters are excluded. Per-committee-member figures use the actual responding-member basis; do not present the committee total as a single member's amount.

The main suite's original per-client timing and the later warmed-up sampling retest use different measurement procedures. Do not combine their records into a single curve. Dropout computation figures use the retest data; see the [computation retest guide](COMPUTATION_EN.md). Historical data retains its measured variability. Values must not be altered to make a protocol appear better.

## 9. Dependencies, Network Access, and Licenses

- System: Linux x86_64, Python 3.10 and development headers, GCC/G++, clang/lld, GMP, OpenSSL, and other dependencies installed by the original setup script.
- Rust: version 1.87.0; Cargo.lock and Bazel lock snapshots are retained.
- Plotting: matplotlib 3.9.2 and numpy 1.26.4 as specified in `requirements.txt`.
- Bundled: the Bazel 8.1.1 Linux executable, Bazel dependency archives, PBC 0.5.14, pinned Charm source, a setuptools wheel, and licenses.
- This package is not claimed to be fully offline. System packages, the Rust toolchain, some Cargo/crates.io dependencies, and the pinned hopcroft-karp Git commit may still require network access. Original dependency sources are retained, without silently changing versions or introducing a new installation workflow.
- If a download times out, retain the logs and existing caches and investigate network access. Do not delete lockfiles, replace pinned versions with latest versions, or bypass correctness checks. Installation waiting time is not protocol execution time.
- Licenses are retained in the upstream source roots and `third_party/LICENSES/`. They are required for dependency redistribution.

The manifests record the documentation cleanup and plotting revisions while retaining the original version hashes. The current whole-package hash is not the historical whole-package hash. However, the retained protocol code, experiment drivers, run/build scripts, parameters, and timing source are identical file by file to the confirmed version. This package neither fixes nor claims to eliminate existing protocol security limitations, and it does not guarantee acceptance of any paper.
