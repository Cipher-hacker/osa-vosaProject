# Computation Retest: Execution and Timing Methodology

See the [run guide](RUN_GUIDE_EN.md) for the overall workflow, paths, and dependencies. This document describes the retained original retest methodology; it does not introduce a new implementation or additional experiments.

## Fixed Parameters

- N=1000, m=50, L=10000. Client dropout rates are 10%, 20%, 30%, and 40%, corresponding to 900, 800, 700, and 600 active clients.
- The four protocols are OSA, OPA, Willow, and TACITA-STE. Each configuration is executed independently three times, for 48 runs in total. The thread count remains 32.
- Within each process, perform three serial client-operation warmups, then time 20 serial client operations and take their arithmetic mean. Finally, average the means from the three independent runs.
- The 20 timed operations assess measurement repeatability. They do not mean that a client must upload 20 times in a single federated learning round. These extra samples are not included in the communication volume of one logical round.
- Each configuration has 60 timed operation samples, but the number of independent repetitions remains three. Warmup samples are excluded from the mean.
- Timing includes the original client encryption and message serialization operations. Previously completed public-parameter setup is excluded from client-operation time.
- OSA and OPA cycle through client IDs. The other protocols retain their original representative client inputs and use fresh randomness. Messages generated during sampling are not used in the main aggregation.
- TACITA's per-client time is the sum of the STE and KAHE stage sample means, not the wall-clock time of a fused execution of the two processes.
- The server, verifier, and committee execute their full operations, with timing recorded by the original role-specific code. OSA, Willow, and TACITA use 40 responding members; OPA uses 34. The original threshold rules are retained, not standardized by this reorganization.

## Preparation and Execution

After the main package installation, build, and smoke test succeed, run the following from the consolidated package root:

```bash
P="$PWD/.work/OSA_Paper_Experiments_CPU_20261008"
C="$PWD/.work/OSA_Computation_Retest_20261013"
JOBS=32 bash "$C/prepare.sh" "$P"
bash "$C/run.sh" "$P"
```

The preparation step copies the source into the retest's own `work/` directory and applies the previously validated sampling instrumentation and dependency compatibility handling. It does not modify the main package source. Dependency versions, checksums, and target-platform features are checked against the original locks. Do not bypass these checks to work around a build failure. Start the formal retest only after `COMPUTATION_PREPARE_PASS` appears.

## Data and Figures

Bundled historical data is in `data/computation/`; new results are written to `$C/runs/` as defined above. The `raw/` directory retains each complete protocol execution, separate STE/KAHE sampling records, and resource records. Do not keep only the summary CSV and delete the evidence directory: strict validation and plotting will then fail.

The retest automatically produces four computation figures: per-online-client, per-responding-committee-member, server, and server-plus-verifier time. It does not generate a separate new set of communication figures. Every retest checks sent-byte counts against the original reference data to detect accidental communication changes caused by timing instrumentation.

Standard deviations are retained in the plotting CSV files, but error bars are not drawn. Measured means are not modified. The paper must distinguish the three independent runs from the 60 timed operation samples.
