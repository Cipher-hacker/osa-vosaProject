## OPA Prototype

This package adds a first `OPALWR`-style prototype on top of the copied Willow repository layout.

What is implemented:

- LWR-style seed-homomorphic PRG
- Packed secret sharing for the long SHPRG seed over a prime field `F_q`
- Standard Shamir sharing for the per-client digest masks
- Committee-side one-shot combine logic
- Server-side reconstruction and unmasking
- ECIES-style envelope encryption for committee auxiliary shares using `curve25519-dalek`

Paper-sized benchmark parameters are `lambda=2048`, `rho=16`, `p=2^53`, committee size `50`, threshold `34`, and the concrete 128-bit prime `q=2^128-159`. Literal `lambda/rho` packing yields 128 packed seed shares.

Two protocol targets are intentionally distinct:

- `//opa:bench_opalwr` uses generic `crypto_bigint::U256` modular arithmetic and is the correctness/reference target.
- `//opa:bench_opalwr_optimized` uses mathematically equivalent pseudo-Mersenne reduction for the fixed `q`; this is the primary performance target.

The optimization changes neither the LWR parameters nor the wire messages. `//opa:opalwr_optimized_test` cross-checks 10,000 deterministic arithmetic samples against the generic `U256` implementation.

What is intentionally not implemented yet:

- Full malicious-security proof machinery from the paper
- Signature-based residual-attack hardening
- The `OPA'` threshold KH-PRF variant
- The paper's class-group / DCR instantiations

The goal of this package is to make the protocol flow in Figure 2 of the OPA paper executable inside the
same Bazel/Rust workspace structure as Willow, while keeping Willow intact as a baseline.

## OPA Communication Simulation

For a separate legacy sensitivity result that includes communication latency, use the helper:

```bash
python experiments_vosa/simulators/simulate_opa_abides_network.py \
  --bench-line "protocol=OPA n_clients=128 active_clients=113 vector_len=1000 committee_size=50 threshold_r=34 seed_dim=1024 packed_secret_dim=16 client_compute_s=3.484141 committee_compute_s=0.381006 server_compute_s=0.236999 plain_server_compute_s=0.000052 server_compute_with_plain_s=0.237051 client_to_server_bytes=8000400 server_to_committee_bytes=6192400 committee_to_server_bytes=127296 total_bytes=8127696" \
  --rounds 1000 \
  --csv-out experiments_vosa/results/summary/opa_l1000_abides_network_summary.csv
```

The simulator follows the OPA paper's ABIDES-style local-network setting:

- base one-way delay sampled from `21us` to `100us`
- default jitter is kept explicit as `--jitter-us`, with script default `0`
- no bandwidth serialization by default, because the quoted OPA setting specifies latency and jitter only
- optional `--bandwidth-mbps` can be set for sensitivity analysis, but those numbers should be labelled separately

For the current full unified comparison, use `experiments_vosa/README_FULL_UNIFIED_COMPARISON.md`. In particular:

- `client_compute_s` is already one directly measured uncontended client operation and must not be divided by `active_clients`.
- `committee_compute_s` is a measured single-member mean, not total committee wall time divided after the fact.
- `server_compute_s` is the complete measured online server path.
- ABIDES-added values must be labelled as a separate network sensitivity analysis, not mixed into local computation.
