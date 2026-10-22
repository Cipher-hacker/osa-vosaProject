# OSA / VOSA Final Experiment Code Package

Please read the [Run and Directory Guide](README/RUN_GUIDE_EN.md) ([中文版](README/RUN_GUIDE_CN.md)) first.

This package contains the confirmed legacy main experiments, computation retests, revised plotting code, 384 raw records of formal measurements, as well as the dependencies and lockfiles bundled with the original package. Cryptographic protocols, timing methods, experimental parameters, and 32-thread configurations remain unchanged.

## Directory Overview

- `data/paper/`: 336 main experiment records.
- `data/computation/`: 48 computation retest records.
- `protocols/`: Core implementations of cryptographic protocols (OSA, Willow, VOSA, OPA, TACITA, mPVAS).
- `scripts/`: Build, environment setup, execution, monitoring, and plotting scripts.
- `third_party/`: Bundled dependencies and lockfiles (note: requires network access for certain builds; not a completely offline environment).
- `README/`: Detailed operational guides, directory structure explanations, and timing specifications:
  - [Run Guide (EN)](README/RUN_GUIDE_EN.md) / [运行说明 (CN)](README/RUN_GUIDE_CN.md)
  - [Computation Retest Methodology (EN)](README/COMPUTATION_EN.md) / [计算补测说明 (CN)](README/COMPUTATION_CN.md)

## Scope & Exclusions

This package does **not** include:
- Real federated learning model training (MNIST / CIFAR) or model weights.
- Formal $L=1$ experiments.
- Deprecated legacy four-protocol dropout packages.
- Generated figure artifacts, virtual environments, or build caches.

> The standalone OSA dropout rate experiment and VOSA/mPVAS verification experiments belong to the original main experiment suite and remain included.

## System Requirements & Reproducibility

- **Re-plotting existing data**: Supported on both **Linux** and **Windows** without re-running cryptographic protocols.
- **Running formal cryptographic benchmarks**: Supports **Linux x86_64** only (minimum 32 logical CPU cores recommended to match original evaluation settings).
