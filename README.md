# OSA / VOSA Final Experiment Code Package

Please read the [Run and Directory Guide](README/RUN_GUIDE_EN.md) ([中文版](README/RUN_GUIDE_CN.md)) first.

This package contains the confirmed legacy main experiments, computation retests, real federated learning training code, revised plotting code, 384 raw records of formal measurements, as well as the dependencies and lockfiles bundled with the original package. Cryptographic protocols, timing methods, experimental parameters, and 32-thread configurations remain unchanged.

## Directory Overview

- `data/paper/`: 336 main experiment records.
- `data/computation/`: 48 computation retest records.
- `datasets/`: Pre-packaged MNIST and CIFAR-10 datasets for offline/reproducible federated training.
- `federated_training/`: End-to-end real federated learning (FedAvg) training code, configs, models (MNIST+LeNet5, CIFAR10+AlexNet-BN), codec, and protocol bridges.
- `protocols/`: Core implementations of cryptographic protocols (OSA, Willow, VOSA, OPA, TACITA, mPVAS).
- `scripts/`: Build, environment setup, execution, monitoring, plotting, and federated learning scripts.
- `third_party/`: Bundled dependencies and lockfiles (note: requires network access for certain builds; not a completely offline environment).
- `README/`: Detailed operational guides, directory structure explanations, and timing specifications:
  - [Run Guide (EN)](README/RUN_GUIDE_EN.md) / [运行说明 (CN)](README/RUN_GUIDE_CN.md)
  - [Computation Retest Methodology (EN)](README/COMPUTATION_EN.md) / [计算补测说明 (CN)](README/COMPUTATION_CN.md)
  - [AutoDL CPU Guide (CN)](README/AUTODL_CPU_ZH.md)

## Real Federated Learning (FedAvg)

This package supports real federated learning training on MNIST (LeNet-5) and CIFAR-10 (AlexNet-BN) using real cryptographic aggregation backends (OSA, Plain, Quantized-Plain, Willow, OPA, VOSA).

### 1. Environment & Setup

Install PyTorch and the required Python dependencies:
```bash
# Setup Python virtual environment with PyTorch and dependencies
bash scripts/setup_federated_training.sh
```

### 2. Build Protocol Bridges

Compile the Rust secure-aggregation bridges required for real FL backends:
```bash
bash scripts/build_federated_bridges.sh
```

To run a fast smoke test verifying all compiled bridges without datasets:
```bash
python3 scripts/smoke_federated_bridges.py --protocol all
```

### 3. Run Federated Training

Run a full training session using the runner script:
```bash
# Run MNIST + LeNet-5 with OSA protocol (e.g., CPU or CUDA)
bash scripts/run_federated_training.sh \
  --config federated_training/configs/mnist_lenet5.json \
  --protocol osa \
  --device cpu \
  --data-root datasets \
  --output-root results/federated_training

# Or run all aggregation backends across the dataset
bash scripts/run_all_federated_training.sh

# Run CIFAR-10 + AlexNet-BN with OSA protocol
bash scripts/run_federated_training.sh \
  --config federated_training/configs/cifar10_alexnet_bn.json \
  --protocol osa \
  --device auto \
  --data-root datasets \
  --output-root results/federated_training
```

### 4. Running on AutoDL / Cloud Server (CPU or GPU)

For pure CPU servers or AutoDL cloud instances:
```bash
# 1. Verify datasets and dependencies
python3 scripts/autodl_osa.py check

# 2. Build the OSA FL bridge
python3 scripts/autodl_osa.py prepare

# 3. Run a 1-round smoke test (800 active clients, real aggregation)
python3 scripts/autodl_osa.py smoke

# 4. Start formal 300-round training (inside tmux recommended)
python3 scripts/autodl_osa.py run
```
See [AutoDL Run Guide](README/AUTODL_CPU_ZH.md) for full instructions on background execution, monitoring, and result parsing.

## Scope & Exclusions

This package does **not** include:
- Historical training checkpoint weights (generated freshly per run).
- Formal $L=1$ experiments.
- Deprecated legacy four-protocol dropout packages.
- Generated figure artifacts, virtual environments, or build caches.

> The standalone OSA dropout rate experiment and VOSA/mPVAS verification experiments belong to the original main experiment suite and remain included.

## System Requirements & Reproducibility

- **Re-plotting existing data**: Supported on both **Linux** and **Windows** without re-running cryptographic protocols.
- **Running formal cryptographic benchmarks**: Supports **Linux x86_64** only (minimum 32 logical CPU cores recommended to match original evaluation settings).
