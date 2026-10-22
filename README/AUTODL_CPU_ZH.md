# AutoDL 纯 CPU：两个 OSA 真实训练从头运行

## 结论与范围

- 机器按 **32 核 CPU、120 GB 内存**使用，不要求 GPU，不使用 CUDA 或 MUSA。
- 运行 **MNIST 小型 CNN（配置名 lenet5）**和 **CIFAR-10 AlexNet-BN**；均只运行 OSA。
- 两个实验分别从第 1 轮开始，共 300 轮；1000 个逻辑客户端，每轮 800 个参与，IID，本地 1 epoch。
- 这是单机模拟多个客户端的真实 SGD 训练和真实 OSA 聚合，不是生成预测曲线，也不是多机器分布式部署。
- 数据完整：MNIST 60000 训练 / 10000 测试，CIFAR-10 50000 训练 / 10000 测试。每轮使用 48000 / 40000 条训练样本是 80% 客户端参与的结果，不是数据缺失。
- 本次仅新增启动、打包和检查辅助代码，没有修改模型、训练算法、配置或协议源码。此前发现的协议安全缺口并未因此修复，不能将“训练跑通”写成“论文安全证明已完整实现”。

## 1. 上传哪个文件

上传本地 `upload/osa_cpu_fresh.tar.gz` 和 `upload/osa_cpu_fresh.tar.gz.sha256`。
包中含两套完整数据、训练代码、OSA 所需源码、Bazel 和已有依赖包；**没有旧结果、旧 checkpoint、预测演示曲线或旧编译缓存**。
为保留共享代码结构，源码中仍可能有 VOSA 等名称；新启动器只传 `--protocol osa`，不会执行这些其他协议的训练。

在 AutoDL 实例的 SSH 登录命令中找到端口和主机名，例如 `ssh -p 端口 root@主机名`。
下面命令在 **你本地 Windows PowerShell** 执行。将 `实际端口` 和 `实际主机名` 替换成实例页面上的值，不要使用容器内部的 `autodl-container-...` 名称。

```powershell
scp -P 实际端口 "C:\Users\JamesHarden\Desktop\OSA_VOSA_Project_Final\upload\osa_cpu_fresh.tar.gz" "C:\Users\JamesHarden\Desktop\OSA_VOSA_Project_Final\upload\osa_cpu_fresh.tar.gz.sha256" root@实际主机名:/root/autodl-tmp/
```

输入实例的 SSH 密码，密码输入时不显示字符是正常的。也可使用 AutoDL 的 JupyterLab 上传按钮，把这两个文件上传到 `/root/autodl-tmp`。上传方式参考 [AutoDL 官方文档](https://www.autodl.com/docs/scp/)。

## 2. 在服务器解压和校验

以下命令均在 **服务器终端**执行；上传文件已经位于 `/root/autodl-tmp`。

```bash
cd /root/autodl-tmp
sha256sum -c osa_cpu_fresh.tar.gz.sha256
OSA_DIR=$(mktemp -d /root/autodl-tmp/osa_cpu_fresh.XXXXXX)
tar -xzf osa_cpu_fresh.tar.gz -C "$OSA_DIR"
cd "$OSA_DIR"
sha256sum -c UPLOAD_SHA256SUMS
pwd
```

校验应全部显示 `OK`。保存 `pwd` 显示的目录路径，新终端中先 `cd` 到这个目录。
使用新目录解压，不会覆盖你服务器已有工程。上传校验值是在本次本地打包时生成的传输校验记录，不是论文作者签名。

## 3. 检查环境并编译 OSA

你贴的 Python 3.10.8、NumPy 1.26.4 可满足本项目要求。先直接使用现有 `python`；安装了 `torch-musa` 不意味着 CPU 不能用，也不必先卸载它。
是否可用以这里的实际导入、前向、反向传播和 SGD 检查为准，而不是只看 `conda list`。

```bash
python scripts/autodl_osa.py check
```

应看到一条 `data=PASS` 和两条 `cpu_training=PASS`。检查会核对原始数据校验值、torchvision 实际加载数量、客户端划分无遗漏/重复、300 轮覆盖所有客户端，并对两个模型各训练一个真实客户端、评估 64 条测试样本。这些小测试不生成正式训练权重或准确率结果。

安装系统编译依赖。你当前是 root，直接使用 apt-get，不需要 sudo：

```bash
apt-get update
apt-get install -y build-essential pkg-config libssl-dev libgmp-dev libffi-dev zlib1g-dev python3-dev ca-certificates unzip zip tmux
python scripts/autodl_osa.py prepare
```

`prepare` 只编译 OSA 训练使用的 Rust/C++ 桥接程序，并执行一次小整数聚合校验。目标文件名含 `osa_vosa` 是共享入口命名，不代表会训练 VOSA。首次编译仍可能联网获取 Rust 工具链、crate 或缺少的 Bazel 依赖；这不是完全离线包。出现下载错误时先解决联网问题，不要跳过构建检查。

项目所在数据盘至少留出 **20 GiB 可用空间**，建议更充裕。CIFAR-10 每轮的整数更新临时文件约 7.50 GiB，正常完成该轮后删除，不会每轮永久累积；Bazel 缓存也需要磁盘空间。120 GB 内存不等于 120 GB 可用磁盘空间。

## 4. 保持终端运行，先试跑，再正式跑

在项目目录中创建持久终端：

```bash
tmux new -s osa_cpu
```

进入 tmux 后，依次执行：

```bash
python scripts/autodl_osa.py smoke
python scripts/autodl_osa.py run
```

**第一条成功结束后再执行第二条。** `smoke` 对两个模型各跑完整 1 轮，包括 800 个客户端训练、OSA 聚合和全测试集评估。`run` 再次初始化模型，从第 1 轮依次完成 MNIST 300 轮和 CIFAR-10 300 轮，不会接着 smoke 的权重训练。

- 全程固定 `--device cpu`、`--protocol osa`；没有 `--resume`，也没有 `--download`。
- 每次创建 `results_fresh/run_时间_随机后缀/`，旧结果完全不读取、不覆盖、不删除。
- 默认 PyTorch/OpenMP 4 线程、MKL 4 线程、OSA 聚合最多 8 个分块进程；构建默认 16 个并发任务。这是保守的起始设置，不声称是你机器的最优性能。
- 1000 个逻辑客户端并非 1000 个并发进程；本地客户端训练是依次执行，卷积算子可多线程。两种模型也依次执行，便于统计独立耗时。
- 不运行 Plain、OPA、Willow 或 VOSA 训练；如需重新生成基线，那是单独的实验，不在此次启动范围。
- 一轮结束后才打印该轮准确率，CIFAR-10 第一轮等较久并不必然是卡死。不要看到暂时没打印新行就重复启动。

按 `Ctrl+B`，松开后按 `D` 离开 tmux，训练继续。重新进入：

```bash
tmux attach -t osa_cpu
```

不要停止/释放 AutoDL 实例，tmux 只能防止终端断开导致的退出，不能防止实例关机。若中途失败，保留日志，先排查再重跑；这个启动器不会自动断点续训。

## 5. 结果在哪里、怎么判断完整

启动时打印 `FRESH_OUTPUT=...`，记住这个实际目录。里面包含：

- `preflight.json`：Python/torch 版本、CPU 设置、两套数据 SHA-256、配置 SHA-256、样本检查结果。
- `mnist_lenet5.log`、`cifar10_alexnet_bn.log`：两项新训练的完整输出。
- `mnist_lenet5/osa/metrics.csv`、`cifar10_alexnet_bn/osa/metrics.csv`：正式训练各 300 行，含表头则文件有 301 行。
- 各模型目录中的 `checkpoint_latest.pt`：此次新训练保存的最后一轮权重；不是读取以前权重的入口。
- 各模型 `bridge_work/round_XXXX/merged_protocol_metrics.json`：每轮合并的聚合记录。
- `completed.json`：两个任务都结束且轮号、样本数、CPU/OSA 标记、有限损失、聚合误差检查通过后才生成。

脚本会检查每轮 `online_clients=800`、MNIST `examples=48000`、CIFAR-10 `examples=40000`、`max_abs_sum_error=0`，并拒绝缺轮、重复轮和非有限损失。该检查仍不是恶意服务器安全性证明。

总时间暂时不做保证。用 smoke 的 `round_wall_s` 估算：`300 × (MNIST 每轮秒数 + CIFAR-10 每轮秒数) / 3600` 小时；实际时间受 CPU 型号、磁盘和系统负载影响。

## 只有现有 torch 导入/训练失败时才使用的备用环境

不要在原 Conda base 中直接覆盖特制的 torch。下面新建隔离 CPU 环境；成功后后续命令都在激活该环境的终端运行：

```bash
python -m venv .runtime/cpu-venv
source .runtime/cpu-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install numpy==1.26.4 matplotlib==3.10.1
python -m pip install torch==2.2.2 torchvision==0.17.2 --index-url https://download.pytorch.org/whl/cpu
python scripts/autodl_osa.py check
```

这一组 torch/torchvision CPU 版本匹配关系来自 [PyTorch 官方历史版本安装表](https://docs.pytorch.org/get-started/previous-versions/)。选它是为贴近现有 2.2/0.17 API，不是建议生产系统长期使用旧版本；这里只使用已核验的数据，不加载陌生来源的 pickle/checkpoint。

## 本地验证边界

Windows 本地可验证数据、打包内容、启动参数及检查逻辑。Linux 上 Rust/C++ 编译和真实 torch 运行必须以服务器执行 `prepare`、`smoke` 的结果为准；没有连接到服务器前，不能声称这两步已经通过。
