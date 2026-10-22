# 最终代码包运行说明

## 1. 版本边界

本包基于已确认的 `OSA_Final_Experiments` 整理。没有切换到后来变慢的 `osaexp` 实现，没有重写运行器、并行模型或密码协议。整理只影响文件摆放、非运行文档、相应清单和运行说明；保留之前确认的绘图修订。

本包包括：

| 实验 | 内容 | 正式测量数 |
|---|---|---:|
| 主实验 | OSA/OPA/Willow/TACITA-STE固定配置、用户数、委员会大小、向量长度；独立OSA掉线率及用户数网格；VOSA/mPVAS验证相关实验 | 336 |
| 计算补测 | 固定N=1000、m=50、L=10000，四协议掉线率10%、20%、30%、40%，每组3次 | 48 |

没有把历史CSV作为新实验结果使用。`data/`明确保存历史原始记录；新执行结果进入`.work/`下的`runs/`。如需进行真实联邦学习训练（MNIST/CIFAR-10），请参阅根目录 `README.md` 与 `README/AUTODL_CPU_ZH.md`；密码学协议对比基准由原代码生成输入。

## 2. CPU与线程：保持旧版

| 项目 | 原设置，保持不变 |
|---|---|
| 正式主实验 | `config/paper.json`中的`threads=32` |
| 正式计算补测 | 原运行器中的`threads=32` |
| 编译并行数 | 原脚本将`JOBS`限制为最多32；下文显式使用`JOBS=32` |
| 底层库线程 | `OMP_NUM_THREADS=1`、`MKL_NUM_THREADS=1`、`OPENBLAS_NUM_THREADS=1` |
| TACITA并行池 | 保留原实现及原来的32线程配置，不增加新的角色线程策略 |
| 计算补测客户端采样 | 原有串行预热3次、采样20次；完整协议的批量部分仍按原设置执行 |
| 重复次数 | 主实验及正式补测均为3次独立执行 |

32是实验进程的线程设置，不表示每个阶段都会同时占满32个核，也不是把20个串行计时样本改成并行。上述环境变量设为1并不把整个实验改成单核。

使用至少32个可用逻辑CPU的Linux x86_64服务器；如要保持原硬件条件，继续使用原来的32核租用配置。代码不会把不足32核的机器自动当作同等条件。建议在数据盘预留充足空间，原程序要求至少20 GiB可用空间；首次编译和依赖缓存还会占用空间。不要同时执行另一个性能实验或大规模编译。

本包不设置CPU亲和性、不修改容器CPU配额，也不更改原来的线程设置来适配小机器。不同CPU型号、频率、负载仍可能产生不同时间，不能承诺与历史数据逐位相同。

## 3. 文件结构

| 路径 | 用途 |
|---|---|
| `run.sh` | 薄入口，转交`project.py`，不设置新线程参数 |
| `project.py` | 校验清单、恢复原相对路径、调用旧脚本；不实现协议或计时 |
| `layout.json` | 整理后文件到原工作路径的映射与SHA-256 |
| `config/paper.json` | 原主实验参数，32线程、3次重复 |
| `config/communication_reference.json` | 计算补测的发送量一致性基准，不是新测量 |
| `config/rust_mirror.cfg` | 原Bazel下载规则 |
| `protocols/secure-aggregation-main/` | 原OSA、Willow、VOSA及KAHE实现、BUILD和依赖锁 |
| `protocols/opa-secure-aggregation/` | 原OPA实现、BUILD和依赖锁 |
| `protocols/tacita/` | 原STE+KAHE复现、桥接代码、Cargo锁及上游源码；不含MKLHTS |
| `protocols/mpvas-experiments/` | 原mPVAS协议与真实pairing基准 |
| `experiments/shared/paper_suite.py` | 主实验计划、执行、归一化、证据校验、续跑 |
| `experiments/shared/resources.py` | 补测进程资源记录 |
| `experiments/computation.py` | 原计算补测计划、采样核验、状态与导出 |
| `experiments/tacita_worker.py` | 原补测TACITA桥接执行 |
| `plotting/paper.py` | 主实验分组、均值和64张图的生成 |
| `plotting/computation.py` | 计算补测4张图与采样CSV |
| `plotting/renderer.py` | 统一样式、图例、线性坐标和内嵌小图 |
| `scripts/setup/paper.sh` | 原系统工具、Python虚拟环境和Rust安装流程 |
| `scripts/environment/paper_env.sh` | 原缓存、临时目录和线程环境 |
| `scripts/build/paper.sh` | 原主实验编译及原生测试 |
| `scripts/build/bazel.sh` | 原Bazel启动适配 |
| `scripts/build/pairing/` | 原PBC/Charm构建和环境检查 |
| `scripts/build/computation_prepare.sh` | 原补测准备流程 |
| `scripts/build/computation/build.py` | 原补测隔离副本构建 |
| `scripts/build/computation/instrument.py` | 已确认的计时采样插桩，不向原主实验源码写入 |
| `scripts/build/computation/dependency_locks.py` | 原依赖锁恢复及严格核验 |
| `scripts/build/computation/client_timing.rs` | 原客户端预热/采样实现 |
| `scripts/run/` | 原主实验和补测启动脚本 |
| `scripts/monitor/` | 原状态与进程查看脚本 |
| `scripts/export/` | 原补测导出脚本 |
| `scripts/plot/` | 原绘图shell入口 |
| `scripts/validation/` | 原STE端到端验证 |
| `scripts/tacita/` | 原TACITA构建、执行与验证辅助脚本 |
| `tests/` | 原构建门禁、数据解析、绘图及路径测试；测试夹具不能冒充正式测量 |
| `manifests/` | 主包、补测、主包依赖文件清单；运行所必需，不是审查报告 |
| `third_party/` | 已附带的依赖归档、Bazel、工作锁快照及许可证 |
| `data/paper/` | 336条历史测量及完整下载原始证据 |
| `data/computation/` | 48条历史补测、预热/采样和原始证据 |
| `README/` | 本说明及计算计时说明 |

第一次`prepare`只复制文件，生成`.work/OSA_Paper_Experiments_CPU_20261008/`和`.work/OSA_Computation_Retest_20261013/`，恢复旧脚本需要的相对目录。整理目录里的原脚本不应单独运行，因为它们仍使用原相对路径；应通过入口或下述`.work`原路径运行。

## 4. 上传后安装与编译

将整个`OSA_Final_Code`文件夹上传到数据盘。以下命令按`/root/autodl-tmp/OSA_Final_Code`写；其他Linux机器只替换此目录，不改协议参数。逐条执行，某一步报错则停止，不能跳过门禁继续运行。

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

如果当前`python3`不是3.10，先准备Python3.10，再将`PYTHON_SOURCE`设为该解释器的绝对路径。不能直接删去版本检查。Ubuntu/Debian可用`--install-system`安装系统包，需要root或sudo；系统依赖已装好时可不传该选项。

依次应看到`SETUP_PASS`、`BUILD_PASS`，以及冒烟运行的`SUITE_COMPLETE`。主冒烟包含6种协议/验证基准，不是真实模型训练。原生构建在Linux服务器执行，本地数据校验不能替代它。

## 5. 原方式执行正式实验

进入tmux可以避免终端断开影响任务：

```bash
tmux new -s osa_final
```

在tmux内重新设置路径，按顺序运行：

```bash
cd /root/autodl-tmp/OSA_Final_Code
P="$PWD/.work/OSA_Paper_Experiments_CPU_20261008"
C="$PWD/.work/OSA_Computation_Retest_20261013"

bash "$P/scripts/run_all.sh"
JOBS=32 bash "$C/prepare.sh" "$P"
bash "$C/run.sh" "$P"
```

必须等上一项成功后再执行下一项，不要并行启动。主实验完成标志为`SUITE_COMPLETE`和`FIGURES_PASS count=64`；补测先要求`COMPUTATION_PREPARE_PASS`，正式结束要求`COMPUTATION_RETEST_COMPLETE`和`FIGURES_PASS count=4`。

等价的整合入口仍为`bash run.sh paper`、`JOBS=32 bash run.sh computation-prepare`、`bash run.sh computation`。这些命令只是转交上述原脚本，参数不变。

离开tmux：先按Ctrl+b，再按d。返回：`tmux attach -t osa_final`。不要同时启动两份相同实验。

## 6. 结果、日志与续跑

新主实验结果位于`$P/runs/paper_时间戳/`；新补测位于`$C/runs/computation_时间戳/`。准确路径以终端打印的`RESULTS=`为准。构建和运行日志分别保存在对应工作目录的`logs/`，每个子任务的日志位于结果目录`raw/`。

```bash
# RUN替换为终端打印的主实验RESULTS完整路径。
RUN="$P/runs/paper_实际时间戳"
bash "$P/scripts/status.sh" "$RUN"
tail -n 3 "$RUN/measurements.csv"

# 补测状态。
bash "$C/status.sh" "$P"

# 仅中断后在原主机、原配置、原二进制下续跑。
bash "$P/scripts/run_all.sh" --resume "$RUN"
# 补测另用它自己的RESULTS路径。
bash "$C/run.sh" "$P" --resume "$C/runs/computation_实际时间戳"
```

不要把`data/`里的历史结果当作本机新实验的续跑目录。它们来自原服务器，仅供校验和重画。不要复制别台机器的Python虚拟环境，也不要将旧`.work`覆盖到本包；已有工作目录对应不同清单时，入口会拒绝混用。

## 7. 仅重画随包数据，不重跑实验

完成Linux安装后，在包根目录执行：

```bash
bash run.sh verify-run paper "$PWD/data/paper"
bash run.sh verify-run computation "$PWD/data/computation"
bash run.sh plot paper "$PWD/data/paper"
bash run.sh plot computation "$PWD/data/computation"
```

Windows只绘图时，用已安装matplotlib和numpy的Python执行，不需要安装Bazel、Rust或Charm：

```powershell
cd "$HOME\Desktop\OSA_Final_Code"
python -m pip install -r requirements.txt
python project.py verify
python project.py verify-run paper "$PWD\data\paper"
python project.py verify-run computation "$PWD\data\computation"
python project.py plot paper "$PWD\data\paper"
python project.py plot computation "$PWD\data\computation"
```

固定的绘图依赖推荐搭配Python3.10；已经具备绘图库的本机解释器也可先执行校验和绘图。每次绘图在相应数据目录下创建新的`figures_时间戳/`，不覆盖原始测量。主图目录包含按类别划分的`paper_figures/`和`plot_data/`；补测为`computation/images/`和`computation/data/`。

绘图只呈现真实算术均值，无误差棒；标准差保留在CSV。TACITA尺度明显更大时，使用三协议大图和含全部四协议的内嵌小图。两处都有图例；坐标线性、纵轴从零起、单位为(s)/(KB)/(MB)。图内不添加参数说明，不换数、不平滑。图注另存于输出目录，不混入图片。

## 8. 通信与计时口径

本次整理不改变统计代码。单用户通信量按单个在线客户端发送量，系统总量按各方发送量之和；不重复累加接收量，不计模型下载和一次性公共参数。单委员会成员图用实际应答成员口径，不能把委员会总量直接当作单人量。

主实验的原始单用户计时与后来的预热采样补测并非同一测量流程。不要把两批记录拼成同一曲线。掉线率计算图使用补测数据；详见[计算补测说明](COMPUTATION_CN.md)。旧数据保留实际波动，不为展示优势改数。

## 9. 依赖、网络与许可证

- 系统：Linux x86_64、Python3.10及开发头文件、GCC/G++、clang/lld、GMP、OpenSSL等，按原setup脚本安装。
- Rust：1.87.0；保留Cargo.lock和Bazel锁快照。
- 绘图：`requirements.txt`中的matplotlib3.9.2、numpy1.26.4。
- 已附带：Bazel8.1.1 Linux程序、Bazel依赖归档、PBC0.5.14、固定版本Charm源码、setuptools wheel及许可证。
- 未声称完全离线：系统包、Rust工具链、部分Cargo/crates.io依赖以及锁定的hopcroft-karp Git提交仍可能需要联网。保留这些原依赖来源，没有静默换版本或改用新安装流程。
- 若下载超时，保留日志和已有缓存，排查网络；不要删除锁文件、替换为latest或跳过正确性检查。安装等待不属于协议运行时间。
- 许可证保留在各上游源码根目录和`third_party/LICENSES/`，它们是分发依赖的必要文件。

清单记录此次文档精简和绘图修订，保留原版本摘要。当前整包摘要不等于历史整包摘要，但保留的协议、实验驱动、运行/构建脚本、参数和计时源码与已确认版本逐文件一致。本包不修复或宣称消除原实现已有的协议安全限制，也不保证任何论文录用。
