"""Read-only Linux resource samples; no extra server dependency."""
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def pairs(path):
    result = {}
    try:
        for line in Path(path).read_text().splitlines():
            fields = line.replace(":", "").split()
            if len(fields) >= 2:
                try:
                    result[fields[0]] = int(fields[1])
                except ValueError:
                    pass
    except OSError:
        pass
    return result


def cgroup_snapshot():
    result = {}
    base = Path("/sys/fs/cgroup")
    candidates = [base]
    try:
        for line in Path("/proc/self/cgroup").read_text().splitlines():
            ident, controllers, relative = line.split(":", 2)
            if ident == "0" and not controllers:
                candidates.insert(0, base / relative.lstrip("/"))
            else:
                for ctrl in controllers.split(","):
                    candidates.extend((base / ctrl / relative.lstrip("/"), base / ctrl))
    except OSError:
        return result
    names = ("memory.current", "memory.max", "memory.peak", "memory.events",
             "memory.swap.current", "memory.swap.max", "cpu.max", "cpu.stat",
             "memory.usage_in_bytes", "memory.limit_in_bytes", "memory.failcnt",
             "memory.memsw.usage_in_bytes", "cpu.cfs_quota_us", "cpu.cfs_period_us")
    for directory in candidates:
        for name in names:
            if name in result:
                continue
            try:
                result[name] = {"path": str(directory / name),
                                "value": (directory / name).read_text().strip()}
            except OSError:
                pass
    return result


def snapshot(pgid=None):
    result = dict(unix_time=time.time(), host_meminfo_kib=pairs("/proc/meminfo"),
                  host_vmstat={k: v for k, v in pairs("/proc/vmstat").items()
                               if k in ("pswpin", "pswpout", "pgmajfault")},
                  cgroup=cgroup_snapshot())
    processes = []
    if pgid is not None and os.name != "nt":
        for path in Path("/proc").glob("[0-9]*"):
            try:
                stat = (path / "stat").read_text().rsplit(")", 1)[1].split()
                if int(stat[2]) != pgid:
                    continue
                memory = pairs(path / "status")
                processes.append(dict(pid=int(path.name), state=stat[0],
                    cpu_ticks=int(stat[11]) + int(stat[12]),
                    rss_bytes=int(stat[21]) * os.sysconf("SC_PAGE_SIZE"),
                    swap_kib=memory.get("VmSwap", 0)))
            except (OSError, ValueError, IndexError):
                continue
    result["processes"] = processes
    result["process_group_rss_bytes"] = sum(p["rss_bytes"] for p in processes)
    result["process_group_swap_kib"] = sum(p["swap_kib"] for p in processes)
    result["clock_ticks_per_second"] = os.sysconf("SC_CLK_TCK") if os.name != "nt" else None
    return result


def stop_group(proc):
    if os.name == "nt":
        if proc.poll() is None:
            proc.terminate()
    else:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The driver can exit before its native children. Clean up the owned group too.
    if os.name != "nt":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif proc.poll() is None:
        proc.kill()
    proc.wait()


def run(command, env, cwd, attempt, timeout, interval):
    start = time.monotonic()
    peak_rss = peak_swap = sample_count = 0
    proc = None
    code = None
    with (attempt / "process.log").open("w", encoding="utf-8") as log, \
            (attempt / "resources.jsonl").open("w", encoding="utf-8") as samples:
        def sample():
            nonlocal peak_rss, peak_swap, sample_count
            item = snapshot(proc.pid if proc else None)
            peak_rss = max(peak_rss, item["process_group_rss_bytes"])
            peak_swap = max(peak_swap, item["process_group_swap_kib"])
            sample_count += 1
            samples.write(json.dumps(item) + "\n")
            samples.flush()

        sample()
        try:
            proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=log,
                                    stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
            (attempt / "pid.json").write_text(json.dumps({"pid": proc.pid, "unix_started": time.time()}))
            while True:
                sample()
                code = proc.poll()
                if code is not None:
                    if code:
                        stop_group(proc)
                    break
                if time.monotonic() - start > timeout:
                    raise TimeoutError(f"Exceeded {timeout}s: {attempt}")
                time.sleep(interval)
        except BaseException:
            if proc is not None:
                stop_group(proc)
            raise
        finally:
            sample()
            (attempt / "resource_summary.json").write_text(json.dumps(dict(
                sample_count=sample_count, interval_seconds=interval,
                peak_sampled_process_group_rss_bytes=peak_rss,
                peak_sampled_process_group_swap_kib=peak_swap,
                exit_code=code, elapsed_seconds=time.monotonic() - start,
                limitations="Periodic samples can miss peaks. Summed RSS can double-count shared pages. "
                "Host and cgroup counters can include other jobs. Missing fields mean unavailable, not zero."),
                indent=2) + "\n", encoding="utf-8")
    if code:
        raise RuntimeError(f"Process exit {code}; see {attempt / 'process.log'}")
    return time.monotonic() - start
