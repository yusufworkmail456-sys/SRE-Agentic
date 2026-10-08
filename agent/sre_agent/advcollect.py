"""M12 collectors: saturation (USE), per-process, kernel/OOM events.

All read-only psutil/journald reads, bounded output. Designed to ride the
existing ingest payload (`metrics.host_saturation`, `processes`, `events`).
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import psutil


def collect_saturation() -> dict:
    """USE method: utilization already in base metrics; here = saturation +
    errors. All values None-safe; missing keys simply stay absent."""
    out: dict = {}
    load1, load5, load15 = (psutil.getloadavg() or (0, 0, 0))
    ncpu = psutil.cpu_count() or 1
    out["load1"], out["load5"], out["load15"] = round(load1, 2), round(load5, 2), round(load15, 2)
    out["load1_per_core"] = round(load1 / ncpu, 3)
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    out["swap_pct"] = swap.percent
    out["swap_used_mb"] = round(swap.used / 1024 / 1024, 1)
    out["mem_available_mb"] = round(mem.available / 1024 / 1024, 1)
    # disk I/O since boot -> instantaneous needs deltas; ship counters, the
    # platform computes rates against the previous point.
    try:
        io = psutil.disk_io_counters()
        if io:
            out["disk_read_bytes"] = io.read_bytes
            out["disk_write_bytes"] = io.write_bytes
            out["disk_read_ops"] = io.read_count
            out["disk_write_ops"] = io.write_count
            out["disk_read_ms"] = io.read_time
            out["disk_write_ms"] = io.write_time
    except Exception:
        pass
    net = psutil.net_io_counters()
    out["net_errin"] = net.errin
    out["net_errout"] = net.errout
    out["net_dropin"] = net.dropin
    out["net_dropout"] = net.dropout
    # TCP connection states (bounded snapshot)
    try:
        states: dict[str, int] = {}
        for conn in psutil.net_connections(kind="tcp"):
            s = str(conn.status).lower()
            states[s] = states.get(s, 0) + 1
        out["tcp_states"] = states
    except Exception:
        pass
    # fd pressure on the host
    try:
        out["fd_allocated"] = _fd_count()
    except Exception:
        pass
    return out


def _fd_count() -> int:
    try:
        return len(Path("/proc/sys/fs/file-nr").read_text().split()[0])
    except Exception:
        return 0


def collect_processes(top_n: int = 8) -> list[dict]:
    """Top processes by CPU (cumulative ptimes) + memory, service-relevant."""
    procs: list[dict] = []
    for p in psutil.process_iter(["pid", "name", "username", "cpu_times", "memory_info", "create_time", "cmdline"]):
        try:
            info = p.info
            cpu_t = info.get("cpu_times")
            mem = info.get("memory_info")
            procs.append({
                "pid": info["pid"],
                "name": (info.get("name") or "?")[:40],
                "user": (info.get("username") or "?")[:24],
                # cumulative CPU seconds; platform derives % from deltas
                "cpu_s": round((cpu_t.user + cpu_t.system), 2) if cpu_t else 0.0,
                "rss_mb": round(mem.rss / 1024 / 1024, 1) if mem else 0.0,
                "started_at": info.get("create_time"),
                "cmd": " ".join((info.get("cmdline") or []))[:160],
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    procs.sort(key=lambda x: (x["cpu_s"], x["rss_mb"]), reverse=True)
    return procs[:top_n]


def collect_kernel_events(since_minutes: int = 5, max_events: int = 20) -> list[dict]:
    """OOM kills, segfaults, service crash-loops from the journal."""
    if not (Path("/usr/bin/journalctl").exists() or Path("/bin/journalctl").exists()):
        return []
    since = f"-{since_minutes}min"
    patterns = [
        ("oom", "Out of memory"),
        ("oom", "oom-kill"),
        ("oom", "Killed process"),
        ("segfault", "segfault"),
        ("segfault", "general protection fault"),
        ("crash", "Main process exited"),
    ]
    events: list[dict] = []
    seen: set[tuple] = set()
    for kind, needle in patterns:
        if len(events) >= max_events:
            break
        try:
            proc = subprocess.run(
                ["journalctl", f"--since={since}", "--no-pager", "-q", "-g", needle, "-n", str(max_events)],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for line in proc.stdout.splitlines():
            if len(events) >= max_events:
                break
            line = line.strip()
            if not line or (kind, line[:120]) in seen:
                continue
            seen.add((kind, line[:120]))
            events.append({"kind": kind, "summary": line[:400]})
    return events
