"""RED metric extraction from nginx access logs (spec §9).

Strategy: parse recent lines, bucket per upstream port (the app's identity on a
shared host), compute req rate + status-class counts + latency percentiles.
Falls back to empty when logs are absent/inaccessible — agents on other hosts
may ship their app's own access logs through the same ingestion instead.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import unquote

LOG_LINE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
# vhost access logs usually carry $host as first field when custom format;
# combined format has it absent, so we accept both.
HOST_PREFIX = re.compile(r"^(\S+) ")


@dataclass
class Bucket:
    port: int | None = None
    requests: int = 0
    status: dict[str, int] = field(default_factory=dict)
    latencies_ms: list[float] = field(default_factory=list)


def _parse_ts(raw: str) -> datetime:
    return datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)


def _pctl(sorted_values: list[float], pct: float) -> float | None:
    if not sorted_values:
        return None
    idx = min(len(sorted_values) - 1, max(0, round(pct / 100 * (len(sorted_values) - 1))))
    return sorted_values[idx]


def parse_access_log(
    text: str,
    window_s: int = 300,
    now: datetime | None = None,
    port_map: dict[str, int] | None = None,
) -> dict[int | None, Bucket]:
    """text -> {upstream_port: Bucket}. Only lines inside the window count."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(seconds=window_s)
    port_map = port_map or {}
    buckets: dict[int | None, Bucket] = {}

    for raw in text.splitlines()[-20000:]:
        m = LOG_LINE.search(raw)
        if not m:
            continue
        try:
            ts = _parse_ts(m.group("ts"))
        except (ValueError, TypeError):
            continue
        if ts < cutoff:
            continue
        status = m.group("status")
        klass = f"{status[0]}xx"
        # latency: nginx $request_time (s) when present in extended formats;
        # absent in combined format, so derive from bytes as a last resort? No —
        # fabricating latency is worse than missing it. Only real fields count.
        lat_ms: float | None = None
        rt = re.search(r"rt=(\d+\.\d+)", raw)
        if rt:
            lat_ms = float(rt.group(1)) * 1000
        upstream = re.search(r"up=([\d.]+):(\d+)", raw) or re.search(
            r"proxy_pass_host[=:](\S+):(\d+)", raw
        )
        port: int | None = None
        if upstream:
            port = int(upstream.group(2))
        else:
            host = port_map.get(unquote(m.group("path").split("/")[1] or ""))
            port = host
        bucket = buckets.setdefault(port, Bucket(port=port))
        bucket.requests += 1
        bucket.status[klass] = bucket.status.get(klass, 0) + 1
        if lat_ms is not None:
            bucket.latencies_ms.append(lat_ms)

    for bucket in buckets.values():
        bucket.latencies_ms.sort()
    return buckets


def summarize(buckets: dict[int | None, Bucket], window_s: int = 300) -> list[dict]:
    out = []
    for port, b in buckets.items():
        req_rate = b.requests / window_s
        total = b.requests or 1
        entry = {
            "port": port,
            "req_rate": round(req_rate, 3),
            "http_2xx": b.status.get("2xx", 0),
            "http_3xx": b.status.get("3xx", 0),
            "http_4xx": b.status.get("4xx", 0),
            "http_5xx": b.status.get("5xx", 0),
            "err_rate": round(
                (b.status.get("4xx", 0) + b.status.get("5xx", 0)) / total, 4
            ),
            "p50_ms": _pctl(b.latencies_ms, 50),
            "p95_ms": _pctl(b.latencies_ms, 95),
            "p99_ms": _pctl(b.latencies_ms, 99),
            "window_s": window_s,
            "ts": datetime.now(UTC).isoformat(),
        }
        out.append(entry)
    return out


def tail_text(path: str | Path, max_bytes: int = 2_000_000) -> str:
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            return fh.read().decode(errors="ignore")
    except OSError:
        return ""


def collect_nginx_red(
    log_paths: list[str] | None = None,
    window_s: int = 300,
    port_map: dict[str, int] | None = None,
) -> list[dict]:
    paths = log_paths or ["/var/log/nginx/access.log"]
    text = "\n".join(tail_text(p) for p in paths)
    if not text.strip():
        return []
    return summarize(parse_access_log(text, window_s=window_s, port_map=port_map), window_s)
