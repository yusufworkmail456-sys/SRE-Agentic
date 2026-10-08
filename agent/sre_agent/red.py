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


# Apdex buckets (seconds). T = 1.3s (satisfying <= T, tolerating <= 4T).
APDEX_T_S = 1.3
# Histogram buckets in ms (Prometheus-style, http_request_duration).
HIST_BUCKETS_MS = (50, 100, 250, 500, 1000, 2500, 5000, 10000)
MAX_ENDPOINTS = 12



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
) -> tuple[dict[int | None, Bucket], list[dict]]:
    """text -> ({upstream_port: Bucket}, per-endpoint stats).

    Only lines inside the window count. Endpoint key = upstream port + method
    + normalized route (numeric ids collapsed) so dashboards show per-route
    latency/errors like mainstream APMs.
    """
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(seconds=window_s)
    port_map = port_map or {}
    buckets: dict[int | None, Bucket] = {}
    endpoints: dict[str, dict] = {}

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

        # ---- per-endpoint aggregation (M12)
        method = m.group("method") or "?"
        route = _normalize_route(unquote(m.group("path")))
        key = f"{method} {route}"
        ep = endpoints.setdefault(
            key, {"route": route, "method": method, "port": port, "requests": 0,
                  "status": {}, "latencies_ms": []}
        )
        ep["requests"] += 1
        ep["status"][klass] = ep["status"].get(klass, 0) + 1
        if lat_ms is not None:
            ep["latencies_ms"].append(lat_ms)

    for bucket in buckets.values():
        bucket.latencies_ms.sort()
    ranked = _rank_endpoints(endpoints)
    return buckets, ranked


_ID_PARTS = re.compile(r"/\d+(?=/|$)")
_UUID = re.compile(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", re.I)
_HEX32 = re.compile(r"/[0-9a-f]{16,}(?=/|$)", re.I)


def _normalize_route(path: str) -> str:
    """Collapse ids/uuids/hashes so routes aggregate across requests."""
    path = _UUID.sub("/{id}", path)
    path = _HEX32.sub("/{id}", path)
    path = _ID_PARTS.sub("/{id}", path)
    # strip query string remnants
    return path.split("?")[0][:120]


def _rank_endpoints(endpoints: dict[str, dict]) -> list[dict]:
    """Top endpoints by requests; each carries p95, error rate, apdex, histogram."""
    def _pctl(sorted_vals: list[float], pct: float) -> float | None:
        if not sorted_vals:
            return None
        idx = min(len(sorted_vals) - 1, max(0, round(pct / 100 * (len(sorted_vals) - 1))))
        return sorted_vals[idx]

    out = []
    for key, ep in endpoints.items():
        lats = sorted(ep["latencies_ms"])
        total = ep["requests"]
        errs = ep["status"].get("4xx", 0) + ep["status"].get("5xx", 0)
        satisfied = sum(1 for v in lats if v <= APDEX_T_S * 1000)
        tolerating = sum(1 for v in lats if APDEX_T_S * 1000 < v <= APDEX_T_S * 4 * 1000)
        hist = {str(b): 0 for b in HIST_BUCKETS_MS}
        for v in lats:
            for b in HIST_BUCKETS_MS:
                if v <= b:
                    hist[str(b)] += 1
        out.append({
            "route": ep["route"],
            "method": ep["method"],
            "port": ep["port"],
            "requests": total,
            "err_rate": round(errs / total, 4),
            "p50_ms": _pctl(lats, 50),
            "p95_ms": _pctl(lats, 95),
            "p99_ms": _pctl(lats, 99),
            "apdex": round((satisfied + tolerating / 2) / total, 3) if total else None,
            "histogram": hist,
        })
    out.sort(key=lambda x: x["requests"], reverse=True)
    return out[:MAX_ENDPOINTS]


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
) -> tuple[list[dict], list[dict]]:
    """Returns (RED entries, per-endpoint stats)."""
    paths = log_paths or ["/var/log/nginx/access.log"]
    text = "\n".join(tail_text(p) for p in paths)
    if not text.strip():
        return [], []
    buckets, endpoints = parse_access_log(text, window_s=window_s, port_map=port_map)
    return summarize(buckets, window_s), endpoints
