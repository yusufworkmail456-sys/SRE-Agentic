"""Metric ingestion + rollups + baselines (spec §9, §7 Health, §21 SLO input)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from .models import (
    Application,
    EndpointStat,
    HostEvent,
    MetricPoint,
    MetricRollup5m,
    ProcessSnapshot,
    Server,
)


def store_server_metrics(db: Session, server: Server, metrics: dict) -> None:
    db.add(
        MetricPoint(
            server_id=server.id,
            ts=datetime.now(UTC),
            cpu_pct=metrics.get("cpu_pct"),
            mem_pct=metrics.get("mem_pct"),
            disk_pct=metrics.get("disk_pct"),
            net_rx_kb=metrics.get("net_rx_kb"),
            net_tx_kb=metrics.get("net_tx_kb"),
            procs=metrics.get("procs"),
            load1=metrics.get("load1"),
            load5=metrics.get("load5"),
            load15=metrics.get("load15"),
            swap_pct=metrics.get("swap_pct"),
            disk_read_kbps=metrics.get("disk_read_kbps"),
            disk_write_kbps=metrics.get("disk_write_kbps"),
            net_errs=metrics.get("net_errs"),
            net_drops=metrics.get("net_drops"),
            raw=metrics,
        )
    )
    server.last_seen = datetime.now(UTC)


def store_app_red(db: Session, server: Server, red_entries: list[dict]) -> int:
    """Each RED entry is keyed by upstream port; map port -> application."""
    stored = 0
    apps = db.scalars(select(Application).where(Application.server_id == server.id)).all()
    by_port: dict[int, Application] = {}
    for app_row in apps:
        for workload in app_row.workloads:
            for instance in workload.instances:
                if instance.listen_port:
                    by_port[instance.listen_port] = app_row
    now = datetime.now(UTC)
    for entry in red_entries:
        port = entry.get("port")
        app_row = by_port.get(port)
        if app_row is None:
            continue
        db.add(
            MetricPoint(
                application_id=app_row.id,
                server_id=server.id,
                ts=now,
                req_rate=entry.get("req_rate"),
                err_rate=entry.get("err_rate"),
                http_2xx=entry.get("http_2xx"),
                http_3xx=entry.get("http_3xx"),
                http_4xx=entry.get("http_4xx"),
                http_5xx=entry.get("http_5xx"),
                p50_ms=entry.get("p50_ms"),
                p95_ms=entry.get("p95_ms"),
                p99_ms=entry.get("p99_ms"),
                raw=entry,
            )
        )
        stored += 1
    return stored


def _app_by_port(db: Session, server: Server, port: int | None) -> Application | None:
    if port is None:
        return None
    apps = db.scalars(select(Application).where(Application.server_id == server.id)).all()
    for app_row in apps:
        for workload in app_row.workloads:
            for instance in workload.instances:
                if instance.listen_port == port:
                    return app_row
    return None


def store_endpoint_stats(db: Session, server: Server, endpoints: list[dict]) -> int:
    """M12: persist per-endpoint RED/Apdex rows (bounded, most recent window)."""
    stored = 0
    now = datetime.now(UTC)
    app_cache: dict[int | None, Application | None] = {}
    for entry in endpoints[:24]:
        port = entry.get("port")
        if port not in app_cache:
            app_cache[port] = _app_by_port(db, server, port)
        app_row = app_cache[port]
        db.add(
            EndpointStat(
                application_id=app_row.id if app_row else None,
                server_id=server.id,
                ts=now,
                route=str(entry.get("route", "?"))[:200],
                method=str(entry.get("method", "?"))[:10],
                requests=int(entry.get("requests") or 0),
                err_rate=entry.get("err_rate"),
                p50_ms=entry.get("p50_ms"),
                p95_ms=entry.get("p95_ms"),
                p99_ms=entry.get("p99_ms"),
                apdex=entry.get("apdex"),
                histogram=entry.get("histogram") or {},
            )
        )
        stored += 1
    return stored


def store_process_snapshot(db: Session, server: Server, processes: list[dict]) -> None:
    db.add(ProcessSnapshot(server_id=server.id, rows=processes[:16]))


def store_host_events(db: Session, server: Server, events: list[dict]) -> int:
    """Dedupe within the last hour; new events also become timeline entries."""
    from .services import touch_timeline

    stored = 0
    apps = db.scalars(select(Application).where(Application.server_id == server.id)).all()
    for event in events[:20]:
        summary = str(event.get("summary", ""))[:400]
        kind = str(event.get("kind", "kernel"))
        hour_ago = datetime.now(UTC) - timedelta(hours=1)
        db.flush()  # make earlier inserts in this session visible to the dup query
        dup = db.scalar(
            select(HostEvent.id).where(
                HostEvent.server_id == server.id,
                HostEvent.kind == kind,
                HostEvent.summary == summary,
                HostEvent.ts >= hour_ago,
            )
        )
        if dup:
            continue
        db.add(HostEvent(server_id=server.id, kind=kind, summary=summary))
        db.flush()
        touch_timeline(
            db, apps[0].id if apps else None, "host_event",
            f"[{kind}] {summary[:160]}", actor="agent",
        )
        stored += 1
    return stored


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


def rollup_5m(db: Session, app_id: int, bucket_start: datetime) -> MetricRollup5m | None:
    """Aggregate raw points of one 5-minute bucket into a rollup row."""
    bucket_start = _utc(bucket_start)
    bucket_end = bucket_start + timedelta(minutes=5)
    rows = db.scalars(
        select(MetricPoint)
        .where(
            MetricPoint.application_id == app_id,
            MetricPoint.ts >= bucket_start,
            MetricPoint.ts < bucket_end,
        )
    ).all()
    if not rows:
        return None

    def avg(values: list[float | None]) -> float | None:
        vals = [v for v in values if v is not None]
        return round(sum(vals) / len(vals), 3) if vals else None

    p95s = [r.p95_ms for r in rows if r.p95_ms is not None]
    rollup = db.scalar(
        select(MetricRollup5m).where(
            MetricRollup5m.application_id == app_id, MetricRollup5m.bucket == bucket_start
        )
    )
    if rollup is None:
        rollup = MetricRollup5m(application_id=app_id, bucket=bucket_start)
        db.add(rollup)
    rollup.samples = len(rows)
    rollup.err_rate_avg = avg([r.err_rate for r in rows])
    rollup.p95_avg = avg(p95s)
    rollup.p95_max = round(max(p95s), 3) if p95s else None
    rollup.cpu_avg = avg([r.cpu_pct for r in rows])
    rollup.mem_avg = avg([r.mem_pct for r in rows])
    return rollup


def run_rollups(db: Session, lookback_minutes: int = 15) -> int:
    """Roll up recent buckets for all apps that have raw points."""
    now = _utc(datetime.now(UTC)).replace(second=0, microsecond=0)
    start = now - timedelta(minutes=lookback_minutes)
    app_ids = db.scalars(
        select(MetricPoint.application_id)
        .where(MetricPoint.ts >= start, MetricPoint.application_id.is_not(None))
        .distinct()
    ).all()
    count = 0
    for app_id in app_ids:
        first = db.scalar(
            select(func.min(MetricPoint.ts)).where(
                MetricPoint.application_id == app_id, MetricPoint.ts >= start
            )
        )
        if first is None:
            continue
        first = _utc(first)
        bucket = first.replace(second=0, microsecond=0) - timedelta(minutes=first.minute % 5)
        while bucket <= now:
            if rollup_5m(db, app_id, bucket) is not None:
                count += 1
            bucket += timedelta(minutes=5)
    return count


def baseline(db: Session, app_id: int, metric_attr: str, days: int = 7) -> dict:
    """Rollup-based baseline — used by trend findings (§11)."""
    now = _utc(datetime.now(UTC))
    since = now - timedelta(days=days)
    rows = db.scalars(
        select(MetricRollup5m)
        .where(
            MetricRollup5m.application_id == app_id,
            MetricRollup5m.bucket >= since,
        )
    ).all()
    values = [getattr(r, metric_attr) for r in rows if getattr(r, metric_attr) is not None]
    if len(values) < 4:
        return {"n": len(values), "mean": None, "std": None}
    mean = sum(values) / len(values)
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return {"n": len(values), "mean": mean, "std": var**0.5}


def latest_points(db: Session, app_id: int, limit: int = 60) -> list[MetricPoint]:
    return db.scalars(
        select(MetricPoint)
        .where(MetricPoint.application_id == app_id)
        .order_by(MetricPoint.ts.desc())
        .limit(limit)
    ).all()


# ---------------------------------------------------------------- M12 queries
def latest_endpoint_stats(db: Session, app_id: int, max_age_min: int = 15, limit: int = 12) -> list[EndpointStat]:
    """Most recent EndpointStat per route (dedup), within the freshness window."""
    since = datetime.now(UTC) - timedelta(minutes=max_age_min)
    rows = db.scalars(
        select(EndpointStat)
        .where(EndpointStat.application_id == app_id, EndpointStat.ts >= since)
        .order_by(EndpointStat.ts.desc())
        .limit(120)
    ).all()
    seen: set[str] = set()
    out: list[EndpointStat] = []
    for row in rows:
        key = f"{row.method} {row.route}"
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
        if len(out) >= limit:
            break
    return out


def latest_process_snapshot(db: Session, server_id: int | None, max_age_min: int = 10) -> list[dict]:
    if server_id is None:
        return []
    since = datetime.now(UTC) - timedelta(minutes=max_age_min)
    row = db.scalars(
        select(ProcessSnapshot)
        .where(ProcessSnapshot.server_id == server_id, ProcessSnapshot.ts >= since)
        .order_by(ProcessSnapshot.ts.desc())
        .limit(1)
    ).first()
    return list(row.rows or []) if row else []


def latest_host_events(db: Session, server_id: int | None, limit: int = 6) -> list[HostEvent]:
    if server_id is None:
        return []
    return list(db.scalars(
        select(HostEvent)
        .where(HostEvent.server_id == server_id)
        .order_by(HostEvent.ts.desc())
        .limit(limit)
    ).all())
