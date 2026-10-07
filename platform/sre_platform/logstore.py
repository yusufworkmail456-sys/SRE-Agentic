"""Log storage + error-rate features for detection (spec §7, §11)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Application, LogBatch, Workload


def store_log_batches(db: Session, server, batches: list[dict]) -> int:
    """Attach batches to apps by workload_ref (unit name or file path)."""
    stored = 0
    apps = db.scalars(
        select(Application).where(Application.server_id == server.id)
    ).all() if server.id else []
    workloads: dict[str, tuple[int, int]] = {}
    for app_row in apps:
        for workload in app_row.workloads:
            if workload.external_id:
                workloads[workload.external_id] = (app_row.id, workload.id)
            if workload.name:
                workloads.setdefault(workload.name, (app_row.id, workload.id))
    now = datetime.now(UTC)
    for batch in batches or []:
        ref = batch.get("workload_ref", "")
        app_id = workload_id = None
        for key, (a_id, w_id) in workloads.items():
            if key and (key in ref or ref in key):
                app_id, workload_id = a_id, w_id
                break
        # Unmatched batches still store server-level (app_id NULL) for search.
        ts_start = _parse_or(batch.get("ts_start"), now - timedelta(minutes=5))
        ts_end = _parse_or(batch.get("ts_end"), now)
        db.add(
            LogBatch(
                application_id=app_id,
                workload_id=workload_id,
                ts_start=ts_start,
                ts_end=ts_end,
                source=batch.get("source"),
                level_counts=batch.get("level_counts", {}),
                sample_lines=batch.get("sample_lines", []),
            )
        )
        stored += 1
    return stored


def _parse_or(raw, default: datetime) -> datetime:
    if not raw:
        return default
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(str(raw)[:19], fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return default


def recent_error_samples(db: Session, app_id: int, minutes: int = 30, limit: int = 10) -> list[dict]:
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    batches = db.scalars(
        select(LogBatch)
        .where(LogBatch.application_id == app_id, LogBatch.ts_end >= since)
        .order_by(LogBatch.ts_end.desc())
        .limit(20)
    ).all()
    out: list[dict] = []
    for batch in batches:
        errors = batch.level_counts.get("ERROR", 0) + batch.level_counts.get("CRITICAL", 0)
        if errors:
            out.append(
                {
                    "ts": batch.ts_end.isoformat(),
                    "source": batch.source,
                    "errors": errors,
                    "samples": batch.sample_lines[:3],
                }
            )
        if len(out) >= limit:
            break
    return out


def window_error_counts(db: Session, app_id: int, minutes: int = 15) -> dict[str, int]:
    since = datetime.now(UTC) - timedelta(minutes=minutes)
    totals: dict[str, int] = {}
    batches = db.scalars(
        select(LogBatch).where(LogBatch.application_id == app_id, LogBatch.ts_end >= since)
    ).all()
    for batch in batches:
        for level, count in (batch.level_counts or {}).items():
            totals[level] = totals.get(level, 0) + int(count)
    return totals
