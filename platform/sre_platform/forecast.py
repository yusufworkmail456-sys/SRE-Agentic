"""Predictive / capacity rules (spec §28 Phase 4 M10): disk & memory exhaustion ETA.

Linear trend over server-level metric history (48h max) -> hours-until-full.
Fires once (upsert) so it never spams; resolves when trend clears.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .detection import _resolve_if_recovered, _upsert_finding
from .models import (
    Application,
    Confidence,
    FindingCategory,
    MetricPoint,
    Severity,
)


def _trend_hours_to(pairs: list[tuple[datetime, float]], threshold: float) -> float | None:
    """Least-squares slope over (ts, pct) pairs -> hours until `threshold`."""
    if len(pairs) < 6:
        return None
    t0 = pairs[0][0]
    xs = [((ts - t0).total_seconds() / 3600, pct) for ts, pct in pairs]
    n = len(xs)
    mean_x = sum(x for x, _ in xs) / n
    mean_y = sum(y for _, y in xs) / n
    denom = sum((x - mean_x) ** 2 for x, _ in xs)
    if denom == 0:
        return None
    slope = sum((x - mean_x) * (y - mean_y) for x, y in xs) / denom  # pct per hour
    if slope <= 0.01:  # flat/declining — no exhaustion
        return None
    latest_y = xs[-1][1]
    if latest_y >= threshold:
        return 0.0
    return round((threshold - latest_y) / slope, 1)


def rule_capacity_forecast(db: Session, app_row: Application) -> None:
    """Predictive disk finding: hours-to-95% from server metric history."""
    rule = "disk_exhaustion_forecast"
    if not app_row.server_id:
        _resolve_if_recovered(db, app_row, rule)
        return
    since = datetime.now(UTC) - timedelta(hours=48)
    points = db.scalars(
        select(MetricPoint)
        .where(
            MetricPoint.server_id == app_row.server_id,
            MetricPoint.disk_pct.is_not(None),
            MetricPoint.ts >= since,
        )
        .order_by(MetricPoint.ts)
    ).all()
    pairs = [
        (p.ts.replace(tzinfo=UTC) if p.ts.tzinfo is None else p.ts, float(p.disk_pct))
        for p in points
        if p.disk_pct is not None
    ]
    latest_disk = pairs[-1][1] if pairs else None
    # Predictive rule: fire on the TREND, not the absolute level (the static
    # rule_disk_capacity covers ≥85% already). ≤72h to 95% = act now.
    hours = _trend_hours_to(pairs, 95.0)
    if hours is not None and hours <= 72:
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.capacity,
                "severity": Severity.critical if hours <= 24 else Severity.warning,
                "confidence": Confidence.likely,
                "title": f"Disk forecast: ~{hours:.0f}h until 95% full",
                "observation": (
                    f"Root disk at {latest_disk:.0f}% with an upward trend; linear "
                    f"projection reaches 95% in ~{hours:.0f}h (48h history, n={len(pairs)})."
                ),
                "probable_cause": "Steady log/artifact growth on a fixed-size volume.",
                "recommendation": "Rotate/clean logs or expand volume within the next maintenance window.",
                "evidence": [{
                    "source": "metric_point", "ref": f"server:{app_row.server_id}:disk_trend",
                    "value": {"latest_pct": latest_disk, "hours_to_95": hours,
                              "samples": len(pairs)},
                }],
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)
