"""Findings engine v1 (spec §11): deterministic rules -> evidence-backed findings.

Rules are cheap, explainable, and run every sweep. Same (app, rule) staying in
violation updates last_seen instead of spawning duplicates. Every finding must
carry evidence items pointing at real rows.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import metrics as metrics_svc
from .models import (
    Application,
    Confidence,
    Finding,
    FindingCategory,
    FindingStatus,
    HealthCheck,
    MetricPoint,
    Severity,
    TimelineEvent,
)

BASELINE_MIN_POINTS = 8


def _evidence(source: str, ref: str, value, ts=None) -> dict:
    stamp = ts or datetime.now(UTC)
    return {
        "source": source,
        "ref": ref,
        "value": value,
        "ts": stamp.isoformat() if isinstance(stamp, datetime) else stamp,
    }


def _upsert_finding(
    db: Session,
    app_row: Application,
    rule_key: str,
    defaults: dict,
) -> Finding | None:
    existing = db.scalar(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.rule_key == rule_key,
            Finding.status.in_([FindingStatus.open, FindingStatus.acknowledged]),
        )
    )
    if existing is not None:
        existing.last_seen = datetime.now(UTC)
        existing.evidence = defaults.get("evidence", existing.evidence)
        existing.observation = defaults.get("observation", existing.observation)
        return existing
    finding = Finding(
        application_id=app_row.id,
        rule_key=rule_key,
        status=FindingStatus.open,
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
        **{k: v for k, v in defaults.items() if k != "evidence"} | {"evidence": defaults.get("evidence", [])},
    )
    db.add(finding)
    db.flush()
    db.add(
        TimelineEvent(
            application_id=app_row.id,
            kind="finding",
            actor="system",
            summary=f"Finding [{defaults.get('severity', Severity.warning).value}] {defaults.get('title', rule_key)}",
            payload={"finding_id": finding.id, "rule": rule_key},
        )
    )
    return finding


def _resolve_if_recovered(db: Session, app_row: Application, rule_key: str) -> None:
    existing = db.scalar(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.rule_key == rule_key,
            Finding.status == FindingStatus.open,
        )
    )
    if existing is not None:
        existing.status = FindingStatus.resolved
        existing.resolved_at = datetime.now(UTC)


# ---------------------------------------------------------------- rules
def rule_error_rate(db: Session, app_row: Application) -> None:
    rule = "error_rate_elevated"
    points = metrics_svc.latest_points(db, app_row.id, limit=3)
    recent = [p for p in points if p.err_rate is not None]
    if len(recent) < 3:
        _resolve_if_recovered(db, app_row, rule)
        return
    avg_err = sum(r.err_rate for r in recent) / len(recent)
    if avg_err >= 0.05:  # 5% over the recent window
        worst = max(recent, key=lambda r: r.err_rate)
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.reliability,
                "severity": Severity.critical if avg_err >= 0.15 else Severity.warning,
                "confidence": Confidence.confirmed,
                "title": f"Error rate elevated ({avg_err:.1%} recent average)",
                "observation": (
                    f"Average error rate over the last {len(recent)} samples is {avg_err:.1%} "
                    f"(4xx+5xx / total requests). Latest sample: {worst.err_rate:.1%}."
                ),
                "probable_cause": "New deployment, dependency failure, or unhandled exception path.",
                "recommendation": "Inspect 5xx log lines and recent deployments before restarting anything.",
                "evidence": [
                    {"source": "metric_point", "ref": f"app:{app_row.id}:err_rate", "value": avg_err,
                     "ts": worst.ts.isoformat()},
                    {"source": "metric_point", "ref": f"app:{app_row.id}:http_5xx", "value": worst.http_5xx,
                     "ts": worst.ts.isoformat()},
                ],
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)


def rule_latency_zscore(db: Session, app_row: Application) -> None:
    rule = "p95_spike"
    base = metrics_svc.baseline(db, app_row.id, "p95_avg")
    points = metrics_svc.latest_points(db, app_row.id, limit=10)
    recent_p95 = [p.p95_ms for p in points if p.p95_ms is not None]
    if base["n"] < BASELINE_MIN_POINTS or not recent_p95:
        _resolve_if_recovered(db, app_row, rule)
        return
    recent_avg = sum(recent_p95) / len(recent_p95)
    mean, std = base["mean"], base["std"] or 1.0
    z = (recent_avg - mean) / (std or 1.0)
    if z >= 3.0 and recent_avg > mean * 1.5:
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.performance,
                "severity": Severity.warning,
                "confidence": Confidence.likely,
                "title": f"P95 latency spike (z={z:.1f} vs 7-day baseline)",
                "observation": (
                    f"Recent P95 average {recent_avg:.0f}ms vs baseline {mean:.0f}ms "
                    f"(+{(recent_avg / max(mean, 1) - 1):.0%})."
                ),
                "probable_cause": "Slow dependency, GC pressure, or increased load after deployment.",
                "recommendation": "Correlate with recent deployments and dependency latency before acting.",
                "evidence": [
                    {"source": "metric_rollup_5m", "ref": f"app:{app_row.id}:p95_baseline",
                     "value": {"mean": round(mean, 1), "std": round(std, 1), "n": base["n"]}},
                    {"source": "metric_point", "ref": f"app:{app_row.id}:p95_recent",
                     "value": round(recent_avg, 1)},
                ],
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)


def rule_disk_capacity(db: Session, app_row: Application) -> None:
    rule = "disk_trending_full"
    points = metrics_svc.latest_points(db, app_row.id, limit=1)
    server_points = (
        db.scalars(
            select(MetricPoint)
            .where(MetricPoint.server_id == app_row.server_id, MetricPoint.disk_pct.is_not(None))
            .order_by(MetricPoint.ts.desc())
            .limit(1)
        ).all()
        if app_row.server_id
        else []
    )
    disk = server_points[0].disk_pct if server_points else None
    if disk is not None and disk >= 85:
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.capacity,
                "severity": Severity.critical if disk >= 92 else Severity.warning,
                "confidence": Confidence.confirmed,
                "title": f"Disk usage {disk:.0f}% on host",
                "observation": f"Root filesystem at {disk:.0f}% — trending toward exhaustion.",
                "probable_cause": "Log growth, artifact accumulation, or undersized volume.",
                "recommendation": "Check largest log dirs; configure rotation before cleanup.",
                "evidence": [{"source": "metric_point", "ref": f"server:{app_row.server_id}:disk_pct",
                              "value": disk}],
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)


def rule_health_flap(db: Session, app_row: Application) -> None:
    rule = "health_check_failures"
    checks = db.scalars(
        select(HealthCheck).where(HealthCheck.application_id == app_row.id)
    ).all()
    failing = [h for h in checks if h.consecutive_failures >= 2]
    if failing:
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.reliability,
                "severity": Severity.warning,
                "confidence": Confidence.confirmed,
                "title": f"Health check failing on {len(failing)} target(s)",
                "observation": "; ".join(
                    f"{h.target} ({h.consecutive_failures} consecutive fails)" for h in failing
                ),
                "probable_cause": "Process restart loop, port change, or upstream saturation.",
                "recommendation": "Verify process alive and port binding; incident opens at 3 fails.",
                "evidence": [
                    {"source": "health_check", "ref": f"hc:{h.id}", "value": h.consecutive_failures}
                    for h in failing
                ],
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)


def rule_security_root_process(db: Session, app_row: Application) -> None:
    """Deployment hygiene: app processes should not run as root (spec §11)."""
    rule = "process_runs_as_root"
    root_instances = [
        (w, i)
        for w in app_row.workloads
        for i in w.instances
        if i.user == "root" and w.source in ("process", "systemd") and i.alive
    ]
    if root_instances and app_row.environment == "prod":
        samples = ", ".join(f"{w.name}(pid {i.pid})" for w, i in root_instances[:3])
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.security,
                "severity": Severity.warning,
                "confidence": Confidence.confirmed,
                "title": "Application process running as root",
                "observation": f"Running as root: {samples}.",
                "probable_cause": "Systemd unit without User= directive.",
                "recommendation": "Add User=/Group= to the unit and set NoNewPrivileges=true.",
                "evidence": [
                    {"source": "runtime_instance", "ref": f"inst:{i.id}", "value": {"pid": i.pid, "user": "root"}}
                    for w, i in root_instances[:3]
                ],
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)


RULES = [rule_error_rate, rule_latency_zscore, rule_disk_capacity, rule_health_flap, rule_security_root_process]


def run_rules_for_app(db: Session, app_row: Application) -> list[str]:
    fired = []
    for rule in RULES:
        before = db.scalar(
            select(Finding.id).where(
                Finding.application_id == app_row.id,
                Finding.rule_key == rule.__name__.removeprefix("rule_"),
                Finding.status == FindingStatus.open,
            )
        )
        try:
            rule(db, app_row)
        except Exception:  # one broken rule must not stop the sweep
            continue
        after = db.scalar(
            select(Finding.id).where(
                Finding.application_id == app_row.id,
                Finding.rule_key == rule.__name__.removeprefix("rule_"),
                Finding.status == FindingStatus.open,
            )
        )
        if after and after != before:
            fired.append(rule.__name__)
    return fired
