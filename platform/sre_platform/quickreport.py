"""M11: one-time passive performance tests + quick application reports."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .llm import LLMClient, LLMUnavailable
from .metrics import baseline
from .models import (
    AppReport,
    Application,
    Deployment,
    Finding,
    FindingStatus,
    HealthCheck,
    Incident,
    LogBatch,
    MetricPoint,
    PerfTest,
)
from .postmortem import slo_summary_for_app


# ---------------------------------------------------------------- perf test
def start_perf_test(db: Session, app_row: Application, duration_s: int) -> PerfTest:
    """Register a passive observation window (60-600s). Metrics keep flowing in
    from the agent; the UI polls live while status=running."""
    duration_s = max(60, min(600, int(duration_s)))
    db.query(PerfTest).filter(
        PerfTest.application_id == app_row.id, PerfTest.status == "running"
    ).update({"status": "done"})
    test = PerfTest(
        application_id=app_row.id, duration_s=duration_s, status="running",
        started_at=datetime.now(UTC),
    )
    db.add(test)
    db.flush()
    return test


def finish_due_perf_tests(db: Session) -> int:
    """Sweeper: finalize perf tests whose window has elapsed."""
    tests = db.scalars(select(PerfTest).where(PerfTest.status == "running")).all()
    finished = 0
    for test in tests:
        started = test.started_at if test.started_at.tzinfo else test.started_at.replace(tzinfo=UTC)
        if datetime.now(UTC) < started + timedelta(seconds=test.duration_s):
            continue
        test.summary = perf_test_summary(db, test.application_id, test.started_at, test.duration_s)
        test.status = "done"
        test.finished_at = datetime.now(UTC)
        finished += 1
    if finished:
        db.flush()
    return finished


def perf_test_summary(
    db: Session, app_id: int, started_at: datetime, duration_s: int
) -> dict:
    """Deterministic aggregates over the observation window — never invented."""
    since = started_at - timedelta(seconds=5)
    until = started_at + timedelta(seconds=duration_s + 5)
    points = db.scalars(
        select(MetricPoint).where(
            MetricPoint.application_id == app_id,
            MetricPoint.ts >= since,
            MetricPoint.ts <= until,
        ).order_by(MetricPoint.ts)
    ).all()

    def _agg(values):
        vals = [v for v in values if v is not None]
        if not vals:
            return None
        return {
            "avg": round(sum(vals) / len(vals), 4),
            "min": round(min(vals), 4),
            "max": round(max(vals), 4),
            "n": len(vals),
        }

    p95s = sorted(p.p95_ms for p in points if p.p95_ms is not None)
    total_requests = sum(
        (p.http_2xx or 0) + (p.http_3xx or 0) + (p.http_4xx or 0) + (p.http_5xx or 0)
        for p in points
    )
    total_5xx = sum(p.http_5xx or 0 for p in points)
    return {
        "window": {
            "started_at": started_at.isoformat(),
            "duration_s": duration_s,
            "samples": len(points),
        },
        "req_rate": _agg([p.req_rate for p in points]),
        "err_rate": _agg([p.err_rate for p in points]),
        "p50_ms": _agg([p.p50_ms for p in points]),
        "p95_ms": {"avg": None, "min": None, "max": None, "n": len(p95s),
                   "p95_of_p95_ms": round(p95s[int(0.95 * (len(p95s) - 1))], 1) if p95s else None},
        "p99_ms": _agg([p.p99_ms for p in points]),
        "http_total": total_requests,
        "http_5xx": total_5xx,
        "cpu_pct": _agg([p.cpu_pct for p in points]),
        "mem_pct": _agg([p.mem_pct for p in points]),
    }


# ---------------------------------------------------------------- app report
def collect_report_facts(db: Session, app_row: Application, window_minutes: int = 120) -> dict:
    """Facts snapshot for the quick report (computed, never generated)."""
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)
    points = db.scalars(
        select(MetricPoint).where(
            MetricPoint.application_id == app_row.id, MetricPoint.ts >= since
        ).order_by(MetricPoint.ts)
    ).all()

    def _agg(values):
        vals = [v for v in values if v is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    err_values = [p.err_rate for p in points if p.err_rate is not None]
    p95_values = [p.p95_ms for p in points if p.p95_ms is not None]
    errors_24h = 0
    day_ago = datetime.now(UTC) - timedelta(hours=24)
    for batch in db.scalars(
        select(LogBatch).where(
            LogBatch.application_id == app_row.id, LogBatch.ts_end >= day_ago
        )
    ).all():
        counts = batch.level_counts or {}
        errors_24h += int(counts.get("ERROR", 0) or 0) + int(counts.get("CRITICAL", 0) or 0)
    findings = db.scalars(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.status.in_([FindingStatus.open, FindingStatus.acknowledged]),
        ).order_by(Finding.last_seen.desc()).limit(10)
    ).all()
    incidents = db.scalars(
        select(Incident).where(
            Incident.application_id == app_row.id, Incident.detected_at >= since
        ).order_by(Incident.detected_at.desc()).limit(5)
    ).all()
    deploys = db.scalars(
        select(Deployment).where(
            Deployment.application_id == app_row.id, Deployment.deployed_at >= since
        ).order_by(Deployment.deployed_at.desc()).limit(5)
    ).all()
    checks = db.scalars(
        select(HealthCheck).where(HealthCheck.application_id == app_row.id)
    ).all()
    return {
        "application": {
            "name": app_row.name, "slug": app_row.slug,
            "environment": app_row.environment,
            "status": app_row.status.value,
            "deployment_model": app_row.deployment_model.value,
            "discovery": app_row.discovery.value,
            "label": "External Resource" if app_row.discovery.value == "manual" else "Detected App",
        },
        "window_minutes": window_minutes,
        "performance": {
            "samples": len(points),
            "req_rate_avg": _agg([p.req_rate for p in points]),
            "err_rate_avg": _agg(err_values),
            "err_rate_max": round(max(err_values), 4) if err_values else None,
            "p95_avg_ms": _agg(p95_values),
            "p95_max_ms": round(max(p95_values), 1) if p95_values else None,
            "p95_baseline_7d": baseline(db, app_row.id, "p95_avg"),
            "http_total": sum(
                (p.http_2xx or 0) + (p.http_3xx or 0) + (p.http_4xx or 0) + (p.http_5xx or 0)
                for p in points
            ),
        },
        "slo_report": slo_summary_for_app(db, app_row.id),
        "quick_findings": [
            {"rule": f.rule_key, "title": f.title, "severity": f.severity.value,
             "status": f.status.value}
            for f in findings if (f.rule_key or "").startswith(("slo_breach", "recurring_error"))
        ],
        "open_findings": [
            {"rule": f.rule_key, "title": f.title, "severity": f.severity.value,
             "observation": (f.observation or "")[:200]}
            for f in findings
        ],
        "incidents_in_window": [
            {"title": i.title, "status": i.status.value, "severity": i.severity.value,
             "detected_at": i.detected_at.isoformat(), "mttr_s": i.mttr_s}
            for i in incidents
        ],
        "deployments_in_window": [
            {"sha": d.sha, "message": (d.message or "")[:100],
             "deployed_at": d.deployed_at.isoformat(), "status": d.status,
             "regression": d.regression}
            for d in deploys
        ],
        "health_checks": [
            {"target": h.target, "last_result": h.last_result,
             "consecutive_failures": h.consecutive_failures}
            for h in checks
        ],
        "log_errors_24h": errors_24h,
    }


SYSTEM_REPORT = (
    "You are an SRE writing a quick on-demand application report. You receive a "
    "facts document — every number is already computed; do not invent any. "
    "Answer ONLY with JSON: {\"summary\": \"<3-5 sentences in the same language "
    "as the facts' app name/context, plain operator language>\", "
    "\"highlights\": [\"<bullet>\", ...], \"risks\": [\"<bullet>\", ...]}. "
    "Reference concrete values from the facts. Keep it under 250 words total."
)


def generate_app_report(
    db: Session, app_row: Application, client: LLMClient | None = None,
    window_minutes: int = 120,
) -> AppReport:
    facts = collect_report_facts(db, app_row, window_minutes)
    generated_by = "system(deterministic)"
    client = client or LLMClient()
    import json as _json

    if client.enabled:
        system = SYSTEM_REPORT
        prompt = (
            f"Application: {app_row.name}\nFacts document (JSON):\n"
            + _json.dumps(facts, default=str)
        )
        try:
            narrative = client.chat_json(system, prompt, max_tokens=700)
            facts["narrative"] = {
                "summary": str(narrative.get("summary", ""))[:2000],
                "highlights": [str(x) for x in (narrative.get("highlights") or [])][:6],
                "risks": [str(x) for x in (narrative.get("risks") or [])][:6],
            }
            generated_by = "agent"
        except (LLMUnavailable, ValueError):
            pass
    report = AppReport(
        application_id=app_row.id, window_minutes=window_minutes,
        doc=facts, generated_by=generated_by,
    )
    db.add(report)
    db.flush()
    return report


def report_to_markdown(report: AppReport, app_name: str) -> str:
    doc = report.doc or {}
    perf = doc.get("performance", {})
    lines = [
        f"# Quick Report — {app_name}",
        "",
        f"- Label: {doc.get('application', {}).get('label', '—')}",
        f"- Status: {doc.get('application', {}).get('status', '—')}",
        f"- Window: last {report.window_minutes} minutes",
        f"- Generated: {report.created_at.isoformat() if report.created_at else '—'} by {report.generated_by}",
        "",
    ]
    if doc.get("narrative", {}).get("summary"):
        lines += ["## Summary", doc["narrative"]["summary"], ""]
    hl = doc.get("narrative", {}).get("highlights") or []
    if hl:
        lines += ["## Highlights"] + [f"- {h}" for h in hl] + [""]
    lines += [
        "## Performance",
        f"- Requests: {perf.get('http_total', '—')} in window",
        f"- Req/s avg: {perf.get('req_rate_avg', '—')}",
        f"- Error rate avg/max: {perf.get('err_rate_avg', '—')} / {perf.get('err_rate_max', '—')}",
        f"- P95 avg/max: {perf.get('p95_avg_ms', '—')}ms / {perf.get('p95_max_ms', '—')}ms",
        f"- Log errors 24h: {doc.get('log_errors_24h', 0)}",
        "",
        "## SLO",
    ]
    for s in doc.get("slo_report", []):
        lines.append(
            f"- {s.get('sli')}: {s.get('current_pct')}% "
            f"(target {s.get('target')}) — {'BREACH' if s.get('exhausted') else 'ok'}"
        )
    qf = doc.get("quick_findings", [])
    if qf:
        lines += ["", "## Quick Reminders active"]
        lines += [f"- [{f.get('severity')}] {f.get('title')}" for f in qf]
    of = doc.get("open_findings", [])
    if of:
        lines += ["", "## Open Findings"]
        lines += [f"- [{f.get('severity')}] {f.get('title')}" for f in of]
    inc = doc.get("incidents_in_window", [])
    if inc:
        lines += ["", "## Incidents (window)"]
        lines += [f"- {i.get('title')} ({i.get('status')}, mttr {i.get('mttr_s')}s)" for i in inc]
    dep = doc.get("deployments_in_window", [])
    if dep:
        lines += ["", "## Deployments (window)"]
        lines += [f"- {(d.get('sha') or 'n/a')[:8]} {d.get('message', '')}" for d in dep]
    risks = doc.get("narrative", {}).get("risks") or []
    if risks:
        lines += ["", "## Risks"] + [f"- {r}" for r in risks]
    return "\n".join(lines) + "\n"


def latest_report(db: Session, app_id: int) -> AppReport | None:
    return db.scalars(
        select(AppReport).where(AppReport.application_id == app_id)
        .order_by(AppReport.created_at.desc()).limit(1)
    ).first()


def perf_test_state(db: Session, app_id: int) -> tuple[PerfTest | None, PerfTest | None]:
    """(running test, latest finished test) for the app page."""
    running = db.scalars(
        select(PerfTest).where(
            PerfTest.application_id == app_id, PerfTest.status == "running"
        ).order_by(PerfTest.started_at.desc()).limit(1)
    ).first()
    latest_done = db.scalars(
        select(PerfTest).where(
            PerfTest.application_id == app_id, PerfTest.status == "done"
        ).order_by(PerfTest.started_at.desc()).limit(1)
    ).first()
    return running, latest_done


def count_active(db: Session, app_id: int) -> int:
    return db.scalar(
        select(func.count()).select_from(Finding).where(
            Finding.application_id == app_id,
            Finding.status == FindingStatus.open,
        )
    ) or 0
