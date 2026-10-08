"""Postmortem generation (spec §20, §32.13) + SLO / error budget (§21).

Facts (times, durations, error rates) are COMPUTED from rows, never generated.
The LLM only writes narrative sections when enabled; unreviewed drafts never
feed learning data (spec §20: never fabricate evidence).
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .llm import LLMClient, LLMUnavailable
from .models import (
    Application,
    Deployment,
    ErrorBudgetState,
    Finding,
    HealthCheck,
    Incident,
    IncidentEvent,
    IncidentStatus,
    MetricPoint,
    MetricRollup5m,
    Postmortem,
    SLO,
    TimelineEvent,
)

log = logging.getLogger("sre-platform.postmortem")


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt


# ---------------------------------------------------------------- postmortem
def generate_postmortem(db: Session, incident: Incident, client: LLMClient | None = None) -> Postmortem | None:
    """Build the §20 doc from real rows. Deterministic facts + optional LLM narrative."""
    app_row = db.get(Application, incident.application_id)
    if app_row is None:
        return None
    existing = db.scalar(select(Postmortem).where(Postmortem.incident_id == incident.id))
    if existing is not None:
        return existing

    resolved_at = _utc(incident.resolved_at) if incident.resolved_at else datetime.now(UTC)
    incident.detected_at = _utc(incident.detected_at)
    duration_s = incident.mttr_s or int((resolved_at - incident.detected_at).total_seconds())

    events = db.scalars(
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.ts)
    ).all()
    timeline = db.scalars(
        select(TimelineEvent)
        .where(
            TimelineEvent.application_id == app_row.id,
            TimelineEvent.ts >= incident.detected_at - timedelta(minutes=10),
            TimelineEvent.ts <= resolved_at + timedelta(minutes=10),
        )
        .order_by(TimelineEvent.ts)
        .limit(80)
    ).all()
    findings = db.scalars(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.first_seen <= resolved_at + timedelta(minutes=10),
            Finding.last_seen >= incident.detected_at - timedelta(minutes=30),
        )
    ).all()
    deploys = db.scalars(
        select(Deployment)
        .where(
            Deployment.application_id == app_row.id,
            Deployment.deployed_at.between(
                incident.detected_at - timedelta(minutes=60), resolved_at
            ),
        )
    ).all()
    actions = (
        db.scalars(
            select(TimelineEvent).where(
                TimelineEvent.application_id == app_row.id,
                TimelineEvent.kind == "agent",
                TimelineEvent.ts.between(incident.detected_at, resolved_at),
            )
        ).all()
    )

    def _metric_window(minutes_before: int, minutes_after: int, *, end_exclusive: datetime | None = None) -> dict:
        end_bound = end_exclusive or (resolved_at + timedelta(minutes=minutes_after))
        pts = db.scalars(
            select(MetricPoint)
            .where(
                MetricPoint.application_id == app_row.id,
                MetricPoint.ts >= incident.detected_at - timedelta(minutes=minutes_before),
                MetricPoint.ts < end_bound,
            )
            .order_by(MetricPoint.ts)
            .limit(200)
        ).all()
        err = [p.err_rate for p in pts if p.err_rate is not None]
        p95 = [p.p95_ms for p in pts if p.p95_ms is not None]
        return {
            "samples": len(pts),
            "err_rate_max": round(max(err), 4) if err else None,
            "p95_max_ms": round(max(p95), 1) if p95 else None,
        }

    before_after = {
        "before": _metric_window(60, 0, end_exclusive=incident.detected_at),
        "after": _metric_window(0, 60),
    }
    investigation = incident.investigation or {}
    llm_verdict = investigation.get("llm_verdict") or {}

    doc = {
        "title": f"Postmortem: {incident.title}",
        "incident_summary": incident.impact or incident.title,
        "impact": incident.impact or f"Application {app_row.name} unavailable/degraded",
        "severity": _enum_value(incident.severity),
        "application": {"name": app_row.name, "slug": app_row.slug, "environment": app_row.environment},
        "start_time": incident.detected_at.isoformat(),
        "end_time": resolved_at.isoformat(),
        "duration_s": duration_s,
        "detection": {
            "detected_at": incident.detected_at.isoformat(),
            "how": "automated health-check hysteresis (3 consecutive failures)"
            if not events
            else events[0].summary,
        },
        "investigation": {
            "steps": [
                {"ts": e.ts.isoformat(), "kind": e.kind, "summary": e.summary}
                for e in events
            ],
            "llm_verdict": llm_verdict if llm_verdict else None,
        },
        "root_cause": {
            "statement": incident.root_cause or incident.probable_root_cause or "Undetermined",
            "confidence": _enum_value(incident.confidence) if incident.confidence else "hypothesis",
            "evidence_refs": llm_verdict.get("evidence_refs", []),
        },
        "contributing_factors": [
            {"rule": f.rule_key, "title": f.title, "confidence": _enum_value(f.confidence)}
            for f in findings
        ],
        "resolution": {
            "resolved_at": resolved_at.isoformat(),
            "mttr_s": duration_s,
            "how": "service recovered (health checks stable)"
            or "see timeline",
            "timeline_tail": [
                {"ts": e.ts.isoformat(), "summary": e.summary} for e in timeline[-6:]
            ],
        },
        "affected": {
            "application": app_row.name,
            "dependencies": [d.name for d in app_row.dependencies],
            "endpoints": [e.url for e in app_row.endpoints],
        },
        "deployment_correlation": [
            {"sha": d.sha, "branch": d.branch, "message": (d.message or "")[:120],
             "deployed_at": d.deployed_at.isoformat(), "status": d.status,
             "regression": d.regression}
            for d in deploys
        ],
        "agent_actions": [
            {"ts": a.ts.isoformat(), "summary": a.summary} for a in actions
        ],
        "metrics": before_after,
        "preventive_actions": _preventive(findings, deploys),
        "lessons_learned": [],
        "narrative": None,  # filled by LLM when enabled
    }

    narrative = _llm_narrative(client, doc) if (client and client.enabled) else None
    if narrative:
        doc["narrative"] = narrative
        doc["lessons_learned"] = narrative.get("lessons_learned", [])
        if narrative.get("root_cause_statement") and doc["root_cause"]["statement"] == "Undetermined":
            doc["root_cause"]["statement"] = narrative["root_cause_statement"]
            doc["root_cause"]["confidence"] = narrative.get("confidence", "hypothesis")

    postmortem = Postmortem(
        incident_id=incident.id,
        doc=doc,
        generated_by="agent" if narrative else "system(deterministic)",
        reviewed_by=None,
        published=False,
    )
    db.add(postmortem)
    db.add(
        TimelineEvent(
            application_id=app_row.id,
            incident_id=incident.id,
            kind="postmortem",
            actor="agent",
            summary=f"Postmortem draft generated ({'LLM-assisted' if narrative else 'deterministic'})",
        )
    )
    db.flush()
    return postmortem


def _enum_value(value) -> str:
    """Enum columns accept raw strings too (SQLAlchemy validates on write), so
    never assume `.value` exists."""
    if value is None:
        return "unknown"
    return value.value if hasattr(value, "value") else str(value)


def _preventive(findings, deploys) -> list[str]:
    out: list[str] = []
    for f in findings:
        if f.recommendation:
            out.append(f.recommendation[:200])
    if deploys:
        out.append("Add deployment regression checks (before/after metric windows) around releases.")
    if not out:
        out.append("Extend monitoring coverage so similar failures are detected earlier.")
    return out[:5]


def _llm_narrative(client: LLMClient | None, doc: dict) -> dict | None:
    if client is None or not client.enabled:
        return None
    from .llm import extract_json

    system = (
        "You are an SRE writing the narrative sections of a postmortem from a "
        "facts document (all facts are already computed — do not invent any). "
        "Answer ONLY with JSON: {\"summary\": \"<3-4 sentences>\", "
        "\"root_cause_statement\": \"<one sentence>\", "
        "\"confidence\": \"confirmed|likely|hypothesis\", "
        "\"lessons_learned\": [\"<bullet>\", ...], "
        "\"preventive_actions\": [\"<bullet>\", ...]}."
    )
    import json as _json

    prompt = "Facts document (JSON):\n" + _json.dumps(doc, default=str)
    try:
        return extract_json(client.chat(system, prompt, max_tokens=800))
    except (LLMUnavailable, ValueError) as exc:
        log.warning("postmortem narrative unavailable: %s", exc)
        return None


def to_markdown(doc: dict) -> str:
    """Editable-doc -> markdown export."""
    lines = [
        f"# {doc.get('title', 'Postmortem')}",
        "",
        f"- **Application**: {doc.get('application', {}).get('name', '—')}",
        f"- **Severity**: {doc.get('severity', '—')}",
        f"- **Start**: {doc.get('start_time', '—')}",
        f"- **End**: {doc.get('end_time', '—')}",
        f"- **Duration**: {doc.get('duration_s', 0)}s",
        "",
        "## Summary",
        doc.get("incident_summary", ""),
        "",
        "## Impact",
        doc.get("impact", ""),
        "",
        "## Detection",
        doc.get("detection", {}).get("how", ""),
        "",
        "## Investigation",
    ]
    for step in doc.get("investigation", {}).get("steps", []):
        lines.append(f"- `{step.get('ts', '')}` ({step.get('kind', '')}) {step.get('summary', '')}")
    verdict = doc.get("investigation", {}).get("llm_verdict")
    if verdict:
        lines.append(f"- LLM verdict [{verdict.get('confidence', '—')}]: {verdict.get('root_cause', '')}")
    rc = doc.get("root_cause", {})
    lines += ["", "## Root Cause", f"{rc.get('statement', '—')} _(confidence: {rc.get('confidence', '—')})_"]
    refs = rc.get("evidence_refs") or []
    if refs:
        lines.append("Evidence: " + ", ".join(f"`{r}`" for r in refs))
    lines += ["", "## Contributing Factors"]
    for f in doc.get("contributing_factors", []):
        lines.append(f"- [{f.get('confidence', '—')}] {f.get('title', '')}")
    res = doc.get("resolution", {})
    lines += [
        "",
        "## Resolution",
        f"Resolved at {res.get('resolved_at', '—')} (MTTR {res.get('mttr_s', '—')}s). {res.get('how', '')}",
    ]
    corr = doc.get("deployment_correlation", [])
    if corr:
        lines += ["", "## Deployment Correlation"]
        for d in corr:
            lines.append(f"- `{d.get('sha', '')}` {d.get('message', '')} regression={d.get('regression')}")
    acts = doc.get("agent_actions", [])
    if acts:
        lines += ["", "## Agent Actions"]
        for a in acts:
            lines.append(f"- `{a.get('ts', '')}` {a.get('summary', '')}")
    m = doc.get("metrics", {})
    lines += [
        "",
        "## Metrics",
        f"- Before: {m.get('before', {})}",
        f"- After: {m.get('after', {})}",
    ]
    lines += ["", "## Preventive Actions"]
    for p in doc.get("preventive_actions", []):
        lines.append(f"- {p}")
    lessons = doc.get("lessons_learned", [])
    if lessons:
        lines += ["", "## Lessons Learned"]
        for l in lessons:
            lines.append(f"- {l}")
    if doc.get("narrative"):
        lines += ["", "## Narrative (AI-assisted)", doc["narrative"].get("summary", "")]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- SLO
def compute_slo_status(db: Session, slo_row: SLO, now: datetime | None = None) -> ErrorBudgetState | None:
    """Availability SLI from health-check outcomes; latency SLI from rollups."""
    now = _utc(now or datetime.now(UTC))
    window_start = now - timedelta(days=slo_row.window_days)
    app_row = db.get(Application, slo_row.application_id)
    if app_row is None:
        return None

    if slo_row.sli == "availability":
        checks = db.scalars(
            select(HealthCheck).where(HealthCheck.application_id == app_row.id)
        ).all()
        if not checks:
            return None
        total_s = slo_row.window_days * 86400
        # Observed uptime from check history stored in timeline (health transitions)
        events = db.scalars(
            select(TimelineEvent)
            .where(
                TimelineEvent.application_id == app_row.id,
                TimelineEvent.kind == "health",
                TimelineEvent.ts >= window_start,
            )
            .order_by(TimelineEvent.ts)
        ).all()
        down_s = 0.0
        down_since: datetime | None = None
        for event in events:
            event.ts = _utc(event.ts)
            payload = event.payload or {}
            new_status = str(payload.get("to", ""))
            if new_status == "down" and down_since is None:
                down_since = event.ts
            elif new_status == "healthy" and down_since is not None:
                down_s += (event.ts - down_since).total_seconds()
                down_since = None
        if down_since is not None:
            down_s += (now - down_since).total_seconds()
        if app_row.status.value == "down":
            down_s += (now - max(down_since or window_start, window_start)).total_seconds()
        burned = min(down_s, total_s)
        current = (total_s - burned) / total_s
    elif slo_row.sli == "latency_p95":
        rollups = db.scalars(
            select(MetricRollup5m).where(
                MetricRollup5m.application_id == app_row.id,
                MetricRollup5m.bucket >= window_start,
                MetricRollup5m.p95_avg.is_not(None),
            )
        ).all()
        if not rollups:
            return None
        bad = sum(1 for r in rollups if r.p95_avg > (slo_row.target_ms or 500))
        total = len(rollups)
        total_s = total * 300
        burned = bad * 300
        current = (total - bad) / total
    else:
        return None

    state = db.scalar(
        select(ErrorBudgetState).where(
            ErrorBudgetState.slo_id == slo_row.id,
            ErrorBudgetState.period_start >= window_start,
        )
    )
    if state is None:
        state = ErrorBudgetState(slo_id=slo_row.id, period_start=window_start)
        db.add(state)
    state.period_end = now
    state.total_s = float(total_s)
    state.burned_s = round(burned, 1)
    state.current_pct = round(current * 100, 4)
    state.exhausted = current < slo_row.target
    return state


def slo_summary_for_app(db: Session, app_id: int) -> list[dict]:
    rows = db.scalars(select(SLO).where(SLO.application_id == app_id, SLO.enabled == True)).all()  # noqa: E712
    out = []
    for slo_row in rows:
        if slo_row.metric:
            # metric-threshold SLO: state comes from quickreminders checks
            out.append(
                {
                    "sli": slo_row.sli,
                    "target": slo_row.threshold,
                    "threshold_display": f"{slo_row.comparison} {slo_row.threshold:g}",
                    "current_pct": None,
                    "burned_s": None,
                    "budget_total_s": None,
                    "exhausted": None,
                    "window_days": slo_row.window_days,
                }
            )
            continue
        state = compute_slo_status(db, slo_row)
        if state is None:
            continue
        out.append(
            {
                "sli": slo_row.sli,
                "target": slo_row.target,
                "threshold_display": None,
                "current_pct": state.current_pct,
                "burned_s": state.burned_s,
                "budget_total_s": state.total_s,
                "exhausted": state.exhausted,
                "window_days": slo_row.window_days,
            }
        )
    return out


def budget_context_for_recommendations(db: Session, app_row: Application) -> str:
    """§21: SLO context shapes agent recommendations (e.g. freeze non-critical deploys)."""
    summaries = slo_summary_for_app(db, app_row.id)
    exhausted = [s for s in summaries if s["exhausted"]]
    if exhausted:
        details = ", ".join(f"{s['sli']} {s['current_pct']}% < target {s['target'] * 100:.2f}%" for s in exhausted)
        return f"Error budget exhausted ({details}). Consider delaying non-critical deployments."
    return ""
