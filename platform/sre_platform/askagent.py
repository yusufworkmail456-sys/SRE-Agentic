"""Ask Agent (spec §24): grounded Q&A over an application's real context.

Tools are deterministic server-side queries (no LLM-chosen code execution).
The model gets pre-fetched evidence and must cite refs, same contract as
investigation.py.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .llm import LLMClient, LLMUnavailable
from .logstore import recent_error_samples, window_error_counts
from .metrics import baseline, latest_points
from .models import (
    AgentAction,
    Application,
    Deployment,
    Finding,
    FindingStatus,
    HealthCheck,
    Incident,
    MetricPoint,
    TimelineEvent,
)

SYSTEM_ASK = (
    "You are an SRE assistant answering questions about ONE application. You get "
    "an evidence pack of real collected data. Answer in at most 6 sentences. "
    "Answer ONLY with JSON: {\"answer\": \"...\", "
    "\"confidence\": \"confirmed|likely|hypothesis\", "
    "\"evidence_refs\": [\"<ref from pack>\"], \"followups\": [\"...\"]}. "
    "Cite refs that exist in the pack. If the data does not answer the question, say "
    'so plainly with confidence "hypothesis" and list what data would be needed. '
    "Never invent metrics or log lines."
)

ALLOWED_TOOLS = (
    "query_metrics",
    "query_logs",
    "check_health",
    "get_deployments",
    "get_findings",
    "get_timeline",
    "get_dependencies",
    "get_endpoints",
)


def build_context(db: Session, app_row: Application, window_minutes: int = 120) -> dict:
    """Deterministic context: every tool call is executed here and logged."""
    since = datetime.now(UTC) - timedelta(minutes=window_minutes)
    points = latest_points(db, app_row.id, limit=24)
    checks = db.scalars(
        select(HealthCheck).where(HealthCheck.application_id == app_row.id)
    ).all()
    findings = db.scalars(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.status.in_([FindingStatus.open, FindingStatus.acknowledged]),
        ).order_by(Finding.last_seen.desc()).limit(8)
    ).all()
    incidents = db.scalars(
        select(Incident)
        .where(Incident.application_id == app_row.id)
        .order_by(Incident.detected_at.desc())
        .limit(5)
    ).all()
    deploys = db.scalars(
        select(Deployment)
        .where(Deployment.application_id == app_row.id)
        .order_by(Deployment.deployed_at.desc())
        .limit(5)
    ).all()
    actions = db.scalars(
        select(AgentAction)
        .where(AgentAction.application_id == app_row.id)
        .order_by(AgentAction.created_at.desc())
        .limit(5)
    ).all()
    timeline = db.scalars(
        select(TimelineEvent)
        .where(TimelineEvent.application_id == app_row.id, TimelineEvent.ts >= since)
        .order_by(TimelineEvent.ts.desc())
        .limit(15)
    ).all()
    server_point = (
        db.scalars(
            select(MetricPoint)
            .where(MetricPoint.server_id == app_row.server_id)
            .order_by(MetricPoint.ts.desc())
            .limit(1)
        ).first()
        if app_row.server_id
        else None
    )

    context = {
        "application": {
            "ref": "application:info",
            "name": app_row.name,
            "environment": app_row.environment,
            "status": app_row.status.value,
            "deployment_model": app_row.deployment_model.value,
            "owner": app_row.owner,
            "confirmed": app_row.confirmed,
        },
        "workloads": [
            {"ref": f"workload:{w.id}", "name": w.name, "kind": w.kind.value, "runtime": w.runtime,
             "source": w.source,
             "instances": [{"ref": f"instance:{i.id}", "pid": i.pid, "port": i.listen_port,
                            "user": i.user, "alive": i.alive, "cmd": (i.cmd or "")[:120]}
                           for i in w.instances]}
            for w in app_row.workloads
        ],
        "endpoints": [
            {"ref": f"endpoint:{e.id}", "url": e.url, "domain": e.domain,
             "tls_expires_at": e.tls_expires_at.isoformat() if e.tls_expires_at else None}
            for e in app_row.endpoints
        ],
        "dependencies": [
            {"ref": f"dependency:{d.id}", "name": d.name, "kind": d.kind, "criticality": d.criticality}
            for d in app_row.dependencies
        ],
        "health_checks": [
            {"ref": f"health_check:{i}", "target": h.target, "kind": h.kind,
             "last_result": h.last_result, "consecutive_failures": h.consecutive_failures,
             "last_ok_at": h.last_ok_at.isoformat() if h.last_ok_at else None}
            for i, h in enumerate(checks)
        ],
        "metrics": {
            "ref": "metrics:window",
            "window_minutes": window_minutes,
            "samples": [
                {"ref": f"metric_sample:{i}", "ts": p.ts.isoformat(), "req_rate": p.req_rate,
                 "err_rate": p.err_rate, "p50_ms": p.p50_ms, "p95_ms": p.p95_ms, "p99_ms": p.p99_ms}
                for i, p in enumerate(reversed(points))
            ],
            "p95_baseline": baseline(db, app_row.id, "p95_avg"),
        },
        "host": {
            "ref": "host:latest",
            "cpu_pct": server_point.cpu_pct if server_point else None,
            "mem_pct": server_point.mem_pct if server_point else None,
            "disk_pct": server_point.disk_pct if server_point else None,
        },
        "log_summary_60m": window_error_counts(db, app_row.id, minutes=60),
        "log_errors_30m": [
            {**s, "ref": f"log_error:{i}"}
            for i, s in enumerate(recent_error_samples(db, app_row.id, minutes=30, limit=5))
        ],
        "findings": [
            {"ref": f"finding:{f.rule_key or f.id}", "severity": f.severity.value,
             "confidence": f.confidence.value, "status": f.status.value,
             "title": f.title, "observation": f.observation[:300],
             "recommendation": (f.recommendation or "")[:200]}
            for f in findings
        ],
        "incidents": [
            {"ref": f"incident:{i.id}", "title": i.title, "status": i.status.value,
             "severity": i.severity.value, "detected_at": i.detected_at.isoformat(),
             "mttr_s": i.mttr_s, "probable_root_cause": (i.probable_root_cause or "")[:300],
             "confidence": i.confidence.value if i.confidence else None}
            for i in incidents
        ],
        "deployments": [
            {"ref": f"deployment:{d.sha or d.id}", "sha": d.sha, "branch": d.branch,
             "message": (d.message or "")[:100], "deployed_at": d.deployed_at.isoformat(),
             "method": d.method, "status": d.status, "regression": d.regression}
            for d in deploys
        ],
        "agent_actions": [
            {"ref": f"action:{a.id}", "action": a.action, "target": a.target,
             "actor": a.actor.value, "status": a.status, "created_at": a.created_at.isoformat()}
            for a in actions
        ],
        "timeline_120m": [
            {"ref": f"timeline:{t.id}", "ts": t.ts.isoformat(), "kind": t.kind,
             "actor": t.actor, "summary": t.summary[:200]}
            for t in timeline
        ],
    }
    return context


def ask(
    db: Session,
    app_row: Application,
    question: str,
    history: list[dict] | None = None,
    client: LLMClient | None = None,
) -> dict:
    """Answer a question about one app. Returns the answer dict (never raises)."""
    client = client or LLMClient()
    context = build_context(db, app_row)
    if not client.enabled:
        return {
            "answer": (
                "LLM is not configured, so I can only report collected facts. "
                f"Status: {app_row.status.value}; open findings: "
                f"{len([f for f in context['findings']])}; recent incidents: "
                f"{len(context['incidents'])}. Configure SRE_LLM_* to enable reasoning."
            ),
            "confidence": "confirmed",
            "evidence_refs": ["application:info", "metrics:window"],
            "followups": [],
            "llm": False,
        }
    allowed = _refs_of(context)
    convo = ""
    for turn in (history or [])[-6:]:
        role = turn.get("role", "user")
        convo += f"\n{role}: {str(turn.get('content', ''))[:500]}"
    prompt = (
        f"Question: {question}\n"
        f"{('Conversation so far:' + convo) if convo else ''}\n\n"
        f"Evidence pack (JSON):\n{json.dumps(context, default=str)}\n\n"
        "Answer with refs copied from the pack."
    )
    try:
        result = client.chat_json(SYSTEM_ASK, prompt, max_tokens=900)
    except LLMUnavailable as exc:
        return {
            "answer": f"LLM unavailable ({exc}). Facts: status {app_row.status.value}, "
                      f"{len(context['findings'])} open findings.",
            "confidence": "confirmed",
            "evidence_refs": ["application:info"],
            "followups": [],
            "llm": False,
        }
    refs = [r for r in (result.get("evidence_refs") or []) if isinstance(r, str) and r in allowed]
    confidence = result.get("confidence", "hypothesis")
    if confidence not in ("confirmed", "likely", "hypothesis"):
        confidence = "hypothesis"
    if not refs:
        confidence = "hypothesis"
    # Answering a question is a read-only agent action -> audit trail (spec §18)
    db.add(
        AgentAction(
            application_id=app_row.id,
            actor="agent",
            action="ask_agent",
            target=app_row.slug,
            reason=question[:300],
            evidence={"question": question[:300], "refs": refs, "tools": list(ALLOWED_TOOLS)},
            result={"answer": str(result.get("answer", ""))[:800], "confidence": confidence},
            status="done",
        )
    )
    db.flush()
    return {
        "answer": str(result.get("answer", "")).strip(),
        "confidence": confidence,
        "evidence_refs": refs,
        "followups": [str(f) for f in (result.get("followups") or [])][:3],
        "llm": True,
    }


def _refs_of(context: dict) -> set[str]:
    refs: set[str] = set()
    for key, value in context.items():
        if isinstance(value, dict):
            if value.get("ref"):
                refs.add(str(value["ref"]))
            for k, v in value.items():
                if isinstance(v, list):
                    for item in v:
                        if isinstance(item, dict) and item.get("ref"):
                            refs.add(str(item["ref"]))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict) and item.get("ref"):
                    refs.add(str(item["ref"]))
    return refs
