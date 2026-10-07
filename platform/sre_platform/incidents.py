"""Incident lifecycle (spec §13/§14/§8): detection → investigation → resolution.

Phase-1 investigation is a deterministic evidence pack builder; the LLM step
plugs in at M5 without changing this interface.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import metrics as metrics_svc
from .models import (
    AppStatus,
    Application,
    Deployment,
    Finding,
    FindingStatus,
    HealthCheck,
    Incident,
    IncidentEvent,
    IncidentStatus,
    MetricPoint,
    Severity,
    TimelineEvent,
)

DOWN_OPEN_THRESHOLD = 3      # consecutive failed checks before incident opens
RECOVERY_CLOSE_OKS = 6       # oks needed before auto-resolve (2 x hysteresis)


def touch_timeline(db: Session, app_id: int, kind: str, summary: str, actor: str = "system", **payload) -> None:
    db.add(TimelineEvent(application_id=app_id, kind=kind, actor=actor, summary=summary, payload=payload))


def _open_incident(db: Session, app_row: Application, trigger: Finding | None, targets: list[str]) -> Incident:
    incident = Incident(
        application_id=app_row.id,
        title=f"{app_row.name} down" if not trigger else f"{app_row.name}: {trigger.title}",
        severity=trigger.severity if trigger and trigger.severity == Severity.critical else Severity.critical,
        status=IncidentStatus.open,
        impact=f"Application {app_row.name} ({app_row.environment}) is not responding on {', '.join(targets)}",
        detected_at=datetime.now(UTC),
    )
    db.add(incident)
    db.flush()
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            kind="detected",
            summary=f"Incident opened; failing targets: {', '.join(targets)}",
        )
    )
    touch_timeline(db, app_row.id, "incident", f"Incident opened: {incident.title}", incident_id=incident.id)
    return incident


def detect_incidents(db: Session) -> list[Incident]:
    """Called on every ingest sweep. Opens incidents for confirmed apps that are
    DOWN (per hysteresis in services.apply_health_checks) without an open one."""
    opened = []
    apps = db.scalars(select(Application).where(Application.confirmed == True)).all()  # noqa: E712
    for app_row in apps:
        if app_row.status is not AppStatus.down:
            continue
        existing = db.scalar(
            select(Incident).where(
                Incident.application_id == app_row.id,
                Incident.status.in_([IncidentStatus.open, IncidentStatus.investigating,
                                     IncidentStatus.identified, IncidentStatus.mitigated]),
            )
        )
        if existing is not None:
            continue
        failing = [
            h.target for h in db.scalars(
                select(HealthCheck).where(
                    HealthCheck.application_id == app_row.id,
                    HealthCheck.consecutive_failures >= 2,
                )
            ).all()
        ]
        trigger = db.scalar(
            select(Finding).where(
                Finding.application_id == app_row.id,
                Finding.status == FindingStatus.open,
                Finding.severity == Severity.critical,
            )
        )
        incident = _open_incident(db, app_row, trigger, failing or ["health"])
        investigate(db, incident)
        opened.append(incident)
    return opened


def build_evidence_pack(db: Session, incident: Incident, max_chars: int = 24000) -> dict:
    app_row = db.get(Application, incident.application_id)
    now = datetime.now(UTC)
    window_start = incident.detected_at - timedelta(minutes=30)
    points = db.scalars(
        select(MetricPoint)
        .where(
            MetricPoint.application_id == app_row.id,
            MetricPoint.ts >= window_start,
        )
        .order_by(MetricPoint.ts.desc())
        .limit(40)
    ).all()
    recent_deploys = db.scalars(
        select(Deployment)
        .where(
            Deployment.application_id == app_row.id,
            Deployment.deployed_at >= now - timedelta(hours=24),
        )
        .order_by(Deployment.deployed_at.desc())
        .limit(5)
    ).all()
    open_findings = db.scalars(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.status.in_([FindingStatus.open, FindingStatus.acknowledged]),
        )
    ).all()
    checks = db.scalars(
        select(HealthCheck).where(HealthCheck.application_id == app_row.id)
    ).all()
    from .logstore import recent_error_samples

    pack = {
        "application": {
            "name": app_row.name, "slug": app_row.slug, "environment": app_row.environment,
            "deployment_model": app_row.deployment_model.value,
            "workloads": [
                {"name": w.name, "kind": w.kind.value, "runtime": w.runtime, "source": w.source,
                 "instances": [{"pid": i.pid, "port": i.listen_port, "user": i.user, "cmd": (i.cmd or "")[:160]}
                               for i in w.instances]}
                for w in app_row.workloads
            ],
        },
        "incident": {
            "title": incident.title, "detected_at": incident.detected_at.isoformat(),
            "status": incident.status.value,
        },
        "health_checks": [
            {"target": h.target, "last_result": h.last_result,
             "consecutive_failures": h.consecutive_failures, "last_ok_at": h.last_ok_at.isoformat() if h.last_ok_at else None}
            for h in checks
        ],
        "metrics_recent": [
            {"ts": p.ts.isoformat(), "req_rate": p.req_rate, "err_rate": p.err_rate,
             "p95_ms": p.p95_ms, "cpu_pct": p.cpu_pct, "mem_pct": p.mem_pct}
            for p in reversed(points)
        ],
        "log_errors_30m": recent_error_samples(db, app_row.id, minutes=30, limit=5),
        "findings": [
            {"rule": f.rule_key, "severity": f.severity.value, "confidence": f.confidence.value,
             "title": f.title, "observation": f.observation, "evidence": f.evidence}
            for f in open_findings
        ],
        "recent_deployments_24h": [
            {"sha": d.sha, "branch": d.branch, "message": (d.message or "")[:120],
             "deployed_at": d.deployed_at.isoformat(), "status": d.status}
            for d in recent_deploys
        ],
        "server": {"hostname": app_row.server.hostname if app_row.server else None},
    }
    serialized = _checked_json(pack, max_chars)
    return serialized


def _checked_json(pack: dict, max_chars: int) -> dict:
    """Cap the pack so a chatty app can never blow the LLM context (§2 guardrail)."""
    import json

    text = json.dumps(pack, default=str)
    if len(text) <= max_chars:
        return pack
    # Drop the heaviest optional section first, then hard-truncate metric history.
    if pack.get("metrics_recent"):
        pack["metrics_recent"] = pack["metrics_recent"][-10:]
    if len(json.dumps(pack, default=str)) > max_chars:
        pack["metrics_recent"] = []
        pack["findings"] = [f for f in pack["findings"] if f["severity"] == "critical"][:5]
    return pack


def investigate(db: Session, incident: Incident) -> dict:
    """Phase-1 deterministic investigation: evidence pack + correlation verdicts."""
    app_row = db.get(Application, incident.application_id)
    pack = build_evidence_pack(db, incident)
    now = datetime.now(UTC)
    steps: list[dict] = []

    # 1. deployment correlation (±30 min around detection, spec §14)
    correlated_deploy = None
    for deploy in pack.get("recent_deployments_24h", []):
        deployed = datetime.fromisoformat(deploy["deployed_at"])
        if abs((incident.detected_at - deployed).total_seconds()) <= 1800:
            correlated_deploy = deploy
            break
    if correlated_deploy:
        steps.append({
            "kind": "correlation",
            "summary": f"Deployment {correlated_deploy.get('sha', '')[:8]} within ±30min of incident",
            "evidence": correlated_deploy,
        })

    # 2. health-check failure shape
    failing = [h for h in pack["health_checks"] if h["consecutive_failures"] >= 2]
    if failing:
        steps.append({
            "kind": "observation",
            "summary": f"{len(failing)} health target(s) failing: {', '.join(h['target'] for h in failing)}",
            "evidence": failing,
        })

    # 3. recent findings as candidate causes
    for finding in pack.get("findings", [])[:3]:
        steps.append({
            "kind": "finding",
            "summary": f"Candidate cause [{finding['confidence']}]: {finding['title']}",
            "evidence": finding.get("evidence", []),
        })

    verdict = {
        "probable_root_cause": (
            f"Deployment {correlated_deploy.get('sha', '')[:8]} correlated with failure"
            if correlated_deploy
            else (pack["findings"][0]["title"] if pack.get("findings") else "Undetermined — evidence collected")
        ),
        "confidence": "likely" if (correlated_deploy or pack.get("findings")) else "hypothesis",
        "evidence_refs": (
            [f"deployment:{correlated_deploy.get('sha')}"] if correlated_deploy else []
        ) + [f"finding:{f.get('rule')}" for f in pack.get("findings", [])[:3]],
        "recommended_action": (
            "Verify last deployment; prepare rollback if regression confirmed"
            if correlated_deploy else
            "Check process/port binding and application logs"
        ),
    }
    incident.investigation = {"pack": pack, "steps": steps, "verdict": verdict}
    incident.status = IncidentStatus.investigating
    incident.probable_root_cause = verdict["probable_root_cause"]
    incident.confidence = verdict["confidence"]
    for step in steps:
        db.add(IncidentEvent(incident_id=incident.id, ts=now, kind=step["kind"], summary=step["summary"],
                             payload={"evidence": step["evidence"]}))
        touch_timeline(db, incident.application_id, "agent", step["summary"], actor="agent",
                       incident_id=incident.id)
    db.flush()
    return verdict


def check_recovery(db: Session) -> int:
    """Auto-resolve: all checks ok for RECOVERY_CLOSE_OKS consecutive cycles."""
    resolved = 0
    open_incidents = db.scalars(
        select(Incident).where(
            Incident.status.in_([IncidentStatus.open, IncidentStatus.investigating,
                                 IncidentStatus.identified, IncidentStatus.mitigated])
        )
    ).all()
    for incident in open_incidents:
        app_row = db.get(Application, incident.application_id)
        if app_row is None or app_row.status is not AppStatus.healthy:
            continue
        checks = db.scalars(
            select(HealthCheck).where(HealthCheck.application_id == app_row.id)
        ).all()
        if checks and all(h.consecutive_oks >= RECOVERY_CLOSE_OKS or h.consecutive_failures == 0 for h in checks):
            incident.status = IncidentStatus.resolved
            incident.resolved_at = datetime.now(UTC)
            incident.detected_at = incident.detected_at.replace(tzinfo=UTC) if incident.detected_at.tzinfo is None else incident.detected_at
            incident.mitigated_at = incident.mitigated_at or incident.resolved_at
            incident.mttr_s = int((incident.resolved_at - incident.detected_at).total_seconds())
            db.add(IncidentEvent(incident_id=incident.id, kind="resolved",
                                 summary=f"Recovered; MTTR {incident.mttr_s}s"))
            touch_timeline(db, app_row.id, "incident",
                           f"Incident resolved (MTTR {incident.mttr_s}s)", incident_id=incident.id)
            resolved += 1
    db.flush()
    return resolved
