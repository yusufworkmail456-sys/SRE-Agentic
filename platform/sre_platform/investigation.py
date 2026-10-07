"""LLM-assisted investigation + periodic analysis (spec §14, §23; approved §2 loop).

Contract with the model:
- input: evidence pack (already capped) + instructions
- output: JSON {root_cause, confidence, recommendations[], findings[]}
- every claim must cite evidence_refs that exist in the pack; refs that do not
  resolve are dropped, and a claim left without refs is downgraded to
  `hypothesis` before storage. The LLM never writes anything but finding rows
  and incident fields — no actions, no code changes (spec §6 hard rules).
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .llm import LLMClient, LLMUnavailable
from .models import (
    Application,
    Confidence,
    Finding,
    FindingCategory,
    FindingStatus,
    Incident,
    IncidentEvent,
    IncidentStatus,
    Severity,
    TimelineEvent,
)
from . import incidents as incidents_svc

log = logging.getLogger("sre-platform.investigation")

SYSTEM_INVESTIGATE = (
    "You are an SRE incident investigator. You receive an evidence pack about a "
    "production incident. Answer ONLY with a JSON object, no prose:\n"
    '{"root_cause": "<one sentence>", "confidence": "confirmed|likely|hypothesis",\n'
    ' "affected_components": ["..."],\n'
    ' "recommendation": "<one sentence>",\n'
    ' "evidence_refs": ["<source>:<ref> copied from the pack"],\n'
    ' "reasoning": "<2-3 sentences max>"}\n'
    "Rules: cite only refs present in the pack; if evidence is insufficient use "
    'confidence "hypothesis"; never invent data; do not propose executing actions '
    "beyond recommending them."
)

SYSTEM_ANALYZE = (
    "You are an SRE reliability analyst doing a periodic review of one application. "
    "You receive a small evidence pack (metrics, health, recent logs, findings). "
    "Answer ONLY with a JSON object:\n"
    '{"findings": [{"category": "performance|reliability|security|operational|deployment|capacity",\n'
    '  "severity": "critical|warning|info", "confidence": "confirmed|likely|hypothesis",\n'
    '  "title": "...", "observation": "...", "probable_cause": "...",\n'
    '  "recommendation": "...", "evidence_refs": ["<source>:<ref> from the pack"]}]}\n'
    "Rules: report only issues supported by the pack; empty findings list is a valid "
    "answer; never invent metrics; cite refs copied from the pack."
)

VALID_CATEGORIES = {c.value for c in FindingCategory}
VALID_SEVERITIES = {s.value for s in Severity}
VALID_CONFIDENCE = {c.value for c in Confidence}


def _pack_refs(pack: dict) -> set[str]:
    """Collect citable refs from an evidence pack (items may carry their own ref)."""
    refs: set[str] = set()
    for key in ("health_checks", "metrics_recent"):
        for i, item in enumerate(pack.get(key) or []):
            if isinstance(item, dict) and item.get("ref"):
                refs.add(str(item["ref"]))
            else:
                refs.add(f"{key[:-1]}:{i}")
    for f in pack.get("findings") or []:
        if f.get("rule"):
            refs.add(f"finding:{f['rule']}")
    for d in pack.get("recent_deployments_24h") or []:
        if d.get("sha"):
            refs.add(f"deployment:{d['sha']}")
    for item in pack.get("log_errors_30m") or []:
        refs.add(str(item.get("ref", f"log_error:{item.get('i', 0)}")) if isinstance(item, dict) else "log_error:0")
    if pack.get("application"):
        refs.add("application:workloads")
    return refs


def _valid_refs(claims_refs, allowed: set[str]) -> list[str]:
    if not isinstance(claims_refs, list):
        return []
    return [r for r in claims_refs if isinstance(r, str) and r in allowed]


def llm_investigate_incident(db: Session, incident: Incident, client: LLMClient | None = None) -> dict | None:
    """LLM diagnosis over the deterministic pack. Returns verdict or None."""
    client = client or LLMClient()
    if not client.enabled:
        return None
    app_row = db.get(Application, incident.application_id)
    pack = incidents_svc.build_evidence_pack(db, incident)
    allowed = _pack_refs(pack)
    prompt = (
        f"Incident: {incident.title}\n"
        f"Application: {app_row.name if app_row else 'unknown'}\n"
        f"Detected: {incident.detected_at.isoformat()}\n\n"
        f"Evidence pack (JSON):\n{json.dumps(pack, default=str)}\n\n"
        "Diagnose. Cite refs from this pack only."
    )
    try:
        verdict = client.chat_json(SYSTEM_INVESTIGATE, prompt)
    except LLMUnavailable as exc:
        log.warning("llm investigate unavailable: %s", exc)
        return None

    refs = _valid_refs(verdict.get("evidence_refs"), allowed)
    confidence = verdict.get("confidence", "hypothesis")
    if confidence not in VALID_CONFIDENCE:
        confidence = "hypothesis"
    if not refs and confidence == "confirmed":
        confidence = "likely"  # uncited certainty is downgraded, never trusted
    verdict["evidence_refs"] = refs
    verdict["confidence"] = confidence
    verdict["generated_at"] = datetime.now(UTC).isoformat()
    verdict["llm_model"] = client.model

    incident.investigation = {**(incident.investigation or {}), "llm_verdict": verdict}
    incident.status = IncidentStatus.identified
    incident.probable_root_cause = str(verdict.get("root_cause") or "")[:512] or incident.probable_root_cause
    incident.confidence = Confidence(confidence)
    incident.identified_at = datetime.now(UTC)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            kind="llm_diagnosis",
            summary=f"LLM diagnosis [{confidence}]: {incident.probable_root_cause[:160]}",
            payload={"evidence_refs": refs, "reasoning": str(verdict.get("reasoning", ""))[:500]},
        )
    )
    db.add(
        TimelineEvent(
            application_id=incident.application_id,
            incident_id=incident.id,
            kind="agent",
            actor="agent",
            summary=f"LLM diagnosis [{confidence}]: {str(verdict.get('root_cause', ''))[:120]}",
        )
    )
    db.flush()
    return verdict


def llm_periodic_analysis(db: Session, app_row: Application, client: LLMClient | None = None) -> list[Finding]:
    """Recurring per-app analysis (approved loop). Emits evidence-cited findings."""
    client = client or LLMClient()
    if not client.enabled:
        return []
    pack = _mini_pack(db, app_row)
    if not pack:
        return []
    allowed = _pack_refs(pack)
    prompt = (
        f"Application: {app_row.name} ({app_row.environment})\n"
        f"Evidence pack (JSON):\n{json.dumps(pack, default=str)}\n\n"
        "Review and report findings with refs from this pack."
    )
    try:
        result = client.chat_json(SYSTEM_ANALYZE, prompt, max_tokens=900)
    except LLMUnavailable as exc:
        log.warning("llm analysis unavailable: %s", exc)
        return []
    created: list[Finding] = []
    for item in (result.get("findings") or [])[:6]:
        if not isinstance(item, dict) or not item.get("title"):
            continue
        refs = _valid_refs(item.get("evidence_refs"), allowed)
        confidence = item.get("confidence", "hypothesis")
        if confidence not in VALID_CONFIDENCE or (not refs and confidence == "confirmed"):
            confidence = "hypothesis" if not refs else confidence
        rule_key = "llm:" + hashlib.sha1(
            f"{app_row.id}:{item.get('title', '')}".encode()
        ).hexdigest()[:12]
        finding = _upsert_llm_finding(db, app_row, rule_key, item, refs, confidence)
        if finding is not None:
            created.append(finding)
    if created:
        db.flush()
    return created


def _upsert_llm_finding(
    db: Session, app_row: Application, rule_key: str, item: dict, refs: list[str], confidence: str
) -> Finding | None:
    severity = item.get("severity", "info")
    if severity not in VALID_SEVERITIES:
        severity = "info"
    category = item.get("category", "reliability")
    if category not in VALID_CATEGORIES:
        category = "reliability"
    existing = db.scalar(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.rule_key == rule_key,
            Finding.status.in_([FindingStatus.open, FindingStatus.acknowledged]),
        )
    )
    if existing is not None:
        existing.last_seen = datetime.now(UTC)
        existing.observation = str(item.get("observation", ""))[:1000]
        return None
    finding = Finding(
        application_id=app_row.id,
        rule_key=rule_key,
        category=FindingCategory(category),
        severity=Severity(severity),
        confidence=Confidence(confidence),
        status=FindingStatus.open,
        title=f"[AI] {str(item.get('title', ''))[:200]}",
        observation=str(item.get("observation", ""))[:1000],
        probable_cause=str(item.get("probable_cause", ""))[:500],
        recommendation=str(item.get("recommendation", ""))[:500],
        evidence=[{"source": "llm_ref", "ref": r, "value": None} for r in refs],
        first_seen=datetime.now(UTC),
        last_seen=datetime.now(UTC),
    )
    db.add(finding)
    db.add(
        TimelineEvent(
            application_id=app_row.id,
            kind="finding",
            actor="agent",
            summary=f"AI finding [{severity}/{confidence}] {finding.title}",
        )
    )
    return finding


def _mini_pack(db: Session, app_row: Application, max_chars: int = 8000) -> dict:
    """Small pack for the recurring loop — cheap on tokens."""
    from .logstore import recent_error_samples
    from .metrics import latest_points
    from .models import Deployment, HealthCheck, MetricPoint

    points = latest_points(db, app_row.id, limit=12)
    checks = db.scalars(
        select(HealthCheck).where(HealthCheck.application_id == app_row.id)
    ).all()
    deploys = db.scalars(
        select(Deployment)
        .where(Deployment.application_id == app_row.id)
        .order_by(Deployment.deployed_at.desc())
        .limit(3)
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
    pack = {
        "application": {
            "name": app_row.name,
            "status": app_row.status.value,
            "environment": app_row.environment,
            "deployment_model": app_row.deployment_model.value,
        },
        "metrics_recent": [
            {"ref": f"metric_sample:{i}", "ts": p.ts.isoformat(), "req_rate": p.req_rate,
             "err_rate": p.err_rate, "p95_ms": p.p95_ms}
            for i, p in enumerate(reversed(points))
        ],
        "host": {"ref": "host:latest", "cpu_pct": server_point.cpu_pct if server_point else None,
                 "mem_pct": server_point.mem_pct if server_point else None,
                 "disk_pct": server_point.disk_pct if server_point else None},
        "health_checks": [
            {"ref": f"health_check:{i}", "target": h.target, "last_result": h.last_result,
             "fails": h.consecutive_failures}
            for i, h in enumerate(checks)
        ],
        "recent_deployments": [
            {"ref": f"deployment:{d.sha}", "sha": d.sha, "message": (d.message or "")[:80],
             "deployed_at": d.deployed_at.isoformat()}
            for d in deploys
        ],
        "log_errors_30m": [
            {**s, "ref": f"log_error:{i}"} for i, s in
            enumerate(recent_error_samples(db, app_row.id, minutes=30, limit=4))
        ],
        "open_findings": [],
    }
    # Repo awareness (spec §15): curated structure + manifests when linked.
    try:
        from .git_tools import inspect as git_inspect

        repo_summary = git_inspect(db, app_row, "structure")
        if repo_summary.get("ok"):
            pack["repository"] = {
                "ref": "repository:structure",
                "branch": repo_summary.get("branch"),
                "tree_top": repo_summary.get("tree_top", [])[:40],
                "manifests": list((repo_summary.get("manifests") or {}).keys()),
                "recent_commits": [
                    {**c, "ref": f"commit:{c['sha']}"} for c in repo_summary.get("recent_commits", [])[:8]
                ],
            }
    except Exception:
        pass
    import json as _json

    if len(_json.dumps(pack, default=str)) > max_chars:
        pack["metrics_recent"] = pack["metrics_recent"][-6:]
    return pack
