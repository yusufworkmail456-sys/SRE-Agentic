"""Remediation API (spec §16/§17/§18): propose -> approve -> execute push_fix.

Flow:
1. POST /api/apps/{slug}/remediations — LLM or human proposes file changes.
   Full contents are stored server-side on the Remediation row (never logged),
   status=proposed + AgentAction(status=proposed, risk=medium).
2. POST /api/remediations/{id}/approve — human approval with TTL nonce.
3. POST /api/remediations/{id}/execute — only when approved & unexpired; runs
   gitwrite.push_fix (branch sre/fix/*, PR, never the default branch).
"""
from __future__ import annotations

import posixpath
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..git_tools import get_repo
from ..gitwrite import GitWriteError, push_fix
from ..models import (
    AgentAction,
    Actor,
    Application,
    Incident,
    Remediation,
    Repository,
    RiskLevel,
    TimelineEvent,
)
from ..security import require_role

router = APIRouter(prefix="/api", tags=["remediation"])

ALLOWED_CHANGE_EXT = {
    ".py", ".js", ".ts", ".json", ".yml", ".yaml", ".toml", ".md", ".txt",
    ".cfg", ".ini", ".sh", ".conf", ".html", ".css",
}
DENIED_PATH_PARTS = (".github/workflows", ".git", ".env", "secret", "credential")


def _get_app(db: Session, slug: str) -> Application:
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    return app_row


class RemediationRequest(BaseModel):
    title: str
    rationale: str | None = None
    incident_id: int | None = None
    file_changes: list[dict] = Field(default_factory=list)


def _validate_changes(file_changes: list[dict]) -> None:
    if not file_changes:
        raise HTTPException(422, "file_changes required")
    if len(file_changes) > 10:
        raise HTTPException(422, "max 10 files per remediation")
    for change in file_changes:
        path = change.get("path", "")
        if not path or path.startswith(("/", "..")) or ".." in path:
            raise HTTPException(422, f"unsafe path {path!r}")
        ext = posixpath.splitext(path)[1].lower()
        if ext not in ALLOWED_CHANGE_EXT:
            raise HTTPException(422, f"file type {ext!r} not allowed (safelist)")
        lowered = path.lower()
        if any(part in lowered for part in DENIED_PATH_PARTS):
            raise HTTPException(422, f"path {path!r} hits denylist (workflows/secrets)")


@router.post("/apps/{slug}/remediations", status_code=201)
def propose(slug: str, req: RemediationRequest, db: Session = Depends(get_db),
            _user=Depends(require_role("viewer"))):
    app_row = _get_app(db, slug)
    _validate_changes(req.file_changes)
    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        raise HTTPException(409, "link a repository first")
    if req.incident_id:
        incident = db.get(Incident, req.incident_id)
        if incident is None or incident.application_id != app_row.id:
            raise HTTPException(404, "incident not found for this application")

    remediation = Remediation(
        application_id=app_row.id,
        incident_id=req.incident_id,
        title=req.title[:300],
        rationale=req.rationale,
        actions=[{"path": c["path"], "bytes": len(c.get("content", ""))} for c in req.file_changes],
        status="proposed",
        risk=RiskLevel.medium,
        evidence=[{"path": c["path"], "content": c.get("content", "")} for c in req.file_changes],
    )
    db.add(remediation)
    db.flush()
    action = AgentAction(
        application_id=app_row.id,
        incident_id=req.incident_id,
        actor=Actor.agent,
        action="propose_remediation",
        target=f"remediation:{remediation.id}",
        reason=req.title,
        evidence={"files": [c["path"] for c in req.file_changes]},
        risk=RiskLevel.medium,
        status="proposed",
    )
    db.add(action)
    db.add(
        TimelineEvent(
            application_id=app_row.id,
            incident_id=req.incident_id,
            kind="remediation",
            actor="agent",
            summary=f"Remediation proposed: {remediation.title} ({len(req.file_changes)} file(s))",
        )
    )
    db.commit()
    return {"id": remediation.id, "status": remediation.status, "risk": remediation.risk.value,
            "next": f"POST /api/remediations/{remediation.id}/approve"}


class ApprovalRequest(BaseModel):
    reviewer: str = "admin"
    ttl_minutes: int = 30


def _approved_action(db: Session, rem_id: int, status: str) -> AgentAction | None:
    return db.scalar(
        select(AgentAction).where(
            AgentAction.target == f"remediation:{rem_id}",
            AgentAction.status == status,
        )
    )


@router.post("/remediations/{rem_id}/approve")
def approve(rem_id: int, req: ApprovalRequest, db: Session = Depends(get_db),
            _user=Depends(require_role("responder"))):
    remediation = db.get(Remediation, rem_id)
    if remediation is None:
        raise HTTPException(404, "not found")
    if remediation.status != "proposed":
        raise HTTPException(409, f"status is {remediation.status}, cannot approve")
    action = _approved_action(db, rem_id, "proposed")
    if action is None:
        raise HTTPException(500, "provenance action missing")
    nonce = secrets.token_urlsafe(16)
    expires = datetime.now(UTC) + timedelta(minutes=req.ttl_minutes)
    action.status = "approved"
    action.approval = {
        "reviewer": req.reviewer,
        "nonce": nonce,
        "approved_at": datetime.now(UTC).isoformat(),
        "expires_at": expires.isoformat(),
    }
    remediation.status = "approved"
    db.add(
        TimelineEvent(
            application_id=remediation.application_id,
            incident_id=remediation.incident_id,
            kind="remediation",
            actor=f"user:{req.reviewer}",
            summary=f"Remediation {rem_id} approved (expires {expires.strftime('%H:%M')}Z)",
        )
    )
    db.commit()
    return {"id": rem_id, "status": "approved", "expires_at": expires.isoformat(),
            "next": f"POST /api/remediations/{rem_id}/execute"}


class ExecuteRequest(BaseModel):
    commit_message: str
    pr_title: str
    pr_body: str = ""


@router.post("/remediations/{rem_id}/execute")
def execute(rem_id: int, req: ExecuteRequest, db: Session = Depends(get_db),
            _user=Depends(require_role("responder"))):
    remediation = db.get(Remediation, rem_id)
    if remediation is None:
        raise HTTPException(404, "not found")
    if remediation.status != "approved":
        raise HTTPException(409, f"status is {remediation.status}, approve first")
    action = _approved_action(db, rem_id, "approved")
    expires_raw = (action.approval or {}).get("expires_at", "") if action else ""
    if action is None or expires_raw < datetime.now(UTC).isoformat():
        remediation.status = "expired"
        if action is not None:
            action.status = "expired"
        db.commit()
        raise HTTPException(409, "approval missing or expired — re-propose")
    app_row = db.get(Application, remediation.application_id)
    if app_row is None:
        raise HTTPException(500, "application missing")
    got = get_repo(db, app_row)
    if got is None:
        raise HTTPException(409, "repository unavailable")
    repo, _path = got

    stored = remediation.evidence or []
    if not stored:
        raise HTTPException(500, "file contents missing — re-propose")

    ref = f"rem-{rem_id}" + (f"-inc-{remediation.incident_id}" if remediation.incident_id else "")
    branch = f"sre/fix/{ref}"
    incident = db.get(Incident, remediation.incident_id) if remediation.incident_id else None
    try:
        result = push_fix(
            db, app_row, incident, repo, branch,
            file_changes=stored,
            commit_message=req.commit_message,
            pr_title=req.pr_title,
            pr_body=req.pr_body + f"\n\nRemediation #{rem_id}.",
            approved_action=action,
        )
    except GitWriteError as exc:
        remediation.status = "failed"
        action.status = "failed"
        action.result = {"error": str(exc)[:300]}
        db.commit()
        raise HTTPException(502, f"git write failed: {exc}") from exc
    remediation.status = "executed"
    db.add(
        TimelineEvent(
            application_id=remediation.application_id,
            incident_id=remediation.incident_id,
            kind="remediation",
            actor="agent",
            summary=f"Fix pushed: {branch} — PR {result['pr'].get('url', 'created')}",
        )
    )
    db.commit()
    return {"id": rem_id, "status": "executed", **result}
