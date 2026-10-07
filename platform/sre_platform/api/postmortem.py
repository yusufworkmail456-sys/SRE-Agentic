"""Postmortem + SLO API (review flow, export, budget states)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Application, Incident, Postmortem, SLO
from ..postmortem import (
    compute_slo_status,
    generate_postmortem,
    slo_summary_for_app,
    to_markdown,
)

router = APIRouter(prefix="/api", tags=["postmortem"])


@router.post("/incidents/{incident_id}/postmortem", status_code=201)
def create_postmortem(incident_id: int, db: Session = Depends(get_db)):
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(404, "incident not found")
    if incident.status != "resolved":
        raise HTTPException(409, "incident not resolved yet")
    pm = generate_postmortem(db, incident)
    db.commit()
    if pm is None:
        raise HTTPException(500, "could not generate postmortem")
    return {"id": pm.id, "incident_id": incident.id, "generated_by": pm.generated_by,
            "published": pm.published}


@router.get("/postmortems")
def list_postmortems(db: Session = Depends(get_db)):
    rows = db.scalars(select(Postmortem).order_by(Postmortem.created_at.desc()).limit(50)).all()
    return [
        {
            "id": p.id,
            "incident_id": p.incident_id,
            "generated_by": p.generated_by,
            "reviewed_by": p.reviewed_by,
            "published": p.published,
            "title": (p.doc or {}).get("title"),
        }
        for p in rows
    ]


@router.get("/postmortems/{pm_id}")
def get_postmortem(pm_id: int, db: Session = Depends(get_db)):
    pm = db.get(Postmortem, pm_id)
    if pm is None:
        raise HTTPException(404, "not found")
    return {"id": pm.id, "incident_id": pm.incident_id, "doc": pm.doc,
            "generated_by": pm.generated_by, "reviewed_by": pm.reviewed_by,
            "published": pm.published}


@router.get("/postmortems/{pm_id}/export.md", response_class=PlainTextResponse)
def export_postmortem(pm_id: int, db: Session = Depends(get_db)):
    pm = db.get(Postmortem, pm_id)
    if pm is None:
        raise HTTPException(404, "not found")
    return to_markdown(pm.doc)


class ReviewRequest(BaseModel):
    reviewer: str = "admin"
    edits: dict = Field(default_factory=dict)


@router.post("/postmortems/{pm_id}/review")
def review_postmortem(pm_id: int, req: ReviewRequest, db: Session = Depends(get_db)):
    """Human review: optional edits, then publish. Unreviewed drafts never feed
    SLO learning data (spec §20)."""
    pm = db.get(Postmortem, pm_id)
    if pm is None:
        raise HTTPException(404, "not found")
    for key, value in (req.edits or {}).items():
        if key in ("title", "incident_summary", "impact", "root_cause", "lessons_learned",
                   "preventive_actions"):
            pm.doc = {**pm.doc, key: value}
    pm.reviewed_by = req.reviewer
    pm.published = True
    db.commit()
    return {"ok": True, "id": pm.id, "reviewed_by": pm.reviewed_by, "published": True}


class SLORequest(BaseModel):
    sli: str = "availability"          # availability | latency_p95
    target: float = 0.999
    target_ms: float | None = None
    window_days: int = 30


@router.post("/apps/{slug}/slos", status_code=201)
def create_slo(slug: str, req: SLORequest, db: Session = Depends(get_db)):
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    if req.sli == "latency_p95" and not req.target_ms:
        raise HTTPException(422, "latency_p95 requires target_ms")
    existing = db.scalar(
        select(SLO).where(SLO.application_id == app_row.id, SLO.sli == req.sli)
    )
    if existing is not None:
        existing.target = req.target
        existing.target_ms = req.target_ms
        existing.window_days = req.window_days
        existing.enabled = True
        slo_row = existing
    else:
        slo_row = SLO(
            application_id=app_row.id, sli=req.sli, target=req.target,
            target_ms=req.target_ms, window_days=req.window_days,
        )
        db.add(slo_row)
    db.commit()
    state = compute_slo_status(db, slo_row)
    db.commit()
    return {"id": slo_row.id, "sli": slo_row.sli, "target": slo_row.target,
            "window_days": slo_row.window_days,
            "state": {"current_pct": state.current_pct if state else None,
                      "exhausted": state.exhausted if state else None,
                      "burned_s": state.burned_s if state else None}}


@router.get("/apps/{slug}/slos")
def get_slos(slug: str, db: Session = Depends(get_db)):
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    return slo_summary_for_app(db, app_row.id)
