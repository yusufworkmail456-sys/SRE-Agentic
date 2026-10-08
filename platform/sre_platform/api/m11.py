"""M11 API: SLO threshold CRUD, quick reminders, perf tests, app reports,
external-resource registration form endpoints (HTMX)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..llm import LLMClient
from ..models import Application, Repository, SLO
from ..quickreminders import active_quick_findings
from ..quickreport import (
    generate_app_report,
    latest_report,
    perf_test_state,
    report_to_markdown,
    start_perf_test,
)
from ..security import require_role
from ..services import slugify, unique_slug

router = APIRouter(prefix="/api", tags=["m11"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "ui" / "templates"))


def _app_u(path: str) -> str:
    """Template url helper for fragments (same prefix logic as app.py)."""
    prefix = (settings.url_prefix or "").rstrip("/")
    return f"{prefix}{path}" if prefix else path


def _get_app(db: Session, slug: str) -> Application:
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    return app_row


# ---------------------------------------------------------------- advanced SLO
VALID_SLO_METRICS = {
    "availability": None,
    "latency_p95": None,
    "error_rate": "error_rate",
    "req_rate": "req_rate",
    "latency_p95_ms": "latency_p95_ms",
    "cpu_pct": "cpu_pct",
    "mem_pct": "mem_pct",
}


class SLOThresholdRequest(BaseModel):
    sli: str = Field(description="error_rate | req_rate | latency_p95_ms | cpu_pct | mem_pct")
    comparison: str = Field(description="'<' or '>' — breach when metric cmp threshold")
    threshold: float
    window_days: int = 30


@router.post("/apps/{slug}/slos/threshold", status_code=201)
def create_threshold_slo(
    slug: str, req: SLOThresholdRequest, db: Session = Depends(get_db),
    _user=Depends(require_role("responder")),
):
    app_row = _get_app(db, slug)
    if req.sli not in ("error_rate", "req_rate", "latency_p95_ms", "cpu_pct", "mem_pct"):
        raise HTTPException(422, "unsupported SLI metric")
    if req.comparison not in ("<", ">"):
        raise HTTPException(422, "comparison must be '<' or '>'")
    existing = db.scalar(
        select(SLO).where(SLO.application_id == app_row.id, SLO.sli == req.sli)
    )
    if existing is not None:
        existing.metric = req.sli
        existing.comparison = req.comparison
        existing.threshold = req.threshold
        existing.window_days = req.window_days
        existing.enabled = True
        existing.target = 0.0
        slo_row = existing
    else:
        slo_row = SLO(
            application_id=app_row.id, sli=req.sli, metric=req.sli,
            comparison=req.comparison, threshold=req.threshold,
            window_days=req.window_days, target=0.0,
        )
        db.add(slo_row)
    db.commit()
    return {"id": slo_row.id, "sli": slo_row.sli, "comparison": slo_row.comparison,
            "threshold": slo_row.threshold, "window_days": slo_row.window_days}


@router.get("/apps/{slug}/slos/threshold")
def list_threshold_slos(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    rows = db.scalars(
        select(SLO).where(
            SLO.application_id == app_row.id, SLO.metric.is_not(None), SLO.enabled == True  # noqa: E712
        )
    ).all()
    return [
        {"id": s.id, "sli": s.sli, "comparison": s.comparison, "threshold": s.threshold,
         "window_days": s.window_days}
        for s in rows
    ]


@router.delete("/apps/{slug}/slos/threshold/{slo_id}")
def delete_threshold_slo(
    slug: str, slo_id: int, db: Session = Depends(get_db),
    _user=Depends(require_role("responder")),
):
    app_row = _get_app(db, slug)
    slo_row = db.scalar(
        select(SLO).where(SLO.id == slo_id, SLO.application_id == app_row.id)
    )
    if slo_row is None:
        raise HTTPException(404, "SLO not found")
    slo_row.enabled = False
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- quick reminders
@router.get("/apps/{slug}/reminders")
def get_reminders(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    return [
        {
            "id": f.id, "rule": f.rule_key, "title": f.title,
            "observation": f.observation, "recommendation": f.recommendation,
            "severity": f.severity.value, "last_seen": f.last_seen.isoformat(),
        }
        for f in active_quick_findings(db, app_row.id)
    ]


@router.post("/apps/{slug}/reminders/{finding_id}/ack")
def ack_reminder(
    slug: str, finding_id: int, db: Session = Depends(get_db),
    _user=Depends(require_role("responder")),
):
    from ..models import Finding, FindingStatus

    app_row = _get_app(db, slug)
    finding = db.scalar(
        select(Finding).where(Finding.id == finding_id, Finding.application_id == app_row.id)
    )
    if finding is None:
        raise HTTPException(404, "reminder not found")
    finding.status = FindingStatus.acknowledged
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------- perf test
class PerfTestRequest(BaseModel):
    duration_s: int = Field(default=120, ge=60, le=600)


@router.post("/apps/{slug}/perf-test", status_code=201)
def start_test(slug: str, req: PerfTestRequest, db: Session = Depends(get_db),
               _user=Depends(require_role("responder"))):
    app_row = _get_app(db, slug)
    running, _ = perf_test_state(db, app_row.id)
    if running is not None:
        raise HTTPException(409, "a perf test is already running")
    test = start_perf_test(db, app_row, req.duration_s)
    db.commit()
    return {"id": test.id, "status": "running", "duration_s": test.duration_s,
            "started_at": test.started_at.isoformat()}


@router.post("/apps/{slug}/perf-test/ui", response_class=HTMLResponse)
def start_test_ui(
    slug: str, request: Request, db: Session = Depends(get_db),
    duration_s: int = Form(120),
    _user=Depends(require_role("responder")),
):
    app_row = _get_app(db, slug)
    running, _ = perf_test_state(db, app_row.id)
    if running is None:
        start_perf_test(db, app_row, duration_s)
        db.commit()
    running, latest_done = perf_test_state(db, app_row.id)
    return templates.TemplateResponse(
        request, "_perf_test.html",
        {"app": app_row, "running_test": running, "latest_test": latest_done,
         "settings": settings, "u": _app_u},
    )


@router.get("/apps/{slug}/perf-test")
def get_test(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    running, latest_done = perf_test_state(db, app_row.id)

    def _view(t):
        if t is None:
            return None
        return {
            "id": t.id, "status": t.status, "duration_s": t.duration_s,
            "started_at": t.started_at.isoformat() if t.started_at else None,
            "finished_at": t.finished_at.isoformat() if t.finished_at else None,
            "summary": t.summary,
        }

    return {"running": _view(running), "latest": _view(latest_done)}


# ---------------------------------------------------------------- quick report
@router.post("/apps/{slug}/report", status_code=201)
def create_report(slug: str, db: Session = Depends(get_db),
                  window_minutes: int = 120, _user=Depends(require_role("responder"))):
    app_row = _get_app(db, slug)
    window = max(15, min(1440, window_minutes))
    report = generate_app_report(db, app_row, LLMClient(), window_minutes=window)
    db.commit()
    return {"id": report.id, "generated_by": report.generated_by,
            "created_at": report.created_at.isoformat() if report.created_at else None}


@router.get("/apps/{slug}/report/latest")
def get_latest_report(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    report = latest_report(db, app_row.id)
    if report is None:
        raise HTTPException(404, "no report yet")
    return {"id": report.id, "doc": report.doc, "generated_by": report.generated_by,
            "created_at": report.created_at.isoformat() if report.created_at else None}


@router.get("/apps/{slug}/report/latest/export.md", response_class=PlainTextResponse)
def export_latest_report(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    report = latest_report(db, app_row.id)
    if report is None:
        raise HTTPException(404, "no report yet")
    return report_to_markdown(report, app_row.name)


# ---------------------------------------------------------------- UI fragments (HTMX)
@router.get("/apps/{slug}/reminders", response_class=HTMLResponse)
def reminders_fragment(slug: str, request: Request, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    return templates.TemplateResponse(
        request, "_reminders_live.html",
        {"app": app_row, "quick_reminders": active_quick_findings(db, app_row.id),
         "settings": settings, "u": _app_u},
    )


@router.get("/apps/{slug}/perf-test/fragment", response_class=HTMLResponse)
def perf_test_fragment(slug: str, request: Request, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    running, latest_done = perf_test_state(db, app_row.id)
    return templates.TemplateResponse(
        request, "_perf_test.html",
        {"app": app_row, "running_test": running, "latest_test": latest_done,
         "settings": settings, "u": _app_u},
    )


@router.get("/apps/{slug}/slos/threshold/ui", response_class=HTMLResponse)
def _noop_slo_ui(slug: str, request: Request, db: Session = Depends(get_db)):
    return HTMLResponse('<span class="muted">—</span>')


@router.post("/apps/{slug}/slos/threshold/ui", response_class=HTMLResponse)
def create_threshold_slo_ui(
    slug: str, request: Request, db: Session = Depends(get_db),
    sli: str = Form(""), comparison: str = Form(">"), threshold: str = Form(""),
    _user=Depends(require_role("responder")),
):
    app_row = _get_app(db, slug)
    try:
        threshold_f = float(threshold)
    except ValueError:
        return HTMLResponse('<span class="err">threshold harus angka</span>', status_code=422)
    if sli not in ("error_rate", "req_rate", "latency_p95_ms", "cpu_pct", "mem_pct"):
        return HTMLResponse('<span class="err">SLI tidak dikenal</span>', status_code=422)
    if comparison not in ("<", ">"):
        return HTMLResponse('<span class="err">comparison harus < atau ></span>', status_code=422)
    existing = db.scalar(select(SLO).where(SLO.application_id == app_row.id, SLO.sli == sli))
    if existing is not None:
        existing.metric, existing.comparison, existing.threshold = sli, comparison, threshold_f
        existing.enabled = True
        existing.target = 0.0
    else:
        db.add(SLO(application_id=app_row.id, sli=sli, metric=sli, comparison=comparison,
                   threshold=threshold_f, target=0.0))
    db.commit()
    return HTMLResponse(
        f'<span class="ok-text">✓ SLO {sli} {comparison} {threshold_f:g} disimpan — '
        f'quick reminder muncul otomatis saat breach. Refresh halaman.</span>'
    )


@router.post("/apps/{slug}/report/ui", response_class=HTMLResponse)
def create_report_ui(
    slug: str, request: Request, db: Session = Depends(get_db),
    window_minutes: int = Form(120),
    _user=Depends(require_role("responder")),
):
    app_row = _get_app(db, slug)
    window = max(15, min(1440, window_minutes or 120))
    report = generate_app_report(db, app_row, LLMClient(), window_minutes=window)
    db.commit()
    perf = report.doc.get("performance", {})
    return HTMLResponse(
        f'<span class="ok-text">✓ Report dibuat ({report.generated_by}) — '
        f'{perf.get("http_total", "—")} requests, '
        f'err {perf.get("err_rate_avg", "—")}, p95 {perf.get("p95_avg_ms", "—")}ms. '
        f'Refresh halaman untuk detail + export .md.</span>'
    )


# ---------------------------------------------------------------- external resource (UI/HTMX)
@router.post("/ui/apps/external", response_class=HTMLResponse)
def register_external_ui(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(""),
    domain: str = Form(""),
    repository_url: str = Form(""),
    health_check_url: str = Form(""),
    owner: str = Form(""),
    environment: str = Form("prod"),
    _user=Depends(require_role("responder")),
):
    if not name.strip() or not domain.strip():
        return HTMLResponse('<span class="err">nama + domain wajib diisi</span>', status_code=422)
    from ..models import DeploymentModel, DiscoverySource, Endpoint, HealthCheck

    slug = unique_slug(db, slugify(name.strip()))
    app_row = Application(
        name=name.strip(), slug=slug, environment=environment or "prod",
        owner=owner or None, discovery=DiscoverySource.manual, confirmed=True,
        deployment_model=DeploymentModel.external,
    )
    db.add(app_row)
    db.flush()
    url = domain.strip() if domain.strip().startswith("http") else f"https://{domain.strip()}"
    db.add(Endpoint(application_id=app_row.id, url=url, domain=domain.strip()))
    target = (health_check_url or url).strip()
    db.add(HealthCheck(application_id=app_row.id, kind="http", target=target, interval_s=60))
    if repository_url.strip():
        db.add(Repository(application_id=app_row.id, url=repository_url.strip(), default_branch="main"))
    from ..services import touch_timeline

    touch_timeline(db, app_row.id, "discovery", "External Resource registered via UI", actor="user")
    db.commit()
    return templates.TemplateResponse(
        request, "_external_added.html",
        {"app": app_row, "settings": settings, "u": _app_u},
    )
