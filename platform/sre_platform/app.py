"""FastAPI app factory: API + server-rendered UI (HTMX) in one process."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import asyncio

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .api import agent as agent_api
from .api import apps as apps_api
from .api import ask as ask_api
from .api import postmortem as pm_api
from .config import settings
from .db import engine, get_db
from .models import (
    Application,
    Base,
    Finding,
    Incident,
    MetricPoint,
    Server,
    TimelineEvent,
)
from .services import confirm_application, slugify, unique_slug
from . import sweeper

BASE_DIR = Path(__file__).resolve().parent


def _ensure_bootstrap_admin() -> None:
    """First-run: create the admin user, one-time password written 0600 (Trazezzo pattern)."""
    import secrets

    from .models import User
    from .security import hash_password

    db = next(get_db())
    try:
        if db.scalar(select(User).limit(1)) is not None:
            return
        password = secrets.token_urlsafe(14)
        db.add(User(username="admin", password_hash=hash_password(password), role="admin"))
        db.commit()
        secret_file = Path(settings.data_dir) / "initial_admin_password.txt"
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(f"admin: {password}\n")
        secret_file.chmod(0o600)
    finally:
        db.close()


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        Base.metadata.create_all(engine)
        _ensure_bootstrap_admin()
        task = asyncio.create_task(sweeper.sweep_loop())
        yield
        task.cancel()

    app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)
    templates = Jinja2Templates(directory=str(BASE_DIR / "ui" / "templates"))
    app.include_router(apps_api.router)
    app.include_router(agent_api.router)
    app.include_router(ask_api.router)
    app.include_router(pm_api.router)

    @app.get("/healthz")
    def healthz(db: Session = Depends(get_db)) -> dict:
        db.execute(select(func.count()).select_from(Application))
        return {"status": "ok", "app": settings.app_name, "version": settings.version}

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request, db: Session = Depends(get_db)):
        """Fleet overview (spec §8): status counts, next actions, per-app RED
        table, live activity feed. Answers 'user harus apa' explicitly."""
        from .logstore import window_error_counts
        from .metrics import latest_points
        from .models import LogBatch, MetricPoint, TimelineEvent

        apps = db.scalars(select(Application).order_by(Application.name)).all()
        counts: dict[str, int] = {"healthy": 0, "degraded": 0, "down": 0, "unknown": 0}
        for a in apps:
            counts[a.status.value] = counts.get(a.status.value, 0) + 1
        unconfirmed = [a for a in apps if not a.confirmed]

        # Per-app row data for the table (RED + counts), and attention ranking.
        app_rows = []
        attention = []
        for app_row in apps:
            latest = latest_points(db, app_row.id, limit=1)
            latest = latest[0] if latest else None
            open_findings = db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.application_id == app_row.id, Finding.status == "open")
            )
            open_incidents = db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(Incident.application_id == app_row.id, Incident.status != "resolved")
            )
            log_counts = window_error_counts(db, app_row.id, minutes=60)
            row = {
                "app": app_row,
                "req_rate": latest.req_rate if latest else None,
                "err_rate": latest.err_rate if latest else None,
                "p95": latest.p95_ms if latest else None,
                "findings": open_findings or 0,
                "incidents": open_incidents or 0,
                "log_errors_60m": log_counts.get("ERROR", 0) + log_counts.get("CRITICAL", 0),
            }
            app_rows.append(row)
            if app_row.confirmed and (
                app_row.status.value in ("down", "degraded")
                or open_incidents
                or (open_findings or 0) > 0
                or row["log_errors_60m"] >= 10
            ):
                attention.append(row)
        attention.sort(
            key=lambda r: (
                r["app"].status.value != "down",
                r["app"].status.value != "degraded",
                -(r["incidents"] or 0),
                -(r["findings"] or 0),
            )
        )

        # Next-actions checklist (what the operator should do now).
        actions: list[dict] = []
        for row in attention:
            if row["app"].status.value == "down":
                actions.append({
                    "level": "critical",
                    "text": f"{row['app'].name} DOWN — buka dashboard, cek incident yang sedang berjalan",
                    "href": f"/applications/{row['app'].slug}",
                })
        for row in attention:
            if row["incidents"] and row["app"].status.value != "down":
                actions.append({
                    "level": "warning",
                    "text": f"{row['app'].name}: {row['incidents']} incident terbuka — review diagnosis",
                    "href": f"/applications/{row['app'].slug}",
                })
        if unconfirmed:
            names = ", ".join(a.name for a in unconfirmed[:3]) + ("…" if len(unconfirmed) > 3 else "")
            actions.append({
                "level": "info",
                "text": f"{len(unconfirmed)} app hasil discovery belum dikonfirmasi ({names}) — review di halaman Discovery",
                "href": "/discovery",
            })
        no_apps = len(apps) == 0
        if no_apps:
            actions.append({
                "level": "info",
                "text": "Belum ada application — install sre-agent di VM target (docs/runbook-agent-install.md) atau register manual via API",
                "href": "/discovery",
            })
        if not actions:
            actions.append({
                "level": "ok",
                "text": "Semua sehat. Tidak ada yang perlu ditindak.",
                "href": "",
            })

        servers = db.scalars(select(Server)).all()
        recent_events = db.scalars(
            select(TimelineEvent).order_by(TimelineEvent.ts.desc()).limit(12)
        ).all()
        return templates.TemplateResponse(
            request,
            "overview.html",
            {
                "settings": settings,
                "counts": counts,
                "total": len(apps),
                "attention": attention,
                "app_rows": app_rows,
                "actions": actions,
                "no_apps": no_apps,
                "unconfirmed_count": len(unconfirmed),
                "servers": servers,
                "recent_events": recent_events,
            },
        )

    @app.get("/discovery", response_class=HTMLResponse)
    def discovery(request: Request, db: Session = Depends(get_db)):
        candidates = db.scalars(
            select(Application).where(Application.confirmed == False)  # noqa: E712
            .order_by(Application.name)
        ).all()
        return templates.TemplateResponse(
            request,
            "discovery.html",
            {
                "settings": settings,
                "candidates": candidates,
                "servers": db.scalars(select(Server)).all(),
                "apps": db.scalars(
                    select(Application).where(Application.confirmed == True)  # noqa: E712
                    .order_by(Application.name)
                ).all(),
            },
        )

    @app.post("/discovery/{slug}/confirm", response_class=HTMLResponse)
    def confirm_form(
        slug: str,
        request: Request,
        db: Session = Depends(get_db),
        name: str = Form(""),
        environment: str = Form("prod"),
        owner: str = Form(""),
        health_check_url: str = Form(""),
    ):
        app_row = db.scalar(select(Application).where(Application.slug == slug))
        if app_row is None:
            return HTMLResponse("<h1>404</h1>", status_code=404)
        if health_check_url:
            from .models import HealthCheck

            db.add(
                HealthCheck(
                    application_id=app_row.id,
                    kind="http" if health_check_url.startswith("http") else "tcp",
                    target=health_check_url,
                    interval_s=30,
                )
            )
        if name and name != app_row.name:
            new_base = slugify(name)
            if new_base != app_row.slug:  # keep slug when unchanged, avoid -2 suffix
                app_row.slug = unique_slug(db, new_base)
            app_row.name = name
        confirm_application(
            db, app_row, environment=environment or None, owner=owner or None
        )
        db.commit()
        return RedirectResponse("/discovery", status_code=303)

    @app.get("/applications/{slug}", response_class=HTMLResponse)
    def application_detail(slug: str, request: Request, db: Session = Depends(get_db)):
        from .logstore import window_error_counts
        from .metrics import latest_points
        from .models import LogBatch, Postmortem, SLO
        from .postmortem import budget_context_for_recommendations, slo_summary_for_app

        app_row = db.scalar(select(Application).where(Application.slug == slug))
        if app_row is None:
            return HTMLResponse("<h1>404</h1><p>Application not found.</p>", status_code=404)
        points = latest_points(db, app_row.id, limit=48)
        latest = points[0] if points else None
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
        return templates.TemplateResponse(
            request,
            "application.html",
            {
                "settings": settings,
                "app": app_row,
                "latest": latest,
                "server_point": server_point,
                "points": list(reversed(points)),  # oldest -> newest for sparkline
                "logs": db.scalars(
                    select(LogBatch)
                    .where(LogBatch.application_id == app_row.id)
                    .order_by(LogBatch.ts_end.desc())
                    .limit(12)
                ).all(),
                "log_counts": window_error_counts(db, app_row.id, minutes=60),
                "slos": slo_summary_for_app(db, app_row.id),
                "budget_note": budget_context_for_recommendations(db, app_row),
                "postmortems": db.scalars(
                    select(Postmortem)
                    .where(Postmortem.incident_id.in_(
                        select(Incident.id).where(Incident.application_id == app_row.id)
                    ))
                    .order_by(Postmortem.created_at.desc())
                    .limit(10)
                ).all(),
                "findings": db.scalars(
                    select(Finding)
                    .where(Finding.application_id == app_row.id)
                    .order_by(Finding.last_seen.desc())
                    .limit(20)
                ).all(),
                "incidents": db.scalars(
                    select(Incident)
                    .where(Incident.application_id == app_row.id)
                    .order_by(Incident.detected_at.desc())
                    .limit(10)
                ).all(),
                "timeline": db.scalars(
                    select(TimelineEvent)
                    .where(TimelineEvent.application_id == app_row.id)
                    .order_by(TimelineEvent.ts.desc())
                    .limit(50)
                ).all(),
            },
        )

    return app


app = create_app()
