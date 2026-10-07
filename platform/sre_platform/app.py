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

    @app.get("/healthz")
    def healthz(db: Session = Depends(get_db)) -> dict:
        db.execute(select(func.count()).select_from(Application))
        return {"status": "ok", "app": settings.app_name, "version": settings.version}

    @app.get("/", response_class=HTMLResponse)
    def overview(request: Request, db: Session = Depends(get_db)):
        apps = db.scalars(select(Application).order_by(Application.name)).all()
        counts: dict[str, int] = {}
        for a in apps:
            counts[a.status.value] = counts.get(a.status.value, 0) + 1
        attention = []
        for app_row in apps:
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
            if app_row.status.value in ("down", "degraded") or open_incidents or open_findings:
                attention.append(
                    {
                        "app": app_row,
                        "findings": open_findings or 0,
                        "incidents": open_incidents or 0,
                    }
                )
        attention.sort(key=lambda r: (r["app"].status.value != "down", r["app"].status.value != "degraded"))
        return templates.TemplateResponse(
            request,
            "overview.html",
            {
                "settings": settings,
                "counts": counts,
                "total": len(apps),
                "attention": attention,
                "servers": db.scalars(select(Server)).all(),
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
        from .models import LogBatch

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
