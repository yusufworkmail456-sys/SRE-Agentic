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
from .api import m11 as m11_api
from .api import ops as ops_api
from .api import postmortem as pm_api
from .api import repo as repo_api
from .api import repo_ui as repo_ui_api
from .api import remediation as remediation_api
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
PAGE_SIZE = 10  # table pagination (user request: max 10 rows per page)


def _now_utc():
    from datetime import UTC, datetime

    return datetime.now(UTC)


def _repo_summary(db, app_row) -> dict:
    """Repo info for the app-page template (linked URL/branch/commits)."""
    from .models import Commit, Repository

    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        return {"linked": False}
    commits = db.scalars(
        select(Commit)
        .where(Commit.repository_id == repo.id)
        .order_by(Commit.committed_at.desc().nullslast())
        .limit(8)
    ).all()
    return {
        "linked": True,
        "url": repo.url,
        "branch": repo.default_branch,
        "token_configured": bool(repo.token_ref),
        "recent_commits": [
            {"sha": c.sha[:8], "author": c.author, "message": (c.message or "")[:90],
             "date": c.committed_at.isoformat() if c.committed_at else None}
            for c in commits
        ],
    }


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
        from .migrations import ensure_schema

        ensure_schema(engine)
        _ensure_bootstrap_admin()
        task = asyncio.create_task(sweeper.sweep_loop())
        yield
        task.cancel()

    app = FastAPI(title=settings.app_name, version=settings.version, lifespan=lifespan)
    templates = Jinja2Templates(directory=str(BASE_DIR / "ui" / "templates"))
    templates.env.globals["now_utc"] = _now_utc

    def _u(path: str) -> str:
        """Prefix an app-relative path with the public mount prefix (/sre)."""
        prefix = (settings.url_prefix or "").rstrip("/")
        return f"{prefix}{path}" if prefix else path

    templates.env.globals["u"] = _u
    app.include_router(apps_api.router)
    app.include_router(agent_api.router)
    app.include_router(ask_api.router)
    app.include_router(m11_api.router)
    app.include_router(ops_api.router)
    app.include_router(pm_api.router)
    app.include_router(repo_api.router)
    app.include_router(repo_ui_api.router)
    app.include_router(remediation_api.router)

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
        # Quick reminders (SLO breach / recurring error) — highest signal of the M11 features
        from .quickreminders import active_quick_findings

        for app_row in apps:
            if not app_row.confirmed:
                continue
            for finding in active_quick_findings(db, app_row.id):
                kind = "SLO breach" if (finding.rule_key or "").startswith("slo_breach") else "error berulang"
                actions.append({
                    "level": "warning" if finding.severity.value != "critical" else "critical",
                    "text": f"{app_row.name}: {kind} — {finding.title}",
                    "href": f"/applications/{app_row.slug}",
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
                "nav": "overview",
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
    def discovery(request: Request, db: Session = Depends(get_db), page: int = 1):
        page = max(1, page)
        all_apps = db.scalars(
            select(Application).where(Application.confirmed == True)  # noqa: E712
            .order_by(Application.name)
        ).all()
        total = len(all_apps)
        pages = max(1, -(-total // PAGE_SIZE))
        page = min(page, pages)
        start = (page - 1) * PAGE_SIZE

        def _page_url(p: int) -> str:
            return f"{_u('/discovery')}?page={p}"

        candidates = db.scalars(
            select(Application).where(Application.confirmed == False)  # noqa: E712
            .order_by(Application.name)
        ).all()
        return templates.TemplateResponse(
            request,
            "discovery.html",
            {
                "settings": settings,
                "nav": "discovery",
                "candidates": candidates,
                "servers": db.scalars(select(Server)).all(),
                "apps": all_apps[start : start + PAGE_SIZE],
                "apps_total": total,
                "nav_pages": {"page": page, "pages": pages,
                              "prev_url": _page_url(page - 1) if page > 1 else None,
                              "next_url": _page_url(page + 1) if page < pages else None},
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
        return RedirectResponse(_u("/discovery"), status_code=303)

    @app.get("/activity", response_class=HTMLResponse)
    def activity_fragment(request: Request, db: Session = Depends(get_db)):
        """Polled fragment: live activity feed (near-realtime UI, §12)."""
        recent_events = db.scalars(
            select(TimelineEvent).order_by(TimelineEvent.ts.desc()).limit(12)
        ).all()
        return templates.TemplateResponse(
            request,
            "_activity_live.html",
            {"settings": settings, "recent_events": recent_events},
        )

    @app.get("/topology", response_class=HTMLResponse)
    def topology_page(request: Request, db: Session = Depends(get_db)):
        """Service/dependency topology (spec §10)."""
        from .deps import topology_for_apps

        topo = topology_for_apps(db)
        return templates.TemplateResponse(
            request,
            "topology.html",
            {
                "settings": settings,
                "nav": "topology",
                "nodes": topo["nodes"],
                "edges": topo["edges"],
                "app_names": topo["app_names"],
            },
        )

    @app.get("/applications/{slug}/metrics", response_class=HTMLResponse)
    def metrics_fragment(slug: str, request: Request, db: Session = Depends(get_db)):
        """Polled fragment: RED cards + sparkline (near-realtime, §7/§9)."""
        from .metrics import latest_points

        app_row = db.scalar(select(Application).where(Application.slug == slug))
        if app_row is None:
            return HTMLResponse('<p class="muted">application not found</p>', status_code=404)
        points = latest_points(db, app_row.id, limit=48)
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
            "_metrics_live.html",
            {
                "settings": settings,
                "app": app_row,
                "latest": points[0] if points else None,
                "server_point": server_point,
                "points": list(reversed(points)),
            },
        )

    @app.get("/applications/{slug}/reminders", response_class=HTMLResponse)
    def reminders_fragment(slug: str, request: Request, db: Session = Depends(get_db)):
        """Polled fragment: pinned quick reminders (M11)."""
        from .quickreminders import active_quick_findings

        app_row = db.scalar(select(Application).where(Application.slug == slug))
        if app_row is None:
            return HTMLResponse('<p class="muted">application not found</p>', status_code=404)
        return templates.TemplateResponse(
            request,
            "_reminders_live.html",
            {"settings": settings, "app": app_row,
             "quick_reminders": active_quick_findings(db, app_row.id)},
        )

    @app.get("/applications/{slug}/perf-test", response_class=HTMLResponse)
    def perf_test_fragment(slug: str, request: Request, db: Session = Depends(get_db)):
        """Polled fragment: perf test state + live metrics during the window (M11)."""
        from .quickreport import perf_test_state

        app_row = db.scalar(select(Application).where(Application.slug == slug))
        if app_row is None:
            return HTMLResponse('<p class="muted">application not found</p>', status_code=404)
        running, latest_done = perf_test_state(db, app_row.id)
        return templates.TemplateResponse(
            request,
            "_perf_test.html",
            {"settings": settings, "app": app_row,
             "running_test": running, "latest_test": latest_done},
        )

    @app.get("/applications/{slug}/logs", response_class=HTMLResponse)
    def logs_fragment(
        slug: str, request: Request, db: Session = Depends(get_db), page: int = 1
    ):
        """Polled fragment: realtime log batches (M11) + pagination."""
        from .logstore import window_error_counts
        from .models import LogBatch

        app_row = db.scalar(select(Application).where(Application.slug == slug))
        if app_row is None:
            return HTMLResponse('<p class="muted">application not found</p>', status_code=404)
        all_logs = db.scalars(
            select(LogBatch)
            .where(LogBatch.application_id == app_row.id)
            .order_by(LogBatch.ts_end.desc())
        ).all()
        page = max(1, page)
        pages = max(1, -(-len(all_logs) // PAGE_SIZE))
        page = min(page, pages)
        start = (page - 1) * PAGE_SIZE
        logs = all_logs[start : start + PAGE_SIZE]

        def _url(p: int) -> str:
            return f"{_u('/applications')}/{slug}/logs?page={p}"

        return templates.TemplateResponse(
            request,
            "_logs_live.html",
            {"settings": settings, "app": app_row, "logs": logs,
             "log_counts": window_error_counts(db, app_row.id, minutes=60),
             "nav_pages": {"page": page, "pages": pages,
                           "prev_url": _url(page - 1) if page > 1 else None,
                           "next_url": _url(page + 1) if page < pages else None}},
        )

    @app.get("/applications/{slug}", response_class=HTMLResponse)
    def application_detail(
        slug: str, request: Request, db: Session = Depends(get_db),
        fpage: int = 1, tpage: int = 1,
    ):
        from .logstore import window_error_counts
        from .metrics import latest_points
        from .models import LogBatch, Postmortem, Repository, SLO
        from .models import Deployment
        from .dora import dora_for_app
        from .postmortem import budget_context_for_recommendations, slo_summary_for_app
        from .quickreminders import active_quick_findings
        from .quickreport import latest_report, perf_test_state

        def _paged(query_rows, page: int):
            page = max(1, page)
            pages = max(1, -(-len(query_rows) // PAGE_SIZE))
            page = min(page, pages)
            start = (page - 1) * PAGE_SIZE

            def _url(p: int) -> str:
                return f"{_u('/applications')}/{slug}?fpage={fpage}&tpage={tpage}".split("?")[0] + \
                    f"?fpage={fpage if p is None else p}&tpage={tpage}"

            return query_rows[start : start + PAGE_SIZE], {
                "page": page, "pages": pages,
                "prev_url": _url(page - 1) if page > 1 else None,
                "next_url": _url(page + 1) if page < pages else None,
            }

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
        running_test, latest_test = perf_test_state(db, app_row.id)
        report = latest_report(db, app_row.id)
        all_findings = db.scalars(
            select(Finding)
            .where(Finding.application_id == app_row.id)
            .order_by(Finding.last_seen.desc())
        ).all()
        findings, findings_pages = _paged(all_findings, fpage)
        all_timeline = db.scalars(
            select(TimelineEvent)
            .where(TimelineEvent.application_id == app_row.id)
            .order_by(TimelineEvent.ts.desc())
        ).all()
        timeline, timeline_pages = _paged(all_timeline, tpage)

        def _fp_url(p: int) -> str:
            return f"{_u('/applications')}/{slug}?fpage={p}&tpage={timeline_pages['page']}"

        def _tp_url(p: int) -> str:
            return f"{_u('/applications')}/{slug}?fpage={findings_pages['page']}&tpage={p}"

        findings_pages.update(prev_url=_fp_url(findings_pages["page"] - 1) if findings_pages["page"] > 1 else None,
                              next_url=_fp_url(findings_pages["page"] + 1) if findings_pages["page"] < findings_pages["pages"] else None)
        timeline_pages.update(prev_url=_tp_url(timeline_pages["page"] - 1) if timeline_pages["page"] > 1 else None,
                              next_url=_tp_url(timeline_pages["page"] + 1) if timeline_pages["page"] < timeline_pages["pages"] else None)
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
                "repo_info": _repo_summary(db, app_row),
                "quick_reminders": active_quick_findings(db, app_row.id),
                "running_test": running_test,
                "latest_test": latest_test,
                "report": report,
                "findings_pages": findings_pages,
                "timeline_pages": timeline_pages,
                "postmortems": db.scalars(
                    select(Postmortem)
                    .where(Postmortem.incident_id.in_(
                        select(Incident.id).where(Incident.application_id == app_row.id)
                    ))
                    .order_by(Postmortem.created_at.desc())
                    .limit(10)
                ).all(),
                "findings": findings,
                "deployments": db.scalars(
                    select(Deployment)
                    .where(Deployment.application_id == app_row.id)
                    .order_by(Deployment.deployed_at.desc())
                    .limit(10)
                ).all(),
                "dora": dora_for_app(db, app_row.id, days=30),
                "incidents": db.scalars(
                    select(Incident)
                    .where(Incident.application_id == app_row.id)
                    .order_by(Incident.detected_at.desc())
                    .limit(10)
                ).all(),
                "timeline": timeline,
            },
        )

    return app


app = create_app()
