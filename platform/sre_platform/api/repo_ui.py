"""HTMX endpoints for the Repository panel (link + sync)."""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..gitprov import clone_or_fetch, normalize_url, sync_commits
from ..models import Application, Repository
from ..security import encrypt_secret

router = APIRouter(prefix="/repo", tags=["repo-ui"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parents[1] / "ui" / "templates"))


@router.post("/{slug}/link", response_class=HTMLResponse)
def link_repo(slug: str, request: Request, db: Session = Depends(get_db),
              url: str = Form(""), branch: str = Form("main")):
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None or not url.strip():
        return HTMLResponse('<span class="err">invalid input</span>')
    normalized = normalize_url(url)
    if normalized is None:
        return HTMLResponse('<span class="err">bukan GitHub https URL yang valid</span>')
    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        repo = Repository(application_id=app_row.id, provider="github")
        db.add(repo)
    repo.url = normalized
    repo.default_branch = branch or "main"
    db.commit()
    path = clone_or_fetch(db, repo)
    stored = sync_commits(db, repo, path) if path else 0
    db.commit()
    return HTMLResponse(
        f'<span class="ok-text">Linked {normalized} — {stored} commit ter-index. Refresh halaman.</span>'
    )


@router.post("/{slug}/sync", response_class=HTMLResponse)
def sync_repo(slug: str, db: Session = Depends(get_db)):
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        return HTMLResponse('<span class="err">app not found</span>')
    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        return HTMLResponse('<span class="err">no repo linked</span>')
    path = clone_or_fetch(db, repo)
    stored = sync_commits(db, repo, path) if path else 0
    db.commit()
    return HTMLResponse(f'<span class="ok-text">synced: +{stored} commit</span>')
