"""Repository API: link repo, inspect (read-only), sync commits (M7)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..git_tools import inspect as git_inspect
from ..gitprov import clone_or_fetch, normalize_url, sync_commits
from ..models import Application, Commit, Repository
from ..security import encrypt_secret

router = APIRouter(prefix="/api", tags=["repo"])


def _get_app(db: Session, slug: str) -> Application:
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    return app_row


class RepoLinkRequest(BaseModel):
    url: str
    branch: str = "main"
    token: str | None = Field(default=None, description="optional PAT; stored encrypted; empty = server credential")


@router.post("/apps/{slug}/repo", status_code=201)
def link_repo(slug: str, req: RepoLinkRequest, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    normalized = normalize_url(req.url)
    if normalized is None:
        raise HTTPException(422, "not a GitHub https URL")
    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        repo = Repository(application_id=app_row.id, provider="github")
        db.add(repo)
    repo.url = normalized
    repo.default_branch = req.branch or "main"
    if req.token:
        from ..config import settings

        repo.token_ref = encrypt_secret(req.token, settings.secret_key)
    db.commit()
    path = clone_or_fetch(db, repo)
    db.commit()
    stored = sync_commits(db, repo, path) if path else 0
    db.commit()
    return {"ok": path is not None, "url": normalized, "branch": repo.default_branch,
            "commits_indexed": stored}


@router.get("/apps/{slug}/repo")
def repo_info(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        return {"linked": False}
    commits = db.scalars(
        select(Commit)
        .where(Commit.repository_id == repo.id)
        .order_by(Commit.committed_at.desc().nullslast())
        .limit(10)
    ).all()
    return {
        "linked": True,
        "url": repo.url,
        "branch": repo.default_branch,
        "last_indexed_at": repo.last_indexed_at.isoformat() if repo.last_indexed_at else None,
        "token_configured": bool(repo.token_ref),
        "recent_commits": [
            {"sha": c.sha[:8], "author": c.author, "message": (c.message or "")[:100],
             "date": c.committed_at.isoformat() if c.committed_at else None}
            for c in commits
        ],
    }


class InspectRequest(BaseModel):
    action: str = "structure"   # structure|tree|file|log|diff|grep
    path: str | None = None
    pattern: str | None = None
    sha: str | None = None
    branch: str | None = None
    depth: int = 2


@router.post("/apps/{slug}/repo/inspect")
def inspect_repo(slug: str, req: InspectRequest, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    result = git_inspect(
        db, app_row, req.action,
        path=req.path, pattern=req.pattern, sha=req.sha,
        branch=req.branch, depth=req.depth,
    )
    return result
