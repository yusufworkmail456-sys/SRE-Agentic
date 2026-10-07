"""CI status watch (spec §16): GitHub Actions runs per repo/PR -> deployment.ci_state.

Polls the GitHub REST API (no webhook infra needed for MVP). Runs on the sweep
cadence for repos whose latest PR/deployment has a pending CI state.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .gitprov import _GIT_URL_RE, _token_for, github_api
from .models import Application, Deployment, Repository, TimelineEvent

log = logging.getLogger("sre-platform.ci")

_STATE_MAP = {
    "success": "success",
    "failure": "failure",
    "neutral": "success",
    "cancelled": "failure",
    "timed_out": "failure",
    "action_required": "pending",
    "requested": "pending",
    "queued": "pending",
    "in_progress": "pending",
    "waiting": "pending",
    "pending": "pending",
}


def _slug_of(repo: Repository) -> str | None:
    m = _GIT_URL_RE.match(repo.url.strip())
    if not m:
        return None
    return m.group(1).removeprefix("https://github.com/")


def watch_repo_ci(db: Session, repo: Repository) -> dict:
    """Latest workflow run on the default branch -> ci_state for newest deployment."""
    slug = _slug_of(repo)
    if slug is None:
        return {"ok": False, "reason": "not a github repo"}
    token = _token_for(db, repo)
    runs = github_api(
        f"/repos/{slug}/actions/runs?branch={repo.default_branch}&per_page=3", token=token
    )
    if not runs or not runs.get("workflow_runs"):
        return {"ok": False, "reason": "no runs visible (private repo without token?)"}
    run = runs["workflow_runs"][0]
    state = _STATE_MAP.get(run.get("status") if run.get("status") != "completed" else
                           run.get("conclusion"), "unknown")
    deployment = db.scalars(
        select(Deployment)
        .where(Deployment.repository_id == repo.id)
        .order_by(Deployment.deployed_at.desc())
        .limit(1)
    ).first()
    changed = False
    if deployment is not None and deployment.ci_state != state:
        deployment.ci_state = state
        deployment.ci_url = run.get("html_url")
        changed = True
        app_row = db.get(Application, deployment.application_id)
        db.add(
            TimelineEvent(
                application_id=deployment.application_id,
                kind="deployment",
                actor="system",
                summary=f"CI {state} for {repo.default_branch} ({(run.get('name') or 'workflow')[:60]})",
            )
        )
    return {"ok": True, "state": state, "changed": changed, "run_url": run.get("html_url")}


def watch_all(db: Session) -> int:
    """Sweep entry: check CI for repos with a pending/unknown deployment CI state."""
    checked = 0
    repos = db.scalars(select(Repository)).all()
    for repo in repos:
        deployment = db.scalars(
            select(Deployment)
            .where(Deployment.repository_id == repo.id)
            .order_by(Deployment.deployed_at.desc())
            .limit(1)
        ).first()
        # Only poll when there is something unresolved — keeps API usage tiny.
        if deployment is None or deployment.ci_state in ("success", "failure"):
            continue
        try:
            watch_repo_ci(db, repo)
            checked += 1
        except Exception as exc:
            log.warning("ci watch failed for repo %s: %s", repo.id, exc)
    return checked
