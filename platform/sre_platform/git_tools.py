"""Git-aware agent tools (spec §14/§15): repo inspection for investigation &
Ask Agent. Read-only; every call goes through AgentAction audit when used in
answering (wired in askagent.build_context / investigation).
"""
from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import gitprov
from .models import Application, Repository

log = logging.getLogger("sre-platform.git-tools")


def get_repo(db: Session, app_row: Application) -> tuple[Repository, Path] | None:
    """Return (repository_row, local_path) or None when app has no repo."""
    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        return None
    path = gitprov.clone_or_fetch(db, repo)
    if path is None:
        return None
    return repo, path


def inspect(db: Session, app_row: Application, action: str, **kwargs) -> dict:
    """Dispatch read-only git inspection. action in:
    tree | file | log | diff | grep | structure"""
    got = get_repo(db, app_row)
    if got is None:
        return {"ok": False, "reason": "no repository linked to this application"}
    repo, path = got
    branch = kwargs.get("branch") or (repo.default_branch if repo is not None else None) or "HEAD"
    try:
        if action == "tree":
            items = gitprov.file_tree(path, branch, depth=kwargs.get("depth", 2))
            return {"ok": True, "branch": branch, "entries": items[:200]}
        if action == "file":
            content = gitprov.read_file(path, kwargs["path"], branch)
            return {"ok": content is not None, "path": kwargs["path"], "content": content}
        if action == "log":
            return {"ok": True, "commits": gitprov.recent_commits(path, branch, kwargs.get("n", 15))}
        if action == "diff":
            patch = gitprov.diff_commit(path, kwargs["sha"])
            return {"ok": patch is not None, "sha": kwargs["sha"], "patch": patch}
        if action == "grep":
            return {"ok": True, "matches": gitprov.grep_repo(path, kwargs["pattern"], branch)}
        if action == "structure":
            """Curated repo summary for LLM context: manifests + tree + recent log."""
            tree = gitprov.file_tree(path, branch, depth=3)
            interesting = [
                p for p in tree
                if p.split("/")[-1] in {
                    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
                    "package.json", "requirements.txt", "pyproject.toml", "pom.xml",
                    "go.mod", "Makefile", "README.md",
                }
                or ".github/workflows" in p
            ]
            files = {}
            for name in interesting[:6]:
                content = gitprov.read_file(path, name, branch, max_bytes=4000)
                if content:
                    files[name] = content
            return {
                "ok": True,
                "branch": branch,
                "tree_top": tree[:120],
                "manifests": files,
                "recent_commits": gitprov.recent_commits(path, branch, n=10),
            }
    except Exception as exc:  # git failures must never break answering
        log.warning("git inspect %s failed: %s", action, exc)
        return {"ok": False, "reason": str(exc)[:200]}
    return {"ok": False, "reason": f"unknown action {action}"}
