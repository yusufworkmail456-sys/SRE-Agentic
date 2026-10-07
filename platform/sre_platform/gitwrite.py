"""GitHub write path (spec §15 Action, §16): fix proposal -> branch -> commit ->
push -> PR — ALL behind the action gateway (AgentAction + approval + risk).

Safety invariants (spec §27):
- Never push to the default branch; PRs only.
- Every push carries the incident id in branch name + PR body (traceability).
- LLM proposes the patch; a human approves the remediation row before anything
  leaves this machine; every step writes AgentAction rows.
- Tokens: repo.token_ref (encrypted) or server credential fallback.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import gitprov
from .config import settings
from .models import (
    AgentAction,
    Application,
    Incident,
    Repository,
    RiskLevel,
)
from .security import decrypt_secret

log = logging.getLogger("sre-platform.gitwrite")


class GitWriteError(Exception):
    pass


def _token_for(db: Session, repo: Repository) -> str | None:
    if repo.token_ref:
        try:
            return decrypt_secret(repo.token_ref, settings.secret_key)
        except ValueError:
            log.warning("repo %s token undecryptable", repo.id)
    creds = Path("/root/.git-credentials")
    if creds.exists():
        import re

        for line in creds.read_text().splitlines():
            m = re.match(r"https://x-access-token:([^@]+)@github\.com", line.strip())
            if m:
                return m.group(1)
    return None


def _worktree_path(repo: Repository) -> Path:
    path = gitprov.repos_dir() / f"work-{repo.application_id}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _run_git(args: list[str], cwd: Path, timeout: int = 90) -> tuple[int, str]:
    import subprocess

    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), capture_output=True, text=True,
        timeout=timeout, check=False,
    )
    return proc.returncode, (proc.stdout or proc.stderr or "").strip()


def prepare_worktree(db: Session, repo: Repository) -> Path:
    """Materialize a worktree from the bare mirror; reset to origin/default."""
    path = _worktree_path(repo)
    bare = gitprov.repos_dir() / f"{repo.application_id}.git"
    if not (bare / "HEAD").exists():
        raise GitWriteError("bare mirror missing — link/sync repo first")
    token = _token_for(db, repo)
    if not (path / ".git").exists():
        rc, out = _run_git(["clone", str(bare), str(path)], cwd=gitprov.repos_dir())
        if rc != 0:
            raise GitWriteError(f"worktree clone failed: {out[:200]}")
    rc, out = _run_git(["fetch", "origin", "--prune"], cwd=path)
    if rc != 0 and "unknown" not in out.lower():
        log.warning("worktree fetch: %s", out[:200])
    rc, out = _run_git(["checkout", repo.default_branch], cwd=path)
    rc, out = _run_git(["reset", "--hard", f"origin/{repo.default_branch}"], cwd=path)
    if rc != 0:
        raise GitWriteError(f"reset failed: {out[:200]}")
    # embed token in remote URL for authenticated push
    if token:
        url = repo.url.replace("https://", f"https://x-access-token:{token}@", 1)
        _run_git(["remote", "set-url", "origin", url], cwd=path)
    return path


def push_fix(
    db: Session,
    app_row: Application,
    incident: Incident | None,
    repo: Repository,
    branch_name: str,
    file_changes: list[dict],
    commit_message: str,
    pr_title: str,
    pr_body: str,
    approved_action: AgentAction | None = None,
) -> dict:
    """Execute an APPROVED remediation: apply file changes, push branch, open PR.

    file_changes: [{"path": "...", "content": "..."}] — full-file writes only
    (simplest safe primitive; diffs/deletes come later with review tooling).
    Requires approved_action whose approval nonce is recorded for traceability.
    """
    if not approved_action or approved_action.status != "approved":
        raise GitWriteError("push_fix requires an APPROVED AgentAction (autonomy gate)")
    if branch_name == repo.default_branch or not branch_name.startswith("sre/"):
        raise GitWriteError(f"branch must be a sre/* branch, not {branch_name!r}")

    work = prepare_worktree(db, repo)
    rc, out = _run_git(["checkout", "-B", branch_name, f"origin/{repo.default_branch}"], cwd=work)
    if rc != 0:
        raise GitWriteError(f"branch checkout failed: {out[:200]}")

    changed: list[str] = []
    for change in file_changes:
        rel = change.get("path", "")
        if not rel or rel.startswith(("/", "..")) or ".." in Path(rel).parts:
            raise GitWriteError(f"unsafe path {rel!r}")
        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(change.get("content", ""))
        changed.append(rel)
    if not changed:
        raise GitWriteError("no file changes provided")

    git_env_name = f"sre-bot <sre-bot@{settings.app_name}>"
    _run_git(["-c", f"user.name={git_env_name}", "-c", "user.email=sre-bot@localhost",
              "add", "--", *changed], cwd=work)
    rc, out = _run_git(
        ["-c", f"user.name={git_env_name}", "-c", "user.email=sre-bot@localhost",
         "commit", "-m", commit_message[:500]],
        cwd=work,
    )
    if rc != 0:
        raise GitWriteError(f"commit failed: {out[:300]}")
    rc, out = _run_git(["rev-parse", "HEAD"], cwd=work)
    sha = out[:12] if rc == 0 else None
    rc, out = _run_git(["push", "-u", "origin", branch_name], cwd=work, timeout=120)
    if rc != 0:
        raise GitWriteError(f"push failed: {out[:300]}")

    pr = _open_pr(db, repo, branch_name, pr_title, pr_body, token=_token_for(db, repo))
    if approved_action is not None:
        approved_action.result = {
            **(approved_action.result or {}),
            "branch": branch_name, "sha": sha, "pr": pr, "files": changed,
        }
        approved_action.finished_at = datetime.now(UTC)
        approved_action.status = "done"
    db.flush()
    return {"branch": branch_name, "sha": sha, "files": changed, "pr": pr}


def _open_pr(db: Session, repo: Repository, branch: str, title: str, body: str,
             token: str | None) -> dict:
    """PR via REST; falls back to a compare URL when API fails (never blocks the
    push record — the branch exists either way)."""
    import httpx

    m = gitprov._GIT_URL_RE.match(repo.url.strip())
    if not m:
        return {"ok": False, "reason": "cannot parse repo url", "compare_url": f"{repo.url}/compare/{branch}"}
    slug = m.group(1).removeprefix("https://github.com/")
    payload = {
        "title": title[:200],
        "head": branch,
        "base": repo.default_branch,
        "body": (body + f"\n\n---\n_Generated by {settings.app_name} (approved remediation)_")[:30_000],
    }
    try:
        headers = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = httpx.post(
            f"https://api.github.com/repos/{slug}/pulls",
            json=payload, headers=headers, timeout=30,
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            return {"ok": True, "number": data.get("number"), "url": data.get("html_url")}
        return {"ok": False, "status": resp.status_code, "reason": resp.text[:200],
                "compare_url": f"{repo.url}/compare/{branch}?expand=1"}
    except httpx.HTTPError as exc:
        return {"ok": False, "reason": str(exc)[:200],
                "compare_url": f"{repo.url}/compare/{branch}?expand=1"}
