"""GitHub adapter — read-only repo awareness (spec §15 Knowledge, §26 GitProvider).

Design:
- Per-app encrypted token (Fernet via SRE_SECRET_KEY) or the server-level
  credential in /root/.git-credentials as fallback — never stored in plaintext.
- Bare mirror clone under DATA_DIR/repos/<slug>.git, refreshed by fetch —
  fast local log/diff/grep, no API rate limits for read paths.
- Write path (branch/commit/push/PR) is Phase-2-later and gated by AgentAction
  approval; this module exposes inspect-only helpers today.
"""
from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from .config import settings
from .models import Application, Commit, Repository
from .security import decrypt_secret

log = logging.getLogger("sre-platform.git")

_GIT_URL_RE = re.compile(r"^(https://github\.com/[\w.\-]+/[\w.\-]+?)(?:\.git)?/?$")


def _token_for(db: Session, repo: Repository) -> str | None:
    if repo.token_ref:
        try:
            return decrypt_secret(repo.token_ref, settings.secret_key)
        except ValueError:
            log.warning("repo %s token undecryptable", repo.id)
    # Server-level fallback credential (this VM pushes to GitHub with it).
    creds = Path("/root/.git-credentials")
    if creds.exists():
        for line in creds.read_text().splitlines():
            m = re.match(r"https://x-access-token:([^@]+)@github\.com", line.strip())
            if m:
                return m.group(1)
    return None


def normalize_url(url: str) -> str | None:
    m = _GIT_URL_RE.match(url.strip())
    return m.group(1) + ".git" if m else None


def repos_dir() -> Path:
    path = Path(settings.data_dir) / "repos"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _run_git(args: list[str], cwd: Path | None = None, timeout: int = 60) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None,
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    return proc.returncode, (proc.stdout or proc.stderr or "").strip()


def clone_or_fetch(db: Session, repo: Repository) -> Path | None:
    """Bare clone once, then `fetch --all` on later calls. Returns repo path."""
    url = normalize_url(repo.url)
    if not url:
        return None
    token = _token_for(db, repo)
    if token:
        url = url.replace("https://", f"https://x-access-token:{token}@", 1)
    path = repos_dir() / f"{repo.application_id}.git"
    if not (path / "HEAD").exists():
        # No --filter=blob:none: a partial mirror breaks local worktree clones in
        # gitwrite (blobs are missing and lazily fetched from origin). Repos here
        # are small; correctness beats clone size.
        rc, out = _run_git(["clone", "--bare", url, str(path)], timeout=180)
        if rc != 0:
            log.warning("clone failed for app %s: %s", repo.application_id, out[:200])
            return None
    else:
        rc, out = _run_git(["fetch", "--all", "--prune"], cwd=path, timeout=120)
        if rc != 0:
            log.warning("fetch failed for app %s: %s", repo.application_id, out[:200])
            # stale copy is still usable for inspection
    return path


# ------------------------------------------------------------------ inspection
def file_tree(repo_path: Path, branch: str | None = None, depth: int = 2) -> list[str]:
    rc, out = _run_git(
        ["ls-tree", "-r", "--name-only", branch or "HEAD"], cwd=repo_path
    )
    if rc != 0:
        return []
    lines = out.splitlines()
    if depth:
        shown = {"/".join(line.split("/")[:depth]) for line in lines}
        return sorted(shown)[:500]
    return lines[:1000]


def read_file(repo_path: Path, path: str, branch: str | None = None, max_bytes: int = 100_000) -> str | None:
    rc, out = _run_git(["show", f"{branch or 'HEAD'}:{path}"], cwd=repo_path)
    if rc != 0:
        return None
    return out[:max_bytes]


def recent_commits(repo_path: Path, branch: str | None = None, n: int = 20) -> list[dict]:
    rc, out = _run_git(
        ["log", f"-{n}", "--pretty=format:%H%x1f%an%x1f%aI%x1f%s", branch or "HEAD"],
        cwd=repo_path,
    )
    if rc != 0:
        return []
    commits = []
    for line in out.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 4:
            commits.append({"sha": parts[0], "author": parts[1], "date": parts[2], "message": parts[3]})
    return commits


def diff_commit(repo_path: Path, sha: str) -> str | None:
    rc, out = _run_git(["show", "--stat", "--patch", "--format=", sha, "-m"], cwd=repo_path, timeout=30)
    return out[:50_000] if rc == 0 else None


def grep_repo(repo_path: Path, pattern: str, branch: str | None = None, max_results: int = 30) -> list[dict]:
    ref = branch or "HEAD"
    rc, out = _run_git(
        ["grep", "-n", "-I", "-E", pattern, ref, "--", "."],
        cwd=repo_path, timeout=30,
    )
    if rc != 0:
        return []
    results = []
    prefix = f"{ref}:"
    for line in out.splitlines()[:max_results]:
        # format: "<ref>:<path>:<lineno>:<text>"
        body = line[len(prefix):] if line.startswith(prefix) else line
        parts = body.split(":", 2)
        if len(parts) == 3:
            results.append({"file": parts[0], "line": parts[1], "text": parts[2][:200]})
    return results


# ------------------------------------------------------------------ sync to DB
def sync_commits(db: Session, repo: Repository, repo_path: Path) -> int:
    from datetime import datetime

    stored = 0
    for c in recent_commits(repo_path, repo.default_branch, n=30):
        exists = db.query(Commit).filter_by(repository_id=repo.id, sha=c["sha"]).first()
        if exists:
            continue
        try:
            committed = datetime.fromisoformat(c["date"])
        except ValueError:
            committed = None
        db.add(
            Commit(
                repository_id=repo.id, sha=c["sha"], author=c["author"],
                message=c["message"][:500], committed_at=committed,
            )
        )
        stored += 1
    from datetime import UTC

    repo.last_indexed_at = datetime.now(UTC)
    return stored


def github_api(path: str, token: str | None = None) -> dict | None:
    """Small REST helper for CI status / PR watch (Phase 2 write path)."""
    import httpx

    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = httpx.get(f"https://api.github.com{path}", headers=headers, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("github api %s failed: %s", path, exc)
        return None
