"""M7 tests: git provider read paths + repo linking + agent repo awareness."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sre_platform import git_tools
from sre_platform.app import create_app, _repo_summary
from sre_platform.db import SessionLocal, engine
from sre_platform.gitprov import normalize_url
from sre_platform.models import (
    AppStatus,
    Application,
    Base,
    Repository,
    Server,
)

TOKEN = "sreag_m7_token"


@pytest.fixture(autouse=True)
def db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture()
def client():
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture(scope="module")
def local_repo(tmp_path_factory):
    """Build a real tiny git repo on disk to exercise the git adapter."""
    path = tmp_path_factory.mktemp("repo")
    work = path / "work"
    work.mkdir()
    def git(*args):
        subprocess.run(["git", *args], cwd=work, check=True, capture_output=True)
    git("init", "-b", "main")
    (work / "README.md").write_text("# demo app\n")
    (work / "app.py").write_text("print('hello')\n")
    (work / "requirements.txt").write_text("fastapi\n")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "initial commit")
    (work / "pkg").mkdir()
    (work / "pkg" / "mod.py").write_text("x = 1\n")
    git("add", "-A")
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-m", "add pkg module")
    return work


def _app(db, slug="app7") -> Application:
    server = Server(hostname=f"vm7-{slug}")
    db.add(server)
    db.flush()
    app_row = Application(name="App7", slug=slug, server_id=server.id, confirmed=True,
                          status=AppStatus.healthy)
    db.add(app_row)
    db.commit()
    return app_row


def test_normalize_url():
    assert normalize_url("https://github.com/u/r") == "https://github.com/u/r.git"
    assert normalize_url("https://github.com/u/r.git") == "https://github.com/u/r.git"
    assert normalize_url("https://github.com/u/r/") == "https://github.com/u/r.git"
    assert normalize_url("ftp://bad") is None
    assert normalize_url("https://gitlab.com/u/r") is None


def test_gitprov_local_operations(db, local_repo):
    app_row = _app(db)
    # point Repository at a local path via gitprov file functions directly
    from sre_platform.gitprov import file_tree, read_file, recent_commits, grep_repo, diff_commit
    assert "README.md" in file_tree(local_repo, "main", depth=3)
    assert "print" in read_file(local_repo, "app.py", "main")
    commits = recent_commits(local_repo, "main", n=5)
    assert commits[0]["message"] == "add pkg module"
    matches = grep_repo(local_repo, "hello", "main")
    assert matches and matches[0]["file"].endswith("app.py")
    patch = diff_commit(local_repo, commits[1]["sha"])
    assert patch is not None and "app.py" in patch


def test_inspect_structure_action(db, local_repo):
    app_row = _app(db)
    # stub get_repo to use the local fixture repo
    original = git_tools.get_repo
    git_tools.get_repo = lambda db, app: (None, local_repo)
    try:
        result = git_tools.inspect(db, app_row, "structure")
    finally:
        git_tools.get_repo = original
    assert result["ok"] is True
    assert "requirements.txt" in result["manifests"]
    assert result["recent_commits"][0]["message"] == "add pkg module"


def test_inspect_no_repo(db):
    app_row = _app(db, "app7b")
    result = git_tools.inspect(db, app_row, "structure")
    assert result["ok"] is False
    assert "no repository" in result["reason"]


def test_repo_link_api_and_context(db, client, local_repo, monkeypatch):
    app_row = _app(db, "app7c")
    # normalize_url rejects local paths, so link via direct model for the context test
    db.add(Repository(application_id=app_row.id, url="https://github.com/u/demo.git",
                      default_branch="main"))
    db.commit()
    original = git_tools.get_repo
    git_tools.get_repo = lambda db, app: (db.query(Repository).first(), local_repo)
    try:
        from sre_platform.askagent import build_context
        ctx = build_context(db, app_row)
        assert "repository" in ctx
        assert ctx["repository"]["ref"] == "repository:structure"
        assert any(c["ref"].startswith("commit:") for c in ctx["repository"]["recent_commits"])
    finally:
        git_tools.get_repo = original


def test_repo_link_api_rejects_bad_url(client, db):
    _app(db, "app7d")
    resp = client.post("/api/apps/app7d/repo", json={"url": "https://gitlab.com/x/y"})
    assert resp.status_code == 422


def test_repo_summary_for_ui(db):
    app_row = _app(db, "app7e")
    assert _repo_summary(db, app_row) == {"linked": False}
    db.add(Repository(application_id=app_row.id, url="https://github.com/u/r.git"))
    db.commit()
    summary = _repo_summary(db, app_row)
    assert summary["linked"] is True
    assert summary["url"].endswith(".git")


def test_repo_ui_link_htmx(client, db, tmp_path):
    """The HTMX link flow with a real local bare repo is covered by e2e; here we
    only assert the endpoint rejects invalid URLs without raising."""
    _app(db, "app7f")
    resp = client.post("/repo/app7f/link", data={"url": "not-a-url", "branch": "main"})
    assert resp.status_code == 200
    assert "valid" in resp.text.lower() or "bukan" in resp.text.lower()
