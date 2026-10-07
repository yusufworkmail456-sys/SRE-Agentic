"""M9/M10 tests: docker fingerprints, container ingest, dependency probes,
CI watch (stubbed), deploy record + regression check, rollback staging, DORA,
capacity forecast, migrations."""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

HDR = {"X-Remote-User": "admin"}  # mirrors nginx basic-auth identity

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))

from sre_platform import ciwatch, deps, dora, deployer, forecast  # noqa: E402
from sre_platform.app import create_app  # noqa: E402
from sre_platform.db import SessionLocal, engine
from sre_platform.migrations import ensure_schema
from sre_platform.models import (
    AppStatus,
    Application,
    Base,
    Dependency,
    Deployment,
    HealthCheck,
    Incident,
    MetricPoint,
    Repository,
    Server,
)


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


def _app(db, slug="opsapp", confirmed=True) -> Application:
    server = Server(hostname=f"vm-ops-{slug}")
    db.add(server)
    db.flush()
    app_row = Application(
        name="OpsApp", slug=slug, server_id=server.id,
        confirmed=confirmed, status=AppStatus.healthy,
    )
    db.add(app_row)
    db.commit()
    return app_row


# ---------------------------------------------------------------- docker
def test_container_fingerprints_compose_grouping():
    from sre_agent.dockercol import Container, container_fingerprints

    containers = [
        Container(id="abc123def456", name="shop-web-1", image="shop/web:2",
                  state="running", status="Up 5m", compose_project="shop",
                  compose_service="web", ports=[8080]),
        Container(id="aaa111bbb222", name="shop-api-1", image="shop/api:2",
                  state="running", status="Up 5m", compose_project="shop",
                  compose_service="api", ports=[]),
        Container(id="ccc333ddd444", name="standalone", image="tools:1",
                  state="exited", status="Exited (0)", ports=[]),
    ]
    fps = container_fingerprints(containers)
    keys = {f["key"] for f in fps}
    assert keys == {"compose:shop", "docker:standalone"}
    shop = next(f for f in fps if f["key"] == "compose:shop")
    assert shop["kind"] == "container" and shop["source"] == "docker"
    assert len(shop["containers"]) == 2 and shop["ports"] == [8080]


def test_container_state_ingest_updates_liveness(db, client):
    app_row = _app(db, "opscont")
    from sre_platform.models import RuntimeInstance, Workload, WorkloadKind

    workload = Workload(application_id=app_row.id, kind=WorkloadKind.container,
                        name="shop", source="docker", external_id="shop")
    db.add(workload)
    db.flush()
    db.add(RuntimeInstance(workload_id=workload.id, container_id="abc123def456", alive=True))
    db.commit()

    from sre_platform.containerops import apply_container_states

    server = db.query(Server).first()
    result = apply_container_states(
        db, server,
        {"states": [{"id": "abc123def456", "name": "shop-web-1", "state": "exited"}],
         "metrics": []},
    )
    db.commit()
    assert result["updated"] >= 1
    inst = db.query(RuntimeInstance).filter_by(container_id="abc123def456").first()
    assert inst.alive is False


# ---------------------------------------------------------------- dependencies
def test_dependency_probe_down_creates_finding(db):
    from sre_platform.models import Finding

    app_row = _app(db, "opsdeps")
    db.add(Dependency(application_id=app_row.id, name="postgres", kind="db",
                      criticality="critical",
                      details={"host": "127.0.0.1", "port": 59999}))
    db.commit()
    probed = deps.probe_all_for_app(db, app_row)
    db.commit()
    assert probed == 1
    findings = db.query(Finding).filter_by(
        application_id=app_row.id, rule_key="dep_down:1").all()
    assert findings and findings[0].severity.value == "critical"


def test_dependency_api_and_topology(db, client):
    a1 = _app(db, "topoa")
    a2 = _app(db, "topob")
    resp = client.post("/api/apps/topoa/dependencies", headers=HDR, json={
        "name": "auth", "kind": "service", "criticality": "high", "target_slug": "topob",
    })
    assert resp.status_code == 201
    resp = client.get("/api/topology")
    data = resp.json()
    assert {n["slug"] for n in data["nodes"]} >= {"topoa", "topob"}
    edge = next(e for e in data["edges"] if e["name"] == "auth")
    assert edge["to"] == a2.id and edge["external"] is False


# ---------------------------------------------------------------- CI watch
def test_ci_watch_maps_state(db, client, monkeypatch):
    app_row = _app(db, "opsci")
    repo = Repository(application_id=app_row.id, url="https://github.com/u/r.git")
    db.add(repo)
    db.flush()
    db.add(Deployment(application_id=app_row.id, repository_id=repo.id,
                      sha="abc", branch="main", deployed_at=datetime.now(UTC)))
    db.commit()

    from sre_platform.gitprov import _token_for as orig_token  # noqa: F401

    monkeypatch.setattr(ciwatch, "github_api", lambda path, token=None: {
        "workflow_runs": [{
            "status": "completed", "conclusion": "failure",
            "name": "CI", "html_url": "https://github.com/u/r/actions/runs/1",
        }]
    })
    result = ciwatch.watch_repo_ci(db, repo)
    db.commit()
    assert result["ok"] and result["state"] == "failure" and result["changed"]
    deployment = db.query(Deployment).first()
    assert deployment.ci_state == "failure"
    assert deployment.ci_url.endswith("/1")


# ---------------------------------------------------------------- deploy/regression
def test_deploy_record_and_regression(db):
    app_row = _app(db, "opsdep")
    now = datetime.now(UTC)
    # healthy baseline before deploy
    for i in range(3):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=10 - i),
                           err_rate=0.01, p95_ms=200))
    db.add(Deployment(application_id=app_row.id, sha="deadbeef", branch="main",
                      deployed_at=now, before_snapshot={"err_rate_avg": 0.01, "p95_avg_ms": 200}))
    db.commit()
    # degraded after
    for i in range(4):
        db.add(MetricPoint(application_id=app_row.id, ts=now + timedelta(minutes=2 + i * 3),
                           err_rate=0.12, p95_ms=210))
    db.commit()
    deployment = db.query(Deployment).first()
    result = deployer.regression_check(db, deployment)
    db.commit()
    assert result["checked"] and result["regression"] is True
    assert deployment.regression is True and deployment.regression_checked is True


def test_no_regression_when_stable(db):
    app_row = _app(db, "opsdep2")
    now = datetime.now(UTC)
    for i in range(3):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=10 - i),
                           err_rate=0.01, p95_ms=200))
    db.add(Deployment(application_id=app_row.id, sha="cafe", branch="main",
                      deployed_at=now, before_snapshot={"err_rate_avg": 0.01, "p95_avg_ms": 200}))
    for i in range(4):
        db.add(MetricPoint(application_id=app_row.id, ts=now + timedelta(minutes=2 + i * 3),
                           err_rate=0.012, p95_ms=205))
    db.commit()
    deployment = db.query(Deployment).first()
    result = deployer.regression_check(db, deployment)
    assert result["regression"] is False


def test_rollback_stages_action(db, client):
    app_row = _app(db, "opsrb")
    db.add(Deployment(application_id=app_row.id, sha="f00d", branch="main",
                      deployed_at=datetime.now(UTC)))
    db.commit()
    dep_id = db.query(Deployment).first().id
    resp = client.post(f"/api/deployments/{dep_id}/rollback", headers=HDR)
    assert resp.status_code == 200
    assert resp.json()["queued"] is True
    rb = db.query(Deployment).filter(Deployment.rollback_of_id == dep_id).first()
    assert rb is not None and rb.method == "rollback"


# ---------------------------------------------------------------- DORA
def test_dora_aggregation(db):
    app_row = _app(db, "opsdora")
    now = datetime.now(UTC)
    db.add(Deployment(application_id=app_row.id, sha="a1", branch="main",
                      deployed_at=now - timedelta(days=2), regression=False))
    db.add(Deployment(application_id=app_row.id, sha="a2", branch="main",
                      deployed_at=now - timedelta(days=1), regression=True))
    db.add(Incident(application_id=app_row.id, title="x", resolved_at=now - timedelta(days=1),
                    detected_at=now - timedelta(days=1, minutes=-0) - timedelta(minutes=0),
                    mttr_s=1200))
    db.commit()
    stats = dora.dora_for_app(db, app_row.id, days=30)
    assert stats["deployments"] == 2
    assert stats["change_failure_rate"] == 0.5
    assert stats["mttr_avg_s"] == 1200.0


# ---------------------------------------------------------------- forecast
def test_disk_forecast_fires(db):
    app_row = _app(db, "opsfc")
    now = datetime.now(UTC)
    # climbing 0.5%/h for 48h (70% -> 94%), still under the 85% static gate at latest
    for h in range(48, 0, -1):
        db.add(MetricPoint(server_id=app_row.server_id, ts=now - timedelta(hours=h),
                           disk_pct=70 + (48 - h) * 0.5))
    db.commit()
    forecast.rule_capacity_forecast(db, app_row)
    db.commit()
    from sre_platform.models import Finding

    finding = db.query(Finding).filter_by(rule_key="disk_exhaustion_forecast").first()
    assert finding is not None
    assert "95%" in finding.title


def test_disk_forecast_quiet_when_flat(db):
    app_row = _app(db, "opsfc2")
    now = datetime.now(UTC)
    for h in range(48, 0, -1):
        db.add(MetricPoint(server_id=app_row.server_id, ts=now - timedelta(hours=h),
                           disk_pct=40.0))
    db.commit()
    forecast.rule_capacity_forecast(db, app_row)
    db.commit()
    from sre_platform.models import Finding

    assert db.query(Finding).filter_by(rule_key="disk_exhaustion_forecast").first() is None


# ---------------------------------------------------------------- migrations
def test_ensure_schema_idempotent():
    ensure_schema(engine)
    ensure_schema(engine)  # second run must not raise
    from sqlalchemy import inspect

    cols = {c["name"] for c in inspect(engine).get_columns("deployment")}
    assert {"pr_url", "ci_state", "ci_url", "regression_checked"} <= cols


# ---------------------------------------------------------------- executor (agent)
def test_executor_allowlist_and_target_safety():
    from sre_agent.executor import execute_action

    res = execute_action(1, "restart_service", "myapp.service", "n", allowlist=[])
    assert res["status"] == "rejected"
    res = execute_action(1, "restart_service", "bad; target", "n", allowlist=["restart_service"])
    assert res["status"] == "rejected"
    res = execute_action(1, "deploy_service", "x", "n", allowlist=["restart_service"])
    assert res["status"] == "rejected"  # unknown playbook
