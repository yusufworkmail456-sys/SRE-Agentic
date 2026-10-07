"""M3 tests: metrics storage, rollups, baseline, rules, incident open/recover."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sre_platform import detection, incidents, metrics as metrics_svc
from sre_platform.app import create_app
from sre_platform.db import SessionLocal, engine
from sre_platform.models import (
    AppStatus,
    Application,
    Base,
    Finding,
    FindingStatus,
    Incident,
    IncidentStatus,
    MetricPoint,
    MetricRollup5m,
    Server,
)

TOKEN = "sreag_m3_token"


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


def _setup(db, confirmed=True) -> tuple[Server, Application]:
    server = Server(hostname="vm3", token_hash=__import__("hashlib").sha256(TOKEN.encode()).hexdigest())
    db.add(server)
    db.flush()
    app_row = Application(
        name="App3", slug="app3", server_id=server.id, confirmed=confirmed,
        status=AppStatus.healthy if confirmed else AppStatus.unknown,
    )
    db.add(app_row)
    db.commit()
    return server, app_row


def _red(port=9000, err=0.0, p95=120.0, req=2.0):
    return {"port": port, "req_rate": req, "err_rate": err, "http_2xx": 100, "http_5xx": int(err * 100),
            "p50_ms": p95 * 0.6, "p95_ms": p95, "p99_ms": p95 * 1.3, "window_s": 300}


def test_red_stored_and_mapped_to_app(client, db):
    server, app_row = _setup(db)
    from sre_platform.models import RuntimeInstance, Workload

    workload = Workload(application_id=app_row.id, name="api", external_id="x")
    db.add(workload)
    db.flush()
    db.add(RuntimeInstance(workload_id=workload.id, listen_port=9000, alive=True))
    db.commit()

    resp = client.post(
        "/api/agent/v1/ingest",
        json={"red": [_red()], "metrics": {"cpu_pct": 11.5, "mem_pct": 40.0, "disk_pct": 50.0}},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["red_stored"] == 1
    db.commit()
    red_point = db.query(MetricPoint).filter(MetricPoint.application_id == app_row.id).one()
    assert red_point.p95_ms == 120.0
    server_point = db.query(MetricPoint).filter(MetricPoint.server_id == server.id,
                                                MetricPoint.application_id.is_(None)).one()
    assert server_point.cpu_pct == 11.5
    assert server_point.disk_pct == 50.0


def test_rollup_and_baseline(client, db):
    _, app_row = _setup(db)
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    # 10 buckets over ~1h with p95 ~100ms
    for i in range(10):
        bucket = now - timedelta(minutes=5 * (i + 1))
        for j in range(3):
            db.add(MetricPoint(application_id=app_row.id, ts=bucket + timedelta(seconds=j * 30),
                               p95_ms=100.0, err_rate=0.01, cpu_pct=10.0))
    db.commit()
    count = metrics_svc.run_rollups(db, lookback_minutes=90)
    db.commit()
    assert count >= 10
    rollups = db.query(MetricRollup5m).all()
    assert all(r.p95_avg == 100.0 for r in rollups)
    base = metrics_svc.baseline(db, app_row.id, "p95_avg")
    assert base["n"] >= 10 and abs(base["mean"] - 100.0) < 1


def test_error_rate_rule_fires_and_resolves(db):
    _, app_row = _setup(db)
    now = datetime.now(UTC)
    for i in range(5):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(seconds=i * 30), err_rate=0.25))
    db.commit()
    detection.rule_error_rate(db, app_row)
    finding = db.query(Finding).filter_by(rule_key="error_rate_elevated").one()
    assert finding.status == FindingStatus.open
    assert finding.severity.value in ("critical", "warning")
    assert finding.evidence  # evidence-backed (spec §11)

    for i in range(5):
        db.add(MetricPoint(application_id=app_row.id, ts=now + timedelta(seconds=60 + i * 30), err_rate=0.005))
    db.commit()
    detection.rule_error_rate(db, app_row)
    assert db.query(Finding).filter_by(rule_key="error_rate_elevated").one().status == FindingStatus.resolved


def test_latency_zscore_needs_baseline(db):
    _, app_row = _setup(db)
    db.add(MetricPoint(application_id=app_row.id, ts=datetime.now(UTC), p95_ms=900.0))
    db.commit()
    detection.rule_latency_zscore(db, app_row)
    assert db.query(Finding).filter_by(rule_key="p95_spike").count() == 0  # no baseline, no noise


def test_incident_open_investigate_recover(client, db):
    _, app_row = _setup(db)
    from sre_platform.models import HealthCheck

    db.add(HealthCheck(application_id=app_row.id, kind="tcp", target="127.0.0.1:9000",
                       last_result="fail", consecutive_failures=3))
    app_row.status = AppStatus.down
    db.commit()

    opened = incidents.detect_incidents(db)
    assert len(opened) == 1
    incident = opened[0]
    assert incident.status == IncidentStatus.investigating
    assert incident.investigation["verdict"]["confidence"] in ("likely", "hypothesis")
    assert db.query(Incident).count() == 1

    # second sweep must NOT open a duplicate
    assert incidents.detect_incidents(db) == []

    # recovery: healthy app + consecutive oks
    app_row.status = AppStatus.healthy
    db.query(HealthCheck).update({"consecutive_oks": 10, "consecutive_failures": 0})
    db.commit()
    assert incidents.check_recovery(db) == 1
    assert db.query(Incident).one().status == IncidentStatus.resolved
    assert db.query(Incident).one().mttr_s is not None


def test_evidence_pack_capped(db, client):
    _, app_row = _setup(db)
    from sre_platform.models import HealthCheck, Incident

    db.add(HealthCheck(application_id=app_row.id, kind="tcp", target="127.0.0.1:9000",
                       consecutive_failures=3))
    incident = Incident(application_id=app_row.id, title="t", detected_at=datetime.now(UTC))
    db.add(incident)
    db.commit()
    pack = incidents.build_evidence_pack(db, incident, max_chars=500)
    import json

    assert len(json.dumps(pack, default=str)) <= 500
