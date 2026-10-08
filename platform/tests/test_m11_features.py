"""M11 tests: labeling, threshold SLOs, quick reminders, perf test, app report,
external resource registration + platform probe."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sre_platform.app import create_app
from sre_platform.db import SessionLocal, engine
from sre_platform.models import (
    Application,
    Base,
    Finding,
    FindingStatus,
    LogBatch,
    MetricPoint,
    SLO,
    Server,
    User,
)
from sre_platform.quickreport import finish_due_perf_tests
from sre_platform.security import hash_password, hash_token

TOKEN = "sreag_test_token_m11"


@pytest.fixture(autouse=True)
def db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    session.add(User(username="admin", password_hash=hash_password("x"), role="admin"))
    session.commit()
    yield session
    session.close()


@pytest.fixture()
def client():
    with TestClient(create_app()) as c:
        yield c


def _headers(user="admin"):
    return {"X-User": user}


def _make_server(db) -> Server:
    server = Server(hostname="vm-m11", token_hash=hash_token(TOKEN), capabilities={"exec": False})
    db.add(server)
    db.commit()
    return server


# ------------------------------------------------------------- 1. labeling
def test_label_detected_vs_external(db, client):
    server = _make_server(db)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    client.post(
        "/api/agent/v1/ingest",
        json={"discovery": [{
            "key": "systemd:svc1", "name": "svc1", "source": "systemd",
            "external_id": "svc1.service", "ports": [9001],
        }]},
        headers=headers,
    )
    client.post("/api/apps/svc1/confirm", json={}, headers=_headers())
    client.post(
        "/api/apps",
        json={"name": "Ext Billing", "domain": "billing.example.com",
              "deployment_model": "external"},
        headers=_headers(),
    )
    detected = db.query(Application).filter_by(slug="svc1").one()
    external = db.query(Application).filter_by(slug="ext-billing").one()
    assert detected.discovery.value in ("auto", "hybrid")
    assert external.discovery.value == "manual"
    resp = client.get("/discovery")
    assert "External Resource" in resp.text and "Detected App" in resp.text


def test_external_registration_ui(db, client):
    resp = client.post(
        "/api/ui/apps/external",
        data={"name": "My External", "domain": "ext.example.com",
              "repository_url": "https://github.com/u/r", "health_check_url": "",
              "owner": "sre", "environment": "prod"},
        headers=_headers(),
    )
    assert resp.status_code == 200, resp.text
    app_row = db.query(Application).filter_by(slug="my-external").one()
    assert app_row.discovery.value == "manual"
    assert app_row.confirmed is True
    assert app_row.endpoints[0].domain == "ext.example.com"
    assert app_row.health_checks[0].kind == "http"
    assert app_row.health_checks[0].target == "https://ext.example.com"
    assert app_row.workloads == []


# ------------------------------------------------- 2. advanced SLO + reminder
def test_threshold_slo_breach_creates_quick_reminder(db, client):
    app_row = Application(name="A1", slug="a1", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    db.add(SLO(application_id=app_row.id, sli="error_rate", metric="error_rate",
               comparison=">", threshold=0.05, target=0.0))
    now = datetime.now(UTC)
    for i in range(3):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=3 - i),
                           err_rate=0.2, req_rate=10))
    db.commit()
    from sre_platform.quickreminders import check_metric_slos

    fired = check_metric_slos(db, app_row, client=None)
    assert fired, "slo breach should fire"
    finding = db.query(Finding).filter_by(application_id=app_row.id).one()
    assert finding.rule_key.startswith("slo_breach:")
    assert finding.status == FindingStatus.open
    assert finding.recommendation and "Langkah awal" in finding.recommendation  # deterministic fallback (LLM off)


def test_threshold_slo_recovers(db, client):
    app_row = Application(name="A2", slug="a2", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    db.add(SLO(application_id=app_row.id, sli="error_rate", metric="error_rate",
               comparison=">", threshold=0.05, target=0.0))
    now = datetime.now(UTC)
    for i in range(3):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=3 - i),
                           err_rate=0.2))
    db.commit()
    from sre_platform.quickreminders import check_metric_slos

    check_metric_slos(db, app_row, client=None)
    assert db.query(Finding).count() == 1
    # healthy now
    for i in range(3):
        db.add(MetricPoint(application_id=app_row.id, ts=now + timedelta(minutes=i + 1),
                           err_rate=0.01))
    db.commit()
    check_metric_slos(db, app_row, client=None)
    finding = db.query(Finding).one()
    assert finding.status == FindingStatus.resolved


def test_threshold_api_roundtrip(db, client):
    resp = client.post(
        "/api/apps/x1/slos/threshold",
        json={"sli": "latency_p95_ms", "comparison": ">", "threshold": 800},
        headers=_headers(),
    )
    assert resp.status_code == 404  # app does not exist


# ------------------------------------------------------ 3. recurring errors
def test_recurring_error_quick_reminder(db, client):
    app_row = Application(name="A3", slug="a3", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    now = datetime.now(UTC)
    line = "2026-10-08 10:00:00 ERROR [worker-7] Connection to db-primary refused (attempt 12)"
    for i in range(4):
        db.add(LogBatch(
            application_id=app_row.id,
            ts_start=now - timedelta(minutes=15 - i),
            ts_end=now - timedelta(minutes=14 - i),
            level_counts={"ERROR": 1},
            sample_lines=[line.replace("worker-7", f"worker-{i}")],
        ))
    db.commit()
    from sre_platform.quickreminders import check_recurring_errors

    fired = check_recurring_errors(db, app_row, client=None)
    assert fired
    finding = db.query(Finding).filter_by(application_id=app_row.id).one()
    assert finding.rule_key.startswith("recurring_error:")
    assert "Connection" in finding.observation
    assert finding.recommendation  # AI/deterministic explanation present


def test_single_error_no_reminder(db, client):
    app_row = Application(name="A4", slug="a4", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    now = datetime.now(UTC)
    db.add(LogBatch(application_id=app_row.id, ts_start=now - timedelta(minutes=5),
                    ts_end=now - timedelta(minutes=4), level_counts={"ERROR": 1},
                    sample_lines=["ERROR one-off blip things happened here now"]))
    db.commit()
    from sre_platform.quickreminders import check_recurring_errors

    check_recurring_errors(db, app_row, client=None)
    assert db.query(Finding).count() == 0


# ------------------------------------------------------------- 4. perf test
def test_perf_test_lifecycle(db, client):
    app_row = Application(name="A5", slug="a5", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    resp = client.post("/api/apps/a5/perf-test", json={"duration_s": 60}, headers=_headers())
    assert resp.status_code == 201, resp.text
    # duplicate rejected
    resp2 = client.post("/api/apps/a5/perf-test", json={"duration_s": 60}, headers=_headers())
    assert resp2.status_code == 409
    # simulate elapsed window
    from sre_platform.models import PerfTest

    test = db.query(PerfTest).one()
    test.started_at = datetime.now(UTC) - timedelta(seconds=120)
    test.duration_s = 60
    now = datetime.now(UTC)
    for i in range(6):
        db.add(MetricPoint(application_id=app_row.id, ts=test.started_at + timedelta(seconds=10 * i),
                           req_rate=5.5, err_rate=0.02, p95_ms=120, http_2xx=100, http_5xx=1,
                           cpu_pct=40, mem_pct=55))
    db.commit()
    finished = finish_due_perf_tests(db)
    db.commit()
    assert finished == 1
    db.refresh(test)
    assert test.status == "done"
    s = test.summary
    assert s["http_total"] == 606  # 101 per sample window edge (2 boundary samples x 101)
    assert abs(s["req_rate"]["avg"] - 5.5) < 0.01
    assert s["p95_ms"]["p95_of_p95_ms"] == 120
    # detail page renders the result
    resp3 = client.get("/applications/a5")
    assert "Hasil test terakhir" in resp3.text


def test_perf_test_duration_clamped(db):
    from sre_platform.quickreport import start_perf_test

    app_row = Application(name="A6", slug="a6", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    test = start_perf_test(db, app_row, 9999)
    assert test.duration_s == 600


# ----------------------------------------------------------- 6. quick report
def test_quick_report_generated(db, client):
    app_row = Application(name="A7", slug="a7", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    now = datetime.now(UTC)
    for i in range(4):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=30 - i * 5),
                           req_rate=3, err_rate=0.01, p95_ms=200, http_2xx=50))
    db.commit()
    resp = client.post("/api/apps/a7/report?window_minutes=120", headers=_headers())
    assert resp.status_code == 201, resp.text
    data = client.get("/api/apps/a7/report/latest").json()
    assert data["doc"]["performance"]["req_rate_avg"] == 3
    assert data["generated_by"] == "system(deterministic)"  # LLM disabled in tests
    md = client.get("/api/apps/a7/report/latest/export.md")
    assert "Quick Report — A7" in md.text
    page = client.get("/applications/a7")
    assert "Quick Application Report" in page.text


# ------------------------------------------------------------ 5. UI polish
def test_app_page_restructured(db, client):
    app_row = Application(name="A8", slug="a8", environment="prod", confirmed=True)
    db.add(app_row)
    db.commit()
    page = client.get("/applications/a8")
    assert page.status_code == 200
    for marker in ("Quick Reminder", "Performance", "Quick Application Report",
                   "Reliability (SLO)", "Ask Agent"):
        assert marker in page.text


def test_healthz_and_overview_ok(client):
    assert client.get("/healthz").json()["status"] == "ok"
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Fleet Overview" in resp.text
