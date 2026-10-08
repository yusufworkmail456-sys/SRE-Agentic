"""M12 tests: endpoints/Apdex, saturation, no-data, fast burn, processes/events."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sre_platform.app import create_app
from sre_platform.db import SessionLocal, engine
from sre_platform.metrics import (
    store_endpoint_stats,
    store_host_events,
    store_process_snapshot,
)
from sre_platform.models import (
    Application,
    Base,
    Finding,
    LogBatch,
    MetricPoint,
    SLO,
    Server,
    User,
    Workload,
)
from sre_platform.security import hash_password, hash_token

TOKEN = "sreag_test_token_m12"


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


def _headers():
    return {"X-User": "admin"}


def _server(db) -> Server:
    s = Server(hostname="vm-m12", token_hash=hash_token(TOKEN), capabilities={})
    db.add(s)
    db.commit()
    return s


def _app(db, server, slug="m12app", port=9100):
    app_row = Application(name="M12 App", slug=slug, environment="prod",
                          confirmed=True, server_id=server.id)
    db.add(app_row)
    db.commit()
    workload = Workload(application_id=app_row.id, name="m12", external_id="m12.service")
    db.add(workload)
    db.commit()
    from sre_platform.models import RuntimeInstance

    db.add(RuntimeInstance(workload_id=workload.id, listen_port=port))
    db.commit()
    return app_row


# ------------------------------------------------------------ ingest plumbing
def test_ingest_endpoints_processes_events(db, client):
    server = _server(db)
    app_row = _app(db, server)
    now = datetime.now(UTC)
    resp = client.post(
        "/api/agent/v1/ingest",
        json={
            "metrics": {"server": {"cpu_pct": 10, "mem_pct": 20, "disk_pct": 30,
                                   "load1": 2.0, "load5": 5.5, "load15": 3.0,
                                   "swap_pct": 60, "net_drops": 200}},
            "endpoints": [{"route": "/api/items/{id}", "method": "GET", "port": 9100,
                           "requests": 100, "err_rate": 0.02, "p50_ms": 10, "p95_ms": 100,
                           "p99_ms": 300, "apdex": 0.95,
                           "histogram": {"50": 60, "100": 80, "250": 95, "500": 100}}],
            "processes": [{"pid": 1, "name": "python", "user": "root", "cpu_s": 12.5,
                           "rss_mb": 120, "started_at": None, "cmd": "python app"}],
            "events": [{"kind": "oom", "summary": "Out of memory: Killed process 1234"}],
        },
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["endpoints_stored"] == 1
    assert data["events_stored"] == 1
    db.refresh(app_row)
    point = db.query(MetricPoint).filter(MetricPoint.server_id == server.id).one()
    assert point.load5 == 5.5 and point.swap_pct == 60 and point.net_drops == 200
    # host saturation finding comes from the sweeper rules (run_rules_for_app),
    # not the ingest path — run it explicitly here.
    from sre_platform.detection import rule_host_saturation

    rule_host_saturation(db, app_row)
    sat = db.query(Finding).filter_by(application_id=app_row.id, rule_key="host_saturation").one()
    assert "load5" in sat.title and "swap" in sat.title
    # endpoint stat attached to app
    from sre_platform.models import EndpointStat

    stat = db.query(EndpointStat).one()
    assert stat.application_id == app_row.id
    assert stat.histogram["500"] == 100
    # UI fragments render
    page = client.get(f"/applications/{app_row.slug}")
    assert page.status_code == 200


def test_no_data_alert(db, client):
    server = _server(db)
    app_row = _app(db, server)
    now = datetime.now(UTC)
    db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=25), err_rate=0.0))
    db.commit()
    from sre_platform.detection import rule_no_data

    rule_no_data(db, app_row)
    finding = db.query(Finding).filter_by(rule_key="no_data").one()
    assert finding.severity.value == "warning"  # 25m: warning; >=30m: critical
    assert "No metric data" in finding.title


def test_no_data_resolves_when_data_flows(db, client):
    server = _server(db)
    app_row = _app(db, server)
    db.add(MetricPoint(application_id=app_row.id, ts=datetime.now(UTC), err_rate=0.0))
    db.commit()
    from sre_platform.detection import rule_no_data

    rule_no_data(db, app_row)
    assert db.query(Finding).count() == 0


def test_fast_burn_alert(db, client):
    server = _server(db)
    app_row = _app(db, server)
    db.add(SLO(application_id=app_row.id, sli="error_rate", metric="error_rate",
               comparison=">", threshold=0.01, target=0.0))
    now = datetime.now(UTC)
    # recent 3 samples 20% error = 20x burn; hourly samples avg 10% = 10x burn
    for i in range(3):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=5 - i), err_rate=0.20))
    for i in range(40):
        db.add(MetricPoint(application_id=app_row.id,
                           ts=now - timedelta(minutes=55 - i), err_rate=0.10))
    db.commit()
    from sre_platform.detection import rule_fast_burn

    rule_fast_burn(db, app_row)
    finding = db.query(Finding).filter_by(rule_key="slo_fast_burn").one()
    assert "burn" in finding.title
    assert finding.severity.value == "critical"


def test_fast_burn_quiet_when_slow_window_ok(db, client):
    server = _server(db)
    app_row = _app(db, server)
    db.add(SLO(application_id=app_row.id, sli="error_rate", metric="error_rate",
               comparison=">", threshold=0.01, target=0.0))
    now = datetime.now(UTC)
    for i in range(3):
        db.add(MetricPoint(application_id=app_row.id, ts=now - timedelta(minutes=5 - i), err_rate=0.5))
    # fill the 1h window with 30+ low-error samples so slow burn stays < 6x
    for i in range(40):
        db.add(MetricPoint(application_id=app_row.id,
                           ts=now - timedelta(minutes=55 - i), err_rate=0.001))
    db.commit()
    from sre_platform.detection import rule_fast_burn

    rule_fast_burn(db, app_row)
    assert db.query(Finding).count() == 0


# ------------------------------------------------------------------ helpers
def test_store_helpers_dedupe_and_binds(db, client):
    server = _server(db)
    app_row = _app(db, server)
    now = datetime.now(UTC)
    db.add(MetricPoint(application_id=app_row.id, ts=now, err_rate=0.01))
    db.commit()
    stored = store_endpoint_stats(db, server, [
        {"route": "/a", "method": "GET", "port": 9100, "requests": 5, "apdex": 1.0},
        {"route": "/unmatched", "method": "GET", "port": 9999, "requests": 2},
    ])
    db.commit()  # session has autoflush=False
    assert stored == 2
    from sre_platform.metrics import latest_endpoint_stats

    rows = latest_endpoint_stats(db, app_row.id)
    assert len(rows) == 1  # only the matched-port endpoint is bound to the app
    assert rows[0].route == "/a"

    store_process_snapshot(db, server, [{"pid": 1, "name": "x", "cpu_s": 1, "rss_mb": 5}])
    db.commit()
    from sre_platform.metrics import latest_process_snapshot

    assert latest_process_snapshot(db, server.id)[0]["name"] == "x"

    n = store_host_events(db, server, [{"kind": "oom", "summary": "Killed process 42"}])
    again = store_host_events(db, server, [{"kind": "oom", "summary": "Killed process 42"}])
    db.commit()
    assert n == 1 and again == 0  # dedup window 1h
    from sre_platform.metrics import latest_host_events

    assert len(latest_host_events(db, server.id)) == 1


# -------------------------------------------------------------- agent-side unit
def test_red_parse_endpoints_apdex():
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))
    from sre_agent.red import parse_access_log

    now = datetime.now(UTC)
    lines = []
    for i in range(50):
        ts = now.strftime("%d/%b/%Y:%H:%M:%S %z")
        lines.append(f'1.2.3.4 - - [{ts}] "GET /api/items/{i} HTTP/1.1" 200 123 rt=0.05 up=1.2.3.4:9100')
    for i in range(5):
        ts = now.strftime("%d/%b/%Y:%H:%M:%S %z")
        lines.append(f'1.2.3.4 - - [{ts}] "GET /api/items/{i} HTTP/1.1" 500 10 rt=2.5 up=1.2.3.4:9100')
    buckets, endpoints = parse_access_log("\n".join(lines), window_s=300, now=now)
    assert buckets[9100].requests == 55
    ep = [e for e in endpoints if e["route"] == "/api/items/{id}"]
    assert ep, endpoints
    e = ep[0]
    assert e["requests"] == 55
    assert abs(e["err_rate"] - 5 / 55) < 0.01
    assert e["apdex"] >= 0.85  # most under 1.3s, a few 5xx-but-fast count partial
    assert e["histogram"]["500"] >= 50
