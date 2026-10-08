"""M4 tests: log collection, storage, rules (ssl/log-spike), evidence enrichment."""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent"))

from sre_agent import logcol  # noqa: E402
from sre_platform import rules_extra  # noqa: E402
from sre_platform.app import create_app  # noqa: E402
from sre_platform.db import SessionLocal, engine  # noqa: E402
from sre_platform.logstore import recent_error_samples, store_log_batches, window_error_counts  # noqa: E402
from sre_platform.models import (  # noqa: E402
    AppStatus,
    Application,
    Base,
    Endpoint,
    Finding,
    FindingStatus,
    LogBatch,
    Server,
)

TOKEN = "sreag_m4_token"


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


def _app(db, **kw) -> Application:
    server = Server(hostname="vm4")
    db.add(server)
    db.flush()
    app_row = Application(
        name="App4", slug=kw.get("slug", "app4"), server_id=server.id,
        confirmed=True, status=AppStatus.healthy, environment=kw.get("env", "prod"),
    )
    db.add(app_row)
    db.commit()
    return app_row


SAMPLE = """2026-10-07 12:00:01 INFO service started
2026-10-07 12:00:05 ERROR NullPointerException at PaymentMapper.java:88
2026-10-07 12:00:06 ERROR DB connection timeout after 5000ms
2026-10-07 12:00:10 INFO health check ok
"""


def test_classify_lines_levels_and_samples():
    result = logcol.classify_lines(SAMPLE.splitlines())
    assert result["level_counts"]["ERROR"] == 2
    assert result["level_counts"]["INFO"] == 2
    assert len(result["sample_lines"]) == 2
    assert "NullPointerException" in result["sample_lines"][0]


def test_journald_batch_graceful_when_unavailable():
    # unit that does not exist -> None (no crash)
    assert logcol.journald_batch("definitely-not-a-unit-xyz") is None


def test_file_batch(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text(SAMPLE)
    result = logcol.file_batch(str(log_file))
    assert result is not None
    assert result["source"] == "file"
    assert result["level_counts"]["ERROR"] == 2
    assert result["ts_start"].startswith("2026-10-07")


def test_store_log_batches_matches_app(db):
    app_row = _app(db)
    from datetime import UTC, datetime, timedelta

    from sre_platform.models import Workload

    db.add(Workload(application_id=app_row.id, name="app4", external_id="app4.service"))
    db.commit()
    now = datetime.now(UTC)
    stored = store_log_batches(
        db,
        db.query(Server).first(),
        [{"source": "journald", "workload_ref": "app4.service", "level_counts": {"ERROR": 4, "INFO": 10},
          "sample_lines": ["ERROR boom"],
          "ts_start": (now - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S"),
          "ts_end": (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")}],
    )
    db.commit()
    assert stored == 1
    batch = db.query(LogBatch).one()
    assert batch.application_id == app_row.id
    assert batch.level_counts["ERROR"] == 4
    assert window_error_counts(db, app_row.id, minutes=60)["ERROR"] == 4
    samples = recent_error_samples(db, app_row.id)
    assert samples and samples[0]["errors"] == 4


def test_log_error_spike_rule(db):
    app_row = _app(db)
    now = datetime.now(UTC)
    # history: quiet batches
    for i in range(6):
        db.add(LogBatch(application_id=app_row.id, ts_start=now - timedelta(hours=i + 2),
                        ts_end=now - timedelta(hours=i + 2) + timedelta(minutes=5),
                        level_counts={"ERROR": 1, "INFO": 50}, sample_lines=[]))
    # recent spike
    db.add(LogBatch(application_id=app_row.id, ts_start=now - timedelta(minutes=10),
                    ts_end=now - timedelta(minutes=2), level_counts={"ERROR": 30}, sample_lines=["ERROR x"]))
    db.commit()
    rules_extra.rule_log_error_spike(db, app_row)
    finding = db.query(Finding).filter_by(rule_key="log_error_spike").one()
    assert finding.status == FindingStatus.open
    assert finding.evidence  # sample lines referenced


def test_ssl_rule_detects_expiry_directly(db):
    app_row = _app(db)
    db.add(Endpoint(application_id=app_row.id, url="https://api.example.test",
                    domain="api.example.test", tls_expires_at=datetime.now(UTC) + timedelta(days=10)))
    db.commit()
    # monkeypatch network probe: unit test should not hit the network
    original = rules_extra._cert_expiry
    rules_extra._cert_expiry = lambda domain, **kw: datetime.now(UTC) + timedelta(days=10)
    try:
        rules_extra.rule_ssl_expiry(db, app_row)
    finally:
        rules_extra._cert_expiry = original
    finding = db.query(Finding).filter_by(rule_key="ssl_expiring_soon").one()
    assert "9 days" in finding.title or "10 days" in finding.title
    assert finding.severity.value == "warning"


def test_ssl_rule_resolves_when_renewed(db):
    app_row = _app(db)
    db.add(Endpoint(application_id=app_row.id, url="https://api.example.test",
                    domain="api.example.test", tls_expires_at=datetime.now(UTC) + timedelta(days=120)))
    db.commit()
    db.add(Finding(application_id=app_row.id, rule_key="ssl_expiring_soon",
                   category="operational", severity="warning", confidence="confirmed",
                   title="old", observation="old"))
    db.commit()
    original = rules_extra._cert_expiry
    rules_extra._cert_expiry = lambda domain, **kw: datetime.now(UTC) + timedelta(days=120)
    try:
        rules_extra.rule_ssl_expiry(db, app_row)
    finally:
        rules_extra._cert_expiry = original
    assert db.query(Finding).filter_by(rule_key="ssl_expiring_soon").one().status == FindingStatus.resolved


def test_ingest_stores_logs_via_api(client, db):
    app_row = _app(db)
    from sre_platform.models import Workload
    from sre_platform.security import hash_token

    db.add(Workload(application_id=app_row.id, name="app4", external_id="app4.service"))
    server = db.query(Server).first()
    server.token_hash = hash_token(TOKEN)
    db.commit()
    resp = client.post(
        "/api/agent/v1/ingest",
        json={"logs": [{"source": "journald", "workload_ref": "app4.service",
                        "level_counts": {"ERROR": 3}, "sample_lines": ["ERROR a", "ERROR b"],
                        "ts_start": "2026-10-07 12:00:00", "ts_end": "2026-10-07 12:05:00"}]},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert resp.status_code == 200
    assert resp.json()["logs_stored"] == 1
    assert db.query(LogBatch).count() == 1


def test_evidence_pack_includes_log_errors(db, client):
    app_row = _app(db)
    from sre_platform import incidents as inc
    from sre_platform.models import Incident

    now = datetime.now(UTC)
    db.add(LogBatch(application_id=app_row.id, ts_start=now - timedelta(minutes=10),
                    ts_end=now - timedelta(minutes=5), level_counts={"ERROR": 9},
                    sample_lines=["ERROR fatal thing"]))
    incident = Incident(application_id=app_row.id, title="t", detected_at=now)
    db.add(incident)
    db.commit()
    pack = inc.build_evidence_pack(db, incident)
    assert pack["log_errors_30m"], "error samples must enrich the evidence pack"
    assert "fatal" in pack["log_errors_30m"][0]["samples"][0]
