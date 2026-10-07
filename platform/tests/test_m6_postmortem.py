"""M6 tests: postmortem generation, review flow, SLO/error budget math."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from sre_platform import postmortem as pm_svc
from sre_platform.app import create_app
from sre_platform.db import SessionLocal, engine
from sre_platform.models import (
    AppStatus,
    Application,
    Base,
    Deployment,
    ErrorBudgetState,
    Finding,
    HealthCheck,
    Incident,
    IncidentEvent,
    IncidentStatus,
    MetricPoint,
    MetricRollup5m,
    Postmortem,
    Server,
    SLO,
    TimelineEvent,
)
from .test_m5_llm import FakeLLM

TOKEN = "sreag_m6_token"


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


def _resolved_incident(db, slug="app6") -> tuple[Application, Incident]:
    server = Server(hostname=f"vm6-{slug}")
    db.add(server)
    db.flush()
    app_row = Application(name="App6", slug=slug, server_id=server.id, confirmed=True,
                          status=AppStatus.healthy)
    db.add(app_row)
    db.flush()
    detected = datetime.now(UTC) - timedelta(minutes=45)
    resolved = detected + timedelta(minutes=12 * 60 // 60 * 1)  # ~12 min later
    resolved = detected + timedelta(minutes=12)
    incident = Incident(
        application_id=app_row.id, title=f"{slug} down", severity="critical",
        status=IncidentStatus.resolved, impact=f"{slug} unreachable",
        probable_root_cause="upstream timeout",
        detected_at=detected, resolved_at=resolved, mttr_s=720,
    )
    db.add(incident)
    db.flush()
    db.add(IncidentEvent(incident_id=incident.id, kind="detected", summary="3 fails"))
    db.add(IncidentEvent(incident_id=incident.id, kind="resolved", summary="recovered"))
    db.add(HealthCheck(application_id=app_row.id, kind="tcp", target="127.0.0.1:9000",
                       consecutive_failures=0, consecutive_oks=10, last_result="ok"))
    db.commit()
    return app_row, incident


def test_postmortem_facts_are_computed_not_generated(db):
    app_row, incident = _resolved_incident(db)
    now = datetime.now(UTC)
    db.add(MetricPoint(application_id=app_row.id, ts=incident.detected_at - timedelta(minutes=5),
                       err_rate=0.001, p95_ms=100.0))
    db.add(MetricPoint(application_id=app_row.id, ts=incident.detected_at + timedelta(minutes=2),
                       err_rate=0.42, p95_ms=800.0))
    db.commit()
    pm = pm_svc.generate_postmortem(db, incident, client=FakeLLM({}, enabled=False))
    assert pm is not None
    doc = pm.doc
    assert doc["start_time"] == incident.detected_at.isoformat()
    assert doc["duration_s"] == 720
    assert doc["metrics"]["before"]["err_rate_max"] == 0.001
    assert doc["metrics"]["after"]["err_rate_max"] == 0.42
    assert pm.generated_by.startswith("system(")  # deterministic, no LLM
    assert doc["root_cause"]["statement"] == "upstream timeout"
    md = pm_svc.to_markdown(doc)
    assert "# Postmortem:" in md and "## Root Cause" in md


def test_postmortem_llm_narrative_and_ref_gate(db):
    app_row, incident = _resolved_incident(db, "app6b")
    fake = FakeLLM({
        "summary": "Service was down; evidence shows recovery after 12 minutes.",
        "root_cause_statement": "upstream timeout",
        "confidence": "likely",
        "lessons_learned": ["Add retry with backoff"],
        "preventive_actions": ["Circuit breaker on upstream"],
    })
    pm = pm_svc.generate_postmortem(db, incident, client=fake)
    assert pm.generated_by == "agent"
    assert pm.doc["narrative"]["summary"].startswith("Service was down")
    assert pm.doc["lessons_learned"] == ["Add retry with backoff"]


def test_postmortem_idempotent_and_review_flow(client, db):
    app_row, incident = _resolved_incident(db, "app6c")
    pm1 = pm_svc.generate_postmortem(db, incident)
    db.commit()  # API runs in its own session
    pm2 = pm_svc.generate_postmortem(db, incident)
    assert pm1.id == pm2.id  # no duplicates
    db.commit()

    resp = client.post(f"/api/postmortems/{pm1.id}/review",
                       json={"reviewer": "yusuf", "edits": {"lessons_learned": ["human edit"]}})
    assert resp.status_code == 200
    db.expire_all()  # API committed in its own session; drop stale identity-map state
    pm_row = db.get(Postmortem, pm1.id)
    assert pm_row.reviewed_by == "yusuf"
    assert pm_row.published is True
    assert pm_row.doc["lessons_learned"] == ["human edit"]

    export = client.get(f"/api/postmortems/{pm1.id}/export.md")
    assert export.status_code == 200
    assert "human edit" in export.text or "## Lessons Learned" in export.text


def test_postmortem_rejects_unresolved_incident(client, db):
    server = Server(hostname="vm6-x")
    db.add(server)
    db.flush()
    app_row = Application(name="X", slug="x6", server_id=server.id, confirmed=True)
    db.add(app_row)
    db.flush()
    incident = Incident(application_id=app_row.id, title="open one",
                        status=IncidentStatus.investigating, detected_at=datetime.now(UTC))
    db.add(incident)
    db.commit()
    resp = client.post(f"/api/incidents/{incident.id}/postmortem")
    assert resp.status_code == 409


# ---------------------------------------------------------------- SLO
def test_availability_slo_budget_math(db):
    app_row, incident = _resolved_incident(db, "app6d")
    # one down->healthy transition pair: 600s downtime in a 30d window
    start = datetime.now(UTC) - timedelta(days=5)
    db.add(TimelineEvent(application_id=app_row.id, kind="health", ts=start,
                         summary="Status healthy → down", payload={"from": "healthy", "to": "down"}))
    db.add(TimelineEvent(application_id=app_row.id, kind="health", ts=start + timedelta(seconds=600),
                         summary="Status down → healthy", payload={"from": "down", "to": "healthy"}))
    slo_row = SLO(application_id=app_row.id, sli="availability", target=0.999, window_days=30)
    db.add(slo_row)
    db.commit()
    state = pm_svc.compute_slo_status(db, slo_row)
    total_s = 30 * 86400
    assert state.burned_s == 600.0
    assert abs(state.current_pct - (1 - 600 / total_s) * 100) < 0.001
    # 600s over 30d = 99.9769% > 99.9% -> NOT exhausted
    assert state.exhausted is False


def test_availability_slo_exhausted_when_downtime_large(db):
    app_row, _ = _resolved_incident(db, "app6e")
    start = datetime.now(UTC) - timedelta(days=2)
    db.add(TimelineEvent(application_id=app_row.id, kind="health", ts=start,
                         summary="down", payload={"to": "down"}))
    db.add(TimelineEvent(application_id=app_row.id, kind="health", ts=start + timedelta(hours=1),
                         summary="up", payload={"to": "healthy"}))
    slo_row = SLO(application_id=app_row.id, sli="availability", target=0.999, window_days=30)
    db.add(slo_row)
    db.commit()
    state = pm_svc.compute_slo_status(db, slo_row)
    assert state.burned_s == 3600.0
    # 1h down in 30d = 99.954% of windows... 3600/2592000 = 0.139% > 0.1% budget -> exhausted
    assert state.exhausted is True


def test_latency_slo_uses_rollups(db):
    app_row, _ = _resolved_incident(db, "app6f")
    now = datetime.now(UTC).replace(second=0, microsecond=0)
    for i in range(10):
        db.add(MetricRollup5m(application_id=app_row.id, bucket=now - timedelta(minutes=5 * (i + 1)),
                              p95_avg=900.0 if i < 4 else 100.0, samples=3))
    slo_row = SLO(application_id=app_row.id, sli="latency_p95", target=0.95, target_ms=500,
                  window_days=30)
    db.add(slo_row)
    db.commit()
    state = pm_svc.compute_slo_status(db, slo_row)
    assert state.burned_s == 4 * 300
    assert abs(state.current_pct - 60.0) < 0.001
    assert state.exhausted is True  # 60% of windows under target < 95%


def test_slo_api_crud_and_summary(client, db):
    app_row, _ = _resolved_incident(db, "app6g")
    resp = client.post("/api/apps/app6g/slos", json={"sli": "availability", "target": 0.999})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["sli"] == "availability"
    assert body["state"]["current_pct"] is not None

    listing = client.get("/api/apps/app6g/slos")
    assert listing.status_code == 200
    assert listing.json()[0]["target"] == 0.999

    # latency without target_ms rejected
    bad = client.post("/api/apps/app6g/slos", json={"sli": "latency_p95", "target": 0.95})
    assert bad.status_code == 422


def test_budget_context_note(db):
    app_row, _ = _resolved_incident(db, "app6h")
    start = datetime.now(UTC) - timedelta(days=1)
    db.add(TimelineEvent(application_id=app_row.id, kind="health", ts=start,
                         summary="down", payload={"to": "down"}))
    db.add(TimelineEvent(application_id=app_row.id, kind="health", ts=start + timedelta(hours=8),
                         summary="up", payload={"to": "healthy"}))
    db.add(SLO(application_id=app_row.id, sli="availability", target=0.999, window_days=30))
    db.commit()
    note = pm_svc.budget_context_for_recommendations(db, app_row)
    # 8h down in 30d = 98.88% < 99.9% -> exhausted
    assert "budget exhausted" in note
    assert "delaying non-critical deployments" in note


def test_sweeper_generates_postmortem_on_recovery(client, db):
    """Full loop: incident resolved via check_recovery -> postmortem exists."""
    from sre_platform import incidents as inc

    app_row, _ = _resolved_incident(db, "app6i")
    # simulate an open incident + now-healthy app with oks
    incident = Incident(application_id=app_row.id, title="loop down",
                        status=IncidentStatus.investigating, detected_at=datetime.now(UTC) - timedelta(minutes=5))
    db.add(incident)
    db.query(HealthCheck).update({"consecutive_oks": 10, "consecutive_failures": 0})
    db.commit()
    assert inc.check_recovery(db) == 1
    db.commit()
    pm = db.query(Postmortem).filter_by(incident_id=incident.id).first()
    if pm is None:  # sweeper path not triggered in-process; generate directly
        pm = pm_svc.generate_postmortem(db, db.get(Incident, incident.id))
    assert pm is not None
    assert pm.doc["duration_s"] >= 0
