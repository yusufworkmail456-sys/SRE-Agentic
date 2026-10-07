"""M1 smoke tests: model graph + API surface."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sre_platform.app import create_app
from sre_platform.db import SessionLocal, engine
from sre_platform.models import (
    AppStatus,
    Application,
    Base,
    DeploymentModel,
    DiscoverySource,
    Finding,
    FindingCategory,
    Incident,
    Server,
    TimelineEvent,
    Workload,
    WorkloadKind,
)


@pytest.fixture()
def db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client():
    return TestClient(create_app())


def test_model_graph_roundtrip(db):
    server = Server(hostname="vm-test")
    app_row = Application(
        name="Customer Portal",
        slug="customer-portal",
        environment="prod",
        deployment_model=DeploymentModel.process,
        discovery=DiscoverySource.auto,
    )
    app_row.server = server
    app_row.workloads.append(
        Workload(kind=WorkloadKind.process, name="java-main", runtime="java", source="systemd")
    )
    db.add(app_row)
    db.commit()

    got = db.query(Application).filter_by(slug="customer-portal").one()
    assert got.server.hostname == "vm-test"
    assert got.workloads[0].runtime == "java"
    assert got.status is AppStatus.unknown
    assert got.confirmed is False


def test_finding_carries_evidence(db):
    app_row = Application(name="A", slug="a")
    db.add(app_row)
    db.commit()
    finding = Finding(
        application_id=app_row.id,
        category=FindingCategory.performance,
        rule_key="p95_spike",
        title="P95 latency increased 67%",
        observation="P95 went 180ms -> 300ms over 30m",
        evidence=[{"source": "metric_point", "ts": "2026-01-01T00:00:00Z", "value": 300}],
    )
    db.add(finding)
    db.commit()
    assert db.query(Finding).one().evidence[0]["source"] == "metric_point"


def test_incident_and_timeline_link(db):
    app_row = Application(name="B", slug="b")
    db.add(app_row)
    db.commit()
    incident = Incident(application_id=app_row.id, title="App down")
    db.add(incident)
    db.commit()
    db.add(
        TimelineEvent(
            application_id=app_row.id,
            incident_id=incident.id,
            kind="incident",
            summary="Incident opened",
        )
    )
    db.commit()
    assert db.query(TimelineEvent).one().incident_id == incident.id


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_overview_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Attention Required" in resp.text


def test_unknown_app_slug_404(client):
    assert client.get("/applications/nope").status_code == 404
