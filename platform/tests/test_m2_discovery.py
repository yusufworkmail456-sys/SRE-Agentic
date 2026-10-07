"""M2 tests: discovery convergence (auto + manual -> one entity) and agent auth."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sre_platform.app import create_app
from sre_platform.db import SessionLocal, engine
from sre_platform.models import Application, Base, DiscoverySource, Server, Workload
from sre_platform.security import hash_token

TOKEN = "sreag_test_token_123"


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


def _make_server(db) -> Server:
    server = Server(hostname="vm-test", token_hash=hash_token(TOKEN), capabilities={"exec": False})
    db.add(server)
    db.commit()
    return server


FINGERPRINTS = [
    {
        "key": "systemd:hermes-gateway",
        "name": "hermes-gateway",
        "kind": "service",
        "source": "systemd",
        "runtime": "python",
        "external_id": "hermes-gateway.service",
        "cmd": "/usr/bin/python3 -m hermes.gateway",
        "cwd": "/root/hermes",
        "user": "root",
        "pid": 4242,
        "ports": [8646],
        "vhosts": [{"server_name": "grumble.ngrok-free.dev", "upstream": "127.0.0.1:8646", "ssl_cert": None}],
    }
]


def test_discovery_creates_unconfirmed_candidate(client, db):
    _make_server(db)
    resp = client.post(
        "/api/agent/v1/ingest",
        json={"discovery": FINGERPRINTS},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["discovery"] == {"created": 1, "matched": 0}

    app_row = db.query(Application).one()
    assert app_row.confirmed is False
    assert app_row.discovery is DiscoverySource.auto
    assert app_row.workloads[0].external_id == "hermes-gateway.service"
    assert app_row.workloads[0].instances[0].listen_port == 8646
    assert app_row.endpoints[0].domain == "grumble.ngrok-free.dev"


def test_discovery_is_idempotent(client, db):
    _make_server(db)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    client.post("/api/agent/v1/ingest", json={"discovery": FINGERPRINTS}, headers=headers)
    second = client.post("/api/agent/v1/ingest", json={"discovery": FINGERPRINTS}, headers=headers)
    assert second.json()["discovery"] == {"created": 0, "matched": 1}
    assert db.query(Application).count() == 1
    assert len(db.query(Workload).all()) == 1


def test_agent_auth_rejected_without_token(client, db):
    _make_server(db)
    resp = client.post("/api/agent/v1/ingest", json={"discovery": FINGERPRINTS})
    assert resp.status_code == 401


def test_confirm_flow_upgrades_candidate(client, db):
    _make_server(db)
    client.post(
        "/api/agent/v1/ingest",
        json={"discovery": FINGERPRINTS},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    resp = client.post(
        "/api/apps/hermes-gateway/confirm",
        json={"name": "Hermes Gateway", "owner": "sre", "environment": "prod"},
        headers={"X-User": "admin"},
    )
    assert resp.status_code == 200, resp.text
    app_row = db.query(Application).one()
    assert app_row.confirmed is True
    assert app_row.discovery is DiscoverySource.hybrid
    assert app_row.owner == "sre"


def test_health_hysteresis_marks_down(client, db):
    server = _make_server(db)
    client.post(
        "/api/agent/v1/ingest",
        json={"discovery": FINGERPRINTS},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    client.post("/api/apps/hermes-gateway/confirm", json={}, headers={"X-User": "admin"})
    headers = {"Authorization": f"Bearer {TOKEN}"}
    for _ in range(2):
        client.post(
            "/api/agent/v1/ingest",
            json={"health_checks": [{"target": "127.0.0.1:8646", "result": "fail"}]},
            headers=headers,
        )
    app_row = db.query(Application).one()
    assert app_row.status.value == "healthy" or app_row.status.value == "unknown"  # not yet down

    client.post(
        "/api/agent/v1/ingest",
        json={"health_checks": [{"target": "127.0.0.1:8646", "result": "fail"}]},
        headers=headers,
    )
    db.refresh(app_row)
    assert app_row.status.value == "down"

    for _ in range(2):
        client.post(
            "/api/agent/v1/ingest",
            json={"health_checks": [{"target": "127.0.0.1:8646", "result": "ok"}]},
            headers=headers,
        )
    db.refresh(app_row)
    assert app_row.status.value == "healthy"


def test_manual_registration_same_entity(client, db):
    server = _make_server(db)
    resp = client.post(
        "/api/apps",
        json={
            "name": "External Billing API",
            "environment": "prod",
            "deployment_model": "external",
            "domain": "billing.partner.example",
            "health_check_url": "https://billing.partner.example/healthz",
            "repository_url": "https://github.com/example/billing",
            "dependencies": [{"name": "PostgreSQL", "kind": "db", "criticality": "high"}],
        },
        headers={"X-User": "admin"},
    )
    assert resp.status_code == 201, resp.text
    slug = resp.json()["slug"]
    assert slug == "external-billing-api"

    detail = client.get(f"/api/apps/{slug}").json()
    assert detail["discovery"] == "manual"
    assert detail["endpoints"][0]["domain"] == "billing.partner.example"
    assert detail["health_checks"][0]["kind"] == "http"

    row = db.query(Application).one()
    assert row.dependencies[0].name == "PostgreSQL"
    assert row.server_id is None or row.server_id == server.id


def test_discovery_never_touches_confirmed_manual_app(client, db):
    _make_server(db)
    client.post(
        "/api/apps",
        json={"name": "Manual App", "environment": "prod"},
        headers={"X-User": "admin"},
    )
    before = db.query(Application).count()
    client.post(
        "/api/agent/v1/ingest",
        json={"discovery": FINGERPRINTS},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    assert db.query(Application).count() == before + 1  # separate candidate, not merged blindly


def test_ui_discovery_page_lists_candidates(client, db):
    _make_server(db)
    client.post(
        "/api/agent/v1/ingest",
        json={"discovery": FINGERPRINTS},
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    resp = client.get("/discovery")
    assert resp.status_code == 200
    assert "hermes-gateway" in resp.text
    assert "Unconfirmed candidates" in resp.text
