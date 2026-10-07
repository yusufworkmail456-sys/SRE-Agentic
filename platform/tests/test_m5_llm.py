"""M5 tests: LLM client quirk handling, citation enforcement, Ask Agent, wiring."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from sre_platform import askagent, investigation
from sre_platform.app import create_app
from sre_platform.db import SessionLocal, engine
from sre_platform.llm import LLMClient, LLMUnavailable, extract_json
from sre_platform.models import (
    AgentAction,
    AppStatus,
    Application,
    Base,
    Finding,
    FindingStatus,
    HealthCheck,
    Incident,
    IncidentStatus,
    LogBatch,
    MetricPoint,
    Server,
)

TOKEN = "sreag_m5_token"


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


class FakeLLM(LLMClient):
    """Deterministic stand-in; records prompts so tests can assert on grounding."""

    def __init__(self, payload: dict | str, enabled: bool = True):
        self._payload = payload
        self.base_url = "http://fake"
        self.api_key = "k"
        self.model = "fake"
        self._enabled = enabled
        self.prompts: list[str] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    def chat(self, system, user, max_tokens=1200, timeout_s=60.0) -> str:
        self.prompts.append(user)
        return json.dumps(self._payload) if isinstance(self._payload, dict) else self._payload

    def chat_json(self, system, user, max_tokens=1200, timeout_s=60.0) -> dict:
        self.prompts.append(user)
        if isinstance(self._payload, dict):
            return self._payload
        return extract_json(self._payload)


def _app(db, slug="app5") -> Application:
    server = Server(hostname=f"vm5-{slug}")
    db.add(server)
    db.flush()
    app_row = Application(name="App5", slug=slug, server_id=server.id, confirmed=True,
                          status=AppStatus.degraded)
    db.add(app_row)
    db.commit()
    return app_row


# ---------------------------------------------------------------- llm client
def test_extract_json_handles_fenced_output():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('prose before {"b": 2} after') == {"b": 2}
    with pytest.raises(LLMUnavailable):
        extract_json("no json at all")


def test_sse_parser_strips_done_sentinel(monkeypatch):
    sse = (
        'data: {"choices":[{"delta":{"content":"help"}}]}\n\n'
        'data: {"choices":[{"delta":{"content":"ful"}}]}\n\n'
        "data: [DONE]\n"
    )
    client = LLMClient("http://fake", "k", "m")

    def fake_post(url, json=None, headers=None, timeout=None):
        return httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    assert client.chat("s", "u") == "helpful"


def test_json_body_with_trailing_done_sentinel(monkeypatch):
    """Live router quirk: content-type says SSE, body is one JSON object then 'data: [DONE]'."""
    body = (
        '{"choices":[{"message":{"content":"OK"},"finish_reason":"stop"}],'
        '"model":"glm-5-3-flash"}\ndata: [DONE]\n'
    )
    client = LLMClient("http://fake", "k", "m")

    def fake_post(url, json=None, headers=None, timeout=None):
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    assert client.chat("s", "u") == "OK"


def test_plain_json_without_sse_headers(monkeypatch):
    body = '{"choices":[{"message":{"content":"plain"}}]}'
    client = LLMClient("http://fake", "k", "m")

    def fake_post(url, json=None, headers=None, timeout=None):
        return httpx.Response(200, text=body, headers={"content-type": "application/json"},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "post", fake_post)
    assert client.chat("s", "u") == "plain"


def test_client_disabled_without_config():
    client = LLMClient("", "", "")
    assert client.enabled is False
    with pytest.raises(LLMUnavailable):
        client.chat("s", "u")


# ---------------------------------------------------------------- investigation
def test_llm_investigate_requires_valid_refs(db):
    app_row = _app(db)
    db.add(HealthCheck(application_id=app_row.id, kind="tcp", target="127.0.0.1:9000",
                       last_result="fail", consecutive_failures=3))
    incident = Incident(application_id=app_row.id, title="down", detected_at=datetime.now(UTC))
    db.add(incident)
    db.commit()

    fake = FakeLLM({
        "root_cause": "DB connection pool exhausted after deploy",
        "confidence": "confirmed",
        "evidence_refs": ["health_check:0", "made:up:ref"],  # one bogus ref
        "recommendation": "Check pool config",
        "reasoning": "fails line up with deploy window",
    })
    verdict = investigation.llm_investigate_incident(db, incident, fake)
    assert verdict is not None
    assert verdict["evidence_refs"] == ["health_check:0"]          # bogus dropped
    assert "made:up:ref" not in verdict["evidence_refs"]
    assert incident.status == IncidentStatus.identified
    assert incident.confidence.value == "confirmed"                # has refs -> kept
    assert incident.identified_at is not None


def test_uncited_claim_downgraded_to_likely(db):
    app_row = _app(db, "app5b")
    incident = Incident(application_id=app_row.id, title="down", detected_at=datetime.now(UTC))
    db.add(incident)
    db.commit()
    fake = FakeLLM({"root_cause": "guess", "confidence": "confirmed", "evidence_refs": []})
    verdict = investigation.llm_investigate_incident(db, incident, fake)
    assert verdict["confidence"] == "likely"       # uncited certainty is never trusted
    assert incident.confidence.value == "likely"


def test_llm_periodic_analysis_creates_ai_finding(db):
    app_row = _app(db, "app5c")
    now = datetime.now(UTC)
    db.add(MetricPoint(application_id=app_row.id, ts=now, err_rate=0.11, p95_ms=400.0))
    db.commit()
    fake = FakeLLM({
        "findings": [{
            "category": "performance", "severity": "warning", "confidence": "likely",
            "title": "Latency drift with error uptick",
            "observation": "p95 and err_rate rose together",
            "probable_cause": "upstream dependency",
            "recommendation": "check dependency latency",
            "evidence_refs": ["metric_sample:0"],
        }]
    })
    created = investigation.llm_periodic_analysis(db, app_row, fake)
    assert len(created) == 1
    assert created[0].rule_key.startswith("llm:")
    assert created[0].evidence
    # same payload twice -> no duplicate (upsert on rule_key)
    again = investigation.llm_periodic_analysis(db, app_row, fake)
    assert again == []


def test_llm_disabled_returns_none(db):
    app_row = _app(db, "app5d")
    incident = Incident(application_id=app_row.id, title="x", detected_at=datetime.now(UTC))
    db.add(incident)
    db.commit()
    assert investigation.llm_investigate_incident(db, incident, FakeLLM({}, enabled=False)) is None
    assert investigation.llm_periodic_analysis(db, app_row, FakeLLM({}, enabled=False)) == []


# ---------------------------------------------------------------- ask agent
def test_ask_agent_grounded_answer_and_audit(db):
    app_row = _app(db, "app5e")
    db.add(HealthCheck(application_id=app_row.id, kind="tcp", target="127.0.0.1:9000",
                       last_result="ok", consecutive_failures=0))
    db.add(Finding(application_id=app_row.id, rule_key="log_error_spike",
                   category="reliability", severity="warning", confidence="likely",
                   title="Error log spike", observation="30 errors", status=FindingStatus.open))
    db.commit()
    fake = FakeLLM({
        "answer": "Errors spiked while health checks stayed green.",
        "confidence": "likely",
        "evidence_refs": ["finding:log_error_spike", "nonexistent:ref"],
        "followups": ["Inspect recent deploy"],
    })
    result = askagent.ask(db, app_row, "Why are there errors?", client=fake)
    assert result["llm"] is True
    assert result["evidence_refs"] == ["finding:log_error_spike"]
    assert result["followups"] == ["Inspect recent deploy"]
    action = db.query(AgentAction).one()
    assert action.action == "ask_agent"
    assert action.reason.startswith("Why are there errors?")


def test_ask_agent_without_llm_reports_facts(db):
    app_row = _app(db, "app5f")
    result = askagent.ask(db, app_row, "Is it healthy?", client=FakeLLM({}, enabled=False))
    assert result["llm"] is False
    assert "degraded" in result["answer"]
    assert result["confidence"] == "confirmed"


def test_context_includes_real_data(db):
    app_row = _app(db, "app5g")
    now = datetime.now(UTC)
    db.add(MetricPoint(application_id=app_row.id, ts=now, err_rate=0.02, p95_ms=150.0))
    db.add(LogBatch(application_id=app_row.id, ts_start=now - timedelta(minutes=5), ts_end=now,
                    level_counts={"ERROR": 7}, sample_lines=["ERROR boom"]))
    db.commit()
    ctx = askagent.build_context(db, app_row)
    assert ctx["metrics"]["samples"], "metric samples must reach the model"
    assert ctx["log_summary_60m"]["ERROR"] == 7
    assert ctx["application"]["ref"] in askagent._refs_of(ctx)


# ---------------------------------------------------------------- api/UI
def test_ask_endpoint_rejects_empty_question(client, db):
    _app(db, "app5h")
    resp = client.post("/api/ask/app5h", json={"question": "  "})
    assert resp.status_code == 422


def test_ask_endpoint_unknown_app_404(client):
    assert client.post("/api/ask/nope", json={"question": "hi"}).status_code == 404


def test_ask_html_fragment_renders(client, db):
    _app(db, "app5i")
    resp = client.post("/api/ask/app5i/html", data={"question": "How healthy is it?"})
    assert resp.status_code == 200
    assert "confidence:" in resp.text


def test_ask_agent_ui_present_on_app_page(client, db):
    _app(db, "app5j")
    page = client.get("/applications/app5j")
    assert "Ask Agent" in page.text
    assert "/api/ask/app5j/html" in page.text
