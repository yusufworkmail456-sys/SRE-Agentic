"""Agent-facing API. Auth = per-server bearer token; every endpoint is agent-scoped."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import AgentAction, Server
from ..security import agent_server, new_agent_token, hash_token
from ..services import apply_discovery, apply_health_checks, apply_server_metrics

router = APIRouter(prefix="/api/agent/v1", tags=["agent"])


class RegisterRequest(BaseModel):
    hostname: str
    agent_version: str | None = None
    capabilities: dict = Field(default_factory=dict)


class RegisterResponse(BaseModel):
    server_id: int
    min_interval_s: int
    issued_token: str | None = None


@router.post("/register", response_model=RegisterResponse)
def register(
    req: RegisterRequest,
    db: Session = Depends(get_db),
    authorization: str | None = Header(default=None),
):
    """Unauthenticated register = bootstrap (or re-bootstrap) and issues a fresh
    token. Authenticated register = identity refresh, no reissue. The token then
    gates everything else (ingest, poll, results)."""
    server = db.scalar(select(Server).where(Server.hostname == req.hostname))
    issued = None
    if server is None:
        issued = new_agent_token()
        server = Server(
            hostname=req.hostname,
            agent_version=req.agent_version,
            token_hash=hash_token(issued),
            capabilities=req.capabilities,
        )
        db.add(server)
    elif not authorization:
        # Re-bootstrap: existing server row but the agent lost its token.
        issued = new_agent_token()
        server.token_hash = hash_token(issued)
    else:
        server.agent_version = req.agent_version or server.agent_version
        server.capabilities = req.capabilities or server.capabilities
    server.last_seen = datetime.now(UTC)
    db.commit()
    return RegisterResponse(server_id=server.id, min_interval_s=30, issued_token=issued)


class IngestRequest(BaseModel):
    server_id: int | None = None
    ts: float | None = None
    discovery: list[dict] | None = None
    metrics: dict | None = None
    red: list[dict] | None = None
    health_checks: list[dict] | None = None
    logs: list[dict] | None = None
    containers: dict | None = None  # {"metrics": [...], "states": [...]}


@router.post("/ingest")
def ingest(
    req: IngestRequest,
    server: Server = Depends(agent_server),
    db: Session = Depends(get_db),
):
    result: dict = {"server_id": server.id}
    if req.discovery is not None:
        result["discovery"] = apply_discovery(db, server, req.discovery)
    if req.health_checks:
        result["health_checks"] = apply_health_checks(db, server, req.health_checks)
    if req.metrics:
        apply_server_metrics(db, server, req.metrics)
        from ..metrics import store_server_metrics, store_app_red

        store_server_metrics(db, server, req.metrics)
    if req.red:
        from ..metrics import store_app_red

        result["red_stored"] = store_app_red(db, server, req.red)
    if req.logs:
        from ..logstore import store_log_batches

        result["logs_stored"] = store_log_batches(db, server, req.logs)
    if req.containers:
        from ..containerops import apply_container_states

        result["containers"] = apply_container_states(db, server, req.containers)
    db.commit()
    return result


@router.post("/actions/poll")
def poll_actions(server: Server = Depends(agent_server), db: Session = Depends(get_db)):
    """Only approved, unexpired, allowlisted actions ever leave this endpoint."""
    now = datetime.now(UTC)
    pending = db.scalars(
        select(AgentAction).where(
            AgentAction.server_id == server.id, AgentAction.status == "approved"
        )
    ).all()
    actions = []
    for action in pending:
        approval = action.approval or {}
        expires = approval.get("expires_at")
        if expires:
            try:
                if datetime.fromisoformat(expires) < now:
                    action.status = "expired"
                    continue
            except ValueError:
                action.status = "expired"
                continue
        actions.append(
            {
                "id": action.id,
                "action": action.action,
                "target": action.target,
                "nonce": approval.get("nonce"),
            }
        )
    db.commit()
    return {"actions": actions, "min_interval_s": 30}


class ActionResult(BaseModel):
    status: str = "done"
    exit_code: int | None = None
    stdout: str | None = None
    duration_s: float | None = None


@router.post("/actions/{action_id}/result")
def action_result(
    action_id: int,
    res: ActionResult,
    server: Server = Depends(agent_server),
    db: Session = Depends(get_db),
):
    action = db.get(AgentAction, action_id)
    if action is None or action.server_id != server.id:
        return {"ok": False, "reason": "unknown action"}
    action.status = res.status
    action.result = res.model_dump()
    action.finished_at = datetime.now(UTC)
    db.commit()
    return {"ok": True}


@router.get("/config")
def agent_config(server: Server = Depends(agent_server), db: Session = Depends(get_db)):
    """Effective agent config + the HTTP health-check URLs registered for this
    server's apps (agent probes them every cycle — §7 HTTP probe)."""
    from ..models import Application, HealthCheck

    urls: list[str] = []
    apps = db.scalars(select(Application).where(Application.server_id == server.id)).all()
    for app_row in apps:
        for check in app_row.health_checks:
            if check.kind == "http" and check.enabled and check.target not in urls:
                urls.append(check.target)
    return {
        "collect_interval_s": 30,
        "discovery_interval_s": 300,
        "allow_exec": bool((server.capabilities or {}).get("exec")),
        "min_interval_s": 30,
        "http_health_targets": urls,
    }
