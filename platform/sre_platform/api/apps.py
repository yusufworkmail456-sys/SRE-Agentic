"""Application + fleet API: manual registration, confirmation, token lifecycle."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import (
    Application,
    DeploymentModel,
    DiscoverySource,
    HealthCheck,
    Repository,
    Server,
)
from ..security import agent_server as _unused  # noqa: F401  (keeps import graph explicit)
from ..security import new_agent_token, hash_token, require_role
from ..services import confirm_application, slugify, touch_timeline, unique_slug

router = APIRouter(prefix="/api", tags=["apps"])


class ManualAppRequest(BaseModel):
    name: str
    environment: str = "prod"
    description: str | None = None
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    deployment_model: DeploymentModel = DeploymentModel.unknown
    runtime: str | None = None
    server_id: int | None = None
    path: str | None = None
    port: int | None = None
    domain: str | None = None
    health_check_url: str | None = None
    repository_url: str | None = None
    branch: str = "main"
    deployment_method: str | None = None
    dependencies: list[dict] = Field(default_factory=list)


@router.get("/apps")
def list_apps(include_unconfirmed: bool = True, db: Session = Depends(get_db)):
    stmt = select(Application).order_by(Application.name)
    apps = db.scalars(stmt).all()
    if not include_unconfirmed:
        apps = [a for a in apps if a.confirmed]
    return [
        {
            "id": a.id,
            "name": a.name,
            "slug": a.slug,
            "environment": a.environment,
            "status": a.status.value,
            "deployment_model": a.deployment_model.value,
            "discovery": a.discovery.value,
            "confirmed": a.confirmed,
            "server": a.server.hostname if a.server else None,
        }
        for a in apps
    ]


@router.post("/apps", status_code=201)
def register_app(req: ManualAppRequest, db: Session = Depends(get_db), _user=Depends(require_role("responder"))):
    """Manual registration — produces the same Application entity as discovery (§5)."""
    if req.server_id is not None and db.get(Server, req.server_id) is None:
        raise HTTPException(404, "server not found")
    app_row = Application(
        name=req.name,
        slug=unique_slug(db, slugify(req.name)),
        environment=req.environment,
        description=req.description,
        owner=req.owner,
        tags=req.tags,
        deployment_model=req.deployment_model,
        discovery=DiscoverySource.manual,
        confirmed=True,
        server_id=req.server_id,
    )
    db.add(app_row)
    db.flush()
    if req.path:
        from ..models import RuntimeInstance, Workload, WorkloadKind

        workload = Workload(
            application_id=app_row.id,
            kind=WorkloadKind.process,
            name=req.name,
            runtime=req.runtime,
            source=req.deployment_method or "manual",
            external_id=req.path,
        )
        db.add(workload)
        db.flush()
        if req.port:
            db.add(
                RuntimeInstance(
                    workload_id=workload.id, cwd=req.path, listen_port=req.port, user=None
                )
            )
    if req.domain:
        from ..models import Endpoint

        url = req.domain if req.domain.startswith("http") else f"https://{req.domain}"
        db.add(Endpoint(application_id=app_row.id, url=url, domain=req.domain))
    if req.health_check_url:
        db.add(
            HealthCheck(
                application_id=app_row.id,
                kind="http" if req.health_check_url.startswith("http") else "tcp",
                target=req.health_check_url,
                interval_s=30,
            )
        )
    if req.repository_url:
        db.add(
            Repository(
                application_id=app_row.id,
                url=req.repository_url,
                default_branch=req.branch,
            )
        )
    for dep in req.dependencies:
        from ..models import Dependency

        db.add(
            Dependency(
                application_id=app_row.id,
                name=dep.get("name", "unknown"),
                kind=dep.get("kind", "api"),
                criticality=dep.get("criticality", "medium"),
                details=dep,
            )
        )
    touch_timeline(db, app_row.id, "discovery", "Application registered manually", actor="user")
    db.commit()
    return {"id": app_row.id, "slug": app_row.slug}


@router.get("/apps/{slug}")
def get_app(slug: str, db: Session = Depends(get_db)):
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    return {
        "id": app_row.id,
        "name": app_row.name,
        "slug": app_row.slug,
        "environment": app_row.environment,
        "status": app_row.status.value,
        "confirmed": app_row.confirmed,
        "deployment_model": app_row.deployment_model.value,
        "discovery": app_row.discovery.value,
        "fingerprint": app_row.auto_discovery_fingerprint,
        "workloads": [
            {
                "id": w.id,
                "name": w.name,
                "kind": w.kind.value,
                "runtime": w.runtime,
                "source": w.source,
                "instances": [
                    {
                        "pid": i.pid,
                        "cwd": i.cwd,
                        "cmd": i.cmd,
                        "user": i.user,
                        "listen_port": i.listen_port,
                        "alive": i.alive,
                    }
                    for i in w.instances
                ],
            }
            for w in app_row.workloads
        ],
        "endpoints": [
            {"url": e.url, "domain": e.domain, "upstream": e.upstream} for e in app_row.endpoints
        ],
        "health_checks": [
            {
                "kind": h.kind,
                "target": h.target,
                "last_result": h.last_result,
                "consecutive_failures": h.consecutive_failures,
            }
            for h in app_row.health_checks
        ],
    }


class ConfirmRequest(BaseModel):
    name: str | None = None
    environment: str | None = None
    owner: str | None = None
    description: str | None = None
    health_check_url: str | None = None


@router.post("/apps/{slug}/confirm")
def confirm(slug: str, req: ConfirmRequest, db: Session = Depends(get_db), _user=Depends(require_role("responder"))):
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    if req.name and req.name != app_row.name:
        new_base = slugify(req.name)
        if new_base != app_row.slug:  # keep slug when unchanged, avoid -2 suffix
            app_row.slug = unique_slug(db, new_base)
        app_row.name = req.name
    if req.health_check_url:
        db.add(
            HealthCheck(
                application_id=app_row.id,
                kind="http" if req.health_check_url.startswith("http") else "tcp",
                target=req.health_check_url,
                interval_s=30,
            )
        )
    confirm_application(
        db,
        app_row,
        environment=req.environment,
        owner=req.owner,
        description=req.description,
    )
    db.commit()
    return {"ok": True, "slug": app_row.slug, "confirmed": True}


@router.get("/servers")
def list_servers(db: Session = Depends(get_db)):
    return [
        {
            "id": s.id,
            "hostname": s.hostname,
            "agent_version": s.agent_version,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            "capabilities": s.capabilities,
            "apps": len(s.applications),
        }
        for s in db.scalars(select(Server)).all()
    ]


@router.post("/servers/{server_id}/rotate-token")
def rotate_token(server_id: int, db: Session = Depends(get_db), _user=Depends(require_role("admin"))):
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(404, "server not found")
    token = new_agent_token()
    server.token_hash = hash_token(token)
    db.commit()
    return {"server_id": server_id, "token": token}
