"""API for M9/M10 features: dependencies, topology, CI, deploy, DORA, forecast.

All mutating endpoints sit behind RBAC and (for deploy) an approved AgentAction,
same gateway pattern as remediation (spec §17/§18).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import ciwatch, deps, dora
from ..db import get_db
from ..deployer import (
    DeployError,
    execute_deploy,
    execute_rollback,
    record_deployment,
    regression_check,
)
from ..models import (
    AgentAction,
    Actor,
    Application,
    Dependency,
    Deployment,
    RiskLevel,
    TimelineEvent,
)
from ..security import require_role

router = APIRouter(prefix="/api", tags=["ops"])


def _get_app(db: Session, slug: str) -> Application:
    app_row = db.scalar(select(Application).where(Application.slug == slug))
    if app_row is None:
        raise HTTPException(404, "application not found")
    return app_row


# ---------------------------------------------------------------- dependencies
class DependencyRequest(BaseModel):
    name: str
    kind: str = "api"  # db / cache / queue / api / service
    criticality: str = "medium"  # low / medium / high / critical
    target_slug: str | None = None
    host: str | None = None
    port: int | None = None


@router.get("/apps/{slug}/dependencies")
def list_dependencies(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    out = []
    for dep in app_row.dependencies:
        probe = (dep.details or {}).get("last_probe")
        out.append({
            "id": dep.id, "name": dep.name, "kind": dep.kind,
            "criticality": dep.criticality,
            "target_app_id": dep.target_application_id,
            "last_probe": probe,
        })
    return out


@router.post("/apps/{slug}/dependencies", status_code=201)
def add_dependency(slug: str, req: DependencyRequest, db: Session = Depends(get_db),
                   _user=Depends(require_role("responder"))):
    app_row = _get_app(db, slug)
    target_id = None
    if req.target_slug:
        target = db.scalar(select(Application).where(Application.slug == req.target_slug))
        if target is None:
            raise HTTPException(404, "target application not found")
        target_id = target.id
    dep = Dependency(
        application_id=app_row.id,
        target_application_id=target_id,
        name=req.name[:255],
        kind=req.kind,
        criticality=req.criticality,
        details={"host": req.host, "port": req.port},
    )
    db.add(dep)
    db.commit()
    return {"id": dep.id, "name": dep.name}


@router.post("/apps/{slug}/dependencies/probe")
def probe_dependencies(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    probed = deps.probe_all_for_app(db, app_row)
    db.commit()
    return {"probed": probed}


@router.get("/topology")
def topology(db: Session = Depends(get_db)):
    return deps.topology_for_apps(db)


# ---------------------------------------------------------------- CI watch
@router.post("/apps/{slug}/ci/watch")
def ci_watch(slug: str, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    from ..models import Repository

    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    if repo is None:
        raise HTTPException(409, "no repository linked")
    result = ciwatch.watch_repo_ci(db, repo)
    db.commit()
    return result


# ---------------------------------------------------------------- deployments
class DeployRecordRequest(BaseModel):
    sha: str | None = None
    branch: str | None = None
    message: str | None = None
    method: str = "manual"


@router.post("/apps/{slug}/deployments", status_code=201)
def record_deploy(slug: str, req: DeployRecordRequest, db: Session = Depends(get_db),
                  _user=Depends(require_role("responder"))):
    app_row = _get_app(db, slug)
    from ..models import Repository

    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    deployment = record_deployment(
        db, app_row, sha=req.sha, branch=req.branch, message=req.message,
        method=req.method, repository_id=repo.id if repo else None,
    )
    db.commit()
    return {"id": deployment.id, "sha": deployment.sha}


@router.post("/deployments/{deployment_id}/regression-check")
def run_regression_check(deployment_id: int, db: Session = Depends(get_db)):
    deployment = db.get(Deployment, deployment_id)
    if deployment is None:
        raise HTTPException(404, "deployment not found")
    result = regression_check(db, deployment)
    db.commit()
    return result


class DeployExecuteRequest(BaseModel):
    service_target: str = Field(description="systemd unit to restart, e.g. myapp.service")
    workdir: str | None = None
    restart_only: bool = False


@router.post("/apps/{slug}/deploy")
def deploy_now(slug: str, req: DeployExecuteRequest, db: Session = Depends(get_db),
               _user=Depends(require_role("responder"))):
    """Stage an agent-executed deploy: creates the approved-pending action.

    The actual pull+restart runs on the app server via the agent executor
    (poll-based). Risk=high -> approval required even at autonomy L3 (§27).
    """
    app_row = _get_app(db, slug)
    if not req.service_target or any(
        ch in req.service_target for ch in " ;|&$`\n"
    ):
        raise HTTPException(422, "unsafe service target")
    action = AgentAction(
        application_id=app_row.id,
        actor=Actor.user,
        actor_name="ui",
        action="deploy_service",
        target=req.service_target,
        reason=f"deploy requested for {app_row.name}",
        risk=RiskLevel.high,
        status="proposed",
    )
    db.add(action)
    db.add(TimelineEvent(
        application_id=app_row.id, kind="deployment", actor="user",
        summary=f"Deploy staged for {req.service_target} — approval required",
    ))
    db.commit()
    return {
        "action_id": action.id, "status": "proposed", "risk": "high",
        "next": f"approve via remediation gateway, agent picks it up on next poll",
        "note": "agent-side allowlist must contain deploy_service/restart_service",
    }


@router.post("/deployments/{deployment_id}/rollback")
def rollback(deployment_id: int, db: Session = Depends(get_db),
             _user=Depends(require_role("responder"))):
    deployment = db.get(Deployment, deployment_id)
    if deployment is None:
        raise HTTPException(404, "deployment not found")
    app_row = db.get(Application, deployment.application_id)
    action = AgentAction(
        application_id=deployment.application_id,
        actor=Actor.user,
        actor_name="ui",
        action="rollback_deployment",
        target=f"deployment:{deployment.id}",
        reason=f"rollback of {(deployment.sha or 'n/a')[:8]}",
        risk=RiskLevel.high,
        status="proposed",
    )
    db.add(action)
    try:
        result = execute_rollback(
            db, deployment, service_target=app_row.name if app_row else "?",
            approved_action=action,
        )
    except DeployError as exc:
        db.rollback()
        raise HTTPException(409, str(exc)) from exc
    db.commit()
    return result


# ---------------------------------------------------------------- DORA
@router.get("/apps/{slug}/dora")
def app_dora(slug: str, days: int = 30, db: Session = Depends(get_db)):
    app_row = _get_app(db, slug)
    return dora.dora_for_app(db, app_row.id, days)


@router.get("/dora")
def fleet_dora(days: int = 30, db: Session = Depends(get_db)):
    return dora.dora_fleet(db, days)
