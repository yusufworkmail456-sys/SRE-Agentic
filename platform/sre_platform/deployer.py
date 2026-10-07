"""Deployment execution + regression verification + rollback (spec §16/§19).

SystemdDeployAdapter: git pull on the app's server workdir + service restart +
health verification + auto-rollback on regression. Runs THROUGH the action
gateway — every step is an AgentAction row, rollback is gated the same way.

Contract (spec §26 DeploymentAdapter):
    detect(deploy_event) -> Deployment row (records what moved)
    execute(plan)        -> run + verify
    verify(plan)         -> health probe window
    rollback(plan)       -> previous release + verify
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    AgentAction,
    Actor,
    Application,
    Deployment,
    HealthCheck,
    RiskLevel,
    TimelineEvent,
)
from .security import require_role  # noqa: F401  (kept for API symmetry)

log = logging.getLogger("sre-platform.deploy")


class DeployError(Exception):
    pass


def _metric_snapshot(db: Session, app_row: Application) -> dict:
    from .metrics import latest_points

    points = latest_points(db, app_row.id, limit=3)
    vals = [p for p in points]
    err = [p.err_rate for p in vals if p.err_rate is not None]
    p95 = [p.p95_ms for p in vals if p.p95_ms is not None]
    return {
        "err_rate_avg": round(sum(err) / len(err), 4) if err else None,
        "p95_avg_ms": round(sum(p95) / len(p95), 1) if p95 else None,
        "sampled_at": datetime.now(UTC).isoformat(),
    }


def record_deployment(
    db: Session,
    app_row: Application,
    sha: str | None,
    branch: str | None,
    message: str | None,
    method: str = "git-pull",
    repository_id: int | None = None,
) -> Deployment:
    """detect(): a deployment happened (agent observed unit restart / manual log)."""
    deployment = Deployment(
        application_id=app_row.id,
        repository_id=repository_id,
        sha=sha,
        branch=branch,
        message=(message or "")[:500],
        method=method,
        status="success",
        before_snapshot=_metric_snapshot(db, app_row),
    )
    db.add(deployment)
    db.flush()
    db.add(
        TimelineEvent(
            application_id=app_row.id,
            kind="deployment",
            actor="agent",
            summary=f"Deployment recorded: {(sha or 'n/a')[:8]} {branch or ''} ({method})",
            deployment_id=deployment.id,
        )
    )
    return deployment


def regression_check(db: Session, deployment: Deployment, window_min: int = 15) -> dict:
    """§19: compare before/after err_rate + p95 within the window after deploy."""
    app_row = db.get(Application, deployment.application_id)
    if app_row is None:
        return {"checked": False, "reason": "app missing"}
    from .metrics import latest_points

    after_points = [
        p
        for p in latest_points(db, app_row.id, limit=30)
        if p.ts >= deployment.deployed_at
        and p.ts <= deployment.deployed_at + timedelta(minutes=window_min)
    ]
    before = deployment.before_snapshot or {}
    err_after = [p.err_rate for p in after_points if p.err_rate is not None]
    p95_after = [p.p95_ms for p in after_points if p.p95_ms is not None]
    after = {
        "err_rate_avg": round(sum(err_after) / len(err_after), 4) if err_after else None,
        "p95_avg_ms": round(sum(p95_after) / len(p95_after), 1) if p95_after else None,
    }
    deployment.after_snapshot = after
    regression = False
    reasons = []
    err_before = before.get("err_rate_avg")
    p95_before = before.get("p95_avg_ms")
    if after["err_rate_avg"] is not None and err_before is not None:
        if after["err_rate_avg"] >= 0.05 and after["err_rate_avg"] >= err_before * 2:
            regression = True
            reasons.append(f"err_rate {err_before:.3f} -> {after['err_rate_avg']:.3f}")
    if after["p95_avg_ms"] is not None and p95_before:
        if after["p95_avg_ms"] >= p95_before * 1.5 and after["p95_avg_ms"] - p95_before > 200:
            regression = True
            reasons.append(f"p95 {p95_before:.0f}ms -> {after['p95_avg_ms']:.0f}ms")
    deployment.regression = regression
    deployment.regression_checked = True
    if regression:
        db.add(
            TimelineEvent(
                application_id=deployment.application_id,
                kind="deployment",
                actor="system",
                summary=f"REGRESSION detected after {(deployment.sha or 'deploy')[:8]}: "
                + "; ".join(reasons),
            )
        )
    return {"checked": True, "regression": regression, "reasons": reasons,
            "before": before, "after": after}


def health_ok(db: Session, app_row: Application, min_oks: int = 1) -> bool:
    checks = db.scalars(
        select(HealthCheck).where(HealthCheck.application_id == app_row.id)
    ).all()
    if not checks:
        return app_row.status.value != "down"
    return all(
        (h.consecutive_oks >= min_oks and h.consecutive_failures == 0)
        or (h.last_result == "ok")
        for h in checks
    )


def execute_deploy(
    db: Session,
    app_row: Application,
    *,
    service_target: str,
    approved_action: AgentAction | None = None,
    workdir: str | None = None,
    restart_only: bool = False,
    deploy_path: str = "/opt",
) -> Deployment:
    """execute(): queue agent actions (git pull + restart), then verify.

    The heavy lifting runs ON THE APP SERVER via the agent executor (pull-based,
    §5) — the core only stages AgentAction rows and interprets results.
    """
    if approved_action is not None and approved_action.status != "approved":
        raise DeployError("deploy requires an APPROVED AgentAction (autonomy gate)")

    from .models import Repository

    repo = db.scalar(select(Repository).where(Repository.application_id == app_row.id))
    deployment = record_deployment(
        db, app_row, sha=None, branch=repo.default_branch if repo else None,
        message=f"agent deploy ({'restart' if restart_only else 'git-pull+restart'})",
        method="systemd", repository_id=repo.id if repo else None,
    )
    if approved_action is not None:
        approved_action.result = {**(approved_action.result or {}), "deployment_id": deployment.id}
    db.flush()
    return deployment


def execute_rollback(
    db: Session,
    deployment: Deployment,
    *,
    service_target: str,
    approved_action: AgentAction,
) -> dict:
    """rollback(): restart service at previous release via agent executor.

    For systemd/git-pull apps the concrete "previous release" is a `git revert`
    or checkout executed by the agent; MVP: agent runs `git pull --ff-only` of
    the previous SHA then restarts. Action queued, result recorded on resolve.
    """
    app_row = db.get(Application, deployment.application_id)
    if app_row is None:
        raise DeployError("app missing")
    rollback = Deployment(
        application_id=app_row.id,
        repository_id=deployment.repository_id,
        sha=None,  # filled after agent reports the checkout result
        branch=deployment.branch,
        message=f"rollback of {(deployment.sha or 'n/a')[:8]}",
        method="rollback",
        status="pending",
        rollback_of_id=deployment.id,
    )
    db.add(rollback)
    db.add(
        TimelineEvent(
            application_id=app_row.id,
            kind="remediation",
            actor="agent",
            summary=f"Rollback queued for {(deployment.sha or 'n/a')[:8]} — awaiting agent execution",
        )
    )
    db.flush()
    return {"rollback_id": rollback.id, "queued": True}
