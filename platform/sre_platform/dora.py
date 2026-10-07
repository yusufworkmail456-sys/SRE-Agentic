"""DORA metrics (spec §22): pure aggregation over deployment + incident rows.

- deployment_frequency: deploys / day over the window
- lead_time_cfp: median minutes commit -> deploy (commit timestamp from repo
  index when the SHA is known; falls back to None when unindexed)
- change_failure_rate: deploys with regression / total deploys
- mttr: mean incident mttr_s over the window
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Application, Commit, Deployment, Incident, Repository


def dora_for_app(db: Session, app_id: int, days: int = 30) -> dict:
    now = datetime.now(UTC)
    since = now - timedelta(days=days)
    deploys = db.scalars(
        select(Deployment)
        .where(Deployment.application_id == app_id, Deployment.deployed_at >= since)
        .order_by(Deployment.deployed_at)
    ).all()
    incidents = db.scalars(
        select(Incident).where(
            Incident.application_id == app_id,
            Incident.resolved_at.is_not(None),
            Incident.resolved_at >= since,
        )
    ).all()

    freq = len(deploys) / days
    total = len(deploys)
    failed = sum(1 for d in deploys if d.regression)
    cfr = (failed / total) if total else None
    mttrs = [i.mttr_s for i in incidents if i.mttr_s is not None]
    mttr_avg = round(sum(mttrs) / len(mttrs), 1) if mttrs else None

    lead_minutes: list[float] = []
    repo = db.scalar(select(Repository).where(Repository.application_id == app_id))
    if repo is not None and deploys:
        shas = {d.sha for d in deploys if d.sha}
        commits = {
            c.sha: c.committed_at
            for c in db.scalars(select(Commit).where(Commit.repository_id == repo.id)).all()
            if c.sha in shas and c.committed_at
        }
        for d in deploys:
            committed = commits.get(d.sha or "")
            if committed:
                committed = committed.replace(tzinfo=UTC) if committed.tzinfo is None else committed
                deployed = d.deployed_at.replace(tzinfo=UTC) if d.deployed_at.tzinfo is None else d.deployed_at
                lead = (deployed - committed).total_seconds() / 60
                if 0 <= lead < 60 * 24 * 14:  # sane window, drop clock-skew outliers
                    lead_minutes.append(lead)
    lead_minutes.sort()
    lead_median = (
        round(lead_minutes[len(lead_minutes) // 2], 1) if lead_minutes else None
    )

    return {
        "window_days": days,
        "deployments": total,
        "deployment_frequency_per_day": round(freq, 3),
        "change_failure_rate": round(cfr, 4) if cfr is not None else None,
        "failed_deployments": failed,
        "lead_time_median_min": lead_median,
        "mttr_avg_s": mttr_avg,
        "incidents_resolved": len(incidents),
    }


def dora_fleet(db: Session, days: int = 30) -> list[dict]:
    apps = db.scalars(select(Application).where(Application.confirmed == True)).all()  # noqa: E712
    out = []
    for app_row in apps:
        stats = dora_for_app(db, app_row.id, days)
        if stats["deployments"] or stats["incidents_resolved"]:
            out.append({"app": app_row.name, "slug": app_row.slug, **stats})
    return out
