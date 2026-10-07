"""Container operations (spec §6/§26 RuntimeAdapter seam — docker adapter v1).

Container state + stats land here from the agent's `containers` ingest block.
Docker apps already store runtime detail in workload/runtime_instance rows via
discovery (external_id = compose project, container_id = short id); this module
updates liveness + stashes per-container stats in runtime_instance.cmd-free
JSON via RuntimeInstance raw extension: we keep stats on the workload's
application metric point `raw` (server metrics) — per-container CPU/mem ride
along in metric_point.raw["containers"].
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Application, MetricPoint, RuntimeInstance, Server, Workload


def apply_container_states(db: Session, server: Server, containers: dict) -> dict:
    """Update container liveness + record a container-stats MetricPoint per app."""
    states = containers.get("states") or []
    stats_by_id = {s.get("container_id"): s for s in (containers.get("metrics") or [])}
    now = datetime.now(UTC)

    apps = db.scalars(select(Application).where(Application.server_id == server.id)).all()
    docker_workloads: dict[int, list[Workload]] = {}
    for app_row in apps:
        for workload in app_row.workloads:
            if workload.source == "docker" or workload.kind.value == "container":
                docker_workloads.setdefault(app_row.id, []).append(workload)

    # group states -> app by workload external_id/name match (compose project)
    per_app: dict[int, list[dict]] = {}
    unmatched: list[dict] = []
    for state in states:
        name = state.get("name") or ""
        cid = (state.get("id") or "")[:12]
        placed = False
        for app_id, workloads in docker_workloads.items():
            for workload in workloads:
                ext = workload.external_id or ""
                if name and (name in ext or ext in name or name == workload.name):
                    per_app.setdefault(app_id, []).append({**state, "id": cid})
                    placed = True
                    break
            if placed:
                break
        if not placed and docker_workloads:
            # sole docker app on the server claims it (single-app VMs)
            first = next(iter(docker_workloads))
            if len(docker_workloads) == 1:
                per_app.setdefault(first, []).append({**state, "id": cid})
                placed = True
        if not placed:
            unmatched.append(state)

    updated = 0
    for app_id, app_states in per_app.items():
        running_ids = {s["id"] for s in app_states if s.get("id") and s.get("state") == "running"}
        for workload in docker_workloads.get(app_id, []):
            for instance in db.scalars(
                select(RuntimeInstance).where(RuntimeInstance.workload_id == workload.id)
            ).all():
                if instance.container_id:
                    instance.alive = instance.container_id in running_ids
                    instance.updated_at = now
                    updated += 1
        stats = [stats_by_id.get(s["id"]) for s in app_states if s.get("id")]
        db.add(
            MetricPoint(
                application_id=app_id,
                server_id=server.id,
                ts=now,
                raw={"containers": [s for s in stats if s]},
            )
        )
    return {"updated": updated, "unmatched": len(unmatched), "apps": len(per_app)}
