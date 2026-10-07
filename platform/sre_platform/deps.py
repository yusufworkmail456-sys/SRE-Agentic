"""Dependency observability (spec §10): probes + dep-down detection.

Probes are cheap TCP dials executed by the CORE (dependencies may live on other
servers; the agent only sees its own VM). Results land on dependency.details.
"""
from __future__ import annotations

import socket
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .detection import _resolve_if_recovered, _upsert_finding
from .models import (
    Application,
    Confidence,
    Dependency,
    FindingCategory,
    RuntimeInstance,
    Severity,
    Workload,
)


def _host_port(db: Session, dep: Dependency) -> tuple[str, int] | None:
    """Extract host/port from details {'host','port'} or from the target app's instance."""
    details = dep.details or {}
    host, port = details.get("host"), details.get("port")
    if host and port:
        try:
            return str(host), int(port)
        except (TypeError, ValueError):
            return None
    if dep.target_application_id:
        inst = (
            db.scalars(
                select(RuntimeInstance)
                .where(
                    RuntimeInstance.workload_id.in_(
                        select(Workload.id).where(
                            Workload.application_id == dep.target_application_id
                        )
                    ),
                    RuntimeInstance.listen_port.is_not(None),
                )
            ).first()
        )
        if inst is not None and inst.listen_port:
            return "127.0.0.1", inst.listen_port
    return None


def probe_dependency(dep: Dependency, host_port: tuple[str, int] | None, timeout: float = 2.0) -> dict:
    """One TCP dial. Returns probe result dict (never raises)."""
    if host_port is None:
        return {"ok": None, "reason": "no host/port configured", "ts": datetime.now(UTC).isoformat()}
    host, port = host_port
    started = datetime.now(UTC)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return {"ok": True, "host": host, "port": port, "ts": started.isoformat()}
    except OSError as exc:
        return {
            "ok": False, "host": host, "port": port, "error": str(exc)[:120],
            "ts": started.isoformat(),
        }


def probe_all_for_app(db: Session, app_row: Application) -> int:
    """Probe each dependency; upsert a dep_down finding when criticality high/critical."""
    probed = 0
    for dep in db.scalars(
        select(Dependency).where(Dependency.application_id == app_row.id)
    ).all():
        result = probe_dependency(dep, _host_port(db, dep))
        probed += 1
        details = dict(dep.details or {})
        details["last_probe"] = result
        dep.details = details
        if result["ok"] is False and dep.criticality in ("high", "critical"):
            _upsert_finding(
                db, app_row, f"dep_down:{dep.id}",
                {
                    "category": FindingCategory.reliability,
                    "severity": Severity.critical if dep.criticality == "critical" else Severity.warning,
                    "confidence": Confidence.confirmed,
                    "title": f"Dependency unreachable: {dep.name}",
                    "observation": (
                        f"{dep.kind} dependency {dep.name} at {result.get('host')}:{result.get('port')} "
                        f"failed: {result.get('error', 'connection refused')}"
                    ),
                    "probable_cause": "Dependency process down, network/ACL change, or wrong address.",
                    "recommendation": f"Verify {dep.name} is running; check connection config and firewall.",
                    "evidence": [{"source": "dependency_probe", "ref": f"dependency:{dep.id}",
                                  "value": result}],
                },
            )
        elif result["ok"] is True:
            _resolve_if_recovered(db, app_row, f"dep_down:{dep.id}")
    return probed


def topology_for_apps(db: Session) -> dict:
    """Node+edge graph for the topology view (spec §10 service map)."""
    apps = db.scalars(select(Application)).all()
    nodes = [
        {
            "id": a.id, "name": a.name, "slug": a.slug, "status": a.status.value,
            "environment": a.environment, "model": a.deployment_model.value,
            "confirmed": a.confirmed,
        }
        for a in apps
    ]
    edges = [
        {
            "from": dep.application_id,
            "to": dep.target_application_id,  # None = external dependency
            "external": dep.target_application_id is None,
            "name": dep.name,
            "kind": dep.kind,
            "criticality": dep.criticality,
            "last_probe": (dep.details or {}).get("last_probe"),
        }
        for dep in db.scalars(select(Dependency)).all()
    ]
    return {"nodes": nodes, "edges": edges, "app_names": {a.id: a.name for a in apps}}
