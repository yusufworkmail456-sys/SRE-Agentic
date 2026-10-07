"""Discovery matching + ingest processing (spec §4.1, §5 convergence).

Rule: automatic discovery and manual registration produce the SAME Application
entity. A fingerprint either (a) already maps to an app, (b) matches an app's
recorded fingerprint, or (c) creates a new *unconfirmed* candidate. Unconfirmed
candidates never alert — they wait for a human (or a manual app) to claim them.
"""
from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    AppStatus,
    Application,
    DeploymentModel,
    DiscoverySource,
    Endpoint,
    HealthCheck,
    RuntimeInstance,
    Server,
    TimelineEvent,
    Workload,
    WorkloadKind,
)

KIND_BY_SOURCE = {
    "systemd": WorkloadKind.service,
    "process": WorkloadKind.process,
    "docker": WorkloadKind.container,
    "k8s": WorkloadKind.pod,
}
MODEL_BY_SOURCE = {
    "systemd": DeploymentModel.process,
    "process": DeploymentModel.process,
    "docker": DeploymentModel.compose,
    "k8s": DeploymentModel.k8s,
}
HEALTH_FAIL_THRESHOLD = 3
HEALTH_OK_THRESHOLD = 2


def slugify(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")
    return slug or "app"


def unique_slug(db: Session, base: str) -> str:
    slug, n = base, 2
    while db.scalar(select(Application.id).where(Application.slug == slug)):
        slug, n = f"{base}-{n}", n + 1
    return slug


def touch_timeline(db: Session, app_id: int | None, kind: str, summary: str, **payload) -> None:
    db.add(
        TimelineEvent(
            application_id=app_id, kind=kind, actor=payload.pop("actor", "system"),
            summary=summary, payload=payload,
        )
    )


def _app_for_fingerprint(db: Session, fp: dict) -> Application | None:
    key = fp.get("key")
    if not key:
        return None
    for candidate in db.scalars(
        select(Application).where(Application.auto_discovery_fingerprint.is_not(None))
    ):
        stored = candidate.auto_discovery_fingerprint or {}
        if stored.get("key") == key:
            return candidate
    return None


def _candidate_for(db: Session, fp: dict, server: Server) -> Application:
    name = fp.get("name") or fp.get("key") or "unknown"
    app_row = Application(
        name=name,
        slug=unique_slug(db, slugify(name)),
        environment="prod",
        deployment_model=MODEL_BY_SOURCE.get(fp.get("source", "process"), DeploymentModel.unknown),
        discovery=DiscoverySource.auto,
        confirmed=False,
        status=AppStatus.unknown,
        server_id=server.id,
        auto_discovery_fingerprint={"key": fp.get("key"), "source": fp.get("source")},
        description=f"Auto-discovered on {server.hostname} ({fp.get('source')})",
    )
    db.add(app_row)
    db.flush()
    touch_timeline(
        db, app_row.id, "discovery", f"Discovered {name} via {fp.get('source')}", fp=fp.get("key")
    )
    return app_row


def _sync_workload(db: Session, app_row: Application, fp: dict) -> Workload:
    ext = fp.get("external_id") or fp.get("cwd") or fp.get("key")
    workload = db.scalar(
        select(Workload).where(Workload.application_id == app_row.id, Workload.external_id == ext)
    )
    if workload is None:
        workload = Workload(
            application_id=app_row.id,
            kind=KIND_BY_SOURCE.get(fp.get("source", "process"), WorkloadKind.process),
            name=fp.get("name") or ext or "workload",
            runtime=fp.get("runtime"),
            source=fp.get("source"),
            external_id=ext,
        )
        db.add(workload)
        db.flush()
    else:
        workload.runtime = fp.get("runtime") or workload.runtime

    ports = fp.get("ports") or []
    instance = db.scalar(
        select(RuntimeInstance).where(
            RuntimeInstance.workload_id == workload.id, RuntimeInstance.pid == fp.get("pid")
        )
    )
    if instance is None:
        instance = RuntimeInstance(workload_id=workload.id, pid=fp.get("pid"))
        db.add(instance)
    instance.cmd = fp.get("cmd")
    instance.cwd = fp.get("cwd")
    instance.user = fp.get("user")
    instance.listen_port = ports[0] if ports else instance.listen_port
    instance.listen_addr = "0.0.0.0" if ports else instance.listen_addr
    instance.alive = True
    return workload


def _sync_endpoints(db: Session, app_row: Application, fp: dict) -> None:
    for vh in fp.get("vhosts") or []:
        url = f"https://{vh['server_name']}" if vh.get("ssl_cert") else f"http://{vh['server_name']}"
        existing = db.scalar(
            select(Endpoint).where(Endpoint.application_id == app_row.id, Endpoint.url == url)
        )
        if existing is None:
            db.add(
                Endpoint(
                    application_id=app_row.id,
                    kind="http",
                    url=url,
                    domain=vh.get("server_name"),
                    vhost=vh.get("server_name"),
                    upstream=vh.get("upstream"),
                )
            )
    for port in fp.get("ports") or []:
        existing = db.scalar(
            select(HealthCheck).where(
                HealthCheck.application_id == app_row.id, HealthCheck.target == f"127.0.0.1:{port}"
            )
        )
        if existing is None:
            db.add(
                HealthCheck(
                    application_id=app_row.id, kind="tcp", target=f"127.0.0.1:{port}", interval_s=30
                )
            )


def apply_discovery(db: Session, server: Server, fingerprints: list[dict]) -> dict:
    created, matched = 0, 0
    for fp in fingerprints:
        app_row = _app_for_fingerprint(db, fp)
        if app_row is None:
            app_row = _candidate_for(db, fp, server)
            created += 1
        else:
            matched += 1
            app_row.auto_discovery_fingerprint = {
                **(app_row.auto_discovery_fingerprint or {}),
                "key": fp.get("key"),
                "source": fp.get("source"),
            }
        _sync_workload(db, app_row, fp)
        _sync_endpoints(db, app_row, fp)
    db.flush()
    return {"created": created, "matched": matched}


def _flip_status(db: Session, app_row: Application, ok: bool, target: str) -> None:
    """Hysteresis (spec §11 health): 3 consecutive fails -> down, 2 oks -> healthy."""
    check = db.scalar(
        select(HealthCheck).where(
            HealthCheck.application_id == app_row.id, HealthCheck.target == target
        )
    )
    if check is None:
        check = HealthCheck(application_id=app_row.id, kind="tcp", target=target)
        db.add(check)
        db.flush()
    check.last_result = "ok" if ok else "fail"
    if ok:
        check.consecutive_oks += 1
        check.consecutive_failures = 0
        check.last_latency_ms = None
    else:
        check.consecutive_failures += 1
        check.consecutive_oks = 0
    if not app_row.confirmed:
        return
    previous = app_row.status
    if check.consecutive_failures >= HEALTH_FAIL_THRESHOLD:
        app_row.status = AppStatus.down
    elif check.consecutive_oks >= HEALTH_OK_THRESHOLD and previous in (AppStatus.down, AppStatus.unknown):
        app_row.status = AppStatus.healthy
    if previous != app_row.status:
        touch_timeline(
            db, app_row.id, "health",
            f"Status {previous.value} \u2192 {app_row.status.value} ({target})",
            actor="agent",
        )


def apply_health_checks(db: Session, server: Server, checks: list[dict]) -> int:
    applied = 0
    for check in checks:
        target = check.get("target")
        if not target:
            continue
        app_row = None
        existing = db.scalar(select(HealthCheck).where(HealthCheck.target == target))
        if existing is not None:
            app_row = db.get(Application, existing.application_id)
        if app_row is None or app_row.server_id != server.id:
            continue
        _flip_status(db, app_row, check.get("result") == "ok", target)
        applied += 1
    db.flush()
    return applied


def apply_server_metrics(db: Session, server: Server, metrics: dict) -> None:
    """Server-level metric points land in M3; M2 only records liveness."""
    server.last_seen = datetime.now(UTC)


def confirm_application(db: Session, app_row: Application, **fields) -> Application:
    """Promote an auto-discovered candidate into a governed application."""
    for key, value in fields.items():
        if value not in (None, "") and hasattr(app_row, key):
            setattr(app_row, key, value)
    if app_row.discovery == DiscoverySource.auto:
        app_row.discovery = DiscoverySource.hybrid
    app_row.confirmed = True
    if app_row.status == AppStatus.unknown:
        app_row.status = AppStatus.healthy if app_row.health_checks else AppStatus.unknown
    touch_timeline(db, app_row.id, "discovery", f"Application confirmed by operator", actor="user")
    db.flush()
    return app_row
