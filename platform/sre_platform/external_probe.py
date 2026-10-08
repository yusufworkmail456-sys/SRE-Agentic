"""Platform-side HTTP probes for External Resource apps (M11).

External resources are registered manually and often have no sre-agent on
their host. The platform probes their public URL/health endpoint itself so
they still produce health + availability data (latency also feeds the metric
stream, same as agent HTTP probes — services.apply_health_checks).
"""
from __future__ import annotations

import logging
import time
from datetime import UTC, datetime

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Application, HealthCheck
from .services import _flip_status

log = logging.getLogger("sre-platform.external-probe")

_UA = "sre-platform-external-probe/1.0"


def probe_unconfirmed_externals(db: Session) -> int:
    """Probe http health targets of apps without an agent (server_id NULL)."""
    probed = 0
    apps = db.scalars(
        select(Application).where(Application.server_id.is_(None))
    ).all()
    for app_row in apps:
        for check in app_row.health_checks:
            if check.kind != "http" or not check.enabled:
                continue
            ok, status_code, latency = _http_probe(check.target)
            _flip_status(db, app_row, ok, check.target, latency_ms=latency, status_code=status_code)
            if ok and latency is not None:
                from .models import MetricPoint

                db.add(
                    MetricPoint(
                        application_id=app_row.id,
                        ts=datetime.now(UTC),
                        p50_ms=latency,
                        p95_ms=latency,
                        raw={"source": "external_probe", "status_code": status_code},
                    )
                )
            probed += 1
    if probed:
        db.flush()
    return probed


def _http_probe(url: str, timeout_s: float = 8.0) -> tuple[bool, int | None, float | None]:
    started = time.monotonic()
    try:
        resp = httpx.get(
            url, timeout=timeout_s, follow_redirects=True,
            headers={"User-Agent": _UA},
        )
        latency = round((time.monotonic() - started) * 1000, 1)
        return resp.status_code < 400, resp.status_code, latency
    except httpx.HTTPError:
        return False, None, None
