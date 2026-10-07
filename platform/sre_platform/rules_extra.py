"""Operational rules: SSL expiry, dependency reachability, log error spikes (§11)."""
from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from .detection import _resolve_if_recovered, _upsert_finding
from .logstore import recent_error_samples
from .models import (
    Application,
    Confidence,
    Endpoint,
    FindingCategory,
    Severity,
)


def rule_ssl_expiry(db: Session, app_row: Application) -> None:
    rule = "ssl_expiring_soon"
    expiring: list[tuple[Endpoint, int]] = []
    for endpoint in db.scalars(
        select(Endpoint).where(Endpoint.application_id == app_row.id)
    ).all():
        if not endpoint.domain:
            continue
        expires = _cert_expiry(endpoint.domain)
        if expires is None:
            continue
        endpoint.tls_expires_at = expires
        days = (expires - datetime.now(UTC)).days
        if days <= 21:
            expiring.append((endpoint, days))
    if expiring:
        soonest = min(expiring, key=lambda pair: pair[1])
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.operational,
                "severity": Severity.critical if soonest[1] <= 7 else Severity.warning,
                "confidence": Confidence.confirmed,
                "title": f"SSL certificate expires in {soonest[1]} days ({soonest[0].domain})",
                "observation": "; ".join(f"{e.domain}: {d}d" for e, d in expiring),
                "probable_cause": "Certificate renewal automation not running or failing.",
                "recommendation": "Check certbot/acme timer; renew before expiry to avoid outage.",
                "evidence": [
                    {"source": "endpoint", "ref": f"endpoint:{e.id}", "value": {"domain": e.domain, "days_left": d}}
                    for e, d in expiring
                ],
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)


def _cert_expiry(domain: str, port: int = 443, timeout: float = 4.0) -> datetime | None:
    """Direct TLS handshake — works for public domains, degrades silently offline."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                not_after = tls.getpeercert().get("notAfter")
        if not_after and isinstance(not_after, str):
            return datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except (OSError, ssl.SSLError, ValueError, KeyError):
        return None
    return None


def rule_log_error_spike(db: Session, app_row: Application) -> None:
    """Error lines jumped in the last 15 min vs the batch history mean."""
    from .logstore import window_error_counts

    rule = "log_error_spike"
    recent = window_error_counts(db, app_row.id, minutes=15)
    recent_errors = recent.get("ERROR", 0) + recent.get("CRITICAL", 0)
    from .models import LogBatch

    history = db.scalars(
        select(LogBatch)
        .where(
            LogBatch.application_id == app_row.id,
            LogBatch.ts_end < datetime.now(UTC) - timedelta(minutes=15),
        )
        .order_by(LogBatch.ts_end.desc())
        .limit(40)
    ).all()
    hist_errors = [
        int((b.level_counts or {}).get("ERROR", 0) or 0)
        + int((b.level_counts or {}).get("CRITICAL", 0) or 0)
        for b in history
    ]
    baseline_avg = (sum(hist_errors) / len(hist_errors)) if hist_errors else 0.0
    if recent_errors >= 10 and recent_errors >= max(4.0, baseline_avg * 3):
        samples = recent_error_samples(db, app_row.id, minutes=15, limit=3)
        _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.reliability,
                "severity": Severity.critical if recent_errors >= 50 else Severity.warning,
                "confidence": Confidence.likely,
                "title": f"Error log spike: {recent_errors} ERROR lines in 15m",
                "observation": (
                    f"15-min error lines {recent_errors} vs history average "
                    f"{baseline_avg:.1f} per batch."
                ),
                "probable_cause": "Unhandled exceptions after a change or a failing dependency.",
                "recommendation": "Read sample lines below; correlate with deployments.",
                "evidence": samples,
            },
        )
    else:
        _resolve_if_recovered(db, app_row, rule)
