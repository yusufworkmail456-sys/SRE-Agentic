"""Background sweeps: rollups, rules, incident detection/recovery.

One asyncio task started by the app lifespan; every collect interval it runs
the cheap deterministic pipeline. LLM periodic analysis hooks in at M5 behind
its own interval + budget guardrails (config.llm_*).
"""
from __future__ import annotations

import asyncio
import logging
import traceback

from sqlalchemy import select

from . import detection, incidents, metrics
from .config import settings
from .db import SessionLocal
from .llm import LLMClient
from .models import Application, Incident, IncidentStatus
from .rules_extra import rule_log_error_spike, rule_ssl_expiry
from . import investigation

log = logging.getLogger("sre-platform.sweeper")

# Per-app LLM analysis state lives in memory; interval from settings (§2 guardrails).
_last_llm_analysis: dict[int, float] = {}


async def sweep_loop() -> None:
    interval = max(15, settings.collect_default_interval_s)
    while True:
        try:
            await asyncio.to_thread(_run_sweep)
        except Exception:
            log.error("sweep failed: %s", traceback.format_exc(limit=3))
        await asyncio.sleep(interval)


def _llm_ready(app_id: int) -> bool:
    import time

    now = time.time()
    last = _last_llm_analysis.get(app_id, 0.0)
    if now - last >= max(60, settings.llm_analysis_interval_s):
        _last_llm_analysis[app_id] = now
        return True
    return False


def _run_sweep() -> None:
    db = SessionLocal()
    try:
        rolled = metrics.run_rollups(db, lookback_minutes=15)
        apps = db.scalars(select(Application)).all()
        fired: list[str] = []
        client = LLMClient()
        for app_row in apps:
            if app_row.confirmed:
                fired += detection.run_rules_for_app(db, app_row)
                for extra_rule in (rule_ssl_expiry, rule_log_error_spike):
                    try:
                        extra_rule(db, app_row)
                    except Exception:
                        continue
                if client.enabled and _llm_ready(app_row.id):
                    try:
                        ai_findings = investigation.llm_periodic_analysis(db, app_row, client)
                        fired += [f.rule_key or "llm" for f in ai_findings]
                    except Exception:
                        log.warning("llm analysis failed for %s", app_row.slug, exc_info=True)
        opened = incidents.detect_incidents(db)
        # LLM deep-dive on fresh incidents (deterministic verdict already present)
        for incident in opened:
            try:
                investigation.llm_investigate_incident(db, incident, client)
            except Exception:
                log.warning("llm investigate failed for incident %s", incident.id, exc_info=True)
        # Retry LLM on incidents still lacking a diagnosis
        if client.enabled:
            pending = db.scalars(
                select(Incident).where(Incident.status == IncidentStatus.investigating)
            ).all()
            for incident in pending[:3]:
                try:
                    investigation.llm_investigate_incident(db, incident, client)
                except Exception:
                    continue
        recovered = incidents.check_recovery(db)
        db.commit()
        if fired or opened or recovered or rolled:
            log.info(
                "sweep: rollups=%s findings_fired=%s incidents_opened=%s recovered=%s",
                rolled, len(fired), len(opened), recovered,
            )
    finally:
        db.close()
