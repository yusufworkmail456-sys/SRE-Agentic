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
from .models import Application
from .rules_extra import rule_log_error_spike, rule_ssl_expiry

log = logging.getLogger("sre-platform.sweeper")


async def sweep_loop() -> None:
    interval = max(15, settings.collect_default_interval_s)
    while True:
        try:
            await asyncio.to_thread(_run_sweep)
        except Exception:
            log.error("sweep failed: %s", traceback.format_exc(limit=3))
        await asyncio.sleep(interval)


def _run_sweep() -> None:
    db = SessionLocal()
    try:
        rolled = metrics.run_rollups(db, lookback_minutes=15)
        apps = db.scalars(select(Application)).all()
        fired: list[str] = []
        for app_row in apps:
            if app_row.confirmed:
                fired += detection.run_rules_for_app(db, app_row)
                for extra_rule in (rule_ssl_expiry, rule_log_error_spike):
                    try:
                        extra_rule(db, app_row)
                    except Exception:
                        continue
        opened = incidents.detect_incidents(db)
        recovered = incidents.check_recovery(db)
        db.commit()
        if fired or opened or recovered or rolled:
            log.info(
                "sweep: rollups=%s findings_fired=%s incidents_opened=%s recovered=%s",
                rolled, len(fired), len(opened), recovered,
            )
    finally:
        db.close()
