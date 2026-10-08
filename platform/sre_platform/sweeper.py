"""Background sweeps: rollups, rules, incidents, LLM loops, SLO refresh.

One asyncio task started by the app lifespan; every collect interval it runs
the cheap deterministic pipeline. LLM periodic analysis runs behind its own
interval + budget guardrails (config.llm_*).
"""
from __future__ import annotations

import asyncio
import logging
import time
import traceback
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import detection, incidents, metrics, postmortem
from .config import settings
from .db import SessionLocal
from .llm import LLMClient
from .models import Application, Deployment, Incident, IncidentStatus
from .quickreminders import check_metric_slos, check_recurring_errors
from .rules_extra import rule_log_error_spike, rule_ssl_expiry
from . import investigation

log = logging.getLogger("sre-platform.sweeper")

# Per-app LLM analysis state lives in memory; interval from settings (§2 guardrails).
_last_llm_analysis: dict[int, float] = {}
_last_slo_refresh = 0.0


async def sweep_loop() -> None:
    interval = max(15, settings.collect_default_interval_s)
    while True:
        try:
            await asyncio.to_thread(_run_sweep)
        except Exception:
            log.error("sweep failed: %s", traceback.format_exc(limit=3))
        await asyncio.sleep(interval)


def _llm_ready(app_id: int) -> bool:
    now = time.time()
    last = _last_llm_analysis.get(app_id, 0.0)
    if now - last >= max(60, settings.llm_analysis_interval_s):
        _last_llm_analysis[app_id] = now
        return True
    return False


def _refresh_slo(db: Session) -> None:
    """Refresh error-budget states at most once per 5 minutes."""
    global _last_slo_refresh
    now = time.time()
    if now - _last_slo_refresh < 300:
        return
    _last_slo_refresh = now
    from .models import SLO

    try:
        for slo_row in db.scalars(select(SLO).where(SLO.enabled == True)).all():  # noqa: E712
            postmortem.compute_slo_status(db, slo_row)
        db.flush()
    except Exception:
        log.warning("slo refresh failed", exc_info=True)


def _run_sweep() -> None:
    db = SessionLocal()
    try:
        rolled = metrics.run_rollups(db, lookback_minutes=15)
        apps = db.scalars(select(Application)).all()
        fired: list[str] = []
        client = LLMClient()
        from .deps import probe_all_for_app
        from .forecast import rule_capacity_forecast
        from .external_probe import probe_unconfirmed_externals

        for app_row in apps:
            if app_row.confirmed:
                fired += detection.run_rules_for_app(db, app_row)
                for extra_rule in (rule_ssl_expiry, rule_log_error_spike, rule_capacity_forecast):
                    try:
                        extra_rule(db, app_row)
                    except Exception:
                        continue
                try:
                    probe_all_for_app(db, app_row)
                except Exception:
                    log.debug("dep probe failed for %s", app_row.slug, exc_info=True)
                # M11 quick reminders: metric-SLO breaches + recurring errors
                try:
                    fired += check_metric_slos(db, app_row, client)
                except Exception:
                    log.debug("slo quick check failed for %s", app_row.slug, exc_info=True)
                try:
                    fired += check_recurring_errors(db, app_row, client)
                except Exception:
                    log.debug("recurring error check failed for %s", app_row.slug, exc_info=True)
                if client.enabled and _llm_ready(app_row.id):
                    try:
                        ai_findings = investigation.llm_periodic_analysis(db, app_row, client)
                        fired += [f.rule_key or "llm" for f in ai_findings]
                    except Exception:
                        log.warning("llm analysis failed for %s", app_row.slug, exc_info=True)
        try:
            probe_unconfirmed_externals(db)
        except Exception:
            log.debug("external probe failed", exc_info=True)
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
        # Auto-postmortem for freshly resolved incidents (spec §20)
        if recovered:
            client0 = LLMClient()
            resolved = db.scalars(
                select(Incident).where(
                    Incident.status == IncidentStatus.resolved,
                    Incident.resolved_at.is_not(None),
                ).order_by(Incident.resolved_at.desc()).limit(5)
            ).all()
            for incident in resolved:
                try:
                    postmortem.generate_postmortem(db, incident, client0)
                except Exception:
                    log.warning("postmortem generation failed for incident %s", incident.id, exc_info=True)
        _refresh_slo(db)
        # M11: finalize finished perf tests
        try:
            from .quickreport import finish_due_perf_tests

            done_tests = finish_due_perf_tests(db)
        except Exception:
            done_tests = 0
            log.debug("perf test finalization failed", exc_info=True)
        # M9/M10: CI status watch + regression checks on recent deployments
        try:
            from .ciwatch import watch_all

            ci_checked = watch_all(db)
        except Exception:
            ci_checked = 0
            log.debug("ci watch failed", exc_info=True)
        try:
            recent_deploys = db.scalars(
                select(Deployment)
                .where(
                    Deployment.regression_checked == False,  # noqa: E712
                    Deployment.deployed_at >= datetime.now(UTC) - timedelta(minutes=120),
                )
                .limit(10)
            ).all()
            from .deployer import regression_check

            regressions = 0
            for deployment in recent_deploys:
                try:
                    result = regression_check(db, deployment)
                    if result.get("regression"):
                        regressions += 1
                except Exception:
                    continue
        except Exception:
            regressions = 0
        db.commit()
        if fired or opened or recovered or rolled:
            log.info(
                "sweep: rollups=%s findings_fired=%s incidents_opened=%s recovered=%s",
                rolled, len(fired), len(opened), recovered,
            )
    finally:
        db.close()
