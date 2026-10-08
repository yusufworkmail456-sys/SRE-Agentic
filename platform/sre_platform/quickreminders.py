"""Quick Reminder engine (M11).

Turns two signals into pinned, AI-explained reminders on the app page:
  1. SLO breach     — a metric-backed SLO crosses its threshold.
  2. Recurring error — the same normalized error signature repeats (>=3 times
     in 15 minutes), independent of volume spikes.

Every reminder gets a ONE-TIME AI recommendation (per finding row), generated
when the finding is created. Repeats only refresh last_seen — no repeated LLM
calls. Recommendations live in Finding.recommendation and render as Quick
Reminder cards; plain metric/log findings stay in Findings.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .llm import LLMClient, LLMUnavailable
from .metrics import latest_points
from .models import (
    Application,
    Finding,
    FindingCategory,
    FindingStatus,
    LogBatch,
    SLO,
    Severity,
)
from .detection import _upsert_finding

QUICK_RULES = ("slo_breach", "recurring_error")
RECUR_MIN_COUNT = 3
RECUR_WINDOW_MIN = 15

_NUMBER = re.compile(r"\b\d+(?:[.,]\d+)?\b")
_HEX = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
_QUOTED = re.compile(r'"[^"]{6,}"|\'[^\']{6,}\'')


# ---------------------------------------------------------------- SLO breach
def check_metric_slos(db: Session, app_row: Application, client: LLMClient | None = None) -> list[str]:
    """Evaluate metric-backed SLOs (metric + comparison + threshold) every sweep."""
    slos = db.scalars(
        select(SLO).where(
            SLO.application_id == app_row.id,
            SLO.enabled == True,  # noqa: E712
            SLO.metric.is_not(None),
        )
    ).all()
    if not slos:
        return []
    points = latest_points(db, app_row.id, limit=3)
    if not points:
        return []
    fired = []
    for slo_row in slos:
        values = [_slo_metric_value(p, slo_row.metric or "") for p in reversed(points)]
        values = [v for v in values if v is not None]
        if not values:
            continue
        current = sum(values) / len(values)  # smoothed over the last 3 samples
        breached = _breaches(current, slo_row.comparison or ">", float(slo_row.threshold or 0))
        rule = f"slo_breach:{slo_row.sli}"
        if breached:
            fired.append(rule)
            finding = _upsert_finding(
                db, app_row, rule,
                {
                    "category": FindingCategory.reliability,
                    "severity": Severity.warning,
                    "confidence": "confirmed",
                    "title": f"SLO breach: {slo_row.sli} is {_cmp_text(slo_row.comparison or '>')} "
                             f"{slo_row.threshold:g} (now {current:.4g})",
                    "observation": (
                        f"Metric '{slo_row.metric}' averaged {current:.4g} over the last "
                        f"{len(values)} sample(s); SLO threshold is {slo_row.comparison or '>'} "
                        f"{slo_row.threshold:g}."
                    ),
                    "evidence": [
                        {"source": "metric_point", "ref": f"app:{app_row.id}:{slo_row.metric}",
                         "value": round(current, 4), "ts": points[0].ts.isoformat()},
                        {"source": "slo", "ref": f"slo:{slo_row.id}",
                         "value": {"sli": slo_row.sli, "comparison": slo_row.comparison,
                                   "threshold": slo_row.threshold}},
                    ],
                },
            )
            if finding is not None and not (finding.recommendation or "").strip():
                _attach_recommendation(
                    db, finding, client,
                    subject=f"SLO '{slo_row.sli}' breached on {app_row.name}",
                )
        else:
            _resolve_quick_finding(db, app_row, rule)
    return fired


def _slo_metric_value(point, metric: str) -> float | None:
    if metric == "error_rate":
        return point.err_rate
    if metric == "req_rate":
        return point.req_rate
    if metric == "latency_p95_ms":
        return point.p95_ms
    if metric == "cpu_pct":
        return point.cpu_pct
    if metric == "mem_pct":
        return point.mem_pct
    return None


def _breaches(value: float, comparison: str, threshold: float) -> bool:
    if comparison == "<":
        return value < threshold
    return value > threshold


def _cmp_text(comparison: str) -> str:
    return "below" if comparison == "<" else "above"


# ------------------------------------------------------------ recurring error
def check_recurring_errors(db: Session, app_row: Application, client: LLMClient | None = None) -> list[str]:
    """Signature-based repeat detection: same normalized error line >=3x/15min."""
    since = datetime.now(UTC) - timedelta(minutes=RECUR_WINDOW_MIN)
    batches = db.scalars(
        select(LogBatch).where(
            LogBatch.application_id == app_row.id,
            LogBatch.ts_end >= since,
        ).order_by(LogBatch.ts_end.desc()).limit(30)
    ).all()
    sig_counts: dict[str, int] = {}
    sig_example: dict[str, str] = {}
    for batch in batches:
        for line in batch.sample_lines or []:
            if not isinstance(line, str) or not line:
                continue
            sig = _signature(line)
            if sig is None:
                continue
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
            sig_example.setdefault(sig, line[:300])
    fired = []
    for sig, count in sig_counts.items():
        if count < RECUR_MIN_COUNT:
            continue
        rule = f"recurring_error:{sig[:12]}"
        fired.append(rule)
        finding = _upsert_finding(
            db, app_row, rule,
            {
                "category": FindingCategory.reliability,
                "severity": Severity.critical if count >= RECUR_MIN_COUNT * 4 else Severity.warning,
                "confidence": "confirmed",
                "title": f"Recurring error x{count} in {RECUR_WINDOW_MIN}m",
                "observation": sig_example.get(sig, sig),
                "probable_cause": "The same failure repeats — likely a persistent fault, not a transient blip.",
                "evidence": [
                    {"source": "log_batch", "ref": f"app:{app_row.id}:log_signature:{sig[:16]}",
                     "value": {"count": count, "window_min": RECUR_WINDOW_MIN, "example": sig_example.get(sig, "")[:200]}},
                ],
            },
        )
        if finding is not None and not (finding.recommendation or "").strip():
            _attach_recommendation(
                db, finding, client,
                subject=f"Recurring error on {app_row.name}",
            )
    # close signatures that stopped repeating
    open_rules = db.scalars(
        select(Finding.rule_key).where(
            Finding.application_id == app_row.id,
            Finding.rule_key.like("recurring_error:%"),
            Finding.status.in_([FindingStatus.open, FindingStatus.acknowledged]),
        )
    ).all()
    for rule in open_rules or []:
        if rule and rule not in fired:
            _resolve_quick_finding(db, app_row, rule)
    return fired


def _signature(line: str) -> str | None:
    """Normalize one error line into a stable signature.

    Strips timestamps, ids, numbers and quoted values; keeps the static text
    (usually exception name + message template). None when nothing remains.
    """
    if "ERROR" not in line.upper() and "CRIT" not in line.upper():
        return None
    text = _QUOTED.sub('"…"', line)
    text = _HEX.sub("<id>", text)
    text = _NUMBER.sub("<n>", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) < 25:  # e.g. "… ERROR <n>: <n>" — nothing left to match on
        return None
    return hashlib.sha1(text.encode()).hexdigest()


# ------------------------------------------------------------- AI explanation
def _attach_recommendation(
    db: Session, finding: Finding, client: LLMClient | None, subject: str
) -> None:
    """One-time AI recommendation per finding; deterministic fallback text."""
    client = client or LLMClient()
    pack = {
        "subject": subject,
        "title": finding.title,
        "observation": finding.observation,
        "evidence": [
            {k: item.get(k) for k in ("source", "ref", "value")}
            for item in (finding.evidence or [])[:4]
            if isinstance(item, dict)
        ],
    }
    recommendation = None
    if client.enabled:
        system = (
            "You are an SRE advisor. Given one alert, answer ONLY with JSON: "
            '{"recommendation": "<2-4 concrete troubleshooting steps, ordered, '
            'referencing the evidence; no invented data>"}'
        )
        try:
            result = client.chat_json(system, json.dumps(pack, default=str), max_tokens=400)
            rec = str(result.get("recommendation") or "").strip()
            if len(rec) >= 20:
                recommendation = rec
        except (LLMUnavailable, ValueError):
            recommendation = None
    if recommendation is None:
        if finding.rule_key and finding.rule_key.startswith("slo_breach"):
            recommendation = (
                "Langkah awal tanpa AI: cek apakah ada deployment baru dalam 1 jam terakhir, "
                "lalu bandingkan metric saat ini dengan baseline 7 hari (tab Findings). "
                "Jika breach terus, verifikasi kapasitas/dependency sebelum restart."
            )
        else:
            recommendation = (
                "Langkah awal tanpa AI: buka sample log di bawah, cari exception yang sama "
                "di kode (repo sync bila terhubung), cek apakah muncul setelah deploy terakhir, "
                "lalu perbaiki penyebabnya — jangan hanya restart."
            )
    finding.recommendation = recommendation[:900]
    db.flush()


def is_quick_finding(finding: Finding) -> bool:
    key = finding.rule_key or ""
    return key.startswith(QUICK_RULES)


def _resolve_quick_finding(db: Session, app_row: Application, rule_key: str) -> None:
    existing = db.scalar(
        select(Finding).where(
            Finding.application_id == app_row.id,
            Finding.rule_key == rule_key,
            Finding.status == FindingStatus.open,
        )
    )
    if existing is not None:
        existing.status = FindingStatus.resolved
        existing.resolved_at = datetime.now(UTC)


def active_quick_findings(db: Session, app_id: int) -> list[Finding]:
    rows = db.scalars(
        select(Finding).where(
            Finding.application_id == app_id,
            Finding.rule_key.like("slo_breach:%") | Finding.rule_key.like("recurring_error:%"),
            Finding.status.in_([FindingStatus.open, FindingStatus.acknowledged]),
        ).order_by(Finding.last_seen.desc()).limit(6)
    ).all()
    return list(rows)
