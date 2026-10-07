"""Log batch collection: journald units + app files (spec §7 Logs, §26 LogBatch).

Agent ships level counts + a bounded sample of recent lines — enough to
correlate incidents without becoming a log indexer (docs §2 trade-off).
"""
from __future__ import annotations

import json
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

LEVELS = ("ERROR", "CRIT", "WARNING", "INFO", "DEBUG", "NOTICE", "ERR", "FATAL", "CRITICAL")
_LEVEL_CANON = {
    "ERR": "ERROR", "CRIT": "CRITICAL", "FATAL": "CRITICAL",
    "WARNING": "WARN", "NOTICE": "INFO", "DEBUG": "DEBUG", "INFO": "INFO",
}
_LEVEL_RE = re.compile(r"\b(?P<lvl>" + "|".join(LEVELS) + r")\b", re.IGNORECASE)
_TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})")


def _canon(level: str) -> str:
    return _LEVEL_CANON.get(level.upper(), level.upper())


def classify_lines(lines: list[str], max_lines: int = 20, level_filter: str | None = None) -> dict:
    counts: dict[str, int] = {}
    samples: list[str] = []
    for line in lines:
        m = _LEVEL_RE.search(line)
        if not m:
            counts.setdefault("OTHER", 0)
            counts["OTHER"] += 1
            continue
        lvl = _canon(m.group("lvl"))
        counts[lvl] = counts.get(lvl, 0) + 1
        if lvl in ("ERROR", "CRITICAL") or (level_filter and lvl == _canon(level_filter)):
            if len(samples) < max_lines:
                samples.append(line[:400])
    return {"level_counts": counts, "sample_lines": samples}


def journald_batch(unit: str, since_minutes: int = 5, max_lines: int = 2000) -> dict | None:
    """Collect one systemd unit's recent journal output. None when unavailable."""
    if not Path("/usr/bin/journalctl").exists() and not Path("/bin/journalctl").exists():
        return None
    since = (datetime.now(UTC) - timedelta(minutes=since_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        proc = subprocess.run(
            ["journalctl", "-u", unit, f"--since={since}", "--no-pager", "-n", str(max_lines), "-q"],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        return None
    parsed = _parse_journal_timestamps(lines)
    result = classify_lines(lines)
    result.update(
        {
            "source": "journald",
            "workload_ref": unit,
            "ts_start": parsed[0] if parsed else None,
            "ts_end": parsed[-1] if parsed else None,
            "line_count": len(lines),
        }
    )
    return result


def _parse_journal_timestamps(lines: list[str]) -> list[str]:
    stamps = []
    for line in lines:
        m = re.match(r"(\w{3} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line) or _TS_RE.search(line)
        if m:
            stamps.append(m.group(1))
    return stamps


def file_batch(path: str, since_minutes: int = 5, max_bytes: int = 400_000) -> dict | None:
    """Tail an app log file; classify the recent window."""
    file_path = Path(path)
    if not file_path.is_file():
        return None
    try:
        with file_path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - max_bytes))
            text = fh.read().decode(errors="ignore")
    except OSError:
        return None
    lines = text.splitlines()[-2000:]
    if not lines:
        return None
    result = classify_lines(lines)
    stamps = [m.group(1) for line in lines if (m := _TS_RE.search(line))]
    result.update(
        {
            "source": "file",
            "workload_ref": str(file_path),
            "ts_start": stamps[0] if stamps else None,
            "ts_end": stamps[-1] if stamps else None,
            "line_count": len(lines),
        }
    )
    return result
