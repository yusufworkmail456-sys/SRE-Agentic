"""Agent logcol tests."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sre_agent.logcol import classify_lines, file_batch, journald_batch  # noqa: E402


def test_classify_canon_and_samples():
    lines = [
        "2026-10-07 10:00:00 CRIT disk full",
        "2026-10-07 10:00:01 err segfault",
        "2026-10-07 10:00:02 INFO ok",
        "no level here",
    ]
    res = classify_lines(lines)
    assert res["level_counts"] == {"CRITICAL": 1, "ERROR": 1, "INFO": 1, "OTHER": 1}
    assert len(res["sample_lines"]) == 2


def test_journal_batch_missing_unit_is_none():
    assert journald_batch("no-such-unit-abc123") is None


def test_file_batch_missing_is_none(tmp_path):
    assert file_batch(str(tmp_path / "nope.log")) is None
