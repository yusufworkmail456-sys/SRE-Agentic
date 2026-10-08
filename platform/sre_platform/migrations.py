"""M11 schema additions.

SQLite create_all never alters existing tables, so new columns land here via
idempotent ALTER TABLE (same pattern as migrations.py).
"""
from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

log = logging.getLogger("sre-platform.migrations")

# table -> {column: DDL type}
ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "slo": {
        "metric": "VARCHAR(32) DEFAULT ''",
        "direction": "VARCHAR(16) DEFAULT 'max'",
        "threshold": "FLOAT",
        "comparison": "VARCHAR(4) DEFAULT ''",
    },
    "metric_point": {
        "load1": "FLOAT",
        "load5": "FLOAT",
        "load15": "FLOAT",
        "swap_pct": "FLOAT",
        "disk_read_kbps": "FLOAT",
        "disk_write_kbps": "FLOAT",
        "net_errs": "INTEGER",
        "net_drops": "INTEGER",
    },
}


def ensure_schema(engine: Engine) -> None:
    if not engine.url.get_backend_name().startswith("sqlite"):
        return  # postgres/alembic handles this in a later phase
    with engine.begin() as conn:
        for table, columns in ADDED_COLUMNS.items():
            existing = {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}
            if not existing:
                continue  # table not created yet; create_all will handle it
            for column, ddl in columns.items():
                if column not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
                    log.info("migration: %s.%s added", table, column)
