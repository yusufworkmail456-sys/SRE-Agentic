"""Lightweight SQLite migrations.

`Base.metadata.create_all` never alters existing tables, so new columns on old
tables (e.g. Deployment gained CI columns after first deploy) must be added via
ALTER TABLE. Idempotent: checks PRAGMA table_info first.
"""
from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.engine import Engine

log = logging.getLogger("sre-platform.migrations")

# table -> {column: DDL type}
ADDED_COLUMNS: dict[str, dict[str, str]] = {
    "deployment": {
        "pr_url": "VARCHAR(512)",
        "ci_state": "VARCHAR(32)",
        "ci_url": "VARCHAR(512)",
        "regression_checked": "BOOLEAN DEFAULT 0",
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
