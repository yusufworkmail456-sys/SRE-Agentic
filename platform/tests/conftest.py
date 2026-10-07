"""Test isolation: point SRE_DATA_DIR/SRE_DATABASE_URL at a temp dir for ALL tests.

Imported via conftest so the production SQLite under platform/data is never
touched by pytest (this bit us once: pytest wiped the live DB).
"""
from __future__ import annotations

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="sre-test-")
os.environ["SRE_DATA_DIR"] = _TMP
os.environ["SRE_DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ.setdefault("SRE_LLM_ENABLED", "false")
