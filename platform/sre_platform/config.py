"""Platform configuration. All knobs env-prefixed SRE_ (e.g. SRE_PORT)."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SRE_", env_file=".env", extra="ignore")

    app_name: str = "sre-platform"
    version: str = "0.1.0"

    # Storage
    database_url: str = f"sqlite:///{REPO_ROOT / 'data' / 'sre-platform.db'}"
    data_dir: str = str(REPO_ROOT / "data")

    # HTTP
    host: str = "127.0.0.1"
    port: int = 9141
    secret_key: str = "change-me"
    # Public mount prefix (nginx: location /sre/ -> proxy .../). Links in the UI
    # are built with this prefix so they stay inside /sre/ instead of escaping
    # to the default vhost root. Empty string = app served at domain root.
    url_prefix: str = "/sre"

    # Agent fleet defaults
    collect_default_interval_s: int = 30

    # LLM periodic analysis loop (approved: LLM runs on a recurring cadence,
    # not only on incidents). Guardrails: per-app interval, evidence-pack cap,
    # and it never executes actions — proposals only.
    llm_enabled: bool = False
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = "coding"
    llm_analysis_interval_s: int = 300
    llm_max_evidence_chars: int = 24000

    # Retention (days)
    retention_raw_metrics_days: int = 2
    retention_rollup_days: int = 30
    retention_logs_days: int = 7

    # UI live-refresh cadence (HTMX polling, seconds)
    ui_refresh_s: int = 30


settings = Settings()
