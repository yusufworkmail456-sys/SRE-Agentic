"""Agent configuration — /etc/sre-agent/config.toml (or --config path).

The agent holds exactly one secret: its own core token. No DB, no LLM, no git
credentials (spec §27: least privilege, minimal blast radius).
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATHS = (
    Path("/etc/sre-agent/config.toml"),
    Path.home() / ".config" / "sre-agent" / "config.toml",
)


@dataclass
class AgentConfig:
    core_url: str = "http://127.0.0.1:9141"
    token: str = ""
    hostname: str = ""
    discovery_interval_s: int = 300
    collect_interval_s: int = 30
    timeout_s: float = 10.0
    verify_tls: bool = True
    log_path: str = "/var/log/sre-agent.log"
    state_path: str = "/var/lib/sre-agent/state.json"
    # Execution is OFF by default. Both sides enforce the allowlist; this copy is
    # the agent-side half of defense-in-depth (spec §17/§27).
    allow_exec: bool = False
    exec_allowlist: list[str] = field(default_factory=list)
    nginx_conf_globs: list[str] = field(default_factory=lambda: ["/etc/nginx/**/*.conf"])
    ignore_users: list[str] = field(
        default_factory=lambda: ["messagebus", "systemd-network", "systemd-resolve", "nobody"]
    )
    # Route prefixes excluded from per-endpoint stats (SSE/websocket/long-poll
    # are long-lived by design and would always top the "slowest" list).
    route_ignore_prefixes: list[str] = field(
        default_factory=lambda: ["/api/events", "/ws", "/stream", "/socket.io"]
    )

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


def load_config(path: str | Path | None = None) -> AgentConfig:
    candidates = [Path(path)] if path else list(DEFAULT_PATHS)
    for candidate in candidates:
        if candidate.is_file():
            data = tomllib.loads(candidate.read_text())
            known = {f for f in AgentConfig.__dataclass_fields__}
            cfg = AgentConfig(**{k: v for k, v in data.items() if k in known})
            cfg.source_path = str(candidate)  # type: ignore[attr-defined]
            return cfg
    cfg = AgentConfig()
    cfg.source_path = str(candidates[0])  # type: ignore[attr-defined]
    return cfg
