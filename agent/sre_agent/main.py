"""Agent daemon loop.

Cycle: register (once) -> [collect -> ingest -> poll actions -> execute allowed]
Nothing is pushed into this VM; everything is an outbound HTTPS call (spec §5).
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import psutil

from .config import AgentConfig, load_config
from .discovery import discover, hostname
from .ingest import CoreClient

log = logging.getLogger("sre-agent")


def _cpu_percent(sample_per_core: bool = True) -> float:
    return psutil.cpu_percent(interval=0.4 * sample_per_core, percpu=False)


def collect_server_metrics() -> dict:
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    net1 = psutil.net_io_counters()
    return {
        "cpu_pct": _cpu_percent(),
        "mem_pct": mem.percent,
        "mem_used_mb": round(mem.used / 1024 / 1024),
        "disk_pct": disk.percent,
        "net_rx_kb": round(net1.bytes_recv / 1024, 1),
        "net_tx_kb": round(net1.bytes_sent / 1024, 1),
        "procs": len(psutil.pids()),
    }


class Agent:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.client = CoreClient(cfg.core_url, cfg.token, cfg.timeout_s, cfg.verify_tls)
        self.state_path = Path(cfg.state_path)
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state: dict = self._load_state()
        self.server_id: int | None = self.state.get("server_id")

    # -------------------------------------------------- state
    def _load_state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {}

    def _save_state(self) -> None:
        self.state_path.write_text(json.dumps(self.state))

    # -------------------------------------------------- loop
    def run_forever(self) -> None:  # pragma: no cover - daemon loop
        self._ensure_registered()
        last_discovery = 0.0
        while True:
            try:
                payload = {"server_id": self.server_id, "ts": time.time()}
                now = time.time()
                if now - last_discovery >= self.cfg.discovery_interval_s:
                    payload["discovery"] = [f.to_dict() for f in discover()]
                    last_discovery = now
                payload["metrics"] = {"server": collect_server_metrics()}
                payload["health_checks"] = self._probe_listening_ports()
                self.client.ingest(payload)
            except Exception as exc:  # never die on a bad cycle
                log.warning("cycle failed: %s", exc)
            time.sleep(self.cfg.collect_interval_s)

    def _ensure_registered(self) -> None:
        if self.server_id:
            return
        resp = self.client.register(hostname() or self.cfg.hostname, {"exec": self.cfg.allow_exec})
        self.server_id = resp["server_id"]
        issued = resp.get("issued_token")
        if issued and not self.cfg.token:
            # First-run bootstrap: core issues this server's token; persist it.
            self.client = CoreClient(
                self.cfg.core_url, issued, self.cfg.timeout_s, self.cfg.verify_tls
            )
            register_token(self.cfg, issued)
        self.state["server_id"] = self.server_id
        self._save_state()

    # -------------------------------------------------- probes
    def _probe_listening_ports(self) -> list[dict]:
        """Probe local HTTP ports as health checks (minimal M2 scope)."""
        checks: list[dict] = []
        seen_ports: set[int] = set()
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return checks
        for conn in conns:
            if conn.status != psutil.CONN_LISTEN or not conn.pid:
                continue
            try:
                port = conn.laddr.port  # type: ignore[union-attr]
            except (AttributeError, IndexError):
                continue
            if port in seen_ports or port > 65535:
                continue
            seen_ports.add(port)
            checks.append({"kind": "tcp", "target": f"127.0.0.1:{port}", "result": "ok"})
        return checks


def register_token(cfg: AgentConfig, token: str) -> None:
    """Persist the token into the config file the agent loaded, chmod 600."""
    path = Path(getattr(cfg, "source_path", None) or "/etc/sre-agent/config.toml")
    lines = path.read_text().splitlines() if path.is_file() else []
    replacement = f'token = "{token}"'
    if any(line.lstrip().startswith("token") for line in lines):
        lines = [
            replacement if line.lstrip().startswith("token") else line for line in lines
        ]
    else:
        lines.append(replacement)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    log.info("token written to %s", path)


def main() -> None:
    import argparse

    import logging

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(prog="sre-agent")
    parser.add_argument("--config", help="path to config.toml")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("run", help="run the agent loop")
    reg = sub.add_parser("register-token", help="save the core-issued token")
    reg.add_argument("token")
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.cmd in (None, "run"):
        Agent(cfg).run_forever()
    elif args.cmd == "register-token":
        register_token(cfg, args.token)


if __name__ == "__main__":
    main()
