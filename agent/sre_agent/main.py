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

from . import dockercol
from . import advcollect
from .config import AgentConfig, load_config
from .discovery import discover, hostname
from .executor import execute_action
from .ingest import CoreClient
from .logcol import file_batch, journald_batch
from .red import collect_nginx_red

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
        _last_proc_collect = 0.0
        prev_disk_io: tuple[float, float] | None = None
        prev_disk_ts: float | None = None
        while True:
            try:
                payload = {"server_id": self.server_id, "ts": time.time()}
                now = time.time()
                if now - last_discovery >= self.cfg.discovery_interval_s:
                    fps = [f.to_dict() for f in discover()]
                    fps += dockercol.container_fingerprints()
                    payload["discovery"] = fps
                    last_discovery = now
                metrics_payload = {"server": collect_server_metrics()}
                saturation = advcollect.collect_saturation()
                # derive instantaneous disk I/O rates from psutil counters
                if prev_disk_io and prev_disk_ts and now > prev_disk_ts:
                    dt = now - prev_disk_ts
                    if "disk_read_bytes" in saturation:
                        saturation["disk_read_kbps"] = round(
                            (saturation["disk_read_bytes"] - prev_disk_io[0]) / dt / 1024, 1)
                        saturation["disk_write_kbps"] = round(
                            (saturation["disk_write_bytes"] - prev_disk_io[1]) / dt / 1024, 1)
                if "disk_read_bytes" in saturation:
                    prev_disk_io = (saturation["disk_read_bytes"], saturation["disk_write_bytes"])
                    prev_disk_ts = now
                metrics_payload["host_saturation"] = saturation
                payload["metrics"] = metrics_payload
                red_entries, endpoint_stats = collect_nginx_red(window_s=self.cfg.collect_interval_s * 10)
                payload["red"] = red_entries
                payload["endpoints"] = endpoint_stats
                if now - _last_proc_collect >= 60:
                    payload["processes"] = advcollect.collect_processes()
                    payload["events"] = advcollect.collect_kernel_events()
                    _last_proc_collect = now
                payload["logs"] = self._collect_logs()
                payload["health_checks"] = self._probe_listening_ports() + self._probe_http_targets()
                containers = dockercol.list_containers()
                if containers:
                    payload["containers"] = {
                        "metrics": dockercol.container_metrics(containers),
                        "states": [
                            {"id": c.id, "name": c.name, "state": c.state, "status": c.status}
                            for c in containers
                        ],
                    }
                self.client.ingest(payload)
                self._poll_and_execute()
                self._refresh_http_targets()
            except Exception as exc:  # never die on a bad cycle
                log.warning("cycle failed: %s", exc)
                # 401 = our token/server row is gone (fresh core DB). Re-bootstrap.
                if "401" in str(exc):
                    self.server_id = None
                    self.state.pop("server_id", None)
                    self._save_state()
                    try:
                        self._ensure_registered()
                    except Exception:
                        pass
            time.sleep(self.cfg.collect_interval_s)

    def _refresh_http_targets(self) -> None:
        """Pull the current http health-check URL list from core config."""
        try:
            cfg = self.client.get_config()
        except Exception:
            return
        targets = cfg.get("http_health_targets") or []
        if targets != self.state.get("http_targets"):
            self.state["http_targets"] = targets
            self._save_state()
            log.info("http health targets updated: %s", targets)

    def _poll_and_execute(self) -> None:
        """Poll approved actions; run ONLY what the local allowlist permits (§18)."""
        if not self.cfg.allow_exec:
            return
        try:
            actions = self.client.poll_actions()
        except Exception as exc:
            log.warning("action poll failed: %s", exc)
            return
        for item in actions:
            result = execute_action(
                action_id=item.get("id", 0),
                action=item.get("action", ""),
                target=item.get("target", ""),
                nonce=item.get("nonce"),
                allowlist=self.cfg.exec_allowlist,
            )
            try:
                self.client.report_action(item["id"], result)
            except Exception as exc:
                log.warning("action result report failed: %s", exc)

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
    def _probe_http_targets(self) -> list[dict]:
        """HTTP health checks (§7): URLs from core config, 2xx/3xx = ok."""
        checks: list[dict] = []
        for url in (self.state.get("http_targets") or [])[:10]:
            ok, status_code, latency_ms = False, None, None
            try:
                started = time.monotonic()
                resp = self.client.http_get(url)
                latency_ms = round((time.monotonic() - started) * 1000, 1)
                status_code = resp.status_code
                ok = resp.status_code < 400
            except Exception as exc:
                log.debug("http probe %s failed: %s", url, exc)
            checks.append(
                {
                    "kind": "http",
                    "target": url,
                    "result": "ok" if ok else "fail",
                    "status_code": status_code,
                    "latency_ms": latency_ms,
                }
            )
        return checks

    def _collect_logs(self) -> list[dict]:
        """Journal batches for discovered service workloads + marked log files + docker logs."""
        batches: list[dict] = []
        seen: set[str] = set()
        try:
            fingerprints = discover(ignore_users=self.cfg.ignore_users)
        except Exception:
            fingerprints = []
        for fp in fingerprints:
            unit = fp.external_id or ""
            if fp.source == "systemd" and unit and unit not in seen:
                seen.add(unit)
                batch = journald_batch(unit, since_minutes=5)
                if batch:
                    batches.append(batch)
            if fp.cwd:
                for marker in ("app.log", "error.log", "combined.log"):
                    candidate = Path(fp.cwd) / marker
                    if candidate.is_file() and str(candidate) not in seen:
                        seen.add(str(candidate))
                        batch = file_batch(str(candidate))
                        if batch:
                            batches.append(batch)
        # docker container logs (spec §6 containerized)
        try:
            for c in dockercol.list_containers():
                if c.state != "running" or c.name in seen:
                    continue
                seen.add(c.name)
                batch = dockercol.container_log_batch(c.name)
                if batch:
                    batches.append(batch)
        except Exception as exc:
            log.warning("docker log collection failed: %s", exc)
        return batches[:12]  # bounded per cycle

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
