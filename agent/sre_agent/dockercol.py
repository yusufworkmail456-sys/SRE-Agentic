"""Docker collector (spec §6 Containerized): containers as first-class workloads.

Uses the docker CLI (`docker ps --format`) — no SDK, degrades to [] when docker
is absent. Output: fingerprints (source=docker) + per-container metrics +
container log batches, all shaped like the systemd/process equivalents so
services.apply_discovery treats containers as normal workloads.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger("sre-agent.docker")

_FMT = (
    "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t"
    "{{.Label \"com.docker.compose.project\"}}\t{{.Label \"com.docker.compose.service\"}}\t"
    "{{.Ports}}"
)


@dataclass
class Container:
    id: str
    name: str
    image: str
    state: str  # running / exited / ...
    status: str  # human string e.g. "Up 3 hours"
    compose_project: str | None = None
    compose_service: str | None = None
    ports: list[int] = field(default_factory=list)


def docker_available() -> bool:
    return bool(shutil.which("docker"))


def list_containers(timeout: int = 10) -> list[Container]:
    if not docker_available():
        return []
    try:
        proc = subprocess.run(
            ["docker", "ps", "-a", "--format", _FMT],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("docker ps failed: %s", exc)
        return []
    if proc.returncode != 0:
        return []
    out: list[Container] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        cid, name, image, state, status = parts[:5]
        project = parts[5] if len(parts) > 5 and parts[5] else None
        service = parts[6] if len(parts) > 6 and parts[6] else None
        ports = _parse_ports(parts[7]) if len(parts) > 7 else []
        out.append(
            Container(
                id=cid[:12], name=name, image=image, state=state, status=status,
                compose_project=project, compose_service=service,
                ports=ports,
            )
        )
    return out


def _parse_ports(raw: str) -> list[int]:
    """Extract HOST ports from `0.0.0.0:8080->80/tcp, :::8080->80/tcp` style."""
    ports: list[int] = []
    for match in raw.split(","):
        chunk = match.strip()
        if "->" not in chunk:
            continue
        host_side = chunk.split("->", 1)[0].split(":")[-1]
        try:
            ports.append(int(host_side))
        except ValueError:
            continue
    return ports


def container_fingerprints(containers: list[Container] | None = None) -> list[dict]:
    """Fingerprint dicts shaped like discovery.Fingerprint.to_dict().

    Grouping: compose project -> ONE application (services become workloads);
    standalone containers -> one app each (spec §6).
    """
    containers = containers if containers is not None else list_containers()
    groups: dict[str, list[Container]] = {}
    for c in containers:
        key = f"compose:{c.compose_project}" if c.compose_project else f"docker:{c.name}"
        groups.setdefault(key, []).append(c)

    fps: list[dict] = []
    for key, members in groups.items():
        primary = members[0]
        name = (
            primary.compose_project
            if primary.compose_project
            else primary.name
        )
        ports = sorted({p for c in members for p in c.ports})
        fps.append(
            {
                "key": key,
                "name": name,
                "kind": "container",
                "source": "docker",
                "runtime": "docker",
                "external_id": primary.compose_project or primary.name,
                "cmd": ", ".join(sorted({c.image for c in members}))[:512],
                "cwd": None,
                "user": None,
                "pid": None,
                "ports": ports,
                "vhosts": [],
                "containers": [
                    {
                        "id": c.id, "name": c.name, "image": c.image,
                        "state": c.state, "status": c.status,
                        "service": c.compose_service,
                        "ports": c.ports,
                    }
                    for c in members
                ],
            }
        )
    return fps


def container_metrics(containers: list[Container] | None = None) -> list[dict]:
    """`docker stats --no-stream` for RUNNING containers (CPU%, Mem%)."""
    if not docker_available():
        return []
    try:
        proc = subprocess.run(
            ["docker", "stats", "--no-stream",
             "--format", "{{.ID}}\t{{.CPUPerc}}\t{{.MemPerc}}\t{{.NetIO}}"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    stats: list[dict] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        stats.append(
            {
                "container_id": parts[0][:12],
                "cpu_pct": _pct(parts[1]),
                "mem_pct": _pct(parts[2]),
                "net_io": parts[3] if len(parts) > 3 else None,
            }
        )
    return stats


def _pct(raw: str) -> float | None:
    try:
        return float(raw.strip().rstrip("%"))
    except (ValueError, AttributeError):
        return None


def container_log_batch(name: str, tail: int = 60) -> dict | None:
    """stdout/stderr tail of one container, level-counted like journald batches."""
    if not docker_available():
        return None
    try:
        proc = subprocess.run(
            ["docker", "logs", "--tail", str(tail), name],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (proc.stdout or "") + (proc.stderr or "")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    levels: dict[str, int] = {"INFO": 0, "WARNING": 0, "ERROR": 0, "CRITICAL": 0}
    for ln in lines:
        upper = ln.upper()
        if "CRITICAL" in upper or "FATAL" in upper:
            levels["CRITICAL"] += 1
        elif "ERROR" in upper or "TRACEBACK" in upper:
            levels["ERROR"] += 1
        elif "WARN" in upper:
            levels["WARNING"] += 1
        else:
            levels["INFO"] += 1
    return {
        "workload_ref": name,
        "source": "docker",
        "ts_start": None,
        "ts_end": None,
        "level_counts": levels,
        "sample_lines": lines[-20:],
    }
