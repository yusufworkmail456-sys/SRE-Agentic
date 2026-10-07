"""Application discovery: correlate process -> port -> systemd -> nginx -> domain.

Deliberately additive and read-only. The agent proposes fingerprints; the core
decides whether a fingerprint is a new candidate, matches an existing app, or
belongs to a manually registered app (spec §4.1 + §5 must converge on one entity).

Nothing here needs root beyond reading /proc and `systemctl show`; failures in
any single source degrade to fewer fields, never to an exception that kills the
collection loop.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import psutil

SYSTEM_USERS = {"root", "nobody", "daemon", "www-data", "messagebus", "systemd-network"}
IGNORED_CMDS = {"systemd", "sshd", "cron", "dbus-daemon", "polkitd", "rsyslogd"}
# systemd units that are platform services, never "applications" (spec §3.1).
SYSTEM_UNIT_PREFIXES = (
    "systemd-", "getty@", "serial-getty@", "user@", "session-", "run-",
    "e2scrub", "fstrim", "logrotate", "man-db", "apt-", "unattended",
    "packagekit", "upower", "udisks", "blk-availability", "lvm2", "dm-event",
    "networkd", "resolved", "timesync", "ModemManager", "audit", "chrony",
    "irqbalance", "multipathd", "cloud-", "elkeid", "acpid", "atd", "rpc",
    "nfs-", "cups", "bluetooth", "wpa_", "spice", "vgauth", "vgagetty",
    "warp-svc", "assist-client", "unscd", "tuned", "nginx", "ssh", "sshd",
)
APP_CWD_MARKERS = (
    "package.json", "requirements.txt", "pyproject.toml", "pom.xml",
    "go.mod", "composer.json", "Cargo.toml", "*.jar", "app.py", "main.py",
    "manage.py", "wsgi.py", "asgi.py", "server.js", "index.js",
)
RUNTIME_BY_BIN = {
    "java": "java",
    "node": "node",
    "nodejs": "node",
    "python": "python",
    "python3": "python",
    "gunicorn": "python",
    "uvicorn": "python",
    "php": "php",
    "php-fpm": "php",
    "dotnet": "dotnet",
    "go": "go",
    "nginx": "nginx",
    "postgres": "postgres",
    "mysqld": "mysql",
    "redis-server": "redis",
}


@dataclass
class Vhost:
    server_name: str
    upstream: str | None = None
    ssl_cert: str | None = None


@dataclass
class Fingerprint:
    """A candidate application, platform-agnostic."""

    key: str  # stable identity, e.g. "systemd:hermes-gateway" or "proc:/opt/app"
    name: str
    kind: str = "process"  # process | service | container
    source: str = "process"  # systemd | process | docker
    runtime: str | None = None
    external_id: str | None = None
    cmd: str | None = None
    cwd: str | None = None
    user: str | None = None
    pid: int | None = None
    ports: list[int] = field(default_factory=list)
    vhosts: list[Vhost] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "name": self.name,
            "kind": self.kind,
            "source": self.source,
            "runtime": self.runtime,
            "external_id": self.external_id,
            "cmd": self.cmd,
            "cwd": self.cwd,
            "user": self.user,
            "pid": self.pid,
            "ports": self.ports,
            "vhosts": [v.__dict__ for v in self.vhosts],
        }


# ------------------------------------------------------------------ primitives
def detect_runtime(cmd: str | None, cwd: str | None = None) -> str | None:
    if cmd:
        first = Path(cmd.split()[0]).name if cmd.split() else ""
        if first in RUNTIME_BY_BIN:
            return RUNTIME_BY_BIN[first]
        for token in cmd.split():
            base = Path(token).name
            if base in RUNTIME_BY_BIN:
                return RUNTIME_BY_BIN[base]
    if cwd:
        markers = {
            "package.json": "node",
            "requirements.txt": "python",
            "pyproject.toml": "python",
            "pom.xml": "java",
            "go.mod": "go",
            "composer.json": "php",
        }
        for filename, runtime in markers.items():
            try:
                if (Path(cwd) / filename).exists():
                    return runtime
            except OSError:
                continue
    return None


def listening_ports_by_pid() -> dict[int, list[int]]:
    """pid -> sorted list of TCP ports it listens on (IPv4+IPv6)."""
    result: dict[int, set[int]] = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        return {}
    for conn in conns:
        if conn.status != psutil.CONN_LISTEN or not conn.pid:
            continue
        try:
            port = conn.laddr.port
        except (AttributeError, IndexError):
            continue
        result.setdefault(conn.pid, set()).add(port)
    return {pid: sorted(ports) for pid, ports in result.items()}


def systemd_units() -> dict[int, dict]:
    """MainPID -> {unit, exec_start, working_dir}. Empty when systemd is absent."""
    if not shutil.which("systemctl"):
        return {}
    try:
        listing = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running",
             "--no-pager", "--plain", "--no-legend"],
            capture_output=True, text=True, timeout=15, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    units = [line.split()[0] for line in listing.splitlines() if line.strip()]
    out: dict[int, dict] = {}
    for unit in units:
        try:
            props = subprocess.run(
                ["systemctl", "show", unit, "-p", "MainPID", "-p", "ExecStart",
                 "-p", "WorkingDirectory", "--no-pager"],
                capture_output=True, text=True, timeout=10, check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        info: dict[str, str] = {}
        for line in props.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip()
        try:
            main_pid = int(info.get("MainPID", "0") or 0)
        except ValueError:
            continue
        if main_pid:
            exec_start = info.get("ExecStart", "")
            argv = re.findall(r"argv\[\]=(.*?)\s*(?:;|$)", exec_start)
            out[main_pid] = {
                "unit": unit,
                "exec_start": (argv[0] if argv else exec_start)[:512],
                "working_dir": info.get("WorkingDirectory", "").strip() or None,
            }
    return out


_NGINX_SERVER_NAME = re.compile(r"server_name\s+([^;]+);")
_NGINX_PROXY_PASS = re.compile(r"proxy_pass\s+(?:https?://)?([^;]+);")
_NGINX_SSL_CERT = re.compile(r"ssl_certificate\s+([^;]+);")


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def parse_nginx(text: str) -> list[Vhost]:
    """Pair each server_name with its own upstream via brace-depth tokenization.

    A naive flat regex pairs one vhost's server_name with another vhost's
    proxy_pass (and chokes on one-line `location / { proxy_pass ...; }`),
    which then maps the wrong domain onto the wrong application.
    """
    vhosts: list[Vhost] = []
    current: dict | None = None
    server_depth = 0
    depth = 0
    previous_directive = ""

    def flush() -> None:
        nonlocal current
        if current is not None:
            for name in current["names"]:
                if name and name != "_":
                    vhosts.append(
                        Vhost(
                            server_name=name,
                            upstream=current["upstream"],
                            ssl_cert=current["cert"],
                        )
                    )
            current = None

    for part in re.split(r"([{}])", _strip_comments(text)):
        token = part.strip()
        if token == "{":
            if current is None and previous_directive.split()[-1:] == ["server"]:
                current = {"names": [], "upstream": None, "cert": None}
                depth += 1
                server_depth = depth
                previous_directive = ""
                continue
            depth += 1
            previous_directive = ""
        elif token == "}":
            depth = max(0, depth - 1)
            if current is not None and depth < server_depth:
                flush()
            previous_directive = ""
        elif token:
            if current is not None and depth >= server_depth:
                if m := _NGINX_SERVER_NAME.search(token):
                    current["names"] += m.group(1).split()
                if m := _NGINX_PROXY_PASS.search(token):
                    current["upstream"] = m.group(1).strip()
                if m := _NGINX_SSL_CERT.search(token):
                    current["cert"] = m.group(1).strip()
            previous_directive = token
    flush()
    return vhosts


def nginx_vhosts(globs: list[str] | None = None) -> list[Vhost]:
    patterns = globs or ["/etc/nginx/**/*.conf"]
    text_parts: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        for path in Path("/").glob(pattern.lstrip("/")):
            if str(path) in seen or not path.is_file():
                continue
            seen.add(str(path))
            try:
                text_parts.append(path.read_text(errors="ignore"))
            except OSError:
                continue
    return parse_nginx("\n".join(text_parts)) if text_parts else []


def _looks_like_app(fp: Fingerprint) -> bool:
    """Candidate filter: an application serves traffic or runs an app runtime.

    Platform plumbing (resolved/warp/nginx units) is excluded so the operator's
    review queue stays actionable; the list grows with real-world noise.
    """
    if fp.ports and not (
        fp.external_id and any(fp.external_id.startswith(p) for p in SYSTEM_UNIT_PREFIXES)
    ):
        return True
    if fp.runtime and fp.runtime not in ("nginx", "postgres", "mysql", "redis"):
        return True
    if fp.external_id and any(fp.external_id.startswith(p) for p in SYSTEM_UNIT_PREFIXES):
        return False
    if fp.cwd:
        cwd = Path(fp.cwd)
        try:
            if any((cwd / marker.split("/")[-1]).exists() for marker in APP_CWD_MARKERS):
                return True
        except OSError:
            pass
        lowered = str(cwd).lower()
        if any(hint in lowered for hint in ("/opt/", "/srv/", "/app", "service", "api", "web")):
            return True
    return False


# ------------------------------------------------------------------ main entry
def discover(ports_by_pid: dict[int, list[int]] | None = None,
             units: dict[int, dict] | None = None,
             vhosts: list[Vhost] | None = None,
             ignore_users: list[str] | None = None) -> list[Fingerprint]:
    """Build deduplicated fingerprints. Pure given its inputs (testable)."""
    ports_by_pid = listening_ports_by_pid() if ports_by_pid is None else ports_by_pid
    units = systemd_units() if units is None else units
    vhosts = nginx_vhosts() if vhosts is None else vhosts
    ignore = set(ignore_users or []) | SYSTEM_USERS

    grouped: dict[str, Fingerprint] = {}
    for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
        try:
            info = proc.info
            pid = info["pid"]
            name = info.get("name") or ""
            if pid == os.getpid() or name in IGNORED_CMDS:
                continue
            user = info.get("username") or ""
            unit_info = units.get(pid)
            # Keep service users (www-data runs the app) but drop pure system noise.
            if user in ignore and not unit_info:
                continue
            cmdline = info.get("cmdline") or []
            cmd = " ".join(cmdline)[:512] if cmdline else None
            if not cmd and not unit_info:
                continue
            try:
                cwd = proc.cwd()
            except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                cwd = None

            if unit_info:
                key = f"systemd:{unit_info['unit']}"
                display = unit_info["unit"].removesuffix(".service")
                source, kind = "systemd", "service"
                external_id = unit_info["unit"]
                cwd = unit_info.get("working_dir") or cwd
                cmd = unit_info.get("exec_start") or cmd
            else:
                root = cwd or (Path(cmdline[0]).parent if cmdline else Path("/"))
                key = f"proc:{root}"
                display = Path(str(root)).name or name
                source, kind, external_id = "process", "process", None

            fp = grouped.get(key)
            if fp is None:
                fp = Fingerprint(
                    key=key,
                    name=display,
                    kind=kind,
                    source=source,
                    external_id=external_id,
                    runtime=detect_runtime(cmd, cwd),
                    cmd=cmd,
                    cwd=str(cwd) if cwd else None,
                    user=user or None,
                    pid=pid,
                )
                grouped[key] = fp
            fp.ports = sorted(set(fp.ports) | set(ports_by_pid.get(pid, [])))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Attach vhosts by matching listen port found inside proxy_pass upstreams.
    for fp in grouped.values():
        for port in fp.ports:
            for vh in vhosts:
                if vh.upstream and re.search(rf"(^|:){port}$", vh.upstream):
                    if vh not in fp.vhosts:
                        fp.vhosts.append(vh)
    return sorted((f for f in grouped.values() if _looks_like_app(f)), key=lambda f: f.key)


def hostname() -> str:
    try:
        return os.uname().nodename
    except OSError:  # pragma: no cover
        return "unknown"


def summary(fps: list[Fingerprint]) -> str:
    return json.dumps([f.to_dict() for f in fps], indent=2)
