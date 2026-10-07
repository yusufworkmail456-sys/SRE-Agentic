"""Agent-side executor (spec §17/§18): ONLY allowlisted, core-approved actions.

Defense in depth: the core already checked autonomy level + approval nonce
before the action ever lands in /actions/poll; the agent re-checks its OWN
allowlist (config.toml `exec_allowlist`) so a compromised core cannot run
arbitrary commands. Default allowlist is EMPTY — exec is opt-in per server.
"""
from __future__ import annotations

import logging
import shlex
import subprocess
import time

log = logging.getLogger("sre-agent.executor")

# action name -> argv template. {target} is substituted from the approved
# action; anything else must come from the template, never from the payload.
PLAYBOOKS: dict[str, list[str]] = {
    "restart_service": ["systemctl", "restart", "{target}"],
    "stop_service": ["systemctl", "stop", "{target}"],
    "start_service": ["systemctl", "start", "{target}"],
    "restart_container": ["docker", "restart", "{target}"],
    "health_check": ["systemctl", "is-active", "{target}"],
    # diagnostics are read-only and always low-risk
    "diagnose_disk": ["sh", "-c", "df -h / && du -x -d1 -h /var 2>/dev/null | sort -rh | head -20"],
    "diagnose_service": ["systemctl", "status", "{target}", "--no-pager", "-l"],
    "diagnose_logs": ["journalctl", "-u", "{target}", "-n", "100", "--no-pager"],
}

# systemd unit-name hygiene: block glob/shell metacharacters outright.
_UNIT_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-_\\")


def build_argv(action: str, target: str) -> list[str] | None:
    template = PLAYBOOKS.get(action)
    if template is None:
        return None
    if action.startswith("diagnose_"):
        # diagnostics tolerate an empty target only where the template allows
        if not target and "{target}" in " ".join(template):
            return None
    argv = [part.format(target=target) for part in template]
    for part in argv:
        if any(ch not in _UNIT_SAFE and ch != " " for ch in part.replace("-", "-", 1)):
            # sh -c diagnostic scripts legitimately contain spaces/|/; — allow only there
            if not (action.startswith("diagnose_") and part == template[-1]):
                return None
    return argv


def validate_target(action: str, target: str) -> bool:
    if not target:
        return False
    if any(ch not in _UNIT_SAFE for ch in target):
        return False
    if len(target) > 255:
        return False
    return True


def execute_action(
    action_id: int,
    action: str,
    target: str,
    nonce: str | None,
    allowlist: list[str],
    timeout: float = 60.0,
) -> dict:
    """Run one approved action. Returns a result dict for /actions/{id}/result."""
    if action not in allowlist:
        return {"status": "rejected", "exit_code": None,
                "stdout": "", "reason": f"action {action!r} not in agent allowlist"}
    if action not in PLAYBOOKS:
        return {"status": "rejected", "exit_code": None,
                "stdout": "", "reason": f"unknown action {action!r}"}
    # diagnostics may omit target; everything else needs a clean one
    if action.startswith("diagnose_"):
        if target and not validate_target(action, target):
            return {"status": "rejected", "exit_code": None,
                    "stdout": "", "reason": "unsafe target"}
    elif not validate_target(action, target):
        return {"status": "rejected", "exit_code": None,
                "stdout": "", "reason": "unsafe target"}

    argv = build_argv(action, target)
    if argv is None:
        return {"status": "rejected", "exit_code": None,
                "stdout": "", "reason": "cannot build safe argv"}

    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SRE_ACTION_ID": str(action_id),
        "SRE_NONCE": nonce or "",
        "LANG": "C",
    }
    started = time.monotonic()
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout,
            env=env, check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout", "exit_code": None, "stdout": "", "stderr": "timeout",
            "duration_s": round(time.monotonic() - started, 2),
        }
    except OSError as exc:
        return {
            "status": "failed", "exit_code": None, "stdout": "", "stderr": str(exc)[:200],
            "duration_s": round(time.monotonic() - started, 2),
        }
    log.info("action %s %s -> rc=%s (%.1fs)", action, target, proc.returncode,
             time.monotonic() - started)
    return {
        "status": "done" if proc.returncode == 0 else "failed",
        "exit_code": proc.returncode,
        "stdout": (proc.stdout or "")[-4000:],
        "stderr": (proc.stderr or "")[-2000:],
        "duration_s": round(time.monotonic() - started, 2),
    }


def quote_hint(cmd: str) -> str:  # pragma: no cover - helper for ops, not runtime
    return shlex.quote(cmd)
