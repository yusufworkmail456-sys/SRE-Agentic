"""Outbound-only communication with the core. The agent never listens."""
from __future__ import annotations

import httpx

from . import __version__


class CoreClient:
    def __init__(self, base_url: str, token: str, timeout_s: float = 10.0, verify_tls: bool = True):
        self.base = base_url.rstrip("/")
        self.verify = verify_tls
        headers = {"X-Agent-Version": __version__}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.client = httpx.Client(base_url=self.base, headers=headers, timeout=timeout_s)

    def register(self, hostname: str, capabilities: dict) -> dict:
        resp = self.client.post(
            "/api/agent/v1/register",
            json={"hostname": hostname, "agent_version": __version__, "capabilities": capabilities},
        )
        resp.raise_for_status()
        return resp.json()

    def ingest(self, payload: dict) -> dict:
        resp = self.client.post("/api/agent/v1/ingest", json=payload)
        resp.raise_for_status()
        return resp.json()

    def poll_actions(self) -> list[dict]:
        resp = self.client.post("/api/agent/v1/actions/poll", json={})
        resp.raise_for_status()
        return resp.json().get("actions", [])

    def report_action(self, action_id: int, result: dict) -> None:
        resp = self.client.post(f"/api/agent/v1/actions/{action_id}/result", json=result)
        resp.raise_for_status()
