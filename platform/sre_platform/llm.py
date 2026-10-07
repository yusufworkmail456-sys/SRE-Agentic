"""LLM client — OpenAI-compatible, provider-agnostic (spec §26).

Known quirk of the configured router (9router): it answers text/event-stream
even for non-streaming calls, so the parser strips SSE frames and the
`data: [DONE]` sentinel before JSON-decoding.
"""
from __future__ import annotations

import json
import logging

import httpx

from .config import settings

log = logging.getLogger("sre-platform.llm")


class LLMUnavailable(Exception):
    pass


class LLMClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, model: str | None = None):
        # None = inherit from settings; explicit "" = force-disabled (tests, opt-out)
        self.base_url = settings.llm_base_url if base_url is None else base_url.rstrip("/")
        self.api_key = settings.llm_api_key if api_key is None else api_key
        self.model = model or settings.llm_model

    @property
    def enabled(self) -> bool:
        return bool(settings.llm_enabled and self.base_url and self.api_key)

    def chat(self, system: str, user: str, max_tokens: int = 1200, timeout_s: float = 60.0) -> str:
        if not self.enabled:
            raise LLMUnavailable("LLM not configured (SRE_LLM_* settings)")
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.2,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=timeout_s,
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailable(f"LLM endpoint unreachable: {exc}") from exc
        return self._extract_text(resp)

    def _extract_text(self, resp: httpx.Response) -> str:
        content_type = resp.headers.get("content-type", "")
        raw = resp.text
        stripped = raw.lstrip()
        # The router sometimes labels responses SSE while sending plain JSON
        # (single complete object, no data: frames).
        if stripped.startswith("{") and '"choices"' in stripped:
            try:
                return self._from_json_body(stripped)
            except LLMUnavailable:
                pass
        if "text/event-stream" in content_type or stripped.startswith("data:"):
            return self._from_sse(raw)
        return self._from_json_body(stripped)

    @staticmethod
    def _from_json_body(raw: str) -> str:
        """Parse the first JSON object; router appends 'data: [DONE]' after it."""
        try:
            data, _ = json.JSONDecoder().raw_decode(raw.lstrip())
            return data["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMUnavailable(f"unexpected LLM response shape: {exc}") from exc

    def _from_sse(self, raw: str) -> str:
        parts: list[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            body = line.removeprefix("data:").strip()
            if body == "[DONE]":
                break
            try:
                chunk = json.loads(body)
                delta = chunk["choices"][0].get("delta", {}) or {}
                text = delta.get("content") or chunk["choices"][0].get("message", {}).get("content")
                if text:
                    parts.append(text)
            except (ValueError, KeyError, IndexError):
                continue
        if not parts:
            raise LLMUnavailable("empty LLM SSE stream")
        return "".join(parts)

    def chat_json(self, system: str, user: str, max_tokens: int = 1200, timeout_s: float = 60.0) -> dict:
        """Chat + tolerant JSON extraction (models love to wrap JSON in prose)."""
        text = self.chat(system, user, max_tokens=max_tokens, timeout_s=timeout_s)
        return extract_json(text)


def extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMUnavailable("no JSON object in LLM output")
    try:
        return json.loads(text[start : end + 1])
    except ValueError as exc:
        raise LLMUnavailable(f"invalid JSON from LLM: {exc}") from exc
