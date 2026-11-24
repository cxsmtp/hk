"""Traffic classification for the local proxy (pure, unit-testable).

Decides whether a destination is AI traffic and, for readable requests, extracts
the prompt / tool call into a dispatcher request. No sockets here — just parsing —
so the classification rules can be tested without opening connections.
"""

from __future__ import annotations

import json
from typing import Any

from ..catalog import AI_APP_DOMAINS
from ..surfaces import Surface

# Direct LLM/inference API hosts (the "LLM gateway" surface, on-device).
LLM_API_HOSTS: tuple[str, ...] = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.cohere.com",
    "api.groq.com",
    "api.perplexity.ai",
    "openrouter.ai",
    "api.together.xyz",
    "api.together.ai",
    "api.deepseek.com",
    "api.x.ai",
    "api.fireworks.ai",
)

# Browser-reached AI app hosts (the "browser extension" surface, on-device).
AI_APP_HOSTS: tuple[str, ...] = tuple(AI_APP_DOMAINS.keys())


def _norm_host(host: str) -> str:
    return (host or "").strip().lower().split(":")[0]


def classify_host(host: str) -> str | None:
    """Return the surface for a host, or None if it is not AI traffic."""
    h = _norm_host(host)
    if not h:
        return None
    if any(h == api or h.endswith("." + api) or h == api for api in LLM_API_HOSTS):
        return Surface.LLM
    if any(h == app or h.endswith("." + app) for app in AI_APP_HOSTS):
        return Surface.BROWSER
    return None


def _extract_prompt_from_body(body: bytes | str) -> str:
    """Best-effort prompt extraction across OpenAI/Anthropic/Gemini shapes."""
    text = body.decode("utf-8", errors="ignore") if isinstance(body, (bytes, bytearray)) else str(body or "")
    if not text.strip():
        return ""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return text[:4000]
    parts: list[str] = []

    def _collect_content(content: Any) -> None:
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)

    if isinstance(payload, dict):
        if isinstance(payload.get("system"), str):
            parts.append(payload["system"])
        for message in payload.get("messages", []) or []:
            if isinstance(message, dict):
                _collect_content(message.get("content"))
        # Gemini: {"contents":[{"parts":[{"text":...}]}]}
        for content in payload.get("contents", []) or []:
            if isinstance(content, dict):
                for part in content.get("parts", []) or []:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        parts.append(part["text"])
        for key in ("prompt", "input", "query"):
            if isinstance(payload.get(key), str):
                parts.append(payload[key])
    return "\n".join(p for p in parts if p).strip()[:8000]


def build_request(host: str, path: str, body: bytes | str, *, provider_hint: str | None = None) -> dict[str, Any] | None:
    """Build a dispatcher request for readable AI traffic, or None if not applicable."""
    surface = classify_host(host)
    if surface is None:
        return None
    prompt = _extract_prompt_from_body(body)
    if not prompt:
        return None
    return {
        "surface": surface,
        "prompt": prompt,
        "provider": provider_hint or _norm_host(host),
        "ai_system_id": _norm_host(host),
        "api_endpoint": path,
        "actor_type": "human",
    }
