from __future__ import annotations

import json
from typing import Any

import httpx

from app.services.brain.providers.base import LLMProvider


class AnthropicProvider(LLMProvider):
    name = "claude"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_secs: int = 30,
        temperature: float = 0.0,
        max_tokens: int = 1200,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout_secs = timeout_secs
        self.temperature = temperature
        self.max_tokens = max_tokens

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

    def _messages(self, *, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        try:
            with httpx.Client(timeout=self.timeout_secs) as client:
                response = client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers=self._headers(),
                    json=payload,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            body = exc.response.text[:500] if exc.response is not None else ""
            raise RuntimeError(f"Anthropic provider request failed with status {status_code}: {body}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Anthropic provider request error: {exc}") from exc

    def _extract_text(self, response_json: dict[str, Any]) -> str:
        content = response_json.get("content")
        if not isinstance(content, list):
            raise RuntimeError("Anthropic response missing content list")
        parts: list[str] = []
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") != "text":
                continue
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
        merged = "\n".join(parts).strip()
        if not merged:
            raise RuntimeError("Anthropic response content is empty")
        return merged

    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict[str, Any]) -> dict[str, Any]:
        strict_prompt = (
            f"{user_prompt}\n\n"
            "Return strictly valid JSON only. Do not include markdown.\n"
            f"JSON Schema:\n{json.dumps(json_schema, sort_keys=True)}"
        )
        response_json = self._messages(system_prompt=system_prompt, user_prompt=strict_prompt)
        content = self._extract_text(response_json)
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Anthropic did not return valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise RuntimeError("Anthropic JSON response must be an object")
        return parsed

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        response_json = self._messages(system_prompt=system_prompt, user_prompt=user_prompt)
        return self._extract_text(response_json)

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": bool(self.api_key and self.model),
            "model": self.model,
        }
