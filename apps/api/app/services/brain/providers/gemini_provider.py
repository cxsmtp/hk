from __future__ import annotations

import json
from typing import Any

import httpx

from app.services.brain.providers.base import LLMProvider


class GeminiProvider(LLMProvider):
    name = "gemini"

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

    def _url(self) -> str:
        return f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"

    def _generate(self, *, system_prompt: str, user_prompt: str) -> dict[str, Any]:
        payload = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}],
                }
            ],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_tokens,
            },
        }
        try:
            with httpx.Client(timeout=self.timeout_secs) as client:
                response = client.post(
                    self._url(),
                    params={"key": self.api_key},
                    json=payload,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            body = exc.response.text[:500] if exc.response is not None else ""
            raise RuntimeError(f"Gemini provider request failed with status {status_code}: {body}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Gemini provider request error: {exc}") from exc

    def _extract_text(self, response_json: dict[str, Any]) -> str:
        candidates = response_json.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise RuntimeError("Gemini response missing candidates")
        content = candidates[0].get("content") if isinstance(candidates[0], dict) else None
        if not isinstance(content, dict):
            raise RuntimeError("Gemini response missing content")
        parts = content.get("parts")
        if not isinstance(parts, list):
            raise RuntimeError("Gemini response missing content parts")
        text_parts: list[str] = []
        for part in parts:
            if not isinstance(part, dict):
                continue
            text = part.get("text")
            if isinstance(text, str) and text.strip():
                text_parts.append(text.strip())
        merged = "\n".join(text_parts).strip()
        if not merged:
            raise RuntimeError("Gemini response content is empty")
        return merged

    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict[str, Any]) -> dict[str, Any]:
        strict_prompt = (
            f"{user_prompt}\n\n"
            "Return strictly valid JSON only. Do not include markdown.\n"
            f"JSON Schema:\n{json.dumps(json_schema, sort_keys=True)}"
        )
        response_json = self._generate(system_prompt=system_prompt, user_prompt=strict_prompt)
        content = self._extract_text(response_json)
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Gemini did not return valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise RuntimeError("Gemini JSON response must be an object")
        return parsed

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        response_json = self._generate(system_prompt=system_prompt, user_prompt=user_prompt)
        return self._extract_text(response_json)

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": bool(self.api_key and self.model),
            "model": self.model,
        }
