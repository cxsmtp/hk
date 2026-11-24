from __future__ import annotations

import json
from typing import Any

import httpx

from app.services.brain.providers.base import LLMProvider


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str | None = None,
        api_version: str | None = None,
        timeout_secs: int = 30,
        temperature: float = 0.0,
        max_tokens: int = 1200,
        reasoning_effort: str | None = None,
    ) -> None:
        if reasoning_effort not in (None, "none"):
            raise ValueError("OpenAI reasoning effort supports only 'none'")
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or "").rstrip("/")
        self.api_version = (api_version or "").strip() or None
        self.timeout_secs = timeout_secs
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.reasoning_effort = reasoning_effort

    def _is_azure(self) -> bool:
        if self.base_url and "azure.com" in self.base_url:
            return True
        return bool(self.base_url and self.api_version)

    def _url(self) -> str:
        if self.base_url:
            return f"{self.base_url}/chat/completions"
        return "https://api.openai.com/v1/chat/completions"

    def _headers(self) -> dict[str, str]:
        if self._is_azure():
            return {"api-key": self.api_key, "Content-Type": "application/json"}
        return {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

    def _params(self) -> dict[str, str]:
        if self._is_azure() and self.api_version:
            return {"api-version": self.api_version}
        return {}

    def _extract_text_content(self, response_json: dict[str, Any]) -> str:
        choices = response_json.get("choices") or []
        if not isinstance(choices, list) or not choices:
            raise RuntimeError("LLM response missing choices")

        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if not isinstance(message, dict):
            raise RuntimeError("LLM response missing message")

        content = message.get("content")
        if isinstance(content, str):
            text = content.strip()
            if not text:
                raise RuntimeError("LLM response content is empty")
            return text

        if isinstance(content, list):
            parts: list[str] = []
            for part in content:
                if not isinstance(part, dict):
                    continue
                text = part.get("text")
                if isinstance(text, str) and text.strip():
                    parts.append(text.strip())
            merged = "\n".join(parts).strip()
            if merged:
                return merged

        raise RuntimeError("LLM response content not parseable as text")

    def _chat_completion(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_format: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        if self.model:
            payload["model"] = self.model
        if self.reasoning_effort is not None:
            payload["reasoning_effort"] = self.reasoning_effort
        if response_format:
            payload["response_format"] = response_format

        try:
            with httpx.Client(timeout=self.timeout_secs) as client:
                response = client.post(
                    self._url(),
                    headers=self._headers(),
                    params=self._params(),
                    json=payload,
                )
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code if exc.response is not None else "unknown"
            body = exc.response.text[:500] if exc.response is not None else ""
            raise RuntimeError(f"OpenAI provider request failed with status {status_code}: {body}") from exc
        except httpx.HTTPError as exc:
            raise RuntimeError(f"OpenAI provider request error: {exc}") from exc

    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict[str, Any]) -> dict[str, Any]:
        response_json = self._chat_completion(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "brain_response",
                    "strict": True,
                    "schema": json_schema,
                },
            },
        )
        content = self._extract_text_content(response_json)
        try:
            loaded = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"LLM did not return valid JSON: {exc}") from exc
        if not isinstance(loaded, dict):
            raise RuntimeError("LLM JSON response must be an object")
        return loaded

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        response_json = self._chat_completion(system_prompt=system_prompt, user_prompt=user_prompt)
        return self._extract_text_content(response_json)

    def health(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": bool(self.api_key and self.model),
            "model": self.model,
        }
