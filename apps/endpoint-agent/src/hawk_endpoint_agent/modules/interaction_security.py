"""Interaction security — inline prompt/response evaluation via the LLM gateway.

Any AI prompt observed on the endpoint (native app or captured input) is sent to
``/gateway/llm/intercept`` for a decision, so the same guardians (PII/secret DLP,
OWASP LLM/Agentic + MITRE ATLAS threat detectors) that protect the gateway also
protect the endpoint. block / redact are preventable here.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..config import AgentConfig
from ..decision import Decision
from ..enforcement import EnforcementOrchestrator
from ..hawk_client import HawkClient


class InteractionSecurityModule:
    def __init__(self, config: AgentConfig, client: HawkClient, orchestrator: EnforcementOrchestrator) -> None:
        self._config = config
        self._client = client
        self._orch = orchestrator

    def evaluate_prompt(
        self,
        *,
        prompt: str,
        ai_system_id: str,
        actor_id: str,
        actor_type: str = "human",
        context_summary: str | None = None,
        tool_output: str | None = None,
        response_text: str | None = None,
        provider: str | None = None,
    ) -> Decision:
        payload: dict[str, Any] = {
            "ai_system_id": ai_system_id,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "request_id": f"endpoint-{uuid.uuid4().hex}",
            "prompt": prompt,
            "context_summary": context_summary or "",
            "tool_output": tool_output,
            "response_text": response_text,
            "provider": provider,
            "data_source": "endpoint-agent",
        }
        return self._orch.evaluate(endpoint=self._client.intercept_llm, payload=payload, surface="llm_prompt")
