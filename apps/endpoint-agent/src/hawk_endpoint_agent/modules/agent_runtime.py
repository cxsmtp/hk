"""Agent runtime / MCP tool authorization on the endpoint.

Local agents and MCP tool calls originating on the device are authorized through
``/gateway/mcp/authorize`` — the same least-privilege, JIT-approval, chain-depth,
and scope enforcement used by the gateway, so an on-device agent cannot exceed its
capability token.
"""

from __future__ import annotations

import uuid
from typing import Any

from ..config import AgentConfig
from ..decision import Decision
from ..enforcement import EnforcementOrchestrator
from ..hawk_client import HawkClient


class AgentRuntimeModule:
    def __init__(self, config: AgentConfig, client: HawkClient, orchestrator: EnforcementOrchestrator) -> None:
        self._config = config
        self._client = client
        self._orch = orchestrator

    def authorize(
        self,
        *,
        ai_system_id: str,
        actor_id: str,
        capability_token: str,
        action: str,
        resource: str,
        chain_depth: int = 1,
        tool_name: str | None = None,
        provider: str | None = None,
        model: str | None = None,
        model_version: str | None = None,
        data_source: str | None = None,
        tool_category: str | None = None,
        api_endpoint: str | None = None,
        tool_usage_meta: dict[str, Any] | list[dict[str, Any]] | None = None,
        context_id: str | None = None,
        chain_id: str | None = None,
        parent_action_id: str | None = None,
        parent_agent_id: str | None = None,
        session_id: str | None = None,
        initiating_user_id: str | None = None,
        session_context: dict[str, Any] | None = None,
        dynamic_permission: dict[str, Any] | None = None,
    ) -> Decision:
        payload: dict[str, Any] = {
            "ai_system_id": ai_system_id,
            "actor_id": actor_id,
            "capability_token": capability_token,
            "action": action,
            "resource": resource,
            "chain_depth": chain_depth,
            "tool_name": tool_name,
            "request_id": f"endpoint-{uuid.uuid4().hex}",
        }
        optional_payload: dict[str, Any] = {
            "provider": provider,
            "model": model,
            "model_version": model_version,
            "data_source": data_source,
            "tool_category": tool_category,
            "api_endpoint": api_endpoint,
            "tool_usage_meta": tool_usage_meta,
            "context_id": context_id,
            "chain_id": chain_id,
            "parent_action_id": parent_action_id,
            "parent_agent_id": parent_agent_id,
            "session_id": session_id,
            "initiating_user_id": initiating_user_id,
            "session_context": session_context,
            "dynamic_permission": dynamic_permission,
        }
        for key, value in optional_payload.items():
            if value is not None:
                payload[key] = value
        return self._orch.evaluate(endpoint=self._client.authorize_mcp, payload=payload, surface="agent_action")
