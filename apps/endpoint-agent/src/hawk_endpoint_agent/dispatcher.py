"""Unified decision dispatcher.

A single entry point that maps any covered surface to the right capability module
and returns a Decision. The local proxy and the control socket both route through
here, so every surface — LLM, browser, native desktop app, MCP, autonomous agent,
data transfer — gets an identical, server-authoritative decision with the enrolled
identity attached.
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timezone
import uuid
import hashlib

from .agent_registration import normalize_agent_registration, registration_telemetry
from .baseline import BaselineStore
from .config import AgentConfig
from .control_plane import EndpointControlPlane
from .decision import Action, Decision
from .evidence_queue import EvidenceQueue
from .enforcement import EnforcementOrchestrator
from .hawk_client import HawkClient
from .governance_status import GovernanceStatusStore
from .identity import resolve_identity
from .modules.agent_runtime import AgentRuntimeModule
from .modules.data_transfer import DataTransferModule
from .modules.interaction_security import InteractionSecurityModule
from .policy import PolicyStore
from .surfaces import Surface

_LLM_SURFACES = {
    Surface.LLM,
    Surface.BROWSER,
    Surface.SDK,
    Surface.FOUNDRY,
    Surface.DESKTOP_NATIVE,
    Surface.SAAS,
}
_MCP_SURFACES = {Surface.MCP, Surface.AI_AGENT, Surface.DEVELOPER_AGENT}


class Dispatcher:
    def __init__(
        self,
        config: AgentConfig,
        *,
        client: HawkClient | None = None,
        policy: PolicyStore | None = None,
        control_plane: EndpointControlPlane | None = None,
        baseline: BaselineStore | None = None,
        evidence_queue: EvidenceQueue | None = None,
        governance_status_store: GovernanceStatusStore | None = None,
    ) -> None:
        self.config = config
        self.client = client or HawkClient(config)
        self.policy = policy or PolicyStore(config, self.client)
        self.control_plane = control_plane or EndpointControlPlane(mode=config.agent_mode)
        self.baseline = baseline or BaselineStore(
            config.baseline_path,
            tenant_key=config.tenant_id or config.endpoint_id or "local",
            max_paths=config.baseline_max_paths,
        )
        self.evidence_queue = evidence_queue or EvidenceQueue(
            config.evidence_queue_path,
            max_items=config.evidence_queue_max_items,
        )
        self.governance_status_store = governance_status_store or GovernanceStatusStore()
        self.orchestrator = EnforcementOrchestrator(config, self.policy)
        self.interaction = InteractionSecurityModule(config, self.client, self.orchestrator)
        self.data_transfer = DataTransferModule(config, self.client, self.orchestrator)
        self.agent_runtime = AgentRuntimeModule(config, self.client, self.orchestrator)
        self.identity = resolve_identity(config)

    def evaluate(
        self,
        request: dict[str, Any],
        *,
        adapter_path: str | None = None,
        pre_action: bool = False,
    ) -> Decision:
        decision = self._evaluate_canonical(request)
        path = str(adapter_path or request.get("surface") or "unknown")
        result = self.control_plane.finalize(
            request=request,
            decision=decision,
            adapter_path=path,
            pre_action=pre_action,
        )
        observed_request = dict(request)
        observed_request["adapter_path"] = path
        self.baseline.observe(request=observed_request, decision=result)
        self._queue_receipt(observed_request, result, pre_action=pre_action)
        self.governance_status_store.record(
            observed_request,
            result,
            adapter_path=path,
        )
        return result

    def _evaluate_canonical(self, request: dict[str, Any]) -> Decision:
        surface = str(request.get("surface") or Surface.LLM).lower()
        if surface in _LLM_SURFACES:
            return self._llm(request)
        if surface in _MCP_SURFACES:
            return self._mcp(request)
        if surface == Surface.DATA_TRANSFER:
            return self._data_transfer(request)
        if request.get("prompt"):
            return self._llm(request)
        return self.policy.fail_secure_decision(surface=surface, reason="unknown_surface")

    def evaluate_as_dict(
        self,
        request: dict[str, Any],
        *,
        adapter_path: str | None = None,
        pre_action: bool = False,
    ) -> dict[str, Any]:
        decision = self.evaluate(request, adapter_path=adapter_path, pre_action=pre_action)
        result = {
            "action": decision.action,
            "control_mode": decision.control_mode,
            "reason": decision.reason,
            "source": decision.source,
            "threat_types": decision.threat_types,
            "framework_refs": decision.framework_refs,
            "evidence_ref": decision.evidence_ref,
            "surface": request.get("surface"),
            "detail": decision.detail,
        }
        if decision.action == Action.SCOPE:
            result["constraints_enforced"] = (
                decision.detail.get("constraints_enforced") is True
            )
        return result

    def scan_mcp_tool(self, request: dict[str, Any]) -> dict[str, Any]:
        """Send an exact MCP descriptor to the backend-owned persistent scanner."""
        payload = {
            "mcp_server_id": request.get("mcp_server_id"),
            "tool_name": request.get("tool_name"),
            "tool_version": request.get("tool_version", "unknown"),
            "description": request.get("description", ""),
            "schema": request.get("schema") or {},
            "examples": request.get("examples") or [],
            "manifest": request.get("manifest"),
            "chain_id": request.get("chain_id"),
            "request_id": request.get("request_id"),
        }
        return self.client.scan_mcp_tool(payload)

    def governance_status(self, request: dict[str, Any]) -> dict[str, Any]:
        """Return the latest fresh, privacy-safe status for one local client."""
        return self.governance_status_store.status(request.get("client_app"))

    def register_agent(self, request: dict[str, Any]) -> dict[str, Any]:
        """Persist a bounded self-registration without asserting authorization."""
        registration = normalize_agent_registration(request)
        telemetry = registration_telemetry(registration)
        response = self.client.report_discovery(telemetry)
        registration_id = hashlib.sha256(
            f"{self.config.endpoint_id}:{registration['agent_id']}".encode("utf-8")
        ).hexdigest()
        return {
            "status": "registered",
            "registration_id": registration_id,
            "evidence_state": "sdk_self_registration",
            "control_state": "monitor_only",
            "active_integration_transport": registration["active_integration_transport"],
            "evidence_ref": (
                str(response.get("evidence_node_id") or "").strip() or None
                if isinstance(response, dict)
                else None
            ),
        }

    def _queue_receipt(self, request: dict[str, Any], decision: Decision, *, pre_action: bool) -> None:
        now = datetime.now(timezone.utc).isoformat()
        kind = "decision_receipt" if self.control_plane.mode == "enforce" and pre_action else "monitor_observation"
        self.evidence_queue.append(
            {
                "id": str(uuid.uuid4()),
                "kind": kind,
                "endpoint_id": self.config.endpoint_id,
                "surface": request.get("surface"),
                "adapter_path": request.get("adapter_path"),
                "action": decision.action,
                "would_action": decision.detail.get("would_action"),
                "control_mode": decision.control_mode,
                "reason": decision.reason,
                "evidence_ref": decision.evidence_ref,
                "pre_action": bool(pre_action),
                "observed_at": now,
            }
        )

    # -- surface routers ---------------------------------------------------
    def _llm(self, r: dict[str, Any]) -> Decision:
        return self.interaction.evaluate_prompt(
            prompt=str(r.get("prompt") or ""),
            ai_system_id=str(
                r.get("ai_system_id")
                or self.config.default_ai_system_id
                or r.get("app")
                or r.get("provider")
                or "endpoint-ai"
            ),
            actor_id=str(r.get("actor_id") or self.identity.user_id or self.identity.os_user or "endpoint-user"),
            actor_type=str(r.get("actor_type") or "human"),
            context_summary=r.get("context_summary"),
            tool_output=r.get("tool_output"),
            response_text=r.get("response_text"),
            provider=r.get("provider"),
        )

    def _mcp(self, r: dict[str, Any]) -> Decision:
        decision = self.agent_runtime.authorize(
            ai_system_id=str(
                r.get("ai_system_id")
                or self.config.default_ai_system_id
                or "endpoint-agent-system"
            ),
            actor_id=str(r.get("actor_id") or self.identity.os_user or "endpoint-agent"),
            capability_token=str(r.get("capability_token") or ""),
            action=str(r.get("action") or ""),
            resource=str(r.get("resource") or ""),
            chain_depth=int(r.get("chain_depth") or 1),
            tool_name=r.get("tool_name"),
            provider=r.get("provider"),
            model=r.get("model"),
            model_version=r.get("model_version"),
            data_source=r.get("data_source"),
            tool_category=r.get("tool_category"),
            api_endpoint=r.get("api_endpoint"),
            tool_usage_meta=r.get("tool_usage_meta"),
            context_id=r.get("context_id"),
            chain_id=r.get("chain_id"),
            parent_action_id=r.get("parent_action_id"),
            parent_agent_id=r.get("parent_agent_id"),
            session_id=r.get("session_id"),
            initiating_user_id=r.get("initiating_user_id"),
            session_context=r.get("session_context"),
            dynamic_permission=r.get("dynamic_permission"),
        )
        if decision.action == Action.SCOPE:
            # HawkClient converts unproven backend scope responses to block. A
            # remaining scope therefore carries an explicit backend enforcement
            # assertion that the IPC client must verify before execution.
            decision.detail["constraints_enforced"] = True
        return decision

    def _data_transfer(self, r: dict[str, Any]) -> Decision:
        return self.data_transfer.evaluate(
            copied_text=str(r.get("copied_text") or ""),
            source_domain=r.get("source_domain"),
            destination_domain=r.get("destination_domain"),
            destination_app=r.get("destination_app"),
        )
