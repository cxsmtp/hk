from __future__ import annotations

from pathlib import Path

from hawk_endpoint_agent.baseline import BaselineStore
from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.control_plane import EndpointControlPlane
from hawk_endpoint_agent.dispatcher import Dispatcher
from hawk_endpoint_agent.evidence_queue import EvidenceQueue


class _Policy:
    policy = None

    def fail_secure_decision(self, *, surface: str, reason: str):
        raise AssertionError(f"unexpected fail secure: {surface}:{reason}")


class _Client:
    def __init__(self):
        self.llm_payloads = []
        self.mcp_payloads = []

    def intercept_llm(self, payload):
        self.llm_payloads.append(payload)
        return {"final_decision": "block", "reason_code": "credential_exposure"}

    def authorize_mcp(self, payload):
        self.mcp_payloads.append(payload)
        return {"decision": "block", "reason": "high_impact_write"}

    def check_data_transfer(self, payload):
        return {"decision": "allow", "reason": "within_policy"}


def _dispatcher(tmp_path: Path, *, mode: str) -> tuple[Dispatcher, EndpointControlPlane, BaselineStore, EvidenceQueue]:
    config = AgentConfig(
        agent_mode=mode,
        default_ai_system_id="registered-ai-system",
        policy_cache_path=str(tmp_path / "policy.json"),
        baseline_path=str(tmp_path / "baseline.json"),
        evidence_queue_path=str(tmp_path / "queue.json"),
    )
    plane = EndpointControlPlane(mode=mode)
    baseline = BaselineStore(config.baseline_path, tenant_key="tenant-1")
    queue = EvidenceQueue(config.evidence_queue_path, max_items=20)
    dispatcher = Dispatcher(
        config,
        client=_Client(),
        policy=_Policy(),
        control_plane=plane,
        baseline=baseline,
        evidence_queue=queue,
    )
    return dispatcher, plane, baseline, queue


def test_monitor_ipc_path_records_would_block_without_raw_prompt(tmp_path) -> None:
    dispatcher, plane, baseline, queue = _dispatcher(tmp_path, mode="monitor")

    result = dispatcher.evaluate_as_dict(
        {"surface": "llm", "prompt": "sk-live-secret", "provider": "openai"},
        adapter_path="local_ipc",
        pre_action=True,
    )

    assert result["action"] == "allow"
    assert result["control_mode"] == "monitor_would_block"
    assert baseline.snapshot()["observation_count"] == 1
    assert queue.items()[0]["kind"] == "monitor_observation"
    assert "sk-live-secret" not in (tmp_path / "baseline.json").read_text()
    assert "sk-live-secret" not in (tmp_path / "queue.json").read_text()
    assert plane.posture()["adapters"]["local_ipc"]["authorization_covered"] is False


def test_enforce_mcp_path_blocks_and_creates_decision_receipt(tmp_path) -> None:
    dispatcher, plane, _baseline, queue = _dispatcher(tmp_path, mode="enforce")

    result = dispatcher.evaluate_as_dict(
        {"surface": "mcp", "tool_name": "repo.delete", "action": "repository.write"},
        adapter_path="mcp",
        pre_action=True,
    )

    assert result["action"] == "block"
    assert result["control_mode"] == "inline_prevented"
    assert queue.items()[0]["kind"] == "decision_receipt"
    posture = plane.posture()
    assert posture["adapters"]["mcp"]["authorization_covered"] is True
    assert posture["adapters"]["sdk"]["authorization_covered"] is False


def test_mcp_path_forwards_gateway_context_without_ui_or_unknown_fields(tmp_path) -> None:
    dispatcher, _plane, _baseline, queue = _dispatcher(tmp_path, mode="enforce")

    result = dispatcher.evaluate_as_dict(
        {
            "protocol_version": 1,
            "op": "evaluate",
            "surface": "mcp",
            "action": "file_read",
            "resource": "github/github-mcp-server",
            "tool_name": "list_pull_requests",
            "provider": "mcp",
            "tool_category": "read",
            "api_endpoint": "github.com",
            "tool_usage_meta": {
                "mcp_server_id": "github-pull-requests",
                "tool_version": "1.8.0",
                "tool_fingerprint_id": "fingerprint-1",
                "parameters": {"sentinel": "HMAIR_RAW_ARG_SENTINEL"},
                "arguments_summary": {"keys": ["owner", "repo", "state"]},
            },
            "context_id": "context-1",
            "chain_id": "chain-1",
            "parent_action_id": "parent-action-1",
            "parent_agent_id": "parent-agent-1",
            "session_id": "session-1",
            "initiating_user_id": "user-1",
            "session_context": {
                "session_id": "session-1",
                "source_surface": "gateway",
                "allowed_tools": ["list_pull_requests"],
            },
            "dynamic_permission": {
                "allowed_tools": ["list_pull_requests"],
                "mode": "monitor",
            },
            "client_app": "Codex",
            "unknown_decoy": "must-not-forward",
        },
        adapter_path="mcp",
        pre_action=True,
    )

    assert result["action"] == "block"
    payload = dispatcher.client.mcp_payloads[-1]
    assert payload["provider"] == "mcp"
    assert payload["tool_category"] == "read"
    assert payload["api_endpoint"] == "github.com"
    assert payload["tool_usage_meta"]["mcp_server_id"] == "github-pull-requests"
    assert payload["tool_usage_meta"]["tool_version"] == "1.8.0"
    assert payload["tool_usage_meta"]["tool_fingerprint_id"] == "fingerprint-1"
    assert payload["tool_usage_meta"]["parameters"] == {"sentinel": "HMAIR_RAW_ARG_SENTINEL"}
    assert payload["context_id"] == "context-1"
    assert payload["chain_id"] == "chain-1"
    assert payload["parent_action_id"] == "parent-action-1"
    assert payload["parent_agent_id"] == "parent-agent-1"
    assert payload["session_id"] == "session-1"
    assert payload["initiating_user_id"] == "user-1"
    assert payload["session_context"]["source_surface"] == "gateway"
    assert payload["dynamic_permission"]["allowed_tools"] == ["list_pull_requests"]
    assert "client_app" not in payload
    assert "protocol_version" not in payload
    assert "op" not in payload
    assert "surface" not in payload
    assert "unknown_decoy" not in payload
    assert queue.items()[0]["kind"] == "decision_receipt"
    assert "HMAIR_RAW_ARG_SENTINEL" not in (tmp_path / "baseline.json").read_text()
    assert "HMAIR_RAW_ARG_SENTINEL" not in (tmp_path / "queue.json").read_text()


def test_unverified_sdk_observation_never_becomes_inline(tmp_path) -> None:
    dispatcher, plane, _baseline, _queue = _dispatcher(tmp_path, mode="enforce")

    result = dispatcher.evaluate_as_dict(
        {"surface": "sdk", "prompt": "safe"},
        adapter_path="sdk",
        pre_action=False,
    )

    assert result["control_mode"] == "detect_only"
    assert plane.posture()["adapters"]["sdk"]["authorization_covered"] is False


def test_llm_and_mcp_use_registered_default_ai_system(tmp_path) -> None:
    dispatcher, _plane, _baseline, _queue = _dispatcher(tmp_path, mode="monitor")

    dispatcher.evaluate_as_dict(
        {"surface": "llm", "prompt": "hello", "provider": "openai"},
        adapter_path="llm",
        pre_action=True,
    )
    dispatcher.evaluate_as_dict(
        {"surface": "mcp", "tool_name": "repo.read", "action": "repository.read"},
        adapter_path="mcp",
        pre_action=True,
    )

    assert dispatcher.client.llm_payloads[-1]["ai_system_id"] == "registered-ai-system"
    assert dispatcher.client.mcp_payloads[-1]["ai_system_id"] == "registered-ai-system"


def test_request_ai_system_overrides_registered_default(tmp_path) -> None:
    dispatcher, _plane, _baseline, _queue = _dispatcher(tmp_path, mode="monitor")

    dispatcher.evaluate_as_dict(
        {"surface": "llm", "prompt": "hello", "ai_system_id": "specific-ai-system"},
        adapter_path="llm",
        pre_action=True,
    )

    assert dispatcher.client.llm_payloads[-1]["ai_system_id"] == "specific-ai-system"
