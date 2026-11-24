from __future__ import annotations

from pathlib import Path

from hawk_endpoint_agent.baseline import BaselineStore
from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.control_plane import EndpointControlPlane
from hawk_endpoint_agent.dispatcher import Dispatcher
from hawk_endpoint_agent.evidence_queue import EvidenceQueue
from hawk_endpoint_agent.ipc.control_server import _adapter_path_for


class _Policy:
    policy = None

    def fail_secure_decision(self, *, surface: str, reason: str):
        raise AssertionError(f"unexpected fail secure: {surface}:{reason}")


class _FunctionalClient:
    def intercept_llm(self, payload):
        prompt = str(payload.get("prompt") or "")
        return {
            "final_decision": "block" if "HAWK_DEMO_TEST_CREDENTIAL" in prompt else "allow",
            "reason_code": "credential_exposure" if "HAWK_DEMO_TEST_CREDENTIAL" in prompt else "within_policy",
        }

    def authorize_mcp(self, payload):
        action = str(payload.get("action") or "")
        blocked = any(value in action for value in ("write", "publish", "delete"))
        return {"decision": "block" if blocked else "allow", "reason": "high_impact_write" if blocked else "within_policy"}

    def check_data_transfer(self, payload):
        copied = str(payload.get("copied_text") or "")
        return {"decision": "block" if "HAWK_DEMO_TEST_CREDENTIAL" in copied else "allow", "reason": "data_boundary"}


def _build(tmp_path: Path, mode: str = "monitor"):
    config = AgentConfig(
        agent_mode=mode,
        tenant_id="tenant-1",
        policy_cache_path=str(tmp_path / "policy.json"),
        baseline_path=str(tmp_path / "baseline.json"),
        evidence_queue_path=str(tmp_path / "queue.json"),
        mode_state_path=str(tmp_path / "mode.json"),
    )
    plane = EndpointControlPlane(mode=mode, mode_path=config.mode_state_path)
    baseline = BaselineStore(config.baseline_path, tenant_key=config.tenant_id)
    queue = EvidenceQueue(config.evidence_queue_path, max_items=100)
    dispatcher = Dispatcher(
        config,
        client=_FunctionalClient(),
        policy=_Policy(),
        control_plane=plane,
        baseline=baseline,
        evidence_queue=queue,
    )
    return dispatcher, plane, baseline, queue


def test_ipc_maps_each_supported_surface_to_its_own_adapter() -> None:
    assert _adapter_path_for({"surface": "browser"}) == "browser"
    assert _adapter_path_for({"surface": "mcp"}) == "mcp"
    assert _adapter_path_for({"surface": "llm"}) == "llm"
    assert _adapter_path_for({"surface": "sdk"}) == "sdk"
    assert _adapter_path_for({"surface": "developer_agent"}) == "developer_agent"
    assert _adapter_path_for({"surface": "foundry"}) == "foundry"
    assert _adapter_path_for({"surface": "unknown"}) == "local_ipc"


def test_monitor_then_enforce_then_rollback_across_llm_surfaces(tmp_path) -> None:
    dispatcher, plane, _baseline, queue = _build(tmp_path)
    sensitive = "HAWK_DEMO_TEST_CREDENTIAL=not-real"

    for surface in ("browser", "llm", "sdk", "foundry"):
        result = dispatcher.evaluate_as_dict(
            {"surface": surface, "prompt": sensitive, "provider": "openai"},
            adapter_path=surface,
            pre_action=True,
        )
        assert result["action"] == "allow"
        assert result["control_mode"] == "monitor_would_block"

    plane.set_mode("enforce")
    blocked = dispatcher.evaluate_as_dict(
        {"surface": "sdk", "prompt": sensitive},
        adapter_path="sdk",
        pre_action=True,
    )
    assert blocked["action"] == "block"
    assert blocked["control_mode"] == "inline_prevented"

    plane.set_mode("monitor")
    rolled_back = dispatcher.evaluate_as_dict(
        {"surface": "sdk", "prompt": sensitive},
        adapter_path="sdk",
        pre_action=True,
    )
    assert rolled_back["action"] == "allow"
    assert rolled_back["control_mode"] == "monitor_would_block"
    assert any(item["kind"] == "decision_receipt" for item in queue.items())


def test_mcp_and_developer_agent_share_canonical_write_policy(tmp_path) -> None:
    dispatcher, plane, _baseline, _queue = _build(tmp_path, mode="enforce")
    plane.set_mode("enforce")

    for surface in ("mcp", "developer_agent"):
        result = dispatcher.evaluate_as_dict(
            {"surface": surface, "action": "repository.write", "tool_name": "repo.write"},
            adapter_path=surface,
            pre_action=True,
        )
        assert result["action"] == "block"
        assert result["control_mode"] == "inline_prevented"


def test_tool_drift_creates_distinct_fingerprints_without_tool_names(tmp_path) -> None:
    dispatcher, _plane, baseline, _queue = _build(tmp_path)
    for tool in ("repo.read@1", "repo.read@2"):
        dispatcher.evaluate_as_dict(
            {"surface": "mcp", "action": "read", "tool_name": tool},
            adapter_path="mcp",
            pre_action=True,
        )

    snapshot = baseline.snapshot()
    fingerprints = {path["tool_fingerprint"] for path in snapshot["paths"]}
    assert len(fingerprints) == 2
    persisted = (tmp_path / "baseline.json").read_text(encoding="utf-8")
    assert "repo.read@1" not in persisted
    assert "repo.read@2" not in persisted


def test_uninstrumented_sdk_path_is_detect_only(tmp_path) -> None:
    dispatcher, plane, _baseline, _queue = _build(tmp_path, mode="enforce")
    plane.set_mode("enforce")

    result = dispatcher.evaluate_as_dict(
        {"surface": "sdk", "prompt": "HAWK_DEMO_TEST_CREDENTIAL=not-real"},
        adapter_path="sdk",
        pre_action=False,
    )

    assert result["control_mode"] == "detect_only"
    assert plane.posture()["adapters"]["sdk"]["authorization_covered"] is False
