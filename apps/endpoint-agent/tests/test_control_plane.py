from __future__ import annotations

from hawk_endpoint_agent.control_plane import EndpointControlPlane
from hawk_endpoint_agent.decision import Action, ControlMode, Decision


def _decision(action: str) -> Decision:
    return Decision(
        action=action,
        control_mode=ControlMode.TELEMETRY_ONLY,
        reason="test_policy",
    )


def test_monitor_mode_records_would_block_but_allows() -> None:
    plane = EndpointControlPlane(mode="monitor")

    result = plane.finalize(
        request={"surface": "mcp", "tool_name": "repo.delete"},
        decision=_decision(Action.BLOCK),
        adapter_path="mcp",
        pre_action=True,
    )

    assert result.action == Action.ALLOW
    assert result.control_mode == ControlMode.MONITOR_WOULD_BLOCK
    assert result.detail["would_action"] == Action.BLOCK
    assert result.enforced is False
    posture = plane.posture()
    assert posture["adapters"]["mcp"]["authorization_covered"] is False
    assert posture["adapters"]["mcp"]["last_pre_action_decision_at"] is None


def test_monitor_mode_preserves_would_review_distinction() -> None:
    plane = EndpointControlPlane(mode="monitor")

    result = plane.finalize(
        request={"surface": "developer_agent", "action": "git.push"},
        decision=_decision(Action.HOLD),
        adapter_path="developer_agent",
        pre_action=True,
    )

    assert result.action == Action.ALLOW
    assert result.control_mode == ControlMode.MONITOR_WOULD_REVIEW
    assert result.detail["would_action"] == Action.HOLD


def test_enforce_requires_verified_pre_action_adapter_for_inline_prevented() -> None:
    plane = EndpointControlPlane(mode="enforce")

    result = plane.finalize(
        request={"surface": "mcp", "tool_name": "repo.delete"},
        decision=_decision(Action.BLOCK),
        adapter_path="mcp",
        pre_action=False,
    )

    assert result.action == Action.BLOCK
    assert result.control_mode == ControlMode.DETECT_ONLY
    assert result.enforced is False


def test_verified_pre_action_block_is_inline_prevented() -> None:
    plane = EndpointControlPlane(mode="enforce")

    result = plane.finalize(
        request={"surface": "llm", "provider": "openai"},
        decision=_decision(Action.BLOCK),
        adapter_path="local_proxy",
        pre_action=True,
    )

    assert result.action == Action.BLOCK
    assert result.control_mode == ControlMode.INLINE_PREVENTED
    assert result.enforced is True
    posture = plane.posture()
    assert posture["adapters"]["local_proxy"]["authorization_covered"] is True
    assert posture["adapters"]["local_proxy"]["last_pre_action_decision_at"]


def test_unobserved_adapter_does_not_inherit_coverage() -> None:
    plane = EndpointControlPlane(mode="enforce")
    plane.finalize(
        request={"surface": "mcp"},
        decision=_decision(Action.ALLOW),
        adapter_path="mcp",
        pre_action=True,
    )

    posture = plane.posture()
    assert posture["adapters"]["mcp"]["authorization_covered"] is True
    assert posture["adapters"]["sdk"]["authorization_covered"] is False
