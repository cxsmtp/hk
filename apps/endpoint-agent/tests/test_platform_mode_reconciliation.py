from __future__ import annotations

from pathlib import Path

from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.control_plane import EndpointControlPlane
from hawk_endpoint_agent.decision import Action, ControlMode, Decision
from hawk_endpoint_agent.hawk_client import HawkUnavailable
from hawk_endpoint_agent.runner import AgentRunner


class PolicyClient:
    def __init__(self, platform_mode: str) -> None:
        self.platform_mode = platform_mode
        self.available = True

    def sync_policy(self) -> dict[str, object]:
        if not self.available:
            raise HawkUnavailable("backend unavailable")
        return {
            "platform_mode": self.platform_mode,
            "modules": {},
            "blocked_domains": [],
            "warn_domains": [],
        }


def _runner(tmp_path: Path, *, local_mode: str, remote_mode: str) -> tuple[AgentRunner, PolicyClient]:
    client = PolicyClient(remote_mode)
    config = AgentConfig(
        agent_mode=local_mode,
        mode_state_path=str(tmp_path / "mode.json"),
        policy_cache_path=str(tmp_path / "policy-cache.json"),
        evidence_queue_path=str(tmp_path / "evidence.json"),
        baseline_path=str(tmp_path / "baseline.json"),
        legacy_bootstrap_path=str(tmp_path / "legacy-bootstrap"),
        enabled_modules=[],
    )
    return AgentRunner(config, client=client), client


def test_fresh_discovery_policy_switches_endpoint_to_monitor(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path, local_mode="enforce", remote_mode="discovery")

    assert runner.refresh_policy() is True

    assert runner.control_plane.mode == "monitor"


def test_fresh_enforce_policy_switches_endpoint_to_enforce(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path, local_mode="monitor", remote_mode="enforce")

    assert runner.refresh_policy() is True

    assert runner.control_plane.mode == "enforce"


def test_failed_policy_refresh_preserves_last_confirmed_endpoint_mode(tmp_path: Path) -> None:
    runner, client = _runner(tmp_path, local_mode="monitor", remote_mode="enforce")
    assert runner.refresh_policy() is True
    assert runner.control_plane.mode == "enforce"
    client.platform_mode = "discovery"
    client.available = False

    assert runner.refresh_policy() is False

    assert runner.control_plane.mode == "enforce"


def test_unknown_policy_mode_does_not_change_endpoint_mode(tmp_path: Path) -> None:
    runner, _ = _runner(tmp_path, local_mode="monitor", remote_mode="future_mode")

    assert runner.refresh_policy() is True

    assert runner.control_plane.mode == "monitor"


def test_action_payload_cannot_change_endpoint_mode() -> None:
    control_plane = EndpointControlPlane(mode="monitor")
    decision = Decision(
        action=Action.BLOCK,
        control_mode=ControlMode.INLINE_PREVENTED,
        reason="policy_block",
        source="backend",
    )

    finalized = control_plane.finalize(
        request={"surface": "mcp", "platform_mode": "enforce", "endpoint_mode": "enforce"},
        decision=decision,
        adapter_path="mcp",
        pre_action=True,
    )

    assert control_plane.mode == "monitor"
    assert finalized.action == Action.ALLOW
    assert finalized.control_mode == ControlMode.MONITOR_WOULD_BLOCK
