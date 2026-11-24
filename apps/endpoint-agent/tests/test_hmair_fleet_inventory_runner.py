from __future__ import annotations

import json
from pathlib import Path

from hawk_endpoint_agent.config import AgentConfig
from hawk_endpoint_agent.policy import EndpointPolicy
from hawk_endpoint_agent.runner import AgentRunner


_ASSIGNMENT_ID = "e08d8ca9-b31c-4fe6-b559-b9ca57bf2e06"
_RUN_ID = "3c042ffd-d3b2-4ea4-b8b8-329e5a557e93"


class _InventoryClient:
    def __init__(self) -> None:
        self.failures: list[tuple[str, str]] = []

    def sync_policy(self) -> dict[str, object]:
        return {
            "platform_mode": "monitor",
            "modules": {},
            "hmair_metadata_inventory": {
                "assignment_id": _ASSIGNMENT_ID,
                "inventory_run_id": _RUN_ID,
                "mode": "metadata_only",
                "expires_at": "2026-09-03T15:00:00+00:00",
            },
        }

    def report_hmair_inventory_failure(self, assignment_id: str, code: str) -> None:
        self.failures.append((assignment_id, code))


def _runner(tmp_path: Path) -> tuple[AgentRunner, _InventoryClient]:
    client = _InventoryClient()
    config = AgentConfig(
        agent_mode="monitor",
        mode_state_path=str(tmp_path / "mode.json"),
        policy_cache_path=str(tmp_path / "policy-cache.json"),
        evidence_queue_path=str(tmp_path / "evidence.json"),
        baseline_path=str(tmp_path / "baseline.json"),
        legacy_bootstrap_path=str(tmp_path / "legacy-bootstrap"),
        enabled_modules=[],
    )
    return AgentRunner(config, client=client), client


def test_policy_rejects_a_malformed_inventory_directive() -> None:
    policy = EndpointPolicy.from_backend(
        {
            "hmair_metadata_inventory": {
                "assignment_id": "not-a-uuid",
                "mode": "metadata_only",
            }
        }
    )

    assert policy.hmair_metadata_inventory is None


def test_runner_executes_a_delivered_assignment_once_and_binds_the_receipt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner, _client = _runner(tmp_path)
    captured: list[dict[str, object]] = []

    def fake_snapshot(config, **kwargs):
        captured.append({"config": config, **kwargs})
        return {
            "scan_id": "00000000-0000-4000-8000-000000000001",
            "status": "complete",
            "observations_count": 1,
            "endpoint_denominator": 1,
            "limitations": ["coverage:single_enrolled_endpoint"],
        }

    monkeypatch.setattr("hawk_endpoint_agent.runner.run_hmair_discovery_snapshot", fake_snapshot)
    assert runner.refresh_policy() is True

    runner._dispatch_hmair_metadata_inventory()
    runner._dispatch_hmair_metadata_inventory()

    assert len(captured) == 1
    assert captured[0]["snapshot_id"] == _ASSIGNMENT_ID
    assert captured[0]["inventory_assignment_id"] == _ASSIGNMENT_ID


def test_inventory_directive_is_not_written_to_the_existing_policy_cache(
    tmp_path: Path,
) -> None:
    runner, _client = _runner(tmp_path)

    assert runner.refresh_policy() is True

    cached = json.loads(Path(runner.config.policy_cache_path).read_text(encoding="utf-8"))
    assert "hmair_metadata_inventory" not in cached["payload"]
    assert runner.policy.policy is not None
    assert runner.policy.policy.hmair_metadata_inventory is not None


def test_runner_reports_only_a_bounded_failure_code(
    tmp_path: Path,
    monkeypatch,
) -> None:
    runner, client = _runner(tmp_path)

    def reject_snapshot(*_args, **_kwargs):
        from hawk_endpoint_agent.hmair_snapshot import HMAIRSnapshotError

        raise HMAIRSnapshotError("unsafe local metadata")

    monkeypatch.setattr(
        "hawk_endpoint_agent.runner.run_hmair_discovery_snapshot", reject_snapshot
    )
    assert runner.refresh_policy() is True

    runner._dispatch_hmair_metadata_inventory()

    assert client.failures == [(_ASSIGNMENT_ID, "snapshot_rejected")]
