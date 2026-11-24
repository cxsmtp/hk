from __future__ import annotations

import json

from hawk_endpoint_agent.baseline import BaselineStore
from hawk_endpoint_agent.decision import Action, ControlMode, Decision


def _decision(action: str, *, threats: list[str] | None = None) -> Decision:
    return Decision(
        action=action,
        control_mode=ControlMode.MONITOR_WOULD_BLOCK,
        reason="sensitive_data",
        threat_types=threats or ["credential_exposure"],
        detail={"would_action": action},
    )


def test_observation_never_persists_raw_content(tmp_path) -> None:
    path = tmp_path / "baseline.json"
    store = BaselineStore(path, tenant_key="tenant-1", max_paths=50)

    store.observe(
        request={
            "surface": "llm",
            "adapter_path": "local_proxy",
            "provider": "openai",
            "prompt": "secret-value",
            "api_key": "sk-test-super-secret",
            "tool_arguments": {"document": "board-plan"},
        },
        decision=_decision(Action.BLOCK),
    )

    persisted = path.read_text(encoding="utf-8")
    assert "secret-value" not in persisted
    assert "sk-test-super-secret" not in persisted
    assert "board-plan" not in persisted
    assert "credential_exposure" in persisted


def test_policy_proposal_is_count_based_and_deterministic(tmp_path) -> None:
    store = BaselineStore(tmp_path / "baseline.json", tenant_key="tenant-1")
    request = {
        "surface": "mcp",
        "adapter_path": "mcp",
        "tool_name": "repo.delete",
        "action": "repository.write",
    }
    store.observe(request=request, decision=_decision(Action.BLOCK))
    store.observe(request=request, decision=_decision(Action.BLOCK))

    first = store.propose()
    second = store.propose()

    assert first == second
    assert first["status"] == "ready"
    assert first["observation_count"] == 2
    assert first["rules"][0]["match"]["surface"] == "mcp"
    assert first["rules"][0]["decision"] == "block"
    serialized = json.dumps(first)
    assert "repo.delete" not in serialized


def test_empty_baseline_reports_insufficient_evidence(tmp_path) -> None:
    store = BaselineStore(tmp_path / "baseline.json")

    assert store.propose() == {
        "status": "insufficient_evidence",
        "observation_count": 0,
        "path_count": 0,
        "rules": [],
    }


def test_path_limit_evicts_oldest_aggregate(tmp_path) -> None:
    store = BaselineStore(tmp_path / "baseline.json", max_paths=2)
    for surface in ("browser", "mcp", "sdk"):
        store.observe(
            request={"surface": surface, "adapter_path": surface},
            decision=_decision(Action.ALLOW, threats=[]),
        )

    snapshot = store.snapshot()
    assert snapshot["path_count"] == 2
    assert snapshot["evicted_path_count"] == 1

