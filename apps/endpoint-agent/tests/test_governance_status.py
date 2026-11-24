from __future__ import annotations

from hawk_endpoint_agent.decision import Action, ControlMode, Decision
from hawk_endpoint_agent.governance_status import GovernanceStatusStore


def _decision(*, action=Action.ALLOW, mode=ControlMode.INLINE_ALLOWED, evidence="evidence-1"):
    return Decision(
        action=action,
        control_mode=mode,
        reason="policy",
        evidence_ref=evidence,
        detail={"policy_id": "policy-7"},
    )


def test_records_only_bounded_privacy_safe_governance_fields() -> None:
    now = [1_800_000_000.0]
    store = GovernanceStatusStore(clock=lambda: now[0], ttl_seconds=30, max_sessions=2)

    store.record(
        {
            "client_app": "Claude Desktop",
            "session_id": "session-1",
            "mcp_server_id": "github",
            "available_tools_count": 42,
            "usage": {"total_tokens": 1234},
            "cost": {
                "amount": 0.0215,
                "currency": "USD",
                "source": "PROVIDER_REPORTED",
            },
            "cost_usage_verified": True,
            "prompt": "bank secret",
            "arguments": {"api_key": "never-store-me"},
            "tool_output": "raw customer data",
        },
        _decision(),
        adapter_path="mcp",
    )

    status = store.status("Claude Desktop")
    assert status["state"] == "governed"
    assert status["client_app"] == "Claude Desktop"
    assert status["session_id"] == "session-1"
    assert status["server_id"] == "github"
    assert status["available_tool_count"] == 42
    assert status["tool_call_count"] == 1
    assert status["token_usage"] == {"total": 1234, "provenance": "estimated"}
    assert status["cost_usage"] == {
        "amount": 0.0215,
        "currency": "USD",
        "provenance": "exact",
        "source": "provider_reported",
    }
    assert status["evidence_ref"] == "evidence-1"
    assert status["policy_id"] == "policy-7"
    serialized = repr(status)
    assert "bank secret" not in serialized
    assert "never-store-me" not in serialized
    assert "raw customer data" not in serialized


def test_exact_token_provenance_requires_verified_adapter_assertion() -> None:
    store = GovernanceStatusStore(clock=lambda: 1_800_000_000.0)
    store.record(
        {
            "client_app": "Codex",
            "usage": {"total_tokens": 25},
            "token_usage_provenance": "exact",
        },
        _decision(),
        adapter_path="mcp",
    )
    assert store.status("Codex")["token_usage"]["provenance"] == "estimated"

    store.record(
        {
            "client_app": "Codex",
            "usage": {"total_tokens": 30},
            "token_usage_provenance": "exact",
            "token_usage_verified": True,
        },
        _decision(),
        adapter_path="mcp",
    )
    assert store.status("Codex")["token_usage"] == {
        "total": 30,
        "provenance": "exact",
    }


def test_cost_without_verified_source_is_not_presented_as_exact() -> None:
    store = GovernanceStatusStore(clock=lambda: 1_800_000_000.0)
    store.record(
        {
            "client_app": "Codex",
            "cost": {
                "amount": 0.014,
                "currency": "USD",
                "source": "PROVIDER_REPORTED",
            },
        },
        _decision(),
        adapter_path="mcp",
    )
    assert store.status("Codex")["cost_usage"] == {
        "amount": 0.014,
        "currency": "USD",
        "provenance": "estimated",
        "source": "provider_reported",
    }


def test_state_is_evidence_backed_and_expires_conservatively() -> None:
    now = [1_800_000_000.0]
    store = GovernanceStatusStore(clock=lambda: now[0], ttl_seconds=30)
    store.record(
        {"client_app": "Claude"},
        _decision(action=Action.BLOCK, mode=ControlMode.INLINE_PREVENTED),
        adapter_path="mcp",
    )
    assert store.status("Claude")["state"] == "blocked"

    store.record(
        {"client_app": "Codex"},
        _decision(mode=ControlMode.MONITOR_WOULD_BLOCK),
        adapter_path="mcp",
    )
    assert store.status("Codex")["state"] == "monitor"

    store.record(
        {"client_app": "No Evidence"},
        _decision(evidence=None),
        adapter_path="mcp",
    )
    assert store.status("No Evidence")["state"] == "unknown"

    now[0] += 31
    expired = store.status("Claude")
    assert expired["state"] == "unknown"
    assert expired["evidence_ref"] is None
    assert expired["reason"] == "no_fresh_verified_decision"


def test_sessions_are_isolated_and_bounded() -> None:
    now = [1_800_000_000.0]
    store = GovernanceStatusStore(clock=lambda: now[0], max_sessions=2)
    for name in ("Claude", "Codex", "Other"):
        store.record({"client_app": name}, _decision(), adapter_path="mcp")
        now[0] += 1

    assert store.status("Claude")["state"] == "unknown"
    assert store.status("Codex")["state"] == "governed"
    assert store.status("Other")["state"] == "governed"
