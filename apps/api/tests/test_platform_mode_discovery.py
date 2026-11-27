from __future__ import annotations

import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.main import app
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "platform_mode.sqlite3"
    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Platform Mode Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _set_platform_mode(client: TestClient, *, headers: dict[str, str], mode: str) -> dict[str, Any]:
    update = client.post(
        "/system/platform-mode",
        headers=headers,
        json={"platform_mode": mode},
    )
    assert update.status_code == 200, update.text
    current = client.get("/system/platform-mode", headers=headers)
    assert current.status_code == 200, current.text
    body = current.json()
    assert body["platform_mode"] == mode
    return body


def _build_guardian(*, guardian_id: str, token: str, ticket_severity: str = "high") -> dict[str, Any]:
    return {
        "guardian_id": guardian_id,
        "description": f"Guardian {guardian_id}",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text"],
            "conditions": [
                {
                    "field": "prompt.text",
                    "operator": "contains",
                    "value": token,
                    "case_sensitive": False,
                }
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.6},
        "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
        "actions": {
            "redact": {"fields": ["prompt"], "strategy": "mask"},
            "mutate_output": {"enabled": False, "strategy": "safe_completion"},
            "notify": {"channels": ["email"]},
            "create_ticket": {"system": "jira", "severity": ticket_severity},
        },
        "evidence": {
            "evidence_signal_type": f"guardian.{guardian_id}.detected",
            "link_to_controls": ["CTRL-DISC-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.1,
            "increase_simulation_frequency": False,
            "enforcement_strictness_increase": 1,
        },
        "approval_workflow": {
            "required_roles": ["owner", "admin"],
            "sla_minutes": 30,
            "default_if_timeout": "block",
        },
    }


def _create_active_policy(client: TestClient, *, headers: dict[str, str], guardian: dict[str, Any]) -> str:
    pack = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Platform Mode Pack", "description": "platform mode", "status": "draft"},
    )
    assert pack.status_code == 200, pack.text
    pack_id = pack.json()["pack"]["id"]

    activate = client.patch(
        f"/policies/packs/{pack_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert activate.status_code == 200, activate.text

    version = client.post(
        f"/policies/packs/{pack_id}/versions",
        headers=headers,
        json={
            "version": "1.0.9",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": [guardian],
        },
    )
    assert version.status_code == 200, version.text
    return version.json()["id"]


def _create_ai_system(client: TestClient, *, headers: dict[str, str], name: str, risk_tier: str = "LOW") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _intercept(client: TestClient, *, headers: dict[str, str], ai_system_id: str, token: str) -> dict[str, Any]:
    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": f"please execute {token}",
            "context_summary": "platform mode test",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _findings_for_enforcement(client: TestClient, *, headers: dict[str, str]) -> list[dict[str, Any]]:
    response = client.get(
        "/findings",
        headers=headers,
        params={"finding_type_filter": "enforcement_event"},
    )
    assert response.status_code == 200, response.text
    return response.json()["items"]


def test_discovery_mode_downgrades_non_critical_block_to_warn(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="pm-discovery-noncritical@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _set_platform_mode(client, headers=headers, mode="discovery")
    token = "noncritical-trigger"
    _create_active_policy(
        client,
        headers=headers,
        guardian=_build_guardian(guardian_id="prompt_injection", token=token, ticket_severity="high"),
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="Discovery Mode Non Critical")

    result = _intercept(client, headers=headers, ai_system_id=ai_system_id, token=token)
    assert result["final_decision"] == "warn", {
        "guardians": [
            {
                "guardian_id": row.get("guardian_id"),
                "decision": row.get("decision"),
                "reason": row.get("reason"),
                "matched_conditions": row.get("matched_conditions"),
                "actions_taken": row.get("actions_taken"),
            }
            for row in result["guardian_results"]
        ],
        "platform_mode_override": result["final_actions"].get("platform_mode_override"),
    }
    assert result["final_actions"]["platform_mode_override"]["override_applied"] is True
    assert result["final_actions"]["platform_mode_override"]["reason"] == "non_critical_discovery_mode"
    assert all(row.get("decision") != "block" for row in result["guardian_results"])


def test_discovery_mode_keeps_critical_threats_blocked(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="pm-discovery-critical@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _set_platform_mode(client, headers=headers, mode="discovery")
    token = "critical-trigger"
    _create_active_policy(
        client,
        headers=headers,
        guardian=_build_guardian(guardian_id="sensitive_data_leakage", token=token, ticket_severity="critical"),
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="Discovery Mode Critical")

    result = _intercept(client, headers=headers, ai_system_id=ai_system_id, token=token)
    assert result["final_decision"] == "block"
    assert result["final_actions"]["platform_mode_override"]["override_applied"] is False
    assert result["final_actions"]["platform_mode_override"]["reason"] == "critical_threat"


def test_findings_generation_remains_identical_across_modes(test_env) -> None:
    client: TestClient = test_env["client"]
    token = "identical-trigger"

    enforce_owner = _register_owner(client, email="pm-enforce@example.com")
    enforce_headers = _headers(enforce_owner["access_token"], enforce_owner["tenant_id"])
    _create_active_policy(
        client,
        headers=enforce_headers,
        guardian=_build_guardian(guardian_id="prompt_injection", token=token, ticket_severity="high"),
    )
    enforce_system_id = _create_ai_system(client, headers=enforce_headers, name="Enforce Tenant")
    enforce_result = _intercept(client, headers=enforce_headers, ai_system_id=enforce_system_id, token=token)
    assert enforce_result["final_decision"] == "block"
    enforce_findings = _findings_for_enforcement(client, headers=enforce_headers)
    assert len(enforce_findings) == 1

    discovery_owner = _register_owner(client, email="pm-discovery@example.com")
    discovery_headers = _headers(discovery_owner["access_token"], discovery_owner["tenant_id"])
    _set_platform_mode(client, headers=discovery_headers, mode="discovery")
    _create_active_policy(
        client,
        headers=discovery_headers,
        guardian=_build_guardian(guardian_id="prompt_injection", token=token, ticket_severity="high"),
    )
    discovery_system_id = _create_ai_system(client, headers=discovery_headers, name="Discovery Tenant")
    discovery_result = _intercept(client, headers=discovery_headers, ai_system_id=discovery_system_id, token=token)
    assert discovery_result["final_decision"] == "warn", (
        discovery_result["guardian_results"],
        discovery_result["final_actions"],
    )
    discovery_findings = _findings_for_enforcement(client, headers=discovery_headers)
    assert len(discovery_findings) == 1

    enforce_finding = enforce_findings[0]
    discovery_finding = discovery_findings[0]
    assert enforce_finding["finding_type"] == discovery_finding["finding_type"] == "enforcement_event"
    assert enforce_finding["risk_category"] == discovery_finding["risk_category"]
    assert enforce_finding["related_control_ids"] == discovery_finding["related_control_ids"]
    assert bool(enforce_finding["evidence_node_ids"])
    assert bool(discovery_finding["evidence_node_ids"])


def test_the_console_is_told_whether_control_coverage_is_on(test_env, monkeypatch) -> None:
    # Off by default: the console leaves Control Coverage out rather than calling it and reporting a 404 as unavailable.
    from app.core.config import settings

    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="features-owner@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    monkeypatch.setattr(settings, "control_coverage_api_enabled", False)
    assert client.get("/system/features", headers=headers).json() == {"control_coverage": False}
    monkeypatch.setattr(settings, "control_coverage_api_enabled", True)
    assert client.get("/system/features", headers=headers).json() == {"control_coverage": True}
