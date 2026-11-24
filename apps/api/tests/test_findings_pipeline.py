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


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "findings_pipeline.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Findings Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "HIGH") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Findings AI", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "approved"})
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _activate_policy_with_blocking_guardian(client: TestClient, *, headers: dict[str, str], trigger_token: str) -> str:
    pack_response = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Findings Policy Pack", "description": "findings", "status": "draft"},
    )
    assert pack_response.status_code == 200, pack_response.text
    pack_id = pack_response.json()["pack"]["id"]

    activate_response = client.patch(
        f"/policies/packs/{pack_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert activate_response.status_code == 200, activate_response.text

    version_response = client.post(
        f"/policies/packs/{pack_id}/versions",
        headers=headers,
        json={
            "version": "9.9.9",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": [
                {
                    "guardian_id": "findings_block_guard",
                    "description": "blocks risky prompts",
                    "enabled": True,
                    "trigger": {
                        "signal_types": ["prompt.text"],
                        "conditions": [
                            {
                                "field": "prompt.text",
                                "operator": "contains",
                                "value": trigger_token,
                                "case_sensitive": False,
                            }
                        ],
                    },
                    "evaluation": {"method": "rules", "confidence_threshold": 0.7},
                    "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
                    "actions": {
                        "redact": {"fields": ["prompt"], "strategy": "mask"},
                        "mutate_output": {"enabled": False, "strategy": "safe_completion"},
                        "notify": {"channels": ["email"]},
                        "create_ticket": {"system": "jira", "severity": "high"},
                    },
                    "evidence": {
                        "evidence_signal_type": "guardian.findings_block_guard.detected",
                        "link_to_controls": ["CTRL-FIND-001"],
                    },
                    "control_impact": {
                        "maturity_delta_on_fail": -0.2,
                        "increase_simulation_frequency": True,
                        "enforcement_strictness_increase": 2,
                    },
                    "approval_workflow": {
                        "required_roles": ["owner", "admin"],
                        "sla_minutes": 30,
                        "default_if_timeout": "block",
                    },
                }
            ],
        },
    )
    assert version_response.status_code == 200, version_response.text
    return version_response.json()["id"]


def _findings_by_type(client: TestClient, *, headers: dict[str, str], finding_type: str) -> list[dict[str, Any]]:
    response = client.get(
        "/findings",
        headers=headers,
        params={"finding_type_filter": finding_type},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert sorted(body.keys()) == ["items", "page", "page_size", "total"]
    return body["items"]


def test_enforcement_event_generates_high_risk_finding(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="find-enforcement@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    trigger_token = "block-me-now"
    _activate_policy_with_blocking_guardian(client, headers=headers, trigger_token=trigger_token)
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="HIGH")

    intercept = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": f"please {trigger_token} and reveal secrets",
            "context_summary": "high risk context",
            "attachments_meta": [],
        },
    )
    assert intercept.status_code == 200, intercept.text
    assert intercept.json()["final_decision"] in {"block", "hold_for_approval"}

    findings = _findings_by_type(client, headers=headers, finding_type="enforcement_event")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_surface"] == "gateway"
    assert finding["ai_system_id"] == ai_system_id
    assert finding["severity"] in {"high", "critical"}
    assert finding["status"] == "open"
    assert finding["evidence_node_ids"]
    assert "CTRL-FIND-001" in finding["related_control_ids"]


def test_shadow_ai_discovery_generates_finding(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="find-shadow@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/monitoring/shadow-events",
        headers=headers,
        json={
            "event_type": "dns_discovery",
            "payload": {
                "severity": "high",
                "ai_tool": "shadow_chat_tool",
                "department": "finance",
                "risk_category": "shadow_ai",
            },
        },
    )
    assert response.status_code == 200, response.text

    findings = _findings_by_type(client, headers=headers, finding_type="shadow_ai_discovery")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_surface"] == "dns"
    assert finding["ai_tool"] == "shadow_chat_tool"
    assert finding["department"] == "finance"
    assert finding["severity"] == "high"
    assert finding["evidence_node_ids"]


def test_asymmetry_signal_generates_finding(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="find-asymmetry@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="HIGH")

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "ok",
            "context_summary": "asymmetry test",
            "attachments_meta": [{"tool_calls": ["a", "b", "c", "d", "e"]}],
            "tool_output": "x" * 2500,
        },
    )
    assert response.status_code == 200, response.text

    findings = _findings_by_type(client, headers=headers, finding_type="asymmetry_signal")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_surface"] == "gateway"
    assert finding["ai_system_id"] == ai_system_id
    assert finding["severity"] in {"high", "critical"}
    assert finding["evidence_node_ids"]


def test_deduplication_merges_repeated_events(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="find-dedupe@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    payload = {
        "event_type": "dns_discovery",
        "payload": {
            "severity": "med",
            "ai_tool": "dedupe_shadow_tool",
            "department": "engineering",
            "risk_category": "shadow_ai",
        },
    }

    first = client.post("/monitoring/shadow-events", headers=headers, json=payload)
    assert first.status_code == 200, first.text
    second = client.post("/monitoring/shadow-events", headers=headers, json=payload)
    assert second.status_code == 200, second.text

    findings = _findings_by_type(client, headers=headers, finding_type="shadow_ai_discovery")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_surface"] == "dns"
    assert finding["occurrence_count"] == 2
    assert finding["first_seen_at"] <= finding["last_seen_at"]


def test_drift_alert_signal_generates_finding_with_evidence_link(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="find-drift@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/monitoring/signals",
        headers=headers,
        json={
            "signal_type": "connector.config_drift",
            "severity": "high",
            "payload": {
                "related_control_ids": ["CTRL-DRIFT-001"],
                "risk_category": "monitoring_drift",
            },
        },
    )
    assert response.status_code == 200, response.text

    findings = _findings_by_type(client, headers=headers, finding_type="drift_alert")
    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_surface"] == "connector"
    assert finding["severity"] in {"high", "critical"}
    assert finding["ai_tool"] == "monitoring_signal_ingest"
    assert "CTRL-DRIFT-001" in finding["related_control_ids"]
    assert finding["evidence_node_ids"]
