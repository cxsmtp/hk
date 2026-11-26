from __future__ import annotations

import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.evidence import EvidenceNode
from app.db.models.enforcement import EnforcementEvent
from app.db.models.policy import ApprovalRequest
from app.db.session import Base, get_db
from app.jobs import enforcement_jobs
from app.main import app
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "enforcement.sqlite3"
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
        yield {"client": client, "SessionLocal": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _register_owner(client: TestClient, *, email: str, full_name: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": full_name},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return {
        "access_token": data["access_token"],
        "tenant_id": data["tenants"][0]["id"],
    }


def _build_guardian(*, on_fail: str, on_uncertain: str = "warn", sla_minutes: int = 30, default_if_timeout: str = "block") -> dict[str, Any]:
    return {
        "guardian_id": "deterministic_guard",
        "description": "Deterministic guardian for contract tests.",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text"],
            "conditions": [
                {
                    "field": "prompt.text",
                    "operator": "contains",
                    "value": "trigger-phrase",
                    "case_sensitive": False,
                }
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.5},
        "decision": {"on_pass": "allow", "on_fail": on_fail, "on_uncertain": on_uncertain},
        "actions": {
            "redact": {"fields": ["prompt"], "strategy": "mask"},
            "mutate_output": {"enabled": False, "strategy": "safe_completion"},
            "notify": {"channels": []},
            "create_ticket": {"system": "jira", "severity": "low"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.deterministic_guard.detected",
            "link_to_controls": ["CTRL-DET-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.1,
            "increase_simulation_frequency": False,
            "enforcement_strictness_increase": 0,
        },
        "approval_workflow": {
            "required_roles": ["owner", "admin"],
            "sla_minutes": sla_minutes,
            "default_if_timeout": default_if_timeout,
        },
    }


def _create_active_policy_version(
    client: TestClient,
    *,
    headers: dict[str, str],
    guardians: list[dict[str, Any]],
) -> tuple[str, str]:
    pack_response = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Deterministic Pack", "description": "test", "status": "draft"},
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
            "version": "1.0.1",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": guardians,
        },
    )
    assert version_response.status_code == 200, version_response.text
    body = version_response.json()
    version_id = body.get("id")
    if not version_id:
        versions_response = client.get(f"/policies/packs/{pack_id}/versions", headers=headers)
        assert versions_response.status_code == 200, versions_response.text
        versions = versions_response.json()
        version_id = next(v["id"] for v in versions if v["version"] == "1.0.1")

    return pack_id, version_id


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str, name: str) -> str:
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


def _intercept(client: TestClient, *, headers: dict[str, str], ai_system_id: str) -> dict[str, Any]:
    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": "please include trigger-phrase in this prompt",
            "context_summary": "deterministic context",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_same_input_same_decision(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="det-owner@example.com", full_name="Det Owner")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _, expected_policy_version = _create_active_policy_version(
        client,
        headers=headers,
        guardians=[_build_guardian(on_fail="warn")],
    )
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW", name="Deterministic LOW")

    first = _intercept(client, headers=headers, ai_system_id=ai_system_id)
    second = _intercept(client, headers=headers, ai_system_id=ai_system_id)

    assert first["final_decision"] == second["final_decision"]
    assert first["final_decision"] == "redact", [
        {
            "guardian_id": row.get("guardian_id"),
            "decision": row.get("decision"),
            "reason": row.get("reason"),
            "matched_conditions": row.get("matched_conditions"),
            "actions_taken": row.get("actions_taken"),
        }
        for row in first["guardian_results"]
    ]
    assert first["guardian_results"] == second["guardian_results"]
    assert first["policy_version_id"] == expected_policy_version
    assert second["policy_version_id"] == expected_policy_version


def test_risk_tier_strictness_changes_outputs(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="strict-owner@example.com", full_name="Strict Owner")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_active_policy_version(
        client,
        headers=headers,
        guardians=[_build_guardian(on_fail="warn")],
    )

    low_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW", name="Strict LOW")
    high_system_id = _create_ai_system(client, headers=headers, risk_tier="HIGH", name="Strict HIGH")

    low = _intercept(client, headers=headers, ai_system_id=low_system_id)
    high = _intercept(client, headers=headers, ai_system_id=high_system_id)

    assert low["strictness_level"] == 0
    assert high["strictness_level"] == 2
    assert low["final_decision"] == "redact", (low["guardian_results"], low["final_actions"])
    assert high["final_decision"] == "hold_for_approval"

    matrix_response = client.get(
        f"/gateway/llm/guardian-matrix?ai_system_id={high_system_id}&actor_type=human",
        headers=headers,
    )
    assert matrix_response.status_code == 200, matrix_response.text
    matrix = matrix_response.json()
    assert matrix["strictness_level"] == 2
    assert matrix["guardians"][0]["guardian_id"] == "deterministic_guard"
    assert "triggers" in matrix["guardians"][0]
    assert "thresholds" in matrix["guardians"][0]
    assert "actions" in matrix["guardians"][0]
    assert "mapped_controls" in matrix["guardians"][0]
    assert "control_impact_deltas" in matrix["guardians"][0]


def test_timed_out_approval_auto_resolves_deterministically(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="timeout-owner@example.com", full_name="Timeout Owner")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_active_policy_version(
        client,
        headers=headers,
        guardians=[_build_guardian(on_fail="hold_for_approval", on_uncertain="hold_for_approval", sla_minutes=0, default_if_timeout="warn")],
    )
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="HIGH", name="Timeout HIGH")

    intercept_out = _intercept(client, headers=headers, ai_system_id=ai_system_id)
    assert intercept_out["final_decision"] == "hold_for_approval"
    assert len(intercept_out["approval_request_ids"]) == 1
    approval_id = intercept_out["approval_request_ids"][0]
    event_id = intercept_out["event_id"]

    original_session_local = enforcement_jobs.SessionLocal
    enforcement_jobs.SessionLocal = session_local
    try:
        first_run = enforcement_jobs.resolve_timed_out_approvals.run(
            tenant_id=owner["tenant_id"],
            batch_limit=100,
        )
        second_run = enforcement_jobs.resolve_timed_out_approvals.run(
            tenant_id=owner["tenant_id"],
            batch_limit=100,
        )
    finally:
        enforcement_jobs.SessionLocal = original_session_local

    assert first_run["resolved_count"] == 1
    assert first_run["resolved_approval_ids"] == [approval_id]
    assert second_run["resolved_count"] == 0

    with session_local() as db:
        req = db.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.id == approval_id,
                ApprovalRequest.tenant_id == owner["tenant_id"],
            )
        )
        assert req is not None
        assert req.status == "timed_out"
        assert req.decision == "timeout_warn"
        assert req.default_if_timeout == "warn"

        event = db.scalar(
            select(EnforcementEvent).where(
                EnforcementEvent.id == event_id,
                EnforcementEvent.tenant_id == owner["tenant_id"],
            )
        )
        assert event is not None
        assert event.final_decision == "warn"
        assert (event.final_actions or {}).get("approval_timeout", {}).get("approval_request_id") == approval_id

        timeout_node = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.signal_type == "approval.timeout.auto_resolved",
            )
        )
        assert timeout_node is not None
