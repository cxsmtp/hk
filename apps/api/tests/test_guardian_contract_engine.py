from __future__ import annotations

import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ApprovalRequest
from app.db.session import Base, get_db
from app.main import app
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "guardian_contract_engine.sqlite3"
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


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Guardian Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "LOW") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Guardian Test AI", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _guardian_template(
    *,
    guardian_id: str,
    trigger_phrase: str,
    on_fail: str,
    block_phrase: str | None = None,
    escalation_sla: int = 10,
) -> dict[str, Any]:
    guardian: dict[str, Any] = {
        "guardian_id": guardian_id,
        "description": f"Guardian {guardian_id}",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text"],
            "conditions": [
                {
                    "field": "prompt.text",
                    "operator": "contains",
                    "value": trigger_phrase,
                    "case_sensitive": False,
                }
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.5},
        "decision": {"on_pass": "allow", "on_fail": on_fail, "on_uncertain": "warn"},
        "actions": {
            "redact": {"fields": ["prompt"], "strategy": "mask"},
            "mutate_output": {"enabled": False, "strategy": "safe_completion"},
            "notify": {"channels": ["email"]},
            "create_ticket": {"system": "jira", "severity": "med"},
        },
        "evidence": {
            "evidence_signal_type": f"guardian.{guardian_id}.detected",
            "link_to_controls": ["CTRL-GUARD-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.1,
            "increase_simulation_frequency": False,
            "enforcement_strictness_increase": 1,
        },
        "approval_workflow": {
            "required_roles": ["owner", "admin"],
            "sla_minutes": escalation_sla,
            "default_if_timeout": "block",
        },
    }
    if block_phrase:
        guardian["block_conditions"] = [
            {
                "field": "prompt.text",
                "operator": "contains",
                "value": block_phrase,
                "case_sensitive": False,
            }
        ]
    return guardian


def _activate_policy_with_guardians(client: TestClient, *, headers: dict[str, str], guardians: list[dict[str, Any]]) -> str:
    pack = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Guardian Contract Pack", "description": "test", "status": "draft"},
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
            "version": "2.0.0",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "MINIMAL", "LIMITED", "RESTRICTED"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": guardians,
        },
    )
    assert version.status_code == 200, version.text
    return version.json()["id"]


def _intercept(client: TestClient, *, headers: dict[str, str], ai_system_id: str, prompt: str) -> dict[str, Any]:
    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "owner",
            "prompt": prompt,
            "context_summary": "guardian-engine-test",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_guardian_block_conditions(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="guardian-block@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    policy_version_id = _activate_policy_with_guardians(
        client,
        headers=headers,
        guardians=[
            _guardian_template(
                guardian_id="contract_block_guard",
                trigger_phrase="warn-only-trigger",
                on_fail="warn",
                block_phrase="hard-block-token",
            )
        ],
    )
    matrix_response = client.get(
        "/policies/guardian-matrix",
        headers=headers,
        params={"policy_version_id": policy_version_id},
    )
    assert matrix_response.status_code == 200, matrix_response.text
    matrix = matrix_response.json()
    assert matrix["total"] >= 1
    assert matrix["items"][0]["guardian_contract_id"] == "contract_block_guard"

    ai_system_id = _create_ai_system(client, headers=headers)

    out = _intercept(client, headers=headers, ai_system_id=ai_system_id, prompt="hard-block-token appears now")
    assert out["final_decision"] == "block"
    assert out["guardian_results"][0]["guardian_contract_id"] == "contract_block_guard"


def test_guardian_escalation_path(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="guardian-escalation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _activate_policy_with_guardians(
        client,
        headers=headers,
        guardians=[
            _guardian_template(
                guardian_id="contract_escalation_guard",
                trigger_phrase="needs-approval-token",
                on_fail="hold_for_approval",
                escalation_sla=7,
            )
        ],
    )
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="MEDIUM")

    out = _intercept(client, headers=headers, ai_system_id=ai_system_id, prompt="needs-approval-token")
    assert out["final_decision"] == "hold_for_approval", [
        {
            "guardian_id": row.get("guardian_id"),
            "decision": row.get("decision"),
            "reason": row.get("reason"),
            "matched_conditions": row.get("matched_conditions"),
            "actions_taken": row.get("actions_taken"),
        }
        for row in out["guardian_results"]
    ]
    assert len(out["approval_request_ids"]) == 1
    approval_id = out["approval_request_ids"][0]

    with session_local() as db:
        req = db.scalar(
            select(ApprovalRequest).where(
                ApprovalRequest.id == approval_id,
                ApprovalRequest.tenant_id == owner["tenant_id"],
            )
        )
        assert req is not None
        assert req.sla_minutes == 7
        assert req.default_if_timeout == "block"
        assert req.required_roles == ["owner", "admin"]


def test_evidence_written(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="guardian-evidence@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _activate_policy_with_guardians(
        client,
        headers=headers,
        guardians=[
            _guardian_template(
                guardian_id="contract_evidence_guard",
                trigger_phrase="evidence-token",
                on_fail="warn",
            )
        ],
    )
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")

    out = _intercept(client, headers=headers, ai_system_id=ai_system_id, prompt="evidence-token")
    event_id = out["event_id"]

    with session_local() as db:
        event = db.scalar(
            select(EnforcementEvent).where(
                EnforcementEvent.id == event_id,
                EnforcementEvent.tenant_id == owner["tenant_id"],
            )
        )
        assert event is not None
        assert event.guardian_results
        assert event.guardian_results[0].get("guardian_contract_id") == "contract_evidence_guard"

        nodes = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.node_type == "guardian_enforcement",
            )
        ).all()
        assert nodes
        assert any(node.payload.get("guardian_contract_id") == "contract_evidence_guard" for node in nodes)
