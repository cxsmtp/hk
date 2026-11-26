from __future__ import annotations

import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.evidence import EvidenceNode
from app.db.session import Base, get_db
from app.main import app
from app.services.gateway_service import evaluate_guardians
from app.services.guardians.threat_registry import THREAT_TYPE_TO_GUARDIAN_CONTRACTS, guardian_contract_to_threat_types
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "vendor_steal_list.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Vendor Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "HIGH") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Vendor AI", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _guardian(
    *,
    guardian_contract_id: str,
    trigger_token: str,
    method: str,
    confidence_threshold: float,
) -> dict[str, Any]:
    return {
        "guardian_contract_id": guardian_contract_id,
        "guardian_id": guardian_contract_id,
        "enabled": True,
        "trigger_conditions": [
            {
                "field": "prompt.text",
                "operator": "contains",
                "value": trigger_token,
                "case_sensitive": False,
            }
        ],
        "block_conditions": [],
        "legacy_evaluation": {"method": method, "confidence_threshold": confidence_threshold},
        "legacy_decision": {
            "on_pass": "allow",
            "on_fail": "warn",
            "on_uncertain": "warn",
        },
        "mandatory_actions": {},
        "escalation_path": {},
        "evidence_requirements": {"link_to_controls": ["CTRL-VENDOR-001"]},
        "framework_mappings": {"control_ids": ["CTRL-VENDOR-001"]},
        "legacy_control_impact": {"maturity_delta_on_fail": -0.1},
    }


def test_threat_taxonomy_multi_label_mapping() -> None:
    assert "prompt_injection" in THREAT_TYPE_TO_GUARDIAN_CONTRACTS
    assert "prompt_injection_guard" in THREAT_TYPE_TO_GUARDIAN_CONTRACTS["prompt_injection"]

    mapped = guardian_contract_to_threat_types("tool_output_injection_guard")
    assert "tool_output_injection" in mapped
    assert "output_asymmetry" in mapped
    assert len(mapped) >= 2


def test_confidence_tiering_calls_arbiter_only_on_ambiguous() -> None:
    guardians = [
        _guardian(
            guardian_contract_id="prompt_injection_guard",
            trigger_token="clear-token",
            method="rules",
            confidence_threshold=0.5,
        ),
        _guardian(
            guardian_contract_id="jailbreak",
            trigger_token="ambiguous-token",
            method="hybrid",
            confidence_threshold=0.95,
        ),
    ]
    payload = {
        "prompt": {"text": "ambiguous-token bypass protections"},
        "context": {"summary": "runtime context"},
        "context_summary": "runtime context",
        "attachments_meta": [],
        "tool_output": "",
    }

    results, _, _, _, _ = evaluate_guardians(payload=payload, guardians=guardians, strictness_level=0)

    assert len(results) == 2
    by_id = {row["guardian_contract_id"]: row for row in results}

    clear_result = by_id["prompt_injection_guard"]
    ambiguous_result = by_id["jailbreak"]

    assert clear_result["confidence_tier"] in {"clear_negative", "clear_positive"}
    assert clear_result["arbiter_invoked"] is False

    assert ambiguous_result["arbiter_invoked"] is True
    assert ambiguous_result["confidence_tier"] in {"clear_negative", "clear_positive"}
    assert ambiguous_result.get("arbiter_reason")

    assert [row["arbiter_invoked"] for row in results].count(True) == 1


def test_asymmetry_signal_emits_evidence_node(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    owner = _register_owner(client, email="vendor-asymmetry@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="HIGH")

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "vendor-owner",
            "prompt": "ok",
            "context_summary": "asymmetry test",
            "attachments_meta": [{"tool_calls": ["a", "b", "c", "d", "e"]}],
            "tool_output": "x" * 2500,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["evidence_nodes_created"]

    with session_local() as db:
        node = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.node_type == "asymmetry_signal",
            )
        )
        assert node is not None
        assert node.correlation_id
        assert node.payload["triggered"] is True
        assert "output_asymmetry" in node.payload["risk_labels"]
        assert node.payload["simulation_schedule_hint"] == "increase_frequency"
        assert int(node.payload["tool_call_count"]) >= 5
