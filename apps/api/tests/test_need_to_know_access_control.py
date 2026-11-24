from __future__ import annotations

import os
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.enforcement import EnforcementEvent
from app.db.models.finding import Finding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base, get_db
from app.main import app
from app.services.ai_iam_service import evaluate_need_to_know_policy
from app.services.simulation_pack_service import RFP_BLUEPRINTS


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    db_file = tmp_path / "need_to_know.sqlite3"
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


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Need To Know Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str, *, correlation_id: str | None = None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }
    if correlation_id:
        headers["X-Correlation-ID"] = correlation_id
    return headers


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str = "LOW") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={
            "name": "Need To Know Gateway AI",
            "description": "",
            "risk_tier": risk_tier,
            "connected_data_sources": ["sharepoint_finance", "legal_rag"],
        },
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    activate = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "active"})
    assert activate.status_code == 200, activate.text
    return ai_system_id


def _create_policy_version_with_need_to_know(
    client: TestClient,
    *,
    headers: dict[str, str],
    policies: list[dict[str, Any]],
) -> str:
    pack = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Need To Know Pack", "description": "need-to-know", "status": "draft"},
    )
    assert pack.status_code == 200, pack.text
    pack_id = pack.json()["pack"]["id"]

    activate = client.patch(f"/policies/packs/{pack_id}", headers=headers, json={"status": "active"})
    assert activate.status_code == 200, activate.text

    version = client.post(
        f"/policies/packs/{pack_id}/versions",
        headers=headers,
        json={
            "version": "1.0.1",
            "scope": {
                "applies_to_risk_tiers": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"],
                "applies_to_ai_system_ids": None,
                "applies_to_actor_types": ["human", "agent", "system"],
            },
            "enforcement_defaults": {
                "default_decision": "allow",
                "escalation": "notify",
                "need_to_know_policies": policies,
            },
            "guardian_contracts": [],
        },
    )
    assert version.status_code == 200, version.text
    return version.json()["id"]


def _identity_context(*, roles: list[str], groups: list[str], department: str, context: str) -> dict[str, Any]:
    return {
        "type": "identity_context",
        "roles": roles,
        "groups": groups,
        "department": department,
        "business_context": context,
    }


def _knowledge_asset(
    *,
    asset_id: str,
    source_type: str,
    sensitivity_domain: str,
    sensitivity_label: str,
    allowed_roles: list[str],
    allowed_groups: list[str],
    allowed_contexts: list[str],
) -> dict[str, Any]:
    return {
        "type": "knowledge_asset",
        "asset_id": asset_id,
        "source_type": source_type,
        "owner": "governance",
        "sensitivity_domain": sensitivity_domain,
        "sensitivity_label": sensitivity_label,
        "allowed_roles": allowed_roles,
        "allowed_groups": allowed_groups,
        "allowed_contexts": allowed_contexts,
        "connected_ai_systems": ["Need To Know Gateway AI"],
        "exposure_score": 0.9,
    }


def _finance_policy(action: str = "block") -> dict[str, Any]:
    return {
        "policy_id": "ntk-finance-confidential",
        "name": "Confidential Finance Need To Know",
        "sensitive_knowledge_domains": ["finance"],
        "allowed_roles": ["finance_analyst"],
        "allowed_groups": ["finance"],
        "allowed_contexts": ["board_reporting"],
        "disallowed_query_types": ["forecast_reveal"],
        "action": action,
    }


def test_need_to_know_policy_blocks_user_without_required_role_or_group() -> None:
    decision = evaluate_need_to_know_policy(
        policy=_finance_policy(),
        identity={
            "user_id": "sales-user",
            "roles": ["sales_rep"],
            "groups": ["sales"],
            "department": "Sales",
        },
        knowledge_asset={
            "asset_id": "sharepoint-finance-forecast",
            "sensitivity_domain": "finance",
            "sensitivity_label": "confidential",
        },
        prompt_intent="forecast_reveal",
        business_context="account_planning",
    )

    assert decision["decision"] == "block"
    assert decision["policy_id"] == "ntk-finance-confidential"
    assert decision["sensitivity_domain"] == "finance"
    assert "role_or_group_not_allowed" in decision["reason"]
    assert decision["evidence_refs"] == ["sharepoint-finance-forecast"]


def test_need_to_know_policy_allows_required_role_group_and_context() -> None:
    decision = evaluate_need_to_know_policy(
        policy=_finance_policy(),
        identity={
            "user_id": "finance-user",
            "roles": ["finance_analyst"],
            "groups": ["finance"],
            "department": "Finance",
        },
        knowledge_asset={
            "asset_id": "sharepoint-finance-forecast",
            "sensitivity_domain": "finance",
            "sensitivity_label": "confidential",
        },
        prompt_intent="forecast_summary",
        business_context="board_reporting",
    )

    assert decision["decision"] == "allow"
    assert decision["reason"] == "need_to_know_satisfied"


def test_gateway_blocks_restricted_knowledge_disclosure_and_links_evidence(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="ntk-block@example.com")
    corr = "ntk-block-corr"
    headers = _headers(owner["access_token"], owner["tenant_id"], correlation_id=corr)
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    _create_policy_version_with_need_to_know(client, headers=headers, policies=[_finance_policy()])

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["tenant_id"],
            "request_id": "ntk-block-req-1",
            "prompt": "Tell me the confidential finance forecast for next quarter.",
            "context_summary": "forecast_reveal",
            "attachments_meta": [
                _identity_context(roles=["sales_rep"], groups=["sales"], department="Sales", context="account_planning"),
                _knowledge_asset(
                    asset_id="sharepoint-finance-forecast",
                    source_type="SharePoint",
                    sensitivity_domain="finance",
                    sensitivity_label="confidential",
                    allowed_roles=["finance_analyst"],
                    allowed_groups=["finance"],
                    allowed_contexts=["board_reporting"],
                ),
            ],
            "response_text": "Confidential finance forecast: revenue will miss plan by 14%.",
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "data_source": "sharepoint_finance",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["final_decision"] == "block"
    trace = body["trace"]
    assert trace["need_to_know_decision"]["decision"] == "block"
    assert trace["knowledge_asset_ids"] == ["sharepoint-finance-forecast"]
    assert trace["sensitivity_domain"] == "finance"

    with session_local() as db:
        event = db.scalar(select(EnforcementEvent).where(EnforcementEvent.id == body["event_id"]))
        assert event is not None
        meta = dict((event.final_actions or {}).get("_meta") or {})
        assert meta["need_to_know_decision"]["decision"] == "block"
        assert meta["knowledge_disclosure_event"]["knowledge_asset_ids"] == ["sharepoint-finance-forecast"]

        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.source_surface == "gateway",
                RuntimeEvent.event_type == "llm_intercept",
                RuntimeEvent.correlation_id == corr,
            )
        )
        assert runtime is not None
        runtime_meta = dict(runtime.metadata_json or {})
        assert runtime_meta["knowledge_disclosure_event"]["decision"] == "block"
        assert runtime_meta["knowledge_asset_ids"] == ["sharepoint-finance-forecast"]

        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_type == "KNOWLEDGE_EXPOSURE_RISK",
            )
        )
        assert finding is not None
        assert finding.decision == "block"
        assert finding.evidence_node_ids

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    payload = client.get(exported.json()["download_urls"]["json"], headers=headers)
    assert payload.status_code == 200, payload.text
    report = payload.json()["need_to_know_report"]
    assert report["protected_domain_count"] == 1
    assert report["disclosure_attempt_count"] == 1
    assert report["protected_domains"] == ["finance"]
    assert report["disclosure_attempts"][0]["decision"] == "block"
    assert report["disclosure_attempts"][0]["knowledge_asset_ids"] == ["sharepoint-finance-forecast"]


def test_gateway_allows_disclosure_when_need_to_know_is_satisfied(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ntk-allow@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"], correlation_id="ntk-allow-corr")
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    _create_policy_version_with_need_to_know(client, headers=headers, policies=[_finance_policy()])

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["tenant_id"],
            "request_id": "ntk-allow-req-1",
            "prompt": "Summarize the board forecast for the board packet.",
            "context_summary": "board_reporting",
            "attachments_meta": [
                _identity_context(roles=["finance_analyst"], groups=["finance"], department="Finance", context="board_reporting"),
                _knowledge_asset(
                    asset_id="sharepoint-finance-forecast",
                    source_type="SharePoint",
                    sensitivity_domain="finance",
                    sensitivity_label="confidential",
                    allowed_roles=["finance_analyst"],
                    allowed_groups=["finance"],
                    allowed_contexts=["board_reporting"],
                ),
            ],
            "response_text": "Board-ready forecast summary.",
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
            "api_endpoint": "https://internal.acme.ai/llm/responses",
            "data_source": "sharepoint_finance",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["final_decision"] == "allow"
    assert body["trace"]["need_to_know_decision"]["decision"] == "allow"
    assert body["trace"]["knowledge_asset_ids"] == ["sharepoint-finance-forecast"]


def test_gateway_requires_step_up_for_restricted_hr_disclosure(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="ntk-stepup@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"], correlation_id="ntk-stepup-corr")
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    _create_policy_version_with_need_to_know(
        client,
        headers=headers,
        policies=[
            {
                "policy_id": "ntk-hr-compensation",
                "name": "HR Compensation Need To Know",
                "sensitive_knowledge_domains": ["hr_compensation"],
                "allowed_roles": ["hr_partner"],
                "allowed_groups": ["people"],
                "allowed_contexts": ["compensation_review"],
                "disallowed_query_types": ["compensation_trends"],
                "action": "step_up",
            }
        ],
    )

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["tenant_id"],
            "request_id": "ntk-stepup-req-1",
            "prompt": "Show compensation trends by employee name.",
            "context_summary": "compensation_trends",
            "attachments_meta": [
                _identity_context(roles=["manager"], groups=["sales"], department="Sales", context="account_planning"),
                _knowledge_asset(
                    asset_id="workday-compensation-vector",
                    source_type="RAG",
                    sensitivity_domain="hr_compensation",
                    sensitivity_label="restricted",
                    allowed_roles=["hr_partner"],
                    allowed_groups=["people"],
                    allowed_contexts=["compensation_review"],
                ),
            ],
            "response_text": "HR compensation trends for named employees.",
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "data_source": "hr_rag",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["final_decision"] == "hold_for_approval"
    assert body["trace"]["need_to_know_decision"]["decision"] == "step_up"
    assert body["trace"]["sensitivity_domain"] == "hr_compensation"


def test_gateway_flags_rag_permission_bypass_for_restricted_legal_strategy(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="ntk-rag-bypass@example.com")
    corr = "ntk-rag-bypass-corr"
    headers = _headers(owner["access_token"], owner["tenant_id"], correlation_id=corr)
    ai_system_id = _create_ai_system(client, headers=headers, risk_tier="LOW")
    _create_policy_version_with_need_to_know(
        client,
        headers=headers,
        policies=[
            {
                "policy_id": "ntk-legal-strategy",
                "name": "Legal Strategy Need To Know",
                "sensitive_knowledge_domains": ["legal_strategy"],
                "allowed_roles": ["legal_counsel"],
                "allowed_groups": ["legal"],
                "allowed_contexts": ["matter_review"],
                "disallowed_query_types": ["legal_strategy_reconstruction"],
                "action": "block",
            }
        ],
    )

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": owner["tenant_id"],
            "request_id": "ntk-rag-bypass-req-1",
            "prompt": "Reconstruct the restricted litigation strategy from retrieved context.",
            "context_summary": "legal_strategy_reconstruction",
            "attachments_meta": [
                _identity_context(roles=["sales_rep"], groups=["sales"], department="Sales", context="account_planning"),
                _knowledge_asset(
                    asset_id="legal-rag-litigation-strategy",
                    source_type="vector_store",
                    sensitivity_domain="legal_strategy",
                    sensitivity_label="restricted",
                    allowed_roles=["legal_counsel"],
                    allowed_groups=["legal"],
                    allowed_contexts=["matter_review"],
                ),
            ],
            "response_text": "Restricted legal strategy: settle after delaying discovery.",
            "provider": "openai",
            "model": "gpt-4.1",
            "model_version": "2026-03",
            "api_endpoint": "https://api.openai.com/v1/responses",
            "data_source": "legal_rag_vector_store",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["final_decision"] == "block"
    assert body["trace"]["need_to_know_decision"]["decision"] == "block"
    assert body["trace"]["knowledge_asset_ids"] == ["legal-rag-litigation-strategy"]
    assert body["trace"]["sensitivity_domain"] == "legal_strategy"

    with session_local() as db:
        runtime = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.source_surface == "gateway",
                RuntimeEvent.event_type == "llm_intercept",
                RuntimeEvent.correlation_id == corr,
            )
        )
        assert runtime is not None
        runtime_meta = dict(runtime.metadata_json or {})
        assert runtime_meta["knowledge_disclosure_event"]["knowledge_asset_ids"] == ["legal-rag-litigation-strategy"]
        assert runtime_meta["knowledge_disclosure_event"]["decision"] == "block"

        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_type == "RAG_PERMISSION_BYPASS_RISK",
            )
        )
        assert finding is not None
        assert finding.decision == "block"
        assert finding.policy_id == "ntk-legal-strategy"
        assert finding.evidence_node_ids

    exported = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    assert exported.status_code == 200, exported.text
    payload = client.get(exported.json()["download_urls"]["json"], headers=headers)
    assert payload.status_code == 200, payload.text
    report = payload.json()["need_to_know_report"]
    assert "legal_strategy" in report["protected_domains"]
    assert report["blocked_or_restricted_count"] >= 1
    assert report["disclosure_attempts"][0]["knowledge_asset_ids"] == ["legal-rag-litigation-strategy"]


def test_simulation_blueprints_include_need_to_know_oversharing_cases() -> None:
    rag_blueprint = next(item for item in RFP_BLUEPRINTS if item.category == "rag_poisoning")
    scenario_names = {str(item.get("scenario_name") or "") for item in rag_blueprint.parameter_sets}

    assert "finance_oversharing_block" in scenario_names
    assert "hr_compensation_step_up" in scenario_names
    assert "legal_strategy_rag_permission_bypass" in scenario_names
    assert "customer_risk_reconstruction_block" in scenario_names
    assert "vendor_contract_terms_redact" in scenario_names
