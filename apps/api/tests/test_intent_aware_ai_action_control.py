from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.finding import Finding
from app.db.models.discovery import DiscoveryApplication
from app.db.models.evidence import EvidenceNode
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.policy import BusinessPurposeSession
from app.db.session import Base, get_db
from app.main import app
from app.services.discovery_service import tool_key_for_name
from app.services.ai_iam_service import (
    classify_input_content_context,
    classify_intent_context,
    classify_output_context,
    evaluate_action_alignment,
    evaluate_intent_aware_action_control,
)


PASSWORD = "Password123!"


def _decision_factor_types(metadata: dict) -> set[str]:
    explanation = metadata.get("decision_explanation") or {}
    return {
        str(item.get("factor_type") or "").strip()
        for item in list(explanation.get("decision_factors") or [])
        if isinstance(item, dict)
    }


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "intent_aware_ai_action_control.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Intent Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _create_ai_system(client: TestClient, headers: dict[str, str], *, name: str = "Intent AI") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "intent-aware test", "risk_tier": "MEDIUM"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "approved"})
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _persist_research_purpose(
    session_local: sessionmaker,
    *,
    owner: dict[str, str],
    agent_id: str,
) -> None:
    with session_local() as db:
        db.add(
            BusinessPurposeSession(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                declared_purpose="Research public company information.",
                purpose_category="public_research",
                business_function="research",
                approved_scope={
                    "identity_id": agent_id,
                    "identity_type": "agent",
                    "purpose": {"name": "public_research"},
                    "scope": {
                        "allowed_actions": ["tool_execution", "browse"],
                        "allowed_tools": ["browser"],
                        "allowed_domains": ["microsoft.com"],
                        "allowed_resources": ["https://www.microsoft.com/*"],
                        "allowed_environments": ["prod"],
                        "allowed_data_scopes": ["unknown", "public"],
                    },
                    "constraints": {"max_risk_level": "critical"},
                    "context": {"connected_systems": ["microsoft.com"], "max_chain_depth": 3},
                    "status": "active",
                    "mode": "block",
                },
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
                status="active",
            )
        )
        db.commit()


def _create_agent(client: TestClient, headers: dict[str, str], *, name: str = "Intent Agent") -> str:
    response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={
            "name": name,
            "description": "intent boundary test",
            "max_chain_depth": 3,
            "capability_inheritance": False,
            "action_scope": ["tool.run", "tool.read", "tool.email_send"],
            "tool_registry": ["browser", "mail_sender"],
            "external_system_access": ["browser", "mail.google.com"],
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _mint_token(client: TestClient, headers: dict[str, str], *, agent_id: str, ai_system_id: str) -> str:
    response = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "scopes": ["tool.run", "tool.read", "tool.email_send"],
            "expires_minutes": 60,
            "chain_depth": 3,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["capability_token"]


def test_company_lookup_intent_allows_public_research() -> None:
    intent = classify_intent_context(
        declared_intent=None,
        text="Look up company ABC and summarize what they do.",
        action_type="prompt_submit",
        business_context=None,
    )
    content = classify_input_content_context("Look up company ABC and summarize what they do.")
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="browse",
        input_content_context=content,
        output_context=None,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=content,
        output_context=None,
        action_alignment_result=alignment,
        action_type="browse",
        policy={"mode": "block"},
    )

    assert intent["intent_category"] == "company_lookup"
    assert content["sensitivity_level"] in {"none", "low"}
    assert alignment["alignment"] == "aligned"
    assert decision["decision"] == "allow"
    assert decision["decision_reason"] == "public_research_allowed"


def test_business_email_list_submission_blocks_public_ai() -> None:
    text = "Here is a prospect list: alice@acme.com, bob@acme.com, carol@customer.io. Write outreach."
    intent = classify_intent_context(declared_intent=None, text=text, action_type="prompt_submit")
    content = classify_input_content_context(text)
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="prompt_submit",
        input_content_context=content,
        output_context=None,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=content,
        output_context=None,
        action_alignment_result=alignment,
        action_type="prompt_submit",
        policy={"mode": "block"},
    )

    assert intent["intent_category"] in {"sales_outreach", "customer_data_processing"}
    assert content["contains_business_emails"] is True
    assert content["sensitivity_level"] in {"medium", "high"}
    assert decision["decision"] == "block"
    assert decision["finding_type"] == "BUSINESS_EMAIL_DATA_TO_AI"


def test_generic_sales_outreach_draft_is_allowed_without_contacts() -> None:
    text = "Draft a concise outbound email for a sales team introducing our SOC workflow automation product."
    intent = classify_intent_context(declared_intent="sales outreach draft", text=text, action_type="prompt_submit")
    content = classify_input_content_context(text)
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="prompt_submit",
        input_content_context=content,
        output_context=None,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=content,
        output_context=None,
        action_alignment_result=alignment,
        action_type="prompt_submit",
        policy={"mode": "block"},
    )

    assert intent["intent_category"] == "sales_outreach"
    assert content["contains_business_emails"] is False
    assert content["sensitivity_level"] in {"none", "low"}
    assert alignment["alignment"] == "aligned"
    assert decision["decision"] == "allow"


def test_csv_upload_with_business_emails_blocks_as_crm_data() -> None:
    text = "name,email,company\nJane,jane@clientcorp.com,ClientCorp\nPat,pat@prospectco.com,ProspectCo"
    intent = classify_intent_context(declared_intent="sales outreach draft", text=text, action_type="file_upload")
    content = classify_input_content_context(text, file_meta=[{"name": "contacts.csv", "type": "text/csv"}])
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="file_upload",
        input_content_context=content,
        output_context=None,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=content,
        output_context=None,
        action_alignment_result=alignment,
        action_type="file_upload",
        policy={"mode": "block"},
    )

    assert content["business_email_count"] == 2
    assert content["contains_crm_like_table"] is True
    assert content["sensitivity_level"] == "high"
    assert decision["decision"] == "block"
    assert decision["finding_type"] in {"BUSINESS_EMAIL_DATA_TO_AI", "CRM_DATA_TO_PUBLIC_AI"}


def test_fake_secret_submission_blocks_with_secret_finding_type() -> None:
    text = "Use this fake test key sk-test1234567890abcdef to configure the API client."
    intent = classify_intent_context(declared_intent=None, text=text, action_type="prompt_submit")
    content = classify_input_content_context(text)
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="prompt_submit",
        input_content_context=content,
        output_context=None,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=content,
        output_context=None,
        action_alignment_result=alignment,
        action_type="prompt_submit",
        policy={"mode": "block"},
    )

    assert content["contains_secrets"] is True
    assert content["sensitivity_level"] == "critical"
    assert decision["decision"] == "block"
    assert decision["finding_type"] == "SECRET_OR_CREDENTIAL_TO_AI"


def test_output_copy_blocks_customer_contacts() -> None:
    output = "Email the customer at jane.customer@clientcorp.com or ops@clientcorp.com tomorrow."
    intent = classify_intent_context(
        declared_intent="company_lookup",
        text="Look up ClientCorp",
        action_type="copy_output",
    )
    output_context = classify_output_context(output_text=output, output_ref="response-1")
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="copy_output",
        input_content_context=None,
        output_context=output_context,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=None,
        output_context=output_context,
        action_alignment_result=alignment,
        action_type="copy_output",
        policy={"mode": "block"},
    )

    assert output_context["contains_business_email"] is True
    assert output_context["output_sensitivity"] in {"medium", "high"}
    assert decision["decision"] == "block"
    assert decision["finding_type"] == "AI_OUTPUT_COPY_BLOCKED"


def test_generic_output_copy_is_allowed() -> None:
    output = "Microsoft is a public technology company with cloud, productivity, and gaming businesses."
    intent = classify_intent_context(
        declared_intent="Summarize public info about Microsoft",
        text="Summarize public info about Microsoft",
        action_type="copy_output",
    )
    output_context = classify_output_context(output_text=output, output_ref="response-generic")
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="copy_output",
        input_content_context=None,
        output_context=output_context,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=None,
        output_context=output_context,
        action_alignment_result=alignment,
        action_type="copy_output",
        policy={"mode": "block"},
    )

    assert output_context["output_sensitivity"] == "low"
    assert alignment["alignment"] == "aligned"
    assert decision["decision"] == "allow"


def test_research_intent_blocks_contact_export_action() -> None:
    intent = classify_intent_context(
        declared_intent="research company ABC",
        text="Research company ABC",
        action_type="export_contacts",
    )
    alignment = evaluate_action_alignment(
        intent_context=intent,
        action_type="export_contacts",
        input_content_context=None,
        output_context=None,
    )
    decision = evaluate_intent_aware_action_control(
        intent_context=intent,
        input_content_context=None,
        output_context=None,
        action_alignment_result=alignment,
        action_type="export_contacts",
        policy={"mode": "block"},
    )

    assert intent["intent_category"] in {"company_lookup", "public_research"}
    assert alignment["alignment"] == "out_of_scope"
    assert decision["decision"] == "block"
    assert decision["finding_type"] == "INTENT_ACTION_SCOPE_VIOLATION"


def test_intent_context_includes_explanation_for_policy_evidence() -> None:
    intent = classify_intent_context(
        declared_intent="market research",
        text="Compare public competitors and market positioning.",
        action_type="browse",
    )

    assert intent["intent_category"] in {"market_research", "public_research"}
    assert intent["explanation"]


def test_browser_telemetry_public_company_lookup_records_allowed_research_context(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-research@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "intent-public-research-1"

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "browser": "chrome",
            "event_type": "prompt_submitted",
            "domain": "chatgpt.com",
            "url": "https://chatgpt.com/",
            "application": "ChatGPT",
            "action_taken": "allow_public_research",
            "action_type": "prompt_submit",
            "prompt_preview_redacted": "Look up company ABC and summarize what they do.",
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["finding_id"] is None
    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.correlation_id == correlation_id))
        assert runtime is not None
        metadata = runtime.metadata_json or {}
        assert metadata["intent_context"]["intent_category"] == "company_lookup"
        assert metadata["input_content_context"]["sensitivity_level"] in {"none", "low"}
        assert metadata["action_alignment_result"]["alignment"] == "aligned"
        assert metadata["intent_aware_decision"]["decision"] == "allow"
        explanation = metadata["decision_explanation"]
        assert explanation["decision_summary"]["final_decision"] in {"allow", "detected_only"}
        assert "intent" in _decision_factor_types(metadata)
        assert any(item["effect"] == "allow" for item in explanation["decision_factors"])


def test_browser_telemetry_business_email_prompt_creates_intent_finding(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-email-list@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "intent-business-email-1"

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "browser": "chrome",
            "event_type": "prompt_submitted",
            "domain": "chatgpt.com",
            "url": "https://chatgpt.com/",
            "application": "ChatGPT",
            "action_taken": "allow_prompt_submit",
            "action_type": "prompt_submit",
            "prompt_preview_redacted": (
                "Here is a prospect list: alice@acme.com, bob@acme.com, carol@customer.io. "
                "Write outreach."
            ),
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding_id"]
    with session_local() as db:
        finding = db.scalar(select(Finding).where(Finding.finding_id == body["finding_id"]))
        assert finding is not None
        assert finding.finding_type == "BUSINESS_EMAIL_DATA_TO_AI"
        assert finding.decision == "block"
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        assert runtime.metadata_json["intent_context"]["intent_category"] in {"sales_outreach", "customer_data_processing"}
        assert runtime.metadata_json["input_content_context"]["contains_business_emails"] is True
        assert runtime.metadata_json["intent_aware_decision"]["finding_type"] == "BUSINESS_EMAIL_DATA_TO_AI"
        explanation = runtime.metadata_json["decision_explanation"]
        assert explanation["decision_summary"]["final_decision"] == "block"
        assert {"content", "destination", "policy"}.issubset(_decision_factor_types(runtime.metadata_json))
        assert explanation["hidden_or_redacted"]["raw_content_redacted"] is True
        evidence = db.scalars(select(EvidenceNode).where(EvidenceNode.correlation_id == correlation_id)).all()
        summaries = [
            dict(node.payload or {}).get("intent_aware_evidence_summary")
            for node in evidence
            if dict(node.payload or {}).get("intent_aware_evidence_summary")
        ]
        assert summaries
        summary = summaries[0]
        assert summary["input_classification_summary"]["sensitivity_level"] in {"medium", "high"}
        assert summary["intent_classification"]["intent_category"] in {"sales_outreach", "customer_data_processing"}
        assert summary["action_classification"]["action_type"] == "prompt_submit"
        assert summary["destination_context"]["trust_level"] == "public_ai"
        assert summary["decision"]["decision"] == "block"
        assert summary["trace"] == [
            "intent_classified",
            "content_classified",
            "action_alignment_evaluated",
            "policy_evaluated",
            "evidence_recorded",
        ]


def test_browser_telemetry_blocks_fake_secret_across_public_ai_apps(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-secret-ai-apps@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    apps = [
        ("ChatGPT", "chatgpt.com"),
        ("Claude", "claude.ai"),
        ("Gemini", "gemini.google.com"),
        ("Perplexity", "perplexity.ai"),
    ]

    for index, (application, domain) in enumerate(apps):
        correlation_id = f"intent-secret-{index}"
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "correlation_id": correlation_id,
                "browser": "chrome",
                "event_type": "prompt_submitted",
                "domain": domain,
                "url": f"https://{domain}/",
                "application": application,
                "action_taken": "allow_prompt_submit",
                "action_type": "prompt_submit",
                "prompt_preview_redacted": "Use this fake key sk-test1234567890abcdef to call the API.",
                "policy_version": "pv-intent-aware",
                "platform_mode": "enforce",
            },
        )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["finding_id"]
        with session_local() as db:
            finding = db.scalar(select(Finding).where(Finding.finding_id == body["finding_id"]))
            assert finding is not None
            assert finding.finding_type == "SECRET_OR_CREDENTIAL_TO_AI"
            assert finding.decision == "block"
            runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
            assert runtime is not None
            assert runtime.application == application
            assert runtime.metadata_json["intent_aware_decision"]["finding_type"] == "SECRET_OR_CREDENTIAL_TO_AI"


def test_browser_telemetry_output_copy_with_business_email_creates_copy_block_finding(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-output-copy@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "intent-output-copy-1"

    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "browser": "chrome",
            "event_type": "clipboard_copy_detected",
            "domain": "chatgpt.com",
            "url": "https://chatgpt.com/",
            "application": "ChatGPT",
            "action_taken": "allow_copy_output",
            "action_type": "copy_output",
            "declared_intent": "company_lookup",
            "output_text_preview_redacted": "Contact jane@clientcorp.com and ops@clientcorp.com for details.",
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["finding_id"]
    with session_local() as db:
        finding = db.scalar(select(Finding).where(Finding.finding_id == body["finding_id"]))
        assert finding is not None
        assert finding.finding_type == "AI_OUTPUT_COPY_BLOCKED"
        assert finding.decision == "block"
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        assert runtime.metadata_json["output_context"]["contains_business_email"] is True
        assert runtime.metadata_json["copy_export_control_applied"] is True
        assert "output" in _decision_factor_types(runtime.metadata_json)
        assert runtime.metadata_json["decision_explanation"]["hidden_or_redacted"]["raw_content_redacted"] is True


def test_browser_interaction_eval_blocks_business_email_prompt_with_intent_context(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-interaction-eval@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "intent-interaction-eval-1"

    response = client.post(
        "/telemetry/browser/interaction-eval",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "domain": "chatgpt.com",
            "url": "https://chatgpt.com/",
            "application": "ChatGPT",
            "prompt_preview_redacted": (
                "Use this lead list to write outreach: alpha@examplecorp.com, beta@examplecorp.com, "
                "gamma@clientcorp.com"
            ),
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
            "browser": "chrome",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["finding_id"]
    with session_local() as db:
        finding = db.scalar(select(Finding).where(Finding.finding_id == body["finding_id"]))
        assert finding is not None
        assert finding.finding_type == "BUSINESS_EMAIL_DATA_TO_AI"
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        assert runtime.metadata_json["intent_context"]["intent_category"] in {"sales_outreach", "customer_data_processing"}
        assert runtime.metadata_json["intent_aware_decision"]["decision"] == "block"


def test_data_transfer_shadow_business_email_copy_records_would_block(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-transfer-shadow@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "intent-transfer-shadow-1"

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "copy_context": {
                "source_url": "https://chatgpt.com/c/1",
                "source_domain": "chatgpt.com",
                "source_app_name": "ChatGPT",
                "source_surface_type": "ai_tool",
                "source_classification_hint": "public",
                "copied_text_hash": "copy-hash-1",
                "copied_text_preview_redacted": "Contact jane@clientcorp.com and ops@clientcorp.com for details.",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "paste_context": {
                "destination_url": "https://wiki.acme.ai/research",
                "destination_domain": "wiki.acme.ai",
                "destination_app_name": "Internal Wiki",
                "destination_surface_type": "internal_app",
                "destination_input_context": "compose_box",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "declared_intent": "company_lookup",
            "action_type": "copy_output",
            "intent_policy": {"mode": "shadow"},
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["finding_id"] is None
    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        metadata = runtime.metadata_json or {}
        assert metadata["intent_aware_decision"]["decision"] == "allow"
        assert metadata["intent_aware_decision"]["would_decision"] == "block"
        assert metadata["output_context"]["contains_business_email"] is True
        assert metadata["copy_export_control_applied"] is True
        explanation = metadata["decision_explanation"]
        assert explanation["decision_summary"]["final_decision"] == "shadow_would_block"
        assert "output" in _decision_factor_types(metadata)


def test_data_transfer_marks_approved_enterprise_vs_public_ai_destination_trust(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-destination-trust@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, name="Enterprise ChatGPT")

    with session_local() as db:
        db.add(
            DiscoveryApplication(
                tenant_id=owner["tenant_id"],
                tool_key=tool_key_for_name("enterprise-chat.acme.ai"),
                tool_name="enterprise-chat.acme.ai",
                vendor="internal",
                status="approved",
                ai_system_id=ai_system_id,
            )
        )
        db.add(
            DiscoveryApplication(
                tenant_id=owner["tenant_id"],
                tool_key=tool_key_for_name("chatgpt.com"),
                tool_name="chatgpt.com",
                vendor="openai",
                status="approved",
                ai_system_id=None,
            )
        )
        db.commit()

    cases = [
        ("enterprise-chat.acme.ai", "Enterprise Chat", "ai_tool", "approved_enterprise", "allow"),
        ("chatgpt.com", "ChatGPT", "ai_tool", "approved_public", "allow"),
        ("claude.ai", "Claude", "ai_tool", "public_ai", "block"),
    ]
    for domain, app_name, surface, expected_trust, expected_decision in cases:
        response = client.post(
            "/runtime-control/data-transfer-check",
            headers=headers,
            json={
                "correlation_id": f"intent-destination-{expected_trust}",
                "copy_context": {
                    "source_url": "https://internal.acme.ai/wiki",
                    "source_domain": "internal.acme.ai",
                    "source_app_name": "Internal Wiki",
                    "source_surface_type": "internal_app",
                    "source_classification_hint": "public",
                    "copied_text_hash": "public-research-hash",
                    "copied_text_preview_redacted": "Summarize public market positioning for ACME.",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                "paste_context": {
                    "destination_url": f"https://{domain}/",
                    "destination_domain": domain,
                    "destination_app_name": app_name,
                    "destination_surface_type": surface,
                    "destination_input_context": "chat_box",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                "declared_intent": "market research",
                "action_type": "prompt_submit",
                "policy_version": "pv-intent-aware",
                "platform_mode": "enforce",
            },
        )

        assert response.status_code == 200, response.text
        assert response.json()["decision"] == expected_decision
        with session_local() as db:
            runtime = db.scalar(
                select(RuntimeEvent).where(RuntimeEvent.correlation_id == f"intent-destination-{expected_trust}")
            )
            assert runtime is not None
            assert runtime.metadata_json["destination_context"]["trust_level"] == expected_trust


def test_data_transfer_csv_upload_with_business_emails_blocks_with_intent_evidence(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-csv-upload@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "intent-csv-upload-1"

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "copy_context": {
                "source_url": "https://chatgpt.com/",
                "source_domain": "chatgpt.com",
                "source_app_name": "ChatGPT",
                "source_surface_type": "ai_tool",
                "source_classification_hint": "unknown",
                "copied_text_hash": "contacts-csv-hash",
                "copied_text_preview_redacted": "contacts.csv",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "paste_context": {
                "destination_url": "https://chatgpt.com/",
                "destination_domain": "chatgpt.com",
                "destination_app_name": "ChatGPT",
                "destination_surface_type": "ai_tool",
                "destination_input_context": "chat_box",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "declared_intent": "sales outreach draft",
            "action_type": "file_upload",
            "file_meta": [
                {
                    "name": "contacts.csv",
                    "type": "text/csv",
                    "mime_type": "text/csv",
                    "text_preview": (
                        "name,email,company\n"
                        "Jane,jane@clientcorp.com,ClientCorp\n"
                        "Pat,pat@prospectco.com,ProspectCo"
                    ),
                    "inline_text_preview": True,
                }
            ],
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
            "browser": "chrome",
            "machine_id": "machine-csv-1",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["finding_id"]
    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        metadata = runtime.metadata_json or {}
        assert metadata["input_content_context"]["contains_business_emails"] is True
        assert metadata["input_content_context"]["contains_crm_like_table"] is True
        assert metadata["input_content_context"]["sensitivity_level"] == "high"
        assert metadata["intent_aware_decision"]["finding_type"] == "CRM_DATA_TO_PUBLIC_AI"
        assert metadata["intent_aware_evidence_summary"]["input_classification_summary"]["contains_business_emails"] is True


def test_agent_declared_research_then_send_email_blocks_intent_scope_violation(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-agent-boundary@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, name="Intent Agent System")
    agent_id = _create_agent(client, headers)
    token = _mint_token(client, headers, agent_id=agent_id, ai_system_id=ai_system_id)
    correlation_id = "intent-agent-boundary-1"

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "tool_execution",
            "tool_name": "mail_sender",
            "target_resource": "mail.google.com",
            "chain_depth": 1,
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
            "input_context": {
                "declared_intent": "Research company ABC",
                "prompt_preview_redacted": "Research company ABC, then send email to sales@example.com.",
                "environment": "prod",
                "session_id": "intent-agent-session-1",
            },
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["pre_action_governance_check"]["policy"]["decision"] == "block"
    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        metadata = runtime.metadata_json or {}
        assert metadata["intent_context"]["intent_category"] in {"company_lookup", "public_research"}
        assert metadata["action_alignment_result"]["alignment"] == "out_of_scope"
        assert metadata["intent_aware_decision"]["finding_type"] == "INTENT_ACTION_SCOPE_VIOLATION"
        assert "context_integrity" in _decision_factor_types(metadata)


def test_agent_declared_research_allows_browser_browse_action(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-agent-browse-allow@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, name="Research Browse Agent System")
    agent_id = _create_agent(client, headers, name="Research Browse Agent")
    _persist_research_purpose(session_local, owner=owner, agent_id=agent_id)
    token = _mint_token(client, headers, agent_id=agent_id, ai_system_id=ai_system_id)
    correlation_id = "intent-agent-browse-allow-1"

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "tool_execution",
            "tool_name": "browser",
            "target_resource": "https://www.microsoft.com/en-us/investor",
            "chain_depth": 1,
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
            "input_context": {
                "declared_intent": "Research public company Microsoft",
                "prompt_preview_redacted": "Research public company Microsoft and summarize public investor information.",
                "attempted_action": "browse",
                "environment": "prod",
                "session_id": "intent-agent-session-browse",
            },
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow", "|".join(
        [
            str(body.get("reason_code")),
            str((body.get("pre_action_governance_check") or {}).get("policy", {}).get("reason")),
            str((body.get("pre_action_governance_check") or {}).get("purpose", {}).get("reason")),
            str((body.get("pre_action_governance_check") or {}).get("authority", {}).get("reason")),
        ]
    )
    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        metadata = runtime.metadata_json or {}
        assert metadata["intent_context"]["intent_category"] in {"company_lookup", "public_research", "market_research"}
        assert metadata["action_alignment_result"]["alignment"] == "aligned"
        assert metadata["intent_aware_decision"]["decision"] == "allow"
        assert any(
            item["effect"] == "allow"
            for item in metadata["decision_explanation"]["decision_factors"]
            if item["factor_type"] in {"action", "intent", "policy"}
        )


def test_agent_declared_research_export_contacts_blocks_intent_scope_violation(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="intent-agent-export-block@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, name="Research Export Agent System")
    agent_id = _create_agent(client, headers, name="Research Export Agent")
    token = _mint_token(client, headers, agent_id=agent_id, ai_system_id=ai_system_id)
    correlation_id = "intent-agent-export-block-1"

    response = client.post(
        "/runtime-control/agent-action-intercept",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token": token,
            "action_type": "tool_execution",
            "tool_name": "browser",
            "target_resource": "https://example.com/prospects/export.csv",
            "chain_depth": 1,
            "policy_version": "pv-intent-aware",
            "platform_mode": "enforce",
            "input_context": {
                "declared_intent": "Research public company ExampleCo",
                "prompt_preview_redacted": "Research ExampleCo, then export contacts for outreach.",
                "attempted_action": "export_contacts",
                "environment": "prod",
                "session_id": "intent-agent-session-export",
            },
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    with session_local() as db:
        runtime = db.scalar(select(RuntimeEvent).where(RuntimeEvent.event_id == body["runtime_event_id"]))
        assert runtime is not None
        metadata = runtime.metadata_json or {}
        assert metadata["action_alignment_result"]["alignment"] == "out_of_scope"
        assert metadata["intent_aware_decision"]["finding_type"] == "INTENT_ACTION_SCOPE_VIOLATION"
        assert "context_integrity" in _decision_factor_types(metadata)
