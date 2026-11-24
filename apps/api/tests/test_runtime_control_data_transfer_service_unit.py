from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.discovery import DiscoveryApplication
from app.db.models.monitoring import MonitoringSignal
from app.db.session import Base, get_db
from app.main import app
from app.services import runtime_control_data_transfer_service as svc
from app.services.discovery_service import tool_key_for_name
from app.services.guardian_policy_engine import CanonicalDecision


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "runtime_control_data_transfer_unit.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Runtime Control Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _check_payload(
    *,
    source_domain: str,
    source_surface: str,
    source_classification: str,
    destination_domain: str,
    destination_surface: str,
    destination_input_context: str = "chat_box",
    platform_mode: str = "enforce",
) -> dict[str, object]:
    return {
        "correlation_id": f"corr-unit-{source_domain}-{destination_domain}-{platform_mode}",
        "copy_context": {
            "source_url": f"https://{source_domain}/doc",
            "source_domain": source_domain,
            "source_app_name": "SourceApp",
            "source_surface_type": source_surface,
            "source_classification_hint": source_classification,
            "copied_text_hash": "abc123hash",
            "copied_text_preview_redacted": "Project [redacted] and [email]",
            "timestamp": "2026-03-23T10:00:00Z",
        },
        "paste_context": {
            "destination_url": f"https://{destination_domain}/chat",
            "destination_domain": destination_domain,
            "destination_app_name": "DestinationApp",
            "destination_surface_type": destination_surface,
            "destination_input_context": destination_input_context,
            "timestamp": "2026-03-23T10:00:05Z",
        },
        "policy_version": "pv-runtime-control-unit",
        "platform_mode": platform_mode,
    }


def test_runtime_control_helper_functions_cover_edge_paths() -> None:
    assert "T" in svc._now_iso()
    assert svc._normalize_domain(" https://www.Example.com:443/path?q=1 ") == "example.com"
    assert svc._normalize_domain("") == ""
    assert svc._normalize_source_classification("invalid") == "unknown"
    assert svc._normalize_source_surface("invalid") == "unknown"
    assert svc._normalize_destination_surface("invalid") == "unknown"
    assert svc._normalize_input_context("invalid") == "unknown"

    assert svc._is_external_domain("") is True
    assert svc._is_external_domain("service.local") is False
    assert svc._is_external_domain("wiki.acme.ai") is False
    assert svc._domain_match("chat.openai.com", "openai.com") is True
    assert svc._domain_match("", "openai.com") is False


def test_resolve_destination_ai_system_handles_empty_and_tool_name_lookup(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="runtime-transfer-unit-resolve@example.com")

    with session_local() as db:
        row = DiscoveryApplication(
            tenant_id=owner["tenant_id"],
            tool_key="custom-tool-key",
            tool_name="assistant.example.ai",
            vendor="Unknown",
            status="discovered",
            ai_system_id=None,
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.commit()

        assert svc._resolve_destination_ai_system(
            db,
            tenant_id=owner["tenant_id"],
            destination_domain="",
        ) == (None, None, "unknown")
        assert svc._resolve_destination_ai_system(
            db,
            tenant_id=owner["tenant_id"],
            destination_domain="assistant.example.ai",
        ) == (None, "assistant.example.ai", "discovered")

        exact = DiscoveryApplication(
            tenant_id=owner["tenant_id"],
            tool_key=tool_key_for_name("chat.openai.com"),
            tool_name="chat.openai.com",
            vendor="OpenAI",
            status="approved",
            ai_system_id="ai-system-1",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add(exact)
        db.commit()

        assert svc._resolve_destination_ai_system(
            db,
            tenant_id=owner["tenant_id"],
            destination_domain="chat.openai.com",
        ) == ("ai-system-1", "chat.openai.com", "approved")


def test_evaluate_transfer_decision_shadow_ai_warn_branch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        svc,
        "evaluate_data_transfer_policy",
        lambda **kwargs: CanonicalDecision(  # type: ignore[no-untyped-def]
            decision="warn",
            reason_code="warn_policy",
            explanation="warn",
            recommended_action="monitor",
            severity="med",
            policy=None,
            matched_conditions=[],
        ),
    )
    decision = svc._evaluate_transfer_decision(
        source_classification="public",
        source_surface="document",
        destination_surface="ai_tool",
        destination_domain="chat.openai.com",
        destination_ai_system_id=None,
        destination_discovery_status="unknown",
        platform_mode="enforce",
        destination_app_name="ChatGPT",
    )
    assert decision.decision == "warn"
    assert decision.risk_category == "shadow_ai"
    assert decision.finding_type == "sensitive_data_external_transfer_attempt"


def test_data_transfer_check_validation_errors(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-unit-validation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    missing_destination = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    missing_destination["paste_context"] = {"destination_input_context": "chat_box"}
    resp_missing_destination = client.post("/runtime-control/data-transfer-check", headers=headers, json=missing_destination)
    assert resp_missing_destination.status_code == 422
    assert "destination_domain" in resp_missing_destination.text

    missing_hash = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    copy_context = dict(missing_hash.get("copy_context") or {})
    copy_context["copied_text_hash"] = ""
    missing_hash["copy_context"] = copy_context
    resp_missing_hash = client.post("/runtime-control/data-transfer-check", headers=headers, json=missing_hash)
    assert resp_missing_hash.status_code == 422
    assert "copied_text_hash" in resp_missing_hash.text


def test_data_transfer_check_uses_fallback_when_primary_eval_raises(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-unit-fallback@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    monkeypatch.setattr(svc, "_evaluate_transfer_decision", lambda **kwargs: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(
        svc,
        "fallback_decision_for_gateway_failure",
        lambda **kwargs: {  # type: ignore[no-untyped-def]
            "decision": "allow",
            "reason_code": "gateway_unavailable",
            "recommended_action": "route_to_governance",
        },
    )
    monkeypatch.setattr(
        svc,
        "record_routing_failure",
        lambda *args, **kwargs: ("audit-fallback", "evidence-fallback"),  # type: ignore[no-untyped-def]
    )

    payload = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    response = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "gateway_unavailable"


def test_data_transfer_justify_branches_and_enrichment(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="runtime-transfer-unit-justify@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    missing_destination_payload = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="unknown",
        destination_domain="mail.google.com",
        destination_surface="email",
    )
    missing_destination_payload["justification"] = "valid justification text"
    missing_destination_payload["policy_decision"] = {"decision": "require_justification"}
    missing_destination_payload["paste_context"] = {"destination_input_context": "compose_box"}
    missing_destination = client.post(
        "/runtime-control/data-transfer-justify",
        headers=headers,
        json=missing_destination_payload,
    )
    assert missing_destination.status_code == 422
    assert "destination_domain" in missing_destination.text

    block_payload = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="unknown",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    block_payload["policy_decision"] = {"decision": "block"}
    block_payload["justification"] = "cannot override blocked policy"
    blocked = client.post("/runtime-control/data-transfer-justify", headers=headers, json=block_payload)
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["decision"] == "block"
    assert blocked.json()["reason_code"] == "blocked_by_policy"

    short_payload = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="unknown",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    short_payload["policy_decision"] = {"decision": "require_justification"}
    short_payload["justification"] = "short"
    short = client.post("/runtime-control/data-transfer-justify", headers=headers, json=short_payload)
    assert short.status_code == 200, short.text
    assert short.json()["decision"] == "block"
    assert short.json()["reason_code"] == "justification_missing_or_too_short"

    unsanctioned_ai_payload = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    unsanctioned_ai_payload["policy_decision"] = {"decision": "require_justification"}
    unsanctioned_ai_payload["justification"] = "Business critical urgency and manager approved"
    unsanctioned = client.post("/runtime-control/data-transfer-justify", headers=headers, json=unsanctioned_ai_payload)
    assert unsanctioned.status_code == 200, unsanctioned.text
    assert unsanctioned.json()["decision"] == "block"
    assert unsanctioned.json()["reason_code"] == "protected_to_unsanctioned_ai_not_overridable"

    business_sheet_payload = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    business_sheet_payload["policy_decision"] = {
        "decision": "require_justification",
        "reason_code": "business_spreadsheet_to_public_ai",
    }
    business_sheet_payload["correlation_id"] = "business-sheet-justification"
    business_sheet_payload["justification"] = "Summarizing approved account list for the renewal review."
    business_sheet_payload["submitter_name"] = "Jane Pilot"
    business_sheet_payload["submitter_email"] = "jane.pilot@acme.ai"
    business_sheet_payload["submitter_role"] = "account_manager"
    business_sheet_payload["actor_role"] = "account_manager"
    business_sheet_payload["file_meta"] = [
        {
            "name": "account-list.xlsx",
            "type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "text_preview": "account,email,owner\nAcme,jane@clientcorp.com,Ayush",
            "spreadsheet_classification": {
                "business_related": True,
                "contains_secret": False,
                "decision": "require_justification",
                "reason_code": "business_spreadsheet_to_public_ai",
                "signal_types": ["spreadsheet_upload", "business_spreadsheet_upload"],
            },
        }
    ]
    business_sheet = client.post("/runtime-control/data-transfer-justify", headers=headers, json=business_sheet_payload)
    assert business_sheet.status_code == 200, business_sheet.text
    business_sheet_body = business_sheet.json()
    assert business_sheet_body["decision"] == "allow"
    assert business_sheet_body["reason_code"] == "justification_accepted"

    secret_sheet_payload = dict(business_sheet_payload)
    secret_sheet_payload["correlation_id"] = "secret-business-sheet"
    secret_sheet_payload["file_meta"] = [
        {
            "name": "service-credentials.xlsx",
            "type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "text_preview": "service,api_key\nprod,api_key: sk-live-1234567890abcdef",
            "spreadsheet_classification": {
                "business_related": True,
                "contains_secret": True,
                "decision": "block",
                "reason_code": "spreadsheet_contains_secret",
                "signal_types": ["spreadsheet_upload", "spreadsheet_contains_secret"],
            },
        }
    ]
    secret_sheet = client.post("/runtime-control/data-transfer-justify", headers=headers, json=secret_sheet_payload)
    assert secret_sheet.status_code == 200, secret_sheet.text
    assert secret_sheet.json()["decision"] == "block"
    assert secret_sheet.json()["reason_code"] == "spreadsheet_contains_secret_not_overridable"

    business_visual_payload = _check_payload(
        source_domain="internal.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    business_visual_payload["policy_decision"] = {
        "decision": "require_justification",
        "reason_code": "visual_business_content_to_public_ai",
    }
    business_visual_payload["correlation_id"] = "business-visual-justification"
    business_visual_payload["justification"] = "Summarizing customer screenshot for approved renewal review."
    business_visual_payload["actor_role"] = "account_manager"
    business_visual_payload["file_meta"] = [
        {
            "name": "account-screenshot.png",
            "type": "image/png",
            "ocr_text": "account,email,owner\nAcme,jane@clientcorp.com,Ayush",
            "visual_classification": {
                "business_related": True,
                "contains_secret": False,
                "decision": "require_justification",
                "reason_code": "visual_business_content_to_public_ai",
                "signal_types": ["visual_content_upload", "visual_business_content", "visual_contains_business_email"],
            },
        }
    ]
    business_visual = client.post("/runtime-control/data-transfer-justify", headers=headers, json=business_visual_payload)
    assert business_visual.status_code == 200, business_visual.text
    assert business_visual.json()["decision"] == "allow"
    assert business_visual.json()["reason_code"] == "justification_accepted"

    secret_visual_payload = dict(business_visual_payload)
    secret_visual_payload["correlation_id"] = "secret-visual"
    secret_visual_payload["file_meta"] = [
        {
            "name": "secret-screenshot.png",
            "type": "image/png",
            "ocr_text": "Production api_key: sk-live-1234567890abcdef",
            "visual_classification": {
                "business_related": False,
                "contains_secret": True,
                "decision": "block",
                "reason_code": "visual_contains_secret",
                "signal_types": ["visual_content_upload", "visual_contains_secret"],
            },
        }
    ]
    secret_visual = client.post("/runtime-control/data-transfer-justify", headers=headers, json=secret_visual_payload)
    assert secret_visual.status_code == 200, secret_visual.text
    assert secret_visual.json()["decision"] == "block"
    assert secret_visual.json()["reason_code"] == "visual_contains_secret_not_overridable"

    monkeypatch.setattr(svc, "classify_data", lambda **kwargs: "public")
    monkeypatch.setattr(
        svc,
        "infer_from_signal",
        lambda payload: {  # type: ignore[no-untyped-def]
            "provider": "OpenAI",
            "tool_name": "ChatGPT",
            "tool_category": "chatbot",
        },
    )
    allow_payload = _check_payload(
        source_domain="public.example.com",
        source_surface="document",
        source_classification="unknown",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    allow_payload["policy_decision"] = {"decision": "allow"}
    allow_payload["justification"] = "not required for allow path"
    allowed = client.post("/runtime-control/data-transfer-justify", headers=headers, json=allow_payload)
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["decision"] == "allow"
    assert allowed.json()["reason_code"] == "no_justification_required"

    with session_local() as db:
        signals = db.scalars(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.signal_type == "runtime_control.data_transfer_justification",
            )
        ).all()
        signal = next(
            (
                row
                for row in reversed(signals)
                if str((row.payload or {}).get("correlation_id") or "") == str(allow_payload["correlation_id"])
            ),
            None,
        )
        assert signal is not None
        payload = signal.payload or {}
        assert payload.get("source_classification_hint") == "public"
        assert payload.get("provider") == "OpenAI"
        assert payload.get("model_provider") == "OpenAI"
        assert payload.get("tool_category") == "chatbot"

        business_signal = next(
            (
                row
                for row in reversed(signals)
                if str((row.payload or {}).get("correlation_id") or "") == str(business_sheet_payload["correlation_id"])
            ),
            None,
        )
        assert business_signal is not None
        business_payload = business_signal.payload or {}
        assert business_payload["submitter_name"] == "Jane Pilot"
        assert business_payload["submitter_email"] == "jane.pilot@acme.ai"
        assert business_payload["submitter_role"] == "account_manager"
        assert business_payload["actor_role"] == "account_manager"
        assert business_payload["actor_role_missing"] is False
        assert business_payload["actor_department_missing"] is True
        assert business_payload["business_spreadsheet"]["business_spreadsheet_upload"] is True
