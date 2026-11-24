from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.evidence import EvidenceNode
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "runtime_control_data_transfer.sqlite3"
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
        yield {"client": client, "session_factory": testing_session_local}
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
):
    return {
        "correlation_id": f"corr-{source_domain}-{destination_domain}-{platform_mode}",
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
        "policy_version": "pv-runtime-control-test",
        "platform_mode": platform_mode,
    }


def _active_policy_version_id(client: TestClient, headers: dict[str, str]) -> str:
    packs = client.get("/policies/packs", headers=headers)
    assert packs.status_code == 200, packs.text
    items = list(packs.json().get("items") or [])
    if not items:
        created = client.post(
            "/policies/packs",
            headers=headers,
            json={"name": "Scoped Runtime Pack", "description": "tests", "status": "active"},
        )
        assert created.status_code == 200, created.text
        return str(created.json()["default_version"]["id"])

    pack_id = str(items[0]["id"])
    versions = client.get(f"/policies/packs/{pack_id}/versions", headers=headers)
    assert versions.status_code == 200, versions.text
    version_items = list(versions.json().get("items") or [])
    assert version_items, "expected at least one policy version"
    return str(version_items[0]["id"])


def _set_scoped_rules(client: TestClient, headers: dict[str, str], policy_version_id: str, rules: list[dict]) -> None:
    response = client.patch(
        f"/policies/versions/{policy_version_id}/scoped-rules",
        headers=headers,
        json={"scoped_rules": rules},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["policy_version_id"] == policy_version_id
    assert payload["rule_count"] == len(rules)


def test_protected_source_to_gmail_requires_justification_or_block(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-gmail@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="internal.acme.ai",
            source_surface="internal_app",
            source_classification="protected",
            destination_domain="mail.google.com",
            destination_surface="email",
            destination_input_context="compose_box",
        ),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] in {"require_justification", "block"}
    assert body["audit_log_id"]
    assert body["evidence_node_id"]
    assert body["runtime_event_id"]
    assert body["policy_snapshot"]["policy_snapshot_id"]
    assert body["policy_snapshot"]["policy_category"] == "ai_action_control"
    assert body["decision_explanation"]["action_id"] == body["runtime_event_id"]
    assert body["decision_explanation"]["decision_summary"]["final_decision"] in {"block", "require_approval"}
    assert body["decision_explanation"]["matched_policies"][0]["policy_snapshot_id"] == body["policy_snapshot"]["policy_snapshot_id"]


def test_protected_source_to_slack_warn_or_requires_justification(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-slack@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="wiki.acme.ai",
            source_surface="document",
            source_classification="protected",
            destination_domain="app.slack.com",
            destination_surface="slack",
            destination_input_context="compose_box",
        ),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] in {"warn", "require_justification", "block"}
    assert body["evidence_node_id"]


def test_protected_source_to_public_ai_blocks(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-public-ai@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="finance.acme.ai",
            source_surface="internal_app",
            source_classification="protected",
            destination_domain="chatgpt.com",
            destination_surface="ai_tool",
        ),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["finding_id"] is not None
    assert body["runtime_event_id"]

    findings = client.get(
        "/findings",
        headers=headers,
        params={"finding_type_filter": "sensitive_data_to_public_ai_attempt"},
    )
    assert findings.status_code == 200, findings.text
    assert len(findings.json()["items"]) >= 1


def test_public_source_to_internal_destination_allows(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-public-internal@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="wikipedia.org",
            source_surface="document",
            source_classification="public",
            destination_domain="wiki.acme.ai",
            destination_surface="saas",
            destination_input_context="form_field",
        ),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["audit_log_id"]
    assert body["evidence_node_id"]


def test_repeated_blocked_transfers_increment_finding_occurrence(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-repeat@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    payload = _check_payload(
        source_domain="docs.acme.ai",
        source_surface="document",
        source_classification="protected",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    first = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    second = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["decision"] == "block"
    assert second.json()["decision"] == "block"

    findings = client.get(
        "/findings",
        headers=headers,
        params={"finding_type_filter": "sensitive_data_to_public_ai_attempt"},
    )
    assert findings.status_code == 200, findings.text
    items = findings.json()["items"]
    assert len(items) >= 1
    assert int(items[0]["occurrence_count"]) >= 2


def test_unknown_ai_destination_routes_to_shadow_ai_discovery(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-shadow@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="internal.acme.ai",
            source_surface="internal_app",
            source_classification="protected",
            destination_domain="unknown-assistant.example.ai",
            destination_surface="ai_tool",
        ),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["runtime_event_id"]

    apps = client.get("/discovery/applications", headers=headers)
    assert apps.status_code == 200, apps.text
    app_items = apps.json()["items"]
    assert any("unknown-assistant.example.ai" in str(item["tool_name"]) for item in app_items)


def test_justification_submit_records_audit_evidence_and_allows_when_permitted(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-justify@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    check_response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="finance.acme.ai",
            source_surface="internal_app",
            source_classification="protected",
            destination_domain="mail.google.com",
            destination_surface="email",
            destination_input_context="compose_box",
        ),
    )
    assert check_response.status_code == 200, check_response.text
    check_body = check_response.json()
    assert check_body["decision"] == "require_justification"

    justify_payload = _check_payload(
        source_domain="finance.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    justify_payload["justification"] = "Sharing with approved legal contact for active incident response."
    justify_payload["actor_role"] = "legal_reviewer"
    justify_payload["actor_department"] = "Legal"
    justify_payload["policy_decision"] = {
        "decision": check_body["decision"],
        "reason_code": check_body["reason_code"],
        "policy_version": check_body["policy_version"],
        "platform_mode": check_body["platform_mode"],
    }

    justify = client.post(
        "/runtime-control/data-transfer-justify",
        headers=headers,
        json=justify_payload,
    )
    assert justify.status_code == 200, justify.text
    body = justify.json()
    assert body["decision"] in {"allow", "block"}
    assert body["audit_log_id"]
    assert body["evidence_node_id"]
    assert body["runtime_event_id"]
    with test_env["session_factory"]() as db:
        evidence = db.get(EvidenceNode, body["evidence_node_id"])
        assert evidence is not None
        payload = evidence.payload or {}
        assert payload["actor_role"] == "legal_reviewer"
        assert payload["actor_department"] == "Legal"
        assert payload["actor_role_missing"] is False
        envelope = payload["approved_context_envelope"]
        assert envelope["status"] == "active"
        assert envelope["approved_for_user_id"] == owner["user_id"]
        assert envelope["approved_scope"]["allowed_destination_domains"] == ["mail.google.com"]
        assert envelope["approved_scope"]["allowed_destination_surfaces"] == ["email"]
        assert envelope["approved_scope"]["source_classification"] == "protected"
        assert envelope["constraints"]["max_action_count"] == 1
        assert set(envelope["constraints"]["require_reapproval_for"]) >= {
            "destination_change",
            "intent_drift",
            "secret_detected",
            "actor_change",
        }
        assert payload["context_integrity_status"] == "valid"
        assert payload["actor_department_missing"] is False


def test_discovery_mode_differs_from_enforce_for_unknown_ai_destination(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-mode-diff@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    enforce = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="finance.acme.ai",
            source_surface="internal_app",
            source_classification="protected",
            destination_domain="new-ai.example.ai",
            destination_surface="ai_tool",
            platform_mode="enforce",
        ),
    )
    discovery = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json=_check_payload(
            source_domain="finance.acme.ai",
            source_surface="internal_app",
            source_classification="protected",
            destination_domain="new-ai.example.ai",
            destination_surface="ai_tool",
            platform_mode="discovery",
        ),
    )
    assert enforce.status_code == 200, enforce.text
    assert discovery.status_code == 200, discovery.text
    assert enforce.json()["decision"] == "block"
    assert discovery.json()["decision"] in {"warn", "require_justification"}


def test_sensitive_file_upload_to_external_ai_blocks_via_ocr_detection(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-file-sensitive@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    payload = _check_payload(
        source_domain="intranet.acme.ai",
        source_surface="document",
        source_classification="unknown",
        destination_domain="chat.openai.com",
        destination_surface="ai_tool",
    )
    payload["file_meta"] = [
        {
            "name": "card-scan.png",
            "ocr_text": "Employee card 4242 4242 4242 4242",
            "mime_type": "image/png",
        }
    ]

    response = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "block"
    assert body["reason_code"] == "sensitive_file_upload"
    assert body["finding_id"] is not None

    events = client.get(
        "/runtime-intelligence/events",
        headers=headers,
        params={"correlation_id": payload["correlation_id"]},
    )
    assert events.status_code == 200, events.text
    items = events.json()["items"]
    assert items
    assert any((item.get("metadata") or {}).get("contains_sensitive") is True for item in items)
    session_factory = test_env["session_factory"]
    with session_factory() as db:
        evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.id == body["evidence_node_id"]))
        assert evidence is not None
        evidence_payload = dict(evidence.payload or {})
    assert evidence_payload.get("contains_sensitive") is True
    assert evidence_payload.get("sensitive_upload_detected") is True
    assert evidence_payload.get("guardian_policy_id") == "guardian.data_transfer.sensitive_file_upload_to_public_ai_block"
    assert any(row.get("entity_type") == "credit_card" for row in evidence_payload.get("sensitive_entities") or [])


def test_sensitive_pdf_upload_to_email_requires_justification(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-file-email@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    payload = _check_payload(
        source_domain="hr.acme.ai",
        source_surface="document",
        source_classification="unknown",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    payload["file_meta"] = [
        {
            "name": "employee-record.pdf",
            "ocr_text": "Candidate Name: Alex Smith, Address: 10 Main Street",
            "mime_type": "application/pdf",
        }
    ]

    response = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "require_justification"
    assert body["reason_code"] == "sensitive_file_upload_requires_justification"


def test_clean_file_upload_allows_when_no_sensitive_text_detected(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-file-clean@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    payload = _check_payload(
        source_domain="docs.public.example",
        source_surface="document",
        source_classification="public",
        destination_domain="wiki.acme.ai",
        destination_surface="saas",
        destination_input_context="form_field",
    )
    payload["file_meta"] = [{"name": "public-brief.png", "ocr_text": "Quarterly public roadmap summary"}]
    response = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"


def test_scoped_policy_can_allow_single_endpoint_for_transfer(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-scoped-endpoint@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    policy_version_id = _active_policy_version_id(client, headers)

    _set_scoped_rules(
        client,
        headers,
        policy_version_id,
        [
            {
                "rule_id": "endpoint_allow_email_transfer",
                "subjects": {"endpoint_ids": ["endpoint-finance-01"]},
                "resources": {"domains": ["mail.google.com"]},
                "actions": {"operations": ["copy_paste"]},
                "effect": {
                    "decision": "allow",
                    "reason_code": "endpoint_allow_email_transfer",
                    "explanation": "Approved endpoint may transfer to Gmail for this flow.",
                    "recommended_action": "monitor",
                    "priority": 600,
                },
            }
        ],
    )

    payload = _check_payload(
        source_domain="finance.acme.ai",
        source_surface="internal_app",
        source_classification="protected",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    payload["policy_version"] = policy_version_id
    payload["endpoint_id"] = "endpoint-finance-01"
    response = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "allow"
    assert body["reason_code"] == "endpoint_allow_email_transfer"


def test_scoped_policy_blocks_sales_upload_but_allows_finance_non_sensitive(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-scoped-dept@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    policy_version_id = _active_policy_version_id(client, headers)
    _set_scoped_rules(
        client,
        headers,
        policy_version_id,
        [
            {
                "rule_id": "sales_block_upload",
                "subjects": {"departments": ["sales"]},
                "resources": {"domains": ["mail.google.com"]},
                "actions": {"operations": ["upload"]},
                "effect": {
                    "decision": "block",
                    "reason_code": "sales_upload_blocked",
                    "explanation": "Sales uploads to Gmail are disallowed.",
                    "recommended_action": "route_to_governance",
                    "priority": 900,
                },
            },
            {
                "rule_id": "finance_allow_upload_if_non_sensitive",
                "subjects": {"departments": ["finance"]},
                "resources": {"domains": ["mail.google.com"]},
                "actions": {"operations": ["upload"]},
                "conditions": {"contains_sensitive": False},
                "effect": {
                    "decision": "allow",
                    "reason_code": "finance_upload_allowed_non_sensitive",
                    "explanation": "Finance uploads are allowed only for non-sensitive content.",
                    "recommended_action": "monitor",
                    "priority": 700,
                },
            },
        ],
    )

    base_payload = _check_payload(
        source_domain="finance.acme.ai",
        source_surface="document",
        source_classification="public",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    base_payload["policy_version"] = policy_version_id
    base_payload["file_meta"] = [{"name": "public-report.pdf", "ocr_text": "Public summary and quarterly highlights."}]

    sales_payload = dict(base_payload)
    sales_payload["actor_department"] = "sales"
    sales_response = client.post("/runtime-control/data-transfer-check", headers=headers, json=sales_payload)
    assert sales_response.status_code == 200, sales_response.text
    assert sales_response.json()["decision"] == "block"
    assert sales_response.json()["reason_code"] == "sales_upload_blocked"

    finance_payload = dict(base_payload)
    finance_payload["actor_department"] = "finance"
    finance_response = client.post("/runtime-control/data-transfer-check", headers=headers, json=finance_payload)
    assert finance_response.status_code == 200, finance_response.text
    assert finance_response.json()["decision"] == "allow"
    assert finance_response.json()["reason_code"] == "finance_upload_allowed_non_sensitive"


def test_scoped_allow_does_not_override_sensitive_upload_hard_block(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="runtime-transfer-scoped-sensitive-hardblock@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    policy_version_id = _active_policy_version_id(client, headers)
    _set_scoped_rules(
        client,
        headers,
        policy_version_id,
        [
            {
                "rule_id": "finance_allow_upload_if_non_sensitive",
                "subjects": {"departments": ["finance"]},
                "resources": {"domains": ["mail.google.com"]},
                "actions": {"operations": ["upload"]},
                "effect": {
                    "decision": "allow",
                    "reason_code": "finance_upload_allowed",
                    "explanation": "Finance uploads allowed when policy permits.",
                    "recommended_action": "monitor",
                    "priority": 700,
                },
            }
        ],
    )
    payload = _check_payload(
        source_domain="finance.acme.ai",
        source_surface="document",
        source_classification="public",
        destination_domain="mail.google.com",
        destination_surface="email",
        destination_input_context="compose_box",
    )
    payload["policy_version"] = policy_version_id
    payload["actor_department"] = "finance"
    payload["file_meta"] = [{"name": "id-scan.png", "ocr_text": "Employee ID 4242 4242 4242 4242"}]
    response = client.post("/runtime-control/data-transfer-check", headers=headers, json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["decision"] == "require_justification"
    assert body["reason_code"] == "sensitive_file_upload_requires_justification"
