from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import get_args, get_origin

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.monitoring import Connector
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base, get_db
from app.main import app
from app.api.routers.monitoring import ConnectorEvaluationResponse


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "connector-evaluation.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Connector Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _headers(auth: dict[str, str]) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {auth['access_token']}",
        "X-Tenant-ID": auth["tenant_id"],
    }


def _managed_browser_metadata(**values) -> dict:
    return {
        "source_surface": "browser_extension",
        "extension_version": "1.0.0",
        "endpoint_id": "managed-chrome-endpoint",
        **values,
    }


def _create_gmail_connector(client: TestClient, *, headers: dict[str, str]) -> str:
    response = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Gmail Evidence Connector",
            "provider_key": "gmail",
            "connector_type": "gmail",
            "config": {"prompt": "never return this configuration field"},
            "secrets": {"access_token": "connector-secret-must-not-leak"},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _add_pull_evidence(
    db,
    *,
    tenant_id: str,
    connector_id: str,
    correlation_id: str,
    created_at: datetime,
    status: str = "success",
    error: str | None = None,
    normalized_signal_count: int = 3,
) -> tuple[str, list[str]]:
    root = EvidenceNode(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        node_type="connector_pull",
        signal_type="connector.gmail.pull",
        label="Gmail connector pull",
        payload={
            "prompt": "email prompt content must not leak",
            "raw_content": "private email body must not leak",
            "client_secret": "evidence-secret-must-not-leak",
        },
        created_at=created_at,
        updated_at=created_at,
    )
    message_node = EvidenceNode(
        tenant_id=tenant_id,
        correlation_id=correlation_id,
        node_type="integration_signal",
        signal_type="connector.gmail.messages.list",
        label="Gmail message inventory observed",
        payload={"content": "raw mailbox content must not leak"},
        created_at=created_at + timedelta(seconds=1),
        updated_at=created_at + timedelta(seconds=1),
    )
    labels_node = EvidenceNode(
        tenant_id=tenant_id,
        correlation_id=None,
        node_type="integration_signal",
        signal_type="connector.gmail.labels",
        label="Gmail label inventory observed",
        payload={"token": "linked-node-secret-must-not-leak"},
        created_at=created_at + timedelta(seconds=2),
        updated_at=created_at + timedelta(seconds=2),
    )
    db.add_all([root, message_node, labels_node])
    db.flush()
    db.add_all(
        [
            EvidenceEdge(
                tenant_id=tenant_id,
                from_node_id=root.id,
                to_node_id=message_node.id,
                edge_type="generated",
                payload={},
            ),
            EvidenceEdge(
                tenant_id=tenant_id,
                from_node_id=root.id,
                to_node_id=labels_node.id,
                edge_type="generated",
                payload={},
            ),
        ]
    )
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            actor_type="system",
            action="monitoring.connector.pull",
            resource_type="connector",
            resource_id=connector_id,
            payload={
                "status": status,
                "error": error,
                "normalized_signal_count": normalized_signal_count,
                "evidence_root_id": root.id,
                "prompt": "audit prompt must not leak",
                "content": "audit content must not leak",
                "secret": "audit-secret-must-not-leak",
            },
            created_at=created_at + timedelta(seconds=3),
        )
    )
    db.flush()
    return root.id, [root.id, message_node.id, labels_node.id]


def test_gmail_evaluation_is_tenant_scoped_bounded_and_read_only(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant_a = _register_owner(client, email="connector-eval-a@example.com")
    tenant_b = _register_owner(client, email="connector-eval-b@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(tenant_a))
    now = datetime.now(timezone.utc)
    pull_correlation_id = "corr-gmail-pull-1"

    with session_local() as db:
        evidence_root_id, evidence_ids = _add_pull_evidence(
            db,
            tenant_id=tenant_a["tenant_id"],
            connector_id=connector_id,
            correlation_id=pull_correlation_id,
            created_at=now - timedelta(minutes=10),
        )
        browser_evidence = EvidenceNode(
            tenant_id=tenant_a["tenant_id"],
            correlation_id="corr-gmail-browser-1",
            node_type="runtime_action",
            signal_type="browser.gmail.send",
            label="Gmail send prevented",
            payload={"prompt": "blocked email body must not leak"},
            created_at=now - timedelta(minutes=1),
            updated_at=now - timedelta(minutes=1),
        )
        db.add(browser_evidence)
        db.flush()
        browser_evidence_id = browser_evidence.id
        db.add_all(
            [
                RuntimeEvent(
                    event_id="gmail-telemetry-older",
                    tenant_id=tenant_a["tenant_id"],
                    source_surface="browser",
                    event_type="browser_telemetry",
                    app_id="mail.google.com",
                    application="Gmail",
                    user_id="gmail-user",
                    browser_type="chrome",
                    evidence_node_ids=[],
                    correlation_id="corr-gmail-browser-older",
                    metadata_json=_managed_browser_metadata(
                        domain="mail.google.com",
                        control_mode="telemetry_only",
                    ),
                    created_at=now - timedelta(minutes=2),
                ),
                RuntimeEvent(
                    event_id="gmail-inline-newest",
                    tenant_id=tenant_a["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_blocked",
                    app_id="mail.google.com",
                    application="Gmail",
                    user_id="gmail-user",
                    browser_type="chrome",
                    decision="block",
                    evidence_node_ids=[browser_evidence.id],
                    correlation_id="corr-gmail-browser-1",
                    metadata_json=_managed_browser_metadata(
                        domain="mail.google.com",
                        action_type="email_send",
                        control_mode="inline_prevented",
                        decision_badge="Pre-Action Blocked",
                        reason_code="sensitive_data_detected",
                        prompt="browser prompt must not leak",
                        raw_content="browser content must not leak",
                        access_token="browser-secret-must-not-leak",
                    ),
                    created_at=now - timedelta(minutes=1),
                ),
                RuntimeEvent(
                    event_id="other-tenant-gmail-latest",
                    tenant_id=tenant_b["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_allowed",
                    app_id="mail.google.com",
                    application="Gmail",
                    user_id="other-tenant-user",
                    browser_type="chrome",
                    decision="allow",
                    evidence_node_ids=[],
                    correlation_id="corr-other-tenant",
                    metadata_json=_managed_browser_metadata(
                        domain="mail.google.com",
                        control_mode="inline_allowed",
                    ),
                    created_at=now,
                ),
            ]
        )
        db.commit()
        counts_before = {
            "audits": db.scalar(select(func.count()).select_from(AuditLog)),
            "evidence": db.scalar(select(func.count()).select_from(EvidenceNode)),
            "events": db.scalar(select(func.count()).select_from(RuntimeEvent)),
        }

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(tenant_a),
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert set(body) == {
        "connector",
        "latest_pull",
        "connector_path",
        "browser_path",
        "latest_browser_action",
        "evidence",
        "limitations",
    }
    assert body["connector"]["id"] == connector_id
    assert body["connector"]["provider_key"] == "gmail"
    assert body["connector"]["name"] == "Gmail Evidence Connector"
    assert body["connector"]["status"] == "active"
    assert body["connector"]["is_stub"] is False
    assert body["connector"]["stub_reason"] == ""
    assert body["connector"]["last_pull_status"] == "never"
    assert body["connector"]["last_pull_error"] is None
    assert body["connector"]["has_secrets"] is True
    assert "config" not in body["connector"]
    assert "secrets" not in body["connector"]
    assert body["connector_path"]["mode"] == "monitor_only"
    assert body["connector_path"]["discovery"] == "covered"
    assert body["connector_path"]["authorization"] == "not_covered"
    assert body["connector_path"]["prove"] == "covered"
    assert body["latest_pull"]["status"] == "success"
    assert body["latest_pull"]["normalized_signal_count"] == 3
    assert body["latest_pull"]["correlation_id"] == pull_correlation_id
    assert body["latest_pull"]["evidence_root_id"] == evidence_root_id
    assert body["browser_path"]["canonical_domain"] == "mail.google.com"
    assert body["browser_path"]["search_status"] == "complete"
    assert body["browser_path"]["mode"] == "inline_prevented"
    assert body["browser_path"]["discovery"] == "covered"
    assert body["browser_path"]["authorization"] == "covered"
    assert body["browser_path"]["prove"] == "covered"
    assert body["latest_browser_action"]["event_id"] == "gmail-inline-newest"
    assert body["latest_browser_action"]["source"] == "browser"
    assert body["latest_browser_action"]["application"] == "Gmail"
    assert body["latest_browser_action"]["action_type"] == "email_send"
    assert body["latest_browser_action"]["reason"] == "sensitive_data_detected"
    assert body["latest_browser_action"]["control_mode"] == "inline_prevented"
    assert body["latest_browser_action"]["decision_badge"] == "Pre-Action Blocked"
    assert body["latest_browser_action"]["domain"] == "mail.google.com"
    assert body["latest_browser_action"]["user"] == "gmail-user"
    assert body["latest_browser_action"]["evidence_node_ids"] == [browser_evidence_id]
    assert body["latest_browser_action"]["evidence_linked"] is True
    assert body["latest_browser_action"]["evidence_integrity_status"] == "valid"
    assert body["evidence"]["root_id"] == evidence_root_id
    assert body["evidence"]["integrity_status"] == "valid"
    assert body["evidence"]["count"] == len(evidence_ids)
    assert {item["id"] for item in body["evidence"]["items"]} == set(evidence_ids)
    assert all("payload" not in item for item in body["evidence"]["items"])
    assert isinstance(body["limitations"], list)
    assert body["limitations"]

    serialized = repr(body).lower()
    for forbidden in (
        "prompt",
        "raw_content",
        "connector-secret-must-not-leak",
        "evidence-secret-must-not-leak",
        "browser-secret-must-not-leak",
        "other-tenant-user",
    ):
        assert forbidden not in serialized

    with session_local() as db:
        counts_after = {
            "audits": db.scalar(select(func.count()).select_from(AuditLog)),
            "evidence": db.scalar(select(func.count()).select_from(EvidenceNode)),
            "events": db.scalar(select(func.count()).select_from(RuntimeEvent)),
        }
    assert counts_after == counts_before

    cross_tenant = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(tenant_b),
    )
    assert cross_tenant.status_code == 404


def test_latest_telemetry_only_browser_event_never_claims_authorization(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="connector-eval-telemetry@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))
    now = datetime.now(timezone.utc)

    with session_local() as db:
        db.add_all(
            [
                RuntimeEvent(
                    event_id="gmail-inline-older",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="prompt_blocked",
                    app_id="mail.google.com",
                    application="Gmail",
                    decision="block",
                    evidence_node_ids=[],
                    metadata_json=_managed_browser_metadata(control_mode="inline_prevented"),
                    created_at=now - timedelta(minutes=2),
                ),
                RuntimeEvent(
                    event_id="gmail-telemetry-newest",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="browser_telemetry",
                    app_id=None,
                    application=None,
                    browser_type="chrome",
                    evidence_node_ids=[],
                    metadata_json=_managed_browser_metadata(
                        url="https://mail.google.com/mail/u/0/#inbox",
                        control_mode="telemetry_only",
                    ),
                    created_at=now - timedelta(minutes=1),
                ),
            ]
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["latest_browser_action"]["event_id"] == "gmail-telemetry-newest"
    assert body["latest_browser_action"]["control_mode"] == "telemetry_only"
    assert body["connector_path"]["discovery"] == "not_covered"
    assert body["connector_path"]["authorization"] == "not_covered"
    assert body["connector_path"]["prove"] == "unknown"
    assert body["browser_path"]["mode"] == "telemetry_only"
    assert body["browser_path"]["discovery"] == "covered"
    assert body["browser_path"]["authorization"] == "unknown"
    assert body["browser_path"]["prove"] == "unknown"
    assert body["evidence"]["integrity_status"] == "unknown"


def test_absent_browser_action_is_not_covered_and_pull_errors_are_bounded(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="connector-eval-absent@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))
    now = datetime.now(timezone.utc)

    with session_local() as db:
        _add_pull_evidence(
            db,
            tenant_id=owner["tenant_id"],
            connector_id=connector_id,
            correlation_id="corr-gmail-error",
            created_at=now - timedelta(minutes=1),
            status="error",
            error="provider unavailable: " + ("x" * 2_000),
            normalized_signal_count=0,
        )
        for index in range(40):
            db.add(
                EvidenceNode(
                    tenant_id=owner["tenant_id"],
                    correlation_id="corr-gmail-error",
                    node_type="integration_signal",
                    signal_type=f"connector.gmail.extra.{index}",
                    label=f"Bounded evidence {index}",
                    payload={"content": "not returned"},
                    created_at=now + timedelta(seconds=index),
                    updated_at=now + timedelta(seconds=index),
                )
            )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["latest_pull"]["status"] == "error"
    assert body["latest_pull"]["normalized_signal_count"] == 0
    assert len(body["latest_pull"]["error"]) <= 512
    assert body["latest_browser_action"] is None
    assert body["connector_path"]["discovery"] == "unknown"
    assert body["connector_path"]["authorization"] == "not_covered"
    assert body["connector_path"]["prove"] == "unknown"
    assert body["browser_path"]["mode"] == "not_observed"
    assert body["browser_path"]["discovery"] == "not_covered"
    assert body["browser_path"]["authorization"] == "not_covered"
    assert body["browser_path"]["prove"] == "not_covered"
    assert body["evidence"]["integrity_status"] == "valid"
    assert body["evidence"]["count"] <= 25
    assert len(body["evidence"]["items"]) <= 25
    limitations = " ".join(body["limitations"]).lower()
    assert "unmanaged browsers" in limitations
    assert "gmail mobile" in limitations
    assert "desktop" in limitations
    assert "direct gmail api actions" in limitations


@pytest.mark.parametrize("control_mode", ["review_required", "warned"])
def test_non_inline_browser_modes_never_claim_authorization(test_env, control_mode: str) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email=f"connector-eval-{control_mode}@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))

    with session_local() as db:
        db.add(
            RuntimeEvent(
                event_id=f"gmail-{control_mode}",
                tenant_id=owner["tenant_id"],
                source_surface="browser",
                event_type="browser_action",
                app_id="mail.google.com",
                application="Gmail",
                browser_type="chrome",
                decision="review",
                evidence_node_ids=[],
                metadata_json=_managed_browser_metadata(
                    control_mode=control_mode,
                    action_type="x" * 1_000,
                    reason_code="y" * 1_000,
                ),
                created_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["browser_path"]["discovery"] == "covered"
    assert body["browser_path"]["authorization"] == "unknown"
    assert body["browser_path"]["prove"] == "unknown"
    assert len(body["latest_browser_action"]["action_type"]) <= 128
    assert len(body["latest_browser_action"]["reason"]) <= 128


@pytest.mark.parametrize(
    ("event_type", "expected_authorization"),
    [("prompt_allowed", "covered"), ("browser_action", "unknown")],
)
def test_inline_allow_requires_pre_action_allow_semantics(
    test_env,
    event_type: str,
    expected_authorization: str,
) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(
        client,
        email=f"connector-eval-allow-{event_type}@example.com",
    )
    connector_id = _create_gmail_connector(client, headers=_headers(owner))

    with session_local() as db:
        db.add(
            RuntimeEvent(
                event_id=f"gmail-{event_type}",
                tenant_id=owner["tenant_id"],
                source_surface="browser_extension",
                event_type=event_type,
                app_id="mail.google.com",
                browser_type="chrome",
                decision="allow",
                evidence_node_ids=[],
                metadata_json=_managed_browser_metadata(control_mode="inline_allowed"),
                created_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    assert response.json()["browser_path"]["authorization"] == expected_authorization


def test_browser_matching_requires_managed_chrome_and_exact_canonical_host(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="connector-eval-browser-source@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))
    now = datetime.now(timezone.utc)

    with session_local() as db:
        db.add_all(
            [
                RuntimeEvent(
                    event_id="gmail-managed-exact",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="browser_telemetry",
                    browser_type="chrome",
                    evidence_node_ids=[],
                    metadata_json=_managed_browser_metadata(
                        url="https://mail.google.com/mail/u/0/#inbox",
                        control_mode="telemetry_only",
                    ),
                    created_at=now - timedelta(minutes=3),
                ),
                RuntimeEvent(
                    event_id="gmail-spoofed-url",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="browser_action",
                    browser_type="chrome",
                    evidence_node_ids=[],
                    metadata_json=_managed_browser_metadata(
                        url="https://evil.example/?next=https://mail.google.com",
                        control_mode="inline_allowed",
                    ),
                    created_at=now - timedelta(minutes=2),
                ),
                RuntimeEvent(
                    event_id="gmail-misleading-label",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="browser_action",
                    application="Gmail",
                    browser_type="chrome",
                    evidence_node_ids=[],
                    metadata_json=_managed_browser_metadata(
                        url="https://example.com/",
                        control_mode="inline_allowed",
                    ),
                    created_at=now - timedelta(minutes=1),
                ),
                RuntimeEvent(
                    event_id="gmail-unmanaged-browser",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="browser_action",
                    app_id="mail.google.com",
                    browser_type="safari",
                    evidence_node_ids=[],
                    metadata_json=_managed_browser_metadata(control_mode="inline_allowed"),
                    created_at=now,
                ),
                RuntimeEvent(
                    event_id="gmail-generic-chrome",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser",
                    event_type="browser_action",
                    app_id="mail.google.com",
                    browser_type="chrome",
                    evidence_node_ids=[],
                    metadata_json={"control_mode": "inline_allowed"},
                    created_at=now + timedelta(seconds=1),
                ),
            ]
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["latest_browser_action"]["event_id"] == "gmail-managed-exact"
    assert body["browser_path"]["search_status"] == "complete"
    assert body["browser_path"]["authorization"] == "unknown"


def test_gmail_url_match_is_not_lost_after_more_than_one_candidate_page(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="connector-eval-browser-pagination@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))
    now = datetime.now(timezone.utc)

    with session_local() as db:
        db.add(
            RuntimeEvent(
                event_id="gmail-managed-behind-first-page",
                tenant_id=owner["tenant_id"],
                source_surface="browser_extension",
                event_type="browser_telemetry",
                browser_type="chrome",
                evidence_node_ids=[],
                metadata_json=_managed_browser_metadata(
                    url="https://mail.google.com/mail/u/0/#inbox",
                    control_mode="telemetry_only",
                ),
                created_at=now - timedelta(hours=1),
            )
        )
        db.add_all(
            [
                RuntimeEvent(
                    event_id=f"irrelevant-managed-{index}",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser_extension",
                    event_type="browser_telemetry",
                    browser_type="chrome",
                    evidence_node_ids=[],
                    metadata_json=_managed_browser_metadata(
                        url=f"https://example-{index}.com/",
                        control_mode="telemetry_only",
                    ),
                    created_at=now + timedelta(seconds=index),
                )
                for index in range(300)
            ]
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["latest_browser_action"] is None
    assert body["browser_path"]["search_status"] == "truncated"
    assert body["browser_path"]["discovery"] == "unknown"
    assert body["browser_path"]["authorization"] == "unknown"
    assert body["browser_path"]["prove"] == "unknown"


def test_claimed_browser_evidence_must_resolve_in_tenant_to_prove_coverage(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="connector-eval-invalid-browser-link@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))

    with session_local() as db:
        db.add(
            RuntimeEvent(
                event_id="gmail-invalid-evidence-link",
                tenant_id=owner["tenant_id"],
                source_surface="browser_extension",
                event_type="browser_action",
                app_id="mail.google.com",
                browser_type="chrome",
                evidence_node_ids=["00000000-0000-0000-0000-000000000000"],
                metadata_json=_managed_browser_metadata(control_mode="inline_prevented"),
                created_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["latest_browser_action"]["evidence_linked"] is False
    assert body["latest_browser_action"]["evidence_integrity_status"] == "invalid"
    assert body["browser_path"]["authorization"] == "unknown"
    assert body["browser_path"]["prove"] == "unknown"


def test_policy_blocked_followup_preserves_correlated_inline_block(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="connector-eval-policy-sequence@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))
    now = datetime.now(timezone.utc)

    with session_local() as db:
        evidence = EvidenceNode(
            tenant_id=owner["tenant_id"],
            correlation_id="corr-policy-sequence",
            node_type="runtime_action",
            signal_type="browser.gmail.block",
            label="Gmail action blocked",
            payload={"content": "must not leak"},
            created_at=now - timedelta(seconds=2),
            updated_at=now - timedelta(seconds=2),
        )
        db.add(evidence)
        db.flush()
        evidence_id = evidence.id
        db.add_all(
            [
                RuntimeEvent(
                    event_id="gmail-prompt-blocked",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser_extension",
                    event_type="prompt_blocked",
                    app_id="mail.google.com",
                    application="Gmail",
                    browser_type="chrome",
                    decision="block",
                    evidence_node_ids=[evidence_id],
                    correlation_id="corr-policy-sequence",
                    metadata_json=_managed_browser_metadata(
                        control_mode="inline_prevented",
                        reason="sensitive_data_detected",
                    ),
                    created_at=now - timedelta(seconds=1),
                ),
                RuntimeEvent(
                    event_id="gmail-policy-blocked-followup",
                    tenant_id=owner["tenant_id"],
                    source_surface="browser_extension",
                    event_type="policy_blocked",
                    app_id="mail.google.com",
                    application="Gmail",
                    browser_type="chrome",
                    decision="block",
                    evidence_node_ids=[evidence_id],
                    correlation_id="corr-policy-sequence",
                    metadata_json=_managed_browser_metadata(
                        control_mode="telemetry_only",
                        decision_reason="policy_blocked",
                        input_signal_types=["sensitive_data"],
                    ),
                    created_at=now,
                ),
            ]
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["latest_browser_action"]["event_id"] == "gmail-prompt-blocked"
    assert body["latest_browser_action"]["control_mode"] == "inline_prevented"
    assert body["latest_browser_action"]["reason"] == "sensitive_data_detected"
    assert body["browser_path"]["authorization"] == "covered"
    assert body["browser_path"]["prove"] == "covered"


def test_invalid_connector_root_never_proves_coverage(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="connector-eval-invalid-root@example.com")
    connector_id = _create_gmail_connector(client, headers=_headers(owner))

    with session_local() as db:
        db.add(
            AuditLog(
                tenant_id=owner["tenant_id"],
                correlation_id="corr-invalid-root",
                actor_type="system",
                action="monitoring.connector.pull",
                resource_type="connector",
                resource_id=connector_id,
                payload={
                    "status": "success",
                    "normalized_signal_count": 1,
                    "evidence_root_id": "00000000-0000-0000-0000-000000000000",
                },
                created_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["evidence"]["integrity_status"] == "invalid"
    assert body["connector_path"]["prove"] == "unknown"


@pytest.mark.parametrize(
    ("enabled", "raw_status", "is_stub", "last_pull_status", "expected_status", "expected_enabled"),
    [
        (False, "active", False, "never", "disabled", False),
        (True, "revoked", False, "never", "revoked", False),
        (True, "active", False, "error", "degraded", True),
        (True, "active", True, "never", "stub", False),
    ],
)
def test_connector_operational_status_is_normalized(
    test_env,
    enabled: bool,
    raw_status: str,
    is_stub: bool,
    last_pull_status: str,
    expected_status: str,
    expected_enabled: bool,
) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(
        client,
        email=f"connector-eval-state-{expected_status}@example.com",
    )
    connector_id = _create_gmail_connector(client, headers=_headers(owner))

    with session_local() as db:
        connector = db.scalar(
            select(Connector).where(
                Connector.id == connector_id,
                Connector.tenant_id == owner["tenant_id"],
            )
        )
        assert connector is not None
        connector.enabled = enabled
        connector.status = raw_status
        connector.is_stub = is_stub
        connector.stub_reason = "stub reason " + ("z" * 1_000) if is_stub else ""
        connector.last_pull_status = last_pull_status
        connector.last_pull_error = "private provider failure " + ("x" * 1_000) if last_pull_status == "error" else None
        if expected_status in {"disabled", "revoked", "stub"}:
            _add_pull_evidence(
                db,
                tenant_id=owner["tenant_id"],
                connector_id=connector_id,
                correlation_id=f"corr-{expected_status}-success",
                created_at=datetime.now(timezone.utc),
                status="success",
            )
        db.commit()

    response = client.get(
        f"/monitoring/connectors/{connector_id}/evaluation",
        headers=_headers(owner),
    )
    assert response.status_code == 200, response.text
    connector_body = response.json()["connector"]
    assert connector_body["status"] == expected_status
    assert connector_body["enabled"] is expected_enabled
    assert connector_body["is_stub"] is is_stub
    assert len(connector_body["stub_reason"]) <= 256
    assert connector_body["last_pull_status"] == last_pull_status
    assert connector_body["has_secrets"] is True
    if last_pull_status == "error":
        assert connector_body["last_pull_error"] == "Connector pull failed; consult server diagnostics."
    if expected_status in {"disabled", "revoked", "stub"}:
        body = response.json()
        assert body["connector_path"]["discovery"] == "not_covered"
        assert body["connector_path"]["prove"] == "unknown"


def test_connector_evaluation_response_uses_explicit_nested_models() -> None:
    pending: list[type[BaseModel]] = [ConnectorEvaluationResponse]
    visited: set[type[BaseModel]] = set()

    while pending:
        model = pending.pop()
        if model in visited:
            continue
        visited.add(model)
        for field in model.model_fields.values():
            annotation = field.annotation
            assert get_origin(annotation) is not dict
            for candidate in (annotation, *get_args(annotation)):
                if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                    pending.append(candidate)
