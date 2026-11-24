from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.discovery import DiscoveryApplication
from app.db.models.finding import Finding
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base, get_db
from app.main import app
from app.services.discovery_service import tool_key_for_name
from app.services.gateway_service import llm_intercept
from app.services.governance_guard import GovernanceViolationError
from app.services.governance_resolution import resolve_ai_system_status
import app.services.governance_guard as governance_guard


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "governance_root_authority.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Governance Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _create_ai_system(client: TestClient, headers: dict[str, str], *, risk_tier: str = "HIGH") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Governance System", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _insert_ai_system(
    db: Session,
    *,
    tenant_id: str,
    risk_tier: str = "HIGH",
    status: str = "active",
    governance_state: str = "APPROVED",
    lifecycle_state: str = "ACTIVE",
) -> str:
    row = AISystem(
        tenant_id=tenant_id,
        name="Inserted Governance System",
        description="",
        risk_tier=risk_tier,
        status=status,
        metadata_json={
            "governance_state": governance_state,
            "lifecycle_state": lifecycle_state,
        },
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row.id


def test_gateway_blocks_unregistered_ai(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="gov-unregistered@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    unknown_ai_system_id = str(uuid4())

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": unknown_ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "context",
            "attachments_meta": [],
        },
    )

    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_context_blocked"
    assert detail["reason_code"] == "ai_system_not_registered"

    with session_local() as db:
        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == owner["tenant_id"],
                Finding.finding_type == "unregistered_ai_system",
                Finding.ai_tool == unknown_ai_system_id,
            )
        )
        assert finding is not None
        assert finding.severity == "high"
        assert finding.evidence_node_ids

        runtime_event = db.scalar(
            select(RuntimeEvent).where(
                RuntimeEvent.tenant_id == owner["tenant_id"],
                RuntimeEvent.event_type == "unregistered_ai_system",
                RuntimeEvent.source_surface == "gateway",
            )
        )
        assert runtime_event is not None
        assert runtime_event.metadata_json.get("requested_ai_system_id") == unknown_ai_system_id
        assert runtime_event.evidence_node_ids

        discovery_app = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == owner["tenant_id"],
                DiscoveryApplication.tool_key == tool_key_for_name(unknown_ai_system_id),
            )
        )
        assert discovery_app is not None
        assert str(discovery_app.status).lower() == "discovered"

        auto_registered = db.scalar(
            select(AISystem).where(
                AISystem.tenant_id == owner["tenant_id"],
                AISystem.name == unknown_ai_system_id,
            )
        )
        assert auto_registered is not None
        assert str(auto_registered.status).lower() == "pending_review"
        assert str(auto_registered.risk_tier).upper() == "HIGH"
        metadata = dict(auto_registered.metadata_json or {})
        assert str(metadata.get("ownership_state") or "") == "UNKNOWN"
        assert str(metadata.get("business_owner") or "") == "UNKNOWN"
        assert str(metadata.get("technical_owner") or "") == "UNKNOWN"


def test_repeated_unknown_gateway_usage_escalates_to_stricter_shadow_controls(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="gov-unknown-repeat-escalation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    unknown_ai_system_id = str(uuid4())

    for idx in range(3):
        response = client.post(
            "/gateway/llm/intercept",
            headers=headers,
            json={
                "ai_system_id": unknown_ai_system_id,
                "actor_type": "human",
                "actor_id": "tester",
                "request_id": f"{uuid4()}-{idx}",
                "prompt": "hello",
                "context_summary": "context",
                "attachments_meta": [],
            },
        )
        assert response.status_code == 403, response.text
        assert response.json()["detail"]["reason_code"] == "ai_system_not_registered"

    with session_local() as db:
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.tenant_id == owner["tenant_id"],
                AISystem.name == unknown_ai_system_id,
            )
        )
        assert ai_system is not None
        metadata = dict(ai_system.metadata_json or {})
        assert metadata.get("strict_unknown_usage_blocking") is True
        assert metadata.get("notify_admin_on_repeat_shadow_usage") is True
        assert metadata.get("require_justification_on_repeated_shadow_usage") is True
        assert int(metadata.get("shadow_usage_repeat_count") or 0) >= 3

        notify_signal = db.scalar(
            select(MonitoringSignal).where(
                MonitoringSignal.tenant_id == owner["tenant_id"],
                MonitoringSignal.ai_system_id == ai_system.id,
                MonitoringSignal.signal_type == "remediation.shadow_ai.repeat_usage_admin_notification",
            )
        )
        assert notify_signal is not None


def test_gateway_blocks_unapproved_ai(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="gov-unapproved@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_local() as db:
        ai_system_id = _insert_ai_system(
            db,
            tenant_id=owner["tenant_id"],
            governance_state="PENDING",
            lifecycle_state="ACTIVE",
        )

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "context",
            "attachments_meta": [],
        },
    )

    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_context_blocked"
    assert detail["reason_code"] == "governance_state_not_approved"


def test_gateway_preserves_unknown_governance_resolution_reason(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="gov-unknown-reason@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    with session_local() as db:
        row = AISystem(
            tenant_id=owner["tenant_id"],
            name="Unknown Governance State System",
            description="",
            risk_tier="MEDIUM",
            status="draft",
            metadata_json={},
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        ai_system_id = row.id

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "context",
            "attachments_meta": [],
        },
    )

    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_context_blocked"
    assert detail["reason_code"] == "governance_state_unknown"


def test_known_approved_ai_is_allowed(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="gov-approved-allowed@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, risk_tier="LOW")

    activate = client.patch(
        f"/ai-systems/{ai_system_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert activate.status_code == 200, activate.text

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "context",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["final_decision"] in {"allow", "warn", "block", "hold_for_approval", "redact"}


def test_gateway_fail_secure_mode_returns_503(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="gov-fail-secure@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)

    def _db_down(_db: Session) -> None:
        raise SQLAlchemyError("db_down")

    monkeypatch.setattr(governance_guard, "_check_db_connectivity", _db_down)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "context",
            "attachments_meta": [],
        },
    )

    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_fail_secure"
    assert detail["reason_code"] == "db_unavailable"


def test_service_guard_blocks_direct_service_call_bypass(test_env) -> None:
    session_local: sessionmaker = test_env["SessionLocal"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="gov-service-guard@example.com")

    with session_local() as db:
        ai_system_id = _insert_ai_system(
            db,
            tenant_id=owner["tenant_id"],
            governance_state="PENDING",
            lifecycle_state="ACTIVE",
        )

        with pytest.raises(GovernanceViolationError) as excinfo:
            llm_intercept(
                db,
                tenant_id=owner["tenant_id"],
                ai_system_id=ai_system_id,
                actor_type="human",
                actor_id="service-test",
                request_id=str(uuid4()),
                prompt="test",
                context_summary="ctx",
                attachments_meta=[],
                tool_output=None,
                audit_actor_user_id=None,
            )

        assert excinfo.value.reason_code == "governance_state_not_approved"


def test_governance_resolution_unknown_never_maps_to_approved(test_env) -> None:
    session_local: sessionmaker = test_env["SessionLocal"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="gov-resolution-status@example.com")

    with session_local() as db:
        unknown = resolve_ai_system_status(
            None,
            {"db": db, "tenant_id": owner["tenant_id"], "source_hint": "trust_center"},
        )
        assert unknown["status"] == "UNKNOWN"
        assert unknown["status"] != "APPROVED"
        assert unknown["risk_tier"] == "HIGH"

        high_risk_ai_system_id = _insert_ai_system(
            db,
            tenant_id=owner["tenant_id"],
            risk_tier="HIGH",
            governance_state="APPROVED",
            lifecycle_state="ACTIVE",
        )
        resolved = resolve_ai_system_status(
            high_risk_ai_system_id,
            {"db": db, "tenant_id": owner["tenant_id"], "source_hint": "trust_center"},
        )
        assert resolved["status"] == "APPROVED"
        assert resolved["risk_tier"] == "HIGH"
        assert resolved["enforcement_mode"] == "strict"


def test_governance_resolution_registered_system_without_state_is_not_approved(test_env) -> None:
    session_local: sessionmaker = test_env["SessionLocal"]
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="gov-resolution-missing-state@example.com")

    with session_local() as db:
        row = AISystem(
            tenant_id=owner["tenant_id"],
            name="Unclassified AI System",
            description="",
            risk_tier="MEDIUM",
            status="draft",
            metadata_json={},
        )
        db.add(row)
        db.commit()
        db.refresh(row)

        resolved = resolve_ai_system_status(
            row.id,
            {"db": db, "tenant_id": owner["tenant_id"], "source_hint": "trust_center"},
        )

        assert resolved["status"] == "UNKNOWN"
        assert resolved["status"] != "APPROVED"
        assert resolved["risk_tier"] == "HIGH"
        assert resolved["enforcement_mode"] == "block"
        assert resolved["reason"] == "governance_state_unknown"
