from __future__ import annotations

import os
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, desc, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Risk Owner"},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return {"access_token": data["access_token"], "tenant_id": data["tenants"][0]["id"]}


def _create_ai_system(client: TestClient, *, headers: dict[str, str], risk_tier: str) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": f"AI-{uuid4()}", "description": "risk propagation", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_strictness_updates_on_risk_change(tmp_path) -> None:
    db_file = tmp_path / "risk_propagation_strictness.sqlite3"
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
        owner = _register_owner(client, email="risk-owner-strictness@example.com")
        headers = _headers(owner["access_token"], owner["tenant_id"])

        ai_system_id = _create_ai_system(client, headers=headers, risk_tier="Minimal")

        before_matrix = client.get(
            "/gateway/llm/guardian-matrix",
            headers=headers,
            params={"ai_system_id": ai_system_id, "actor_type": "human"},
        )
        assert before_matrix.status_code == 200, before_matrix.text
        assert before_matrix.json()["strictness_level"] == 0

        update_response = client.patch(
            f"/ai-systems/{ai_system_id}",
            headers=headers,
            json={"risk_tier": "Restricted"},
        )
        assert update_response.status_code == 200, update_response.text

        after_matrix = client.get(
            "/gateway/llm/guardian-matrix",
            headers=headers,
            params={"ai_system_id": ai_system_id, "actor_type": "human"},
        )
        assert after_matrix.status_code == 200, after_matrix.text
        assert after_matrix.json()["strictness_level"] == 2

        with testing_session_local() as db:
            audit_row = db.scalar(
                select(AuditLog)
                .where(
                    AuditLog.tenant_id == owner["tenant_id"],
                    AuditLog.action == "risk_propagation",
                    AuditLog.resource_id == ai_system_id,
                )
                .order_by(desc(AuditLog.created_at))
            )
            assert audit_row is not None
            assert audit_row.payload.get("strictness_profile") == "maximum"
            assert audit_row.payload.get("simulation_frequency") == "hourly"

            evidence_row = db.scalar(
                select(EvidenceNode)
                .where(
                    EvidenceNode.tenant_id == owner["tenant_id"],
                    EvidenceNode.node_type == "risk_propagation",
                    EvidenceNode.signal_type == "risk_propagation",
                )
                .order_by(desc(EvidenceNode.created_at))
            )
            assert evidence_row is not None
            assert evidence_row.payload.get("current_risk_tier") == "Restricted"
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_simulation_frequency_adjusted(tmp_path) -> None:
    db_file = tmp_path / "risk_propagation_frequency.sqlite3"
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
        owner = _register_owner(client, email="risk-owner-frequency@example.com")
        headers = _headers(owner["access_token"], owner["tenant_id"])

        ai_system_id = _create_ai_system(client, headers=headers, risk_tier="Limited")

        update_response = client.patch(
            f"/ai-systems/{ai_system_id}",
            headers=headers,
            json={"risk_tier": "High"},
        )
        assert update_response.status_code == 200, update_response.text

        with testing_session_local() as db:
            ai_system = db.scalar(
                select(AISystem).where(
                    AISystem.id == ai_system_id,
                    AISystem.tenant_id == owner["tenant_id"],
                )
            )
            assert ai_system is not None
            metadata = ai_system.metadata_json or {}
            assert metadata.get("enforcement_profile") == "strict"
            assert metadata.get("simulation_frequency") == "daily"
            assert metadata.get("simulation_interval_minutes") == 1440
            assert metadata.get("audit_posture_status") in {"degraded", "stable"}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
