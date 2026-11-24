from __future__ import annotations

import os

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.models.knowledge_base import KBControl, KBDoc, KBFramework
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "full_name": "KB Owner",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str, correlation_id: str | None = None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }
    if correlation_id:
        headers["X-Correlation-ID"] = correlation_id
    return headers


def _seed_kb_rows(session_local: sessionmaker) -> None:
    with session_local() as db:
        framework = KBFramework(name="ISO42001", version="2023", source_type="authored")
        db.add(framework)
        db.flush()

        db.add(
            KBControl(
                id="ISO42001.7.2",
                framework_id=framework.id,
                title="Auditability baseline",
                objective="Keep immutable logs for policy and approvals.",
                requirement_level="MUST",
                applicability_tags=["audit", "logs"],
                maturity_model={"level_0": "ad_hoc", "level_5": "adaptive"},
                evidence_requirements={"sources": ["audit_log"], "freshness_sla_hours": 24},
            )
        )

        db.add(
            KBDoc(
                framework_id=framework.id,
                title="Authored overview",
                body="Authored summary for control intent.",
                source_type="authored",
            )
        )
        db.add(
            KBDoc(
                framework_id=framework.id,
                title="Customer licensed document",
                body="CUSTOMER_LICENSED_FRAMEWORK_TEXT",
                source_type="customer_provided",
            )
        )
        db.commit()


def test_kb_endpoints_return_ids_without_raw_doc_text_and_log_search(tmp_path) -> None:
    db_file = tmp_path / "kb_router.sqlite3"
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
        _seed_kb_rows(testing_session_local)
        user = _register_owner(client, email="kb-owner@example.com")
        headers = _headers(user["access_token"], user["tenant_id"], correlation_id="kb-corr-001")

        frameworks_resp = client.get("/kb/frameworks", headers=headers)
        assert frameworks_resp.status_code == 200, frameworks_resp.text
        frameworks_payload = frameworks_resp.json()
        assert frameworks_payload["total"] >= 1
        assert "CUSTOMER_LICENSED_FRAMEWORK_TEXT" not in frameworks_resp.text

        controls_resp = client.get("/kb/controls?framework=ISO42001", headers=headers)
        assert controls_resp.status_code == 200, controls_resp.text
        controls_payload = controls_resp.json()
        assert controls_payload["total"] == 1
        assert controls_payload["items"][0]["id"] == "ISO42001.7.2"
        assert "CUSTOMER_LICENSED_FRAMEWORK_TEXT" not in controls_resp.text

        search_resp = client.post(
            "/kb/search",
            headers=headers,
            json={
                "question": "Show auditability controls and evidence hooks",
                "frameworks_in_scope": ["ISO42001"],
            },
        )
        assert search_resp.status_code == 200, search_resp.text
        payload = search_resp.json()
        assert set(payload.keys()) == {
            "top_controls",
            "top_guardian_contracts",
            "top_sim_templates",
            "top_docs",
            "evidence_hooks",
        }
        assert all(isinstance(item, str) for item in payload["top_controls"])
        assert all(isinstance(item, str) for item in payload["top_docs"])
        assert "CUSTOMER_LICENSED_FRAMEWORK_TEXT" not in search_resp.text

        with testing_session_local() as db:
            audit_row = db.scalar(
                select(AuditLog).where(
                    AuditLog.tenant_id == user["tenant_id"],
                    AuditLog.action == "kb.search",
                )
            )
            assert audit_row is not None
            assert audit_row.correlation_id == "kb-corr-001"

            evidence_row = db.scalar(
                select(EvidenceNode).where(
                    EvidenceNode.tenant_id == user["tenant_id"],
                    EvidenceNode.node_type == "kb_search",
                    EvidenceNode.signal_type == "kb.search",
                )
            )
            assert evidence_row is not None
            assert evidence_row.correlation_id == "kb-corr-001"
            assert isinstance(evidence_row.payload.get("retrieved_ids"), dict)
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
