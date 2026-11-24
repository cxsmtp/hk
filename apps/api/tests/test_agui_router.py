from __future__ import annotations

import os
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.finding import Finding
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def test_agui_router_list_and_decide(tmp_path) -> None:
    db_file = tmp_path / "agui_router.sqlite3"
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
        register = client.post(
            "/auth/register",
            json={"email": "agui-router-owner@example.com", "password": PASSWORD, "full_name": "AGUI Owner"},
        )
        assert register.status_code == 200, register.text
        register_payload = register.json()
        access_token = register_payload["access_token"]
        tenant_id = register_payload["tenants"][0]["id"]
        user_id = register_payload["user"]["id"]
        headers = _headers(access_token, tenant_id)

        finding_id = f"finding-{uuid4().hex[:12]}"
        with testing_session_local() as db:
            db.add(
                Finding(
                    finding_id=finding_id,
                    tenant_id=tenant_id,
                    source_surface="gateway",
                    ai_tool="llm_gateway",
                    ai_system_id=None,
                    user_id=user_id,
                    department="security",
                    severity="high",
                    finding_type="enforcement_event",
                    risk_category="prompt_injection",
                    data_classification=None,
                    status="open",
                    recommended_action="Investigate",
                    policy_version_id=None,
                    evidence_node_ids=[],
                    related_control_ids=["CTRL-AGUI-001"],
                    dedupe_key=f"dedupe-{uuid4().hex[:16]}",
                    occurrence_count=1,
                )
            )
            db.commit()

        actions_response = client.get("/agui/actions?source_module=findings&page=1&page_size=100", headers=headers)
        assert actions_response.status_code == 200, actions_response.text
        actions_payload = actions_response.json()
        assert set(actions_payload.keys()) == {"items", "total", "page", "page_size"}
        assert isinstance(actions_payload["items"], list)
        assert any(item["action_id"] == "findings.accept_risk" for item in actions_payload["items"])

        missing_justification_response = client.post(
            "/agui/actions/findings.accept_risk/decide",
            headers=headers,
            json={
                "decision": "approve",
                "justification": "",
                "evidence_displayed": True,
                "decision_payload": {
                    "finding_id": finding_id,
                    "source_object_type": "finding",
                    "source_object_id": finding_id,
                },
            },
        )
        assert missing_justification_response.status_code == 422
        assert "requires justification" in missing_justification_response.text

        decide_response = client.post(
            "/agui/actions/findings.accept_risk/decide",
            headers=headers,
            json={
                "decision": "approve",
                "justification": "Risk accepted with compensating controls documented.",
                "evidence_displayed": True,
                "decision_payload": {
                    "finding_id": finding_id,
                    "source_object_type": "finding",
                    "source_object_id": finding_id,
                },
            },
        )
        assert decide_response.status_code == 200, decide_response.text
        decision_payload = decide_response.json()
        assert decision_payload["action_id"] == "findings.accept_risk"
        assert decision_payload["decision"] == "approve"
        assert decision_payload["source_object_id"] == finding_id
        assert decision_payload["proof_timeline_url"] == f"/discovery/findings/{finding_id}"
        assert "Finding" in decision_payload["source_summary"]

        decisions_response = client.get(
            f"/agui/decisions?action_id=findings.accept_risk&source_object_id={finding_id}",
            headers=headers,
        )
        assert decisions_response.status_code == 200, decisions_response.text
        decisions_payload = decisions_response.json()
        assert set(decisions_payload.keys()) == {"items", "total", "page", "page_size"}
        assert decisions_payload["total"] >= 1
        assert decisions_payload["items"][0]["decision_id"] == decision_payload["decision_id"]

        with testing_session_local() as db:
            finding = db.scalar(
                select(Finding).where(
                    Finding.tenant_id == tenant_id,
                    Finding.finding_id == finding_id,
                )
            )
            assert finding is not None
            assert finding.status == "accepted_risk"
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()

