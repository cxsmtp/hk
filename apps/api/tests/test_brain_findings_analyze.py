from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.maturity import ControlMaturity
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.db.session import Base, get_db
from app.main import app
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "brain_findings_analyze.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Brain Finding Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {"access_token": payload["access_token"], "tenant_id": payload["tenants"][0]["id"], "user_id": payload["user"]["id"]}


def _create_ai_system(client: TestClient, *, headers: dict[str, str], name: str, risk_tier: str) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "brain finding analyze", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approve = approve_ai_system(client, headers, ai_system_id)
    assert approve.status_code == 200, approve.text
    return ai_system_id


def test_brain_findings_analyze_insufficient_evidence(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="brain-find-insufficient@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, name="Brain Missing Evidence AI", risk_tier="HIGH")

    finding_id = f"finding-{uuid4().hex[:12]}"
    with session_local() as db:
        finding = Finding(
            finding_id=finding_id,
            tenant_id=owner["tenant_id"],
            source_surface="gateway",
            ai_tool="llm_gateway",
            ai_system_id=ai_system_id,
            user_id=owner["user_id"],
            department="security",
            severity="high",
            finding_type="enforcement_event",
            risk_category="prompt_injection",
            data_classification=None,
            status="open",
            recommended_action="Investigate",
            policy_version_id=None,
            evidence_node_ids=[],
            related_control_ids=["CTRL-INPUT-001"],
            dedupe_key=f"dedupe-{uuid4().hex[:20]}",
            occurrence_count=1,
        )
        db.add(finding)
        db.commit()

    response = client.post(f"/brain/findings/{finding_id}/analyze", headers=headers, json={})
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["answer"] == "INSUFFICIENT EVIDENCE"
    assert payload["summary"] == "INSUFFICIENT EVIDENCE"
    assert payload["citations"] == []
    assert payload["proposed_actions"]
    assert payload["proposed_next_steps"]
    assert payload["missing_evidence"]


def test_brain_findings_analyze_changes_with_live_control_state(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="brain-find-live-state@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers=headers, name="Brain Live State AI", risk_tier="HIGH")

    control_id = "CTRL-INPUT-001"
    finding_id = f"finding-{uuid4().hex[:12]}"
    evidence_id: str

    with session_local() as db:
        control = Control(
            id=control_id,
            tenant_id=owner["tenant_id"],
            is_global=False,
            name="Input Control",
            category="interaction_security",
            description="Input protection",
            mapped_framework_refs=[{"framework": "NIST AI RMF", "control_ref": "GV-1"}],
        )
        db.add(control)

        evidence = EvidenceNode(
            tenant_id=owner["tenant_id"],
            node_type="guardian_enforcement",
            signal_type="guardian.prompt_injection.detected",
            label="Prompt injection detected",
            payload={"finding_id": finding_id},
        )
        db.add(evidence)
        db.flush()
        evidence_id = evidence.id

        finding = Finding(
            finding_id=finding_id,
            tenant_id=owner["tenant_id"],
            source_surface="gateway",
            ai_tool="llm_gateway",
            ai_system_id=ai_system_id,
            user_id=owner["user_id"],
            department="security",
            severity="high",
            finding_type="enforcement_event",
            risk_category="prompt_injection",
            data_classification=None,
            status="open",
            recommended_action="Investigate",
            policy_version_id=None,
            evidence_node_ids=[evidence.id],
            related_control_ids=[control_id],
            dedupe_key=f"dedupe-{uuid4().hex[:20]}",
            occurrence_count=1,
        )
        db.add(finding)

        maturity = ControlMaturity(
            tenant_id=owner["tenant_id"],
            ai_system_id=ai_system_id,
            control_id=control_id,
            technical_enforcement_score=0.9,
            simulation_pass_rate=0.9,
            coverage_score=0.9,
            maturity_score=0.9,
            status="healthy",
            confidence_score=0.9,
            confidence_inputs={"seed": True},
        )
        db.add(maturity)
        db.commit()

    stable = client.post(f"/brain/findings/{finding_id}/analyze", headers=headers, json={})
    assert stable.status_code == 200, stable.text
    stable_payload = stable.json()
    assert stable_payload["answer"] == "ANALYZED"
    assert stable_payload["citations"]
    stable_action = stable_payload["recommended_action"]
    assert "Maintain current enforcement posture" in stable_action

    with session_local() as db:
        maturity = db.scalar(
            select(ControlMaturity).where(
                ControlMaturity.tenant_id == owner["tenant_id"],
                ControlMaturity.ai_system_id == ai_system_id,
                ControlMaturity.control_id == control_id,
            )
        )
        assert maturity is not None
        maturity.maturity_score = 0.2
        maturity.simulation_pass_rate = 0.2
        maturity.status = "needs_review"

        sim_def = SimulationDefinition(
            tenant_id=owner["tenant_id"],
            name="Live State Simulation",
            category="injection",
            target_module="interaction_security",
            version="1.0.0",
            dsl_json={"maps_to_controls": [control_id]},
        )
        db.add(sim_def)
        db.flush()
        run = SimulationRun(
            tenant_id=owner["tenant_id"],
            simulation_id=sim_def.id,
            ai_system_id=ai_system_id,
            mode="deterministic",
            inputs_used={},
            results={
                "result": "fail",
                "pass_rate": 0.0,
                "evidence_nodes_created": [evidence_id],
                "control_maturity_delta": [{"control_id": control_id, "delta": -0.4}],
                "enforcement_strictness_delta": [{"control_id": control_id, "delta": 1}],
            },
            controls_impacted=[{"control_id": control_id, "delta": -0.2}],
            notes="live-state-test",
        )
        db.add(run)
        db.commit()

    degraded = client.post(f"/brain/findings/{finding_id}/analyze", headers=headers, json={})
    assert degraded.status_code == 200, degraded.text
    degraded_payload = degraded.json()
    assert degraded_payload["answer"] == "ANALYZED"
    degraded_action = degraded_payload["recommended_action"]
    assert degraded_action != stable_action
    assert "Run immediate control validation" in degraded_action
    assert "recent_sim_failures=1" in degraded_payload["summary"]

