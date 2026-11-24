from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, desc, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.ai_system import AISystem
from app.db.models.simulation import SimulationScheduleDecision
from app.db.session import Base, get_db
from app.main import app
from app.core.config import settings
from app.services.integration_connector_service import ConnectorPullResult, NormalizedSignal
import app.services.monitoring_service as monitoring_service
from app.services import outbound_destination_policy


PASSWORD = "Password123!"


@pytest.fixture(autouse=True)
def _mock_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        outbound_destination_policy,
        "_system_resolver",
        lambda _hostname, _port: ("93.184.216.34",),
    )


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "simulation_scheduler.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Scheduler Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {"access_token": payload["access_token"], "tenant_id": payload["tenants"][0]["id"]}


def _create_ai_system(
    client: TestClient,
    *,
    headers: dict[str, str],
    name: str,
    session_local: sessionmaker,
    risk_tier: str = "LOW",
) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "scheduler", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]

    with session_local() as db:
        row = db.get(AISystem, ai_system_id)
        assert row is not None
        metadata = dict(row.metadata_json or {})
        metadata["governance_state"] = "APPROVED"
        metadata["lifecycle_state"] = "ACTIVE"
        metadata["ownership_state"] = "ASSIGNED"
        metadata["owner_user_id"] = "owner:test"
        metadata["business_owner_user_id"] = "owner:test"
        metadata["technical_owner_user_id"] = "security:test"
        metadata["compliance_state"] = "COMPLIANT"
        row.metadata_json = metadata
        db.commit()

    return ai_system_id


def _create_control_and_simulation(
    client: TestClient,
    *,
    headers: dict[str, str],
    tenant_id: str,
    control_id: str,
    simulation_name: str,
) -> str:
    control_response = client.post(
        "/simulations/controls",
        headers=headers,
        json={
            "id": control_id,
            "name": f"Control {control_id}",
            "category": "interaction_security",
            "description": "scheduler control",
            "mapped_framework_refs": [],
            "is_global": False,
            "success_criteria": {
                "required_sim_pass_rate": 0.8,
                "required_evidence_sources": ["telemetry", "simulation", "config"],
                "min_maturity": 3,
            },
        },
    )
    assert control_response.status_code == 200, control_response.text

    sim_id = f"sim-{uuid4().hex[:12]}"
    version = "1.0.0"
    dsl = {
        "id": sim_id,
        "tenant_id": tenant_id,
        "name": simulation_name,
        "category": "injection",
        "target_module": "interaction_security",
        "version": version,
        "safety": {
            "requires_sandbox": False,
            "max_runtime_seconds": 30,
            "no_external_network": True,
        },
        "inputs_schema": {"fields": [{"name": "prompt", "type": "string"}]},
        "steps": [
            {
                "step_id": "monitor_step",
                "kind": "monitoring_signal",
                "payload_template": {
                    "signal_type": "simulation.scheduler.signal",
                    "severity": "low",
                    "payload": {"source": "auto_scheduler"},
                },
                "variable_bindings": {},
            }
        ],
        "assertions": [
            {
                "assertion_id": "assert_low_signal",
                "check": {
                    "field": "monitor_step.signal_id",
                    "operator": "exists",
                    "value": True,
                },
                "on_fail": {
                    "result": "fail",
                    "evidence_signal_type": "simulation.scheduler.assertion.failed",
                    "severity": "low",
                },
            }
        ],
        "maps_to_controls": [control_id],
        "expected_outcomes": {
            "pass_conditions": ["final_decision=allow"],
            "fail_conditions": ["final_decision=block"],
        },
    }
    definition_response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": simulation_name,
            "category": "injection",
            "target_module": "interaction_security",
            "version": version,
            "dsl_json": dsl,
        },
    )
    assert definition_response.status_code == 200, definition_response.text
    return definition_response.json()["id"]


def _create_block_policy_version(client: TestClient, *, headers: dict[str, str]) -> None:
    pack = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": "Scheduler Pack", "description": "scheduler", "status": "draft"},
    )
    assert pack.status_code == 200, pack.text
    pack_id = pack.json()["pack"]["id"]

    activate = client.patch(
        f"/policies/packs/{pack_id}",
        headers=headers,
        json={"status": "active"},
    )
    assert activate.status_code == 200, activate.text

    guardian = {
        "guardian_id": "scheduler_block_guard",
        "description": "Block when token appears",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text"],
            "conditions": [
                {
                    "field": "prompt.text",
                    "operator": "contains",
                    "value": "scheduler-block-token",
                    "case_sensitive": False,
                }
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.5},
        "decision": {"on_pass": "allow", "on_fail": "block", "on_uncertain": "warn"},
        "actions": {
            "redact": {"fields": ["prompt"], "strategy": "mask"},
            "mutate_output": {"enabled": False, "strategy": "safe_completion"},
            "notify": {"channels": []},
            "create_ticket": {"system": "jira", "severity": "high"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.scheduler.block",
            "link_to_controls": ["CTRL-INPUT-001"],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.1,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 1,
        },
        "approval_workflow": {
            "required_roles": ["owner", "admin"],
            "sla_minutes": 30,
            "default_if_timeout": "block",
        },
    }
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
            "enforcement_defaults": {"default_decision": "allow", "escalation": "notify"},
            "guardian_contracts": [guardian],
        },
    )
    assert version.status_code == 200, version.text


def _latest_schedule_decision(
    session_local: sessionmaker,
    *,
    tenant_id: str,
    reason_code: str,
) -> SimulationScheduleDecision | None:
    with session_local() as db:
        return db.scalar(
            select(SimulationScheduleDecision)
            .where(
                SimulationScheduleDecision.tenant_id == tenant_id,
                SimulationScheduleDecision.reason_code == reason_code,
            )
            .order_by(desc(SimulationScheduleDecision.created_at))
        )


def test_scheduler_triggers_on_new_ai_system_approved(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="scheduler-approved@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control_and_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id="CTRL-INPUT-001",
        simulation_name="Approved Scheduler Sim",
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="Approved Trigger", session_local=session_local, risk_tier="LOW")

    response = client.patch(
        f"/ai-systems/{ai_system_id}",
        headers=headers,
        json={"status": "approved"},
    )
    assert response.status_code == 200, response.text

    decision = _latest_schedule_decision(
        session_local,
        tenant_id=owner["tenant_id"],
        reason_code="ai_system_approved",
    )
    assert decision is not None
    assert decision.target_ai_system_id == ai_system_id
    assert decision.simulation_run_ids, decision.error_message or decision.execution_summary
    assert decision.status == "completed"


def test_scheduler_triggers_on_high_risk_tier(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="scheduler-high-risk@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control_and_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id="CTRL-INPUT-001",
        simulation_name="High Risk Scheduler Sim",
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="High Risk Trigger", session_local=session_local, risk_tier="LOW")

    response = client.patch(
        f"/ai-systems/{ai_system_id}",
        headers=headers,
        json={"risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text

    decision = _latest_schedule_decision(
        session_local,
        tenant_id=owner["tenant_id"],
        reason_code="high_risk_tier",
    )
    assert decision is not None
    assert decision.target_ai_system_id == ai_system_id
    assert decision.simulation_run_ids, decision.error_message or decision.execution_summary
    assert decision.status == "completed"


def test_scheduler_triggers_on_asymmetry_spike(test_env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "runtime_intelligence_schedule_simulations", True)
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="scheduler-asymmetry@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control_and_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id="CTRL-TOOL-001",
        simulation_name="Asymmetry Scheduler Sim",
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="Asymmetry Trigger", session_local=session_local, risk_tier="HIGH")

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "scheduler-owner",
            "prompt": "ok",
            "context_summary": "scheduler asymmetry",
            "attachments_meta": [{"tool_calls": ["a", "b", "c", "d", "e"]}],
            "tool_output": "x" * 2600,
        },
    )
    assert response.status_code == 200, response.text

    decision = _latest_schedule_decision(
        session_local,
        tenant_id=owner["tenant_id"],
        reason_code="asymmetry_spike",
    )
    assert decision is not None
    assert decision.target_ai_system_id == ai_system_id
    assert "TOOL_CALL_VALIDATION" in decision.target_control_ids
    assert decision.status in {"completed", "failed", "no_simulations"}


def test_scheduler_triggers_on_repeated_enforcement_blocks(test_env, monkeypatch) -> None:
    monkeypatch.setattr(settings, "runtime_intelligence_schedule_simulations", True)
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="scheduler-repeated-blocks@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control_and_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id="CTRL-INPUT-001",
        simulation_name="Repeated Blocks Scheduler Sim",
    )
    _create_block_policy_version(client, headers=headers)
    ai_system_id = _create_ai_system(client, headers=headers, name="Repeated Block Trigger", session_local=session_local, risk_tier="LOW")

    for _ in range(3):
        response = client.post(
            "/gateway/llm/intercept",
            headers=headers,
            json={
                "ai_system_id": ai_system_id,
                "actor_type": "human",
                "actor_id": "scheduler-owner",
                "prompt": "scheduler-block-token please block this",
                "context_summary": "repeat blocks",
                "attachments_meta": [],
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["final_decision"] == "block"

    decision = _latest_schedule_decision(
        session_local,
        tenant_id=owner["tenant_id"],
        reason_code="repeated_enforcement_blocks",
    )
    assert decision is not None
    assert decision.target_ai_system_id == ai_system_id
    assert decision.simulation_run_ids, decision.error_message or decision.execution_summary
    assert decision.status == "completed"


def test_scheduler_triggers_on_connector_drift_event(test_env, monkeypatch) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    owner = _register_owner(client, email="scheduler-drift@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control_and_simulation(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        control_id="CTRL-AI-IAM-001",
        simulation_name="Drift Scheduler Sim",
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="Drift Trigger", session_local=session_local, risk_tier="MEDIUM")
    approve = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "approved"})
    assert approve.status_code == 200, approve.text

    connector = client.post(
        "/monitoring/connectors",
        headers=headers,
        json={
            "name": "Entra Connector",
            "provider_key": "entra_id",
            "enabled": True,
            "polling_interval_minutes": 15,
            "config": {"tenant": "test"},
            "secrets": {"access_token": "token"},
        },
    )
    assert connector.status_code == 200, connector.text
    connector_id = connector.json()["id"]

    def _fake_pull(**kwargs) -> ConnectorPullResult:
        del kwargs
        return ConnectorPullResult(
            status="success",
            is_stub=False,
            stub_reason="",
            error=None,
            pulled_count=1,
            normalized_signals=[
                NormalizedSignal(
                    signal_type="identity.entra.directory_audit",
                    severity="high",
                    payload={
                        "source_metadata": {"provider": "entra_id"},
                        "observed_at": datetime.now(timezone.utc).isoformat(),
                    },
                    control_id="CTRL-AI-IAM-001",
                    evidence_signal_type="connector.entra.directory_audit",
                    drift_title="Entra drift",
                )
            ],
        )

    monkeypatch.setattr(monitoring_service, "run_provider_pull", _fake_pull)

    pull = client.post(f"/monitoring/connectors/{connector_id}/pull", headers=headers)
    assert pull.status_code == 200, pull.text

    decision = _latest_schedule_decision(
        session_local,
        tenant_id=owner["tenant_id"],
        reason_code="connector_drift_event",
    )
    assert decision is not None
    assert decision.target_ai_system_id == ai_system_id
    assert decision.simulation_run_ids
    assert decision.status == "completed"
