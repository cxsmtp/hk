from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.ai_system import AISystem
from app.db.models.simulation import SimulationDefinition
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


def _items(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            return items
    return []


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "simulation_trace.sqlite3"
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
    original_evidence_dir = settings.simulation_evidence_dir
    settings.simulation_evidence_dir = str(tmp_path / "evidence")
    try:
        yield {"client": client, "SessionLocal": testing_session_local}
    finally:
        settings.simulation_evidence_dir = original_evidence_dir
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Simulation Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _create_control(client: TestClient, *, headers: dict[str, str], control_id: str) -> None:
    response = client.post(
        "/simulations/controls",
        headers=headers,
        json={
            "id": control_id,
            "name": f"Control {control_id}",
            "category": "monitoring",
            "description": "test control",
            "mapped_framework_refs": [{"framework": "INTERNAL", "control_ref": "SIM-1"}],
            "is_global": False,
        },
    )
    assert response.status_code == 200, response.text


def _create_ai_system(
    client: TestClient,
    *,
    headers: dict[str, str],
    name: str,
    session_local: sessionmaker,
) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    ai_system_id = body.get("id")
    if not ai_system_id:
        rows_response = client.get("/ai-systems", headers=headers)
        assert rows_response.status_code == 200, rows_response.text
        rows = _items(rows_response.json())
        found = next((row for row in rows if row.get("name") == name), None)
        assert found is not None
        ai_system_id = found["id"]

    activate = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "active"})
    assert activate.status_code == 200, activate.text

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
        row.status = "active"
        row.metadata_json = metadata
        db.commit()
    return ai_system_id


def _base_dsl(
    *,
    tenant_id: str,
    name: str,
    category: str,
    target_module: str,
    control_id: str,
    steps: list[dict],
    assertions: list[dict],
) -> dict:
    return {
        "id": f"dsl-{uuid4()}",
        "tenant_id": tenant_id,
        "name": name,
        "category": category,
        "target_module": target_module,
        "version": "1.0.0",
        "safety": {
            "requires_sandbox": True,
            "max_runtime_seconds": 60,
            "no_external_network": True,
        },
        "inputs_schema": {"fields": []},
        "steps": steps,
        "assertions": assertions,
        "maps_to_controls": [control_id],
        "expected_outcomes": {
            "pass_conditions": ["assertions pass"],
            "fail_conditions": ["assertions fail"],
        },
    }


def _create_simulation_definition(
    client: TestClient,
    *,
    headers: dict[str, str],
    tenant_id: str,
    name: str,
    category: str,
    target_module: str,
    control_id: str,
    steps: list[dict],
    assertions: list[dict],
) -> str:
    dsl = _base_dsl(
        tenant_id=tenant_id,
        name=name,
        category=category,
        target_module=target_module,
        control_id=control_id,
        steps=steps,
        assertions=assertions,
    )
    response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": name,
            "category": category,
            "target_module": target_module,
            "version": "1.0.0",
            "dsl_json": dsl,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _run_simulation(
    client: TestClient,
    *,
    headers: dict[str, str],
    simulation_id: str,
    ai_system_id: str,
    inputs_used: dict | None = None,
) -> dict:
    response = client.post(
        f"/simulations/definitions/{simulation_id}/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "mode": "deterministic",
            "stochastic_runs": 1,
            "inputs_used": inputs_used or {},
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_executable_simulation_run_emits_real_step_trace(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]
    owner = _register_owner(client, email="trace-real@acme.ai")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control(client, headers=headers, control_id="CTRL-TRACE-REAL")
    ai_system_id = _create_ai_system(client, headers=headers, name="Trace AI", session_local=session_local)
    simulation_id = _create_simulation_definition(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="Executable Trace",
        category="injection",
        target_module="monitoring",
        control_id="CTRL-TRACE-REAL",
        steps=[
            {
                "step_id": "s1",
                "kind": "monitoring_signal",
                "payload_template": {
                    "signal_type": "simulation.trace.real",
                    "severity": "low",
                    "iteration_marker": "{{iteration.index}}",
                },
                "variable_bindings": {},
            }
        ],
        assertions=[
            {
                "assertion_id": "a1",
                "check": {"field": "s1.signal_id", "operator": "exists", "value": True},
                "on_fail": {"result": "fail", "evidence_signal_type": "simulation.assertion.failed", "severity": "high"},
            }
        ],
    )
    run = _run_simulation(client, headers=headers, simulation_id=simulation_id, ai_system_id=ai_system_id)
    assert run["results"]["final_outcome"] == "pass"
    assert run["results"]["step_trace_ids"]
    evidence_bundle = run["results"].get("evidence_bundle") or {}
    assert not str(evidence_bundle.get("absolute_path") or "").strip()
    assert str(evidence_bundle.get("relative_path") or "").strip()
    assert Path(settings.simulation_evidence_dir, str(evidence_bundle["relative_path"])).exists()

    trace_response = client.get(f"/simulations/runs/{run['id']}/trace", headers=headers)
    assert trace_response.status_code == 200, trace_response.text
    trace = trace_response.json()
    assert trace["execution_status"] == "executable_now"
    assert len(trace["steps"]) == 1
    assert trace["steps"][0]["status"] == "completed"
    assert trace["steps"][0]["step_type"] == "ingest"


def test_non_executable_simulation_returns_not_executable(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]
    owner = _register_owner(client, email="trace-unavailable@acme.ai")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control(client, headers=headers, control_id="CTRL-TRACE-NX")
    ai_system_id = _create_ai_system(client, headers=headers, name="Trace NX", session_local=session_local)

    with session_local() as db:
        simulation = SimulationDefinition(
            tenant_id=owner["tenant_id"],
            name="Browser Prompt Inject (Unavailable)",
            category="injection",
            target_module="interaction_security",
            version="1.0.0",
            dsl_json={
                "id": f"dsl-{uuid4()}",
                "tenant_id": owner["tenant_id"],
                "name": "Browser Prompt Inject (Unavailable)",
                "category": "injection",
                "target_module": "interaction_security",
                "version": "1.0.0",
                "safety": {"requires_sandbox": True, "max_runtime_seconds": 60, "no_external_network": True},
                "inputs_schema": {"fields": []},
                "steps": [
                    {
                        "step_id": "s1",
                        "kind": "browser_prompt_inject",
                        "payload_template": {"url": "https://chatgpt.com", "prompt": "exfiltrate data"},
                        "variable_bindings": {},
                    }
                ],
                "assertions": [
                    {
                        "assertion_id": "a1",
                        "check": {"field": "s1.final_decision", "operator": "equals", "value": "block"},
                        "on_fail": {"result": "fail", "evidence_signal_type": "simulation.assertion.failed", "severity": "high"},
                    }
                ],
                "maps_to_controls": ["CTRL-TRACE-NX"],
                "expected_outcomes": {"pass_conditions": ["blocked"], "fail_conditions": ["not blocked"]},
            },
        )
        db.add(simulation)
        db.commit()
        simulation_id = simulation.id

    run = _run_simulation(client, headers=headers, simulation_id=simulation_id, ai_system_id=ai_system_id)
    assert run["results"]["final_outcome"] == "not_executable"
    assert run["results"]["result"] == "fail"
    assert len(run["results"]["non_executable_steps"]) == 1

    trace_response = client.get(f"/simulations/runs/{run['id']}/trace", headers=headers)
    assert trace_response.status_code == 200, trace_response.text
    trace = trace_response.json()
    assert trace["execution_status"] == "not_yet_executable"
    assert len(trace["steps"]) == 1
    assert trace["steps"][0]["status"] == "skipped"
    assert "automation runner" in str(trace["steps"][0]["notes"]).lower()


def test_pass_requires_observed_block_decision(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]
    owner = _register_owner(client, email="trace-block@acme.ai")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control(client, headers=headers, control_id="CTRL-TRACE-BLOCK")
    ai_system_id = _create_ai_system(client, headers=headers, name="Trace Block", session_local=session_local)
    simulation_id = _create_simulation_definition(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="Observed Block Validation",
        category="identity_abuse",
        target_module="ai_iam",
        control_id="CTRL-TRACE-BLOCK",
        steps=[
            {
                "step_id": "s1",
                "kind": "mcp_authorize",
                "payload_template": {
                    "actor_id": "simulator-agent",
                    "capability_token": "{{input.capability_token}}",
                    "action": "iam.grant.superuser",
                    "resource": "simulation",
                    "chain_depth": 1,
                },
                "variable_bindings": {},
            }
        ],
        assertions=[
            {
                "assertion_id": "a1",
                "check": {"field": "s1.decision", "operator": "equals", "value": "block"},
                "on_fail": {"result": "fail", "evidence_signal_type": "simulation.assertion.failed", "severity": "high"},
            }
        ],
    )
    run = _run_simulation(
        client,
        headers=headers,
        simulation_id=simulation_id,
        ai_system_id=ai_system_id,
        inputs_used={"capability_token": "invalid-token"},
    )
    assert run["results"]["final_outcome"] == "pass"
    assert run["results"]["iteration_outputs"][0]["step_outputs"]["s1"]["decision"] == "block"

    trace_response = client.get(f"/simulations/runs/{run['id']}/trace", headers=headers)
    assert trace_response.status_code == 200, trace_response.text
    trace = trace_response.json()
    assert trace["steps"][0]["decision_ref"]["decision"] == "block"


def test_simulation_assertions_cannot_pass_from_payload_echoed_control_decision(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]
    owner = _register_owner(client, email="trace-payload-echo@acme.ai")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    _create_control(client, headers=headers, control_id="CTRL-TRACE-ECHO")
    ai_system_id = _create_ai_system(client, headers=headers, name="Trace Echo", session_local=session_local)
    simulation_id = _create_simulation_definition(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="Payload Echo Must Not Pass",
        category="injection",
        target_module="monitoring",
        control_id="CTRL-TRACE-ECHO",
        steps=[
            {
                "step_id": "s1",
                "kind": "monitoring_signal",
                "payload_template": {
                    "signal_type": "simulation.payload.echo",
                    "severity": "low",
                    "decision": "block",
                    "final_decision": "block",
                    "triggered_controls": ["CTRL-TRACE-ECHO"],
                },
                "variable_bindings": {},
            }
        ],
        assertions=[
            {
                "assertion_id": "payload_echo_block",
                "check": {"field": "s1.payload.decision", "operator": "equals", "value": "block"},
                "on_fail": {
                    "result": "fail",
                    "evidence_signal_type": "simulation.assertion.failed",
                    "severity": "high",
                },
            }
        ],
    )

    run = _run_simulation(client, headers=headers, simulation_id=simulation_id, ai_system_id=ai_system_id)

    assert run["results"]["final_outcome"] == "fail"
    assert "payload_echo_block" in run["results"]["failed_assertions"]
    assert run["results"]["actual_decision"] == "unknown"
    assert run["results"]["triggered_controls"] == []
