from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.ai_system import AISystem
from app.db.models.simulation import SimulationDefinition
from app.db.session import Base, get_db
from app.main import app
from app.services.simulation_policy_service import pre_run_check
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"


def _items(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        rows = payload.get("items")
        if isinstance(rows, list):
            return rows
    return []


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "simulation_policy_engine.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Simulation Policy Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _create_control(client: TestClient, *, headers: dict[str, str], control_id: str) -> None:
    response = client.post(
        "/simulations/controls",
        headers=headers,
        json={
            "id": control_id,
            "name": control_id,
            "category": "monitoring",
            "description": "policy test control",
            "mapped_framework_refs": [{"framework": "NIST AI RMF", "control_ref": control_id}],
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
        json={"name": name, "description": "policy test", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    activate = approve_ai_system(client, headers, ai_system_id, status="active")
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


def _simulation_dsl(
    *,
    tenant_id: str,
    name: str,
    category: str,
    target_surface: str,
    control_id: str,
    severity: str = "med",
    required_executor: str | None = None,
) -> dict:
    dsl: dict[str, object] = {
        "id": f"dsl-{uuid4()}",
        "tenant_id": tenant_id,
        "name": name,
        "category": category,
        "target_module": "monitoring",
        "target_surface": target_surface,
        "executable_status": "executable_now",
        "version": "1.0.0",
        "severity": severity,
        "safety": {
            "requires_sandbox": True,
            "max_runtime_seconds": 60,
            "no_external_network": True,
        },
        "inputs_schema": {"fields": []},
        "steps": [
            {
                "step_id": "s1",
                "kind": "monitoring_signal",
                "payload_template": {
                    "signal_type": "simulation.policy.engine",
                    "severity": "low",
                    "iteration_marker": "{{iteration.index}}",
                },
                "variable_bindings": {},
            }
        ],
        "assertions": [
            {
                "assertion_id": "a1",
                "check": {
                    "field": "s1.payload.iteration_marker",
                    "operator": "equals",
                    "value": "1",
                },
                "on_fail": {
                    "result": "fail",
                    "evidence_signal_type": "simulation.assertion.failed",
                    "severity": "high",
                },
            }
        ],
        "maps_to_controls": [control_id],
        "expected_outcomes": {
            "pass_conditions": ["assertion passes"],
            "fail_conditions": ["assertion fails"],
        },
    }
    if required_executor:
        dsl["required_executor"] = required_executor
    return dsl


def _create_simulation_definition(
    client: TestClient,
    *,
    headers: dict[str, str],
    tenant_id: str,
    name: str,
    category: str,
    target_surface: str,
    control_id: str,
    severity: str = "med",
    required_executor: str | None = None,
) -> str:
    dsl = _simulation_dsl(
        tenant_id=tenant_id,
        name=name,
        category=category,
        target_surface=target_surface,
        control_id=control_id,
        severity=severity,
        required_executor=required_executor,
    )
    response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": name,
            "category": category,
            "target_module": "monitoring",
            "version": "1.0.0",
            "dsl_json": dsl,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def test_policy_persistence_and_single_active_policy_per_tenant(test_env) -> None:
    client: TestClient = test_env["client"]
    auth = _register_owner(client, email="sim-policy-active@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    initial = client.get("/simulation-policies", headers=headers)
    assert initial.status_code == 200, initial.text
    initial_items = _items(initial.json())
    assert len(initial_items) >= 1
    assert sum(1 for row in initial_items if bool(row.get("active"))) == 1

    created = client.post(
        "/simulation-policies",
        headers=headers,
        json={
            "name": "Strict Sandbox Policy",
            "active": True,
            "enabled_categories": ["injection"],
            "enabled_surfaces": ["gateway"],
            "allowed_execution_modes": ["manual"],
            "environment_scope": ["sandbox"],
            "minimum_severity": "low",
        },
    )
    assert created.status_code == 200, created.text
    created_id = created.json()["id"]

    listing = client.get("/simulation-policies", headers=headers)
    assert listing.status_code == 200, listing.text
    rows = _items(listing.json())
    active_rows = [row for row in rows if bool(row.get("active"))]
    assert len(active_rows) == 1
    assert active_rows[0]["id"] == created_id

    active = client.get("/simulation-policies/active", headers=headers)
    assert active.status_code == 200, active.text
    assert active.json()["id"] == created_id


def test_pre_run_policy_blocks_surface_and_requires_approval(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    auth = _register_owner(client, email="sim-policy-blocks@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    control_id = "CTRL-SIM-POLICY-001"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Policy Test AI", session_local=session_local)

    browser_sim_id = _create_simulation_definition(
        client,
        headers=headers,
        tenant_id=auth["tenant_id"],
        name="Browser Block Test",
        category="injection",
        target_surface="browser",
        control_id=control_id,
        severity="high",
    )

    active = client.get("/simulation-policies/active", headers=headers)
    assert active.status_code == 200, active.text
    policy_id = active.json()["id"]

    patch_surface = client.patch(
        f"/simulation-policies/{policy_id}",
        headers=headers,
        json={
            "enabled_surfaces": ["gateway"],
            "enabled_categories": ["injection"],
            "allowed_execution_modes": ["manual"],
            "environment_scope": ["sandbox"],
            "minimum_severity": "low",
            "require_approval_for": [],
            "active": True,
        },
    )
    assert patch_surface.status_code == 200, patch_surface.text

    blocked = client.post(
        f"/simulations/definitions/{browser_sim_id}/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "mode": "deterministic",
            "stochastic_runs": 1,
            "inputs_used": {},
            "execution_environment": "sandbox",
        },
    )
    assert blocked.status_code == 200, blocked.text
    blocked_payload = blocked.json()
    assert blocked_payload["results"]["result"] == "not_executable"
    pre_run = blocked_payload["results"]["pre_run_policy"]
    assert pre_run["status"] == "blocked_by_policy"
    assert any(str(reason).startswith("surface_not_enabled:browser") for reason in pre_run.get("reasons", []))

    gateway_sim_id = _create_simulation_definition(
        client,
        headers=headers,
        tenant_id=auth["tenant_id"],
        name="Approval Test",
        category="injection",
        target_surface="gateway",
        control_id=control_id,
        severity="high",
    )

    patch_approval = client.patch(
        f"/simulation-policies/{policy_id}",
        headers=headers,
        json={
            "enabled_surfaces": ["gateway"],
            "enabled_categories": ["injection"],
            "allowed_execution_modes": ["manual"],
            "environment_scope": ["sandbox"],
            "minimum_severity": "low",
            "require_approval_for": ["severity:high"],
            "active": True,
        },
    )
    assert patch_approval.status_code == 200, patch_approval.text

    approval_required = client.post(
        f"/simulations/definitions/{gateway_sim_id}/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "mode": "deterministic",
            "stochastic_runs": 1,
            "inputs_used": {},
            "execution_environment": "sandbox",
            "approval_granted": False,
        },
    )
    assert approval_required.status_code == 200, approval_required.text
    approval_payload = approval_required.json()
    assert approval_payload["results"]["result"] == "not_executable"
    assert approval_payload["results"]["pre_run_policy"]["status"] == "approval_required"

    approved = client.post(
        f"/simulations/definitions/{gateway_sim_id}/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "mode": "deterministic",
            "stochastic_runs": 1,
            "inputs_used": {},
            "execution_environment": "sandbox",
            "approval_granted": True,
        },
    )
    assert approved.status_code == 200, approved.text
    approved_payload = approved.json()
    assert approved_payload["results"]["pre_run_policy"]["status"] == "approved_to_run"
    assert approved_payload["results"]["result"] in {"pass", "fail", "partial"}


def test_executor_registry_and_missing_executor_not_executable(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    auth = _register_owner(client, email="sim-policy-executors@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    control_id = "CTRL-SIM-POLICY-002"
    _create_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="Executor Test AI", session_local=session_local)

    sim_id = _create_simulation_definition(
        client,
        headers=headers,
        tenant_id=auth["tenant_id"],
        name="Missing Executor Test",
        category="injection",
        target_surface="gateway",
        control_id=control_id,
        severity="med",
        required_executor="missing_executor",
    )

    executors = client.get("/simulation-policies/executors", headers=headers)
    assert executors.status_code == 200, executors.text
    executor_names = {str(row.get("name")) for row in _items(executors.json())}
    assert "gateway_executor" in executor_names

    run_response = client.post(
        f"/simulations/definitions/{sim_id}/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "mode": "deterministic",
            "stochastic_runs": 1,
            "inputs_used": {},
            "execution_environment": "sandbox",
            "approval_granted": True,
        },
    )
    assert run_response.status_code == 200, run_response.text
    payload = run_response.json()
    assert payload["results"]["result"] == "not_executable"
    pre_run = payload["results"]["pre_run_policy"]
    assert pre_run["status"] == "not_executable"
    assert pre_run["required_executor"] == "missing_executor"
    assert any("missing_executor" in str(reason) for reason in pre_run.get("reasons", []))


def test_scheduled_mode_policy_and_catalog_coverage_sync(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    auth = _register_owner(client, email="sim-policy-scheduler@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    control_id = "CTRL-SIM-POLICY-003"
    _create_control(client, headers=headers, control_id=control_id)
    _create_ai_system(client, headers=headers, name="Scheduler Policy AI", session_local=session_local)

    simulation_id = _create_simulation_definition(
        client,
        headers=headers,
        tenant_id=auth["tenant_id"],
        name="Scheduler Policy Simulation",
        category="injection",
        target_surface="gateway",
        control_id=control_id,
        severity="med",
    )

    active = client.get("/simulation-policies/active", headers=headers)
    assert active.status_code == 200, active.text
    policy_id = active.json()["id"]

    policy_patch = client.patch(
        f"/simulation-policies/{policy_id}",
        headers=headers,
        json={
            "enabled_categories": ["injection"],
            "enabled_surfaces": ["gateway"],
            "allowed_execution_modes": ["manual"],
            "environment_scope": ["sandbox"],
            "evidence_retention_days": 31,
            "active": True,
        },
    )
    assert policy_patch.status_code == 200, policy_patch.text

    with session_local() as db:
        simulation = db.scalar(
            select(SimulationDefinition).where(
                SimulationDefinition.id == simulation_id,
                SimulationDefinition.tenant_id == auth["tenant_id"],
            )
        )
        assert simulation is not None

        scheduled_check = pre_run_check(
            db,
            tenant_id=auth["tenant_id"],
            simulation=simulation,
            execution_mode="scheduled",
            execution_environment="sandbox",
            approval_granted=False,
        )
        assert scheduled_check["status"] == "blocked_by_policy"
        assert any(str(reason).startswith("execution_mode_not_allowed:scheduled") for reason in scheduled_check.get("reasons", []))
        assert int(scheduled_check.get("evidence_retention_days") or 0) == 31

        manual_check = pre_run_check(
            db,
            tenant_id=auth["tenant_id"],
            simulation=simulation,
            execution_mode="manual",
            execution_environment="sandbox",
            approval_granted=False,
        )
        assert manual_check["status"] == "approved_to_run"
        assert int(manual_check.get("evidence_retention_days") or 0) == 31

    sync_response = client.post("/simulation-policies/catalog/sync", headers=headers)
    assert sync_response.status_code == 200, sync_response.text
    coverage = sync_response.json()
    assert int(coverage["total_required"]) == 240
    assert int(coverage["total_defined"]) >= 240
    assert "prompt_instruction_attacks" in coverage["by_category"]
