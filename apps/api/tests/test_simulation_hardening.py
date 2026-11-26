from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, desc, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.audit import AuditLog
from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import (
    ControlGuardianBinding,
    GuardianContract,
    GuardianContractBindingV2,
    GuardianContractV2,
    PolicyVersion,
)
from app.db.models.remediation import RemediationAction
from app.db.session import Base, get_db
from app.main import app
from ai_system_approval_helpers import approve_ai_system


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
    db_file = tmp_path / "simulation_hardening.sqlite3"
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


def _create_control(
    client: TestClient,
    *,
    headers: dict[str, str],
    control_id: str,
    success_criteria: dict | None = None,
) -> None:
    payload = {
        "id": control_id,
        "name": f"Control {control_id}",
        "category": "monitoring",
        "description": "test control",
        "mapped_framework_refs": [{"framework": "INTERNAL", "control_ref": "SIM-1"}],
        "is_global": False,
    }
    if success_criteria is not None:
        payload["success_criteria"] = success_criteria

    response = client.post(
        "/simulations/controls",
        headers=headers,
        json=payload,
    )
    assert response.status_code == 200, response.text


def _create_ai_system(
    client: TestClient,
    *,
    headers: dict[str, str],
    name: str,
    session_local: sessionmaker | None = None,
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
        list_response = client.get("/ai-systems", headers=headers)
        assert list_response.status_code == 200, list_response.text
        rows = _items(list_response.json())
        resolved = next((row for row in rows if row.get("name") == name), None)
        assert resolved is not None
        ai_system_id = resolved["id"]

    activate = approve_ai_system(client, headers, ai_system_id, status="active")
    assert activate.status_code == 200, activate.text

    if session_local is not None:
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
    target_module: str,
    version: str,
    control_id: str,
    assertion_operator: str,
    assertion_value,
) -> dict:
    return {
        "id": f"dsl-{uuid4()}",
        "tenant_id": tenant_id,
        "name": name,
        "category": category,
        "target_module": target_module,
        "version": version,
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
                    "signal_type": "simulation.phase_d.signal",
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
                    "field": "s1.iteration_index",
                    "operator": assertion_operator,
                    "value": assertion_value,
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


def _create_simulation_def(
    client: TestClient,
    *,
    headers: dict[str, str],
    tenant_id: str,
    name: str,
    control_id: str,
    assertion_operator: str,
    assertion_value,
) -> str:
    dsl = _simulation_dsl(
        tenant_id=tenant_id,
        name=name,
        category="injection",
        target_module="monitoring",
        version="1.0.0",
        control_id=control_id,
        assertion_operator=assertion_operator,
        assertion_value=assertion_value,
    )
    response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": name,
            "category": "injection",
            "target_module": "monitoring",
            "version": "1.0.0",
            "dsl_json": dsl,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    simulation_id = body.get("id")
    if simulation_id:
        return simulation_id

    list_response = client.get("/simulations/definitions", headers=headers)
    assert list_response.status_code == 200, list_response.text
    rows = _items(list_response.json())
    resolved = next((row for row in rows if row.get("name") == name and row.get("version") == "1.0.0"), None)
    assert resolved is not None
    return resolved["id"]


def _create_policy_pack_for_control(
    client: TestClient,
    *,
    headers: dict[str, str],
    control_id: str,
) -> str:
    pack = client.post(
        "/policies/packs",
        headers=headers,
        json={"name": f"Sim Hardening Pack {control_id}", "description": "simulation hardening", "status": "draft"},
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
        "guardian_id": f"sim_guard_{control_id.lower()}",
        "description": "Simulation hardening guard",
        "enabled": True,
        "trigger": {
            "signal_types": ["prompt.text"],
            "conditions": [
                {"field": "prompt.text", "operator": "contains", "value": "unsafe", "case_sensitive": False}
            ],
        },
        "evaluation": {"method": "rules", "confidence_threshold": 0.5},
        "decision": {"on_pass": "allow", "on_fail": "warn", "on_uncertain": "warn"},
        "actions": {
            "redact": {"fields": ["prompt"], "strategy": "mask"},
            "mutate_output": {"enabled": False, "strategy": "safe_completion"},
            "notify": {"channels": []},
            "create_ticket": {"system": "jira", "severity": "high"},
        },
        "evidence": {
            "evidence_signal_type": "guardian.simulation_hardening.detected",
            "link_to_controls": [control_id],
        },
        "control_impact": {
            "maturity_delta_on_fail": -0.2,
            "increase_simulation_frequency": True,
            "enforcement_strictness_increase": 2,
        },
    }
    version = client.post(
        f"/policies/packs/{pack_id}/versions",
        headers=headers,
        json={
            "version": "1.0.0",
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
    return pack_id


def _run_simulation(
    client: TestClient,
    *,
    headers: dict[str, str],
    simulation_id: str,
    ai_system_id: str,
    mode: str,
    stochastic_runs: int,
) -> dict:
    response = client.post(
        f"/simulations/definitions/{simulation_id}/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "mode": mode,
            "stochastic_runs": stochastic_runs,
            "inputs_used": {},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    if isinstance(body.get("results"), dict) and body["results"].get("failure_context"):
        return body
    run_id = str(body.get("id") or "").strip()
    if run_id:
        list_response = client.get("/simulations/runs?page=1&page_size=500", headers=headers)
        assert list_response.status_code == 200, list_response.text
        rows = _items(list_response.json())
        by_id = next((row for row in rows if str(row.get("id") or "").strip() == run_id), None)
        if by_id is not None:
            return by_id

    if body.get("id") and body.get("results"):
        return body

    list_response = client.get("/simulations/runs", headers=headers)
    assert list_response.status_code == 200, list_response.text
    rows = _items(list_response.json())
    matching = [row for row in rows if row.get("simulation_id") == simulation_id and row.get("ai_system_id") == ai_system_id]
    assert matching
    resolved = matching[0]
    assert resolved is not None
    return resolved


def _maturity_for_control(client: TestClient, *, headers: dict[str, str], control_id: str) -> dict:
    response = client.get("/trust-center/maturity", headers=headers)
    assert response.status_code == 200, response.text
    rows = _items(response.json())
    row = next((item for item in rows if item["control_id"] == control_id), None)
    assert row is not None
    return row


def _force_ai_system_governance_approved(session_local: sessionmaker, *, ai_system_id: str) -> None:
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


def test_failing_simulation_downgrades_maturity_deterministically(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]

    owner = _register_owner(client, email="phase-d-deterministic@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-PHASED-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)

    ai_system_id = _create_ai_system(client, headers=headers, name="Phase D System", session_local=session_local)

    pass_sim_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="Pass Simulation",
        control_id=control_id,
        assertion_operator="equals",
        assertion_value=1,
    )
    _run_simulation(
        client,
        headers=headers,
        simulation_id=pass_sim_id,
        ai_system_id=ai_system_id,
        mode="deterministic",
        stochastic_runs=1,
    )

    maturity_before = _maturity_for_control(client, headers=headers, control_id=control_id)

    fail_sim_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="Fail Simulation",
        control_id=control_id,
        assertion_operator="equals",
        assertion_value="never-matches",
    )
    failed_run = _run_simulation(
        client,
        headers=headers,
        simulation_id=fail_sim_id,
        ai_system_id=ai_system_id,
        mode="deterministic",
        stochastic_runs=1,
    )

    assert failed_run["results"]["result"] == "fail"

    maturity_after = _maturity_for_control(client, headers=headers, control_id=control_id)
    assert maturity_after["maturity_score"] < maturity_before["maturity_score"]


def test_stochastic_simulation_computation_correct(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]

    owner = _register_owner(client, email="phase-d-stochastic@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-STOCH-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)

    ai_system_id = _create_ai_system(client, headers=headers, name="Stochastic System", session_local=session_local)

    simulation_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="Stochastic Simulation",
        control_id=control_id,
        assertion_operator="in",
        assertion_value=[1, 3],
    )

    run = _run_simulation(
        client,
        headers=headers,
        simulation_id=simulation_id,
        ai_system_id=ai_system_id,
        mode="stochastic",
        stochastic_runs=4,
    )

    results = run["results"]
    assert results["iterations"] == 4
    assert results["passes"] == 2
    assert results["pass_rate"] == 0.5
    assert results["result"] == "fail"
    assert len(results["iteration_outputs"]) == 4


def test_control_auto_degrade(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]

    owner = _register_owner(client, email="phase-i1-auto-degrade@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-I1-DEGRADE-{uuid4().hex[:8]}"
    _create_control(
        client,
        headers=headers,
        control_id=control_id,
        success_criteria={
            "required_sim_pass_rate": 0.95,
            "required_evidence_sources": ["telemetry", "simulation", "config"],
            "min_maturity": 4,
        },
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="I1 Auto Degrade System", session_local=session_local)

    fail_sim_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="I1 Auto Degrade Simulation",
        control_id=control_id,
        assertion_operator="equals",
        assertion_value="never-matches",
    )
    run = _run_simulation(
        client,
        headers=headers,
        simulation_id=fail_sim_id,
        ai_system_id=ai_system_id,
        mode="deterministic",
        stochastic_runs=1,
    )
    assert run["results"]["result"] == "fail"
    assert run["results"]["pass_rate"] == 0.0

    maturity_after = _maturity_for_control(client, headers=headers, control_id=control_id)
    assert maturity_after["maturity_score"] == 0.0

    with session_local() as db:
        audit_row = db.scalar(
            select(AuditLog)
            .where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "control.degraded",
                AuditLog.resource_id == control_id,
            )
            .order_by(desc(AuditLog.created_at))
        )
        assert audit_row is not None
        assert audit_row.payload.get("simulation_id") == fail_sim_id
        assert audit_row.payload.get("computed_new_maturity") == 0
        evidence_row = db.scalar(
            select(EvidenceNode)
            .where(
                EvidenceNode.tenant_id == owner["tenant_id"],
                EvidenceNode.node_type == "control_degradation",
                EvidenceNode.signal_type == "control.degraded",
            )
            .order_by(desc(EvidenceNode.created_at))
        )
        assert evidence_row is not None
        assert evidence_row.payload.get("control_id") == control_id
        assert evidence_row.payload.get("simulation_id") == fail_sim_id
        assert evidence_row.payload.get("new_maturity") == 0
        # The evidence links to a degrade entry of this control and simulation. Audit entries carry the time to the
        # microsecond since the chain (migration 0097); evidence nodes created in the same second tie, so the newest of
        # each is not always the same pair.
        linked = db.get(AuditLog, evidence_row.payload.get("audit_log_id"))
        assert linked is not None and linked.action == "control.degraded" and linked.resource_id == control_id
        assert linked.payload.get("simulation_id") == fail_sim_id


def test_enforcement_strictness_escalates_on_degrade(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]

    owner = _register_owner(client, email="phase-i1-enforcement-escalate@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-I1-STRICT-{uuid4().hex[:8]}"
    _create_control(
        client,
        headers=headers,
        control_id=control_id,
        success_criteria={
            "required_sim_pass_rate": 0.9,
            "required_evidence_sources": ["simulation"],
            "min_maturity": 3,
        },
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="I1 Strictness System", session_local=session_local)

    guardian_id = f"guardian_i1_{uuid4().hex[:8]}"
    with session_local() as db:
        db.add(
            GuardianContract(
                id=guardian_id,
                name="I1 Guardian",
                trigger_conditions=[{"field": "prompt.text", "operator": "contains", "value": "x"}],
                block_conditions=[{"field": "prompt.text", "operator": "contains", "value": "x"}],
                mandatory_actions={},
                escalation_path={},
                evidence_requirements={},
                framework_mappings={},
            )
        )
        db.add(
            ControlGuardianBinding(
                control_id=control_id,
                guardian_contract_id=guardian_id,
                enforcement_strength="baseline",
            )
        )
        db.commit()

    fail_sim_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="I1 Strictness Escalation Simulation",
        control_id=control_id,
        assertion_operator="equals",
        assertion_value="never-matches",
    )
    _run_simulation(
        client,
        headers=headers,
        simulation_id=fail_sim_id,
        ai_system_id=ai_system_id,
        mode="deterministic",
        stochastic_runs=1,
    )

    with session_local() as db:
        binding = db.scalar(
            select(ControlGuardianBinding).where(
                ControlGuardianBinding.control_id == control_id,
                ControlGuardianBinding.guardian_contract_id == guardian_id,
            )
        )
        assert binding is not None
        assert binding.enforcement_strength in {"strict", "maximum"}


def test_enforcement_strictness_prefers_v2_bindings(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]

    owner = _register_owner(client, email="phase-i1-enforcement-v2@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-I1-V2-{uuid4().hex[:8]}"
    _create_control(
        client,
        headers=headers,
        control_id=control_id,
        success_criteria={
            "required_sim_pass_rate": 0.9,
            "required_evidence_sources": ["simulation"],
            "min_maturity": 3,
        },
    )
    ai_system_id = _create_ai_system(client, headers=headers, name="I1 V2 Strictness System", session_local=session_local)

    guardian_id = f"guardian_i1_v2_{uuid4().hex[:8]}"
    with session_local() as db:
        db.add(
            GuardianContract(
                id=guardian_id,
                name="I1 V2 Preference Guardian",
                trigger_conditions=[{"field": "prompt.text", "operator": "contains", "value": "x"}],
                block_conditions=[{"field": "prompt.text", "operator": "contains", "value": "x"}],
                mandatory_actions={},
                escalation_path={},
                evidence_requirements={},
                framework_mappings={},
            )
        )
        db.add(
            ControlGuardianBinding(
                control_id=control_id,
                guardian_contract_id=guardian_id,
                enforcement_strength="baseline",
            )
        )
        db.add(
            GuardianContractV2(
                tenant_id=owner["tenant_id"],
                id=guardian_id,
                version="2.0",
                name="I1 V2 Guardian Contract",
                trigger_conditions=[{"field": "prompt.text", "operator": "contains", "value": "x"}],
                block_conditions=[{"field": "prompt.text", "operator": "contains", "value": "x"}],
                mandatory_actions={},
                escalation_path={},
                evidence_requirements={},
                framework_mappings={},
            )
        )
        db.add(
            GuardianContractBindingV2(
                tenant_id=owner["tenant_id"],
                guardian_contract_id=guardian_id,
                ai_system_id=ai_system_id,
                policy_version_id=None,
                enforcement_strength="baseline",
                enabled=True,
            )
        )
        db.commit()

    fail_sim_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="I1 V2 Strictness Escalation Simulation",
        control_id=control_id,
        assertion_operator="equals",
        assertion_value="never-matches",
    )
    _run_simulation(
        client,
        headers=headers,
        simulation_id=fail_sim_id,
        ai_system_id=ai_system_id,
        mode="deterministic",
        stochastic_runs=1,
    )

    with session_local() as db:
        v2_binding = db.scalar(
            select(GuardianContractBindingV2).where(
                GuardianContractBindingV2.tenant_id == owner["tenant_id"],
                GuardianContractBindingV2.guardian_contract_id == guardian_id,
                GuardianContractBindingV2.ai_system_id == ai_system_id,
            )
        )
        assert v2_binding is not None
        assert v2_binding.enforcement_strength in {"strict", "maximum"}

        v1_binding = db.scalar(
            select(ControlGuardianBinding).where(
                ControlGuardianBinding.control_id == control_id,
                ControlGuardianBinding.guardian_contract_id == guardian_id,
            )
        )
        assert v1_binding is not None
        assert v1_binding.enforcement_strength == "baseline"


def test_repeated_critical_simulation_failures_require_approval_and_block_deployment(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local = test_env["SessionLocal"]

    owner = _register_owner(client, email="phase-i1-critical-repeat@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-I1-CRIT-{uuid4().hex[:8]}"
    _create_control(
        client,
        headers=headers,
        control_id=control_id,
        success_criteria={
            "required_sim_pass_rate": 0.95,
            "required_evidence_sources": ["simulation"],
            "min_maturity": 4,
        },
    )
    _create_policy_pack_for_control(client, headers=headers, control_id=control_id)
    ai_system_id = _create_ai_system(client, headers=headers, name="I1 Critical Repeat System", session_local=session_local)

    fail_sim_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="I1 Critical Repeat Simulation",
        control_id=control_id,
        assertion_operator="equals",
        assertion_value="never-matches",
    )

    last_run = {}
    for _ in range(3):
        _force_ai_system_governance_approved(session_local, ai_system_id=ai_system_id)
        last_run = _run_simulation(
            client,
            headers=headers,
            simulation_id=fail_sim_id,
            ai_system_id=ai_system_id,
            mode="deterministic",
            stochastic_runs=1,
        )
        assert last_run["results"]["result"] == "fail"

    failure_context = dict(last_run.get("results", {}).get("failure_context") or {})
    assert int(failure_context.get("repeated_failures") or 0) >= 3
    assert failure_context.get("critical_failure") is True
    assert int((failure_context.get("policy_feedback") or {}).get("escalation_level") or 0) >= 3
    assert bool((failure_context.get("deployment_block") or {}).get("blocked")) is True

    with session_local() as db:
        ai_system = db.get(AISystem, ai_system_id)
        assert ai_system is not None
        assert str(ai_system.status or "").lower() == "restricted"
        metadata = dict(ai_system.metadata_json or {})
        assert metadata.get("deployment_blocked") is True
        assert metadata.get("requires_reapproval") is True
        assert int(metadata.get("simulation_failure_repeat_count") or 0) >= 3

        remediation = db.scalar(
            select(RemediationAction)
            .where(
                RemediationAction.tenant_id == owner["tenant_id"],
                RemediationAction.source_trigger_type == "simulation_failure",
                RemediationAction.target_type == "ai_system",
                RemediationAction.target_id == ai_system_id,
                RemediationAction.remediation_type == "require_step_up",
            )
            .order_by(desc(RemediationAction.created_at))
        )
        assert remediation is not None
        assert remediation.requires_approval is True

        block_audit = db.scalar(
            select(AuditLog)
            .where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "simulation.deployment.blocked",
                AuditLog.resource_id == ai_system_id,
            )
            .order_by(desc(AuditLog.created_at))
        )
        assert block_audit is not None

        tightened_versions = db.scalars(
            select(PolicyVersion)
            .where(PolicyVersion.tenant_id == owner["tenant_id"])
            .order_by(desc(PolicyVersion.created_at))
        ).all()
        assert tightened_versions
        assert any(
            int(((row.contract_json or {}).get("tightening") or {}).get("escalation_level") or 0) >= 2
            for row in tightened_versions
        )


def test_invalid_dsl_rejected_on_create_and_update(test_env) -> None:
    client: TestClient = test_env["client"]

    owner = _register_owner(client, email="phase-d-validation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    control_id = f"CTRL-VALID-{uuid4().hex[:8]}"
    _create_control(client, headers=headers, control_id=control_id)

    invalid_create = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": "Invalid DSL",
            "category": "injection",
            "target_module": "monitoring",
            "version": "1.0.0",
            "dsl_json": {
                "id": f"dsl-{uuid4()}",
                "tenant_id": owner["tenant_id"],
                "name": "Invalid DSL",
                "category": "injection",
                "target_module": "monitoring",
                "version": "1.0.0",
                "safety": {
                    "requires_sandbox": True,
                    "max_runtime_seconds": 60,
                    "no_external_network": True,
                },
                "inputs_schema": {"fields": []},
                "steps": [],
                "assertions": [],
                "maps_to_controls": [],
                "expected_outcomes": {"pass_conditions": [], "fail_conditions": []},
            },
        },
    )
    assert invalid_create.status_code == 422

    sim_id = _create_simulation_def(
        client,
        headers=headers,
        tenant_id=owner["tenant_id"],
        name="Valid DSL",
        control_id=control_id,
        assertion_operator="equals",
        assertion_value=1,
    )

    invalid_update = client.patch(
        f"/simulations/definitions/{sim_id}",
        headers=headers,
        json={
            "dsl_json": {
                "id": f"dsl-{uuid4()}",
                "tenant_id": owner["tenant_id"],
                "name": "Valid DSL",
                "category": "injection",
                "target_module": "monitoring",
                "version": "1.0.0",
                "safety": {
                    "requires_sandbox": True,
                    "max_runtime_seconds": 60,
                    "no_external_network": False,
                },
                "inputs_schema": {"fields": []},
                "steps": [],
                "assertions": [],
                "maps_to_controls": [control_id],
                "expected_outcomes": {"pass_conditions": [], "fail_conditions": []},
            }
        },
    )
    assert invalid_update.status_code == 422
