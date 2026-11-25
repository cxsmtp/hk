from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.main import app
from app.core.config import settings
from app.services import control_plane_health_service
from app.services import fail_secure_service


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "fail_secure.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Fail Secure Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _create_ai_system(client: TestClient, headers: dict[str, str], *, risk_tier: str = "MEDIUM") -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": f"Fail Secure System {risk_tier}", "description": "", "risk_tier": risk_tier},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": "approved"})
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _create_agent(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/ai-iam/agents",
        headers=headers,
        json={"name": "Fail Secure Agent", "description": "agent"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _create_control_and_simulation(client: TestClient, headers: dict[str, str], tenant_id: str) -> str:
    control_response = client.post(
        "/simulations/controls",
        headers=headers,
        json={
            "id": "CTRL-FAIL-SECURE-001",
            "name": "Fail Secure Control",
            "category": "monitoring",
            "description": "control",
            "mapped_framework_refs": [{"framework": "INTERNAL", "control_ref": "FS-1"}],
            "is_global": False,
        },
    )
    assert control_response.status_code == 200, control_response.text

    simulation_response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={
            "name": "Fail Secure Simulation",
            "category": "injection",
            "target_module": "interaction_security",
            "version": "1.0.0",
            "dsl_json": {
                "id": "sim-fail-secure",
                "tenant_id": tenant_id,
                "name": "Fail Secure Simulation",
                "category": "injection",
                "target_module": "interaction_security",
                "version": "1.0.0",
                "safety": {"requires_sandbox": True, "max_runtime_seconds": 30, "no_external_network": True},
                "inputs_schema": {"fields": []},
                "steps": [
                    {
                        "step_id": "s1",
                        "kind": "monitoring_signal",
                        "payload_template": {"signal_type": "simulation.signal", "severity": "low"},
                        "variable_bindings": {},
                    }
                ],
                "assertions": [
                    {
                        "assertion_id": "a1",
                        "check": {"field": "s1.signal_id", "operator": "contains", "value": "-"},
                        "on_fail": {"result": "fail", "evidence_signal_type": "simulation.fail", "severity": "low"},
                    }
                ],
                "maps_to_controls": ["CTRL-FAIL-SECURE-001"],
                "expected_outcomes": {"pass_conditions": ["signal exists"], "fail_conditions": ["signal missing"]},
            },
        },
    )
    assert simulation_response.status_code == 200, simulation_response.text
    return simulation_response.json()["id"]


def test_fail_secure_blocks_gateway_ai_iam_and_suspends_simulations(monkeypatch, test_env) -> None:
    monkeypatch.setattr(settings, "fail_secure_mode", True)
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="fail-secure-block@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    ai_system_id = _create_ai_system(client, headers)
    agent_id = _create_agent(client, headers)
    simulation_id = _create_control_and_simulation(client, headers, owner["tenant_id"])

    queue_calls: list[tuple[str, str]] = []

    def _db_down(_db):
        raise SQLAlchemyError("db_down")

    def _queue_stub(*, tenant_id: str, ai_system_id: str | None, module: str, reason: str, request_id: str | None):
        queue_calls.append((module, reason))
        return {"queued": True, "error": None}

    monkeypatch.setattr(fail_secure_service, "check_db_connectivity", _db_down)
    monkeypatch.setattr(fail_secure_service, "queue_auditor_fail_secure_job", _queue_stub)

    gateway_response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "user-1",
            "request_id": str(uuid4()),
            "prompt": "test",
            "context_summary": "",
            "attachments_meta": [],
        },
    )
    assert gateway_response.status_code == 503, gateway_response.text
    gateway_detail = gateway_response.json()["detail"]
    assert gateway_detail["code"] == "fail_secure_block"
    assert gateway_detail["module"] == "gateway"
    assert gateway_detail["reason"] == "db_unavailable"

    mint_response = client.post(
        f"/ai-iam/agents/{agent_id}/tokens",
        headers=headers,
        json={"ai_system_id": ai_system_id, "scopes": ["tool.read"], "expires_minutes": 60, "chain_depth": 1},
    )
    assert mint_response.status_code == 503, mint_response.text
    mint_detail = mint_response.json()["detail"]
    assert mint_detail["code"] == "fail_secure_block"
    assert mint_detail["module"] == "ai_iam"
    assert mint_detail["reason"] == "db_unavailable"

    simulation_response = client.post(
        f"/simulations/definitions/{simulation_id}/run",
        headers=headers,
        json={"ai_system_id": ai_system_id, "mode": "deterministic", "inputs_used": {}},
    )
    assert simulation_response.status_code == 503, simulation_response.text
    simulation_detail = simulation_response.json()["detail"]
    assert simulation_detail["code"] == "fail_secure_block"
    assert simulation_detail["module"] == "simulations"
    assert simulation_detail["reason"] == "db_unavailable"

    assert len(queue_calls) == 3
    assert {module for module, _ in queue_calls} == {"gateway", "ai_iam", "simulations"}


def test_control_plane_health_reports_fail_secure_when_db_down(monkeypatch, test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="fail-secure-health@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    monkeypatch.setattr(
        control_plane_health_service,
        "_check_database_connectivity",
        lambda _db: control_plane_health_service.ControlPlaneCheckResult(
            ok=False,
            status="unavailable",
            detail="db_down",
        ),
    )

    response = client.get("/system/control-plane-health", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["governance_status"] == "unavailable"
    assert body["enforcement_status"] == "blocked_fail_secure"
    assert body["iam_status"] == "blocked_fail_secure"
    assert body["auditor_status"] == "queued_fail_secure"


def test_governance_context_failure_blocks_request(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="fail-secure-governance@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers, risk_tier="PROHIBITED")

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "user-gov",
            "request_id": str(uuid4()),
            "prompt": "test",
            "context_summary": "",
            "attachments_meta": [],
        },
    )
    # The explicit PROHIBITED risk tier is rejected by the fail-secure
    # preflight before the later lifecycle guard is reached.
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "fail_secure_block"
    assert detail["reason"] == "governance_context_failed:risk_tier_prohibited"


def test_new_system_risk_escalation_enters_review_and_denies_simulation(test_env):
    from sqlalchemy import func, select
    from app.db.models.ai_system import AISystem
    from app.db.models.simulation import SimulationRun
    from app.services.governance_resolution import resolve_ai_system_status

    client = test_env["client"]
    owner = _register_owner(client, email="risk-escalation-fixture@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    created = client.post("/ai-systems", headers=headers, json={"name": "Unapproved risk fixture", "risk_tier": "LOW"})
    assert created.status_code == 200, created.text
    system_id = created.json()["id"]
    escalated = client.patch(f"/ai-systems/{system_id}", headers=headers, json={"risk_tier": "HIGH"})
    assert escalated.status_code == 200, escalated.text
    simulation_id = _create_control_and_simulation(client, headers, owner["tenant_id"])
    with test_env["SessionLocal"]() as db:
        system = db.get(AISystem, system_id)
        assert system.metadata_json["governance_state"] == "REVIEW"
        assert system.metadata_json["requires_reapproval"] is True
        assert resolve_ai_system_status(system_id, {"db": db, "tenant_id": owner["tenant_id"]})["status"] == "PROPOSED"
    denied = client.post(f"/simulations/definitions/{simulation_id}/run", headers=headers,
                         json={"ai_system_id": system_id, "mode": "deterministic", "stochastic_runs": 1, "inputs_used": {}})
    assert denied.status_code == 403, denied.text
    assert denied.json()["detail"]["reason_code"] == "governance_state_not_approved"
    with test_env["SessionLocal"]() as db:
        assert db.scalar(select(func.count()).select_from(SimulationRun).where(SimulationRun.ai_system_id == system_id)) == 0


@pytest.mark.parametrize("risk_tier", ["HIGH", "CRITICAL", "RESTRICTED", "PROHIBITED"])
def test_risk_escalation_persists_bounded_distinct_remediation_ids(test_env, risk_tier):
    from sqlalchemy import select
    from app.db.models.ai_system import AISystem
    from app.db.models.remediation import RemediationAction

    client = test_env["client"]
    owner = _register_owner(client, email="bounded-risk-escalation@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    identifiers = []
    for index in range(2):
        created = client.post("/ai-systems", headers=headers,
                              json={"name": f"Bounded escalation {index}", "risk_tier": "LOW"})
        assert created.status_code == 200, created.text
        system_id = created.json()["id"]
        response = client.patch(f"/ai-systems/{system_id}", headers=headers,
                                json={"risk_tier": risk_tier})
        assert response.status_code == 200, response.text
        with test_env["SessionLocal"]() as db:
            remediation = db.scalars(select(RemediationAction).where(
                RemediationAction.tenant_id == owner["tenant_id"],
                RemediationAction.target_id == system_id,
                RemediationAction.source_trigger_type == "runtime_pattern",
            )).one()
            assert len(remediation.source_trigger_id) <= RemediationAction.__table__.c.source_trigger_id.type.length
            prefix, full_system_id, full_tier = remediation.source_trigger_id.split(":")
            assert prefix == "risk_escalation"
            assert full_system_id == system_id
            assert full_tier == risk_tier
            assert db.get(AISystem, system_id).metadata_json["governance_state"] == "REVIEW"
            identifiers.append(remediation.source_trigger_id)
    assert len(set(identifiers)) == 2


# --- Missing or unknown AI-system context fails closed -------------------------------------------------------------


def _intercept_body(ai_system_id: str) -> dict:
    return {
        "ai_system_id": ai_system_id,
        "actor_type": "human",
        "actor_id": "user-ctx",
        "request_id": str(uuid4()),
        "prompt": "test",
        "context_summary": "",
        "attachments_meta": [],
    }


def test_validate_governance_context_denies_missing_context_by_default(test_env) -> None:
    with test_env["SessionLocal"]() as db:
        assert fail_secure_service.validate_governance_context(db, tenant_id="t-1", ai_system_id=None) == (
            False,
            "no_ai_system_context",
        )
        assert fail_secure_service.validate_governance_context(db, tenant_id="t-1", ai_system_id="") == (
            False,
            "no_ai_system_context",
        )
        assert fail_secure_service.validate_governance_context(db, tenant_id="t-1", ai_system_id="missing-system") == (
            False,
            "ai_system_not_found",
        )


def test_validate_governance_context_explicit_reason_is_the_only_allow(test_env) -> None:
    with test_env["SessionLocal"]() as db:
        assert fail_secure_service.validate_governance_context(
            db, tenant_id="t-1", ai_system_id=None, no_ai_system_context_reason="tenant_registry"
        ) == (True, "not_ai_system_scoped:tenant_registry")
        assert fail_secure_service.validate_governance_context(
            db, tenant_id="t-1", ai_system_id=None, no_ai_system_context_reason="containment"
        ) == (True, "not_ai_system_scoped:containment")
        # An undocumented reason is not an allow.
        assert fail_secure_service.validate_governance_context(
            db, tenant_id="t-1", ai_system_id=None, no_ai_system_context_reason="because"
        ) == (False, "invalid_no_ai_system_context_reason")
        # A reason never excuses an AI system that is given but unknown.
        assert fail_secure_service.validate_governance_context(
            db, tenant_id="t-1", ai_system_id="missing-system", no_ai_system_context_reason="tenant_registry"
        ) == (False, "ai_system_not_found")


def test_enforce_fail_secure_denies_missing_context(monkeypatch, test_env) -> None:
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "fail_secure_mode", True)
    monkeypatch.setattr(
        fail_secure_service,
        "queue_auditor_fail_secure_job",
        lambda **_kwargs: {"queued": False, "error": None},
    )
    with test_env["SessionLocal"]() as db:
        with pytest.raises(HTTPException) as raised:
            fail_secure_service.enforce_fail_secure_or_raise(db, tenant_id="t-1", module="gateway", request_id="r-1")
        assert raised.value.status_code == 503
        assert raised.value.detail["code"] == "fail_secure_block"
        assert raised.value.detail["reason"] == "governance_context_failed:no_ai_system_context"
        # Stated at the call site: allowed.
        fail_secure_service.enforce_fail_secure_or_raise(
            db, tenant_id="t-1", module="ai_iam", request_id="r-2", no_ai_system_context_reason="tenant_registry"
        )


def test_enforce_fail_secure_denies_unknown_ai_system(monkeypatch, test_env) -> None:
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "fail_secure_mode", True)
    monkeypatch.setattr(
        fail_secure_service,
        "queue_auditor_fail_secure_job",
        lambda **_kwargs: {"queued": False, "error": None},
    )
    with test_env["SessionLocal"]() as db:
        with pytest.raises(HTTPException) as raised:
            fail_secure_service.enforce_fail_secure_or_raise(
                db, tenant_id="t-1", module="gateway", ai_system_id="missing-system", request_id="r-1"
            )
        assert raised.value.status_code == 503
        assert raised.value.detail["reason"] == "governance_context_failed:ai_system_not_found"
        # Asked for as a governance block, it is still a denial, never an allow.
        with pytest.raises(fail_secure_service.UnregisteredAISystemBlock):
            fail_secure_service.enforce_fail_secure_or_raise(
                db,
                tenant_id="t-1",
                module="gateway",
                ai_system_id="missing-system",
                request_id="r-2",
                unknown_ai_system_is_governance_block=True,
            )
        # Only the unknown AI system becomes a governance block: missing context stays a 503.
        with pytest.raises(HTTPException) as raised:
            fail_secure_service.enforce_fail_secure_or_raise(
                db, tenant_id="t-1", module="gateway", request_id="r-3", unknown_ai_system_is_governance_block=True
            )
        assert raised.value.status_code == 503
        assert raised.value.detail["reason"] == "governance_context_failed:no_ai_system_context"


def test_gateway_unknown_ai_system_is_a_governance_block(monkeypatch, test_env) -> None:
    monkeypatch.setattr(settings, "fail_secure_mode", True)
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="fail-secure-unknown@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post("/gateway/llm/intercept", headers=headers, json=_intercept_body("no-such-ai-system"))
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_context_blocked"
    assert detail["reason_code"] == "ai_system_not_registered"


def test_gateway_unknown_ai_system_denied_even_if_guard_does_not_block(monkeypatch, test_env) -> None:
    from app.services import governance_guard

    monkeypatch.setattr(settings, "fail_secure_mode", True)
    monkeypatch.setattr(governance_guard, "enforce", lambda *args, **kwargs: None)
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="fail-secure-unknown-noguard@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post("/gateway/llm/intercept", headers=headers, json=_intercept_body("no-such-ai-system"))
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == "ai_system_not_registered"


def test_gateway_missing_ai_system_context_stays_fail_secure(monkeypatch, test_env) -> None:
    monkeypatch.setattr(settings, "fail_secure_mode", True)
    monkeypatch.setattr(
        fail_secure_service,
        "queue_auditor_fail_secure_job",
        lambda **_kwargs: {"queued": False, "error": None},
    )
    with test_env["SessionLocal"]() as db:
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as raised:
            fail_secure_service.enforce_gateway_fail_secure_or_raise(
                db,
                tenant_id="t-1",
                ai_system_id=None,
                request_id="r-1",
                governance_route="/gateway/llm/intercept",
                governance_action="gateway.llm.intercept",
            )
        assert raised.value.status_code == 503
        assert raised.value.detail["code"] == "fail_secure_block"
        assert raised.value.detail["reason"] == "governance_context_failed:no_ai_system_context"


def test_gateway_another_tenants_ai_system_is_blocked(monkeypatch, test_env) -> None:
    monkeypatch.setattr(settings, "fail_secure_mode", True)
    client: TestClient = test_env["client"]
    other = _register_owner(client, email="fail-secure-other@example.com")
    other_system = _create_ai_system(client, _headers(other["access_token"], other["tenant_id"]))
    owner = _register_owner(client, email="fail-secure-mine@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    response = client.post("/gateway/llm/intercept", headers=headers, json=_intercept_body(other_system))
    assert response.status_code == 403, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_context_blocked"
    assert detail["reason_code"] == "ai_system_not_registered"


def test_ai_iam_registry_and_containment_routes_state_their_missing_context(monkeypatch, test_env) -> None:
    monkeypatch.setattr(settings, "fail_secure_mode", True)
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="fail-secure-registry@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])

    agent_id = _create_agent(client, headers)
    listed = client.get("/ai-iam/agents", headers=headers)
    assert listed.status_code == 200, listed.text
    fetched = client.get(f"/agents/{agent_id}", headers=headers)
    assert fetched.status_code == 200, fetched.text
    kill = client.post(f"/ai-iam/agents/{agent_id}/kill-switch", headers=headers)
    assert kill.status_code == 200, kill.text
