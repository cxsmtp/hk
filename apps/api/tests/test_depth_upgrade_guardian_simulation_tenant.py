from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.policy import GuardianContractV2
from app.db.models.ai_system import AISystem
from app.db.models.simulation import (
    Control,
    SimulationDefinition,
    SimulationExecutionStep,
    SimulationPolicy,
    SimulationRun,
)
from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"
FRAMEWORK_MAPPINGS = {
    "nist_ai_rmf": ["GV.RM"],
    "iso_42001": ["A.5"],
    "eu_ai_act": ["risk_management"],
    "owasp_genai": ["LLM01"],
    "mitre_atlas": ["AML.TA0001"],
    "control_ids": ["CTRL-TENANT-001"],
}


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "guardian_simulation_tenant.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Tenant Scope Owner"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
    }


def _headers(auth: dict[str, str]) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {auth['access_token']}",
        "X-Tenant-ID": auth["tenant_id"],
    }


def _contract_payload(*, contract_id: str, name: str) -> dict:
    return {
        "id": contract_id,
        "version": "2.0",
        "name": name,
        "trigger_conditions": [],
        "block_conditions": [],
        "mandatory_actions": {},
        "escalation_path": {},
        "evidence_requirements": {"link_to_controls": ["CTRL-TENANT-001"]},
        "framework_mappings": FRAMEWORK_MAPPINGS,
    }


def _create_approved_ai_system(
    client: TestClient,
    *,
    auth: dict[str, str],
    session_local: sessionmaker,
    name: str,
) -> str:
    response = client.post(
        "/ai-systems",
        headers=_headers(auth),
        json={"name": name, "description": "tenant isolation", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    with session_local() as db:
        row = db.get(AISystem, ai_system_id)
        assert row is not None
        row.status = "active"
        row.metadata_json = {
            **dict(row.metadata_json or {}),
            "governance_state": "APPROVED",
            "lifecycle_state": "ACTIVE",
            "ownership_state": "ASSIGNED",
            "owner_user_id": "owner:test",
            "business_owner_user_id": "owner:test",
            "technical_owner_user_id": "security:test",
            "compliance_state": "COMPLIANT",
        }
        db.commit()
    return ai_system_id


def test_guardian_contract_crud_and_bindings_are_tenant_scoped(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant_a = _register_owner(client, email="guardian-tenant-a@example.com")
    tenant_b = _register_owner(client, email="guardian-tenant-b@example.com")
    headers_a = _headers(tenant_a)
    headers_b = _headers(tenant_b)

    contract_id = "shared-business-id"
    created_a = client.post(
        "/guardian-contracts/v2",
        headers=headers_a,
        json=_contract_payload(contract_id=contract_id, name="Tenant A Contract"),
    )
    assert created_a.status_code == 200, created_a.text

    list_b = client.get("/guardian-contracts/v2", headers=headers_b)
    assert list_b.status_code == 200, list_b.text
    assert contract_id not in {row["id"] for row in list_b.json()["items"]}
    assert client.get(f"/guardian-contracts/v2/{contract_id}", headers=headers_b).status_code == 404
    assert (
        client.patch(
            f"/guardian-contracts/v2/{contract_id}",
            headers=headers_b,
            json={"name": "Cross-tenant overwrite"},
        ).status_code
        == 404
    )
    assert client.delete(f"/guardian-contracts/v2/{contract_id}", headers=headers_b).status_code == 404

    created_b = client.post(
        "/guardian-contracts/v2",
        headers=headers_b,
        json=_contract_payload(contract_id=contract_id, name="Tenant B Contract"),
    )
    assert created_b.status_code == 200, created_b.text
    assert client.get(f"/guardian-contracts/v2/{contract_id}", headers=headers_a).json()["name"] == "Tenant A Contract"
    assert client.get(f"/guardian-contracts/v2/{contract_id}", headers=headers_b).json()["name"] == "Tenant B Contract"

    bind_b = client.post(
        "/guardian-contracts/v2/bindings",
        headers=headers_b,
        json={
            "guardian_contract_id": contract_id,
            "enforcement_strength": "strict",
            "enabled": True,
        },
    )
    assert bind_b.status_code == 200, bind_b.text
    bindings_a = client.get("/guardian-contracts/v2/bindings", headers=headers_a)
    assert bindings_a.status_code == 200, bindings_a.text
    assert contract_id not in {row["guardian_contract_id"] for row in bindings_a.json()["items"]}
    matrix_a = client.get("/guardian-contracts/v2/matrix", headers=headers_a)
    matrix_b = client.get("/guardian-contracts/v2/matrix", headers=headers_b)
    assert matrix_a.status_code == matrix_b.status_code == 200
    assert next(row for row in matrix_a.json()["items"] if row["guardian_contract_id"] == contract_id)["bindings"] == []
    assert next(row for row in matrix_b.json()["items"] if row["guardian_contract_id"] == contract_id)["bindings"]

    with session_local() as db:
        rows = db.scalars(select(GuardianContractV2).where(GuardianContractV2.id == contract_id)).all()
        assert {(row.tenant_id, row.name) for row in rows} == {
            (tenant_a["tenant_id"], "Tenant A Contract"),
            (tenant_b["tenant_id"], "Tenant B Contract"),
        }


def test_guardian_binding_rejects_foreign_contract_even_when_business_id_exists(test_env) -> None:
    client: TestClient = test_env["client"]
    tenant_a = _register_owner(client, email="guardian-bind-a@example.com")
    tenant_b = _register_owner(client, email="guardian-bind-b@example.com")
    contract_id = "tenant-a-only-contract"
    created = client.post(
        "/guardian-contracts/v2",
        headers=_headers(tenant_a),
        json=_contract_payload(contract_id=contract_id, name="Tenant A Only"),
    )
    assert created.status_code == 200, created.text

    response = client.post(
        "/guardian-contracts/v2/bindings",
        headers=_headers(tenant_b),
        json={"guardian_contract_id": contract_id, "enabled": True},
    )
    assert response.status_code == 404, response.text


def test_default_guardians_and_controls_persist_for_a_second_session(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant = _register_owner(client, email="default-persistence@example.com")
    headers = _headers(tenant)

    guardians = client.get("/guardian-contracts/v2", headers=headers)
    controls = client.get("/simulations/controls?page_size=100", headers=headers)
    assert guardians.status_code == 200, guardians.text
    assert controls.status_code == 200, controls.text

    with session_local() as second_session:
        guardian_rows = second_session.scalars(
            select(GuardianContractV2).where(GuardianContractV2.tenant_id == tenant["tenant_id"])
        ).all()
        control_rows = second_session.scalars(
            select(Control).where(Control.tenant_id == tenant["tenant_id"])
        ).all()
    assert len(guardian_rows) == 3
    assert len(control_rows) == 24


def test_concurrent_default_seed_requests_are_idempotent(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant = _register_owner(client, email="default-race@example.com")
    headers = _headers(tenant)

    def _seed_once() -> tuple[int, int]:
        guardians = client.get("/guardian-contracts/v2", headers=headers)
        controls = client.get("/simulations/controls?page_size=100", headers=headers)
        return guardians.status_code, controls.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: _seed_once(), range(2)))
    assert results == [(200, 200), (200, 200)]

    with session_local() as db:
        guardian_count = len(
            db.scalars(
                select(GuardianContractV2).where(GuardianContractV2.tenant_id == tenant["tenant_id"])
            ).all()
        )
        control_count = len(
            db.scalars(select(Control).where(Control.tenant_id == tenant["tenant_id"])).all()
        )
    assert guardian_count == 3
    assert control_count == 24


@pytest.mark.parametrize(
    "path",
    [
        "/controls/explorer?foundation_only=false",
        "/controls/runtime-view",
        "/controls/simulation-view",
        "/controls/PROMPT_INJECTION_DETECTION/coverage",
        "/frameworks/NIST%20AI%20RMF/coverage",
    ],
)
def test_coverage_control_views_durably_seed_on_first_touch(test_env, path: str) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant = _register_owner(
        client,
        email="coverage-first-touch@example.com",
    )

    response = client.get(path, headers=_headers(tenant))
    assert response.status_code == 200, response.text
    if path.startswith("/controls/PROMPT_INJECTION_DETECTION"):
        assert response.json()["control_id"] == "PROMPT_INJECTION_DETECTION"
    if path.startswith("/frameworks/"):
        assert response.json()["total_controls"] > 0
    with session_local() as second_session:
        count = len(
            second_session.scalars(
                select(Control).where(Control.tenant_id == tenant["tenant_id"])
            ).all()
        )
    assert count == 24


def test_simulation_policy_foreign_ids_are_not_read_updated_or_activated(test_env) -> None:
    client: TestClient = test_env["client"]
    tenant_a = _register_owner(client, email="simulation-policy-a@example.com")
    tenant_b = _register_owner(client, email="simulation-policy-b@example.com")
    headers_a = _headers(tenant_a)
    headers_b = _headers(tenant_b)

    created = client.post(
        "/simulation-policies",
        headers=headers_a,
        json={"name": "Tenant A Policy", "active": True},
    )
    assert created.status_code == 200, created.text
    policy_id = created.json()["id"]

    list_b = client.get("/simulation-policies", headers=headers_b)
    assert list_b.status_code == 200, list_b.text
    assert policy_id not in {row["id"] for row in list_b.json()["items"]}
    assert client.get(f"/simulation-policies/{policy_id}", headers=headers_b).status_code == 404
    assert (
        client.patch(
            f"/simulation-policies/{policy_id}",
            headers=headers_b,
            json={"name": "Cross-tenant overwrite"},
        ).status_code
        == 404
    )
    assert client.post(f"/simulation-policies/{policy_id}/activate", headers=headers_b).status_code == 404
    assert client.get(f"/simulation-policies/{policy_id}", headers=headers_a).json()["name"] == "Tenant A Policy"


def test_tenant_admin_cannot_create_or_observe_global_simulation_control(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant_a = _register_owner(client, email="simulation-control-a@example.com")
    tenant_b = _register_owner(client, email="simulation-control-b@example.com")
    control_id = "CTRL-PRIVATE-TENANT-A"
    response = client.post(
        "/simulations/controls",
        headers=_headers(tenant_a),
        json={
            "id": control_id,
            "name": "Tenant A Private Control",
            "category": "monitoring",
            "description": "must not become global",
            "is_global": True,
        },
    )
    assert response.status_code == 422, response.text

    created = client.post(
        "/simulations/controls",
        headers=_headers(tenant_a),
        json={
            "id": control_id,
            "name": "Tenant A Private Control",
            "category": "monitoring",
            "description": "tenant scoped",
        },
    )
    assert created.status_code == 200, created.text
    listing_b = client.get("/simulations/controls", headers=_headers(tenant_b))
    assert listing_b.status_code == 200, listing_b.text
    assert control_id not in {row["id"] for row in listing_b.json()["items"]}

    with session_local() as db:
        row = db.get(Control, (control_id, tenant_a["tenant_id"]))
        assert row is not None
        assert row.tenant_id == tenant_a["tenant_id"]
        assert row.is_global is False


def test_simulation_policy_tenant_id_can_only_come_from_authenticated_context(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant_a = _register_owner(client, email="simulation-policy-forged-a@example.com")
    tenant_b = _register_owner(client, email="simulation-policy-forged-b@example.com")
    response = client.post(
        "/simulation-policies",
        headers=_headers(tenant_a),
        json={"name": "Forged Tenant Policy", "tenant_id": tenant_b["tenant_id"]},
    )
    assert response.status_code == 422, response.text
    with session_local() as db:
        assert db.scalars(select(SimulationPolicy).where(SimulationPolicy.name == "Forged Tenant Policy")).all() == []


def test_simulation_policy_ensure_default_uses_authenticated_tenant(test_env) -> None:
    client: TestClient = test_env["client"]
    tenant = _register_owner(client, email="simulation-ensure-default@example.com")
    response = client.post("/simulation-policies/ensure-default", headers=_headers(tenant))
    assert response.status_code == 200, response.text
    assert response.json()["tenant_id"] == tenant["tenant_id"]


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/simulations/templates",
            {
                "name": "Forged template",
                "category": "validation",
                "target_module": "monitoring",
                "template_body": {},
            },
        ),
        ("/simulations/templates/missing-template/generate", {"count": 1}),
        ("/simulations/packs/top20/run", {"ai_system_id": "missing-ai"}),
        ("/simulations/catalog/bootstrap-rfp", {"per_category_target": 1}),
        ("/simulations/catalog/bootstrap-initial-real-seed-pack", {"update_existing": False}),
        ("/simulations/agentic-chain-integrity/run", {"run_all": True}),
    ],
)
def test_all_simulation_mutation_payloads_reject_forged_tenant_id(
    test_env,
    path: str,
    payload: dict,
) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant_a = _register_owner(client, email=f"mutation-a-{path.replace('/', '-')[:40]}@example.com")
    tenant_b = _register_owner(client, email=f"mutation-b-{path.replace('/', '-')[:40]}@example.com")
    if path == "/simulations/packs/top20/run":
        payload = {
            **payload,
            "ai_system_id": _create_approved_ai_system(
                client,
                auth=tenant_a,
                session_local=session_local,
                name="Forged Pack Payload AI",
            ),
        }
    response = client.post(
        path,
        headers=_headers(tenant_a),
        json={**payload, "tenant_id": tenant_b["tenant_id"]},
    )
    assert response.status_code == 422, response.text


def test_simulation_definition_execute_results_trace_and_evidence_refs_reject_foreign_ids(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    tenant_a = _register_owner(client, email="simulation-runtime-a@example.com")
    tenant_b = _register_owner(client, email="simulation-runtime-b@example.com")
    ai_a = _create_approved_ai_system(
        client,
        auth=tenant_a,
        session_local=session_local,
        name="Tenant A Simulation AI",
    )
    ai_b = _create_approved_ai_system(
        client,
        auth=tenant_b,
        session_local=session_local,
        name="Tenant B Simulation AI",
    )

    with session_local() as db:
        definition = SimulationDefinition(
            tenant_id=tenant_a["tenant_id"],
            name="Tenant A Private Simulation",
            category="validation",
            target_module="monitoring",
            version="1.0",
            dsl_json={"id": "tenant-a-private-simulation", "maps_to_controls": []},
        )
        db.add(definition)
        db.flush()
        run = SimulationRun(
            tenant_id=tenant_a["tenant_id"],
            simulation_id=definition.id,
            ai_system_id=ai_a,
            mode="deterministic",
            inputs_used={},
            results={"result": "pass", "evidence_refs": ["tenant-a-evidence"]},
            controls_impacted=[],
            notes="",
        )
        db.add(run)
        db.flush()
        db.add(
            SimulationExecutionStep(
                tenant_id=tenant_a["tenant_id"],
                simulation_run_id=run.id,
                iteration_index=1,
                step_id="tenant-a-step",
                step_order=1,
                step_type="assertion",
                title="Tenant A evidence step",
                status="passed",
                actor="evaluator",
                target_surface="monitoring",
                input_payload_ref={},
                output_payload_ref={},
                control_refs=[],
                decision_ref={},
                evidence_refs=["tenant-a-evidence"],
                notes="",
            )
        )
        db.commit()
        definition_id = definition.id
        run_id = run.id

    headers_b = _headers(tenant_b)
    definitions_b = client.get("/simulations/definitions", headers=headers_b)
    assert definitions_b.status_code == 200, definitions_b.text
    assert definition_id not in {row["id"] for row in definitions_b.json()["items"]}
    assert (
        client.patch(
            f"/simulations/definitions/{definition_id}",
            headers=headers_b,
            json={"name": "Cross-tenant overwrite"},
        ).status_code
        == 404
    )
    execute = client.post(
        f"/simulations/definitions/{definition_id}/run",
        headers=headers_b,
        json={"ai_system_id": ai_b, "mode": "deterministic", "stochastic_runs": 1},
    )
    assert execute.status_code == 404, execute.text
    runs_b = client.get("/simulations/runs", headers=headers_b)
    assert runs_b.status_code == 200, runs_b.text
    assert run_id not in {row["id"] for row in runs_b.json()["items"]}
    trace_b = client.get(f"/simulations/runs/{run_id}/trace", headers=headers_b)
    assert trace_b.status_code == 404, trace_b.text

    forged_create = client.post(
        "/simulations/definitions",
        headers=headers_b,
        json={
            "name": "Forged Definition",
            "category": "validation",
            "target_module": "monitoring",
            "version": "1.0",
            "dsl_json": {},
            "tenant_id": tenant_a["tenant_id"],
        },
    )
    assert forged_create.status_code == 422, forged_create.text
