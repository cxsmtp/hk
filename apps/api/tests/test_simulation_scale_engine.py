from __future__ import annotations

import os
from collections import defaultdict

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.session import Base, get_db
from app.main import app
from app.db.models.ai_system import AISystem
from app.services.simulation_contract_service import validate_and_normalize_simulation_dsl
from ai_system_approval_helpers import approve_ai_system


PASSWORD = "Password123!"
REQUIRED_RFP_CATEGORIES = {
    "injection",
    "leakage",
    "agent_misuse",
    "identity_abuse",
    "rag_poisoning",
    "output_safety",
    "resource_abuse",
}


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "simulation_scale_engine.sqlite3"
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


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Simulation Scale Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _create_control(client: TestClient, *, headers: dict[str, str], control_id: str, framework: str, category: str) -> None:
    response = client.post(
        "/simulations/controls",
        headers=headers,
        json={
            "id": control_id,
            "name": f"Control {control_id}",
            "category": category,
            "description": f"Control {control_id}",
            "mapped_framework_refs": [{"framework": framework, "control_ref": f"{control_id}-REF"}],
            "is_global": False,
        },
    )
    assert response.status_code == 200, response.text


def _create_required_controls(client: TestClient, *, headers: dict[str, str]) -> None:
    _create_control(client, headers=headers, control_id="CTRL-INPUT-001", framework="NIST AI RMF", category="interaction_security")
    _create_control(client, headers=headers, control_id="CTRL-INPUT-002", framework="OWASP LLM", category="interaction_security")
    _create_control(client, headers=headers, control_id="CTRL-DLP-001", framework="ISO/IEC 42001", category="leakage")
    _create_control(client, headers=headers, control_id="CTRL-TOOL-001", framework="Google SAIF", category="agent_misuse")
    _create_control(client, headers=headers, control_id="CTRL-AI-IAM-001", framework="SOC 2", category="ai_iam")
    _create_control(client, headers=headers, control_id="CTRL-RAG-001", framework="MITRE ATLAS", category="rag_poisoning")
    _create_control(client, headers=headers, control_id="CTRL-TENANT-ISO-001", framework="NIST AI RMF", category="identity_abuse")


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
        json={"name": name, "description": "simulation scale", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
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


def test_rfp_catalog_bootstrap_generates_required_categories_and_valid_dsl(test_env) -> None:
    client: TestClient = test_env["client"]
    auth = _register_owner(client, email="sim-scale-bootstrap@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])
    _create_required_controls(client, headers=headers)

    bootstrap = client.post(
        "/simulations/catalog/bootstrap-rfp",
        headers=headers,
        json={"per_category_target": 4},
    )
    assert bootstrap.status_code == 200, bootstrap.text
    bootstrap_payload = bootstrap.json()
    assert int((bootstrap_payload.get("bootstrap") or {}).get("generated_total") or 0) >= 20

    coverage_categories = {row["category"] for row in bootstrap_payload["category_coverage"]}
    assert REQUIRED_RFP_CATEGORIES.issubset(coverage_categories)

    defs_response = client.get("/simulations/definitions?page=1&page_size=500", headers=headers)
    assert defs_response.status_code == 200, defs_response.text
    definitions = defs_response.json()["items"]
    assert len(definitions) >= 28

    counts = defaultdict(int)
    for row in definitions:
        dsl = row["dsl_json"]
        validate_and_normalize_simulation_dsl(
            dsl_json=dsl,
            tenant_id=auth["tenant_id"],
            simulation_id=dsl.get("id"),
            name=row["name"],
            category=row["category"],
            target_module=row["target_module"],
            version=row["version"],
        )
        category = str(row["category"])
        counts[category] += 1
        if category in REQUIRED_RFP_CATEGORIES:
            pack = dsl.get("pack") or {}
            assert isinstance(pack, dict)
            assert str(pack.get("id") or "").strip()
            assert isinstance(dsl.get("framework_domains"), list)
            assert len(dsl.get("maps_to_controls") or []) >= 1

    for category in REQUIRED_RFP_CATEGORIES:
        assert counts[category] >= 4


def test_pack_execution_and_reporting_with_deterministic_maturity_deltas(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    auth = _register_owner(client, email="sim-scale-pack-run@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])
    _create_required_controls(client, headers=headers)

    bootstrap = client.post(
        "/simulations/catalog/bootstrap-rfp",
        headers=headers,
        json={"per_category_target": 3},
    )
    assert bootstrap.status_code == 200, bootstrap.text

    packs_response = client.get("/simulations/packs?page=1&page_size=100", headers=headers)
    assert packs_response.status_code == 200, packs_response.text
    packs = {row["pack_id"]: row for row in packs_response.json()["items"]}
    assert "prompt_attack_pack" in packs
    assert int(packs["prompt_attack_pack"]["simulation_count"]) >= 1

    ai_system_a = _create_ai_system(client, headers=headers, name="Sim Scale AI A", session_local=session_local)
    ai_system_b = _create_ai_system(client, headers=headers, name="Sim Scale AI B", session_local=session_local)

    run_a = client.post(
        "/simulations/packs/prompt_attack_pack/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_a,
            "mode": "deterministic",
            "stochastic_runs": 1,
            "inputs_used": {"prompt": "ignore prior instructions", "rag_context": "untrusted context"},
            "max_definitions": 1,
        },
    )
    assert run_a.status_code == 200, run_a.text
    run_a_payload = run_a.json()
    assert run_a_payload["total_runs"] == 1
    assert len(run_a_payload["run_ids"]) == 1

    run_b = client.post(
        "/simulations/packs/prompt_attack_pack/run",
        headers=headers,
        json={
            "ai_system_id": ai_system_b,
            "mode": "deterministic",
            "stochastic_runs": 1,
            "inputs_used": {"prompt": "ignore prior instructions", "rag_context": "untrusted context"},
            "max_definitions": 1,
        },
    )
    assert run_b.status_code == 200, run_b.text
    run_b_payload = run_b.json()
    assert run_b_payload["total_runs"] == 1
    assert len(run_b_payload["run_ids"]) == 1

    runs_response = client.get("/simulations/runs?page=1&page_size=300", headers=headers)
    assert runs_response.status_code == 200, runs_response.text
    runs = {row["id"]: row for row in runs_response.json()["items"]}
    run_a_row = runs[run_a_payload["run_ids"][0]]
    run_b_row = runs[run_b_payload["run_ids"][0]]
    assert run_a_row["results"]["result"] == run_b_row["results"]["result"]
    assert run_a_row["results"]["control_maturity_delta"] == run_b_row["results"]["control_maturity_delta"]

    summary_response = client.get("/simulations/coverage/summary", headers=headers)
    assert summary_response.status_code == 200, summary_response.text
    summary = summary_response.json()
    assert int(summary["totals"]["simulation_definitions"]) >= 21
    assert int(summary["totals"]["simulation_runs"]) >= 2
    assert int(summary["trigger_sources"]["governance_changes"]) >= 0
    assert any(row["pack_id"] == "prompt_attack_pack" for row in summary["pack_coverage"])

    heatmap_response = client.get("/simulations/coverage/heatmap", headers=headers)
    assert heatmap_response.status_code == 200, heatmap_response.text
    heatmap = heatmap_response.json()
    assert "categories" in heatmap
    assert "rows" in heatmap
    assert len(heatmap["categories"]) >= 1

    trends_response = client.get("/simulations/coverage/trends?lookback_days=14", headers=headers)
    assert trends_response.status_code == 200, trends_response.text
    trends = trends_response.json()
    assert int(trends["lookback_days"]) == 14
    assert any(int(row.get("total_runs") or 0) >= 1 for row in trends["series"])
