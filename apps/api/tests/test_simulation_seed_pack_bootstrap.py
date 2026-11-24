from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.session import Base, get_db
from app.main import app


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "simulation_seed_pack.sqlite3"
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
        yield {"client": client}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Simulation Admin"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    return {
        "access_token": payload["access_token"],
        "tenant_id": payload["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def test_bootstrap_initial_real_seed_pack_exposes_top50_seed_definitions(test_env) -> None:
    client: TestClient = test_env["client"]
    auth = _register_owner(client, email="sim-seed-pack@acme.ai")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    bootstrap = client.post(
        "/simulations/catalog/bootstrap-initial-real-seed-pack",
        headers=headers,
        json={"update_existing": False},
    )
    assert bootstrap.status_code == 200, bootstrap.text
    summary = bootstrap.json()
    assert summary["seed_pack"] == "top50_real_execution_seed_pack"
    assert int(summary["defined_total"]) == 50
    assert int(summary["created"]) >= 1

    defs_response = client.get("/simulations/definitions?page=1&page_size=300", headers=headers)
    assert defs_response.status_code == 200, defs_response.text
    rows = defs_response.json()["items"]
    assert len(rows) >= 50

    seed_rows = [row for row in rows if str((row.get("dsl_json") or {}).get("id", "")).startswith("SIM-")]
    assert len(seed_rows) >= 50

    sample = next((row for row in seed_rows if (row.get("dsl_json") or {}).get("id") == "SIM-PROMPT-001"), None)
    assert sample is not None
    dsl = sample["dsl_json"]
    assert dsl["target_surface"] == "browser"
    assert dsl["executable_status"] in {"executable_now", "partially_executable", "not_yet_executable"}
    expected_behavior = dsl.get("expected_control_behavior") or {}
    assert expected_behavior.get("expected_decision") in {"block", "deny"}
    assert len(expected_behavior.get("expected_controls") or []) >= 1
    assert len(dsl.get("framework_mappings") or []) >= 1
    assert len(dsl.get("attack_steps") or []) >= 1

    decomposition_seed = next((row for row in seed_rows if (row.get("dsl_json") or {}).get("id") == "SIM-PROMPT-004"), None)
    assert decomposition_seed is not None
    decomposition_dsl = decomposition_seed["dsl_json"]
    assert "decomposition" in str(decomposition_dsl.get("name") or "").lower()
    decomposition_controls = set(
        str(item).strip().upper()
        for item in ((decomposition_dsl.get("expected_control_behavior") or {}).get("expected_controls") or [])
        if str(item).strip()
    )
    assert "PROMPT_INJECTION_DETECTION" in decomposition_controls
    assert "CHAIN_OF_ACTION_VALIDATION" in decomposition_controls

    by_category: dict[str, int] = {}
    for row in seed_rows:
        category = str((row.get("dsl_json") or {}).get("category") or "")
        by_category[category] = by_category.get(category, 0) + 1

    assert by_category.get("injection", 0) >= 15
    assert by_category.get("leakage", 0) >= 10
    assert by_category.get("agent_misuse", 0) >= 8
    assert by_category.get("identity_abuse", 0) >= 7
    assert by_category.get("rag_poisoning", 0) >= 4
    assert by_category.get("infra_misconfig", 0) >= 3
    assert by_category.get("resource_abuse", 0) >= 2
    assert by_category.get("output_safety", 0) >= 1

    rag_rows = [row for row in seed_rows if (row.get("dsl_json") or {}).get("id", "").startswith("SIM-RAG-")]
    assert len(rag_rows) >= 4
    rag_statuses = {str((row.get("dsl_json") or {}).get("executable_status") or "") for row in rag_rows[:4]}
    assert "partially_executable" in rag_statuses
