from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.simulation import SimulationCatalogEntry
from app.db.session import Base, get_db
from app.main import app
from app.services.simulation_catalog_service import CATEGORY_TARGET_COUNTS
from app.services.simulation_catalog_source import load_simulation_catalog_entries
from app.services.simulation_executor_registry import list_executors


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "simulation_catalog_generation.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Simulation Catalog Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def test_catalog_files_cover_required_taxonomy_and_mapping() -> None:
    entries = load_simulation_catalog_entries()
    assert len(entries) >= 240

    by_category: dict[str, int] = {}
    for entry in entries:
        category = str(entry.get("category") or "").strip().lower()
        by_category[category] = by_category.get(category, 0) + 1

        assert str(entry.get("simulation_id") or "").strip()
        assert str(entry.get("required_executor") or "").strip()
        assert str(entry.get("executable_status") or "").strip() in {
            "executable_now",
            "partially_executable",
            "not_yet_executable",
            "expected_gap",
            "requires_environment",
        }
        assert isinstance(entry.get("control_ids"), list) and len(entry.get("control_ids") or []) > 0
        assert isinstance(entry.get("framework_mappings"), list) and len(entry.get("framework_mappings") or []) > 0

    for category, required in CATEGORY_TARGET_COUNTS.items():
        assert int(by_category.get(category, 0)) >= int(required), f"category={category}"

    decomposition_entry = next(
        (
            entry
            for entry in entries
            if str(entry.get("simulation_id") or "").strip().upper() == "SIM-PROMPT-024"
        ),
        None,
    )
    assert decomposition_entry is not None
    assert str(decomposition_entry.get("subcategory") or "").strip().lower() == "prompt_decomposition"
    expected_controls = set(decomposition_entry.get("control_ids") or [])
    assert "PROMPT_INJECTION_DETECTION" in expected_controls
    assert "CHAIN_OF_ACTION_VALIDATION" in expected_controls

    ocr_cases = {
        "SIM-DATA-041": ("ocr_image_data_exfiltration", "high"),
        "SIM-DATA-042": ("ocr_document_upload_to_ai", "high"),
        "SIM-DATA-043": ("repeated_sensitive_uploads", "critical"),
    }
    by_id = {str(entry.get("simulation_id") or "").strip().upper(): entry for entry in entries}
    for simulation_id, (subcategory, severity) in ocr_cases.items():
        entry = by_id.get(simulation_id)
        assert entry is not None
        assert str(entry.get("subcategory") or "").strip().lower() == subcategory
        assert str(entry.get("severity") or "").strip().lower() == severity
        assert str((entry.get("attack_vector") or {}).get("type") or "").strip().lower() == "file_upload"
        output_contract = entry.get("simulation_output_contract") or {}
        assert str(output_contract.get("result") or "").strip()
        assert str(output_contract.get("control_effectiveness") or "").strip()
        assert str(output_contract.get("severity") or "").strip().lower() == severity
        controls = set(entry.get("control_ids") or [])
        assert "FILE_UPLOAD_INSPECTION" in controls
        assert "OCR_DATA_EXTRACTION_CONTROL" in controls
        assert "DATA_EXFILTRATION_PREVENTION" in controls


def test_catalog_sync_persists_entries_and_honors_executor_support(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    auth = _register_owner(client, email="sim-catalog-sync@example.com")
    headers = _headers(auth["access_token"], auth["tenant_id"])

    sync_response = client.post("/simulation-policies/catalog/sync", headers=headers)
    assert sync_response.status_code == 200, sync_response.text
    summary = sync_response.json()
    assert int(summary["total_required"]) == 240
    assert int(summary["total_defined"]) >= 240
    assert isinstance(summary.get("coverage_by_framework"), dict)
    assert isinstance(summary.get("coverage_by_control"), dict)
    assert summary["coverage_by_framework"]
    assert summary["coverage_by_control"]

    with session_local() as db:
        rows = db.scalars(
            select(SimulationCatalogEntry).where(SimulationCatalogEntry.tenant_id == auth["tenant_id"])
        ).all()
        assert len(rows) >= 240

        executors = {
            str(row.name or "").strip().lower(): row
            for row in list_executors(db, tenant_id=auth["tenant_id"])
        }
        assert executors

        # Never overclaim executable_now without an active, surface-compatible executor.
        for row in rows:
            if str(row.executable_status or "").strip().lower() != "executable_now":
                continue

            required_executor = str(row.required_executor or "").strip().lower()
            executor = executors.get(required_executor)
            assert executor is not None, f"missing executor for {row.simulation_id}"
            assert str(executor.status or "").strip().lower() == "active", f"inactive executor for {row.simulation_id}"

            supported_surfaces = {str(item).strip().lower() for item in (executor.supported_surfaces or []) if str(item).strip()}
            if supported_surfaces:
                assert str(row.target_surface or "").strip().lower() in supported_surfaces, f"surface mismatch for {row.simulation_id}"
