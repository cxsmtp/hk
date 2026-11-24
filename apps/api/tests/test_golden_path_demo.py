from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"

from app.db.session import Base, get_db
from app import main as main_module
from app.main import app


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from infra.scripts.golden_path_demo import run_golden_path_demo


@pytest.fixture()
def test_env(tmp_path, monkeypatch):
    db_file = tmp_path / "golden_path_demo.sqlite3"
    artifact_dir = tmp_path / "artifacts"
    monkeypatch.setenv("ARTIFACT_DIR", str(artifact_dir))

    engine = create_engine(
        f"sqlite+pysqlite:///{db_file}",
        connect_args={"check_same_thread": False},
    )
    testing_session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main_module, "SessionLocal", testing_session_local)

    def override_get_db():
        db = testing_session_local()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "artifact_dir": artifact_dir}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_golden_path_demo_spine_is_deterministic(test_env) -> None:
    client: TestClient = test_env["client"]
    artifact_dir: Path = test_env["artifact_dir"]

    result = run_golden_path_demo(session=client)

    assert result["status"] == "ok"
    assert result["govern"]["ai_system_id"]
    assert result["govern"]["audit_log_id"]
    assert result["govern"]["evidence_node_id"]

    assert result["enforce"]["final_decision"] == "block"
    assert result["enforce"]["event_id"]
    assert result["enforce"]["audit_log_id"]
    assert result["enforce"]["evidence_nodes_created"]

    assert result["validate"]["simulation_result"] == "pass"
    assert result["validate"]["simulation_pass_rate"] == 1.0
    assert result["validate"]["simulation_run_id"]
    assert result["validate"]["audit_log_id"]
    assert result["validate"]["evidence_node_id"]

    assert result["prove"]["snapshot_id"]
    assert result["prove"]["export_snapshot_id"]
    assert result["prove"]["download_verified"] is True
    assert result["prove"]["json_artifact"]
    assert result["prove"]["csv_artifact"]
    assert result["prove"]["artifact_hash"]
    assert result["prove"]["audit_log_id"]
    assert result["prove"]["evidence_node_id"]

    assert (artifact_dir / Path(result["prove"]["json_artifact"])).is_file()
    assert (artifact_dir / Path(result["prove"]["csv_artifact"])).is_file()
    assert artifact_dir.exists()
