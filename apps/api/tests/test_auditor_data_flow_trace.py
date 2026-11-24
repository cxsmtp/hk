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
    db_file = tmp_path / "auditor_data_flow_trace.sqlite3"
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
        json={"email": email, "password": PASSWORD, "full_name": "Auditor Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def test_auditor_data_flow_trace_contains_cross_module_chain(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="auditor-trace@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    correlation_id = "corr-auditor-data-flow-trace"

    response = client.post(
        "/runtime-control/data-transfer-check",
        headers=headers,
        json={
            "correlation_id": correlation_id,
            "copy_context": {
                "source_url": "https://internal.acme.ai/docs",
                "source_domain": "internal.acme.ai",
                "source_app_name": "Internal Docs",
                "source_surface_type": "internal_app",
                "source_classification_hint": "protected",
                "copied_text_hash": "hash-123",
                "copied_text_preview_redacted": "customer email [redacted]",
                "timestamp": "2026-03-23T10:00:00Z",
            },
            "paste_context": {
                "destination_url": "https://chatgpt.com",
                "destination_domain": "chatgpt.com",
                "destination_app_name": "ChatGPT",
                "destination_surface_type": "ai_tool",
                "destination_input_context": "chat_box",
                "timestamp": "2026-03-23T10:00:05Z",
            },
            "policy_version": "pv-auditor-trace",
            "platform_mode": "enforce",
        },
    )
    assert response.status_code == 200, response.text

    trace = client.get(f"/auditor/data-flow-trace/{correlation_id}", headers=headers)
    assert trace.status_code == 200, trace.text
    body = trace.json()

    assert body["correlation_id"] == correlation_id
    assert body["summary"]["counts"]["audits"] >= 1
    assert body["summary"]["counts"]["monitoring_signals"] >= 1
    assert body["summary"]["counts"]["runtime_events"] >= 1
    assert body["summary"]["counts"]["evidence_nodes"] >= 1
    assert len(body["source_destination"]) >= 1
