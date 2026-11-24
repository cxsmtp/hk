from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.session import Base, get_db
from app.main import app
from app.services.brain.providers.provider_factory import get_provider


PASSWORD = "Password123!"


class DummyProvider:
    name = "openai"
    model = "mock-model"

    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict) -> dict:
        return {"ok": True}

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        return "ok"

    def health(self) -> dict:
        return {"name": self.name, "ok": True, "model": self.model}


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "brain_phase0.sqlite3"
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
        json={
            "email": email,
            "password": PASSWORD,
            "full_name": "Brain Owner",
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str, correlation_id: str | None = None) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Tenant-ID": tenant_id,
    }
    if correlation_id:
        headers["X-Correlation-ID"] = correlation_id
    return headers


def test_provider_selection_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "openai")
    monkeypatch.setattr(settings, "openai_api_key", "test-key")
    monkeypatch.setattr(settings, "openai_model", "gpt-test")
    monkeypatch.setattr(settings, "openai_base_url", None)
    monkeypatch.setattr(settings, "llm_api_key", "")
    monkeypatch.setattr(settings, "llm_model", "")
    monkeypatch.setattr(settings, "llm_base_url", None)
    monkeypatch.setattr(settings, "llm_api_version", None)
    monkeypatch.setattr(settings, "llm_timeout_secs", 30)
    monkeypatch.setattr(settings, "llm_temperature", 0.0)
    monkeypatch.setattr(settings, "llm_max_tokens", 1200)

    provider = get_provider()
    assert provider.name == "openai"
    assert getattr(provider, "model", None) == "gpt-test"


def test_provider_selection_missing_api_key_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "llm_provider", "openai")
    monkeypatch.setattr(settings, "openai_api_key", "")
    monkeypatch.setattr(settings, "openai_model", "gpt-test")
    monkeypatch.setattr(settings, "llm_api_key", "")
    monkeypatch.setattr(settings, "llm_model", "gpt-test")

    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        get_provider()


def test_brain_health_returns_provider_model_and_writes_audit_evidence(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]
    user = _register_owner(client, email="brain-phase0-owner@example.com")

    monkeypatch.setattr(settings, "llm_router_mode", "council")
    monkeypatch.setattr(
        "app.api.routers.brain.get_provider_health_map",
        lambda: [
            {"name": "openai", "ok": True, "model": "gpt-mock"},
            {"name": "claude", "ok": True, "model": "claude-mock"},
            {"name": "gemini", "ok": False, "model": "", "error": "missing key"},
        ],
    )

    correlation_id = "brain-correlation-test-001"
    response = client.get(
        "/brain/health",
        headers=_headers(user["access_token"], user["tenant_id"], correlation_id=correlation_id),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["router_mode"] == "council"
    assert isinstance(payload["providers"], list)
    assert len(payload["providers"]) == 3
    assert response.headers.get("x-correlation-id") == correlation_id

    with session_local() as db:
        audit_row = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == user["tenant_id"],
                AuditLog.action == "brain.health",
                AuditLog.resource_id == "/brain/health",
            )
        )
        assert audit_row is not None
        assert audit_row.correlation_id == correlation_id

        evidence_row = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == user["tenant_id"],
                EvidenceNode.node_type == "brain_request",
                EvidenceNode.signal_type == "brain.health",
            )
        )
        assert evidence_row is not None
        assert evidence_row.correlation_id == correlation_id
        assert evidence_row.payload.get("source") == "brain"


def test_brain_providers_returns_active_config(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client: TestClient = test_env["client"]
    user = _register_owner(client, email="brain-phase0-providers@example.com")

    monkeypatch.setattr(settings, "llm_router_mode", "council")
    response = client.get(
        "/brain/providers",
        headers=_headers(user["access_token"], user["tenant_id"]),
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["available_providers"] == ["openai", "claude", "gemini"]
    assert payload["active_config"]["router_mode"] == "council"
    assert payload["active_config"]["planner_models"] == ["openai", "claude"]
