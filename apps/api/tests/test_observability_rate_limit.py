from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core.config import settings
from app.db.models.audit import AuditLog
from app.db.models.enforcement import EnforcementEvent
from app.db.models.evidence import EvidenceNode
from app.db.session import Base, get_db
from app.main import app
from app.services.rate_limit_service import tenant_rate_limiter
from ai_system_approval_helpers import approve_ai_system


def test_structured_error_level_is_observable_and_unknown_level_falls_back(monkeypatch):
    from app.core import observability

    calls = []

    class RecordingLogger:
        def debug(self, payload): calls.append(("debug", json.loads(payload)))
        def info(self, payload): calls.append(("info", json.loads(payload)))
        def warning(self, payload): calls.append(("warning", json.loads(payload)))
        def error(self, payload): calls.append(("error", json.loads(payload)))
        def critical(self, payload): calls.append(("critical", json.loads(payload)))

    monkeypatch.setattr(observability, "request_logger", RecordingLogger())
    observability.log_structured("native_control_callback_unhandled_error", level="error", error_type="RuntimeError")
    observability.log_structured("unknown_level", level="arbitrary_method")
    observability.log_structured("nonstring_level", level=["error"])
    assert [level for level, _ in calls] == ["error", "info", "info"]
    assert calls[0][1]["event"] == "native_control_callback_unhandled_error"
    assert calls[0][1]["error_type"] == "RuntimeError"


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "observability.sqlite3"
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
    tenant_rate_limiter.reset()
    client = TestClient(app)
    try:
        yield {"client": client, "SessionLocal": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        tenant_rate_limiter.reset()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Observability Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
    }


def _headers(access_token: str, tenant_id: str, correlation_id: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}
    if correlation_id:
        headers["X-Correlation-ID"] = correlation_id
    return headers


def _create_ai_system(client: TestClient, *, headers: dict[str, str], name: str) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": name, "description": "", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approved = approve_ai_system(client, headers, ai_system_id)
    assert approved.status_code == 200, approved.text
    return ai_system_id


def _intercept(client: TestClient, *, headers: dict[str, str], ai_system_id: str, request_id: str):
    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "user-1",
            "request_id": request_id,
            "prompt": "normal prompt",
            "context_summary": "",
            "attachments_meta": [],
        },
    )
    return response


def test_correlation_id_header_and_persistence(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    user = _register_owner(client, email="corr-owner@example.com")
    correlation_id = "corr-test-id-001"
    headers = _headers(user["access_token"], user["tenant_id"], correlation_id=correlation_id)

    ai_system_id = _create_ai_system(client, headers=headers, name="Correlation System")
    request_id = str(uuid4())
    response = _intercept(client, headers=headers, ai_system_id=ai_system_id, request_id=request_id)

    assert response.status_code == 200, response.text
    assert response.headers.get("x-correlation-id") == correlation_id
    body = response.json()
    event_id = body["event_id"]

    with session_local() as db:
        audit_row = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == user["tenant_id"],
                AuditLog.action == "gateway.llm.intercept",
                AuditLog.resource_id == ai_system_id,
            )
        )
        assert audit_row is not None
        assert audit_row.correlation_id == correlation_id

        evidence_row = db.scalar(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == user["tenant_id"],
                EvidenceNode.signal_type == "gateway.llm.intercept",
            )
        )
        assert evidence_row is not None
        assert evidence_row.correlation_id == correlation_id

        event_row = db.scalar(
            select(EnforcementEvent).where(
                EnforcementEvent.id == event_id,
                EnforcementEvent.tenant_id == user["tenant_id"],
            )
        )
        assert event_row is not None
        assert event_row.correlation_id == correlation_id


def test_tenant_rate_limit_enforced(test_env) -> None:
    client: TestClient = test_env["client"]
    session_local: sessionmaker = test_env["SessionLocal"]

    original_qps = settings.llm_intercept_qps_per_tenant
    original_window = settings.rate_limit_window_seconds
    settings.llm_intercept_qps_per_tenant = 1
    settings.rate_limit_window_seconds = 60.0
    tenant_rate_limiter.reset()

    try:
        user = _register_owner(client, email="ratelimit-owner@example.com")
        headers = _headers(user["access_token"], user["tenant_id"], correlation_id="corr-rate-limit")
        ai_system_id = _create_ai_system(client, headers=headers, name="Rate Limit System")

        first = _intercept(client, headers=headers, ai_system_id=ai_system_id, request_id=str(uuid4()))
        assert first.status_code == 200, first.text

        second = _intercept(client, headers=headers, ai_system_id=ai_system_id, request_id=str(uuid4()))
        assert second.status_code == 429, second.text
        detail = second.json()["detail"]
        assert detail["code"] == "rate_limited"
        assert detail["final_decision"] == "block"
        assert detail["retry_after_seconds"] > 0
        assert second.headers.get("Retry-After") is not None

        with session_local() as db:
            rate_limit_audit = db.scalar(
                select(AuditLog).where(
                    AuditLog.tenant_id == user["tenant_id"],
                    AuditLog.action == "gateway.llm.intercept.rate_limited",
                )
            )
            assert rate_limit_audit is not None
            assert rate_limit_audit.correlation_id == "corr-rate-limit"
    finally:
        settings.llm_intercept_qps_per_tenant = original_qps
        settings.rate_limit_window_seconds = original_window
        tenant_rate_limiter.reset()
