from __future__ import annotations

import os
from uuid import uuid4

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
from app.services import control_plane_health_service


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    db_file = tmp_path / "control_plane_health_dependency.sqlite3"
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
    prior_strict_mode = settings.control_plane_strict_dependency_checks
    settings.control_plane_strict_dependency_checks = True
    try:
        yield {"client": client, "SessionLocal": testing_session_local}
    finally:
        settings.control_plane_strict_dependency_checks = prior_strict_mode
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Control Plane Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {"access_token": body["access_token"], "tenant_id": body["tenants"][0]["id"]}


def _headers(access_token: str, tenant_id: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def _create_ai_system(client: TestClient, headers: dict[str, str]) -> str:
    response = client.post(
        "/ai-systems",
        headers=headers,
        json={"name": "Fail Secure Route", "description": "", "risk_tier": "HIGH"},
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _patch_non_target_checks_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_migrations_applied",
        lambda db, strict_mode: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="migrations ok",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_artifact_storage",
        lambda: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="artifact ok",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_celery_heartbeat",
        lambda **kwargs: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="heartbeat ok",
        ),
    )


def test_db_down_blocks_gateway_route_with_fail_secure_audit_and_evidence(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_non_target_checks_ok(monkeypatch)
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_database_connectivity",
        lambda db: control_plane_health_service.ControlPlaneCheckResult(
            ok=False,
            status="unavailable",
            detail="database down",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_redis_connectivity",
        lambda strict_mode: (
            control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="redis ok"),
            None,
        ),
    )

    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="cp-db-down@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "ctx",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_fail_secure"
    assert "database" in detail["failed_checks"]

    with test_env["SessionLocal"]() as db:
        audit = db.scalar(
            select(AuditLog)
            .where(AuditLog.tenant_id == owner["tenant_id"], AuditLog.action == "governance.fail_secure.blocked")
            .order_by(AuditLog.created_at.desc())
        )
        assert audit is not None
        node = db.scalar(
            select(EvidenceNode)
            .where(EvidenceNode.tenant_id == owner["tenant_id"], EvidenceNode.node_type == "control_plane_fail_secure")
            .order_by(EvidenceNode.created_at.desc())
        )
        assert node is not None


def test_redis_down_blocks_gateway_route_with_fail_secure_audit_and_evidence(test_env, monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_non_target_checks_ok(monkeypatch)
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_database_connectivity",
        lambda db: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="database ok",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_redis_connectivity",
        lambda strict_mode: (
            control_plane_health_service.ControlPlaneCheckResult(
                ok=False,
                status="unavailable",
                detail="redis down",
            ),
            None,
        ),
    )

    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="cp-redis-down@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "ctx",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_fail_secure"
    assert "redis" in detail["failed_checks"]

    with test_env["SessionLocal"]() as db:
        audit = db.scalar(
            select(AuditLog)
            .where(AuditLog.tenant_id == owner["tenant_id"], AuditLog.action == "governance.fail_secure.blocked")
            .order_by(AuditLog.created_at.desc())
        )
        assert audit is not None
        node = db.scalar(
            select(EvidenceNode)
            .where(EvidenceNode.tenant_id == owner["tenant_id"], EvidenceNode.node_type == "control_plane_fail_secure")
            .order_by(EvidenceNode.created_at.desc())
        )
        assert node is not None


def test_worker_unavailable_blocks_gateway_route_with_fail_secure_audit_and_evidence(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_database_connectivity",
        lambda db: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="database ok",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_migrations_applied",
        lambda db, strict_mode: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="migrations ok",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_redis_connectivity",
        lambda strict_mode: (
            control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="redis ok"),
            None,
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_celery_heartbeat",
        lambda *, redis_client, key, actor, strict_mode: control_plane_health_service.ControlPlaneCheckResult(
            ok=False if actor == "celery_worker" else True,
            status="stale" if actor == "celery_worker" else "ok",
            detail="worker heartbeat missing" if actor == "celery_worker" else "heartbeat ok",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_artifact_storage",
        lambda: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="artifact storage ok",
        ),
    )

    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="cp-worker-down@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "ctx",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_fail_secure"
    assert "celery_worker" in detail["failed_checks"]

    with test_env["SessionLocal"]() as db:
        audit = db.scalar(
            select(AuditLog)
            .where(AuditLog.tenant_id == owner["tenant_id"], AuditLog.action == "governance.fail_secure.blocked")
            .order_by(AuditLog.created_at.desc())
        )
        assert audit is not None
        node = db.scalar(
            select(EvidenceNode)
            .where(EvidenceNode.tenant_id == owner["tenant_id"], EvidenceNode.node_type == "control_plane_fail_secure")
            .order_by(EvidenceNode.created_at.desc())
        )
        assert node is not None


def test_artifact_storage_unavailable_blocks_gateway_route_with_fail_secure_audit_and_evidence(
    test_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_non_target_checks_ok(monkeypatch)
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_database_connectivity",
        lambda db: control_plane_health_service.ControlPlaneCheckResult(
            ok=True,
            status="ok",
            detail="database ok",
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_redis_connectivity",
        lambda strict_mode: (
            control_plane_health_service.ControlPlaneCheckResult(ok=True, status="ok", detail="redis ok"),
            None,
        ),
    )
    monkeypatch.setattr(
        control_plane_health_service,
        "_check_artifact_storage",
        lambda: control_plane_health_service.ControlPlaneCheckResult(
            ok=False,
            status="unavailable",
            detail="artifact storage unavailable",
        ),
    )

    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="cp-artifact-down@example.com")
    headers = _headers(owner["access_token"], owner["tenant_id"])
    ai_system_id = _create_ai_system(client, headers)

    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "tester",
            "request_id": str(uuid4()),
            "prompt": "hello",
            "context_summary": "ctx",
            "attachments_meta": [],
        },
    )
    assert response.status_code == 503, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "governance_fail_secure"
    assert "artifact_storage" in detail["failed_checks"]

    with test_env["SessionLocal"]() as db:
        audit = db.scalar(
            select(AuditLog)
            .where(AuditLog.tenant_id == owner["tenant_id"], AuditLog.action == "governance.fail_secure.blocked")
            .order_by(AuditLog.created_at.desc())
        )
        assert audit is not None
        node = db.scalar(
            select(EvidenceNode)
            .where(EvidenceNode.tenant_id == owner["tenant_id"], EvidenceNode.node_type == "control_plane_fail_secure")
            .order_by(EvidenceNode.created_at.desc())
        )
        assert node is not None
