"""What a caller says about itself never outranks what Hawk AI records (Checkmarx PR 12 triage):

- the browser extension's own role or department does not choose the scoped policy rule for a signed-in person
  (browser_extension_service -> policy_scope_service._resolve_actor_role took the hint over the person's role);
- remediation guidance for a finding, an AI system or a shadow AI entity is routed with at least the data
  sensitivity recorded for it (the request's default "internal" used to replace it).
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.api.routers import ai_orchestration as orchestration_router
from app.db.session import Base, get_db
from app.main import app
from app.services import browser_extension_service

PASSWORD = "Password123!"


@pytest.fixture()
def client(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'hints.sqlite3'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    try:
        yield test_client
    finally:
        test_client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_extension_role_and_department_do_not_choose_the_scoped_rule(client, monkeypatch) -> None:
    seen: list[dict] = []
    real = browser_extension_service.resolve_scoped_policy_decision

    def spy(db, *, tenant_id, policy_version_id, context, **kwargs):
        seen.append(dict(context))
        return real(db, tenant_id=tenant_id, policy_version_id=policy_version_id, context=context, **kwargs)

    monkeypatch.setattr(browser_extension_service, "resolve_scoped_policy_decision", spy)
    registered = client.post("/auth/register", json={"email": "hint-owner@example.com", "password": PASSWORD, "full_name": "Hint Owner"})
    assert registered.status_code == 200, registered.text
    body = registered.json()
    headers = {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["tenants"][0]["id"]}
    response = client.post(
        "/telemetry/browser/interaction-eval",
        headers=headers,
        json={
            "correlation_id": "hint-1",
            "domain": "chatgpt.com",
            "url": "https://chatgpt.com/",
            "application": "ChatGPT",
            "prompt_preview_redacted": "Summarise the quarterly plan.",
            "policy_version": "pv-hints",
            "platform_mode": "enforce",
            "browser": "chrome",
            "actor_role": "security-exempt",
            "actor_department": "Board",
            "department": "Board",
        },
    )
    assert response.status_code == 200, response.text
    assert seen, "the scoped policy was not consulted"
    assert all(ctx["actor_user_id"] == body["user"]["id"] for ctx in seen)
    assert all(ctx["actor_role"] is None and ctx["actor_department"] is None for ctx in seen)


@pytest.mark.parametrize(
    "asked, recorded, routed",
    [
        ("internal", "restricted", "restricted"),  # the request's default no longer hides the record
        ("public", "confidential", "sensitive"),
        ("restricted", "internal", "restricted"),  # asking for more care is kept
        ("internal", None, "internal"),
        ("", "", "internal"),
    ],
)
def test_guidance_is_routed_with_at_least_the_recorded_sensitivity(asked, recorded, routed) -> None:
    assert orchestration_router._recorded_floor(asked, recorded) == routed


def test_a_restricted_finding_is_not_routed_as_internal_by_default() -> None:
    row = SimpleNamespace(
        recommended_action="Rotate the key",
        finding_type="SECRET_TO_AI",
        ai_tool="ChatGPT",
        related_control_ids=[],
        finding_id="f-1",
        severity="high",
        data_classification="restricted",
        evidence_node_ids=[],
        status="open",
        ai_system_id=None,
        source_surface="browser",
        risk_category="data_leak",
    )
    task = orchestration_router._finding_task(row=row, overrides=orchestration_router.GuidanceOverrides())
    assert task.data_sensitivity == "restricted"
