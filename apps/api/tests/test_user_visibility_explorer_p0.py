from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.db.models.activity_audit import AIAction, AISession, PromptPayload, UserRegistry
from app.db.models.account_boundary import AIAccountIdentity, AIAccountSession
from app.db.models.audit import AuditLog
from app.db.models.policy_pack_platform import (
    PolicyPackAssignment,
    PolicyPackDefinition,
    PolicyPackGroupMembership,
    PolicyPackInstance,
    PolicyPackUserGroup,
)
from app.db.models.user import UserTenantRole
from app.db.models.provider_signal import ProviderSignalRecord
from app.db.session import Base, get_db
from app.main import app
from app.services.activity_audit_service import record_activity_event


PASSWORD = "Password123!"


@pytest.fixture()
def test_env(tmp_path):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'user_visibility.sqlite3'}",
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
        yield {"client": client, "sessionmaker": testing_session_local}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _register_owner(client: TestClient, *, email: str) -> dict[str, str]:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": PASSWORD, "full_name": "Visibility Owner"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(owner: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {owner['access_token']}", "X-Tenant-ID": owner["tenant_id"]}


def _grant_visibility(client: TestClient, owner: dict[str, str], *, user_id: str, capabilities: list[str], department_scope: list[str] | None = None):
    return client.post(
        "/user-visibility/access-grants",
        headers=_headers(owner),
        json={
            "user_id": user_id,
            "capabilities": capabilities,
            "department_scope": department_scope or [],
            "reason": "focused user visibility test",
        },
    )


def _seed_action(
    session_factory,
    *,
    tenant_id: str,
    user_id: str,
    action_id: str,
    raw_prompt: str | None,
    redacted_prompt: str,
    storage_mode: str = "full",
    department: str = "Risk",
    enforcement_action: str = "allowed",
    metadata: dict | None = None,
    ai_app: str = "ChatGPT",
) -> None:
    with session_factory() as db:
        db.add(
            UserRegistry(
                tenant_id=tenant_id,
                user_id=user_id,
                display_name="Visibility Owner",
                email="user-visibility-owner@example.com",
                department=department,
                role="owner",
            )
        )
        session_id = f"session-{action_id}"
        db.add(
            AISession(
                session_id=session_id,
                tenant_id=tenant_id,
                user_id=user_id,
                source_surface="browser",
                ai_app=ai_app,
                ai_model="gpt-5",
                metadata_json={"provider": "openai"},
            )
        )
        db.add(
            AIAction(
                action_id=action_id,
                tenant_id=tenant_id,
                session_id=session_id,
                user_id=user_id,
                action_type="prompt_submit",
                ai_app=ai_app,
                ai_model="gpt-5",
                data_classification="confidential",
                enforcement_action=enforcement_action,
                metadata_json=metadata or {"provider": "openai"},
            )
        )
        db.add(
            PromptPayload(
                action_id=action_id,
                raw_prompt=raw_prompt,
                redacted_prompt=redacted_prompt,
                storage_mode=storage_mode,
                sensitive_entities=["confidential"],
                prompt_hash="a" * 64,
            )
        )
        db.commit()


def _seed_account_context(
    session_factory,
    *,
    tenant_id: str,
    user_id: str,
    suffix: str = "primary",
    account_class: str = "ENTERPRISE_MANAGED_USER",
    verification_status: str = "VERIFIED",
    session_state: str = "ENTERPRISE_VERIFIED",
    expires_at: datetime | None = None,
    drift_state: str = "NONE",
) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    with session_factory() as db:
        identity = AIAccountIdentity(
            tenant_id=tenant_id,
            provider="openai",
            provider_subject_ref=f"subject-{user_id}-{suffix}",
            account_class=account_class,
            organisation_ids=["org-company"],
            workspace_ids=["workspace-company"],
            tenant_ids=["provider-tenant-company"],
            subscription_class="enterprise",
            enterprise_membership=True,
            licence_state="licensed",
            verification_method="server_owned_adapter",
            verification_status=verification_status,
            verified_at=now,
            evidence_refs=["account-boundary:integration-1"],
        )
        db.add(identity)
        db.flush()
        session = AIAccountSession(
            account_session_id=f"account-session-{user_id}-{suffix}",
            tenant_id=tenant_id,
            provider="openai",
            product="chatgpt",
            surface="browser",
            user_identity_ref=user_id,
            account_identity_ref=identity.id,
            device_id=f"device-{user_id}-{suffix}",
            organisation_id="org-company",
            workspace_id="workspace-company",
            tenant_id_external="provider-tenant-company",
            subscription_class="enterprise",
            assurance_level="AB4",
            verification_method="server_owned_adapter",
            issued_at=now,
            last_verified_at=now,
            expires_at=expires_at or now + timedelta(hours=1),
            session_state=session_state,
            drift_state=drift_state,
            evidence_refs=["account-boundary:integration-1"],
        )
        db.add(session)
        db.commit()
        return identity.id, session.account_session_id


def test_admin_must_explicitly_create_visibility_capability_before_users_workspace_is_accessible(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-owner@example.com")
    headers = _headers(owner)

    denied = client.get("/user-visibility/users", headers=headers)
    assert denied.status_code == 403

    created = client.post(
        "/user-visibility/access-grants",
        headers=headers,
        json={
            "user_id": owner["user_id"],
            "capabilities": ["view_aggregates", "view_user_metadata", "view_action_details"],
            "department_scope": [],
            "reason": "initial security visibility",
        },
    )
    assert created.status_code == 201, created.text
    assert set(created.json()["capabilities"]) == {"view_aggregates", "view_user_metadata", "view_action_details"}

    directory = client.get("/user-visibility/users", headers=headers)
    assert directory.status_code == 200, directory.text
    assert directory.json()["total"] == 1


def test_owner_safe_visibility_recovery_grant_is_tenant_user_bound_and_excludes_privileged_capabilities(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-safe-recovery-owner@example.com")
    other_owner = _register_owner(client, email="user-visibility-safe-recovery-other@example.com")
    capabilities = ["view_aggregates", "view_user_metadata", "view_action_details"]

    created = _grant_visibility(
        client,
        owner,
        user_id=owner["user_id"],
        capabilities=capabilities,
    )

    assert created.status_code == 201, created.text
    body = created.json()
    assert body["user_id"] == owner["user_id"]
    assert set(body["capabilities"]) == set(capabilities)
    assert not {"view_evidence", "reveal_prompt_content", "manage_privacy"} & set(body["capabilities"])
    cross_tenant = _grant_visibility(
        client,
        owner,
        user_id=other_owner["user_id"],
        capabilities=capabilities,
    )
    assert cross_tenant.status_code == 404, cross_tenant.text
    with test_env["sessionmaker"]() as db:
        audit = db.scalar(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.action == "user_visibility.access_grant.created",
                AuditLog.resource_id == body["grant_id"],
            )
        )
        assert audit is not None
        assert audit.actor_user_id == owner["user_id"]
        assert audit.payload["subject_user_id"] == owner["user_id"]
        assert set(audit.payload["capabilities"]) == set(capabilities)


def test_directory_summary_is_safe_and_directory_sort_is_allow_listed(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-directory-summary@example.com")
    grant = _grant_visibility(
        client,
        owner,
        user_id=owner["user_id"],
        capabilities=["view_aggregates", "view_user_metadata"],
    )
    assert grant.status_code == 201, grant.text

    summary = client.get("/user-visibility/users/summary", headers=_headers(owner))
    assert summary.status_code == 200, summary.text
    payload = summary.json()
    assert payload["known_user_count"] == 1
    assert "risk_score" not in payload
    assert "raw_prompt" not in str(payload)

    invalid_sort = client.get(
        "/user-visibility/users",
        headers=_headers(owner),
        params={"sort_by": "metadata_json", "sort_direction": "asc"},
    )
    assert invalid_sort.status_code == 422, invalid_sort.text


def test_user_experience_sections_are_lazy_bounded_and_prompt_safe(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-sections@example.com")
    _seed_action(
        test_env["sessionmaker"],
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        action_id="visibility-section-action",
        raw_prompt="do not return this from the section endpoint",
        redacted_prompt="do not return [redacted]",
        metadata={"provider": "openai", "agent_id": "section-agent", "tool": "section-tool"},
    )
    grant = _grant_visibility(
        client,
        owner,
        user_id=owner["user_id"],
        capabilities=["view_user_metadata", "view_action_details"],
    )
    assert grant.status_code == 201, grant.text

    overview = client.get(
        f"/user-visibility/users/{owner['user_id']}/experience/overview",
        headers=_headers(owner),
    )
    assert overview.status_code == 200, overview.text
    assert overview.json()["section"] == "overview"
    assert overview.json()["data"]["user"]["user_id"] == owner["user_id"]
    assert "recent_actions" not in overview.json()["data"]

    actions = client.get(
        f"/user-visibility/users/{owner['user_id']}/experience/actions",
        headers=_headers(owner),
        params={"page": 1, "page_size": 1},
    )
    assert actions.status_code == 200, actions.text
    assert actions.json()["section"] == "actions"
    assert actions.json()["data"]["page_size"] == 1
    assert "raw_prompt" not in str(actions.json())


def test_accounts_section_is_direct_bound_masked_without_evidence_and_revealed_with_evidence(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="account-visibility-owner@example.com")
    _identity_id, account_session_id = _seed_account_context(
        test_env["sessionmaker"], tenant_id=owner["tenant_id"], user_id=owner["user_id"],
    )
    with test_env["sessionmaker"]() as db:
        db.add(ProviderSignalRecord(
            tenant_id=owner["tenant_id"], provider="openai", product="chatgpt", source_type="provider_api",
            source_schema_version="1", source_record_id="signal-direct", dedup_key="signal-direct",
            record_kind="usage", occurred_at=datetime.now(timezone.utc), user_id=owner["user_id"],
            client="codex", model="gpt-5", session_ref=account_session_id,
        ))
        db.commit()
    grant = _grant_visibility(client, owner, user_id=owner["user_id"], capabilities=["view_user_metadata"])
    assert grant.status_code == 201, grant.text
    masked_response = client.get(f"/user-visibility/users/{owner['user_id']}/experience/accounts", headers=_headers(owner))
    assert masked_response.status_code == 200, masked_response.text
    masked = masked_response.json()
    assert masked["section"] == "accounts"
    assert masked["data"]["summary"]["company_enterprise"] == 1
    context = masked["data"]["items"][0]
    assert context["display_category"] == "COMPANY_ENTERPRISE"
    assert context["current"] is True
    assert context["user_binding"] == "DIRECT"
    assert context["models"] == ["gpt-5"]
    assert context["clients"] == ["codex"]
    assert context["provider_subject_ref"] == "MASKED"
    assert context["provider_tenant"]["organisation_ids"] == ["MASKED"]
    assert context["evidence_refs"] == []
    for forbidden in ("raw_prompt", "access_token", "refresh_token", "cookie", "password"):
        assert forbidden not in str(masked).casefold()

    grant = _grant_visibility(client, owner, user_id=owner["user_id"], capabilities=["view_user_metadata", "view_evidence"])
    assert grant.status_code == 201, grant.text
    detailed = client.get(f"/user-visibility/users/{owner['user_id']}/experience/accounts", headers=_headers(owner)).json()["data"]["items"][0]
    assert detailed["provider_tenant"]["organisation_ids"] == ["org-company"]
    assert detailed["provider_tenant"]["workspace_ids"] == ["workspace-company"]
    assert detailed["provider_tenant"]["tenant_ids"] == ["provider-tenant-company"]
    assert detailed["evidence_refs"] == ["account-boundary:integration-1"]


@pytest.mark.parametrize(
    ("account_class", "session_state", "verification_status", "expected_category"),
    [
        ("PERSONAL_FREE", "PERSONAL_DETECTED", "OBSERVED", "PERSONAL"),
        ("PARTNER_ENTERPRISE", "PARTNER_VERIFIED", "VERIFIED", "PARTNER_EXTERNAL_ENTERPRISE"),
        ("EXTERNAL_ENTERPRISE", "EXTERNAL_UNAPPROVED", "VERIFIED", "PARTNER_EXTERNAL_ENTERPRISE"),
        ("ANONYMOUS", "ANONYMOUS_DETECTED", "OBSERVED", "ANONYMOUS"),
        ("UNKNOWN", "UNKNOWN", "UNKNOWN", "UNKNOWN"),
    ],
)
def test_accounts_categories_and_expired_enterprise_are_truthful(test_env, account_class, session_state, verification_status, expected_category) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email=f"account-{account_class.casefold()}@example.com")
    _seed_account_context(test_env["sessionmaker"], tenant_id=owner["tenant_id"], user_id=owner["user_id"], account_class=account_class, session_state=session_state, verification_status=verification_status)
    assert _grant_visibility(client, owner, user_id=owner["user_id"], capabilities=["view_user_metadata"]).status_code == 201
    context = client.get(f"/user-visibility/users/{owner['user_id']}/experience/accounts", headers=_headers(owner)).json()["data"]["items"][0]
    assert context["display_category"] == expected_category

    if account_class == "UNKNOWN":
        _seed_account_context(test_env["sessionmaker"], tenant_id=owner["tenant_id"], user_id=owner["user_id"], suffix="expired", expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        body = client.get(f"/user-visibility/users/{owner['user_id']}/experience/accounts", headers=_headers(owner)).json()["data"]
        expired = next(item for item in body["items"] if item["relationship_state"] == "EXPIRED")
        assert expired["display_category"] == "COMPANY_ENTERPRISE"
        assert expired["current"] is False
        assert body["summary"]["current_company_enterprise"] == 0


def test_accounts_attach_repeated_exact_direct_session_references_and_keep_unmatched_unknown(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="account-exact-owner@example.com")
    other = _register_owner(client, email="account-exact-other@example.com")
    _identity_id, direct_ref = _seed_account_context(test_env["sessionmaker"], tenant_id=owner["tenant_id"], user_id=owner["user_id"])
    _seed_account_context(test_env["sessionmaker"], tenant_id=owner["tenant_id"], user_id=other["user_id"], suffix="other")
    with test_env["sessionmaker"]() as db:
        now = datetime.now(timezone.utc)
        for suffix, session_ref in (("exact", direct_ref), ("near", f"{direct_ref}-near"), ("missing", None), ("duplicate-a", direct_ref), ("duplicate-b", direct_ref)):
            db.add(ProviderSignalRecord(tenant_id=owner["tenant_id"], provider="openai", product="chatgpt", source_type="provider_api", source_schema_version="1", source_record_id=suffix, dedup_key=suffix, record_kind="usage", occurred_at=now, user_id=owner["user_id"], client=suffix, model=suffix, session_ref=session_ref))
        db.add(ProviderSignalRecord(tenant_id=other["tenant_id"], provider="openai", product="chatgpt", source_type="provider_api", source_schema_version="1", source_record_id="cross", dedup_key="cross", record_kind="usage", occurred_at=now, user_id=other["user_id"], client="cross", model="cross", session_ref=direct_ref))
        db.commit()
    assert _grant_visibility(client, owner, user_id=owner["user_id"], capabilities=["view_user_metadata"]).status_code == 201
    body = client.get(f"/user-visibility/users/{owner['user_id']}/experience/accounts", headers=_headers(owner)).json()["data"]
    verified = next(item for item in body["items"] if item["user_binding"] == "DIRECT")
    assert verified["models"] == ["duplicate-a", "duplicate-b", "exact"]
    assert verified["clients"] == ["duplicate-a", "duplicate-b", "exact"]
    assert verified["activity_count"] == 3
    assert any(item["display_category"] == "UNKNOWN" and item["user_binding"] == "OBSERVED_UNMATCHED" for item in body["items"])


@pytest.mark.parametrize(
    ("verification_status", "identity_verification_method"),
    [("OBSERVED", "server_owned_adapter"), ("VERIFIED", "provider_claim")],
)
def test_unverified_or_non_server_owned_enterprise_identity_is_unknown(test_env, verification_status, identity_verification_method) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email=f"account-authority-{verification_status}-{identity_verification_method}@example.com")
    identity_id, _account_session_id = _seed_account_context(
        test_env["sessionmaker"], tenant_id=owner["tenant_id"], user_id=owner["user_id"], verification_status=verification_status,
    )
    with test_env["sessionmaker"]() as db:
        identity = db.get(AIAccountIdentity, identity_id)
        assert identity is not None
        identity.verification_method = identity_verification_method
        db.commit()
    assert _grant_visibility(client, owner, user_id=owner["user_id"], capabilities=["view_user_metadata"]).status_code == 201
    context = client.get(f"/user-visibility/users/{owner['user_id']}/experience/accounts", headers=_headers(owner)).json()["data"]["items"][0]
    assert context["account_class"] == "ENTERPRISE_MANAGED_USER"
    assert context["display_category"] == "UNKNOWN"
    assert context["current"] is False


def test_prompt_reveal_is_explicitly_authorized_user_bound_and_single_use(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-reveal@example.com")
    _seed_action(
        test_env["sessionmaker"],
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        action_id="visibility-action-1",
        raw_prompt="internal incident evidence",
        redacted_prompt="internal incident [redacted]",
    )
    grant = _grant_visibility(
        client,
        owner,
        user_id=owner["user_id"],
        capabilities=["view_user_metadata", "view_action_details", "reveal_prompt_content", "manage_privacy"],
    )
    assert grant.status_code == 201, grant.text

    timeline = client.get(f"/users/{owner['user_id']}/timeline", headers=_headers(owner))
    assert timeline.status_code == 200, timeline.text
    normal_prompt = timeline.json()["actions"][0]["prompt_payload"]
    assert "raw_prompt" not in normal_prompt
    assert normal_prompt["content_access_level"] == "REDACTED_PREVIEW"

    retention_disabled = client.post(
        "/user-visibility/prompts/visibility-action-1/reveal-grants",
        headers=_headers(owner),
        json={"purpose": "security_investigation", "reason": "incident-42"},
    )
    assert retention_disabled.status_code == 422

    retention_enabled = client.put(
        "/user-visibility/privacy-settings",
        headers=_headers(owner),
        json={"full_content_reveal_enabled": True, "retention_days": 7},
    )
    assert retention_enabled.status_code == 200, retention_enabled.text

    requested = client.post(
        "/user-visibility/prompts/visibility-action-1/reveal-grants",
        headers=_headers(owner),
        json={"purpose": "security_investigation", "reason": "incident-42"},
    )
    assert requested.status_code == 201, requested.text

    consumed = client.post(
        f"/user-visibility/prompt-reveal/{requested.json()['grant_id']}",
        headers=_headers(owner),
    )
    assert consumed.status_code == 200, consumed.text
    assert consumed.json()["content"] == "internal incident evidence"

    replay = client.post(
        f"/user-visibility/prompt-reveal/{requested.json()['grant_id']}",
        headers=_headers(owner),
    )
    assert replay.status_code == 409

    with test_env["sessionmaker"]() as db:
        audit_entries = db.scalars(
            select(AuditLog).where(
                AuditLog.tenant_id == owner["tenant_id"],
                AuditLog.resource_id == "visibility-action-1",
                AuditLog.action.in_(("user_visibility.prompt_reveal.requested", "user_visibility.prompt_reveal.consumed")),
            )
        ).all()
    assert {entry.action for entry in audit_entries} == {
        "user_visibility.prompt_reveal.requested",
        "user_visibility.prompt_reveal.consumed",
    }
    assert all("internal incident evidence" not in str(entry.payload) for entry in audit_entries)


def test_existing_browser_action_update_preserves_realtime_prompt_projection(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-realtime-prompt@example.com")
    action_id = "runtime-browser-action-1"
    with test_env["sessionmaker"]() as db:
        db.add(
            UserRegistry(
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                display_name="Visibility Owner",
                email="user-visibility-realtime-prompt@example.com",
                department="Engineering",
                role="owner",
            )
        )
        db.add(
            AISession(
                session_id="runtime-browser-session-1",
                tenant_id=owner["tenant_id"],
                user_id=owner["user_id"],
                source_surface="browser",
                ai_app="chatgpt.com",
                ai_model="gpt-5",
                metadata_json={"provider": "openai"},
            )
        )
        db.add(
            AIAction(
                action_id=action_id,
                tenant_id=owner["tenant_id"],
                session_id="runtime-browser-session-1",
                user_id=owner["user_id"],
                action_type="prompt_submitted",
                ai_app="chatgpt.com",
                ai_model="gpt-5",
                enforcement_action="warned",
                correlation_id="runtime-browser-correlation-1",
                metadata_json={"provider": "openai"},
            )
        )
        db.commit()

    with test_env["sessionmaker"]() as db:
        result = record_activity_event(
            db,
            tenant_id=owner["tenant_id"],
            user_id=owner["user_id"],
            payload={
                "action_id": action_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "prompt_submitted",
                "action_type": "prompt_submitted",
                "source_surface": "browser",
                "domain": "chatgpt.com",
                "ai_app": "chatgpt.com",
                "ai_model": "gpt-5",
                "action_taken": "warn",
                "correlation_id": "runtime-browser-correlation-1",
                "prompt_preview_redacted": "Demo prompt [redacted]",
                "prompt_storage_mode": "redacted",
                "metadata": {"provider": "openai", "evidence_quality": "OS_OBSERVED"},
            },
        )
        db.commit()
        assert result.action_id == action_id
        assert db.get(PromptPayload, action_id) is not None
        db.add(
            AIAction(
                action_id="newer-browser-discovery-heartbeat",
                tenant_id=owner["tenant_id"],
                session_id="runtime-browser-session-1",
                user_id=owner["user_id"],
                timestamp=datetime.now(timezone.utc) + timedelta(seconds=10),
                action_type="agent_discovery",
                ai_app="chatgpt.com",
                enforcement_action="warned",
                correlation_id="newer-browser-discovery-heartbeat",
                metadata_json={"evidence_quality": "OS_OBSERVED"},
            )
        )
        db.commit()

    grant = _grant_visibility(
        client,
        owner,
        user_id=owner["user_id"],
        capabilities=["view_user_metadata", "view_action_details"],
    )
    assert grant.status_code == 201, grant.text

    response = client.get("/user-visibility/actions", headers=_headers(owner), params={"page_size": 5})
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["action_id"] == action_id
    prompt_payload = response.json()["items"][0]["prompt_payload"]
    assert prompt_payload["content_access_level"] == "REDACTED_PREVIEW"
    assert prompt_payload["redacted_preview"] == "Demo prompt [redacted]"
    assert "raw_prompt" not in str(response.json())


def test_directory_department_organization_and_action_explorer_enforce_tenant_and_department_scope(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-directory-owner@example.com")
    department_viewer = _register_owner(client, email="user-visibility-department-viewer@example.com")
    with test_env["sessionmaker"]() as db:
        db.add(
            UserTenantRole(
                tenant_id=owner["tenant_id"],
                user_id=department_viewer["user_id"],
                role="viewer",
            )
        )
        db.commit()

    _seed_action(
        test_env["sessionmaker"],
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        action_id="visibility-risk-action",
        raw_prompt="risk planning",
        redacted_prompt="risk [redacted]",
        department="Risk",
        metadata={
            "provider": "openai",
            "account_class": "enterprise",
            "agent_id": "risk-agent",
            "tool": "search",
            "destination": "internal",
            "resource": "customer-record",
            "target": "case-17",
            "side_effect": "none",
            "executing_principal": "service-risk",
            "approval": "not_required",
            "execution_result": "succeeded",
            "evidence_quality": "OS_OBSERVED",
            "control_point": "runtime",
            "drift": "none",
        },
        ai_app="RiskGPT",
    )
    _seed_action(
        test_env["sessionmaker"],
        tenant_id=owner["tenant_id"],
        user_id=department_viewer["user_id"],
        action_id="visibility-finance-action",
        raw_prompt="finance planning",
        redacted_prompt="finance [redacted]",
        department="Finance",
        enforcement_action="blocked",
        metadata={"provider": "anthropic", "agent_id": "finance-agent", "tool": "export", "destination": "external"},
        ai_app="FinanceGPT",
    )
    owner_grant = _grant_visibility(
        client,
        owner,
        user_id=owner["user_id"],
        capabilities=["view_aggregates", "view_user_metadata", "view_action_details", "view_evidence"],
    )
    assert owner_grant.status_code == 201, owner_grant.text

    directory = client.get("/user-visibility/users", headers=_headers(owner), params={"page_size": 1})
    assert directory.status_code == 200, directory.text
    assert directory.json()["total"] == 2
    assert len(directory.json()["items"]) == 1
    directory_all = client.get("/user-visibility/users", headers=_headers(owner), params={"page_size": 50})
    assert directory_all.status_code == 200, directory_all.text
    owner_row = next(row for row in directory_all.json()["items"] if row["user_id"] == owner["user_id"])
    assert owner_row["ai_usage"] == {
        "applications": ["RiskGPT"],
        "providers": ["openai"],
        "models": ["gpt-5"],
        "agents": ["risk-agent"],
        "tools": ["search"],
        "account_classes": ["enterprise"],
        "prompt_request_count": 1,
        "action_count": 1,
        "sensitive_data_event_count": 1,
        "warning_approval_block_count": 0,
    }
    assert "risk_score" not in owner_row

    filtered_directory = client.get(
        "/user-visibility/users",
        headers=_headers(owner),
        params={
            "status": "active",
            "application": "RiskGPT",
            "provider": "openai",
            "model": "gpt-5",
            "account_class": "enterprise",
        },
    )
    assert filtered_directory.status_code == 200, filtered_directory.text
    assert [row["user_id"] for row in filtered_directory.json()["items"]] == [owner["user_id"]]

    user_detail = client.get(f"/user-visibility/users/{owner['user_id']}", headers=_headers(owner))
    assert user_detail.status_code == 200, user_detail.text
    assert user_detail.json()["user"]["department"] == "Risk"

    departments = client.get("/user-visibility/departments", headers=_headers(owner))
    assert departments.status_code == 200, departments.text
    assert {item["department"] for item in departments.json()["items"]} == {"Finance", "Risk"}

    organization = client.get("/user-visibility/organization", headers=_headers(owner))
    assert organization.status_code == 200, organization.text
    assert organization.json()["action_count"] == 2

    actions = client.get(
        "/user-visibility/actions",
        headers=_headers(owner),
        params={"provider": "anthropic", "decision": "blocked", "page_size": 50},
    )
    assert actions.status_code == 200, actions.text
    assert [row["action_id"] for row in actions.json()["items"]] == ["visibility-finance-action"]
    assert "raw_prompt" not in str(actions.json()["items"])

    bound_action = client.get(
        "/user-visibility/actions",
        headers=_headers(owner),
        params={"resource": "customer-record", "target": "case-17", "side_effect": "none"},
    )
    assert bound_action.status_code == 200, bound_action.text
    assert [row["action_id"] for row in bound_action.json()["items"]] == ["visibility-risk-action"]
    assert bound_action.json()["items"][0]["executing_principal"] == "service-risk"
    assert bound_action.json()["items"][0]["approval"] == "not_required"
    assert bound_action.json()["items"][0]["execution_result"] == "succeeded"
    assert bound_action.json()["items"][0]["evidence_quality"] == "OS_OBSERVED"
    assert bound_action.json()["items"][0]["control_point"] == "runtime"
    assert bound_action.json()["items"][0]["drift"] == "none"

    viewer_grant = _grant_visibility(
        client,
        owner,
        user_id=department_viewer["user_id"],
        capabilities=["view_aggregates", "view_user_metadata", "view_action_details"],
        department_scope=["Risk"],
    )
    assert viewer_grant.status_code == 201, viewer_grant.text
    department_organization = client.get(
        "/user-visibility/organization",
        headers={"Authorization": f"Bearer {department_viewer['access_token']}", "X-Tenant-ID": owner["tenant_id"]},
    )
    assert department_organization.status_code == 200, department_organization.text
    assert department_organization.json()["action_count"] == 1
    assert department_organization.json()["applications"] == [{"name": "RiskGPT", "count": 1}]
    denied = client.get(
        f"/user-visibility/users/{department_viewer['user_id']}",
        headers={"Authorization": f"Bearer {department_viewer['access_token']}", "X-Tenant-ID": owner["tenant_id"]},
    )
    assert denied.status_code == 403


def test_groups_membership_and_effective_pack_references_reuse_policy_pack_records(test_env) -> None:
    client: TestClient = test_env["client"]
    owner = _register_owner(client, email="user-visibility-groups-owner@example.com")
    member = _register_owner(client, email="user-visibility-groups-member@example.com")
    with test_env["sessionmaker"]() as db:
        db.add(UserTenantRole(tenant_id=owner["tenant_id"], user_id=member["user_id"], role="viewer"))
        group = PolicyPackUserGroup(
            tenant_id=owner["tenant_id"],
            group_key="risk-static",
            name="Risk Static",
            group_type="static",
            membership_rule={},
            nested_group_ids=[],
            source_ref="test",
        )
        definition = PolicyPackDefinition(
            publisher_ref="hawk",
            stable_pack_id="UAI-001",
            version="1.0.0",
            name="Approved AI",
            description="test",
        )
        db.add_all([group, definition])
        db.flush()
        db.add(
            PolicyPackGroupMembership(
                tenant_id=owner["tenant_id"],
                group_id=group.id,
                user_id=owner["user_id"],
                source="static",
                active=True,
            )
        )
        instance = PolicyPackInstance(
            tenant_id=owner["tenant_id"],
            definition_id=definition.id,
            source_pack_id="UAI-001",
            source_pack_version="1.0.0",
            owner_ref=f"user:{owner['user_id']}",
        )
        db.add(instance)
        db.flush()
        db.add(
            PolicyPackAssignment(
                tenant_id=owner["tenant_id"],
                instance_id=instance.id,
                assignment_key="risk-static-group",
                targets={"group": [group.id]},
                active=True,
            )
        )
        db.add_all(
            [
                PolicyPackAssignment(
                    tenant_id=owner["tenant_id"],
                    instance_id=instance.id,
                    assignment_key="organization-baseline",
                    targets={"organization": ["all"]},
                    active=True,
                ),
                PolicyPackAssignment(
                    tenant_id=owner["tenant_id"],
                    instance_id=instance.id,
                    assignment_key="risk-department",
                    targets={"department": ["Risk"]},
                    active=True,
                ),
                PolicyPackAssignment(
                    tenant_id=owner["tenant_id"],
                    instance_id=instance.id,
                    assignment_key="direct-owner",
                    targets={"user": [owner["user_id"]]},
                    active=True,
                ),
            ]
        )
        db.commit()
        group_id = group.id
    _seed_action(
        test_env["sessionmaker"],
        tenant_id=owner["tenant_id"],
        user_id=owner["user_id"],
        action_id="group-owner-action",
        raw_prompt="owner prompt",
        redacted_prompt="owner [redacted]",
    )
    _seed_action(
        test_env["sessionmaker"],
        tenant_id=owner["tenant_id"],
        user_id=member["user_id"],
        action_id="group-member-action",
        raw_prompt="member prompt",
        redacted_prompt="member [redacted]",
    )
    grant = _grant_visibility(
        client,
        owner,
        user_id=owner["user_id"],
        capabilities=["view_user_metadata", "view_action_details", "manage_groups"],
    )
    assert grant.status_code == 201, grant.text

    groups = client.get("/user-visibility/groups", headers=_headers(owner))
    assert groups.status_code == 200, groups.text
    assert any(row["group_id"] == group_id and row["group_type"] == "static" for row in groups.json()["items"])

    detail = client.get(f"/user-visibility/groups/{group_id}", headers=_headers(owner))
    assert detail.status_code == 200, detail.text
    assert detail.json()["member_ids"] == [owner["user_id"]]
    assert detail.json()["policy_pack_assignments"][0]["assignment_key"] == "risk-static-group"

    group_actions = client.get(
        "/user-visibility/actions",
        headers=_headers(owner),
        params={"group_id": group_id},
    )
    assert group_actions.status_code == 200, group_actions.text
    assert [row["action_id"] for row in group_actions.json()["items"]] == ["group-owner-action"]

    updated = client.post(
        f"/user-visibility/groups/{group_id}/memberships",
        headers=_headers(owner),
        json={"add_user_ids": [member["user_id"]], "remove_user_ids": []},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["added_user_ids"] == [member["user_id"]]

    duplicate = client.post(
        f"/user-visibility/groups/{group_id}/memberships",
        headers=_headers(owner),
        json={"add_user_ids": [member["user_id"]], "remove_user_ids": []},
    )
    assert duplicate.status_code == 200, duplicate.text
    assert duplicate.json()["added_user_ids"] == []

    group_after_update = client.get(f"/user-visibility/groups/{group_id}", headers=_headers(owner))
    assert group_after_update.status_code == 200, group_after_update.text
    assert any(item["action"] == "policy_pack.group_memberships.updated" for item in group_after_update.json()["audit_refs"])

    effective = client.get(
        f"/user-visibility/users/{owner['user_id']}/effective-policies",
        headers=_headers(owner),
    )
    assert effective.status_code == 200, effective.text
    assert group_id in effective.json()["group_refs"]
    assert {item["assignment_key"] for item in effective.json()["pack_assignments"]} == {
        "direct-owner",
        "organization-baseline",
        "risk-department",
        "risk-static-group",
    }

    stack = client.get(
        f"/user-visibility/users/{owner['user_id']}/policy-stack",
        headers=_headers(owner),
    )
    assert stack.status_code == 200, stack.text
    assert {item["assignment_kind"] for item in stack.json()["entries"]} >= {"direct", "inherited", "pack"}
    assert {item["source_pack"] for item in stack.json()["entries"]} == {"UAI-001"}
    assert "raw_prompt" not in str(stack.json())

    user_360 = client.get(f"/user-visibility/users/{owner['user_id']}", headers=_headers(owner))
    assert user_360.status_code == 200, user_360.text
    assert group_id in user_360.json()["identity_groups"]["group_refs"]
    assert "risk-static-group" in {
        item["assignment_key"] for item in user_360.json()["policies"]["pack_assignments"]
    }
    assert user_360.json()["controls_evidence"]["evidence_quality"] == "unknown"
    assert user_360.json()["lineage"]["recent_action_refs"][0]["action_id"] == "group-owner-action"
