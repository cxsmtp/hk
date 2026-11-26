"""The AI system approval workflow (app/services/ai_system_approval_service.py, app/api/routers/ai_system_approvals.py):
the per-tenant policy by risk tier, distinct approvers and self-approval, approval scopes (blanket, one-time,
time-bound), the scheduled expiry, the refused bypass, the audit trail and who may do what."""

from __future__ import annotations

import contextlib
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.security import get_password_hash
from app.db.models.ai_system import AISystem
from app.db.models.ai_system_approval import AISystemApprovalGrant
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ApprovalRequest
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import ai_system_approval_service as approvals
from app.services.auth_service import issue_tokens
from app.services.governance_guard import GovernanceViolationError, enforce
from app.services.governance_resolution import resolve_ai_system_status

PEOPLE = ("owner", "admin", "admin2", "operator", "operator2", "auditor", "viewer")


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'approvals.sqlite3'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    headers: dict[str, dict[str, str]] = {}
    users: dict[str, str] = {}
    with factory() as db:
        tenant = Tenant(name="Acme", slug="acme-approvals", is_active=True)
        db.add(tenant)
        db.flush()
        for person in PEOPLE:
            role = person.rstrip("2")
            user = User(email=f"{person}@example.test", full_name=person, hashed_password=get_password_hash("correct-Horse-2026"), is_active=True)
            db.add(user)
            db.flush()
            db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
            db.flush()
            tokens = issue_tokens(db, user=user, tenant_id=tenant.id, role=role)
            headers[person] = {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tenant.id}
            users[person] = user.id
        tenant_id = tenant.id
        db.commit()
    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield {"client": client, "headers": headers, "users": users, "tenant_id": tenant_id, "factory": factory}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _system(env, *, risk_tier: str, name: str | None = None) -> str:
    response = env["client"].post(
        "/ai-systems", headers=env["headers"]["operator"], json={"name": name or f"System {risk_tier}", "description": "", "risk_tier": risk_tier}
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


def _ask(env, system_id: str, *, who: str = "operator", **body) -> dict:
    response = env["client"].post(f"/ai-systems/{system_id}/approval-requests", headers=env["headers"][who], json=body)
    assert response.status_code == 200, response.text
    return response.json()["request"]


def _decide(env, request_id: str, *, who: str, decision: str = "approve", **body):
    return env["client"].post(f"/ai-system-approvals/{request_id}/decision", headers=env["headers"][who], json={"decision": decision, **body})


def _load(env, system_id: str) -> AISystem:
    with env["factory"]() as db:
        row = db.get(AISystem, system_id)
        db.expunge(row)
        return row


def _actions(env) -> list[str]:
    with env["factory"]() as db:
        return [row.action for row in db.scalars(select(AuditLog).where(AuditLog.tenant_id == env["tenant_id"]).order_by(AuditLog.created_at))]


def _governance(env, system_id: str) -> str:
    with env["factory"]() as db:
        return resolve_ai_system_status(system_id, {"db": db, "tenant_id": env["tenant_id"]})["status"]


# ---- The policy, tier by tier ---------------------------------------------------------------------------------------


def test_defaults_are_stricter_for_higher_tiers():
    tiers = approvals.default_config()["tiers"]
    assert [tiers[t]["min_approvers"] for t in approvals.TIERS] == [1, 1, 2, 2, 2]
    assert not any(rule["allow_self_approval"] for rule in tiers.values())
    assert tiers["LOW"]["allowed_scopes"] == ["blanket", "one_time", "time_bound"] and tiers["LOW"]["default_scope"] == "blanket"
    assert tiers["MEDIUM"]["default_scope"] == "time_bound"
    assert "blanket" not in tiers["HIGH"]["allowed_scopes"]
    assert tiers["CRITICAL"]["allowed_scopes"] == ["time_bound"]
    assert tiers["RESTRICTED"]["default_scope"] == "one_time"
    assert [tiers[t]["max_duration_hours"] for t in approvals.TIERS] == [8760, 8760, 2160, 720, 168]
    assert "operator" in tiers["LOW"]["approver_roles"] and "operator" not in tiers["HIGH"]["approver_roles"]
    # Tiers outside the policy: PROHIBITED is never approvable, aliases map, the unknown read as CRITICAL.
    assert approvals.tier_of("PROHIBITED") is None
    assert approvals.tier_of("minimal") == "LOW" and approvals.tier_of("LIMITED") == "MEDIUM"
    assert approvals.tier_of("SOMETHING") == "CRITICAL" and approvals.tier_of("") == "CRITICAL"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"HIGH": {"allow_self_approval": True}}, "only when one approval is needed"),
        ({"LOW": {"allowed_scopes": ["forever"]}}, "blanket, one_time and time_bound"),
        ({"LOW": {"default_scope": "blanket", "allowed_scopes": ["time_bound"]}}, "default scope"),
        ({"LOW": {"approver_roles": []}}, "at least one role"),
        ({"LOW": {"approver_roles": ["nobody"]}}, "no role 'nobody'"),
        ({"LOW": {"min_approvers": 9}}, "between 1 and 5"),
        ({"CRITICAL": {"default_duration_hours": 900}}, "between 1 and 720"),
        ({"PROHIBITED": {"min_approvers": 1}}, "no policy for risk tier PROHIBITED"),
        ({"LOW": {"surprise": 1}}, "unknown field"),
    ],
)
def test_policy_refuses_what_does_not_hold_together(change, message):
    with pytest.raises(approvals.ApprovalWorkflowError) as caught:
        approvals.sanitize_config({"tiers": change}, known_roles=["owner", "admin", "operator", "auditor", "viewer"])
    assert message in caught.value.message
    assert caught.value.status_code == 400


def test_policy_merges_field_by_field_and_one_approver_may_allow_self_approval():
    config = approvals.sanitize_config({"tiers": {"LOW": {"allow_self_approval": True}}}, known_roles=["owner", "admin", "operator"])
    assert config["tiers"]["LOW"]["allow_self_approval"] is True
    assert config["tiers"]["LOW"]["approver_roles"] == ["owner", "admin", "operator"]
    assert config["tiers"]["HIGH"] == approvals.DEFAULT_TIER_RULES["HIGH"]


def test_policy_api_reads_for_the_inventory_and_saves_for_owners_and_admins_with_audit(env):
    client, headers = env["client"], env["headers"]
    for person in ("viewer", "operator", "auditor", "admin"):
        got = client.get("/settings/ai-system-approvals", headers=headers[person])
        assert got.status_code == 200, got.text
        assert got.json()["policy"] == approvals.default_config()
        assert got.json()["may_manage"] is (person == "admin")
    change = {"tiers": {"MEDIUM": {"min_approvers": 2, "approver_roles": ["owner", "admin", "auditor"]}}, "request_ttl_hours": 48}
    for person in ("viewer", "operator", "auditor"):
        assert client.put("/settings/ai-system-approvals", headers=headers[person], json=change).status_code == 403
    saved = client.put("/settings/ai-system-approvals", headers=headers["admin"], json=change)
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["policy"]["tiers"]["MEDIUM"]["min_approvers"] == 2
    assert body["policy"]["request_ttl_hours"] == 48 and body["revision"] == 1 and body["updated_by"] == "admin@example.test"
    bad = client.put("/settings/ai-system-approvals", headers=headers["owner"], json={"tiers": {"MEDIUM": {"allow_self_approval": True}}})
    assert bad.status_code == 400 and "one approval" in bad.json()["error"]
    with env["factory"]() as db:
        entry = db.scalar(select(AuditLog).where(AuditLog.action == "settings.ai_system_approvals"))
        assert entry is not None and entry.payload["changed_tiers"] == ["MEDIUM"]


# ---- Enforcement: no approved status without the workflow -----------------------------------------------------------


@pytest.mark.parametrize("wanted", ["approved", "active", "live"])
def test_a_direct_status_write_that_bypasses_the_policy_is_refused_and_audited(env, wanted):
    system_id = _system(env, risk_tier="LOW")
    refused = env["client"].patch(f"/ai-systems/{system_id}", headers=env["headers"]["owner"], json={"status": wanted})
    if wanted == "live":
        # LIVE without its prerequisites keeps its own refusal (owner and policy missing).
        assert refused.status_code == 409 and refused.json()["detail"]["code"] == "lifecycle_transition_blocked"
        return
    assert refused.status_code == 409, refused.text
    assert refused.json()["detail"]["code"] == "approval_required"
    assert _load(env, system_id).status == "draft"
    assert _governance(env, system_id) != "APPROVED"
    assert "ai_system.approval.bypass_refused" in _actions(env)
    # Other changes still go through.
    assert env["client"].patch(f"/ai-systems/{system_id}", headers=env["headers"]["owner"], json={"status": "paused"}).status_code == 200


def test_the_enforcement_decision_endpoint_cannot_decide_an_ai_system_approval(env):
    system_id = _system(env, risk_tier="LOW")
    request = _ask(env, system_id)
    legacy = env["client"].post(f"/enforcement/approvals/{request['id']}/decision", headers=env["headers"]["owner"], json={"decision": "approve"})
    assert legacy.status_code == 409, legacy.text
    assert _load(env, system_id).status == "pending_approval"


def test_agui_risk_tier_change_cannot_set_an_approved_status(env):
    from app.services.agui.core_actions import _exec_governance_change_risk_tier

    system_id = _system(env, risk_tier="LOW")
    ctx = type("Ctx", (), {"tenant_id": env["tenant_id"], "user_id": env["users"]["owner"]})()
    with env["factory"]() as db, pytest.raises(ValueError, match="approval workflow"):
        _exec_governance_change_risk_tier(db, ctx, None, "approve", None, [], {"ai_system_id": system_id, "risk_tier": "LOW", "status": "approved"})


# ---- Distinct approvers and self-approval ----------------------------------------------------------------------------


def test_low_tier_needs_one_approver_who_is_not_the_requester_by_default(env):
    system_id = _system(env, risk_tier="LOW")
    request = _ask(env, system_id, who="operator")
    assert request["approvals_needed"] == 1 and request["scope"] == "blanket"
    assert _load(env, system_id).status == "pending_approval"
    assert _governance(env, system_id) != "APPROVED"

    own = _decide(env, request["id"], who="operator")
    assert own.status_code == 403 and own.json()["detail"]["code"] == "self_approval_refused"
    viewer = _decide(env, request["id"], who="viewer")
    assert viewer.status_code == 403 and viewer.json()["detail"]["code"] == "role_not_allowed"

    approved = _decide(env, request["id"], who="operator2")
    assert approved.status_code == 200, approved.text
    body = approved.json()
    assert body["request"]["status"] == "approved" and body["grant"]["scope"] == "blanket" and body["grant"]["expires_at"] is None
    assert body["ai_system_status"] == "approved"
    assert _governance(env, system_id) == "APPROVED"
    actions = _actions(env)
    assert "ai_system.approval.refused" in actions
    assert {"ai_system.approval.requested", "ai_system.approval.approved", "ai_system.approval.granted"} <= set(actions)


def test_self_approval_is_allowed_only_when_the_policy_says_so(env):
    client = env["client"]
    saved = client.put("/settings/ai-system-approvals", headers=env["headers"]["owner"], json={"tiers": {"LOW": {"allow_self_approval": True}}})
    assert saved.status_code == 200, saved.text
    system_id = _system(env, risk_tier="LOW")
    request = _ask(env, system_id, who="operator")
    assert request["may_approve"] is True
    assert _decide(env, request["id"], who="operator").status_code == 200
    assert _governance(env, system_id) == "APPROVED"
    with env["factory"]() as db:
        approved = db.scalar(select(AuditLog).where(AuditLog.action == "ai_system.approval.approved"))
        assert approved.payload["self_approval"] is True


def test_two_approvers_required_means_two_different_people_neither_the_requester(env):
    system_id = _system(env, risk_tier="HIGH")
    request = _ask(env, system_id, who="admin")
    assert request["approvals_needed"] == 2 and request["scope"] == "time_bound"

    own = _decide(env, request["id"], who="admin")
    assert own.status_code == 403 and own.json()["detail"]["code"] == "self_approval_refused"
    operator = _decide(env, request["id"], who="operator")
    assert operator.status_code == 403 and operator.json()["detail"]["code"] == "role_not_allowed"

    first = _decide(env, request["id"], who="owner", scope="time_bound", duration_hours=48)
    assert first.status_code == 200, first.text
    assert first.json()["request"]["status"] == "pending" and first.json()["grant"] is None
    assert _governance(env, system_id) != "APPROVED"

    again = _decide(env, request["id"], who="owner")
    assert again.status_code == 409 and again.json()["detail"]["code"] == "duplicate_approver"
    other_scope = _decide(env, request["id"], who="admin2", scope="one_time")
    assert other_scope.status_code == 409 and other_scope.json()["detail"]["code"] == "scope_fixed"

    second = _decide(env, request["id"], who="admin2")
    assert second.status_code == 200, second.text
    grant = second.json()["grant"]
    assert grant["scope"] == "time_bound"
    assert sorted(grant["approver_user_ids"]) == sorted([env["users"]["owner"], env["users"]["admin2"]])
    expires = datetime.fromisoformat(grant["expires_at"])
    assert timedelta(hours=47) < expires - datetime.now(timezone.utc) <= timedelta(hours=48)
    assert _governance(env, system_id) == "APPROVED"


def test_a_denial_closes_the_request_and_leaves_the_system_unapproved(env):
    system_id = _system(env, risk_tier="MEDIUM")
    request = _ask(env, system_id)
    denied = _decide(env, request["id"], who="admin", decision="deny", reason="no data protection review yet")
    assert denied.status_code == 200, denied.text
    assert denied.json()["request"]["status"] == "denied"
    assert _load(env, system_id).status == "draft"
    assert _decide(env, request["id"], who="owner").json()["detail"]["code"] == "request_closed"
    assert "ai_system.approval.denied" in _actions(env)
    # A new request may be made afterwards; only one waits at a time.
    _ask(env, system_id)
    again = env["client"].post(f"/ai-systems/{system_id}/approval-requests", headers=env["headers"]["operator"], json={})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "request_pending"


# ---- Scopes ---------------------------------------------------------------------------------------------------------


def test_scopes_are_limited_to_what_the_tier_allows(env):
    critical = _system(env, risk_tier="CRITICAL")
    blanket = env["client"].post(f"/ai-systems/{critical}/approval-requests", headers=env["headers"]["operator"], json={"scope": "blanket"})
    assert blanket.status_code == 409 and blanket.json()["detail"]["code"] == "scope_not_allowed"
    too_long = env["client"].post(
        f"/ai-systems/{critical}/approval-requests", headers=env["headers"]["operator"], json={"scope": "time_bound", "duration_hours": 721}
    )
    assert too_long.status_code == 409 and "720 hours" in too_long.json()["detail"]["message"]
    request = _ask(env, critical)
    assert request["scope"] == "time_bound" and request["duration_hours"] == 168
    first = _decide(env, request["id"], who="owner", scope="blanket")
    assert first.status_code == 409 and first.json()["detail"]["code"] == "scope_not_allowed"
    prohibited = _system(env, risk_tier="PROHIBITED")
    refused = env["client"].post(f"/ai-systems/{prohibited}/approval-requests", headers=env["headers"]["operator"], json={})
    assert refused.status_code == 409 and refused.json()["detail"]["code"] == "tier_not_approvable"


def _approve_low(env, *, scope: str, duration_hours: int | None = None) -> tuple[str, dict]:
    system_id = _system(env, risk_tier="LOW", name=f"Low {scope}")
    request = _ask(env, system_id)
    body = {"scope": scope}
    if duration_hours:
        body["duration_hours"] = duration_hours
    decided = _decide(env, request["id"], who="admin", **body)
    assert decided.status_code == 200, decided.text
    return system_id, decided.json()["grant"]


def test_time_bound_approval_lapses_at_once_and_the_scheduled_check_records_the_expiry(env):
    system_id, grant = _approve_low(env, scope="time_bound", duration_hours=2)
    blanket_id, _ = _approve_low(env, scope="blanket")
    assert _governance(env, system_id) == "APPROVED"
    later = datetime.now(timezone.utc) + timedelta(hours=3)

    with env["factory"]() as db:
        row = db.get(AISystem, system_id)
        # Before the scheduled check runs, the governance decision already reads it as not approved.
        assert resolve_ai_system_status(system_id, {"db": db, "tenant_id": env["tenant_id"]})["status"] == "APPROVED"
        from app.services.governance_resolution import approval_has_lapsed

        assert approval_has_lapsed(row, now=later)
        result = approvals.expire_due(db, now=later)
        db.commit()
    assert result["expired_grant_ids"] == [grant["id"]]
    row = _load(env, system_id)
    assert row.status == "pending_reapproval"
    assert row.metadata_json["governance_state"] == "PENDING_REAPPROVAL" and row.metadata_json["requires_reapproval"] is True
    assert _governance(env, system_id) == "PROPOSED"
    # The blanket approval stands.
    assert _governance(env, blanket_id) == "APPROVED"
    with env["factory"]() as db:
        assert db.get(AISystemApprovalGrant, grant["id"]).state == "EXPIRED"
        assert db.scalar(select(EvidenceNode).where(EvidenceNode.signal_type == "ai_system.approval.expired")) is not None
    assert "ai_system.approval.expired" in _actions(env)
    # Pending re-approval is not approved: a direct write is still refused.
    refused = env["client"].patch(f"/ai-systems/{system_id}", headers=env["headers"]["owner"], json={"status": "approved"})
    assert refused.status_code == 409


def test_a_lapsed_time_bound_approval_is_not_approved_even_before_the_check(env):
    system_id, _ = _approve_low(env, scope="time_bound", duration_hours=1)
    with env["factory"]() as db:
        row = db.get(AISystem, system_id)
        metadata = dict(row.metadata_json)
        metadata["approval"] = {**metadata["approval"], "expires_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()}
        row.metadata_json = metadata
        db.commit()
    with env["factory"]() as db:
        status = resolve_ai_system_status(system_id, {"db": db, "tenant_id": env["tenant_id"]})
    assert status["status"] == "PROPOSED" and status["reason"] == "approval_lapsed"
    with env["factory"]() as db, pytest.raises(GovernanceViolationError):
        enforce(db, tenant_id=env["tenant_id"], ai_system_id=system_id, action="gateway.llm.intercept", route="/gateway/llm/intercept", module="gateway_service")


def test_one_time_approval_is_consumed_by_the_first_governed_use(env):
    system_id, grant = _approve_low(env, scope="one_time")
    with env["factory"]() as db:
        # Checks that are not a use (a snapshot, a simulation) do not consume it.
        enforce(db, tenant_id=env["tenant_id"], ai_system_id=system_id, action="snapshot.export", route="/auditor/export", module="snapshot_service")
        db.commit()
    assert _governance(env, system_id) == "APPROVED"
    with env["factory"]() as db:
        enforce(db, tenant_id=env["tenant_id"], ai_system_id=system_id, action="gateway.llm.intercept", route="/gateway/llm/intercept", module="gateway_service")
        # The rest of the same use still passes.
        assert resolve_ai_system_status(system_id, {"db": db, "tenant_id": env["tenant_id"]})["status"] == "APPROVED"
        enforce(db, tenant_id=env["tenant_id"], ai_system_id=system_id, action="gateway.mcp.authorize", route="/gateway/mcp/authorize", module="gateway_service")
        db.commit()
    row = _load(env, system_id)
    assert row.status == "pending_reapproval"
    with env["factory"]() as db:
        assert db.get(AISystemApprovalGrant, grant["id"]).state == "CONSUMED"
        # The response check of that use, in its own call, passes for a short while.
        enforce(db, tenant_id=env["tenant_id"], ai_system_id=system_id, action="llm_gateway.response", route="/llm-gateway/response", module="llm_gateway_service")
    with env["factory"]() as db, pytest.raises(GovernanceViolationError) as blocked:
        enforce(db, tenant_id=env["tenant_id"], ai_system_id=system_id, action="gateway.llm.intercept", route="/gateway/llm/intercept", module="gateway_service")
    assert blocked.value.reason_code == "governance_state_not_approved"
    assert "ai_system.approval.consumed" in _actions(env)


def test_blanket_approval_stands_until_revoked(env):
    system_id, grant = _approve_low(env, scope="blanket")
    with env["factory"]() as db:
        assert approvals.expire_due(db, now=datetime.now(timezone.utc) + timedelta(days=3650))["expired_grant_count"] == 0
        for _ in range(3):
            enforce(db, tenant_id=env["tenant_id"], ai_system_id=system_id, action="gateway.llm.intercept", route="/gateway/llm/intercept", module="gateway_service")
        db.commit()
    assert _governance(env, system_id) == "APPROVED"
    client = env["client"]
    viewer = client.post(f"/ai-system-approvals/grants/{grant['id']}/revoke", headers=env["headers"]["viewer"], json={"reason": "no"})
    assert viewer.status_code == 403
    revoked = client.post(f"/ai-system-approvals/grants/{grant['id']}/revoke", headers=env["headers"]["operator2"], json={"reason": "vendor changed terms"})
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["grant"]["state"] == "REVOKED" and revoked.json()["ai_system_status"] == "pending_reapproval"
    assert _governance(env, system_id) == "PROPOSED"
    assert client.post(f"/ai-system-approvals/grants/{grant['id']}/revoke", headers=env["headers"]["owner"], json={}).status_code == 409
    listed = client.get("/ai-system-approvals/grants", headers=env["headers"]["viewer"], params={"state": "all"})
    assert listed.status_code == 200 and listed.json()["items"][0]["end_reason"] == "vendor changed terms"
    assert "ai_system.approval.revoked" in _actions(env)


def test_a_new_approval_supersedes_the_old_and_a_raised_risk_tier_revokes(env):
    system_id, grant = _approve_low(env, scope="blanket")
    renewal = _ask(env, system_id, scope="time_bound")
    assert renewal["renewal"] is True and _load(env, system_id).status == "approved"
    assert _decide(env, renewal["id"], who="admin").status_code == 200
    with env["factory"]() as db:
        assert db.get(AISystemApprovalGrant, grant["id"]).state == "SUPERSEDED"
    raised = env["client"].patch(f"/ai-systems/{system_id}", headers=env["headers"]["owner"], json={"risk_tier": "MEDIUM"})
    assert raised.status_code == 200, raised.text
    assert raised.json()["status"] == "pending_reapproval"
    assert _governance(env, system_id) == "PROPOSED"


def test_a_request_that_waits_too_long_expires(env):
    system_id = _system(env, risk_tier="MEDIUM")
    request = _ask(env, system_id)
    with env["factory"]() as db:
        result = approvals.expire_due(db, now=datetime.now(timezone.utc) + timedelta(hours=approvals.DEFAULT_REQUEST_TTL_HOURS + 1))
        db.commit()
    assert result["expired_request_ids"] == [request["id"]]
    assert _load(env, system_id).status == "draft"
    with env["factory"]() as db:
        assert db.get(ApprovalRequest, request["id"]).status == "expired"
    assert "ai_system.approval.request_expired" in _actions(env)


# ---- The scheduled check, the lists and the audit trail -----------------------------------------------------------


def test_the_expiry_job_runs_every_minute_and_expires(env, monkeypatch):
    from app.jobs import celery_app as celery_module
    from app.jobs import enforcement_jobs

    beat = celery_module.celery_app.conf.beat_schedule["ai-system-approval-expiry-every-minute"]
    assert beat["task"] == "app.jobs.enforcement_jobs.expire_ai_system_approvals" and beat["schedule"] == 60.0
    system_id, grant = _approve_low(env, scope="time_bound", duration_hours=1)
    with env["factory"]() as db:
        row = db.get(AISystemApprovalGrant, grant["id"])
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    monkeypatch.setattr(enforcement_jobs, "SessionLocal", env["factory"])
    monkeypatch.setattr(enforcement_jobs, "tracked_scheduled_job", lambda *a, **k: contextlib.nullcontext())
    result = enforcement_jobs.expire_ai_system_approvals.run()
    assert result["expired_grant_ids"] == [grant["id"]]
    assert _load(env, system_id).status == "pending_reapproval"
    # The SLA job for other approvals leaves AI system approval requests to this one.
    other = _system(env, risk_tier="LOW", name="Waiting")
    _ask(env, other)
    with env["factory"]() as db:
        pending = db.scalar(select(ApprovalRequest).where(ApprovalRequest.ai_system_id == other))
        pending.sla_minutes = 0
        db.commit()
    assert enforcement_jobs.resolve_timed_out_approvals.run()["resolved_count"] == 0


def test_every_step_is_in_the_audit_log_with_evidence(env):
    _approve_low(env, scope="one_time")
    system_id = _system(env, risk_tier="LOW", name="Denied")
    request = _ask(env, system_id)
    _decide(env, request["id"], who="admin", decision="deny")
    with env["factory"]() as db:
        entries = db.scalars(select(AuditLog).where(AuditLog.action.like("ai_system.approval.%"))).all()
        by_action = {row.action: row for row in entries}
        for action in ("ai_system.approval.requested", "ai_system.approval.approved", "ai_system.approval.granted", "ai_system.approval.denied"):
            assert action in by_action, action
            node_id = by_action[action].payload["evidence_node_id"]
            node = db.get(EvidenceNode, node_id)
            assert node is not None and node.signal_type == action and node.tenant_id == env["tenant_id"]
        assert by_action["ai_system.approval.granted"].actor_user_id == env["users"]["admin"]
        assert by_action["ai_system.approval.requested"].actor_user_id == env["users"]["operator"]


def test_requests_list_says_who_may_approve(env):
    system_id = _system(env, risk_tier="HIGH")
    _ask(env, system_id, who="admin")
    for person, may in (("admin", False), ("owner", True), ("operator", False)):
        listed = env["client"].get("/ai-system-approvals", headers=env["headers"][person])
        assert listed.status_code == 200
        item = listed.json()["items"][0]
        assert item["may_approve"] is may, person
        assert item["approvals_needed"] == 2 and item["allowed_scopes"] == ["one_time", "time_bound"]
    assert env["client"].get("/ai-system-approvals", headers=env["headers"]["viewer"], params={"status": "nope"}).status_code == 400
    # Asking needs an inventory operator; viewers and auditors only read.
    other = _system(env, risk_tier="LOW", name="Other")
    for person in ("viewer", "auditor"):
        assert env["client"].post(f"/ai-systems/{other}/approval-requests", headers=env["headers"][person], json={}).status_code == 403


# ---- Upgrade ----------------------------------------------------------------------------------------------------------


def test_upgrade_keeps_what_was_approved_as_blanket():
    path = Path(__file__).resolve().parents[1] / "app/db/migrations/versions/0102_ai_system_approval_policy.py"
    spec = importlib.util.spec_from_file_location("migration_0102", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.down_revision == "0101_github_agent_controls"
    approved = module._approved_now
    assert approved("approved", {"governance_state": "APPROVED"})
    assert approved("draft", {"governance_state": "APPROVED"})
    assert approved("active", {})
    assert approved("live", {"lifecycle_state": "LIVE"})
    assert not approved("draft", {})
    assert not approved("approved", {"governance_state": "REVIEW"})
    assert not approved("approved", {"governance_state": "APPROVED", "compliance_state": "NON_COMPLIANT"})
    assert not approved("approved", {"governance_state": "APPROVED", "ownership_state": "MISSING"})
    # A system carried over (metadata approval with no expiry, blanket) reads as approved.
    row = AISystem(id="x", tenant_id="t", name="n", risk_tier="LOW", status="approved", metadata_json={
        "governance_state": "APPROVED",
        "approval": {"grant_id": "g", "scope": "blanket", "state": "active", "origin": "upgrade", "expires_at": None},
    })
    from app.services.governance_resolution import ai_system_is_approved

    assert ai_system_is_approved(row)
    # And one with no approval record at all (made before the workflow, not migrated) is read as before.
    assert ai_system_is_approved(AISystem(id="y", tenant_id="t", name="n", risk_tier="LOW", status="approved", metadata_json={"governance_state": "APPROVED"}))
