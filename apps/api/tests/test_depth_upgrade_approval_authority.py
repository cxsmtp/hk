from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.api.routers import ai_iam as ai_iam_router
from app.api.routers.enforcement import ApprovalDecisionRequest, decide_approval
from app.core.tenant import TenantContext
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.audit import AuditLog
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ApprovalBinding, ApprovalRequest
from app.db.models.runtime_intelligence import ChainEvent
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.services.agentic_action_integrity_service import bind_or_verify_approval
from app.services.agui.context import AGUIExecutionContext
from app.services.agui.core_actions import _exec_aiiam_approve_token_mint
from app.services.ai_iam_service import (
    consume_jit_token_mint_approval,
    mint_capability_token_with_authority,
)
from app.jobs import enforcement_jobs


@pytest.fixture()
def authority_env(tmp_path):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'approval-authority.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    with session_local() as db:
        suffix = uuid4().hex[:8]
        tenant = Tenant(name="Approval Authority", slug=f"approval-authority-{suffix}", is_active=True)
        foreign_tenant = Tenant(name="Foreign Authority", slug=f"foreign-authority-{suffix}", is_active=True)
        approver = User(
            email=f"approver-{suffix}@example.com",
            hashed_password="x",
            full_name="Persisted Approver",
            is_active=True,
        )
        caller = User(
            email=f"caller-{suffix}@example.com",
            hashed_password="x",
            full_name="Untrusted Caller",
            is_active=True,
        )
        db.add_all([tenant, foreign_tenant, approver, caller])
        db.flush()
        db.add_all(
            [
                UserTenantRole(user_id=approver.id, tenant_id=tenant.id, role="owner"),
                UserTenantRole(user_id=caller.id, tenant_id=tenant.id, role="admin"),
            ]
        )
        ai_system = AISystem(
            tenant_id=tenant.id,
            name="High Risk Agent System",
            description="approval authority test",
            risk_tier="HIGH",
            status="active",
            metadata_json={},
        )
        agent = AgentIdentity(
            tenant_id=tenant.id,
            name="Approval-bound Agent",
            description="authority test",
            status="active",
            max_chain_depth=3,
            capability_inheritance=False,
        )
        db.add_all([ai_system, agent])
        db.commit()
        ids = {
            "tenant_id": tenant.id,
            "foreign_tenant_id": foreign_tenant.id,
            "approver_id": approver.id,
            "caller_id": caller.id,
            "ai_system_id": ai_system.id,
            "agent_id": agent.id,
        }
    try:
        yield session_local, ids
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _ctx(ids: dict[str, str]) -> AGUIExecutionContext:
    return AGUIExecutionContext(
        tenant_id=ids["tenant_id"],
        user_id=ids["caller_id"],
        user_role="admin",
    )


def _jit_request(db: Session, ids: dict[str, str], **overrides) -> ApprovalRequest:
    values = {
        "tenant_id": ids["tenant_id"],
        "enforcement_event_id": None,
        "ai_system_id": ids["ai_system_id"],
        "request_payload": {
            "type": "jit_token_mint",
            "agent_id": ids["agent_id"],
            "scopes": ["records.read"],
            "chain_depth": 1,
            "expires_minutes": 60,
        },
        "required_roles": ["owner", "admin"],
        "sla_minutes": 30,
        "default_if_timeout": "block",
        "status": "approved",
        "decision": "approve",
        "decided_by": ids["approver_id"],
        "decided_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    row = ApprovalRequest(**values)
    db.add(row)
    db.flush()
    return row


def _canonical_action(ids: dict[str, str]) -> dict:
    return {
        "action_type": "mcp_tool_call",
        "action_id": "action-123",
        "tool_name": "create_webhook",
        "tool_version": "1.0.0",
        "tool_fingerprint": "fp-approved",
        "arguments": {"target": "support_queue"},
        "target_resource": "support_queue",
        "affected_resources": ["support_queue"],
        "identity_scope": ["workflow:create"],
        "data_destination": "internal",
        "side_effect_class": "persistent_write",
        "persistence_risk": "persistent",
        "external_destination": "",
        "time_window": "30m",
        "requester_agent_id": ids["agent_id"],
    }


def _binding_request(db: Session, ids: dict[str, str], action: dict, **overrides) -> ApprovalRequest:
    values = {
        "tenant_id": ids["tenant_id"],
        "enforcement_event_id": None,
        "ai_system_id": ids["ai_system_id"],
        "request_payload": {
            "type": "agentic_action_approval",
            "chain_id": "chain-authority",
            "canonical_action": action,
        },
        "required_roles": ["owner", "admin"],
        "sla_minutes": 30,
        "default_if_timeout": "block",
        "status": "approved",
        "decision": "approve",
        "decided_by": ids["approver_id"],
        "decided_at": datetime.now(timezone.utc),
    }
    values.update(overrides)
    row = ApprovalRequest(**values)
    db.add(row)
    db.flush()
    return row


def _agui_mint(
    db: Session,
    ids: dict[str, str],
    approval_request_id: str | None = None,
    *,
    expires_minutes: int = 60,
):
    payload = {
        "agent_id": ids["agent_id"],
        "ai_system_id": ids["ai_system_id"],
        "scopes": ["records.read"],
        "chain_depth": 1,
        "expires_minutes": expires_minutes,
    }
    if approval_request_id is not None:
        payload["approval_request_id"] = approval_request_id
    return _exec_aiiam_approve_token_mint(db, _ctx(ids), None, "approve", None, [], payload)


def test_agui_cannot_mint_high_risk_token_from_caller_decision_alone(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        with pytest.raises(ValueError, match="approved.*request|approval request"):
            _agui_mint(db, ids)
        assert db.scalar(select(CapabilityToken).where(CapabilityToken.tenant_id == ids["tenant_id"])) is None


def test_approved_jit_request_mints_once_and_is_consumed(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        approval = _jit_request(db, ids)
        approval_id = approval.id
        result = _agui_mint(db, ids, approval_id)
        db.commit()
        assert result["token_id"]
        assert db.get(ApprovalRequest, approval_id).status == "used"

        with pytest.raises(ValueError, match="approved.*request|already.*used|consume"):
            _agui_mint(db, ids, approval_id)
        assert len(db.scalars(select(CapabilityToken)).all()) == 1


def test_agui_rejects_token_lifetime_above_approved_max_without_consuming(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        approval = _jit_request(db, ids)
        with pytest.raises(ValueError, match="lifetime|expires_minutes|does not match"):
            _agui_mint(db, ids, approval.id, expires_minutes=61)
        assert db.get(ApprovalRequest, approval.id).status == "approved"
        assert db.scalar(select(CapabilityToken)) is None


def test_rest_rejects_token_lifetime_above_approved_max_without_consuming(authority_env, monkeypatch):
    session_local, ids = authority_env
    monkeypatch.setattr(ai_iam_router, "enforce_fail_secure_or_raise", lambda *args, **kwargs: None)
    with session_local() as db:
        approval = _jit_request(db, ids)
        tenant = db.get(Tenant, ids["tenant_id"])
        with pytest.raises(HTTPException) as exc_info:
            ai_iam_router.mint_token(
                ids["agent_id"],
                ai_iam_router.MintTokenRequest(
                    ai_system_id=ids["ai_system_id"],
                    scopes=["records.read"],
                    chain_depth=1,
                    expires_minutes=61,
                    approval_request_id=approval.id,
                ),
                TenantContext(tenant=tenant, role="admin", user=db.get(User, ids["caller_id"])),
                db,
            )
        assert exc_info.value.status_code == 400
        assert db.get(ApprovalRequest, approval.id).status == "approved"
        assert db.scalar(select(CapabilityToken)) is None


def test_legacy_jit_approval_without_lifetime_fails_closed(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        approval = _jit_request(
            db,
            ids,
            request_payload={
                "type": "jit_token_mint",
                "agent_id": ids["agent_id"],
                "scopes": ["records.read"],
                "chain_depth": 1,
            },
        )
        with pytest.raises(ValueError, match="lifetime|expires_minutes|does not match"):
            mint_capability_token_with_authority(
                db,
                tenant_id=ids["tenant_id"],
                ai_system=db.get(AISystem, ids["ai_system_id"]),
                agent_identity_id=ids["agent_id"],
                raw_token="legacy-missing-lifetime",
                scopes=["records.read"],
                expires_minutes=30,
                chain_depth=1,
                issued_by_user_id=ids["caller_id"],
                approval_request_id=approval.id,
            )
        assert approval.status == "approved"


def test_jit_consume_rolls_back_if_sla_crosses_during_conditional_update(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        approval = _jit_request(db, ids, sla_minutes=1)
        db.commit()
        created = approval.created_at.replace(tzinfo=timezone.utc) if approval.created_at.tzinfo is None else approval.created_at
        deadline = created + timedelta(minutes=1)
        moments = iter([deadline - timedelta(microseconds=1), deadline + timedelta(microseconds=1)])
        with pytest.raises(ValueError, match="expired|SLA"):
            consume_jit_token_mint_approval(
                db,
                tenant_id=ids["tenant_id"],
                approval_request_id=approval.id,
                ai_system_id=ids["ai_system_id"],
                agent_id=ids["agent_id"],
                scopes=["records.read"],
                chain_depth=1,
                expires_minutes=30,
                clock=lambda: next(moments),
            )
        db.refresh(approval)
        assert approval.status == "approved"


@pytest.mark.parametrize("missing_field", ["decided_by", "decided_at"])
def test_jit_mint_rejects_approval_without_authenticated_decision_authority(authority_env, missing_field):
    session_local, ids = authority_env
    with session_local() as db:
        approval = _jit_request(db, ids, **{missing_field: None})
        with pytest.raises(ValueError, match="authenticated approval authority"):
            consume_jit_token_mint_approval(
                db,
                tenant_id=ids["tenant_id"],
                approval_request_id=approval.id,
                ai_system_id=ids["ai_system_id"],
                agent_id=ids["agent_id"],
                scopes=["records.read"],
                chain_depth=1,
                expires_minutes=30,
            )
        assert approval.status == "approved"


@pytest.mark.parametrize("invalid_kind", ["foreign_tenant", "expired", "scope_mismatch"])
def test_jit_mint_rejects_foreign_expired_or_scope_mismatched_request(authority_env, invalid_kind):
    session_local, ids = authority_env
    with session_local() as db:
        overrides = {}
        if invalid_kind == "foreign_tenant":
            overrides["tenant_id"] = ids["foreign_tenant_id"]
        elif invalid_kind == "expired":
            overrides["created_at"] = datetime.now(timezone.utc) - timedelta(minutes=31)
        else:
            overrides["request_payload"] = {
                "type": "jit_token_mint",
                "agent_id": ids["agent_id"],
                "scopes": ["records.write"],
                "chain_depth": 1,
            }
        approval = _jit_request(db, ids, **overrides)
        with pytest.raises(ValueError, match="not found|expired|does not match"):
            consume_jit_token_mint_approval(
                db,
                tenant_id=ids["tenant_id"],
                approval_request_id=approval.id,
                ai_system_id=ids["ai_system_id"],
                agent_id=ids["agent_id"],
                scopes=["records.read"],
                chain_depth=1,
                expires_minutes=30,
            )
        assert db.get(ApprovalRequest, approval.id).status == "approved"


def test_jit_approval_consumption_rolls_back_with_token_mint(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        approval = _jit_request(db, ids)
        approval_id = approval.id
        db.commit()
        ai_system = db.get(AISystem, ids["ai_system_id"])
        mint_capability_token_with_authority(
            db,
            tenant_id=ids["tenant_id"],
            ai_system=ai_system,
            agent_identity_id=ids["agent_id"],
            raw_token="rollback-token",
            scopes=["records.read"],
            expires_minutes=30,
            chain_depth=1,
            issued_by_user_id=ids["caller_id"],
            approval_request_id=approval_id,
        )
        assert db.get(ApprovalRequest, approval_id).status == "used"
        db.rollback()

    with session_local() as db:
        assert db.get(ApprovalRequest, approval_id).status == "approved"
        assert db.scalar(select(CapabilityToken).where(CapabilityToken.token_hash.is_not(None))) is None


def test_invalid_token_arguments_do_not_burn_approval_if_caller_commits_after_error(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        approval = _jit_request(db, ids, request_payload={
            "type": "jit_token_mint",
            "agent_id": ids["agent_id"],
            "scopes": ["records.read"],
            "chain_depth": 99,
        })
        approval_id = approval.id
        db.commit()
        with pytest.raises(ValueError, match="max_chain_depth"):
            mint_capability_token_with_authority(
                db,
                tenant_id=ids["tenant_id"],
                ai_system=db.get(AISystem, ids["ai_system_id"]),
                agent_identity_id=ids["agent_id"],
                raw_token="invalid-depth-token",
                scopes=["records.read"],
                expires_minutes=30,
                chain_depth=99,
                issued_by_user_id=ids["caller_id"],
                approval_request_id=approval_id,
            )
        db.commit()

    with session_local() as db:
        assert db.get(ApprovalRequest, approval_id).status == "approved"
        assert db.scalar(select(CapabilityToken)) is None


def test_low_risk_token_mint_remains_compatible_without_approval(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        ai_system = db.get(AISystem, ids["ai_system_id"])
        ai_system.risk_tier = "LOW"
        token, approval_id = mint_capability_token_with_authority(
            db,
            tenant_id=ids["tenant_id"],
            ai_system=ai_system,
            agent_identity_id=ids["agent_id"],
            raw_token="low-risk-token",
            scopes=["records.read"],
            expires_minutes=30,
            chain_depth=1,
            issued_by_user_id=ids["caller_id"],
        )
        assert token.id
        assert approval_id is None


@pytest.mark.parametrize("risk_tier", ["PROHIBITED", "UNKNOWN_BANK_TIER"])
def test_prohibited_or_unknown_risk_requires_exact_single_use_approval(authority_env, risk_tier):
    session_local, ids = authority_env
    with session_local() as db:
        ai_system = db.get(AISystem, ids["ai_system_id"])
        ai_system.risk_tier = risk_tier
        db.flush()

        with pytest.raises(ValueError, match="approved persisted approval request"):
            mint_capability_token_with_authority(
                db,
                tenant_id=ids["tenant_id"],
                ai_system=ai_system,
                agent_identity_id=ids["agent_id"],
                raw_token=f"{risk_tier}-missing-approval",
                scopes=["records.read"],
                expires_minutes=30,
                chain_depth=1,
                issued_by_user_id=ids["caller_id"],
            )

        approval = _jit_request(db, ids)
        token, approval_id = mint_capability_token_with_authority(
            db,
            tenant_id=ids["tenant_id"],
            ai_system=ai_system,
            agent_identity_id=ids["agent_id"],
            raw_token=f"{risk_tier}-approved",
            scopes=["records.read"],
            expires_minutes=30,
            chain_depth=1,
            issued_by_user_id=ids["caller_id"],
            approval_request_id=approval.id,
        )
        assert token.id
        assert approval_id == approval.id
        assert db.get(ApprovalRequest, approval.id).status == "used"

        with pytest.raises(ValueError, match="already.*consumed|approved persisted approval request"):
            mint_capability_token_with_authority(
                db,
                tenant_id=ids["tenant_id"],
                ai_system=ai_system,
                agent_identity_id=ids["agent_id"],
                raw_token=f"{risk_tier}-reused",
                scopes=["records.read"],
                expires_minutes=30,
                chain_depth=1,
                issued_by_user_id=ids["caller_id"],
                approval_request_id=approval.id,
            )


def test_rest_mint_adapter_uses_shared_authority_service(authority_env, monkeypatch):
    session_local, ids = authority_env
    calls = []
    real_shared_mint = ai_iam_router.mint_capability_token_with_authority

    def recording_shared_mint(*args, **kwargs):
        calls.append(kwargs.copy())
        return real_shared_mint(*args, **kwargs)

    monkeypatch.setattr(ai_iam_router, "mint_capability_token_with_authority", recording_shared_mint)
    monkeypatch.setattr(ai_iam_router, "enforce_fail_secure_or_raise", lambda *args, **kwargs: None)
    with session_local() as db:
        approval = _jit_request(db, ids)
        approval.request_payload = {**approval.request_payload, "expires_minutes": 120}
        db.flush()
        tenant = db.get(Tenant, ids["tenant_id"])
        result = ai_iam_router.mint_token(
            ids["agent_id"],
            ai_iam_router.MintTokenRequest(
                ai_system_id=ids["ai_system_id"],
                scopes=["records.read"],
                chain_depth=1,
                approval_request_id=approval.id,
            ),
            TenantContext(tenant=tenant, role="admin", user=db.get(User, ids["caller_id"])),
            db,
        )
        assert result.approval_request_id == approval.id
        assert len(calls) == 1
        assert calls[0]["approval_request_id"] == approval.id


def test_enforcement_decision_records_authenticated_context_user(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        request = _jit_request(db, ids, status="pending", decision=None, decided_by=None, decided_at=None)
        tenant = db.get(Tenant, ids["tenant_id"])
        caller = db.get(User, ids["caller_id"])
        result = decide_approval(
            request.id,
            ApprovalDecisionRequest(decision="approve"),
            TenantContext(tenant=tenant, role="admin", user=caller),
            db,
        )
        assert result.decided_by == ids["caller_id"]


@pytest.mark.parametrize(
    ("required_roles", "ctx_role", "allowed"),
    [
        (["owner"], "admin", False),
        (["owner"], "owner", True),
        ([], "owner", False),
        (["unknown_role"], "owner", False),
    ],
)
def test_enforcement_decision_enforces_normalized_required_roles(authority_env, required_roles, ctx_role, allowed):
    session_local, ids = authority_env
    with session_local() as db:
        request = _jit_request(
            db,
            ids,
            required_roles=required_roles,
            status="pending",
            decision=None,
            decided_by=None,
            decided_at=None,
        )
        tenant = db.get(Tenant, ids["tenant_id"])
        caller = db.get(User, ids["caller_id"])
        if allowed:
            result = decide_approval(
                request.id,
                ApprovalDecisionRequest(decision="approve"),
                TenantContext(tenant=tenant, role=ctx_role, user=caller),
                db,
            )
            assert result.status == "approved"
        else:
            with pytest.raises(HTTPException) as exc_info:
                decide_approval(
                    request.id,
                    ApprovalDecisionRequest(decision="approve"),
                    TenantContext(tenant=tenant, role=ctx_role, user=caller),
                    db,
                )
            assert exc_info.value.status_code == 403
            db.refresh(request)
            assert request.status == "pending"


@pytest.mark.parametrize(
    ("request_kind", "existing_status", "existing_decision"),
    [
        ("jit", "used", "approve"),
        ("binding", "used", "approve"),
        ("jit", "approved", "approve"),
        ("jit", "denied", "deny"),
    ],
)
def test_enforcement_cannot_rearm_or_redecide_non_pending_request(
    authority_env,
    request_kind,
    existing_status,
    existing_decision,
):
    session_local, ids = authority_env
    with session_local() as db:
        if request_kind == "binding":
            request = _binding_request(db, ids, _canonical_action(ids))
        else:
            request = _jit_request(db, ids)
        request.status = existing_status
        request.decision = existing_decision
        original_decider = request.decided_by
        db.commit()
        tenant = db.get(Tenant, ids["tenant_id"])
        caller = db.get(User, ids["caller_id"])

        with pytest.raises(HTTPException) as exc_info:
            decide_approval(
                request.id,
                ApprovalDecisionRequest(decision="approve" if existing_decision == "deny" else "deny"),
                TenantContext(tenant=tenant, role="admin", user=caller),
                db,
            )
        assert exc_info.value.status_code == 409
        db.refresh(request)
        assert request.status == existing_status
        assert request.decision == existing_decision
        assert request.decided_by == original_decider


def test_fabricated_binding_approval_id_fails_before_binding_or_evidence(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        with pytest.raises(ValueError, match="approval request not found"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id="fabricated-approval-id",
                canonical_action=_canonical_action(ids),
                approver_user_id=ids["caller_id"],
            )
        assert db.scalar(select(ApprovalBinding)) is None


def test_binding_requires_explicit_agentic_action_approval_type(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(
            db,
            ids,
            action,
            request_payload={"chain_id": "chain-authority", "canonical_action": action},
        )
        with pytest.raises(ValueError, match="does not match action semantics"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
            )
        assert db.scalar(select(ApprovalBinding)) is None


def test_binding_rejects_oversize_same_prefix_material_instead_of_truncating(authority_env):
    session_local, ids = authority_env
    approved = _canonical_action(ids)
    supplied = _canonical_action(ids)
    shared_prefix = "x" * 128
    approved["tool_name"] = shared_prefix + "-approved-tail"
    supplied["tool_name"] = shared_prefix + "-substituted-tail"
    with session_local() as db:
        approval = _binding_request(db, ids, approved)
        with pytest.raises(ValueError, match="tool_name.*maximum|tool_name.*long"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=supplied,
                approver_user_id=ids["caller_id"],
            )
        assert approval.status == "approved"
        assert db.scalar(select(ApprovalBinding)) is None


def test_binding_action_id_substitution_is_material_drift(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        created = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
        )
        substituted = dict(action)
        substituted["action_id"] = "action-substituted"
        verified = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=substituted,
            approver_user_id=ids["caller_id"],
            verify_binding_id=created["binding_id"],
        )
        assert verified["decision"] == "block"
        assert "action_id" in verified["drifted_fields"]


def test_exact_binding_approval_is_consumed_once_and_uses_server_approver(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        approval_id = approval.id
        result = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval_id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=20),
        )
        binding = db.get(ApprovalBinding, result["binding_id"])
        assert binding.approver_user_id == ids["approver_id"]
        assert db.get(ApprovalRequest, approval_id).status == "used"

        with pytest.raises(ValueError, match="approved.*request|already.*used|consume"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval_id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
            )


def test_binding_stores_shorter_explicit_expiry(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    explicit_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        created = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
            expires_at=explicit_expiry,
        )
        binding = db.get(ApprovalBinding, created["binding_id"])
        stored = binding.expires_at.replace(tzinfo=timezone.utc) if binding.expires_at.tzinfo is None else binding.expires_at
        assert abs((stored - explicit_expiry).total_seconds()) < 1


def test_binding_rejects_past_explicit_expiry_without_consuming(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        with pytest.raises(ValueError, match="expiry.*past|expired"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            )
        assert approval.status == "approved"


def test_binding_creation_rolls_back_if_sla_crosses_during_conditional_update(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action, sla_minutes=1)
        db.commit()
        created = approval.created_at.replace(tzinfo=timezone.utc) if approval.created_at.tzinfo is None else approval.created_at
        deadline = created + timedelta(minutes=1)
        moments = iter([deadline - timedelta(microseconds=1), deadline + timedelta(microseconds=1)])
        with pytest.raises(ValueError, match="expired|SLA"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                clock=lambda: next(moments),
            )
        db.refresh(approval)
        assert approval.status == "approved"
        assert db.scalar(select(ApprovalBinding)) is None


def test_binding_creation_rolls_back_if_shorter_explicit_expiry_crosses_during_update(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action, sla_minutes=30)
        db.commit()
        explicit_expiry = datetime.now(timezone.utc) + timedelta(minutes=1)
        moments = iter(
            [
                explicit_expiry - timedelta(microseconds=1),
                explicit_expiry + timedelta(microseconds=1),
            ]
        )
        evidence_before = len(db.scalars(select(EvidenceNode)).all())
        with pytest.raises(ValueError, match="expired|expiry"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                expires_at=explicit_expiry,
                clock=lambda: next(moments),
            )
        db.refresh(approval)
        assert approval.status == "approved"
        assert db.scalar(select(ApprovalBinding)) is None
        assert len(db.scalars(select(EvidenceNode)).all()) == evidence_before


def test_binding_verification_evidence_uses_persisted_approver_not_caller(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        created = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
        )
        bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
            verify_binding_id=created["binding_id"],
        )
        event_rows = db.scalars(
            select(ChainEvent)
            .where(ChainEvent.chain_id == "chain-authority", ChainEvent.event_type == "approval_bound")
        ).all()
        assert event_rows
        assert {event_row.actor_id for event_row in event_rows} == {ids["approver_id"]}


@pytest.mark.parametrize("binding_state", ["expired", "invalidated", "used"])
def test_existing_binding_rejects_expired_invalidated_or_reused_state(authority_env, binding_state):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        created = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
        )
        binding = db.get(ApprovalBinding, created["binding_id"])
        if binding_state == "expired":
            binding.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        else:
            binding.status = binding_state
        db.commit()

        with pytest.raises(ValueError, match="expired|not active|already.*used"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                verify_binding_id=binding.id,
            )


@pytest.mark.parametrize("mismatch", ["approval_id", "chain_id"])
def test_existing_binding_verification_rejects_authority_identity_mismatch_before_evidence(authority_env, mismatch):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        created = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
        )
        binding_id = created["binding_id"]
        evidence_before = len(db.scalars(select(EvidenceNode)).all())

        with pytest.raises(ValueError, match="does not match"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="different-chain" if mismatch == "chain_id" else "chain-authority",
                approval_id="fabricated-approval" if mismatch == "approval_id" else approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                verify_binding_id=binding_id,
            )
        assert len(db.scalars(select(EvidenceNode)).all()) == evidence_before
        assert db.get(ApprovalBinding, binding_id).status == "active"


def test_existing_binding_conditional_consume_blocks_stale_session_reuse(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as setup_db:
        approval = _binding_request(setup_db, ids, action)
        created = bind_or_verify_approval(
            setup_db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
        )
        binding_id = created["binding_id"]
        approval_id = approval.id

    first = session_local()
    stale = session_local()
    statements = []

    def capture_statement(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement.lower())

    try:
        assert stale.get(ApprovalBinding, binding_id).status == "active"
        event.listen(first.get_bind(), "before_cursor_execute", capture_statement)
        try:
            first_result = bind_or_verify_approval(
                first,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval_id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                verify_binding_id=binding_id,
            )
        finally:
            event.remove(first.get_bind(), "before_cursor_execute", capture_statement)
        assert first_result["decision"] == "allow"
        binding_updates = [sql for sql in statements if sql.lstrip().startswith("update approval_bindings")]
        assert binding_updates
        assert any("status" in sql.split(" where ", 1)[1] for sql in binding_updates if " where " in sql)
        assert any("expires_at" in sql.split(" where ", 1)[1] for sql in binding_updates if " where " in sql)

        with pytest.raises(ValueError, match="already.*used|not active|consume"):
            bind_or_verify_approval(
                stale,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval_id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                verify_binding_id=binding_id,
            )
    finally:
        first.close()
        stale.close()


def test_binding_verification_rolls_back_if_expiry_crosses_after_conditional_update(authority_env):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        approval = _binding_request(db, ids, action)
        expiry = datetime.now(timezone.utc) + timedelta(minutes=1)
        created = bind_or_verify_approval(
            db,
            tenant_id=ids["tenant_id"],
            chain_id="chain-authority",
            approval_id=approval.id,
            canonical_action=action,
            approver_user_id=ids["caller_id"],
            expires_at=expiry,
        )
        binding_id = created["binding_id"]
        evidence_before = len(db.scalars(select(EvidenceNode)).all())
        moments = iter([expiry - timedelta(microseconds=1), expiry + timedelta(microseconds=1)])
        with pytest.raises(ValueError, match="expired"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
                verify_binding_id=binding_id,
                clock=lambda: next(moments),
            )
        assert db.get(ApprovalBinding, binding_id).status == "active"
        assert len(db.scalars(select(EvidenceNode)).all()) == evidence_before


def test_enforcement_rejects_preexpired_pending_request(authority_env):
    session_local, ids = authority_env
    with session_local() as db:
        request = _jit_request(
            db,
            ids,
            status="pending",
            decision=None,
            decided_by=None,
            decided_at=None,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=31),
        )
        db.commit()
        with pytest.raises(HTTPException) as exc_info:
            decide_approval(
                request.id,
                ApprovalDecisionRequest(decision="approve"),
                TenantContext(tenant=db.get(Tenant, ids["tenant_id"]), role="owner", user=db.get(User, ids["caller_id"])),
                db,
            )
        assert exc_info.value.status_code == 409
        db.refresh(request)
        assert request.status == "pending"


def test_enforcement_rolls_back_if_sla_crosses_after_conditional_update(authority_env, monkeypatch):
    session_local, ids = authority_env
    with session_local() as db:
        request = _jit_request(
            db,
            ids,
            status="pending",
            decision=None,
            decided_by=None,
            decided_at=None,
            sla_minutes=1,
        )
        db.commit()
        created = request.created_at.replace(tzinfo=timezone.utc) if request.created_at.tzinfo is None else request.created_at
        deadline = created + timedelta(minutes=1)
        moments = iter([deadline - timedelta(microseconds=1), deadline + timedelta(microseconds=1)])
        monkeypatch.setattr("app.api.routers.enforcement._utcnow", lambda: next(moments), raising=False)
        with pytest.raises(HTTPException) as exc_info:
            decide_approval(
                request.id,
                ApprovalDecisionRequest(decision="approve"),
                TenantContext(tenant=db.get(Tenant, ids["tenant_id"]), role="owner", user=db.get(User, ids["caller_id"])),
                db,
            )
        assert exc_info.value.status_code == 409
        db.refresh(request)
        assert request.status == "pending"


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("tool_name", False),
        ("tool_name", 0),
        ("tool_name", None),
        ("affected_resources", ""),
        ("affected_resources", False),
        ("arguments", ""),
        ("arguments", []),
        ("arguments", None),
    ],
)
def test_binding_rejects_noncanonical_material_types(authority_env, field, bad_value):
    session_local, ids = authority_env
    approved = _canonical_action(ids)
    supplied = _canonical_action(ids)
    supplied[field] = bad_value
    with session_local() as db:
        approval = _binding_request(db, ids, approved)
        with pytest.raises(ValueError, match="must be"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=supplied,
                approver_user_id=ids["caller_id"],
            )
        assert approval.status == "approved"


def test_timeout_worker_stale_session_cannot_overwrite_decision_winner(authority_env, monkeypatch):
    session_local, ids = authority_env
    with session_local() as setup:
        request = _jit_request(
            setup,
            ids,
            status="pending",
            decision=None,
            decided_by=None,
            decided_at=None,
            sla_minutes=30,
        )
        setup.commit()
        approval_id = request.id

    stale = session_local()
    stale_request = stale.get(ApprovalRequest, approval_id)
    assert stale_request.status == "pending"

    with session_local() as winner:
        decide_approval(
            approval_id,
            ApprovalDecisionRequest(decision="approve"),
            TenantContext(
                tenant=winner.get(Tenant, ids["tenant_id"]),
                role="owner",
                user=winner.get(User, ids["caller_id"]),
            ),
            winner,
        )

    future = datetime.now(timezone.utc) + timedelta(hours=1)

    class FutureDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return future if tz is not None else future.replace(tzinfo=None)

    monkeypatch.setattr(enforcement_jobs, "SessionLocal", lambda: stale)
    monkeypatch.setattr(enforcement_jobs, "datetime", FutureDateTime)

    class StaleResult:
        @staticmethod
        def all():
            return [stale_request]

    monkeypatch.setattr(stale, "scalars", lambda _query: StaleResult())
    result = enforcement_jobs.resolve_timed_out_approvals.run(tenant_id=ids["tenant_id"], batch_limit=10)
    assert result["resolved_count"] == 0

    with session_local() as verify:
        persisted = verify.get(ApprovalRequest, approval_id)
        assert persisted.status == "approved"
        assert persisted.decision == "approve"
        assert verify.scalar(
            select(AuditLog).where(
                AuditLog.resource_id == approval_id,
                AuditLog.action == "approval.timeout.auto_resolve",
            )
        ) is None


@pytest.mark.parametrize("invalid_kind", ["foreign_tenant", "expired", "mismatched_action"])
def test_binding_rejects_foreign_expired_or_mismatched_request(authority_env, invalid_kind):
    session_local, ids = authority_env
    action = _canonical_action(ids)
    with session_local() as db:
        overrides = {}
        if invalid_kind == "foreign_tenant":
            overrides["tenant_id"] = ids["foreign_tenant_id"]
        elif invalid_kind == "expired":
            overrides["created_at"] = datetime.now(timezone.utc) - timedelta(minutes=31)
        else:
            changed = dict(action)
            changed["arguments"] = {"target": "admin_users"}
            overrides["request_payload"] = {
                "type": "agentic_action_approval",
                "chain_id": "chain-authority",
                "canonical_action": changed,
            }
        approval = _binding_request(db, ids, action, **overrides)

        with pytest.raises(ValueError, match="not found|expired|does not match"):
            bind_or_verify_approval(
                db,
                tenant_id=ids["tenant_id"],
                chain_id="chain-authority",
                approval_id=approval.id,
                canonical_action=action,
                approver_user_id=ids["caller_id"],
            )
        assert db.scalar(select(ApprovalBinding)) is None
