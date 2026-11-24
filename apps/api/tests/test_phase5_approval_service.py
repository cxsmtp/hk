from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def test_v2_approval_service_is_available() -> None:
    from app.services.action_integrity.approval_service import decide_approval_request_v2

    assert callable(decide_approval_request_v2)


def test_v2_approval_result_has_deterministic_replay_shape() -> None:
    from app.services.action_integrity.approval_service import ApprovalDecisionResult

    result = ApprovalDecisionResult(result="APPLIED", approval_request_id="request-1", binding_id=None)
    assert result.result == "APPLIED"


def _canonical_action(tenant_id: str) -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "tenant_id": tenant_id,
        "action_id": "action-1",
        "chain_id": "chain-1",
        "correlation_id": "correlation-1",
        "parent_action_id": None,
        "actor_principal": "principal:requester",
        "executing_principal": "principal:agent",
        "represented_subjects": ["subject:customer-1"],
        "resource_scopes": ["resource:account-1"],
        "authority_context": "authority:delegated-1",
        "business_purpose": "purpose:payment",
        "environment": "production",
        "provider_runtime_context": "runtime:api",
        "action_semantics": {
            "action_class": "consequential",
            "operation": "transfer",
            "object_type": "payment",
            "tool_or_service_ref": "service:payments",
            "tool_fingerprint": "tool:v1",
            "safe_parameters": {"currency": "USD"},
            "represented_subject_refs": ["subject:customer-1"],
            "resource_refs": ["resource:account-1"],
            "counterparty_refs": [],
            "target_refs": ["target:recipient-1"],
            "destination_refs": ["destination:account-2"],
            "values_or_quantities": [{"value": "10", "currency": "USD"}],
            "authority_ref": "authority:delegated-1",
            "business_purpose_ref": "purpose:payment",
            "side_effect": "external_write",
            "persistence": "none",
            "environment": "production",
            "reversibility": "compensatable",
            "expected_outcome_ref": "outcome:payment-posted",
        },
        "domain_profile_ref": "profile:neutral",
        "domain_profile_hash": "a" * 64,
        "materiality_profile_ref": "phase5-p0",
        "materiality_profile_hash": "b" * 64,
        "resolver_versions": {},
        "policy_version_id": "policy:1",
        "policy_epoch": 7,
        "control_plan_id": "plan:1",
        "control_plan_digest": "c" * 64,
        "approval_requirement": "required",
        "delegation_digest": "d" * 64,
        "action_plan_binding": {
            "binding_type": "STANDALONE",
            "action_plan_id": None,
            "action_plan_digest": None,
            "action_plan_step_id": None,
            "action_plan_step_digest": None,
        },
        "unresolved_material": [],
        "evidence_refs": [],
        "created_at": "2026-08-24T00:00:00.000000Z",
    }


def test_v2_approval_approve_is_atomic_and_replays_only_the_same_decision(tmp_path) -> None:
    """A V2 approval writes its signed binding/event/projection exactly once."""
    from app.db.models.action_integrity import (
        ApprovalAuthorityEventV2,
        ApprovalAuthorityProjectionV2,
        ApprovalBindingV2Extension,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.db.models.ai_system import AISystem
    from app.db.models.policy import ApprovalRequest
    from app.db.models.tenant import Tenant
    from app.db.models.user import User
    from app.db.session import Base
    from app.services.action_integrity.approval_service import decide_approval_request_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'approval-v2.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            suffix = uuid4().hex[:8]
            tenant = Tenant(name="Phase 5", slug=f"phase5-{suffix}", is_active=True)
            approver = User(email=f"approver-{suffix}@example.test", hashed_password="x", full_name="Approver", is_active=True)
            db.add_all([tenant, approver])
            db.flush()
            system = AISystem(tenant_id=tenant.id, name="phase5", description="test", risk_tier="HIGH", status="active", metadata_json={})
            db.add(system)
            db.flush()
            db.add_all([TenantPolicyEpoch(tenant_id=tenant.id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1)])
            tenant_id, system_id, user_id = tenant.id, system.id, approver.id

        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        provider.add_key(purpose="approval_binding_signing", tenant_id=tenant_id, key_id="approval-key", secret=b"a" * 32)
        provider.add_key(purpose="permitted_variation_signing", tenant_id=tenant_id, key_id="variation-key", secret=b"v" * 32)
        now = datetime.now(timezone.utc)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id=tenant_id,
                action=_canonical_action(tenant_id), now=now,
                authoritative_decision="REQUIRE_APPROVAL",
            )
            request = ApprovalRequest(
                tenant_id=tenant_id, ai_system_id=system_id, decision_receipt_id=fixture.decision_receipt_id,
                request_payload={"canonical_action": fixture.action, "decision_receipt_id": fixture.decision_receipt_id,
                    "profile_selection_id": fixture.profile_selection_id, "profile_selection_hash": fixture.profile_selection_hash,
                    "control_selection_id": fixture.control_selection_id, "use_limit": 1},
                required_roles=["owner"], sla_minutes=10, default_if_timeout="deny", status="pending",
                authority_schema_version="2.0", decision_version=1, created_at=now,
            )
            db.add(request)
            db.flush()
            request_id = request.id
        dto = SimpleNamespace(decision="approve", expected_version=1, idempotency_key="approval-decision-0001", reason="reviewed")
        actor = SimpleNamespace(id=user_id, role="owner")
        with session_local.begin() as db:
            applied = decide_approval_request_v2(db, tenant_id=tenant_id, approval_request_id=request_id, actor=actor, dto=dto, signing_provider=provider, now=now)
            assert applied.result == "APPLIED"
            assert applied.binding_id
            assert applied.binding_hash

        with session_local.begin() as db:
            replay = decide_approval_request_v2(db, tenant_id=tenant_id, approval_request_id=request_id, actor=actor, dto=dto, signing_provider=provider, now=now)
            assert replay.result == "REPLAYED"
            assert replay.binding_id == applied.binding_id
            assert db.scalar(select(ApprovalBindingV2Extension).where(ApprovalBindingV2Extension.approval_request_id == request_id)) is not None
            assert db.scalar(select(ApprovalAuthorityProjectionV2).where(ApprovalAuthorityProjectionV2.approval_request_id == request_id)).state == "APPROVED"
            assert len(db.scalars(select(ApprovalAuthorityEventV2).where(ApprovalAuthorityEventV2.approval_request_id == request_id)).all()) == 1

        # A previously used key cannot turn into an authorization capability.
        # The old implementation returned REPLAYED before checking this role.
        with session_local.begin() as db:
            with pytest.raises(PermissionError, match="role"):
                decide_approval_request_v2(
                    db,
                    tenant_id=tenant_id,
                    approval_request_id=request_id,
                    actor=SimpleNamespace(id=user_id, role="viewer"),
                    dto=dto,
                    signing_provider=provider,
                    now=now,
                )

        with session_local.begin() as db:
            conflict = SimpleNamespace(decision="deny", expected_version=1, idempotency_key="approval-decision-0001", reason="reviewed")
            with pytest.raises(ValueError, match="idempotency"):
                decide_approval_request_v2(db, tenant_id=tenant_id, approval_request_id=request_id, actor=actor, dto=conflict, signing_provider=provider, now=now)

        # A cached projection is never enough: a changed signed predecessor
        # invalidates the fresh fold before a permit can consume authority.
        from app.db.models.action_integrity import ApprovalAuthorityEventV2
        from app.services.action_integrity.execution_authority import ExecutionPermitAuthority

        with session_local.begin() as db:
            event = db.scalar(select(ApprovalAuthorityEventV2).where(ApprovalAuthorityEventV2.approval_request_id == request_id))
            assert event is not None
            tampered = dict(event.signed_envelope)
            tampered["decision"] = "deny"
            event.signed_envelope = tampered
        with session_local.begin() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider)
            with pytest.raises(PermissionError, match="history"):
                authority.issue(
                    tenant_id=tenant_id,
                    action=fixture.action,
                    expires_at=now + timedelta(minutes=1),
                    rollout_mode="AUTHORITATIVE",
                    approval_request_id=request_id,
                    decision_receipt_id=fixture.decision_receipt_id,
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_database_permit_claim_is_atomic_and_never_reopens_after_lease(tmp_path) -> None:
    from app.db.models.action_integrity import ExecutionPermitV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'permit-v2.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Permit tenant", slug=f"permit-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all([TenantPolicyEpoch(tenant_id=tenant_id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        now = datetime.now(timezone.utc)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(db, provider=provider, tenant_id=tenant_id, action={**_canonical_action(tenant_id), "approval_requirement": "not_required"}, now=now)
        with session_local.begin() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            permit = authority.issue(
                tenant_id=tenant_id,
                action=fixture.action,
                expires_at=now + timedelta(minutes=1),
                rollout_mode="AUTHORITATIVE",
                decision_receipt_id=fixture.decision_receipt_id,
            )
            assert authority.claim(permit.permit_id, tenant_id=tenant_id, action=fixture.action, claimed_by_ref="seam:test")
        with session_local.begin() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now + timedelta(seconds=31))
            assert not authority.claim(permit.permit_id, tenant_id=tenant_id, action=fixture.action, claimed_by_ref="seam:retry")
            recovered = db.get(ExecutionPermitV2, permit.permit_id)
            assert recovered is not None and recovered.state == "UNKNOWN" and recovered.state_version == 2
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_permit_claim_commits_before_a_failing_final_callback(tmp_path) -> None:
    """A callback rollback must never put a claimed permit back into circulation."""
    from app.db.models.action_integrity import ExecutionPermitV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'durable-claim.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Durable claim", slug=f"durable-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all([TenantPolicyEpoch(tenant_id=tenant_id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        now = datetime.now(timezone.utc)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(db, provider=provider, tenant_id=tenant_id, action={**_canonical_action(tenant_id), "approval_requirement": "not_required"}, now=now)
        with session_local.begin() as db:
            permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                tenant_id=tenant_id,
                    action=fixture.action,
                    expires_at=now + timedelta(minutes=1),
                    rollout_mode="AUTHORITATIVE",
                    decision_receipt_id=fixture.decision_receipt_id,
            )

        with session_local() as db:
            with pytest.raises(RuntimeError, match="external failure"):
                with db.begin():
                    ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                        permit.permit_id,
                        tenant_id=tenant_id,
                        action=fixture.action,
                        claimed_by_ref="seam:durable-test",
                        executor=lambda: (_ for _ in ()).throw(RuntimeError("external failure")),
                    )

        with session_local() as verifier:
            persisted = verifier.scalar(
                select(ExecutionPermitV2).where(
                    ExecutionPermitV2.tenant_id == tenant_id,
                    ExecutionPermitV2.permit_id == permit.permit_id,
                )
            )
            assert persisted is not None
            assert persisted.state == "UNKNOWN"
            assert persisted.state_version == 2
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_fresh_session_rejects_tampered_transition_and_projection_reset(tmp_path) -> None:
    from app.db.models.action_integrity import ExecutionPermitTransitionV2, ExecutionPermitV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'transition-fold.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Transition fold", slug=f"transition-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all([TenantPolicyEpoch(tenant_id=tenant_id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        now = datetime.now(timezone.utc)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(db, provider=provider, tenant_id=tenant_id, action={**_canonical_action(tenant_id), "approval_requirement": "not_required"}, now=now)
        action = fixture.action
        with session_local.begin() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            permit = authority.issue(tenant_id=tenant_id, action=action, expires_at=now + timedelta(minutes=1), rollout_mode="AUTHORITATIVE", decision_receipt_id=fixture.decision_receipt_id)
            assert authority.claim(permit.permit_id, tenant_id=tenant_id, action=action, claimed_by_ref="seam:test")
        with session_local.begin() as db:
            row = db.scalar(select(ExecutionPermitV2).where(ExecutionPermitV2.permit_id == permit.permit_id))
            transition = db.scalar(select(ExecutionPermitTransitionV2).where(ExecutionPermitTransitionV2.permit_id == permit.permit_id))
            assert row is not None and transition is not None
            tampered = dict(transition.signed_envelope)
            tampered["claimed_by_ref"] = "seam:forged"
            transition.signed_envelope = tampered
            row.state, row.state_version, row.claim_id, row.claimed_by_ref, row.claim_lease_expires_at = "ISSUED", 0, None, None, None
        with session_local.begin() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            assert not authority.claim(permit.permit_id, tenant_id=tenant_id, action=action, claimed_by_ref="seam:retry")
            row = db.scalar(select(ExecutionPermitV2).where(ExecutionPermitV2.permit_id == permit.permit_id))
            assert row is not None and row.reconstruction_status == "INVALID"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_v2_expiry_leaves_a_terminal_fail_closed_request_for_the_caller_to_commit(tmp_path) -> None:
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.ai_system import AISystem
    from app.db.models.policy import ApprovalRequest
    from app.db.models.tenant import Tenant
    from app.db.models.user import User
    from app.db.session import Base
    from app.services.action_integrity.approval_service import ApprovalRequestExpiredError, decide_approval_request_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'approval-expired-v2.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            suffix = uuid4().hex[:8]
            tenant = Tenant(name="Expired approval", slug=f"expired-{suffix}", is_active=True)
            approver = User(email=f"expired-{suffix}@example.test", hashed_password="x", full_name="Approver", is_active=True)
            db.add_all([tenant, approver])
            db.flush()
            system = AISystem(tenant_id=tenant.id, name="phase5-expired", description="test", risk_tier="HIGH", status="active", metadata_json={})
            db.add(system)
            db.flush()
            db.add_all([TenantPolicyEpoch(tenant_id=tenant.id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1)])
            tenant_id, system_id, user_id = tenant.id, system.id, approver.id

        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        now = datetime.now(timezone.utc)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id=tenant_id, action=_canonical_action(tenant_id), now=now,
                authoritative_decision="REQUIRE_APPROVAL",
            )
            request = ApprovalRequest(
                tenant_id=tenant_id, ai_system_id=system_id, decision_receipt_id=fixture.decision_receipt_id,
                request_payload={"canonical_action": fixture.action, "decision_receipt_id": fixture.decision_receipt_id,
                    "profile_selection_id": fixture.profile_selection_id, "profile_selection_hash": fixture.profile_selection_hash,
                    "control_selection_id": fixture.control_selection_id, "use_limit": 1},
                required_roles=["owner"], sla_minutes=1, default_if_timeout="deny", status="pending",
                authority_schema_version="2.0", decision_version=1, created_at=now - timedelta(minutes=2),
            )
            db.add(request)
            db.flush()
            request_id = request.id
        dto = SimpleNamespace(decision="deny", expected_version=1, idempotency_key="expired-decision-0001", reason="late")
        actor = SimpleNamespace(id=user_id, role="owner")
        with session_local.begin() as db:
            with pytest.raises(ApprovalRequestExpiredError, match="expired"):
                decide_approval_request_v2(db, tenant_id=tenant_id, approval_request_id=request_id, actor=actor, dto=dto, signing_provider=provider, now=now)
        with session_local() as db:
            expired = db.get(ApprovalRequest, request_id)
            assert expired is not None
            assert expired.status == "expired"
            assert expired.decision_version == 2
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
