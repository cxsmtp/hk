from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def test_same_v2_approval_idempotency_key_replays_without_a_second_authority_event(tmp_path) -> None:
    from app.db.models.action_integrity import ApprovalAuthorityEventV2, ApprovalAuthorityProjectionV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.ai_system import AISystem
    from app.db.models.policy import ApprovalRequest
    from app.db.models.tenant import Tenant
    from app.db.models.user import User
    from app.db.session import Base
    from app.services.action_integrity.approval_service import decide_approval_request_v2
    from app.services.action_integrity.execution_authority import build_trusted_execution_action
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'approval-atomicity.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Atomic", slug="approval-atomicity", is_active=True)
            owner = User(email="approval-atomicity@example.test", hashed_password="x", full_name="Owner", is_active=True)
            db.add_all([tenant, owner])
            db.flush()
            system = AISystem(tenant_id=tenant.id, name="atomic", description="test", risk_tier="HIGH", status="active", metadata_json={})
            db.add_all([system, TenantPolicyEpoch(tenant_id=tenant.id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1)])
            db.flush()
            tenant_id, system_id, owner_id = tenant.id, system.id, owner.id
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        provider.add_key(purpose="approval_binding_signing", tenant_id=tenant_id, key_id="approval", secret=b"a" * 32)
        provider.add_key(purpose="permitted_variation_signing", tenant_id=tenant_id, key_id="variation", secret=b"v" * 32)
        with session_local.begin() as db:
            action = build_trusted_execution_action(
                tenant_id=tenant_id, action_id="approval-atomic-action", chain_id="approval-atomic-chain",
                actor_principal="user:requester", executing_principal="service:test", operation="tool_execution",
                tool_or_service_ref="test:atomic", tool_fingerprint="f" * 64,
                parameter_hash="p" * 64, target_ref="resource:atomic", policy_epoch=1,
                approval_requirement="required", policy_version_id="policy:atomic", now=now,
            )
            fixture = seed_stored_allow_authority(db, provider=provider, tenant_id=tenant_id, action=action, now=now, authoritative_decision="REQUIRE_APPROVAL")
            request = ApprovalRequest(
                tenant_id=tenant_id, ai_system_id=system_id, decision_receipt_id=fixture.decision_receipt_id,
                request_payload={"canonical_action": fixture.action, "decision_receipt_id": fixture.decision_receipt_id, "profile_selection_id": fixture.profile_selection_id, "profile_selection_hash": fixture.profile_selection_hash, "control_selection_id": fixture.control_selection_id, "use_limit": 1},
                required_roles=["owner"], sla_minutes=10, default_if_timeout="deny", status="pending", authority_schema_version="2.0", decision_version=1, created_at=now,
            )
            db.add(request)
            db.flush()
            request_id = request.id
        dto = SimpleNamespace(decision="approve", expected_version=1, idempotency_key="atomic-approval-key", reason="reviewed")
        actor = SimpleNamespace(id=owner_id, role="owner")
        with session_local.begin() as db:
            assert decide_approval_request_v2(db, tenant_id=tenant_id, approval_request_id=request_id, actor=actor, dto=dto, signing_provider=provider, now=now).result == "APPLIED"
        with session_local.begin() as db:
            replay = decide_approval_request_v2(db, tenant_id=tenant_id, approval_request_id=request_id, actor=actor, dto=dto, signing_provider=provider, now=now)
            events = list(db.scalars(select(ApprovalAuthorityEventV2).where(ApprovalAuthorityEventV2.approval_request_id == request_id)))
            projection = db.scalar(select(ApprovalAuthorityProjectionV2).where(ApprovalAuthorityProjectionV2.approval_request_id == request_id))
            assert replay.result == "REPLAYED"
            assert len(events) == 1
            assert projection is not None and projection.state == "APPROVED" and projection.history_head_sequence == 1
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
