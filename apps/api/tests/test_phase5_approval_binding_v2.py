from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def test_approved_v2_request_creates_a_binding_for_the_exact_stored_decision(tmp_path) -> None:
    from app.db.models.action_integrity import ApprovalBindingV2Extension, TenantActionIntegrityRollout, TenantPolicyEpoch
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
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'approval-binding-v2.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Approval", slug="approval-binding-v2", is_active=True)
            approver = User(email="approval-binding@example.test", hashed_password="x", full_name="Approver", is_active=True)
            db.add_all([tenant, approver])
            db.flush()
            system = AISystem(tenant_id=tenant.id, name="approval", description="test", risk_tier="HIGH", status="active", metadata_json={})
            db.add_all([
                system,
                TenantPolicyEpoch(tenant_id=tenant.id, epoch=1),
                TenantActionIntegrityRollout(tenant_id=tenant.id, mode="AUTHORITATIVE", policy_epoch=1),
            ])
            db.flush()
            tenant_id, system_id, approver_id = tenant.id, system.id, approver.id
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        provider.add_key(purpose="approval_binding_signing", tenant_id=tenant_id, key_id="approval", secret=b"a" * 32)
        provider.add_key(purpose="permitted_variation_signing", tenant_id=tenant_id, key_id="variation", secret=b"v" * 32)
        with session_local.begin() as db:
            action = build_trusted_execution_action(
                tenant_id=tenant_id, action_id="approval-binding-action", chain_id="approval-binding-chain",
                actor_principal="user:requester", executing_principal="service:test", operation="tool_execution",
                tool_or_service_ref="test:approval", tool_fingerprint="f" * 64,
                parameter_hash="p" * 64, target_ref="resource:approval", policy_epoch=1,
                approval_requirement="required", policy_version_id="policy:approval", now=now,
            )
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id=tenant_id, action=action, now=now,
                authoritative_decision="REQUIRE_APPROVAL",
            )
            request = ApprovalRequest(
                tenant_id=tenant_id, ai_system_id=system_id, decision_receipt_id=fixture.decision_receipt_id,
                request_payload={
                    "canonical_action": fixture.action,
                    "decision_receipt_id": fixture.decision_receipt_id,
                    "profile_selection_id": fixture.profile_selection_id,
                    "profile_selection_hash": fixture.profile_selection_hash,
                    "control_selection_id": fixture.control_selection_id,
                    "use_limit": 1,
                },
                required_roles=["owner"], sla_minutes=10, default_if_timeout="deny", status="pending",
                authority_schema_version="2.0", decision_version=1, created_at=now,
            )
            db.add(request)
            db.flush()
            request_id = request.id
        with session_local.begin() as db:
            result = decide_approval_request_v2(
                db, tenant_id=tenant_id, approval_request_id=request_id,
                actor=SimpleNamespace(id=approver_id, role="owner"),
                dto=SimpleNamespace(decision="approve", expected_version=1, idempotency_key="binding-approval", reason="reviewed"),
                signing_provider=provider, now=now,
            )
            binding = db.scalar(select(ApprovalBindingV2Extension).where(ApprovalBindingV2Extension.approval_request_id == request_id))
            assert result.result == "APPLIED"
            assert binding is not None
            assert binding.decision_receipt_id == fixture.decision_receipt_id
            assert binding.profile_selection_id == fixture.profile_selection_id
            assert binding.control_selection_id == fixture.control_selection_id
            assert binding.use_limit == 1
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
