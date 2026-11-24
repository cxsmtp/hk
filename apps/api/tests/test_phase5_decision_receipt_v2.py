from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def test_signed_decision_receipt_binds_current_profile_and_native_authority(tmp_path) -> None:
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import build_trusted_execution_action
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.action_integrity.stored_authority import require_current_decision_authority_v1
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'decision-receipt-v2.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-decision", name="Decision", slug="decision-v2", is_active=True))
            db.add_all([
                TenantPolicyEpoch(tenant_id="tenant-decision", epoch=1),
                TenantActionIntegrityRollout(tenant_id="tenant-decision", mode="AUTHORITATIVE", policy_epoch=1),
            ])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id="tenant-decision")
        with session_local.begin() as db:
            action = build_trusted_execution_action(
                tenant_id="tenant-decision", action_id="decision-action", chain_id="decision-chain",
                actor_principal="user:owner", executing_principal="service:test", operation="tool_execution",
                tool_or_service_ref="test:decision", tool_fingerprint="f" * 64,
                parameter_hash="p" * 64, target_ref="resource:decision", policy_epoch=1,
                approval_requirement="not_required", policy_version_id="policy:decision", now=now,
            )
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id="tenant-decision", action=action, now=now,
            )
            decision, authority = require_current_decision_authority_v1(
                db, provider=provider, tenant_id="tenant-decision",
                decision_receipt_id=fixture.decision_receipt_id, action=fixture.action, now=now,
            )
            envelope = decision.signed_envelope
            assert envelope["phase5_canonical_action_hash_domain"] == "hawk:canonical-ai-action:v2"
            assert envelope["base_receipt_canonical_action_hash_domain"] == "hawk:decision-receipt-canonical-action:v1"
            assert envelope["native_authorization_action_hash_domain"] == "hawk:native-control-authorization-request:v1"
            assert authority.selection.selection_id == fixture.profile_selection_id
            assert authority.native_selection.selection_id == fixture.control_selection_id

            altered = {**fixture.action, "control_plan_digest": "0" * 64}
            with pytest.raises(PermissionError):
                require_current_decision_authority_v1(
                    db, provider=provider, tenant_id="tenant-decision",
                    decision_receipt_id=fixture.decision_receipt_id, action=altered,
                    now=now + timedelta(seconds=1),
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
