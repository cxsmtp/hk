from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


def test_permit_failure_is_terminal_and_replay_never_invokes_the_callback(tmp_path) -> None:
    from app.db.models.action_integrity import ExecutionPermitAttemptV2, ExecutionPermitV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority, build_trusted_execution_action
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'execution-permit.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-permit", name="Permit", slug="execution-permit", is_active=True))
            db.add_all([
                TenantPolicyEpoch(tenant_id="tenant-permit", epoch=1),
                TenantActionIntegrityRollout(tenant_id="tenant-permit", mode="AUTHORITATIVE", policy_epoch=1),
            ])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id="tenant-permit")
        with session_local.begin() as db:
            action = build_trusted_execution_action(
                tenant_id="tenant-permit", action_id="permit-action", chain_id="permit-chain",
                actor_principal="user:owner", executing_principal="service:test", operation="tool_execution",
                tool_or_service_ref="test:permit", tool_fingerprint="f" * 64,
                parameter_hash="p" * 64, target_ref="resource:permit", policy_epoch=1,
                approval_requirement="not_required", policy_version_id="policy:permit", now=now,
            )
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id="tenant-permit", action=action, now=now,
            )
            permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                tenant_id="tenant-permit", action=fixture.action, expires_at=now + timedelta(minutes=1),
                rollout_mode="AUTHORITATIVE", decision_receipt_id=fixture.decision_receipt_id,
            )
        with session_local() as db:
            attempt = db.scalar(
                select(ExecutionPermitAttemptV2).where(
                    ExecutionPermitAttemptV2.tenant_id == "tenant-permit",
                    ExecutionPermitAttemptV2.attempt_id == permit.attempt_id,
                )
            )
            assert attempt is not None
            assert attempt.decision_receipt_id == fixture.decision_receipt_id
            assert attempt.execution_permit_id == permit.permit_id
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            with pytest.raises(RuntimeError, match="downstream failed"):
                authority.execute(
                    permit.permit_id, tenant_id="tenant-permit", action=fixture.action,
                    claimed_by_ref="test.seam",
                    executor=lambda: (_ for _ in ()).throw(RuntimeError("downstream failed")),
                )
        with session_local() as db:
            row = db.get(ExecutionPermitV2, permit.permit_id)
            assert row is not None and row.state == "UNKNOWN"
            callbacks: list[str] = []
            assert ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                permit.permit_id, tenant_id="tenant-permit", action=fixture.action,
                claimed_by_ref="test.replay", executor=lambda: callbacks.append("called"),
            ) == (False, None)
            assert callbacks == []
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_cross_substituted_attempt_authority_blocks_the_final_callback(tmp_path) -> None:
    """A real but different decision/permit pair cannot authorize this attempt."""
    from app.db.models.action_integrity import ExecutionPermitAttemptV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority, build_trusted_execution_action
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'execution-permit-cross-substitution.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with session_local.begin() as db:
            db.add(Tenant(id="tenant-cross", name="Cross", slug="execution-permit-cross", is_active=True))
            db.add_all([
                TenantPolicyEpoch(tenant_id="tenant-cross", epoch=1),
                TenantActionIntegrityRollout(tenant_id="tenant-cross", mode="AUTHORITATIVE", policy_epoch=1),
            ])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id="tenant-cross")
        with session_local.begin() as db:
            action = build_trusted_execution_action(
                tenant_id="tenant-cross", action_id="cross-action", chain_id="cross-chain",
                actor_principal="user:owner", executing_principal="service:test", operation="tool_execution",
                tool_or_service_ref="test:cross", tool_fingerprint="f" * 64,
                parameter_hash="p" * 64, target_ref="resource:cross", policy_epoch=1,
                approval_requirement="not_required", policy_version_id="policy:cross", now=now,
            )
            other_action = build_trusted_execution_action(
                tenant_id="tenant-cross", action_id="cross-action-other", chain_id="cross-chain-other",
                actor_principal="user:owner", executing_principal="service:test", operation="tool_execution",
                tool_or_service_ref="test:cross", tool_fingerprint="f" * 64,
                parameter_hash="q" * 64, target_ref="resource:cross-other", policy_epoch=1,
                approval_requirement="not_required", policy_version_id="policy:cross", now=now,
            )
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id="tenant-cross", action=action,
                decision_receipt_id="decision-cross-primary", now=now,
            )
            other_fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id="tenant-cross", action=other_action,
                decision_receipt_id="decision-cross-other", now=now,
            )
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            permit = authority.issue(
                tenant_id="tenant-cross", action=fixture.action, expires_at=now + timedelta(minutes=1),
                rollout_mode="AUTHORITATIVE", decision_receipt_id=fixture.decision_receipt_id,
            )
            other_permit = authority.issue(
                tenant_id="tenant-cross", action=other_fixture.action, expires_at=now + timedelta(minutes=1),
                rollout_mode="AUTHORITATIVE", decision_receipt_id=other_fixture.decision_receipt_id,
            )
            attempt = db.scalar(
                select(ExecutionPermitAttemptV2).where(
                    ExecutionPermitAttemptV2.tenant_id == "tenant-cross",
                    ExecutionPermitAttemptV2.attempt_id == permit.attempt_id,
                )
            )
            assert attempt is not None
            assert attempt.decision_receipt_id == fixture.decision_receipt_id
            assert attempt.execution_permit_id == permit.permit_id
            # Simulate a corrupted persisted association: both substituted IDs
            # are real authority records, but belong to another action/attempt.
            attempt.decision_receipt_id = other_fixture.decision_receipt_id
            attempt.execution_permit_id = other_permit.permit_id

        with session_local() as db:
            callbacks: list[str] = []
            assert ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                permit.permit_id, tenant_id="tenant-cross", action=fixture.action,
                claimed_by_ref="test.cross", executor=lambda: callbacks.append("called"),
            ) == (False, None)
            assert callbacks == []
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
