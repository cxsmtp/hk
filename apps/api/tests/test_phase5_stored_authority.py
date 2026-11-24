from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker


def test_signed_profile_selection_advances_only_the_tenant_cas_head(tmp_path) -> None:
    from app.db.models.action_integrity import (
        TenantActionIntegrityRollout,
        TenantDomainProfileSelectionProjectionV2,
        TenantPolicyEpoch,
    )
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.action_integrity.policy_epoch import PolicyEpochService
    from app.services.action_integrity.stored_authority import (
        append_profile_selection_v1,
        issue_domain_semantic_profile_v1,
        require_current_profile_selection_v1,
    )

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'stored-authority.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Stored authority", slug="stored-authority", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all(
                [
                    TenantPolicyEpoch(tenant_id=tenant_id, epoch=1),
                    TenantActionIntegrityRollout(
                        tenant_id=tenant_id,
                        mode="AUTHORITATIVE",
                        policy_epoch=1,
                    ),
                ]
            )

        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="domain_profile_signing", tenant_id=tenant_id, key_id="profile", secret=b"p" * 32)
        provider.add_key(purpose="domain_profile_selection_signing", tenant_id=tenant_id, key_id="selection", secret=b"s" * 32)

        with session_local.begin() as db:
            profile = issue_domain_semantic_profile_v1(
                db,
                provider=provider,
                tenant_id=tenant_id,
                profile_id="profile:payments",
                version="2026.08",
                status="reviewed",
                content={"materiality": "payments"},
                issued_at=now,
                effective_at=now,
                expires_at=now + timedelta(hours=2),
            )
            first = append_profile_selection_v1(
                db,
                provider=provider,
                tenant_id=tenant_id,
                profile=profile,
                policy_epoch=1,
                selected_by_principal_ref="user:owner",
                reason_code="policy-update",
                issued_at=now,
                effective_at=now,
                expires_at=now + timedelta(hours=1),
            )
            projection = db.get(TenantDomainProfileSelectionProjectionV2, tenant_id)
            assert projection is not None
            assert (projection.current_selection_id, projection.current_selection_hash, projection.current_selection_generation, projection.current_selection_sequence, projection.state_version) == (
                first.selection_id,
                first.selection_hash,
                1,
                1,
                1,
            )

            epoch = db.get(TenantPolicyEpoch, tenant_id)
            rollout = db.get(TenantActionIntegrityRollout, tenant_id)
            assert epoch is not None and rollout is not None
            PolicyEpochService(db).bump_material_change(
                tenant_id=tenant_id,
                expected_epoch=1,
                expected_state_version=1,
                current_policy_snapshot_id="policy:stored-authority:v2",
                material_policy_digest="a" * 64,
                actor_principal_ref="user:owner",
                reason_code="policy-update",
            )
            rollout.policy_epoch = 2
            second = append_profile_selection_v1(
                db,
                provider=provider,
                tenant_id=tenant_id,
                profile=profile,
                policy_epoch=2,
                selected_by_principal_ref="user:owner",
                reason_code="policy-update",
                issued_at=now + timedelta(minutes=1),
                effective_at=now + timedelta(minutes=1),
                expires_at=now + timedelta(hours=1),
            )
            assert (second.selection_sequence, second.prior_selection_id, second.prior_selection_hash) == (
                2,
                first.selection_id,
                first.selection_hash,
            )

        with session_local.begin() as db:
            current = require_current_profile_selection_v1(
                db,
                provider=provider,
                tenant_id=tenant_id,
                now=now + timedelta(minutes=2),
            )
            assert current.selection_id == second.selection_id
            assert current.selection_hash == second.selection_hash
            assert current.profile_id == "profile:payments"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_current_profile_authority_rejects_expiry_tamper_rotation_revocation_and_epoch_mismatch(tmp_path) -> None:
    from app.db.models.action_integrity import (
        TenantActionIntegrityRollout,
        TenantDomainProfileSelectionV2,
        TenantPolicyEpoch,
    )
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.action_integrity.policy_epoch import PolicyEpochService
    from app.services.action_integrity.stored_authority import (
        append_profile_selection_v1,
        issue_domain_semantic_profile_v1,
        require_current_profile_selection_v1,
    )

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'stored-authority-negative.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Stored authority negative", slug="stored-authority-negative", is_active=True)
            other = Tenant(name="Other tenant", slug="stored-authority-other", is_active=True)
            db.add_all([tenant, other])
            db.flush()
            tenant_id, other_tenant_id = tenant.id, other.id
            db.add_all(
                [
                    TenantPolicyEpoch(tenant_id=tenant_id, epoch=1),
                    TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1),
                    TenantPolicyEpoch(tenant_id=other_tenant_id, epoch=1),
                    TenantActionIntegrityRollout(tenant_id=other_tenant_id, mode="AUTHORITATIVE", policy_epoch=1),
                ]
            )
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="domain_profile_signing", tenant_id=tenant_id, key_id="profile-v1", secret=b"p" * 32)
        provider.add_key(purpose="domain_profile_selection_signing", tenant_id=tenant_id, key_id="selection-v1", secret=b"s" * 32)
        with session_local.begin() as db:
            first_profile = issue_domain_semantic_profile_v1(
                db, provider=provider, tenant_id=tenant_id, profile_id="profile:first", version="1", status="reviewed",
                content={"tier": "first"}, issued_at=now, effective_at=now, expires_at=now + timedelta(hours=4),
            )
            first = append_profile_selection_v1(
                db, provider=provider, tenant_id=tenant_id, profile=first_profile, policy_epoch=1,
                selected_by_principal_ref="user:owner", reason_code="initial", issued_at=now,
                effective_at=now, expires_at=now + timedelta(hours=3),
            )
            with pytest.raises(ValueError, match="selection authority"):
                append_profile_selection_v1(
                    db, provider=provider, tenant_id=other_tenant_id, profile=first_profile, policy_epoch=1,
                    selected_by_principal_ref="user:owner", reason_code="cross-tenant", issued_at=now,
                    effective_at=now, expires_at=now + timedelta(hours=1),
                )

            provider.set_state(purpose="domain_profile_signing", tenant_id=tenant_id, key_id="profile-v1", state="verify_only")
            provider.set_state(purpose="domain_profile_selection_signing", tenant_id=tenant_id, key_id="selection-v1", state="verify_only")
            provider.add_key(purpose="domain_profile_signing", tenant_id=tenant_id, key_id="profile-v2", secret=b"q" * 32)
            provider.add_key(purpose="domain_profile_selection_signing", tenant_id=tenant_id, key_id="selection-v2", secret=b"t" * 32)
            epoch = db.get(TenantPolicyEpoch, tenant_id)
            rollout = db.get(TenantActionIntegrityRollout, tenant_id)
            assert epoch is not None and rollout is not None
            PolicyEpochService(db).bump_material_change(
                tenant_id=tenant_id,
                expected_epoch=1,
                expected_state_version=1,
                current_policy_snapshot_id="policy:stored-authority-negative:v2",
                material_policy_digest="b" * 64,
                actor_principal_ref="user:owner",
                reason_code="key-rotation",
            )
            rollout.policy_epoch = 2
            second_profile = issue_domain_semantic_profile_v1(
                db, provider=provider, tenant_id=tenant_id, profile_id="profile:second", version="2", status="reviewed",
                content={"tier": "second"}, issued_at=now, effective_at=now, expires_at=now + timedelta(hours=4),
            )
            second = append_profile_selection_v1(
                db, provider=provider, tenant_id=tenant_id, profile=second_profile, policy_epoch=2,
                selected_by_principal_ref="user:owner", reason_code="rotation", issued_at=now + timedelta(minutes=1),
                effective_at=now + timedelta(minutes=1), expires_at=now + timedelta(hours=3),
            )
            assert second.prior_selection_hash == first.selection_hash

        with session_local.begin() as db:
            # Historical verify-only envelopes still reconstruct, while the
            # active head remains eligible to authorize.
            assert require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2)).selection_id == second.selection_id
            with pytest.raises(PermissionError, match="profile selection projection"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(hours=4))

            # The Base.metadata unit database intentionally has no 0069
            # append-only triggers. Mutating an in-memory fixture here proves
            # the service fold itself detects envelope/prior/sequence tamper.
            persisted = db.scalar(select(TenantDomainProfileSelectionV2).where(TenantDomainProfileSelectionV2.selection_id == second.selection_id))
            assert persisted is not None
            original_envelope = dict(persisted.signed_envelope or {})
            original_prior_hash = persisted.prior_selection_hash
            original_sequence = persisted.selection_sequence
            persisted.signed_envelope = {**original_envelope, "reason_code": "tampered"}
            with pytest.raises(PermissionError, match="history"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2))
            persisted.signed_envelope = original_envelope
            persisted.prior_selection_hash = "f" * 64
            with pytest.raises(PermissionError, match="history"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2))
            persisted.prior_selection_hash = original_prior_hash
            persisted.selection_sequence = 3
            with pytest.raises(PermissionError, match="history"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2))
            persisted.selection_sequence = original_sequence

            rollout = db.get(TenantActionIntegrityRollout, tenant_id)
            assert rollout is not None
            rollout.policy_epoch = 3
            with pytest.raises(PermissionError, match="rollout/epoch"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2))
            rollout.policy_epoch = 2

        provider.set_state(purpose="domain_profile_selection_signing", tenant_id=tenant_id, key_id="selection-v2", state="verify_only")
        with session_local.begin() as db:
            with pytest.raises(PermissionError, match="current domain profile"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2))
        provider.set_state(purpose="domain_profile_selection_signing", tenant_id=tenant_id, key_id="selection-v2", state="active")
        provider.set_state(purpose="domain_profile_signing", tenant_id=tenant_id, key_id="profile-v2", state="verify_only")
        with session_local.begin() as db:
            with pytest.raises(PermissionError, match="current domain profile"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2))
        provider.set_state(purpose="domain_profile_signing", tenant_id=tenant_id, key_id="profile-v2", state="active")
        provider.set_state(purpose="domain_profile_selection_signing", tenant_id=tenant_id, key_id="selection-v1", state="revoked")
        with session_local.begin() as db:
            with pytest.raises(PermissionError, match="history"):
                require_current_profile_selection_v1(db, provider=provider, tenant_id=tenant_id, now=now + timedelta(minutes=2))

        # A second child of the same parent cannot be inserted: the database
        # has generation-scoped fork prevention independently of the fold.
        db = session_local()
        try:
            clone = TenantDomainProfileSelectionV2(
                id=str(uuid4()), tenant_id=tenant_id, selection_id=str(uuid4()), selection_hash="d" * 64,
                selection_generation=1, selection_sequence=3, profile_id=second.profile_id,
                profile_version=second.profile_version, profile_content_hash=second.profile_content_hash,
                prior_selection_id=first.selection_id, prior_selection_hash=first.selection_hash, policy_epoch=3,
                authority_binding_version=1, issued_at=now, effective_at=now, expires_at=now + timedelta(hours=1),
                selected_by_principal_ref="user:owner", reason_code="fork", algorithm="HS256", signing_key_id="selection-v2",
                signature="u" * 43, signed_envelope={},
            )
            db.add(clone)
            with pytest.raises(IntegrityError):
                db.flush()
        finally:
            db.rollback()
            db.close()
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
