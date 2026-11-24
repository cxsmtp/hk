from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


def test_v1_delegated_action_discovery_does_not_lock_leaf_before_lineage(monkeypatch: pytest.MonkeyPatch) -> None:
    """The action lookup supplies only an ID; lineage owns all row locking."""
    import app.services.action_integrity.delegation_lifecycle as lifecycle

    class Context:
        delegation_context_id = "child-context"

    class RecordingSession:
        statement = None

        def scalar(self, statement):
            self.statement = statement
            return Context()

    db = RecordingSession()
    ancestry_calls: list[str] = []
    expected = Context()

    def require_ancestry(*args, **kwargs):
        ancestry_calls.append(kwargs["delegation_context_id"])
        return expected

    monkeypatch.setattr(lifecycle, "require_active_delegation_ancestry", require_ancestry)
    result = lifecycle.require_active_delegated_action_authority(
        db,
        provider=object(),
        tenant_id="tenant-ordering",
        delegated_action_id="child-action",
        now=NOW,
    )

    assert result is expected
    assert ancestry_calls == ["child-context"]
    assert db.statement is not None and db.statement._for_update_arg is None


def test_v1_delegation_lineage_folds_and_revokes_descendants() -> None:
    """A V1 context has immutable lineage and an append-only lifecycle fold."""
    from app.db.models.action_integrity import DelegationContextV2, DelegationLifecycleEventV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import (
        issue_delegation_context_v2,
        revoke_delegation_context_v2,
    )
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine("sqlite+pysqlite:///:memory:")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-lineage", name="Lineage", slug="tenant-lineage", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(
            purpose="delegation_context_signing",
            tenant_id="tenant-lineage",
            key_id="lineage",
            secret=b"l" * 32,
        )

        with sessions.begin() as db:
            root = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id="tenant-lineage",
                parent_action_id="root-action",
                delegated_action_id="root-delegated-action",
                parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:root",
                destination_principal_ref="agent:child",
                expires_at=NOW + timedelta(minutes=5),
                issued_at=NOW,
            )
            assert root.lineage_binding_version == 1
            assert root.signed_envelope["parent_delegation_ref"] is None
            assert root.signed_envelope["delegated_action_id"] == "root-delegated-action"
            assert root.state == "REGISTERED" and root.state_version == 0
            assert root.history_head_event_id is None and root.history_head_sequence == 0
            assert db.scalars(
                select(DelegationLifecycleEventV2).where(
                    DelegationLifecycleEventV2.delegation_context_id == root.delegation_context_id
                )
            ).all() == []

            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id="tenant-lineage",
                delegation_context_id=root.delegation_context_id,
                observed_at=NOW,
            )
            child = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id="tenant-lineage",
                parent_action_id="root-delegated-action",
                delegated_action_id="child-delegated-action",
                parent_delegation_context_id=root.delegation_context_id,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "8"},
                source_principal_ref="agent:child",
                destination_principal_ref="agent:grandchild",
                expires_at=NOW + timedelta(minutes=4),
                issued_at=NOW,
            )
            assert child.depth == 2
            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id="tenant-lineage",
                delegation_context_id=child.delegation_context_id,
                observed_at=NOW,
            )

            affected = revoke_delegation_context_v2(
                db,
                provider=provider,
                tenant_id="tenant-lineage",
                delegation_context_id=root.delegation_context_id,
                reason_code="test_revocation",
                observed_at=NOW + timedelta(seconds=1),
            )
            assert affected == [root.delegation_context_id, child.delegation_context_id]
            assert root.state == child.state == "REVOKED"
            assert root.state_version == child.state_version == 2
            assert root.history_head_sequence == child.history_head_sequence == 2
            root_events = db.scalars(
                select(DelegationLifecycleEventV2)
                .where(DelegationLifecycleEventV2.delegation_context_id == root.delegation_context_id)
                .order_by(DelegationLifecycleEventV2.sequence)
            ).all()
            assert [event.event_type for event in root_events] == ["ISSUED", "REVOKED"]
            assert root_events[-1].affected_unconsumed_descendant_refs == [child.delegation_context_id]
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_v1_child_requires_the_parent_contexts_exact_delegated_action() -> None:
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import issue_delegation_context_v2
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine("sqlite+pysqlite:///:memory:")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-parent-match", name="Parent match", slug="tenant-parent-match", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="delegation_context_signing", tenant_id="tenant-parent-match", key_id="lineage", secret=b"l" * 32)
        with sessions.begin() as db:
            root = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id="tenant-parent-match",
                parent_action_id="root-action",
                delegated_action_id="root-delegated-action",
                parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:root",
                destination_principal_ref="agent:child",
                expires_at=NOW + timedelta(minutes=5),
                issued_at=NOW,
            )
            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id="tenant-parent-match",
                delegation_context_id=root.delegation_context_id,
                observed_at=NOW,
            )
            with pytest.raises(PermissionError, match="parent delegated action"):
                register_delegated_child_v2(
                    db,
                    provider=provider,
                    tenant_id="tenant-parent-match",
                    parent_action_id="wrong-parent-action",
                    delegated_action_id="child-delegated-action",
                    parent_delegation_context_id=root.delegation_context_id,
                    parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                    child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "8"},
                    source_principal_ref="agent:child",
                    destination_principal_ref="agent:grandchild",
                    expires_at=NOW + timedelta(minutes=4),
                    issued_at=NOW,
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_v1_child_scope_is_intersected_with_the_signed_parent_scope() -> None:
    """A caller cannot widen a descendant by supplying a substituted parent scope."""
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import issue_delegation_context_v2
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine("sqlite+pysqlite:///:memory:")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(
            purpose="delegation_context_signing",
            tenant_id="tenant-scope-intersection",
            key_id="delegation",
            secret=b"d" * 32,
        )
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-scope-intersection", name="Scope", slug="tenant-scope-intersection", is_active=True))
            root = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id="tenant-scope-intersection",
                parent_action_id="root-action",
                delegated_action_id="root-delegated-action",
                parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["read", "write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["read"], "max_value": "9"},
                source_principal_ref="agent:root",
                destination_principal_ref="agent:child",
                expires_at=NOW + timedelta(minutes=5),
                issued_at=NOW,
            )
            assert root.signed_envelope["effective_scope"] == {
                "resources": ["resource:a"], "operations": ["read"], "max_value": "9"
            }
            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id="tenant-scope-intersection",
                delegation_context_id=root.delegation_context_id,
                observed_at=NOW,
            )
            with pytest.raises(PermissionError, match="parent scope"):
                register_delegated_child_v2(
                    db,
                    provider=provider,
                    tenant_id="tenant-scope-intersection",
                    parent_action_id="root-delegated-action",
                    delegated_action_id="widened-child",
                    parent_delegation_context_id=root.delegation_context_id,
                    parent_scope={"resources": ["resource:a", "resource:b"], "operations": ["read", "write"], "max_value": "10"},
                    child_scope={"resources": ["resource:b"], "operations": ["read"], "max_value": "8"},
                    source_principal_ref="agent:child",
                    destination_principal_ref="agent:grandchild",
                    expires_at=NOW + timedelta(minutes=4),
                    issued_at=NOW,
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_legacy_v0_delegation_context_is_ineligible_for_issue() -> None:
    from app.db.models.action_integrity import DelegationContextV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import issue_delegation_context_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine("sqlite+pysqlite:///:memory:")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-legacy", name="Legacy", slug="tenant-legacy", is_active=True))
            db.add(
                DelegationContextV2(
                    tenant_id="tenant-legacy",
                    delegation_context_id="legacy-context",
                    parent_action_id="legacy-parent",
                    source_principal_ref="agent:legacy",
                    destination_principal_ref="agent:legacy-child",
                    authority_scope_hash="a" * 64,
                    depth=1,
                    state="REGISTERED",
                    state_version=0,
                    expires_at=NOW + timedelta(minutes=5),
                    lineage_binding_version=0,
                    reconstruction_status="INVALID",
                    algorithm="HS256",
                    signing_key_id="legacy",
                    signature="x" * 43,
                    signed_envelope={},
                )
            )
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="delegation_context_signing", tenant_id="tenant-legacy", key_id="legacy", secret=b"l" * 32)
        with sessions.begin() as db:
            with pytest.raises(PermissionError, match="legacy"):
                issue_delegation_context_v2(
                    db,
                    provider=provider,
                    tenant_id="tenant-legacy",
                    delegation_context_id="legacy-context",
                    observed_at=NOW,
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_fresh_delegation_fold_verifies_historical_signatures_after_key_rotation() -> None:
    from app.db.models.action_integrity import DelegationContextV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import (
        fresh_delegation_context_fold,
        issue_delegation_context_v2,
    )
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine("sqlite+pysqlite:///:memory:")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-rotation", name="Rotation", slug="tenant-rotation", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="delegation_context_signing", tenant_id="tenant-rotation", key_id="old", secret=b"o" * 32)
        with sessions.begin() as db:
            context = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id="tenant-rotation",
                parent_action_id="root-action",
                delegated_action_id="root-delegated-action",
                parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:root",
                destination_principal_ref="agent:child",
                expires_at=NOW + timedelta(minutes=5),
                issued_at=NOW,
            )
            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id="tenant-rotation",
                delegation_context_id=context.delegation_context_id,
                observed_at=NOW,
            )
        provider.set_state(purpose="delegation_context_signing", tenant_id="tenant-rotation", key_id="old", state="verify_only")
        with sessions.begin() as db:
            context = db.scalar(
                select(DelegationContextV2).where(DelegationContextV2.tenant_id == "tenant-rotation")
            )
            assert context is not None
            assert fresh_delegation_context_fold(db, provider=provider, context=context).state == "ACTIVE"
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_fresh_delegation_fold_rejects_a_revoked_historical_key() -> None:
    """Verify-only keys preserve history, but revoked keys never preserve eligibility."""
    from app.db.models.action_integrity import DelegationContextV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import (
        fresh_delegation_context_fold,
        issue_delegation_context_v2,
    )
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine("sqlite+pysqlite:///:memory:")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-revoked-key", name="Revoked key", slug="tenant-revoked-key", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="delegation_context_signing", tenant_id="tenant-revoked-key", key_id="old", secret=b"o" * 32)
        with sessions.begin() as db:
            context = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id="tenant-revoked-key",
                parent_action_id="root-action",
                delegated_action_id="root-delegated-action",
                parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:root",
                destination_principal_ref="agent:child",
                expires_at=NOW + timedelta(minutes=5),
                issued_at=NOW,
            )
            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id="tenant-revoked-key",
                delegation_context_id=context.delegation_context_id,
                observed_at=NOW,
            )
        provider.set_state(purpose="delegation_context_signing", tenant_id="tenant-revoked-key", key_id="old", state="revoked")
        with sessions.begin() as db:
            context = db.scalar(select(DelegationContextV2).where(DelegationContextV2.tenant_id == "tenant-revoked-key"))
            assert context is not None
            with pytest.raises(PermissionError, match="revoked"):
                fresh_delegation_context_fold(db, provider=provider, context=context)
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_ancestor_revocation_skips_terminal_children_and_revokes_live_siblings() -> None:
    from app.db.models.action_integrity import DelegationLifecycleEventV2
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.delegation_lifecycle import (
        issue_delegation_context_v2,
        revoke_delegation_context_v2,
    )
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine("sqlite+pysqlite:///:memory:")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-terminal-child", name="Terminal child", slug="tenant-terminal-child", is_active=True))
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(purpose="delegation_context_signing", tenant_id="tenant-terminal-child", key_id="lineage", secret=b"l" * 32)
        with sessions.begin() as db:
            root = register_delegated_child_v2(
                db, provider=provider, tenant_id="tenant-terminal-child", parent_action_id="root-action",
                delegated_action_id="root-delegated-action", parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:root", destination_principal_ref="agent:child",
                expires_at=NOW + timedelta(minutes=5), issued_at=NOW,
            )
            issue_delegation_context_v2(db, provider=provider, tenant_id="tenant-terminal-child", delegation_context_id=root.delegation_context_id, observed_at=NOW)

            def child(action_id: str):
                value = register_delegated_child_v2(
                    db, provider=provider, tenant_id="tenant-terminal-child", parent_action_id="root-delegated-action",
                    delegated_action_id=action_id, parent_delegation_context_id=root.delegation_context_id,
                    parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                    child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "8"},
                    source_principal_ref="agent:child", destination_principal_ref=f"agent:{action_id}",
                    expires_at=NOW + timedelta(minutes=4), issued_at=NOW,
                )
                issue_delegation_context_v2(db, provider=provider, tenant_id="tenant-terminal-child", delegation_context_id=value.delegation_context_id, observed_at=NOW)
                return value

            terminal, live = child("terminal-delegated-action"), child("live-delegated-action")
            assert revoke_delegation_context_v2(
                db, provider=provider, tenant_id="tenant-terminal-child", delegation_context_id=terminal.delegation_context_id,
                reason_code="preexisting_terminal", observed_at=NOW + timedelta(seconds=1),
            ) == [terminal.delegation_context_id]
            affected = revoke_delegation_context_v2(
                db, provider=provider, tenant_id="tenant-terminal-child", delegation_context_id=root.delegation_context_id,
                reason_code="ancestor_revoke", observed_at=NOW + timedelta(seconds=2),
            )
            assert affected == [root.delegation_context_id, live.delegation_context_id]
            assert root.state == live.state == terminal.state == "REVOKED"
            root_event = db.scalars(
                select(DelegationLifecycleEventV2)
                .where(DelegationLifecycleEventV2.delegation_context_id == root.delegation_context_id)
                .order_by(DelegationLifecycleEventV2.sequence.desc())
            ).first()
            assert root_event is not None
            assert root_event.affected_unconsumed_descendant_refs == [live.delegation_context_id]
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_ancestor_revocation_atomically_invalidates_linked_unconsumed_approval_and_permit(tmp_path) -> None:
    """The same transaction revokes both exact delegated-action authorities."""
    from types import SimpleNamespace

    from app.db.models.action_integrity import (
        ApprovalAuthorityEventV2,
        ApprovalAuthorityProjectionV2,
        DelegationLifecycleEventV2,
        ExecutionPermitTransitionV2,
        ExecutionPermitV2,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.db.models.ai_system import AISystem
    from app.db.models.policy import ApprovalRequest
    from app.db.models.tenant import Tenant
    from app.db.models.user import User
    from app.db.session import Base
    from app.services.action_integrity.approval_service import decide_approval_request_v2
    from app.services.action_integrity.delegation_lifecycle import issue_delegation_context_v2, revoke_delegation_context_v2
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority, build_trusted_execution_action
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'delegation-authority-revoke.sqlite3'}")
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    try:
        provider = LocalSigningKeyProvider(development=True)
        with sessions.begin() as db:
            suffix = "lineage-authority"
            tenant = Tenant(name="Lineage authority", slug=suffix, is_active=True)
            approver = User(email=f"{suffix}@example.test", hashed_password="x", full_name="Approver", is_active=True)
            db.add_all([tenant, approver])
            db.flush()
            tenant_id, approver_id = tenant.id, approver.id
            db.add(AISystem(tenant_id=tenant_id, name=suffix, description="test", risk_tier="HIGH", status="active", metadata_json={}))
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
            db.flush()
            system_id = db.scalar(select(AISystem.id).where(AISystem.tenant_id == tenant_id))

        add_stored_authority_keys(provider, tenant_id=tenant_id)
        for purpose, key_id, secret in (
            ("delegation_context_signing", "lineage", b"l" * 32),
            ("approval_binding_signing", "approval", b"a" * 32),
            ("permitted_variation_signing", "variation", b"v" * 32),
        ):
            provider.add_key(purpose=purpose, tenant_id=tenant_id, key_id=key_id, secret=secret)

        with sessions.begin() as db:
            root = register_delegated_child_v2(
                db, provider=provider, tenant_id=tenant_id, parent_action_id="root-action",
                delegated_action_id="root-delegated-action", parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:root", destination_principal_ref="agent:child",
                expires_at=NOW + timedelta(minutes=5), issued_at=NOW,
            )
            issue_delegation_context_v2(db, provider=provider, tenant_id=tenant_id, delegation_context_id=root.delegation_context_id, observed_at=NOW)
            root_action = build_trusted_execution_action(
                tenant_id=tenant_id, action_id=root.delegated_action_id, chain_id="lineage-root-chain",
                actor_principal="user:requester", executing_principal="service:agent", operation="write",
                tool_or_service_ref="service:lineage", tool_fingerprint="f" * 64, parameter_hash="p" * 64,
                target_ref="resource:a", policy_epoch=1, approval_requirement="not_required", policy_version_id="policy:1", now=NOW,
            )
            root_fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=root_action,
                now=NOW,
                decision_receipt_id="decision-lineage-root",
            )
            root_permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: NOW).issue(
                tenant_id=tenant_id,
                action=root_fixture.action,
                expires_at=NOW + timedelta(minutes=2),
                rollout_mode="AUTHORITATIVE",
                decision_receipt_id=root_fixture.decision_receipt_id,
            )
            child = register_delegated_child_v2(
                db, provider=provider, tenant_id=tenant_id, parent_action_id="root-delegated-action",
                delegated_action_id="child-delegated-action", parent_delegation_context_id=root.delegation_context_id,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "8"},
                source_principal_ref="agent:child", destination_principal_ref="agent:grandchild",
                expires_at=NOW + timedelta(minutes=4), issued_at=NOW,
            )
            issue_delegation_context_v2(db, provider=provider, tenant_id=tenant_id, delegation_context_id=child.delegation_context_id, observed_at=NOW)
            action = build_trusted_execution_action(
                tenant_id=tenant_id, action_id=child.delegated_action_id, chain_id="lineage-chain",
                actor_principal="user:requester", executing_principal="service:agent", operation="write",
                tool_or_service_ref="service:lineage", tool_fingerprint="f" * 64, parameter_hash="p" * 64,
                target_ref="resource:a", policy_epoch=1, approval_requirement="required", policy_version_id="policy:1", now=NOW,
            )
            fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=action,
                now=NOW,
                decision_receipt_id="decision-lineage-child",
                authoritative_decision="REQUIRE_APPROVAL",
            )
            action = fixture.action
            request = ApprovalRequest(
                tenant_id=tenant_id,
                ai_system_id=str(system_id),
                decision_receipt_id=fixture.decision_receipt_id,
                request_payload={
                    "canonical_action": action,
                    "decision_receipt_id": fixture.decision_receipt_id,
                    "profile_selection_id": fixture.profile_selection_id,
                    "profile_selection_hash": fixture.profile_selection_hash,
                    "control_selection_id": fixture.control_selection_id,
                    "use_limit": 2,
                },
                required_roles=["owner"], sla_minutes=10, default_if_timeout="deny", status="pending",
                authority_schema_version="2.0", decision_version=1, created_at=NOW,
            )
            db.add(request)
            db.flush()
            request_id = request.id
            decide_approval_request_v2(
                db, tenant_id=tenant_id, approval_request_id=request_id,
                actor=SimpleNamespace(id=approver_id, role="owner"),
                dto=SimpleNamespace(decision="approve", expected_version=1, idempotency_key="lineage-approval-0001", reason="approved"),
                signing_provider=provider, now=NOW,
            )
            permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: NOW).issue(
                tenant_id=tenant_id,
                action=action,
                expires_at=NOW + timedelta(minutes=2),
                rollout_mode="AUTHORITATIVE",
                approval_request_id=request_id,
                decision_receipt_id=fixture.decision_receipt_id,
            )
            exhausted_request = ApprovalRequest(
                tenant_id=tenant_id,
                ai_system_id=str(system_id),
                decision_receipt_id=fixture.decision_receipt_id,
                request_payload={
                    "canonical_action": action,
                    "decision_receipt_id": fixture.decision_receipt_id,
                    "profile_selection_id": fixture.profile_selection_id,
                    "profile_selection_hash": fixture.profile_selection_hash,
                    "control_selection_id": fixture.control_selection_id,
                    "use_limit": 1,
                },
                required_roles=["owner"], sla_minutes=10, default_if_timeout="deny", status="pending",
                authority_schema_version="2.0", decision_version=1, created_at=NOW,
            )
            db.add(exhausted_request)
            db.flush()
            exhausted_request_id = exhausted_request.id
            decide_approval_request_v2(
                db, tenant_id=tenant_id, approval_request_id=exhausted_request_id,
                actor=SimpleNamespace(id=approver_id, role="owner"),
                dto=SimpleNamespace(decision="approve", expected_version=1, idempotency_key="lineage-approval-0002", reason="approved"),
                signing_provider=provider, now=NOW,
            )
            exhausted_permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: NOW).issue(
                tenant_id=tenant_id,
                action=action,
                expires_at=NOW + timedelta(minutes=2),
                rollout_mode="AUTHORITATIVE",
                approval_request_id=exhausted_request_id,
                decision_receipt_id=fixture.decision_receipt_id,
            )

        # An exception after the revocation call rolls every context, approval,
        # permit, event, and projection change back as one transaction.
        with pytest.raises(RuntimeError, match="rollback"):
            with sessions.begin() as db:
                revoke_delegation_context_v2(
                    db, provider=provider, tenant_id=tenant_id, delegation_context_id=root.delegation_context_id,
                    reason_code="delegation_revoked", observed_at=NOW + timedelta(seconds=1),
                )
                raise RuntimeError("rollback")

        with sessions.begin() as db:
            assert db.get(ExecutionPermitV2, root_permit.permit_id).state == "ISSUED"
            assert db.get(ExecutionPermitV2, permit.permit_id).state == "ISSUED"
            assert db.get(ExecutionPermitV2, exhausted_permit.permit_id).state == "ISSUED"
            assert db.get(ApprovalAuthorityProjectionV2, (tenant_id, request_id)).state == "APPROVED"
            assert db.get(ApprovalAuthorityProjectionV2, (tenant_id, exhausted_request_id)).state == "EXHAUSTED"

        with sessions.begin() as db:
            revoked = revoke_delegation_context_v2(
                db, provider=provider, tenant_id=tenant_id, delegation_context_id=root.delegation_context_id,
                reason_code="delegation_revoked", observed_at=NOW + timedelta(seconds=1),
            )
            assert revoked == [root.delegation_context_id, child.delegation_context_id]
            permit_row = db.get(ExecutionPermitV2, permit.permit_id)
            root_permit_row = db.get(ExecutionPermitV2, root_permit.permit_id)
            exhausted_permit_row = db.get(ExecutionPermitV2, exhausted_permit.permit_id)
            approval = db.get(ApprovalAuthorityProjectionV2, (tenant_id, request_id))
            exhausted_approval = db.get(ApprovalAuthorityProjectionV2, (tenant_id, exhausted_request_id))
            assert permit_row is not None and permit_row.state == "REVOKED" and permit_row.state_version == 1
            assert root_permit_row is not None and root_permit_row.state == "REVOKED" and root_permit_row.state_version == 1
            assert exhausted_permit_row is not None and exhausted_permit_row.state == "REVOKED" and exhausted_permit_row.state_version == 1
            assert approval is not None and approval.state == "REVOKED" and approval.state_version == 2
            assert exhausted_approval is not None and exhausted_approval.state == "EXHAUSTED" and exhausted_approval.state_version == 1
            assert [item.to_state for item in db.scalars(select(ExecutionPermitTransitionV2).where(ExecutionPermitTransitionV2.permit_id == permit.permit_id))] == ["REVOKED"]
            assert [item.event_type for item in db.scalars(select(ApprovalAuthorityEventV2).where(ApprovalAuthorityEventV2.approval_request_id == request_id).order_by(ApprovalAuthorityEventV2.sequence))] == ["DECIDED", "USE_CONSUMED", "REVOKED"]
            assert [item.event_type for item in db.scalars(select(ApprovalAuthorityEventV2).where(ApprovalAuthorityEventV2.approval_request_id == exhausted_request_id).order_by(ApprovalAuthorityEventV2.sequence))] == ["DECIDED", "USE_CONSUMED"]
            root_event = db.scalars(
                select(DelegationLifecycleEventV2)
                .where(DelegationLifecycleEventV2.delegation_context_id == root.delegation_context_id)
                .order_by(DelegationLifecycleEventV2.sequence.desc())
            ).first()
            assert root_event is not None
            exact_affected = sorted([
                child.delegation_context_id,
                f"approval_request:{request_id}",
                f"execution_permit:{root_permit.permit_id}",
                f"execution_permit:{permit.permit_id}",
                f"execution_permit:{exhausted_permit.permit_id}",
            ])
            assert root_event.affected_unconsumed_descendant_refs == exact_affected
            assert root_event.signed_envelope["affected_unconsumed_descendant_refs"] == exact_affected
        with sessions.begin() as db:
            with pytest.raises(PermissionError, match="inactive|revoked"):
                ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: NOW).issue(
                    tenant_id=tenant_id,
                    action=action,
                    expires_at=NOW + timedelta(minutes=1),
                    rollout_mode="AUTHORITATIVE",
                    approval_request_id=request_id,
                    decision_receipt_id=fixture.decision_receipt_id,
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
