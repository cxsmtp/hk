from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import sessionmaker


def _action(tenant_id: str, *, profile_id: str, profile_hash: str, plan_id: str, plan_digest: str) -> dict[str, object]:
    return {
        "schema_version": "2.0",
        "tenant_id": tenant_id,
        "action_id": "stored-action-1",
        "chain_id": "stored-chain-1",
        "correlation_id": "stored-correlation-1",
        "parent_action_id": None,
        "actor_principal": "user:requester",
        "executing_principal": "service:stored-test",
        "represented_subjects": [],
        "resource_scopes": ["resource:stored"],
        "authority_context": "authority:stored",
        "business_purpose": "purpose:stored",
        "environment": "production",
        "provider_runtime_context": "runtime:stored-test",
        "action_semantics": {
            "action_class": "consequential",
            "operation": "write",
            "object_type": "stored-test",
            "tool_or_service_ref": "service:stored-test",
            "tool_fingerprint": "f" * 64,
            "safe_parameters": {"parameter_hash": "p" * 64},
            "represented_subject_refs": [],
            "resource_refs": ["resource:stored"],
            "counterparty_refs": [],
            "target_refs": ["target:stored"],
            "destination_refs": [],
            "values_or_quantities": [],
            "authority_ref": "authority:stored",
            "business_purpose_ref": "purpose:stored",
            "side_effect": "external_write",
            "persistence": "none",
            "environment": "production",
            "reversibility": "compensatable",
            "expected_outcome_ref": "outcome:stored",
        },
        "domain_profile_ref": profile_id,
        "domain_profile_hash": profile_hash,
        "materiality_profile_ref": "phase5-p0",
        "materiality_profile_hash": "e" * 64,
        "resolver_versions": {},
        "policy_version_id": "policy:stored",
        "policy_epoch": 1,
        "control_plan_id": plan_id,
        "control_plan_digest": plan_digest,
        "approval_requirement": "not_required",
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


def test_stored_decision_permit_is_terminal_after_success_or_callback_failure(tmp_path) -> None:
    from app.db.models.action_integrity import (
        ExecutionPermitAttemptV2,
        ExecutionPermitTransitionV2,
        ExecutionPermitV2,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'stored-permit.sqlite3'}")
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    Base.metadata.create_all(engine)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Stored permit", slug="stored-permit", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all([
                TenantPolicyEpoch(tenant_id=tenant_id, epoch=1),
                TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1),
            ])

        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)

        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=_action(tenant_id, profile_id="placeholder", profile_hash="a" * 64, plan_id="placeholder", plan_digest="b" * 64),
                now=now,
            )
            action = fixture.action

        with session_local.begin() as db:
            permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                tenant_id=tenant_id, action=action, expires_at=now + timedelta(minutes=3), rollout_mode="AUTHORITATIVE",
                decision_receipt_id=fixture.decision_receipt_id,
            )
            first_permit_id = permit.permit_id

        with session_local() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            assert authority.execute(first_permit_id, tenant_id=tenant_id, action=action, claimed_by_ref="seam:stored", executor=lambda: "ok") == (True, "ok")
            replay_callbacks: list[str] = []
            assert authority.execute(
                first_permit_id,
                tenant_id=tenant_id,
                action=action,
                claimed_by_ref="seam:stored-replay",
                executor=lambda: replay_callbacks.append("called"),
            ) == (False, None)
            assert replay_callbacks == []
        with session_local.begin() as db:
            permit = db.get(ExecutionPermitV2, first_permit_id)
            attempt = db.scalar(select(ExecutionPermitAttemptV2).where(ExecutionPermitAttemptV2.attempt_id == permit.attempt_id))
            transitions = db.scalars(select(ExecutionPermitTransitionV2).where(ExecutionPermitTransitionV2.permit_id == first_permit_id).order_by(ExecutionPermitTransitionV2.sequence)).all()
            assert permit is not None and permit.state == "CONSUMED" and permit.state_version == 2
            assert attempt is not None and attempt.status == "CONSUMED"
            assert [(row.from_state, row.to_state, row.executor_invocation_state) for row in transitions] == [
                ("ISSUED", "CLAIMED", "NOT_INVOKED"), ("CLAIMED", "CONSUMED", "INVOKED"),
            ]

        with session_local.begin() as db:
            permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                tenant_id=tenant_id, action=action, expires_at=now + timedelta(minutes=3), rollout_mode="AUTHORITATIVE",
                decision_receipt_id=fixture.decision_receipt_id,
            )
            failed_permit_id = permit.permit_id
        with session_local() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            with pytest.raises(RuntimeError, match="callback failed"):
                authority.execute(failed_permit_id, tenant_id=tenant_id, action=action, claimed_by_ref="seam:stored", executor=lambda: (_ for _ in ()).throw(RuntimeError("callback failed")))
        with session_local.begin() as db:
            failed = db.get(ExecutionPermitV2, failed_permit_id)
            assert failed is not None and failed.state == "UNKNOWN" and failed.state_version == 2
        with session_local() as db:
            replay_callbacks: list[str] = []
            assert ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                failed_permit_id,
                tenant_id=tenant_id,
                action=action,
                claimed_by_ref="seam:stored-replay",
                executor=lambda: replay_callbacks.append("called"),
            ) == (False, None)
            assert replay_callbacks == []
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_shared_stored_authority_fixture_satisfies_the_base_decision_fk(tmp_path) -> None:
    from app.db.models.action_integrity import TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.evidence import DecisionReceipt
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'stored-permit-fk.sqlite3'}")
    event.listen(engine, "connect", lambda connection, _record: connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Stored permit FK", slug="stored-permit-fk", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all([
                TenantPolicyEpoch(tenant_id=tenant_id, epoch=1),
                TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1),
            ])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id=tenant_id,
                action=_action(tenant_id, profile_id="placeholder", profile_hash="a" * 64, plan_id="placeholder", plan_digest="b" * 64),
                now=now,
            )
            assert db.get(DecisionReceipt, fixture.decision_receipt_id) is not None
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.mark.parametrize(
    ("authoritative_decision", "authority_status"),
    [("BLOCK", "CURRENT"), ("ALLOW", "STALE")],
)
def test_ineligible_signed_decision_never_issues_a_permit(tmp_path, authoritative_decision: str, authority_status: str) -> None:
    from app.db.models.action_integrity import ExecutionPermitV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / f'blocked-{authoritative_decision}-{authority_status}.sqlite3'}")
    Base.metadata.create_all(engine)
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Blocked permit", slug=f"blocked-{authoritative_decision}-{authority_status}".lower(), is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all([
                TenantPolicyEpoch(tenant_id=tenant_id, epoch=1),
                TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1),
            ])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id=tenant_id,
                action=_action(tenant_id, profile_id="placeholder", profile_hash="a" * 64, plan_id="placeholder", plan_digest="b" * 64),
                now=now, authoritative_decision=authoritative_decision, authority_status=authority_status,
            )
        with session_local.begin() as db:
            with pytest.raises(PermissionError, match="not currently eligible"):
                ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                    tenant_id=tenant_id, action=fixture.action, expires_at=now + timedelta(minutes=3),
                    rollout_mode="AUTHORITATIVE", decision_receipt_id=fixture.decision_receipt_id,
                )
            assert db.scalar(select(func.count()).select_from(ExecutionPermitV2)) == 0
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.mark.parametrize("approval_requirement", [None, "optional", "NOT_REQUIRED"])
def test_unknown_approval_requirement_never_bypasses_the_decision_gate(tmp_path, approval_requirement: object) -> None:
    from app.db.models.action_integrity import ExecutionPermitV2, TenantActionIntegrityRollout, TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'unknown-approval.sqlite3'}")
    Base.metadata.create_all(engine)
    session_local = sessionmaker(bind=engine, expire_on_commit=False)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)
    try:
        with session_local.begin() as db:
            tenant = Tenant(name="Unknown approval", slug=f"unknown-approval-{uuid4().hex[:8]}", is_active=True)
            db.add(tenant)
            db.flush()
            tenant_id = tenant.id
            db.add_all([TenantPolicyEpoch(tenant_id=tenant_id, epoch=1), TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1)])
        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        with session_local.begin() as db:
            fixture = seed_stored_allow_authority(
                db, provider=provider, tenant_id=tenant_id,
                action=_action(tenant_id, profile_id="placeholder", profile_hash="a" * 64, plan_id="placeholder", plan_digest="b" * 64),
                now=now,
            )
        with session_local.begin() as db:
            invalid_action = {**fixture.action, "approval_requirement": approval_requirement}
            with pytest.raises(PermissionError, match="approval requirement"):
                ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                    tenant_id=tenant_id, action=invalid_action, expires_at=now + timedelta(minutes=1),
                    rollout_mode="AUTHORITATIVE", decision_receipt_id=fixture.decision_receipt_id,
                )
            assert db.scalar(select(func.count()).select_from(ExecutionPermitV2)) == 0
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
