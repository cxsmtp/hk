"""Explicit, disposable-DB acceptance coverage for Phase 5 authority invariants."""

from __future__ import annotations

import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker


ACCEPTANCE_DATABASE_NAME = "aicontrol_phase5_acceptance"


def _acceptance_database_url() -> str:
    """Require an intentional, isolated PostgreSQL target without exposing it."""
    database_url = os.getenv("PHASE5_ACCEPTANCE_DATABASE_URL")
    if not database_url:
        pytest.skip("set PHASE5_ACCEPTANCE_DATABASE_URL to run PostgreSQL Phase 5 acceptance coverage")

    url = make_url(database_url)
    if url.get_backend_name() != "postgresql" or url.database != ACCEPTANCE_DATABASE_NAME:
        pytest.fail(
            "PHASE5_ACCEPTANCE_DATABASE_URL must target the disposable "
            f"{ACCEPTANCE_DATABASE_NAME} PostgreSQL database"
        )
    return database_url


def _generic_action(
    *,
    tenant_id: str,
    suffix: str,
    now: datetime,
    operation: str = "write",
    action_id: str | None = None,
    chain_id: str | None = None,
) -> dict[str, Any]:
    from app.services.action_integrity.canonical_v2 import domain_hash
    from app.services.action_integrity.execution_authority import build_trusted_execution_action

    return build_trusted_execution_action(
        tenant_id=tenant_id,
        action_id=action_id or f"accept-action-{suffix}",
        chain_id=chain_id or f"accept-chain-{suffix}",
        actor_principal="user:acceptance",
        executing_principal="service:acceptance",
        operation=operation,
        tool_or_service_ref="acceptance:postgresql",
        tool_fingerprint=domain_hash(
            "hawk:closed-seam-fingerprint:v1",
            {"seam": f"acceptance.postgresql.{suffix}", "tool": "acceptance:postgresql"},
        ),
        parameter_hash="p" * 64,
        target_ref="resource:acceptance",
        policy_epoch=1,
        approval_requirement="not_required",
        policy_version_id="phase5:persisted-rollout",
        now=now,
    )


@pytest.mark.integration
def test_phase5_authoritative_permit_acceptance_on_postgresql_16() -> None:
    """Exercise authoritative lifecycle invariants against one migrated PG16 schema."""
    from sqlalchemy import create_engine

    from app.db.models.action_integrity import (
        ActionPlanStepV2,
        ActionPlanV2,
        DelegationContextV2,
        ExecutionPermitV2,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.db.models.tenant import Tenant
    from app.services.action_integrity.execution_authority import (
        ExecutionPermitAuthority,
        install_generic_seam_authority,
        invoke_final_seam,
    )
    from app.services.action_integrity.lifecycle_persistence import (
        persist_action_plan_v2,
        register_delegated_child_v2,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(_acceptance_database_url(), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            version_num = int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
        assert 160000 <= version_num < 170000, "acceptance coverage requires PostgreSQL 16"

        required_tables = {
            "tenants",
            "tenant_action_integrity_rollouts",
            "execution_permits_v2",
            "execution_permit_attempts_v2",
            "execution_permit_transitions_v2",
            "action_plans_v2",
            "action_plan_steps_v2",
            "delegation_contexts_v2",
            "decision_receipt_v2_extensions",
            "native_control_selections",
            "tenant_domain_profile_selections",
        }
        missing_tables = required_tables.difference(inspect(engine).get_table_names())
        assert not missing_tables, f"acceptance database is not migrated for Phase 5: {sorted(missing_tables)}"

        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        suffix = uuid4().hex[:16]
        tenant_id = str(uuid4())
        other_tenant_id = str(uuid4())
        now = datetime.now(timezone.utc)

        provider = LocalSigningKeyProvider(development=True)
        add_stored_authority_keys(provider, tenant_id=tenant_id)
        provider.add_key(
            purpose="action_plan_signing",
            tenant_id=tenant_id,
            key_id=f"plan-{suffix}",
            secret=b"a" * 32,
        )
        provider.add_key(
            purpose="delegation_context_signing",
            tenant_id=tenant_id,
            key_id=f"delegation-{suffix}",
            secret=b"g" * 32,
        )

        with sessions.begin() as db:
            db.add_all(
                [
                    Tenant(id=tenant_id, name=f"Phase 5 acceptance {suffix}", slug=f"phase5-accept-{suffix}", is_active=True),
                    Tenant(id=other_tenant_id, name=f"Phase 5 isolation {suffix}", slug=f"phase5-isolation-{suffix}", is_active=True),
                ]
            )
            db.flush()
            db.add_all(
                [
                    TenantPolicyEpoch(tenant_id=tenant_id, epoch=1),
                    TenantActionIntegrityRollout(tenant_id=tenant_id, mode="AUTHORITATIVE", policy_epoch=1),
                ]
            )

        # A generic final seam may use only a prior server-created, signed V1
        # decision.  It discovers that decision by the exact server action ID;
        # no caller-provided receipt identifier is accepted here.
        seam_ref = f"acceptance.postgresql.{suffix}"
        seam_action = _generic_action(
            tenant_id=tenant_id,
            suffix=suffix,
            now=now,
            action_id=f"seam-{suffix}",
            chain_id=f"seam-chain-{suffix}",
        )
        with sessions.begin() as db:
            seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=seam_action,
                now=now,
                decision_receipt_id=f"decision-seam-{suffix}",
            )
        with sessions() as db:
            db.info["phase5_signing_provider"] = provider
            handle = install_generic_seam_authority(
                db,
                tenant_id=tenant_id,
                seam_ref=seam_ref,
                action_id=f"seam-{suffix}",
                chain_id=f"seam-chain-{suffix}",
                actor_principal="user:acceptance",
                executing_principal="service:acceptance",
                operation="write",
                tool_or_service_ref="acceptance:postgresql",
                parameter_hash="p" * 64,
                target_ref="resource:acceptance",
                now=lambda: now,
            )
            assert handle is not None and handle.permit_id is not None
            seam_calls: list[str] = []
            assert invoke_final_seam(db, seam_ref=seam_ref, executor=lambda: seam_calls.append("called") or "ok") == "ok"
            assert seam_calls == ["called"]

        with sessions() as db:
            seam_permit = db.get(ExecutionPermitV2, handle.permit_id)
            assert seam_permit is not None and seam_permit.state == "CONSUMED"

        # A material mutation is rejected before the protected callback.
        mutable_action = _generic_action(tenant_id=tenant_id, suffix=f"mutate-{suffix}", now=now)
        with sessions.begin() as db:
            mutable_fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=mutable_action,
                now=now,
                decision_receipt_id=f"decision-mutate-{suffix}",
            )
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            mutation_permit = authority.issue(
                tenant_id=tenant_id,
                action=mutable_fixture.action,
                expires_at=now + timedelta(minutes=5),
                rollout_mode="AUTHORITATIVE",
                decision_receipt_id=mutable_fixture.decision_receipt_id,
            )
        mutated_action = {
            **mutable_fixture.action,
            "action_semantics": {
                **mutable_fixture.action["action_semantics"],
                "safe_parameters": {"parameter_hash": "m" * 64},
            },
        }
        mutation_calls: list[str] = []
        with sessions() as db:
            invoked, _ = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                mutation_permit.permit_id,
                tenant_id=tenant_id,
                action=mutated_action,
                claimed_by_ref="acceptance:mutation",
                executor=lambda: mutation_calls.append("called"),
            )
        assert not invoked
        assert mutation_calls == []

        # A signed plan can register an attenuated delegated child, while a
        # widened child is rejected in the same authoritative tenant scope.
        with sessions.begin() as db:
            plan = persist_action_plan_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                parent_action_id=f"parent-{suffix}",
                steps=[
                    {
                        "step_id": f"step-{suffix}",
                        "child_action_id": f"child-{suffix}",
                        "authority_mode": "SCOPED_PARENT_PERMIT",
                        "unbound_material_fields_hash": "a" * 64,
                    }
                ],
                issued_at=now,
                expires_at=now + timedelta(minutes=5),
            )
            assert db.scalar(select(ActionPlanV2).where(ActionPlanV2.plan_id == plan.plan_id)) is plan
            assert db.scalar(select(ActionPlanStepV2).where(ActionPlanStepV2.plan_id == plan.plan_id)) is not None
            child = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                parent_action_id=f"parent-{suffix}",
                delegated_action_id=f"child-{suffix}",
                parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:acceptance"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:acceptance"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:parent",
                destination_principal_ref="agent:child",
                expires_at=now + timedelta(minutes=5),
            )
            assert db.scalar(
                select(DelegationContextV2).where(DelegationContextV2.delegation_context_id == child.delegation_context_id)
            ) is child
            with pytest.raises(PermissionError, match="widens"):
                register_delegated_child_v2(
                    db,
                    provider=provider,
                    tenant_id=tenant_id,
                    parent_action_id=f"parent-{suffix}",
                    delegated_action_id=f"widened-child-{suffix}",
                    parent_delegation_context_id=None,
                    parent_scope={"resources": ["resource:acceptance"], "operations": ["write"], "max_value": "10"},
                    child_scope={"resources": ["resource:acceptance", "resource:widened"], "operations": ["write"], "max_value": "9"},
                    source_principal_ref="agent:parent",
                    destination_principal_ref="agent:child",
                    expires_at=now + timedelta(minutes=5),
                )

        # A second tenant cannot claim a permit it does not own. The genuine
        # tenant can execute once, but a replay cannot invoke its callback.
        replay_action = _generic_action(tenant_id=tenant_id, suffix=f"replay-{suffix}", now=now)
        with sessions.begin() as db:
            replay_fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=replay_action,
                now=now,
                decision_receipt_id=f"decision-replay-{suffix}",
            )
            replay_permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                tenant_id=tenant_id,
                action=replay_fixture.action,
                expires_at=now + timedelta(minutes=5),
                rollout_mode="AUTHORITATIVE",
                decision_receipt_id=replay_fixture.decision_receipt_id,
            )
        with sessions.begin() as db:
            assert not ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).claim(
                replay_permit.permit_id,
                tenant_id=other_tenant_id,
                action=_generic_action(tenant_id=other_tenant_id, suffix=f"replay-{suffix}", now=now),
                claimed_by_ref="acceptance:other-tenant",
            )
        replay_calls: list[str] = []
        with sessions() as db:
            authority = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now)
            first_invoked, _ = authority.execute(
                replay_permit.permit_id,
                tenant_id=tenant_id,
                action=replay_fixture.action,
                claimed_by_ref="acceptance:replay",
                executor=lambda: replay_calls.append("called"),
            )
            second_invoked, _ = authority.execute(
                replay_permit.permit_id,
                tenant_id=tenant_id,
                action=replay_fixture.action,
                claimed_by_ref="acceptance:replay",
                executor=lambda: replay_calls.append("replayed"),
            )
        assert first_invoked and not second_invoked
        assert replay_calls == ["called"]

        # Two independent SQLAlchemy sessions contend on the same PostgreSQL
        # row. The durable claim transition permits exactly one callback.
        race_action = _generic_action(tenant_id=tenant_id, suffix=f"race-{suffix}", now=now)
        with sessions.begin() as db:
            race_fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=race_action,
                now=now,
                decision_receipt_id=f"decision-race-{suffix}",
            )
            race_permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                tenant_id=tenant_id,
                action=race_fixture.action,
                expires_at=now + timedelta(minutes=5),
                rollout_mode="AUTHORITATIVE",
                decision_receipt_id=race_fixture.decision_receipt_id,
            )
        barrier = threading.Barrier(2)
        race_calls: list[int] = []
        race_results: list[bool] = []
        result_lock = threading.Lock()

        def race_claim(worker_id: int) -> None:
            with sessions() as db:
                barrier.wait(timeout=10)
                invoked, _ = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                    race_permit.permit_id,
                    tenant_id=tenant_id,
                    action=race_fixture.action,
                    claimed_by_ref=f"acceptance:race:{worker_id}",
                    executor=lambda: race_calls.append(worker_id),
                )
                with result_lock:
                    race_results.append(invoked)

        workers = [threading.Thread(target=race_claim, args=(worker_id,)) for worker_id in (1, 2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=15)
        assert not any(worker.is_alive() for worker in workers), "PostgreSQL permit race did not complete"
        assert race_results.count(True) == 1
        assert race_results.count(False) == 1
        assert len(race_calls) == 1

        # A callback exception is terminal UNKNOWN and cannot be replayed.
        failed_action = _generic_action(tenant_id=tenant_id, suffix=f"failure-{suffix}", now=now)
        with sessions.begin() as db:
            failed_fixture = seed_stored_allow_authority(
                db,
                provider=provider,
                tenant_id=tenant_id,
                action=failed_action,
                now=now,
                decision_receipt_id=f"decision-failure-{suffix}",
            )
            failed_permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                tenant_id=tenant_id,
                action=failed_fixture.action,
                expires_at=now + timedelta(minutes=5),
                rollout_mode="AUTHORITATIVE",
                decision_receipt_id=failed_fixture.decision_receipt_id,
            )
        with sessions() as db:
            with pytest.raises(RuntimeError, match="acceptance callback failure"):
                ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                    failed_permit.permit_id,
                    tenant_id=tenant_id,
                    action=failed_fixture.action,
                    claimed_by_ref="acceptance:failure",
                    executor=lambda: (_ for _ in ()).throw(RuntimeError("acceptance callback failure")),
                )
        with sessions() as db:
            failed_row = db.get(ExecutionPermitV2, failed_permit.permit_id)
            assert failed_row is not None and failed_row.state == "UNKNOWN"
            failure_replay_calls: list[str] = []
            invoked, _ = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).execute(
                failed_permit.permit_id,
                tenant_id=tenant_id,
                action=failed_fixture.action,
                claimed_by_ref="acceptance:failure-replay",
                executor=lambda: failure_replay_calls.append("replayed"),
            )
            assert not invoked
            assert failure_replay_calls == []
    finally:
        engine.dispose()


@pytest.mark.integration
def test_phase5_0068_postgresql_parent_lineage_key_is_native_and_enforced() -> None:
    """Exercise the referenced composite unique and self-FK on PostgreSQL."""
    from sqlalchemy import create_engine

    from app.db.models.action_integrity import DelegationContextV2
    from app.db.models.tenant import Tenant

    engine = create_engine(_acceptance_database_url(), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            version_num = int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
        assert 160000 <= version_num < 170000, "acceptance coverage requires PostgreSQL 16"
        inspector = inspect(engine)
        unique_constraints = {
            item["name"]: tuple(item["column_names"])
            for item in inspector.get_unique_constraints("delegation_contexts_v2")
        }
        assert unique_constraints["uq_phase5_delegation_context_action"] == (
            "tenant_id", "delegation_context_id", "delegated_action_id"
        )
        assert unique_constraints["uq_phase5_delegated_action_context"] == (
            "tenant_id", "delegated_action_id"
        )
        parent_fk = next(
            item for item in inspector.get_foreign_keys("delegation_contexts_v2")
            if item["name"] == "fk_phase5_delegation_parent_context"
        )
        assert tuple(parent_fk["constrained_columns"]) == (
            "tenant_id", "parent_delegation_context_id", "parent_action_id"
        )
        assert tuple(parent_fk["referred_columns"]) == (
            "tenant_id", "delegation_context_id", "delegated_action_id"
        )

        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        suffix = uuid4().hex[:16]
        tenant_id = str(uuid4())
        now = datetime.now(timezone.utc)
        with sessions.begin() as db:
            db.add(Tenant(id=tenant_id, name=f"0068 lineage {suffix}", slug=f"lineage-{suffix}", is_active=True))
            # PostgreSQL does not infer ORM insertion ordering from the raw
            # tenant_id scalar on this independent context fixture.
            db.flush()
            db.add(
                DelegationContextV2(
                    tenant_id=tenant_id,
                    delegation_context_id=f"root-{suffix}",
                    parent_action_id="root-action",
                    parent_delegation_context_id=None,
                    delegated_action_id="root-delegated-action",
                    lineage_binding_version=1,
                    source_principal_ref="agent:root",
                    destination_principal_ref="agent:child",
                    authority_scope_hash="a" * 64,
                    depth=1,
                    state="REGISTERED",
                    state_version=0,
                    history_head_sequence=0,
                    reconstruction_status="VERIFIED",
                    expires_at=now + timedelta(minutes=5),
                    algorithm="HS256",
                    signing_key_id="acceptance",
                    signature="s" * 43,
                    signed_envelope={"schema_version": "2.1"},
                )
            )
        with sessions() as db:
            with pytest.raises(IntegrityError):
                with db.begin():
                    db.add(
                        DelegationContextV2(
                            tenant_id=tenant_id,
                            delegation_context_id=f"child-{suffix}",
                            parent_action_id="not-the-parent-delegated-action",
                            parent_delegation_context_id=f"root-{suffix}",
                            delegated_action_id="child-delegated-action",
                            lineage_binding_version=1,
                            source_principal_ref="agent:child",
                            destination_principal_ref="agent:grandchild",
                            authority_scope_hash="b" * 64,
                            depth=2,
                            state="REGISTERED",
                            state_version=0,
                            history_head_sequence=0,
                            reconstruction_status="VERIFIED",
                            expires_at=now + timedelta(minutes=4),
                            algorithm="HS256",
                            signing_key_id="acceptance",
                            signature="s" * 43,
                            signed_envelope={"schema_version": "2.1"},
                        )
                    )
                    db.flush()
    finally:
        engine.dispose()


@pytest.mark.integration
def test_phase5_0068_postgresql_claim_and_revocation_linearize_on_lineage_locks() -> None:
    """Two sessions prove revocation/claim ordering without a permit→context inversion."""
    from sqlalchemy import create_engine

    from app.db.models.action_integrity import (
        ExecutionPermitTransitionV2,
        ExecutionPermitV2,
        TenantActionIntegrityRollout,
        TenantPolicyEpoch,
    )
    from app.db.models.tenant import Tenant
    from app.services.action_integrity.delegation_lifecycle import issue_delegation_context_v2, revoke_delegation_context_v2
    from app.services.action_integrity.execution_authority import ExecutionPermitAuthority, build_trusted_execution_action
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from phase5_stored_authority_support import add_stored_authority_keys, seed_stored_allow_authority

    engine = create_engine(_acceptance_database_url(), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            version_num = int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
        assert 160000 <= version_num < 170000, "acceptance coverage requires PostgreSQL 16"
        sessions = sessionmaker(bind=engine, expire_on_commit=False)

        def setup_lineage(label: str):
            suffix = uuid4().hex[:12]
            tenant_id = str(uuid4())
            now = datetime.now(timezone.utc)
            provider = LocalSigningKeyProvider(development=True)
            add_stored_authority_keys(provider, tenant_id=tenant_id)
            for purpose, key_id, secret in (
                ("action_plan_signing", f"lineage-{suffix}", b"l" * 32),
                ("delegation_context_signing", f"delegation-{suffix}", b"g" * 32),
            ):
                provider.add_key(purpose=purpose, tenant_id=tenant_id, key_id=key_id, secret=secret)
            with sessions.begin() as db:
                db.add(Tenant(id=tenant_id, name=f"0068 race {label} {suffix}", slug=f"race-{label}-{suffix}", is_active=True))
                db.flush()
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
            with sessions.begin() as db:
                root = register_delegated_child_v2(
                    db, provider=provider, tenant_id=tenant_id, parent_action_id=f"root-{suffix}",
                    delegated_action_id=f"delegated-root-{suffix}", parent_delegation_context_id=None,
                    parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                    child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                    source_principal_ref="agent:root", destination_principal_ref="agent:child",
                    expires_at=now + timedelta(minutes=5), issued_at=now,
                )
                issue_delegation_context_v2(db, provider=provider, tenant_id=tenant_id, delegation_context_id=root.delegation_context_id, observed_at=now)
                child = register_delegated_child_v2(
                    db, provider=provider, tenant_id=tenant_id, parent_action_id=root.delegated_action_id,
                    delegated_action_id=f"delegated-child-{suffix}", parent_delegation_context_id=root.delegation_context_id,
                    parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                    child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "8"},
                    source_principal_ref="agent:child", destination_principal_ref="agent:grandchild",
                    expires_at=now + timedelta(minutes=4), issued_at=now,
                )
                issue_delegation_context_v2(db, provider=provider, tenant_id=tenant_id, delegation_context_id=child.delegation_context_id, observed_at=now)
                action = build_trusted_execution_action(
                    tenant_id=tenant_id, action_id=child.delegated_action_id, chain_id=f"race-chain-{suffix}",
                    actor_principal="user:race", executing_principal="service:race", operation="write",
                    tool_or_service_ref="service:race", tool_fingerprint="f" * 64, parameter_hash="p" * 64,
                    target_ref="resource:a", policy_epoch=1, approval_requirement="not_required", policy_version_id="policy:1", now=now,
                )
                stored = seed_stored_allow_authority(
                    db,
                    provider=provider,
                    tenant_id=tenant_id,
                    action=action,
                    now=now,
                    decision_receipt_id=f"decision-race-{suffix}",
                )
                permit = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now).issue(
                    tenant_id=tenant_id,
                    action=stored.action,
                    expires_at=now + timedelta(minutes=2),
                    rollout_mode="AUTHORITATIVE",
                    decision_receipt_id=stored.decision_receipt_id,
                )
            return tenant_id, now, provider, root.delegation_context_id, stored.action, permit.permit_id

        # Revocation holds the root-to-descendant locks first.  A concurrent
        # durable claim waits, observes the terminal lineage, and cannot invoke.
        tenant_id, now, provider, root_id, action, permit_id = setup_lineage("revoke-wins")
        revocation_ready, release_revocation = threading.Event(), threading.Event()
        errors: list[BaseException] = []
        claim_results: list[bool] = []
        callbacks: list[str] = []

        def revoke_first() -> None:
            try:
                with sessions() as db:
                    with db.begin():
                        revoke_delegation_context_v2(
                            db, provider=provider, tenant_id=tenant_id, delegation_context_id=root_id,
                            reason_code="race_revoke", observed_at=now + timedelta(seconds=1),
                        )
                        revocation_ready.set()
                        assert release_revocation.wait(timeout=10)
            except BaseException as exc:  # thread failures must fail the test
                errors.append(exc)

        def claim_after_revoke_lock() -> None:
            try:
                with sessions() as db:
                    invoked, _ = ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now + timedelta(seconds=1)).execute(
                        permit_id, tenant_id=tenant_id, action=action, claimed_by_ref="race:claim-after-revoke",
                        executor=lambda: callbacks.append("called"),
                    )
                    claim_results.append(invoked)
            except BaseException as exc:
                errors.append(exc)

        revoker = threading.Thread(target=revoke_first)
        revoker.start()
        assert revocation_ready.wait(timeout=10)
        claimant = threading.Thread(target=claim_after_revoke_lock)
        claimant.start()
        release_revocation.set()
        revoker.join(timeout=15)
        claimant.join(timeout=15)
        assert not revoker.is_alive() and not claimant.is_alive(), "PostgreSQL lineage race did not complete"
        assert not errors
        assert claim_results == [False]
        assert callbacks == []
        with sessions() as db:
            assert db.get(ExecutionPermitV2, permit_id).state == "REVOKED"

        # In the inverse linearization the completed claim is not recast as an
        # unconsumed permit by the later ancestor revocation.
        tenant_id, now, provider, root_id, action, permit_id = setup_lineage("claim-wins")
        claim_ready, release_claim = threading.Event(), threading.Event()
        errors = []
        direct_claim_results: list[bool] = []

        def claim_first() -> None:
            try:
                with sessions() as db:
                    with db.begin():
                        direct_claim_results.append(
                            ExecutionPermitAuthority(db, signing_provider=provider, now=lambda: now + timedelta(seconds=1)).claim(
                                permit_id, tenant_id=tenant_id, action=action, claimed_by_ref="race:claim-first"
                            )
                        )
                        claim_ready.set()
                        assert release_claim.wait(timeout=10)
            except BaseException as exc:
                errors.append(exc)

        def revoke_after_claim_lock() -> None:
            try:
                with sessions() as db:
                    with db.begin():
                        revoke_delegation_context_v2(
                            db, provider=provider, tenant_id=tenant_id, delegation_context_id=root_id,
                            reason_code="race_revoke", observed_at=now + timedelta(seconds=1),
                        )
            except BaseException as exc:
                errors.append(exc)

        claimant = threading.Thread(target=claim_first)
        claimant.start()
        assert claim_ready.wait(timeout=10)
        revoker = threading.Thread(target=revoke_after_claim_lock)
        revoker.start()
        release_claim.set()
        claimant.join(timeout=15)
        revoker.join(timeout=15)
        assert not claimant.is_alive() and not revoker.is_alive(), "PostgreSQL lineage claim race did not complete"
        assert not errors
        assert direct_claim_results == [True]
        with sessions() as db:
            permit = db.get(ExecutionPermitV2, permit_id)
            assert permit is not None and permit.state == "CLAIMED" and permit.state_version == 1
            assert [item.to_state for item in db.scalars(
                select(ExecutionPermitTransitionV2)
                .where(ExecutionPermitTransitionV2.permit_id == permit_id)
                .order_by(ExecutionPermitTransitionV2.sequence)
            )] == ["CLAIMED"]
    finally:
        engine.dispose()


@pytest.mark.integration
def test_phase5_0068_postgresql_issuer_never_leaf_locks_before_root() -> None:
    """A blocked issuer leaves the child lock available to ancestor revocation."""
    from sqlalchemy import create_engine

    from app.db.models.action_integrity import DelegationContextV2
    from app.db.models.tenant import Tenant
    import app.services.action_integrity.delegation_lifecycle as delegation_lifecycle
    from app.services.action_integrity.delegation_lifecycle import (
        issue_delegation_context_v2,
        require_active_delegated_action_authority,
        revoke_delegation_context_v2,
    )
    from app.services.action_integrity.lifecycle_persistence import register_delegated_child_v2
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    engine = create_engine(_acceptance_database_url(), pool_pre_ping=True)
    try:
        with engine.connect() as connection:
            version_num = int(connection.exec_driver_sql("SHOW server_version_num").scalar_one())
        assert 160000 <= version_num < 170000, "acceptance coverage requires PostgreSQL 16"
        sessions = sessionmaker(bind=engine, expire_on_commit=False)
        suffix = uuid4().hex[:12]
        tenant_id = str(uuid4())
        now = datetime.now(timezone.utc)
        provider = LocalSigningKeyProvider(development=True)
        provider.add_key(
            purpose="action_plan_signing",
            tenant_id=tenant_id,
            key_id=f"lineage-{suffix}",
            secret=b"l" * 32,
        )
        provider.add_key(
            purpose="delegation_context_signing",
            tenant_id=tenant_id,
            key_id=f"delegation-{suffix}",
            secret=b"d" * 32,
        )

        with sessions.begin() as db:
            db.add(Tenant(id=tenant_id, name=f"0068 ordering {suffix}", slug=f"ordering-{suffix}", is_active=True))
            db.flush()
            root = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                parent_action_id=f"root-{suffix}",
                delegated_action_id=f"delegated-root-{suffix}",
                parent_delegation_context_id=None,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "10"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                source_principal_ref="agent:root",
                destination_principal_ref="agent:child",
                expires_at=now + timedelta(minutes=5),
                issued_at=now,
            )
            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                delegation_context_id=root.delegation_context_id,
                observed_at=now,
            )
            child = register_delegated_child_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                parent_action_id=root.delegated_action_id,
                delegated_action_id=f"delegated-child-{suffix}",
                parent_delegation_context_id=root.delegation_context_id,
                parent_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "9"},
                child_scope={"resources": ["resource:a"], "operations": ["write"], "max_value": "8"},
                source_principal_ref="agent:child",
                destination_principal_ref="agent:grandchild",
                expires_at=now + timedelta(minutes=4),
                issued_at=now,
            )
            issue_delegation_context_v2(
                db,
                provider=provider,
                tenant_id=tenant_id,
                delegation_context_id=child.delegation_context_id,
                observed_at=now,
            )

        root_locked = threading.Event()
        issuer_attempted_root = threading.Event()
        release_revocation = threading.Event()
        errors: list[BaseException] = []
        issuer_results: list[str] = []
        original_locked_context = delegation_lifecycle._locked_context

        def observe_issuer_root_lock(*args, **kwargs):
            if (
                threading.current_thread().name == "phase5-issuer"
                and kwargs["delegation_context_id"] == root.delegation_context_id
            ):
                issuer_attempted_root.set()
            return original_locked_context(*args, **kwargs)

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(delegation_lifecycle, "_locked_context", observe_issuer_root_lock)
        try:
            def revoke_after_holding_root() -> None:
                try:
                    with sessions() as db:
                        with db.begin():
                            held_root = db.scalar(
                                select(DelegationContextV2)
                                .where(
                                    DelegationContextV2.tenant_id == tenant_id,
                                    DelegationContextV2.delegation_context_id == root.delegation_context_id,
                                )
                                .with_for_update()
                            )
                            assert held_root is not None
                            root_locked.set()
                            assert release_revocation.wait(timeout=10)
                            revoke_delegation_context_v2(
                                db,
                                provider=provider,
                                tenant_id=tenant_id,
                                delegation_context_id=root.delegation_context_id,
                                reason_code="ordering_test",
                                observed_at=now + timedelta(seconds=1),
                            )
                except BaseException as exc:  # thread failures must fail the test
                    errors.append(exc)

            def issue_after_root_is_held() -> None:
                try:
                    with sessions() as db:
                        with db.begin():
                            require_active_delegated_action_authority(
                                db,
                                provider=provider,
                                tenant_id=tenant_id,
                                delegated_action_id=child.delegated_action_id,
                                now=now + timedelta(seconds=1),
                            )
                            issuer_results.append("allowed")
                except PermissionError:
                    issuer_results.append("rejected")
                except BaseException as exc:
                    errors.append(exc)

            revoker = threading.Thread(target=revoke_after_holding_root, name="phase5-revoker")
            revoker.start()
            assert root_locked.wait(timeout=10)
            issuer = threading.Thread(target=issue_after_root_is_held, name="phase5-issuer")
            issuer.start()
            assert issuer_attempted_root.wait(timeout=10)

            # If issuance had first locked the leaf, this NOWAIT probe would
            # fail while the issuer waited on the root.  The fixed flow only
            # discovers the leaf before requesting the root-to-leaf lineage.
            with sessions.begin() as db:
                locked_child = db.scalar(
                    select(DelegationContextV2)
                    .where(
                        DelegationContextV2.tenant_id == tenant_id,
                        DelegationContextV2.delegation_context_id == child.delegation_context_id,
                    )
                    .with_for_update(nowait=True)
                )
                assert locked_child is not None
        finally:
            release_revocation.set()
            revoker.join(timeout=15)
            issuer.join(timeout=15)
            monkeypatch.undo()

        assert not revoker.is_alive() and not issuer.is_alive(), "PostgreSQL issuer/revocation crossing schedule deadlocked"
        assert not errors
        assert issuer_results == ["rejected"]
        with sessions() as db:
            states = {
                context.delegation_context_id: context.state
                for context in db.scalars(
                    select(DelegationContextV2).where(
                        DelegationContextV2.tenant_id == tenant_id,
                        DelegationContextV2.delegation_context_id.in_(
                            (root.delegation_context_id, child.delegation_context_id)
                        ),
                    )
                )
            }
        assert states == {
            root.delegation_context_id: "REVOKED",
            child.delegation_context_id: "REVOKED",
        }
    finally:
        engine.dispose()
