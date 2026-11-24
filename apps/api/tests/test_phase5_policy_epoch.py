from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def test_epoch_service_is_positive_monotonic_and_auditable() -> None:
    from app.db.models.action_integrity import TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.policy_epoch import PolicyEpochService

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        sessions = sessionmaker(bind=engine)
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-epoch", is_active=True))
            db.add(TenantPolicyEpoch(tenant_id="tenant-a", epoch=1))
        with sessions.begin() as db:
            service = PolicyEpochService(db)
            before = service.current(tenant_id="tenant-a")
            assert before.epoch == before.state_version == 1
            after = service.bump_material_change(
                tenant_id="tenant-a", expected_epoch=1, expected_state_version=1, current_policy_snapshot_id="policy-v2",
                material_policy_digest="a" * 64, actor_principal_ref="user:owner", reason_code="policy_rule_changed",
            )
            assert (after.epoch, after.state_version) == (2, 2)
            with pytest.raises(ValueError, match="compare-and-set"):
                service.bump_material_change(
                    tenant_id="tenant-a", expected_epoch=1, expected_state_version=1, current_policy_snapshot_id="policy-v3",
                    material_policy_digest="b" * 64, actor_principal_ref="user:owner", reason_code="stale",
                )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_memory_epoch_store_never_starts_at_zero() -> None:
    from app.services.action_integrity.policy_epoch import PolicyEpochStore

    store = PolicyEpochStore()
    with pytest.raises(RuntimeError, match="database-backed"):
        store.current("tenant-a")


@pytest.mark.parametrize("kwargs", [
    {"current_policy_snapshot_id": None, "material_policy_digest": "a" * 64, "actor_principal_ref": "user:owner"},
    {"current_policy_snapshot_id": "policy-v2", "material_policy_digest": "not-a-digest", "actor_principal_ref": "user:owner"},
    {"current_policy_snapshot_id": "policy-v2", "material_policy_digest": "a" * 64, "actor_principal_ref": None},
])
def test_epoch_bump_requires_a_complete_auditable_material_change(kwargs: dict[str, str | None]) -> None:
    from app.db.models.action_integrity import TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.policy_epoch import PolicyEpochService

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        sessions = sessionmaker(bind=engine)
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-epoch-audit", is_active=True))
            db.add(TenantPolicyEpoch(tenant_id="tenant-a", epoch=1))
        with sessions.begin() as db, pytest.raises(ValueError):
            PolicyEpochService(db).bump_material_change(
                tenant_id="tenant-a", expected_epoch=1, expected_state_version=1, reason_code="material_change", **kwargs,
            )
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_epoch_cas_rejects_boolean_epoch_or_state_version() -> None:
    from app.db.models.action_integrity import TenantPolicyEpoch
    from app.db.models.tenant import Tenant
    from app.db.session import Base
    from app.services.action_integrity.policy_epoch import PolicyEpochService

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        sessions = sessionmaker(bind=engine)
        with sessions.begin() as db:
            db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a-epoch-bool", is_active=True))
            db.add(TenantPolicyEpoch(tenant_id="tenant-a", epoch=1))
        with sessions.begin() as db:
            service = PolicyEpochService(db)
            common = {
                "tenant_id": "tenant-a", "current_policy_snapshot_id": "policy-v2",
                "material_policy_digest": "a" * 64, "actor_principal_ref": "user:owner",
                "reason_code": "material_change",
            }
            with pytest.raises(ValueError, match="epoch"):
                service.bump_material_change(expected_epoch=True, expected_state_version=1, **common)
            with pytest.raises(ValueError, match="state version"):
                service.bump_material_change(expected_epoch=1, expected_state_version=True, **common)
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
