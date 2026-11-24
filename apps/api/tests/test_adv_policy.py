from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session

from app.db.models.discovery_verification import DiscoveryVerificationPolicy
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.adv.policy import (
    VerificationPolicyConflict,
    VerificationPolicyResolver,
    create_verification_policy,
)


NOW = datetime(2026, 8, 20, 8, 0, tzinfo=timezone.utc)
TENANT = "10000000-0000-0000-0000-000000000061"


@contextmanager
def _database():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    event.listen(engine, "connect", lambda connection, _: connection.execute("PRAGMA foreign_keys=ON"))
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        session.add(Tenant(id=TENANT, name="ADV", slug="adv", is_active=True, platform_mode="enforce"))
        session.flush()
        yield session
    finally:
        session.close()
        engine.dispose()


def _requirements() -> tuple[dict[str, object], ...]:
    return (
        {
            "requirement_id": "endpoint_identity",
            "task_type": "endpoint_confirm",
            "accepted_methods": ("endpoint_metadata",),
            "evidence_class": "endpoint_identity",
            "independence_group": "endpoint",
            "required": True,
            "minimum_result_count": 1,
            "maximum_age_seconds": 3600,
            "applicability": {},
        },
        {
            "requirement_id": "network_usage",
            "task_type": "network_confirm",
            "accepted_methods": ("network_metadata",),
            "evidence_class": "usage",
            "independence_group": "network",
            "required": False,
            "minimum_result_count": 1,
            "maximum_age_seconds": 1800,
            "applicability": {"environments": ["production"]},
        },
    )


def _create(db: Session, *, policy_id: str = "default", key: str = "policy-1"):
    return create_verification_policy(
        db,
        tenant_id=TENANT,
        policy_id=policy_id,
        version=1,
        ecosystem_classes=("coding",),
        environments=("production",),
        minimum_evidence_quality=0.8,
        minimum_confidence=0.85,
        minimum_source_diversity=1,
        assertion_ttl_seconds=3600,
        rescan_interval_seconds=1800,
        effective_from=NOW,
        effective_until=NOW + timedelta(days=30),
        requirements=_requirements(),
        actor_id="admin-1",
        idempotency_key=key,
    )


def test_policy_creation_is_immutable_replay_safe_and_explicit() -> None:
    with _database() as db:
        first = _create(db)
        replay = _create(db)
        assert replay.policy_record_id == first.policy_record_id
        assert first.version == 1
        assert [item.requirement_id for item in first.requirements] == [
            "endpoint_identity",
            "network_usage",
        ]

        with pytest.raises(VerificationPolicyConflict, match="idempotency"):
            create_verification_policy(
                db,
                tenant_id=TENANT,
                policy_id="default",
                version=1,
                ecosystem_classes=("coding",),
                environments=("production",),
                minimum_evidence_quality=0.7,
                minimum_confidence=0.85,
                minimum_source_diversity=1,
                assertion_ttl_seconds=3600,
                rescan_interval_seconds=1800,
                effective_from=NOW,
                effective_until=NOW + timedelta(days=30),
                requirements=_requirements(),
                actor_id="admin-1",
                idempotency_key="policy-1",
            )


def test_policy_resolution_preserves_required_and_optional_sources() -> None:
    with _database() as db:
        _create(db)
        selected = VerificationPolicyResolver().resolve(
            db,
            tenant_id=TENANT,
            ecosystem_class="coding",
            environment="production",
            at=NOW + timedelta(hours=1),
        )
        assert selected.required_requirement_ids == ("endpoint_identity",)
        assert selected.optional_requirement_ids == ("network_usage",)
        assert selected.substitutions == ()


def test_policy_resolution_rejects_equal_specificity_ambiguity() -> None:
    with _database() as db:
        _create(db, policy_id="first", key="policy-first")
        _create(db, policy_id="second", key="policy-second")
        with pytest.raises(VerificationPolicyConflict, match="ambiguous"):
            VerificationPolicyResolver().resolve(
                db,
                tenant_id=TENANT,
                ecosystem_class="coding",
                environment="production",
                at=NOW + timedelta(hours=1),
            )


def test_policy_rejects_missing_sources_and_invalid_lifecycle_bounds() -> None:
    with _database() as db:
        with pytest.raises(VerificationPolicyConflict, match="requirement"):
            create_verification_policy(
                db,
                tenant_id=TENANT,
                policy_id="empty",
                version=1,
                ecosystem_classes=("coding",),
                environments=("production",),
                minimum_evidence_quality=0.8,
                minimum_confidence=0.8,
                minimum_source_diversity=1,
                assertion_ttl_seconds=3600,
                rescan_interval_seconds=1800,
                effective_from=NOW,
                effective_until=NOW + timedelta(days=1),
                requirements=(),
                actor_id="admin-1",
                idempotency_key="empty-policy",
            )
        assert db.scalars(select(DiscoveryVerificationPolicy)).all() == []

