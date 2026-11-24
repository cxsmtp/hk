from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, fields
from datetime import UTC, datetime, timedelta
import hashlib
import json
from threading import Barrier
from typing import Any, Iterator, get_type_hints

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.services.hmair import scan_service
from app.services.hmair.contracts import DiscoveryScanCreate
from app.services.hmair.deep_scan_contracts import (
    DeepScanCoverageBaseline,
    DeepScanObservationMode,
    DeepScanProfile,
    DeepScanReadinessState,
    DeepScanSourceReadiness,
)
from app.services.hmair.scan_service import (
    ALLOWED_SCAN_TRANSITIONS,
    cancel_scan,
    create_scan,
    finalize_assignment,
    finalize_scan,
    get_scan,
    rescan,
)


class NoCommitSession(Session):
    """A test session that preserves the caller-owned transaction boundary."""

    flush_calls: int
    commit_calls: int
    rollback_calls: int
    allow_fixture_rollback: bool

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0
        self.allow_fixture_rollback = False

    def flush(self, objects: object | None = None) -> None:
        self.flush_calls += 1
        super().flush(objects)

    def commit(self) -> None:
        self.commit_calls += 1
        raise AssertionError("scan service must not commit the caller's transaction")

    def rollback(self) -> None:
        self.rollback_calls += 1
        if not self.allow_fixture_rollback:
            raise AssertionError(
                "scan service must not roll back the caller's transaction"
            )
        super().rollback()


@dataclass(frozen=True)
class HMAIRSeed:
    tenant_id: str
    other_tenant_id: str
    user_id: str
    unscoped_user_id: str
    cross_tenant_user_id: str
    target_ids: tuple[str, str]
    collector_ids: tuple[str, str]
    other_target_id: str
    other_collector_id: str
    scan_create: DiscoveryScanCreate


class _PostgreSQLDiagnostic:
    def __init__(self, *, constraint_name: str) -> None:
        self.constraint_name = constraint_name


class _PostgreSQLUniqueViolation(Exception):
    """Minimal psycopg-shaped unique violation without SQLite text."""

    pgcode = "23505"
    sqlstate = "23505"

    def __init__(self, *, constraint_name: str) -> None:
        super().__init__("duplicate key value violates a database constraint")
        self.diag = _PostgreSQLDiagnostic(constraint_name=constraint_name)


@dataclass(frozen=True)
class ConcurrentHMAIREnv:
    engine: Engine
    session_factory: sessionmaker[Session]
    tenant_id: str
    user_id: str
    target_id: str
    collector_id: str
    scan_id: str
    assignment_id: str


@pytest.fixture()
def db(tmp_path) -> Iterator[NoCommitSession]:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'hmair-scan-service.sqlite3'}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    tables = [
        Tenant.__table__,
        User.__table__,
        UserTenantRole.__table__,
        EvidenceNode.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        DiscoveryScan.__table__,
        DiscoveryScanTarget.__table__,
        DiscoveryScanAssignment.__table__,
    ]
    Base.metadata.create_all(bind=engine, tables=tables)
    factory = sessionmaker(
        bind=engine,
        class_=NoCommitSession,
        autocommit=False,
        autoflush=False,
    )
    session = factory()
    try:
        yield session
    finally:
        session.allow_fixture_rollback = True
        session.rollback()
        session.close()
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))
        engine.dispose()


@pytest.fixture()
def hmair_seed(db: NoCommitSession) -> HMAIRSeed:
    tenant = Tenant(name="HMAIR Primary", slug="hmair-primary")
    other_tenant = Tenant(name="HMAIR Other", slug="hmair-other")
    user = User(
        email="hmair-owner@example.test",
        hashed_password="not-used-by-unit-tests",
        full_name="HMAIR Owner",
    )
    unscoped_user = User(
        email="hmair-unscoped@example.test",
        hashed_password="not-used-by-unit-tests",
        full_name="HMAIR Unscoped",
    )
    cross_tenant_user = User(
        email="hmair-other-owner@example.test",
        hashed_password="not-used-by-unit-tests",
        full_name="HMAIR Other Owner",
    )
    db.add_all(
        [tenant, other_tenant, user, unscoped_user, cross_tenant_user]
    )
    db.flush()
    db.add_all(
        [
            UserTenantRole(
                user_id=user.id,
                tenant_id=tenant.id,
                role="owner",
            ),
            UserTenantRole(
                user_id=cross_tenant_user.id,
                tenant_id=other_tenant.id,
                role="owner",
            ),
        ]
    )
    db.flush()

    targets = (
        _target(
            tenant_id=tenant.id,
            target_id="endpoint-estate",
            target_type="endpoint_group",
        ),
        _target(
            tenant_id=tenant.id,
            target_id="browser-estate",
            target_type="browser_tenant",
        ),
    )
    collectors = (
        _collector(
            tenant_id=tenant.id,
            collector_id="endpoint-collector",
            collector_type="endpoint_metadata",
            supported_targets=["endpoint_group", "browser_tenant"],
        ),
        _collector(
            tenant_id=tenant.id,
            collector_id="browser-collector",
            collector_type="browser_metadata",
            supported_targets=["endpoint_group", "browser_tenant"],
        ),
    )
    other_target = _target(
        tenant_id=other_tenant.id,
        target_id="other-tenant-target",
        target_type="endpoint_group",
    )
    other_collector = _collector(
        tenant_id=other_tenant.id,
        collector_id="other-tenant-collector",
        collector_type="endpoint_metadata",
        supported_targets=["endpoint_group"],
    )
    db.add_all([*targets, *collectors, other_target, other_collector])
    db.flush()
    db.flush_calls = 0

    payload = DiscoveryScanCreate(
        name="Enterprise AI estate scan",
        scan_type="full_enterprise",
        scope={"environment": "production", "business_unit": "all"},
        target_ids=tuple(item.target_id for item in targets),
        collector_ids=tuple(item.collector_id for item in collectors),
        safety_profile="metadata_only",
        dry_run=False,
    )
    return HMAIRSeed(
        tenant_id=tenant.id,
        other_tenant_id=other_tenant.id,
        user_id=user.id,
        unscoped_user_id=unscoped_user.id,
        cross_tenant_user_id=cross_tenant_user.id,
        target_ids=(targets[0].target_id, targets[1].target_id),
        collector_ids=(collectors[0].collector_id, collectors[1].collector_id),
        other_target_id=other_target.target_id,
        other_collector_id=other_collector.collector_id,
        scan_create=payload,
    )


@pytest.fixture()
def concurrent_hmair_env(tmp_path) -> Iterator[ConcurrentHMAIREnv]:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'hmair-concurrency.sqlite3'}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
        finally:
            cursor.close()

    tables = [
        Tenant.__table__,
        User.__table__,
        UserTenantRole.__table__,
        EvidenceNode.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        DiscoveryScan.__table__,
        DiscoveryScanTarget.__table__,
        DiscoveryScanAssignment.__table__,
    ]
    Base.metadata.create_all(bind=engine, tables=tables)
    factory: sessionmaker[Session] = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    tenant_id = "40000000-0000-4000-8000-000000000001"
    user_id = "40000000-0000-4000-8000-000000000002"
    target_id = "concurrent-endpoint-estate"
    collector_id = "concurrent-endpoint-collector"
    scan_id = "40000000-0000-4000-8000-000000000003"
    assignment_id = "40000000-0000-4000-8000-000000000004"
    started_at = datetime(2026, 8, 2, 9, 0)
    with factory() as seed_db:
        seed_db.add_all(
            [
                Tenant(
                    id=tenant_id,
                    name="HMAIR Concurrent",
                    slug="hmair-concurrent",
                ),
                User(
                    id=user_id,
                    email="hmair-concurrent@example.test",
                    hashed_password="not-used-by-unit-tests",
                    full_name="HMAIR Concurrent Owner",
                ),
            ]
        )
        seed_db.flush()
        seed_db.add_all(
            [
                UserTenantRole(
                    user_id=user_id,
                    tenant_id=tenant_id,
                    role="owner",
                ),
                _target(
                    tenant_id=tenant_id,
                    target_id=target_id,
                    target_type="endpoint_group",
                ),
                _collector(
                    tenant_id=tenant_id,
                    collector_id=collector_id,
                    collector_type="endpoint_metadata",
                    supported_targets=["endpoint_group"],
                ),
            ]
        )
        seed_db.flush()
        seed_db.add(
            DiscoveryScan(
                scan_id=scan_id,
                tenant_id=tenant_id,
                name="Concurrent lifecycle scan",
                requested_by=user_id,
                scan_type="targeted",
                scope_json={"environment": "production"},
                safety_profile="metadata_only",
                request_idempotency_key="concurrent-lifecycle-seed",
                request_digest="c" * 64,
                status="running",
                dry_run=False,
                started_at=started_at,
                completed_at=None,
                cancelled_at=None,
                observations_count=0,
                assets_created=0,
                assets_updated=0,
                assets_unresolved=0,
                warnings_json=[],
                errors_json=[],
                coverage_summary_json={},
                evidence_bundle_id=None,
                rescan_of_scan_id=None,
            )
        )
        seed_db.flush()
        seed_db.add(
            DiscoveryScanTarget(
                tenant_id=tenant_id,
                scan_id=scan_id,
                target_id=target_id,
            )
        )
        seed_db.flush()
        seed_db.add(
            DiscoveryScanAssignment(
                assignment_id=assignment_id,
                tenant_id=tenant_id,
                scan_id=scan_id,
                target_id=target_id,
                collector_id=collector_id,
                status="running",
                warning=None,
                error=None,
                started_at=started_at,
                completed_at=None,
                observations_count=0,
            )
        )
        seed_db.commit()

    try:
        yield ConcurrentHMAIREnv(
            engine=engine,
            session_factory=factory,
            tenant_id=tenant_id,
            user_id=user_id,
            target_id=target_id,
            collector_id=collector_id,
            scan_id=scan_id,
            assignment_id=assignment_id,
        )
    finally:
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))
        engine.dispose()


def _target(
    *, tenant_id: str, target_id: str, target_type: str
) -> DiscoveryTarget:
    return DiscoveryTarget(
        target_id=target_id,
        tenant_id=tenant_id,
        target_type=target_type,
        identifier=f"urn:hawk:{target_id}",
        environment="production",
        owner_hint=None,
        credentials_reference=None,
        permitted_methods_json=["metadata"],
        exclusions_json=[],
        rate_limit=10,
        active_scan_allowed=True,
        sensitive_scope=False,
        last_scanned_at=None,
    )


def _collector(
    *,
    tenant_id: str,
    collector_id: str,
    collector_type: str,
    supported_targets: list[str],
) -> DiscoveryCollector:
    return DiscoveryCollector(
        collector_id=collector_id,
        tenant_id=tenant_id,
        collector_type=collector_type,
        version="2.0.0",
        supported_targets_json=supported_targets,
        active_capabilities_json=[],
        passive_capabilities_json=["inventory"],
        permissions_required_json=["metadata.read"],
        sensitive_data_accessed_json=[],
        health="healthy",
        last_success_at=None,
        last_failure_at=None,
        data_residency="tenant_region",
        control_capability="monitor_only",
        schema_version="2.0",
        limitations_json=["metadata only"],
        declaration_hash="a" * 64,
    )


def _scan_request_digest(
    *,
    tenant_id: str,
    requested_by: str | None,
    payload: DiscoveryScanCreate,
    rescan_of_scan_id: str | None = None,
) -> str:
    material = {
        "tenant_id": tenant_id,
        "requested_by": requested_by,
        "rescan_of_scan_id": rescan_of_scan_id,
        "payload": payload.model_dump(mode="json"),
    }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _race_winner_scan(
    *,
    seed: HMAIRSeed,
    key: str,
    payload: DiscoveryScanCreate,
    rescan_of_scan_id: str | None = None,
) -> DiscoveryScan:
    return DiscoveryScan(
        scan_id="50000000-0000-4000-8000-000000000001",
        tenant_id=seed.tenant_id,
        name=payload.name,
        requested_by=seed.user_id,
        scan_type=payload.scan_type,
        scope_json=payload.model_dump(mode="json")["scope"],
        safety_profile=payload.safety_profile,
        request_idempotency_key=key,
        request_digest=_scan_request_digest(
            tenant_id=seed.tenant_id,
            requested_by=seed.user_id,
            payload=payload,
            rescan_of_scan_id=rescan_of_scan_id,
        ),
        status="queued",
        dry_run=payload.dry_run,
        started_at=None,
        completed_at=None,
        cancelled_at=None,
        observations_count=0,
        assets_created=0,
        assets_updated=0,
        assets_unresolved=0,
        warnings_json=[],
        errors_json=[],
        coverage_summary_json={},
        evidence_bundle_id=None,
        rescan_of_scan_id=rescan_of_scan_id,
    )


def _listen_for_first_scan_lookup(
    db: NoCommitSession,
    *,
    winner: DiscoveryScan,
) -> tuple[dict[str, bool], Any]:
    state = {"injected": False}

    def inject_winner(orm_execute_state: Any) -> None:
        if state["injected"] or not orm_execute_state.is_select:
            return
        entities = {
            description.get("entity")
            for description in orm_execute_state.statement.column_descriptions
        }
        if DiscoveryScan not in entities:
            return
        db.add(winner)
        state["injected"] = True

    event.listen(db, "do_orm_execute", inject_winner)
    return state, inject_winner


def _postgresql_integrity_error(*, constraint_name: str) -> IntegrityError:
    return IntegrityError(
        "INSERT INTO discovery_scans (...) VALUES (...) ",
        {},
        _PostgreSQLUniqueViolation(constraint_name=constraint_name),
    )


def _assert_race_parents_intact(
    db: NoCommitSession, *, seed: HMAIRSeed
) -> None:
    assert db.get(Tenant, seed.tenant_id) is not None
    assert db.get(User, seed.user_id) is not None
    assert db.scalar(
        select(UserTenantRole.id).where(
            UserTenantRole.user_id == seed.user_id,
            UserTenantRole.tenant_id == seed.tenant_id,
        )
    ) is not None
    assert db.get(DiscoveryTarget, seed.target_ids[0]) is not None
    assert db.get(DiscoveryCollector, seed.collector_ids[0]) is not None


def _create(
    db: NoCommitSession,
    seed: HMAIRSeed,
    *,
    key: str,
    payload: DiscoveryScanCreate | None = None,
) -> DiscoveryScan:
    return create_scan(
        db,
        tenant_id=seed.tenant_id,
        requested_by=seed.user_id,
        request_idempotency_key=key,
        payload=payload or seed.scan_create,
    )


def _assignment_rows(
    db: NoCommitSession, *, tenant_id: str, scan_id: str
) -> list[DiscoveryScanAssignment]:
    return list(
        db.scalars(
            select(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == tenant_id,
                DiscoveryScanAssignment.scan_id == scan_id,
            )
            .order_by(
                DiscoveryScanAssignment.target_id,
                DiscoveryScanAssignment.collector_id,
            )
        )
    )


def _mark_scan_running(
    db: NoCommitSession, *, scan: DiscoveryScan
) -> list[DiscoveryScanAssignment]:
    now = datetime.now(UTC)
    scan.status = "running"
    scan.started_at = now
    assignments = _assignment_rows(
        db, tenant_id=scan.tenant_id, scan_id=scan.scan_id
    )
    for assignment in assignments:
        assignment.status = "running"
        assignment.started_at = now
    db.flush()
    return assignments


def _complete_source_scan(
    db: NoCommitSession, seed: HMAIRSeed, *, key: str
) -> DiscoveryScan:
    scan = _create(db, seed, key=key)
    assignments = _mark_scan_running(db, scan=scan)
    for assignment in assignments:
        finalize_assignment(
            db,
            tenant_id=seed.tenant_id,
            assignment_id=assignment.assignment_id,
            status="complete",
            observations_count=1,
        )
    completed = finalize_scan(
        db, tenant_id=seed.tenant_id, scan_id=scan.scan_id
    )
    assert completed.status == "complete"
    return completed


def test_allowed_scan_transitions_match_the_approved_terminal_contract() -> None:
    assert ALLOWED_SCAN_TRANSITIONS == {
        "queued": {"running", "cancelled", "failed"},
        "running": {
            "partially_complete",
            "complete",
            "failed",
            "cancelled",
        },
        "partially_complete": set(),
        "complete": set(),
        "failed": set(),
        "cancelled": set(),
    }


def test_create_scan_is_queued_tenant_bound_and_atomic(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="estate-scan-001")

    assert scan.tenant_id == hmair_seed.tenant_id
    assert scan.requested_by == hmair_seed.user_id
    assert scan.status == "queued"
    assert scan.started_at is None
    assert scan.completed_at is None
    assert scan.cancelled_at is None
    assert scan.observations_count == 0
    assert len(scan.request_digest) == 64
    assert set(scan.request_digest) <= set("0123456789abcdef")

    selected_targets = set(
        db.scalars(
            select(DiscoveryScanTarget.target_id).where(
                DiscoveryScanTarget.tenant_id == hmair_seed.tenant_id,
                DiscoveryScanTarget.scan_id == scan.scan_id,
            )
        )
    )
    assignments = _assignment_rows(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )
    assert selected_targets == set(hmair_seed.target_ids)
    assert {
        (item.target_id, item.collector_id) for item in assignments
    } == {
        (target_id, collector_id)
        for target_id in hmair_seed.target_ids
        for collector_id in hmair_seed.collector_ids
    }
    assert {item.status for item in assignments} == {"pending"}
    assert db.flush_calls >= 1
    assert db.commit_calls == 0
    assert db.rollback_calls == 0
    assert db.in_transaction()


@pytest.mark.parametrize(
    "requester_field",
    ["unscoped_user_id", "cross_tenant_user_id"],
)
def test_create_scan_rejects_requester_without_same_tenant_role_safely(
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
    requester_field: str,
) -> None:
    requested_by = getattr(hmair_seed, requester_field)

    with pytest.raises(LookupError) as error:
        create_scan(
            db,
            tenant_id=hmair_seed.tenant_id,
            requested_by=requested_by,
            request_idempotency_key=f"requester-scope-{requester_field}",
            payload=hmair_seed.scan_create,
        )

    assert str(error.value) == "requesting user was not found"
    assert requested_by not in str(error.value)
    assert db.scalar(select(func.count(DiscoveryScan.scan_id))) == 0
    assert db.rollback_calls == 0


def test_create_scan_replay_returns_same_scan_for_normalized_request(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    first = _create(db, hmair_seed, key="estate-scan-replay")
    equivalent = DiscoveryScanCreate(
        name=hmair_seed.scan_create.name,
        scan_type=hmair_seed.scan_create.scan_type,
        scope={"business_unit": "all", "environment": "production"},
        target_ids=hmair_seed.scan_create.target_ids,
        collector_ids=hmair_seed.scan_create.collector_ids,
        safety_profile=hmair_seed.scan_create.safety_profile,
        dry_run=hmair_seed.scan_create.dry_run,
    )

    second = _create(
        db,
        hmair_seed,
        key="estate-scan-replay",
        payload=equivalent,
    )

    assert second.scan_id == first.scan_id
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id,
            DiscoveryScan.request_idempotency_key == "estate-scan-replay",
        )
    ) == 1
    assert db.commit_calls == 0


def test_create_scan_companion_reports_authoritative_creation_and_replay(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    result_type = getattr(scan_service, "ScanMutationResult", None)
    create_with_outcome = getattr(
        scan_service,
        "create_scan_with_outcome",
        None,
    )

    assert result_type is not None
    assert tuple(field.name for field in fields(result_type)) == (
        "scan",
        "created",
    )
    assert result_type.__dataclass_params__.frozen is True
    assert get_type_hints(result_type) == {
        "scan": DiscoveryScan,
        "created": bool,
    }
    assert callable(create_with_outcome)

    first = create_with_outcome(
        db,
        tenant_id=hmair_seed.tenant_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="estate-scan-outcome",
        payload=hmair_seed.scan_create,
    )
    replay = create_with_outcome(
        db,
        tenant_id=hmair_seed.tenant_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="estate-scan-outcome",
        payload=hmair_seed.scan_create,
    )
    legacy = create_scan(
        db,
        tenant_id=hmair_seed.tenant_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="estate-scan-outcome",
        payload=hmair_seed.scan_create,
    )

    assert isinstance(first, result_type)
    assert isinstance(replay, result_type)
    assert first.created is True
    assert replay.created is False
    assert replay.scan.scan_id == first.scan.scan_id
    assert legacy.scan_id == first.scan.scan_id
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id,
            DiscoveryScan.request_idempotency_key == "estate-scan-outcome",
        )
    ) == 1
    assert db.commit_calls == 0


def test_request_idempotency_key_is_scoped_by_tenant(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    primary = _create(db, hmair_seed, key="tenant-local-request-key")
    other_payload = hmair_seed.scan_create.model_copy(
        update={
            "target_ids": (hmair_seed.other_target_id,),
            "collector_ids": (hmair_seed.other_collector_id,),
        }
    )

    other = create_scan(
        db,
        tenant_id=hmair_seed.other_tenant_id,
        requested_by=hmair_seed.cross_tenant_user_id,
        request_idempotency_key="tenant-local-request-key",
        payload=other_payload,
    )

    assert other.scan_id != primary.scan_id
    assert other.tenant_id == hmair_seed.other_tenant_id
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.request_idempotency_key == "tenant-local-request-key"
        )
    ) == 2


def test_create_scan_replay_with_altered_request_is_a_conflict(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    first = _create(db, hmair_seed, key="estate-scan-conflict")
    altered = hmair_seed.scan_create.model_copy(
        update={"name": "A different scan request"}
    )

    with pytest.raises(ValueError):
        _create(
            db,
            hmair_seed,
            key="estate-scan-conflict",
            payload=altered,
        )

    replayed = get_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=first.scan_id
    )
    assert replayed is not None
    assert replayed.scan_id == first.scan_id
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id
        )
    ) == 1


def test_request_key_unique_race_returns_same_digest_savepoint_winner(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    key = "concurrent-request-winner"
    winner = _race_winner_scan(
        seed=hmair_seed,
        key=key,
        payload=hmair_seed.scan_create,
    )
    injection, listener = _listen_for_first_scan_lookup(db, winner=winner)
    try:
        row = _create(db, hmair_seed, key=key)
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert row.scan_id == winner.scan_id
    assert row.request_digest == winner.request_digest
    assert db.rollback_calls == 0
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id,
            DiscoveryScan.request_idempotency_key == key,
        )
    ) == 1
    _assert_race_parents_intact(db, seed=hmair_seed)


def test_request_key_unique_race_outcome_marks_loser_as_replayed(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    create_with_outcome = getattr(
        scan_service,
        "create_scan_with_outcome",
        None,
    )
    assert callable(create_with_outcome)
    key = "concurrent-request-outcome"
    winner = _race_winner_scan(
        seed=hmair_seed,
        key=key,
        payload=hmair_seed.scan_create,
    )
    injection, listener = _listen_for_first_scan_lookup(db, winner=winner)
    try:
        outcome = create_with_outcome(
            db,
            tenant_id=hmair_seed.tenant_id,
            requested_by=hmair_seed.user_id,
            request_idempotency_key=key,
            payload=hmair_seed.scan_create,
        )
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert outcome.created is False
    assert outcome.scan.scan_id == winner.scan_id
    assert outcome.scan.request_digest == winner.request_digest
    assert db.rollback_calls == 0
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id,
            DiscoveryScan.request_idempotency_key == key,
        )
    ) == 1
    _assert_race_parents_intact(db, seed=hmair_seed)


def test_request_key_unique_race_rejects_altered_digest_without_rollback(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    key = "concurrent-request-conflict"
    winner = _race_winner_scan(
        seed=hmair_seed,
        key=key,
        payload=hmair_seed.scan_create,
    )
    altered = hmair_seed.scan_create.model_copy(
        update={"name": "Altered concurrent scan"}
    )
    injection, listener = _listen_for_first_scan_lookup(db, winner=winner)
    try:
        with pytest.raises(ValueError):
            _create(db, hmair_seed, key=key, payload=altered)
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert db.rollback_calls == 0
    persisted = db.scalar(
        select(DiscoveryScan).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id,
            DiscoveryScan.request_idempotency_key == key,
        )
    )
    assert persisted is not None
    assert persisted.scan_id == winner.scan_id
    assert persisted.request_digest == winner.request_digest
    _assert_race_parents_intact(db, seed=hmair_seed)


def test_postgresql_request_constraint_race_is_detected_portably(
    monkeypatch: pytest.MonkeyPatch,
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
) -> None:
    key = "postgresql-request-winner"
    winner = _race_winner_scan(
        seed=hmair_seed,
        key=key,
        payload=hmair_seed.scan_create,
    )
    injection, listener = _listen_for_first_scan_lookup(db, winner=winner)
    original_flush = db.flush
    raised_postgresql_conflict = False
    postgresql_conflict = _postgresql_integrity_error(
        constraint_name="uq_discovery_scan_tenant_request"
    )
    assert postgresql_conflict.orig.diag.constraint_name == (
        "uq_discovery_scan_tenant_request"
    )
    assert "UNIQUE constraint failed" not in str(postgresql_conflict)

    def flush_with_postgresql_conflict(
        objects: object | None = None,
    ) -> None:
        nonlocal raised_postgresql_conflict
        pending_scans = [
            item for item in db.new if isinstance(item, DiscoveryScan)
        ]
        winner_is_pending = any(item is winner for item in pending_scans)
        if (
            not raised_postgresql_conflict
            and pending_scans
            and not winner_is_pending
        ):
            raised_postgresql_conflict = True
            raise postgresql_conflict
        original_flush(objects)

    monkeypatch.setattr(db, "flush", flush_with_postgresql_conflict)
    try:
        row = _create(db, hmair_seed, key=key)
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert raised_postgresql_conflict is True
    assert row.scan_id == winner.scan_id
    assert db.rollback_calls == 0
    _assert_race_parents_intact(db, seed=hmair_seed)


def test_non_request_unique_constraint_is_not_swallowed(
    monkeypatch: pytest.MonkeyPatch,
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
) -> None:
    key = "postgresql-other-constraint"
    winner = _race_winner_scan(
        seed=hmair_seed,
        key=key,
        payload=hmair_seed.scan_create,
    )
    _injection, listener = _listen_for_first_scan_lookup(db, winner=winner)
    original_flush = db.flush
    raised_postgresql_conflict = False
    postgresql_conflict = _postgresql_integrity_error(
        constraint_name="uq_discovery_scan_tenant_id"
    )

    def flush_with_other_constraint(
        objects: object | None = None,
    ) -> None:
        nonlocal raised_postgresql_conflict
        pending_scans = [
            item for item in db.new if isinstance(item, DiscoveryScan)
        ]
        winner_is_pending = any(item is winner for item in pending_scans)
        if (
            not raised_postgresql_conflict
            and pending_scans
            and not winner_is_pending
        ):
            raised_postgresql_conflict = True
            raise postgresql_conflict
        original_flush(objects)

    monkeypatch.setattr(db, "flush", flush_with_other_constraint)
    try:
        with pytest.raises(IntegrityError) as caught:
            _create(db, hmair_seed, key=key)
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert caught.value is postgresql_conflict
    assert raised_postgresql_conflict is True
    assert db.rollback_calls == 0
    _assert_race_parents_intact(db, seed=hmair_seed)


@pytest.mark.parametrize("request_key", ["", "x" * 129])
def test_create_scan_rejects_unbounded_request_idempotency_keys(
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
    request_key: str,
) -> None:
    with pytest.raises(ValueError):
        _create(db, hmair_seed, key=request_key)

    assert db.scalar(select(func.count(DiscoveryScan.scan_id))) == 0
    assert not any(isinstance(item, DiscoveryScan) for item in db.new)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("target_ids", ("missing-target",)),
        ("collector_ids", ("missing-collector",)),
    ],
)
def test_create_scan_rejects_missing_targets_or_collectors_without_partial_rows(
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
    field: str,
    replacement: tuple[str, ...],
) -> None:
    payload = hmair_seed.scan_create.model_copy(update={field: replacement})

    with pytest.raises(LookupError):
        _create(db, hmair_seed, key=f"missing-{field}", payload=payload)

    assert db.scalar(select(func.count(DiscoveryScan.scan_id))) == 0
    assert db.scalar(select(func.count(DiscoveryScanTarget.scan_id))) == 0
    assert db.scalar(select(func.count(DiscoveryScanAssignment.assignment_id))) == 0
    assert not any(
        isinstance(
            item,
            (DiscoveryScan, DiscoveryScanTarget, DiscoveryScanAssignment),
        )
        for item in db.new
    )
    assert db.rollback_calls == 0


@pytest.mark.parametrize(
    ("field", "foreign_id"),
    [
        ("target_ids", "other_target_id"),
        ("collector_ids", "other_collector_id"),
    ],
)
def test_create_scan_rejects_cross_tenant_targets_or_collectors(
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
    field: str,
    foreign_id: str,
) -> None:
    payload = hmair_seed.scan_create.model_copy(
        update={field: (getattr(hmair_seed, foreign_id),)}
    )

    with pytest.raises(LookupError):
        _create(db, hmair_seed, key=f"cross-tenant-{field}", payload=payload)

    assert db.scalar(select(func.count(DiscoveryScan.scan_id))) == 0
    assert db.commit_calls == 0


def test_get_scan_hides_cross_tenant_and_missing_resources(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="tenant-get")

    found = get_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )
    assert found is not None
    assert found.scan_id == scan.scan_id
    assert (
        get_scan(
            db,
            tenant_id=hmair_seed.other_tenant_id,
            scan_id=scan.scan_id,
        )
        is None
    )
    assert (
        get_scan(
            db,
            tenant_id=hmair_seed.tenant_id,
            scan_id="00000000-0000-0000-0000-000000000000",
        )
        is None
    )


def test_cancel_scan_is_idempotent_and_never_commits(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="cancel-idempotent")

    first = cancel_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )
    first_cancelled_at = first.cancelled_at
    second = cancel_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert first.status == second.status == "cancelled"
    assert first_cancelled_at is not None
    assert second.cancelled_at == first_cancelled_at
    assert db.commit_calls == 0


def test_cancel_scan_companion_exposes_the_frozen_outcome_contract() -> None:
    result_type = getattr(scan_service, "ScanCancellationResult", None)
    cancel_with_outcome = getattr(
        scan_service,
        "cancel_scan_with_outcome",
        None,
    )

    assert result_type is not None
    assert tuple(field.name for field in fields(result_type)) == (
        "scan",
        "changed",
        "previous_status",
    )
    assert result_type.__dataclass_params__.frozen is True
    assert get_type_hints(result_type) == {
        "scan": DiscoveryScan,
        "changed": bool,
        "previous_status": str,
    }
    assert callable(cancel_with_outcome)


@pytest.mark.parametrize("initial_status", ["queued", "running"])
def test_cancel_scan_companion_reports_the_first_transition_once(
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
    initial_status: str,
) -> None:
    cancel_with_outcome = getattr(
        scan_service,
        "cancel_scan_with_outcome",
        None,
    )
    assert callable(cancel_with_outcome)
    scan = _create(
        db,
        hmair_seed,
        key=f"cancel-outcome-{initial_status}",
    )
    if initial_status == "running":
        _mark_scan_running(db, scan=scan)
    started_at = scan.started_at

    outcome = cancel_with_outcome(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=scan.scan_id,
    )

    assert outcome.changed is True
    assert outcome.previous_status == initial_status
    assert outcome.scan.scan_id == scan.scan_id
    assert outcome.scan.status == "cancelled"
    assert outcome.scan.started_at == started_at
    assert outcome.scan.completed_at is None
    assert outcome.scan.cancelled_at is not None
    assert db.commit_calls == 0


def test_cancel_scan_companion_replay_is_unchanged_and_preserves_timestamp(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    cancel_with_outcome = getattr(
        scan_service,
        "cancel_scan_with_outcome",
        None,
    )
    assert callable(cancel_with_outcome)
    scan = _create(db, hmair_seed, key="cancel-outcome-replay")

    first = cancel_with_outcome(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=scan.scan_id,
    )
    cancelled_at = first.scan.cancelled_at
    replay = cancel_with_outcome(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=scan.scan_id,
    )

    assert first.changed is True
    assert first.previous_status == "queued"
    assert replay.changed is False
    assert replay.previous_status == "cancelled"
    assert replay.scan.status == "cancelled"
    assert replay.scan.cancelled_at == cancelled_at
    assert db.commit_calls == 0


def test_legacy_cancel_scan_remains_a_scan_returning_wrapper(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    result_type = getattr(scan_service, "ScanCancellationResult", None)
    assert result_type is not None
    scan = _create(db, hmair_seed, key="cancel-legacy-wrapper")

    first = cancel_scan(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=scan.scan_id,
    )
    replay = cancel_scan(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=scan.scan_id,
    )

    assert isinstance(first, DiscoveryScan)
    assert not isinstance(first, result_type)
    assert replay is first
    assert replay.status == "cancelled"
    assert db.commit_calls == 0


def test_concurrent_cancel_outcomes_serialize_to_one_changed_transition(
    concurrent_hmair_env: ConcurrentHMAIREnv,
) -> None:
    cancel_with_outcome = getattr(
        scan_service,
        "cancel_scan_with_outcome",
        None,
    )
    assert callable(cancel_with_outcome)
    ready = Barrier(2)

    def cancel_in_transaction() -> tuple[bool, str, str, datetime | None]:
        with concurrent_hmair_env.session_factory() as worker_db:
            ready.wait(timeout=5)
            # SQLite does not render SELECT FOR UPDATE. BEGIN IMMEDIATE gives
            # this real two-connection test the same serialized write boundary
            # that the service's row lock provides on PostgreSQL.
            worker_db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            outcome = cancel_with_outcome(
                worker_db,
                tenant_id=concurrent_hmair_env.tenant_id,
                scan_id=concurrent_hmair_env.scan_id,
            )
            values = (
                outcome.changed,
                outcome.previous_status,
                outcome.scan.status,
                outcome.scan.cancelled_at,
            )
            worker_db.commit()
            return values

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(cancel_in_transaction) for _ in range(2)]
        outcomes = [future.result(timeout=10) for future in futures]

    assert sorted(outcome[0] for outcome in outcomes) == [False, True]
    assert sorted(outcome[1] for outcome in outcomes) == [
        "cancelled",
        "running",
    ]
    assert {outcome[2] for outcome in outcomes} == {"cancelled"}
    assert len({outcome[3] for outcome in outcomes}) == 1
    assert outcomes[0][3] is not None

    with concurrent_hmair_env.session_factory() as read_db:
        persisted = read_db.get(
            DiscoveryScan,
            concurrent_hmair_env.scan_id,
        )
        assert persisted is not None
        assert persisted.status == "cancelled"
        assert persisted.cancelled_at is not None
        assert persisted.cancelled_at.replace(tzinfo=UTC) == outcomes[0][3]


def test_cancel_scan_rejects_cross_tenant_resource_as_not_found(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="cancel-cross-tenant")

    with pytest.raises(LookupError):
        cancel_scan(
            db,
            tenant_id=hmair_seed.other_tenant_id,
            scan_id=scan.scan_id,
        )

    assert scan.status == "queued"
    assert scan.cancelled_at is None


def test_cancel_scan_allows_running_to_cancelled_transition(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="cancel-running")
    _mark_scan_running(db, scan=scan)

    cancelled = cancel_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert cancelled.status == "cancelled"
    assert cancelled.started_at is not None
    assert cancelled.completed_at is None
    assert cancelled.cancelled_at is not None


def test_cancel_scan_cannot_reopen_or_replace_a_terminal_completion(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _complete_source_scan(db, hmair_seed, key="cancel-terminal")
    completed_at = scan.completed_at

    with pytest.raises(ValueError):
        cancel_scan(
            db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
        )

    assert scan.status == "complete"
    assert scan.completed_at == completed_at
    assert scan.cancelled_at is None


@pytest.mark.parametrize(
    ("terminal_status", "assignment_statuses"),
    [
        ("partially_complete", ("complete", "failed", "failed", "failed")),
        ("failed", ("failed", "failed", "failed", "failed")),
    ],
)
def test_cancel_scan_rejects_other_terminal_outcomes(
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
    terminal_status: str,
    assignment_statuses: tuple[str, str, str, str],
) -> None:
    scan = _create(db, hmair_seed, key=f"cancel-{terminal_status}")
    assignments = _mark_scan_running(db, scan=scan)
    for assignment, assignment_status in zip(
        assignments, assignment_statuses, strict=True
    ):
        finalize_assignment(
            db,
            tenant_id=hmair_seed.tenant_id,
            assignment_id=assignment.assignment_id,
            status=assignment_status,
            observations_count=1 if assignment_status == "complete" else 0,
        )
    finalized = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )
    assert finalized.status == terminal_status
    completed_at = finalized.completed_at

    with pytest.raises(ValueError):
        cancel_scan(
            db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
        )

    assert finalized.status == terminal_status
    assert finalized.completed_at == completed_at
    assert finalized.cancelled_at is None


def test_finalize_scan_all_successful_is_complete_and_sums_observations(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="finalize-complete")
    assignments = _mark_scan_running(db, scan=scan)
    observation_counts = [1, 2, 3, 4]
    for assignment, count in zip(assignments, observation_counts, strict=True):
        finalized = finalize_assignment(
            db,
            tenant_id=hmair_seed.tenant_id,
            assignment_id=assignment.assignment_id,
            status="complete",
            observations_count=count,
        )
        assert finalized.completed_at is not None

    finalized_scan = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert finalized_scan.status == "complete"
    assert finalized_scan.observations_count == sum(observation_counts)
    assert finalized_scan.completed_at is not None
    assert finalized_scan.cancelled_at is None
    assert db.commit_calls == 0
    completed_at = finalized_scan.completed_at

    replayed = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )
    assert replayed.status == "complete"
    assert replayed.observations_count == sum(observation_counts)
    assert replayed.completed_at == completed_at


def test_deep_scan_without_reconciled_coverage_remains_partially_complete(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    now = datetime.now(UTC)
    source = DeepScanSourceReadiness(
        target_id=hmair_seed.target_ids[0],
        collector_id=hmair_seed.collector_ids[0],
        target_type="endpoint_group",
        required=True,
        state=DeepScanReadinessState.READY,
        observation_mode=DeepScanObservationMode.AUTHORITATIVE,
        expected_count=1,
        baseline=DeepScanCoverageBaseline(
            expected_count=1,
            authority_kind="mdm",
            authority_reference="mdm-2026-09",
            verified_at=now,
            expires_at=now.replace(year=now.year + 1),
        ),
        last_success_at=now,
    )
    profile = DeepScanProfile(
        version="v1",
        mode="full_enterprise",
        sources=(source,),
        customer_authorization_reference="approval-2026-09",
        window_start=now,
        window_end=now + timedelta(minutes=1),
        issued_at=now,
        expires_at=now.replace(year=now.year + 1),
        digest="b" * 64,
    )
    payload = DiscoveryScanCreate(
        name="Deep Scan coverage gate",
        scan_type="full_enterprise",
        scope={"deep_scan": profile.model_dump(mode="json")},
        target_ids=(hmair_seed.target_ids[0],),
        collector_ids=(hmair_seed.collector_ids[0],),
        safety_profile="metadata_only",
        dry_run=False,
    )
    scan = _create(db, hmair_seed, key="deep-scan-coverage-gate", payload=payload)
    assignments = _mark_scan_running(db, scan=scan)
    assert len(assignments) == 1
    finalize_assignment(
        db,
        tenant_id=hmair_seed.tenant_id,
        assignment_id=assignments[0].assignment_id,
        status="complete",
        observations_count=1,
    )

    finalized = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert finalized.status == "partially_complete"


@pytest.mark.parametrize(
    "non_success_status",
    [
        "failed",
        "permission_denied",
        "unsupported",
        "stale",
        "rate_limited",
        "empty",
        "cancelled",
    ],
)
def test_any_non_success_with_a_success_is_partially_complete(
    db: NoCommitSession,
    hmair_seed: HMAIRSeed,
    non_success_status: str,
) -> None:
    scan = _create(
        db, hmair_seed, key=f"finalize-partial-{non_success_status}"
    )
    assignments = _mark_scan_running(db, scan=scan)
    outcomes = [
        ("complete", 4),
        (non_success_status, 0),
        ("complete", 2),
        ("complete", 1),
    ]
    for assignment, (status, count) in zip(assignments, outcomes, strict=True):
        finalize_assignment(
            db,
            tenant_id=hmair_seed.tenant_id,
            assignment_id=assignment.assignment_id,
            status=status,
            observations_count=count,
        )

    finalized_scan = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert finalized_scan.status == "partially_complete"
    assert finalized_scan.observations_count == 7
    assert finalized_scan.completed_at is not None


def test_finalize_scan_failed_before_any_success_is_failed(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="finalize-failed")
    assignments = _mark_scan_running(db, scan=scan)
    outcomes = ["failed", "permission_denied", "unsupported", "failed"]
    for assignment, status in zip(assignments, outcomes, strict=True):
        finalize_assignment(
            db,
            tenant_id=hmair_seed.tenant_id,
            assignment_id=assignment.assignment_id,
            status=status,
            observations_count=0,
        )

    finalized_scan = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert finalized_scan.status == "failed"
    assert finalized_scan.observations_count == 0
    assert finalized_scan.completed_at is not None


def test_finalize_scan_remains_running_while_assignments_are_active(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="finalize-still-running")
    assignments = _mark_scan_running(db, scan=scan)
    finalize_assignment(
        db,
        tenant_id=hmair_seed.tenant_id,
        assignment_id=assignments[0].assignment_id,
        status="complete",
        observations_count=2,
    )

    finalized_scan = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert finalized_scan.status == "running"
    assert finalized_scan.completed_at is None
    assert finalized_scan.observations_count == 2


def test_finalize_cancelled_scan_preserves_cancellation_outcome(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="finalize-cancelled")
    cancelled = cancel_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )
    cancelled_at = cancelled.cancelled_at

    finalized_scan = finalize_scan(
        db, tenant_id=hmair_seed.tenant_id, scan_id=scan.scan_id
    )

    assert finalized_scan.status == "cancelled"
    assert finalized_scan.cancelled_at == cancelled_at
    assert finalized_scan.completed_at is None


def test_finalize_assignment_is_tenant_scoped(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="assignment-tenant")
    assignment = _mark_scan_running(db, scan=scan)[0]

    with pytest.raises(LookupError):
        finalize_assignment(
            db,
            tenant_id=hmair_seed.other_tenant_id,
            assignment_id=assignment.assignment_id,
            status="complete",
            observations_count=1,
        )

    assert assignment.status == "running"
    assert assignment.completed_at is None


def test_finalize_scan_rejects_cross_tenant_and_missing_scans(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    scan = _create(db, hmair_seed, key="finalize-tenant")
    _mark_scan_running(db, scan=scan)

    with pytest.raises(LookupError):
        finalize_scan(
            db,
            tenant_id=hmair_seed.other_tenant_id,
            scan_id=scan.scan_id,
        )
    with pytest.raises(LookupError):
        finalize_scan(
            db,
            tenant_id=hmair_seed.tenant_id,
            scan_id="00000000-0000-0000-0000-000000000000",
        )

    assert scan.status == "running"
    assert scan.completed_at is None
    assert db.rollback_calls == 0


def test_rescan_copies_selections_preserves_history_and_replays_idempotently(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    source = _complete_source_scan(db, hmair_seed, key="rescan-source")
    source_completed_at = source.completed_at
    original_pairs = {
        (item.target_id, item.collector_id)
        for item in _assignment_rows(
            db,
            tenant_id=hmair_seed.tenant_id,
            scan_id=source.scan_id,
        )
    }

    first = rescan(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=source.scan_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="rescan-001",
    )
    second = rescan(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=source.scan_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="rescan-001",
    )

    assert first.scan_id == second.scan_id
    assert first.scan_id != source.scan_id
    assert first.status == "queued"
    assert first.rescan_of_scan_id == source.scan_id
    assert first.name == source.name
    assert first.scope_json == source.scope_json
    assert first.safety_profile == source.safety_profile
    assert first.dry_run == source.dry_run
    copied_targets = set(
        db.scalars(
            select(DiscoveryScanTarget.target_id).where(
                DiscoveryScanTarget.tenant_id == hmair_seed.tenant_id,
                DiscoveryScanTarget.scan_id == first.scan_id,
            )
        )
    )
    copied_pairs = {
        (item.target_id, item.collector_id)
        for item in _assignment_rows(
            db,
            tenant_id=hmair_seed.tenant_id,
            scan_id=first.scan_id,
        )
    }
    assert copied_targets == set(hmair_seed.target_ids)
    assert copied_pairs == original_pairs
    assert source.status == "complete"
    assert source.completed_at == source_completed_at
    assert source.rescan_of_scan_id is None
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id
        )
    ) == 2
    assert db.commit_calls == 0


def test_rescan_companion_reports_authoritative_creation_and_replay(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    rescan_with_outcome = getattr(
        scan_service,
        "rescan_with_outcome",
        None,
    )
    assert callable(rescan_with_outcome)
    source = _complete_source_scan(
        db,
        hmair_seed,
        key="rescan-outcome-source",
    )

    first = rescan_with_outcome(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=source.scan_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="rescan-outcome",
    )
    replay = rescan_with_outcome(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=source.scan_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="rescan-outcome",
    )
    legacy = rescan(
        db,
        tenant_id=hmair_seed.tenant_id,
        scan_id=source.scan_id,
        requested_by=hmair_seed.user_id,
        request_idempotency_key="rescan-outcome",
    )

    assert first.created is True
    assert replay.created is False
    assert replay.scan.scan_id == first.scan.scan_id
    assert replay.scan.rescan_of_scan_id == source.scan_id
    assert legacy.scan_id == first.scan.scan_id
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id,
            DiscoveryScan.request_idempotency_key == "rescan-outcome",
        )
    ) == 1
    assert db.commit_calls == 0


def test_rescan_unique_key_race_outcome_marks_loser_as_replayed(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    rescan_with_outcome = getattr(
        scan_service,
        "rescan_with_outcome",
        None,
    )
    assert callable(rescan_with_outcome)
    source = _complete_source_scan(
        db,
        hmair_seed,
        key="rescan-race-source",
    )
    key = "rescan-race-outcome"
    payload = DiscoveryScanCreate(
        name=source.name,
        scan_type=source.scan_type,
        scope=source.scope_json,
        target_ids=tuple(sorted(hmair_seed.target_ids)),
        collector_ids=tuple(sorted(hmair_seed.collector_ids)),
        safety_profile=source.safety_profile,
        dry_run=source.dry_run,
    )
    winner = _race_winner_scan(
        seed=hmair_seed,
        key=key,
        payload=payload,
        rescan_of_scan_id=source.scan_id,
    )
    injection, listener = _listen_for_first_scan_lookup(db, winner=winner)
    try:
        outcome = rescan_with_outcome(
            db,
            tenant_id=hmair_seed.tenant_id,
            scan_id=source.scan_id,
            requested_by=hmair_seed.user_id,
            request_idempotency_key=key,
        )
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert outcome.created is False
    assert outcome.scan.scan_id == winner.scan_id
    assert outcome.scan.request_digest == winner.request_digest
    assert outcome.scan.rescan_of_scan_id == source.scan_id
    assert db.rollback_calls == 0
    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id,
            DiscoveryScan.request_idempotency_key == key,
        )
    ) == 1
    _assert_race_parents_intact(db, seed=hmair_seed)


def test_rescan_rejects_cross_tenant_and_missing_source_scans(
    db: NoCommitSession, hmair_seed: HMAIRSeed
) -> None:
    source = _complete_source_scan(
        db, hmair_seed, key="rescan-tenant-source"
    )

    with pytest.raises(LookupError):
        rescan(
            db,
            tenant_id=hmair_seed.other_tenant_id,
            scan_id=source.scan_id,
            requested_by=hmair_seed.user_id,
            request_idempotency_key="cross-tenant-rescan",
        )
    with pytest.raises(LookupError):
        rescan(
            db,
            tenant_id=hmair_seed.tenant_id,
            scan_id="00000000-0000-0000-0000-000000000000",
            requested_by=hmair_seed.user_id,
            request_idempotency_key="missing-rescan",
        )

    assert db.scalar(
        select(func.count(DiscoveryScan.scan_id)).where(
            DiscoveryScan.tenant_id == hmair_seed.tenant_id
        )
    ) == 1
    assert db.commit_calls == 0


def test_stale_cancel_cannot_overwrite_concurrent_terminal_completion(
    concurrent_hmair_env: ConcurrentHMAIREnv,
) -> None:
    factory = concurrent_hmair_env.session_factory
    terminal_at = datetime(2026, 8, 2, 10, 0)
    with factory() as stale_db:
        stale = stale_db.get(DiscoveryScan, concurrent_hmair_env.scan_id)
        assert stale is not None
        assert stale.status == "running"
        stale_db.commit()

        with factory() as winner_db:
            winner = winner_db.get(
                DiscoveryScan, concurrent_hmair_env.scan_id
            )
            assert winner is not None
            winner.status = "complete"
            winner.completed_at = terminal_at
            winner.cancelled_at = None
            winner.observations_count = 9
            winner_db.commit()

        assert stale.status == "running"
        try:
            result = cancel_scan(
                stale_db,
                tenant_id=concurrent_hmair_env.tenant_id,
                scan_id=concurrent_hmair_env.scan_id,
            )
        except ValueError:
            result = None
        if result is not None:
            assert result.status == "complete"
        stale_db.commit()

    with factory() as read_db:
        persisted = read_db.get(
            DiscoveryScan, concurrent_hmair_env.scan_id
        )
        assert persisted is not None
        assert persisted.status == "complete"
        assert persisted.completed_at == terminal_at
        assert persisted.cancelled_at is None
        assert persisted.observations_count == 9


def test_stale_finalize_cannot_overwrite_concurrent_cancellation(
    concurrent_hmair_env: ConcurrentHMAIREnv,
) -> None:
    factory = concurrent_hmair_env.session_factory
    terminal_at = datetime(2026, 8, 2, 10, 5)
    with factory() as stale_db:
        stale = stale_db.get(DiscoveryScan, concurrent_hmair_env.scan_id)
        assert stale is not None
        assert stale.status == "running"
        stale_db.commit()

        with factory() as winner_db:
            winner = winner_db.get(
                DiscoveryScan, concurrent_hmair_env.scan_id
            )
            assignment = winner_db.get(
                DiscoveryScanAssignment,
                concurrent_hmair_env.assignment_id,
            )
            assert winner is not None
            assert assignment is not None
            winner.status = "cancelled"
            winner.completed_at = None
            winner.cancelled_at = terminal_at
            assignment.status = "complete"
            assignment.completed_at = terminal_at
            assignment.observations_count = 6
            winner_db.commit()

        assert stale.status == "running"
        try:
            result = finalize_scan(
                stale_db,
                tenant_id=concurrent_hmair_env.tenant_id,
                scan_id=concurrent_hmair_env.scan_id,
            )
        except ValueError:
            result = None
        if result is not None:
            assert result.status == "cancelled"
        stale_db.commit()

    with factory() as read_db:
        persisted = read_db.get(
            DiscoveryScan, concurrent_hmair_env.scan_id
        )
        assert persisted is not None
        assert persisted.status == "cancelled"
        assert persisted.completed_at is None
        assert persisted.cancelled_at == terminal_at
        assert persisted.observations_count == 0


def test_stale_assignment_finalize_cannot_rewrite_terminal_winner(
    concurrent_hmair_env: ConcurrentHMAIREnv,
) -> None:
    factory = concurrent_hmair_env.session_factory
    terminal_at = datetime(2026, 8, 2, 10, 10)
    with factory() as stale_db:
        stale = stale_db.get(
            DiscoveryScanAssignment,
            concurrent_hmair_env.assignment_id,
        )
        assert stale is not None
        assert stale.status == "running"
        stale_db.commit()

        with factory() as winner_db:
            winner = winner_db.get(
                DiscoveryScanAssignment,
                concurrent_hmair_env.assignment_id,
            )
            assert winner is not None
            winner.status = "complete"
            winner.completed_at = terminal_at
            winner.observations_count = 7
            winner.warning = "concurrent winner"
            winner.error = None
            winner_db.commit()

        assert stale.status == "running"
        try:
            result = finalize_assignment(
                stale_db,
                tenant_id=concurrent_hmair_env.tenant_id,
                assignment_id=concurrent_hmair_env.assignment_id,
                status="failed",
                observations_count=0,
                error="stale worker failure",
            )
        except ValueError:
            result = None
        if result is not None:
            assert result.status == "complete"
        stale_db.commit()

    with factory() as read_db:
        persisted = read_db.get(
            DiscoveryScanAssignment,
            concurrent_hmair_env.assignment_id,
        )
        assert persisted is not None
        assert persisted.status == "complete"
        assert persisted.completed_at == terminal_at
        assert persisted.observations_count == 7
        assert persisted.warning == "concurrent winner"
        assert persisted.error is None
