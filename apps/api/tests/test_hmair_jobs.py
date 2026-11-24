from __future__ import annotations

import importlib
import inspect
import os
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
import subprocess
import sys
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest
import yaml
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryObservation,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.services.hmair.collector_sdk import (
    CollectorHealthReport,
    CollectorRecord,
    CollectorTerminalOutcome,
    ConnectivityResult,
    DiscoveryTargetView,
    ScopeItem,
)
from app.services.hmair.contracts import (
    CollectorDeclaration,
    CollectorRunStatus,
    DiscoveryObservationInput,
)
from app.services.hmair import scan_service


class _LazyJobsModule:
    """Keep absent Task8 production from blocking independent RED groups."""

    _module_name = "app.jobs.hmair_discovery_jobs"

    def _load(self):
        return importlib.import_module(self._module_name)

    def __getattr__(self, name: str):
        return getattr(self._load(), name)

    def __setattr__(self, name: str, value: object) -> None:
        if name == "_module_name":
            object.__setattr__(self, name, value)
            return
        setattr(self._load(), name, value)

    def __delattr__(self, name: str) -> None:
        delattr(self._load(), name)


jobs = _LazyJobsModule()


def _celery_app():
    from app.jobs.celery_app import celery_app

    return celery_app


TASK_NAMES = (
    "app.jobs.hmair_discovery_jobs.dispatch_scan",
    "app.jobs.hmair_discovery_jobs.run_collector_assignment",
    "app.jobs.hmair_discovery_jobs.finalize_discovery_scan",
    "app.jobs.hmair_discovery_jobs.reconcile_endpoint_metadata_inventory",
    "app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation",
)
EXPECTED_RETRY_POLICY = {
    "autoretry_for": (Exception,),
    "retry_backoff": True,
    "retry_backoff_max": 120,
    "retry_jitter": True,
    "max_retries": 5,
}
_DEFAULT_ASSIGNMENT = object()


class RecordingSession:
    def __init__(self) -> None:
        self.commit_calls = 0
        self.rollback_calls = 0
        self.enter_calls = 0
        self.exit_errors: list[type[BaseException] | None] = []

    def __enter__(self) -> "RecordingSession":
        self.enter_calls += 1
        return self

    def __exit__(
        self,
        error_type: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: object | None,
    ) -> bool:
        self.exit_errors.append(error_type)
        return False

    def commit(self) -> None:
        self.commit_calls += 1

    def rollback(self) -> None:
        self.rollback_calls += 1


class RecordingSessionFactory:
    def __init__(self, *sessions: RecordingSession) -> None:
        self.sessions = list(sessions)
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def __call__(self, *args: object, **kwargs: object) -> RecordingSession:
        self.calls.append((args, kwargs))
        if not self.sessions:
            raise AssertionError("job opened more database sessions than expected")
        return self.sessions.pop(0)


@contextmanager
def _task_request(task: object, *, retries: int):
    task.push_request(retries=retries)
    try:
        yield
    finally:
        task.pop_request()


@contextmanager
def _worker_task_request(
    task: object,
    *,
    task_args: tuple[str, ...],
    retries: int,
    delivery_info: dict[str, object] | None = None,
):
    task.push_request(
        id="hmair-job-test-task",
        args=task_args,
        kwargs={},
        retries=retries,
        called_directly=False,
        is_eager=True,
        delivery_info={} if delivery_info is None else delivery_info,
    )
    try:
        yield
    finally:
        task.pop_request()


def _task_function(task: object):
    return getattr(task, "run")


def _scan(
    *,
    status: str = "queued",
    dry_run: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        tenant_id="tenant-a",
        scan_id="scan-a",
        status=status,
        scan_type="targeted",
        safety_profile="metadata_only",
        dry_run=dry_run,
        observations_count=0,
    )


def _assignment(
    number: int = 1,
    *,
    status: str = "running",
) -> SimpleNamespace:
    return SimpleNamespace(
        assignment_id=f"assignment-{number}",
        scan_id="scan-a",
        collector_id=f"collector-{number}",
        target_id=f"target-{number}",
        status=status,
    )


def _target() -> SimpleNamespace:
    return SimpleNamespace(
        target_id="target-1",
        target_type="endpoint_group",
    )


def _target_view(
    target_type: str = "endpoint_group",
) -> DiscoveryTargetView:
    return DiscoveryTargetView(
        target_id="target-1",
        target_type=target_type,
        identifier=f"urn:hawk:tenant-a:{target_type}:target-1",
        environment="production",
        owner_hint=None,
        credentials_reference=None,
        permitted_methods=("collect_inventory",),
        exclusions=(),
        rate_limit=10,
        active_scan_allowed=True,
        sensitive_scope=False,
        last_scanned_at=None,
    )


def _persisted_collector() -> SimpleNamespace:
    # Registry keys are canonical collector types, not tenant-local collector
    # IDs. This intentionally differs from the assignment's collector_id.
    return SimpleNamespace(
        collector_id="collector-1",
        collector_type="endpoint_metadata",
    )


def _runtime_collector() -> SimpleNamespace:
    return SimpleNamespace(declaration=_collector_declaration(active=False))


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "secret_key": "hmair-job-test-secret",
        "secret_key_lock_enabled": False,
        "connector_secrets_key": "hmair-job-connector-secret",
        "connector_secrets_kdf_salt": "hmair-job-kdf-salt",
        "onprem_bundle_signing_secret": "hmair-job-onprem-secret",
    }
    values.update(overrides)
    return Settings(**values)


def _collector_declaration(
    *,
    active: bool,
    target_type: str = "endpoint_group",
) -> CollectorDeclaration:
    return CollectorDeclaration(
        collector_id="endpoint-metadata-runtime",
        collector_type="endpoint_metadata",
        version="2.0.0",
        supported_targets=(target_type,),
        active_capabilities=("collect_inventory",) if active else (),
        passive_capabilities=("collect_inventory",),
        permissions_required=("metadata.read",),
        sensitive_data_accessed=(),
        health="healthy",
        last_success_at=None,
        last_failure_at=None,
        data_residency="tenant_region",
        control_capability="monitor_only",
        schema_version="2.0",
        limitations=("metadata only",),
        declaration_hash="b" * 64,
    )


def _validated_runtime_collector() -> SimpleNamespace:
    return _runtime_collector()


class _EnvelopeCollector:
    """Real SDK collector whose runtime identity differs from its DB row."""

    def __init__(self) -> None:
        self.declaration = _collector_declaration(active=False)
        self.source_observation = DiscoveryObservationInput(
            observation_id="runtime-observation-1",
            scan_id="runtime-scan-context",
            collector_id=self.declaration.collector_id,
            collector_type=self.declaration.collector_type,
            collector_version=self.declaration.version,
            target_id="target-1",
            source_surface="runtime",
            subject_reference="runtime-a",
            observed_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
            observation_type="running_process",
            normalized_signal={"runtime_family": "local_ai_runtime"},
            candidate_asset_type="runtime",
            observed_state="observed",
            identifiers={"runtime_name": "runtime-a"},
            attributes={"version": "2.0.0"},
            configuration_summary={},
            usage_summary={},
            capability_hints=("local_inference",),
            identity_hints=(),
            relationship_hints=(),
            evidence_reference="evidence://runtime-a/inventory",
            evidence_hash="d" * 64,
            signature_status="verified",
            confidence=0.9,
            freshness="fresh",
            verification_state="verified",
            source_trust="strong",
            collection_scope={"scope_type": "runtime_environment"},
            parser_version="2.0.0",
            schema_version="2.0",
            evidence_mode="direct",
            evidence_mutability="immutable",
            contradiction_state="none",
            contradiction_references=(),
            sensitivity="metadata",
            redaction_status="not_required",
        )
        self.calls: list[str] = []

    def validate_configuration(self, configuration: Mapping[str, Any]) -> None:
        assert isinstance(configuration, Mapping)
        self.calls.append("validate_configuration")

    def test_connectivity(
        self,
        target: DiscoveryTargetView,
    ) -> ConnectivityResult:
        assert target.target_id == "target-1"
        self.calls.append("test_connectivity")
        return ConnectivityResult(
            reachable=True,
            status="available",
            checked_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
            safe_message="connected",
        )

    def enumerate_scope(
        self,
        target: DiscoveryTargetView,
    ) -> tuple[ScopeItem, ...]:
        assert target.target_id == "target-1"
        self.calls.append("enumerate_scope")
        return (
            ScopeItem(
                scope_id="runtime-scope-a",
                scope_type="endpoint_group",
                permitted_methods=("collect_inventory",),
            ),
        )

    def collect_inventory(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]:
        self.calls.append("collect_inventory")
        return (
            CollectorRecord(
                record_type="inventory",
                source_reference=scope.scope_id,
                observed_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
                safe_summary="metadata-only runtime inventory",
            ),
        )

    def collect_configuration(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]:
        del scope
        return ()

    def collect_usage(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]:
        del scope
        return ()

    def collect_identity_hints(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]:
        del scope
        return ()

    def collect_relationship_hints(
        self,
        scope: ScopeItem,
    ) -> tuple[CollectorRecord, ...]:
        del scope
        return ()

    def emit_observations(self) -> tuple[DiscoveryObservationInput, ...]:
        self.calls.append("emit_observations")
        return (self.source_observation,)

    def report_health(self) -> CollectorHealthReport:
        return CollectorHealthReport(
            health="healthy",
            checked_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
            safe_message="healthy",
        )

    def report_limitations(self) -> tuple[str, ...]:
        return ("metadata only",)


def _runtime_observation(
    observation_id: str = "observation-1",
) -> DiscoveryObservationInput:
    return _EnvelopeCollector().source_observation.model_copy(
        update={
            "observation_id": observation_id,
        }
    )


@dataclass(frozen=True)
class JobDatabase:
    engine: object
    factory: sessionmaker


@pytest.fixture()
def job_database(tmp_path) -> JobDatabase:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'hmair-jobs.sqlite3'}",
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
        DiscoveryObservation.__table__,
    ]
    Base.metadata.create_all(bind=engine, tables=tables)
    factory = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    try:
        yield JobDatabase(engine=engine, factory=factory)
    finally:
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))
        engine.dispose()


def _seed_job_scan(
    db: Session,
    *,
    tenant_id: str = "tenant-a",
    scan_id: str = "scan-a",
    statuses: tuple[str, ...] = ("pending",),
    dry_run: bool = False,
) -> tuple[DiscoveryScan, tuple[DiscoveryScanAssignment, ...]]:
    now = datetime.now(UTC)
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        db.add(Tenant(id=tenant_id, name=tenant_id, slug=tenant_id))
        db.flush()
    collector = db.scalar(
        select(DiscoveryCollector).where(
            DiscoveryCollector.tenant_id == tenant_id,
            DiscoveryCollector.collector_id == "collector-1",
        )
    )
    if collector is None:
        db.add(
            DiscoveryCollector(
                collector_id="collector-1",
                tenant_id=tenant_id,
                collector_type="endpoint_metadata",
                version="2.0.0",
                supported_targets_json=["endpoint_group"],
                active_capabilities_json=[],
                passive_capabilities_json=["collect_inventory"],
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
        )
        db.flush()
    running = any(status == "running" for status in statuses)
    scan = DiscoveryScan(
        scan_id=scan_id,
        tenant_id=tenant_id,
        name="Job orchestration scan",
        requested_by=None,
        scan_type="targeted",
        scope_json={"environment": "production"},
        safety_profile="metadata_only",
        request_idempotency_key=f"request-{scan_id}",
        request_digest="c" * 64,
        status="running" if running else "queued",
        dry_run=dry_run,
        started_at=now if running else None,
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
    db.add(scan)
    targets = [
        DiscoveryTarget(
            target_id=f"target-{index}",
            tenant_id=tenant_id,
            target_type="endpoint_group",
            identifier=f"urn:hawk:{tenant_id}:target-{index}",
            environment="production",
            owner_hint=None,
            credentials_reference=None,
            permitted_methods_json=["collect_inventory"],
            exclusions_json=[],
            rate_limit=10,
            active_scan_allowed=True,
            sensitive_scope=False,
            last_scanned_at=None,
        )
        for index in range(1, len(statuses) + 1)
    ]
    db.add_all(targets)
    db.flush()
    db.add_all(
        DiscoveryScanTarget(
            tenant_id=tenant_id,
            scan_id=scan_id,
            target_id=target.target_id,
        )
        for target in targets
    )
    db.flush()
    assignments: list[DiscoveryScanAssignment] = []
    for index, status in enumerate(statuses, start=1):
        target_id = f"target-{index}"
        assignment = DiscoveryScanAssignment(
            assignment_id=f"assignment-{index}",
            tenant_id=tenant_id,
            scan_id=scan_id,
            target_id=target_id,
            collector_id="collector-1",
            status=status,
            warning=None,
            error=None,
            started_at=now if status == "running" else None,
            completed_at=None,
            observations_count=0,
        )
        db.add(assignment)
        assignments.append(assignment)
    db.commit()
    return scan, tuple(assignments)


def _configure_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    session: RecordingSession,
    scan: SimpleNamespace | None,
    batch: tuple[SimpleNamespace, ...] = (),
    maximum: int = 8,
) -> tuple[Mock, Mock, Mock, RecordingSessionFactory]:
    factory = RecordingSessionFactory(session)
    get_scan = Mock(return_value=scan)
    claim_batch = Mock(return_value=batch)
    require_enabled = Mock()
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "get_scan", get_scan)
    monkeypatch.setattr(jobs, "claim_assignment_batch", claim_batch)
    monkeypatch.setattr(jobs, "require_hmair_job_enabled", require_enabled)
    monkeypatch.setattr(
        jobs,
        "settings",
        SimpleNamespace(hmair_max_concurrent_assignments=maximum),
    )
    return get_scan, claim_batch, require_enabled, factory


def _configure_assignment_start(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sessions: tuple[RecordingSession, ...],
    assignment: object = _DEFAULT_ASSIGNMENT,
    target: SimpleNamespace | None = None,
    persisted_collector: SimpleNamespace | None = None,
    runtime_collector: SimpleNamespace | None = None,
) -> tuple[RecordingSessionFactory, Mock, Mock, Mock, Mock, Mock, Mock]:
    factory = RecordingSessionFactory(*sessions)
    started_assignment = (
        _assignment() if assignment is _DEFAULT_ASSIGNMENT else assignment
    )
    start_assignment = Mock(return_value=started_assignment)
    get_target = Mock(return_value=target or _target())
    get_collector = Mock(
        return_value=(
            persisted_collector
            if persisted_collector is not None
            else _persisted_collector()
        )
    )
    registry_get = Mock(
        return_value=(
            runtime_collector
            if runtime_collector is not None
            else _runtime_collector()
        )
    )
    get_scan = Mock(return_value=_scan(status="running"))
    require_enabled = Mock()
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "start_assignment", start_assignment)
    monkeypatch.setattr(jobs, "get_target", get_target)
    monkeypatch.setattr(jobs, "get_collector", get_collector)
    monkeypatch.setattr(
        jobs,
        "collector_registry",
        SimpleNamespace(get=registry_get),
    )
    monkeypatch.setattr(jobs, "get_scan", get_scan)
    monkeypatch.setattr(
        jobs,
        "require_hmair_collector_enabled",
        require_enabled,
    )
    return (
        factory,
        start_assignment,
        get_target,
        get_collector,
        registry_get,
        require_enabled,
        get_scan,
    )


def test_claim_assignment_batch_is_tenant_scoped_bounded_and_duplicate_safe(
    job_database: JobDatabase,
) -> None:
    with job_database.factory() as db:
        scan, _ = _seed_job_scan(
            db,
            statuses=("pending", "pending", "pending", "pending"),
        )

    with job_database.factory() as first_db:
        first = scan_service.claim_assignment_batch(
            first_db,
            tenant_id="tenant-a",
            scan_id=scan.scan_id,
            limit=2,
        )
        assert len(first) == 2
        assert {item.status for item in first} == {"running"}
        first_ids = {item.assignment_id for item in first}
        first_db.commit()

    with job_database.factory() as second_db:
        duplicate = scan_service.claim_assignment_batch(
            second_db,
            tenant_id="tenant-a",
            scan_id=scan.scan_id,
            limit=2,
        )
        assert not duplicate
        assert not scan_service.claim_assignment_batch(
            second_db,
            tenant_id="tenant-b",
            scan_id=scan.scan_id,
            limit=2,
        )
        second_db.commit()

    with job_database.factory() as verify_db:
        running_ids = set(
            verify_db.scalars(
                select(DiscoveryScanAssignment.assignment_id).where(
                    DiscoveryScanAssignment.tenant_id == "tenant-a",
                    DiscoveryScanAssignment.scan_id == scan.scan_id,
                    DiscoveryScanAssignment.status == "running",
                )
            )
        )
        pending_count = verify_db.scalar(
            select(func.count())
            .select_from(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == "tenant-a",
                DiscoveryScanAssignment.scan_id == scan.scan_id,
                DiscoveryScanAssignment.status == "pending",
            )
        )
    assert running_ids == first_ids
    assert pending_count == 2


def test_claim_assignment_batch_uses_remaining_running_slots(
    job_database: JobDatabase,
) -> None:
    with job_database.factory() as db:
        scan, _ = _seed_job_scan(
            db,
            statuses=("running", "pending", "pending", "pending"),
        )

    with job_database.factory() as db:
        claimed = scan_service.claim_assignment_batch(
            db,
            tenant_id="tenant-a",
            scan_id=scan.scan_id,
            limit=2,
        )
        db.commit()

    assert len(claimed) == 1
    with job_database.factory() as db:
        running_count = db.scalar(
            select(func.count())
            .select_from(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == "tenant-a",
                DiscoveryScanAssignment.scan_id == scan.scan_id,
                DiscoveryScanAssignment.status == "running",
            )
        )
    assert running_count == 2


def test_claim_assignment_batch_emits_postgresql_skip_locked_query(
    job_database: JobDatabase,
) -> None:
    with job_database.factory() as db:
        scan, _ = _seed_job_scan(db, statuses=("pending", "pending"))

    compiled_queries: list[str] = []

    def capture_query(
        _connection: object,
        clause: object,
        _multiparams: object,
        _params: object,
        _execution_options: object,
    ) -> None:
        try:
            compiled = clause.compile(dialect=postgresql.dialect())
        except (AttributeError, TypeError):
            return
        compiled_queries.append(str(compiled).upper())

    event.listen(job_database.engine, "before_execute", capture_query)
    try:
        with job_database.factory() as db:
            scan_service.claim_assignment_batch(
                db,
                tenant_id="tenant-a",
                scan_id=scan.scan_id,
                limit=2,
            )
            db.rollback()
    finally:
        event.remove(job_database.engine, "before_execute", capture_query)

    assert any("FOR UPDATE SKIP LOCKED" in query for query in compiled_queries)


def test_start_assignment_emits_postgresql_row_lock_query(
    job_database: JobDatabase,
) -> None:
    with job_database.factory() as db:
        _, assignments = _seed_job_scan(db, statuses=("running",))
        assignment_id = assignments[0].assignment_id

    compiled_queries: list[str] = []

    def capture_query(
        _connection: object,
        clause: object,
        _multiparams: object,
        _params: object,
        _execution_options: object,
    ) -> None:
        try:
            compiled = clause.compile(dialect=postgresql.dialect())
        except (AttributeError, TypeError):
            return
        compiled_queries.append(str(compiled).upper())

    event.listen(job_database.engine, "before_execute", capture_query)
    try:
        with job_database.factory() as db:
            scan_service.start_assignment(
                db,
                tenant_id="tenant-a",
                assignment_id=assignment_id,
            )
            db.rollback()
    finally:
        event.remove(job_database.engine, "before_execute", capture_query)

    assignment_queries = [
        query
        for query in compiled_queries
        if "FROM DISCOVERY_SCAN_ASSIGNMENTS" in query
    ]
    assert assignment_queries
    assert all("FOR UPDATE" in query for query in assignment_queries)


def test_start_assignment_is_tenant_scoped_and_terminally_idempotent(
    job_database: JobDatabase,
) -> None:
    with job_database.factory() as db:
        _, assignments = _seed_job_scan(db, statuses=("pending",))
        assignment_id = assignments[0].assignment_id

    with job_database.factory() as db:
        assert (
            scan_service.start_assignment(
                db,
                tenant_id="tenant-b",
                assignment_id=assignment_id,
            )
            is None
        )
        started = scan_service.start_assignment(
            db,
            tenant_id="tenant-a",
            assignment_id=assignment_id,
        )
        assert started is not None
        assert started.status == "running"
        assert started.started_at is not None
        started_at = started.started_at
        db.commit()

    with job_database.factory() as db:
        resumed = scan_service.start_assignment(
            db,
            tenant_id="tenant-a",
            assignment_id=assignment_id,
        )
        assert resumed is not None
        assert resumed.status == "running"
        assert resumed.started_at == started_at
        scan_service.finalize_assignment(
            db,
            tenant_id="tenant-a",
            assignment_id=assignment_id,
            status="complete",
            observations_count=1,
        )
        db.commit()

    with job_database.factory() as db:
        terminal = scan_service.start_assignment(
            db,
            tenant_id="tenant-a",
            assignment_id=assignment_id,
        )
        assert terminal is not None
        assert terminal.status == "complete"
        assert terminal.started_at == started_at
        assert terminal.observations_count == 1
        assert terminal.completed_at is not None


def test_get_job_parents_return_only_tenant_owned_typed_rows(
    job_database: JobDatabase,
) -> None:
    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("pending",))

    with job_database.factory() as db:
        target = scan_service.get_target(
            db,
            tenant_id="tenant-a",
            target_id="target-1",
        )
        collector = scan_service.get_collector(
            db,
            tenant_id="tenant-a",
            collector_id="collector-1",
        )
        assert target is not None
        assert isinstance(target, DiscoveryTargetView)
        assert target.target_id == "target-1"
        assert target.target_type == "endpoint_group"
        assert target.permitted_methods == ("collect_inventory",)
        assert collector is not None
        assert collector.collector_id == "collector-1"
        assert collector.collector_type == "endpoint_metadata"
        assert (
            scan_service.get_target(
                db,
                tenant_id="tenant-b",
                target_id="target-1",
            )
            is None
        )
        assert (
            scan_service.get_collector(
                db,
                tenant_id="tenant-b",
                collector_id="collector-1",
            )
            is None
        )


def test_finalize_scan_fails_closed_for_zero_success_expected_terminal_mix(
    job_database: JobDatabase,
) -> None:
    terminal_statuses = (
        "stale",
        "rate_limited",
        "empty",
        "cancelled",
    )
    with job_database.factory() as db:
        scan, assignments = _seed_job_scan(
            db,
            statuses=("running",) * len(terminal_statuses),
        )
        for assignment, status in zip(
            assignments,
            terminal_statuses,
            strict=True,
        ):
            scan_service.finalize_assignment(
                db,
                tenant_id="tenant-a",
                assignment_id=assignment.assignment_id,
                status=status,
                observations_count=0,
            )

        finalized = scan_service.finalize_scan(
            db,
            tenant_id="tenant-a",
            scan_id=scan.scan_id,
        )

        assert finalized.status == "failed"
        assert finalized.completed_at is not None
        assert finalized.cancelled_at is None
        assert not db.scalar(
            select(func.count())
            .select_from(DiscoveryScanAssignment)
            .where(
                DiscoveryScanAssignment.tenant_id == "tenant-a",
                DiscoveryScanAssignment.scan_id == scan.scan_id,
                DiscoveryScanAssignment.status.in_(("pending", "running")),
            )
        )


def test_finalize_scan_preserves_requested_cancellation_after_work_is_terminal(
    job_database: JobDatabase,
) -> None:
    with job_database.factory() as db:
        scan, assignments = _seed_job_scan(db, statuses=("running",))
        cancelled = scan_service.cancel_scan(
            db,
            tenant_id="tenant-a",
            scan_id=scan.scan_id,
        )
        scan_service.finalize_assignment(
            db,
            tenant_id="tenant-a",
            assignment_id=assignments[0].assignment_id,
            status="cancelled",
            observations_count=0,
        )

        finalized = scan_service.finalize_scan(
            db,
            tenant_id="tenant-a",
            scan_id=scan.scan_id,
        )

        assert cancelled.status == finalized.status == "cancelled"
        assert finalized.cancelled_at is not None
        assert finalized.completed_at is None


def test_hmair_tasks_have_exact_names_and_database_free_signatures() -> None:
    tasks = (
        jobs.dispatch_scan,
        jobs.run_collector_assignment,
        jobs.finalize_discovery_scan,
        jobs.reconcile_endpoint_metadata_inventory,
        jobs.enqueue_endpoint_metadata_inventory_reconciliation,
    )

    assert tuple(task.name for task in tasks) == TASK_NAMES
    assert tuple(
        tuple(inspect.signature(_task_function(task)).parameters)
        for task in tasks
    ) == (
        ("tenant_id", "scan_id"),
        (
            "tenant_id",
            "scan_id",
            "assignment_id",
            "collector_id",
            "target_id",
            ),
            ("tenant_id", "scan_id"),
            ("tenant_id",),
            (),
        )
    assert all("db" not in inspect.signature(_task_function(task)).parameters for task in tasks)
    app = _celery_app()
    assert all(app.tasks[name].name == name for name in TASK_NAMES)


def test_hmair_tasks_route_to_discovery_with_retry_and_backoff() -> None:
    app = _celery_app()
    for task_name in TASK_NAMES:
        assert app.conf.task_routes[task_name] == {"queue": "discovery"}
        assert app.conf.task_annotations[task_name] == EXPECTED_RETRY_POLICY


def test_assignment_worker_has_bounded_soft_and_hard_time_limits() -> None:
    task = jobs.run_collector_assignment
    soft_limit = task.soft_time_limit
    hard_limit = task.time_limit

    assert type(soft_limit) in (int, float)
    assert type(hard_limit) in (int, float)
    assert 0 < soft_limit < hard_limit <= 3600


def test_postgresql_advisory_execution_lock_spans_entire_assignment_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AdvisorySession(RecordingSession):
        def __init__(self) -> None:
            super().__init__()
            self.execute_calls: list[tuple[str, dict[str, object]]] = []

        def execute(
            self,
            statement: object,
            parameters: dict[str, object],
        ) -> None:
            self.execute_calls.append((str(statement), parameters))

    class AdvisoryFactory:
        kw = {
            "bind": SimpleNamespace(
                dialect=SimpleNamespace(name="postgresql")
            )
        }

        def __init__(self, session: AdvisorySession) -> None:
            self.session = session
            self.calls = 0

        def __call__(self) -> AdvisorySession:
            self.calls += 1
            if self.calls != 1:
                raise AssertionError("execution lock opened an extra session")
            return self.session

    lock_session = AdvisorySession()
    factory = AdvisoryFactory(lock_session)

    def run_locked(*args: object) -> dict[str, object]:
        assert args[1:] == (
            "tenant-a",
            "scan-a",
            "assignment-1",
            "collector-1",
            "target-1",
        )
        assert lock_session.enter_calls == 1
        assert lock_session.exit_errors == []
        assert lock_session.commit_calls == 0
        assert lock_session.rollback_calls == 0
        assert len(lock_session.execute_calls) == 1
        statement, parameters = lock_session.execute_calls[0]
        assert statement == "SELECT pg_advisory_xact_lock(:lock_key)"
        assert set(parameters) == {"lock_key"}
        assert type(parameters["lock_key"]) is int
        expected_key = jobs._advisory_lock_key("tenant-a", "assignment-1")
        assert parameters["lock_key"] == expected_key
        assert jobs._advisory_lock_key("tenant-a", "assignment-1") == expected_key
        assert jobs._advisory_lock_key("tenant-b", "assignment-1") != expected_key
        assert jobs._advisory_lock_key("tenant-a", "assignment-2") != expected_key
        return {
            "tenant_id": "tenant-a",
            "assignment_id": "assignment-1",
            "status": "processed",
        }

    run_locked_mock = Mock(side_effect=run_locked)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "_run_collector_assignment_locked", run_locked_mock)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    assert result["status"] == "processed"
    assert lock_session.commit_calls == 0
    assert lock_session.rollback_calls == 1
    assert lock_session.exit_errors == [None]
    assert factory.calls == 1


def test_clean_celery_worker_bootstrap_registers_all_hmair_tasks() -> None:
    script = """
import json
from app.jobs.celery_app import celery_app

expected = (
    "app.jobs.hmair_discovery_jobs.dispatch_scan",
    "app.jobs.hmair_discovery_jobs.run_collector_assignment",
    "app.jobs.hmair_discovery_jobs.finalize_discovery_scan",
    "app.jobs.hmair_discovery_jobs.reconcile_endpoint_metadata_inventory",
    "app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation",
)
print(json.dumps([name for name in expected if name in celery_app.tasks]))
"""
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == (
        '["app.jobs.hmair_discovery_jobs.dispatch_scan", '
        '"app.jobs.hmair_discovery_jobs.run_collector_assignment", '
        '"app.jobs.hmair_discovery_jobs.finalize_discovery_scan", '
        '"app.jobs.hmair_discovery_jobs.reconcile_endpoint_metadata_inventory", '
        '"app.jobs.hmair_discovery_jobs.enqueue_endpoint_metadata_inventory_reconciliation"]'
    )


def test_job_flag_helper_fails_closed_until_core_and_active_scan_are_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(jobs, "settings", _settings())
    with pytest.raises(RuntimeError):
        jobs.require_hmair_job_enabled(_scan())

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(hmair_core=True, hmair_endpoint=True),
    )
    with pytest.raises(RuntimeError):
        jobs.require_hmair_job_enabled(_scan())

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
        ),
    )
    assert jobs.require_hmair_job_enabled(_scan()) is None


def test_collector_flag_helper_requires_matching_surface_and_active_gate_only_when_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target_view()
    passive = _collector_declaration(active=False)
    active = _collector_declaration(active=True)

    monkeypatch.setattr(jobs, "settings", _settings())
    with pytest.raises(RuntimeError):
        jobs.require_hmair_collector_enabled(passive, target)

    monkeypatch.setattr(jobs, "settings", _settings(hmair_core=True))
    with pytest.raises(RuntimeError):
        jobs.require_hmair_collector_enabled(passive, target)

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(hmair_core=True, hmair_fingerprinting=True),
    )
    with pytest.raises(RuntimeError):
        jobs.require_hmair_collector_enabled(passive, target)

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(hmair_core=True, hmair_endpoint=True),
    )
    assert jobs.require_hmair_collector_enabled(passive, target) is None
    with pytest.raises(RuntimeError):
        jobs.require_hmair_collector_enabled(active, target)

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
        ),
    )
    assert jobs.require_hmair_collector_enabled(active, target) is None


def test_deep_scan_connector_bridge_requires_its_own_explicit_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector_target = _target_view("saas_tenant")
    browser_target = _target_view("browser_tenant")

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_saas=True,
            hmair_browser=True,
        ),
    )
    assert jobs.require_hmair_deep_scan_source_enabled(browser_target) is None
    with pytest.raises(RuntimeError, match="connector source bridge"):
        jobs.require_hmair_deep_scan_source_enabled(connector_target)

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_saas=True,
            hmair_connector_sources=True,
        ),
    )
    assert jobs.require_hmair_deep_scan_source_enabled(connector_target) is None


@pytest.mark.parametrize(
    ("target_type", "surface_flag"),
    (
        ("endpoint_group", "hmair_endpoint"),
        ("browser_tenant", "hmair_browser"),
        ("mcp_environment", "hmair_mcp_runtime"),
        ("llm_gateway", "hmair_mcp_runtime"),
        ("runtime_environment", "hmair_mcp_runtime"),
        ("cloud_subscription", "hmair_cloud"),
        ("saas_tenant", "hmair_saas"),
        ("identity_tenant", "hmair_identity"),
        ("repository", "hmair_repository"),
        ("repository_org", "hmair_repository"),
        ("network_range", "hmair_network"),
        ("database_platform", "hmair_database"),
    ),
)
def test_collector_flag_helper_maps_each_true_scan_surface_exactly(
    monkeypatch: pytest.MonkeyPatch,
    target_type: str,
    surface_flag: str,
) -> None:
    target = _target_view(target_type)
    declaration = _collector_declaration(
        active=False,
        target_type=target_type,
    )
    wrong_flag = (
        "hmair_cloud" if surface_flag == "hmair_endpoint" else "hmair_endpoint"
    )

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(hmair_core=True, **{wrong_flag: True}),
    )
    with pytest.raises(RuntimeError):
        jobs.require_hmair_collector_enabled(declaration, target)

    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(hmair_core=True, **{surface_flag: True}),
    )
    assert jobs.require_hmair_collector_enabled(declaration, target) is None


@pytest.mark.parametrize(
    "compose_path",
    (
        "infra/docker-compose.yml",
        "infra/docker-compose.test.yml",
        "infra/podman-compose.yml",
    ),
)
def test_every_compose_worker_consumes_the_discovery_queue(
    compose_path: str,
) -> None:
    repository_root = Path(__file__).resolve().parents[3]
    content = yaml.safe_load(
        (repository_root / compose_path).read_text(encoding="utf-8")
    )
    worker_command = content["services"]["worker"]["command"]
    command_text = (
        worker_command
        if isinstance(worker_command, str)
        else " ".join(worker_command)
    )
    queue_argument = command_text.split(" -Q ", maxsplit=1)[1].split()[0]

    assert "discovery" in queue_argument.split(",")


def test_dispatch_returns_not_found_without_claim_or_child_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    get_scan, claim_batch, require_enabled, factory = _configure_dispatch(
        monkeypatch,
        session=session,
        scan=None,
    )
    child_delay = Mock()
    finalize_delay = Mock()
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", child_delay)
    monkeypatch.setattr(jobs.finalize_discovery_scan, "delay", finalize_delay)

    result = _task_function(jobs.dispatch_scan)("tenant-a", "scan-a")

    assert result == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
        "status": "not_found",
    }
    get_scan.assert_called_once_with(
        session,
        tenant_id="tenant-a",
        scan_id="scan-a",
    )
    claim_batch.assert_not_called()
    require_enabled.assert_not_called()
    child_delay.assert_not_called()
    finalize_delay.assert_not_called()
    assert session.commit_calls == 0
    assert factory.calls == [((), {})]


def test_dispatch_respects_cancelled_scan_without_claim_or_child_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    cancelled = _scan(status="cancelled")
    _, claim_batch, require_enabled, factory = _configure_dispatch(
        monkeypatch,
        session=session,
        scan=cancelled,
    )
    child_delay = Mock()
    finalize_delay = Mock()
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", child_delay)
    monkeypatch.setattr(jobs.finalize_discovery_scan, "delay", finalize_delay)

    result = _task_function(jobs.dispatch_scan)("tenant-a", "scan-a")

    assert result == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
        "status": "cancelled",
    }
    claim_batch.assert_not_called()
    require_enabled.assert_not_called()
    child_delay.assert_not_called()
    finalize_delay.assert_not_called()
    assert session.commit_calls == 0
    assert factory.calls == [((), {})]


def test_dispatch_rechecks_flag_claims_a_bounded_batch_and_commits_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    scan = _scan()
    batch = (_assignment(1, status="pending"), _assignment(2, status="pending"))
    _, claim_batch, require_enabled, factory = _configure_dispatch(
        monkeypatch,
        session=session,
        scan=scan,
        batch=batch,
        maximum=2,
    )
    child_calls: list[tuple[object, ...]] = []

    def record_child(*args: object) -> None:
        assert session.commit_calls == 1
        child_calls.append(args)

    finalize_delay = Mock()
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", record_child)
    monkeypatch.setattr(jobs.finalize_discovery_scan, "delay", finalize_delay)

    result = _task_function(jobs.dispatch_scan)("tenant-a", "scan-a")

    require_enabled.assert_called_once_with(scan)
    claim_batch.assert_called_once_with(
        session,
        tenant_id="tenant-a",
        scan_id="scan-a",
        limit=2,
    )
    assert child_calls == [
        (
            "tenant-a",
            "scan-a",
            "assignment-1",
            "collector-1",
            "target-1",
        ),
        (
            "tenant-a",
            "scan-a",
            "assignment-2",
            "collector-2",
            "target-2",
        ),
    ]
    finalize_delay.assert_not_called()
    assert result == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
        "status": "dispatched",
        "assignments": 2,
    }
    assert factory.calls == [((), {})]


def test_dispatch_does_not_claim_when_worker_flag_recheck_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    scan = _scan()
    _, claim_batch, require_enabled, _ = _configure_dispatch(
        monkeypatch,
        session=session,
        scan=scan,
    )
    require_enabled.side_effect = RuntimeError("HMAIR job is disabled")
    child_delay = Mock()
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", child_delay)

    with pytest.raises(RuntimeError, match="HMAIR job is disabled"):
        _task_function(jobs.dispatch_scan)("tenant-a", "scan-a")

    require_enabled.assert_called_once_with(scan)
    claim_batch.assert_not_called()
    child_delay.assert_not_called()
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


def test_dispatch_waits_for_running_work_instead_of_finalizing_early(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("running",))

    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
            hmair_max_concurrent_assignments=2,
        ),
    )
    child_delay = Mock()
    finalize_delay = Mock()
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", child_delay)
    monkeypatch.setattr(jobs.finalize_discovery_scan, "delay", finalize_delay)

    _task_function(jobs.dispatch_scan)("tenant-a", "scan-a")

    child_delay.assert_not_called()
    finalize_delay.assert_not_called()


def test_multi_batch_dispatch_eventually_processes_all_without_exceeding_limit(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with job_database.factory() as db:
        _seed_job_scan(
            db,
            statuses=("pending",) * 5,
        )

    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
            hmair_max_concurrent_assignments=2,
        ),
    )
    scheduled: list[tuple[str, str, str, str, str]] = []
    finalized_scans: list[tuple[str, str]] = []
    monkeypatch.setattr(
        jobs.run_collector_assignment,
        "delay",
        lambda *args: scheduled.append(args),
    )
    monkeypatch.setattr(
        jobs.finalize_discovery_scan,
        "delay",
        lambda *args: finalized_scans.append(args),
    )

    _task_function(jobs.dispatch_scan)("tenant-a", "scan-a")
    assert len(scheduled) == 2
    processed: list[str] = []

    while scheduled:
        task_args = scheduled.pop(0)
        assignment_id = task_args[2]
        assert assignment_id not in processed
        processed.append(assignment_id)
        with job_database.factory() as db:
            scan_service.finalize_assignment(
                db,
                tenant_id="tenant-a",
                assignment_id=assignment_id,
                status="complete",
                observations_count=1,
            )
            db.commit()

        # A completed child continues dispatch so a bounded worker pool cannot
        # strand assignments beyond the first claimed batch.
        _task_function(jobs.dispatch_scan)("tenant-a", "scan-a")
        with job_database.factory() as db:
            running_count = db.scalar(
                select(func.count())
                .select_from(DiscoveryScanAssignment)
                .where(
                    DiscoveryScanAssignment.tenant_id == "tenant-a",
                    DiscoveryScanAssignment.scan_id == "scan-a",
                    DiscoveryScanAssignment.status == "running",
                )
            )
        assert running_count <= 2

    assert set(processed) == {f"assignment-{index}" for index in range(1, 6)}
    assert finalized_scans == [("tenant-a", "scan-a")]


def test_child_publication_failure_is_retryable_and_does_not_strand_claim(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import Retry

    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("pending",))

    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
            hmair_max_concurrent_assignments=1,
        ),
    )
    publication = Mock(
        side_effect=(ConnectionError("broker unavailable"), None)
    )
    finalize_delay = Mock()
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", publication)
    monkeypatch.setattr(jobs.finalize_discovery_scan, "delay", finalize_delay)
    task = jobs.dispatch_scan
    task_args = ("tenant-a", "scan-a")

    first_error: BaseException | None = None
    try:
        with _worker_task_request(task, task_args=task_args, retries=0):
            task.run(*task_args)
    except BaseException as error:
        first_error = error

    with job_database.factory() as db:
        after_failure = db.get(DiscoveryScanAssignment, "assignment-1")
        assert after_failure is not None
        # No schema or lease representation is prescribed here. The observable
        # requirement is that a committed claim whose child was not published
        # remains distinguishable from work already executing and reclaimable.
        assert (after_failure.status, after_failure.started_at) in {
            ("pending", None),
            ("running", None),
        }
    assert isinstance(first_error, Retry)
    assert publication.call_count == 1

    with _worker_task_request(task, task_args=task_args, retries=1):
        result = task.run(*task_args)

    assert result == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
        "status": "dispatched",
        "assignments": 1,
    }
    assert publication.call_count == 2
    finalize_delay.assert_not_called()


def test_redelivered_dispatch_recovers_unpublished_claim_even_at_retry_zero(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("pending",))
    with job_database.factory() as db:
        claimed = scan_service.claim_assignment_batch(
            db,
            tenant_id="tenant-a",
            scan_id="scan-a",
            limit=1,
        )
        assert len(claimed) == 1
        unpublished_started_at = claimed[0].started_at
        assert unpublished_started_at is not None
        db.commit()

    publication = Mock()
    finalize_delay = Mock()
    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
            hmair_max_concurrent_assignments=1,
        ),
    )
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", publication)
    monkeypatch.setattr(jobs.finalize_discovery_scan, "delay", finalize_delay)
    task = jobs.dispatch_scan
    task_args = ("tenant-a", "scan-a")

    with _worker_task_request(
        task,
        task_args=task_args,
        retries=0,
        delivery_info={"redelivered": True},
    ):
        result = task.run(*task_args)

    publication.assert_called_once_with(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )
    finalize_delay.assert_not_called()
    assert result == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
        "status": "dispatched",
        "assignments": 1,
    }
    with job_database.factory() as db:
        republished = db.get(DiscoveryScanAssignment, "assignment-1")
        assert republished is not None
        assert republished.status == "running"
        assert republished.started_at is not None
        assert republished.started_at.replace(tzinfo=None) == (
            unpublished_started_at.replace(tzinfo=None)
        )


def test_publication_claim_recovery_failure_is_not_swallowed(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import Retry

    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("pending",))

    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
            hmair_max_concurrent_assignments=1,
        ),
    )
    publication = Mock(side_effect=ConnectionError("broker unavailable"))
    release = Mock(
        side_effect=RuntimeError("claim release failed password=hunter2")
    )
    monkeypatch.setattr(jobs.run_collector_assignment, "delay", publication)
    monkeypatch.setattr(jobs, "release_unpublished_assignment_claims", release)
    task = jobs.dispatch_scan
    task_args = ("tenant-a", "scan-a")

    with _worker_task_request(task, task_args=task_args, retries=0):
        with pytest.raises(Retry) as retry_signal:
            task.run(*task_args)

    assert type(retry_signal.value.exc) is RuntimeError
    retry_message = str(retry_signal.value.exc)
    assert "recovery failed" in retry_message
    assert retry_message != "assignment publication failed"
    assert "hunter2" not in retry_message
    publication.assert_called_once()
    release.assert_called_once()
    assert release.call_args.kwargs == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
        "assignment_ids": ("assignment-1",),
    }
    with job_database.factory() as db:
        recoverable = db.get(DiscoveryScanAssignment, "assignment-1")
        assert recoverable is not None
        assert recoverable.status == "running"
        assert recoverable.started_at is not None
        released = scan_service.release_unpublished_assignment_claims(
            db,
            tenant_id="tenant-a",
            scan_id="scan-a",
            assignment_ids=("assignment-1",),
        )
        assert released == 1
        db.commit()
    with job_database.factory() as db:
        recovered = db.get(DiscoveryScanAssignment, "assignment-1")
        assert recovered is not None
        assert recovered.status == "pending"
        assert recovered.started_at is None


def test_dry_run_validates_assignment_without_sdk_source_or_ingestion(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("running",), dry_run=True)

    collect = Mock(
        side_effect=AssertionError("dry-run must not execute collector source")
    )
    ingest = Mock(
        side_effect=AssertionError("dry-run must not ingest observations")
    )
    continuation_delay = Mock()
    get_target = Mock(wraps=scan_service.get_target)
    get_collector = Mock(wraps=scan_service.get_collector)
    require_enabled = Mock(wraps=jobs.require_hmair_collector_enabled)
    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
        ),
    )
    registry_get = Mock(
        side_effect=AssertionError(
            "dry-run must not resolve a runtime collector"
        )
    )
    monkeypatch.setattr(
        jobs,
        "collector_registry",
        SimpleNamespace(get=registry_get),
    )
    monkeypatch.setattr(jobs, "get_target", get_target)
    monkeypatch.setattr(jobs, "get_collector", get_collector)
    monkeypatch.setattr(
        jobs,
        "require_hmair_collector_enabled",
        require_enabled,
    )
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)
    monkeypatch.setattr(jobs, "ingest_observation", ingest)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    with job_database.factory() as db:
        assignment = db.get(DiscoveryScanAssignment, "assignment-1")
        observation_count = db.scalar(
            select(func.count()).select_from(DiscoveryObservation)
        )
        assert assignment is not None
        assert assignment.status == "complete"
        assert assignment.observations_count == 0
        assert assignment.completed_at is not None
        assert observation_count == 0
    collect.assert_not_called()
    ingest.assert_not_called()
    registry_get.assert_not_called()
    get_target.assert_called_once()
    assert get_target.call_args.kwargs == {
        "tenant_id": "tenant-a",
        "target_id": "target-1",
    }
    get_collector.assert_called_once()
    assert get_collector.call_args.kwargs == {
        "tenant_id": "tenant-a",
        "collector_id": "collector-1",
    }
    require_enabled.assert_called_once()
    dry_declaration, dry_target = require_enabled.call_args.args
    assert type(dry_declaration) is CollectorDeclaration
    assert (
        dry_declaration.collector_id,
        dry_declaration.collector_type,
        dry_declaration.version,
    ) == ("collector-1", "endpoint_metadata", "2.0.0")
    assert type(dry_target) is DiscoveryTargetView
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result == {
        "tenant_id": "tenant-a",
        "assignment_id": "assignment-1",
        "status": "processed",
    }


def test_assignment_worker_rechecks_scan_cancellation_during_collection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start_session = RecordingSession()
    first_check_session = RecordingSession()
    second_check_session = RecordingSession()
    finalize_session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(
            start_session,
            first_check_session,
            second_check_session,
            finalize_session,
        ),
    )
    cancelled = False

    def get_scan(
        _db: RecordingSession,
        *,
        tenant_id: str,
        scan_id: str,
    ) -> SimpleNamespace:
        assert tenant_id == "tenant-a"
        assert scan_id == "scan-a"
        return _scan(status="cancelled" if cancelled else "running")

    get_scan_mock = Mock(side_effect=get_scan)

    def collect(
        *,
        collector: object,
        target: object,
        cancellation_check: object,
    ) -> tuple[object, ...]:
        nonlocal cancelled
        assert collector is not None
        assert target is not None
        assert callable(cancellation_check)
        assert cancellation_check() is False
        cancelled = True
        assert cancellation_check() is True
        raise CollectorTerminalOutcome(
            CollectorRunStatus.CANCELLED,
            "collector run cancelled",
        )

    ingest = Mock()
    finalize_assignment = Mock()
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "get_scan", get_scan_mock)
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)
    monkeypatch.setattr(jobs, "ingest_observation", ingest)
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    assert get_scan_mock.call_count >= 2
    for invocation in get_scan_mock.call_args_list:
        assert invocation.kwargs == {
            "tenant_id": "tenant-a",
            "scan_id": "scan-a",
        }
    ingest.assert_not_called()
    finalize_assignment.assert_called_once_with(
        finalize_session,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
        status=CollectorRunStatus.CANCELLED,
        observations_count=0,
        warning="collector run cancelled",
    )
    assert finalize_session.commit_calls == 1
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result["status"] == "processed"


def test_duplicate_assignment_delivery_serializes_source_execution_and_noops_terminal_duplicate(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("running",))

    state_lock = threading.Lock()
    first_entered = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()
    second_attempted = threading.Event()
    active = 0
    maximum_active = 0
    collection_calls = 0
    errors: list[BaseException] = []

    def collect(
        *,
        collector: object,
        target: object,
        **_kwargs: object,
    ) -> tuple[object, ...]:
        nonlocal active, maximum_active, collection_calls
        assert collector is not None
        assert target is not None
        with state_lock:
            collection_calls += 1
            active += 1
            maximum_active = max(maximum_active, active)
            call_number = collection_calls
        if call_number == 1:
            first_entered.set()
        else:
            second_entered.set()
        assert release_first.wait(timeout=5)
        with state_lock:
            active -= 1
        return ()

    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
        ),
    )
    monkeypatch.setattr(
        jobs,
        "collector_registry",
        SimpleNamespace(get=Mock(return_value=_validated_runtime_collector())),
    )
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)
    continuation_delay = Mock()
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    task_args = (
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    def invoke(*, duplicate: bool) -> None:
        if duplicate:
            second_attempted.set()
        try:
            _task_function(jobs.run_collector_assignment)(*task_args)
        except BaseException as error:
            with state_lock:
                errors.append(error)

    first = threading.Thread(target=invoke, kwargs={"duplicate": False})
    duplicate = threading.Thread(target=invoke, kwargs={"duplicate": True})
    first.start()
    assert first_entered.wait(timeout=5)
    duplicate.start()
    assert second_attempted.wait(timeout=5)
    second_entered.wait(timeout=0.5)
    release_first.set()
    first.join(timeout=5)
    duplicate.join(timeout=5)

    assert not first.is_alive()
    assert not duplicate.is_alive()
    assert errors == []
    assert maximum_active == 1
    assert collection_calls == 1
    with job_database.factory() as db:
        assignment = db.get(DiscoveryScanAssignment, "assignment-1")
        assert assignment is not None
        assert assignment.status == "complete"
        assert assignment.observations_count == 0
    assert continuation_delay.call_count == 2


def test_terminal_duplicate_uses_persisted_scan_for_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EqualCallerScanId(str):
        pass

    persisted_scan_id = "".join(("scan", "-a"))
    caller_scan_id = EqualCallerScanId(persisted_scan_id)
    assignment = SimpleNamespace(
        assignment_id="assignment-1",
        scan_id=persisted_scan_id,
        collector_id="collector-1",
        target_id="target-1",
        status="complete",
    )
    session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(session,),
        assignment=assignment,
    )
    collect = Mock()
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        caller_scan_id,
        "assignment-1",
        "collector-1",
        "target-1",
    )

    collect.assert_not_called()
    continuation_delay.assert_called_once()
    assert continuation_delay.call_args.args[0] == "tenant-a"
    assert continuation_delay.call_args.args[1] is persisted_scan_id
    assert result["status"] == "processed"


@pytest.mark.parametrize(
    ("forged_field", "task_args"),
    (
        (
            "scan_id",
            (
                "tenant-a",
                "forged-scan",
                "assignment-1",
                "collector-1",
                "target-1",
            ),
        ),
        (
            "collector_id",
            (
                "tenant-a",
                "scan-a",
                "assignment-1",
                "forged-collector",
                "target-1",
            ),
        ),
        (
            "target_id",
            (
                "tenant-a",
                "scan-a",
                "assignment-1",
                "collector-1",
                "forged-target",
            ),
        ),
    ),
)
def test_terminal_duplicate_rejects_forged_execution_identity(
    monkeypatch: pytest.MonkeyPatch,
    forged_field: str,
    task_args: tuple[str, ...],
) -> None:
    from celery.exceptions import Retry

    assignment = SimpleNamespace(
        assignment_id="assignment-1",
        scan_id="scan-a",
        collector_id="collector-1",
        target_id="target-1",
        status="complete",
    )
    session = RecordingSession()
    (
        _,
        _,
        get_target,
        get_collector,
        registry_get,
        require_enabled,
        _,
    ) = _configure_assignment_start(
        monkeypatch,
        sessions=(session,),
        assignment=assignment,
    )
    continuation_delay = Mock()
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)
    task = jobs.run_collector_assignment

    with _worker_task_request(task, task_args=task_args, retries=0):
        with pytest.raises(Retry) as retry_signal:
            task.run(*task_args)

    assert type(retry_signal.value.exc) is RuntimeError
    assert str(retry_signal.value.exc) == "collector preflight failed"
    assert forged_field not in str(retry_signal.value.exc)
    get_target.assert_not_called()
    get_collector.assert_not_called()
    registry_get.assert_not_called()
    require_enabled.assert_not_called()
    continuation_delay.assert_not_called()
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.parametrize("assignment", [None, _assignment(status="cancelled")])
def test_assignment_worker_stops_cancelled_or_missing_assignment_without_collection(
    monkeypatch: pytest.MonkeyPatch,
    assignment: SimpleNamespace | None,
) -> None:
    session = RecordingSession()
    factory, _, get_target, get_collector, registry_get, require_enabled, _ = (
        _configure_assignment_start(
            monkeypatch,
            sessions=(session,),
            assignment=assignment,
        )
    )
    collect = Mock()
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    assert result == {
        "tenant_id": "tenant-a",
        "assignment_id": "assignment-1",
        "status": "cancelled",
    }
    get_target.assert_not_called()
    get_collector.assert_not_called()
    registry_get.assert_not_called()
    require_enabled.assert_not_called()
    collect.assert_not_called()
    if assignment is None:
        continuation_delay.assert_not_called()
    else:
        continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert session.commit_calls == 0
    assert factory.calls == [((), {})]


def test_assignment_worker_queries_tenant_parents_uses_collector_type_and_ingests_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start_session = RecordingSession()
    persist_session = RecordingSession()
    target = _target()
    persisted_collector = _persisted_collector()
    runtime_collector = _runtime_collector()
    (
        factory,
        start_assignment,
        get_target,
        get_collector,
        registry_get,
        require_enabled,
        get_scan,
    ) = _configure_assignment_start(
        monkeypatch,
        sessions=(start_session, persist_session),
        target=target,
        persisted_collector=persisted_collector,
        runtime_collector=runtime_collector,
    )
    observations = (
        _runtime_observation(),
        _runtime_observation("observation-2"),
    )

    def collect_source(**_kwargs: object) -> tuple[DiscoveryObservationInput, ...]:
        return observations

    def ingest_source(*_args: object, **_kwargs: object) -> None:
        return None

    def finalize_source(*_args: object, **_kwargs: object) -> None:
        return None

    collect = Mock(side_effect=collect_source)
    ingest = Mock(side_effect=ingest_source)
    finalize_assignment = Mock(side_effect=finalize_source)
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)
    monkeypatch.setattr(jobs, "ingest_observation", ingest)
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    start_assignment.assert_called_once_with(
        start_session,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
    )
    get_target.assert_called_once_with(
        start_session,
        tenant_id="tenant-a",
        target_id="target-1",
    )
    get_collector.assert_called_once_with(
        start_session,
        tenant_id="tenant-a",
        collector_id="collector-1",
    )
    registry_get.assert_called_once_with("endpoint_metadata")
    require_enabled.assert_called_once_with(runtime_collector.declaration, target)
    get_scan.assert_called_once()
    assert get_scan.call_args.args[0] in (start_session, persist_session)
    assert get_scan.call_args.kwargs == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
    }
    collect.assert_called_once()
    assert collect.call_args.kwargs["collector"] is runtime_collector
    assert collect.call_args.kwargs["target"] is target
    assert callable(collect.call_args.kwargs["cancellation_check"])
    atomic_session = ingest.call_args_list[0].args[0]
    assert atomic_session in (start_session, persist_session)
    expected_payloads = tuple(
        observation.model_copy(
            update={
                "scan_id": "scan-a",
                "collector_id": "collector-1",
                "target_id": "target-1",
            }
        )
        for observation in observations
    )
    assert ingest.call_args_list == [
        call(atomic_session, tenant_id="tenant-a", payload=expected_payloads[0]),
        call(atomic_session, tenant_id="tenant-a", payload=expected_payloads[1]),
    ]
    finalize_assignment.assert_called_once_with(
        atomic_session,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
        status="complete",
        observations_count=2,
    )
    assert atomic_session.commit_calls == 1
    assert sum(
        session.commit_calls for session in (start_session, persist_session)
    ) in {1, 2}
    assert not any(
        session.rollback_calls for session in (start_session, persist_session)
    )
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result == {
        "tenant_id": "tenant-a",
        "assignment_id": "assignment-1",
        "status": "processed",
    }
    assert 1 <= len(factory.calls) <= 2


def test_real_sdk_observation_is_rebound_to_persisted_execution_envelope(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("running",))

    collector = _EnvelopeCollector()
    source_snapshot = collector.source_observation.model_dump(mode="python")
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
        ),
    )
    registry_get = Mock(return_value=collector)
    monkeypatch.setattr(
        jobs,
        "collector_registry",
        SimpleNamespace(get=registry_get),
    )
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    with job_database.factory() as db:
        observation = db.scalar(select(DiscoveryObservation))
        assignment = db.get(DiscoveryScanAssignment, "assignment-1")
        assert observation is not None
        assert (
            observation.tenant_id,
            observation.scan_id,
            observation.assignment_id,
            observation.target_id,
            observation.collector_id,
        ) == (
            "tenant-a",
            "scan-a",
            "assignment-1",
            "target-1",
            "collector-1",
        )
        assert observation.collector_type == "endpoint_metadata"
        assert observation.collector_version == "2.0.0"
        assert assignment is not None
        assert assignment.status == "complete"
        assert assignment.observations_count == 1

    # The SDK must first accept the raw runtime identity. Only the immutable
    # copy passed into persistence receives the tenant execution envelope.
    assert collector.calls == [
        "validate_configuration",
        "test_connectivity",
        "enumerate_scope",
        "collect_inventory",
        "emit_observations",
    ]
    assert collector.source_observation.model_dump(mode="python") == source_snapshot
    assert collector.source_observation.scan_id == "runtime-scan-context"
    assert (
        collector.source_observation.collector_id
        == collector.declaration.collector_id
        == "endpoint-metadata-runtime"
    )
    registry_get.assert_called_once_with("endpoint_metadata")
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result["status"] == "processed"


def test_assignment_worker_rechecks_collector_flag_before_committing_or_collecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    _, _, _, _, _, require_enabled, _ = _configure_assignment_start(
        monkeypatch,
        sessions=(session,),
    )
    require_enabled.side_effect = RuntimeError(
        "HMAIR collector surface is disabled"
    )
    collect = Mock()
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)

    with pytest.raises(RuntimeError, match="HMAIR collector surface is disabled"):
        _task_function(jobs.run_collector_assignment)(
            "tenant-a",
            "scan-a",
            "assignment-1",
            "collector-1",
            "target-1",
        )

    require_enabled.assert_called_once()
    collect.assert_not_called()
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


def test_missing_persisted_collector_is_retryable_before_assignment_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    _, _, _, get_collector, registry_get, _, _ = _configure_assignment_start(
        monkeypatch,
        sessions=(session,),
    )
    get_collector.side_effect = LookupError("collector was not found")
    collect = Mock()
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)

    with pytest.raises(LookupError, match="collector was not found"):
        _task_function(jobs.run_collector_assignment)(
            "tenant-a",
            "scan-a",
            "assignment-1",
            "collector-1",
            "target-1",
        )

    registry_get.assert_not_called()
    collect.assert_not_called()
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


def test_unknown_runtime_collector_is_retryable_before_assignment_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    _, _, _, _, registry_get, require_enabled, _ = _configure_assignment_start(
        monkeypatch,
        sessions=(session,),
    )
    registry_get.side_effect = KeyError("collector type is not registered")
    collect = Mock()
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)

    with pytest.raises(KeyError, match="collector type is not registered"):
        _task_function(jobs.run_collector_assignment)(
            "tenant-a",
            "scan-a",
            "assignment-1",
            "collector-1",
            "target-1",
        )

    registry_get.assert_called_once_with("endpoint_metadata")
    require_enabled.assert_not_called()
    collect.assert_not_called()
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.parametrize("failure_stage", ("persisted", "registry"))
def test_worker_semantics_autoretry_precollection_failure_with_backoff(
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    from celery.exceptions import Retry

    session = RecordingSession()
    _, _, _, get_collector, registry_get, require_enabled, _ = (
        _configure_assignment_start(
            monkeypatch,
            sessions=(session,),
        )
    )
    if failure_stage == "persisted":
        get_collector.side_effect = LookupError("collector was not found")
        expected_error = LookupError
    else:
        registry_get.side_effect = KeyError("collector type is not registered")
        expected_error = KeyError
    task = jobs.run_collector_assignment
    task_args = (
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    with _worker_task_request(task, task_args=task_args, retries=0):
        with pytest.raises(Retry) as retry_signal:
            task.run(*task_args)

    assert type(retry_signal.value.exc) is expected_error
    assert isinstance(retry_signal.value.when, (int, float))
    assert 0 <= retry_signal.value.when <= 120
    if failure_stage == "persisted":
        registry_get.assert_not_called()
    else:
        registry_get.assert_called_once_with("endpoint_metadata")
    require_enabled.assert_not_called()
    assert session.commit_calls == 0
    assert session.rollback_calls == 1


@pytest.mark.parametrize(
    "terminal_status",
    (
        CollectorRunStatus.CANCELLED,
        CollectorRunStatus.UNSUPPORTED,
        CollectorRunStatus.PERMISSION_DENIED,
        CollectorRunStatus.RATE_LIMITED,
        CollectorRunStatus.STALE,
        CollectorRunStatus.EMPTY,
    ),
)
def test_expected_collector_outcomes_finalize_normally_without_retry(
    monkeypatch: pytest.MonkeyPatch,
    terminal_status: CollectorRunStatus,
) -> None:
    start_session = RecordingSession()
    finalize_session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(start_session, finalize_session),
    )
    outcome = CollectorTerminalOutcome(terminal_status, "source unavailable")
    monkeypatch.setattr(
        jobs,
        "collect_assignment_observations",
        Mock(side_effect=outcome),
    )
    ingest = Mock()
    finalize_assignment = Mock()
    continuation_delay = Mock()
    retry = Mock(side_effect=AssertionError("terminal outcomes must not retry"))
    monkeypatch.setattr(jobs, "ingest_observation", ingest)
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)
    monkeypatch.setattr(jobs.run_collector_assignment, "retry", retry)

    result = _task_function(jobs.run_collector_assignment)(
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    ingest.assert_not_called()
    finalize_assignment.assert_called_once_with(
        finalize_session,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
        status=terminal_status,
        observations_count=0,
        warning="source unavailable",
    )
    assert start_session.commit_calls == 1
    assert finalize_session.commit_calls == 1
    retry.assert_not_called()
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result == {
        "tenant_id": "tenant-a",
        "assignment_id": "assignment-1",
        "status": "processed",
    }


def test_soft_time_limit_requests_sanitized_retry_without_releasing_capacity(
    job_database: JobDatabase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from billiard.exceptions import SoftTimeLimitExceeded
    from celery.exceptions import Retry

    with job_database.factory() as db:
        _seed_job_scan(db, statuses=("running",))
    with job_database.factory() as db:
        before = db.get(DiscoveryScanAssignment, "assignment-1")
        assert before is not None
        assert before.started_at is not None
        started_at_before = before.started_at.replace(tzinfo=None)

    monkeypatch.setattr(jobs, "SessionLocal", job_database.factory)
    monkeypatch.setattr(
        jobs,
        "settings",
        _settings(
            hmair_core=True,
            hmair_active_scan=True,
            hmair_endpoint=True,
        ),
    )
    monkeypatch.setattr(
        jobs,
        "collector_registry",
        SimpleNamespace(get=Mock(return_value=_validated_runtime_collector())),
    )
    monkeypatch.setattr(
        jobs,
        "collect_assignment_observations",
        Mock(
            side_effect=SoftTimeLimitExceeded(
                "collector blocked password=hunter2"
            )
        ),
    )
    finalize_assignment = Mock()
    continuation_delay = Mock()
    release_claims = Mock()
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)
    monkeypatch.setattr(
        jobs,
        "release_unpublished_assignment_claims",
        release_claims,
    )
    task = jobs.run_collector_assignment
    task_args = (
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    with _worker_task_request(task, task_args=task_args, retries=0):
        with pytest.raises(Retry) as retry_signal:
            task.run(*task_args)

    assert type(retry_signal.value.exc) is RuntimeError
    assert str(retry_signal.value.exc) == "collector execution failed"
    assert "hunter2" not in str(retry_signal.value.exc)
    finalize_assignment.assert_not_called()
    continuation_delay.assert_not_called()
    release_claims.assert_not_called()
    with job_database.factory() as db:
        after = db.get(DiscoveryScanAssignment, "assignment-1")
        assert after is not None
        assert after.status == "running"
        assert after.started_at is not None
        assert after.started_at.replace(tzinfo=None) == started_at_before
        assert after.completed_at is None


def test_soft_time_limit_exhaustion_finalizes_safely_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from billiard.exceptions import SoftTimeLimitExceeded

    start_session = RecordingSession()
    failure_session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(start_session, failure_session),
    )
    monkeypatch.setattr(
        jobs,
        "collect_assignment_observations",
        Mock(
            side_effect=SoftTimeLimitExceeded(
                "collector blocked password=hunter2"
            )
        ),
    )
    finalize_assignment = Mock()
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)
    task = jobs.run_collector_assignment
    task_args = (
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    with _worker_task_request(
        task,
        task_args=task_args,
        retries=task.max_retries,
    ):
        result = task.run(*task_args)

    finalize_assignment.assert_called_once_with(
        failure_session,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
        status="failed",
        observations_count=0,
        error="collector execution failed",
    )
    assert "hunter2" not in str(finalize_assignment.call_args)
    assert start_session.commit_calls == 1
    assert failure_session.commit_calls == 1
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result["status"] == "processed"


def test_unexpected_collection_failure_stays_running_and_requests_safe_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import Retry

    start_session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(start_session,),
    )
    raw_error = "collector execution exploded with password=hunter2"
    monkeypatch.setattr(
        jobs,
        "collect_assignment_observations",
        Mock(side_effect=RuntimeError(raw_error)),
    )
    finalize_assignment = Mock()
    continuation_delay = Mock()
    retry = Mock(side_effect=Retry("retry requested"))
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)
    monkeypatch.setattr(jobs.run_collector_assignment, "retry", retry)

    with _task_request(jobs.run_collector_assignment, retries=0):
        with pytest.raises(Retry, match="retry requested"):
            _task_function(jobs.run_collector_assignment)(
                "tenant-a",
                "scan-a",
                "assignment-1",
                "collector-1",
                "target-1",
            )

    finalize_assignment.assert_not_called()
    assert start_session.commit_calls == 1
    retry.assert_called_once()
    retry_error = retry.call_args.kwargs["exc"]
    assert type(retry_error) is RuntimeError
    assert str(retry_error) == "collector execution failed"
    assert raw_error not in str(retry.call_args)
    continuation_delay.assert_not_called()


def test_retry_attempt_can_resume_running_assignment_and_complete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import Retry

    first_start = RecordingSession()
    second_start = RecordingSession()
    persistence = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(first_start, second_start, persistence),
    )
    observation = _runtime_observation()
    collect = Mock(
        side_effect=(RuntimeError("first attempt failed"), (observation,))
    )
    retry = Mock(side_effect=Retry("retry requested"))
    ingest = Mock()
    finalize_assignment = Mock()
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "collect_assignment_observations", collect)
    monkeypatch.setattr(jobs.run_collector_assignment, "retry", retry)
    monkeypatch.setattr(jobs, "ingest_observation", ingest)
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    with _task_request(jobs.run_collector_assignment, retries=0):
        with pytest.raises(Retry):
            _task_function(jobs.run_collector_assignment)(
                "tenant-a",
                "scan-a",
                "assignment-1",
                "collector-1",
                "target-1",
            )
    retry.reset_mock(side_effect=True)
    retry.side_effect = Retry("successful retry requested another retry")

    with _task_request(jobs.run_collector_assignment, retries=1):
        result = _task_function(jobs.run_collector_assignment)(
            "tenant-a",
            "scan-a",
            "assignment-1",
            "collector-1",
            "target-1",
        )

    retry.assert_not_called()
    persisted_observation = observation.model_copy(
        update={
            "scan_id": "scan-a",
            "collector_id": "collector-1",
            "target_id": "target-1",
        }
    )
    ingest.assert_called_once_with(
        persistence,
        tenant_id="tenant-a",
        payload=persisted_observation,
    )
    finalize_assignment.assert_called_once_with(
        persistence,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
        status="complete",
        observations_count=1,
    )
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert first_start.commit_calls == second_start.commit_calls == 1
    assert persistence.commit_calls == 1
    assert result["status"] == "processed"


def test_exhausted_unexpected_failure_finalizes_safely_and_continues_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import MaxRetriesExceededError

    start_session = RecordingSession()
    failure_session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(start_session, failure_session),
    )
    monkeypatch.setattr(
        jobs,
        "collect_assignment_observations",
        Mock(side_effect=RuntimeError("password=hunter2")),
    )
    finalize_assignment = Mock()
    retry = Mock(side_effect=MaxRetriesExceededError())
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.run_collector_assignment, "retry", retry)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)

    with _task_request(
        jobs.run_collector_assignment,
        retries=EXPECTED_RETRY_POLICY["max_retries"],
    ):
        result = _task_function(jobs.run_collector_assignment)(
            "tenant-a",
            "scan-a",
            "assignment-1",
            "collector-1",
            "target-1",
        )

    retry.assert_called_once()
    retry_error = retry.call_args.kwargs["exc"]
    assert type(retry_error) is RuntimeError
    assert str(retry_error) == "collector execution failed"
    finalize_assignment.assert_called_once_with(
        failure_session,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
        status="failed",
        observations_count=0,
        error="collector execution failed",
    )
    assert "hunter2" not in str(finalize_assignment.call_args)
    assert failure_session.commit_calls == 1
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result["status"] == "processed"


def test_real_task_retry_exhaustion_finalizes_failed_and_continues(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start_session = RecordingSession()
    failure_session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(start_session, failure_session),
    )
    monkeypatch.setattr(
        jobs,
        "collect_assignment_observations",
        Mock(side_effect=RuntimeError("password=hunter2")),
    )
    finalize_assignment = Mock()
    continuation_delay = Mock()
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.dispatch_scan, "delay", continuation_delay)
    task = jobs.run_collector_assignment
    task_args = (
        "tenant-a",
        "scan-a",
        "assignment-1",
        "collector-1",
        "target-1",
    )

    with _worker_task_request(
        task,
        task_args=task_args,
        retries=task.max_retries,
    ):
        result = task.run(*task_args)

    finalize_assignment.assert_called_once_with(
        failure_session,
        tenant_id="tenant-a",
        assignment_id="assignment-1",
        status="failed",
        observations_count=0,
        error="collector execution failed",
    )
    assert "hunter2" not in str(finalize_assignment.call_args)
    assert failure_session.commit_calls == 1
    continuation_delay.assert_called_once_with("tenant-a", "scan-a")
    assert result["status"] == "processed"


def test_observation_ingestion_failure_never_commits_partial_observations_and_is_retry_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery.exceptions import Retry

    start_session = RecordingSession()
    observation_session = RecordingSession()
    _configure_assignment_start(
        monkeypatch,
        sessions=(start_session, observation_session),
    )
    observations = (
        _runtime_observation(),
        _runtime_observation("observation-2"),
    )
    monkeypatch.setattr(
        jobs,
        "collect_assignment_observations",
        Mock(return_value=observations),
    )
    ingest = Mock(side_effect=[None, RuntimeError("write failed")])
    finalize_assignment = Mock()
    retry = Mock(side_effect=Retry("retry requested"))
    monkeypatch.setattr(jobs, "ingest_observation", ingest)
    monkeypatch.setattr(jobs, "finalize_assignment", finalize_assignment)
    monkeypatch.setattr(jobs.run_collector_assignment, "retry", retry)

    with _task_request(jobs.run_collector_assignment, retries=0):
        with pytest.raises(Retry):
            _task_function(jobs.run_collector_assignment)(
                "tenant-a",
                "scan-a",
                "assignment-1",
                "collector-1",
                "target-1",
            )

    assert observation_session.commit_calls == 0
    assert observation_session.exit_errors == [RuntimeError]
    assert observation_session.rollback_calls == 1
    finalize_assignment.assert_not_called()
    retry.assert_called_once()
    assert str(retry.call_args.kwargs["exc"]) == "collector execution failed"


def test_finalize_discovery_scan_commits_and_returns_partial_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    factory = RecordingSessionFactory(session)
    finalized = SimpleNamespace(
        status="partially_complete",
        observations_count=7,
    )
    finalize_scan = Mock(return_value=finalized)
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "finalize_scan", finalize_scan)

    result = _task_function(jobs.finalize_discovery_scan)(
        "tenant-a",
        "scan-a",
    )

    finalize_scan.assert_called_once_with(
        session,
        tenant_id="tenant-a",
        scan_id="scan-a",
    )
    assert session.commit_calls == 1
    assert result == {
        "tenant_id": "tenant-a",
        "scan_id": "scan-a",
        "status": "partially_complete",
        "observations_count": 7,
    }
    assert factory.calls == [((), {})]


def test_finalize_discovery_scan_reraises_without_committing_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = RecordingSession()
    factory = RecordingSessionFactory(session)
    finalize_scan = Mock(side_effect=RuntimeError("finalization failed"))
    monkeypatch.setattr(jobs, "SessionLocal", factory)
    monkeypatch.setattr(jobs, "finalize_scan", finalize_scan)

    with pytest.raises(RuntimeError, match="finalization failed"):
        _task_function(jobs.finalize_discovery_scan)(
            "tenant-a",
            "scan-a",
        )

    finalize_scan.assert_called_once_with(
        session,
        tenant_id="tenant-a",
        scan_id="scan-a",
    )
    assert session.commit_calls == 0
    assert session.rollback_calls == 1
    assert session.exit_errors == [RuntimeError]
    assert factory.calls == [((), {})]
