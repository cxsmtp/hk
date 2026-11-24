from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any

import pytest
from sqlalchemy import create_engine, delete, event, func, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.models.ai_system import AISystem
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
from app.db.models.user import User
from app.services.hmair.contracts import DiscoveryObservationInput
from app.services.hmair.observation_service import (
    HMAIRIdempotencyConflict,
    HMAIRScopeError,
    ingest_observation,
    observation_idempotency_key,
    observation_payload_digest,
)
from app.services.privacy_sanitizer import sanitize_privacy_payload


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
SECRET = "Bearer secret-token-value"
FAMILY_FIELDS = (
    "normalized_signal",
    "attributes",
    "configuration_summary",
    "usage_summary",
    "identity_hints",
    "relationship_hints",
    "collection_scope",
)


class TrackingSession(Session):
    """A real Session that turns an accidental service commit into a test failure."""

    flush_calls: int
    commit_calls: int
    rollback_calls: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.flush_calls = 0
        self.commit_calls = 0
        self.rollback_calls = 0

    def flush(self, objects: object | None = None) -> None:
        self.flush_calls += 1
        super().flush(objects=objects)

    def commit(self) -> None:
        self.commit_calls += 1
        raise AssertionError("observation ingestion must not commit the caller transaction")

    def rollback(self) -> None:
        self.rollback_calls += 1
        super().rollback()


class _PostgreSQLDiagnostic:
    def __init__(self, *, constraint_name: str) -> None:
        self.constraint_name = constraint_name


class _PostgreSQLUniqueViolation(Exception):
    """Minimal psycopg-shaped exception without a SQLite error string."""

    pgcode = "23505"
    sqlstate = "23505"

    def __init__(self, *, constraint_name: str) -> None:
        super().__init__("duplicate key value violates a database constraint")
        self.diag = _PostgreSQLDiagnostic(constraint_name=constraint_name)


@dataclass(frozen=True)
class HMAIRSeed:
    tenant_id: str
    scan_id: str
    collector_id: str
    target_id: str
    assignment_id: str
    observation: DiscoveryObservationInput


@dataclass(frozen=True)
class TwoTenantSeed:
    first: HMAIRSeed
    second: HMAIRSeed

    @property
    def first_tenant_id(self) -> str:
        return self.first.tenant_id

    @property
    def second_tenant_id(self) -> str:
        return self.second.tenant_id

    @property
    def first_tenant_observation(self) -> DiscoveryObservationInput:
        return self.first.observation


def _enable_sqlite_foreign_keys(dbapi_connection: object, _record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


@pytest.fixture
def hmair_engine() -> Iterator[Engine]:
    # The production migration supports PostgreSQL and SQLite. The unit suite uses
    # an isolated SQLite schema with the exact ORM tables and the immutable 0047
    # triggers, never the developer's local runtime database.
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)

    # Register the optional FK targets even though tests keep those columns NULL.
    assert User.__table__.name == "users"
    assert EvidenceNode.__table__.name == "evidence_nodes"
    tables = [
        Tenant.__table__,
        User.__table__,
        EvidenceNode.__table__,
        AISystem.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        DiscoveryScan.__table__,
        DiscoveryScanTarget.__table__,
        DiscoveryScanAssignment.__table__,
        DiscoveryObservation.__table__,
    ]
    Tenant.metadata.create_all(engine, tables=tables)
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TRIGGER trg_discovery_observations_immutable_update "
            "BEFORE UPDATE ON discovery_observations BEGIN "
            "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER trg_discovery_observations_immutable_delete "
            "BEFORE DELETE ON discovery_observations BEGIN "
            "SELECT RAISE(ABORT, 'immutable_table:discovery_observations'); END"
        )
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db(hmair_engine: Engine) -> Iterator[TrackingSession]:
    factory = sessionmaker(
        bind=hmair_engine,
        class_=TrackingSession,
        autoflush=False,
        expire_on_commit=False,
    )
    session = factory()
    try:
        yield session
    finally:
        Session.rollback(session)
        session.close()


def _observation(
    *,
    suffix: str,
    scan_id: str,
    collector_id: str,
    target_id: str,
) -> DiscoveryObservationInput:
    return DiscoveryObservationInput(
        observation_id=f"observation-{suffix}",
        scan_id=scan_id,
        collector_id=collector_id,
        collector_type="endpoint",
        collector_version="2.0",
        target_id=target_id,
        source_surface="endpoint",
        subject_reference=f"managed-device-{suffix}",
        observed_at=NOW,
        observation_type="running_process",
        normalized_signal={"process_family": "local_ai_runtime"},
        candidate_asset_type="runtime",
        observed_state="observed",
        identifiers={"runtime_name": f"local-runtime-{suffix}"},
        attributes={"version": "1.0"},
        configuration_summary={"mode": "metadata-only"},
        usage_summary={"last_seen": "2026-07-30T12:00:00Z"},
        capability_hints=("local_inference",),
        identity_hints=({"principal_type": "user"},),
        relationship_hints=({"relationship_type": "runs_on"},),
        evidence_reference=f"evidence://bundle-{suffix}/node-a",
        evidence_hash="b" * 64,
        signature_status="verified",
        confidence=0.9,
        freshness="fresh",
        verification_state="verified",
        source_trust="strong",
        collection_scope={"scope_type": "endpoint_group"},
        parser_version="2.0.0",
        schema_version="2.0",
        evidence_mode="direct",
        evidence_mutability="immutable",
        contradiction_state="none",
        contradiction_references=(),
        sensitivity="metadata",
        redaction_status="not_required",
    )


def _seed_tenant(db: TrackingSession, *, suffix: str) -> HMAIRSeed:
    tenant_id = f"tenant-{suffix}"
    scan_id = f"00000000-0000-4000-8000-{int(suffix):012d}"
    collector_id = f"collector-{suffix}"
    target_id = f"target-{suffix}"
    assignment_id = f"10000000-0000-4000-8000-{int(suffix):012d}"

    db.add(
        Tenant(
            id=tenant_id,
            name=f"Tenant {suffix}",
            slug=f"tenant-{suffix}",
            is_active=True,
            platform_mode="enforce",
        )
    )
    db.flush()
    db.add_all(
        [
            DiscoveryTarget(
                target_id=target_id,
                tenant_id=tenant_id,
                target_type="endpoint_group",
                identifier=f"managed-endpoints-{suffix}",
                environment="production",
                owner_hint=None,
                credentials_reference=f"vault-ref-{suffix}",
                permitted_methods_json=["collect_inventory"],
                exclusions_json=[],
                rate_limit=100,
                active_scan_allowed=False,
                sensitive_scope=False,
                last_scanned_at=None,
            ),
            DiscoveryCollector(
                collector_id=collector_id,
                tenant_id=tenant_id,
                collector_type="endpoint",
                version="2.0",
                supported_targets_json=["endpoint_group"],
                active_capabilities_json=[],
                passive_capabilities_json=["inventory"],
                permissions_required_json=["endpoint.metadata.read"],
                sensitive_data_accessed_json=[],
                health="healthy",
                last_success_at=NOW,
                last_failure_at=None,
                data_residency="uae-north",
                control_capability="monitor_only",
                schema_version="2.0",
                limitations_json=["metadata-only"],
                declaration_hash="a" * 64,
            ),
            DiscoveryScan(
                scan_id=scan_id,
                tenant_id=tenant_id,
                name=f"HMAIR seed scan {suffix}",
                requested_by=None,
                scan_type="targeted",
                scope_json={"environment": "production"},
                safety_profile="read-only",
                request_idempotency_key=f"request-{suffix}",
                request_digest="c" * 64,
                status="queued",
                dry_run=False,
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
                rescan_of_scan_id=None,
            ),
        ]
    )
    db.flush()
    db.add(
        DiscoveryScanTarget(
            tenant_id=tenant_id,
            scan_id=scan_id,
            target_id=target_id,
        )
    )
    db.flush()
    db.add(
        DiscoveryScanAssignment(
            assignment_id=assignment_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            target_id=target_id,
            collector_id=collector_id,
            status="pending",
            warning=None,
            error=None,
            started_at=None,
            completed_at=None,
            observations_count=0,
        )
    )
    db.flush()
    return HMAIRSeed(
        tenant_id=tenant_id,
        scan_id=scan_id,
        collector_id=collector_id,
        target_id=target_id,
        assignment_id=assignment_id,
        observation=_observation(
            suffix=suffix,
            scan_id=scan_id,
            collector_id=collector_id,
            target_id=target_id,
        ),
    )


@pytest.fixture
def hmair_seed(db: TrackingSession) -> HMAIRSeed:
    seed = _seed_tenant(db, suffix="1")
    db.flush_calls = 0
    db.commit_calls = 0
    db.rollback_calls = 0
    return seed


@pytest.fixture
def two_tenant_seed(db: TrackingSession) -> TwoTenantSeed:
    seed = TwoTenantSeed(
        first=_seed_tenant(db, suffix="1"),
        second=_seed_tenant(db, suffix="2"),
    )
    db.flush_calls = 0
    db.commit_calls = 0
    db.rollback_calls = 0
    return seed


def _trusted_unsafe_copy(
    payload: DiscoveryObservationInput,
    **updates: object,
) -> DiscoveryObservationInput:
    """Bypass the input contract only to test persistence-layer defense in depth."""

    material = payload.model_dump(mode="python")
    material.update(updates)
    return DiscoveryObservationInput.model_construct(**material)


def _changed_parent(
    payload: DiscoveryObservationInput,
    **updates: object,
) -> DiscoveryObservationInput:
    material = payload.model_dump(mode="json")
    material.update(updates)
    return DiscoveryObservationInput.model_validate(material)


def _sanitized_payload(payload: DiscoveryObservationInput) -> dict[str, Any]:
    material = payload.model_dump(mode="json")
    for field in FAMILY_FIELDS:
        material[field] = sanitize_privacy_payload(material[field])
    return material


def _stored_row(
    *,
    seed: HMAIRSeed,
    payload: DiscoveryObservationInput,
) -> DiscoveryObservation:
    material = _sanitized_payload(payload)
    return DiscoveryObservation(
        observation_id=payload.observation_id,
        tenant_id=seed.tenant_id,
        assignment_id=seed.assignment_id,
        scan_id=payload.scan_id,
        collector_id=payload.collector_id,
        collector_type=payload.collector_type,
        collector_version=payload.collector_version,
        target_id=payload.target_id,
        source_surface=payload.source_surface.value,
        subject_reference=payload.subject_reference,
        normalized_signal_json=material["normalized_signal"],
        observed_at=payload.observed_at,
        received_at=NOW,
        observation_type=payload.observation_type,
        candidate_asset_type=payload.candidate_asset_type,
        observed_state=payload.observed_state.value,
        identifiers_json=material["identifiers"],
        attributes_json=material["attributes"],
        configuration_summary_json=material["configuration_summary"],
        usage_summary_json=material["usage_summary"],
        capability_hints_json=material["capability_hints"],
        identity_hints_json=material["identity_hints"],
        relationship_hints_json=material["relationship_hints"],
        evidence_reference=payload.evidence_reference,
        evidence_hash=payload.evidence_hash,
        signature_status=payload.signature_status,
        confidence=payload.confidence,
        freshness=payload.freshness.value,
        verification_state=payload.verification_state.value,
        source_trust=payload.source_trust.value,
        collection_scope_json=material["collection_scope"],
        parser_version=payload.parser_version,
        schema_version=payload.schema_version,
        evidence_mode=payload.evidence_mode.value,
        evidence_mutability=payload.evidence_mutability.value,
        contradiction_state=payload.contradiction_state.value,
        contradiction_references_json=list(payload.contradiction_references),
        sensitivity=payload.sensitivity,
        redaction_status=payload.redaction_status,
        idempotency_key=observation_idempotency_key(
            tenant_id=seed.tenant_id,
            payload=payload,
        ),
        payload_digest=observation_payload_digest(sanitized_payload=material),
    )


def _listen_for_first_observation_lookup(
    db: TrackingSession,
    *,
    winner: DiscoveryObservation,
) -> tuple[dict[str, bool], Any]:
    state = {"injected": False}

    def inject_winner(orm_execute_state: Any) -> None:
        if state["injected"] or not orm_execute_state.is_select:
            return
        entities = {
            description.get("entity")
            for description in orm_execute_state.statement.column_descriptions
        }
        if DiscoveryObservation not in entities:
            return
        db.add(winner)
        state["injected"] = True

    event.listen(db, "do_orm_execute", inject_winner)
    return state, inject_winner


def _postgresql_integrity_error(*, constraint_name: str) -> IntegrityError:
    return IntegrityError(
        "INSERT INTO discovery_observations (...) VALUES (...) ",
        {},
        _PostgreSQLUniqueViolation(constraint_name=constraint_name),
    )


def test_observation_idempotency_key_is_exact_and_deterministic(
    hmair_seed: HMAIRSeed,
) -> None:
    payload = hmair_seed.observation
    material = {
        "tenant_id": hmair_seed.tenant_id,
        "scan_id": payload.scan_id,
        "collector_id": payload.collector_id,
        "target_id": payload.target_id,
        "observation_id": payload.observation_id,
    }
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    first = observation_idempotency_key(
        tenant_id=hmair_seed.tenant_id,
        payload=payload,
    )
    second = observation_idempotency_key(
        tenant_id=hmair_seed.tenant_id,
        payload=payload,
    )
    altered_content = payload.model_copy(update={"attributes": {"version": "2.0"}})

    assert first == hashlib.sha256(encoded).hexdigest()
    assert second == first
    assert observation_idempotency_key(
        tenant_id=hmair_seed.tenant_id,
        payload=altered_content,
    ) == first
    assert observation_idempotency_key(
        tenant_id="tenant-other",
        payload=payload,
    ) != first


def test_observation_payload_digest_is_exact_and_order_independent() -> None:
    first: Mapping[str, Any] = {
        "z": [3, 2, 1],
        "a": {"name": "caf\u00e9", "enabled": True},
    }
    same_different_order: Mapping[str, Any] = {
        "a": {"enabled": True, "name": "caf\u00e9"},
        "z": [3, 2, 1],
    }
    encoded = json.dumps(
        first,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    digest = observation_payload_digest(sanitized_payload=first)

    assert digest == hashlib.sha256(encoded).hexdigest()
    assert observation_payload_digest(sanitized_payload=same_different_order) == digest
    assert observation_payload_digest(
        sanitized_payload={"a": {"enabled": False, "name": "caf\u00e9"}, "z": [3, 2, 1]}
    ) != digest


def test_ingest_observation_is_idempotent(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    first = ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )
    second = ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )

    assert second.observation_id == first.observation_id
    assert second.payload_digest == first.payload_digest
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 1


def test_ingest_persists_evidence_truth_and_server_owned_receipt_time(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    before = datetime.now(timezone.utc)
    row = ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )
    after = datetime.now(timezone.utc)

    assert before <= row.received_at <= after
    assert row.source_surface == "endpoint"
    assert row.subject_reference == "managed-device-1"
    assert row.normalized_signal_json == {"process_family": "local_ai_runtime"}
    assert row.observed_state == "observed"
    assert row.verification_state == "verified"
    assert row.source_trust == "strong"
    assert row.collection_scope_json == {"scope_type": "endpoint_group"}
    assert row.parser_version == "2.0.0"
    assert row.schema_version == "2.0"
    assert row.evidence_mode == "direct"
    assert row.evidence_mutability == "immutable"
    assert row.contradiction_state == "none"
    assert row.contradiction_references_json == []


def test_ingest_sanitizes_nested_secret_material(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    payload = _trusted_unsafe_copy(
        hmair_seed.observation,
        attributes={
            "nested": {"authorization": SECRET, "contact": "owner@example.com"}
        },
        normalized_signal={"nested": {"authorization": SECRET}},
        configuration_summary={
            "provider": {"raw_prompt": "classify this private prompt"}
        },
        usage_summary={
            "sample": {"screenshot_b64": "c2VjcmV0LWJ5dGVz"}
        },
        identity_hints=(
            {"principal": {"password": "correct-horse-battery-staple"}},
        ),
        relationship_hints=(
            {
                "edge": {
                    "target_url": "https://example.test/path?access_token=secret"
                }
            },
        ),
        collection_scope={"nested": {"authorization": SECRET}},
    )

    row = ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=payload,
    )

    assert row.attributes_json["nested"] == {
        "authorization": "[redacted]",
        "contact": "[email]",
    }
    assert row.normalized_signal_json["nested"] == {
        "authorization": "[redacted]"
    }
    assert row.collection_scope_json["nested"] == {
        "authorization": "[redacted]"
    }
    assert row.configuration_summary_json["provider"]["raw_prompt"] == "[hashed_only]"
    assert row.usage_summary_json["sample"]["screenshot_b64"] == "[omitted:binary]"
    assert row.identity_hints_json[0]["principal"]["password"] == "[redacted]"
    assert (
        row.relationship_hints_json[0]["edge"]["target_url"]
        == "https://example.test/path"
    )
    stored = json.dumps(
        {
            field: getattr(row, f"{field}_json")
            for field in FAMILY_FIELDS
        },
        sort_keys=True,
    )
    assert SECRET not in stored
    assert "correct-horse-battery-staple" not in stored
    assert "c2VjcmV0LWJ5dGVz" not in stored
    assert "classify this private prompt" not in stored
    assert "access_token=secret" not in stored


def test_cross_tenant_parent_reference_is_rejected(
    db: TrackingSession,
    two_tenant_seed: TwoTenantSeed,
) -> None:
    with pytest.raises(HMAIRScopeError):
        ingest_observation(
            db,
            tenant_id=two_tenant_seed.second_tenant_id,
            payload=two_tenant_seed.first_tenant_observation,
        )


@pytest.mark.parametrize("parent", ["scan", "collector", "target"])
def test_each_cross_tenant_parent_isolation_is_enforced(
    parent: str,
    db: TrackingSession,
    two_tenant_seed: TwoTenantSeed,
) -> None:
    first = two_tenant_seed.first
    second = two_tenant_seed.second
    changes: dict[str, object]
    if parent == "scan":
        changes = {"scan_id": first.scan_id}
    elif parent == "collector":
        changes = {
            "collector_id": first.collector_id,
            "collector_type": first.observation.collector_type,
            "collector_version": first.observation.collector_version,
        }
    else:
        changes = {"target_id": first.target_id}
    payload = _changed_parent(second.observation, **changes)

    with pytest.raises(HMAIRScopeError):
        ingest_observation(
            db,
            tenant_id=second.tenant_id,
            payload=payload,
        )

    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 0


def test_tenant_local_assignment_is_required_even_when_parents_exist(
    db: TrackingSession,
    two_tenant_seed: TwoTenantSeed,
) -> None:
    second = two_tenant_seed.second
    assignment = db.get(DiscoveryScanAssignment, second.assignment_id)
    assert assignment is not None
    db.delete(assignment)
    db.flush()

    with pytest.raises(HMAIRScopeError):
        ingest_observation(
            db,
            tenant_id=second.tenant_id,
            payload=second.observation,
        )

    assert db.get(DiscoveryScanAssignment, two_tenant_seed.first.assignment_id) is not None
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 0


def test_altered_replay_is_an_idempotency_conflict(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )
    changed = hmair_seed.observation.model_copy(
        update={"attributes": {"process_name": "different-process"}}
    )

    with pytest.raises(HMAIRIdempotencyConflict):
        ingest_observation(
            db,
            tenant_id=hmair_seed.tenant_id,
            payload=changed,
        )

    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 1


def test_scope_and_conflict_failures_do_not_disclose_secret_material(
    db: TrackingSession,
    two_tenant_seed: TwoTenantSeed,
) -> None:
    first = two_tenant_seed.first
    unsafe_scope = _trusted_unsafe_copy(first.observation, target_id=SECRET)
    with pytest.raises(HMAIRScopeError) as scope_error:
        ingest_observation(
            db,
            tenant_id=first.tenant_id,
            payload=unsafe_scope,
        )

    ingest_observation(db, tenant_id=first.tenant_id, payload=first.observation)
    unsafe_conflict = _trusted_unsafe_copy(
        first.observation,
        attributes={"nested": {"authorization": SECRET}},
    )
    with pytest.raises(HMAIRIdempotencyConflict) as conflict_error:
        ingest_observation(
            db,
            tenant_id=first.tenant_id,
            payload=unsafe_conflict,
        )

    assert "secret-token-value" not in str(scope_error.value)
    assert "secret-token-value" not in repr(scope_error.value)
    assert "secret-token-value" not in str(conflict_error.value)
    assert "secret-token-value" not in repr(conflict_error.value)


def test_unique_conflict_race_returns_savepoint_winner_without_session_rollback(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    winner = _stored_row(seed=hmair_seed, payload=hmair_seed.observation)
    injection, listener = _listen_for_first_observation_lookup(db, winner=winner)
    try:
        row = ingest_observation(
            db,
            tenant_id=hmair_seed.tenant_id,
            payload=hmair_seed.observation,
        )
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert row.observation_id == winner.observation_id
    assert row.payload_digest == winner.payload_digest
    assert db.rollback_calls == 0
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 1
    persisted = db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.observation_id == winner.observation_id
        )
    )
    assert persisted is not None
    assert persisted.observation_id == winner.observation_id
    assert persisted.payload_digest == winner.payload_digest


def test_altered_digest_unique_race_is_an_idempotency_conflict_without_rollback(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    winner = _stored_row(seed=hmair_seed, payload=hmair_seed.observation)
    changed = hmair_seed.observation.model_copy(
        update={"attributes": {"process_name": "different-process"}}
    )
    changed_digest = observation_payload_digest(
        sanitized_payload=_sanitized_payload(changed)
    )
    assert changed_digest != winner.payload_digest
    injection, listener = _listen_for_first_observation_lookup(db, winner=winner)
    try:
        with pytest.raises(HMAIRIdempotencyConflict):
            ingest_observation(
                db,
                tenant_id=hmair_seed.tenant_id,
                payload=changed,
            )
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert db.rollback_calls == 0
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 1
    persisted = db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.observation_id == winner.observation_id
        )
    )
    assert persisted is not None
    assert persisted.payload_digest == winner.payload_digest


def test_postgresql_retry_constraint_race_is_detected_portably(
    monkeypatch: pytest.MonkeyPatch,
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    winner = _stored_row(seed=hmair_seed, payload=hmair_seed.observation)
    injection, listener = _listen_for_first_observation_lookup(db, winner=winner)
    original_flush = db.flush
    raised_postgresql_conflict = False
    postgresql_conflict = _postgresql_integrity_error(
        constraint_name="uq_discovery_observation_retry"
    )
    assert postgresql_conflict.orig.diag.constraint_name == (
        "uq_discovery_observation_retry"
    )
    assert "UNIQUE constraint failed" not in str(postgresql_conflict)

    def flush_with_postgresql_retry_conflict(objects: object | None = None) -> None:
        nonlocal raised_postgresql_conflict
        pending_observations = [
            item for item in db.new if isinstance(item, DiscoveryObservation)
        ]
        winner_is_pending = any(item is winner for item in pending_observations)
        if (
            not raised_postgresql_conflict
            and pending_observations
            and not winner_is_pending
        ):
            raised_postgresql_conflict = True
            raise postgresql_conflict
        original_flush(objects=objects)

    monkeypatch.setattr(db, "flush", flush_with_postgresql_retry_conflict)
    try:
        row = ingest_observation(
            db,
            tenant_id=hmair_seed.tenant_id,
            payload=hmair_seed.observation,
        )
    finally:
        event.remove(db, "do_orm_execute", listener)

    assert injection["injected"] is True
    assert raised_postgresql_conflict is True
    assert row.observation_id == winner.observation_id
    assert row.payload_digest == winner.payload_digest
    assert db.rollback_calls == 0
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 1


def test_non_unique_integrity_error_is_not_swallowed(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    invalid = _trusted_unsafe_copy(hmair_seed.observation, confidence=2.0)

    with pytest.raises(IntegrityError):
        ingest_observation(
            db,
            tenant_id=hmair_seed.tenant_id,
            payload=invalid,
        )

    assert db.rollback_calls == 0
    assert db.get(DiscoveryScan, hmair_seed.scan_id) is not None
    assert db.get(DiscoveryCollector, hmair_seed.collector_id) is not None
    assert db.get(DiscoveryTarget, hmair_seed.target_id) is not None
    assert db.get(DiscoveryScanAssignment, hmair_seed.assignment_id) is not None
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 0


def test_ingest_flushes_without_committing(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    row = ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )

    assert row in db
    assert db.flush_calls >= 1
    assert db.commit_calls == 0


def test_ingest_does_not_create_a_canonical_ai_asset(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    before = db.scalar(select(func.count(AISystem.id)))

    ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )

    assert db.scalar(select(func.count(AISystem.id))) == before == 0


def test_accepted_observation_is_append_only_on_update(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    row = ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )

    with pytest.raises(IntegrityError, match="immutable_table:discovery_observations"):
        db.execute(
            update(DiscoveryObservation)
            .where(DiscoveryObservation.observation_id == row.observation_id)
            .values(confidence=1.0)
        )


def test_accepted_observation_is_append_only_on_delete(
    db: TrackingSession,
    hmair_seed: HMAIRSeed,
) -> None:
    row = ingest_observation(
        db,
        tenant_id=hmair_seed.tenant_id,
        payload=hmair_seed.observation,
    )

    with pytest.raises(IntegrityError, match="immutable_table:discovery_observations"):
        db.execute(
            delete(DiscoveryObservation).where(
                DiscoveryObservation.observation_id == row.observation_id
            )
        )
