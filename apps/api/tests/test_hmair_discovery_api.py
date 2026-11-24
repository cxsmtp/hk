from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any, Iterator

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import Engine, create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.security import create_access_token
from app.db.models.audit import AuditLog
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
from app.db.session import Base, get_db
from app.main import app


HMAIR_FLAGS = (
    "hmair_core",
    "hmair_active_scan",
    "hmair_endpoint",
    "hmair_cloud",
    "hmair_saas",
    "hmair_identity",
    "hmair_repository",
    "hmair_network",
    "hmair_database",
    "hmair_fingerprinting",
    "hmair_usage_attribution",
    "hmair_shadow_ai",
    "hmair_reachability",
)
SURFACE_FLAG_CASES = (
    ("endpoint_group", "hmair_endpoint"),
    ("cloud_subscription", "hmair_cloud"),
    ("saas_tenant", "hmair_saas"),
    ("identity_tenant", "hmair_identity"),
    ("repository", "hmair_repository"),
    ("network_range", "hmair_network"),
    ("database_platform", "hmair_database"),
)
SCAN_RESPONSE_FIELDS = {
    "scan_id",
    "name",
    "scan_type",
    "status",
    "safety_profile",
    "dry_run",
    "observations_count",
    "warnings",
    "errors",
    "coverage_summary",
    "started_at",
    "completed_at",
    "cancelled_at",
}
COLLECTOR_RESPONSE_FIELDS = {
    "collector_id",
    "collector_type",
    "version",
    "health",
    "supported_targets",
    "active_capabilities",
    "passive_capabilities",
    "limitations",
    "enabled",
}
PRIVATE_SCAN_FIELDS = {
    "tenant_id",
    "requested_by",
    "scope_json",
    "request_idempotency_key",
    "request_digest",
    "evidence_bundle_id",
}
PRIVATE_COLLECTOR_FIELDS = {
    "tenant_id",
    "permissions_required_json",
    "sensitive_data_accessed_json",
    "data_residency",
    "declaration_hash",
}
ENQUEUE_PENDING_WARNING = (
    "Discovery dispatch is pending and requires a safe retry."
)
OMITTED_WARNING_NOTICE = "Additional warning detail was omitted for privacy."
OMITTED_ERROR_NOTICE = "Additional error detail was omitted for privacy."
OMITTED_LIMITATION_NOTICE = (
    "Additional limitation detail was omitted for privacy."
)


@dataclass(frozen=True)
class Identity:
    user_id: str
    tenant_id: str
    headers: dict[str, str]


@dataclass(frozen=True)
class SeededScope:
    tenant_id: str
    other_tenant_id: str
    target_id: str
    collector_id: str
    inactive_target_id: str
    mismatched_method_collector_id: str
    unsupported_collector_id: str
    cloud_target_id: str
    cloud_collector_id: str
    foreign_target_id: str
    foreign_collector_id: str
    identities: dict[str, Identity]
    second_owner: Identity
    request_body: dict[str, Any]


@dataclass(frozen=True)
class ApiEnv:
    client: TestClient
    engine: Engine
    session_factory: sessionmaker[Session]
    seed: SeededScope


def _set_hmair_flags(
    monkeypatch: pytest.MonkeyPatch,
    **enabled: bool,
) -> None:
    for flag in HMAIR_FLAGS:
        monkeypatch.setitem(settings.__dict__, flag, bool(enabled.get(flag, False)))


def _identity(
    db: Session,
    *,
    tenant_id: str,
    role: str,
    email: str,
) -> Identity:
    user = User(
        email=email,
        hashed_password="not-used-by-api-tests",
        full_name=f"HMAIR {role.title()}",
        is_active=True,
    )
    db.add(user)
    db.flush()
    db.add(
        UserTenantRole(
            user_id=user.id,
            tenant_id=tenant_id,
            role=role,
        )
    )
    db.flush()
    return Identity(
        user_id=user.id,
        tenant_id=tenant_id,
        headers={
            "Authorization": (
                "Bearer "
                + create_access_token(
                    user.id,
                    tenant_id=tenant_id,
                    role=role,
                )
            ),
            "X-Tenant-ID": tenant_id,
        },
    )


def _target(
    *,
    tenant_id: str,
    target_id: str,
    target_type: str = "endpoint_group",
    active_scan_allowed: bool = True,
    permitted_methods: list[str] | None = None,
) -> DiscoveryTarget:
    return DiscoveryTarget(
        target_id=target_id,
        tenant_id=tenant_id,
        target_type=target_type,
        identifier=f"urn:hawk:{tenant_id}:{target_id}",
        environment="production",
        owner_hint=None,
        credentials_reference=None,
        permitted_methods_json=permitted_methods or ["metadata"],
        exclusions_json=[],
        rate_limit=10,
        active_scan_allowed=active_scan_allowed,
        sensitive_scope=False,
        last_scanned_at=None,
    )


def _collector(
    *,
    tenant_id: str,
    collector_id: str,
    collector_type: str,
    supported_targets: list[str],
    active_capabilities: list[str] | None = None,
    health: str = "healthy",
) -> DiscoveryCollector:
    return DiscoveryCollector(
        collector_id=collector_id,
        tenant_id=tenant_id,
        collector_type=collector_type,
        version="1.0.0",
        supported_targets_json=supported_targets,
        active_capabilities_json=active_capabilities or [],
        passive_capabilities_json=["inventory", "configuration"],
        permissions_required_json=["metadata.read"],
        sensitive_data_accessed_json=[],
        health=health,
        last_success_at=datetime(2026, 8, 1, 12, 0, tzinfo=UTC),
        last_failure_at=None,
        data_residency="tenant_region",
        control_capability="monitor_only",
        schema_version="1.0",
        limitations_json=["Metadata only; unsupported sources remain unknown."],
        declaration_hash="a" * 64,
    )


def _seed_environment(session_factory: sessionmaker[Session]) -> SeededScope:
    with session_factory() as db:
        tenant = Tenant(name="HMAIR API Primary", slug="hmair-api-primary")
        other_tenant = Tenant(name="HMAIR API Other", slug="hmair-api-other")
        db.add_all([tenant, other_tenant])
        db.flush()

        identities = {
            role: _identity(
                db,
                tenant_id=tenant.id,
                role=role,
                email=f"hmair-api-{role}@example.test",
            )
            for role in ("owner", "admin", "auditor", "operator", "viewer")
        }
        second_owner = _identity(
            db,
            tenant_id=other_tenant.id,
            role="owner",
            email="hmair-api-other-owner@example.test",
        )

        target_id = "endpoint-estate"
        collector_id = "endpoint-metadata-collector"
        inactive_target_id = "endpoint-active-scan-disabled"
        mismatched_method_collector_id = "endpoint-process-probe"
        unsupported_collector_id = "cloud-only-collector"
        cloud_target_id = "cloud-estate"
        cloud_collector_id = "cloud-metadata-collector"
        foreign_target_id = "foreign-endpoint-estate"
        foreign_collector_id = "foreign-endpoint-collector"

        db.add_all(
            [
                _target(
                    tenant_id=tenant.id,
                    target_id=target_id,
                ),
                _target(
                    tenant_id=tenant.id,
                    target_id=inactive_target_id,
                    active_scan_allowed=False,
                ),
                _target(
                    tenant_id=tenant.id,
                    target_id=cloud_target_id,
                    target_type="cloud_subscription",
                ),
                _target(
                    tenant_id=other_tenant.id,
                    target_id=foreign_target_id,
                ),
                _collector(
                    tenant_id=tenant.id,
                    collector_id=collector_id,
                    collector_type="endpoint_group",
                    supported_targets=["endpoint_group"],
                    active_capabilities=["metadata"],
                    health="warning",
                ),
                _collector(
                    tenant_id=tenant.id,
                    collector_id=mismatched_method_collector_id,
                    collector_type="endpoint_process_probe",
                    supported_targets=["endpoint_group"],
                    active_capabilities=["process_probe"],
                ),
                _collector(
                    tenant_id=tenant.id,
                    collector_id=unsupported_collector_id,
                    collector_type="cloud_subscription",
                    supported_targets=["cloud_subscription"],
                    active_capabilities=["metadata"],
                ),
                _collector(
                    tenant_id=tenant.id,
                    collector_id=cloud_collector_id,
                    collector_type="cloud_subscription",
                    supported_targets=["cloud_subscription"],
                    active_capabilities=["metadata"],
                ),
                _collector(
                    tenant_id=other_tenant.id,
                    collector_id=foreign_collector_id,
                    collector_type="endpoint_group",
                    supported_targets=["endpoint_group"],
                    active_capabilities=["metadata"],
                ),
            ]
        )
        db.commit()

        request_body = {
            "name": "Enterprise AI estate scan",
            "scan_type": "full_enterprise",
            "scope": {
                "environment": "production",
                "business_unit": "all",
            },
            "target_ids": [target_id],
            "collector_ids": [collector_id],
            "safety_profile": "metadata_only",
            "dry_run": False,
        }
        return SeededScope(
            tenant_id=tenant.id,
            other_tenant_id=other_tenant.id,
            target_id=target_id,
            collector_id=collector_id,
            inactive_target_id=inactive_target_id,
            mismatched_method_collector_id=mismatched_method_collector_id,
            unsupported_collector_id=unsupported_collector_id,
            cloud_target_id=cloud_target_id,
            cloud_collector_id=cloud_collector_id,
            foreign_target_id=foreign_target_id,
            foreign_collector_id=foreign_collector_id,
            identities=identities,
            second_owner=second_owner,
            request_body=request_body,
        )


@pytest.fixture()
def api_env(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[ApiEnv]:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'hmair-discovery-api.sqlite3'}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    session_factory: sessionmaker[Session] = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
    )
    tables = [
        Tenant.__table__,
        User.__table__,
        UserTenantRole.__table__,
        AuditLog.__table__,
        EvidenceNode.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        DiscoveryScan.__table__,
        DiscoveryScanTarget.__table__,
        DiscoveryScanAssignment.__table__,
    ]
    Base.metadata.create_all(bind=engine, tables=tables)
    seed = _seed_environment(session_factory)
    _set_hmair_flags(
        monkeypatch,
        hmair_core=True,
        hmair_active_scan=True,
        hmair_endpoint=True,
    )

    def override_get_db() -> Iterator[Session]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield ApiEnv(
            client=client,
            engine=engine,
            session_factory=session_factory,
            seed=seed,
        )
    finally:
        client.close()
        app.dependency_overrides.clear()
        with engine.begin() as connection:
            connection.execute(
                DiscoveryScan.__table__.update().values(rescan_of_scan_id=None)
            )
        Base.metadata.drop_all(bind=engine, tables=list(reversed(tables)))
        engine.dispose()


@pytest.fixture()
def dispatch_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    from app.api.routers import discovery_scans

    calls: list[tuple[str, str]] = []

    def record(tenant_id: str, scan_id: str) -> None:
        calls.append((tenant_id, scan_id))

    monkeypatch.setattr(discovery_scans.dispatch_scan, "delay", record)
    return calls


def _post_scan(
    env: ApiEnv,
    *,
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    key: str = "estate-scan-001",
):
    request_headers = dict(headers or env.seed.identities["owner"].headers)
    request_headers["Idempotency-Key"] = key
    return env.client.post(
        "/discovery/scans",
        headers=request_headers,
        json=body or env.seed.request_body,
    )


def _assert_scan_response(payload: dict[str, Any]) -> None:
    assert set(payload) == SCAN_RESPONSE_FIELDS
    assert PRIVATE_SCAN_FIELDS.isdisjoint(payload)
    assert isinstance(payload["warnings"], list)
    assert isinstance(payload["errors"], list)
    assert isinstance(payload["coverage_summary"], dict)


def _scan_count(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: str,
) -> int:
    with session_factory() as db:
        return int(
            db.scalar(
                select(func.count(DiscoveryScan.scan_id)).where(
                    DiscoveryScan.tenant_id == tenant_id
                )
            )
            or 0
        )


def _scan_status(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: str,
    scan_id: str,
) -> str | None:
    with session_factory() as db:
        return db.scalar(
            select(DiscoveryScan.status).where(
                DiscoveryScan.tenant_id == tenant_id,
                DiscoveryScan.scan_id == scan_id,
            )
        )


def _nested_mapping_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return {
            *(str(key) for key in value),
            *(
                nested
                for item in value.values()
                for nested in _nested_mapping_keys(item)
            ),
        }
    if isinstance(value, list):
        return {
            nested
            for item in value
            for nested in _nested_mapping_keys(item)
        }
    return set()


def _assert_safe_validation_error(
    response,
    *,
    error_type: str,
    location: list[str],
    message: str,
    marker: str | None = None,
) -> None:
    assert response.status_code == 422
    payload = response.json()
    assert payload == {
        "detail": [
            {
                "type": error_type,
                "loc": location,
                "msg": message,
            }
        ]
    }
    assert "input" not in _nested_mapping_keys(payload)
    if marker is not None:
        assert marker not in response.text


def _tenant_scan_graph_snapshot(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: str,
) -> dict[str, list[dict[str, Any]]]:
    def row_payload(row: object) -> dict[str, Any]:
        return {
            column.name: deepcopy(getattr(row, column.name))
            for column in row.__table__.columns
        }

    with session_factory() as db:
        scans = list(
            db.scalars(
                select(DiscoveryScan)
                .where(DiscoveryScan.tenant_id == tenant_id)
                .order_by(DiscoveryScan.scan_id)
            )
        )
        scan_targets = list(
            db.scalars(
                select(DiscoveryScanTarget)
                .where(DiscoveryScanTarget.tenant_id == tenant_id)
                .order_by(
                    DiscoveryScanTarget.scan_id,
                    DiscoveryScanTarget.target_id,
                )
            )
        )
        assignments = list(
            db.scalars(
                select(DiscoveryScanAssignment)
                .where(DiscoveryScanAssignment.tenant_id == tenant_id)
                .order_by(DiscoveryScanAssignment.assignment_id)
            )
        )
        return {
            "scans": [row_payload(row) for row in scans],
            "scan_targets": [row_payload(row) for row in scan_targets],
            "assignments": [row_payload(row) for row in assignments],
        }


def _tenant_audit_snapshot(
    session_factory: sessionmaker[Session],
    *,
    tenant_id: str,
) -> list[dict[str, Any]]:
    with session_factory() as db:
        rows = list(
            db.scalars(
                select(AuditLog)
                .where(AuditLog.tenant_id == tenant_id)
                .order_by(AuditLog.created_at, AuditLog.id)
            )
        )
        return [
            {
                "id": row.id,
                "tenant_id": row.tenant_id,
                "correlation_id": row.correlation_id,
                "actor_user_id": row.actor_user_id,
                "actor_type": row.actor_type,
                "action": row.action,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "payload": deepcopy(row.payload),
                "created_at": row.created_at,
            }
            for row in rows
        ]


def _assert_scan_audit(
    record: dict[str, Any],
    *,
    tenant_id: str,
    actor_user_id: str,
    action: str,
    resource_id: str,
    payload: dict[str, Any],
    correlation_id: str,
) -> None:
    assert record["tenant_id"] == tenant_id
    assert record["actor_user_id"] == actor_user_id
    assert record["actor_type"] == "human"
    assert record["action"] == action
    assert record["resource_type"] == "discovery_scan"
    assert record["resource_id"] == resource_id
    assert record["payload"] == payload
    assert record["correlation_id"] == correlation_id
    assert isinstance(record["id"], str) and len(record["id"]) == 36
    assert record["created_at"] is not None


def test_owner_can_create_and_read_scan(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    created = _post_scan(api_env)

    assert created.status_code == 202, created.text
    created_payload = created.json()
    _assert_scan_response(created_payload)
    assert created_payload["status"] == "queued"
    assert created_payload["name"] == api_env.seed.request_body["name"]
    assert dispatch_calls == [
        (api_env.seed.tenant_id, created_payload["scan_id"])
    ]

    read = api_env.client.get(
        f"/discovery/scans/{created_payload['scan_id']}",
        headers=api_env.seed.identities["owner"].headers,
    )
    assert read.status_code == 200, read.text
    assert read.json() == created_payload


@pytest.mark.parametrize("role", ("owner", "admin", "auditor", "operator"))
def test_safe_scan_roles_can_create(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    role: str,
) -> None:
    response = _post_scan(
        api_env,
        headers=api_env.seed.identities[role].headers,
        key=f"create-as-{role}",
    )

    assert response.status_code == 202, response.text
    _assert_scan_response(response.json())
    assert response.json()["status"] == "queued"
    assert dispatch_calls == [
        (api_env.seed.tenant_id, response.json()["scan_id"])
    ]


def test_viewer_cannot_create_scan(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    response = _post_scan(
        api_env,
        headers=api_env.seed.identities["viewer"].headers,
        key="viewer-cannot-create",
    )

    assert response.status_code == 403
    assert dispatch_calls == []
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 0


def test_viewer_can_list_and_read_tenant_scans(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    created = _post_scan(api_env, key="viewer-readable-scan")
    assert created.status_code == 202, created.text

    listed = api_env.client.get(
        "/discovery/scans",
        headers=api_env.seed.identities["viewer"].headers,
    )
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1
    _assert_scan_response(listed.json()["items"][0])
    assert [item["scan_id"] for item in listed.json()["items"]] == [
        created.json()["scan_id"]
    ]

    read = api_env.client.get(
        f"/discovery/scans/{created.json()['scan_id']}",
        headers=api_env.seed.identities["viewer"].headers,
    )
    assert read.status_code == 200, read.text


@pytest.mark.parametrize("role", ("owner", "admin", "auditor", "operator"))
def test_safe_scan_roles_can_cancel_idempotently(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    role: str,
) -> None:
    created = _post_scan(api_env, key=f"cancel-source-{role}")
    scan_id = created.json()["scan_id"]

    first = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=api_env.seed.identities[role].headers,
    )
    second = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=api_env.seed.identities[role].headers,
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    _assert_scan_response(first.json())
    _assert_scan_response(second.json())
    assert first.json()["status"] == "cancelled"
    assert second.json()["scan_id"] == scan_id
    assert second.json()["status"] == "cancelled"


@pytest.mark.parametrize("role", ("owner", "admin", "auditor", "operator"))
def test_safe_scan_roles_can_rescan_with_a_bounded_idempotency_key(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    role: str,
) -> None:
    source = _post_scan(api_env, key=f"rescan-source-{role}")
    source_id = source.json()["scan_id"]
    headers = {
        **api_env.seed.identities[role].headers,
        "Idempotency-Key": f"rescan-as-{role}",
    }

    created = api_env.client.post(
        f"/discovery/scans/{source_id}/rescan",
        headers=headers,
    )

    assert created.status_code == 202, created.text
    _assert_scan_response(created.json())
    assert created.json()["scan_id"] != source_id
    assert created.json()["status"] == "queued"
    assert dispatch_calls[-1] == (
        api_env.seed.tenant_id,
        created.json()["scan_id"],
    )


@pytest.mark.parametrize("mutation", ("cancel", "rescan"))
def test_viewer_cannot_mutate_an_existing_scan(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    mutation: str,
) -> None:
    source = _post_scan(api_env, key=f"viewer-{mutation}-source")
    headers = dict(api_env.seed.identities["viewer"].headers)
    if mutation == "rescan":
        headers["Idempotency-Key"] = "viewer-rescan-key"
    calls_before = list(dispatch_calls)
    count_before = _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )

    response = api_env.client.post(
        f"/discovery/scans/{source.json()['scan_id']}/{mutation}",
        headers=headers,
    )

    assert response.status_code == 403
    assert _scan_status(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
        scan_id=source.json()["scan_id"],
    ) == "queued"
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == count_before
    assert dispatch_calls == calls_before


def test_cross_tenant_scan_reads_and_mutations_are_not_found(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    created = _post_scan(api_env, key="tenant-a-private-scan")
    scan_id = created.json()["scan_id"]
    other_headers = api_env.seed.second_owner.headers
    calls_before = list(dispatch_calls)
    primary_count_before = _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )

    assert api_env.client.get(
        f"/discovery/scans/{scan_id}",
        headers=other_headers,
    ).status_code == 404
    assert api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=other_headers,
    ).status_code == 404
    assert api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={**other_headers, "Idempotency-Key": "foreign-rescan"},
    ).status_code == 404

    listed = api_env.client.get("/discovery/scans", headers=other_headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 0
    assert listed.json()["items"] == []
    assert _scan_status(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
        scan_id=scan_id,
    ) == "queued"
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == primary_count_before
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    ) == 0
    assert dispatch_calls == calls_before


def test_create_requires_a_nonempty_bounded_idempotency_key(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    owner_headers = api_env.seed.identities["owner"].headers

    missing = api_env.client.post(
        "/discovery/scans",
        headers=owner_headers,
        json=api_env.seed.request_body,
    )
    empty = api_env.client.post(
        "/discovery/scans",
        headers={**owner_headers, "Idempotency-Key": ""},
        json=api_env.seed.request_body,
    )
    oversized = api_env.client.post(
        "/discovery/scans",
        headers={**owner_headers, "Idempotency-Key": "k" * 129},
        json=api_env.seed.request_body,
    )
    blank = api_env.client.post(
        "/discovery/scans",
        headers={**owner_headers, "Idempotency-Key": "   "},
        json=api_env.seed.request_body,
    )

    assert missing.status_code == 422
    assert empty.status_code == 422
    assert oversized.status_code == 422
    assert blank.status_code == 422
    assert dispatch_calls == []
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 0


def test_rescan_requires_a_nonempty_bounded_idempotency_key(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    source = _post_scan(api_env, key="rescan-key-bound-source")
    scan_id = source.json()["scan_id"]
    owner_headers = api_env.seed.identities["owner"].headers

    missing = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers=owner_headers,
    )
    oversized = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={**owner_headers, "Idempotency-Key": "k" * 129},
    )
    empty = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={**owner_headers, "Idempotency-Key": ""},
    )
    blank = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={**owner_headers, "Idempotency-Key": "   "},
    )

    assert missing.status_code == 422
    assert oversized.status_code == 422
    assert empty.status_code == 422
    assert blank.status_code == 422
    assert len(dispatch_calls) == 1
    assert _scan_status(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
        scan_id=scan_id,
    ) == "queued"
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 1


def test_create_replay_returns_the_same_scan_without_duplicate_enqueue(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    first = _post_scan(api_env, key="create-replay")
    replay = _post_scan(api_env, key="create-replay")

    assert first.status_code == 202, first.text
    assert replay.status_code == 202, replay.text
    _assert_scan_response(first.json())
    _assert_scan_response(replay.json())
    assert replay.json() == first.json()
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 1
    assert dispatch_calls == [
        (api_env.seed.tenant_id, first.json()["scan_id"])
    ]


def test_create_dispatch_uses_the_authoritative_service_outcome(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.routers import discovery_scans
    from app.services.hmair import scan_service

    result_type = getattr(scan_service, "ScanMutationResult", None)
    assert result_type is not None
    assert hasattr(discovery_scans, "create_scan_with_outcome_record")
    service_calls: list[str] = []

    def resolve_simulated_race(db: Session, **kwargs: Any):
        service_calls.append(kwargs["request_idempotency_key"])
        row = scan_service.create_scan(db, **kwargs)
        return result_type(scan=row, created=False)

    monkeypatch.setattr(
        discovery_scans,
        "create_scan_with_outcome_record",
        resolve_simulated_race,
    )
    audits_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )

    response = _post_scan(api_env, key="authoritative-create-race-loser")

    assert response.status_code == 202, response.text
    _assert_scan_response(response.json())
    assert service_calls == ["authoritative-create-race-loser"]
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 1
    assert dispatch_calls == []
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == audits_before


def test_create_replay_with_altered_normalized_content_is_conflict(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    first = _post_scan(api_env, key="create-conflict")
    altered = {
        **api_env.seed.request_body,
        "name": "A different enterprise scan",
    }
    graph_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    audits_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_before = list(dispatch_calls)
    conflict = _post_scan(
        api_env,
        key="create-conflict",
        body=altered,
    )

    assert first.status_code == 202, first.text
    _assert_scan_response(first.json())
    assert conflict.status_code == 409
    assert "request_digest" not in conflict.text
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 1
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == graph_before
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == audits_before
    assert dispatch_calls == calls_before


def test_mutation_keys_are_tenant_scoped(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    first = _post_scan(api_env, key="tenant-local-key")
    second_body = {
        **api_env.seed.request_body,
        "target_ids": [api_env.seed.foreign_target_id],
        "collector_ids": [api_env.seed.foreign_collector_id],
    }
    second = _post_scan(
        api_env,
        headers=api_env.seed.second_owner.headers,
        key="tenant-local-key",
        body=second_body,
    )

    assert first.status_code == 202, first.text
    assert second.status_code == 202, second.text
    _assert_scan_response(first.json())
    _assert_scan_response(second.json())
    assert second.json()["scan_id"] != first.json()["scan_id"]
    assert len(dispatch_calls) == 2


def test_rescan_replay_and_cross_source_conflict_are_idempotent(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    first_source = _post_scan(api_env, key="first-rescan-source")
    second_source = _post_scan(api_env, key="second-rescan-source")
    headers = {
        **api_env.seed.identities["owner"].headers,
        "Idempotency-Key": "rescan-replay-key",
    }

    first = api_env.client.post(
        f"/discovery/scans/{first_source.json()['scan_id']}/rescan",
        headers=headers,
    )
    assert first.status_code == 202, first.text
    graph_after_first = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_after_first = list(dispatch_calls)
    replay = api_env.client.post(
        f"/discovery/scans/{first_source.json()['scan_id']}/rescan",
        headers=headers,
    )
    assert replay.status_code == 202, replay.text
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == graph_after_first
    assert dispatch_calls == calls_after_first
    graph_before_conflict = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    audits_before_conflict = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_before_conflict = list(dispatch_calls)
    conflict = api_env.client.post(
        f"/discovery/scans/{second_source.json()['scan_id']}/rescan",
        headers=headers,
    )

    _assert_scan_response(first.json())
    _assert_scan_response(replay.json())
    assert replay.json()["scan_id"] == first.json()["scan_id"]
    assert conflict.status_code == 409
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == graph_before_conflict
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == audits_before_conflict
    assert dispatch_calls == calls_before_conflict


def test_rescan_dispatch_uses_the_authoritative_service_outcome(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.routers import discovery_scans
    from app.services.hmair import scan_service

    source = _post_scan(api_env, key="authoritative-rescan-source")
    assert source.status_code == 202, source.text
    calls_before = list(dispatch_calls)
    result_type = getattr(scan_service, "ScanMutationResult", None)
    assert result_type is not None
    assert hasattr(discovery_scans, "rescan_with_outcome_record")
    service_calls: list[str] = []

    def resolve_simulated_race(db: Session, **kwargs: Any):
        service_calls.append(kwargs["request_idempotency_key"])
        row = scan_service.rescan(db, **kwargs)
        return result_type(scan=row, created=False)

    monkeypatch.setattr(
        discovery_scans,
        "rescan_with_outcome_record",
        resolve_simulated_race,
    )
    audits_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )

    response = api_env.client.post(
        f"/discovery/scans/{source.json()['scan_id']}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": "authoritative-rescan-race-loser",
        },
    )

    assert response.status_code == 202, response.text
    _assert_scan_response(response.json())
    assert service_calls == ["authoritative-rescan-race-loser"]
    assert response.json()["scan_id"] != source.json()["scan_id"]
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 2
    assert dispatch_calls == calls_before
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == audits_before


def test_create_writes_one_tenant_bound_privacy_safe_audit_on_replay(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    private_name_marker = "private-audit-name-marker-not-for-evidence"
    body = {
        **api_env.seed.request_body,
        "name": private_name_marker,
    }
    created = _post_scan(api_env, key="audit-create-once", body=body)
    replay = _post_scan(api_env, key="audit-create-once", body=body)

    assert created.status_code == 202, created.text
    assert replay.status_code == 202, replay.text
    assert replay.json()["scan_id"] == created.json()["scan_id"]
    correlation_id = created.headers.get("X-Correlation-Id")
    assert isinstance(correlation_id, str) and 1 <= len(correlation_id) <= 64
    records = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    assert len(records) == 1
    assert private_name_marker not in str(records)
    _assert_scan_audit(
        records[0],
        tenant_id=api_env.seed.tenant_id,
        actor_user_id=api_env.seed.identities["owner"].user_id,
        action="discovery.scan.create",
        resource_id=created.json()["scan_id"],
        payload={
            "scan_type": api_env.seed.request_body["scan_type"],
            "safety_profile": api_env.seed.request_body["safety_profile"],
            "dry_run": api_env.seed.request_body["dry_run"],
            "exclusion_count": 0,
        },
        correlation_id=correlation_id,
    )
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    ) == []
    assert dispatch_calls == [
        (api_env.seed.tenant_id, created.json()["scan_id"])
    ]


def test_cancel_writes_one_tenant_bound_privacy_safe_audit_on_replay(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    created = _post_scan(api_env, key="audit-cancel-source")
    scan_id = created.json()["scan_id"]
    first = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=api_env.seed.identities["operator"].headers,
    )
    replay = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=api_env.seed.identities["operator"].headers,
    )

    assert first.status_code == 200, first.text
    assert replay.status_code == 200, replay.text
    assert replay.json()["status"] == "cancelled"
    correlation_id = first.headers.get("X-Correlation-Id")
    assert isinstance(correlation_id, str) and 1 <= len(correlation_id) <= 64
    records = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    cancel_records = [
        record
        for record in records
        if record["action"] == "discovery.scan.cancel"
    ]
    assert len(cancel_records) == 1
    _assert_scan_audit(
        cancel_records[0],
        tenant_id=api_env.seed.tenant_id,
        actor_user_id=api_env.seed.identities["operator"].user_id,
        action="discovery.scan.cancel",
        resource_id=scan_id,
        payload={"status": "cancelled"},
        correlation_id=correlation_id,
    )
    assert [record["action"] for record in records].count(
        "discovery.scan.create"
    ) == 1


def test_rescan_writes_one_tenant_bound_privacy_safe_audit_on_replay(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    source = _post_scan(api_env, key="audit-rescan-source")
    source_id = source.json()["scan_id"]
    headers = {
        **api_env.seed.identities["auditor"].headers,
        "Idempotency-Key": "audit-rescan-once",
    }
    first = api_env.client.post(
        f"/discovery/scans/{source_id}/rescan",
        headers=headers,
    )
    replay = api_env.client.post(
        f"/discovery/scans/{source_id}/rescan",
        headers=headers,
    )

    assert first.status_code == 202, first.text
    assert replay.status_code == 202, replay.text
    rescan_id = first.json()["scan_id"]
    assert replay.json()["scan_id"] == rescan_id
    correlation_id = first.headers.get("X-Correlation-Id")
    assert isinstance(correlation_id, str) and 1 <= len(correlation_id) <= 64
    records = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    rescan_records = [
        record
        for record in records
        if record["action"] == "discovery.scan.rescan"
    ]
    assert len(rescan_records) == 1
    _assert_scan_audit(
        rescan_records[0],
        tenant_id=api_env.seed.tenant_id,
        actor_user_id=api_env.seed.identities["auditor"].user_id,
        action="discovery.scan.rescan",
        resource_id=rescan_id,
        payload={
            "source_scan_id": source_id,
            "scan_type": api_env.seed.request_body["scan_type"],
            "safety_profile": api_env.seed.request_body["safety_profile"],
            "dry_run": api_env.seed.request_body["dry_run"],
        },
        correlation_id=correlation_id,
    )
    assert [record["action"] for record in records].count(
        "discovery.scan.create"
    ) == 1


def test_forbidden_scan_mutations_do_not_write_audit_evidence(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    source = _post_scan(api_env, key="audit-forbidden-source")
    scan_id = source.json()["scan_id"]
    before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_before = list(dispatch_calls)
    viewer_headers = api_env.seed.identities["viewer"].headers

    create = _post_scan(
        api_env,
        headers=viewer_headers,
        key="audit-forbidden-create",
    )
    cancel = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=viewer_headers,
    )
    rescan = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={
            **viewer_headers,
            "Idempotency-Key": "audit-forbidden-rescan",
        },
    )

    assert [create.status_code, cancel.status_code, rescan.status_code] == [
        403,
        403,
        403,
    ]
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == before
    assert dispatch_calls == calls_before


def test_cross_tenant_scan_rejections_do_not_write_audit_evidence(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    source = _post_scan(api_env, key="audit-cross-tenant-source")
    scan_id = source.json()["scan_id"]
    primary_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    other_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    )
    calls_before = list(dispatch_calls)
    foreign_body = {
        **api_env.seed.request_body,
        "target_ids": [api_env.seed.foreign_target_id],
        "collector_ids": [api_env.seed.foreign_collector_id],
    }

    create = _post_scan(
        api_env,
        key="audit-cross-tenant-create",
        body=foreign_body,
    )
    cancel = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=api_env.seed.second_owner.headers,
    )
    rescan = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={
            **api_env.seed.second_owner.headers,
            "Idempotency-Key": "audit-cross-tenant-rescan",
        },
    )

    assert [create.status_code, cancel.status_code, rescan.status_code] == [
        404,
        404,
        404,
    ]
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == primary_before
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    ) == other_before
    assert dispatch_calls == calls_before


def test_core_off_scan_mutations_do_not_write_audit_evidence(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _post_scan(api_env, key="audit-core-off-source")
    scan_id = source.json()["scan_id"]
    primary_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    other_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    )
    calls_before = list(dispatch_calls)
    monkeypatch.setitem(settings.__dict__, "hmair_core", False)
    marker = "sk-live-core-off-audit-marker"

    create = api_env.client.post(
        "/discovery/scans",
        headers={
            "Content-Type": "application/json",
            "Idempotency-Key": "audit-core-off-create",
        },
        content=(
            '{"scan_type":"full_enterprise","raw_prompt":"password='
            f"{marker}"
        ),
    )
    cancel = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=api_env.seed.identities["owner"].headers,
    )
    rescan = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": "audit-core-off-rescan",
        },
    )

    assert [create.status_code, cancel.status_code, rescan.status_code] == [
        404,
        404,
        404,
    ]
    assert marker not in create.text
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == primary_before
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    ) == other_before
    assert dispatch_calls == calls_before


def test_invalid_scan_requests_do_not_write_audit_evidence(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    source = _post_scan(api_env, key="audit-validation-source")
    scan_id = source.json()["scan_id"]
    before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_before = list(dispatch_calls)
    marker = "sk-live-invalid-audit-marker"
    owner_headers = api_env.seed.identities["owner"].headers

    malformed = api_env.client.post(
        "/discovery/scans",
        headers={
            **owner_headers,
            "Content-Type": "application/json",
            "Idempotency-Key": "audit-malformed-create",
        },
        content=f'{{"name":"password={marker}"',
    )
    missing_create_key = api_env.client.post(
        "/discovery/scans",
        headers=owner_headers,
        json=api_env.seed.request_body,
    )
    invalid_body = _post_scan(
        api_env,
        key="audit-invalid-body",
        body={
            **api_env.seed.request_body,
            "scan_type": f"password={marker}",
        },
    )
    missing_rescan_key = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers=owner_headers,
    )

    assert [
        malformed.status_code,
        missing_create_key.status_code,
        invalid_body.status_code,
        missing_rescan_key.status_code,
    ] == [422, 422, 422, 422]
    assert marker not in malformed.text
    assert marker not in invalid_body.text
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == before
    assert dispatch_calls == calls_before


def test_audit_writer_failure_rolls_back_create_and_prevents_dispatch(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.routers import discovery_scans

    marker = "private-audit-failure-marker-not-for-storage"
    graph_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    primary_audits_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    other_audits_before = _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    )

    def fail_audit(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("audit sink failed")

    monkeypatch.setattr(
        discovery_scans,
        "write_audit_log",
        fail_audit,
        raising=False,
    )

    response = _post_scan(
        api_env,
        key="audit-writer-failure",
        body={
            **api_env.seed.request_body,
            "name": marker,
        },
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": {
            "code": "internal_error",
            "message": (
                "Request failed. Use the correlation_id to investigate server logs."
            ),
            "correlation_id": response.headers["X-Correlation-Id"],
        }
    }
    assert marker not in response.text
    assert "audit sink failed" not in response.text

    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == graph_before
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == primary_audits_before
    assert _tenant_audit_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    ) == other_audits_before
    assert marker not in str(primary_audits_before)
    assert dispatch_calls == []


def test_creation_commits_before_enqueue(
    api_env: ApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.routers import discovery_scans

    observed: list[tuple[str, str, str, str, dict[str, Any]]] = []

    def inspect_committed_scan(tenant_id: str, scan_id: str) -> None:
        with api_env.session_factory() as db:
            row = db.scalar(
                select(DiscoveryScan).where(
                    DiscoveryScan.tenant_id == tenant_id,
                    DiscoveryScan.scan_id == scan_id,
                )
            )
            assert row is not None
            audit = db.scalar(
                select(AuditLog).where(
                    AuditLog.tenant_id == tenant_id,
                    AuditLog.action == "discovery.scan.create",
                    AuditLog.resource_type == "discovery_scan",
                    AuditLog.resource_id == scan_id,
                )
            )
            assert audit is not None
            assert audit.actor_user_id == api_env.seed.identities["owner"].user_id
            assert audit.actor_type == "human"
            assert audit.correlation_id
            observed.append(
                (
                    tenant_id,
                    scan_id,
                    row.status,
                    audit.action,
                    dict(audit.payload),
                )
            )

    monkeypatch.setattr(
        discovery_scans.dispatch_scan,
        "delay",
        inspect_committed_scan,
    )

    response = _post_scan(api_env, key="commit-before-enqueue")

    assert response.status_code == 202, response.text
    _assert_scan_response(response.json())
    assert observed == [
        (
            api_env.seed.tenant_id,
            response.json()["scan_id"],
            "queued",
            "discovery.scan.create",
            {
                "scan_type": api_env.seed.request_body["scan_type"],
                "safety_profile": api_env.seed.request_body["safety_profile"],
                "dry_run": api_env.seed.request_body["dry_run"],
                "exclusion_count": 0,
            },
        )
    ]


def test_enqueue_failure_is_sanitized_and_leaves_a_queued_retry_warning(
    api_env: ApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.routers import discovery_scans

    secret = "sk-live-enqueue-secret-must-not-leak"

    def fail_enqueue(_tenant_id: str, _scan_id: str) -> None:
        raise RuntimeError(f"broker rejected password={secret}")

    monkeypatch.setattr(discovery_scans.dispatch_scan, "delay", fail_enqueue)

    response = _post_scan(api_env, key="enqueue-failure")

    assert response.status_code == 202, response.text
    _assert_scan_response(response.json())
    assert secret not in response.text
    scan_id = response.json()["scan_id"]
    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == scan_id,
            )
        )
        assert row is not None
        assert row.status == "queued"
        assert row.warnings_json
        assert secret not in str(row.warnings_json)
        assert ENQUEUE_PENDING_WARNING in row.warnings_json
        row.warnings_json = [
            *row.warnings_json,
            "Endpoint evidence is stale.",
        ]
        db.commit()

    retry_calls: list[tuple[str, str]] = []

    def succeed_enqueue(tenant_id: str, retry_scan_id: str) -> None:
        retry_calls.append((tenant_id, retry_scan_id))

    monkeypatch.setattr(
        discovery_scans.dispatch_scan,
        "delay",
        succeed_enqueue,
    )
    retry = _post_scan(api_env, key="enqueue-failure")

    assert retry.status_code == 202, retry.text
    assert retry.json()["scan_id"] == scan_id
    assert retry_calls == [(api_env.seed.tenant_id, scan_id)]
    assert ENQUEUE_PENDING_WARNING not in retry.json()["warnings"]
    assert "Endpoint evidence is stale." in retry.json()["warnings"]
    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == scan_id,
            )
        )
        assert row is not None
        assert ENQUEUE_PENDING_WARNING not in row.warnings_json
        assert "Endpoint evidence is stale." in row.warnings_json

    replay = _post_scan(api_env, key="enqueue-failure")

    assert replay.status_code == 202, replay.text
    assert replay.json()["scan_id"] == scan_id
    assert retry_calls == [(api_env.seed.tenant_id, scan_id)]
    audit_records = [
        record
        for record in _tenant_audit_snapshot(
            api_env.session_factory,
            tenant_id=api_env.seed.tenant_id,
        )
        if record["action"] == "discovery.scan.create"
        and record["resource_id"] == scan_id
    ]
    assert len(audit_records) == 1
    assert secret not in str(audit_records[0])
    _assert_scan_audit(
        audit_records[0],
        tenant_id=api_env.seed.tenant_id,
        actor_user_id=api_env.seed.identities["owner"].user_id,
        action="discovery.scan.create",
        resource_id=scan_id,
        payload={
            "scan_type": api_env.seed.request_body["scan_type"],
            "safety_profile": api_env.seed.request_body["safety_profile"],
            "dry_run": api_env.seed.request_body["dry_run"],
            "exclusion_count": 0,
        },
        correlation_id=response.headers["X-Correlation-Id"],
    )


def test_rescan_commits_the_new_scan_before_enqueue(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.routers import discovery_scans

    source = _post_scan(api_env, key="rescan-commit-source")
    source_id = source.json()["scan_id"]
    observed: list[
        tuple[str, str, str, str | None, str, dict[str, Any]]
    ] = []

    def inspect_committed_scan(tenant_id: str, scan_id: str) -> None:
        with api_env.session_factory() as db:
            row = db.scalar(
                select(DiscoveryScan).where(
                    DiscoveryScan.tenant_id == tenant_id,
                    DiscoveryScan.scan_id == scan_id,
                )
            )
            assert row is not None
            audit = db.scalar(
                select(AuditLog).where(
                    AuditLog.tenant_id == tenant_id,
                    AuditLog.action == "discovery.scan.rescan",
                    AuditLog.resource_type == "discovery_scan",
                    AuditLog.resource_id == scan_id,
                )
            )
            assert audit is not None
            assert audit.actor_user_id == api_env.seed.identities["owner"].user_id
            assert audit.actor_type == "human"
            assert audit.correlation_id
            observed.append(
                (
                    tenant_id,
                    scan_id,
                    row.status,
                    row.rescan_of_scan_id,
                    audit.action,
                    dict(audit.payload),
                )
            )

    monkeypatch.setattr(
        discovery_scans.dispatch_scan,
        "delay",
        inspect_committed_scan,
    )

    response = api_env.client.post(
        f"/discovery/scans/{source_id}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": "rescan-commit-before-enqueue",
        },
    )

    assert response.status_code == 202, response.text
    _assert_scan_response(response.json())
    assert observed == [
        (
            api_env.seed.tenant_id,
            response.json()["scan_id"],
            "queued",
            source_id,
            "discovery.scan.rescan",
            {
                "source_scan_id": source_id,
                "scan_type": api_env.seed.request_body["scan_type"],
                "safety_profile": api_env.seed.request_body["safety_profile"],
                "dry_run": api_env.seed.request_body["dry_run"],
            },
        )
    ]


def test_rescan_enqueue_failure_is_sanitized_and_retryable(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.routers import discovery_scans

    source = _post_scan(api_env, key="rescan-enqueue-failure-source")
    secret = "sk-live-rescan-enqueue-secret-must-not-leak"

    def fail_enqueue(_tenant_id: str, _scan_id: str) -> None:
        raise RuntimeError(f"broker rejected password={secret}")

    monkeypatch.setattr(discovery_scans.dispatch_scan, "delay", fail_enqueue)

    response = api_env.client.post(
        f"/discovery/scans/{source.json()['scan_id']}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": "rescan-enqueue-failure",
        },
    )

    assert response.status_code == 202, response.text
    _assert_scan_response(response.json())
    assert secret not in response.text
    rescan_id = response.json()["scan_id"]
    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == rescan_id,
            )
        )
        assert row is not None
        assert row.status == "queued"
        assert row.rescan_of_scan_id == source.json()["scan_id"]
        assert row.warnings_json
        assert secret not in str(row.warnings_json)
        assert ENQUEUE_PENDING_WARNING in row.warnings_json
        row.warnings_json = [
            *row.warnings_json,
            "Endpoint evidence is stale.",
        ]
        db.commit()

    retry_calls: list[tuple[str, str]] = []

    def succeed_enqueue(tenant_id: str, retry_scan_id: str) -> None:
        retry_calls.append((tenant_id, retry_scan_id))

    monkeypatch.setattr(
        discovery_scans.dispatch_scan,
        "delay",
        succeed_enqueue,
    )
    headers = {
        **api_env.seed.identities["owner"].headers,
        "Idempotency-Key": "rescan-enqueue-failure",
    }
    retry = api_env.client.post(
        f"/discovery/scans/{source.json()['scan_id']}/rescan",
        headers=headers,
    )

    assert retry.status_code == 202, retry.text
    assert retry.json()["scan_id"] == rescan_id
    assert retry_calls == [(api_env.seed.tenant_id, rescan_id)]
    assert ENQUEUE_PENDING_WARNING not in retry.json()["warnings"]
    assert "Endpoint evidence is stale." in retry.json()["warnings"]
    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == rescan_id,
            )
        )
        assert row is not None
        assert ENQUEUE_PENDING_WARNING not in row.warnings_json
        assert "Endpoint evidence is stale." in row.warnings_json

    replay = api_env.client.post(
        f"/discovery/scans/{source.json()['scan_id']}/rescan",
        headers=headers,
    )

    assert replay.status_code == 202, replay.text
    assert replay.json()["scan_id"] == rescan_id
    assert retry_calls == [(api_env.seed.tenant_id, rescan_id)]
    audit_records = [
        record
        for record in _tenant_audit_snapshot(
            api_env.session_factory,
            tenant_id=api_env.seed.tenant_id,
        )
        if record["action"] == "discovery.scan.rescan"
        and record["resource_id"] == rescan_id
    ]
    assert len(audit_records) == 1
    assert secret not in str(audit_records[0])
    _assert_scan_audit(
        audit_records[0],
        tenant_id=api_env.seed.tenant_id,
        actor_user_id=api_env.seed.identities["owner"].user_id,
        action="discovery.scan.rescan",
        resource_id=rescan_id,
        payload={
            "source_scan_id": source.json()["scan_id"],
            "scan_type": api_env.seed.request_body["scan_type"],
            "safety_profile": api_env.seed.request_body["safety_profile"],
            "dry_run": api_env.seed.request_body["dry_run"],
        },
        correlation_id=response.headers["X-Correlation-Id"],
    )


@pytest.mark.parametrize(
    ("target_field", "collector_field"),
    (
        ("foreign_target_id", "collector_id"),
        ("target_id", "foreign_collector_id"),
    ),
)
def test_cross_tenant_scan_parents_are_nonrevealing_not_found(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    target_field: str,
    collector_field: str,
) -> None:
    target_id = getattr(api_env.seed, target_field)
    collector_id = getattr(api_env.seed, collector_field)
    body = {
        **api_env.seed.request_body,
        "target_ids": [target_id],
        "collector_ids": [collector_id],
    }
    primary_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    other_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    )

    response = _post_scan(
        api_env,
        key=f"cross-tenant-{target_field}-{collector_field}",
        body=body,
    )

    assert response.status_code == 404
    assert target_id not in response.text
    assert collector_id not in response.text
    assert dispatch_calls == []
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == primary_before
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    ) == other_before


def test_unknown_target_is_sanitized_not_found(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    secret_target = "target-password-sk-live-must-not-leak"
    body = {
        **api_env.seed.request_body,
        "target_ids": [secret_target],
    }
    primary_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    other_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    )

    response = _post_scan(
        api_env,
        key="unknown-target",
        body=body,
    )

    assert response.status_code == 404
    assert secret_target not in response.text
    assert dispatch_calls == []
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == primary_before
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.other_tenant_id,
    ) == other_before


@pytest.mark.parametrize(
    ("body_update", "expected_status"),
    (
        ({"target_ids": ["endpoint-active-scan-disabled"]}, 422),
        ({"collector_ids": ["endpoint-process-probe"]}, 422),
        ({"collector_ids": ["cloud-only-collector"]}, 422),
    ),
)
def test_target_safety_method_and_collector_compatibility_are_enforced(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    body_update: dict[str, Any],
    expected_status: int,
) -> None:
    body = {**api_env.seed.request_body, **body_update}

    response = _post_scan(
        api_env,
        key=f"invalid-selection-{next(iter(body_update.values()))[0]}",
        body=body,
    )

    assert response.status_code == expected_status
    assert dispatch_calls == []
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 0


def test_selected_surface_flag_is_required_for_creation(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    body = {
        **api_env.seed.request_body,
        "target_ids": [api_env.seed.cloud_target_id],
        "collector_ids": [api_env.seed.cloud_collector_id],
    }

    response = _post_scan(
        api_env,
        key="cloud-surface-disabled",
        body=body,
    )

    assert response.status_code == 404
    assert dispatch_calls == []


@pytest.mark.parametrize(("target_type", "surface_flag"), SURFACE_FLAG_CASES)
def test_scan_creation_maps_every_true_surface_to_its_exact_flag(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
    target_type: str,
    surface_flag: str,
) -> None:
    target_id = f"{target_type}-mapping-target"
    collector_id = f"{target_type}-mapping-collector"
    with api_env.session_factory() as db:
        db.add_all(
            [
                _target(
                    tenant_id=api_env.seed.tenant_id,
                    target_id=target_id,
                    target_type=target_type,
                ),
                _collector(
                    tenant_id=api_env.seed.tenant_id,
                    collector_id=collector_id,
                    collector_type=target_type,
                    supported_targets=[target_type],
                    active_capabilities=["metadata"],
                ),
            ]
        )
        db.commit()
    for _target_type, flag in SURFACE_FLAG_CASES:
        monkeypatch.setitem(settings.__dict__, flag, False)
    wrong_flag = (
        "hmair_cloud"
        if surface_flag == "hmair_endpoint"
        else "hmair_endpoint"
    )
    monkeypatch.setitem(settings.__dict__, wrong_flag, True)
    body = {
        **api_env.seed.request_body,
        "target_ids": [target_id],
        "collector_ids": [collector_id],
    }

    wrong = _post_scan(
        api_env,
        key=f"wrong-flag-{target_type}",
        body=body,
    )

    assert wrong.status_code == 404
    assert dispatch_calls == []
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 0

    monkeypatch.setitem(settings.__dict__, wrong_flag, False)
    monkeypatch.setitem(settings.__dict__, surface_flag, True)
    accepted = _post_scan(
        api_env,
        key=f"correct-flag-{target_type}",
        body=body,
    )

    assert accepted.status_code == 202, accepted.text
    _assert_scan_response(accepted.json())
    assert dispatch_calls == [
        (api_env.seed.tenant_id, accepted.json()["scan_id"])
    ]


@pytest.mark.parametrize("disabled_flag", ("hmair_core", "hmair_active_scan", "hmair_endpoint"))
def test_scan_creation_is_hidden_when_a_required_flag_is_disabled(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
    disabled_flag: str,
) -> None:
    monkeypatch.setitem(settings.__dict__, disabled_flag, False)

    response = _post_scan(
        api_env,
        key=f"disabled-{disabled_flag}",
    )

    assert response.status_code == 404
    assert dispatch_calls == []
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 0


@pytest.mark.parametrize("disabled_flag", ("hmair_active_scan", "hmair_endpoint"))
def test_rescan_is_hidden_when_active_scan_or_selected_surface_is_off(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
    disabled_flag: str,
) -> None:
    source = _post_scan(api_env, key=f"rescan-flag-source-{disabled_flag}")
    scan_id = source.json()["scan_id"]
    graph_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_before = list(dispatch_calls)
    monkeypatch.setitem(settings.__dict__, disabled_flag, False)

    response = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": f"rescan-disabled-{disabled_flag}",
        },
    )

    assert response.status_code == 404
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == graph_before
    assert dispatch_calls == calls_before


@pytest.mark.parametrize(
    "safety_mutation",
    ("active_scan_allowed", "permitted_methods", "collector_compatibility"),
)
def test_rescan_revalidates_current_target_and_collector_safety(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    safety_mutation: str,
) -> None:
    source = _post_scan(api_env, key=f"rescan-safety-source-{safety_mutation}")
    scan_id = source.json()["scan_id"]
    with api_env.session_factory() as db:
        target = db.scalar(
            select(DiscoveryTarget).where(
                DiscoveryTarget.tenant_id == api_env.seed.tenant_id,
                DiscoveryTarget.target_id == api_env.seed.target_id,
            )
        )
        collector = db.scalar(
            select(DiscoveryCollector).where(
                DiscoveryCollector.tenant_id == api_env.seed.tenant_id,
                DiscoveryCollector.collector_id == api_env.seed.collector_id,
            )
        )
        assert target is not None
        assert collector is not None
        if safety_mutation == "active_scan_allowed":
            target.active_scan_allowed = False
        elif safety_mutation == "permitted_methods":
            target.permitted_methods_json = ["configuration"]
        else:
            collector.supported_targets_json = ["cloud_subscription"]
        db.commit()
    graph_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_before = list(dispatch_calls)

    response = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": f"rescan-safety-{safety_mutation}",
        },
    )

    assert response.status_code == 422
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == graph_before
    assert dispatch_calls == calls_before


def test_read_routes_remain_available_when_active_scan_and_surface_are_off(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _post_scan(api_env, key="read-while-active-disabled")
    scan_id = created.json()["scan_id"]
    calls_before = list(dispatch_calls)
    monkeypatch.setitem(settings.__dict__, "hmair_active_scan", False)
    monkeypatch.setitem(settings.__dict__, "hmair_endpoint", False)

    responses = (
        api_env.client.get(
            "/discovery/scans",
            headers=api_env.seed.identities["viewer"].headers,
        ),
        api_env.client.get(
            f"/discovery/scans/{scan_id}",
            headers=api_env.seed.identities["viewer"].headers,
        ),
        api_env.client.get(
            "/discovery/collectors",
            headers=api_env.seed.identities["viewer"].headers,
        ),
        api_env.client.get(
            f"/discovery/collectors/{api_env.seed.collector_id}/health",
            headers=api_env.seed.identities["viewer"].headers,
        ),
    )

    assert [response.status_code for response in responses] == [200, 200, 200, 200]
    assert responses[3].json()["enabled"] is False
    assert _scan_status(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
        scan_id=scan_id,
    ) == "queued"
    assert dispatch_calls == calls_before


@pytest.mark.parametrize(
    ("method", "path"),
    (
        ("get", "/discovery/scans"),
        ("get", "/discovery/scans/missing"),
        ("post", "/discovery/scans"),
        ("post", "/discovery/scans/missing/cancel"),
        ("post", "/discovery/scans/missing/rescan"),
        ("get", "/discovery/collectors"),
        ("get", "/discovery/collectors/missing/health"),
    ),
)
def test_all_hmair_routes_are_hidden_while_core_is_off(
    api_env: ApiEnv,
    monkeypatch: pytest.MonkeyPatch,
    method: str,
    path: str,
) -> None:
    monkeypatch.setitem(settings.__dict__, "hmair_core", False)
    headers = {
        **api_env.seed.identities["owner"].headers,
        "Idempotency-Key": "feature-hidden-request",
    }
    kwargs: dict[str, Any] = {"headers": headers}
    if method == "post" and path == "/discovery/scans":
        kwargs["json"] = api_env.seed.request_body

    response = getattr(api_env.client, method)(path, **kwargs)

    assert response.status_code == 404


def test_core_off_is_nonrevealing_before_authentication(
    api_env: ApiEnv,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(settings.__dict__, "hmair_core", False)
    requests = (
        api_env.client.get("/discovery/scans"),
        api_env.client.get("/discovery/scans/missing"),
        api_env.client.post(
            "/discovery/scans",
            headers={"Idempotency-Key": "core-off-unauthenticated-create"},
            json=api_env.seed.request_body,
        ),
        api_env.client.post("/discovery/scans/missing/cancel"),
        api_env.client.post(
            "/discovery/scans/missing/rescan",
            headers={"Idempotency-Key": "core-off-unauthenticated-rescan"},
        ),
        api_env.client.get("/discovery/collectors"),
        api_env.client.get("/discovery/collectors/missing/health"),
    )
    assert [response.status_code for response in requests] == [404] * 7
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 0


def test_core_off_rejects_malformed_secret_json_before_parsing_or_auth(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "sk-live-core-off-malformed-json-marker"
    malformed = (
        '{"scan_type":"full_enterprise","raw_prompt":"password='
        f"{marker}"
    )
    graph_before = _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    calls_before = list(dispatch_calls)
    monkeypatch.setitem(settings.__dict__, "hmair_core", False)

    response = api_env.client.post(
        "/discovery/scans",
        headers={
            "Content-Type": "application/json",
            "Idempotency-Key": "core-off-malformed-json",
        },
        content=malformed,
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}
    assert marker not in response.text
    assert "raw_prompt" not in response.text
    assert _tenant_scan_graph_snapshot(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == graph_before
    assert dispatch_calls == calls_before


def test_core_off_blocks_existing_scan_mutations_without_side_effects(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _post_scan(api_env, key="core-off-existing-source")
    scan_id = source.json()["scan_id"]
    calls_before = list(dispatch_calls)
    monkeypatch.setitem(settings.__dict__, "hmair_core", False)

    cancelled = api_env.client.post(
        f"/discovery/scans/{scan_id}/cancel",
        headers=api_env.seed.identities["owner"].headers,
    )
    rescanned = api_env.client.post(
        f"/discovery/scans/{scan_id}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": "core-off-existing-rescan",
        },
    )

    assert cancelled.status_code == 404
    assert rescanned.status_code == 404
    assert _scan_status(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
        scan_id=scan_id,
    ) == "queued"
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 1
    assert dispatch_calls == calls_before


def test_invalid_contract_errors_do_not_echo_private_input(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    secret = "sk-live-validation-secret-must-not-leak"
    body = {
        **api_env.seed.request_body,
        "scan_type": secret,
    }

    response = _post_scan(
        api_env,
        key="sanitized-validation",
        body=body,
    )

    _assert_safe_validation_error(
        response,
        error_type="hmair_contract_invalid",
        location=["body", "scan_type"],
        message="invalid HMAIR contract",
        marker=secret,
    )
    assert dispatch_calls == []


def test_private_header_and_query_validation_inputs_use_safe_envelopes(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    source = _post_scan(api_env, key="private-validation-source")
    source_id = source.json()["scan_id"]
    calls_before = list(dispatch_calls)
    marker = "sk-live-private-validation-marker"
    oversized_key = (marker + ("k" * 129))[:129]
    oversized_cursor = marker + ("c" * 256)
    bounded_tampered_cursor = f"v1.{marker}.tampered"

    create_response = api_env.client.post(
        "/discovery/scans",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": oversized_key,
        },
        json=api_env.seed.request_body,
    )
    rescan_response = api_env.client.post(
        f"/discovery/scans/{source_id}/rescan",
        headers={
            **api_env.seed.identities["owner"].headers,
            "Idempotency-Key": oversized_key,
        },
    )
    cursor_response = api_env.client.get(
        "/discovery/scans",
        headers=api_env.seed.identities["viewer"].headers,
        params={"cursor": oversized_cursor},
    )
    tampered_cursor_response = api_env.client.get(
        "/discovery/scans",
        headers=api_env.seed.identities["viewer"].headers,
        params={"cursor": bounded_tampered_cursor},
    )

    for response in (create_response, rescan_response):
        _assert_safe_validation_error(
            response,
            error_type="hmair_request_invalid",
            location=["header", "Idempotency-Key"],
            message="invalid HMAIR request",
            marker=marker,
        )
    _assert_safe_validation_error(
        cursor_response,
        error_type="hmair_request_invalid",
        location=["query", "cursor"],
        message="invalid HMAIR request",
        marker=marker,
    )
    _assert_safe_validation_error(
        tampered_cursor_response,
        error_type="hmair_request_invalid",
        location=["query", "cursor"],
        message="invalid HMAIR request",
        marker=marker,
    )
    assert _scan_status(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
        scan_id=source_id,
    ) == "queued"
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == 1
    assert dispatch_calls == calls_before


def test_scan_read_preserves_safe_uncertainty_without_private_internals(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    created = _post_scan(api_env, key="uncertainty-scan")
    scan_id = created.json()["scan_id"]
    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == scan_id,
            )
        )
        assert row is not None
        row.warnings_json = ["Endpoint evidence is stale."]
        row.errors_json = ["Network source unavailable."]
        row.coverage_summary_json = {
            "confidence": "medium",
            "freshness": "stale",
            "unsupported": ["intrusive_probe"],
            "unknown": ["personal_device_activity"],
        }
        db.commit()

    response = api_env.client.get(
        f"/discovery/scans/{scan_id}",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    _assert_scan_response(payload)
    assert payload["warnings"] == ["Endpoint evidence is stale."]
    assert payload["errors"] == ["Network source unavailable."]
    assert payload["coverage_summary"] == {
        "confidence": "medium",
        "freshness": "stale",
        "unsupported": ["intrusive_probe"],
        "unknown": ["personal_device_activity"],
    }


def test_scan_read_projects_adversarial_persisted_detail_safely_and_bounded(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    marker = "sk-live-scan-projection-marker"
    proprietary = "hawk-proprietary-internal-probe-plan"
    created = _post_scan(api_env, key="adversarial-projection-scan")
    scan_id = created.json()["scan_id"]
    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == scan_id,
            )
        )
        assert row is not None
        row.warnings_json = [
            "Endpoint evidence is stale.",
            "w" * 501,
            {
                "private_key": marker,
                "raw_prompt": proprietary,
            },
            [marker, proprietary],
            42,
            f"password={marker}",
            *(f"Bounded warning {index}" for index in range(70)),
        ]
        row.errors_json = [
            "Network source unavailable.",
            "e" * 501,
            [marker, {"internal_method": proprietary}],
            {"private_key": marker, "raw_error": proprietary},
            42,
            f"Bearer {marker}-token-material",
            *(f"Bounded error {index}" for index in range(70)),
        ]
        row.coverage_summary_json = {
            "confidence": "medium",
            "freshness": "stale",
            "unsupported": [
                "intrusive_probe",
                "u" * 129,
                {"private_key": marker, "method": proprietary},
                f"password={marker}",
                *(f"safe_unsupported_{index}" for index in range(70)),
            ],
            "unknown": [
                "personal_device_activity",
                "n" * 129,
                [marker, proprietary],
                f"Bearer {marker}-token-material",
                *(f"safe_unknown_{index}" for index in range(70)),
            ],
            "private_key": marker,
            "raw_payload": {
                "prompt": marker,
                "internal_method": proprietary,
            },
        }
        db.commit()

    response = api_env.client.get(
        f"/discovery/scans/{scan_id}",
        headers=api_env.seed.identities["viewer"].headers,
    )
    listed = api_env.client.get(
        "/discovery/scans",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert response.status_code == 200, response.text
    assert listed.status_code == 200, listed.text
    payload = response.json()
    listed_item = next(
        item
        for item in listed.json()["items"]
        if item["scan_id"] == scan_id
    )
    assert listed_item == payload
    _assert_scan_response(payload)
    assert marker not in response.text
    assert marker not in listed.text
    assert proprietary not in response.text
    assert proprietary not in listed.text
    assert "private_key" not in response.text
    assert "raw_payload" not in response.text
    assert "raw_prompt" not in response.text
    assert payload["warnings"][0] == "Endpoint evidence is stale."
    assert payload["warnings"].count(OMITTED_WARNING_NOTICE) == 1
    assert 1 <= len(payload["warnings"]) <= 64
    assert all(
        isinstance(item, str) and 1 <= len(item) <= 500
        for item in payload["warnings"]
    )
    assert payload["errors"][0] == "Network source unavailable."
    assert payload["errors"].count(OMITTED_ERROR_NOTICE) == 1
    assert 1 <= len(payload["errors"]) <= 64
    assert all(
        isinstance(item, str) and 1 <= len(item) <= 500
        for item in payload["errors"]
    )
    coverage = payload["coverage_summary"]
    assert set(coverage) == {
        "confidence",
        "freshness",
        "unsupported",
        "unknown",
    }
    assert coverage["confidence"] == "medium"
    assert coverage["freshness"] == "stale"
    assert coverage["unsupported"][0] == "intrusive_probe"
    assert coverage["unknown"][0] == "personal_device_activity"
    assert 1 <= len(coverage["unsupported"]) <= 64
    assert 1 <= len(coverage["unknown"]) <= 64
    assert all(
        isinstance(item, str) and 1 <= len(item) <= 128
        for key in ("unsupported", "unknown")
        for item in coverage[key]
    )

    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == scan_id,
            )
        )
        assert row is not None
        row.coverage_summary_json = {
            "confidence": "c" * 33,
            "freshness": f"password={marker}",
            "unsupported": ["intrusive_probe"],
            "unknown": ["personal_device_activity"],
        }
        db.commit()

    unsafe_scalars = api_env.client.get(
        f"/discovery/scans/{scan_id}",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert unsafe_scalars.status_code == 200, unsafe_scalars.text
    assert marker not in unsafe_scalars.text
    unsafe_coverage = unsafe_scalars.json()["coverage_summary"]
    assert isinstance(unsafe_coverage.get("confidence"), str)
    assert 1 <= len(unsafe_coverage["confidence"]) <= 32
    assert "freshness" not in unsafe_coverage
    assert unsafe_coverage["unsupported"] == ["intrusive_probe"]
    assert unsafe_coverage["unknown"] == ["personal_device_activity"]

    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryScan).where(
                DiscoveryScan.tenant_id == api_env.seed.tenant_id,
                DiscoveryScan.scan_id == scan_id,
            )
        )
        assert row is not None
        row.coverage_summary_json = {
            "confidence": {"private_key": marker},
            "freshness": 20260802,
            "unsupported": [],
            "unknown": [],
        }
        db.commit()

    non_string_scalars = api_env.client.get(
        f"/discovery/scans/{scan_id}",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert non_string_scalars.status_code == 200, non_string_scalars.text
    assert marker not in non_string_scalars.text
    non_string_coverage = non_string_scalars.json()["coverage_summary"]
    assert "confidence" not in non_string_coverage
    assert "freshness" not in non_string_coverage
    assert non_string_coverage["unsupported"] == []
    assert non_string_coverage["unknown"] == []


def test_scan_list_uses_bounded_seek_pagination_and_stable_sql_ordering(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    created_ids: set[str] = set()
    for index in range(5):
        response = _post_scan(
            api_env,
            key=f"pagination-scan-{index}",
            body={
                **api_env.seed.request_body,
                "name": f"Pagination scan {index}",
            },
        )
        assert response.status_code == 202, response.text
        created_ids.add(response.json()["scan_id"])

    ordered_ids = sorted(created_ids)
    newer_ids = set(ordered_ids[:3])
    newer_timestamp = datetime(2026, 8, 2, 14, 0, tzinfo=UTC)
    older_timestamp = datetime(2026, 8, 2, 13, 0, tzinfo=UTC)
    with api_env.session_factory() as db:
        rows = list(
            db.scalars(
                select(DiscoveryScan).where(
                    DiscoveryScan.tenant_id == api_env.seed.tenant_id
                )
            )
        )
        for row in rows:
            row.created_at = (
                newer_timestamp
                if row.scan_id in newer_ids
                else older_timestamp
            )
        db.commit()
    expected_order = [
        *sorted(newer_ids, reverse=True),
        *sorted(created_ids - newer_ids, reverse=True),
    ]

    statements: list[tuple[str, object]] = []

    def capture_sql(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        normalized = " ".join(str(statement).split()).casefold()
        if normalized.startswith("select") and "discovery_scans" in normalized:
            statements.append((normalized, _parameters))

    event.listen(api_env.engine, "before_cursor_execute", capture_sql)
    try:
        cursor: str | None = None
        listed_ids: list[str] = []
        for page_index in range(3):
            response = api_env.client.get(
                "/discovery/scans",
                headers=api_env.seed.identities["viewer"].headers,
                params={
                    "limit": 2,
                    **({"cursor": cursor} if cursor is not None else {}),
                },
            )
            assert response.status_code == 200, response.text
            payload = response.json()
            assert payload["total"] == 5
            assert payload["page"] == 1
            assert payload["page_size"] == 2
            assert 1 <= len(payload["items"]) <= 2
            for item in payload["items"]:
                _assert_scan_response(item)
            page_ids = [item["scan_id"] for item in payload["items"]]
            assert set(page_ids).isdisjoint(listed_ids)
            listed_ids.extend(page_ids)
            next_cursor = payload["next_cursor"]
            if page_index < 2:
                assert isinstance(next_cursor, str)
                assert 1 <= len(next_cursor) <= 255
                assert next_cursor not in page_ids
                assert all(scan_id not in next_cursor for scan_id in page_ids)
            else:
                assert next_cursor is None
            cursor = next_cursor
        assert set(listed_ids) == created_ids
        assert len(listed_ids) == 5
        assert listed_ids == expected_order
    finally:
        event.remove(api_env.engine, "before_cursor_execute", capture_sql)

    scan_selects = [
        (statement, parameters)
        for statement, parameters in statements
        if "select" in statement and "discovery_scans" in statement
    ]
    assert scan_selects
    ordered_scan_selects = [
        (statement, parameters)
        for statement, parameters in scan_selects
        if " order by " in statement
    ]
    assert len(ordered_scan_selects) == 3
    assert all(
        "created_at" in statement
        for statement, _ in ordered_scan_selects
    )
    assert all(
        "scan_id" in statement
        for statement, _ in ordered_scan_selects
    )
    assert all(
        " limit " in statement
        for statement, _ in ordered_scan_selects
    )
    assert all(
        re.search(
            r"order by\s+[^,]*created_at\s+desc\s*,\s*[^,]*scan_id\s+desc",
            statement,
        )
        for statement, _ in ordered_scan_selects
    )
    for _statement, parameters in ordered_scan_selects:
        values = (
            tuple(parameters.values())
            if isinstance(parameters, dict)
            else tuple(parameters)
        )
        integer_values = [
            value
            for value in values
            if type(value) is int
        ]
        assert 3 in integer_values
        assert all(value <= 3 for value in integer_values)
    for cursor_statement, _parameters in ordered_scan_selects[1:]:
        cursor_predicate = cursor_statement.split(" where ", 1)[1].split(
            " order by ", 1
        )[0]
        assert " or " in cursor_predicate
        assert " and " in cursor_predicate
        assert re.search(r"created_at\s*<", cursor_predicate)
        assert re.search(r"created_at\s*=", cursor_predicate)
        assert re.search(r"scan_id\s*<", cursor_predicate)

    unordered_row_selects = [
        statement
        for statement, _parameters in scan_selects
        if " order by " not in statement
        and "count(" not in statement
        and "count (*)" not in statement
    ]
    for statement in unordered_row_selects:
        predicate = statement.split(" where ", 1)[1]
        assert re.search(r"scan_id\s*=", predicate)


@pytest.mark.parametrize(
    "query",
    (
        "limit=0",
        "limit=201",
        f"cursor={'x' * 256}",
    ),
)
def test_scan_list_pagination_bounds_are_closed(
    api_env: ApiEnv,
    query: str,
) -> None:
    response = api_env.client.get(
        f"/discovery/scans?{query}",
        headers=api_env.seed.identities["viewer"].headers,
    )
    assert response.status_code == 422


def test_collectors_are_tenant_scoped_safe_viewer_reads(
    api_env: ApiEnv,
) -> None:
    response = api_env.client.get(
        "/discovery/collectors",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 4
    collector_ids = {item["collector_id"] for item in payload["items"]}
    assert collector_ids == {
        api_env.seed.collector_id,
        api_env.seed.mismatched_method_collector_id,
        api_env.seed.unsupported_collector_id,
        api_env.seed.cloud_collector_id,
    }
    assert api_env.seed.foreign_collector_id not in collector_ids
    for item in payload["items"]:
        assert set(item) == COLLECTOR_RESPONSE_FIELDS
        assert PRIVATE_COLLECTOR_FIELDS.isdisjoint(item)


def test_collector_health_is_tenant_scoped_and_exposes_safe_limitations(
    api_env: ApiEnv,
) -> None:
    response = api_env.client.get(
        f"/discovery/collectors/{api_env.seed.collector_id}/health",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert set(payload) == COLLECTOR_RESPONSE_FIELDS
    assert payload["collector_id"] == api_env.seed.collector_id
    assert payload["health"] == "warning"
    assert payload["supported_targets"] == ["endpoint_group"]
    assert payload["active_capabilities"] == ["metadata"]
    assert payload["limitations"] == [
        "Metadata only; unsupported sources remain unknown."
    ]
    assert payload["enabled"] is True
    assert PRIVATE_COLLECTOR_FIELDS.isdisjoint(payload)

    foreign = api_env.client.get(
        f"/discovery/collectors/{api_env.seed.foreign_collector_id}/health",
        headers=api_env.seed.identities["viewer"].headers,
    )
    missing = api_env.client.get(
        "/discovery/collectors/missing/health",
        headers=api_env.seed.identities["viewer"].headers,
    )
    assert foreign.status_code == 404
    assert missing.status_code == 404


def test_collector_reads_project_adversarial_declarations_safely_and_bounded(
    api_env: ApiEnv,
) -> None:
    marker = "sk-live-collector-projection-marker"
    proprietary = "hawk-proprietary-collector-internal-method"
    with api_env.session_factory() as db:
        row = db.scalar(
            select(DiscoveryCollector).where(
                DiscoveryCollector.tenant_id == api_env.seed.tenant_id,
                DiscoveryCollector.collector_id == api_env.seed.collector_id,
            )
        )
        assert row is not None
        row.supported_targets_json = [
            "endpoint_group",
            "t" * 65,
            {"private_target": proprietary, "api_key": marker},
            f"password={marker}",
            *("endpoint_group" for _index in range(40)),
        ]
        row.active_capabilities_json = [
            "metadata",
            "a" * 129,
            {"raw_method": proprietary, "token": marker},
            f"password={marker}",
            *("metadata" for _index in range(70)),
        ]
        row.passive_capabilities_json = [
            "inventory",
            "p" * 129,
            [proprietary, marker],
            f"Bearer {marker}-token-material",
            *("inventory" for _index in range(70)),
        ]
        row.limitations_json = [
            "Metadata only; unsupported sources remain unknown.",
            "l" * 501,
            {"private_limit": proprietary, "secret": marker},
            [marker, proprietary],
            42,
            f"password={marker}",
            *(
                "Metadata only; unsupported sources remain unknown."
                for _index in range(70)
            ),
        ]
        db.commit()

    health = api_env.client.get(
        f"/discovery/collectors/{api_env.seed.collector_id}/health",
        headers=api_env.seed.identities["viewer"].headers,
    )
    listed = api_env.client.get(
        "/discovery/collectors",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert health.status_code == 200, health.text
    assert listed.status_code == 200, listed.text
    listed_item = next(
        item
        for item in listed.json()["items"]
        if item["collector_id"] == api_env.seed.collector_id
    )
    assert listed_item == health.json()
    payload = health.json()
    assert set(payload) == COLLECTOR_RESPONSE_FIELDS
    assert marker not in health.text
    assert proprietary not in health.text
    assert "private_target" not in health.text
    assert "raw_method" not in health.text
    assert "private_limit" not in health.text
    assert payload["supported_targets"][0] == "endpoint_group"
    assert 1 <= len(payload["supported_targets"]) <= 32
    assert all(
        isinstance(item, str) and 1 <= len(item) <= 64
        for item in payload["supported_targets"]
    )
    assert payload["active_capabilities"][0] == "metadata"
    assert 1 <= len(payload["active_capabilities"]) <= 64
    assert all(
        isinstance(item, str) and 1 <= len(item) <= 128
        for item in payload["active_capabilities"]
    )
    assert payload["passive_capabilities"][0] == "inventory"
    assert 1 <= len(payload["passive_capabilities"]) <= 64
    assert all(
        isinstance(item, str) and 1 <= len(item) <= 128
        for item in payload["passive_capabilities"]
    )
    assert payload["limitations"][0] == (
        "Metadata only; unsupported sources remain unknown."
    )
    assert payload["limitations"].count(OMITTED_LIMITATION_NOTICE) == 1
    assert 1 <= len(payload["limitations"]) <= 64
    assert all(
        isinstance(item, str) and 1 <= len(item) <= 500
        for item in payload["limitations"]
    )


def test_collector_enabled_is_conservative_for_disabled_surface(
    api_env: ApiEnv,
) -> None:
    response = api_env.client.get(
        f"/discovery/collectors/{api_env.seed.cloud_collector_id}/health",
        headers=api_env.seed.identities["viewer"].headers,
    )

    assert response.status_code == 200, response.text
    assert response.json()["enabled"] is False


def test_every_hmair_endpoint_requires_authentication_when_core_is_on(
    api_env: ApiEnv,
    dispatch_calls: list[tuple[str, str]],
) -> None:
    source = _post_scan(api_env, key="authentication-source")
    scan_id = source.json()["scan_id"]
    calls_before = list(dispatch_calls)
    count_before = _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    )
    requests = (
        api_env.client.get("/discovery/scans"),
        api_env.client.get(f"/discovery/scans/{scan_id}"),
        api_env.client.post(
            "/discovery/scans",
            headers={"Idempotency-Key": "unauthenticated-create"},
            json=api_env.seed.request_body,
        ),
        api_env.client.post(f"/discovery/scans/{scan_id}/cancel"),
        api_env.client.post(
            f"/discovery/scans/{scan_id}/rescan",
            headers={"Idempotency-Key": "unauthenticated-rescan"},
        ),
        api_env.client.get("/discovery/collectors"),
        api_env.client.get(
            f"/discovery/collectors/{api_env.seed.collector_id}/health"
        ),
    )

    assert [response.status_code for response in requests] == [401] * 7
    assert _scan_status(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
        scan_id=scan_id,
    ) == "queued"
    assert _scan_count(
        api_env.session_factory,
        tenant_id=api_env.seed.tenant_id,
    ) == count_before
    assert dispatch_calls == calls_before
