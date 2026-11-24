from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base

try:
    from app.db.models.endpoint_metadata_inventory import (
        EndpointMetadataInventoryAssignment,
        EndpointMetadataInventoryRun,
    )
    from app.services.hmair.endpoint_metadata_inventory_service import (
        complete_endpoint_metadata_inventory_assignment,
        create_endpoint_metadata_inventory_run,
        next_endpoint_metadata_inventory_assignment,
    )
except ImportError:  # TDD: this is the expected red state before implementation.
    EndpointMetadataInventoryAssignment = None
    EndpointMetadataInventoryRun = None
    complete_endpoint_metadata_inventory_assignment = None
    create_endpoint_metadata_inventory_run = None
    next_endpoint_metadata_inventory_assignment = None


def test_inventory_service_contract_is_available() -> None:
    assert create_endpoint_metadata_inventory_run is not None
    assert next_endpoint_metadata_inventory_assignment is not None
    assert complete_endpoint_metadata_inventory_assignment is not None


@pytest.fixture()
def inventory_db() -> Session:
    assert EndpointMetadataInventoryAssignment is not None
    assert EndpointMetadataInventoryRun is not None
    engine = create_engine("sqlite+pysqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_foreign_keys(dbapi_connection: object, _record: object) -> None:
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    tables = [
        Tenant.__table__,
        User.__table__,
        UserTenantRole.__table__,
        EndpointDeviceIdentity.__table__,
        EndpointMetadataInventoryRun.__table__,
        EndpointMetadataInventoryAssignment.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)

    tenant = Tenant(name="Inventory Tenant", slug="inventory-tenant", is_active=True)
    other_tenant = Tenant(name="Other Tenant", slug="other-tenant", is_active=True)
    owner = User(
        email="inventory-owner@example.test",
        hashed_password="not-used-by-unit-tests",
        full_name="Inventory Owner",
        is_active=True,
    )
    db.add_all([tenant, other_tenant, owner])
    db.flush()
    db.add(UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"))
    db.add_all(
        [
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="mac-enrolled-1",
                public_key_pem="x" * 100,
                key_thumbprint="a" * 64,
                key_provider="macos_secure_enclave",
                status="active",
                scopes=["endpoint:policy:read", "endpoint:discovery:write"],
            ),
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="mac-no-discovery-scope",
                public_key_pem="y" * 100,
                key_thumbprint="b" * 64,
                key_provider="macos_secure_enclave",
                status="active",
                scopes=["endpoint:policy:read"],
            ),
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="windows-revoked",
                public_key_pem="z" * 100,
                key_thumbprint="c" * 64,
                key_provider="windows_tpm_cng",
                status="revoked",
                scopes=["endpoint:discovery:write"],
            ),
            EndpointDeviceIdentity(
                tenant_id=other_tenant.id,
                endpoint_id="other-tenant-device",
                public_key_pem="w" * 100,
                key_thumbprint="d" * 64,
                key_provider="windows_tpm_cng",
                status="active",
                scopes=["endpoint:discovery:write"],
            ),
        ]
    )
    db.flush()
    db.info.update(tenant_id=tenant.id, owner_id=owner.id, other_tenant_id=other_tenant.id)
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def test_creates_only_tenant_scoped_active_discovery_assignments(
    inventory_db: Session,
) -> None:
    assert create_endpoint_metadata_inventory_run is not None
    assert next_endpoint_metadata_inventory_assignment is not None
    now = datetime(2026, 9, 3, 14, 0, tzinfo=UTC)

    run = create_endpoint_metadata_inventory_run(
        inventory_db,
        tenant_id=inventory_db.info["tenant_id"],
        requested_by_user_id=inventory_db.info["owner_id"],
        request_idempotency_key="inventory-request-001",
        endpoint_ids=None,
        expires_in_minutes=30,
        now=now,
    )

    assert run.endpoint_denominator == 1
    assert run.status == "queued"
    directive = next_endpoint_metadata_inventory_assignment(
        inventory_db,
        tenant_id=inventory_db.info["tenant_id"],
        endpoint_identity_id=inventory_db.scalar(
            EndpointDeviceIdentity.__table__.select()
            .where(EndpointDeviceIdentity.endpoint_id == "mac-enrolled-1")
            .with_only_columns(EndpointDeviceIdentity.id)
        ),
        now=now,
    )
    assert directive is not None
    assert directive.mode == "metadata_only"
    assert directive.inventory_run_id == run.id
    assert (
        next_endpoint_metadata_inventory_assignment(
            inventory_db,
            tenant_id=inventory_db.info["other_tenant_id"],
            endpoint_identity_id=inventory_db.scalar(
                EndpointDeviceIdentity.__table__.select()
                .where(EndpointDeviceIdentity.endpoint_id == "other-tenant-device")
                .with_only_columns(EndpointDeviceIdentity.id)
            ),
            now=now,
        )
        is None
    )


def test_completion_is_bound_to_the_assigned_endpoint_and_updates_run(
    inventory_db: Session,
) -> None:
    assert create_endpoint_metadata_inventory_run is not None
    assert next_endpoint_metadata_inventory_assignment is not None
    assert complete_endpoint_metadata_inventory_assignment is not None
    now = datetime(2026, 9, 3, 14, 0, tzinfo=UTC)
    tenant_id = inventory_db.info["tenant_id"]
    endpoint_identity_id = inventory_db.scalar(
        EndpointDeviceIdentity.__table__.select()
        .where(EndpointDeviceIdentity.endpoint_id == "mac-enrolled-1")
        .with_only_columns(EndpointDeviceIdentity.id)
    )
    run = create_endpoint_metadata_inventory_run(
        inventory_db,
        tenant_id=tenant_id,
        requested_by_user_id=inventory_db.info["owner_id"],
        request_idempotency_key="inventory-request-002",
        endpoint_ids=None,
        expires_in_minutes=30,
        now=now,
    )
    directive = next_endpoint_metadata_inventory_assignment(
        inventory_db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoint_identity_id,
        now=now,
    )
    assert directive is not None

    completed = complete_endpoint_metadata_inventory_assignment(
        inventory_db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoint_identity_id,
        assignment_id=directive.assignment_id,
        scan_id="00000000-0000-4000-8000-000000000001",
        observations_count=2,
        now=now + timedelta(minutes=1),
    )

    assert completed.status == "complete"
    assert completed.completed_count == 1
    assert completed.endpoint_denominator == 1
    with pytest.raises(ValueError, match="not assigned"):
        complete_endpoint_metadata_inventory_assignment(
            inventory_db,
            tenant_id=tenant_id,
            endpoint_identity_id="not-the-assigned-identity",
            assignment_id=directive.assignment_id,
            scan_id="00000000-0000-4000-8000-000000000001",
            observations_count=2,
            now=now + timedelta(minutes=1),
        )
