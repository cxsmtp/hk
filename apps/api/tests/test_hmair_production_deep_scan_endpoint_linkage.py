from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.endpoint_metadata_inventory import (
    EndpointMetadataInventoryAssignment,
    EndpointMetadataInventoryRun,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.jobs import hmair_discovery_jobs as jobs
from app.services.hmair.deep_scan_contracts import (
    DeepScanCoverageBaseline,
    DeepScanObservationMode,
    DeepScanProfile,
    DeepScanReadinessState,
    DeepScanSourceReadiness,
)
from app.services.hmair.deep_scan_receipt_service import (
    issue_deep_scan_unit_completion_receipt,
)
from app.services.hmair.endpoint_metadata_inventory_service import (
    complete_endpoint_metadata_inventory_assignment,
    create_endpoint_metadata_inventory_run,
    fail_endpoint_metadata_inventory_assignment,
    get_endpoint_metadata_inventory_run,
    list_endpoint_metadata_inventory_runs,
    next_endpoint_metadata_inventory_assignment,
    reconcile_endpoint_metadata_inventory_runs,
)
from app.services.hmair.scan_service import get_scan, get_target
from app.services.hmair.scan_service import record_deep_scan_source_coverage


NOW = datetime(2026, 9, 3, 15, 0, tzinfo=UTC)


def _receipt_settings() -> object:
    return type(
        "ReceiptSettings",
        (),
        {
            "receipt_signing_active_key_id": "hmair-test-receipt",
            "receipt_signing_keys_json": (
                '{"hmair-test-receipt":'
                '"hmair-deep-scan-receipt-test-secret-00000001"}'
            ),
        },
    )()


def _profile(*, target_id: str, collector_id: str) -> DeepScanProfile:
    source = DeepScanSourceReadiness(
        target_id=target_id,
        collector_id=collector_id,
        target_type="endpoint_group",
        required=True,
        state=DeepScanReadinessState.READY,
        observation_mode=DeepScanObservationMode.AUTHORITATIVE,
        expected_count=2,
        baseline=DeepScanCoverageBaseline(
            expected_count=2,
            authority_kind="mdm",
            authority_reference="mdm-estate-2026-09",
            verified_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(days=7),
        ),
        last_success_at=NOW - timedelta(minutes=1),
    )
    return DeepScanProfile(
        version="v1",
        mode="full_enterprise",
        sources=(source,),
        customer_authorization_reference="change-2026-09",
        window_start=NOW - timedelta(minutes=30),
        window_end=NOW,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        digest="d" * 64,
    )


def _target(*, tenant_id: str, target_id: str) -> DiscoveryTarget:
    return DiscoveryTarget(
        tenant_id=tenant_id,
        target_id=target_id,
        target_type="endpoint_group",
        identifier="managed-endpoints",
        environment="production",
        owner_hint="security",
        credentials_reference="endpoint-enrollment-v1",
        permitted_methods_json=["collect_inventory"],
        exclusions_json=[],
        rate_limit=100,
        active_scan_allowed=True,
        sensitive_scope=False,
        coverage_baseline_json={
            "expected_count": 2,
            "authority_kind": "mdm",
            "authority_reference": "mdm-estate-2026-09",
            "verified_at": (NOW - timedelta(minutes=5)).isoformat(),
            "expires_at": (NOW + timedelta(days=7)).isoformat(),
        },
    )


def _collector(*, tenant_id: str, collector_id: str) -> DiscoveryCollector:
    return DiscoveryCollector(
        tenant_id=tenant_id,
        collector_id=collector_id,
        collector_type="endpoint_metadata_snapshot",
        version="1.0.0",
        supported_targets_json=["endpoint_group"],
        active_capabilities_json=[],
        passive_capabilities_json=["installed_application"],
        permissions_required_json=["endpoint:discovery:write"],
        sensitive_data_accessed_json=[],
        health="healthy",
        last_success_at=NOW - timedelta(minutes=1),
        last_failure_at=None,
        data_residency="tenant-selected",
        control_capability="monitor_only",
        schema_version="v1",
        limitations_json=["metadata_only"],
        declaration_hash="a" * 64,
    )


def _parent_scan(
    *,
    tenant_id: str,
    requested_by: str,
    target_id: str,
    collector_id: str,
) -> tuple[DiscoveryScan, DiscoveryScanAssignment]:
    profile = _profile(target_id=target_id, collector_id=collector_id)
    scan = DiscoveryScan(
        scan_id=str(uuid4()),
        tenant_id=tenant_id,
        name="Deep Scan endpoint source",
        requested_by=requested_by,
        scan_type="full_enterprise",
        scope_json={"deep_scan": profile.model_dump(mode="json")},
        safety_profile="metadata_only",
        request_idempotency_key=f"parent-{uuid4()}",
        request_digest="f" * 64,
        status="running",
        dry_run=False,
        started_at=NOW,
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
    assignment = DiscoveryScanAssignment(
        assignment_id=str(uuid4()),
        tenant_id=tenant_id,
        scan_id=scan.scan_id,
        target_id=target_id,
        collector_id=collector_id,
        status="running",
        warning=None,
        error=None,
        started_at=NOW,
        completed_at=None,
        observations_count=0,
    )
    return scan, assignment


@pytest.fixture()
def linkage_db() -> Session:
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
        EvidenceNode.__table__,
        EndpointDeviceIdentity.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        DiscoveryScan.__table__,
        DiscoveryScanTarget.__table__,
        DiscoveryScanAssignment.__table__,
        EndpointMetadataInventoryRun.__table__,
        EndpointMetadataInventoryAssignment.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    tenant = Tenant(name="Linkage Tenant", slug="linkage-tenant", is_active=True)
    other_tenant = Tenant(name="Other Linkage Tenant", slug="linkage-other", is_active=True)
    owner = User(
        email="linkage-owner@example.test",
        hashed_password="not-used-by-unit-tests",
        full_name="Linkage Owner",
        is_active=True,
    )
    db.add_all([tenant, other_tenant, owner])
    db.flush()
    db.add(UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"))
    target = _target(tenant_id=tenant.id, target_id="endpoint-target")
    other_target = _target(tenant_id=other_tenant.id, target_id="other-endpoint-target")
    collector = _collector(tenant_id=tenant.id, collector_id="endpoint-collector")
    other_collector = _collector(tenant_id=other_tenant.id, collector_id="other-endpoint-collector")
    db.add_all([target, other_target, collector, other_collector])
    db.flush()
    scan, assignment = _parent_scan(
        tenant_id=tenant.id,
        requested_by=owner.id,
        target_id=target.target_id,
        collector_id=collector.collector_id,
    )
    other_scan, other_assignment = _parent_scan(
        tenant_id=other_tenant.id,
        requested_by=None,
        target_id=other_target.target_id,
        collector_id=other_collector.collector_id,
    )
    db.add_all([scan, other_scan])
    db.flush()
    db.add_all(
        [
            DiscoveryScanTarget(
                tenant_id=tenant.id,
                scan_id=scan.scan_id,
                target_id=target.target_id,
            ),
            DiscoveryScanTarget(
                tenant_id=other_tenant.id,
                scan_id=other_scan.scan_id,
                target_id=other_target.target_id,
            ),
        ]
    )
    db.flush()
    db.add_all([assignment, other_assignment])
    db.add_all(
        [
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="managed-mac-1",
                public_key_pem="x" * 100,
                key_thumbprint="1" * 64,
                key_provider="macos_secure_enclave",
                status="active",
                scopes=["endpoint:discovery:write"],
            ),
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="managed-windows-1",
                public_key_pem="y" * 100,
                key_thumbprint="2" * 64,
                key_provider="windows_tpm_cng",
                status="active",
                scopes=["endpoint:discovery:write"],
            ),
        ]
    )
    db.flush()
    db.info.update(
        tenant_id=tenant.id,
        owner_id=owner.id,
        scan_id=scan.scan_id,
        assignment_id=assignment.assignment_id,
        other_scan_id=other_scan.scan_id,
        other_assignment_id=other_assignment.assignment_id,
    )
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def test_endpoint_inventory_can_only_link_to_a_same_tenant_deep_scan_assignment(
    linkage_db: Session,
) -> None:
    with pytest.raises(LookupError):
        create_endpoint_metadata_inventory_run(
            linkage_db,
            tenant_id=linkage_db.info["tenant_id"],
            requested_by_user_id=linkage_db.info["owner_id"],
            request_idempotency_key="deep-link-cross-tenant",
            endpoint_ids=None,
            expires_in_minutes=30,
            parent_scan_id=linkage_db.info["other_scan_id"],
            parent_assignment_id=linkage_db.info["other_assignment_id"],
            now=NOW,
        )


def test_deep_scan_worker_hands_an_endpoint_source_to_enrolled_identities(
    linkage_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = linkage_db.info["tenant_id"]
    scan = get_scan(
        linkage_db,
        tenant_id=tenant_id,
        scan_id=linkage_db.info["scan_id"],
    )
    target = get_target(
        linkage_db,
        tenant_id=tenant_id,
        target_id="endpoint-target",
    )
    assert scan is not None
    assert target is not None
    monkeypatch.setattr(
        jobs,
        "settings",
        type(
            "Settings",
            (),
            {"hmair_core": True, "hmair_active_scan": True},
        )(),
    )

    status, inventory_run_id = jobs._execute_deep_scan_source_in_execution(
        linkage_db,
        tenant_id=tenant_id,
        scan_id=scan.scan_id,
        assignment_id=linkage_db.info["assignment_id"],
        collector_id="endpoint-collector",
        target=target,
        scan=scan,
    )

    assert status is None
    assert inventory_run_id is not None
    summary = get_endpoint_metadata_inventory_run(
        linkage_db,
        tenant_id=tenant_id,
        run_id=inventory_run_id,
        now=datetime.now(UTC),
    )
    assert summary.endpoint_denominator == 2
    assert summary.status == "queued"
    parent = get_scan(linkage_db, tenant_id=tenant_id, scan_id=scan.scan_id)
    assert parent is not None
    source = parent.coverage_summary_json["deep_scan"]["sources"][0]
    assert source["state"] == "partial"
    assert source["reason"] == "endpoint_inventory_pending"


def test_endpoint_inventory_expiry_reconciles_the_parent_deep_scan(
    linkage_db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = linkage_db.info["tenant_id"]
    scan = get_scan(
        linkage_db,
        tenant_id=tenant_id,
        scan_id=linkage_db.info["scan_id"],
    )
    target = get_target(
        linkage_db,
        tenant_id=tenant_id,
        target_id="endpoint-target",
    )
    assert scan is not None
    assert target is not None
    monkeypatch.setattr(
        jobs,
        "settings",
        type(
            "Settings",
            (),
            {"hmair_core": True, "hmair_active_scan": True},
        )(),
    )
    _status, inventory_run_id = jobs._execute_deep_scan_source_in_execution(
        linkage_db,
        tenant_id=tenant_id,
        scan_id=scan.scan_id,
        assignment_id=linkage_db.info["assignment_id"],
        collector_id="endpoint-collector",
        target=target,
        scan=scan,
    )
    assert inventory_run_id is not None

    reconcile_endpoint_metadata_inventory_runs(
        linkage_db,
        tenant_id=tenant_id,
        now=datetime.now(UTC) + timedelta(hours=1),
    )

    parent = get_scan(linkage_db, tenant_id=tenant_id, scan_id=scan.scan_id)
    assert parent is not None
    assert parent.status == "partially_complete"
    source = parent.coverage_summary_json["deep_scan"]["sources"][0]
    assert source["state"] == "stale"
    assert source["reason"] == "endpoint_inventory_expired"


def test_partial_endpoint_responses_finalize_parent_as_partial_not_complete(
    linkage_db: Session,
) -> None:
    tenant_id = linkage_db.info["tenant_id"]
    run = create_endpoint_metadata_inventory_run(
        linkage_db,
        tenant_id=tenant_id,
        requested_by_user_id=linkage_db.info["owner_id"],
        request_idempotency_key="deep-link-partial",
        endpoint_ids=None,
        expires_in_minutes=30,
        parent_scan_id=linkage_db.info["scan_id"],
        parent_assignment_id=linkage_db.info["assignment_id"],
        now=NOW,
    )
    endpoints = tuple(
        linkage_db.query(EndpointDeviceIdentity)
        .filter(EndpointDeviceIdentity.tenant_id == tenant_id)
        .order_by(EndpointDeviceIdentity.endpoint_id)
        .all()
    )
    first = next_endpoint_metadata_inventory_assignment(
        linkage_db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoints[0].id,
        now=NOW,
    )
    second = next_endpoint_metadata_inventory_assignment(
        linkage_db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoints[1].id,
        now=NOW,
    )
    assert first is not None
    assert second is not None
    complete_endpoint_metadata_inventory_assignment(
        linkage_db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoints[0].id,
        assignment_id=first.assignment_id,
        scan_id="00000000-0000-4000-8000-000000000010",
        observations_count=2,
        now=NOW + timedelta(minutes=1),
    )
    completed = fail_endpoint_metadata_inventory_assignment(
        linkage_db,
        tenant_id=tenant_id,
        endpoint_identity_id=endpoints[1].id,
        assignment_id=second.assignment_id,
        code="scanner_rejected",
        now=NOW + timedelta(minutes=2),
    )

    assert completed.status == "partially_complete"
    scan = get_scan(linkage_db, tenant_id=tenant_id, scan_id=linkage_db.info["scan_id"])
    assert scan is not None
    assert scan.status == "partially_complete"
    coverage = scan.coverage_summary_json["deep_scan"]["sources"]
    assert coverage == [
        {
            "target_id": "endpoint-target",
            "collector_id": "endpoint-collector",
            "state": "partial",
            "expected_count": 2,
            "observed_count": 1,
            "evidence_fresh_at": (NOW + timedelta(minutes=2)).isoformat().replace(
                "+00:00", "Z"
            ),
            "reason": "endpoint_denominator_not_reconciled",
        }
    ]
    replayed = get_endpoint_metadata_inventory_run(
        linkage_db,
        tenant_id=tenant_id,
        run_id=run.id,
        now=NOW + timedelta(minutes=3),
    )
    assert replayed.status == "partially_complete"


def test_terminal_inventory_history_does_not_reparse_a_changed_parent_profile(
    linkage_db: Session,
) -> None:
    """Historical inventory reads remain available after contract evolution.

    Parent Deep Scan coverage is reconciled exactly once when the inventory run
    becomes terminal.  A later history read must not re-open or re-validate the
    already-finalized parent profile.
    """

    tenant_id = linkage_db.info["tenant_id"]
    run = create_endpoint_metadata_inventory_run(
        linkage_db,
        tenant_id=tenant_id,
        requested_by_user_id=linkage_db.info["owner_id"],
        request_idempotency_key="deep-link-terminal-history",
        endpoint_ids=None,
        expires_in_minutes=30,
        parent_scan_id=linkage_db.info["scan_id"],
        parent_assignment_id=linkage_db.info["assignment_id"],
        now=NOW,
    )
    endpoints = tuple(
        linkage_db.query(EndpointDeviceIdentity)
        .filter(EndpointDeviceIdentity.tenant_id == tenant_id)
        .order_by(EndpointDeviceIdentity.endpoint_id)
        .all()
    )
    for index, endpoint in enumerate(endpoints, start=1):
        directive = next_endpoint_metadata_inventory_assignment(
            linkage_db,
            tenant_id=tenant_id,
            endpoint_identity_id=endpoint.id,
            now=NOW,
        )
        assert directive is not None
        complete_endpoint_metadata_inventory_assignment(
            linkage_db,
            tenant_id=tenant_id,
            endpoint_identity_id=endpoint.id,
            assignment_id=directive.assignment_id,
            scan_id=f"00000000-0000-4000-8000-{index:012d}",
            observations_count=1,
            now=NOW + timedelta(minutes=index),
        )

    parent = get_scan(
        linkage_db,
        tenant_id=tenant_id,
        scan_id=linkage_db.info["scan_id"],
    )
    assert parent is not None
    assert parent.status in {"complete", "partially_complete"}
    parent.scope_json = {"deep_scan": {"version": "v1", "legacy": True}}
    linkage_db.flush()

    history = list_endpoint_metadata_inventory_runs(
        linkage_db,
        tenant_id=tenant_id,
        limit=20,
        now=NOW + timedelta(minutes=10),
    )

    historical_run = next(item for item in history if item.id == run.id)
    assert historical_run.status == "complete"
    assert historical_run.completed_count == 2


def test_non_authoritative_source_coverage_stays_partial(
    linkage_db: Session,
) -> None:
    tenant_id = linkage_db.info["tenant_id"]
    recorded = record_deep_scan_source_coverage(
        linkage_db,
        tenant_id=tenant_id,
        scan_id=linkage_db.info["scan_id"],
        assignment_id=linkage_db.info["assignment_id"],
        state="partial",
        observed_count=1,
        evidence_fresh_at=NOW,
        reason="source_denominator_not_reconciled",
    )

    assert recorded.coverage_summary_json == {
        "deep_scan": {
            "sources": [
                {
                    "target_id": "endpoint-target",
                    "collector_id": "endpoint-collector",
                    "state": "partial",
                    "expected_count": 2,
                    "observed_count": 1,
                    "evidence_fresh_at": NOW.isoformat().replace("+00:00", "Z"),
                    "reason": "source_denominator_not_reconciled",
                }
            ],
            "exhaustive_claim_permitted": False,
        }
    }


def test_browser_source_can_close_only_with_valid_reconciled_unit_receipt(
    linkage_db: Session,
) -> None:
    tenant_id = linkage_db.info["tenant_id"]
    target = linkage_db.query(DiscoveryTarget).filter(
        DiscoveryTarget.tenant_id == tenant_id,
        DiscoveryTarget.target_id == "endpoint-target",
    ).one()
    scan = get_scan(linkage_db, tenant_id=tenant_id, scan_id=linkage_db.info["scan_id"])
    assert scan is not None
    target.target_type = "browser_tenant"
    source = DeepScanSourceReadiness(
        target_id="endpoint-target",
        collector_id="endpoint-collector",
        target_type="browser_tenant",
        required=True,
        state=DeepScanReadinessState.READY,
        observation_mode=DeepScanObservationMode.AUTHORITATIVE,
        expected_count=1,
        baseline=DeepScanCoverageBaseline(
            expected_count=1,
            authority_kind="browser_management",
            authority_reference="managed-browser-2026-09",
            verified_at=NOW - timedelta(minutes=5),
            expires_at=NOW + timedelta(days=7),
        ),
        last_success_at=NOW - timedelta(minutes=1),
    )
    profile = DeepScanProfile(
        version="v1",
        mode="partial",
        sources=(source,),
        customer_authorization_reference="change-browser-2026-09",
        window_start=NOW - timedelta(minutes=30),
        window_end=NOW,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        digest="e" * 64,
    )
    scan.scope_json = {"deep_scan": profile.model_dump(mode="json")}
    linkage_db.flush()
    receipt = issue_deep_scan_unit_completion_receipt(
        tenant_id=tenant_id,
        scan_id=linkage_db.info["scan_id"],
        target_id="endpoint-target",
        collector_id="endpoint-collector",
        unit_id="managed-mac:chrome:managed",
        source_record_id="browser-health-record",
        observed_at=NOW - timedelta(minutes=1),
        settings_obj=_receipt_settings(),
    )

    recorded = record_deep_scan_source_coverage(
        linkage_db,
        tenant_id=tenant_id,
        scan_id=linkage_db.info["scan_id"],
        assignment_id=linkage_db.info["assignment_id"],
        state="complete",
        observed_count=1,
        evidence_fresh_at=receipt.observed_at,
        reason=None,
        completion_receipts=(receipt,),
        settings_obj=_receipt_settings(),
    )

    coverage = recorded.coverage_summary_json["deep_scan"]["sources"][0]
    assert coverage["state"] == "complete"
    assert coverage["observed_count"] == 1
    assert len(coverage["completion_receipts"]) == 1
    assert "managed-mac" not in str(coverage)
