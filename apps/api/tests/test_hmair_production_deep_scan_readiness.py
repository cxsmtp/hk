from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.deep_scan_contracts import DeepScanPreflightRequest
from app.services.hmair.deep_scan_readiness_service import preflight_deep_scan


NOW = datetime(2026, 9, 3, 14, 0, tzinfo=UTC)


def _target(*, tenant_id: str, target_id: str, baseline: dict) -> DiscoveryTarget:
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
        coverage_baseline_json=baseline,
    )


def _collector(*, tenant_id: str, collector_id: str, last_success_at: datetime) -> DiscoveryCollector:
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
        last_success_at=last_success_at,
        last_failure_at=None,
        data_residency="tenant-selected",
        control_capability="monitor_only",
        schema_version="v1",
        limitations_json=["metadata_only"],
        declaration_hash="a" * 64,
    )


@pytest.fixture()
def deep_scan_db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        EndpointDeviceIdentity.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    tenant = Tenant(name="Deep Scan Tenant", slug="deep-scan-tenant", is_active=True)
    other_tenant = Tenant(name="Other Tenant", slug="deep-scan-other", is_active=True)
    db.add_all([tenant, other_tenant])
    db.flush()
    baseline = {
        "expected_count": 1,
        "authority_kind": "mdm",
        "authority_reference": "mdm-inventory-2026-09",
        "verified_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(days=7)).isoformat(),
    }
    db.add_all(
        [
            _target(tenant_id=tenant.id, target_id="endpoint-target", baseline=baseline),
            _target(tenant_id=other_tenant.id, target_id="other-endpoint-target", baseline=baseline),
            _collector(
                tenant_id=tenant.id,
                collector_id="endpoint-collector",
                last_success_at=NOW - timedelta(minutes=2),
            ),
            _collector(
                tenant_id=other_tenant.id,
                collector_id="other-endpoint-collector",
                last_success_at=NOW - timedelta(minutes=2),
            ),
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="managed-mac-1",
                public_key_pem="x" * 100,
                key_thumbprint="b" * 64,
                key_provider="macos_secure_enclave",
                status="active",
                scopes=["endpoint:discovery:write"],
                last_authenticated_at=NOW - timedelta(minutes=1),
            ),
        ]
    )
    db.flush()
    db.info.update(tenant_id=tenant.id, other_tenant_id=other_tenant.id)
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def _request(*, target_id: str, collector_id: str) -> DeepScanPreflightRequest:
    return DeepScanPreflightRequest.model_validate(
        {
            "target_ids": [target_id],
            "collector_ids": [collector_id],
            "required_target_ids": [target_id],
            "time_window_minutes": 30,
            "customer_authorization_reference": "change-2026-09",
            "requested_mode": "full_enterprise",
        }
    )


def test_preflight_requires_current_authoritative_endpoint_baseline(
    deep_scan_db: Session,
) -> None:
    result = preflight_deep_scan(
        deep_scan_db,
        tenant_id=deep_scan_db.info["tenant_id"],
        request=_request(target_id="endpoint-target", collector_id="endpoint-collector"),
        now=NOW,
    )

    source = result.sources[0]
    assert source.state == "ready"
    assert source.observation_mode == "authoritative"
    assert source.expected_count == 1
    assert result.ready_assignment_count == 1
    # A reconciled endpoint denominator is source evidence, not proof that
    # every organization surface is connected and complete.
    assert result.exhaustive_claim_permitted is False


def test_preflight_never_promotes_missing_baseline_to_ready(deep_scan_db: Session) -> None:
    target = deep_scan_db.get(DiscoveryTarget, "endpoint-target")
    assert target is not None
    target.coverage_baseline_json = {}
    deep_scan_db.flush()

    result = preflight_deep_scan(
        deep_scan_db,
        tenant_id=deep_scan_db.info["tenant_id"],
        request=_request(target_id="endpoint-target", collector_id="endpoint-collector"),
        now=NOW,
    )

    assert result.sources[0].state == "partial"
    assert result.sources[0].observation_mode == "observed_only"
    assert result.exhaustive_claim_permitted is False


def test_endpoint_baseline_must_reconcile_the_enrolled_denominator(
    deep_scan_db: Session,
) -> None:
    target = deep_scan_db.get(DiscoveryTarget, "endpoint-target")
    assert target is not None
    target.coverage_baseline_json = {
        **target.coverage_baseline_json,
        "expected_count": 2,
    }
    deep_scan_db.flush()

    result = preflight_deep_scan(
        deep_scan_db,
        tenant_id=deep_scan_db.info["tenant_id"],
        request=_request(target_id="endpoint-target", collector_id="endpoint-collector"),
        now=NOW,
    )

    assert result.sources[0].expected_count is None
    assert result.sources[0].state == "partial"
    assert result.sources[0].limitations == ("baseline_does_not_match_enrolled_denominator",)
    assert result.exhaustive_claim_permitted is False


def test_preflight_is_tenant_scoped(deep_scan_db: Session) -> None:
    with pytest.raises(LookupError):
        preflight_deep_scan(
            deep_scan_db,
            tenant_id=deep_scan_db.info["other_tenant_id"],
            request=_request(target_id="endpoint-target", collector_id="endpoint-collector"),
            now=NOW,
        )
