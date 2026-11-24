from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget
from app.db.models.monitoring import Connector, MonitoringSignal
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.deep_scan_contracts import DeepScanPreflightRequest
from app.services.hmair.deep_scan_readiness_service import preflight_deep_scan
from app.services.hmair.contracts import ObservationType
from app.services.hmair.source_connectors.contracts import (
    HMAIRNormalizedRecord,
    HMAIRSourceCapability,
    HMAIRSourceCollectionResult,
    HMAIRSourceProvider,
)
from app.services.connector_secret_service import encrypt_connector_secrets
from app.services.hmair.collector_sdk import CollectorTerminalOutcome
from app.core.config import settings

try:
    from app.services.hmair.deep_scan_source_service import (
        collect_connector_source_observations,
    )
except ImportError:  # TDD: expected before the connector bridge exists.
    collect_connector_source_observations = None


NOW = datetime(2026, 9, 3, 17, 0, tzinfo=UTC)


def _target(*, tenant_id: str) -> DiscoveryTarget:
    return DiscoveryTarget(
        tenant_id=tenant_id,
        target_id="aws-target",
        target_type="cloud_subscription",
        identifier="aws-subscription-safe-ref",
        environment="production",
        owner_hint="security",
        credentials_reference=None,
        permitted_methods_json=["collect_inventory"],
        exclusions_json=[],
        rate_limit=100,
        active_scan_allowed=True,
        sensitive_scope=False,
        coverage_baseline_json={
            "expected_count": 1,
            "authority_kind": "vendor_api",
            "authority_reference": "aws-inventory-contract-2026-09",
            "verified_at": (NOW - timedelta(minutes=5)).isoformat(),
            "expires_at": (NOW + timedelta(days=7)).isoformat(),
        },
    )


def _collector(*, tenant_id: str) -> DiscoveryCollector:
    return DiscoveryCollector(
        tenant_id=tenant_id,
        collector_id="aws-collector",
        collector_type="connector_source_bridge",
        version="1.0.0",
        supported_targets_json=["cloud_subscription"],
        active_capabilities_json=[],
        passive_capabilities_json=["metadata_only"],
        permissions_required_json=[],
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


def _request() -> DeepScanPreflightRequest:
    return DeepScanPreflightRequest.model_validate(
        {
            "target_ids": ["aws-target"],
            "collector_ids": ["aws-collector"],
            "required_target_ids": ["aws-target"],
            "time_window_minutes": 30,
            "customer_authorization_reference": "change-2026-09",
            "requested_mode": "full_enterprise",
        }
    )


def _contract(*, inventory_capable: bool) -> dict:
    return {
        "hmair_deep_scan_contract": {
            "version": "v1",
            "metadata_only": True,
            "inventory_capable": inventory_capable,
            "customer_authorization_reference": "change-2026-09",
        }
    }


def test_connected_vendor_source_requires_exact_contract_and_connector_reference() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        Connector.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    try:
        tenant = Tenant(name="Connector Source", slug="connector-source", is_active=True)
        db.add(tenant)
        db.flush()
        target = _target(tenant_id=tenant.id)
        db.add_all([target, _collector(tenant_id=tenant.id)])
        db.flush()

        missing = preflight_deep_scan(db, tenant_id=tenant.id, request=_request(), now=NOW)
        assert missing.sources[0].state == "not_connected"

        connector = Connector(
            tenant_id=tenant.id,
            name="AWS tenant inventory",
            connector_type="cloud",
            provider_key="aws",
            enabled=True,
            status="active",
            config={},
            encrypted_secrets=encrypt_connector_secrets(
                {
                    "tenant_id": "tenant-0001",
                    "client_id": "client-0001",
                    "client_secret": "customer-secret",
                }
            ),
            is_stub=False,
            last_pull_status="success",
            last_signal_count=1,
            metadata_json=_contract(inventory_capable=False),
            last_run_at=NOW - timedelta(minutes=1),
        )
        db.add(connector)
        db.flush()
        target.credentials_reference = f"connector:{connector.id}"
        db.flush()

        observed_only = preflight_deep_scan(
            db, tenant_id=tenant.id, request=_request(), now=NOW
        )
        source = observed_only.sources[0]
        assert source.state == "partial"
        assert source.observation_mode == "observed_only"
        assert observed_only.exhaustive_claim_permitted is False
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def test_connector_bridge_never_projects_secret_or_raw_payload(
    monkeypatch,
) -> None:
    assert collect_connector_source_observations is not None
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        Connector.__table__,
        MonitoringSignal.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    try:
        tenant = Tenant(name="Connector Bridge", slug="connector-bridge", is_active=True)
        db.add(tenant)
        db.flush()
        target = _target(tenant_id=tenant.id)
        connector = Connector(
            tenant_id=tenant.id,
            name="AWS tenant inventory",
            connector_type="cloud",
            provider_key="aws",
            enabled=True,
            status="active",
            config={},
            encrypted_secrets=encrypt_connector_secrets(
                {
                    "tenant_id": "tenant-0001",
                    "client_id": "client-0001",
                    "client_secret": "customer-secret",
                }
            ),
            is_stub=False,
            last_pull_status="success",
            last_signal_count=1,
            metadata_json=_contract(inventory_capable=True),
            last_run_at=NOW - timedelta(minutes=1),
        )
        db.add_all([target, connector])
        db.flush()
        target.credentials_reference = f"connector:{connector.id}"
        signal = MonitoringSignal(
            tenant_id=tenant.id,
            ai_system_id=None,
            signal_type="connector.aws.inventory",
            severity="low",
            payload={
                "resource_type": "cloud_account",
                "secret_access_key": "must never leave the source row",
                "raw_event": {"must": "never leave the source row"},
            },
            created_at=NOW - timedelta(minutes=1),
        )
        db.add(signal)
        db.flush()

        def _fake_run(_db, *, tenant_id: str, connector: Connector):
            assert tenant_id == tenant.id
            assert connector.id == connector_id
            return [signal]

        connector_id = connector.id
        monkeypatch.setattr(
            "app.services.hmair.deep_scan_source_service.run_connector_once",
            _fake_run,
        )
        observations = collect_connector_source_observations(
            db,
            tenant_id=tenant.id,
            scan_id="00000000-0000-4000-8000-000000000051",
            target_id=target.target_id,
            collector_id="aws-collector",
            connector_id=connector.id,
            window_start=NOW - timedelta(minutes=30),
            window_end=NOW,
        )

        assert observations[0].source_surface.value == "cloud"
        rendered = observations[0].model_dump(mode="json")
        assert "secret_access_key" not in rendered["normalized_signal"]
        assert "raw_event" not in rendered["normalized_signal"]
        assert "connector_id" not in rendered["identifiers"]
        assert len(rendered["identifiers"]["connector_id_hash"]) == 64
        assert rendered["identifiers"]["provider_key"] == "aws"
        assert rendered["observed_state"] == "observed"
        assert rendered["usage_summary"] == {}
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def test_typed_m365_source_never_calls_legacy_monitoring_pull(monkeypatch) -> None:
    assert collect_connector_source_observations is not None
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        Connector.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    try:
        tenant = Tenant(name="Typed M365", slug="typed-m365", is_active=True)
        db.add(tenant)
        db.flush()
        target = DiscoveryTarget(
            tenant_id=tenant.id,
            target_id="m365-target",
            target_type="saas_tenant",
            identifier="tenant-0001",
            environment="production",
            owner_hint="security",
            credentials_reference=None,
            permitted_methods_json=["collect_inventory"],
            exclusions_json=[],
            rate_limit=100,
            active_scan_allowed=True,
            sensitive_scope=False,
            coverage_baseline_json={},
        )
        connector = Connector(
            tenant_id=tenant.id,
            name="M365",
            connector_type="hmair_source",
            provider_key="hmair_microsoft365_copilot",
            auth_type="client_credentials",
            enabled=True,
            status="active",
            config={},
            encrypted_secrets=encrypt_connector_secrets(
                {
                    "tenant_id": "tenant-0001",
                    "client_id": "client-0001",
                    "client_secret": "customer-secret",
                }
            ),
            is_stub=False,
            last_pull_status="success",
            last_signal_count=1,
            metadata_json={
                "hmair_source_contract": {
                    "version": "v1",
                    "requested_capabilities": ["copilot_usage"],
                    "include_entra_account_evidence": False,
                    "source_metadata": {},
                }
            },
            last_run_at=NOW - timedelta(minutes=1),
        )
        db.add_all([target, connector])
        db.flush()
        target.credentials_reference = f"connector:{connector.id}"

        class _Collector:
            def collect(self, *_args, **_kwargs):
                return HMAIRSourceCollectionResult(
                    capability=HMAIRSourceCapability(
                        provider_key=HMAIRSourceProvider.MICROSOFT365,
                        state="partial",
                        allowed_capabilities=("copilot_usage",),
                        limitations=("source_denominator_unavailable",),
                    ),
                    records=(
                        HMAIRNormalizedRecord(
                            record_id="m365-record-1",
                            record_kind="copilot_usage",
                            observed_at=NOW,
                            candidate_asset_type="ai_application",
                            observation_type=ObservationType.WEB_AI_USAGE,
                            identifiers={"user_hash": "a" * 64},
                            metadata={"report_period_days": 7},
                        ),
                    ),
                    entra_records=(),
                )

        monkeypatch.setattr(
            "app.services.hmair.deep_scan_source_service.run_connector_once",
            lambda *_args, **_kwargs: pytest.fail("legacy monitoring pull must not run"),
        )
        monkeypatch.setattr(
            "app.services.hmair.deep_scan_source_service.source_registry.get_collector",
            lambda _provider: _Collector(),
        )
        monkeypatch.setattr(
            "app.services.hmair.deep_scan_source_service._typed_source_http",
            lambda *_args, **_kwargs: object(),
        )
        monkeypatch.setitem(settings.__dict__, "hmair_microsoft365_source", False)
        with pytest.raises(CollectorTerminalOutcome, match="provider-specific source flag"):
            collect_connector_source_observations(
                db,
                tenant_id=tenant.id,
                scan_id="00000000-0000-4000-8000-000000000052",
                target_id=target.target_id,
                collector_id="m365-collector",
                connector_id=connector.id,
                window_start=NOW - timedelta(minutes=30),
                window_end=NOW,
            )
        monkeypatch.setitem(settings.__dict__, "hmair_microsoft365_source", True)
        observations = collect_connector_source_observations(
            db,
            tenant_id=tenant.id,
            scan_id="00000000-0000-4000-8000-000000000052",
            target_id=target.target_id,
            collector_id="m365-collector",
            connector_id=connector.id,
            window_start=NOW - timedelta(minutes=30),
            window_end=NOW,
        )

        assert observations[0].raw_signal_type is ObservationType.WEB_AI_USAGE
        assert observations[0].source_surface.value == "saas"
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()
