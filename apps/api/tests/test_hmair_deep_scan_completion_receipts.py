from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryTarget
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.deep_scan_receipt_service import (
    verify_deep_scan_unit_completion_receipt,
)
from app.services.hmair.deep_scan_source_service import (
    collect_browser_source_batch,
    collect_mcp_runtime_source_batch,
    managed_browser_unit_binding_hash,
)


NOW = datetime(2026, 9, 9, 12, 0, tzinfo=UTC)
SIGNING_KEY_ID = "hmair-test-receipt"
SIGNING_SECRET = "hmair-deep-scan-receipt-test-secret-00000001"


def _target(
    *, tenant_id: str, target_id: str, target_type: str, identifier: str
) -> DiscoveryTarget:
    return DiscoveryTarget(
        tenant_id=tenant_id,
        target_id=target_id,
        target_type=target_type,
        identifier=identifier,
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


def _db() -> tuple[Session, str, str]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        EndpointDeviceIdentity.__table__,
        MonitoringSignal.__table__,
        RuntimeEvent.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    tenant = Tenant(name="Receipt Tenant", slug="receipt-tenant", is_active=True)
    other = Tenant(name="Receipt Other", slug="receipt-other", is_active=True)
    db.add_all([tenant, other])
    db.flush()
    db.add_all(
        [
            _target(
                tenant_id=tenant.id,
                target_id="browser-target",
                target_type="browser_tenant",
                identifier="managed-chrome",
            ),
            _target(
                tenant_id=tenant.id,
                target_id="mcp-target",
                target_type="mcp_environment",
                identifier="governed-mcp",
            ),
        ]
    )
    db.flush()
    db.info["_receipt_test_engine"] = engine
    db.info["_receipt_test_tables"] = tables
    return db, tenant.id, other.id


def _close(db: Session) -> None:
    engine = db.info["_receipt_test_engine"]
    tables = db.info["_receipt_test_tables"]
    db.close()
    Base.metadata.drop_all(engine, tables=list(reversed(tables)))
    engine.dispose()


def _receipt_settings() -> object:
    return type(
        "ReceiptSettings",
        (),
        {
            "receipt_signing_active_key_id": SIGNING_KEY_ID,
            "receipt_signing_keys_json": (
                '{"hmair-test-receipt":'
                '"hmair-deep-scan-receipt-test-secret-00000001"}'
            ),
        },
    )()


def test_browser_completion_receipts_count_unique_healthy_managed_units_only() -> None:
    db, tenant_id, other_tenant_id = _db()
    try:
        target = db.get(DiscoveryTarget, "browser-target")
        assert target is not None
        target.coverage_baseline_json = {
            "expected_count": 1,
            "managed_browser_unit_hashes": [
                managed_browser_unit_binding_hash(
                    endpoint_id="managed-mac-01",
                    browser="chrome",
                    browser_profile="managed",
                )
            ],
        }
        db.add(
            EndpointDeviceIdentity(
                tenant_id=tenant_id,
                endpoint_id="managed-mac-01",
                assigned_user_id="user-1",
                public_key_pem="test-public-key",
                key_thumbprint="a" * 64,
                key_provider="macos_secure_enclave",
                status="active",
                scopes=["endpoint:discovery:write"],
                last_authenticated_at=NOW - timedelta(minutes=4),
            )
        )
        for row_id, row_tenant, endpoint_id, observed_at in (
            ("browser-health-1", tenant_id, "managed-mac-01", NOW - timedelta(minutes=3)),
            ("browser-health-2", tenant_id, "managed-mac-01", NOW - timedelta(minutes=2)),
            ("browser-health-other", other_tenant_id, "other-mac", NOW - timedelta(minutes=1)),
        ):
            db.add(
                MonitoringSignal(
                    id=row_id,
                    tenant_id=row_tenant,
                    ai_system_id=None,
                    signal_type="browser.extension_health_status",
                    severity="low",
                    payload={
                        "healthy": True,
                        "endpoint_id": endpoint_id,
                        "browser": "chrome",
                        "browser_profile": "managed",
                        "user_id": "user-1",
                        "domain": "chatgpt.com",
                    },
                    created_at=observed_at,
                )
            )
        db.add(
            MonitoringSignal(
                id="browser-ai-1",
                tenant_id=tenant_id,
                ai_system_id=None,
                signal_type="browser.ai_domain_visit",
                severity="low",
                payload={"domain": "chatgpt.com"},
                created_at=NOW - timedelta(minutes=1),
            )
        )
        db.flush()

        batch = collect_browser_source_batch(
            db,
            tenant_id=tenant_id,
            scan_id="00000000-0000-4000-8000-000000000101",
            target_id="browser-target",
            collector_id="browser-collector",
            window_start=NOW - timedelta(minutes=30),
            window_end=NOW,
            settings_obj=_receipt_settings(),
        )

        assert len(batch.observations) == 1
        assert len(batch.completion_receipts) == 1
        receipt = batch.completion_receipts[0]
        assert receipt.target_id == "browser-target"
        assert receipt.collector_id == "browser-collector"
        assert verify_deep_scan_unit_completion_receipt(
            receipt,
            tenant_id=tenant_id,
            settings_obj=_receipt_settings(),
        )
        rendered = str(receipt.model_dump(mode="json"))
        assert "managed-mac-01" not in rendered
        assert other_tenant_id not in rendered
    finally:
        _close(db)


def test_browser_completion_receipt_rejects_unbound_client_assertion() -> None:
    db, tenant_id, _other_tenant_id = _db()
    try:
        db.add_all(
            [
                MonitoringSignal(
                    id="unbound-browser-health",
                    tenant_id=tenant_id,
                    ai_system_id=None,
                    signal_type="browser.extension_health_status",
                    severity="low",
                    payload={
                        "healthy": True,
                        "endpoint_id": "caller-asserted-endpoint",
                        "browser": "chrome",
                        "browser_profile": "managed",
                        "user_id": "user-1",
                    },
                    created_at=NOW - timedelta(minutes=2),
                ),
                MonitoringSignal(
                    id="unbound-browser-ai",
                    tenant_id=tenant_id,
                    ai_system_id=None,
                    signal_type="browser.ai_domain_visit",
                    severity="low",
                    payload={"domain": "chatgpt.com"},
                    created_at=NOW - timedelta(minutes=1),
                ),
            ]
        )
        db.flush()

        from app.services.hmair.collector_sdk import CollectorTerminalOutcome

        with pytest.raises(CollectorTerminalOutcome) as exc_info:
            collect_browser_source_batch(
                db,
                tenant_id=tenant_id,
                scan_id="00000000-0000-4000-8000-000000000103",
                target_id="browser-target",
                collector_id="browser-collector",
                window_start=NOW - timedelta(minutes=30),
                window_end=NOW,
                settings_obj=_receipt_settings(),
            )
        assert exc_info.value.status.value == "stale"
    finally:
        _close(db)


def test_mcp_completion_receipt_is_exact_target_bound_and_event_volume_safe() -> None:
    db, tenant_id, _other_tenant_id = _db()
    try:
        for index, server_id in enumerate(("governed-mcp", "governed-mcp", "other-mcp"), 1):
            db.add(
                RuntimeEvent(
                    event_id=f"00000000-0000-4000-8000-00000000011{index}",
                    tenant_id=tenant_id,
                    source_surface="gateway",
                    event_type="mcp_authorize",
                    ai_system_id=None,
                    app_id=server_id,
                    user_id=None,
                    machine_id=None,
                    browser_type=None,
                    application=None,
                    agent_id="agent-1",
                    decision="allow",
                    risk_tier=None,
                    policy_version_id=None,
                    governance_version=None,
                    severity="low",
                    confidence_tier="confirmed",
                    evidence_node_ids=[],
                    evidence_bundle_id=None,
                    correlation_id=None,
                    context_id=None,
                    chain_id=None,
                    parent_action_id=None,
                    entity_type="agent",
                    entity_id="agent-1",
                    risk_score=0.0,
                    metadata_json={"mcp_server_id": server_id},
                    created_at=NOW - timedelta(minutes=index),
                )
            )
        db.flush()

        batch = collect_mcp_runtime_source_batch(
            db,
            tenant_id=tenant_id,
            scan_id="00000000-0000-4000-8000-000000000102",
            target_id="mcp-target",
            collector_id="mcp-collector",
            window_start=NOW - timedelta(minutes=30),
            window_end=NOW,
            settings_obj=_receipt_settings(),
        )

        assert len(batch.observations) == 2
        assert len(batch.completion_receipts) == 1
        receipt = batch.completion_receipts[0]
        assert verify_deep_scan_unit_completion_receipt(
            receipt,
            tenant_id=tenant_id,
            settings_obj=_receipt_settings(),
        )
        assert (
            verify_deep_scan_unit_completion_receipt(
                receipt,
                tenant_id="different-tenant",
                settings_obj=_receipt_settings(),
            )
            is False
        )
    finally:
        _close(db)
