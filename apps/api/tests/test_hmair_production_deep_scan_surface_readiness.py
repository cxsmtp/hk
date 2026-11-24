from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.deep_scan_contracts import DeepScanPreflightRequest
from app.services.hmair.deep_scan_readiness_service import preflight_deep_scan


NOW = datetime(2026, 9, 3, 16, 30, tzinfo=UTC)


def _target(
    *,
    tenant_id: str,
    target_id: str,
    target_type: str,
    baseline: dict,
    identifier: str | None = None,
) -> DiscoveryTarget:
    return DiscoveryTarget(
        tenant_id=tenant_id,
        target_id=target_id,
        target_type=target_type,
        identifier=identifier or f"{target_type}-source",
        environment="production",
        owner_hint="security",
        credentials_reference=None,
        permitted_methods_json=["collect_inventory"],
        exclusions_json=[],
        rate_limit=100,
        active_scan_allowed=True,
        sensitive_scope=False,
        coverage_baseline_json=baseline,
    )


def _collector(*, tenant_id: str, collector_id: str, target_type: str) -> DiscoveryCollector:
    return DiscoveryCollector(
        tenant_id=tenant_id,
        collector_id=collector_id,
        collector_type=f"{target_type}_bridge",
        version="1.0.0",
        supported_targets_json=[target_type],
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
            "target_ids": ["browser-target", "mcp-target"],
            "collector_ids": ["browser-collector", "mcp-collector"],
            "required_target_ids": ["browser-target", "mcp-target"],
            "time_window_minutes": 30,
            "customer_authorization_reference": "change-2026-09",
            "requested_mode": "full_enterprise",
        }
    )


def test_preflight_requires_current_direct_browser_and_routed_mcp_evidence() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        MonitoringSignal.__table__,
        RuntimeEvent.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    try:
        tenant = Tenant(name="Surface Readiness", slug="surface-readiness", is_active=True)
        db.add(tenant)
        db.flush()
        browser_baseline = {
            "expected_count": 2,
            "authority_kind": "browser_management",
            "authority_reference": "managed-browser-2026-09",
            "verified_at": (NOW - timedelta(minutes=5)).isoformat(),
            "expires_at": (NOW + timedelta(days=7)).isoformat(),
        }
        mcp_baseline = {
            "expected_count": 1,
            "authority_kind": "runtime_registry",
            "authority_reference": "gateway-runtime-2026-09",
            "verified_at": (NOW - timedelta(minutes=5)).isoformat(),
            "expires_at": (NOW + timedelta(days=7)).isoformat(),
        }
        db.add_all(
            [
                _target(
                    tenant_id=tenant.id,
                    target_id="browser-target",
                    target_type="browser_tenant",
                    baseline=browser_baseline,
                ),
                _target(
                    tenant_id=tenant.id,
                    target_id="mcp-target",
                    target_type="mcp_environment",
                    baseline=mcp_baseline,
                    identifier="proxied-server",
                ),
                _collector(
                    tenant_id=tenant.id,
                    collector_id="browser-collector",
                    target_type="browser_tenant",
                ),
                _collector(
                    tenant_id=tenant.id,
                    collector_id="mcp-collector",
                    target_type="mcp_environment",
                ),
            ]
        )
        db.flush()

        before = preflight_deep_scan(
            db, tenant_id=tenant.id, request=_request(), now=NOW
        )
        assert {row.target_id: row.state for row in before.sources} == {
            "browser-target": "not_connected",
            "mcp-target": "not_connected",
        }
        assert before.exhaustive_claim_permitted is False

        db.add(
            MonitoringSignal(
                tenant_id=tenant.id,
                ai_system_id=None,
                signal_type="browser.extension_health_status",
                severity="low",
                payload={"healthy": True, "event_type": "extension_health_status"},
                created_at=NOW - timedelta(minutes=1),
            )
        )
        db.add(
            RuntimeEvent(
                event_id="00000000-0000-4000-8000-000000000041",
                tenant_id=tenant.id,
                source_surface="gateway",
                event_type="mcp_authorize",
                ai_system_id=None,
                app_id="proxied-server",
                user_id=None,
                machine_id=None,
                browser_type=None,
                application=None,
                agent_id=None,
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
                entity_type=None,
                entity_id=None,
                risk_score=0.0,
                metadata_json={"mcp_server_id": "proxied-server"},
                created_at=NOW - timedelta(minutes=1),
            )
        )
        db.flush()

        after = preflight_deep_scan(
            db, tenant_id=tenant.id, request=_request(), now=NOW
        )
        assert {row.target_id: row.state for row in after.sources} == {
            # A generic extension heartbeat is not proof that either of the
            # two customer-authorized managed-browser units completed the
            # scan. Readiness requires an opaque unit baseline plus an active,
            # freshly authenticated endpoint identity for that unit.
            "browser-target": "not_connected",
            "mcp-target": "ready",
        }
        assert after.exhaustive_claim_permitted is False
        assert "managed_browser_identity_or_health_not_current" in next(
            row.limitations for row in after.sources if row.target_id == "browser-target"
        )
        assert next(
            row.limitations for row in after.sources if row.target_id == "mcp-target"
        ) == ()
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()
