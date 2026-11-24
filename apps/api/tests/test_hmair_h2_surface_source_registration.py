from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector, DiscoveryTarget
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.deep_scan_contracts import DeepScanPreflightRequest
from app.services.hmair.deep_scan_readiness_service import preflight_deep_scan
from app.services.hmair.deep_scan_source_service import (
    collect_mcp_runtime_source_observations,
)
from app.services.hmair.collector_sdk import CollectorTerminalOutcome
from app.services.hmair.surface_source_registration_service import (
    SurfaceSourceRegistrationInput,
    register_surface_source,
)


NOW = datetime(2026, 9, 4, 13, 0, tzinfo=UTC)


def _preflight(target_id: str, collector_id: str) -> DeepScanPreflightRequest:
    return DeepScanPreflightRequest.model_validate(
        {
            "target_ids": [target_id],
            "collector_ids": [collector_id],
            "required_target_ids": [target_id],
            "time_window_minutes": 30,
            "customer_authorization_reference": "change-2026-09",
            "requested_mode": "partial",
        }
    )


def _registration(
    *, source_kind: str, identifier: str
) -> SurfaceSourceRegistrationInput:
    managed_units = (
        [
            {
                "endpoint_id": "managed-browser-endpoint-1",
                "browser": "chrome",
                "browser_profile": "managed",
            }
        ]
        if source_kind == "managed_browser"
        else []
    )
    return SurfaceSourceRegistrationInput.model_validate(
        {
            "source_kind": source_kind,
            "target_identifier": identifier,
            "environment": "production",
            "expected_count": 1,
            "authority_reference": "change-2026-09",
            "baseline_expires_at": (NOW + timedelta(days=7)).isoformat(),
            "managed_browser_units": managed_units,
        }
    )


def _event(
    *, tenant_id: str, event_id: str, app_id: str, server_id: str | None = None
) -> RuntimeEvent:
    return RuntimeEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        source_surface="gateway",
        event_type="mcp_authorize",
        ai_system_id=None,
        app_id=app_id,
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
        metadata_json=({"mcp_server_id": server_id} if server_id else {}),
        created_at=NOW - timedelta(minutes=1),
    )


def test_surface_source_requires_fresh_matching_browser_or_runtime_evidence() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        EndpointDeviceIdentity.__table__,
        MonitoringSignal.__table__,
        RuntimeEvent.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    try:
        tenant = Tenant(name="Surface Registration", slug="surface-registration")
        db.add(tenant)
        db.flush()

        browser = register_surface_source(
            db,
            tenant_id=tenant.id,
            input=_registration(
                source_kind="managed_browser", identifier="acme-chrome"
            ),
            now=NOW,
        )
        runtime = register_surface_source(
            db,
            tenant_id=tenant.id,
            input=_registration(
                source_kind="mcp_environment", identifier="mcp-prod-01"
            ),
            now=NOW,
        )
        db.flush()

        assert browser.collector.health == "unknown"
        assert runtime.collector.health == "unknown"
        assert {
            item.target_type
            for item in (browser.target, runtime.target)
        } == {"browser_tenant", "mcp_environment"}

        browser_before = preflight_deep_scan(
            db,
            tenant_id=tenant.id,
            request=_preflight(browser.target.target_id, browser.collector.collector_id),
            now=NOW,
        )
        runtime_before = preflight_deep_scan(
            db,
            tenant_id=tenant.id,
            request=_preflight(runtime.target.target_id, runtime.collector.collector_id),
            now=NOW,
        )
        assert browser_before.sources[0].state == "not_connected"
        assert runtime_before.sources[0].state == "not_connected"

        db.add(
            EndpointDeviceIdentity(
                tenant_id=tenant.id,
                endpoint_id="managed-browser-endpoint-1",
                assigned_user_id="user-browser-1",
                public_key_pem="test-public-key",
                key_thumbprint="b" * 64,
                key_provider="macos_secure_enclave",
                status="active",
                scopes=["endpoint:discovery:write"],
                last_authenticated_at=NOW - timedelta(minutes=2),
            )
        )
        db.add(
            MonitoringSignal(
                tenant_id=tenant.id,
                ai_system_id=None,
                signal_type="browser.extension_health_status",
                severity="low",
                payload={
                    "healthy": True,
                    "endpoint_id": "managed-browser-endpoint-1",
                    "browser": "chrome",
                    "browser_profile": "managed",
                    "user_id": "user-browser-1",
                },
                created_at=NOW - timedelta(minutes=1),
            )
        )
        db.add(
            _event(
                tenant_id=tenant.id,
                event_id="00000000-0000-4000-8000-000000000051",
                app_id="other-mcp-environment",
                server_id="other-mcp-environment",
            )
        )
        db.flush()

        browser_after = preflight_deep_scan(
            db,
            tenant_id=tenant.id,
            request=_preflight(browser.target.target_id, browser.collector.collector_id),
            now=NOW,
        )
        runtime_other = preflight_deep_scan(
            db,
            tenant_id=tenant.id,
            request=_preflight(runtime.target.target_id, runtime.collector.collector_id),
            now=NOW,
        )
        assert browser_after.sources[0].state == "ready"
        assert runtime_other.sources[0].state == "not_connected"

        db.add(
            _event(
                tenant_id=tenant.id,
                event_id="00000000-0000-4000-8000-000000000052",
                app_id="mcp-prod-01",
                server_id="mcp-prod-01",
            )
        )
        db.flush()
        runtime_after = preflight_deep_scan(
            db,
            tenant_id=tenant.id,
            request=_preflight(runtime.target.target_id, runtime.collector.collector_id),
            now=NOW,
        )
        assert runtime_after.sources[0].state == "ready"
        assert runtime_after.sources[0].expected_count == 1
        assert runtime_after.exhaustive_claim_permitted is False
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def test_mcp_source_projects_only_events_for_its_registered_runtime() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        RuntimeEvent.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    try:
        tenant = Tenant(name="MCP Scope", slug="mcp-scope")
        db.add(tenant)
        db.flush()
        runtime = register_surface_source(
            db,
            tenant_id=tenant.id,
            input=_registration(
                source_kind="mcp_environment", identifier="mcp-prod-01"
            ),
            now=NOW,
        )
        db.add_all(
            [
                _event(
                    tenant_id=tenant.id,
                    event_id="00000000-0000-4000-8000-000000000061",
                    app_id="other-mcp-environment",
                    server_id="other-mcp-environment",
                ),
                _event(
                    tenant_id=tenant.id,
                    event_id="00000000-0000-4000-8000-000000000062",
                    app_id="mcp-prod-01",
                    server_id="mcp-prod-01",
                ),
            ]
        )
        db.flush()

        observations = collect_mcp_runtime_source_observations(
            db,
            tenant_id=tenant.id,
            scan_id="00000000-0000-4000-8000-000000000063",
            target_id=runtime.target.target_id,
            collector_id=runtime.collector.collector_id,
            window_start=NOW - timedelta(minutes=30),
            window_end=NOW,
        )

        assert [item.identifiers["mcp_server_id"] for item in observations] == [
            "mcp-prod-01"
        ]
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def test_mcp_source_rejects_a_conflicting_explicit_server_identity() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        DiscoveryCollector.__table__,
        RuntimeEvent.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    try:
        tenant = Tenant(name="MCP Identity Binding", slug="mcp-identity-binding")
        db.add(tenant)
        db.flush()
        runtime = register_surface_source(
            db,
            tenant_id=tenant.id,
            input=_registration(
                source_kind="mcp_environment", identifier="mcp-prod-01"
            ),
            now=NOW,
        )
        db.add(
            _event(
                tenant_id=tenant.id,
                event_id="00000000-0000-4000-8000-000000000064",
                app_id="mcp-prod-01",
                server_id="other-mcp-environment",
            )
        )
        db.flush()

        try:
            collect_mcp_runtime_source_observations(
                db,
                tenant_id=tenant.id,
                scan_id="00000000-0000-4000-8000-000000000065",
                target_id=runtime.target.target_id,
                collector_id=runtime.collector.collector_id,
                window_start=NOW - timedelta(minutes=30),
                window_end=NOW,
            )
        except CollectorTerminalOutcome as outcome:
            assert outcome.status.value == "empty"
        else:
            raise AssertionError("conflicting MCP server identity must not be projected")
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()
