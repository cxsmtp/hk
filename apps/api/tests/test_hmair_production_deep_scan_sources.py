from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryTarget
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.collector_sdk import CollectorTerminalOutcome
from app.services.hmair.contracts import CollectorRunStatus

try:
    from app.services.hmair.deep_scan_source_service import (
        collect_browser_source_observations,
        collect_mcp_runtime_source_observations,
    )
except ImportError:  # TDD: expected before the bridge is implemented.
    collect_browser_source_observations = None
    collect_mcp_runtime_source_observations = None


NOW = datetime(2026, 9, 3, 16, 0, tzinfo=UTC)


def _target(
    *, tenant_id: str, target_id: str, target_type: str, identifier: str | None = None
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
        coverage_baseline_json={},
    )


@pytest.fixture()
def source_db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    tables = [
        Tenant.__table__,
        DiscoveryTarget.__table__,
        MonitoringSignal.__table__,
        RuntimeEvent.__table__,
    ]
    Base.metadata.create_all(engine, tables=tables)
    db = Session(engine)
    tenant = Tenant(name="Source Bridge Tenant", slug="source-bridge", is_active=True)
    other_tenant = Tenant(name="Source Bridge Other", slug="source-bridge-other", is_active=True)
    db.add_all([tenant, other_tenant])
    db.flush()
    db.add_all(
        [
            _target(
                tenant_id=tenant.id,
                target_id="browser-target",
                target_type="browser_tenant",
            ),
            _target(
                tenant_id=tenant.id,
                target_id="mcp-target",
                target_type="mcp_environment",
                identifier="proxied-server",
            ),
        ]
    )
    db.add(
        MonitoringSignal(
            tenant_id=tenant.id,
            ai_system_id=None,
            signal_type="browser.ai_domain_visit",
            severity="low",
            payload={
                "event_type": "prompt_submitted",
                "domain": "approved-ai.example",
                "application": "Approved AI",
                "extension_version": "1.2.3",
                "raw_prompt": "must never leave the source row",
                "url": "https://approved-ai.example/private/path",
                "cookies": "must never leave the source row",
            },
            created_at=NOW - timedelta(minutes=1),
        )
    )
    db.add_all(
        [
            RuntimeEvent(
                event_id="00000000-0000-4000-8000-000000000021",
                tenant_id=tenant.id,
                source_surface="gateway",
                event_type="mcp_authorize",
                ai_system_id=None,
                app_id="proxied-server",
                user_id=None,
                machine_id=None,
                browser_type=None,
                application=None,
                agent_id="agent-safe-1",
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
                entity_id="agent-safe-1",
                risk_score=0.0,
                metadata_json={
                    "mcp_server_id": "proxied-server",
                    "tool_fingerprint": "a" * 64,
                    "tool_arguments": {"secret": "must never leave source"},
                    "tool_result": "must never leave source",
                },
                created_at=NOW - timedelta(minutes=2),
            ),
            RuntimeEvent(
                event_id="00000000-0000-4000-8000-000000000022",
                tenant_id=tenant.id,
                source_surface="mcp",
                event_type="mcp_tool_call",
                ai_system_id=None,
                app_id="configured-but-unproxied",
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
                confidence_tier="unknown",
                evidence_node_ids=[],
                evidence_bundle_id=None,
                correlation_id=None,
                context_id=None,
                chain_id=None,
                parent_action_id=None,
                entity_type=None,
                entity_id=None,
                risk_score=0.0,
                metadata_json={"mcp_server_id": "configured-but-unproxied"},
                created_at=NOW - timedelta(minutes=2),
            ),
        ]
    )
    db.flush()
    db.info["tenant_id"] = tenant.id
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(engine, tables=list(reversed(tables)))
        engine.dispose()


def test_browser_bridge_maps_only_safe_existing_telemetry(source_db: Session) -> None:
    assert collect_browser_source_observations is not None
    observations = collect_browser_source_observations(
        source_db,
        tenant_id=source_db.info["tenant_id"],
        scan_id="00000000-0000-4000-8000-000000000031",
        target_id="browser-target",
        collector_id="browser-collector",
        window_start=NOW - timedelta(minutes=30),
        window_end=NOW,
    )

    assert observations[0].source_surface.value == "browser"
    rendered = observations[0].model_dump(mode="json")
    assert "raw_prompt" not in rendered["normalized_signal"]
    assert "url" not in rendered["normalized_signal"]
    assert "cookies" not in rendered["normalized_signal"]
    assert rendered["identifiers"]["ai_domain"] == "approved-ai.example"


def test_mcp_bridge_excludes_unproxied_configuration(source_db: Session) -> None:
    assert collect_mcp_runtime_source_observations is not None
    observations = collect_mcp_runtime_source_observations(
        source_db,
        tenant_id=source_db.info["tenant_id"],
        scan_id="00000000-0000-4000-8000-000000000032",
        target_id="mcp-target",
        collector_id="mcp-collector",
        window_start=NOW - timedelta(minutes=30),
        window_end=NOW,
    )

    assert [item.identifiers["mcp_server_id"] for item in observations] == [
        "proxied-server"
    ]
    rendered = observations[0].model_dump(mode="json")
    assert "tool_arguments" not in rendered["normalized_signal"]
    assert "tool_result" not in rendered["normalized_signal"]


def test_bridge_returns_expected_empty_not_false_absence(source_db: Session) -> None:
    assert collect_browser_source_observations is not None
    with pytest.raises(CollectorTerminalOutcome) as raised:
        collect_browser_source_observations(
            source_db,
            tenant_id=source_db.info["tenant_id"],
            scan_id="00000000-0000-4000-8000-000000000033",
            target_id="browser-target",
            collector_id="browser-collector",
            window_start=NOW + timedelta(minutes=1),
            window_end=NOW + timedelta(minutes=30),
        )
    assert raised.value.status is CollectorRunStatus.EMPTY
