from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.control_coverage import CoverageDimension
from app.core.security import create_access_token
from app.db.models.activity_audit import AIAction, AISession
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    ControlCoverageSnapshot,
    DeploymentSurface,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.control_coverage.deployment_family_projection import (
    SURFACE_PROJECTION_WATERMARK_KEY,
    deployment_family_surface_projection_digest,
)
from app.services.control_coverage.path_projection import (
    make_path_key,
    runtime_event_candidate,
)
from app.services.control_coverage.service import (
    VALIDATED_BYPASS_OBSERVATION_KEY,
    _snapshot_digest,
    calculate_tenant_control_coverage,
)
from app.services.findings_service import generate_unprotected_path_finding


FAMILY_ORDER = ("browser", "endpoint", "runtime", "saas_api", "unknown")
HEALTH_COUNTS = {
    "healthy": 0,
    "warning": 0,
    "degraded": 0,
    "offline": 0,
    "stale": 0,
    "unknown": 0,
}
OPERATIONAL_FIELDS = (
    "collector_version",
    "gateway_version",
    "active_policy_id",
    "active_policy_version",
    "policy_age_seconds",
    "cache_state",
    "decision_latency_ms",
    "evidence_lag_seconds",
    "event_lag_seconds",
    "export_state",
    "degraded_mode",
    "bypass_state",
    "upgrade_state",
    "fail_open_count",
    "fail_safe_count",
)


@pytest.fixture()
def operations_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'd5-operations.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    monkeypatch.setitem(
        settings.__dict__,
        "deployment_family_experience_enabled",
        True,
    )
    monkeypatch.setitem(
        settings.__dict__,
        "deployment_family_coverage_enabled",
        True,
    )

    def override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield client, factory
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _identity(factory, *, role: str = "viewer"):
    with factory() as db:
        tenant = Tenant(
            name=f"D5 {role}",
            slug=f"d5-{role}-{datetime.now(timezone.utc).timestamp()}",
            is_active=True,
        )
        user = User(
            email=f"d5-{role}-{datetime.now(timezone.utc).timestamp()}@example.com",
            hashed_password="unused",
            full_name=f"D5 {role}",
            is_active=True,
        )
        db.add_all((tenant, user))
        db.flush()
        db.add(
            UserTenantRole(
                user_id=user.id,
                tenant_id=tenant.id,
                role=role,
            )
        )
        db.commit()
        return tenant.id, {
            "Authorization": (
                "Bearer "
                + create_access_token(
                    user.id,
                    tenant_id=tenant.id,
                    role=role,
                )
            ),
            "X-Tenant-ID": tenant.id,
        }


@contextmanager
def _capture_mutations(factory):
    statements: list[str] = []
    engine = factory.kw["bind"]

    def before_cursor_execute(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ):
        normalized = " ".join(str(statement).split()).lower()
        if normalized.startswith(("insert ", "update ", "delete ")):
            statements.append(normalized)

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)


def test_deployment_route_table_is_exactly_the_eight_approved_gets() -> None:
    from app.api.routers import deployments

    routes = [
        route
        for route in deployments.router.routes
        if isinstance(route, APIRoute)
    ]
    assert {route.path for route in routes} == {
        "/deployments/overview",
        "/deployments/families",
        "/deployments/instances",
        "/deployments/instances/{id}",
        "/deployments/coverage",
        "/deployments/coverage/{family}",
        "/deployments/blind-spots",
        "/deployments/health",
    }
    assert all(route.methods == {"GET"} for route in routes)


def _action(**overrides):
    from app.services.ai_iam_service import build_ai_action_record

    values = {
        "tenant_id": "tenant-a",
        "action_id": "action-a",
        "timestamp": "2026-07-27T12:00:00+00:00",
        "source_surface": "gateway",
        "event_type": "tool_call",
        "chain_id": "chain-a",
        "metadata": {},
    }
    values.update(overrides)
    return build_ai_action_record(**values)


def test_ai_action_deployment_linkage_is_always_present_and_trusted_only() -> None:
    spoofed = _action(
        metadata={
            "deployment": {
                "verified": True,
                "deployment_instance_id": "spoofed",
                "technical_surface_type": "mcp_gateway",
                "deployment_family": "runtime",
                "collector_id": "spoofed",
                "authorization_path": "inline_pre_execution",
                "control_mode": "inline_allowed",
                "evidence_capability_at_decision_time": "complete",
            }
        }
    )
    assert spoofed["deployment"] == {
        "deployment_instance_id": None,
        "technical_surface_type": "unknown",
        "deployment_family": "unknown",
        "collector_id": None,
        "authorization_path": "unknown",
        "control_mode": "incomplete",
        "evidence_capability_at_decision_time": "unknown",
    }

    trusted = _action(
        trusted_pre_action_governance_check={
            "deployment": {
                "verified": True,
                "deployment_instance_id": "surface-a",
                "technical_surface_type": "mcp_gateway",
                "deployment_family": "runtime",
                "collector_id": "collector-a",
                "authorization_path": "inline_pre_execution",
                "control_mode": "inline_allowed",
                "evidence_capability_at_decision_time": "complete",
            }
        }
    )
    assert trusted["deployment"] == {
        "deployment_instance_id": "surface-a",
        "technical_surface_type": "mcp_gateway",
        "deployment_family": "runtime",
        "collector_id": "collector-a",
        "authorization_path": "inline_pre_execution",
        "control_mode": "inline_allowed",
        "evidence_capability_at_decision_time": "complete",
    }

    from app.core.control_engine.canonical_action import (
        adapt_existing_hawk_action,
    )

    canonical = adapt_existing_hawk_action(
        trusted,
        source_surface="gateway",
        event_type="tool_call",
    )
    assert canonical["deployment"] == trusted["deployment"]


@pytest.mark.parametrize(
    "spoofed_mode",
    ("inline_prevented", "inline_allowed"),
)
def test_ai_action_caller_metadata_cannot_claim_inline_authority(
    spoofed_mode,
) -> None:
    action = _action(
        decision="allow",
        metadata={
            "control_mode": spoofed_mode,
            "business_purpose_decision": {
                "control_mode": spoofed_mode,
            },
        },
    )
    assert action["policy"]["control_mode"] not in {
        "inline_prevented",
        "inline_allowed",
    }

    trusted = _action(
        decision="allow",
        metadata={
            "control_mode": "inline_prevented",
            "business_purpose_decision": {
                "control_mode": "inline_prevented",
            },
        },
        trusted_pre_action_governance_check={
            "control_mode": "inline_allowed",
        },
    )
    assert trusted["policy"]["control_mode"] == "inline_allowed"


@pytest.mark.parametrize(
    "hostile_confidence",
    (True, float("nan"), float("inf"), float("-inf")),
)
def test_canonical_purpose_confidence_rejects_bool_and_nonfinite(
    hostile_confidence,
) -> None:
    from app.core.control_engine.canonical_action import (
        ControlPathEvidence,
        adapt_existing_hawk_action,
    )

    action = _action(
        metadata={
            "business_purpose": {
                "purpose_confidence": hostile_confidence,
            },
        },
    )
    canonical = adapt_existing_hawk_action(
        action,
        source_surface="gateway",
        event_type="tool_call",
        path_evidence=ControlPathEvidence(telemetry_observation=True),
    )
    assert canonical["purpose"]["purpose_confidence"] == "unknown"
    json.dumps(canonical, allow_nan=False)


def test_invalid_trusted_deployment_linkage_fails_closed() -> None:
    invalid_values = (
        {
            "verified": False,
            "deployment_instance_id": "surface-a",
            "technical_surface_type": "mcp_gateway",
            "deployment_family": "runtime",
            "collector_id": "collector-a",
            "authorization_path": "inline_pre_execution",
            "control_mode": "inline_allowed",
            "evidence_capability_at_decision_time": "complete",
        },
        {
            "verified": True,
            "deployment_instance_id": "surface-a\nsecret",
            "technical_surface_type": "mcp_gateway",
            "deployment_family": "runtime",
            "collector_id": "https://secret.example/token",
            "authorization_path": "inline_pre_execution",
            "control_mode": "inline_allowed",
            "evidence_capability_at_decision_time": "complete",
        },
        {
            "verified": True,
            "deployment_instance_id": "surface-a",
            "technical_surface_type": "mcp_gateway",
            "deployment_family": "other",
            "collector_id": "collector-a",
            "authorization_path": "invented",
            "control_mode": "admin_override",
            "evidence_capability_at_decision_time": "perfect",
        },
    )
    for deployment in invalid_values:
        action = _action(
            trusted_pre_action_governance_check={
                "deployment": deployment,
            }
        )
        assert action["deployment"]["deployment_instance_id"] is None
        assert action["deployment"]["deployment_family"] == "unknown"


def test_flags_auth_and_typed_empty_operations_responses(
    operations_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)

    assert client.get("/deployments/health").status_code == 401
    assert client.get("/deployments/blind-spots").status_code == 401

    monkeypatch.setitem(
        settings.__dict__,
        "deployment_family_coverage_enabled",
        False,
    )
    blind_disabled = client.get(
        "/deployments/blind-spots",
        headers=headers,
    )
    assert blind_disabled.status_code == 404
    assert blind_disabled.json() == {"detail": "Not found"}
    assert client.get("/deployments/health", headers=headers).status_code == 200

    monkeypatch.setitem(
        settings.__dict__,
        "deployment_family_coverage_enabled",
        True,
    )
    with _capture_mutations(factory) as mutations:
        blind = client.get("/deployments/blind-spots", headers=headers)
        health = client.get("/deployments/health", headers=headers)
    assert mutations == []

    assert blind.status_code == 200, blind.text
    blind_payload = blind.json()
    assert blind_payload["tenant_id"] == tenant_id
    assert blind_payload["methodology"] == "deployment-family-coverage/1.0"
    assert blind_payload["freshness_status"] == "unknown"
    assert blind_payload["items"] == []
    assert blind_payload["total"] == 0
    assert blind_payload["page"] == 1
    assert blind_payload["page_size"] == 50
    assert blind_payload["diagnostics"] == [
        "missing_current_control_coverage_snapshot"
    ]
    assert datetime.fromisoformat(blind_payload["calculated_at"]).tzinfo

    assert health.status_code == 200, health.text
    health_payload = health.json()
    assert health_payload["tenant_id"] == tenant_id
    assert health_payload["items"] == []
    assert health_payload["total"] == 0
    assert health_payload["page"] == 1
    assert health_payload["page_size"] == 50
    assert health_payload["diagnostics"] == []
    assert datetime.fromisoformat(health_payload["generated_at"]).tzinfo
    assert [item["deployment_family"] for item in health_payload["families"]] == list(
        FAMILY_ORDER
    )
    assert all(item["count"] == 0 for item in health_payload["families"])
    assert all(
        item["health_counts"] == HEALTH_COUNTS
        for item in health_payload["families"]
    )

    monkeypatch.setitem(
        settings.__dict__,
        "deployment_family_experience_enabled",
        False,
    )
    for path in ("/deployments/blind-spots", "/deployments/health"):
        disabled = client.get(path, headers=headers)
        assert disabled.status_code == 404
        assert disabled.json() == {"detail": "Not found"}


def test_health_projects_only_allowlisted_bounded_operational_metadata(
    operations_env,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with factory() as db:
        surface = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="runtime_observation",
            source_id="gateway:mcp-a",
            name="MCP A",
            surface_type="mcp_gateway",
            deployment_mode="inline",
            deployment_family="runtime",
            hosting_mode="hybrid",
            environment="production",
            status="active",
            capability_profile={},
            capability_sources=[],
            control_capability="inline",
            evidence_capability="complete",
            containment_capability="direct",
            bypass_detection_capability="supported",
            health_status="healthy",
            health_reason="verified_heartbeat",
            first_seen_at=now,
            last_seen_at=now,
            last_heartbeat_at=now,
            last_health_check_at=now,
            policy_bundle_version="bundle-7",
            collector_version="collector-1",
            metadata_json={
                "gateway_version": "gateway-2",
                "active_policy_id": "policy-a",
                "active_policy_version": "7",
                "policy_age_seconds": 60,
                "cache_state": "warm",
                "decision_latency_ms": 12.5,
                "evidence_lag_seconds": 4,
                "event_lag_seconds": 3,
                "export_state": "ready",
                "degraded_mode": False,
                "bypass_state": "protected",
                "upgrade_state": "current",
                "fail_open_count": 0,
                "fail_safe_count": 2,
                "evidence_refs": ["evidence:health-node"],
                "secret": "never-return",
                "url": "https://secret.example/token",
                "health_reason": "caller-spoof",
            },
        )
        db.add(surface)
        db.commit()
        surface_id = surface.id

    response = client.get("/deployments/health", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"] == [
        {
            "instance_id": surface_id,
            "deployment_family": "runtime",
            "technical_surface_type": "mcp_gateway",
            "health_status": "healthy",
            "health_reason": "verified_heartbeat",
            "last_heartbeat_at": now.isoformat().replace("+00:00", "Z"),
            "last_action_at": None,
            "collector_version": "collector-1",
            "gateway_version": "gateway-2",
            "active_policy_id": "policy-a",
            "active_policy_version": "7",
            "policy_age_seconds": 60,
            "cache_state": "warm",
            "decision_latency_ms": 12.5,
            "evidence_lag_seconds": 4.0,
            "event_lag_seconds": 3.0,
            "export_state": "ready",
            "degraded_mode": False,
            "bypass_state": "protected",
            "upgrade_state": "current",
            "fail_open_count": 0,
            "fail_safe_count": 2,
            "evidence_refs": ["evidence:health-node"],
        }
    ]
    runtime = payload["families"][2]
    assert runtime == {
        "deployment_family": "runtime",
        "count": 1,
        "health_counts": {**HEALTH_COUNTS, "healthy": 1},
        "last_heartbeat_at": now.isoformat().replace("+00:00", "Z"),
        "last_action_at": None,
        "operational_field_counts": {
            field: {"known": 1, "unknown": 0}
            for field in OPERATIONAL_FIELDS
        },
    }
    rendered = response.text
    assert "never-return" not in rendered
    assert "secret.example" not in rendered
    assert "caller-spoof" not in rendered


def test_trusted_linkage_resolver_requires_exact_tenant_source_identity(
    operations_env,
) -> None:
    from app.services.deployment_family_operations_service import (
        resolve_trusted_deployment_linkage,
    )

    _client, factory = operations_env
    tenant_id, _headers = _identity(factory)
    other_tenant_id, _other_headers = _identity(factory)
    with factory() as db:
        surface = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="runtime_observation",
            source_id="mcp_gateway:mcp-a",
            name="MCP A",
            surface_type="mcp_gateway",
            deployment_mode="inline",
            deployment_family="runtime",
            hosting_mode="hybrid",
            environment="production",
            status="active",
            capability_profile={},
            capability_sources=[],
            control_capability="inline",
            evidence_capability="complete",
            containment_capability="direct",
            bypass_detection_capability="supported",
            health_status="healthy",
            health_reason="verified_heartbeat",
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            metadata_json={},
        )
        db.add(surface)
        db.commit()
        surface_id = surface.id

        exact = resolve_trusted_deployment_linkage(
            db,
            tenant_id=tenant_id,
            technical_surface_type="mcp_gateway",
            source_kind="runtime_observation",
            source_id="mcp_gateway:mcp-a",
            collector_id="runtime-event-normalizer",
            authorization_path="inline_pre_execution",
            control_mode="inline_allowed",
        )
        assert exact == {
            "verified": True,
            "deployment_instance_id": surface_id,
            "technical_surface_type": "mcp_gateway",
            "deployment_family": "runtime",
            "collector_id": "runtime-event-normalizer",
            "authorization_path": "inline_pre_execution",
            "control_mode": "inline_allowed",
            "evidence_capability_at_decision_time": "complete",
        }
        for tenant, surface_type in (
            (other_tenant_id, "mcp_gateway"),
            (tenant_id, "browser_extension"),
        ):
            unknown = resolve_trusted_deployment_linkage(
                db,
                tenant_id=tenant,
                technical_surface_type=surface_type,
                source_kind="runtime_observation",
                source_id="mcp_gateway:mcp-a",
                collector_id="runtime-event-normalizer",
                authorization_path="inline_pre_execution",
                control_mode="inline_allowed",
            )
            assert unknown["verified"] is False
            assert unknown["deployment_instance_id"] is None


def _seed_current_blind_spot(
    factory,
    *,
    tenant_id: str,
    link_evidence: bool = True,
    finding_type: str = "UNPROTECTED_MCP_ROUTE",
    target_dimension: str = "authorization",
    target_state: str = "not_covered",
    target_reason: str = "monitor_only_surface",
    surface_type: str = "mcp_gateway",
    event_type: str = "tool_call",
    source_surface: str = "mcp_gateway",
    health_status: str = "healthy",
    health_reason: str = "verified_heartbeat",
    containment_capability: str = "none",
    evidence_signal_type: str = "unprotected_path.mcp",
    evidence_payload: dict | None = None,
    event_metadata: dict | None = None,
) -> tuple[str, str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with factory() as db:
        surface = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="runtime_observation",
            source_id="mcp_gateway:mcp-a",
            name="MCP A",
            surface_type=surface_type,
            deployment_mode="monitor",
            deployment_family="runtime",
            hosting_mode="hybrid",
            environment="production",
            status="active",
            capability_profile={},
            capability_sources=[],
            control_capability="monitor_only",
            evidence_capability="complete",
            containment_capability=containment_capability,
            bypass_detection_capability="supported",
            health_status=health_status,
            health_reason=health_reason,
            first_seen_at=now - timedelta(days=1),
            last_seen_at=now,
            last_heartbeat_at=now,
            last_health_check_at=now,
            metadata_json={},
        )
        db.add(surface)
        db.flush()
        runtime = RuntimeEvent(
            event_id="event-blind-a",
            tenant_id=tenant_id,
            source_surface=source_surface,
            event_type=event_type,
            evidence_node_ids=[],
            risk_score=0.0,
            metadata_json={
                "deployment_surface_row_id": surface.id,
                "control_mode": "telemetry_only",
                **(event_metadata or {}),
            },
            created_at=now,
        )
        db.add(runtime)
        db.flush()
        candidate = runtime_event_candidate(
            runtime,
            deployment_surface=surface,
        )
        path = ControlCoveragePath(
            tenant_id=tenant_id,
            path_key=make_path_key(candidate),
            asset_ref=candidate.asset_ref,
            identity_type=candidate.identity_type,
            identity_ref=candidate.identity_ref,
            runtime_ref=candidate.runtime_ref,
            deployment_surface_id=surface.id,
            deployment_surface_ref=candidate.deployment_surface_ref,
            destination_type=candidate.destination_type,
            destination_ref=candidate.destination_ref,
            source_refs=["runtime_event:event-blind-a"],
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(path)
        db.flush()
        assertions = []
        for dimension in CoverageDimension:
            refs = ["runtime_event:event-blind-a"]
            assertion = ControlCoverageAssertion(
                tenant_id=tenant_id,
                path_id=path.id,
                dimension=dimension.value,
                state=(
                    target_state
                    if dimension.value == target_dimension
                    else "unknown"
                ),
                reason_code=(
                    target_reason
                    if dimension.value == target_dimension
                    else "insufficient_evidence"
                ),
                explanation="must-not-be-returned raw",
                methodology_version="control-coverage/1.0",
                evaluator_version="control-coverage-evaluator/1.0",
                evidence_refs=refs,
                source_watermark=hashlib.sha256(
                    json.dumps(refs, separators=(",", ":")).encode()
                ).hexdigest(),
                observed_at=now,
                evaluated_at=now,
                valid_until=now + timedelta(hours=1),
            )
            db.add(assertion)
            assertions.append(assertion)
        node = EvidenceNode(
            tenant_id=tenant_id,
            node_type="observation",
            signal_type=evidence_signal_type,
            label="verified route evidence",
            payload=evidence_payload
            or {"fact_state": "current", "route_kind": "mcp"},
            created_at=now,
        )
        db.add(node)
        db.flush()
        if link_evidence:
            for assertion in assertions:
                refs = [
                    "runtime_event:event-blind-a",
                    f"evidence:{node.id}",
                ]
                assertion.evidence_refs = refs
                assertion.source_watermark = hashlib.sha256(
                    json.dumps(refs, separators=(",", ":")).encode()
                ).hexdigest()
        finding = Finding(
            finding_id="finding-blind-a",
            tenant_id=tenant_id,
            source_surface="mcp_gateway",
            ai_tool="must-not-leak-tool",
            severity="high",
            finding_type=finding_type,
            risk_category="deployment",
            status="open",
            recommended_action="must-not-leak recommendation",
            evidence_node_ids=[node.id, node.id],
            related_event_ids=["event-blind-a", "event-blind-a"],
            dedupe_key="finding-blind-a",
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(finding)
        db.flush()
        watermarks = {
            "runtime_event": runtime.event_id,
            "ai_action": "none",
            "decision_receipt": "none",
            "execution_receipt": "none",
            "deployment_surface": surface.id,
            SURFACE_PROJECTION_WATERMARK_KEY: (
                deployment_family_surface_projection_digest(
                    paths=(path,),
                    surfaces_by_id={surface.id: surface},
                )
            ),
        }
        db.add(
            ControlCoverageSnapshot(
                tenant_id=tenant_id,
                methodology_version="control-coverage/1.0",
                window_start=now - timedelta(days=30),
                window_end=now,
                input_digest=_snapshot_digest(
                    watermarks=watermarks,
                    paths=(path,),
                    assertions=assertions,
                ),
                headline_counts={},
                headline_score=None,
                dimension_summaries={},
                input_watermarks=watermarks,
                diagnostics=[],
                freshness_status="current",
                computed_at=now,
            )
        )
        db.commit()
        authorization = next(
            row
            for row in assertions
            if row.dimension == "authorization"
        )
        return surface.id, path.id, authorization.id


def test_blind_spot_requires_current_tenant_proof_and_safe_evidence(
    operations_env,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    surface_id, path_id, assertion_id = _seed_current_blind_spot(
        factory,
        tenant_id=tenant_id,
    )
    other_tenant_id, other_headers = _identity(factory, role="viewer")

    response = client.get("/deployments/blind-spots", headers=headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["tenant_id"] == tenant_id
    assert payload["methodology"] == "deployment-family-coverage/1.0"
    assert payload["freshness_status"] == "current"
    assert payload["diagnostics"] == []
    assert payload["total"] == 1
    assert payload["items"] == [
        {
            "finding_id": "finding-blind-a",
            "finding_type": "UNPROTECTED_MCP_ROUTE",
            "observed_fact": "An MCP route was observed without verified inline authorization.",
            "observing_source": "mcp_gateway",
            "reason": "monitor_only_surface",
            "confidence": "high",
            "freshness_status": "current",
            "deployment_family": "runtime",
            "technical_surface_type": "mcp_gateway",
            "deployment_instance_id": surface_id,
            "path_id": path_id,
            "assertion_ids": [assertion_id],
            "control_mode": "telemetry_only",
            "evidence_refs": [
                payload["items"][0]["evidence_refs"][0],
                "finding:finding-blind-a",
                "runtime_event:event-blind-a",
            ],
            "recommended_deployment_action": (
                "If this route is in scope, route eligible MCP actions through "
                "a verified pre-execution authorization surface."
            ),
            "conditional": True,
        }
    ]
    assert payload["items"][0]["evidence_refs"][0].startswith("evidence:")
    rendered = response.text
    assert "must-not-leak" not in rendered
    assert "\nsecret" not in rendered

    other = client.get("/deployments/blind-spots", headers=other_headers)
    assert other.status_code == 200
    assert other.json()["tenant_id"] == other_tenant_id
    assert other.json()["items"] == []


def test_blind_spot_contract_covers_all_approved_types_with_closed_predicates() -> None:
    from app.services.deployment_family_operations_service import (
        BLIND_SPOT_RULES,
    )

    expected = {
        "UNPROTECTED_LLM_ROUTE": (
            "authorization",
            {"not_covered"},
            {"monitor_only_surface"},
            {"unprotected_path.llm"},
            True,
        ),
        "UNPROTECTED_MCP_ROUTE": (
            "authorization",
            {"not_covered"},
            {"monitor_only_surface"},
            {"unprotected_path.mcp"},
            True,
        ),
        "DEPLOYMENT_SURFACE_OFFLINE": (
            "deployment",
            {"not_covered"},
            {"surface_offline"},
            set(),
            True,
        ),
        "DEPLOYMENT_POLICY_STALE": (
            "deployment",
            set(),
            set(),
            set(),
            False,
        ),
        "DEPLOYMENT_IDENTITY_UNRESOLVED": (
            "identity",
            {"not_covered"},
            {"missing_identity_binding"},
            set(),
            True,
        ),
        "EVIDENCE_SOURCE_MISSING": (
            "evidence",
            {"not_covered"},
            {"missing_execution_proof"},
            set(),
            True,
        ),
        "UNMANAGED_AI_ACCOUNT": (
            "identity",
            {"not_covered"},
            {"missing_identity_binding"},
            set(),
            True,
        ),
        "UNKNOWN_AI_RUNTIME": (
            "runtime",
            {"not_covered", "unknown"},
            {"runtime_unmanaged", "insufficient_evidence"},
            set(),
            True,
        ),
        "UNKNOWN_MCP_SERVER": (
            "runtime",
            {"not_covered", "unknown"},
            {"runtime_unmanaged", "insufficient_evidence"},
            set(),
            True,
        ),
        "GATEWAY_BYPASS_SUSPECTED": (
            "bypass",
            {"covered", "not_covered"},
            {"bypass_observed"},
            set(),
            True,
        ),
        "DISCOVERY_COVERAGE_GAP": (
            "discovery",
            {"not_covered", "unknown"},
            {"confirmed_unmanaged_path", "insufficient_evidence"},
            set(),
            True,
        ),
        "AUTHORIZATION_COVERAGE_GAP": (
            "authorization",
            {"not_covered", "unknown"},
            {"monitor_only_surface", "insufficient_evidence"},
            set(),
            True,
        ),
        "CONTAINMENT_COVERAGE_GAP": (
            "containment",
            {"not_covered"},
            {"monitor_only_surface", "surface_offline"},
            set(),
            True,
        ),
    }
    assert set(BLIND_SPOT_RULES) == set(expected)
    for finding_type, (
        dimension,
        states,
        reasons,
        signals,
        reachable,
    ) in expected.items():
        rule = BLIND_SPOT_RULES[finding_type]
        assert rule["dimension"] == dimension
        assert set(rule["states"]) == states
        assert set(rule["reasons"]) == reasons
        assert set(rule["evidence_signal_types"]) == signals
        assert rule["reachable"] is reachable
        for key in ("observed_fact", "recommended_deployment_action"):
            text = rule[key]
            assert isinstance(text, str) and text
            assert not any(
                marker in text.lower()
                for marker in (
                    "http://",
                    "https://",
                    "secret",
                    "password",
                    "token",
                    "\n",
                    "\r",
                )
            )

    from app.api.routers.deployments import DeploymentBlindSpotItemResponse

    schema = DeploymentBlindSpotItemResponse.model_json_schema()
    assert set(schema["properties"]["finding_type"]["enum"]) == set(expected)


def _seed_materialized_bypass(
    factory,
    *,
    tenant_id: str,
    detector_operational: bool,
    finding_type: str = "GATEWAY_BYPASS_SUSPECTED",
) -> tuple[str, str]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    event_id = (
        "event-bypass-detector"
        if detector_operational
        else "event-bypass-independent"
    )
    with factory() as db:
        evidence = EvidenceNode(
            tenant_id=tenant_id,
            node_type="unprotected_path_observation",
            signal_type="unprotected_path.mcp",
            label="Observed direct MCP route outside Hawk MCP Gateway",
            payload={
                "runtime_event_id": event_id,
                "route_kind": "mcp",
                "fact_state": "current",
            },
            created_at=now,
        )
        db.add(evidence)
        db.flush()
        metadata = {
            "mcp_server_id": "mcp-a",
            "control_mode": "post_execution",
            "execution_observed": True,
            "gateway_bypass_detected": True,
            "gateway_routed": False,
            "enforcement_path": "observed_unprotected_route",
            "bypass_detection": (
                "supported" if detector_operational else "unsupported"
            ),
        }
        if detector_operational:
            metadata.update(
                {
                    VALIDATED_BYPASS_OBSERVATION_KEY: True,
                    "identity_binding_state": "authenticated_self",
                    "reason_code": "unprotected_mcp_route_observed",
                    "triggered_controls": ["SHADOW_AI_DETECTION"],
                }
            )
        else:
            metadata["bypass_observed"] = True
        runtime = RuntimeEvent(
            event_id=event_id,
            tenant_id=tenant_id,
            source_surface="gateway",
            event_type="mcp_observation",
            evidence_node_ids=[evidence.id],
            user_id="verified-user",
            risk_score=0.0,
            metadata_json=metadata,
            created_at=now,
        )
        db.add(runtime)
        db.flush()
        if finding_type == "UNPROTECTED_MCP_ROUTE":
            finding = generate_unprotected_path_finding(
                db,
                tenant_id=tenant_id,
                source_surface="gateway",
                finding_type=finding_type,
                ai_tool="mcp-tool",
                application="direct-mcp-route",
                provider=None,
                tool_name="mcp-tool",
                path_fingerprint=f"path-{event_id}",
                user_id="verified-user",
                agent_id=None,
                machine_id=None,
                policy_version_id=None,
                evidence_node_id=evidence.id,
                runtime_event_id=event_id,
                recommended_action="producer-owned recommendation",
            )
        else:
            finding = Finding(
                finding_id=f"finding-{event_id}",
                tenant_id=tenant_id,
                source_surface="gateway",
                ai_tool="mcp-tool",
                severity="high",
                finding_type=finding_type,
                risk_category="unprotected_path",
                status="open",
                recommended_action="producer-owned recommendation",
                evidence_node_ids=[evidence.id],
                related_event_ids=[event_id],
                dedupe_key=f"finding-{event_id}",
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(finding)
        result = calculate_tenant_control_coverage(
            db,
            tenant_id=tenant_id,
            now=datetime.now(timezone.utc),
            window_days=30,
        )
        bypass = next(
            assertion
            for assertion in result.assertions
            if assertion.dimension == "bypass"
        )
        finding_id = finding.finding_id
        assertion_id = bypass.id
        db.commit()
    return finding_id, assertion_id


@pytest.mark.parametrize(
    ("detector_operational", "expected_state"),
    ((True, "covered"), (False, "not_covered")),
)
def test_bypass_blind_spot_consumes_real_v1_materialized_assertion(
    operations_env,
    detector_operational,
    expected_state,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    finding_id, assertion_id = _seed_materialized_bypass(
        factory,
        tenant_id=tenant_id,
        detector_operational=detector_operational,
    )

    with factory() as db:
        assertion = db.get(ControlCoverageAssertion, assertion_id)
        assert assertion is not None
        assert assertion.state == expected_state
        assert assertion.reason_code == "bypass_observed"

    payload = client.get("/deployments/blind-spots", headers=headers).json()
    assert payload["diagnostics"] == []
    assert [(item["finding_id"], item["reason"]) for item in payload["items"]] == [
        (finding_id, "bypass_observed")
    ]


def test_real_unprotected_path_producer_vocabulary_is_consumed(
    operations_env,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    finding_id, _ = _seed_materialized_bypass(
        factory,
        tenant_id=tenant_id,
        detector_operational=True,
        finding_type="UNPROTECTED_MCP_ROUTE",
    )

    payload = client.get("/deployments/blind-spots", headers=headers).json()
    assert payload["diagnostics"] == []
    assert [
        (
            item["finding_id"],
            item["finding_type"],
            item["reason"],
        )
        for item in payload["items"]
    ] == [
        (
            finding_id,
            "UNPROTECTED_MCP_ROUTE",
            "monitor_only_surface",
        )
    ]


def test_containment_gap_exposes_only_the_assertion_that_proves_offline(
    operations_env,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    _seed_current_blind_spot(
        factory,
        tenant_id=tenant_id,
        finding_type="CONTAINMENT_COVERAGE_GAP",
        target_dimension="deployment",
        target_state="not_covered",
        target_reason="surface_offline",
        health_status="offline",
        health_reason="surface_offline",
        containment_capability="none",
    )
    with factory() as db:
        deployment_assertion = db.scalar(
            select(ControlCoverageAssertion).where(
                ControlCoverageAssertion.tenant_id == tenant_id,
                ControlCoverageAssertion.dimension == "deployment",
            )
        )
        assert deployment_assertion is not None
        deployment_assertion_id = deployment_assertion.id

    payload = client.get("/deployments/blind-spots", headers=headers).json()
    assert payload["diagnostics"] == []
    assert payload["items"] == [
        {
            **payload["items"][0],
            "finding_type": "CONTAINMENT_COVERAGE_GAP",
            "reason": "surface_offline",
            "assertion_ids": [deployment_assertion_id],
        }
    ]


@pytest.mark.parametrize(
    "proof_mutation",
    ("expired_assertion", "conflicting_evidence", "expired_evidence"),
)
def test_expired_or_conflicting_substantiation_never_emits_blind_spot(
    operations_env,
    proof_mutation,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    _seed_current_blind_spot(
        factory,
        tenant_id=tenant_id,
        finding_type="UNPROTECTED_MCP_ROUTE",
        target_dimension="authorization",
        target_state="not_covered",
        target_reason="monitor_only_surface",
        evidence_signal_type="unprotected_path.mcp",
        evidence_payload={"fact_state": "current"},
    )
    with factory() as db:
        if proof_mutation == "expired_assertion":
            assertion = db.scalar(
                select(ControlCoverageAssertion).where(
                    ControlCoverageAssertion.tenant_id == tenant_id,
                    ControlCoverageAssertion.dimension == "authorization",
                )
            )
            assertion.valid_until = datetime.now(timezone.utc) - timedelta(
                seconds=1
            )
        else:
            node = db.scalar(
                select(EvidenceNode).where(
                    EvidenceNode.tenant_id == tenant_id
                )
            )
            if proof_mutation == "conflicting_evidence":
                node.payload = {
                    **node.payload,
                    "conflicting": True,
                }
            else:
                snapshot = db.scalar(
                    select(ControlCoverageSnapshot).where(
                        ControlCoverageSnapshot.tenant_id == tenant_id
                    )
                )
                node.created_at = snapshot.window_start - timedelta(
                    seconds=1
                )
        db.commit()

    payload = client.get(
        "/deployments/blind-spots",
        headers=headers,
    ).json()
    assert payload["items"] == []
    assert all(
        item.get("confidence") != "low"
        for item in payload["items"]
    )


def test_health_and_blind_spot_processing_bounds_fail_closed_with_diagnostics(
    operations_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import deployment_family_operations_service as service

    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with factory() as db:
        for index in range(2):
            db.add(
                DeploymentSurface(
                    tenant_id=tenant_id,
                    source_kind="runtime_observation",
                    source_id=f"gateway:bound-{index}",
                    name=f"Bound {index}",
                    surface_type="mcp_gateway",
                    deployment_mode="monitor",
                    deployment_family="runtime",
                    hosting_mode="hybrid",
                    environment="production",
                    status="active",
                    capability_profile={},
                    capability_sources=[],
                    control_capability="monitor_only",
                    evidence_capability="complete",
                    containment_capability="none",
                    bypass_detection_capability="supported",
                    health_status="healthy",
                    health_reason="persisted",
                    first_seen_at=now,
                    last_seen_at=now,
                    metadata_json={},
                )
            )
        db.commit()

    _seed_current_blind_spot(
        factory,
        tenant_id=tenant_id,
        evidence_signal_type="unprotected_path.mcp",
    )
    monkeypatch.setattr(service, "MAX_HEALTH_SURFACES", 1)
    health = client.get("/deployments/health", headers=headers)
    assert health.status_code == 200
    assert health.json()["items"] == []
    assert health.json()["diagnostics"] == [
        "deployment_health_processing_limit_exceeded"
    ]

    monkeypatch.setattr(service, "MAX_BLIND_PATHS", 0)
    blind = client.get("/deployments/blind-spots", headers=headers)
    assert blind.status_code == 200
    assert blind.json()["items"] == []
    assert blind.json()["diagnostics"] == [
        "deployment_blind_spot_processing_limit_exceeded"
    ]

    assert client.get(
        "/deployments/health?page_size=201",
        headers=headers,
    ).status_code == 422


def test_health_evidence_refs_reject_secret_shaped_suffixes_and_urls(
    operations_env,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    hostile = [
        "evidence:Bearer-abcd",
        "evidence:token-value",
        "evidence:api_key-value",
        "evidence:AKIAIOSFODNN7EXAMPLE",
        "evidence:AIzaSyExampleGoogleKey",
        "evidence:https://example.test/path",
        "evidence:node?credential=value",
        "evidence:node#fragment",
    ]
    with factory() as db:
        db.add(
            DeploymentSurface(
                tenant_id=tenant_id,
                source_kind="runtime_observation",
                source_id="gateway:hostile-refs",
                name="Hostile refs",
                surface_type="mcp_gateway",
                deployment_mode="monitor",
                deployment_family="runtime",
                hosting_mode="hybrid",
                environment="production",
                status="active",
                capability_profile={},
                capability_sources=[],
                control_capability="monitor_only",
                evidence_capability="complete",
                containment_capability="none",
                bypass_detection_capability="supported",
                health_status="healthy",
                health_reason="persisted",
                first_seen_at=now,
                last_seen_at=now,
                metadata_json={
                    "evidence_refs": [
                        "evidence:verified-node",
                        *hostile,
                    ]
                },
            )
        )
        db.commit()

    payload = client.get(
        "/deployments/health",
        headers=headers,
    ).json()
    assert payload["items"][0]["evidence_refs"] == [
        "evidence:verified-node"
    ]
    rendered = json.dumps(payload).lower()
    for value in hostile:
        assert value.lower() not in rendered


def test_blind_spot_omits_closed_out_of_window_and_unbound_finding_proof(
    operations_env,
) -> None:
    client, factory = operations_env

    tenant_closed, headers_closed = _identity(factory)
    _seed_current_blind_spot(factory, tenant_id=tenant_closed)
    with factory() as db:
        finding = db.get(Finding, "finding-blind-a")
        finding.status = "closed"
        db.commit()
    assert client.get(
        "/deployments/blind-spots",
        headers=headers_closed,
    ).json()["items"] == []

    with factory() as db:
        finding = db.get(Finding, "finding-blind-a")
        finding.status = "open"
        snapshot = db.scalar(
            select(ControlCoverageSnapshot).where(
                ControlCoverageSnapshot.tenant_id == tenant_closed
            )
        )
        paths = db.scalars(
            select(ControlCoveragePath).where(
                ControlCoveragePath.tenant_id == tenant_closed
            )
        ).all()
        assertions = db.scalars(
            select(ControlCoverageAssertion).where(
                ControlCoverageAssertion.tenant_id == tenant_closed
            )
        ).all()
        for assertion in assertions:
            refs = ["runtime_event:event-blind-a"]
            assertion.evidence_refs = refs
            assertion.source_watermark = hashlib.sha256(
                json.dumps(refs, separators=(",", ":")).encode()
            ).hexdigest()
        snapshot.input_digest = _snapshot_digest(
            watermarks=snapshot.input_watermarks,
            paths=paths,
            assertions=assertions,
        )
        db.commit()
    assert client.get(
        "/deployments/blind-spots",
        headers=headers_closed,
    ).json()["items"] == []

    with factory() as db:
        finding = db.get(Finding, "finding-blind-a")
        snapshot = db.scalar(
            select(ControlCoverageSnapshot).where(
                ControlCoverageSnapshot.tenant_id == tenant_closed
            )
        )
        finding.last_seen_at = snapshot.window_start - timedelta(seconds=1)
        db.commit()
    assert client.get(
        "/deployments/blind-spots",
        headers=headers_closed,
    ).json()["items"] == []


def test_health_rejects_unbounded_or_secret_shaped_operational_metadata(
    operations_env,
) -> None:
    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with factory() as db:
        db.add(
            DeploymentSurface(
                tenant_id=tenant_id,
                source_kind="runtime_observation",
                source_id="gateway:bad-health",
                name="Bad health",
                surface_type="mcp_gateway",
                deployment_mode="inline",
                deployment_family="runtime",
                hosting_mode="hybrid",
                environment="production",
                status="active",
                capability_profile={},
                capability_sources=[],
                control_capability="inline",
                evidence_capability="complete",
                containment_capability="direct",
                bypass_detection_capability="supported",
                health_status="healthy",
                health_reason="persisted",
                first_seen_at=now,
                last_seen_at=now,
                metadata_json={
                    "gateway_version": "https://user:pass@example.test",
                    "active_policy_id": "policy secret",
                    "active_policy_version": "v1\nspoof",
                    "policy_age_seconds": 10**20,
                    "cache_state": "not warm",
                    "decision_latency_ms": float("inf"),
                    "evidence_lag_seconds": float("nan"),
                    "event_lag_seconds": -1,
                    "export_state": "ready?credential=x",
                    "degraded_mode": "false",
                    "bypass_state": "bearer-secret",
                    "upgrade_state": "current/path",
                    "fail_open_count": 1.5,
                    "fail_safe_count": 10**20,
                },
            )
        )
        db.commit()

    response = client.get("/deployments/health", headers=headers)
    assert response.status_code == 200, response.text
    item = response.json()["items"][0]
    for field in (
        "gateway_version",
        *OPERATIONAL_FIELDS,
    ):
        assert item[field] is None
    runtime = response.json()["families"][2]
    assert runtime["operational_field_counts"] == {
        field: {"known": 0, "unknown": 1}
        for field in OPERATIONAL_FIELDS
    }
    rendered = response.text.lower()
    assert "example.test" not in rendered
    assert "bearer-secret" not in rendered


def test_health_last_action_uses_only_server_verified_exact_instance_linkage(
    operations_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import deployment_family_operations_service as service

    client, factory = operations_env
    tenant_id, headers = _identity(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with factory() as db:
        surface = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="runtime_observation",
            source_id="gateway:health-action",
            name="Health action",
            surface_type="mcp_gateway",
            deployment_mode="inline",
            deployment_family="runtime",
            hosting_mode="hybrid",
            environment="production",
            status="active",
            capability_profile={},
            capability_sources=[],
            control_capability="inline",
            evidence_capability="complete",
            containment_capability="direct",
            bypass_detection_capability="supported",
            health_status="healthy",
            health_reason="persisted",
            first_seen_at=now,
            last_seen_at=now,
            metadata_json={},
        )
        db.add(surface)
        db.flush()
        session = AISession(
            session_id="d5-health-session",
            tenant_id=tenant_id,
            source_surface="gateway",
        )
        db.add(session)
        db.flush()
        deployment = {
            "deployment_instance_id": surface.id,
            "technical_surface_type": "mcp_gateway",
            "deployment_family": "runtime",
            "collector_id": "runtime-event-normalizer",
            "authorization_path": "telemetry_observation",
            "control_mode": "detected_only",
            "evidence_capability_at_decision_time": "complete",
        }
        db.add_all(
            (
                AIAction(
                    action_id="d5-health-trusted",
                    tenant_id=tenant_id,
                    session_id=session.session_id,
                    timestamp=now,
                    action_type="tool_call",
                    metadata_json={
                        "ai_action": {"deployment": deployment},
                        "deployment_linkage_verified": True,
                    },
                ),
                AIAction(
                    action_id="d5-health-spoofed",
                    tenant_id=tenant_id,
                    session_id=session.session_id,
                    timestamp=now + timedelta(minutes=1),
                    action_type="tool_call",
                    metadata_json={
                        "ai_action": {"deployment": deployment},
                        "deployment_linkage_verified": False,
                    },
                ),
            )
        )
        db.commit()

    response = client.get("/deployments/health", headers=headers)
    assert response.status_code == 200, response.text
    expected = now.isoformat().replace("+00:00", "Z")
    assert response.json()["items"][0]["last_action_at"] == expected
    assert response.json()["families"][2]["last_action_at"] == expected

    monkeypatch.setattr(service, "MAX_HEALTH_ACTIONS", 1)
    bounded = client.get("/deployments/health", headers=headers)
    assert bounded.status_code == 200
    assert bounded.json()["items"] == []
    assert bounded.json()["diagnostics"] == [
        "deployment_health_processing_limit_exceeded"
    ]


def test_runtime_writer_resolves_server_owned_immutable_deployment_linkage(
    operations_env,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services.runtime_intelligence.runtime_event_normalizer import (
        ingest_runtime_event,
    )
    from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

    _client, factory = operations_env
    tenant_id, _headers = _identity(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setitem(settings.__dict__, "runtime_intelligence_enabled", True)
    with factory() as db:
        surface = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="runtime_observation",
            source_id="gateway:mcp-a",
            name="Writer MCP",
            surface_type="mcp_gateway",
            deployment_mode="monitor",
            deployment_family="runtime",
            hosting_mode="hybrid",
            environment="production",
            status="active",
            capability_profile={},
            capability_sources=[],
            control_capability="monitor_only",
            evidence_capability="complete",
            containment_capability="none",
            bypass_detection_capability="supported",
            health_status="healthy",
            health_reason="persisted",
            first_seen_at=now,
            last_seen_at=now,
            metadata_json={},
        )
        db.add(surface)
        db.flush()
        surface_id = surface.id
        decoy = DeploymentSurface(
            tenant_id=tenant_id,
            source_kind="runtime_observation",
            source_id="browser:decoy",
            name="Caller-selected decoy",
            surface_type="browser_extension",
            deployment_mode="monitor",
            deployment_family="browser",
            hosting_mode="saas",
            environment="production",
            status="active",
            capability_profile={},
            capability_sources=[],
            control_capability="monitor_only",
            evidence_capability="partial",
            containment_capability="none",
            bypass_detection_capability="unknown",
            health_status="healthy",
            health_reason="persisted",
            first_seen_at=now,
            last_seen_at=now,
            metadata_json={},
        )
        db.add(decoy)
        db.flush()
        for index in range(64):
            db.add(
                DeploymentSurface(
                    tenant_id=tenant_id,
                    source_kind="runtime_observation",
                    source_id=f"connector:unrelated-{index}",
                    name=f"Unrelated {index}",
                    surface_type="saas_api_connector",
                    deployment_mode="monitor",
                    deployment_family="saas_api",
                    hosting_mode="saas",
                    environment="production",
                    status="active",
                    capability_profile={},
                    capability_sources=[],
                    control_capability="monitor_only",
                    evidence_capability="partial",
                    containment_capability="none",
                    bypass_detection_capability="unknown",
                    health_status="healthy",
                    health_reason="persisted",
                    first_seen_at=now,
                    last_seen_at=now,
                    metadata_json={},
                )
            )
        db.flush()
        spoof = {
            "verified": True,
            "deployment_instance_id": "spoofed",
            "technical_surface_type": "browser_extension",
            "deployment_family": "browser",
            "collector_id": "caller",
            "authorization_path": "inline_pre_execution",
            "control_mode": "inline_allowed",
            "evidence_capability_at_decision_time": "complete",
        }
        surface_selects: list[str] = []

        def capture_surface_select(
            _connection,
            _cursor,
            statement,
            _parameters,
            _context,
            _executemany,
        ) -> None:
            normalized = " ".join(str(statement).split()).lower()
            if (
                normalized.startswith("select ")
                and " from deployment_surfaces " in normalized
            ):
                surface_selects.append(normalized)

        engine = factory.kw["bind"]
        event.listen(engine, "before_cursor_execute", capture_surface_select)
        try:
            runtime = ingest_runtime_event(
                db,
                payload=RuntimeEventIngestPayload(
                    tenant_id=tenant_id,
                    source_surface="gateway",
                    event_type="tool_call",
                    correlation_id="d5-writer-linkage",
                    metadata={
                        "mcp_server_id": "mcp-a",
                        "deployment_surface_row_id": decoy.id,
                        "deployment": spoof,
                        "operational_telemetry": True,
                        "suppress_shadow_ai": True,
                        "suppress_ai_discovery": True,
                        "suppress_anomaly_detection": True,
                    },
                ),
                trusted_pre_action_governance_check={"deployment": spoof},
            )
        finally:
            event.remove(
                engine,
                "before_cursor_execute",
                capture_surface_select,
            )
        assert len(surface_selects) == 1
        assert "source_kind" in surface_selects[0]
        assert "source_id" in surface_selects[0]
        assert " limit " in surface_selects[0]
        assert runtime is not None
        expected = {
            "deployment_instance_id": surface_id,
            "technical_surface_type": "mcp_gateway",
            "deployment_family": "runtime",
            "collector_id": "runtime-event-normalizer",
            "authorization_path": "telemetry_observation",
            "control_mode": "detected_only",
            "evidence_capability_at_decision_time": "complete",
        }
        assert runtime.metadata_json["ai_action"]["deployment"] == expected
        assert runtime.metadata_json["deployment_linkage_verified"] is True
        activity = db.scalar(
            select(AIAction).where(
                AIAction.tenant_id == tenant_id,
                AIAction.runtime_event_id == runtime.event_id,
            )
        )
        assert activity is not None
        assert activity.metadata_json["ai_action"]["deployment"] == expected
        assert activity.metadata_json["deployment_linkage_verified"] is True

        surface.deployment_family = "endpoint"
        surface.evidence_capability = "partial"
        db.commit()
        db.expire_all()
        persisted_runtime = db.get(RuntimeEvent, runtime.event_id)
        persisted_activity = db.get(AIAction, activity.action_id)
        assert persisted_runtime.metadata_json["ai_action"]["deployment"] == expected
        assert persisted_activity.metadata_json["ai_action"]["deployment"] == expected


@pytest.mark.parametrize(
    ("event_type", "surface_type", "metadata"),
    (
        ("llm_intercept", "llm_gateway", {}),
        ("mcp_authorize", "mcp_gateway", {"mcp_server_id": "mcp-a"}),
    ),
)
def test_runtime_event_name_alone_cannot_prove_inline_control(
    operations_env,
    monkeypatch: pytest.MonkeyPatch,
    event_type,
    surface_type,
    metadata,
) -> None:
    from app.core.control_engine.canonical_action import ControlPathEvidence
    from app.services.runtime_intelligence.runtime_event_normalizer import (
        ingest_runtime_event,
    )
    from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

    _client, factory = operations_env
    tenant_id, _headers = _identity(factory)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    monkeypatch.setitem(settings.__dict__, "runtime_intelligence_enabled", True)
    source_id = (
        "gateway:mcp-a"
        if metadata.get("mcp_server_id")
        else "gateway:gateway"
    )
    with factory() as db:
        db.add(
            DeploymentSurface(
                tenant_id=tenant_id,
                source_kind="runtime_observation",
                source_id=source_id,
                name="Canonical gateway",
                surface_type=surface_type,
                deployment_mode="inline",
                deployment_family="runtime",
                hosting_mode="hybrid",
                environment="production",
                status="active",
                capability_profile={},
                capability_sources=[],
                control_capability="inline",
                evidence_capability="complete",
                containment_capability="direct",
                bypass_detection_capability="supported",
                health_status="healthy",
                health_reason="persisted",
                first_seen_at=now,
                last_seen_at=now,
                metadata_json={},
            )
        )
        db.flush()
        common_metadata = {
            **metadata,
            "decision": "allow",
            "operational_telemetry": True,
            "suppress_shadow_ai": True,
            "suppress_ai_discovery": True,
            "suppress_anomaly_detection": True,
        }
        spoofed = ingest_runtime_event(
            db,
            payload=RuntimeEventIngestPayload(
                tenant_id=tenant_id,
                source_surface="gateway",
                event_type=event_type,
                correlation_id=f"{event_type}-spoof",
                metadata=common_metadata,
            ),
        )
        assert spoofed is not None
        spoofed_action = spoofed.metadata_json["ai_action"]
        assert spoofed_action["deployment"]["authorization_path"] == (
            "telemetry_observation"
        )
        assert spoofed_action["policy"]["control_mode"] == "detected_only"

        trusted = ingest_runtime_event(
            db,
            payload=RuntimeEventIngestPayload(
                tenant_id=tenant_id,
                source_surface="gateway",
                event_type=event_type,
                correlation_id=f"{event_type}-trusted",
                metadata=common_metadata,
            ),
            canonical_control_path=ControlPathEvidence(
                inline_pre_execution=True,
            ),
        )
        assert trusted is not None
        trusted_action = trusted.metadata_json["ai_action"]
        assert trusted_action["deployment"]["authorization_path"] == (
            "inline_pre_execution"
        )
        assert trusted_action["policy"]["control_mode"] == "inline_allowed"


@pytest.mark.parametrize(
    "hostile_risk",
    (True, float("nan"), float("inf"), float("-inf")),
)
def test_runtime_ingest_payload_rejects_bool_and_nonfinite_risk(
    hostile_risk,
) -> None:
    from pydantic import ValidationError

    from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

    with pytest.raises(ValidationError):
        RuntimeEventIngestPayload(
            tenant_id="tenant-hostile-risk",
            source_surface="gateway",
            event_type="tool_call",
            risk_score=hostile_risk,
        )


@pytest.mark.parametrize(
    "hostile_number",
    (True, float("nan"), float("inf"), float("-inf")),
)
def test_runtime_numeric_projection_rejects_bool_and_nonfinite(
    hostile_number,
) -> None:
    from app.services.runtime_intelligence.runtime_event_normalizer import (
        _to_float,
    )

    assert _to_float(hostile_number) is None


@pytest.mark.parametrize(
    "hostile_confidence",
    (True, float("nan"), float("inf"), float("-inf"), "malformed"),
)
def test_activity_projection_rejects_hostile_sensitive_confidence(
    hostile_confidence,
) -> None:
    from app.services.runtime_intelligence.runtime_event_normalizer import (
        _activity_audit_payload_from_runtime_event,
    )

    row = RuntimeEvent(
        event_id="activity-hostile-confidence",
        tenant_id="tenant-hostile-confidence",
        source_surface="gateway",
        event_type="tool_call",
        risk_score=0.1,
        metadata_json={},
        created_at=datetime.now(timezone.utc),
    )
    payload = _activity_audit_payload_from_runtime_event(
        row=row,
        metadata={
            "sensitive_entities": ["email"],
            "sensitive_confidence": hostile_confidence,
        },
        runtime_node_id=None,
        runtime_receipt_audit_id=None,
    )
    assert payload["sensitive_detection"]["confidence_score"] == 1.0

    finite = _activity_audit_payload_from_runtime_event(
        row=row,
        metadata={
            "sensitive_entities": ["email"],
            "sensitive_confidence": 0.75,
        },
        runtime_node_id=None,
        runtime_receipt_audit_id=None,
    )
    assert finite["sensitive_detection"]["confidence_score"] == 0.75


@pytest.mark.parametrize(
    "hostile_confidence",
    (True, float("nan"), float("inf"), float("-inf"), "malformed"),
)
def test_gateway_projection_rejects_hostile_sensitive_confidence(
    monkeypatch: pytest.MonkeyPatch,
    hostile_confidence,
) -> None:
    from app.db.models.enforcement import EnforcementEvent
    from app.services.runtime_intelligence import (
        runtime_event_normalizer as normalizer,
    )

    captured = {}

    def capture_ingest(_db, *, payload, **_kwargs):
        captured["payload"] = payload
        return payload

    monkeypatch.setattr(normalizer, "ingest_runtime_event", capture_ingest)
    event_row = EnforcementEvent(
        tenant_id="tenant-gateway-confidence",
        ai_system_id="ai-system",
        actor_type="human",
        actor_id="user-a",
        request_id="request-a",
        input_prompt="redacted",
        input_context_summary="llm_intercept",
        input_attachments_meta=[],
        guardian_results=[],
        final_decision="allow",
        final_actions={
            "_trace": {
                "sensitive_confidence_score": hostile_confidence,
            },
        },
        evidence_nodes_created=[],
        controls_impacted=[],
        audit_log_id="audit-a",
    )
    normalizer.ingest_from_gateway_enforcement(None, event=event_row)
    assert (
        captured["payload"].metadata["sensitive_confidence_score"]
        is None
    )

    event_row.final_actions = {
        "_trace": {"sensitive_confidence_score": 0.75},
    }
    normalizer.ingest_from_gateway_enforcement(None, event=event_row)
    assert (
        captured["payload"].metadata["sensitive_confidence_score"]
        == 0.75
    )


@pytest.mark.parametrize(
    "hostile_risk",
    (True, float("nan"), float("inf"), float("-inf"), "malformed"),
)
def test_ai_iam_runtime_adapter_passes_raw_risk_to_schema_validation(
    monkeypatch: pytest.MonkeyPatch,
    hostile_risk,
) -> None:
    from pydantic import ValidationError

    from app.services.runtime_intelligence import (
        runtime_event_normalizer as normalizer,
    )

    captured = {}

    def capture_ingest(_db, *, payload, **_kwargs):
        captured["payload"] = payload
        return payload

    monkeypatch.setattr(normalizer, "ingest_runtime_event", capture_ingest)
    with pytest.raises(ValidationError):
        normalizer.ingest_from_ai_iam_event(
            None,
            tenant_id="tenant-ai-iam-risk",
            event_type="agent_action",
            ai_system_id=None,
            user_id="user-a",
            agent_id=None,
            severity="low",
            evidence_node_ids=[],
            correlation_id="risk-hostile",
            risk_score=hostile_risk,
        )

    normalizer.ingest_from_ai_iam_event(
        None,
        tenant_id="tenant-ai-iam-risk",
        event_type="agent_action",
        ai_system_id=None,
        user_id="user-a",
        agent_id=None,
        severity="low",
        evidence_node_ids=[],
        correlation_id="risk-finite",
        risk_score=0.75,
    )
    assert captured["payload"].risk_score == 0.75
