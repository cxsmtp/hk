from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routers.discovery_assets import (
    get_asset_detail,
    get_asset_evidence,
    get_asset_history,
)
from app.api.routers.discovery_ecosystems import list_unknown_ai
from app.db.models import *  # noqa: F401,F403
from app.db.models.ai_asset import DiscoveryEvidenceClaim
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.control_coverage.discovery_coverage import (
    calculate_discovery_coverage,
)
from app.services.hmair.attribution_service import link_identity
from app.services.hmair.capability_inference_service import infer_capability
from app.services.hmair.collectors.browser import BrowserPathCollector
from app.services.hmair.collectors.endpoint import EndpointPathCollector
from app.services.hmair.collectors.llm_gateway import LLMGatewayPathCollector
from app.services.hmair.collectors.mcp_gateway import MCPGatewayPathCollector
from app.services.hmair.collectors.path_native import (
    PathNativeCollector,
    PathNativeSignal,
)
from app.services.hmair.contracts import (
    AIAssetCreate,
    EvidenceClaimCreate,
    ResolutionActor,
    ResolutionRequest,
    ResolutionSignal,
)
from app.services.hmair.discovery_context_service import get_discovery_context
from app.services.hmair.discovery_finding_service import upsert_discovery_finding
from app.services.hmair.evidence_claim_service import persist_evidence_claim
from app.services.hmair.evidence_fusion_service import fuse_observations
from app.services.hmair.hypothesis_service import create_hypothesis
from app.services.hmair.observation_service import ingest_observation
from app.services.hmair.reachability_service import assert_reachability
from app.services.hmair.resolution_service import resolve_observations
from app.services.hmair.usage_service import persist_usage_fact


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "hmair"
COLLECTORS: dict[str, type[PathNativeCollector]] = {
    "endpoint": EndpointPathCollector,
    "browser": BrowserPathCollector,
    "mcp": MCPGatewayPathCollector,
    "llm_gateway": LLMGatewayPathCollector,
}
NOW = datetime(2026, 9, 11, 8, 0, tzinfo=timezone.utc)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


def _observations(name: str):
    fixture = _fixture(name)
    observations = []
    collector_types: dict[str, type[PathNativeCollector]] = {}
    for item in fixture["signals"]:
        surface = item["surface"]
        collector_type = COLLECTORS[surface]
        signal = PathNativeSignal.model_validate(item["signal"])
        collector = collector_type(signals=(signal,))
        observation = collector.emit_observations()[0]
        observations.append(observation)
        collector_types[observation.collector_id] = collector_type
    return fixture, tuple(observations), collector_types


def _seed_scope(
    db: Session,
    *,
    fixture: dict[str, object],
    observations: tuple[object, ...],
    collector_types: dict[str, type[PathNativeCollector]],
) -> str:
    tenant_id = str(fixture["tenant_id"])
    scan_id = str(fixture["scan_id"])
    db.add(Tenant(id=tenant_id, name="H2 fixture tenant", slug=f"h2-{scan_id[-8:]}"))
    db.add(
        DiscoveryScan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            name=str(fixture["scenario_id"]),
            requested_by=None,
            scan_type="targeted",
            scope_json={"fixture_only": True, "enterprise_denominator_complete": False},
            safety_profile="read_only",
            request_idempotency_key=f"fixture-{scan_id}",
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
            coverage_summary_json={
                "enterprise_denominator_complete": False,
                "unknown": ["customer_estate_denominator"],
            },
            evidence_bundle_id=None,
            rescan_of_scan_id=None,
        )
    )
    db.flush()

    pairs: dict[tuple[str, str], object] = {}
    for observation in observations:
        pairs[(observation.collector_id, observation.target_id)] = observation
    target_ids: set[str] = set()
    collector_ids: set[str] = set()
    for ordinal, ((collector_id, target_id), observation) in enumerate(
        sorted(pairs.items())
    ):
        collector_type = collector_types[collector_id]
        if target_id not in target_ids:
            db.add(
                DiscoveryTarget(
                    target_id=target_id,
                    tenant_id=tenant_id,
                    target_type=collector_type.supported_target.value,
                    identifier=f"fixture-unit-{ordinal}",
                    environment="test",
                    owner_hint=None,
                    credentials_reference=None,
                    permitted_methods_json=["metadata"],
                    exclusions_json=["raw_content", "credentials"],
                    rate_limit=10,
                    active_scan_allowed=False,
                    sensitive_scope=False,
                    last_scanned_at=NOW,
                )
            )
            target_ids.add(target_id)
        if collector_id not in collector_ids:
            declaration = collector_type().declaration
            db.add(
                DiscoveryCollector(
                    collector_id=collector_id,
                    tenant_id=tenant_id,
                    collector_type=collector_type.collector_type,
                    version="1.0.0",
                    supported_targets_json=[collector_type.supported_target.value],
                    active_capabilities_json=[],
                    passive_capabilities_json=list(declaration.passive_capabilities),
                    permissions_required_json=list(declaration.permissions_required),
                    sensitive_data_accessed_json=[],
                    health="healthy",
                    last_success_at=NOW,
                    last_failure_at=None,
                    data_residency="tenant_region",
                    control_capability="monitor_only",
                    schema_version="2.0",
                    limitations_json=list(declaration.limitations),
                    declaration_hash=declaration.declaration_hash,
                )
            )
            collector_ids.add(collector_id)
        db.flush()
        if target_id not in {
            row.target_id
            for row in db.scalars(
                select(DiscoveryScanTarget).where(
                    DiscoveryScanTarget.tenant_id == tenant_id,
                    DiscoveryScanTarget.scan_id == scan_id,
                )
            )
        }:
            db.add(
                DiscoveryScanTarget(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    target_id=target_id,
                )
            )
            db.flush()
        db.add(
            DiscoveryScanAssignment(
                assignment_id=str(uuid4()),
                tenant_id=tenant_id,
                scan_id=scan_id,
                target_id=target_id,
                collector_id=collector_id,
                status="running",
                warning=None,
                error=None,
                started_at=NOW,
                completed_at=None,
                observations_count=0,
            )
        )
        db.flush()
    for observation in observations:
        ingest_observation(db, tenant_id=tenant_id, payload=observation)
    return tenant_id


def _ctx(tenant_id: str) -> SimpleNamespace:
    return SimpleNamespace(tenant=SimpleNamespace(id=tenant_id), user=None)


def _keys(value: object) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            found.add(str(key).casefold())
            found |= _keys(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            found |= _keys(nested)
    return found


def test_claude_mcp_and_cursor_fixtures_reach_canonical_observation_contracts() -> None:
    _, claude, _ = _observations("claude-code-mcp.json")
    _, cursor, _ = _observations("cursor-browser.json")

    assert {item.source_surface.value for item in claude} == {
        "endpoint",
        "mcp",
        "model_endpoint",
    }
    assert {item.source_surface.value for item in cursor} == {"browser", "endpoint"}
    assert {item.raw_signal_type.value for item in claude} >= {
        "installed_application",
        "mcp_tool",
        "token_usage",
    }
    assert {item.raw_signal_type.value for item in cursor} == {
        "running_process",
        "web_ai_usage",
    }
    forbidden = {
        "prompt",
        "response",
        "tool_arguments",
        "tool_result",
        "file_content",
        "source_code",
        "credential",
        "api_token",
    }
    for item in (*claude, *cursor):
        assert item.sensitivity == "metadata"
        assert item.redaction_status == "not_required"
        assert _keys(item.model_dump(mode="python")).isdisjoint(forbidden)
        assert item.collection_scope["coverage_claim"] == "fixture_only"


def test_claude_mcp_fixture_resolves_cross_surface_context_and_conservative_coverage() -> None:
    db = _db()
    try:
        fixture, observations, collector_types = _observations("claude-code-mcp.json")
        tenant_id = _seed_scope(
            db,
            fixture=fixture,
            observations=observations,
            collector_types=collector_types,
        )
        observation_ids = tuple(item.observation_id for item in observations)
        bundle = fuse_observations(
            db, tenant_id=tenant_id, observation_ids=observation_ids
        )
        first_id = sorted(observation_ids)[0]
        resolution_claim = db.scalar(
            select(DiscoveryEvidenceClaim).where(
                DiscoveryEvidenceClaim.tenant_id == tenant_id,
                DiscoveryEvidenceClaim.subject_observation_id == first_id,
                DiscoveryEvidenceClaim.evidence_node_id == bundle.bundle_id,
            )
        )
        assert resolution_claim is not None
        result = resolve_observations(
            db,
            tenant_id=tenant_id,
            actor=ResolutionActor(actor_id="h2-fixture-resolver", actor_role="system"),
            payload=ResolutionRequest(
                candidate_observation_ids=observation_ids,
                new_asset=AIAssetCreate.model_validate(fixture["asset"]),
                existing_asset_id=None,
                matched_signals=(
                    ResolutionSignal(category="process and executable hashes"),
                    ResolutionSignal(category="MCP schema fingerprint"),
                    ResolutionSignal(category="API endpoint"),
                ),
                conflicting_signals=(),
                confidence=0.93,
                algorithm_version="hmair-h2-fixture-v1",
                evidence_claim_id=resolution_claim.claim_id,
                evidence_node_id=bundle.bundle_id,
                idempotency_key="resolve-h2-claude-mcp",
                reason="Three metadata-only surfaces refer to the same fixture workload",
            ),
        )
        assert result.asset is not None
        asset_id = result.asset.asset_id
        asset_claim = persist_evidence_claim(
            db,
            tenant_id=tenant_id,
            payload=EvidenceClaimCreate(
                claim_type="cross_surface_asset",
                subject_observation_id=None,
                subject_asset_id=asset_id,
                source_observation_id=first_id,
                evidence_node_id=bundle.bundle_id,
                claim_result="supported",
                claim_method="hmair-h2-fixture-v1",
                limitations=("fixture_only", "enterprise_denominator_unknown"),
                confidence=0.93,
                freshness="fresh",
                observed_at=NOW,
                idempotency_key="claim-h2-claude-mcp-asset",
            ),
        )
        infer_capability(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            source_observation_id=first_id,
            evidence_claim_id=asset_claim.claim_id,
            name="tool_execution",
            state="observed",
            confidence=0.9,
            verification_state="verified",
            freshness="fresh",
            observed_usage=True,
            declared_only=False,
            inferred_only=False,
            first_observed_at=NOW,
            last_observed_at=NOW,
            extractor_version="hmair-h2-fixture-v1",
            idempotency_key="capability-h2-claude-mcp",
        )
        link_identity(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            identity_type="workload_identity",
            identity_reference_hash="1" * 64,
            access_state="active",
            evidence_node_id=bundle.bundle_id,
            confidence=0.9,
            verification_state="verified",
            usage_proven=True,
            first_observed_at=NOW,
            last_observed_at=NOW,
            idempotency_key="identity-h2-claude-mcp",
        )
        persist_usage_fact(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            actor_type="workload",
            actor_reference_hash="1" * 64,
            usage_state="occasional",
            event_count=2,
            first_observed_at=NOW,
            last_observed_at=NOW,
            source_surface="mcp",
            evidence_node_id=bundle.bundle_id,
            confidence=0.9,
            verification_state="verified",
            freshness="fresh",
            telemetry_complete=False,
            methodology_id="hmair-h2-fixture-v1",
            limitations=("fixture_only",),
            idempotency_key="usage-h2-claude-mcp",
        )
        assert_reachability(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            target_category="mcp",
            target_reference_hash="2" * 64,
            reachability_state="observed",
            evidence_node_id=bundle.bundle_id,
            confidence=0.9,
            verification_state="verified",
            freshness="fresh",
            observed_usage=True,
            first_observed_at=NOW,
            last_observed_at=NOW,
            limitations=("fixture_only",),
            idempotency_key="reachability-h2-claude-mcp",
        )
        upsert_discovery_finding(
            db,
            tenant_id=tenant_id,
            asset_id=asset_id,
            finding_type="mcp_tool_requires_governance_review",
            severity="medium",
            confidence=0.9,
            verification_state="verified",
            evidence_node_ids=(bundle.bundle_id,),
            first_seen_at=NOW,
            last_seen_at=NOW,
            remediation="Review the tool identity and assign the appropriate policy.",
            verification_action="Verify the MCP fingerprint and effective policy.",
            coverage_impact="MCP governance coverage requires explicit validation.",
            dedupe_key="finding-h2-claude-mcp",
        )
        db.flush()

        context = get_discovery_context(db, tenant_id=tenant_id, asset_id=asset_id)
        detail = get_asset_detail(asset_id, ctx=_ctx(tenant_id), db=db)
        evidence = get_asset_evidence(
            asset_id, limit=50, cursor=None, ctx=_ctx(tenant_id), db=db
        )
        history = get_asset_history(
            asset_id, page=1, page_size=50, ctx=_ctx(tenant_id), db=db
        )
        coverage = calculate_discovery_coverage(db, tenant_id=tenant_id, now=NOW)

        assert set(bundle.source_surfaces) == {"endpoint", "mcp", "model_endpoint"}
        assert set(result.asset.source_observation_ids) == set(observation_ids)
        assert context["capabilities"][0]["name"] == "tool_execution"
        assert context["identities"][0]["usage_proven"] is True
        assert context["reachability"][0]["state"] == "observed"
        assert context["usage"][0]["event_count"] == 2
        assert context["findings"][0]["evidence_node_ids"] == [bundle.bundle_id]
        assert len(context["evidence"]) == 1
        assert len(detail.capabilities) == 1
        assert evidence.total == 3
        assert {item.source_surface for item in evidence.items} == {
            "endpoint",
            "mcp",
            "model_endpoint",
        }
        assert history.total == 1
        assert coverage.denominator.enterprise_denominator_complete is False
        assert coverage.dimensions["discovery"].score is None
        assert coverage.dimensions["discovery"].score_withheld_reason == (
            "enterprise_denominator_not_established"
        )
    finally:
        db.close()
        db.bind.dispose()


def test_cursor_fixture_enters_unknown_candidate_queue_without_false_resolution() -> None:
    db = _db()
    try:
        fixture, observations, collector_types = _observations("cursor-browser.json")
        tenant_id = _seed_scope(
            db,
            fixture=fixture,
            observations=observations,
            collector_types=collector_types,
        )
        bundle = fuse_observations(
            db,
            tenant_id=tenant_id,
            observation_ids=tuple(item.observation_id for item in observations),
        )
        create_hypothesis(
            db,
            tenant_id=tenant_id,
            hypothesis_type="coding_assistant",
            label="Cursor coding assistant candidate",
            candidate_key_hash=hashlib.sha256(b"cursor-h2-fixture").hexdigest(),
            confidence=0.74,
            verification_state="partially_verified",
            freshness="fresh",
            contradiction_state="none",
            evidence_node_id=bundle.bundle_id,
            observed_at=NOW,
            idempotency_key="hypothesis-h2-cursor",
        )
        db.flush()

        unknown = list_unknown_ai(
            page=1, page_size=50, ctx=_ctx(tenant_id), db=db
        )
        assert unknown.total == 1
        assert unknown.items[0].label == "Cursor coding assistant candidate"
        assert unknown.items[0].verification_state == "partially_verified"
        assert unknown.items[0].evidence_node_id == bundle.bundle_id
    finally:
        db.close()
        db.bind.dispose()
