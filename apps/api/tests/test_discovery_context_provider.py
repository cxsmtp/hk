from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.api.routers.native_controls import _enrich_native_request_with_discovery_context
from app.core.config import settings
from app.core.control_engine.authorization import AuthorizationRequest
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.ai_asset import DiscoveryAICapability, DiscoveryAIAsset, DiscoveryEvidenceClaim
from app.db.models.control_coverage import ControlCoverageAssertion, ControlCoveragePath
from app.db.models.discovery_attribution import DiscoveryAssetIdentityLink
from app.db.models.discovery_intelligence import DiscoveryAssetUsageFact
from app.db.models.discovery_resolution import DiscoveryResolutionGraphNode
from app.db.models.discovery_verification import DiscoveryVerificationAssertion
from app.db.models.evidence_resolution import DiscoveryAIEcosystem, DiscoveryEcosystemMembership
from app.db.models.capability_inference import DiscoveryCapabilityGenome
from app.db.session import Base
from app.services.hmair import discovery_context_provider
from app.services.hmair.discovery_context_provider import DiscoveryContextProvider


NOW = datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc)


@pytest.fixture()
def db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = Session(engine, autoflush=False, expire_on_commit=False)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _asset(
    db: Session,
    *,
    tenant_id: str = "tenant-a",
    canonical_name: str = "Hawk Runtime",
    provider: str = "OpenAI",
) -> DiscoveryAIAsset:
    asset = DiscoveryAIAsset(
        asset_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_type="runtime",
        canonical_name=canonical_name,
        provider=provider,
        product=canonical_name,
        framework="mcp",
        version="gpt-5",
        deployment_family="endpoint",
        technical_surface="runtime",
        environment="production",
        approved_status="unknown",
        lifecycle_status="active",
        shadow_ai_status="unknown",
        first_seen_at=NOW - timedelta(days=1),
        last_seen_at=NOW,
        resolution_confidence=0.9,
        evidence_bundle_id=str(uuid4()),
        projection_version=7,
    )
    db.add(asset)
    db.flush()
    return asset


def _capability(
    db: Session,
    *,
    asset: DiscoveryAIAsset,
    name: str,
    capability_id: str | None = None,
    verification_state: str = "verified",
    freshness: str = "fresh",
    last_observed_at: datetime = NOW,
    supersedes_capability_id: str | None = None,
    assertion_sequence: int = 1,
) -> DiscoveryAICapability:
    row = DiscoveryAICapability(
        capability_id=capability_id or str(uuid4()),
        tenant_id=asset.tenant_id,
        asset_id=asset.asset_id,
        source_observation_id=str(uuid4()),
        evidence_claim_id=str(uuid4()),
        capability_name=name,
        capability_state="observed",
        extractor_version="provider-test-v1",
        assertion_sequence=assertion_sequence,
        supersedes_capability_id=supersedes_capability_id,
        input_digest=("a" * 63) + str(assertion_sequence),
        confidence=0.8,
        verification_state=verification_state,
        freshness=freshness,
        observed_usage=True,
        declared_only=False,
        inferred_only=False,
        first_observed_at=last_observed_at - timedelta(minutes=1),
        last_observed_at=last_observed_at,
    )
    db.add(row)
    db.flush()
    return row


def _coverage_path(
    db: Session,
    *,
    asset: DiscoveryAIAsset,
    asset_ref: str,
    valid_until: datetime | None = None,
    runtime_ref: str = "runtime:hash-only",
) -> ControlCoveragePath:
    path = ControlCoveragePath(
        id=str(uuid4()),
        tenant_id=asset.tenant_id,
        path_key=uuid4().hex,
        key_version="1.0",
        asset_ref=asset_ref,
        identity_type="user",
        identity_ref="user:hash-only",
        runtime_ref=runtime_ref,
        deployment_surface_id=None,
        deployment_surface_ref="surface:browser",
        destination_type="application",
        destination_ref="application:hash-only",
        lifecycle_status="active",
        source_refs=[],
        first_seen_at=NOW - timedelta(minutes=1),
        last_seen_at=NOW,
    )
    db.add(path)
    db.flush()
    db.add(
        ControlCoverageAssertion(
            id=str(uuid4()),
            tenant_id=asset.tenant_id,
            path_id=path.id,
            dimension="discovery",
            state="covered",
            reason_code="verified_reference",
            explanation="No raw evidence is projected.",
            methodology_version="1.0",
            evaluator_version="1.0",
            evidence_refs=[],
            source_watermark="test",
            observed_at=NOW,
            evaluated_at=NOW,
            valid_until=valid_until,
        )
    )
    db.flush()
    return path


def _identity(db: Session, *, asset: DiscoveryAIAsset, reference_hash: str) -> DiscoveryAssetIdentityLink:
    row = DiscoveryAssetIdentityLink(
        identity_link_id=str(uuid4()),
        tenant_id=asset.tenant_id,
        asset_id=asset.asset_id,
        identity_type="workload_identity",
        identity_reference_hash=reference_hash,
        access_state="active",
        evidence_node_id=str(uuid4()),
        confidence=0.8,
        verification_state="verified",
        usage_proven=True,
        first_observed_at=NOW - timedelta(minutes=1),
        last_observed_at=NOW,
        idempotency_key=uuid4().hex,
        input_digest=uuid4().hex * 2,
    )
    db.add(row)
    db.flush()
    return row


def _usage(db: Session, *, asset: DiscoveryAIAsset, reference_hash: str) -> DiscoveryAssetUsageFact:
    row = DiscoveryAssetUsageFact(
        usage_fact_id=str(uuid4()),
        tenant_id=asset.tenant_id,
        asset_id=asset.asset_id,
        actor_type="workload",
        actor_reference_hash=reference_hash,
        usage_state="active",
        event_count=1,
        first_observed_at=NOW - timedelta(minutes=1),
        last_observed_at=NOW,
        source_surface="endpoint",
        evidence_node_id=str(uuid4()),
        confidence=0.8,
        verification_state="verified",
        freshness="fresh",
        telemetry_complete=True,
        methodology_id="provider-test-v1",
        limitations_json=[],
        idempotency_key=uuid4().hex,
        input_digest=uuid4().hex * 2,
    )
    db.add(row)
    db.flush()
    return row


def _forbidden_keys(value: object) -> set[str]:
    forbidden = {"allow", "block", "decision", "authorization", "policy"}
    found: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).casefold() in forbidden:
                found.add(str(key))
            found |= _forbidden_keys(nested)
    elif isinstance(value, (list, tuple)):
        for nested in value:
            found |= _forbidden_keys(nested)
    return found


def _digest() -> str:
    return uuid4().hex * 2


def test_provider_exposes_exact_snake_case_and_camel_case_apis(db: Session) -> None:
    asset = _asset(db)
    provider = DiscoveryContextProvider(db)

    snake = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, actor="actor-1", application="Hawk Runtime", as_of=NOW,
        enabled_override=True,
    )
    camel = provider.getContextForAIAction(
        tenant="tenant-a", asset=asset.asset_id, actor="actor-1", application="Hawk Runtime", as_of=NOW,
        enabled_override=True,
    )

    assert snake["status"] == camel["status"]
    assert snake["ai_asset_ref"] == camel["ai_asset_ref"]
    assert snake["status"] == "partial"
    assert snake["ai_asset_ref"] == f"discovery_asset:{asset.asset_id}"
    assert snake["asset_version"] == 7


def test_provider_is_disabled_by_default_without_reading_discovery(db: Session) -> None:
    context = DiscoveryContextProvider(db).getContextForAIAction(
        tenant="tenant-a", asset=str(uuid4()), as_of=NOW
    )

    assert context["status"] == "disabled"
    assert context["limitations"] == ["disabled"]


def test_provider_requires_unique_tenant_scoped_exact_resolution(db: Session) -> None:
    asset = _asset(db)
    _asset(db, canonical_name="Hawk Runtime", provider="OpenAI")
    foreign = _asset(db, tenant_id="tenant-b", canonical_name="Other", provider="OpenAI")
    provider = DiscoveryContextProvider(db)

    ambiguous = provider.get_context_for_ai_action(
        tenant="tenant-a", application=" hawk runtime ", provider=" openai ", enabled_override=True,
    )
    cross_tenant = provider.get_context_for_ai_action(tenant="tenant-a", asset=foreign.asset_id, enabled_override=True)
    malformed = provider.get_context_for_ai_action(
        tenant="tenant-a", asset="not-a-discovery-asset", application="Hawk Runtime", provider="OpenAI", enabled_override=True,
    )
    explicit = provider.get_context_for_ai_action(tenant="tenant-a", asset=asset.asset_id, enabled_override=True)

    assert ambiguous["status"] == "unknown"
    assert cross_tenant["status"] == "unknown"
    assert malformed["status"] == "unknown"
    assert explicit["ai_asset_ref"] == f"discovery_asset:{asset.asset_id}"


def test_provider_rejects_any_invalid_supplied_resolution_selector(db: Session) -> None:
    asset = _asset(db)

    context = DiscoveryContextProvider(db).get_context_for_ai_action(
        tenant="tenant-a",
        application=asset.canonical_name,
        provider="x" * 256,
        as_of=NOW,
        enabled_override=True,
    )

    assert context["status"] == "unknown"
    assert context["limitations"] == ["asset_not_resolved"]


def test_provider_selects_only_current_verified_references_and_exact_coverage_binding(db: Session) -> None:
    asset = _asset(db)
    old = _capability(db, asset=asset, name="file_read")
    current = _capability(
        db,
        asset=asset,
        name="file_read",
        assertion_sequence=2,
        supersedes_capability_id=old.capability_id,
    )
    stale_predecessor = _capability(db, asset=asset, name="file_write")
    _capability(db, asset=asset, name="file_write", freshness="stale", assertion_sequence=2, supersedes_capability_id=stale_predecessor.capability_id)
    unverified_predecessor = _capability(db, asset=asset, name="file_upload")
    _capability(db, asset=asset, name="file_upload", verification_state="inferred", assertion_sequence=2, supersedes_capability_id=unverified_predecessor.capability_id)
    future_predecessor = _capability(db, asset=asset, name="file_download")
    _capability(db, asset=asset, name="file_download", last_observed_at=NOW + timedelta(minutes=1), assertion_sequence=2, supersedes_capability_id=future_predecessor.capability_id)
    exact_path = _coverage_path(db, asset=asset, asset_ref=f"discovery_asset:{asset.asset_id}")
    _coverage_path(db, asset=asset, asset_ref="application:Hawk Runtime")
    _coverage_path(
        db,
        asset=asset,
        asset_ref=asset.asset_id,
        valid_until=NOW - timedelta(seconds=1),
    )
    provider = DiscoveryContextProvider(db)

    context = provider.get_context_for_ai_action(tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True)

    assert context["capability_refs"] == [f"capability:{current.capability_id}"]
    assert context["control_coverage"]["path_refs"] == [f"control_coverage_path:{exact_path.id}"]
    assert len(context["control_coverage"]["assertion_refs"]) == 1
    assert context["last_discovery"] == NOW.isoformat()

    coverage_assertion = db.scalar(
        select(ControlCoverageAssertion).where(ControlCoverageAssertion.path_id == exact_path.id)
    )
    assert coverage_assertion is not None
    # 13:00 +04:00 is 09:00 UTC, already expired at NOW.  The provider must
    # compare instants rather than overwrite the offset as UTC.
    coverage_assertion.valid_until = datetime(2026, 8, 20, 13, 0, tzinfo=timezone(timedelta(hours=4)))
    db.flush()

    expired = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True
    )

    assert expired["control_coverage"]["path_refs"] == []
    assert expired["control_coverage"]["assertion_refs"] == []


def test_actor_identity_and_runtime_exactly_narrow_their_own_summaries(db: Session) -> None:
    asset = _asset(db)
    matching_actor = "a" * 64
    matching_identity = "b" * 64
    usage = _usage(db, asset=asset, reference_hash=matching_actor)
    _usage(db, asset=asset, reference_hash="c" * 64)
    identity = _identity(db, asset=asset, reference_hash=matching_identity)
    _identity(db, asset=asset, reference_hash="d" * 64)
    matching_path = _coverage_path(
        db,
        asset=asset,
        asset_ref=asset.asset_id,
        runtime_ref="runtime:exact",
    )
    _coverage_path(db, asset=asset, asset_ref=asset.asset_id, runtime_ref="runtime:other")

    context = DiscoveryContextProvider(db).get_context_for_ai_action(
        tenant="tenant-a",
        asset=asset.asset_id,
        actor=matching_actor,
        identity=matching_identity,
        runtime="runtime:exact",
        as_of=NOW,
        enabled_override=True,
    )
    invalid = DiscoveryContextProvider(db).get_context_for_ai_action(
        tenant="tenant-a",
        asset=asset.asset_id,
        actor="not-a-reference-hash",
        identity="not-a-reference-hash",
        runtime="runtime:missing",
        as_of=NOW,
        enabled_override=True,
    )

    assert context["usage_refs"] == [f"usage:{usage.usage_fact_id}"]
    assert context["identity_refs"] == [f"identity:{identity.identity_link_id}"]
    assert context["control_coverage"]["path_refs"] == [f"control_coverage_path:{matching_path.id}"]
    assert invalid["usage_refs"] == []
    assert invalid["identity_refs"] == []
    assert invalid["control_coverage"]["path_refs"] == []
    assert {"actor_ref_unmatched", "identity_ref_unmatched", "missing_authoritative_dimensions"} <= set(invalid["limitations"])


def test_dependency_and_verification_require_one_exact_current_asset_graph_membership(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = _asset(db)
    node = DiscoveryResolutionGraphNode(
        graph_node_id=str(uuid4()),
        tenant_id=asset.tenant_id,
        node_class="ai_asset",
        subject_reference=f"discovery_asset:{asset.asset_id}",
        idempotency_key=uuid4().hex,
        input_digest=_digest(),
    )
    genome = DiscoveryCapabilityGenome(
        genome_id=str(uuid4()),
        tenant_id=asset.tenant_id,
        inference_run_id=str(uuid4()),
        subject_reference_hash="e" * 64,
        genome_version=1,
        supersedes_genome_id=None,
        genome_digest=_digest(),
        capabilities_json=[], dependencies_json=[{"secret": "never project"}],
        permissions_json=[], reachability_json=[], usage_json=[], models_json=[], providers_json=[],
        runtime_json=[], data_json=[], marketplace_json=[], identity_json=[],
        first_observed_at=NOW - timedelta(minutes=1), last_observed_at=NOW,
    )
    ecosystem = DiscoveryAIEcosystem(
        ecosystem_record_id=str(uuid4()), tenant_id=asset.tenant_id, ecosystem_id=str(uuid4()),
        resolution_version=1, supersedes_record_id=None, canonical_name="private ecosystem",
        ecosystem_class="runtime", lifecycle_state="active", resolution_state="resolved",
        confidence=0.8, evidence_quality=0.8, capability_genome_id=genome.genome_id,
        first_observed_at=NOW - timedelta(minutes=1), last_observed_at=NOW, last_validated_at=NOW,
        methodology_id="provider-test", methodology_version="1.0", limitations_json=[],
        outstanding_contradictions=0, idempotency_key=uuid4().hex, input_digest=_digest(),
    )
    membership = DiscoveryEcosystemMembership(
        membership_id=str(uuid4()), tenant_id=asset.tenant_id, ecosystem_record_id=ecosystem.ecosystem_record_id,
        ecosystem_id=ecosystem.ecosystem_id, graph_node_id=node.graph_node_id, member_type="ai_asset",
        membership_state="active", membership_sequence=1, predecessor_membership_id=None,
        evidence_node_id=str(uuid4()), confidence=0.8, verification_state="verified",
        first_observed_at=NOW - timedelta(minutes=1), last_observed_at=NOW, limitations_json=[], input_digest=_digest(),
    )
    assertion = DiscoveryVerificationAssertion(
        assertion_id=str(uuid4()), tenant_id=asset.tenant_id, ecosystem_id=ecosystem.ecosystem_id,
        ecosystem_record_id=ecosystem.ecosystem_record_id, episode_id=str(uuid4()), erg_evaluation_id=str(uuid4()),
        policy_record_id=str(uuid4()), predecessor_assertion_id=None, assertion_sequence=1,
        conclusion="verified", required_requirement_count=1, required_verified_count=1,
        optional_requirement_count=0, optional_verified_count=0, source_diversity=1,
        evidence_quality=0.8, verification_quality=0.8, issued_at=NOW - timedelta(minutes=1),
        valid_from=NOW - timedelta(minutes=1), valid_until=NOW + timedelta(minutes=1), invalidated_at=None,
        methodology_version="1.0", limitations_json=[], contradictions_json=[], idempotency_key=uuid4().hex,
        input_digest=_digest(),
    )
    db.add_all((node, genome, ecosystem, membership, assertion))
    db.flush()

    provider = DiscoveryContextProvider(db)
    context = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )

    assert context["dependency_refs"] == [f"capability_genome:{genome.genome_id}"]
    assert context["verification_refs"] == [f"verification_assertion:{assertion.assertion_id}"]
    assert "never project" not in repr(context)

    # The context remains partial because unrelated dimensions are absent. A
    # unique, current asset plus a real verification assertion is nevertheless
    # sufficient for target-identity enrichment; Discovery does not make a
    # policy decision or claim that every context dimension is complete.
    monkeypatch.setitem(settings.__dict__, "discovery_context_provider", True)
    assertion.valid_until = datetime.now(timezone.utc) + timedelta(days=1)
    asset.approved_status = "approved"
    enriched = _enrich_native_request_with_discovery_context(
        db,
        AuthorizationRequest(
            tenant_id=asset.tenant_id,
            environment="production",
            collector_id="native-control-test",
            action_id=str(uuid4()),
            chain_id="discovery-context-chain",
            surface="runtime_control",
            runtime={"runtime": "unknown"},
            actor={"identity_id": "workload"},
            authority={"authority_type": "unknown"},
            action={"action_type": "tool_execution", "action_class": "file_read"},
            tool={"name": asset.framework},
            target={"resource": "README.md", "destination": "local"},
            discovery_context={"provider": asset.provider, "product": asset.product},
            policy_snapshot_id="policy-test",
            policy_profile={},
            path_evidence={},
        ),
    )
    assert context["status"] == "partial"
    assert enriched.discovery_context["asset_status"] == "verified"
    assert enriched.discovery_context["asset_intelligence_ref"] == f"discovery_asset:{asset.asset_id}"
    assert enriched.discovery_context["verification_refs"] == [
        f"verification_assertion:{assertion.assertion_id}"
    ]

    # Verified evidence cannot override a governed asset denial. The request
    # stays Unknown so the existing policy path can fail safely.
    asset.approved_status = "unapproved"
    db.flush()
    denied = _enrich_native_request_with_discovery_context(
        db,
        enriched,
    )
    assert denied.discovery_context["asset_status"] == "unknown"
    assert denied.discovery_context["asset_intelligence_ref"] is None

    assertion.valid_until = datetime(2026, 8, 20, 13, 0, tzinfo=timezone(timedelta(hours=4)))
    db.flush()
    expired = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )
    assert expired["verification_refs"] == []

    assertion.valid_until = NOW + timedelta(minutes=1)
    node.node_class = "application"
    db.flush()
    wrong_node_class = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )
    assert wrong_node_class["dependency_refs"] == []
    assert wrong_node_class["verification_refs"] == []

    node.node_class = "ai_asset"
    genome.dependencies_json = []
    db.flush()
    no_dependencies = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )
    assert no_dependencies["dependency_refs"] == []

    genome.dependencies_json = [{"dependency": "safe-reference-only"}]
    superseding_genome = DiscoveryCapabilityGenome(
        genome_id=str(uuid4()),
        tenant_id=asset.tenant_id,
        inference_run_id=str(uuid4()),
        subject_reference_hash=genome.subject_reference_hash,
        genome_version=2,
        supersedes_genome_id=genome.genome_id,
        genome_digest=_digest(),
        capabilities_json=[], dependencies_json=[{"dependency": "superseding"}],
        permissions_json=[], reachability_json=[], usage_json=[], models_json=[], providers_json=[],
        runtime_json=[], data_json=[], marketplace_json=[], identity_json=[],
        first_observed_at=NOW - timedelta(minutes=1), last_observed_at=NOW,
    )
    db.add(superseding_genome)
    db.flush()
    stale_ecosystem_pin = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )
    assert stale_ecosystem_pin["dependency_refs"] == []

    previous_record = DiscoveryAIEcosystem(
        ecosystem_record_id=str(uuid4()), tenant_id=asset.tenant_id, ecosystem_id=ecosystem.ecosystem_id,
        resolution_version=1, supersedes_record_id=None, canonical_name="prior private ecosystem",
        ecosystem_class="runtime", lifecycle_state="superseded", resolution_state="resolved",
        confidence=0.8, evidence_quality=0.8, capability_genome_id=genome.genome_id,
        first_observed_at=NOW - timedelta(minutes=1), last_observed_at=NOW, last_validated_at=NOW,
        methodology_id="provider-test", methodology_version="1.0", limitations_json=[],
        outstanding_contradictions=0, idempotency_key=uuid4().hex, input_digest=_digest(),
    )
    ecosystem.resolution_version = 2
    ecosystem.supersedes_record_id = previous_record.ecosystem_record_id
    successor_assertion = DiscoveryVerificationAssertion(
        assertion_id=str(uuid4()), tenant_id=asset.tenant_id, ecosystem_id=ecosystem.ecosystem_id,
        ecosystem_record_id=previous_record.ecosystem_record_id, episode_id=str(uuid4()), erg_evaluation_id=str(uuid4()),
        policy_record_id=str(uuid4()), predecessor_assertion_id=assertion.assertion_id, assertion_sequence=2,
        conclusion="contradicted", required_requirement_count=1, required_verified_count=0,
        optional_requirement_count=0, optional_verified_count=0, source_diversity=1,
        evidence_quality=0.8, verification_quality=0.8, issued_at=NOW,
        valid_from=NOW, valid_until=NOW + timedelta(minutes=1), invalidated_at=None,
        methodology_version="1.0", limitations_json=[], contradictions_json=[], idempotency_key=uuid4().hex,
        input_digest=_digest(),
    )
    db.add_all((previous_record, successor_assertion))
    db.flush()
    successor_on_other_record = provider.get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )
    assert successor_on_other_record["verification_refs"] == []


def test_provider_never_projects_a_future_asset(db: Session) -> None:
    asset = _asset(db)
    asset.first_seen_at = NOW + timedelta(minutes=1)
    asset.last_seen_at = NOW + timedelta(minutes=2)
    db.flush()

    context = DiscoveryContextProvider(db).get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )

    assert context["status"] == "unknown"
    assert context["ai_asset_ref"] is None
    assert context["limitations"] == ["asset_not_resolved"]


def test_provider_marks_identity_and_indirect_evidence_as_partial_without_verification_timestamps(
    db: Session,
) -> None:
    asset = _asset(db)
    capability = _capability(db, asset=asset, name="file_read")
    identity = _identity(db, asset=asset, reference_hash="a" * 64)
    claim = DiscoveryEvidenceClaim(
        claim_id=capability.evidence_claim_id,
        tenant_id=asset.tenant_id,
        claim_type="capability",
        subject_observation_id=None,
        subject_asset_id=asset.asset_id,
        source_observation_id=str(uuid4()),
        evidence_node_id=str(uuid4()),
        claim_result="observed",
        claim_method="provider-test",
        limitations_json=[],
        confidence=0.8,
        freshness="fresh",
        observed_at=NOW,
        idempotency_key=uuid4().hex,
        input_digest=_digest(),
    )
    db.add(claim)
    db.flush()

    context = DiscoveryContextProvider(db).get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )

    assert context["identity_refs"] == [f"identity:{identity.identity_link_id}"]
    assert context["evidence_refs"] == [f"evidence_claim:{claim.claim_id}"]
    assert context["last_verification"] is None
    assert {"identity_freshness_unproven", "evidence_verification_indirect"} <= set(context["limitations"])


def test_control_coverage_uses_one_combined_dimension_budget(db: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    asset = _asset(db)
    _coverage_path(db, asset=asset, asset_ref=asset.asset_id)
    monkeypatch.setattr(discovery_context_provider, "MAX_REFS_PER_DIMENSION", 1)

    context = DiscoveryContextProvider(db).get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, as_of=NOW, enabled_override=True,
    )

    coverage = context["control_coverage"]
    assert len(coverage["path_refs"]) + len(coverage["assertion_refs"]) <= 1


def test_provider_bounds_results_avoids_forbidden_keys_and_performs_no_writes(
    db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    asset = _asset(db)
    names = (
        "inference", "model_inference", "embeddings", "multimodal", "image_generation",
        "audio", "code_generation", "file_read", "file_write", "file_upload",
        "file_download", "source_code_access", "terminal_execution", "process_execution",
        "filesystem_read", "filesystem_write", "browser_automation", "email_send",
    )
    for name in names:
        _capability(db, asset=asset, name=name)
    db.flush()
    assert not db.new and not db.dirty
    monkeypatch.setattr(discovery_context_provider, "MAX_REFS_PER_DIMENSION", 16)

    context = DiscoveryContextProvider(db).get_context_for_ai_action(
        tenant="tenant-a", asset=asset.asset_id, actor="person@example.com" * 100, enabled_override=True,
    )

    assert context["status"] == "partial"
    assert len(context["capability_refs"]) <= 16 <= 64
    assert "result_bounds_reached" in context["limitations"]
    assert _forbidden_keys(context) == set()
    assert "person@example.com" not in repr(context)
    assert not db.new and not db.dirty
