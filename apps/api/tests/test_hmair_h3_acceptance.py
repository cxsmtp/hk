from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.routers.discovery_erg import get_ecosystem
from app.core.config import settings
from app.db.models.ai_asset import DiscoveryAICapability, DiscoveryAssetFingerprint
from app.db.models.audit import AuditLog
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.session import Base
from app.services.hmair.capability_extraction_service import (
    CAPABILITY_EXTRACTOR_VERSION,
    SUPPORTED_CAPABILITY_EXTRACTORS,
    extract_capabilities,
    extract_and_persist_capabilities,
)
from app.services.hmair.contracts import (
    ResolutionActor,
    AICapabilityType,
    FingerprintComponentCategory,
)
from app.services.hmair.erg.resolution_history import ResolutionHistory
from app.services.hmair.fingerprint_engine import (
    FINGERPRINT_ENGINE_VERSION,
    SUPPORTED_FINGERPRINT_COMPONENTS,
    derive_fingerprint_material,
    fingerprint_observation,
)
from app.services.hmair.normalization_service import normalize_observation
from app.services.hmair.resolution_explainability_service import (
    RESOLUTION_EXPLANATION_VERSION,
    explain_resolution,
)
from app.services.hmair.resolution_graph_service import (
    create_graph_edge,
    create_graph_node,
)
from app.services.hmair.resolution_service import resolve_observations
from test_phase2_asset_resolution_service import (
    NOW,
    _asset,
    _persist_claim,
    _resolution_payload,
    _seed,
)


def _db() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine, autoflush=False, expire_on_commit=False)


def _rich_observation(db):
    seed = _seed(db, suffix="h3-rich")
    row = db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.tenant_id == seed["tenant_id"],
            DiscoveryObservation.observation_id == seed["observation_id"],
        )
    )
    assert row is not None
    row.identifiers_json = {
        "executable_hash": "a" * 64,
        "package": "hawk-agent",
        "provider_id": "provider-opaque",
        "model_id": "model-opaque",
    }
    row.normalized_signal_json = {
        "executable": "/Applications/Hawk.app/Contents/MacOS/Hawk",
        "dependency": "mcp-sdk",
        "protocol": "MCP",
        "runtime": "node",
        "destination": "api.example.invalid",
        "prompt": "do not fingerprint raw prompt content",
    }
    row.attributes_json = {
        "application": "Hawk",
        "framework": "agents-sdk",
        "version": "1.2.3",
    }
    row.configuration_summary_json = {
        "transport": "stdio",
        "secret_token": "must-never-influence-a-fingerprint",
        "mode": "metadata_only",
    }
    row.usage_summary_json = {"action_class": "tool_call", "event_count": 1}
    row.capability_hints_json = [item.value for item in AICapabilityType]
    row.identity_hints_json = [{"principal_id": "principal-opaque"}]
    row.relationship_hints_json = [
        {"destination": "api.example.invalid", "relationship": "connects_to"}
    ]
    db.flush()
    return seed, row


def test_twelve_component_fingerprint_engine_is_private_deterministic_and_versioned() -> None:
    db = _db()
    try:
        seed, row = _rich_observation(db)
        asset = _asset(db, seed)
        claim = _persist_claim(
            db,
            seed,
            key="h3-rich-claim",
            asset_id=asset.asset_id,
        )
        normalized = normalize_observation(row)

        first_material = derive_fingerprint_material((normalized,))
        replay_material = derive_fingerprint_material((normalized,))
        assert SUPPORTED_FINGERPRINT_COMPONENTS == tuple(
            item.value for item in FingerprintComponentCategory
        )
        assert set(first_material.component_hashes) == set(
            SUPPORTED_FINGERPRINT_COMPONENTS
        )
        assert first_material == replay_material
        assert all(
            len(value) == 64 and value == value.lower()
            for value in first_material.component_hashes.values()
        )
        serialized = first_material.model_dump_json()
        assert "do not fingerprint raw prompt content" not in serialized
        assert "must-never-influence-a-fingerprint" not in serialized

        baseline = fingerprint_observation(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            source_observation_id=row.observation_id,
            evidence_claim_id=claim.claim_id,
        )
        assert baseline.fingerprint_version == FINGERPRINT_ENGINE_VERSION
        assert baseline.chain_sequence == 1
        assert baseline.drift_summary_json["status"] == "baseline"

        row.usage_summary_json = {"action_class": "tool_call", "event_count": 2}
        db.flush()
        successor = fingerprint_observation(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            source_observation_id=row.observation_id,
            evidence_claim_id=claim.claim_id,
        )
        assert successor.supersedes_fingerprint_id == baseline.fingerprint_id
        assert successor.chain_sequence == 2
        assert successor.drift_summary_json == {
            "status": "changed",
            "changed_component_categories": ["behavior"],
            "changed_collections": [],
        }
        assert db.scalars(select(DiscoveryAssetFingerprint)).all() == [
            baseline,
            successor,
        ]
    finally:
        db.close()
        db.bind.dispose()


def test_exact_twenty_seven_extractors_preserve_all_six_truth_states() -> None:
    db = _db()
    try:
        seed, row = _rich_observation(db)
        base = normalize_observation(row)
        assert SUPPORTED_CAPABILITY_EXTRACTORS == tuple(
            item.value for item in AICapabilityType
        )
        assert len(SUPPORTED_CAPABILITY_EXTRACTORS) == 27
        assert CAPABILITY_EXTRACTOR_VERSION

        cases = {
            "installed": "declared",
            "configured": "configured",
            "observed": "observed",
            "inferred": "inferred",
            "unknown": "unknown",
        }
        for observed_state, expected in cases.items():
            fact = base.model_copy(
                update={
                    "observed_state": observed_state,
                    "capability_hints": ("model_inference",),
                    "evidence_mode": (
                        "inferred" if observed_state == "inferred" else "direct"
                    ),
                }
            )
            assert extract_capabilities(fact).assertions[0].state == expected

        denied = base.model_copy(
            update={
                "capability_hints": ("file_download",),
                "attributes": {"capability_state": "denied"},
                "evidence_mode": "direct",
                "verification_state": "verified",
                "freshness": "fresh",
            }
        )
        assert extract_capabilities(denied).assertions[0].state == "denied"

        asset = _asset(db, seed)
        claim = _persist_claim(
            db,
            seed,
            key="h3-capability-claim",
            asset_id=asset.asset_id,
        )
        persisted = extract_and_persist_capabilities(
            db,
            tenant_id=seed["tenant_id"],
            asset_id=asset.asset_id,
            source_observation_id=row.observation_id,
            evidence_claim_id=claim.claim_id,
        )
        assert len(persisted.assertions) == 27
        assert len(db.scalars(select(DiscoveryAICapability)).all()) == 27
        assert all(item.observed_usage for item in persisted.assertions)
    finally:
        db.close()
        db.bind.dispose()


def test_resolution_path_enriches_the_resolved_asset_when_fingerprinting_is_enabled(
    monkeypatch,
) -> None:
    monkeypatch.setattr(settings, "hmair_fingerprinting", True)
    db = _db()
    try:
        seed, row = _rich_observation(db)
        claim = _persist_claim(db, seed, key="h3-resolution-enrichment")
        result = resolve_observations(
            db,
            tenant_id=seed["tenant_id"],
            actor=ResolutionActor(actor_id="owner-1", actor_role="owner"),
            payload=_resolution_payload(
                seed,
                claim.claim_id,
                idempotency_key="h3-resolution-enrichment",
            ),
        )
        assert result.asset is not None
        assert result.asset.fingerprint_id is not None
        assert len(
            db.scalars(
                select(DiscoveryAICapability).where(
                    DiscoveryAICapability.asset_id == result.asset.asset_id
                )
            ).all()
        ) == 27
    finally:
        db.close()
        db.bind.dispose()


def test_resolution_explanation_is_truthful_and_does_not_expose_private_weights() -> None:
    explanation = explain_resolution(
        confidence=0.91,
        evidence_quality=0.88,
        evidence_categories=("same_provider", "same_runtime"),
        source_surfaces=("endpoint", "runtime"),
        collector_ids=("collector-a", "collector-b"),
        independent_source_groups=(),
        conflicts=("tenant_identity_conflict",),
        limitations=(),
        methodology_id="hmair-resolution-v3",
        methodology_version="3.0.0",
    )
    payload = explanation.model_dump()
    assert explanation.methodology_version == RESOLUTION_EXPLANATION_VERSION
    assert explanation.confidence_band == "high"
    assert explanation.evidence_quality_band == "high"
    assert explanation.source_independence == "not_established"
    assert "source_independence_not_established" in explanation.limitations
    assert explanation.conflicts == ("tenant_identity_conflict",)
    assert explanation.is_empirical_probability is False
    assert not {"weight", "weights", "calculation", "component_hashes"} & payload.keys()


def test_public_ecosystem_explanation_omits_private_scoring_material(monkeypatch) -> None:
    monkeypatch.setattr(settings, "cie_core", True)
    db = _db()
    try:
        seed = _seed(db, suffix="h3-public-boundary")
        first = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="application",
            subject_reference="application:opaque",
            idempotency_key="h3-public-node-a",
        )
        second = create_graph_node(
            db,
            tenant_id=seed["tenant_id"],
            node_class="runtime",
            subject_reference="runtime:opaque",
            idempotency_key="h3-public-node-b",
        )
        create_graph_edge(
            db,
            tenant_id=seed["tenant_id"],
            from_node_id=first.graph_node_id,
            to_node_id=second.graph_node_id,
            edge_type="runs_on",
            evidence_node_id=seed["node_id"],
            confidence=0.91,
            verification_state="verified",
            freshness="fresh",
            contradiction_state="none",
            first_observed_at=NOW,
            last_observed_at=NOW,
            idempotency_key="h3-public-edge",
            collector_id="collector-h3-public-boundary",
            source_surface="endpoint",
            signal_class="runtime",
            observation_quality=0.92,
            collector_quality=0.93,
        )
        created = ResolutionHistory().create_ecosystem(
            db,
            tenant_id=seed["tenant_id"],
            canonical_name="Governed runtime",
            ecosystem_class="runtime",
            graph_node_ids=(first.graph_node_id, second.graph_node_id),
            evidence_node_id=seed["node_id"],
            confidence=0.91,
            evidence_quality=0.88,
            operator_id="owner-1",
            operator_role="owner",
            reason="Reviewed evidence",
            occurred_at=NOW,
            idempotency_key="h3-public-create",
        )

        detail = get_ecosystem(
            created.ecosystem_ids[0],
            ctx=SimpleNamespace(
                tenant=SimpleNamespace(id=seed["tenant_id"]),
                user=SimpleNamespace(id="owner-1"),
                role="owner",
            ),
            db=db,
        ).model_dump()
        assert detail["why"]["confidence_band"] == "high"
        assert detail["why"]["evidence_categories"] == ["runs_on"]
        assert detail["why"]["source_independence"] == "not_established"
        assert detail["relationships"][0]["confidence_band"] == "high"
        assert detail["relationships"][0]["evidence_state"] == "verified_current"
        serialized = str(detail)
        assert "base_confidence" not in serialized
        assert "relationship_weight" not in serialized
        assert "'weight':" not in serialized
        assert "component_hashes" not in serialized
        assert "calculation" not in serialized
    finally:
        db.close()
        db.bind.dispose()


def test_manual_review_and_reject_are_append_only_audited() -> None:
    db = _db()
    try:
        seed = _seed(db, suffix="h3-actions")
        history = ResolutionHistory()
        for action in ("manual_review", "reject"):
            history.record_disposition(
                db,
                tenant_id=seed["tenant_id"],
                action=action,
                subject_reference=f"observation:{action}",
                evidence_node_id=seed["node_id"],
                confidence=0.7,
                operator_id="owner-1",
                operator_role="owner",
                reason=f"Owner selected {action}",
                occurred_at=datetime(2026, 9, 11, tzinfo=timezone.utc),
                idempotency_key=f"h3-{action}",
            )
        actions = set(db.scalars(select(AuditLog.action)))
        assert "discovery.ecosystem.manual_review" in actions
        assert "discovery.ecosystem.reject" in actions
    finally:
        db.close()
        db.bind.dispose()
