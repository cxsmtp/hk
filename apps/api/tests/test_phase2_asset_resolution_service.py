from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryAICapability,
    DiscoveryAssetFingerprint,
    DiscoveryAssetHistoryEvent,
    DiscoveryAssetHistoryMember,
    DiscoveryEvidenceClaim,
    DiscoveryObservationAssetLink,
    DiscoveryResolutionDecision,
)
from app.db.models.discovery_canonical import (
    DiscoveryCollector,
    DiscoveryObservation,
    DiscoveryScan,
    DiscoveryScanAssignment,
    DiscoveryScanTarget,
    DiscoveryTarget,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.contracts import (
    AICapabilityAssertionCreate,
    AIAssetCreate,
    AssetMergeRequest,
    AssetSplitRequest,
    AssetFingerprintCreate,
    EvidenceClaimCreate,
    HistoryReversalRequest,
    ResolutionActor,
    ResolutionRequest,
    SplitPartition,
)
from app.services.hmair.evidence_claim_service import (
    EvidenceClaimConflict,
    EvidenceClaimScopeError,
    persist_evidence_claim,
)
from app.services.hmair.fingerprint_service import (
    AssertionChainConflict,
    persist_fingerprint,
)
from app.services.hmair.capability_assertion_service import (
    persist_capability_assertion,
)
from app.services.hmair.resolution_service import (
    APPROVED_RESOLUTION_RULES,
    merge_assets,
    resolve_observations,
    reverse_history_event,
    split_asset,
)


NOW = datetime(2026, 8, 15, 9, 0, tzinfo=timezone.utc)


@pytest.fixture
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
        session.rollback()
        session.close()
        engine.dispose()


def _seed(
    db: Session,
    *,
    suffix: str = "a",
    include_tenant: bool = True,
) -> dict[str, str]:
    tenant_id = f"tenant-{suffix}"
    target_id = f"target-{suffix}"
    collector_id = f"collector-{suffix}"
    scan_id = str(uuid4())
    assignment_id = str(uuid4())
    observation_id = f"observation-{suffix}"
    node_id = str(uuid4())
    if include_tenant:
        db.add(Tenant(id=tenant_id, name=f"Tenant {suffix}", slug=f"tenant-{suffix}"))
        db.flush()
    db.add_all(
        [
            DiscoveryTarget(
                target_id=target_id,
                tenant_id=tenant_id,
                target_type="endpoint_group",
                identifier=f"managed-{suffix}",
                environment="production",
                owner_hint=None,
                credentials_reference=None,
                permitted_methods_json=["metadata"],
                exclusions_json=[],
                rate_limit=10,
                active_scan_allowed=False,
                sensitive_scope=False,
                last_scanned_at=NOW,
            ),
            DiscoveryCollector(
                collector_id=collector_id,
                tenant_id=tenant_id,
                collector_type="endpoint",
                version="2.0.0",
                supported_targets_json=["endpoint_group"],
                active_capabilities_json=[],
                passive_capabilities_json=["metadata"],
                permissions_required_json=[],
                sensitive_data_accessed_json=[],
                health="healthy",
                last_success_at=NOW,
                last_failure_at=None,
                data_residency="tenant_region",
                control_capability="monitor_only",
                schema_version="2.0",
                limitations_json=[],
                declaration_hash="a" * 64,
            ),
            DiscoveryScan(
                scan_id=scan_id,
                tenant_id=tenant_id,
                name="Phase 2 proof",
                requested_by=None,
                scan_type="targeted",
                scope_json={},
                safety_profile="read_only",
                request_idempotency_key=f"scan-{suffix}",
                request_digest="b" * 64,
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
                coverage_summary_json={},
                evidence_bundle_id=None,
                rescan_of_scan_id=None,
            ),
            EvidenceNode(
                id=node_id,
                tenant_id=tenant_id,
                correlation_id=f"phase2-{suffix}",
                node_type="bundle",
                signal_type="discovery.metadata",
                label="Phase 2 evidence bundle",
                payload={"classification": "metadata_only"},
            ),
        ]
    )
    db.flush()
    db.add(DiscoveryScanTarget(tenant_id=tenant_id, scan_id=scan_id, target_id=target_id))
    db.flush()
    db.add(
        DiscoveryScanAssignment(
            assignment_id=assignment_id,
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
    db.add(
        DiscoveryObservation(
            observation_id=observation_id,
            tenant_id=tenant_id,
            assignment_id=assignment_id,
            scan_id=scan_id,
            collector_id=collector_id,
            collector_type="endpoint",
            collector_version="2.0.0",
            target_id=target_id,
            source_surface="endpoint",
            subject_reference=f"managed-device-{suffix}",
            normalized_signal_json={"process_family": "local_ai_runtime"},
            observed_at=NOW,
            received_at=NOW,
            observation_type="running_process",
            candidate_asset_type="runtime",
            observed_state="observed",
            identifiers_json={"device_ref": f"device-{suffix}"},
            attributes_json={},
            configuration_summary_json={},
            usage_summary_json={},
            capability_hints_json=[],
            identity_hints_json=[],
            relationship_hints_json=[],
            evidence_reference=f"evidence://{node_id}",
            evidence_hash="c" * 64,
            signature_status="verified",
            confidence=0.9,
            freshness="fresh",
            verification_state="verified",
            source_trust="strong",
            collection_scope_json={"scope_type": "endpoint_group"},
            parser_version="2.0.0",
            schema_version="2.0",
            evidence_mode="direct",
            evidence_mutability="immutable",
            contradiction_state="none",
            contradiction_references_json=[],
            sensitivity="metadata",
            redaction_status="not_required",
            idempotency_key="d" * 64,
            payload_digest="e" * 64,
        )
    )
    db.flush()
    return {
        "tenant_id": tenant_id,
        "observation_id": observation_id,
        "node_id": node_id,
    }


def _claim_payload(seed: dict[str, str], **updates: object) -> EvidenceClaimCreate:
    data: dict[str, object] = {
        "claim_type": "asset_candidate",
        "subject_observation_id": seed["observation_id"],
        "subject_asset_id": None,
        "source_observation_id": seed["observation_id"],
        "evidence_node_id": seed["node_id"],
        "claim_result": "supported",
        "claim_method": "phase2-direct-observation-v1",
        "limitations": (),
        "confidence": 0.9,
        "freshness": "fresh",
        "observed_at": NOW,
        "idempotency_key": "claim-a",
    }
    data.update(updates)
    return EvidenceClaimCreate(**data)


def test_evidence_claim_is_tenant_safe_and_idempotent(db: Session) -> None:
    seed = _seed(db)
    first = persist_evidence_claim(
        db, tenant_id=seed["tenant_id"], payload=_claim_payload(seed)
    )
    second = persist_evidence_claim(
        db, tenant_id=seed["tenant_id"], payload=_claim_payload(seed)
    )

    assert second.claim_id == first.claim_id
    assert len(first.input_digest) == 64
    assert db.scalar(select(func.count(DiscoveryEvidenceClaim.claim_id))) == 1

    altered = _claim_payload(seed, claim_result="contradicted")
    with pytest.raises(EvidenceClaimConflict):
        persist_evidence_claim(db, tenant_id=seed["tenant_id"], payload=altered)


def test_evidence_claim_rejects_cross_tenant_and_time_mismatch(db: Session) -> None:
    first = _seed(db, suffix="a")
    second = _seed(db, suffix="b")
    with pytest.raises(EvidenceClaimScopeError):
        persist_evidence_claim(
            db, tenant_id=second["tenant_id"], payload=_claim_payload(first)
        )
    with pytest.raises(EvidenceClaimScopeError):
        persist_evidence_claim(
            db,
            tenant_id=first["tenant_id"],
            payload=_claim_payload(
                first, observed_at=datetime(2026, 8, 15, 9, 1, tzinfo=timezone.utc)
            ),
        )


def _asset(db: Session, seed: dict[str, str]) -> DiscoveryAIAsset:
    asset = DiscoveryAIAsset(
        asset_id=str(uuid4()),
        tenant_id=seed["tenant_id"],
        asset_type="runtime",
        canonical_name="Local AI runtime",
        provider=None,
        product=None,
        framework=None,
        version=None,
        deployment_family="endpoint",
        technical_surface="runtime",
        environment="production",
        approved_status="unknown",
        lifecycle_status="unknown",
        shadow_ai_status="unknown",
        first_seen_at=NOW,
        last_seen_at=NOW,
        resolution_confidence=0.9,
        evidence_bundle_id=seed["node_id"],
        projection_version=1,
    )
    db.add(asset)
    db.flush()
    return asset


def test_fingerprint_and_capability_chains_are_explicit(db: Session) -> None:
    seed = _seed(db)
    asset = _asset(db, seed)
    claim = persist_evidence_claim(
        db,
        tenant_id=seed["tenant_id"],
        payload=_claim_payload(
            seed,
            subject_observation_id=None,
            subject_asset_id=asset.asset_id,
            idempotency_key="claim-asset",
        ),
    )
    fingerprint = persist_fingerprint(
        db,
        tenant_id=seed["tenant_id"],
        payload=AssetFingerprintCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim.claim_id,
            fingerprint_version="1.0",
            component_hashes={"executable": "f" * 64},
            detected_products=(),
            detected_frameworks=(),
            detected_models=(),
            detected_protocols=(),
            detected_capabilities=("model_inference",),
            observed_destinations=(),
            confidence=0.9,
            supersedes_fingerprint_id=None,
            drift_summary={},
        ),
    )
    capability = persist_capability_assertion(
        db,
        tenant_id=seed["tenant_id"],
        payload=AICapabilityAssertionCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim.claim_id,
            name="model_inference",
            state="observed",
            confidence=0.9,
            first_observed_at=NOW,
            last_observed_at=NOW,
            extractor_version="phase2-v1",
            supersedes_capability_id=None,
        ),
    )

    assert fingerprint.chain_sequence == 1
    assert capability.assertion_sequence == 1
    assert db.scalar(select(func.count(DiscoveryAssetFingerprint.fingerprint_id))) == 1
    assert db.scalar(select(func.count(DiscoveryAICapability.capability_id))) == 1

    changed = AssetFingerprintCreate(
        **{
            **AssetFingerprintCreate(
                asset_id=asset.asset_id,
                source_observation_id=seed["observation_id"],
                evidence_claim_id=claim.claim_id,
                fingerprint_version="1.1",
                component_hashes={"executable": "a" * 64},
                detected_products=(), detected_frameworks=(), detected_models=(),
                detected_protocols=(), detected_capabilities=(),
                observed_destinations=(), confidence=0.8,
                supersedes_fingerprint_id=None, drift_summary={},
            ).model_dump(mode="python")
        }
    )
    with pytest.raises(AssertionChainConflict):
        persist_fingerprint(db, tenant_id=seed["tenant_id"], payload=changed)


def test_successor_fingerprint_derives_compact_drift_summary(db: Session) -> None:
    seed = _seed(db)
    asset = _asset(db, seed)
    claim = persist_evidence_claim(
        db,
        tenant_id=seed["tenant_id"],
        payload=_claim_payload(
            seed,
            subject_observation_id=None,
            subject_asset_id=asset.asset_id,
            idempotency_key="claim-fingerprint-drift",
        ),
    )
    baseline = persist_fingerprint(
        db,
        tenant_id=seed["tenant_id"],
        payload=AssetFingerprintCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim.claim_id,
            fingerprint_version="1.0",
            component_hashes={"executable": "f" * 64},
            detected_products=("Cursor",),
            detected_frameworks=(),
            detected_models=("model-a",),
            detected_protocols=(),
            detected_capabilities=("model_inference",),
            observed_destinations=("baseline.example",),
            confidence=0.9,
            supersedes_fingerprint_id=None,
            drift_summary={},
        ),
    )
    assert baseline.drift_summary_json == {
        "status": "baseline",
        "changed_component_categories": [],
        "changed_collections": [],
    }

    successor = persist_fingerprint(
        db,
        tenant_id=seed["tenant_id"],
        payload=AssetFingerprintCreate(
            asset_id=asset.asset_id,
            source_observation_id=seed["observation_id"],
            evidence_claim_id=claim.claim_id,
            fingerprint_version="1.1",
            component_hashes={"executable": "a" * 64},
            detected_products=("Codex",),
            detected_frameworks=(),
            detected_models=("model-b",),
            detected_protocols=(),
            detected_capabilities=("tool_execution",),
            observed_destinations=("changed.example",),
            confidence=0.9,
            supersedes_fingerprint_id=baseline.fingerprint_id,
            drift_summary={},
        ),
    )

    assert successor.drift_summary_json == {
        "status": "changed",
        "changed_component_categories": ["executable"],
        "changed_collections": ["capabilities", "destinations", "models", "products"],
    }


def _resolution_payload(seed: dict[str, str], claim_id: str, **updates: object) -> ResolutionRequest:
    data: dict[str, object] = {
        "candidate_observation_ids": (seed["observation_id"],),
        "new_asset": AIAssetCreate(
            asset_type="runtime",
            canonical_name="Resolved local runtime",
            provider=None,
            product=None,
            framework=None,
            version=None,
            deployment_family="endpoint",
            technical_surface="runtime",
            environment="production",
        ),
        "existing_asset_id": None,
        "matched_signals": (),
        "conflicting_signals": (),
        "confidence": 0.9,
        "algorithm_version": "phase2-resolution-v1",
        "evidence_claim_id": claim_id,
        "evidence_node_id": seed["node_id"],
        "idempotency_key": "resolve-a",
        "reason": "Direct evidence supports a distinct runtime asset",
    }
    data.update(updates)
    return ResolutionRequest(**data)


def test_create_resolution_is_atomic_and_manual_review_is_conservative(db: Session) -> None:
    seed = _seed(db)
    claim = persist_evidence_claim(
        db, tenant_id=seed["tenant_id"], payload=_claim_payload(seed)
    )
    actor = ResolutionActor(actor_id="operator-a", actor_role="admin")
    result = resolve_observations(
        db,
        tenant_id=seed["tenant_id"],
        actor=actor,
        payload=_resolution_payload(seed, claim.claim_id),
    )

    assert APPROVED_RESOLUTION_RULES == {}
    assert result.decision.action.value == "create"
    assert result.asset is not None
    assert db.scalar(select(func.count(DiscoveryAIAsset.asset_id))) == 1
    assert db.scalar(select(func.count(DiscoveryAssetHistoryEvent.history_event_id))) == 1
    assert db.scalar(select(func.count(DiscoveryResolutionDecision.decision_id))) == 1
    assert db.scalar(select(func.count(DiscoveryObservationAssetLink.link_id))) == 1
    assert db.scalar(select(func.count(DiscoveryAssetHistoryMember.history_member_id))) == 1

    replay = resolve_observations(
        db,
        tenant_id=seed["tenant_id"],
        actor=actor,
        payload=_resolution_payload(seed, claim.claim_id),
    )
    assert replay.decision.decision_id == result.decision.decision_id


def test_unmatched_resolution_defaults_to_manual_review(db: Session) -> None:
    seed = _seed(db)
    claim = persist_evidence_claim(
        db, tenant_id=seed["tenant_id"], payload=_claim_payload(seed)
    )
    payload = _resolution_payload(
        seed,
        claim.claim_id,
        new_asset=None,
        reason=None,
        idempotency_key="review-a",
    )
    result = resolve_observations(
        db,
        tenant_id=seed["tenant_id"],
        actor=ResolutionActor(actor_id="resolver", actor_role="system"),
        payload=payload,
    )

    assert result.decision.action.value == "manual_review"
    assert result.asset is None
    assert db.scalar(select(func.count(DiscoveryAssetHistoryEvent.history_event_id))) == 0
    assert db.scalar(select(func.count(DiscoveryObservationAssetLink.link_id))) == 0


def _add_observation(db: Session, seed: dict[str, str], *, suffix: str) -> str:
    original = db.get(DiscoveryObservation, seed["observation_id"])
    assert original is not None
    observation_id = f"observation-{suffix}"
    db.add(
        DiscoveryObservation(
            observation_id=observation_id,
            tenant_id=original.tenant_id,
            assignment_id=original.assignment_id,
            scan_id=original.scan_id,
            collector_id=original.collector_id,
            collector_type=original.collector_type,
            collector_version=original.collector_version,
            target_id=original.target_id,
            source_surface=original.source_surface,
            subject_reference=f"managed-device-{suffix}",
            normalized_signal_json={"process_family": f"runtime-{suffix}"},
            observed_at=NOW,
            received_at=NOW,
            observation_type="running_process",
            candidate_asset_type="runtime",
            observed_state="observed",
            identifiers_json={"device_ref": f"device-{suffix}"},
            attributes_json={},
            configuration_summary_json={},
            usage_summary_json={},
            capability_hints_json=[],
            identity_hints_json=[],
            relationship_hints_json=[],
            evidence_reference=f"evidence://{seed['node_id']}",
            evidence_hash="1" * 64,
            signature_status="verified",
            confidence=0.9,
            freshness="fresh",
            verification_state="verified",
            source_trust="strong",
            collection_scope_json={"scope_type": "endpoint_group"},
            parser_version="2.0.0",
            schema_version="2.0",
            evidence_mode="direct",
            evidence_mutability="immutable",
            contradiction_state="none",
            contradiction_references_json=[],
            sensitivity="metadata",
            redaction_status="not_required",
            idempotency_key=(suffix.encode().hex() + "0" * 64)[:64],
            payload_digest=(suffix.encode().hex() + "1" * 64)[:64],
        )
    )
    db.flush()
    return observation_id


def _persist_claim(
    db: Session,
    seed: dict[str, str],
    *,
    key: str,
    observation_id: str | None = None,
    asset_id: str | None = None,
) -> DiscoveryEvidenceClaim:
    source_observation_id = observation_id or seed["observation_id"]
    return persist_evidence_claim(
        db,
        tenant_id=seed["tenant_id"],
        payload=_claim_payload(
            seed,
            source_observation_id=source_observation_id,
            subject_observation_id=(None if asset_id is not None else source_observation_id),
            subject_asset_id=asset_id,
            idempotency_key=key,
        ),
    )


def _create_asset_for_observations(
    db: Session,
    seed: dict[str, str],
    *,
    observation_ids: tuple[str, ...],
    key: str,
    name: str,
) -> tuple[str, str]:
    claim = _persist_claim(
        db, seed, key=f"claim-{key}", observation_id=observation_ids[0]
    )
    payload = _resolution_payload(
        seed,
        claim.claim_id,
        candidate_observation_ids=observation_ids,
        new_asset=AIAssetCreate(
            asset_type="runtime",
            canonical_name=name,
            provider=None,
            product=None,
            framework=None,
            version=None,
            deployment_family="endpoint",
            technical_surface="runtime",
            environment="production",
        ),
        idempotency_key=f"resolve-{key}",
    )
    result = resolve_observations(
        db,
        tenant_id=seed["tenant_id"],
        actor=ResolutionActor(actor_id="operator-a", actor_role="admin"),
        payload=payload,
    )
    assert result.asset is not None
    history_id = db.scalar(
        select(DiscoveryResolutionDecision.history_event_id).where(
            DiscoveryResolutionDecision.decision_id == result.decision.decision_id
        )
    )
    assert history_id is not None
    return result.asset.asset_id, history_id


def test_merge_is_append_only_admin_scoped_and_reversible(db: Session) -> None:
    seed = _seed(db)
    second_observation = _add_observation(db, seed, suffix="merge-b")
    first_asset_id, _ = _create_asset_for_observations(
        db,
        seed,
        observation_ids=(seed["observation_id"],),
        key="merge-a",
        name="Runtime A",
    )
    second_asset_id, _ = _create_asset_for_observations(
        db,
        seed,
        observation_ids=(second_observation,),
        key="merge-b",
        name="Runtime B",
    )
    result_asset = _asset(db, seed)
    claim = _persist_claim(
        db, seed, key="claim-merge", observation_id=seed["observation_id"]
    )
    request = AssetMergeRequest(
        source_asset_ids=(first_asset_id, second_asset_id),
        result_asset_id=result_asset.asset_id,
        candidate_observation_ids=(seed["observation_id"], second_observation),
        matched_signals=(),
        conflicting_signals=(),
        confidence=0.95,
        algorithm_version="phase2-manual-merge-v1",
        evidence_claim_id=claim.claim_id,
        evidence_node_id=seed["node_id"],
        idempotency_key="merge-operation-a",
        reason="Administrator confirmed both observations are one runtime",
    )

    with pytest.raises(EvidenceClaimScopeError):
        merge_assets(
            db,
            tenant_id=seed["tenant_id"],
            actor=ResolutionActor(actor_id="resolver", actor_role="system"),
            payload=request,
        )

    merged = merge_assets(
        db,
        tenant_id=seed["tenant_id"],
        actor=ResolutionActor(actor_id="owner-a", actor_role="owner"),
        payload=request,
    )
    replay = merge_assets(
        db,
        tenant_id=seed["tenant_id"],
        actor=ResolutionActor(actor_id="owner-a", actor_role="owner"),
        payload=request,
    )
    assert replay.history_event_id == merged.history_event_id
    assert len(merged.results) == 1
    assert merged.results[0].asset is not None
    assert merged.results[0].asset.asset_id == result_asset.asset_id
    assert db.scalar(select(func.count(DiscoveryAIAsset.asset_id))) == 3

    reversed_result = reverse_history_event(
        db,
        tenant_id=seed["tenant_id"],
        actor=ResolutionActor(actor_id="admin-a", actor_role="admin"),
        payload=HistoryReversalRequest(
            idempotency_key="reverse-merge-a",
            reversal_of_event_id=merged.history_event_id,
            reason="Administrator corrected the manual merge",
            evidence_claim_id=claim.claim_id,
            evidence_node_id=seed["node_id"],
        ),
    )
    assert reversed_result.results == ()
    assert db.scalar(select(func.count(DiscoveryAIAsset.asset_id))) == 3
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 2
    assert db.scalar(select(func.count(DiscoveryObservationAssetLink.link_id))) == 6


def test_split_requires_exact_disjoint_current_membership(db: Session) -> None:
    seed = _seed(db)
    second_observation = _add_observation(db, seed, suffix="split-b")
    source_asset_id, _ = _create_asset_for_observations(
        db,
        seed,
        observation_ids=(seed["observation_id"], second_observation),
        key="split-source",
        name="Combined runtime",
    )
    event_claim = _persist_claim(
        db, seed, key="claim-split-event", asset_id=source_asset_id
    )
    first_claim = _persist_claim(
        db, seed, key="claim-split-a", observation_id=seed["observation_id"]
    )
    second_claim = _persist_claim(
        db, seed, key="claim-split-b", observation_id=second_observation
    )
    request = AssetSplitRequest(
        idempotency_key="split-operation-a",
        source_asset_id=source_asset_id,
        reason="Administrator separated two independently verified runtimes",
        event_evidence_claim_id=event_claim.claim_id,
        event_evidence_node_id=seed["node_id"],
        partitions=(
            SplitPartition(
                candidate_observation_ids=(second_observation,),
                new_asset=AIAssetCreate(
                    asset_type="runtime",
                    canonical_name="Runtime B",
                    provider=None,
                    product=None,
                    framework=None,
                    version=None,
                    deployment_family="endpoint",
                    technical_surface="runtime",
                    environment="production",
                ),
                existing_asset_id=None,
                matched_signals=(),
                conflicting_signals=(),
                confidence=0.88,
                algorithm_version="phase2-split-b-v1",
                evidence_claim_id=second_claim.claim_id,
                evidence_node_id=seed["node_id"],
            ),
            SplitPartition(
                candidate_observation_ids=(seed["observation_id"],),
                new_asset=AIAssetCreate(
                    asset_type="runtime",
                    canonical_name="Runtime A",
                    provider=None,
                    product=None,
                    framework=None,
                    version=None,
                    deployment_family="endpoint",
                    technical_surface="runtime",
                    environment="production",
                ),
                existing_asset_id=None,
                matched_signals=(),
                conflicting_signals=(),
                confidence=0.93,
                algorithm_version="phase2-split-a-v1",
                evidence_claim_id=first_claim.claim_id,
                evidence_node_id=seed["node_id"],
            ),
        ),
    )

    split = split_asset(
        db,
        tenant_id=seed["tenant_id"],
        actor=ResolutionActor(actor_id="admin-a", actor_role="admin"),
        payload=request,
    )
    replay = split_asset(
        db,
        tenant_id=seed["tenant_id"],
        actor=ResolutionActor(actor_id="admin-a", actor_role="admin"),
        payload=request,
    )
    assert replay.history_event_id == split.history_event_id
    assert len(split.results) == 2
    assert {item.asset.canonical_name for item in split.results if item.asset} == {
        "Runtime A",
        "Runtime B",
    }
    assert db.scalar(select(func.count(DiscoveryAIAsset.asset_id))) == 3
    assert db.scalar(select(func.count(DiscoveryObservation.observation_id))) == 2
