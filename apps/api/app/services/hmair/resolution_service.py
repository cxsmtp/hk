from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from types import MappingProxyType
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from app.core.config import settings
from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryAssetFingerprint,
    DiscoveryAssetHistoryEvent,
    DiscoveryAssetHistoryMember,
    DiscoveryObservationAssetLink,
    DiscoveryResolutionDecision,
    DiscoveryResolutionDecisionObservation,
)
from app.db.models.audit import AuditLog
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import (
    AIAssetContract,
    AIAssetCreate,
    AssetMergeRequest,
    AssetSplitRequest,
    HistoryReversalRequest,
    ResolutionAction,
    ResolutionActor,
    ResolutionDecisionContract,
    ResolutionOperationResult,
    ResolutionRequest,
    ResolutionResult,
    ResolutionSignal,
    SplitPartition,
    _canonicalize_merge_request,
    _canonicalize_resolution_request,
    _canonicalize_reversal_request,
    _canonicalize_split_request,
)
from app.services.hmair.evidence_claim_service import (
    EvidenceClaimScopeError,
    require_evidence_claim,
)


APPROVED_RESOLUTION_RULES: Mapping[str, tuple[str, str]] = MappingProxyType({})


class ResolutionConflict(RuntimeError):
    """Resolution replay or effective membership could not be proven."""


def _require_manual_actor(actor: ResolutionActor) -> None:
    if actor.actor_role.value not in {"owner", "admin"}:
        raise EvidenceClaimScopeError(
            "manual asset mutation requires tenant owner or admin authority"
        )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _observations(
    db: Session, *, tenant_id: str, observation_ids: tuple[str, ...]
) -> tuple[DiscoveryObservation, ...]:
    rows = tuple(
        db.scalars(
            select(DiscoveryObservation)
            .where(
                DiscoveryObservation.tenant_id == tenant_id,
                DiscoveryObservation.observation_id.in_(observation_ids),
            )
            .order_by(DiscoveryObservation.observation_id)
        )
    )
    if tuple(row.observation_id for row in rows) != tuple(sorted(observation_ids)):
        raise EvidenceClaimScopeError("resolution observations are unavailable")
    return rows


def _asset(
    db: Session, *, tenant_id: str, asset_id: str
) -> DiscoveryAIAsset:
    row = db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )
    if row is None:
        raise EvidenceClaimScopeError("resolution asset is unavailable")
    return row


def _evidence_node(
    db: Session, *, tenant_id: str, node_id: str
) -> EvidenceNode:
    row = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == node_id,
        )
    )
    if row is None:
        raise EvidenceClaimScopeError("resolution evidence is unavailable")
    return row


def _signals(values: list[dict[str, str]]) -> tuple[ResolutionSignal, ...]:
    return tuple(ResolutionSignal(category=item["category"]) for item in values)


def _asset_contract(db: Session, row: DiscoveryAIAsset) -> AIAssetContract:
    current_fingerprint = db.scalar(
        select(DiscoveryAssetFingerprint)
        .where(
            DiscoveryAssetFingerprint.tenant_id == row.tenant_id,
            DiscoveryAssetFingerprint.asset_id == row.asset_id,
        )
        .order_by(
            DiscoveryAssetFingerprint.chain_sequence.desc(),
            DiscoveryAssetFingerprint.fingerprint_id.desc(),
        )
        .limit(1)
    )
    predecessor = aliased(DiscoveryObservationAssetLink)
    links = tuple(
        db.scalars(
            select(DiscoveryObservationAssetLink)
            .where(
                DiscoveryObservationAssetLink.tenant_id == row.tenant_id,
                DiscoveryObservationAssetLink.asset_id == row.asset_id,
                ~select(predecessor.link_id)
                .where(
                    predecessor.tenant_id
                    == DiscoveryObservationAssetLink.tenant_id,
                    predecessor.observation_id
                    == DiscoveryObservationAssetLink.observation_id,
                    predecessor.predecessor_link_id
                    == DiscoveryObservationAssetLink.link_id,
                )
                .exists(),
            )
            .order_by(DiscoveryObservationAssetLink.observation_id)
            .limit(128)
        )
    )
    unresolved = db.scalar(
        select(DiscoveryResolutionDecision)
        .where(
            DiscoveryResolutionDecision.tenant_id == row.tenant_id,
            DiscoveryResolutionDecision.canonical_asset_id == row.asset_id,
            DiscoveryResolutionDecision.action == "manual_review",
        )
        .order_by(DiscoveryResolutionDecision.created_at.desc())
        .limit(1)
    )
    return AIAssetContract(
        asset_id=row.asset_id,
        tenant_id=row.tenant_id,
        asset_type=row.asset_type,
        canonical_name=row.canonical_name,
        provider=row.provider,
        product=row.product,
        framework=row.framework,
        version=row.version,
        deployment_family=row.deployment_family,
        technical_surface=row.technical_surface,
        environment=row.environment,
        owner=None,
        business_unit=None,
        approved_status=row.approved_status,
        shadow_ai_status=row.shadow_ai_status,
        lifecycle_status=row.lifecycle_status,
        first_seen_at=_aware(row.first_seen_at),
        last_seen_at=_aware(row.last_seen_at),
        last_used_at=None,
        identity_ids=(),
        runtime_ids=(),
        model_ids=(),
        tool_ids=(),
        data_source_ids=(),
        capability_profile_id=None,
        fingerprint_id=(
            current_fingerprint.fingerprint_id
            if current_fingerprint is not None
            else None
        ),
        usage_profile_id=None,
        control_coverage_ref=None,
        resolution_confidence=float(row.resolution_confidence),
        source_observation_ids=tuple(link.observation_id for link in links),
        unresolved_conflicts=(
            _signals(unresolved.conflicting_signals_json)
            if unresolved is not None
            else ()
        ),
        evidence_bundle_id=row.evidence_bundle_id,
    )


def _decision_contract(
    db: Session, row: DiscoveryResolutionDecision
) -> ResolutionDecisionContract:
    candidate_ids = tuple(
        db.scalars(
            select(DiscoveryResolutionDecisionObservation.observation_id)
            .where(
                DiscoveryResolutionDecisionObservation.tenant_id == row.tenant_id,
                DiscoveryResolutionDecisionObservation.decision_id
                == row.decision_id,
            )
            .order_by(DiscoveryResolutionDecisionObservation.ordinal)
        )
    )
    return ResolutionDecisionContract(
        decision_id=row.decision_id,
        candidate_observation_ids=candidate_ids,
        canonical_asset_id=row.canonical_asset_id,
        action=row.action,
        matched_signals=_signals(row.matched_signals_json),
        conflicting_signals=_signals(row.conflicting_signals_json),
        confidence=float(row.confidence),
        algorithm_version=row.algorithm_version,
        created_at=_aware(row.created_at),
    )


def _result(
    db: Session, decision: DiscoveryResolutionDecision
) -> ResolutionResult:
    asset = (
        _asset(db, tenant_id=decision.tenant_id, asset_id=decision.canonical_asset_id)
        if decision.canonical_asset_id is not None
        else None
    )
    return ResolutionResult(
        decision=_decision_contract(db, decision),
        asset=_asset_contract(db, asset) if asset is not None else None,
    )


def _signals_json(values: tuple[ResolutionSignal, ...]) -> list[dict[str, str]]:
    return [{"category": item.category.value} for item in values]


def _terminal_links(
    db: Session,
    *,
    tenant_id: str,
    observation_ids: tuple[str, ...] | None = None,
    asset_id: str | None = None,
) -> tuple[DiscoveryObservationAssetLink, ...]:
    successor = aliased(DiscoveryObservationAssetLink)
    statement = select(DiscoveryObservationAssetLink).where(
        DiscoveryObservationAssetLink.tenant_id == tenant_id,
        ~select(successor.link_id)
        .where(
            successor.tenant_id == DiscoveryObservationAssetLink.tenant_id,
            successor.observation_id
            == DiscoveryObservationAssetLink.observation_id,
            successor.predecessor_link_id
            == DiscoveryObservationAssetLink.link_id,
        )
        .exists(),
    )
    if observation_ids is not None:
        statement = statement.where(
            DiscoveryObservationAssetLink.observation_id.in_(observation_ids)
        )
    if asset_id is not None:
        statement = statement.where(
            DiscoveryObservationAssetLink.asset_id == asset_id
        )
    statement = statement.order_by(
        DiscoveryObservationAssetLink.observation_id,
        DiscoveryObservationAssetLink.sequence_no,
        DiscoveryObservationAssetLink.link_id,
    )
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        statement = statement.with_for_update()
    rows = tuple(db.scalars(statement))
    if observation_ids is not None and tuple(
        row.observation_id for row in rows
    ) != tuple(sorted(observation_ids)):
        raise ResolutionConflict("effective observation membership is incomplete")
    return rows


def _new_asset(
    db: Session,
    *,
    tenant_id: str,
    payload: AIAssetCreate,
    observations: tuple[DiscoveryObservation, ...],
    confidence: float,
    evidence_bundle_id: str,
) -> DiscoveryAIAsset:
    asset = DiscoveryAIAsset(
        asset_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_type=payload.asset_type.value,
        canonical_name=payload.canonical_name,
        provider=payload.provider,
        product=payload.product,
        framework=payload.framework,
        version=payload.version,
        deployment_family=payload.deployment_family,
        technical_surface=payload.technical_surface,
        environment=payload.environment,
        approved_status="unknown",
        lifecycle_status="unknown",
        shadow_ai_status="unknown",
        first_seen_at=min(row.observed_at for row in observations),
        last_seen_at=max(row.observed_at for row in observations),
        resolution_confidence=confidence,
        evidence_bundle_id=evidence_bundle_id,
        projection_version=1,
    )
    db.add(asset)
    db.flush()
    return asset


def _history_event(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    actor: ResolutionActor,
    reason: str,
    evidence_claim_id: str,
    idempotency_key: str,
    input_digest: str,
    reversal_of_event_id: str | None = None,
) -> DiscoveryAssetHistoryEvent:
    event = DiscoveryAssetHistoryEvent(
        history_event_id=str(uuid4()),
        tenant_id=tenant_id,
        event_type=event_type,
        reversal_of_event_id=reversal_of_event_id,
        actor_id=actor.actor_id,
        actor_role=actor.actor_role.value,
        reason=reason,
        evidence_claim_id=evidence_claim_id,
        idempotency_key=idempotency_key,
        input_digest=input_digest,
    )
    db.add(event)
    db.flush()
    return event


def _decision_row(
    db: Session,
    *,
    tenant_id: str,
    history_event_id: str,
    operation_index: int,
    action: ResolutionAction,
    asset_id: str,
    observation_ids: tuple[str, ...],
    matched_signals: tuple[ResolutionSignal, ...],
    conflicting_signals: tuple[ResolutionSignal, ...],
    confidence: float,
    algorithm_version: str,
    evidence_claim_id: str,
    idempotency_key: str,
    input_digest: str,
) -> DiscoveryResolutionDecision:
    decision = DiscoveryResolutionDecision(
        decision_id=str(uuid4()),
        tenant_id=tenant_id,
        canonical_asset_id=asset_id,
        history_event_id=history_event_id,
        operation_index=operation_index,
        action=action.value,
        matched_signals_json=_signals_json(matched_signals),
        conflicting_signals_json=_signals_json(conflicting_signals),
        confidence=confidence,
        algorithm_version=algorithm_version,
        evidence_claim_id=evidence_claim_id,
        idempotency_key=idempotency_key,
        input_digest=input_digest,
    )
    db.add(decision)
    db.flush()
    for ordinal, observation_id in enumerate(sorted(observation_ids)):
        db.add(
            DiscoveryResolutionDecisionObservation(
                decision_observation_id=str(uuid4()),
                tenant_id=tenant_id,
                decision_id=decision.decision_id,
                observation_id=observation_id,
                ordinal=ordinal,
            )
        )
    db.flush()
    return decision


def _history_members(
    db: Session,
    *,
    tenant_id: str,
    history_event_id: str,
    source_asset_ids: tuple[str, ...],
    result_asset_ids: tuple[str, ...],
) -> None:
    for role, values in (
        ("source", tuple(sorted(set(source_asset_ids)))),
        ("result", tuple(dict.fromkeys(result_asset_ids))),
    ):
        for ordinal, asset_id in enumerate(values):
            db.add(
                DiscoveryAssetHistoryMember(
                    history_member_id=str(uuid4()),
                    tenant_id=tenant_id,
                    history_event_id=history_event_id,
                    asset_id=asset_id,
                    member_role=role,
                    ordinal=ordinal,
                )
            )


def _append_membership(
    db: Session,
    *,
    tenant_id: str,
    history_event_id: str,
    decision_id: str,
    target_asset_id: str,
    current_links: tuple[DiscoveryObservationAssetLink, ...],
) -> None:
    for current in current_links:
        db.add(
            DiscoveryObservationAssetLink(
                link_id=str(uuid4()),
                tenant_id=tenant_id,
                observation_id=current.observation_id,
                asset_id=target_asset_id,
                decision_id=decision_id,
                history_event_id=history_event_id,
                link_kind="reassign",
                sequence_no=current.sequence_no + 1,
                predecessor_link_id=current.link_id,
                reversal_of_link_id=None,
            )
        )


def _audit_operation(
    db: Session,
    *,
    tenant_id: str,
    actor: ResolutionActor,
    event: DiscoveryAssetHistoryEvent,
    resource_id: str,
    decision_count: int,
    candidate_count: int,
) -> None:
    db.add(
        AuditLog(
            tenant_id=tenant_id,
            correlation_id=event.history_event_id,
            actor_user_id=None,
            actor_type=actor.actor_role.value,
            action=f"discovery.asset.{event.event_type}",
            resource_type="discovery_ai_asset",
            resource_id=resource_id,
            payload={
                "history_event_id": event.history_event_id,
                "decision_count": decision_count,
                "candidate_count": candidate_count,
            },
        )
    )


def _replay_operation(
    db: Session,
    *,
    tenant_id: str,
    request_key: str,
    event_digest: str,
    decision_digests: tuple[str, ...],
    reversal_of_event_id: str | None = None,
) -> ResolutionOperationResult | None:
    event = db.scalar(
        select(DiscoveryAssetHistoryEvent).where(
            DiscoveryAssetHistoryEvent.tenant_id == tenant_id,
            DiscoveryAssetHistoryEvent.idempotency_key == request_key,
        )
    )
    if event is None:
        return None
    if (
        event.input_digest != event_digest
        or event.reversal_of_event_id != reversal_of_event_id
    ):
        raise ResolutionConflict("resolution idempotency conflict")
    decisions = tuple(
        db.scalars(
            select(DiscoveryResolutionDecision)
            .where(
                DiscoveryResolutionDecision.tenant_id == tenant_id,
                DiscoveryResolutionDecision.history_event_id
                == event.history_event_id,
            )
            .order_by(DiscoveryResolutionDecision.operation_index)
        )
    )
    if tuple(row.input_digest for row in decisions) != decision_digests:
        raise ResolutionConflict("resolution replay is incomplete")
    return ResolutionOperationResult(
        history_event_id=event.history_event_id,
        results=tuple(_result(db, row) for row in decisions),
    )


def _claim_is_valid_for_action(
    *,
    claim: object,
    action: ResolutionAction,
    observation_ids: tuple[str, ...],
    asset_id: str | None,
) -> bool:
    subject_observation_id = getattr(claim, "subject_observation_id")
    subject_asset_id = getattr(claim, "subject_asset_id")
    if action is ResolutionAction.CREATE:
        return subject_observation_id in observation_ids
    if action is ResolutionAction.ATTACH:
        return (
            subject_observation_id in observation_ids
            or subject_asset_id == asset_id
        )
    return subject_observation_id in observation_ids


def resolve_observations(
    db: Session,
    *,
    tenant_id: str,
    actor: ResolutionActor,
    payload: ResolutionRequest,
) -> ResolutionResult:
    if payload.new_asset is not None:
        action = ResolutionAction.CREATE
    elif payload.existing_asset_id is not None:
        action = ResolutionAction.ATTACH
    else:
        action = ResolutionAction.MANUAL_REVIEW

    observations = _observations(
        db,
        tenant_id=tenant_id,
        observation_ids=payload.candidate_observation_ids,
    )
    if any(row.freshness != "fresh" for row in observations):
        raise EvidenceClaimScopeError("resolution observations are not fresh")
    claim = require_evidence_claim(
        db,
        tenant_id=tenant_id,
        claim_id=payload.evidence_claim_id,
        evidence_node_id=payload.evidence_node_id,
        require_fresh=True,
    )
    node = _evidence_node(
        db, tenant_id=tenant_id, node_id=payload.evidence_node_id
    )
    target_asset = (
        _asset(db, tenant_id=tenant_id, asset_id=payload.existing_asset_id)
        if payload.existing_asset_id is not None
        else None
    )
    if not _claim_is_valid_for_action(
        claim=claim,
        action=action,
        observation_ids=payload.candidate_observation_ids,
        asset_id=target_asset.asset_id if target_asset is not None else None,
    ):
        raise EvidenceClaimScopeError("resolution claim subject is invalid")

    material = _canonicalize_resolution_request(
        tenant_id=tenant_id,
        actor=actor,
        action=action,
        payload=payload,
    )
    decision_material = material.decisions[0]

    if material.event_input_digest is not None:
        existing_event = db.scalar(
            select(DiscoveryAssetHistoryEvent).where(
                DiscoveryAssetHistoryEvent.tenant_id == tenant_id,
                DiscoveryAssetHistoryEvent.idempotency_key
                == payload.idempotency_key,
            )
        )
        if existing_event is not None:
            if existing_event.input_digest != material.event_input_digest:
                raise ResolutionConflict("resolution idempotency conflict")
            existing_decision = db.scalar(
                select(DiscoveryResolutionDecision).where(
                    DiscoveryResolutionDecision.tenant_id == tenant_id,
                    DiscoveryResolutionDecision.history_event_id
                    == existing_event.history_event_id,
                    DiscoveryResolutionDecision.operation_index == 0,
                )
            )
            if (
                existing_decision is None
                or existing_decision.input_digest
                != decision_material.decision_input_digest
            ):
                raise ResolutionConflict("resolution replay is incomplete")
            return _result(db, existing_decision)
    else:
        existing_decision = db.scalar(
            select(DiscoveryResolutionDecision).where(
                DiscoveryResolutionDecision.tenant_id == tenant_id,
                DiscoveryResolutionDecision.idempotency_key
                == decision_material.decision_idempotency_key,
            )
        )
        if existing_decision is not None:
            if existing_decision.input_digest != decision_material.decision_input_digest:
                raise ResolutionConflict("resolution idempotency conflict")
            return _result(db, existing_decision)

    history: DiscoveryAssetHistoryEvent | None = None
    resolved_asset = target_asset
    if action is ResolutionAction.CREATE:
        if node.node_type != "bundle":
            raise EvidenceClaimScopeError("asset evidence bundle is invalid")
        assert payload.new_asset is not None
        new_asset = payload.new_asset
        resolved_asset = DiscoveryAIAsset(
            asset_id=str(uuid4()),
            tenant_id=tenant_id,
            asset_type=new_asset.asset_type.value,
            canonical_name=new_asset.canonical_name,
            provider=new_asset.provider,
            product=new_asset.product,
            framework=new_asset.framework,
            version=new_asset.version,
            deployment_family=new_asset.deployment_family,
            technical_surface=new_asset.technical_surface,
            environment=new_asset.environment,
            approved_status="unknown",
            lifecycle_status="unknown",
            shadow_ai_status="unknown",
            first_seen_at=min(row.observed_at for row in observations),
            last_seen_at=max(row.observed_at for row in observations),
            resolution_confidence=payload.confidence,
            evidence_bundle_id=node.id,
            projection_version=1,
        )
        db.add(resolved_asset)
        db.flush()

    if action in {ResolutionAction.CREATE, ResolutionAction.ATTACH}:
        assert resolved_asset is not None
        assert material.event_input_digest is not None
        history = DiscoveryAssetHistoryEvent(
            history_event_id=str(uuid4()),
            tenant_id=tenant_id,
            event_type=action.value,
            reversal_of_event_id=None,
            actor_id=actor.actor_id,
            actor_role=actor.actor_role.value,
            reason=payload.reason,
            evidence_claim_id=payload.evidence_claim_id,
            idempotency_key=payload.idempotency_key,
            input_digest=material.event_input_digest,
        )
        db.add(history)
        db.flush()

    decision = DiscoveryResolutionDecision(
        decision_id=str(uuid4()),
        tenant_id=tenant_id,
        canonical_asset_id=(
            resolved_asset.asset_id if resolved_asset is not None else None
        ),
        history_event_id=(history.history_event_id if history is not None else None),
        operation_index=0,
        action=action.value,
        matched_signals_json=[
            {"category": item.category.value} for item in payload.matched_signals
        ],
        conflicting_signals_json=[
            {"category": item.category.value}
            for item in payload.conflicting_signals
        ],
        confidence=payload.confidence,
        algorithm_version=payload.algorithm_version,
        evidence_claim_id=payload.evidence_claim_id,
        idempotency_key=decision_material.decision_idempotency_key,
        input_digest=decision_material.decision_input_digest,
    )
    db.add(decision)
    db.flush()
    for ordinal, observation in enumerate(observations):
        db.add(
            DiscoveryResolutionDecisionObservation(
                decision_observation_id=str(uuid4()),
                tenant_id=tenant_id,
                decision_id=decision.decision_id,
                observation_id=observation.observation_id,
                ordinal=ordinal,
            )
        )
    db.flush()

    if history is not None:
        assert resolved_asset is not None
        for observation in observations:
            existing_link = db.scalar(
                select(DiscoveryObservationAssetLink).where(
                    DiscoveryObservationAssetLink.tenant_id == tenant_id,
                    DiscoveryObservationAssetLink.observation_id
                    == observation.observation_id,
                )
            )
            if existing_link is not None:
                raise ResolutionConflict("effective membership already exists")
            db.add(
                DiscoveryObservationAssetLink(
                    link_id=str(uuid4()),
                    tenant_id=tenant_id,
                    observation_id=observation.observation_id,
                    asset_id=resolved_asset.asset_id,
                    decision_id=decision.decision_id,
                    history_event_id=history.history_event_id,
                    link_kind="attach",
                    sequence_no=1,
                    predecessor_link_id=None,
                    reversal_of_link_id=None,
                )
            )
        db.add(
            DiscoveryAssetHistoryMember(
                history_member_id=str(uuid4()),
                tenant_id=tenant_id,
                history_event_id=history.history_event_id,
                asset_id=resolved_asset.asset_id,
                member_role="result",
                ordinal=0,
            )
        )
        db.add(
            AuditLog(
                tenant_id=tenant_id,
                correlation_id=history.history_event_id,
                actor_user_id=None,
                actor_type=actor.actor_role.value,
                action=f"discovery.asset.{action.value}",
                resource_type="discovery_ai_asset",
                resource_id=resolved_asset.asset_id,
                payload={
                    "history_event_id": history.history_event_id,
                    "decision_id": decision.decision_id,
                    "candidate_count": len(observations),
                },
            )
        )
        db.flush()

    if (
        settings.hmair_fingerprinting
        and resolved_asset is not None
        and claim.source_observation_id in payload.candidate_observation_ids
    ):
        # Import locally so the immutable persistence services can depend on
        # shared resolution helpers without creating a module cycle.
        from app.services.hmair.capability_extraction_service import (
            extract_and_persist_capabilities,
        )
        from app.services.hmair.fingerprint_engine import fingerprint_observation

        fingerprint_observation(
            db,
            tenant_id=tenant_id,
            asset_id=resolved_asset.asset_id,
            source_observation_id=claim.source_observation_id,
            evidence_claim_id=claim.claim_id,
        )
        extract_and_persist_capabilities(
            db,
            tenant_id=tenant_id,
            asset_id=resolved_asset.asset_id,
            source_observation_id=claim.source_observation_id,
            evidence_claim_id=claim.claim_id,
        )
        db.flush()

    return _result(db, decision)


def merge_assets(
    db: Session,
    *,
    tenant_id: str,
    actor: ResolutionActor,
    payload: AssetMergeRequest,
) -> ResolutionOperationResult:
    _require_manual_actor(actor)
    observations = _observations(
        db,
        tenant_id=tenant_id,
        observation_ids=payload.candidate_observation_ids,
    )
    if any(row.freshness != "fresh" for row in observations):
        raise EvidenceClaimScopeError("merge observations are not fresh")
    source_assets = tuple(
        _asset(db, tenant_id=tenant_id, asset_id=asset_id)
        for asset_id in sorted(payload.source_asset_ids)
    )
    result_asset = _asset(
        db, tenant_id=tenant_id, asset_id=payload.result_asset_id
    )
    claim = require_evidence_claim(
        db,
        tenant_id=tenant_id,
        claim_id=payload.evidence_claim_id,
        evidence_node_id=payload.evidence_node_id,
        require_fresh=True,
    )
    _evidence_node(db, tenant_id=tenant_id, node_id=payload.evidence_node_id)
    if (
        claim.subject_observation_id not in payload.candidate_observation_ids
        and claim.subject_asset_id
        not in {*payload.source_asset_ids, payload.result_asset_id}
    ):
        raise EvidenceClaimScopeError("merge claim subject is invalid")
    if payload.conflicting_signals:
        raise ResolutionConflict("conflicted evidence requires manual review")

    material = _canonicalize_merge_request(
        tenant_id=tenant_id, actor=actor, payload=payload
    )
    assert material.event_input_digest is not None
    replay = _replay_operation(
        db,
        tenant_id=tenant_id,
        request_key=payload.idempotency_key,
        event_digest=material.event_input_digest,
        decision_digests=tuple(
            item.decision_input_digest for item in material.decisions
        ),
    )
    if replay is not None:
        return replay

    current_links = _terminal_links(
        db,
        tenant_id=tenant_id,
        observation_ids=payload.candidate_observation_ids,
    )
    if {row.asset_id for row in current_links} != set(payload.source_asset_ids):
        raise ResolutionConflict(
            "merge candidates do not exactly represent the source assets"
        )

    event = _history_event(
        db,
        tenant_id=tenant_id,
        event_type="merge",
        actor=actor,
        reason=payload.reason,
        evidence_claim_id=payload.evidence_claim_id,
        idempotency_key=payload.idempotency_key,
        input_digest=material.event_input_digest,
    )
    decision_material = material.decisions[0]
    decision = _decision_row(
        db,
        tenant_id=tenant_id,
        history_event_id=event.history_event_id,
        operation_index=0,
        action=ResolutionAction.MERGE,
        asset_id=result_asset.asset_id,
        observation_ids=payload.candidate_observation_ids,
        matched_signals=payload.matched_signals,
        conflicting_signals=payload.conflicting_signals,
        confidence=payload.confidence,
        algorithm_version=payload.algorithm_version,
        evidence_claim_id=payload.evidence_claim_id,
        idempotency_key=decision_material.decision_idempotency_key,
        input_digest=decision_material.decision_input_digest,
    )
    _append_membership(
        db,
        tenant_id=tenant_id,
        history_event_id=event.history_event_id,
        decision_id=decision.decision_id,
        target_asset_id=result_asset.asset_id,
        current_links=current_links,
    )
    _history_members(
        db,
        tenant_id=tenant_id,
        history_event_id=event.history_event_id,
        source_asset_ids=tuple(asset.asset_id for asset in source_assets),
        result_asset_ids=(result_asset.asset_id,),
    )
    result_asset.first_seen_at = min(
        [_aware(result_asset.first_seen_at), *(_aware(row.observed_at) for row in observations)]
    )
    result_asset.last_seen_at = max(
        [_aware(result_asset.last_seen_at), *(_aware(row.observed_at) for row in observations)]
    )
    result_asset.resolution_confidence = payload.confidence
    result_asset.projection_version += 1
    _audit_operation(
        db,
        tenant_id=tenant_id,
        actor=actor,
        event=event,
        resource_id=result_asset.asset_id,
        decision_count=1,
        candidate_count=len(observations),
    )
    db.flush()
    return ResolutionOperationResult(
        history_event_id=event.history_event_id,
        results=(_result(db, decision),),
    )


def _partition_for_material(
    payload: AssetSplitRequest,
    claim_id: str,
) -> SplitPartition:
    for partition in payload.partitions:
        if partition.evidence_claim_id == claim_id:
            return partition
    raise ResolutionConflict("split decision material is not bound to a partition")


def split_asset(
    db: Session,
    *,
    tenant_id: str,
    actor: ResolutionActor,
    payload: AssetSplitRequest,
) -> ResolutionOperationResult:
    _require_manual_actor(actor)
    candidate_ids = tuple(
        sorted(
            observation_id
            for partition in payload.partitions
            for observation_id in partition.candidate_observation_ids
        )
    )
    observations = _observations(
        db, tenant_id=tenant_id, observation_ids=candidate_ids
    )
    if any(row.freshness != "fresh" for row in observations):
        raise EvidenceClaimScopeError("split observations are not fresh")
    source_asset = _asset(
        db, tenant_id=tenant_id, asset_id=payload.source_asset_id
    )
    event_claim = require_evidence_claim(
        db,
        tenant_id=tenant_id,
        claim_id=payload.event_evidence_claim_id,
        evidence_node_id=payload.event_evidence_node_id,
        require_fresh=True,
    )
    _evidence_node(
        db, tenant_id=tenant_id, node_id=payload.event_evidence_node_id
    )
    if (
        event_claim.subject_asset_id != source_asset.asset_id
        and event_claim.subject_observation_id not in candidate_ids
    ):
        raise EvidenceClaimScopeError("split event claim subject is invalid")

    for partition in payload.partitions:
        claim = require_evidence_claim(
            db,
            tenant_id=tenant_id,
            claim_id=partition.evidence_claim_id,
            evidence_node_id=partition.evidence_node_id,
            require_fresh=True,
        )
        _evidence_node(
            db, tenant_id=tenant_id, node_id=partition.evidence_node_id
        )
        existing_target = (
            _asset(
                db,
                tenant_id=tenant_id,
                asset_id=partition.existing_asset_id,
            )
            if partition.existing_asset_id is not None
            else None
        )
        if (
            claim.subject_observation_id
            not in partition.candidate_observation_ids
            and (
                existing_target is None
                or claim.subject_asset_id != existing_target.asset_id
            )
        ):
            raise EvidenceClaimScopeError("split child claim subject is invalid")
        if partition.conflicting_signals:
            raise ResolutionConflict("conflicted split evidence requires manual review")

    material = _canonicalize_split_request(
        tenant_id=tenant_id, actor=actor, payload=payload
    )
    assert material.event_input_digest is not None
    replay = _replay_operation(
        db,
        tenant_id=tenant_id,
        request_key=payload.idempotency_key,
        event_digest=material.event_input_digest,
        decision_digests=tuple(
            item.decision_input_digest for item in material.decisions
        ),
    )
    if replay is not None:
        return replay

    all_source_links = _terminal_links(
        db, tenant_id=tenant_id, asset_id=source_asset.asset_id
    )
    if tuple(row.observation_id for row in all_source_links) != candidate_ids:
        raise ResolutionConflict(
            "split partitions must exactly cover current source membership"
        )
    links_by_observation = {row.observation_id: row for row in all_source_links}

    event = _history_event(
        db,
        tenant_id=tenant_id,
        event_type="split",
        actor=actor,
        reason=payload.reason,
        evidence_claim_id=payload.event_evidence_claim_id,
        idempotency_key=payload.idempotency_key,
        input_digest=material.event_input_digest,
    )
    observation_by_id = {row.observation_id: row for row in observations}
    decisions: list[DiscoveryResolutionDecision] = []
    result_assets: list[DiscoveryAIAsset] = []
    for decision_material in material.decisions:
        child = decision_material.child_object
        if child is None:
            raise ResolutionConflict("split decision material is incomplete")
        partition = _partition_for_material(
            payload, str(child["evidence_claim_id"])
        )
        partition_observations = tuple(
            observation_by_id[item]
            for item in partition.candidate_observation_ids
        )
        if partition.new_asset is not None:
            target_asset = _new_asset(
                db,
                tenant_id=tenant_id,
                payload=partition.new_asset,
                observations=partition_observations,
                confidence=partition.confidence,
                evidence_bundle_id=partition.evidence_node_id,
            )
            action = ResolutionAction.CREATE
        else:
            assert partition.existing_asset_id is not None
            target_asset = _asset(
                db,
                tenant_id=tenant_id,
                asset_id=partition.existing_asset_id,
            )
            action = ResolutionAction.ATTACH
            target_asset.first_seen_at = min(
                [_aware(target_asset.first_seen_at), *(_aware(row.observed_at) for row in partition_observations)]
            )
            target_asset.last_seen_at = max(
                [_aware(target_asset.last_seen_at), *(_aware(row.observed_at) for row in partition_observations)]
            )
            target_asset.resolution_confidence = partition.confidence
            target_asset.projection_version += 1
        decision = _decision_row(
            db,
            tenant_id=tenant_id,
            history_event_id=event.history_event_id,
            operation_index=decision_material.operation_index,
            action=action,
            asset_id=target_asset.asset_id,
            observation_ids=partition.candidate_observation_ids,
            matched_signals=partition.matched_signals,
            conflicting_signals=partition.conflicting_signals,
            confidence=partition.confidence,
            algorithm_version=partition.algorithm_version,
            evidence_claim_id=partition.evidence_claim_id,
            idempotency_key=decision_material.decision_idempotency_key,
            input_digest=decision_material.decision_input_digest,
        )
        _append_membership(
            db,
            tenant_id=tenant_id,
            history_event_id=event.history_event_id,
            decision_id=decision.decision_id,
            target_asset_id=target_asset.asset_id,
            current_links=tuple(
                links_by_observation[item]
                for item in sorted(partition.candidate_observation_ids)
            ),
        )
        decisions.append(decision)
        result_assets.append(target_asset)

    _history_members(
        db,
        tenant_id=tenant_id,
        history_event_id=event.history_event_id,
        source_asset_ids=(source_asset.asset_id,),
        result_asset_ids=tuple(asset.asset_id for asset in result_assets),
    )
    _audit_operation(
        db,
        tenant_id=tenant_id,
        actor=actor,
        event=event,
        resource_id=source_asset.asset_id,
        decision_count=len(decisions),
        candidate_count=len(observations),
    )
    db.flush()
    return ResolutionOperationResult(
        history_event_id=event.history_event_id,
        results=tuple(_result(db, row) for row in decisions),
    )


def reverse_history_event(
    db: Session,
    *,
    tenant_id: str,
    actor: ResolutionActor,
    payload: HistoryReversalRequest,
) -> ResolutionOperationResult:
    _require_manual_actor(actor)
    target = db.scalar(
        select(DiscoveryAssetHistoryEvent).where(
            DiscoveryAssetHistoryEvent.tenant_id == tenant_id,
            DiscoveryAssetHistoryEvent.history_event_id
            == payload.reversal_of_event_id,
        )
    )
    if target is None or target.event_type == "reversal":
        raise EvidenceClaimScopeError("reversal target is unavailable")
    claim = require_evidence_claim(
        db,
        tenant_id=tenant_id,
        claim_id=payload.evidence_claim_id,
        evidence_node_id=payload.evidence_node_id,
        require_fresh=True,
    )
    _evidence_node(db, tenant_id=tenant_id, node_id=payload.evidence_node_id)
    target_links = tuple(
        db.scalars(
            select(DiscoveryObservationAssetLink)
            .where(
                DiscoveryObservationAssetLink.tenant_id == tenant_id,
                DiscoveryObservationAssetLink.history_event_id
                == target.history_event_id,
            )
            .order_by(DiscoveryObservationAssetLink.observation_id)
        )
    )
    target_members = tuple(
        db.scalars(
            select(DiscoveryAssetHistoryMember).where(
                DiscoveryAssetHistoryMember.tenant_id == tenant_id,
                DiscoveryAssetHistoryMember.history_event_id
                == target.history_event_id,
            )
        )
    )
    if not target_links:
        raise ResolutionConflict("reversal target has no effective membership")
    if (
        claim.subject_observation_id
        not in {row.observation_id for row in target_links}
        and claim.subject_asset_id
        not in {row.asset_id for row in target_members}
    ):
        raise EvidenceClaimScopeError("reversal claim subject is invalid")

    material = _canonicalize_reversal_request(
        tenant_id=tenant_id, actor=actor, payload=payload
    )
    assert material.event_input_digest is not None
    replay = _replay_operation(
        db,
        tenant_id=tenant_id,
        request_key=payload.idempotency_key,
        event_digest=material.event_input_digest,
        decision_digests=(),
        reversal_of_event_id=payload.reversal_of_event_id,
    )
    if replay is not None:
        return replay
    existing_reversal = db.scalar(
        select(DiscoveryAssetHistoryEvent).where(
            DiscoveryAssetHistoryEvent.tenant_id == tenant_id,
            DiscoveryAssetHistoryEvent.reversal_of_event_id
            == payload.reversal_of_event_id,
        )
    )
    if existing_reversal is not None:
        raise ResolutionConflict("history event was already reversed")

    current_by_observation = {
        row.observation_id: row
        for row in _terminal_links(
            db,
            tenant_id=tenant_id,
            observation_ids=tuple(row.observation_id for row in target_links),
        )
    }
    if any(
        current_by_observation[row.observation_id].link_id != row.link_id
        for row in target_links
    ):
        raise ResolutionConflict("only a current history event can be reversed")

    event = _history_event(
        db,
        tenant_id=tenant_id,
        event_type="reversal",
        actor=actor,
        reason=payload.reason,
        evidence_claim_id=payload.evidence_claim_id,
        idempotency_key=payload.idempotency_key,
        input_digest=material.event_input_digest,
        reversal_of_event_id=target.history_event_id,
    )
    restored_asset_ids: list[str] = []
    source_asset_ids: list[str] = []
    for target_link in target_links:
        predecessor = (
            db.scalar(
                select(DiscoveryObservationAssetLink).where(
                    DiscoveryObservationAssetLink.tenant_id == tenant_id,
                    DiscoveryObservationAssetLink.observation_id
                    == target_link.observation_id,
                    DiscoveryObservationAssetLink.link_id
                    == target_link.predecessor_link_id,
                )
            )
            if target_link.predecessor_link_id is not None
            else None
        )
        restored_asset_id = predecessor.asset_id if predecessor is not None else None
        if target_link.asset_id is not None:
            source_asset_ids.append(target_link.asset_id)
        if restored_asset_id is not None:
            restored_asset_ids.append(restored_asset_id)
        db.add(
            DiscoveryObservationAssetLink(
                link_id=str(uuid4()),
                tenant_id=tenant_id,
                observation_id=target_link.observation_id,
                asset_id=restored_asset_id,
                decision_id=None,
                history_event_id=event.history_event_id,
                link_kind="reverse",
                sequence_no=target_link.sequence_no + 1,
                predecessor_link_id=target_link.link_id,
                reversal_of_link_id=target_link.link_id,
            )
        )
    _history_members(
        db,
        tenant_id=tenant_id,
        history_event_id=event.history_event_id,
        source_asset_ids=tuple(source_asset_ids),
        result_asset_ids=tuple(restored_asset_ids),
    )
    _audit_operation(
        db,
        tenant_id=tenant_id,
        actor=actor,
        event=event,
        resource_id=target.history_event_id,
        decision_count=0,
        candidate_count=len(target_links),
    )
    db.flush()
    return ResolutionOperationResult(
        history_event_id=event.history_event_id,
        results=(),
    )


__all__ = [
    "APPROVED_RESOLUTION_RULES",
    "ResolutionConflict",
    "merge_assets",
    "resolve_observations",
    "reverse_history_event",
    "split_asset",
]
