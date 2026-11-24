from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.db.models import *  # noqa: F401,F403
from app.db.models.activity_audit import AIAction, AISession
from app.db.models.ai_asset import DiscoveryAIAsset, DiscoveryAICapability
from app.db.models.control_coverage import ControlCoverageAssertion, ControlCoveragePath
from app.db.models.discovery_attribution import DiscoveryAssetIdentityLink
from app.db.models.discovery_intelligence import DiscoveryAssetUsageFact
from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence import DecisionReceipt, EvidenceNode
from app.db.models.tenant import Tenant
from app.db.session import Base
from app.services.hmair.exposure.category_catalog import load_category_catalog
from app.services.hmair.exposure.contracts import (
    ExposureDimension,
    ExposureExtent,
    ExposureFactor,
    ExposureTimelineEventType,
)
from app.services.hmair.exposure.drift import compare_exposure_states
from app.services.hmair.exposure.exposure_timeline import build_timeline_entry
from app.services.hmair.exposure.input_assembler import ExposureInputAssembler
from app.services.hmair.exposure.reasoning_rules import ExposureRuleResult, evaluate_category
from app.services.hmair.exposure.reasoning_service import REASONING_RULE_VERSION
from app.services.hmair.exposure.source_reader import (
    ExposureAssetUnavailable,
    ExposureSourceReader,
)


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
FIXTURE_PATH = Path(__file__).with_name("fixtures") / "ai_exposure_reasoning_cases.json"
RULE_VERSION = REASONING_RULE_VERSION
SOL_VERDICTS = frozenset({"APPROVED", "REJECTED", "REQUIRES_CORRECTION"})


def _uuid(material: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"hawk-exposure-simulation:{material}"))


def _digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _table_counts(db: Session) -> dict[str, int]:
    return {
        table.name: int(db.scalar(select(func.count()).select_from(table)) or 0)
        for table in Base.metadata.sorted_tables
    }


@dataclass(frozen=True)
class ProjectionRun:
    input_digest: str
    output_digest: str
    result: ExposureRuleResult
    source_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    row_counts_before: dict[str, int]
    row_counts_after: dict[str, int]
    factor_states: tuple[str, ...]
    factors: tuple[ExposureFactor, ...]
    persisted_risk_scores: tuple[float, ...]


def _seed_profile(
    *,
    case_id: str,
    factor_names: list[str],
    definitions: dict[str, dict[str, object]],
    risk_score: float | None = None,
) -> tuple[Session, str, str]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    db = Session(engine, autoflush=False, expire_on_commit=False)
    tenant_id = _uuid(f"{case_id}:tenant")
    asset_id = _uuid(f"{case_id}:asset")
    evidence_node_id = _uuid(f"{case_id}:evidence")
    governance = next(
        (
            str(definitions[name]["state"])
            for name in factor_names
            if definitions[name]["kind"] == "governance"
        ),
        "unknown",
    )
    db.add(
        Tenant(
            id=tenant_id,
            name=f"Exposure Simulation {case_id}"[:255],
            slug=f"exp-{_digest(case_id)[:20]}",
            is_active=True,
            platform_mode="enforce",
        )
    )
    db.flush()
    db.add(
        EvidenceNode(
            id=evidence_node_id,
            tenant_id=tenant_id,
            correlation_id=f"sim-{_digest(case_id)[:12]}",
            node_type="bundle",
            signal_type="simulation.exposure",
            label="AI exposure simulation evidence",
            payload={"classification": "synthetic_metadata_only"},
        )
    )
    db.flush()
    db.add(
        DiscoveryAIAsset(
            asset_id=asset_id,
            tenant_id=tenant_id,
            asset_type="runtime",
            canonical_name="Synthetic governed runtime",
            provider="synthetic-provider",
            product="simulation-fixture",
            framework=None,
            version="1.0.0",
            deployment_family="runtime",
            technical_surface="runtime",
            environment="test",
            approved_status=governance,
            lifecycle_status="active",
            shadow_ai_status="unknown",
            first_seen_at=NOW,
            last_seen_at=NOW,
            resolution_confidence=0.95,
            evidence_bundle_id=evidence_node_id,
            projection_version=1,
        )
    )
    db.flush()

    graph_asset_id = _uuid(f"{case_id}:graph-asset")
    graph_factors = [
        name for name in factor_names
        if definitions[name]["kind"] in {"permission", "reachability", "identity_removal"}
    ]
    if graph_factors:
        db.add(
            DiscoveryResolutionGraphNode(
                graph_node_id=graph_asset_id,
                tenant_id=tenant_id,
                node_class="ai_asset",
                subject_reference=asset_id,
                idempotency_key=f"graph-asset-{_digest(case_id)[:32]}",
                input_digest=_digest(f"{case_id}:graph-asset"),
                created_at=NOW,
            )
        )
        db.flush()

    coverage_path_id = _uuid(f"{case_id}:coverage-path")
    coverage_path_source_refs = [evidence_node_id]
    risk_action_id = f"action-{_digest(case_id + ':risk-source')[:20]}"
    if risk_score is not None:
        coverage_path_source_refs.append(f"ai_action:{risk_action_id}")
        db.add_all(
            [
                AISession(
                    session_id=f"session-{_digest(case_id + ':risk-source')[:20]}",
                    tenant_id=tenant_id,
                    source_surface="runtime",
                    ai_app="Synthetic governed runtime",
                    ai_model="test-model",
                    start_time=NOW,
                    total_actions=1,
                    risk_score=risk_score,
                    status="active",
                    metadata_json={},
                ),
                AIAction(
                    action_id=risk_action_id,
                    tenant_id=tenant_id,
                    session_id=f"session-{_digest(case_id + ':risk-source')[:20]}",
                    evidence_node_id=evidence_node_id,
                    evidence_bundle_id=evidence_node_id,
                    timestamp=NOW,
                    action_type="file_write",
                    ai_app="Synthetic governed runtime",
                    ai_model="test-model",
                    data_classification="restricted",
                    sensitivity_score=1.0,
                    enforcement_action="observed",
                    semantic_drift_score=0.0,
                    risk_score=risk_score,
                    metadata_json={"discovery_asset_ref": asset_id},
                ),
            ]
        )
        db.flush()
    for factor_name in factor_names:
        factor_definition = definitions[factor_name]
        factor_kind = str(factor_definition["kind"])
        if factor_kind == "governance":
            continue
        factor_source_id = _uuid(f"{case_id}:{factor_name}:source")
        source_type_by_kind = {
            "capability": "discovery_capability",
            "permission": "erg_relationship",
            "reachability": "erg_relationship",
            "identity": "discovery_identity",
            "identity_removal": "erg_relationship",
            "usage": "discovery_usage",
        }
        if factor_kind in source_type_by_kind:
            coverage_path_source_refs.append(
                f"{source_type_by_kind[factor_kind]}:{factor_source_id}"
            )
        elif factor_kind == "ai_action":
            action_id = f"action-{_digest(case_id + factor_name)[:20]}"
            coverage_path_source_refs.append(f"ai_action:{action_id}")
    coverage_added = False
    for index, name in enumerate(factor_names):
        definition = definitions[name]
        kind = str(definition["kind"])
        state = str(definition["state"])
        confidence = definition.get("confidence")
        verification = str(definition["verification"])
        freshness = str(definition["freshness"])
        source_id = _uuid(f"{case_id}:{name}:source")
        if kind == "governance":
            continue
        if kind == "capability":
            db.add(
                DiscoveryAICapability(
                    capability_id=source_id,
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    source_observation_id=f"observation-{_digest(case_id)[:20]}",
                    evidence_claim_id=_uuid(f"{case_id}:{name}:claim"),
                    capability_name=state,
                    capability_state="observed",
                    extractor_version="exposure-simulation/1.0",
                    assertion_sequence=1,
                    supersedes_capability_id=None,
                    input_digest=_digest(f"{case_id}:{name}:input"),
                    confidence=float(confidence),
                    verification_state=verification,
                    freshness=freshness,
                    observed_usage=False,
                    declared_only=False,
                    inferred_only=False,
                    first_observed_at=NOW,
                    last_observed_at=NOW,
                )
            )
        elif kind in {"permission", "reachability", "identity_removal"}:
            target_id = _uuid(f"{case_id}:{name}:target")
            db.add(
                DiscoveryResolutionGraphNode(
                    graph_node_id=target_id,
                    tenant_id=tenant_id,
                    node_class=(
                        "permission"
                        if kind == "permission"
                        else "network_destination"
                        if kind == "reachability"
                        else "identity"
                    ),
                    subject_reference=state,
                    idempotency_key=f"target-{_digest(case_id + name)[:32]}",
                    input_digest=_digest(f"{case_id}:{name}:target"),
                    created_at=NOW,
                )
            )
            db.flush()
            db.add(
                DiscoveryResolutionGraphEdge(
                    edge_id=source_id,
                    tenant_id=tenant_id,
                    from_node_id=graph_asset_id,
                    to_node_id=target_id,
                    edge_type=(
                        "accesses"
                        if kind == "permission"
                        else "connects_to"
                        if kind == "reachability"
                        else "authenticates_as"
                    ),
                    evidence_node_id=evidence_node_id,
                    collector_id=f"simulation-{kind}",
                    source_surface="identity" if kind == "permission" else "network",
                    signal_class=kind,
                    base_confidence=float(confidence),
                    observation_quality_factor=1.0,
                    collector_quality_factor=1.0,
                    confidence=float(confidence),
                    relationship_weight=1.0,
                    relationship_rule_id=f"simulation-{kind}-binding",
                    relationship_rule_version="1.0.0",
                    decay_policy_id="simulation-freshness",
                    decay_policy_version="1.0.0",
                    verification_state=verification,
                    freshness=freshness,
                    contradiction_state="none",
                    first_observed_at=NOW,
                    last_observed_at=NOW,
                    last_validated_at=NOW,
                    edge_schema_version="1.0",
                    edge_sequence=1,
                    predecessor_edge_id=None,
                    idempotency_key=f"edge-{_digest(case_id + name)[:32]}",
                    input_digest=_digest(f"{case_id}:{name}:edge"),
                )
            )
        elif kind == "identity":
            identity_type, access_state = state.split(":", 1)
            db.add(
                DiscoveryAssetIdentityLink(
                    identity_link_id=source_id,
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    identity_type=identity_type,
                    identity_reference_hash=_digest(f"{case_id}:{name}:identity"),
                    access_state=access_state,
                    evidence_node_id=evidence_node_id,
                    confidence=float(confidence),
                    verification_state=verification,
                    usage_proven=True,
                    first_observed_at=NOW,
                    last_observed_at=NOW,
                    idempotency_key=f"identity-{_digest(case_id + name)[:30]}",
                    input_digest=_digest(f"{case_id}:{name}:input"),
                )
            )
        elif kind == "coverage":
            if not coverage_added:
                db.add(
                    ControlCoveragePath(
                        id=coverage_path_id,
                        tenant_id=tenant_id,
                        path_key=_digest(f"{case_id}:coverage-key"),
                        key_version="1.0",
                        asset_ref=asset_id,
                        identity_type="asset",
                        identity_ref=asset_id,
                        runtime_ref=asset_id,
                        deployment_surface_id=None,
                        deployment_surface_ref="simulation-runtime",
                        destination_type="local",
                        destination_ref="simulation-target",
                        lifecycle_status="active",
                        source_refs=sorted(set(coverage_path_source_refs)),
                        first_seen_at=NOW,
                        last_seen_at=NOW,
                    )
                )
                db.flush()
                coverage_added = True
            dimension, coverage_state = state.split(":", 1)
            db.add(
                ControlCoverageAssertion(
                    id=source_id,
                    tenant_id=tenant_id,
                    path_id=coverage_path_id,
                    dimension=dimension,
                    state=coverage_state,
                    reason_code="simulation_evidence",
                    explanation="Synthetic metadata-only exposure simulation proof.",
                    methodology_version="1.0",
                    evaluator_version="1.0",
                    evidence_refs=[evidence_node_id],
                    source_watermark=_digest(f"{case_id}:{name}:watermark")[:64],
                    observed_at=NOW,
                    evaluated_at=NOW,
                    valid_until=NOW + timedelta(days=1),
                )
            )
        elif kind == "usage":
            db.add(
                DiscoveryAssetUsageFact(
                    usage_fact_id=source_id,
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    actor_type="workload",
                    actor_reference_hash=_digest(f"{case_id}:usage-actor"),
                    usage_state=state,
                    event_count=100 if state == "high_usage" else 10,
                    first_observed_at=NOW - timedelta(days=1),
                    last_observed_at=NOW,
                    source_surface="runtime",
                    evidence_node_id=evidence_node_id,
                    confidence=float(confidence),
                    verification_state=verification,
                    freshness=freshness,
                    telemetry_complete=True,
                    methodology_id="exposure-simulation/1.0",
                    limitations_json=[],
                    idempotency_key=f"usage-{_digest(case_id + name)[:32]}",
                    input_digest=_digest(f"{case_id}:{name}:input"),
                )
            )
        elif kind == "ai_action":
            decision, control_mode = state.split(":", 1)
            action_id = f"action-{_digest(case_id + name)[:20]}"
            session_id = f"session-{_digest(case_id + name)[:20]}"
            db.add_all(
                [
                    AISession(
                        session_id=session_id,
                        tenant_id=tenant_id,
                        source_surface="runtime",
                        ai_app="Synthetic governed runtime",
                        ai_model="test-model",
                        start_time=NOW,
                        total_actions=1,
                        risk_score=0.0,
                        status="active",
                        metadata_json={},
                    ),
                    AIAction(
                        action_id=action_id,
                        tenant_id=tenant_id,
                        session_id=session_id,
                        evidence_node_id=evidence_node_id,
                        evidence_bundle_id=evidence_node_id,
                        timestamp=NOW,
                        action_type="file_write",
                        ai_app="Synthetic governed runtime",
                        ai_model="test-model",
                        data_classification="restricted",
                        sensitivity_score=1.0,
                        enforcement_action=decision,
                        semantic_drift_score=0.0,
                        risk_score=1.0,
                        metadata_json={"discovery_asset_ref": asset_id},
                    ),
                ]
            )
            db.flush()
            db.add(
                DecisionReceipt(
                    receipt_id=source_id,
                    schema_version="1.0",
                    tenant_id=tenant_id,
                    action_id=action_id,
                    chain_id=f"chain-{_digest(case_id)[:20]}",
                    canonical_action_hash=_digest(f"{case_id}:{name}:action"),
                    actor_hash=_digest(f"{case_id}:actor"),
                    authority_hash=_digest(f"{case_id}:authority"),
                    purpose_hash=_digest(f"{case_id}:purpose"),
                    tool_fingerprint="tool:filesystem_write",
                    parameter_hash=_digest(f"{case_id}:parameters"),
                    target_resource_hash=_digest(f"{case_id}:target"),
                    destination_hash=_digest(f"{case_id}:destination"),
                    side_effect_class="persistent_side_effect",
                    approval_binding_hash=_digest(f"{case_id}:approval"),
                    approval_binding_id=None,
                    policy_snapshot_id="simulation-policy-v1",
                    decision=decision,
                    control_mode=control_mode,
                    transformations=[],
                    expires_at=NOW + timedelta(minutes=1),
                    issued_at=NOW,
                    signature=_digest(f"{case_id}:signature"),
                    signing_key_id="simulation-decision-key",
                    collector_id="simulation-native-control",
                    canonical_action_evidence_node_id=evidence_node_id,
                    policy_snapshot_evidence_node_id=None,
                    evidence_bundle_id=evidence_node_id,
                    evidence_node_id=evidence_node_id,
                    idempotency_key=_digest(f"{case_id}:{name}:idempotency"),
                )
            )
        else:
            raise AssertionError(f"unsupported simulation factor kind: {kind}")
        if index % 4 == 3:
            db.flush()
    db.flush()
    return db, tenant_id, asset_id


def _artifact_sol_verdict() -> str:
    verdict = os.environ.get(
        "HAWK_EXPOSURE_SOL_VERDICT",
        "REQUIRES_CORRECTION",
    ).strip().upper()
    if verdict not in SOL_VERDICTS:
        raise ValueError("HAWK_EXPOSURE_SOL_VERDICT is not a reviewed verdict")
    return verdict


def _project(
    *,
    case_id: str,
    factor_names: list[str],
    definitions: dict[str, dict[str, object]],
    risk_score: float | None = None,
) -> ProjectionRun:
    db, tenant_id, asset_id = _seed_profile(
        case_id=case_id,
        factor_names=factor_names,
        definitions=definitions,
        risk_score=risk_score,
    )
    try:
        counts_before = _table_counts(db)
        snapshot = ExposureSourceReader().read(
            db, tenant_id=tenant_id, asset_id=asset_id, as_of=NOW
        )
        assembled = ExposureInputAssembler().assemble(snapshot)
        category = next(
            item for item in load_category_catalog().categories
            if item.category_id == "coding_exposure"
        )
        result = evaluate_category(
            definition=category,
            factors=assembled.factors,
            methodology_version=RULE_VERSION,
        )
        counts_after = _table_counts(db)
        persisted_risk_scores = tuple(
            sorted(
                float(item)
                for item in db.scalars(
                    select(AIAction.risk_score).where(
                        AIAction.tenant_id == tenant_id,
                    )
                )
            )
        )
        assert counts_after == counts_before
        assert not db.new
        assert not db.dirty
        assert not db.deleted
        return ProjectionRun(
            input_digest=assembled.input_digest,
            output_digest=_digest(result.model_dump(mode="json")),
            result=result,
            source_refs=tuple(
                sorted(
                    {
                        f"{item.source_type}:{item.source_id}"
                        for item in assembled.factors
                    }
                )
            ),
            evidence_refs=tuple(
                sorted(f"evidence_ref:{reference}" for reference in result.evidence_refs)
            ),
            row_counts_before=counts_before,
            row_counts_after=counts_after,
            factor_states=tuple(
                f"{item.dimension.value}:{item.state}" for item in assembled.factors
            ),
            factors=assembled.factors,
            persisted_risk_scores=persisted_risk_scores,
        )
    finally:
        engine = db.get_bind()
        db.close()
        engine.dispose()


def _assert_case(case: dict[str, object], before: ProjectionRun, after: ProjectionRun) -> None:
    expected = case["expected"]
    assert isinstance(expected, dict)
    if "before_extent" in expected:
        assert before.result.extent.value == expected["before_extent"]
    if "after_extent" in expected:
        assert after.result.extent.value == expected["after_extent"]
    relation = expected["relation"]
    if relation == "increased":
        assert before.result.extent is not after.result.extent
        assert after.result.extent in {ExposureExtent.MATERIAL, ExposureExtent.BROAD}
    elif relation == "governance_improved":
        assert before.result.extent is after.result.extent
        assert any(state == "governance:approved" for state in after.factor_states)
        assert any(state.startswith("capability:filesystem_write") for state in after.factor_states)
    elif relation == "coverage_improved":
        assert any(
            state == "control_coverage:authorization:not_covered"
            for state in before.factor_states
        )
        assert any("control_coverage:authorization:covered" == state for state in after.factor_states)
        assert any(state.startswith("capability:filesystem_write") for state in after.factor_states)
    elif relation == "reduced":
        assert before.result.extent is ExposureExtent.MATERIAL
        assert after.result.extent is ExposureExtent.LIMITED
    elif relation == "became_unknown":
        assert after.result.extent is ExposureExtent.UNKNOWN
        assert ExposureDimension.IDENTITY in after.result.unknown_dimensions
    elif relation == "conflicted":
        assert after.result.extent is ExposureExtent.UNKNOWN
        assert after.result.contradictions
    elif relation == "verification_degraded":
        assert after.result.extent is ExposureExtent.UNKNOWN
        assert ExposureDimension.CAPABILITY in after.result.unknown_dimensions
    elif relation == "exact_block_only":
        assert before.result.extent is after.result.extent
        assert any(state == "ai_action:block:inline" for state in after.factor_states)
    elif relation == "identical":
        assert before.input_digest == after.input_digest
        assert before.output_digest == after.output_digest
    elif relation == "digest_changed":
        assert before.input_digest != after.input_digest
        assert before.output_digest != after.output_digest
    elif relation == "coverage_unknown":
        assert ExposureDimension.CONTROL_COVERAGE in before.result.unknown_dimensions
        assert before.result.extent is ExposureExtent.UNKNOWN
    elif relation == "risk_unchanged":
        assert case["before_risk_score"] != case["after_risk_score"]
        assert before.persisted_risk_scores == (float(case["before_risk_score"]),)
        assert after.persisted_risk_scores == (float(case["after_risk_score"]),)
        assert before.input_digest == after.input_digest
        assert before.output_digest == after.output_digest
    elif relation == "no_persistent_writes":
        assert before.row_counts_before == before.row_counts_after
        assert after.row_counts_before == after.row_counts_after
    else:
        raise AssertionError(f"unsupported expected relation: {relation}")


def test_mandatory_exposure_simulation_pack() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    definitions = fixture["factor_definitions"]
    catalog = load_category_catalog()
    evidence: list[dict[str, object]] = []
    assert len(fixture["cases"]) == 15
    for case in fixture["cases"]:
        case_id = case["case_id"]
        if case["expected"]["relation"] == "hard_rejection":
            db, tenant_id, asset_id = _seed_profile(
                case_id=case_id,
                factor_names=case["before_factors"],
                definitions=definitions,
            )
            try:
                counts_before = _table_counts(db)
                attempted_tenant_id = _uuid(f"{case_id}:wrong-tenant")
                try:
                    ExposureSourceReader().read(
                        db,
                        tenant_id=attempted_tenant_id,
                        asset_id=asset_id,
                        as_of=NOW,
                    )
                except ExposureAssetUnavailable:
                    rejected = True
                else:
                    rejected = False
                assert rejected is True
                assert _table_counts(db) == counts_before
                evidence.append(
                    {
                        "case_id": case_id,
                        "expected": case["expected"],
                        "actual": {"cross_tenant_rejected": True},
                        "tenant_id": tenant_id,
                        "asset_id": asset_id,
                        "source_refs": [
                            f"discovery_asset:{asset_id}",
                            f"tenant_attempt:{attempted_tenant_id}",
                            f"tenant_seed:{tenant_id}",
                        ],
                        "evidence_refs": [
                            f"evidence_node:{_uuid(f'{case_id}:evidence')}"
                        ],
                        "database_write_count": 0,
                    }
                )
            finally:
                engine = db.get_bind()
                db.close()
                engine.dispose()
            continue

        before_risk_score = (
            float(case["before_risk_score"])
            if "before_risk_score" in case
            else None
        )
        after_risk_score = (
            float(case["after_risk_score"])
            if "after_risk_score" in case
            else None
        )
        before = _project(
            case_id=case_id,
            factor_names=case["before_factors"],
            definitions=definitions,
            risk_score=before_risk_score,
        )
        after = _project(
            case_id=case_id,
            factor_names=case["after_factors"],
            definitions=definitions,
            risk_score=after_risk_score,
        )
        _assert_case(case, before, after)
        timeline_actual: dict[str, object] = {}
        required_event = case["expected"].get("required_event")
        if required_event is not None:
            drift = compare_exposure_states(
                before=before.result,
                after=after.result,
                before_factors=before.factors,
                after_factors=after.factors,
                source_event_refs=(f"simulation_case:{case_id}",),
                occurred_at=NOW,
            )
            entry = build_timeline_entry(drift=drift, rule_version=RULE_VERSION)
            assert entry.event_type.value == required_event
            timeline_actual = {
                "timeline_event_type": entry.event_type.value,
                "timeline_event_id": entry.event_id,
                "timeline_changed_factors": list(entry.changed_factors),
            }
        missing_identity_actual: dict[str, object] = {}
        if case_id == "identity-verifiably-removed":
            missing = _project(
                case_id=f"{case_id}:missing",
                factor_names=[
                    name
                    for name in case["before_factors"]
                    if name != "identity_primary"
                ],
                definitions=definitions,
            )
            assert missing.result.extent is ExposureExtent.UNKNOWN
            assert ExposureDimension.IDENTITY in missing.result.unknown_dimensions
            missing_identity_actual = {
                "missing_identity_extent": missing.result.extent.value,
                "missing_identity_is_not_removal": True,
            }
        evidence.append(
            {
                "case_id": case_id,
                "expected": case["expected"],
                "actual": {
                    "before_extent": before.result.extent.value,
                    "after_extent": after.result.extent.value,
                    "before_input_digest": before.input_digest,
                    "after_input_digest": after.input_digest,
                    "before_output_digest": before.output_digest,
                    "after_output_digest": after.output_digest,
                    "before_reasoning_trace": list(before.result.reasoning_trace),
                    "after_reasoning_trace": list(after.result.reasoning_trace),
                    "before_persisted_risk_scores": list(before.persisted_risk_scores),
                    "after_persisted_risk_scores": list(after.persisted_risk_scores),
                    **timeline_actual,
                    **missing_identity_actual,
                },
                "source_refs": sorted(set(before.source_refs + after.source_refs)),
                "evidence_refs": sorted(set(before.evidence_refs + after.evidence_refs)),
                "database_write_count": 0,
            }
        )

    assert all(item.get("source_refs") for item in evidence)
    assert all(item.get("evidence_refs") for item in evidence)
    assert all(
        all(":" in reference for reference in item["source_refs"])
        for item in evidence
    )
    artifact = {
        "schema_version": "1.1.0",
        "as_of": NOW.isoformat(),
        "review_authority": "gpt-5.6-sol-extra-high",
        "sol_verdict": _artifact_sol_verdict(),
        "category_catalog_version": catalog.version,
        "category_catalog_digest": catalog.digest,
        "reasoning_rule_version": RULE_VERSION,
        "cases": evidence,
        "mandatory_cases": "all_passed",
        "persistent_exposure_writes": 0,
    }
    output = os.environ.get("HAWK_EXPOSURE_SIMULATION_OUTPUT")
    if output:
        Path(output).write_text(
            json.dumps(artifact, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    assert len(evidence) == 15
    assert all(item["database_write_count"] == 0 for item in evidence)
