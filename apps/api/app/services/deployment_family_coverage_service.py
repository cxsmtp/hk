"""Read-only deployment-family coverage projection over current v1 proof."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.control_coverage import (
    METHODOLOGY_VERSION as V1_METHODOLOGY_VERSION,
    CoverageDimension,
)
from app.core.deployment_family_coverage import (
    FAMILY_ORDER,
    ContainmentEvidence,
    DimensionAssertion,
    FamilyCoverageCalculation,
    V1_WATERMARK_KEYS,
    calculate_family_coverage,
    evaluate_containment,
    sanitize_evidence_refs,
    valid_watermark_value,
)
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    ControlCoverageSnapshot,
    DeploymentSurface,
)
from app.db.models.activity_audit import AIAction
from app.db.models.evidence import DecisionReceipt
from app.db.models.evidence import EvidenceNode, ExecutionReceipt
from app.db.models.policy import ApprovalBinding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.control_coverage.deployment_family_projection import (
    SURFACE_PROJECTION_WATERMARK_KEY,
    deployment_family_surface_projection_digest,
)
from app.services.control_coverage.path_projection import (
    ai_action_candidate,
    make_path_key,
    runtime_event_candidate,
)
from app.services.control_coverage.service import _snapshot_digest
from app.services.control_coverage.source_resolution import (
    surface_for_action,
    surface_for_event,
    surface_indexes,
)
from app.services.receipt_service import (
    _approval_binding_hash,
    _approval_material,
    _canonical_material,
    _hash,
    verify_decision_receipt,
    verify_execution_receipt,
)


CURRENT_SNAPSHOT_MAX_AGE = timedelta(minutes=30)
MAX_PATHS = 10_000
MAX_ASSERTIONS = MAX_PATHS * len(CoverageDimension)
MAX_PATH_SOURCE_REFS = 20
MAX_ASSERTION_EVIDENCE_REFS = 20
MAX_SOURCE_IDS = 20_000
MAX_RECEIPTS = 20_000
QUERY_BATCH_SIZE = 500
_V1_DIMENSIONS = tuple(item.value for item in CoverageDimension)
_EXECUTIVE_DIMENSION_MAP = {
    "discovery": "discovery",
    "identity": "identity",
    "authorization": "authorization",
    "evidence": "evidence",
    "bypass": "bypass_detection",
}
_STALE_REASONS = {"stale_evidence"}
_CONFLICT_REASONS = {"conflicting_evidence"}
_CLOSED_STATES = {"covered", "not_covered", "unknown", "not_applicable"}
@dataclass(frozen=True)
class _ResolvedEvidence:
    observation_refs_by_path: Mapping[str, frozenset[str]]
    action_ids_by_path: Mapping[str, frozenset[str]]
    verified_decisions: Mapping[str, DecisionReceipt]
    verified_executions: Mapping[str, ExecutionReceipt]
    diagnostic: str | None = None
    predicates_by_path: Mapping[str, "_PathPredicates"] = field(
        default_factory=dict
    )


@dataclass(frozen=True)
class _PathPredicates:
    discovery_observed: bool = False
    confirmed_unmanaged: bool = False
    identity_resolved: bool = False
    identity_confirmed_unbound: bool = False
    control_modes: frozenset[str] = frozenset()
    execution_observed: bool = False
    bypass_detector_operational: bool = False
    bypass_observed: bool = False


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _empty(
    *,
    calculated_at: datetime,
    diagnostics: Iterable[str],
    input_watermarks: Mapping[str, object] | None = None,
    freshness_status: str = "unknown",
) -> FamilyCoverageCalculation:
    return calculate_family_coverage(
        (),
        calculated_at=calculated_at,
        input_watermarks=input_watermarks or {},
        diagnostics=diagnostics,
        freshness_status=freshness_status,
    )


def _latest_snapshot(
    db: Session,
    *,
    tenant_id: str,
    window_days: int,
) -> tuple[ControlCoverageSnapshot | None, str | None]:
    candidates = db.scalars(
        select(ControlCoverageSnapshot)
        .where(
            ControlCoverageSnapshot.tenant_id == tenant_id,
            ControlCoverageSnapshot.methodology_version
            == V1_METHODOLOGY_VERSION,
        )
        .order_by(
            ControlCoverageSnapshot.computed_at.desc(),
            ControlCoverageSnapshot.id.desc(),
        )
        .limit(100)
    ).all()
    requested = timedelta(days=window_days)
    matching = [
        row
        for row in candidates
        if abs((_utc(row.window_end) - _utc(row.window_start)) - requested)
        < timedelta(microseconds=1)
    ]
    if not matching:
        return None, None
    latest_computed_at = max(_utc(row.computed_at) for row in matching)
    latest = [
        row for row in matching if _utc(row.computed_at) == latest_computed_at
    ]
    proof_keys = {
        (
            row.input_digest,
            _watermark_proof_key(row.input_watermarks),
            _utc(row.window_start).isoformat(),
            _utc(row.window_end).isoformat(),
            row.freshness_status,
        )
        for row in latest
    }
    if len(proof_keys) > 1:
        return None, "snapshot_conflicting"
    return sorted(latest, key=lambda row: row.id)[0], None


def _watermark_proof_key(value: object) -> tuple[tuple[str, str], ...]:
    if type(value) is not dict or not all(
        type(key) is str and type(item) is str
        for key, item in value.items()
    ):
        return (("__invalid__", "__invalid__"),)
    return tuple(sorted(value.items()))


def _snapshot_diagnostic(
    snapshot: ControlCoverageSnapshot,
    *,
    calculated_at: datetime,
) -> str | None:
    computed_at = _utc(snapshot.computed_at)
    derived_watermarks = {
        "control_coverage_snapshot": snapshot.id,
        "control_coverage_input_digest": snapshot.input_digest,
        "control_coverage_computed_at": computed_at.isoformat(),
        "deployment_family_calculated_at": calculated_at.isoformat(),
    }
    if not all(
        valid_watermark_value(key, value)
        for key, value in derived_watermarks.items()
    ):
        return "invalid_control_coverage_watermarks"
    if _utc(snapshot.window_end) != computed_at:
        return "control_coverage_snapshot_incoherent"
    if computed_at > calculated_at or _utc(snapshot.window_end) > calculated_at:
        return "future_control_coverage_snapshot"
    if not _valid_v1_watermarks(snapshot.input_watermarks):
        return "invalid_control_coverage_watermarks"
    if snapshot.freshness_status != "current":
        return "noncurrent_control_coverage_snapshot"
    if calculated_at - computed_at > CURRENT_SNAPSHOT_MAX_AGE:
        return "stale_control_coverage_snapshot"
    return None


def _valid_v1_watermarks(value: object) -> bool:
    if type(value) is not dict or set(value) != V1_WATERMARK_KEYS:
        return False
    return all(
        type(key) is str
        and valid_watermark_value(key, item)
        for key, item in value.items()
    )


def _bounded_safe_refs(
    value: object,
    *,
    maximum: int,
) -> tuple[str, ...] | None:
    if type(value) is not list or len(value) > maximum:
        return None
    if any(type(item) is not str for item in value):
        return None
    refs = tuple(value)
    if len(sanitize_evidence_refs(refs)) != len(set(refs)):
        return None
    if len(set(refs)) != len(refs):
        return None
    return refs


def _source_watermark_matches(assertion: ControlCoverageAssertion) -> bool:
    refs = _bounded_safe_refs(
        assertion.evidence_refs,
        maximum=MAX_ASSERTION_EVIDENCE_REFS,
    )
    if refs is None or type(assertion.source_watermark) is not str:
        return False
    expected = hashlib.sha256(
        json.dumps(list(refs), separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return assertion.source_watermark == expected


def _chunks(values: Iterable[str]) -> Iterable[tuple[str, ...]]:
    ordered = sorted(set(values))
    for start in range(0, len(ordered), QUERY_BATCH_SIZE):
        yield tuple(ordered[start : start + QUERY_BATCH_SIZE])


def _source_metadata(row: RuntimeEvent | AIAction) -> Mapping[str, object]:
    return row.metadata_json if isinstance(row.metadata_json, Mapping) else {}


def _source_control_mode(metadata: Mapping[str, object]) -> str:
    canonical = (
        metadata.get("canonical_ai_action_v1")
        if isinstance(metadata.get("canonical_ai_action_v1"), Mapping)
        else {}
    )
    canonical_policy = (
        canonical.get("policy")
        if isinstance(canonical.get("policy"), Mapping)
        else {}
    )
    ai_action = (
        metadata.get("ai_action")
        if isinstance(metadata.get("ai_action"), Mapping)
        else {}
    )
    ai_action_policy = (
        ai_action.get("policy")
        if isinstance(ai_action.get("policy"), Mapping)
        else {}
    )
    value = (
        canonical_policy.get("control_mode")
        or ai_action_policy.get("control_mode")
        or metadata.get("control_mode")
        or "unknown"
    )
    return value.strip().lower() if type(value) is str else "unknown"


def _validated_bypass_observation(
    metadata: Mapping[str, object],
) -> bool:
    return bool(
        metadata.get("hawk_validated_bypass_observation") is True
        and metadata.get("gateway_bypass_detected") is True
        and metadata.get("gateway_routed") is False
        and metadata.get("enforcement_path") == "observed_unprotected_route"
        and metadata.get("control_mode") == "post_execution"
        and metadata.get("triggered_controls")
        == ["SHADOW_AI_DETECTION"]
        and metadata.get("reason_code")
        in {
            "unprotected_llm_route_observed",
            "unprotected_mcp_route_observed",
        }
    )


def _assertion_flags(
    assertion: ControlCoverageAssertion,
    *,
    calculated_at: datetime,
) -> tuple[bool, bool]:
    reason = (
        assertion.reason_code
        if type(assertion.reason_code) is str
        else "__invalid__"
    )
    state = (
        assertion.state if type(assertion.state) is str else "__invalid__"
    )
    stale = (
        reason in _STALE_REASONS
        or assertion.valid_until is None
        or _utc(assertion.valid_until) <= calculated_at
    )
    conflicting = (
        reason in _CONFLICT_REASONS
        or _utc(assertion.observed_at) > calculated_at
        or _utc(assertion.evaluated_at) > calculated_at
        or state not in _CLOSED_STATES
    )
    return stale, conflicting


def _effective_v1_assertion(
    assertion: ControlCoverageAssertion | None,
    *,
    family: str,
    path_id: str,
    dimension: str,
    calculated_at: datetime,
    proof_valid: bool,
) -> DimensionAssertion:
    if assertion is None:
        return DimensionAssertion(
            path_id=path_id,
            family=family,
            dimension=dimension,
            state="unknown",
            conflicting=True,
        )
    stale, conflicting = _assertion_flags(
        assertion,
        calculated_at=calculated_at,
    )
    state = (
        assertion.state if type(assertion.state) is str else "__invalid__"
    )
    refs = sanitize_evidence_refs(assertion.evidence_refs or ())
    if state not in _CLOSED_STATES or stale or conflicting:
        state = "unknown"
    if state in {"covered", "not_covered"} and (not refs or not proof_valid):
        state = "unknown"
    return DimensionAssertion(
        path_id=path_id,
        family=family,
        dimension=dimension,
        state=state,
        evidence_refs=refs,
        # Current v1 assertions do not persist a trustworthy path-level
        # partial/metadata-only quality marker, so this service never invents low.
        evidence_quality="verified",
        stale=stale,
        conflicting=conflicting,
    )


def _receipt_ids(assertion: ControlCoverageAssertion | None) -> frozenset[str]:
    if assertion is None:
        return frozenset()
    return frozenset(
        ref.removeprefix("decision_receipt:")
        for ref in sanitize_evidence_refs(assertion.evidence_refs or ())
        if ref.startswith("decision_receipt:")
        and len(ref) > len("decision_receipt:")
    )


def _verified_decision_evidence(
    *,
    tenant_id: str,
    receipt: DecisionReceipt,
    canonical_node: EvidenceNode | None,
    approval_binding: ApprovalBinding | None,
    calculated_at: datetime,
) -> bool:
    try:
        signature_valid = verify_decision_receipt(
            receipt,
            tenant_id=tenant_id,
            settings_obj=settings,
            now=calculated_at,
            db=None,
        )
    except (TypeError, ValueError):
        return False
    if not signature_valid or canonical_node is None:
        return False
    payload = (
        canonical_node.payload
        if type(canonical_node.payload) is dict
        else {}
    )
    canonical_payload = payload.get("canonical_action")
    if not isinstance(canonical_payload, Mapping):
        return False
    try:
        canonical_material = _canonical_material(
            canonical_payload,
            tenant_id=tenant_id,
        )
    except (TypeError, ValueError):
        return False
    if (
        payload.get("action_id") != receipt.action_id
        or payload.get("canonical_action_hash")
        != receipt.canonical_action_hash
        or canonical_material["action_id"] != receipt.action_id
        or canonical_material["chain_id"] != receipt.chain_id
        or canonical_material["canonical_action_hash"]
        != receipt.canonical_action_hash
        or canonical_material["actor_hash"] != receipt.actor_hash
        or canonical_material["authority_hash"] != receipt.authority_hash
        or canonical_material["purpose_hash"] != receipt.purpose_hash
        or canonical_material["tool_fingerprint"] != receipt.tool_fingerprint
        or canonical_material["parameter_hash"] != receipt.parameter_hash
        or canonical_material["target_resource_hash"]
        != receipt.target_resource_hash
        or canonical_material["destination_hash"] != receipt.destination_hash
        or canonical_material["side_effect_class"] != receipt.side_effect_class
    ):
        return False
    if receipt.approval_binding_id:
        binding = approval_binding
        if binding is None or type(binding.material_fields) is not dict:
            return False
        try:
            expected_material = _approval_material(canonical_material)
            expected_material_hash = _hash(expected_material)
            expected_binding_hash = _approval_binding_hash(binding)
        except (TypeError, ValueError):
            return False
        if (
            binding.action_id != receipt.action_id
            or binding.chain_id != receipt.chain_id
            or binding.status not in {"active", "used"}
            or (
                binding.expires_at is not None
                and _utc(binding.expires_at) <= calculated_at
            )
            or _utc(receipt.expires_at)
            > (
                _utc(binding.expires_at)
                if binding.expires_at is not None
                else _utc(receipt.expires_at)
            )
            or binding.canonical_action_hash
            != receipt.canonical_action_hash
            or binding.receipt_material_hash
            != expected_material_hash
            or binding.material_fields != expected_material
            or expected_binding_hash != receipt.approval_binding_hash
        ):
            return False
    return True


def _resolve_evidence(
    db: Session,
    *,
    tenant_id: str,
    paths: tuple[ControlCoveragePath, ...],
    surfaces_by_id: Mapping[str, DeploymentSurface],
    surfaces_by_source: Mapping[tuple[str, str], DeploymentSurface],
    assertions: tuple[ControlCoverageAssertion, ...],
    window_start: datetime,
    snapshot_computed_at: datetime,
    calculated_at: datetime,
) -> _ResolvedEvidence:
    runtime_ids: set[str] = set()
    action_ids: set[str] = set()
    source_refs_by_path: dict[str, tuple[str, ...]] = {}
    for path in paths:
        refs = _bounded_safe_refs(
            path.source_refs,
            maximum=MAX_PATH_SOURCE_REFS,
        )
        if refs is None or any(
            not ref.startswith(("runtime_event:", "ai_action:"))
            for ref in refs
        ):
            return _ResolvedEvidence({}, {}, {}, {}, "invalid_path_source_refs")
        source_refs_by_path[path.id] = refs
        for ref in refs:
            prefix, value = ref.split(":", 1)
            if prefix == "runtime_event":
                runtime_ids.add(value)
            else:
                action_ids.add(value)
    if len(runtime_ids) + len(action_ids) > MAX_SOURCE_IDS:
        return _ResolvedEvidence({}, {}, {}, {}, "coverage_processing_limit_exceeded")

    runtime_rows: dict[str, RuntimeEvent] = {}
    for batch in _chunks(runtime_ids):
        runtime_rows.update(
            {
                row.event_id: row
                for row in db.scalars(
                    select(RuntimeEvent).where(
                        RuntimeEvent.tenant_id == tenant_id,
                        RuntimeEvent.event_id.in_(batch),
                    )
                ).all()
            }
        )
    action_rows: dict[str, AIAction] = {}
    for batch in _chunks(action_ids):
        action_rows.update(
            {
                row.action_id: row
                for row in db.scalars(
                    select(AIAction).where(
                        AIAction.tenant_id == tenant_id,
                        AIAction.action_id.in_(batch),
                    )
                ).all()
            }
        )

    observation_refs_by_path: dict[str, frozenset[str]] = {}
    extant_action_ids_by_path: dict[str, frozenset[str]] = {}
    predicates_by_path: dict[str, _PathPredicates] = {}
    for path in paths:
        extant_refs: set[str] = set()
        extant_action_ids: set[str] = set()
        confirmed_unmanaged = False
        identity_resolved = False
        identity_confirmed_unbound = False
        control_modes: set[str] = set()
        bypass_detector_operational = False
        bypass_observed = False
        for ref in source_refs_by_path[path.id]:
            prefix, value = ref.split(":", 1)
            row = (
                runtime_rows.get(value)
                if prefix == "runtime_event"
                else action_rows.get(value)
            )
            observed_at = (
                _utc(row.created_at)
                if isinstance(row, RuntimeEvent)
                else _utc(row.timestamp)
                if isinstance(row, AIAction)
                else None
            )
            if observed_at is None:
                continue
            if observed_at > snapshot_computed_at:
                return _ResolvedEvidence(
                    {},
                    {},
                    {},
                    {},
                    "control_coverage_snapshot_incoherent",
                )
            if _utc(window_start) <= observed_at <= snapshot_computed_at:
                try:
                    source_surface = (
                        surface_for_event(
                            row,
                            by_id=surfaces_by_id,
                            by_source=surfaces_by_source,
                        )
                        if isinstance(row, RuntimeEvent)
                        else surface_for_action(
                            row,
                            by_source=surfaces_by_source,
                        )
                    )
                    resolved_surface_id = (
                        source_surface.id
                        if source_surface is not None
                        else None
                    )
                    if resolved_surface_id != path.deployment_surface_id:
                        return _ResolvedEvidence(
                            {},
                            {},
                            {},
                            {},
                            "control_coverage_snapshot_incoherent",
                        )
                    candidate = (
                        runtime_event_candidate(
                            row,
                            deployment_surface=source_surface,
                        )
                        if isinstance(row, RuntimeEvent)
                        else ai_action_candidate(
                            row,
                            deployment_surface=source_surface,
                        )
                    )
                    candidate_matches = make_path_key(candidate) == path.path_key
                except (TypeError, ValueError):
                    candidate_matches = False
                if not candidate_matches:
                    return _ResolvedEvidence(
                        {},
                        {},
                        {},
                        {},
                        "control_coverage_snapshot_incoherent",
                    )
                extant_refs.add(ref)
                extant_action_ids.add(value)
                metadata = _source_metadata(row)
                validated_bypass = _validated_bypass_observation(metadata)
                confirmed_unmanaged = confirmed_unmanaged or any(
                    metadata.get(key) is True
                    for key in (
                        "confirmed_unmanaged",
                        "unmanaged_path_confirmed",
                    )
                )
                identity_resolved = identity_resolved or (
                    metadata.get("identity_binding_state")
                    == "authenticated_self"
                    if validated_bypass
                    else candidate.identity_type != "unknown"
                )
                identity_confirmed_unbound = (
                    identity_confirmed_unbound
                    or any(
                        metadata.get(key) is True
                        for key in (
                            "identity_confirmed_unbound",
                            "anonymous_activity_confirmed",
                        )
                    )
                )
                control_modes.add(_source_control_mode(metadata))
                bypass_detector_operational = (
                    bypass_detector_operational
                    or validated_bypass
                    or (
                        source_surface is not None
                        and isinstance(
                            source_surface.capability_profile,
                            Mapping,
                        )
                        and source_surface.capability_profile.get(
                            "bypass_detection"
                        )
                        == "supported"
                    )
                )
                source_managed = (
                    metadata.get("activity_audit_managed_by_source") is True
                )
                observed_from_source = validated_bypass
                if not source_managed:
                    observed_from_source = (
                        observed_from_source
                        or any(
                            metadata.get(key) is True
                            for key in (
                                "bypass_observed",
                                "bypass_confirmed",
                            )
                        )
                        or "bypass"
                        in str(
                            row.event_type
                            if isinstance(row, RuntimeEvent)
                            else row.action_type
                        )
                        .strip()
                        .lower()
                    )
                bypass_observed = bypass_observed or observed_from_source
        observation_refs_by_path[path.id] = frozenset(extant_refs)
        extant_action_ids_by_path[path.id] = frozenset(extant_action_ids)
        predicates_by_path[path.id] = _PathPredicates(
            discovery_observed=bool(extant_refs),
            confirmed_unmanaged=confirmed_unmanaged,
            identity_resolved=identity_resolved,
            identity_confirmed_unbound=identity_confirmed_unbound,
            control_modes=frozenset(control_modes),
            execution_observed=bool(extant_refs),
            bypass_detector_operational=bypass_detector_operational,
            bypass_observed=bypass_observed,
        )

    decision_ids: set[str] = set()
    execution_ids: set[str] = set()
    for assertion in assertions:
        refs = _bounded_safe_refs(
            assertion.evidence_refs,
            maximum=MAX_ASSERTION_EVIDENCE_REFS,
        )
        if refs is None:
            return _ResolvedEvidence({}, {}, {}, {}, "invalid_assertion_evidence_refs")
        for ref in refs:
            if ref.startswith("decision_receipt:"):
                decision_ids.add(ref.removeprefix("decision_receipt:"))
            elif ref.startswith("execution_receipt:"):
                execution_ids.add(ref.removeprefix("execution_receipt:"))
    if len(decision_ids) + len(execution_ids) > MAX_RECEIPTS:
        return _ResolvedEvidence({}, {}, {}, {}, "coverage_processing_limit_exceeded")

    decisions: dict[str, DecisionReceipt] = {}
    for batch in _chunks(decision_ids):
        decisions.update(
            {
                row.receipt_id: row
                for row in db.scalars(
                    select(DecisionReceipt).where(
                        DecisionReceipt.tenant_id == tenant_id,
                        DecisionReceipt.receipt_id.in_(batch),
                    )
                ).all()
            }
        )
    executions: dict[str, ExecutionReceipt] = {}
    for batch in _chunks(execution_ids):
        executions.update(
            {
                row.receipt_id: row
                for row in db.scalars(
                    select(ExecutionReceipt).where(
                        ExecutionReceipt.tenant_id == tenant_id,
                        ExecutionReceipt.receipt_id.in_(batch),
                    )
                ).all()
            }
        )
    linked_decision_ids = {
        row.decision_receipt_id for row in executions.values()
    }
    if len(decision_ids | linked_decision_ids) > MAX_RECEIPTS:
        return _ResolvedEvidence({}, {}, {}, {}, "coverage_processing_limit_exceeded")
    missing_decision_ids = linked_decision_ids - set(decisions)
    for batch in _chunks(missing_decision_ids):
        decisions.update(
            {
                row.receipt_id: row
                for row in db.scalars(
                    select(DecisionReceipt).where(
                        DecisionReceipt.tenant_id == tenant_id,
                        DecisionReceipt.receipt_id.in_(batch),
                    )
                ).all()
            }
        )

    if any(
        _utc(row.issued_at) > snapshot_computed_at
        for row in decisions.values()
    ) or any(
        _utc(row.executed_at) > snapshot_computed_at
        for row in executions.values()
    ):
        return _ResolvedEvidence(
            {},
            {},
            {},
            {},
            "control_coverage_snapshot_incoherent",
        )
    node_ids = {
        row.canonical_action_evidence_node_id
        for row in decisions.values()
    }
    binding_ids = {
        row.approval_binding_id
        for row in decisions.values()
        if row.approval_binding_id
    }
    nodes: dict[str, EvidenceNode] = {}
    for batch in _chunks(node_ids):
        nodes.update(
            {
                row.id: row
                for row in db.scalars(
                    select(EvidenceNode).where(
                        EvidenceNode.tenant_id == tenant_id,
                        EvidenceNode.id.in_(batch),
                    )
                ).all()
            }
        )
    bindings: dict[str, ApprovalBinding] = {}
    for batch in _chunks(binding_ids):
        bindings.update(
            {
                row.id: row
                for row in db.scalars(
                    select(ApprovalBinding).where(
                        ApprovalBinding.tenant_id == tenant_id,
                        ApprovalBinding.id.in_(batch),
                    )
                ).all()
            }
        )
    verified_decisions = {
        receipt_id: receipt
        for receipt_id, receipt in decisions.items()
        if _verified_decision_evidence(
            tenant_id=tenant_id,
            receipt=receipt,
            canonical_node=nodes.get(
                receipt.canonical_action_evidence_node_id
            ),
            approval_binding=bindings.get(receipt.approval_binding_id or ""),
            calculated_at=calculated_at,
        )
    }
    verified_executions: dict[str, ExecutionReceipt] = {}
    for receipt_id, receipt in executions.items():
        try:
            verified = verify_execution_receipt(
                receipt,
                tenant_id=tenant_id,
                settings_obj=settings,
            )
        except (TypeError, ValueError):
            verified = False
        if verified:
            verified_executions[receipt_id] = receipt
    return _ResolvedEvidence(
        observation_refs_by_path=observation_refs_by_path,
        action_ids_by_path=extant_action_ids_by_path,
        verified_decisions=verified_decisions,
        verified_executions=verified_executions,
        predicates_by_path=predicates_by_path,
    )


def _closed_family(surface: DeploymentSurface | None) -> str:
    value = surface.deployment_family if surface is not None else "unknown"
    if type(value) is not str:
        return "unknown"
    return value if value in FAMILY_ORDER else "unknown"


def _assertion_refs(
    assertion: ControlCoverageAssertion,
) -> frozenset[str]:
    refs = _bounded_safe_refs(
        assertion.evidence_refs,
        maximum=MAX_ASSERTION_EVIDENCE_REFS,
    )
    return frozenset(refs or ())


def _observation_proven(
    assertion: ControlCoverageAssertion,
    *,
    observation_refs: frozenset[str],
) -> bool:
    return bool(_assertion_refs(assertion) & observation_refs)


def _mapped_assertion_proof_valid(
    assertion: ControlCoverageAssertion,
    *,
    dimension: str,
    observation_refs: frozenset[str],
    action_ids: frozenset[str],
    resolved: _ResolvedEvidence,
) -> bool:
    state = (
        assertion.state if type(assertion.state) is str else "__invalid__"
    )
    reason = (
        assertion.reason_code
        if type(assertion.reason_code) is str
        else "__invalid__"
    )
    if state in {"unknown", "not_applicable"}:
        return True
    predicates = resolved.predicates_by_path.get(
        assertion.path_id,
        _PathPredicates(),
    )
    observation_proven = _observation_proven(
        assertion,
        observation_refs=observation_refs,
    )
    if dimension == "discovery":
        if state == "covered":
            return (
                reason == "verified_discovery_observation"
                and observation_proven
                and predicates.discovery_observed
            )
        if state == "not_covered":
            return (
                reason == "confirmed_unmanaged_path"
                and observation_proven
                and predicates.confirmed_unmanaged
            )
    if dimension == "identity":
        if state == "covered":
            return (
                reason == "verified_identity_binding"
                and observation_proven
                and predicates.identity_resolved
            )
        if state == "not_covered":
            return (
                reason == "missing_identity_binding"
                and observation_proven
                and predicates.identity_confirmed_unbound
                and not predicates.identity_resolved
            )
    if dimension == "authorization" and state == "not_covered":
        effective_modes = {
            mode for mode in predicates.control_modes if mode != "unknown"
        }
        has_verified_inline_receipt = any(
            (
                receipt := resolved.verified_decisions.get(
                    ref.removeprefix("decision_receipt:")
                )
            )
            is not None
            and receipt.action_id in action_ids
            and receipt.control_mode
            in {"inline_allowed", "inline_prevented"}
            for ref in _assertion_refs(assertion)
            if ref.startswith("decision_receipt:")
        )
        return (
            reason == "monitor_only_surface"
            and observation_proven
            and len(effective_modes) == 1
            and bool(
                effective_modes
                & {
                    "telemetry_only",
                    "detected_only",
                    "external_required",
                    "post_execution",
                    "monitor_only",
                }
            )
            and not has_verified_inline_receipt
        )
    if dimension == "evidence" and state == "not_covered":
        return (
            reason == "missing_execution_proof"
            and observation_proven
            and predicates.execution_observed
        )
    if dimension == "bypass":
        if state == "covered":
            return (
                reason
                in {"bypass_detector_operational", "bypass_observed"}
                and observation_proven
                and predicates.bypass_detector_operational
            )
        if state == "not_covered":
            return (
                reason == "bypass_observed"
                and observation_proven
                and predicates.bypass_observed
                and not predicates.bypass_detector_operational
            )
    refs = _assertion_refs(assertion)
    if dimension == "authorization" and state == "covered":
        if reason != "verified_inline_decision":
            return False
        for ref in refs:
            if not ref.startswith("decision_receipt:"):
                continue
            receipt = resolved.verified_decisions.get(
                ref.removeprefix("decision_receipt:")
            )
            if (
                receipt is not None
                and receipt.action_id in action_ids
                and type(receipt.control_mode) is str
                and receipt.control_mode
                in {"inline_allowed", "inline_prevented"}
            ):
                return True
        return False
    if dimension == "evidence" and state == "covered":
        if reason != "verified_execution_evidence":
            return False
        for ref in refs:
            if not ref.startswith("execution_receipt:"):
                continue
            execution = resolved.verified_executions.get(
                ref.removeprefix("execution_receipt:")
            )
            if execution is None or execution.action_id not in action_ids:
                continue
            decision = resolved.verified_decisions.get(
                execution.decision_receipt_id
            )
            if (
                decision is not None
                and decision.action_id == execution.action_id
                and decision.action_id in action_ids
            ):
                return True
        return False
    return False


def _containment_assertion(
    *,
    path: ControlCoveragePath,
    family: str,
    surface: DeploymentSurface | None,
    assertions_by_path_dimension: Mapping[
        tuple[str, str],
        ControlCoverageAssertion,
    ],
    verified_receipt_ids: tuple[str, ...],
    observation_refs: frozenset[str],
    authorization_proof_valid: bool,
    calculated_at: datetime,
) -> DimensionAssertion:
    authorization = assertions_by_path_dimension.get((path.id, "authorization"))
    deployment = assertions_by_path_dimension.get((path.id, "deployment"))
    authorization_stale, authorization_conflicting = (
        _assertion_flags(authorization, calculated_at=calculated_at)
        if authorization is not None
        else (False, False)
    )
    deployment_stale, deployment_conflicting = (
        _assertion_flags(deployment, calculated_at=calculated_at)
        if deployment is not None
        else (False, False)
    )
    auth_state = (
        authorization.state
        if authorization is not None and type(authorization.state) is str
        else ""
    )
    auth_reason = (
        authorization.reason_code
        if authorization is not None
        and type(authorization.reason_code) is str
        else ""
    )
    deployment_state = (
        deployment.state
        if deployment is not None and type(deployment.state) is str
        else ""
    )
    deployment_reason = (
        deployment.reason_code
        if deployment is not None
        and type(deployment.reason_code) is str
        else ""
    )
    refs = sanitize_evidence_refs(
        (
            *(authorization.evidence_refs or () if authorization is not None else ()),
            *(deployment.evidence_refs or () if deployment is not None else ()),
            *(f"decision_receipt:{item}" for item in verified_receipt_ids),
        )
    )
    authorization_observation_proven = bool(
        authorization is not None
        and _observation_proven(
            authorization,
            observation_refs=observation_refs,
        )
    )
    deployment_observation_proven = bool(
        deployment is not None
        and _observation_proven(
            deployment,
            observation_refs=observation_refs,
        )
    )
    result = evaluate_containment(
        ContainmentEvidence(
            capability=(
                surface.containment_capability
                if surface is not None
                else "unknown"
            ),
            health_status=(
                surface.health_status if surface is not None else "unknown"
            ),
            verified_block_inline_prevented=(
                bool(verified_receipt_ids)
                and deployment_state == "covered"
                and deployment_reason == "deployment_surface_active"
                and deployment_observation_proven
                and bool(
                    sanitize_evidence_refs(
                        deployment.evidence_refs or ()
                        if deployment is not None
                        else ()
                    )
                )
            ),
            authorization_monitor_only_proven=(
                auth_state == "not_covered"
                and auth_reason == "monitor_only_surface"
                and authorization_observation_proven
                and authorization_proof_valid
                and bool(
                    sanitize_evidence_refs(
                        authorization.evidence_refs or ()
                        if authorization is not None
                        else ()
                    )
                )
            ),
            deployment_offline_proven=(
                deployment_state == "not_covered"
                and deployment_reason == "surface_offline"
                and deployment_observation_proven
                and bool(
                    sanitize_evidence_refs(
                        deployment.evidence_refs or ()
                        if deployment is not None
                        else ()
                    )
                )
            ),
            evidence_refs=refs,
            stale=authorization_stale or deployment_stale,
            conflicting=authorization_conflicting or deployment_conflicting,
        )
    )
    return DimensionAssertion(
        path_id=path.id,
        family=family,
        dimension="containment",
        state=result.state,
        evidence_refs=result.evidence_refs,
        evidence_quality=result.evidence_quality,
        stale=result.stale,
        conflicting=result.conflicting,
    )


def read_deployment_family_coverage(
    db: Session,
    *,
    tenant_id: str,
    calculated_at: datetime,
    window_days: int,
) -> FamilyCoverageCalculation:
    if not 1 <= window_days <= 90:
        raise ValueError("window_days must be between 1 and 90")
    current = _utc(calculated_at)
    snapshot, selection_diagnostic = _latest_snapshot(
        db,
        tenant_id=tenant_id,
        window_days=window_days,
    )
    if snapshot is None:
        return _empty(
            calculated_at=current,
            diagnostics=(
                selection_diagnostic
                or "missing_current_control_coverage_snapshot",
            ),
        )
    diagnostic = _snapshot_diagnostic(snapshot, calculated_at=current)
    base_watermarks = (
        dict(snapshot.input_watermarks)
        if isinstance(snapshot.input_watermarks, Mapping)
        else {}
    )
    output_watermarks = {
        **base_watermarks,
        "control_coverage_snapshot": snapshot.id,
        "control_coverage_input_digest": snapshot.input_digest,
        "control_coverage_computed_at": _utc(snapshot.computed_at).isoformat(),
        "deployment_family_calculated_at": current.isoformat(),
    }
    recoverable_stale = diagnostic in {
        "noncurrent_control_coverage_snapshot",
        "stale_control_coverage_snapshot",
    }
    if diagnostic is not None and not recoverable_stale:
        return _empty(
            calculated_at=current,
            diagnostics=(diagnostic,),
            input_watermarks=output_watermarks,
        )

    paths = tuple(
        db.scalars(
            select(ControlCoveragePath)
            .where(
                ControlCoveragePath.tenant_id == tenant_id,
                ControlCoveragePath.last_seen_at >= snapshot.window_start,
                ControlCoveragePath.last_seen_at <= snapshot.window_end,
            )
            .order_by(ControlCoveragePath.path_key, ControlCoveragePath.id)
            .limit(MAX_PATHS + 1)
        ).all()
    )
    if len(paths) > MAX_PATHS:
        return _empty(
            calculated_at=current,
            diagnostics=("coverage_processing_limit_exceeded",),
            input_watermarks=output_watermarks,
        )
    snapshot_computed_at = _utc(snapshot.computed_at)
    if any(
        _bounded_safe_refs(
            path.source_refs,
            maximum=MAX_PATH_SOURCE_REFS,
        )
        is None
        for path in paths
    ):
        return _empty(
            calculated_at=current,
            diagnostics=("control_coverage_snapshot_incoherent",),
            input_watermarks=output_watermarks,
        )
    path_ids = tuple(path.id for path in paths)
    assertion_rows: list[ControlCoverageAssertion] = []
    for batch in _chunks(path_ids):
        assertion_rows.extend(
            db.scalars(
                select(ControlCoverageAssertion)
                .where(
                    ControlCoverageAssertion.tenant_id == tenant_id,
                    ControlCoverageAssertion.methodology_version
                    == V1_METHODOLOGY_VERSION,
                    ControlCoverageAssertion.path_id.in_(batch),
                )
                .order_by(
                    ControlCoverageAssertion.path_id,
                    ControlCoverageAssertion.dimension,
                )
            ).all()
        )
        if len(assertion_rows) > MAX_ASSERTIONS:
            break
    assertions = tuple(
        sorted(
            assertion_rows,
            key=lambda row: (row.path_id, row.dimension),
        )
    )
    if len(assertions) > MAX_ASSERTIONS:
        return _empty(
            calculated_at=current,
            diagnostics=("coverage_processing_limit_exceeded",),
            input_watermarks=output_watermarks,
        )
    if any(
        _utc(row.observed_at) > snapshot_computed_at
        or _utc(row.evaluated_at) > snapshot_computed_at
        for row in assertions
    ):
        return _empty(
            calculated_at=current,
            diagnostics=("control_coverage_snapshot_incoherent",),
            input_watermarks=output_watermarks,
        )
    if any(
        _bounded_safe_refs(
            row.evidence_refs,
            maximum=MAX_ASSERTION_EVIDENCE_REFS,
        )
        is None
        for row in assertions
    ):
        return _empty(
            calculated_at=current,
            diagnostics=("invalid_assertion_evidence_refs",),
            input_watermarks=output_watermarks,
        )
    if any(not _source_watermark_matches(row) for row in assertions):
        return _empty(
            calculated_at=current,
            diagnostics=("control_coverage_assertion_watermark_mismatch",),
            input_watermarks=output_watermarks,
        )
    if _snapshot_digest(
        watermarks=base_watermarks,
        paths=paths,
        assertions=assertions,
    ) != snapshot.input_digest:
        return _empty(
            calculated_at=current,
            diagnostics=("control_coverage_input_digest_mismatch",),
            input_watermarks=output_watermarks,
        )
    assertions_by_path_dimension = {
        (row.path_id, row.dimension): row for row in assertions
    }
    expected_assertions = {
        (path.id, dimension)
        for path in paths
        for dimension in _V1_DIMENSIONS
    }
    if expected_assertions != set(assertions_by_path_dimension):
        return _empty(
            calculated_at=current,
            diagnostics=("incomplete_control_coverage_assertions",),
            input_watermarks=output_watermarks,
        )

    surfaces = db.scalars(
        select(DeploymentSurface)
        .where(DeploymentSurface.tenant_id == tenant_id)
        .order_by(DeploymentSurface.id)
        .limit(MAX_PATHS + 1)
    ).all()
    if len(surfaces) > MAX_PATHS:
        return _empty(
            calculated_at=current,
            diagnostics=("coverage_processing_limit_exceeded",),
            input_watermarks=output_watermarks,
    )
    surfaces_by_id, surfaces_by_source = surface_indexes(surfaces)
    if deployment_family_surface_projection_digest(
        paths=paths,
        surfaces_by_id=surfaces_by_id,
    ) != base_watermarks.get(SURFACE_PROJECTION_WATERMARK_KEY):
        return _empty(
            calculated_at=current,
            diagnostics=(
                "deployment_family_surface_projection_mismatch",
            ),
            input_watermarks=output_watermarks,
        )
    if recoverable_stale:
        stale_assertions: list[DimensionAssertion] = []
        for path in paths:
            family = _closed_family(
                surfaces_by_id.get(path.deployment_surface_id or "")
            )
            for v1_dimension, executive_dimension in (
                _EXECUTIVE_DIMENSION_MAP.items()
            ):
                source = assertions_by_path_dimension[
                    (path.id, v1_dimension)
                ]
                stale_assertions.append(
                    DimensionAssertion(
                        path_id=path.id,
                        family=family,
                        dimension=executive_dimension,
                        state=(
                            "not_applicable"
                            if source.state == "not_applicable"
                            else "unknown"
                        ),
                        evidence_refs=sanitize_evidence_refs(
                            source.evidence_refs or ()
                        ),
                        stale=True,
                    )
                )
            stale_assertions.append(
                DimensionAssertion(
                    path_id=path.id,
                    family=family,
                    dimension="containment",
                    state="unknown",
                    stale=True,
                )
            )
        return calculate_family_coverage(
            stale_assertions,
            calculated_at=current,
            input_watermarks=output_watermarks,
            diagnostics=(diagnostic,),
            freshness_status="stale",
        )

    resolved = _resolve_evidence(
        db,
        tenant_id=tenant_id,
        paths=paths,
        surfaces_by_id=surfaces_by_id,
        surfaces_by_source=surfaces_by_source,
        assertions=assertions,
        window_start=_utc(snapshot.window_start),
        snapshot_computed_at=snapshot_computed_at,
        calculated_at=current,
    )
    if resolved.diagnostic is not None:
        return _empty(
            calculated_at=current,
            diagnostics=(resolved.diagnostic,),
            input_watermarks=output_watermarks,
        )

    executive_assertions: list[DimensionAssertion] = []
    for path in paths:
        surface = surfaces_by_id.get(path.deployment_surface_id or "")
        family = _closed_family(surface)
        observation_refs = resolved.observation_refs_by_path.get(
            path.id,
            frozenset(),
        )
        action_ids = resolved.action_ids_by_path.get(path.id, frozenset())
        proof_valid_by_dimension: dict[str, bool] = {}
        for v1_dimension, executive_dimension in _EXECUTIVE_DIMENSION_MAP.items():
            source_assertion = assertions_by_path_dimension.get(
                (path.id, v1_dimension)
            )
            proof_valid = (
                _mapped_assertion_proof_valid(
                    source_assertion,
                    dimension=v1_dimension,
                    observation_refs=observation_refs,
                    action_ids=action_ids,
                    resolved=resolved,
                )
                if source_assertion is not None
                else False
            )
            proof_valid_by_dimension[v1_dimension] = proof_valid
            executive_assertions.append(
                _effective_v1_assertion(
                    source_assertion,
                    family=family,
                    path_id=path.id,
                    dimension=executive_dimension,
                    calculated_at=current,
                    proof_valid=proof_valid,
                )
            )
        authorization = assertions_by_path_dimension.get(
            (path.id, "authorization")
        )
        verified_block_receipt_ids = tuple(
            sorted(
                receipt_id
                for receipt_id in _receipt_ids(authorization)
                if (
                    authorization is not None
                    and authorization.state == "covered"
                    and authorization.reason_code
                    == "verified_inline_decision"
                    and proof_valid_by_dimension.get("authorization") is True
                    and
                    (receipt := resolved.verified_decisions.get(receipt_id))
                    is not None
                    and receipt.action_id in action_ids
                    and type(receipt.decision) is str
                    and receipt.decision == "block"
                    and type(receipt.control_mode) is str
                    and receipt.control_mode == "inline_prevented"
                )
            )
        )
        executive_assertions.append(
            _containment_assertion(
                path=path,
                family=family,
                surface=surface,
                assertions_by_path_dimension=assertions_by_path_dimension,
                verified_receipt_ids=verified_block_receipt_ids,
                observation_refs=observation_refs,
                authorization_proof_valid=proof_valid_by_dimension.get(
                    "authorization",
                    False,
                ),
                calculated_at=current,
            )
        )
    return calculate_family_coverage(
        executive_assertions,
        calculated_at=current,
        input_watermarks=output_watermarks,
        diagnostics=(),
    )


__all__ = ["read_deployment_family_coverage"]
