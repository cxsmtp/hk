"""Tenant-scoped Control Coverage calculation and snapshot persistence."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Iterable, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.control_coverage import (
    DEFAULT_CONTROL_COVERAGE_WINDOW_DAYS,
    METHODOLOGY_VERSION,
    PHASE5_METHODOLOGY_VERSION,
    CoverageDimension,
    CoverageState,
    Phase5CoverageDimension,
)
from app.db.models.activity_audit import AIAction
from app.db.models.action_integrity import (
    ApprovalBindingV2Extension,
    DecisionReceiptV2Extension,
    DelegationContextV2,
    ExecutionComparisonV2,
    ExecutionPermitAttemptV2,
    ExecutionPermitV2,
    ExecutionReceiptV2Extension,
    ExpectedOutcomeV2,
    OutcomeVerificationV2,
    PersistentEffectV2,
)
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    ControlCoverageSnapshot,
    DeploymentSurface,
)
from app.db.models.evidence import DecisionReceipt, ExecutionReceipt
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.control_coverage.assertion_evaluators import PathEvidence, evaluate_all, evaluate_phase5_all
from app.services.control_coverage.calculator import AssertionView, CoverageSummary, summarize_assertions
from app.services.control_coverage.deployment_family_projection import (
    SURFACE_PROJECTION_WATERMARK_KEY,
    deployment_family_surface_projection_digest,
)
from app.services.control_coverage.deployment_surfaces import reconcile_deployment_surfaces
from app.services.control_coverage.path_projection import (
    PathCandidate,
    ai_action_candidate,
    runtime_event_candidate,
    upsert_path,
)
from app.services.control_coverage.source_resolution import (
    surface_for_action,
    surface_for_event,
    surface_indexes,
)
from app.services.receipt_service import verify_decision_receipt, verify_execution_receipt
from app.services.action_integrity.approval_binding import BINDING_DOMAIN
from app.services.action_integrity.canonical_v2 import canonical_action_hash_v2
from app.services.action_integrity.delegation_lifecycle import fresh_delegation_context_fold
from app.services.action_integrity.execution_authority import ExecutionPermitAuthority, PERMIT_DOMAIN
from app.services.action_integrity.execution_proof import (
    EXECUTION_COMPARISON_DOMAIN,
    EXECUTION_RECEIPT_DOMAIN,
)
from app.services.action_integrity.lifecycle_persistence import (
    DECISION_RECEIPT_DOMAIN,
    EFFECT_DOMAIN,
    EXPECTED_OUTCOME_DOMAIN,
    OUTCOME_DOMAIN,
)
from app.services.action_integrity.signing import verify_signed_object


EVALUATOR_VERSION = "control-coverage-evaluator/1.0"
CURRENT_EVIDENCE_TTL = timedelta(hours=24)
MAX_ASSERTION_EVIDENCE_REFS = 20
VALIDATED_BYPASS_OBSERVATION_KEY = "hawk_validated_bypass_observation"
PERSISTENT_EFFECT_SIGNING_PURPOSE = "persistent_effect_signing"
OUTCOME_VERIFICATION_SIGNING_PURPOSE = "outcome_verification_signing"
EXPECTED_OUTCOME_SIGNING_PURPOSE = "outcome_verification_signing"


@dataclass(frozen=True)
class ControlCoverageCalculation:
    snapshot: ControlCoverageSnapshot
    paths: tuple[ControlCoveragePath, ...]
    assertions: tuple[ControlCoverageAssertion, ...]
    summary: CoverageSummary


@dataclass
class _ObservedPath:
    path: ControlCoveragePath
    candidate: PathCandidate
    observed_at: datetime
    surface: DeploymentSurface | None
    control_modes: set[str]
    evidence_refs: set[str]
    discovery_current: bool = True
    confirmed_unmanaged: bool = False
    identity_verified: bool = False
    identity_confirmed_unbound: bool = False
    execution_observed: bool = True
    decision_receipt_verified: bool = False
    execution_evidence_verified: bool = False
    runtime_confirmed_unmanaged: bool = False
    bypass_detector_operational: bool = False
    bypass_observed: bool = False
    conflicting: bool = False
    source_missing: bool = False
    action_ids: set[str] | None = None


@dataclass
class _Phase5ActionEvidence:
    applicable: bool = False
    subject_binding_verified: bool = False
    resource_binding_verified: bool = False
    purpose_binding_verified: bool = False
    authority_binding_verified: bool = False
    parameter_binding_verified: bool = False
    target_binding_verified: bool = False
    destination_binding_verified: bool = False
    approval_binding_verified: bool = False
    approval_binding_not_applicable: bool = False
    execution_visibility_verified: bool = False
    execution_verification_verified: bool = False
    execution_verification_failed: bool = False
    persistence_tracking_verified: bool = False
    persistence_tracking_failed: bool = False
    persistence_tracking_not_applicable: bool = False
    delegation_integrity_verified: bool = False
    delegation_integrity_failed: bool = False
    delegation_integrity_not_applicable: bool = False
    outcome_verification_verified: bool = False
    outcome_verification_failed: bool = False
    outcome_verification_not_applicable: bool = False
    conflicting: bool = False
    evidence_refs: set[str] | None = None

    def __post_init__(self) -> None:
        if self.evidence_refs is None:
            self.evidence_refs = set()


@dataclass(frozen=True)
class Phase5ActionAssuranceEvidence:
    """Minimal public Phase 5 proof projection consumed by Phase 6.

    The projection is deliberately derived by the same signature, permit-fold,
    tenant and material-binding checks used by Control Coverage.  Phase 6 does
    not create a second receipt-verification implementation.
    """

    action_id: str
    decision_verified: bool
    execution_visible: bool
    execution_matched: bool
    execution_failed: bool
    outcome_verified: bool
    evidence_refs: tuple[str, ...]


def phase5_action_assurance_evidence(
    db: Session,
    *,
    tenant_id: str,
    action_id: str,
    now: datetime,
) -> Phase5ActionAssuranceEvidence:
    row = _phase5_action_evidence(
        db,
        tenant_id=tenant_id,
        action_ids={action_id},
        now=now,
    ).get(action_id)
    if row is None:
        return Phase5ActionAssuranceEvidence(
            action_id=action_id,
            decision_verified=False,
            execution_visible=False,
            execution_matched=False,
            execution_failed=False,
            outcome_verified=False,
            evidence_refs=(),
        )
    return Phase5ActionAssuranceEvidence(
        action_id=action_id,
        decision_verified=row.applicable and not row.conflicting,
        execution_visible=row.execution_visibility_verified,
        execution_matched=row.execution_verification_verified,
        execution_failed=row.execution_verification_failed,
        outcome_verified=row.outcome_verification_verified,
        evidence_refs=tuple(sorted(row.evidence_refs or ())),
    )


def _aggregate_phase5_action_evidence(
    *,
    action_ids: set[str],
    by_action: Mapping[str, _Phase5ActionEvidence],
) -> dict[Phase5CoverageDimension, CoverageState]:
    """Aggregate V2 proof per action without path-wide success precedence.

    A dimension is covered only when every applicable action has that proof.
    A signed failure always wins.  N/A actions are excluded from the covered
    set and yield N/A only when every observed action proves N/A.
    """
    values = [by_action.get(action_id) for action_id in action_ids]

    def state(
        covered: str,
        *,
        failed: str | None = None,
        not_applicable: str | None = None,
    ) -> CoverageState:
        if not values or any(value is None or not value.applicable for value in values):
            return CoverageState.UNKNOWN
        concrete = [value for value in values if value is not None]
        if failed is not None and any(bool(getattr(value, failed)) for value in concrete):
            return CoverageState.NOT_COVERED
        applicable = (
            [value for value in concrete if not bool(getattr(value, not_applicable))]
            if not_applicable is not None
            else concrete
        )
        if not applicable:
            return CoverageState.NOT_APPLICABLE
        if all(bool(getattr(value, covered)) for value in applicable):
            return CoverageState.COVERED
        return CoverageState.UNKNOWN

    return {
        Phase5CoverageDimension.SUBJECT_BINDING: state("subject_binding_verified"),
        Phase5CoverageDimension.RESOURCE_BINDING: state("resource_binding_verified"),
        Phase5CoverageDimension.PURPOSE_BINDING: state("purpose_binding_verified"),
        Phase5CoverageDimension.AUTHORITY_BINDING: state("authority_binding_verified"),
        Phase5CoverageDimension.PARAMETER_BINDING: state("parameter_binding_verified"),
        Phase5CoverageDimension.TARGET_BINDING: state("target_binding_verified"),
        Phase5CoverageDimension.DESTINATION_BINDING: state("destination_binding_verified"),
        Phase5CoverageDimension.APPROVAL_BINDING: state(
            "approval_binding_verified", not_applicable="approval_binding_not_applicable"
        ),
        Phase5CoverageDimension.EXECUTION_VISIBILITY: state("execution_visibility_verified"),
        Phase5CoverageDimension.EXECUTION_VERIFICATION: state(
            "execution_verification_verified", failed="execution_verification_failed"
        ),
        Phase5CoverageDimension.PERSISTENCE_TRACKING: state(
            "persistence_tracking_verified",
            failed="persistence_tracking_failed",
            not_applicable="persistence_tracking_not_applicable",
        ),
        Phase5CoverageDimension.DELEGATION_INTEGRITY: state(
            "delegation_integrity_verified",
            failed="delegation_integrity_failed",
            not_applicable="delegation_integrity_not_applicable",
        ),
        Phase5CoverageDimension.OUTCOME_VERIFICATION: state(
            "outcome_verification_verified",
            failed="outcome_verification_failed",
            not_applicable="outcome_verification_not_applicable",
        ),
    }


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _same_signed_instant(persisted: datetime | None, signed: object) -> bool:
    if persisted is None or not isinstance(signed, str):
        return False
    try:
        parsed = datetime.fromisoformat(signed.replace("Z", "+00:00"))
    except ValueError:
        return False
    return _utc(persisted) == _utc(parsed)


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _truthy(metadata: Mapping[str, Any], *keys: str) -> bool:
    return any(metadata.get(key) is True for key in keys)


def _control_mode(metadata: Mapping[str, Any]) -> str:
    canonical = _mapping(metadata.get("canonical_ai_action_v1"))
    canonical_policy = _mapping(canonical.get("policy"))
    ai_action = _mapping(metadata.get("ai_action"))
    ai_action_policy = _mapping(ai_action.get("policy"))
    return str(
        canonical_policy.get("control_mode")
        or ai_action_policy.get("control_mode")
        or metadata.get("control_mode")
        or "unknown"
    ).strip().lower()


def _latest_marker(rows: Iterable[tuple[datetime, str]]) -> str:
    values = list(rows)
    if not values:
        return "none"
    return max(values, key=lambda item: (_utc(item[0]), item[1]))[1]


def _safe_verify_decision(db: Session, *, tenant_id: str, receipt: DecisionReceipt, now: datetime) -> bool:
    try:
        return verify_decision_receipt(
            receipt,
            tenant_id=tenant_id,
            settings_obj=settings,
            now=now,
            db=db,
        )
    except (TypeError, ValueError):
        return False


def _safe_verify_execution(*, tenant_id: str, receipt: ExecutionReceipt) -> bool:
    try:
        return verify_execution_receipt(receipt, tenant_id=tenant_id, settings_obj=settings)
    except (TypeError, ValueError):
        return False


def _merge_observation(
    observed: dict[str, _ObservedPath],
    *,
    path: ControlCoveragePath,
    candidate: PathCandidate,
    observed_at: datetime,
    surface: DeploymentSurface | None,
    metadata: Mapping[str, Any],
    event_type: str,
    action_id: str,
) -> _ObservedPath:
    current = observed.get(path.id)
    mode = _control_mode(metadata)
    if current is None:
        current = _ObservedPath(
            path=path,
            candidate=candidate,
            observed_at=observed_at,
            surface=surface,
            control_modes={mode},
            evidence_refs={candidate.source_ref},
            action_ids={action_id},
        )
        observed[path.id] = current
    else:
        current.observed_at = max(_utc(current.observed_at), _utc(observed_at))
        current.control_modes.add(mode)
        current.evidence_refs.add(candidate.source_ref)
        if current.surface is None:
            current.surface = surface
        if current.action_ids is None:
            current.action_ids = set()
        current.action_ids.add(action_id)

    current.confirmed_unmanaged = current.confirmed_unmanaged or _truthy(
        metadata, "confirmed_unmanaged", "unmanaged_path_confirmed"
    )
    validated_bypass_observation = bool(
        metadata.get(VALIDATED_BYPASS_OBSERVATION_KEY) is True
        and metadata.get("gateway_bypass_detected") is True
        and metadata.get("gateway_routed") is False
        and str(metadata.get("enforcement_path") or "").strip() == "observed_unprotected_route"
        and str(metadata.get("control_mode") or "").strip() == "post_execution"
        and list(metadata.get("triggered_controls") or []) == ["SHADOW_AI_DETECTION"]
        and str(metadata.get("reason_code") or "").strip()
        in {
            "unprotected_llm_route_observed",
            "unprotected_mcp_route_observed",
        }
    )
    identity_is_verified = (
        str(metadata.get("identity_binding_state") or "").strip()
        == "authenticated_self"
        if validated_bypass_observation
        else candidate.identity_type != "unknown"
    )
    current.identity_verified = current.identity_verified or identity_is_verified
    current.identity_confirmed_unbound = current.identity_confirmed_unbound or _truthy(
        metadata, "identity_confirmed_unbound", "anonymous_activity_confirmed"
    )
    current.runtime_confirmed_unmanaged = current.runtime_confirmed_unmanaged or _truthy(
        metadata, "runtime_confirmed_unmanaged", "unmanaged_runtime_confirmed"
    )
    current.bypass_detector_operational = (
        current.bypass_detector_operational or validated_bypass_observation
    )
    current.bypass_observed = current.bypass_observed or validated_bypass_observation
    source_managed_observation = metadata.get("activity_audit_managed_by_source") is True
    if not source_managed_observation:
        current.bypass_observed = current.bypass_observed or _truthy(
            metadata, "bypass_observed", "bypass_confirmed"
        )
        current.bypass_observed = (
            current.bypass_observed
            or "bypass" in str(event_type or "").strip().lower()
        )
    current.conflicting = current.conflicting or _truthy(metadata, "coverage_evidence_conflicting")
    return current


def _verified_phase5_row(
    db: Session,
    *,
    row: Any,
    purpose: str,
    domain: str,
    tenant_id: str,
    current_authority: bool = False,
) -> bool:
    """Verify a durable V2 row before it can affect coverage.

    V2 coverage is a product projection, never a second authority source.  A
    stored row without the injected signer, a valid signature, and an envelope
    matching the durable identifiers remains Unknown.
    """
    provider = db.info.get("phase5_signing_provider")
    envelope = dict(getattr(row, "signed_envelope", {}) or {})
    if provider is None or not envelope:
        return False
    try:
        valid = verify_signed_object(
            provider,
            purpose=purpose,
            domain=domain,
            tenant_id=tenant_id,
            value=envelope,
            current_authority=current_authority,
        )
    except (KeyError, TypeError, ValueError):
        return False
    if not valid:
        return False
    if envelope.get("tenant_id") != tenant_id:
        return False
    for field in (
        "receipt_id",
        "approval_request_id",
        "binding_id",
        "attempt_id",
        "permit_id",
        "action_id",
        "canonical_action_hash",
        "material_fields_hash",
        "actual_material_fields_hash",
        "control_plan_digest",
        "policy_epoch",
        "result",
        "terminal_state",
        "state",
        "verification_id",
        "outcome_contract_id",
    ):
        persisted = getattr(row, field, None)
        if persisted is not None and field in envelope and envelope[field] != persisted:
            return False
    return (
        envelope.get("algorithm") == getattr(row, "algorithm", None)
        and envelope.get("signing_key_id") == getattr(row, "signing_key_id", None)
        and envelope.get("signature") == getattr(row, "signature", None)
    )


def _verified_phase5_permit(
    db: Session,
    *,
    permit: ExecutionPermitV2,
    decision: DecisionReceiptV2Extension,
    tenant_id: str,
) -> ExecutionPermitAttemptV2 | None:
    """Return the exact persisted attempt only for current signed authority.

    Coverage reuses the authoritative signed fold and rejects any
    permit/attempt mismatch rather than projecting a plausible action chain.
    """
    if not _verified_phase5_row(
        db,
        row=permit,
        purpose="execution_permit_signing",
        domain=PERMIT_DOMAIN,
        tenant_id=tenant_id,
        current_authority=True,
    ):
        return None
    envelope = dict(permit.signed_envelope or {})
    if not (
        permit.tenant_id == tenant_id
        and permit.action_id == decision.action_id
        and permit.decision_receipt_id == decision.receipt_id
        and permit.canonical_action_hash == decision.canonical_action_hash
        and permit.material_fields_hash == decision.material_fields_hash
        and envelope.get("action_id") == permit.action_id
        and envelope.get("attempt_id") == permit.attempt_id
        and envelope.get("decision_receipt_id") == decision.receipt_id
        and envelope.get("canonical_action_hash") == decision.canonical_action_hash
        and envelope.get("material_fields_hash") == decision.material_fields_hash
        and envelope.get("authoritative_decision") == decision.authoritative_decision
        and envelope.get("authority_status") == decision.authority_status == "CURRENT"
        and permit.authoritative_decision == decision.authoritative_decision
        and permit.policy_epoch == decision.policy_epoch
        and permit.control_plan_digest == decision.control_plan_digest
        and permit.profile_selection_id == decision.profile_selection_id
        and permit.profile_selection_hash == decision.profile_selection_hash
        and permit.control_selection_id == decision.control_selection_id
        and permit.control_plan_id == decision.control_plan_id
        and permit.decision_version == decision.decision_version
        and permit.reconstruction_status == "VERIFIED"
    ):
        return None
    attempt = db.scalar(
        select(ExecutionPermitAttemptV2).where(
            ExecutionPermitAttemptV2.tenant_id == tenant_id,
            ExecutionPermitAttemptV2.attempt_id == permit.attempt_id,
        )
    )
    if attempt is None or not (
        attempt.action_id == permit.action_id
        and attempt.canonical_action_hash == permit.canonical_action_hash
        and attempt.material_fields_hash == permit.material_fields_hash
        and attempt.decision_receipt_id == decision.receipt_id
        and attempt.execution_permit_id == permit.permit_id
    ):
        return None
    original_reconstruction_status = permit.reconstruction_status
    authority = ExecutionPermitAuthority(
        db,
        signing_provider=db.info["phase5_signing_provider"],
    )
    try:
        try:
            fold_valid = authority._fresh_permit_fold(permit)
        except (KeyError, PermissionError, TypeError, ValueError):
            fold_valid = False
    finally:
        # Coverage is a read projection.  The authority fold may mark an
        # invalid in-memory row, but it must not mutate stored authority.
        permit.reconstruction_status = original_reconstruction_status
    if not fold_valid or not (
        permit.state == "CONSUMED"
        and permit.state_version == 2
        and attempt.status == "CONSUMED"
    ):
        return None
    return attempt


def _phase5_action_evidence(
    db: Session,
    *,
    tenant_id: str,
    action_ids: set[str],
    now: datetime,
) -> dict[str, _Phase5ActionEvidence]:
    """Derive V2 coverage only from signed, tenant-scoped durable facts."""
    if not action_ids:
        return {}
    results = {action_id: _Phase5ActionEvidence() for action_id in action_ids}
    decisions = db.scalars(
        select(DecisionReceiptV2Extension).where(
            DecisionReceiptV2Extension.tenant_id == tenant_id,
            DecisionReceiptV2Extension.action_id.in_(action_ids),
        )
    ).all()
    decision_by_receipt: dict[str, tuple[DecisionReceiptV2Extension, Mapping[str, Any]]] = {}
    canonical_hashes_by_action: dict[str, set[str]] = defaultdict(set)
    for row in decisions:
        if not _verified_phase5_row(
            db,
            row=row,
            purpose="decision_receipt_signing",
            domain=DECISION_RECEIPT_DOMAIN,
            tenant_id=tenant_id,
            current_authority=True,
        ):
            continue
        action = row.signed_envelope.get("canonical_action")
        if not isinstance(action, Mapping) or row.action_id not in results:
            continue
        try:
            action_hash_matches = canonical_action_hash_v2(dict(action)) == row.canonical_action_hash
        except (KeyError, TypeError, ValueError):
            action_hash_matches = False
        if (
            not action_hash_matches
            or action.get("tenant_id") != tenant_id
            or action.get("action_id") != row.action_id
            or row.signed_envelope.get("authoritative_decision") != row.authoritative_decision
            or row.signed_envelope.get("authority_status") != row.authority_status
            or row.signed_envelope.get("decision_version") != row.decision_version
            or row.authoritative_decision not in {"ALLOW", "BLOCK", "REQUIRE_APPROVAL"}
            or row.authority_status != "CURRENT"
        ):
            continue
        # The signed canonical action itself is the only evidence used to
        # promote semantic bindings; raw telemetry is deliberately ignored.
        semantics = action.get("action_semantics")
        if not isinstance(semantics, Mapping):
            continue
        value = results[row.action_id]
        value.applicable = True
        canonical_hashes_by_action[row.action_id].add(row.canonical_action_hash)
        value.evidence_refs.add(f"decision_receipt:{row.receipt_id}")
        value.subject_binding_verified = value.subject_binding_verified or bool(
            action.get("represented_subjects") and semantics.get("represented_subject_refs")
        )
        value.resource_binding_verified = value.resource_binding_verified or bool(
            action.get("resource_scopes") and semantics.get("resource_refs")
        )
        value.purpose_binding_verified = value.purpose_binding_verified or bool(
            action.get("business_purpose") and semantics.get("business_purpose_ref")
        )
        value.authority_binding_verified = value.authority_binding_verified or bool(
            action.get("authority_context") and semantics.get("authority_ref")
        )
        value.parameter_binding_verified = value.parameter_binding_verified or isinstance(
            semantics.get("safe_parameters"), Mapping
        )
        value.target_binding_verified = value.target_binding_verified or bool(semantics.get("target_refs"))
        value.destination_binding_verified = value.destination_binding_verified or bool(
            semantics.get("destination_refs")
        )
        requirement = str(action.get("approval_requirement") or "").strip().lower()
        value.approval_binding_not_applicable = value.approval_binding_not_applicable or requirement == "not_required"
        persistence = str(semantics.get("persistence") or "").strip().lower()
        value.persistence_tracking_not_applicable = value.persistence_tracking_not_applicable or persistence == "none"
        value.delegation_integrity_not_applicable = value.delegation_integrity_not_applicable or not bool(
            action.get("parent_action_id")
        )
        value.outcome_verification_not_applicable = value.outcome_verification_not_applicable or not bool(
            semantics.get("expected_outcome_ref")
        )
        decision_by_receipt[row.receipt_id] = (row, action)

    for action_id, hashes in canonical_hashes_by_action.items():
        if len(hashes) > 1:
            results[action_id].conflicting = True

    approval_rows = db.scalars(
        select(ApprovalBindingV2Extension).where(ApprovalBindingV2Extension.tenant_id == tenant_id)
    ).all()
    for row in approval_rows:
        decision = decision_by_receipt.get(str(row.decision_receipt_id or ""))
        if decision is None or not _verified_phase5_row(
            db,
            row=row,
            purpose="approval_binding_signing",
            domain=BINDING_DOMAIN,
            tenant_id=tenant_id,
            current_authority=True,
        ):
            continue
        decision_row, action = decision
        action_id = decision_row.action_id
        if (
            row.canonical_action_hash != decision_row.canonical_action_hash
            or row.signed_envelope.get("approval_binding_id") != row.binding_id
            or row.signed_envelope.get("decision_receipt_id") != row.decision_receipt_id
            or row.control_selection_id != decision_row.control_selection_id
            or row.signed_envelope.get("control_selection_id") != decision_row.control_selection_id
        ):
            continue
        result = results[action_id]
        result.approval_binding_verified = True
        result.evidence_refs.add(f"evidence:phase5:approval_binding:{row.binding_id}")

    executions = db.scalars(
        select(ExecutionReceiptV2Extension).where(ExecutionReceiptV2Extension.tenant_id == tenant_id)
    ).all()
    execution_chain_by_attempt: dict[str, tuple[str, ExecutionPermitV2, ExecutionReceiptV2Extension]] = {}
    for row in executions:
        if not _verified_phase5_row(
            db,
            row=row,
            purpose="execution_receipt_signing",
            domain=EXECUTION_RECEIPT_DOMAIN,
            tenant_id=tenant_id,
        ):
            continue
        permit_id = str(row.permit_id or "")
        if not permit_id:
            continue
        permit = db.scalar(
            select(ExecutionPermitV2).where(
                ExecutionPermitV2.tenant_id == tenant_id,
                ExecutionPermitV2.permit_id == permit_id,
            )
        )
        if permit is None or not permit.decision_receipt_id:
            continue
        decision = decision_by_receipt.get(permit.decision_receipt_id)
        if decision is None:
            continue
        decision_row, _action = decision
        attempt = _verified_phase5_permit(
            db, permit=permit, decision=decision_row, tenant_id=tenant_id
        )
        action_id = decision_row.action_id
        if (
            action_id not in results
            or attempt is None
            or row.attempt_id != permit.attempt_id
            or row.permit_id != permit.permit_id
            or row.canonical_action_hash != permit.canonical_action_hash
            or row.signed_envelope.get("receipt_id") != row.receipt_id
            or row.signed_envelope.get("attempt_id") != permit.attempt_id
            or row.signed_envelope.get("permit_id") != permit.permit_id
            or row.signed_envelope.get("canonical_action_hash") != permit.canonical_action_hash
            or row.terminal_state not in {"EXECUTED", "PARTIALLY_EXECUTED", "FAILED", "BLOCKED"}
        ):
            continue
        result = results[action_id]
        result.execution_visibility_verified = True
        result.evidence_refs.add(f"execution_receipt:{row.receipt_id}")
        execution_chain_by_attempt[row.attempt_id] = (action_id, permit, row)

    comparisons = db.scalars(
        select(ExecutionComparisonV2).where(ExecutionComparisonV2.tenant_id == tenant_id)
    ).all()
    for row in comparisons:
        chain = execution_chain_by_attempt.get(row.attempt_id)
        if chain is None or not _verified_phase5_row(
            db,
            row=row,
            purpose="execution_comparison_signing",
            domain=EXECUTION_COMPARISON_DOMAIN,
            tenant_id=tenant_id,
        ):
            continue
        action_id, permit, execution = chain
        envelope = dict(row.signed_envelope or {})
        if not (
            row.decision_receipt_id == permit.decision_receipt_id
            and row.execution_receipt_id == execution.receipt_id
            and envelope.get("comparison_id") == row.id
            and envelope.get("attempt_id") == permit.attempt_id
            and envelope.get("canonical_action_hash") == permit.canonical_action_hash
            and envelope.get("material_fields_hash") == permit.material_fields_hash
            and envelope.get("result") == row.result
            and envelope.get("drift_fields") == row.material_differences
            and envelope.get("unresolved_fields") == row.unresolved_fields
        ):
            continue
        result = results[action_id]
        if (
            row.result in {"MATCHED", "SEMANTICALLY_MATCHED"}
            and not row.unresolved_fields
            and not row.material_differences
            and execution.actual_material_fields_hash == permit.material_fields_hash
        ):
            result.execution_verification_verified = True
        elif row.result in {"DRIFTED", "FAILED", "PARTIAL"}:
            result.execution_verification_failed = True
        result.evidence_refs.add(f"evidence:phase5:execution_comparison:{row.id}")

    effects = db.scalars(
        select(PersistentEffectV2).where(
            PersistentEffectV2.tenant_id == tenant_id,
            PersistentEffectV2.action_id.in_(action_ids),
        )
    ).all()
    for row in effects:
        chain = execution_chain_by_attempt.get(row.attempt_id)
        if chain is None:
            continue
        action_id, _permit, execution = chain
        if not _verified_phase5_row(
            db,
            row=row,
            purpose=PERSISTENT_EFFECT_SIGNING_PURPOSE,
            domain=EFFECT_DOMAIN,
            tenant_id=tenant_id,
        ):
            continue
        if not (
            row.action_id == action_id
            and row.execution_receipt_id == execution.receipt_id
            and row.signed_envelope.get("effect_id") == row.id
            and row.signed_envelope.get("attempt_id") == row.attempt_id
            and row.signed_envelope.get("execution_receipt_id") == execution.receipt_id
            and row.expires_at > now
        ):
            continue
        result = results[action_id]
        if row.state in {"UNKNOWN", "ORPHANED"}:
            result.persistence_tracking_failed = True
        else:
            result.persistence_tracking_verified = True
        result.evidence_refs.add(f"evidence:phase5:persistent_effect:{row.id}")

    outcomes = db.scalars(
        select(OutcomeVerificationV2).where(
            OutcomeVerificationV2.tenant_id == tenant_id,
            OutcomeVerificationV2.action_id.in_(action_ids),
        )
    ).all()
    expected_outcomes = {
        row.outcome_contract_id: row
        for row in db.scalars(
            select(ExpectedOutcomeV2).where(
                ExpectedOutcomeV2.tenant_id == tenant_id,
                ExpectedOutcomeV2.action_id.in_(action_ids),
            )
        ).all()
        if _verified_phase5_row(
            db,
            row=row,
            purpose=EXPECTED_OUTCOME_SIGNING_PURPOSE,
            domain=EXPECTED_OUTCOME_DOMAIN,
            tenant_id=tenant_id,
        )
        and row.signed_envelope.get("outcome_contract_id") == row.outcome_contract_id
        and row.signed_envelope.get("action_id") == row.action_id
    }
    for row in outcomes:
        chain = execution_chain_by_attempt.get(row.attempt_id)
        expected = expected_outcomes.get(row.outcome_contract_id)
        if chain is None or expected is None:
            continue
        action_id, _permit, execution = chain
        if not _verified_phase5_row(
            db,
            row=row,
            purpose=OUTCOME_VERIFICATION_SIGNING_PURPOSE,
            domain=OUTCOME_DOMAIN,
            tenant_id=tenant_id,
        ):
            continue
        if not (
            row.action_id == action_id == expected.action_id
            and row.id == row.verification_id
            and row.execution_receipt_id == execution.receipt_id
            and row.signed_envelope.get("verification_id") == row.verification_id
            and row.signed_envelope.get("attempt_id") == row.attempt_id
            and row.signed_envelope.get("outcome_contract_id") == expected.outcome_contract_id
            and row.signed_envelope.get("execution_receipt_id") == execution.receipt_id
            and row.signed_envelope.get("verification_source_set_hash")
            == row.verification_source_set_hash
            and row.signed_envelope.get("evidence_quality") == row.evidence_quality
            and _same_signed_instant(row.evaluated_at, row.signed_envelope.get("evaluated_at"))
            and not (row.result == "SATISFIED" and row.evidence_quality == "PROVIDER_REPORTED")
        ):
            continue
        result = results[action_id]
        if row.result == "SATISFIED":
            result.outcome_verification_verified = True
        elif row.result in {"VIOLATED", "PARTIAL"}:
            result.outcome_verification_failed = True
        result.evidence_refs.add(f"evidence:phase5:outcome_verification:{row.verification_id}")

    provider = db.info.get("phase5_signing_provider")
    contexts = db.scalars(
        select(DelegationContextV2).where(
            DelegationContextV2.tenant_id == tenant_id,
            DelegationContextV2.delegated_action_id.in_(action_ids),
        )
    ).all()
    for row in contexts:
        result = results[row.delegated_action_id]
        if provider is None:
            continue
        try:
            fold = fresh_delegation_context_fold(db, provider=provider, context=row)
            valid = fold.state == "ACTIVE" and row.expires_at > now
        except (KeyError, PermissionError, TypeError, ValueError):
            valid = False
        if valid:
            result.delegation_integrity_verified = True
            result.evidence_refs.add(f"evidence:phase5:delegation_context:{row.delegation_context_id}")
        else:
            result.delegation_integrity_failed = True
    return results


def _path_evidence(
    item: _ObservedPath,
    *,
    now: datetime,
    phase5_by_action: Mapping[str, _Phase5ActionEvidence] | None = None,
) -> PathEvidence:
    surface = item.surface
    profile = dict(surface.capability_profile or {}) if surface is not None else {}
    inline = profile.get("inline_authorization") == "yes"
    containment = profile.get("containment") in {"surface", "end_to_end"}
    monitor_only = bool(
        surface is not None
        and (
            surface.deployment_mode == "monitor_only"
            or (profile.get("inline_authorization") == "no" and profile.get("containment") == "none")
        )
    )
    runtime_known = not item.candidate.runtime_ref.startswith("unknown_runtime:")
    modes = {mode for mode in item.control_modes if mode != "unknown"}
    conflicting_modes = len(modes) > 1
    control_mode = next(iter(modes)) if len(modes) == 1 else "unknown"
    observed_at = _utc(item.observed_at)
    valid_until = observed_at + CURRENT_EVIDENCE_TTL
    phase5 = _Phase5ActionEvidence()
    for action_id in item.action_ids or set():
        value = (phase5_by_action or {}).get(action_id)
        if value is None:
            continue
        for field in (
            "subject_binding_verified", "resource_binding_verified", "purpose_binding_verified",
            "authority_binding_verified", "parameter_binding_verified", "target_binding_verified",
            "destination_binding_verified", "approval_binding_verified", "approval_binding_not_applicable",
            "execution_visibility_verified", "execution_verification_verified", "execution_verification_failed",
            "persistence_tracking_verified", "persistence_tracking_failed", "persistence_tracking_not_applicable",
            "delegation_integrity_verified", "delegation_integrity_failed", "delegation_integrity_not_applicable",
            "outcome_verification_verified", "outcome_verification_failed", "outcome_verification_not_applicable",
        ):
            setattr(phase5, field, bool(getattr(phase5, field) or getattr(value, field)))
        phase5.conflicting = phase5.conflicting or value.conflicting
        phase5.evidence_refs.update(value.evidence_refs or set())
    phase5_dimension_states = _aggregate_phase5_action_evidence(
        action_ids=set(item.action_ids or set()),
        by_action=phase5_by_action or {},
    )
    return PathEvidence(
        discovery_current=item.discovery_current,
        confirmed_unmanaged=item.confirmed_unmanaged,
        identity_verified=item.identity_verified,
        identity_confirmed_unbound=item.identity_confirmed_unbound,
        execution_observed=item.execution_observed,
        control_mode=control_mode,
        decision_receipt_verified=item.decision_receipt_verified,
        execution_evidence_verified=item.execution_evidence_verified,
        surface_mapped=surface is not None,
        surface_health=surface.health_status if surface is not None else "unknown",
        surface_control_capable=inline or containment,
        surface_monitor_only=monitor_only,
        runtime_known=runtime_known,
        runtime_governed=runtime_known and profile.get("runtime_governance") == "supported",
        runtime_confirmed_unmanaged=item.runtime_confirmed_unmanaged,
        bypass_detector_operational=(
            item.bypass_detector_operational
            or profile.get("bypass_detection") == "supported"
        ),
        bypass_observed=item.bypass_observed,
        conflicting=item.conflicting or conflicting_modes,
        stale=item.source_missing or _utc(now) > valid_until,
        subject_binding_verified=phase5.subject_binding_verified,
        resource_binding_verified=phase5.resource_binding_verified,
        purpose_binding_verified=phase5.purpose_binding_verified,
        authority_binding_verified=phase5.authority_binding_verified,
        parameter_binding_verified=phase5.parameter_binding_verified,
        target_binding_verified=phase5.target_binding_verified,
        destination_binding_verified=phase5.destination_binding_verified,
        approval_binding_verified=phase5.approval_binding_verified,
        approval_binding_not_applicable=phase5.approval_binding_not_applicable,
        execution_visibility_verified=phase5.execution_visibility_verified,
        execution_verification_verified=phase5.execution_verification_verified,
        execution_verification_failed=phase5.execution_verification_failed,
        persistence_tracking_verified=phase5.persistence_tracking_verified,
        persistence_tracking_failed=phase5.persistence_tracking_failed,
        persistence_tracking_not_applicable=phase5.persistence_tracking_not_applicable,
        delegation_integrity_verified=phase5.delegation_integrity_verified,
        delegation_integrity_failed=phase5.delegation_integrity_failed,
        delegation_integrity_not_applicable=phase5.delegation_integrity_not_applicable,
        outcome_verification_verified=phase5.outcome_verification_verified,
        outcome_verification_failed=phase5.outcome_verification_failed,
        outcome_verification_not_applicable=phase5.outcome_verification_not_applicable,
        phase5_conflicting=phase5.conflicting,
        phase5_dimension_states=phase5_dimension_states,
        evidence_refs=tuple(sorted(item.evidence_refs | phase5.evidence_refs))[:MAX_ASSERTION_EVIDENCE_REFS],
        observed_at=observed_at,
        valid_until=valid_until,
    )


def _upsert_assertion(
    db: Session,
    *,
    tenant_id: str,
    path: ControlCoveragePath,
    dimension: CoverageDimension | Phase5CoverageDimension,
    evidence: PathEvidence,
    now: datetime,
    methodology_version: str,
) -> ControlCoverageAssertion:
    result = (evaluate_phase5_all(evidence) if methodology_version == PHASE5_METHODOLOGY_VERSION else evaluate_all(evidence))[dimension]
    row = db.scalar(
        select(ControlCoverageAssertion).where(
            ControlCoverageAssertion.tenant_id == tenant_id,
            ControlCoverageAssertion.path_id == path.id,
            ControlCoverageAssertion.dimension == dimension.value,
            ControlCoverageAssertion.methodology_version == methodology_version,
        )
    )
    watermark_material = json.dumps(list(result.evidence_refs), separators=(",", ":"))
    source_watermark = hashlib.sha256(watermark_material.encode("utf-8")).hexdigest()
    if row is None:
        row = ControlCoverageAssertion(
            tenant_id=tenant_id,
            path_id=path.id,
            dimension=dimension.value,
            methodology_version=methodology_version,
        )
        db.add(row)
    row.state = result.state.value
    row.reason_code = result.reason.value
    row.explanation = result.explanation
    row.evaluator_version = EVALUATOR_VERSION
    row.evidence_refs = list(result.evidence_refs)
    row.source_watermark = source_watermark
    row.observed_at = result.observed_at or evidence.observed_at or now
    row.evaluated_at = now
    row.valid_until = result.valid_until
    db.flush()
    return row


def _assertion_view(path: ControlCoveragePath, assertion: ControlCoverageAssertion) -> AssertionView:
    return AssertionView(
        assertion_id=assertion.id,
        path_id=path.id,
        asset_ref=path.asset_ref,
        identity_ref=path.identity_ref,
        runtime_ref=path.runtime_ref,
        deployment_surface_ref=path.deployment_surface_ref,
        dimension=assertion.dimension,
        state=assertion.state,
    )


def _snapshot_digest(
    *,
    watermarks: Mapping[str, str],
    paths: Iterable[ControlCoveragePath],
    assertions: Iterable[ControlCoverageAssertion],
) -> str:
    material = {
        "watermarks": dict(sorted(watermarks.items())),
        "paths": sorted(path.path_key for path in paths),
        "assertions": sorted(
            (row.path_id, row.dimension, row.state, row.reason_code, row.source_watermark) for row in assertions
        ),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def calculate_tenant_control_coverage(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
    window_days: int = DEFAULT_CONTROL_COVERAGE_WINDOW_DAYS,
    methodology_version: str = METHODOLOGY_VERSION,
) -> ControlCoverageCalculation:
    if not 1 <= window_days <= 90:
        raise ValueError("window_days must be between 1 and 90")
    if methodology_version not in {METHODOLOGY_VERSION, PHASE5_METHODOLOGY_VERSION}:
        raise ValueError("unknown control coverage methodology version")
    dimensions = Phase5CoverageDimension if methodology_version == PHASE5_METHODOLOGY_VERSION else CoverageDimension
    current = _utc(now)
    window_start = current - timedelta(days=window_days)

    surfaces = reconcile_deployment_surfaces(db, tenant_id=tenant_id, now=current)
    by_surface_id, by_surface_source = surface_indexes(surfaces)
    events = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.created_at >= window_start,
            RuntimeEvent.created_at <= current,
        )
        .order_by(RuntimeEvent.created_at, RuntimeEvent.event_id)
    ).all()
    actions = db.scalars(
        select(AIAction)
        .where(
            AIAction.tenant_id == tenant_id,
            AIAction.timestamp >= window_start,
            AIAction.timestamp <= current,
        )
        .order_by(AIAction.timestamp, AIAction.action_id)
    ).all()

    action_ids = {event.event_id for event in events} | {action.action_id for action in actions}
    decisions = (
        db.scalars(
            select(DecisionReceipt).where(
                DecisionReceipt.tenant_id == tenant_id,
                DecisionReceipt.action_id.in_(action_ids),
            )
        ).all()
        if action_ids
        else []
    )
    executions = (
        db.scalars(
            select(ExecutionReceipt).where(
                ExecutionReceipt.tenant_id == tenant_id,
                ExecutionReceipt.action_id.in_(action_ids),
            )
        ).all()
        if action_ids
        else []
    )
    decisions_by_action: dict[str, list[DecisionReceipt]] = defaultdict(list)
    executions_by_action: dict[str, list[ExecutionReceipt]] = defaultdict(list)
    for receipt in decisions:
        decisions_by_action[receipt.action_id].append(receipt)
    for receipt in executions:
        executions_by_action[receipt.action_id].append(receipt)

    observed: dict[str, _ObservedPath] = {}
    for event in events:
        surface = surface_for_event(
            event,
            by_id=by_surface_id,
            by_source=by_surface_source,
        )
        candidate = runtime_event_candidate(event, deployment_surface=surface)
        path = upsert_path(db, tenant_id=tenant_id, candidate=candidate, observed_at=_utc(event.created_at))
        item = _merge_observation(
            observed,
            path=path,
            candidate=candidate,
            observed_at=_utc(event.created_at),
            surface=surface,
            metadata=_mapping(event.metadata_json),
            event_type=event.event_type,
            action_id=event.event_id,
        )
        for receipt in decisions_by_action.get(event.event_id, []):
            item.evidence_refs.add(f"decision_receipt:{receipt.receipt_id}")
            verified = _safe_verify_decision(db, tenant_id=tenant_id, receipt=receipt, now=current)
            item.decision_receipt_verified = item.decision_receipt_verified or verified
            item.conflicting = item.conflicting or not verified
            if verified:
                item.control_modes.add(str(receipt.control_mode).strip().lower())
        for receipt in executions_by_action.get(event.event_id, []):
            item.evidence_refs.add(f"execution_receipt:{receipt.receipt_id}")
            verified = _safe_verify_execution(tenant_id=tenant_id, receipt=receipt)
            item.execution_evidence_verified = item.execution_evidence_verified or verified
            item.conflicting = item.conflicting or not verified

    for action in actions:
        surface = surface_for_action(action, by_source=by_surface_source)
        candidate = ai_action_candidate(action, deployment_surface=surface)
        path = upsert_path(db, tenant_id=tenant_id, candidate=candidate, observed_at=_utc(action.timestamp))
        item = _merge_observation(
            observed,
            path=path,
            candidate=candidate,
            observed_at=_utc(action.timestamp),
            surface=surface,
            metadata=_mapping(action.metadata_json),
            event_type=action.action_type,
            action_id=action.action_id,
        )
        for receipt in decisions_by_action.get(action.action_id, []):
            item.evidence_refs.add(f"decision_receipt:{receipt.receipt_id}")
            verified = _safe_verify_decision(db, tenant_id=tenant_id, receipt=receipt, now=current)
            item.decision_receipt_verified = item.decision_receipt_verified or verified
            item.conflicting = item.conflicting or not verified
            if verified:
                item.control_modes.add(str(receipt.control_mode).strip().lower())
        for receipt in executions_by_action.get(action.action_id, []):
            item.evidence_refs.add(f"execution_receipt:{receipt.receipt_id}")
            verified = _safe_verify_execution(tenant_id=tenant_id, receipt=receipt)
            item.execution_evidence_verified = item.execution_evidence_verified or verified
            item.conflicting = item.conflicting or not verified

    observed_path_ids = set(observed)
    retained_paths = db.scalars(
        select(ControlCoveragePath).where(
            ControlCoveragePath.tenant_id == tenant_id,
            ControlCoveragePath.last_seen_at >= window_start,
            ControlCoveragePath.last_seen_at <= current,
        )
    ).all()
    for path in retained_paths:
        if path.id in observed_path_ids:
            continue
        path.lifecycle_status = "source_missing"
        source_refs = {str(item) for item in (path.source_refs or []) if item}
        source_ref = next(iter(sorted(source_refs)), f"runtime_event:source_missing:{path.id}")
        candidate = PathCandidate(
            asset_ref=path.asset_ref,
            identity_type=path.identity_type,
            identity_ref=path.identity_ref,
            runtime_ref=path.runtime_ref,
            deployment_surface_id=path.deployment_surface_id,
            deployment_surface_ref=path.deployment_surface_ref,
            destination_type=path.destination_type,
            destination_ref=path.destination_ref,
            source_ref=source_ref,
        )
        observed[path.id] = _ObservedPath(
            path=path,
            candidate=candidate,
            observed_at=_utc(path.last_seen_at),
            surface=by_surface_id.get(path.deployment_surface_id or ""),
            control_modes={"unknown"},
            evidence_refs=source_refs or {source_ref},
            discovery_current=False,
            execution_observed=False,
            source_missing=True,
        )

    paths = tuple(sorted((item.path for item in observed.values()), key=lambda row: row.path_key))
    phase5_by_action = (
        _phase5_action_evidence(
            db,
            tenant_id=tenant_id,
            action_ids={action_id for item in observed.values() for action_id in (item.action_ids or set())},
            now=current,
        )
        if methodology_version == PHASE5_METHODOLOGY_VERSION
        else {}
    )
    assertion_rows: list[ControlCoverageAssertion] = []
    views: list[AssertionView] = []
    any_stale = False
    for item in sorted(observed.values(), key=lambda value: value.path.path_key):
        evidence = _path_evidence(item, now=current, phase5_by_action=phase5_by_action)
        any_stale = any_stale or evidence.stale
        for dimension in dimensions:
            assertion = _upsert_assertion(
                db,
                tenant_id=tenant_id,
                path=item.path,
                dimension=dimension,
                evidence=evidence,
                now=current,
                methodology_version=methodology_version,
            )
            assertion_rows.append(assertion)
            views.append(_assertion_view(item.path, assertion))

    summary = summarize_assertions(views, dimensions=[dimension.value for dimension in dimensions])
    watermarks = {
        "runtime_event": _latest_marker((_utc(row.created_at), row.event_id) for row in events),
        "ai_action": _latest_marker((_utc(row.timestamp), row.action_id) for row in actions),
        "decision_receipt": _latest_marker((_utc(row.issued_at), row.receipt_id) for row in decisions),
        "execution_receipt": _latest_marker((_utc(row.executed_at), row.receipt_id) for row in executions),
        "deployment_surface": _latest_marker((_utc(row.last_seen_at), row.id) for row in surfaces),
        SURFACE_PROJECTION_WATERMARK_KEY: (
            deployment_family_surface_projection_digest(
                paths=paths,
                surfaces_by_id=by_surface_id,
            )
        ),
    }
    input_digest = _snapshot_digest(watermarks=watermarks, paths=paths, assertions=assertion_rows)
    snapshot = db.scalar(
        select(ControlCoverageSnapshot).where(
            ControlCoverageSnapshot.tenant_id == tenant_id,
            ControlCoverageSnapshot.methodology_version == methodology_version,
            ControlCoverageSnapshot.window_start == window_start,
            ControlCoverageSnapshot.window_end == current,
            ControlCoverageSnapshot.input_digest == input_digest,
        )
    )
    diagnostics = ["no_observed_paths"] if not paths else []
    if snapshot is None:
        snapshot = ControlCoverageSnapshot(
            tenant_id=tenant_id,
            methodology_version=methodology_version,
            window_start=window_start,
            window_end=current,
            input_digest=input_digest,
            headline_counts=summary.headline_counts.as_dict(),
            headline_score=summary.headline_score,
            dimension_summaries=summary.dimensions,
            input_watermarks=watermarks,
            diagnostics=diagnostics,
            freshness_status="stale" if any_stale else "current",
            computed_at=current,
        )
        db.add(snapshot)
        db.flush()

    return ControlCoverageCalculation(
        snapshot=snapshot,
        paths=paths,
        assertions=tuple(assertion_rows),
        summary=summary,
    )
