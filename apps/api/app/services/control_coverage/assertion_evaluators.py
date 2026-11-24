"""Pure, conservative evaluators for each Control Coverage dimension."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Mapping

from app.core.control_coverage import CoverageDimension, CoverageReason, CoverageState, Phase5CoverageDimension


@dataclass(frozen=True)
class AssertionDecision:
    state: CoverageState
    reason: CoverageReason
    explanation: str
    evidence_refs: tuple[str, ...] = ()
    observed_at: datetime | None = None
    valid_until: datetime | None = None


@dataclass(frozen=True)
class PathEvidence:
    discovery_current: bool = False
    confirmed_unmanaged: bool = False
    identity_verified: bool = False
    identity_confirmed_unbound: bool = False
    execution_observed: bool = False
    control_mode: str = "unknown"
    decision_receipt_verified: bool = False
    execution_evidence_verified: bool = False
    surface_mapped: bool = False
    surface_health: str = "unknown"
    surface_control_capable: bool = False
    surface_monitor_only: bool = False
    runtime_known: bool = False
    runtime_governed: bool = False
    runtime_confirmed_unmanaged: bool = False
    bypass_detector_operational: bool = False
    bypass_observed: bool = False
    # V2 dimensions are deliberately independent of legacy discovery and
    # authorization success.  Only the matching verified authority/evidence
    # path may promote one of these fields to covered.
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
    # V1 receipt verification failures are legacy-methodology evidence.  They
    # must not downgrade a separately signed V2 binding.  Only contradictions
    # between valid V2 records affect this methodology.
    phase5_conflicting: bool = False
    # Service calculations supply a conservative per-action aggregation here.
    # The legacy booleans remain for direct evaluator tests and callers that do
    # not yet have durable Phase 5 records.
    phase5_dimension_states: Mapping[Phase5CoverageDimension, CoverageState] | None = None
    stale: bool = False
    evidence_refs: tuple[str, ...] = ()
    observed_at: datetime | None = None
    valid_until: datetime | None = None


EXPLANATIONS = {
    CoverageReason.VERIFIED_DISCOVERY_OBSERVATION: "Current discovery evidence identifies this path.",
    CoverageReason.CONFIRMED_UNMANAGED_PATH: "Current telemetry confirms an unmanaged path.",
    CoverageReason.VERIFIED_IDENTITY_BINDING: "A server-resolved identity is bound to this path.",
    CoverageReason.MISSING_IDENTITY_BINDING: "Observed activity is confirmed unbound or anonymous.",
    CoverageReason.VERIFIED_INLINE_DECISION: "A verified pre-execution Decision Receipt binds this path.",
    CoverageReason.MONITOR_ONLY_SURFACE: "This path is observed but is not inline-authorized by Hawk.",
    CoverageReason.VERIFIED_EXECUTION_EVIDENCE: "Verifiable execution evidence is bound to this path.",
    CoverageReason.MISSING_EXECUTION_PROOF: "Execution was observed without verifiable execution proof.",
    CoverageReason.DEPLOYMENT_SURFACE_ACTIVE: "A healthy control-capable Hawk surface protects this path.",
    CoverageReason.SURFACE_OFFLINE: "The mapped deployment surface cannot currently provide control.",
    CoverageReason.SURFACE_CAPABILITY_UNKNOWN: "Deployment capability or health cannot be verified.",
    CoverageReason.RUNTIME_GOVERNANCE_VERIFIED: "Current evidence binds the runtime to Hawk governance.",
    CoverageReason.RUNTIME_UNMANAGED: "The observed runtime is unmanaged or only passively monitored.",
    CoverageReason.BYPASS_DETECTOR_OPERATIONAL: "Bypass detection is operational for this path.",
    CoverageReason.BYPASS_OBSERVED: "A bypass observation is linked to this path.",
    CoverageReason.INSUFFICIENT_EVIDENCE: "Hawk does not have enough current evidence to verify coverage.",
    CoverageReason.CONFLICTING_EVIDENCE: "Current evidence conflicts, so coverage is unknown.",
    CoverageReason.STALE_EVIDENCE: "The supporting evidence is stale.",
    CoverageReason.VERIFIED_SUBJECT_BINDING: "A signed decision binds the represented subject.",
    CoverageReason.VERIFIED_RESOURCE_BINDING: "A signed decision binds the resource scope.",
    CoverageReason.VERIFIED_PURPOSE_BINDING: "A signed decision binds the business purpose.",
    CoverageReason.VERIFIED_AUTHORITY_BINDING: "A signed decision binds the authority context.",
    CoverageReason.VERIFIED_PARAMETER_BINDING: "A signed decision binds material parameters.",
    CoverageReason.VERIFIED_TARGET_BINDING: "A signed decision binds the target.",
    CoverageReason.VERIFIED_DESTINATION_BINDING: "A signed decision binds the destination.",
    CoverageReason.VERIFIED_APPROVAL_BINDING: "A signed approval binding is attached to the exact decision.",
    CoverageReason.VERIFIED_EXECUTION_VISIBILITY: "A signed execution receipt records the execution attempt.",
    CoverageReason.VERIFIED_EXECUTION_VERIFICATION: "A signed execution comparison verifies the authorized material.",
    CoverageReason.VERIFIED_PERSISTENCE_TRACKING: "A signed persistent-effect record tracks the consequential state.",
    CoverageReason.VERIFIED_DELEGATION_INTEGRITY: "A verified delegation lineage binds the delegated action.",
    CoverageReason.VERIFIED_OUTCOME_VERIFICATION: "A signed outcome verification confirms the expected result.",
    CoverageReason.EXECUTION_VERIFICATION_FAILED: "Signed comparison evidence reports unresolved or drifted execution.",
    CoverageReason.PERSISTENCE_TRACKING_FAILED: "Signed persistent-effect evidence cannot verify the state.",
    CoverageReason.DELEGATION_INTEGRITY_FAILED: "Signed delegation lineage evidence is invalid or no longer eligible.",
    CoverageReason.OUTCOME_VERIFICATION_FAILED: "Signed outcome evidence reports a mismatch or cannot verify the result.",
}


def decision(state: CoverageState, reason: CoverageReason, evidence: PathEvidence) -> AssertionDecision:
    return AssertionDecision(
        state=state,
        reason=reason,
        explanation=EXPLANATIONS[reason],
        evidence_refs=evidence.evidence_refs,
        observed_at=evidence.observed_at,
        valid_until=evidence.valid_until,
    )


def guarded(evidence: PathEvidence) -> AssertionDecision | None:
    if evidence.conflicting:
        return decision(CoverageState.UNKNOWN, CoverageReason.CONFLICTING_EVIDENCE, evidence)
    if evidence.stale:
        return decision(CoverageState.UNKNOWN, CoverageReason.STALE_EVIDENCE, evidence)
    return None


def evaluate_discovery(evidence: PathEvidence) -> AssertionDecision:
    if value := guarded(evidence):
        return value
    if evidence.discovery_current:
        return decision(CoverageState.COVERED, CoverageReason.VERIFIED_DISCOVERY_OBSERVATION, evidence)
    if evidence.confirmed_unmanaged:
        return decision(CoverageState.NOT_COVERED, CoverageReason.CONFIRMED_UNMANAGED_PATH, evidence)
    return decision(CoverageState.UNKNOWN, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)


def evaluate_identity(evidence: PathEvidence) -> AssertionDecision:
    if value := guarded(evidence):
        return value
    if evidence.identity_verified:
        return decision(CoverageState.COVERED, CoverageReason.VERIFIED_IDENTITY_BINDING, evidence)
    if evidence.identity_confirmed_unbound:
        return decision(CoverageState.NOT_COVERED, CoverageReason.MISSING_IDENTITY_BINDING, evidence)
    return decision(CoverageState.UNKNOWN, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)


def evaluate_authorization(evidence: PathEvidence) -> AssertionDecision:
    if value := guarded(evidence):
        return value
    if evidence.decision_receipt_verified and evidence.control_mode.startswith("inline_"):
        return decision(CoverageState.COVERED, CoverageReason.VERIFIED_INLINE_DECISION, evidence)
    if evidence.execution_observed and evidence.control_mode in {
        "telemetry_only",
        "detected_only",
        "external_required",
        "post_execution",
        "monitor_only",
    }:
        return decision(CoverageState.NOT_COVERED, CoverageReason.MONITOR_ONLY_SURFACE, evidence)
    return decision(CoverageState.UNKNOWN, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)


def evaluate_evidence(evidence: PathEvidence) -> AssertionDecision:
    if value := guarded(evidence):
        return value
    if evidence.execution_evidence_verified:
        return decision(CoverageState.COVERED, CoverageReason.VERIFIED_EXECUTION_EVIDENCE, evidence)
    if evidence.execution_observed:
        return decision(CoverageState.NOT_COVERED, CoverageReason.MISSING_EXECUTION_PROOF, evidence)
    return decision(CoverageState.UNKNOWN, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)


def evaluate_deployment(evidence: PathEvidence) -> AssertionDecision:
    if value := guarded(evidence):
        return value
    if evidence.surface_mapped and evidence.surface_health == "healthy" and evidence.surface_control_capable:
        return decision(CoverageState.COVERED, CoverageReason.DEPLOYMENT_SURFACE_ACTIVE, evidence)
    if evidence.surface_mapped and evidence.surface_health in {"offline", "degraded"}:
        return decision(CoverageState.NOT_COVERED, CoverageReason.SURFACE_OFFLINE, evidence)
    if evidence.surface_mapped and evidence.surface_monitor_only:
        return decision(CoverageState.NOT_COVERED, CoverageReason.MONITOR_ONLY_SURFACE, evidence)
    return decision(CoverageState.UNKNOWN, CoverageReason.SURFACE_CAPABILITY_UNKNOWN, evidence)


def evaluate_runtime(evidence: PathEvidence) -> AssertionDecision:
    if value := guarded(evidence):
        return value
    if evidence.runtime_known and evidence.runtime_governed:
        return decision(CoverageState.COVERED, CoverageReason.RUNTIME_GOVERNANCE_VERIFIED, evidence)
    if evidence.runtime_confirmed_unmanaged:
        return decision(CoverageState.NOT_COVERED, CoverageReason.RUNTIME_UNMANAGED, evidence)
    return decision(CoverageState.UNKNOWN, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)


def evaluate_bypass(evidence: PathEvidence) -> AssertionDecision:
    if value := guarded(evidence):
        return value
    if evidence.bypass_detector_operational:
        reason = CoverageReason.BYPASS_OBSERVED if evidence.bypass_observed else CoverageReason.BYPASS_DETECTOR_OPERATIONAL
        return decision(CoverageState.COVERED, reason, evidence)
    if evidence.bypass_observed:
        return decision(CoverageState.NOT_COVERED, CoverageReason.BYPASS_OBSERVED, evidence)
    return decision(CoverageState.UNKNOWN, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)


_EVALUATORS: dict[CoverageDimension, Callable[[PathEvidence], AssertionDecision]] = {
    CoverageDimension.DISCOVERY: evaluate_discovery,
    CoverageDimension.IDENTITY: evaluate_identity,
    CoverageDimension.AUTHORIZATION: evaluate_authorization,
    CoverageDimension.EVIDENCE: evaluate_evidence,
    CoverageDimension.DEPLOYMENT: evaluate_deployment,
    CoverageDimension.RUNTIME: evaluate_runtime,
    CoverageDimension.BYPASS: evaluate_bypass,
}


def evaluate_all(evidence: PathEvidence) -> dict[CoverageDimension, AssertionDecision]:
    return {dimension: evaluator(evidence) for dimension, evaluator in _EVALUATORS.items()}


def evaluate_phase5_all(evidence: PathEvidence) -> dict[Phase5CoverageDimension, AssertionDecision]:
    """Conservative 2.0 union: no V2 dimension is inferred from V1 success."""
    if evidence.phase5_conflicting:
        guarded_value = decision(CoverageState.UNKNOWN, CoverageReason.CONFLICTING_EVIDENCE, evidence)
        return {dimension: guarded_value for dimension in Phase5CoverageDimension}
    if evidence.stale:
        guarded_value = decision(CoverageState.UNKNOWN, CoverageReason.STALE_EVIDENCE, evidence)
        return {dimension: guarded_value for dimension in Phase5CoverageDimension}
    if evidence.phase5_dimension_states is not None:
        covered_reasons = {
            Phase5CoverageDimension.SUBJECT_BINDING: CoverageReason.VERIFIED_SUBJECT_BINDING,
            Phase5CoverageDimension.RESOURCE_BINDING: CoverageReason.VERIFIED_RESOURCE_BINDING,
            Phase5CoverageDimension.PURPOSE_BINDING: CoverageReason.VERIFIED_PURPOSE_BINDING,
            Phase5CoverageDimension.AUTHORITY_BINDING: CoverageReason.VERIFIED_AUTHORITY_BINDING,
            Phase5CoverageDimension.PARAMETER_BINDING: CoverageReason.VERIFIED_PARAMETER_BINDING,
            Phase5CoverageDimension.TARGET_BINDING: CoverageReason.VERIFIED_TARGET_BINDING,
            Phase5CoverageDimension.DESTINATION_BINDING: CoverageReason.VERIFIED_DESTINATION_BINDING,
            Phase5CoverageDimension.APPROVAL_BINDING: CoverageReason.VERIFIED_APPROVAL_BINDING,
            Phase5CoverageDimension.EXECUTION_VISIBILITY: CoverageReason.VERIFIED_EXECUTION_VISIBILITY,
            Phase5CoverageDimension.EXECUTION_VERIFICATION: CoverageReason.VERIFIED_EXECUTION_VERIFICATION,
            Phase5CoverageDimension.PERSISTENCE_TRACKING: CoverageReason.VERIFIED_PERSISTENCE_TRACKING,
            Phase5CoverageDimension.DELEGATION_INTEGRITY: CoverageReason.VERIFIED_DELEGATION_INTEGRITY,
            Phase5CoverageDimension.OUTCOME_VERIFICATION: CoverageReason.VERIFIED_OUTCOME_VERIFICATION,
        }
        failed_reasons = {
            Phase5CoverageDimension.EXECUTION_VERIFICATION: CoverageReason.EXECUTION_VERIFICATION_FAILED,
            Phase5CoverageDimension.PERSISTENCE_TRACKING: CoverageReason.PERSISTENCE_TRACKING_FAILED,
            Phase5CoverageDimension.DELEGATION_INTEGRITY: CoverageReason.DELEGATION_INTEGRITY_FAILED,
            Phase5CoverageDimension.OUTCOME_VERIFICATION: CoverageReason.OUTCOME_VERIFICATION_FAILED,
        }

        def state_decision(dimension: Phase5CoverageDimension) -> AssertionDecision:
            state = evidence.phase5_dimension_states.get(dimension, CoverageState.UNKNOWN)
            reason = (
                covered_reasons[dimension]
                if state is CoverageState.COVERED
                else failed_reasons.get(dimension, CoverageReason.INSUFFICIENT_EVIDENCE)
                if state is CoverageState.NOT_COVERED
                else CoverageReason.INSUFFICIENT_EVIDENCE
            )
            return decision(state, reason, evidence)

        return {
            dimension: state_decision(dimension)
            for dimension in Phase5CoverageDimension
        }
    unknown = decision(CoverageState.UNKNOWN, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)

    def binding(verified: bool, reason: CoverageReason) -> AssertionDecision:
        return decision(CoverageState.COVERED, reason, evidence) if verified else unknown

    def verified_or_failed(
        *,
        verified: bool,
        failed: bool,
        verified_reason: CoverageReason,
        failed_reason: CoverageReason,
        not_applicable: bool = False,
    ) -> AssertionDecision:
        if failed:
            return decision(CoverageState.NOT_COVERED, failed_reason, evidence)
        if verified:
            return decision(CoverageState.COVERED, verified_reason, evidence)
        if not_applicable:
            return decision(CoverageState.NOT_APPLICABLE, CoverageReason.INSUFFICIENT_EVIDENCE, evidence)
        return unknown

    return {
        Phase5CoverageDimension.SUBJECT_BINDING: binding(
            evidence.subject_binding_verified, CoverageReason.VERIFIED_SUBJECT_BINDING
        ),
        Phase5CoverageDimension.RESOURCE_BINDING: binding(
            evidence.resource_binding_verified, CoverageReason.VERIFIED_RESOURCE_BINDING
        ),
        Phase5CoverageDimension.PURPOSE_BINDING: binding(
            evidence.purpose_binding_verified, CoverageReason.VERIFIED_PURPOSE_BINDING
        ),
        Phase5CoverageDimension.AUTHORITY_BINDING: binding(
            evidence.authority_binding_verified, CoverageReason.VERIFIED_AUTHORITY_BINDING
        ),
        Phase5CoverageDimension.PARAMETER_BINDING: binding(
            evidence.parameter_binding_verified, CoverageReason.VERIFIED_PARAMETER_BINDING
        ),
        Phase5CoverageDimension.TARGET_BINDING: binding(
            evidence.target_binding_verified, CoverageReason.VERIFIED_TARGET_BINDING
        ),
        Phase5CoverageDimension.DESTINATION_BINDING: binding(
            evidence.destination_binding_verified, CoverageReason.VERIFIED_DESTINATION_BINDING
        ),
        Phase5CoverageDimension.APPROVAL_BINDING: binding(
            evidence.approval_binding_verified, CoverageReason.VERIFIED_APPROVAL_BINDING
        ) if not evidence.approval_binding_not_applicable else decision(
            CoverageState.NOT_APPLICABLE, CoverageReason.INSUFFICIENT_EVIDENCE, evidence
        ),
        Phase5CoverageDimension.EXECUTION_VISIBILITY: binding(
            evidence.execution_visibility_verified, CoverageReason.VERIFIED_EXECUTION_VISIBILITY
        ),
        Phase5CoverageDimension.EXECUTION_VERIFICATION: verified_or_failed(
            verified=evidence.execution_verification_verified,
            failed=evidence.execution_verification_failed,
            verified_reason=CoverageReason.VERIFIED_EXECUTION_VERIFICATION,
            failed_reason=CoverageReason.EXECUTION_VERIFICATION_FAILED,
        ),
        Phase5CoverageDimension.PERSISTENCE_TRACKING: verified_or_failed(
            verified=evidence.persistence_tracking_verified,
            failed=evidence.persistence_tracking_failed,
            not_applicable=evidence.persistence_tracking_not_applicable,
            verified_reason=CoverageReason.VERIFIED_PERSISTENCE_TRACKING,
            failed_reason=CoverageReason.PERSISTENCE_TRACKING_FAILED,
        ),
        Phase5CoverageDimension.DELEGATION_INTEGRITY: verified_or_failed(
            verified=evidence.delegation_integrity_verified,
            failed=evidence.delegation_integrity_failed,
            not_applicable=evidence.delegation_integrity_not_applicable,
            verified_reason=CoverageReason.VERIFIED_DELEGATION_INTEGRITY,
            failed_reason=CoverageReason.DELEGATION_INTEGRITY_FAILED,
        ),
        Phase5CoverageDimension.OUTCOME_VERIFICATION: verified_or_failed(
            verified=evidence.outcome_verification_verified,
            failed=evidence.outcome_verification_failed,
            not_applicable=evidence.outcome_verification_not_applicable,
            verified_reason=CoverageReason.VERIFIED_OUTCOME_VERIFICATION,
            failed_reason=CoverageReason.OUTCOME_VERIFICATION_FAILED,
        ),
    }
