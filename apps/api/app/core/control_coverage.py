from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


METHODOLOGY_VERSION = "control-coverage/1.0"
PHASE5_METHODOLOGY_VERSION = "control-coverage/2.0"
PHASE8_METHODOLOGY_VERSION = "control-coverage/3.0"
DEFAULT_CONTROL_COVERAGE_WINDOW_DAYS = 30

# These extend the existing methodology rather than creating a second coverage
# engine. V1 snapshots retain their original seven dimensions and version.
PHASE5_V2_DIMENSIONS = (
    "subject_binding",
    "resource_binding",
    "purpose_binding",
    "authority_binding",
    "parameter_binding",
    "target_binding",
    "destination_binding",
    "approval_binding",
    "execution_visibility",
    "execution_verification",
    "persistence_tracking",
    "delegation_integrity",
    "outcome_verification",
)


class CoverageDimension(StrEnum):
    DISCOVERY = "discovery"
    IDENTITY = "identity"
    AUTHORIZATION = "authorization"
    EVIDENCE = "evidence"
    DEPLOYMENT = "deployment"
    RUNTIME = "runtime"
    BYPASS = "bypass"


class Phase5CoverageDimension(StrEnum):
    SUBJECT_BINDING = "subject_binding"
    RESOURCE_BINDING = "resource_binding"
    PURPOSE_BINDING = "purpose_binding"
    AUTHORITY_BINDING = "authority_binding"
    PARAMETER_BINDING = "parameter_binding"
    TARGET_BINDING = "target_binding"
    DESTINATION_BINDING = "destination_binding"
    APPROVAL_BINDING = "approval_binding"
    EXECUTION_VISIBILITY = "execution_visibility"
    EXECUTION_VERIFICATION = "execution_verification"
    PERSISTENCE_TRACKING = "persistence_tracking"
    DELEGATION_INTEGRITY = "delegation_integrity"
    OUTCOME_VERIFICATION = "outcome_verification"


class CoverageState(StrEnum):
    COVERED = "covered"
    NOT_COVERED = "not_covered"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class CoverageApplicability(StrEnum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class CoverageDeployment(StrEnum):
    PRESENT = "present"
    CONFIGURED = "configured"
    MISSING = "missing"
    UNKNOWN = "unknown"


class CoverageCapability(StrEnum):
    VERIFIED = "verified"
    PARTIAL = "partial"
    UNVERIFIED = "unverified"
    EXPERIMENTAL = "experimental"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class CoverageAssurance(StrEnum):
    CURRENT = "current"
    STALE = "stale"
    REGRESSED = "regressed"
    UNKNOWN = "unknown"


class ExecutiveCoverageState(StrEnum):
    COVERED_CURRENT = "covered_current"
    COVERED_STALE = "covered_stale"
    PARTIALLY_COVERED = "partially_covered"
    CONFIGURED_UNVALIDATED = "configured_unvalidated"
    REGRESSED = "regressed"
    GAP = "gap"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class ExecutiveCoverageFacts:
    """Orthogonal, evidence-backed facts used to derive one coverage state."""

    applicability: CoverageApplicability
    deployment: CoverageDeployment
    capability: CoverageCapability
    assurance: CoverageAssurance
    evidence_quality: str
    evidence_refs: tuple[str, ...]
    expected_control_points: tuple[str, ...]
    contributing_control_points: tuple[str, ...]
    missing_contributions: tuple[str, ...]
    bypass_reachable: bool
    compensating_bypass_control: bool
    previously_validated: bool
    unresolved_regression: bool


@dataclass(frozen=True)
class ExecutiveCoverageDerivation:
    state: ExecutiveCoverageState
    reason_code: str
    explanation: str


def derive_executive_coverage(facts: ExecutiveCoverageFacts) -> ExecutiveCoverageDerivation:
    """Derive coverage without allowing configuration or old evidence to become green."""

    if facts.applicability is CoverageApplicability.NOT_APPLICABLE:
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.NOT_APPLICABLE,
            "requirement_not_applicable",
            "The scoped action semantics explicitly make this control requirement not applicable.",
        )
    if facts.applicability is CoverageApplicability.UNKNOWN:
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.UNKNOWN,
            "applicability_unknown",
            "Available evidence cannot determine whether this control requirement applies.",
        )
    if facts.assurance is CoverageAssurance.REGRESSED or facts.unresolved_regression:
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.REGRESSED,
            "validation_regressed",
            "Current revalidation evidence shows that the previously expected control property no longer holds.",
        )
    if facts.capability is CoverageCapability.UNSUPPORTED:
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.UNSUPPORTED,
            "capability_unsupported",
            "Available control points cannot provide the required capability on this action path.",
        )
    if facts.deployment is CoverageDeployment.MISSING:
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.GAP,
            "applicable_control_missing",
            "The requirement applies, but no required control point is deployed for this action path.",
        )
    if facts.bypass_reachable and not facts.compensating_bypass_control:
        state = (
            ExecutiveCoverageState.PARTIALLY_COVERED
            if facts.contributing_control_points
            else ExecutiveCoverageState.GAP
        )
        return ExecutiveCoverageDerivation(
            state,
            "reachable_bypass_uncontrolled",
            "A reachable route avoids the expected control and no verified compensating control closes that path.",
        )
    if facts.capability is CoverageCapability.PARTIAL or facts.missing_contributions:
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.PARTIALLY_COVERED,
            "composed_control_incomplete",
            "At least one required control contribution is verified, but the composed control plan remains incomplete.",
        )
    if (
        facts.capability is CoverageCapability.VERIFIED
        and facts.assurance is CoverageAssurance.STALE
        and facts.previously_validated
    ):
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.COVERED_STALE,
            "validation_stale",
            "The property was previously validated, but current evidence is outside its assurance window or affected by drift.",
        )
    if (
        facts.deployment is CoverageDeployment.CONFIGURED
        and facts.capability is CoverageCapability.VERIFIED
        and facts.assurance is CoverageAssurance.CURRENT
        and bool(facts.evidence_refs)
        and set(facts.expected_control_points).issubset(facts.contributing_control_points)
    ):
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.COVERED_CURRENT,
            "current_verified_control",
            "The applicable property has a configured capable control, current validation, and supporting evidence.",
        )
    if facts.deployment in {CoverageDeployment.PRESENT, CoverageDeployment.CONFIGURED}:
        return ExecutiveCoverageDerivation(
            ExecutiveCoverageState.CONFIGURED_UNVALIDATED,
            "configured_without_current_validation",
            "A control is present or configured, but sufficient current validation evidence does not exist.",
        )
    return ExecutiveCoverageDerivation(
        ExecutiveCoverageState.UNKNOWN,
        "coverage_truth_unknown",
        "Available evidence is insufficient to determine deployment, capability, or current assurance.",
    )


class CoverageReason(StrEnum):
    VERIFIED_DISCOVERY_OBSERVATION = "verified_discovery_observation"
    CONFIRMED_UNMANAGED_PATH = "confirmed_unmanaged_path"
    VERIFIED_IDENTITY_BINDING = "verified_identity_binding"
    MISSING_IDENTITY_BINDING = "missing_identity_binding"
    VERIFIED_INLINE_DECISION = "verified_inline_decision"
    MONITOR_ONLY_SURFACE = "monitor_only_surface"
    VERIFIED_EXECUTION_EVIDENCE = "verified_execution_evidence"
    MISSING_EXECUTION_PROOF = "missing_execution_proof"
    DEPLOYMENT_SURFACE_ACTIVE = "deployment_surface_active"
    SURFACE_OFFLINE = "surface_offline"
    SURFACE_CAPABILITY_UNKNOWN = "surface_capability_unknown"
    RUNTIME_GOVERNANCE_VERIFIED = "runtime_governance_verified"
    RUNTIME_UNMANAGED = "runtime_unmanaged"
    BYPASS_DETECTOR_OPERATIONAL = "bypass_detector_operational"
    BYPASS_OBSERVED = "bypass_observed"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    STALE_EVIDENCE = "stale_evidence"
    VERIFIED_SUBJECT_BINDING = "verified_subject_binding"
    VERIFIED_RESOURCE_BINDING = "verified_resource_binding"
    VERIFIED_PURPOSE_BINDING = "verified_purpose_binding"
    VERIFIED_AUTHORITY_BINDING = "verified_authority_binding"
    VERIFIED_PARAMETER_BINDING = "verified_parameter_binding"
    VERIFIED_TARGET_BINDING = "verified_target_binding"
    VERIFIED_DESTINATION_BINDING = "verified_destination_binding"
    VERIFIED_APPROVAL_BINDING = "verified_approval_binding"
    VERIFIED_EXECUTION_VISIBILITY = "verified_execution_visibility"
    VERIFIED_EXECUTION_VERIFICATION = "verified_execution_verification"
    VERIFIED_PERSISTENCE_TRACKING = "verified_persistence_tracking"
    VERIFIED_DELEGATION_INTEGRITY = "verified_delegation_integrity"
    VERIFIED_OUTCOME_VERIFICATION = "verified_outcome_verification"
    EXECUTION_VERIFICATION_FAILED = "execution_verification_failed"
    PERSISTENCE_TRACKING_FAILED = "persistence_tracking_failed"
    DELEGATION_INTEGRITY_FAILED = "delegation_integrity_failed"
    OUTCOME_VERIFICATION_FAILED = "outcome_verification_failed"


@dataclass(frozen=True)
class AssertionCounts:
    covered: int = 0
    not_covered: int = 0
    unknown: int = 0
    not_applicable: int = 0

    def __post_init__(self) -> None:
        if min(self.covered, self.not_covered, self.unknown, self.not_applicable) < 0:
            raise ValueError("coverage assertion counts must be non-negative")

    @property
    def denominator(self) -> int:
        return self.covered + self.not_covered + self.unknown

    def as_dict(self) -> dict[str, int]:
        return {
            "covered": self.covered,
            "not_covered": self.not_covered,
            "unknown": self.unknown,
            "not_applicable": self.not_applicable,
            "denominator": self.denominator,
        }


def calculate_score(counts: AssertionCounts) -> float | None:
    if counts.denominator == 0:
        return None
    return round((counts.covered / counts.denominator) * 100.0, 2)


def phase5_coverage_counts(states: dict[str, str]) -> dict[str, dict[str, int]]:
    """Produce conservative V2 counts; absence is explicit UNKNOWN evidence."""
    result: dict[str, dict[str, int]] = {}
    for dimension in PHASE5_V2_DIMENSIONS:
        state = str(states.get(dimension, "unknown")).lower()
        counts = AssertionCounts(
            covered=1 if state == "covered" else 0,
            not_covered=1 if state == "not_covered" else 0,
            unknown=1 if state not in {"covered", "not_covered", "not_applicable"} else 0,
            not_applicable=1 if state == "not_applicable" else 0,
        )
        result[dimension] = counts.as_dict()
    return result
