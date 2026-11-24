"""Authoritative Phase 1-7 inputs for Phase 8 executive coverage."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.control_coverage import (
    CoverageApplicability,
    CoverageAssurance,
    CoverageCapability,
    CoverageDeployment,
    ExecutiveCoverageFacts,
)
from app.db.models.activity_lineage import ActivityLineage
from app.db.models.continuous_assurance import ControlAssertion, DriftSignal
from app.db.models.control_coverage import ControlCoverageAssertion, ControlCoveragePath, DeploymentSurface
from app.db.models.native_control import NativeControlSelection
from app.services.control_coverage.executive import (
    MAX_EXECUTIVE_PATH_INPUTS,
    CoverageAssessmentInput,
)


_ASSURANCE_RANK = {"CURRENT": 0, "UNKNOWN": 1, "STALE": 2, "REGRESSED": 3}
_KNOWN_SURFACES = {"browser", "endpoint", "runtime", "saas_api"}


def _action_ids(path: ControlCoveragePath) -> tuple[str, ...]:
    result: set[str] = set()
    for ref in path.source_refs or []:
        text = str(ref or "")
        if text.startswith("ai_action:") and len(text) > len("ai_action:"):
            result.add(text.split(":", 1)[1])
    return tuple(sorted(result))


def _surface_family(surface: DeploymentSurface | None) -> str:
    if surface is None:
        return "unknown"
    value = str(surface.deployment_family or "unknown").lower()
    return value if value in _KNOWN_SURFACES else "unknown"


def _deployment(surface: DeploymentSurface | None) -> CoverageDeployment:
    if surface is None:
        return CoverageDeployment.MISSING
    if surface.health_status in {"healthy", "warning"} and surface.status not in {"disabled", "removed", "offline"}:
        return CoverageDeployment.CONFIGURED
    if surface.status not in {"unknown", "missing", "removed"}:
        return CoverageDeployment.PRESENT
    return CoverageDeployment.UNKNOWN


def _assurance(rows: list[ControlAssertion]) -> tuple[CoverageAssurance, ControlAssertion | None]:
    if not rows:
        return CoverageAssurance.UNKNOWN, None
    selected = max(rows, key=lambda row: (_ASSURANCE_RANK.get(row.assurance_state, 3), row.assurance_version, row.id))
    return CoverageAssurance(selected.assurance_state.lower()), selected


def _profile_capability(surface: DeploymentSurface | None, dimension: str) -> CoverageCapability | None:
    if surface is None:
        return None
    profile = dict(surface.capability_profile or {})
    claims = profile.get("capabilities") if isinstance(profile.get("capabilities"), dict) else profile
    claim = claims.get(dimension) if isinstance(claims, dict) else None
    if isinstance(claim, str):
        value = claim.lower()
        if value in {"unavailable", "unsupported"}:
            return CoverageCapability.UNSUPPORTED
    if isinstance(claim, dict):
        level = str(claim.get("level") or "").lower()
        verification = str(claim.get("verification_status") or claim.get("verification") or "").lower()
        if level in {"unavailable", "unsupported"}:
            return CoverageCapability.UNSUPPORTED
        if verification == "verified":
            return CoverageCapability.VERIFIED
        if verification == "experimental":
            return CoverageCapability.EXPERIMENTAL
        if verification in {"unverified", "broken", "removed"}:
            return CoverageCapability.UNVERIFIED
    return None


def _legacy_capability(
    assertion: ControlCoverageAssertion, surface: DeploymentSurface | None
) -> CoverageCapability:
    profile = _profile_capability(surface, assertion.dimension)
    if profile is not None:
        return profile
    if assertion.state == "covered" and assertion.evidence_refs:
        return CoverageCapability.VERIFIED
    if assertion.state == "not_covered":
        return CoverageCapability.PARTIAL
    return CoverageCapability.UNKNOWN


def _criticality(action_class: str) -> str:
    normalized = action_class.lower()
    if any(token in normalized for token in ("write", "update", "delete", "create", "transfer", "execute", "persistent")):
        return "high"
    return "medium"


def collect_executive_coverage_inputs(
    db: Session, *, tenant_id: str, assessed_at: datetime
) -> tuple[list[CoverageAssessmentInput], dict[str, str]]:
    """Project authoritative coverage facts without re-evaluating policy or evidence."""

    paths = db.scalars(
        select(ControlCoveragePath)
        .where(ControlCoveragePath.tenant_id == tenant_id)
        .order_by(ControlCoveragePath.id)
        .limit(MAX_EXECUTIVE_PATH_INPUTS)
    ).all()
    path_ids = [path.id for path in paths]
    legacy = (
        db.scalars(
            select(ControlCoverageAssertion).where(
                ControlCoverageAssertion.tenant_id == tenant_id,
                ControlCoverageAssertion.path_id.in_(path_ids),
            )
        ).all()
        if path_ids
        else []
    )
    surfaces = db.scalars(select(DeploymentSurface).where(DeploymentSurface.tenant_id == tenant_id)).all()
    phase6 = db.scalars(select(ControlAssertion).where(ControlAssertion.tenant_id == tenant_id)).all()
    drifts = db.scalars(
        select(DriftSignal).where(DriftSignal.tenant_id == tenant_id, DriftSignal.status == "OPEN")
    ).all()
    selections = db.scalars(
        select(NativeControlSelection).where(NativeControlSelection.tenant_id == tenant_id)
    ).all()
    lineages = db.scalars(select(ActivityLineage).where(ActivityLineage.tenant_id == tenant_id)).all()

    surface_by_id = {row.id: row for row in surfaces}
    assertions_by_path: dict[str, list[ControlCoverageAssertion]] = defaultdict(list)
    for row in legacy:
        assertions_by_path[row.path_id].append(row)
    assurance_by_asset_capability: dict[tuple[str, str], list[ControlAssertion]] = defaultdict(list)
    for row in phase6:
        if row.asset_ref:
            assurance_by_asset_capability[(row.asset_ref, row.required_capability)].append(row)
    drifted_assertions = {
        str(assertion_id)
        for signal in drifts
        for assertion_id in (signal.affected_assertion_ids or [])
    }
    selection_by_action: dict[str, NativeControlSelection] = {}
    for row in selections:
        current = selection_by_action.get(row.action_id)
        if current is None or (row.selected_at, row.selection_id) > (current.selected_at, current.selection_id):
            selection_by_action[row.action_id] = row
    lineage_by_action: dict[str, list[ActivityLineage]] = defaultdict(list)
    for row in lineages:
        lineage_by_action[row.seed_action_id].append(row)
        if row.root_action_id != row.seed_action_id:
            lineage_by_action[row.root_action_id].append(row)

    inputs: list[CoverageAssessmentInput] = []
    policy_versions: set[str] = set()
    matrix_versions: set[str] = set()
    for path in paths:
        path_assertions = assertions_by_path.get(path.id, [])
        bypass_assertions = [row for row in path_assertions if row.dimension == "bypass"]
        bypass_reachable = any(
            row.state == "not_covered" or row.reason_code in {"bypass_observed", "reachable_bypass_uncontrolled"}
            for row in bypass_assertions
        )
        bypass_refs = tuple(
            sorted({str(ref) for row in bypass_assertions for ref in (row.evidence_refs or []) if ref})
        )
        surface = surface_by_id.get(path.deployment_surface_id or "")
        action_ids = _action_ids(path)
        selection = next((selection_by_action[action_id] for action_id in action_ids if action_id in selection_by_action), None)
        if selection is not None:
            policy_versions.add(selection.policy_version)
            matrix_versions.add(selection.matrix_version)
        for assertion in sorted(path_assertions, key=lambda row: (row.dimension, row.methodology_version, row.id)):
            assurance_state, assurance_row = _assurance(
                assurance_by_asset_capability.get((path.asset_ref, assertion.dimension), [])
            )
            action_class = assurance_row.action_class if assurance_row and assurance_row.action_class else "unknown"
            expected: set[str] = {path.deployment_surface_ref} if path.deployment_surface_ref else set()
            contributing: set[str] = set()
            missing: set[str] = set()
            control_plan_ref = None
            if assertion.state == "covered" and path.deployment_surface_ref:
                contributing.add(path.deployment_surface_ref)
            if selection is not None and assertion.dimension in set(selection.required_capabilities or []):
                control_plan_ref = selection.control_plan_id
                if selection.semantic_primary_control_point_id:
                    expected.add(selection.semantic_primary_control_point_id)
                if assertion.dimension in set(selection.satisfied_capabilities or []):
                    if selection.semantic_primary_control_point_id:
                        contributing.add(selection.semantic_primary_control_point_id)
                else:
                    missing.add(assertion.dimension)
            if assertion.state == "not_covered":
                missing.update(expected or {assertion.dimension})

            evidence_refs = {
                str(ref) for ref in (assertion.evidence_refs or []) if ref
            }
            validation_refs: tuple[str, ...] = ()
            evidence_quality = "unknown"
            previously_validated = False
            unresolved_regression = False
            if assurance_row is not None:
                previously_validated = assurance_row.last_validated_at is not None
                unresolved_regression = (
                    assurance_row.assurance_state == "REGRESSED" or assurance_row.id in drifted_assertions
                )
                evidence_quality = str(assurance_row.required_evidence_level or "unknown").lower()
                if assurance_row.last_validation_run_id:
                    validation_refs = (f"validation_run:{assurance_row.last_validation_run_id}",)
                    evidence_refs.add(f"validation_run:{assurance_row.last_validation_run_id}")
            lineage_refs = tuple(
                sorted(
                    {
                        f"lineage:{lineage.id}"
                        for action_id in action_ids
                        for lineage in lineage_by_action.get(action_id, [])
                    }
                )
            )
            applicability = (
                CoverageApplicability.NOT_APPLICABLE
                if assertion.state == "not_applicable"
                else CoverageApplicability.APPLICABLE
            )
            key_material = f"{path.id}|{assertion.dimension}|{assertion.methodology_version}"
            inputs.append(
                CoverageAssessmentInput(
                    assessment_key=hashlib.sha256(key_material.encode("utf-8")).hexdigest(),
                    asset_ref=path.asset_ref,
                    action_class=action_class,
                    action_path_ref=f"control_coverage_path:{path.id}",
                    deployment_surface=_surface_family(surface),
                    dimension=assertion.dimension,
                    requirement_ref=f"control_requirement:{assertion.dimension}",
                    applicability_reason=(
                        "The authoritative path assertion explicitly marks this property not applicable."
                        if applicability is CoverageApplicability.NOT_APPLICABLE
                        else "An authoritative Control Coverage path assesses this property for the scoped action."
                    ),
                    facts=ExecutiveCoverageFacts(
                        applicability=applicability,
                        deployment=_deployment(surface),
                        capability=_legacy_capability(assertion, surface),
                        assurance=assurance_state,
                        evidence_quality=evidence_quality,
                        evidence_refs=tuple(sorted(evidence_refs)),
                        expected_control_points=tuple(sorted(expected)),
                        contributing_control_points=tuple(sorted(contributing)),
                        missing_contributions=tuple(sorted(missing)),
                        bypass_reachable=bypass_reachable,
                        compensating_bypass_control=False,
                        previously_validated=previously_validated,
                        unresolved_regression=unresolved_regression,
                    ),
                    control_plan_ref=control_plan_ref,
                    validation_refs=validation_refs,
                    lineage_refs=lineage_refs,
                    bypass_refs=bypass_refs if bypass_reachable else (),
                    criticality=_criticality(action_class),
                    source_versions={
                        "coverage_methodology": assertion.methodology_version,
                        "coverage_evaluator": assertion.evaluator_version,
                        **({"policy": selection.policy_version, "capability_matrix": selection.matrix_version} if selection else {}),
                    },
                )
            )

    source_versions = {
        "coverage": max((row.methodology_version for row in legacy), default="unknown"),
        "assurance": max((str(row.assurance_version) for row in phase6), default="unknown"),
        "lineage": max((row.schema_version for row in lineages), default="unknown"),
        "policy": max(policy_versions, default="unknown"),
        "capability_matrix": max(matrix_versions, default="unknown"),
        "assessed_at": assessed_at.isoformat(),
    }
    return inputs, source_versions
