from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from app.services.native_control.contracts import (
    AssuranceLevel,
    CapabilityDimension,
    CapabilityLevel,
    ControlMethod,
    ControlPlanResolutionResult,
    ControlPointCandidate,
    ControlPointSelectionResult,
    ControlRequirementProfile,
    HealthState,
    MandatoryEnforcementFloorRequirement,
    RejectedCandidate,
    SelectionContext,
    VerificationStatus,
)
from app.services.native_control.versioning import version_in_verified_range


SELECTOR_VERSION = "trusted-control-selector/1.0"
CONTROL_PLAN_SELECTOR_VERSION = "trusted-control-plan-selector/1.0"


_LEVEL_RANK = {
    CapabilityLevel.UNKNOWN: 0,
    CapabilityLevel.UNAVAILABLE: 0,
    CapabilityLevel.OBSERVE: 1,
    CapabilityLevel.EXTERNAL: 2,
    CapabilityLevel.INLINE: 3,
    CapabilityLevel.INLINE_BOUND: 4,
}


@dataclass(frozen=True, slots=True)
class _Evaluation:
    candidate: ControlPointCandidate
    reasons: tuple[str, ...]
    assurance: AssuranceLevel
    satisfied: tuple[CapabilityDimension, ...]
    unsatisfied: tuple[CapabilityDimension, ...]


def _version_supported(context: SelectionContext, candidate: ControlPointCandidate) -> bool:
    return (
        version_in_verified_range(
            context.provider_version,
            candidate.profile.tested_min_version,
            candidate.profile.tested_max_version,
        )
        and version_in_verified_range(
            candidate.provider_version,
            candidate.profile.tested_min_version,
            candidate.profile.tested_max_version,
        )
    )


def _required_capabilities(requirement: ControlRequirementProfile) -> tuple[tuple[CapabilityDimension, CapabilityLevel], ...]:
    required: list[tuple[CapabilityDimension, CapabilityLevel]] = []
    if requirement.requires_identity:
        required.append((CapabilityDimension.IDENTITY, CapabilityLevel.OBSERVE))
    if requirement.requires_pre_execution:
        required.append((requirement.pre_execution_capability, CapabilityLevel.INLINE))
    if requirement.requires_parameter_binding:
        required.append((CapabilityDimension.PARAMETER_BINDING, CapabilityLevel.INLINE_BOUND))
    if requirement.requires_target_binding:
        required.append((CapabilityDimension.TARGET_BINDING, CapabilityLevel.INLINE_BOUND))
    if requirement.requires_destination_binding:
        required.append((CapabilityDimension.DESTINATION_BINDING, CapabilityLevel.INLINE_BOUND))
    if requirement.requires_post_execution:
        required.append((CapabilityDimension.POST_EXECUTION_VERIFICATION, CapabilityLevel.INLINE_BOUND))
    if requirement.requires_persistence_detection:
        required.append((CapabilityDimension.PERSISTENT_SIDE_EFFECT_CONTROL, CapabilityLevel.OBSERVE))
    return tuple(required)


def _assurance(
    requirement: ControlRequirementProfile,
    candidate: ControlPointCandidate,
) -> AssuranceLevel:
    verified_claims = {
        dimension: claim
        for dimension, claim in candidate.profile.capabilities.items()
        if claim.verification_status is VerificationStatus.VERIFIED
    }
    if not verified_claims:
        return AssuranceLevel.A0_UNKNOWN
    assurance = AssuranceLevel.A1_DISCOVERED
    if any(_LEVEL_RANK[claim.level] >= _LEVEL_RANK[CapabilityLevel.OBSERVE] for claim in verified_claims.values()):
        assurance = AssuranceLevel.A2_OBSERVED
    if candidate.blocking_semantics and candidate.profile.security_properties.pre_execution_capable:
        assurance = AssuranceLevel.A3_INLINE
    binding_dimensions = tuple(
        dimension
        for dimension, required_now in (
            (CapabilityDimension.PARAMETER_BINDING, requirement.requires_parameter_binding),
            (CapabilityDimension.TARGET_BINDING, requirement.requires_target_binding),
            (CapabilityDimension.DESTINATION_BINDING, requirement.requires_destination_binding),
        )
        if required_now
    )
    if assurance >= AssuranceLevel.A3_INLINE and binding_dimensions and all(
        dimension not in candidate.profile.capabilities
        or (
            dimension in verified_claims
            and _LEVEL_RANK[verified_claims[dimension].level] >= _LEVEL_RANK[CapabilityLevel.INLINE_BOUND]
        )
        for dimension in binding_dimensions
    ):
        assurance = AssuranceLevel.A4_BOUND
    execution = verified_claims.get(CapabilityDimension.POST_EXECUTION_VERIFICATION)
    if (
        assurance >= AssuranceLevel.A4_BOUND
        and requirement.requires_post_execution
        and execution is not None
        and execution.level is CapabilityLevel.INLINE_BOUND
        and candidate.profile.security_properties.post_execution_capable
    ):
        assurance = AssuranceLevel.A5_VERIFIED
    return assurance


def _reason_for_capability(dimension: CapabilityDimension) -> str:
    if dimension is CapabilityDimension.POST_EXECUTION_VERIFICATION:
        return "insufficient_post_execution_verification"
    return f"insufficient_{dimension.value}"


def _evaluate(
    context: SelectionContext,
    requirement: ControlRequirementProfile,
    candidate: ControlPointCandidate,
) -> _Evaluation:
    reasons: list[str] = []
    satisfied: list[CapabilityDimension] = []
    unsatisfied: list[CapabilityDimension] = []
    required = _required_capabilities(requirement)

    if candidate.tenant_id != context.tenant_id or not candidate.tenant_binding_valid:
        reasons.append("tenant_binding_invalid")
    if candidate.profile.provider != context.provider or candidate.profile.product != context.product:
        reasons.append("provider_product_mismatch")
    if candidate.profile.verification_status is not VerificationStatus.VERIFIED:
        reasons.append(f"profile_{candidate.profile.verification_status.value}")
    if str(context.provider_version or "").strip().lower() in {"", "unknown"}:
        reasons.append("provider_version_unavailable")
    if str(candidate.provider_version or "").strip() != str(context.provider_version or "").strip():
        reasons.append("provider_version_route_mismatch")
    if not _version_supported(context, candidate):
        reasons.append("provider_version_unsupported")
    if str(context.adapter_version or "").strip().lower() in {"", "unknown"}:
        reasons.append("adapter_version_unavailable")
    if str(candidate.adapter_version or "").strip() != str(context.adapter_version or "").strip():
        reasons.append("adapter_version_route_mismatch")
    if str(candidate.adapter_version or "").strip() != str(candidate.profile.adapter_version or "").strip():
        reasons.append("adapter_version_unsupported")
    if candidate.policy_binding_mode not in {"authoritative_per_action", "pinned_snapshot"}:
        reasons.append("policy_binding_mode_unverified")
    elif candidate.policy_binding_mode == "pinned_snapshot" and (
        str(candidate.policy_version or "").strip()
        != str(context.policy_version or "").strip()
    ):
        reasons.append("policy_version_mismatch")
    elif candidate.policy_binding_mode == "authoritative_per_action" and str(
        context.policy_version or ""
    ).strip().lower() in {"", "unknown"}:
        reasons.append("policy_version_unavailable")
    if candidate.health.state is not HealthState.HEALTHY:
        reasons.append(f"health_{candidate.health.state.value}")
    if not candidate.health.callback_authenticated:
        reasons.append("callback_authentication_failed")
    if not candidate.health.validation_current:
        reasons.append("validation_stale")
    if not candidate.health.configuration_integrity_valid:
        reasons.append("configuration_integrity_invalid")
    if not context.policy_fresh or not candidate.health.policy_fresh:
        reasons.append("policy_stale")
    if not candidate.health.evidence_flowing:
        reasons.append("evidence_flow_unavailable")
    if str(context.current_bypass_state or "").strip().lower() in {
        "bypassed",
        "detected",
        "known",
        "open",
        "present",
        "uncovered",
    }:
        reasons.append("active_bypass_detected")
    if candidate.health.observed_latency_ms > requirement.maximum_latency_ms:
        reasons.append("latency_requirement_unsatisfied")
    if candidate.current_degradation_mode not in requirement.acceptable_degradation_modes:
        reasons.append("degradation_mode_unacceptable")
    if context.required_lifecycle_event and context.required_lifecycle_event not in candidate.exposed_lifecycle_events:
        reasons.append("required_lifecycle_event_missing")
    if requirement.requires_pre_execution and not candidate.blocking_semantics:
        reasons.append("blocking_semantics_unavailable")

    visible_fields = set(candidate.visible_action_fields)
    for field_name, required_now in (
        ("identity", requirement.requires_identity),
        ("parameters", requirement.requires_parameter_binding),
        ("target", requirement.requires_target_binding),
        ("destination", requirement.requires_destination_binding),
        ("result", requirement.requires_post_execution),
    ):
        if required_now and field_name not in visible_fields:
            reasons.append(f"action_field_{field_name}_not_visible")

    for dimension, minimum_level in required:
        claim = candidate.profile.capabilities.get(dimension)
        if claim is None or claim.verification_status is not VerificationStatus.VERIFIED:
            unsatisfied.append(dimension)
            reasons.append(f"capability_{dimension.value}_unverified")
            continue
        if _LEVEL_RANK[claim.level] < _LEVEL_RANK[minimum_level]:
            unsatisfied.append(dimension)
            reasons.append(_reason_for_capability(dimension))
            continue
        satisfied.append(dimension)

    assurance = _assurance(requirement, candidate)
    if assurance < requirement.minimum_assurance:
        reasons.append("minimum_assurance_unsatisfied")

    return _Evaluation(
        candidate=candidate,
        reasons=tuple(dict.fromkeys(reasons)),
        assurance=assurance,
        satisfied=tuple(sorted(set(satisfied), key=lambda item: item.value)),
        unsatisfied=tuple(sorted(set(unsatisfied), key=lambda item: item.value)),
    )


def _selection_id(context: SelectionContext, requirement: ControlRequirementProfile, evaluations: list[_Evaluation]) -> str:
    stable_context = {
        name: getattr(context, name)
        for name in context.__dataclass_fields__
        if name != "evaluated_at"
    }
    body = {
        "selector_version": SELECTOR_VERSION,
        "context": stable_context,
        "requirement": {
            name: getattr(requirement, name) for name in requirement.__dataclass_fields__
        },
        "candidates": sorted(
            (
                {
                    "control_point_id": row.candidate.control_point_id,
                    "profile_id": row.candidate.profile.profile_id,
                    "profile_version": row.candidate.profile.profile_version,
                    "reasons": row.reasons,
                    "assurance": int(row.assurance),
                    "satisfied": tuple(value.value for value in row.satisfied),
                    "unsatisfied": tuple(value.value for value in row.unsatisfied),
                    "health": row.candidate.health.state.value,
                    "latency_ms": row.candidate.health.observed_latency_ms,
                    "blocking_strength": row.candidate.profile.security_properties.blocking_strength,
                    "action_fidelity": row.candidate.profile.security_properties.action_fidelity,
                    "bypass_resistance": row.candidate.profile.security_properties.bypass_resistance,
                }
                for row in evaluations
            ),
            key=lambda item: item["control_point_id"],
        ),
    }
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=lambda value: getattr(value, "value", str(value)))
    return sha256(raw.encode("utf-8")).hexdigest()[:36]


class TrustedControlPointSelector:
    version = SELECTOR_VERSION

    def select(
        self,
        context: SelectionContext,
        requirement: ControlRequirementProfile,
        candidates: list[ControlPointCandidate] | tuple[ControlPointCandidate, ...],
    ) -> ControlPointSelectionResult:
        evaluations = [_evaluate(context, requirement, row) for row in candidates]
        eligible = [row for row in evaluations if not row.reasons]
        eligible.sort(
            key=lambda row: (
                row.candidate.health.observed_latency_ms
                + row.candidate.profile.security_properties.operational_complexity
                + row.candidate.profile.security_properties.required_privilege
                + row.candidate.profile.security_properties.privacy_impact_score
                + row.candidate.profile.security_properties.deployment_friction,
                -row.candidate.profile.security_properties.blocking_strength,
                -row.candidate.profile.security_properties.action_fidelity,
                -row.candidate.profile.security_properties.bypass_resistance,
                -int(row.assurance),
                row.candidate.control_point_id,
            )
        )
        primary = eligible[0] if eligible else None
        rejected = tuple(
            RejectedCandidate(control_point_id=row.candidate.control_point_id, reason_codes=row.reasons)
            for row in sorted((item for item in evaluations if item.reasons), key=lambda item: item.candidate.control_point_id)
        )
        required = tuple(dimension for dimension, _minimum in _required_capabilities(requirement))
        satisfied = primary.satisfied if primary else ()
        unsatisfied = (
            primary.unsatisfied
            if primary
            else tuple(
                sorted(
                    {dimension for row in evaluations for dimension in row.unsatisfied} or set(required),
                    key=lambda item: item.value,
                )
            )
        )
        def trusted_for_auxiliary(row: _Evaluation) -> bool:
            blocking_only = {
                "blocking_semantics_unavailable",
                "minimum_assurance_unsatisfied",
                *(
                    reason
                    for reason in row.reasons
                    if reason.startswith("capability_") or reason.startswith("insufficient_")
                ),
                *(
                    reason
                    for reason in row.reasons
                    if reason.startswith("action_field_")
                ),
            }
            return not (set(row.reasons) - blocking_only)

        secondary = tuple(
            row.candidate.control_point_id
            for row in sorted(evaluations, key=lambda item: item.candidate.control_point_id)
            if row is not primary
            and trusted_for_auxiliary(row)
            and any(
                (claim := row.candidate.profile.capabilities.get(dimension)) is not None
                and claim.verification_status is VerificationStatus.VERIFIED
                and _LEVEL_RANK[claim.level] >= _LEVEL_RANK[CapabilityLevel.OBSERVE]
                for dimension in (
                    CapabilityDimension.DISCOVERY,
                    CapabilityDimension.IDENTITY,
                    CapabilityDimension.POST_EXECUTION_VISIBILITY,
                )
            )
        )
        containment = tuple(
            row.candidate.control_point_id
            for row in sorted(evaluations, key=lambda item: item.candidate.control_point_id)
            if row is not primary
            and trusted_for_auxiliary(row)
            if (
                (claim := row.candidate.profile.capabilities.get(CapabilityDimension.CONTAINMENT)) is not None
                and claim.verification_status is VerificationStatus.VERIFIED
                and _LEVEL_RANK[claim.level] >= _LEVEL_RANK[CapabilityLevel.EXTERNAL]
            )
        )
        blind_spots = tuple(
            sorted(
                {
                    blind_spot
                    for row in ([primary] if primary else evaluations)
                    if row is not None
                    for blind_spot in row.candidate.profile.known_blind_spots
                }
            )
        )
        assurance = primary.assurance if primary else AssuranceLevel.A0_UNKNOWN
        selected_id = primary.candidate.control_point_id if primary else None
        profile_version = primary.candidate.profile.profile_version if primary else None
        coverage = {
            "authorization": "covered" if primary and assurance >= AssuranceLevel.A3_INLINE else "not_covered",
            "binding": "covered" if primary and assurance >= AssuranceLevel.A4_BOUND else "not_covered",
            "execution_verification": "covered" if primary and assurance >= AssuranceLevel.A5_VERIFIED else "not_covered",
            "bypass": "unknown" if context.current_bypass_state == "unknown" else context.current_bypass_state,
        }
        return ControlPointSelectionResult(
            selection_id=_selection_id(context, requirement, evaluations),
            action_id=context.action_id,
            primary_control_point=selected_id,
            secondary_observation_points=secondary,
            containment_points=containment,
            rejected_candidates=rejected,
            selection_reason="strongest_verified_eligible_control_point" if primary else "CONTROL_REQUIREMENT_UNSATISFIED",
            required_capabilities=required,
            satisfied_capabilities=satisfied,
            unsatisfied_capabilities=unsatisfied,
            assurance_level=assurance,
            coverage_implications=coverage,
            known_blind_spots=blind_spots,
            selector_version=SELECTOR_VERSION,
            matrix_version=context.matrix_version,
            policy_version=context.policy_version,
            control_profile_version=profile_version,
            timestamp=context.evaluated_at,
        )

    def resolve_control_plan(
        self,
        context: SelectionContext,
        semantic_requirement: ControlRequirementProfile | None,
        mandatory_floors: tuple[MandatoryEnforcementFloorRequirement, ...]
        | list[MandatoryEnforcementFloorRequirement],
        candidates: list[ControlPointCandidate] | tuple[ControlPointCandidate, ...],
    ) -> ControlPlanResolutionResult:
        """Compose OS enforcement floors with, rather than instead of, semantics.

        Callers pass only route-correlated candidates. Endpoint floors are
        intentionally evaluated independently of provider/product identity: the
        operating-system consequence remains applicable to known and unknown AI.
        """
        rows = tuple(candidates)
        semantic = (
            self.select(context, semantic_requirement, rows)
            if semantic_requirement is not None
            else None
        )
        selected_floors: list[tuple[str, str]] = []
        rejected_by_floor: dict[str, tuple[RejectedCandidate, ...]] = {}
        unsatisfied: list[str] = []

        for floor in sorted(mandatory_floors, key=lambda item: item.floor_id):
            evaluations: list[tuple[ControlPointCandidate, tuple[str, ...]]] = []
            for candidate in rows:
                reasons = self._floor_rejection_reasons(context, floor, candidate)
                evaluations.append((candidate, reasons))
            eligible = [candidate for candidate, reasons in evaluations if not reasons]
            eligible.sort(
                key=lambda candidate: (
                    -candidate.profile.security_properties.blocking_strength,
                    -candidate.profile.security_properties.bypass_resistance,
                    -candidate.profile.security_properties.tamper_resistance,
                    candidate.health.observed_latency_ms,
                    candidate.control_point_id,
                )
            )
            rejected_by_floor[floor.floor_id] = tuple(
                RejectedCandidate(candidate.control_point_id, reasons)
                for candidate, reasons in sorted(
                    (item for item in evaluations if item[1]),
                    key=lambda item: item[0].control_point_id,
                )
            )
            if eligible:
                selected_floors.append((floor.floor_id, eligible[0].control_point_id))
            else:
                unsatisfied.append(floor.floor_id)

        selected_floor_ids = {point_id for _floor_id, point_id in selected_floors}
        semantic_id = semantic.primary_control_point if semantic is not None else None
        trusted_context = tuple(
            sorted(
                candidate.control_point_id
                for candidate in rows
                if candidate.control_point_id not in selected_floor_ids
                and candidate.control_point_id != semantic_id
                and self._candidate_is_trusted_context(context, candidate)
            )
        )
        verification = tuple(
            sorted(
                candidate.control_point_id
                for candidate in rows
                if self._candidate_is_verification_point(context, candidate)
            )
        )
        containment = set(semantic.containment_points if semantic is not None else ())
        containment.update(
            candidate.control_point_id
            for candidate in rows
            if self._candidate_has_verified_claim(
                candidate, CapabilityDimension.CONTAINMENT, CapabilityLevel.EXTERNAL
            )
            and self._candidate_has_healthy_runtime(context, candidate)
        )
        semantic_unsatisfied = semantic_requirement is not None and semantic_id is None
        requirement_unsatisfied = bool(unsatisfied) or semantic_unsatisfied
        reason_codes = [
            *(f"CONTROL_REQUIREMENT_UNSATISFIED:{floor_id}" for floor_id in unsatisfied),
            *(("CONTROL_REQUIREMENT_UNSATISFIED:semantic",) if semantic_unsatisfied else ()),
        ]
        coverage = {
            "mandatory_floor": "covered" if not unsatisfied else "not_covered",
            "semantic": (
                "not_required"
                if semantic_requirement is None
                else "covered" if semantic_id else "not_covered"
            ),
            "authorization": "covered" if not requirement_unsatisfied else "not_covered",
            "bypass": "unknown" if context.current_bypass_state == "unknown" else context.current_bypass_state,
        }
        required_capabilities = {floor.capability for floor in mandatory_floors}
        if semantic_requirement is not None:
            required_capabilities.update(
                dimension
                for dimension, _minimum in _required_capabilities(semantic_requirement)
            )
        satisfied_capabilities = {
            floor.capability
            for floor in mandatory_floors
            if floor.floor_id not in unsatisfied
        }
        unsatisfied_capabilities = {
            floor.capability
            for floor in mandatory_floors
            if floor.floor_id in unsatisfied
        }
        if semantic is not None:
            satisfied_capabilities.update(semantic.satisfied_capabilities)
            unsatisfied_capabilities.update(semantic.unsatisfied_capabilities)
        unsatisfied_capabilities.update(required_capabilities - satisfied_capabilities)

        candidate_by_id = {candidate.control_point_id: candidate for candidate in rows}
        degradation_policy = {
            floor_id: candidate_by_id[point_id].current_degradation_mode.value
            for floor_id, point_id in selected_floors
        }
        degradation_policy.update({floor_id: "unavailable" for floor_id in unsatisfied})
        if semantic_requirement is not None:
            degradation_policy["semantic"] = (
                candidate_by_id[semantic_id].current_degradation_mode.value
                if semantic_id is not None
                else "unavailable"
            )

        selected_point_ids = {point_id for _floor_id, point_id in selected_floors}
        if semantic_id is not None:
            selected_point_ids.add(semantic_id)
        plan_blind_spots = {
            blind_spot
            for point_id in selected_point_ids
            for blind_spot in candidate_by_id[point_id].profile.known_blind_spots
        }
        plan_blind_spots.update(
            f"mandatory_floor_unsatisfied:{floor_id}" for floor_id in unsatisfied
        )
        if semantic_unsatisfied:
            plan_blind_spots.add("semantic_control_unsatisfied")
        if str(context.current_bypass_state or "").strip().lower() == "unknown":
            plan_blind_spots.add("bypass_state_unknown")

        plan_assurance = AssuranceLevel.A0_UNKNOWN
        if not requirement_unsatisfied:
            if semantic is not None:
                plan_assurance = semantic.assurance_level
            elif selected_floors:
                plan_assurance = AssuranceLevel.A3_INLINE
        stable = {
            "version": CONTROL_PLAN_SELECTOR_VERSION,
            "context": {
                name: getattr(context, name)
                for name in context.__dataclass_fields__
                if name != "evaluated_at"
            },
            "floors": [
                {
                    "floor_id": floor.floor_id,
                    "capability": floor.capability.value,
                    "minimum_level": floor.minimum_level.value,
                    "allowed_methods": [method.value for method in floor.allowed_methods],
                    "maximum_latency_ms": floor.maximum_latency_ms,
                }
                for floor in sorted(mandatory_floors, key=lambda item: item.floor_id)
            ],
            "selected_floors": selected_floors,
            "semantic_selection": semantic.selection_id if semantic is not None else None,
        }
        plan_id = sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()[:36]
        return ControlPlanResolutionResult(
            plan_id=plan_id,
            action_id=context.action_id,
            mandatory_enforcement_floors=tuple(selected_floors),
            semantic_primary_control=semantic_id,
            secondary_context_points=trusted_context,
            verification_points=verification,
            containment_points=tuple(sorted(containment)),
            unsatisfied_mandatory_floors=tuple(unsatisfied),
            rejected_mandatory_floor_candidates=rejected_by_floor,
            control_requirement_unsatisfied=requirement_unsatisfied,
            reason_codes=tuple(reason_codes),
            coverage_implications=coverage,
            selector_version=CONTROL_PLAN_SELECTOR_VERSION,
            matrix_version=context.matrix_version,
            policy_version=context.policy_version,
            timestamp=context.evaluated_at,
            required_capabilities=tuple(sorted(required_capabilities, key=lambda item: item.value)),
            satisfied_capabilities=tuple(sorted(satisfied_capabilities, key=lambda item: item.value)),
            unsatisfied_capabilities=tuple(sorted(unsatisfied_capabilities, key=lambda item: item.value)),
            minimum_assurance=plan_assurance,
            degradation_policy=dict(sorted(degradation_policy.items())),
            expiry=context.plan_expires_at,
            blind_spots=tuple(sorted(plan_blind_spots)),
        )

    @staticmethod
    def _candidate_has_verified_claim(
        candidate: ControlPointCandidate,
        dimension: CapabilityDimension,
        minimum: CapabilityLevel,
    ) -> bool:
        claim = candidate.profile.capabilities.get(dimension)
        return bool(
            claim is not None
            and claim.verification_status is VerificationStatus.VERIFIED
            and _LEVEL_RANK[claim.level] >= _LEVEL_RANK[minimum]
        )

    @staticmethod
    def _candidate_has_healthy_runtime(
        context: SelectionContext,
        candidate: ControlPointCandidate,
    ) -> bool:
        return bool(
            candidate.tenant_id == context.tenant_id
            and candidate.tenant_binding_valid
            and candidate.profile.verification_status is VerificationStatus.VERIFIED
            and candidate.health.state is HealthState.HEALTHY
            and candidate.health.callback_authenticated
            and candidate.health.validation_current
            and candidate.health.configuration_integrity_valid
            and candidate.health.policy_fresh
            and candidate.policy_version == context.policy_version
        )

    @classmethod
    def _candidate_is_trusted_context(
        cls,
        context: SelectionContext,
        candidate: ControlPointCandidate,
    ) -> bool:
        return cls._candidate_has_healthy_runtime(context, candidate) and any(
            cls._candidate_has_verified_claim(candidate, dimension, CapabilityLevel.OBSERVE)
            for dimension in (
                CapabilityDimension.DISCOVERY,
                CapabilityDimension.IDENTITY,
                CapabilityDimension.PROCESS_IDENTITY,
            )
        )

    @classmethod
    def _candidate_is_verification_point(
        cls,
        context: SelectionContext,
        candidate: ControlPointCandidate,
    ) -> bool:
        return cls._candidate_has_healthy_runtime(context, candidate) and any(
            cls._candidate_has_verified_claim(candidate, dimension, CapabilityLevel.OBSERVE)
            for dimension in (
                CapabilityDimension.POST_EXECUTION_VISIBILITY,
                CapabilityDimension.POST_EXECUTION_VERIFICATION,
                CapabilityDimension.PROCESS_IDENTITY,
            )
        )

    @classmethod
    def _floor_rejection_reasons(
        cls,
        context: SelectionContext,
        floor: MandatoryEnforcementFloorRequirement,
        candidate: ControlPointCandidate,
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if candidate.profile.integration_method not in floor.allowed_methods:
            reasons.append("not_endpoint_enforcement_floor")
        if not cls._candidate_has_healthy_runtime(context, candidate):
            if candidate.tenant_id != context.tenant_id or not candidate.tenant_binding_valid:
                reasons.append("tenant_binding_invalid")
            if candidate.profile.verification_status is not VerificationStatus.VERIFIED:
                reasons.append("profile_unverified")
            if candidate.health.state is not HealthState.HEALTHY:
                reasons.append(f"health_{candidate.health.state.value}")
            if not candidate.health.callback_authenticated:
                reasons.append("callback_unauthenticated")
            if not candidate.health.validation_current:
                reasons.append("validation_stale")
            if not candidate.health.configuration_integrity_valid:
                reasons.append("configuration_integrity_invalid")
            if not candidate.health.policy_fresh or candidate.policy_version != context.policy_version:
                reasons.append("policy_stale")
        if candidate.health.observed_latency_ms > floor.maximum_latency_ms:
            reasons.append("latency_budget_exceeded")
        if not candidate.blocking_semantics or not candidate.profile.security_properties.pre_execution_capable:
            reasons.append("blocking_semantics_unavailable")
        if candidate.current_degradation_mode not in floor.acceptable_degradation_modes:
            reasons.append("degradation_mode_unacceptable")
        if not cls._candidate_has_verified_claim(candidate, floor.capability, floor.minimum_level):
            reasons.append(f"capability_{floor.capability.value}_unsatisfied")
        return tuple(dict.fromkeys(reasons))
