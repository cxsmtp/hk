from __future__ import annotations

from collections.abc import Mapping, Sequence

from .contracts import (
    EndpointFloorPosture,
    EndpointHealthState,
    EndpointPrimitive,
    FloorComponent,
    RuntimeComponentState,
    VerificationState,
)


def evaluate_floor_posture(
    *,
    states: Sequence[RuntimeComponentState],
    required: Mapping[EndpointPrimitive, Sequence[FloorComponent]],
) -> EndpointFloorPosture:
    by_component = {state.component: state for state in states}
    primitive_status: dict[str, str] = {}
    component_status: dict[str, dict[str, object]] = {}
    reasons: list[str] = []
    blind_spots: list[str] = []
    evidence_refs: set[str] = set()

    for state in sorted(states, key=lambda row: row.component.value):
        evidence_refs.update(state.evidence_refs)
        health_state = state.health_state or (
            EndpointHealthState.HEALTHY if state.healthy else EndpointHealthState.UNHEALTHY
        )
        component_status[state.component.value] = {
            "active": state.active,
            "healthy": state.healthy,
            "health_state": health_state.value,
            "verification": state.verification.value,
            "policy_fresh": state.policy_fresh,
            "configuration_integrity_valid": state.configuration_integrity_valid,
            "binary_integrity_valid": state.binary_integrity_valid,
            "deadline_miss_count": max(0, state.deadline_miss_count),
            "dropped_event_count": max(0, state.dropped_event_count),
            "reason_codes": list(state.reason_codes),
            "evidence_refs": list(state.evidence_refs),
        }

    for primitive, components in sorted(required.items(), key=lambda item: item[0].value):
        rows = [by_component.get(component) for component in components]
        if any(row is None for row in rows):
            primitive_status[primitive.value] = "unknown"
            reasons.append(f"CONTROL_REQUIREMENT_UNSATISFIED:{primitive.value}")
            blind_spots.append(f"missing_runtime_component:{primitive.value}")
            continue
        concrete = [row for row in rows if row is not None]
        if all(
            row.active
            and row.healthy
            and (row.health_state or EndpointHealthState.HEALTHY)
            is EndpointHealthState.HEALTHY
            and row.verification is VerificationState.VERIFIED
            and row.policy_fresh
            and row.configuration_integrity_valid
            and row.binary_integrity_valid
            and row.deadline_miss_count == 0
            for row in concrete
        ):
            primitive_status[primitive.value] = "inline"
            continue
        if any(
            row.verification is not VerificationState.VERIFIED
            or row.health_state in {
                EndpointHealthState.TAMPERED,
                EndpointHealthState.UNKNOWN,
            }
            or not row.configuration_integrity_valid
            or not row.binary_integrity_valid
            for row in concrete
        ):
            primitive_status[primitive.value] = "unknown"
        else:
            primitive_status[primitive.value] = "not_covered"
        reasons.append(f"CONTROL_REQUIREMENT_UNSATISFIED:{primitive.value}")
        blind_spots.append(f"mandatory_floor_inactive:{primitive.value}")

    satisfied = bool(primitive_status) and all(value == "inline" for value in primitive_status.values())
    return EndpointFloorPosture(
        minimum_floor_satisfied=satisfied,
        primitive_status=primitive_status,
        component_status=component_status,
        reason_codes=tuple(dict.fromkeys(reasons)),
        blind_spots=tuple(dict.fromkeys(blind_spots)),
        evidence_refs=tuple(sorted(evidence_refs)),
    )
