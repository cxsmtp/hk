from __future__ import annotations

from hawk_endpoint_agent.endpoint_floor.contracts import (
    EndpointPrimitive,
    FloorComponent,
    RuntimeComponentState,
    VerificationState,
)
from hawk_endpoint_agent.endpoint_floor.health import evaluate_floor_posture


def _state(
    component: FloorComponent,
    *,
    active: bool = True,
    healthy: bool = True,
    verified: VerificationState = VerificationState.VERIFIED,
) -> RuntimeComponentState:
    return RuntimeComponentState(
        component=component,
        active=active,
        healthy=healthy,
        verification=verified,
        policy_fresh=True,
        configuration_integrity_valid=True,
        binary_integrity_valid=True,
        deadline_miss_count=0,
        dropped_event_count=0,
        evidence_refs=(f"evidence:{component.value}",),
    )


def test_all_mandatory_components_must_be_active_for_covered_primitive() -> None:
    posture = evaluate_floor_posture(
        states=(
            _state(FloorComponent.MACOS_ENDPOINT_FILE),
            _state(FloorComponent.MACOS_ENDPOINT_PROCESS),
            _state(FloorComponent.MACOS_ENDPOINT_NETWORK),
        ),
        required={
            EndpointPrimitive.FILE_READ: (FloorComponent.MACOS_ENDPOINT_FILE,),
            EndpointPrimitive.PROCESS_EXEC: (FloorComponent.MACOS_ENDPOINT_PROCESS,),
            EndpointPrimitive.NETWORK_CONNECT: (FloorComponent.MACOS_ENDPOINT_NETWORK,),
        },
    )

    assert posture.minimum_floor_satisfied is True
    assert posture.primitive_status["file_read"] == "inline"
    assert posture.primitive_status["process_execute"] == "inline"
    assert posture.primitive_status["network_connect"] == "inline"


def test_dead_or_unverified_component_triggers_anti_downgrade() -> None:
    posture = evaluate_floor_posture(
        states=(
            _state(FloorComponent.MACOS_ENDPOINT_FILE),
            _state(FloorComponent.MACOS_ENDPOINT_NETWORK, active=False),
        ),
        required={
            EndpointPrimitive.FILE_READ: (FloorComponent.MACOS_ENDPOINT_FILE,),
            EndpointPrimitive.NETWORK_CONNECT: (FloorComponent.MACOS_ENDPOINT_NETWORK,),
        },
    )

    assert posture.minimum_floor_satisfied is False
    assert posture.primitive_status["network_connect"] == "not_covered"
    assert "CONTROL_REQUIREMENT_UNSATISFIED:network_connect" in posture.reason_codes


def test_missing_component_is_unknown_not_protected() -> None:
    posture = evaluate_floor_posture(
        states=(),
        required={EndpointPrimitive.FILE_READ: (FloorComponent.MACOS_ENDPOINT_FILE,)},
    )

    assert posture.minimum_floor_satisfied is False
    assert posture.primitive_status == {"file_read": "unknown"}
