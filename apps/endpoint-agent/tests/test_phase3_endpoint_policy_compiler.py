from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hawk_endpoint_agent.endpoint_floor.contracts import (
    EndpointPrimitive,
    EndpointPrimitiveContext,
    EndpointProcessIdentity,
)
from hawk_endpoint_agent.endpoint_floor.local_policy import (
    EndpointPolicyFastPath,
    FastPathAction,
    canonical_policy_bytes,
)
from hawk_endpoint_agent.endpoint_floor.policy_compiler import EndpointPolicyCompiler


NOW = datetime(2026, 8, 15, 10, 0, tzinfo=UTC)
PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
PUBLIC = PRIVATE.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def _source_policy(*, unsupported: bool = False) -> dict[str, object]:
    conditions: dict[str, object] = {
        "primitives": ["file_read"],
        "resource_classifications": ["public"],
    }
    if unsupported:
        conditions["live_model_reputation"] = ["trusted"]
    return {
        "policy_id": "policy-source-1",
        "rules": [
            {
                "rule_id": "allow-public-read",
                "priority": 20,
                "conditions": conditions,
                "decision": "allow",
            },
            {
                "rule_id": "block-external-transfer",
                "priority": 10,
                "conditions": {
                    "primitives": ["external_transfer"],
                    "destination_classifications": ["external"],
                },
                "decision": "block",
            },
        ],
        "user_group_scope": {"users": ["user-1"], "groups": ["security"]},
        "business_purpose_references": ["purpose:approved-development"],
        "exception_references": [],
    }


def _compile(*, unsupported: bool = False) -> dict[str, object]:
    return EndpointPolicyCompiler().compile(
        _source_policy(unsupported=unsupported),
        tenant_id="tenant-1",
        device_id="device-1",
        policy_version="policy-8",
        policy_epoch=8,
        issued_at="2026-08-15T09:55:00Z",
        expires_at="2026-08-15T10:05:00Z",
        rollback_version="policy-7",
        platform_capability_requirements=("file_open_control", "network_connect_control"),
    )


def _signed(policy: dict[str, object]) -> dict[str, object]:
    return {
        "key_id": "endpoint-policy-prod-2",
        "algorithm": "Ed25519",
        "policy": copy.deepcopy(policy),
        "signature": base64.b64encode(
            PRIVATE.sign(canonical_policy_bytes(policy))
        ).decode("ascii"),
    }


def _context(*, epoch: int, primitive: EndpointPrimitive = EndpointPrimitive.FILE_READ) -> EndpointPrimitiveContext:
    process = EndpointProcessIdentity(
        process_id=55,
        parent_process_id=1,
        process_start_time_ns=500,
        binary_path="/Applications/TestAI.app/Contents/MacOS/TestAI",
        binary_signature="TEAM:test.ai",
        binary_hash_reference="sha256:binary",
        bundle_or_package_identity="test.ai",
        user_id="user-1",
        device_id="device-1",
        session_id="session-1",
        tenant_id="tenant-1",
        platform="macos",
    )
    return EndpointPrimitiveContext(
        tenant_id="tenant-1",
        device_id="device-1",
        process=process,
        primitive=primitive,
        resource_reference="file:public",
        resource_classification="public",
        destination_reference="destination:external",
        destination_classification="external",
        business_purpose_reference="purpose:approved-development",
        policy_version="policy-8",
        policy_epoch=epoch,
    )


def test_fast_path_actions_are_the_exact_phase3_contract() -> None:
    assert {item.value for item in FastPathAction} == {
        "allow",
        "block",
        "require_preauthorized_permit",
        "require_remote_decision",
        "require_user_retry_after_approval",
        "allow_with_evidence",
    }
    assert FastPathAction.LOCAL_ESCALATION_REQUIRED is FastPathAction.REQUIRE_USER_RETRY_AFTER_APPROVAL
    assert FastPathAction("remote_enrichment_allowed") is FastPathAction.ALLOW_WITH_EVIDENCE


def test_compiler_is_deterministic_and_exposes_supported_truth() -> None:
    forward = _compile()
    source = _source_policy()
    source["rules"] = list(reversed(source["rules"]))
    reverse = EndpointPolicyCompiler().compile(
        source,
        tenant_id="tenant-1",
        device_id="device-1",
        policy_version="policy-8",
        policy_epoch=8,
        issued_at="2026-08-15T09:55:00Z",
        expires_at="2026-08-15T10:05:00Z",
        rollback_version="policy-7",
        platform_capability_requirements=("network_connect_control", "file_open_control"),
    )

    assert canonical_policy_bytes(forward) == canonical_policy_bytes(reverse)
    assert forward["version"] == 2
    assert forward["policy_epoch"] == 8
    assert forward["rollback_version"] == "policy-7"
    assert forward["omitted_predicates"] == []
    assert forward["required_remote_context"] == []
    assert forward["supported_primitives"] == ["external_transfer", "file_read"]
    assert forward["platform_capability_requirements"] == [
        "file_open_control",
        "network_connect_control",
    ]


def test_unsupported_predicate_is_explicit_and_cannot_silently_allow() -> None:
    policy = _compile(unsupported=True)
    assert policy["omitted_predicates"] == ["live_model_reputation"]
    assert policy["required_remote_context"] == ["live_model_reputation"]

    fast_path = EndpointPolicyFastPath.load_signed(
        _signed(policy),
        trusted_public_keys={"endpoint-policy-prod-2": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )
    decision = fast_path.evaluate(_context(epoch=8), now=NOW, now_monotonic_ns=1)
    assert decision.action is FastPathAction.REQUIRE_REMOTE_DECISION
    assert decision.rule_id == "compiler-remote-evaluation-required"


@pytest.mark.parametrize(
    "forbidden",
    [
        {"script": "rm -rf /"},
        {"command": ["powershell.exe", "-Command"]},
        {"plugin_url": "https://attacker.invalid/module"},
        {"executable_module": "payload.dll"},
    ],
)
def test_compiler_rejects_executable_policy_channel_material(forbidden: dict[str, object]) -> None:
    source = _source_policy()
    source["delivery"] = forbidden
    with pytest.raises(ValueError, match="executable policy material"):
        EndpointPolicyCompiler().compile(
            source,
            tenant_id="tenant-1",
            device_id="device-1",
            policy_version="policy-8",
            policy_epoch=8,
            issued_at="2026-08-15T09:55:00Z",
            expires_at="2026-08-15T10:05:00Z",
            rollback_version="policy-7",
            platform_capability_requirements=(),
        )


def test_signed_v2_policy_binds_epoch_and_invalidates_old_authority() -> None:
    fast_path = EndpointPolicyFastPath.load_signed(
        _signed(_compile()),
        trusted_public_keys={"endpoint-policy-prod-2": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )

    allowed = fast_path.evaluate(_context(epoch=8), now=NOW, now_monotonic_ns=1)
    stale = fast_path.evaluate(_context(epoch=7), now=NOW, now_monotonic_ns=2)

    assert allowed.action is FastPathAction.ALLOW
    assert allowed.policy_epoch == 8
    assert stale.action is FastPathAction.BLOCK
    assert stale.reason == "policy_epoch_mismatch"
    assert fast_path.invalidate_for_policy_epoch(8) is True
    assert fast_path.invalidate_for_policy_epoch(9) is False


def test_v2_bundle_rejects_undeclared_executable_fields_after_signing() -> None:
    policy = _compile()
    policy["shell"] = "echo bypass"
    result = EndpointPolicyFastPath.try_load_signed(
        _signed(policy),
        trusted_public_keys={"endpoint-policy-prod-2": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )
    assert result.accepted is False
    assert "invalid_policy_fields" in result.failures
