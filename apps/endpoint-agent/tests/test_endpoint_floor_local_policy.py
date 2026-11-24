from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime, timedelta

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


PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x19" * 32)
PUBLIC = PRIVATE.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
NOW = datetime(2026, 8, 12, 10, 0, tzinfo=UTC)


def _identity(*, digest: str = "sha256:binary") -> EndpointProcessIdentity:
    return EndpointProcessIdentity(
        process_id=100,
        parent_process_id=10,
        process_start_time_ns=55,
        binary_path="/Applications/UnknownAI.app/Contents/MacOS/UnknownAI",
        binary_signature="TEAM:unknown.ai",
        binary_hash_reference=digest,
        bundle_or_package_identity="unknown.ai",
        user_id="user-1",
        device_id="device-1",
        session_id="session-1",
        process_name="UnknownAI",
    )


def _policy() -> dict[str, object]:
    return {
        "schema": "hawk.endpoint-fast-path-policy",
        "version": 1,
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "policy_version": "policy-7",
        "issued_at": "2026-08-12T09:55:00Z",
        "expires_at": "2026-08-12T10:05:00Z",
        "rules": [
            {
                "rule_id": "block-sensitive-external",
                "priority": 10,
                "match": {
                    "primitives": ["file_read", "external_transfer"],
                    "resource_classifications": ["restricted"],
                    "destination_classifications": ["external", "unknown"],
                },
                "action": "block",
            },
            {
                "rule_id": "allow-approved-read",
                "priority": 20,
                "match": {
                    "primitives": ["file_read"],
                    "resource_classifications": ["public"],
                },
                "action": "allow",
            },
        ],
        "degradation": {
            "low_risk_read": "allow_with_evidence",
            "sensitive_file_read": "fail_closed",
            "file_write": "local_policy_only",
            "process_exec": "local_policy_only",
            "known_approved_destination": "allow_with_evidence",
            "unknown_external_destination": "require_exception",
            "sensitive_external_transfer": "fail_closed",
            "mcp_local_connection": "require_exception",
        },
    }


def _signed(policy: dict[str, object] | None = None) -> dict[str, object]:
    body = copy.deepcopy(policy or _policy())
    return {
        "key_id": "endpoint-policy-prod-1",
        "algorithm": "Ed25519",
        "policy": body,
        "signature": base64.b64encode(PRIVATE.sign(canonical_policy_bytes(body))).decode("ascii"),
    }


def _context(**overrides) -> EndpointPrimitiveContext:
    values = {
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "process": _identity(),
        "primitive": EndpointPrimitive.FILE_READ,
        "resource_reference": "file:hash",
        "resource_classification": "restricted",
        "destination_reference": "destination:hash",
        "destination_classification": "external",
        "business_purpose_reference": "purpose:quarterly-review",
        "policy_version": "policy-7",
        "deadline_monotonic_ns": None,
    }
    values.update(overrides)
    return EndpointPrimitiveContext(**values)


def test_signed_policy_blocks_a_sensitive_file_read_deterministically() -> None:
    fast_path = EndpointPolicyFastPath.load_signed(
        _signed(),
        trusted_public_keys={"endpoint-policy-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )

    decision = fast_path.evaluate(_context(), now_monotonic_ns=1, now=NOW)

    assert decision.action is FastPathAction.BLOCK
    assert decision.rule_id == "block-sensitive-external"
    assert decision.policy_version == "policy-7"
    assert decision.cache_hit is False
    assert fast_path.evaluate(_context(), now_monotonic_ns=2, now=NOW).cache_hit is True


def test_cache_scope_includes_binary_operation_resource_destination_policy_and_purpose() -> None:
    fast_path = EndpointPolicyFastPath.load_signed(
        _signed(),
        trusted_public_keys={"endpoint-policy-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )
    first = fast_path.evaluate(_context(), now_monotonic_ns=1, now=NOW)
    changed = fast_path.evaluate(
        _context(
            process=_identity(digest="sha256:changed"),
            destination_reference="destination:other",
        ),
        now_monotonic_ns=2,
        now=NOW,
    )

    assert first.cache_hit is False
    assert changed.cache_hit is False
    assert first.cache_key != changed.cache_key


def test_tampered_expired_wrong_scope_and_unknown_key_fail_closed() -> None:
    cases = []
    tampered = _signed()
    tampered["policy"]["policy_version"] = "attacker"
    cases.append(tampered)
    expired_policy = _policy()
    expired_policy["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
    cases.append(_signed(expired_policy))
    wrong_tenant = _policy()
    wrong_tenant["tenant_id"] = "tenant-2"
    cases.append(_signed(wrong_tenant))
    unknown_key = _signed()
    unknown_key["key_id"] = "unknown-key"
    cases.append(unknown_key)

    for envelope in cases:
        result = EndpointPolicyFastPath.try_load_signed(
            envelope,
            trusted_public_keys={"endpoint-policy-prod-1": PUBLIC},
            expected_tenant_id="tenant-1",
            expected_device_id="device-1",
            now=NOW,
        )
        assert result.accepted is False
        assert result.fast_path is None
        assert result.failures


def test_deadline_exhaustion_uses_per_primitive_degradation_without_remote_lookup() -> None:
    fast_path = EndpointPolicyFastPath.load_signed(
        _signed(),
        trusted_public_keys={"endpoint-policy-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )
    context = _context(
        primitive=EndpointPrimitive.MCP_LOCAL_CONNECTION,
        deadline_monotonic_ns=100,
    )

    decision = fast_path.evaluate(context, now_monotonic_ns=101, now=NOW)

    assert decision.action is FastPathAction.LOCAL_ESCALATION_REQUIRED
    assert decision.reason == "deadline_exhausted:require_exception"
    assert decision.remote_lookup_performed is False


def test_expired_policy_invalidates_cached_allows_at_evaluation_time() -> None:
    fast_path = EndpointPolicyFastPath.load_signed(
        _signed(),
        trusted_public_keys={"endpoint-policy-prod-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )
    first = fast_path.evaluate(_context(), now_monotonic_ns=1, now=NOW)
    later = NOW + timedelta(seconds=301)
    expired = fast_path.evaluate(_context(), now_monotonic_ns=2, now=later)

    assert first.action is FastPathAction.BLOCK
    assert expired.cache_hit is False
    assert expired.reason == "policy_not_current"
    assert expired.action is FastPathAction.BLOCK
