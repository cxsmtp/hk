from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from time import perf_counter_ns

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


NOW = datetime(2026, 8, 12, 10, 0, tzinfo=UTC)
PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x27" * 32)
PUBLIC = PRIVATE.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def _policy() -> dict:
    return {
        "schema": "hawk.endpoint-fast-path-policy",
        "version": 1,
        "tenant_id": "tenant-1",
        "device_id": "device-1",
        "policy_version": "policy-security-1",
        "issued_at": "2026-08-12T09:55:00Z",
        "expires_at": "2026-08-12T10:05:00Z",
        "rules": [
            {
                "rule_id": "approved-binary-exec",
                "priority": 10,
                "match": {
                    "primitives": ["process_exec"],
                    "binary_identities": ["sha256:approved"],
                },
                "action": "allow",
            }
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


def _signed(policy: dict) -> dict:
    return {
        "key_id": "policy-key-1",
        "algorithm": "Ed25519",
        "policy": policy,
        "signature": base64.b64encode(PRIVATE.sign(canonical_policy_bytes(policy))).decode("ascii"),
    }


def _process(*, digest: str, user_id: str = "user-1") -> EndpointProcessIdentity:
    return EndpointProcessIdentity(
        process_id=900,
        parent_process_id=1,
        process_start_time_ns=123_456,
        binary_path="/Applications/Approved.app/Contents/MacOS/Approved",
        binary_signature="TEAM:approved",
        binary_hash_reference=digest,
        bundle_or_package_identity="com.example.approved",
        user_id=user_id,
        device_id="device-1",
        session_id=f"session:{user_id}",
        process_name="Approved",
    )


def _context(*, digest: str = "sha256:approved", user_id: str = "user-1") -> EndpointPrimitiveContext:
    return EndpointPrimitiveContext(
        tenant_id="tenant-1",
        device_id="device-1",
        process=_process(digest=digest, user_id=user_id),
        primitive=EndpointPrimitive.PROCESS_EXEC,
        resource_reference="binary:approved",
        resource_classification="internal",
        destination_reference=None,
        destination_classification="local",
        business_purpose_reference="purpose:approved-development",
        policy_version="policy-security-1",
    )


def _load() -> EndpointPolicyFastPath:
    return EndpointPolicyFastPath.load_signed(
        _signed(_policy()),
        trusted_public_keys={"policy-key-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )


def test_same_name_and_path_cannot_bypass_binary_identity() -> None:
    fast_path = _load()

    approved = fast_path.evaluate(_context(), now=NOW, now_monotonic_ns=1)
    replaced_binary = fast_path.evaluate(_context(digest="sha256:replaced"), now=NOW, now_monotonic_ns=2)

    assert approved.action is FastPathAction.ALLOW
    assert replaced_binary.action is FastPathAction.BLOCK
    assert replaced_binary.reason == "no_matching_rule:local_policy_only"
    assert approved.cache_key != replaced_binary.cache_key


def test_cache_is_isolated_between_users_on_the_same_device() -> None:
    fast_path = _load()

    first_user = fast_path.evaluate(_context(user_id="user-1"), now=NOW, now_monotonic_ns=1)
    second_user = fast_path.evaluate(_context(user_id="user-2"), now=NOW, now_monotonic_ns=2)

    assert first_user.cache_hit is False
    assert second_user.cache_hit is False
    assert first_user.cache_key != second_user.cache_key


def test_oversized_policy_is_rejected_before_activation() -> None:
    policy = _policy()
    policy["rules"] = [
        {
            "rule_id": f"rule-{index}",
            "priority": index,
            "match": {},
            "action": "block",
        }
        for index in range(4097)
    ]

    result = EndpointPolicyFastPath.try_load_signed(
        _signed(policy),
        trusted_public_keys={"policy-key-1": PUBLIC},
        expected_tenant_id="tenant-1",
        expected_device_id="device-1",
        now=NOW,
    )

    assert result.accepted is False
    assert result.fast_path is None
    assert "rules_invalid" in result.failures


def test_cached_local_decision_latency_has_a_bounded_development_ceiling() -> None:
    fast_path = _load()
    context = _context()
    fast_path.evaluate(context, now=NOW, now_monotonic_ns=1)
    samples_ms: list[float] = []

    for sequence in range(1, 5001):
        started = perf_counter_ns()
        decision = fast_path.evaluate(context, now=NOW, now_monotonic_ns=sequence + 1)
        samples_ms.append((perf_counter_ns() - started) / 1_000_000)
        assert decision.remote_lookup_performed is False

    ordered = sorted(samples_ms)
    p50 = ordered[int(len(ordered) * 0.50)]
    p95 = ordered[int(len(ordered) * 0.95)]
    p99 = ordered[int(len(ordered) * 0.99)]
    print(f"endpoint_fast_path_local_ms p50={p50:.6f} p95={p95:.6f} p99={p99:.6f}")

    # This is a regression ceiling for the Python development implementation,
    # not a production OS callback latency claim. Native acceptance is separate.
    assert p99 < 20.0


def test_current_policy_becomes_ineligible_after_expiry() -> None:
    fast_path = _load()
    decision = fast_path.evaluate(
        _context(), now=NOW + timedelta(minutes=10), now_monotonic_ns=1
    )
    assert decision.action is FastPathAction.BLOCK
    assert decision.reason == "policy_not_current"
