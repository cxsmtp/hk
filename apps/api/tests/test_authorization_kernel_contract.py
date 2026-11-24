from __future__ import annotations

from copy import deepcopy
import json
import os
import subprocess
import sys

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.control_engine import authorization
from app.core.control_engine import canonical_action as canonical_contract
from app.services.ai_iam_service import build_ai_action_record


SURFACES = (
    "llm_gateway",
    "mcp_gateway",
    "runtime_control",
    "browser",
    "sdk",
    "internal_mcp",
)


def _settings_env(**overrides: str) -> dict[str, str]:
    env = {
        "secret_key": "auth-kernel-test-secret-key",
        "connector_secrets_key": "auth-kernel-test-connector-key",
        "connector_secrets_kdf_salt": "auth-kernel-test-salt",
        "onprem_bundle_signing_secret": "auth-kernel-test-bundle-key",
        "canonical_action_binding_key": "auth-kernel-test-canonical-binding-key-0001",
        "_env_file": None,
    }
    env.update({key.lower(): value for key, value in overrides.items()})
    return env


def _canonical(surface: str = "llm_gateway", *, risk: str = "low") -> dict:
    return {
        "schema_name": "hawk.ai_action",
        "schema_version": "1.0",
        "adapter": surface,
        "action_id": "action-001",
        "tenant_id": "tenant-001",
        "chain_id": "chain-001",
        "timestamp": "2026-07-21T00:00:00+00:00",
        "actor": {"identity_id": "user-001", "user_id": "user-001", "agent_id": "agent-001"},
        "authority": {
            "authority_type": "delegated",
            "authority_source": "capability-token",
            "permission_scope": ["tool:read"],
            "verified": True,
        },
        "purpose": {"declared_purpose": "customer-support", "purpose_status": "verified"},
        "surface": {
            "surface_type": surface,
            "collector_type": surface,
            "environment": "prod",
            "application": "bank-assistant",
            "asset_status": "approved",
            "mcp_server_id": "mcp-bank" if "mcp" in surface else "unknown",
        },
        "action": {
            "action_type": "tool_execution" if "mcp" in surface or surface == "runtime_control" else "prompt",
            "action_category": "read",
            "risk_level": risk,
            "tool_name": "accounts.read",
            "tool_version": "1",
            "tool_fingerprint_id": "fp-001",
            "parameter_hash": "parameter-hash",
            "target_resource": "account/42",
            "target_resource_hash": "target-hash",
            "data_destination": "internal",
            "destination_hash": "destination-hash",
            "side_effect_class": "read_only",
            "persistent_side_effect": False,
        },
        "content": {
            "input_sensitivity": "internal",
            "output_sensitivity": "internal",
            "taint_labels": [],
        },
        "approval": {"approval_required": False, "approval_status": "not_required"},
        "policy": {"policy_snapshot_id": "policy-001", "matched_rules": [], "decision": "allow"},
        "evidence": {"trace_id": "trace-001"},
    }


def _request(surface: str = "llm_gateway", *, risk: str = "low", authority_verified: bool = True):
    canonical = _canonical(surface, risk=risk)
    canonical["authority"]["verified"] = authority_verified
    return authorization.adapt_authorization_request(
        canonical,
        collector_id=f"collector-{surface}",
        policy_snapshot_id="policy-001",
        policy_profile={
            "base_decision": "allow",
            "matched_rules": [],
            "dependencies_healthy": True,
            "cache_ttl": 15,
            "degraded_behavior": "block",
        },
        path_evidence={
            "collector_inline_capable": True,
            "inline_pre_execution": True,
        },
    )


def test_authorization_response_is_byte_stable_for_same_request_and_policy() -> None:
    request = _request()

    first = authorization.authorize_ai_action(request)
    second = authorization.authorize_ai_action(deepcopy(request))

    assert first.to_canonical_json() == second.to_canonical_json()
    assert first.response_hash == second.response_hash
    assert first.decision == "allow"
    assert first.policy_snapshot_id == "policy-001"


def test_server_resolved_pre_action_context_survives_record_canonical_and_authorization(
    monkeypatch,
) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "canonical_action_binding_key", "authorization-trace-binding-key-0001")
    server_parameter_hash = "1" * 64
    trusted_context = {
        "authority": {
            "authority_type": "capability_token",
            "authority_source": "persisted_mcp_session",
            "verified": True,
            "permission_scope": ["tool:read"],
        },
        "surface": {
            "surface_type": "mcp",
            "application": "bank-mcp",
            "asset_status": "approved",
            "environment": "prod",
        },
        "action": {
            "action_type": "tool_execution",
            "action_risk": "low",
            "tool_name": "accounts.read",
            "tool_version": "1",
            "tool_fingerprint_id": "fingerprint-approved-001",
            "parameter_hash": server_parameter_hash,
            "target_resource": "account/42",
        },
    }
    record = build_ai_action_record(
        tenant_id="tenant-trace",
        action_id="action-trace",
        timestamp="2026-07-21T00:00:00+00:00",
        source_surface="gateway",
        event_type="mcp_authorize",
        agent_id="agent-trace",
        ai_system_id="system-trace",
        decision="allow",
        correlation_id="correlation-trace",
        chain_id="chain-trace",
        metadata={"pre_action_governance_check": {"authority": {"verified": False}}},
        trusted_pre_action_governance_check=trusted_context,
    )
    canonical = canonical_contract.adapt_mcp_gateway_action(record)
    request = authorization.adapt_mcp_gateway_authorization_request(
        canonical,
        collector_id="mcp-gateway",
        policy_snapshot_id="policy-trace",
        policy_profile={"base_decision": "allow", "dependencies_healthy": True},
    )

    assert record["authority"]["verified"] is True
    assert record["surface"]["asset_status"] == "approved"
    assert record["action"]["tool_fingerprint_id"] == "fingerprint-approved-001"
    assert record["action"]["parameter_hash"] == server_parameter_hash
    assert record["action"]["parameter_hash_binding"]
    assert canonical["authority"]["verified"] is True
    assert canonical["surface"]["asset_status"] == "approved"
    assert canonical["action"]["tool_fingerprint_id"] == "fingerprint-approved-001"
    assert canonical["action"]["parameter_hash"] == server_parameter_hash
    assert request.authority["verified"] is True
    assert request.discovery_context["asset_status"] == "approved"
    assert request.tool["fingerprint_id"] == "fingerprint-approved-001"
    assert request.parameters["parameter_hash"] == server_parameter_hash
    assert authorization.authorize_ai_action(request).decision == "allow"


def test_caller_metadata_cannot_forge_trusted_pre_action_authority(monkeypatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "canonical_action_binding_key", "authorization-forgery-binding-key-0001")
    forged = {
        "authority": {
            "authority_type": "capability_token",
            "authority_source": "caller_payload",
            "verified": True,
        },
        "surface": {"asset_status": "approved"},
        "action": {"tool_fingerprint_id": "caller-fingerprint"},
    }
    record = build_ai_action_record(
        tenant_id="tenant-forgery",
        action_id="action-forgery",
        timestamp="2026-07-21T00:00:00+00:00",
        source_surface="gateway",
        event_type="mcp_authorize",
        agent_id="agent-forgery",
        decision="allow",
        correlation_id="correlation-forgery",
        chain_id="chain-forgery",
        metadata={
            "pre_action_governance_check": forged,
            "action_type": "tool_execution",
            "target_resource": "account/42",
            "tool_name": "accounts.read",
        },
    )
    canonical = canonical_contract.adapt_mcp_gateway_action(record)
    request = authorization.adapt_mcp_gateway_authorization_request(
        canonical,
        collector_id="mcp-gateway",
        policy_snapshot_id="policy-forgery",
        policy_profile={"base_decision": "allow", "dependencies_healthy": True},
    )

    assert record["authority"].get("verified") is not True
    assert record["surface"].get("asset_status") != "approved"
    assert record["action"].get("tool_fingerprint_id") != "caller-fingerprint"
    assert authorization.authorize_ai_action(request).decision != "allow"


@pytest.mark.parametrize("surface", SURFACES)
def test_six_surface_adapters_use_one_request_contract_and_decision(surface: str) -> None:
    adapter = getattr(authorization, f"adapt_{surface}_authorization_request")
    request = adapter(
        _canonical(surface),
        collector_id=f"collector-{surface}",
        policy_snapshot_id="policy-001",
        policy_profile={"base_decision": "allow", "dependencies_healthy": True},
        path_evidence={"collector_inline_capable": True, "inline_pre_execution": True},
    )

    response = authorization.authorize_ai_action(request)

    assert isinstance(request, authorization.AuthorizationRequest)
    assert request.surface == surface
    assert response.decision == "allow"


@pytest.mark.parametrize(
    ("risk", "expected"),
    (("low", "review"), ("medium", "require_approval"), ("high", "block"), ("unknown", "block")),
)
def test_unknown_authority_never_silently_allows(risk: str, expected: str) -> None:
    response = authorization.authorize_ai_action(
        _request(risk=risk, authority_verified=False)
    )

    assert response.decision == expected
    assert response.reason.startswith("authority_unverified")


def test_unknown_high_risk_target_fails_closed() -> None:
    request = _request(risk="high")
    request["discovery_context"] = {"asset_status": "unknown"}

    response = authorization.authorize_ai_action(request)

    assert response.decision == "block"
    assert response.reason.startswith("target_authority_unknown")


def test_high_risk_external_send_without_verified_destination_fails_closed() -> None:
    request = _request(risk="high")
    request["action"]["action_type"] = "api_call"
    request["target"]["destination"] = "external"
    request["target"]["destination_hash"] = "unknown"

    response = authorization.authorize_ai_action(request)

    assert response.decision == "block"
    assert response.reason.startswith("target_authority_unknown")


@pytest.mark.parametrize(
    ("risk", "expected"),
    (("low", "review"), ("medium", "require_approval"), ("high", "block")),
)
@pytest.mark.parametrize("asset_status", (None, "", "unknown", "unverified"))
def test_missing_or_unverified_asset_status_never_allows(
    risk: str, expected: str, asset_status: str | None
) -> None:
    request = _request(risk=risk)
    request["discovery_context"]["asset_status"] = asset_status

    response = authorization.authorize_ai_action(request)

    assert response.decision == expected
    assert response.reason.startswith("target_authority_unknown")


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("schema_version", "3.0"),
        ("surface", "proxy"),
    ),
)
def test_request_contract_rejects_invalid_enums(field: str, invalid: str) -> None:
    payload = _request().model_dump()
    payload[field] = invalid
    with pytest.raises(ValidationError):
        authorization.AuthorizationRequest.model_validate(payload)


def test_request_contract_rejects_extra_fields() -> None:
    payload = _request().model_dump()
    payload["caller_enforce"] = True
    with pytest.raises(ValidationError):
        authorization.AuthorizationRequest.model_validate(payload)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda payload: payload["policy_profile"].update({"nested": {"x": {"y": {"z": {"q": {"r": {"s": {"t": {"u": {"v": {"w": {"a": {"b": {"c": {"d": {"e": {"f": "too-deep"}}}}}}}}}}}}}}}}}),
        lambda payload: payload["policy_profile"].update({"oversized": "x" * 70_000}),
        lambda payload: payload["policy_profile"].update({"wide": {str(index): index for index in range(1_025)}}),
    ),
)
def test_request_contract_rejects_unbounded_nested_material(mutation) -> None:
    payload = _request().model_dump()
    mutation(payload)

    with pytest.raises(ValidationError):
        authorization.AuthorizationRequest.model_validate(payload)


@pytest.mark.parametrize(
    "invalid",
    ({"set-value"}, frozenset({"frozen-value"}), ("tuple-value",), object()),
)
def test_request_contract_rejects_non_json_container_types(invalid) -> None:
    payload = _request().model_dump()
    payload["policy_profile"]["non_json"] = invalid

    with pytest.raises(ValidationError):
        authorization.AuthorizationRequest.model_validate(payload)


def test_authorization_response_is_stable_across_process_hash_seeds() -> None:
    payload_json = json.dumps(_request().model_dump(mode="json"), sort_keys=True)
    script = (
        "import json; "
        "from app.core.control_engine.authorization import AuthorizationRequest, authorize_ai_action; "
        f"request=AuthorizationRequest.model_validate(json.loads({payload_json!r})); "
        "print(authorize_ai_action(request).to_canonical_json())"
    )
    outputs = []
    for seed in ("1", "987654"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        outputs.append(
            subprocess.check_output(
                [sys.executable, "-c", script],
                cwd=os.getcwd(),
                env=env,
                text=True,
            ).strip()
        )

    assert outputs[0] == outputs[1]


def test_invalid_risk_token_normalizes_to_unknown_and_fails_closed() -> None:
    request = _request()
    request["action"]["risk_level"] = "banana"
    request["parameters"]["parameter_hash"] = "unknown"

    response = authorization.authorize_ai_action(request)

    assert response.decision == "block"
    assert response.reason == "risk_classification_invalid:risk=unknown"


@pytest.mark.parametrize(
    ("risk", "expected"),
    (("low", "review"), ("medium", "require_approval"), ("high", "block")),
)
def test_executable_action_missing_server_parameter_hash_fails_closed(
    risk: str, expected: str
) -> None:
    request = _request("mcp_gateway", risk=risk)
    request["parameters"]["parameter_hash"] = "unknown"

    response = authorization.authorize_ai_action(request)

    assert response.decision == expected
    assert response.reason.startswith("parameter_binding_unknown")


def test_changed_executable_parameters_fail_closed_against_server_expected_hash() -> None:
    request = _request("mcp_gateway", risk="high")
    request["parameters"]["parameter_hash"] = "actual-args-hash"
    request["policy_profile"]["expected_parameter_hash"] = "approved-args-hash"

    response = authorization.authorize_ai_action(request)

    assert response.decision == "block"
    assert response.reason.startswith("parameter_binding_mismatch")


def test_known_safe_read_with_server_parameter_hash_remains_allowed() -> None:
    response = authorization.authorize_ai_action(_request("mcp_gateway", risk="low"))

    assert response.decision == "allow"


@pytest.mark.parametrize(
    ("field", "invalid"),
    (
        ("schema_version", "3.0"),
        ("decision", "deny"),
        ("control_mode", "blocked"),
        ("degraded_behavior", "allow"),
    ),
)
def test_response_contract_rejects_invalid_enums(field: str, invalid: str) -> None:
    payload = authorization.authorize_ai_action(_request()).model_dump()
    payload[field] = invalid
    with pytest.raises(ValidationError):
        authorization.AuthorizationResponse.model_validate(payload)


def test_response_contract_rejects_extra_fields() -> None:
    payload = authorization.authorize_ai_action(_request()).model_dump()
    payload["raw_content"] = "forbidden"
    with pytest.raises(ValidationError):
        authorization.AuthorizationResponse.model_validate(payload)


@pytest.mark.parametrize("missing_field", ("authority_type", "authority_source"))
def test_verified_bit_cannot_replace_missing_authority_identity(missing_field: str) -> None:
    request = _request(risk="high")
    request["authority"].pop(missing_field)

    response = authorization.authorize_ai_action(request)

    assert response.decision == "block"
    assert response.reason.startswith("authority_unverified")


def test_surface_adapter_rejects_mismatched_canonical_surface() -> None:
    with pytest.raises(ValueError, match="surface mismatch"):
        authorization.adapt_mcp_gateway_authorization_request(
            _canonical("browser"),
            collector_id="mcp-collector",
            policy_snapshot_id="policy-001",
            policy_profile={"base_decision": "allow", "dependencies_healthy": True},
        )


def test_dependency_failure_uses_fail_closed_degraded_behavior() -> None:
    request = _request()
    request["policy_profile"]["dependencies_healthy"] = False
    request["policy_profile"]["degraded_behavior"] = "require_approval"

    response = authorization.authorize_ai_action(request)

    assert response.decision == "require_approval"
    assert response.degraded_behavior == "require_approval"
    assert response.reason == "authorization_dependency_unavailable"


def test_control_mode_does_not_claim_prevention_without_execution_proof() -> None:
    request = _request(risk="high", authority_verified=False)

    response = authorization.authorize_ai_action(request)

    assert response.decision == "block"
    assert response.control_mode == "incomplete"


def test_shadow_block_is_honestly_labeled() -> None:
    request = _request(risk="high", authority_verified=False)
    request["path_evidence"] = {
        "collector_inline_capable": True,
        "inline_pre_execution": True,
        "shadow_evaluation": True,
        "shadow_would_block": True,
    }

    response = authorization.authorize_ai_action(request)

    assert response.control_mode == "shadow_would_block"


def test_shadow_comparison_is_redacted_bounded_and_idempotent() -> None:
    request = _request()
    response = authorization.authorize_ai_action(request)
    metadata = {"prompt": "do not persist me", "authorization_kernel_v2_enforce": True}

    first = authorization.persist_shadow_comparison_metadata(
        metadata,
        request=request,
        response=response,
        legacy_decision="allow",
        legacy_reason="secret customer payload 4111 1111 1111 1111",
        legacy_control_mode="inline_allowed",
        legacy_policy_snapshot_id="legacy-policy",
    )
    second = authorization.persist_shadow_comparison_metadata(
        first,
        request=request,
        response=response,
        legacy_decision="allow",
        legacy_reason="secret customer payload 4111 1111 1111 1111",
        legacy_control_mode="inline_allowed",
        legacy_policy_snapshot_id="legacy-policy",
    )

    comparison = first["authorization_kernel_v2_shadow"]
    encoded = json.dumps(comparison, sort_keys=True)
    assert first == second
    assert "secret customer" not in encoded
    assert "4111" not in encoded
    assert len(encoded.encode()) <= authorization.MAX_SHADOW_COMPARISON_BYTES
    assert set(comparison) == {
        "schema_version",
        "action_id",
        "legacy",
        "v2",
        "parity",
        "comparison_hash",
    }


def test_shadow_authority_never_changes_legacy_result_or_metadata_when_flag_off() -> None:
    settings = Settings(**_settings_env())
    metadata = {"decision": "allow", "authorization_kernel_v2_enforce": True}

    outcome = authorization.apply_authorization_rollout(
        metadata=metadata,
        request=_request(risk="high", authority_verified=False),
        legacy_decision="allow",
        legacy_reason="legacy_allow",
        legacy_control_mode="inline_allowed",
        settings_obj=settings,
    )

    assert outcome.authoritative_decision == "allow"
    assert outcome.metadata == metadata
    assert outcome.v2_response is None


def test_flag_off_preserves_legacy_decision_token_exactly() -> None:
    settings = Settings(**_settings_env())

    outcome = authorization.apply_authorization_rollout(
        metadata={},
        request=_request(),
        legacy_decision="Allowed",
        legacy_reason="legacy_allow",
        legacy_control_mode="inline_allowed",
        settings_obj=settings,
    )

    assert outcome.authoritative_decision == "Allowed"


@pytest.mark.parametrize(
    "settings",
    (
        Settings(**_settings_env()),
        Settings(
            **_settings_env(
                AUTHORIZATION_KERNEL_V2_ENABLED="true",
                AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED="true",
                AUTHORIZATION_KERNEL_V2_ENFORCE="true",
                AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT='{"tenant-other":["mcp_gateway"]}',
            )
        ),
    ),
    ids=("disabled", "enabled-unselected-shadow"),
)
def test_trusted_pre_action_unselected_is_exact_legacy_noop_before_validation(
    settings: Settings,
    monkeypatch,
) -> None:
    oversized_invalid_material = {
        "actor": {"nested": {"too_wide": {str(index): index for index in range(1_025)}}},
        "action": {"action_risk": "not-a-risk", "oversized": "x" * 70_000},
    }

    def fail_if_request_is_constructed(*args, **kwargs):
        raise AssertionError("unselected pre-action material must not be validated")

    monkeypatch.setattr(authorization, "AuthorizationRequest", fail_if_request_is_constructed)

    outcome = authorization.apply_trusted_pre_action_rollout(
        tenant_id="tenant-001",
        surface="mcp_gateway",
        action_id="legacy-action",
        chain_id="legacy-chain",
        collector_id="legacy-collector",
        trusted_pre_action_governance_check=oversized_invalid_material,
        legacy_decision="Allowed",
        legacy_reason="legacy reason remains untouched",
        legacy_control_mode="legacy-control-token",
        policy_snapshot_id="legacy-policy",
        settings_obj=settings,
    )

    assert outcome == authorization.AuthorizationRolloutOutcome(
        authoritative_decision="Allowed",
        metadata={},
        v2_response=None,
        enforced=False,
    )


def test_caller_cannot_forge_enforcement_rollout() -> None:
    settings = Settings(
        **_settings_env(
            AUTHORIZATION_KERNEL_V2_ENABLED="true",
            AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED="true",
            AUTHORIZATION_KERNEL_V2_ENFORCE="true",
            AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT='{"tenant-other":["llm_gateway"]}',
        )
    )

    outcome = authorization.apply_authorization_rollout(
        metadata={"authorization_kernel_v2_enforce": True, "tenant_id": "tenant-001"},
        request=_request(risk="high", authority_verified=False),
        legacy_decision="allow",
        legacy_reason="legacy_allow",
        legacy_control_mode="inline_allowed",
        settings_obj=settings,
    )

    assert outcome.authoritative_decision == "allow"
    assert outcome.v2_response is not None
    assert outcome.metadata["authorization_kernel_v2_shadow"]["v2"]["decision"] == "block"


def test_server_rollout_can_make_v2_authoritative_for_exact_tenant_surface() -> None:
    settings = Settings(
        **_settings_env(
            AUTHORIZATION_KERNEL_V2_ENABLED="true",
            AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED="true",
            AUTHORIZATION_KERNEL_V2_ENFORCE="true",
            AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT='{"tenant-001":["llm_gateway"]}',
        )
    )

    outcome = authorization.apply_authorization_rollout(
        metadata={},
        request=_request(risk="high", authority_verified=False),
        legacy_decision="allow",
        legacy_reason="legacy_allow",
        legacy_control_mode="inline_allowed",
        settings_obj=settings,
    )

    assert outcome.authoritative_decision == "block"


def test_selected_rollout_builds_bounded_validated_persistence_metadata() -> None:
    settings = Settings(
        **_settings_env(
            AUTHORIZATION_KERNEL_V2_ENABLED="true",
            AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED="true",
            AUTHORIZATION_KERNEL_V2_ENFORCE="true",
            AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT='{"tenant-001":["llm_gateway"]}',
        )
    )
    outcome = authorization.apply_authorization_rollout(
        metadata={},
        request=_request(risk="high", authority_verified=False),
        legacy_decision="allow",
        legacy_reason="legacy_allow",
        legacy_control_mode="inline_allowed",
        legacy_policy_snapshot_id="policy-001",
        settings_obj=settings,
    )

    persisted = authorization.authorization_rollout_persistence_metadata(outcome)
    validated = authorization.validate_precomputed_authorization_metadata(
        persisted,
        expected_action_id="action-001",
        expected_policy_snapshot_id="policy-001",
    )

    assert persisted == validated
    assert set(persisted) == {
        "authorization_kernel_v2_shadow",
        "authorization_kernel_v2_shadow_health",
    }
    assert persisted["authorization_kernel_v2_shadow_health"] == {
        "schema_version": "2.0",
        "status": "ok",
        "error_code": None,
    }


@pytest.mark.parametrize("surface", ("browser", "sdk"))
def test_startup_rejects_enforcement_selection_for_post_action_only_surface(surface: str) -> None:
    with pytest.raises(ValueError, match="pre-side-effect authorization hook"):
        Settings(
            **_settings_env(
                AUTHORIZATION_KERNEL_V2_ENABLED="true",
                AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED="true",
                AUTHORIZATION_KERNEL_V2_ENFORCE="true",
                AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT=json.dumps({"tenant-001": [surface]}),
            )
        )


@pytest.mark.parametrize(
    "overrides",
    (
        {"AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED": "true"},
        {"AUTHORIZATION_KERNEL_V2_ENFORCE": "true"},
        {
            "AUTHORIZATION_KERNEL_V2_ENABLED": "true",
            "AUTHORIZATION_KERNEL_V2_ENFORCE": "true",
            "AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT": '{"tenant-001":["llm_gateway"]}',
        },
        {
            "AUTHORIZATION_KERNEL_V2_ENABLED": "true",
            "AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED": "true",
            "AUTHORIZATION_KERNEL_V2_ENFORCE": "true",
            "AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT": '{}',
        },
    ),
)
def test_unsafe_flag_combinations_are_rejected(overrides: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        Settings(**_settings_env(**overrides))
