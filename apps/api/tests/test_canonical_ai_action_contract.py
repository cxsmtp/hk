from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings, settings
from app.core.control_engine import canonical_action as contract
from app.db.models.activity_audit import AIAction
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import Base, get_db
from app.main import app


def test_canonical_ai_action_contract_module_exists() -> None:
    assert importlib.util.find_spec("app.core.control_engine.canonical_action") is not None


def test_canonical_ai_action_contract_exports_surface_adapters() -> None:
    expected = {
        "ControlPathEvidence",
        "adapt_browser_action",
        "adapt_internal_mcp_action",
        "adapt_llm_gateway_action",
        "adapt_mcp_gateway_action",
        "adapt_runtime_control_action",
        "adapt_sdk_action",
        "build_canonical_ai_action_v1",
        "canonical_action_hash",
        "canonical_field_hash",
        "canonical_field_material",
        "canonical_projection_reconciliation_counts",
        "canonical_reconciliation_counts",
        "gateway_control_path_evidence",
        "maybe_dual_write_canonical_action",
    }
    assert expected.issubset(set(dir(contract)))


def test_canonical_dual_write_defaults_off() -> None:
    assert settings.canonical_ai_action_dual_write_enabled is False


def _legacy_action(*, decision: str = "block", control_mode: str = "inline_prevented") -> dict:
    return {
        "action_id": "legacy-action-17",
        "tenant_id": "tenant-17",
        "timestamp": "2026-07-17T10:15:00Z",
        "actor": {
            "identity_id": "identity-17",
            "identity_type": "agent",
            "user_id": "user-17",
            "agent_id": "agent-17",
            "session_id": "session-17",
        },
        "authority": {
            "authority_type": "delegated_agent",
            "authority_source": "capability_token",
            "authority_owner": "user-17",
            "standing_privilege": "none",
            "verified": True,
        },
        "business_purpose": {
            "business_function": "customer_support",
            "declared_purpose": "Resolve an approved support case",
            "purpose_status": "verified",
        },
        "surface": {
            "surface_type": "gateway",
            "application": "support-assistant",
            "provider": "azure_openai",
            "model": "gpt-5",
            "environment": "production",
        },
        "action": {
            "action_type": "customer_record_update",
            "action_category": "write",
            "action_risk": "high",
            "tool_name": "crm.update",
            "target_resource": "customer:417",
            "data_destination": "crm.internal",
            "side_effect_class": "persistent_write",
        },
        "context": {
            "chain_id": "chain-17",
            "input": {"sensitivity_level": "confidential", "contains_secrets": False},
            "output": {"output_sensitivity": "internal"},
        },
        "approval": {
            "approval_required": True,
            "approval_id": "approval-17",
            "approval_binding_id": "binding-17",
            "approval_status": "approved",
        },
        "policy": {
            "policy_snapshot_id": "policy-17",
            "control_ids": ["CUSTOMER_SCOPE"],
            "decision": decision,
            "reason": "customer_scope_policy",
            "control_mode": control_mode,
            "evaluated_at": "2026-07-17T10:15:00Z",
        },
        "evidence": {"evidence_bundle_id": "bundle-17", "trace_id": "trace-17"},
    }


def _inline_proof(*, prevented: bool = False) -> contract.ControlPathEvidence:
    return contract.ControlPathEvidence(
        collector_inline_capable=True,
        inline_pre_execution=True,
        execution_prevented=prevented,
    )


def test_same_input_has_deterministic_payload_and_hash() -> None:
    first = contract.adapt_llm_gateway_action(
        _legacy_action(),
        path_evidence=_inline_proof(prevented=True),
        parameters={"customer_id": 417, "fields": {"status": "resolved", "priority": 2}},
    )
    second = contract.adapt_llm_gateway_action(
        _legacy_action(),
        path_evidence=_inline_proof(prevented=True),
        parameters={"fields": {"priority": 2, "status": "resolved"}, "customer_id": 417},
    )

    assert first == second
    assert contract.canonical_action_hash(first) == contract.canonical_action_hash(second)
    assert first["schema_version"] == "1.0"
    assert len(first["canonical_action_hash"]) == 64
    assert first["action"]["parameter_hash"] != "unknown"


def test_exact_field_hashes_bind_secret_values_tenant_and_domain() -> None:
    first = contract.adapt_llm_gateway_action(
        _legacy_action(decision="allow"),
        path_evidence=_inline_proof(),
        parameters={"password": "alpha-password", "api_key": "sk-alpha-secret"},
    )
    second = contract.adapt_llm_gateway_action(
        _legacy_action(decision="allow"),
        path_evidence=_inline_proof(),
        parameters={"password": "beta-password", "api_key": "sk-beta-secret"},
    )
    foreign_tenant = _legacy_action(decision="allow")
    foreign_tenant["tenant_id"] = "tenant-18"
    third = contract.adapt_llm_gateway_action(
        foreign_tenant,
        path_evidence=_inline_proof(),
        parameters={"password": "alpha-password", "api_key": "sk-alpha-secret"},
    )

    assert first["action"]["parameter_hash"] != second["action"]["parameter_hash"]
    assert first["action"]["parameter_hash"] != third["action"]["parameter_hash"]
    assert contract.canonical_field_hash("tenant-17", "parameters", "same") != contract.canonical_field_hash(
        "tenant-17", "target_resource", "same"
    )


def test_exact_binding_hashes_include_complete_tail_and_key_rotation() -> None:
    key_a = "binding-key-a-012345678901234567890123456789"
    key_b = "binding-key-b-012345678901234567890123456789"
    long_a = ("x" * 4096) + "tail-a"
    long_b = ("x" * 4096) + "tail-b"
    wide_a = [*range(64), "tail-a"]
    wide_b = [*range(64), "tail-b"]

    assert contract.canonical_field_hash(
        "tenant-bind", "parameters", long_a, binding_key=key_a
    ) != contract.canonical_field_hash("tenant-bind", "parameters", long_b, binding_key=key_a)
    assert contract.canonical_field_hash(
        "tenant-bind", "parameters", wide_a, binding_key=key_a
    ) != contract.canonical_field_hash("tenant-bind", "parameters", wide_b, binding_key=key_a)
    assert contract.canonical_field_hash(
        "tenant-bind", "parameters", {"password": "alpha"}, binding_key=key_a
    ) != contract.canonical_field_hash(
        "tenant-bind", "parameters", {"password": "beta"}, binding_key=key_a
    )
    assert contract.canonical_field_hash(
        "tenant-bind", "parameters", {"record": 417}, binding_key=key_a
    ) != contract.canonical_field_hash(
        "tenant-bind", "parameters", {"record": 417}, binding_key=key_b
    )


def test_binding_key_is_required_for_flag_on_production_and_cannot_reuse_secrets() -> None:
    base = {
        "env": "production",
        "pilot_mode": False,
        "demo_mode": False,
        "self_registration_enabled": False,
        "secret_key": "production-secret-key-01234567890123456789",
        "connector_secrets_key": "connector-secret-key-012345678901234567",
        "connector_secrets_kdf_salt": "connector-kdf-salt-0123456789012345678",
        "onprem_bundle_signing_secret": "onprem-signing-secret-0123456789012345678",
        "secret_key_lock_enabled": False,
        "canonical_ai_action_dual_write_enabled": True,
    }
    with pytest.raises(ValueError, match="CANONICAL_ACTION_BINDING_KEY"):
        Settings(**base, canonical_action_binding_key="")
    for existing_secret in (
        base["secret_key"],
        base["connector_secrets_key"],
        base["onprem_bundle_signing_secret"],
    ):
        with pytest.raises(ValueError, match="distinct"):
            Settings(**base, canonical_action_binding_key=existing_secret)

    configured = Settings(
        **base,
        canonical_action_binding_key="canonical-binding-key-01234567890123456789",
    )
    assert configured.canonical_action_binding_key.startswith("canonical-binding-key")


@pytest.mark.parametrize(
    ("env", "demo_mode"),
    [
        ("dev", False),
        ("development", False),
        ("test", False),
        ("production", True),
    ],
)
def test_binding_key_is_required_for_flag_on_in_every_environment(env: str, demo_mode: bool) -> None:
    base = {
        "env": env,
        "demo_mode": demo_mode,
        "pilot_mode": False,
        "self_registration_enabled": False,
        "secret_key": "nonproduction-secret-key-0123456789012345",
        "connector_secrets_key": "nonproduction-connector-key-012345678901",
        "connector_secrets_kdf_salt": "nonproduction-kdf-salt-0123456789012345",
        "onprem_bundle_signing_secret": "nonproduction-onprem-secret-0123456789",
        "secret_key_lock_enabled": False,
        "canonical_ai_action_dual_write_enabled": True,
    }
    with pytest.raises(ValueError, match="CANONICAL_ACTION_BINDING_KEY"):
        Settings(**base, canonical_action_binding_key="")
    with pytest.raises(ValueError, match="32 characters"):
        Settings(**base, canonical_action_binding_key="too-short")

    configured = Settings(
        **base,
        canonical_action_binding_key="nonproduction-canonical-binding-key-0123456789",
    )
    assert len(configured.canonical_action_binding_key) >= 32


def test_field_hash_material_is_bounded_redacted_and_depth_limited() -> None:
    material = contract.canonical_field_material(
        {
            "password": "must-never-hash-raw",
            "authorization": "Bearer must-never-hash-raw-either",
            "items": [*range(100), "tail-is-preserved-within-budget"],
            "oversize": "x" * 5000,
        }
    )
    serialized = json.dumps(material, sort_keys=True)

    assert "must-never-hash-raw" not in serialized
    assert material["password"] == "[redacted]"
    assert len(material["items"]) == 101
    assert "tail-is-preserved-within-budget" in serialized
    assert len(material["oversize"]) <= 528


def test_all_canonicalization_paths_reject_attacker_material_before_hashing(monkeypatch) -> None:
    class ExplodingList(list):
        def __iter__(self):
            raise AssertionError("oversized list must be rejected before iteration or copy")

    class ExplodingTuple(tuple):
        def __iter__(self):
            raise AssertionError("oversized tuple must be rejected before iteration or copy")

    class ExplodingSet(set):
        def __iter__(self):
            raise AssertionError("oversized set must be rejected before iteration or sort")

    class ExplodingMap(dict):
        def __iter__(self):
            raise AssertionError("oversized map must be rejected before iteration or copy")

        def items(self):
            raise AssertionError("oversized map must be rejected before item traversal")

        def keys(self):
            raise AssertionError("oversized map must be rejected before key traversal")

    deep: object = "leaf"
    for _ in range(18):
        deep = {"next": deep}

    for oversized_scope in (
        ExplodingList(range(65)),
        ExplodingTuple(range(65)),
        ExplodingSet(range(65)),
    ):
        with pytest.raises(contract.CanonicalMaterialLimitError):
            contract._safe_list(oversized_scope)

    cases: list[dict] = []
    for oversized_scope in (list(range(65)), tuple(range(65)), set(range(65))):
        source = _legacy_action(decision="allow")
        source["authority"]["permission_scope"] = oversized_scope
        cases.append(source)
    oversized_map_source = _legacy_action(decision="allow")
    oversized_map_source["attacker_material"] = ExplodingMap(
        {f"key-{index}": index for index in range(1025)}
    )
    cases.append(oversized_map_source)
    deep_source = _legacy_action(decision="allow")
    deep_source["attacker_material"] = deep
    cases.append(deep_source)
    aggregate_source = _legacy_action(decision="allow")
    aggregate_source["attacker_material"] = {
        f"part-{index}": "x" * 15000 for index in range(5)
    }
    cases.append(aggregate_source)
    node_source = _legacy_action(decision="allow")
    node_source["attacker_material"] = [list(range(64)) for _ in range(64)]
    cases.append(node_source)
    string_source = _legacy_action(decision="allow")
    string_source["business_purpose"]["declared_purpose"] = "x" * 16385
    cases.append(string_source)

    hash_called = False

    def fail_if_hash_called(*args, **kwargs):
        nonlocal hash_called
        hash_called = True
        raise AssertionError("canonical hash must not run for rejected builder material")

    monkeypatch.setattr(contract, "canonical_action_hash", fail_if_hash_called)
    for source in cases:
        with pytest.raises(contract.CanonicalMaterialLimitError):
            contract.build_canonical_ai_action_v1(source)
    assert hash_called is False


def test_reconciliation_and_canonical_hash_reject_overflow_before_digest(monkeypatch) -> None:
    payload = contract.build_canonical_ai_action_v1(_legacy_action(decision="allow"))
    payload["actor"]["attacker_material"] = list(range(1025))
    digest_called = False

    def fail_if_digest_called(*args, **kwargs):
        nonlocal digest_called
        digest_called = True
        raise AssertionError("digest must not run for rejected redacted material")

    monkeypatch.setattr(contract.hashlib, "sha256", fail_if_digest_called)
    with pytest.raises(contract.CanonicalMaterialLimitError):
        contract.canonical_action_hash(payload)
    assert digest_called is False

    oversized_metadata = {f"key-{index}": index for index in range(1025)}
    with pytest.raises(contract.CanonicalMaterialLimitError):
        contract.canonical_reconciliation_counts([oversized_metadata])


def test_adapters_and_dual_write_preflight_before_deepcopy() -> None:
    class ExplodingMap(dict):
        def __iter__(self):
            raise AssertionError("oversized adapter source must be rejected before deepcopy")

        def keys(self):
            raise AssertionError("oversized adapter source must be rejected before deepcopy")

    class ExplodingList(list):
        def __iter__(self):
            raise AssertionError("oversized projection must be rejected before deepcopy")

    oversized_source = ExplodingMap(_legacy_action(decision="allow"))
    oversized_source.update({f"attacker-{index}": index for index in range(1025)})
    with pytest.raises(contract.CanonicalMaterialLimitError):
        contract.adapt_llm_gateway_action(oversized_source)

    canonical = contract.build_canonical_ai_action_v1(_legacy_action(decision="allow"))
    canonical["actor"]["attacker_material"] = ExplodingList(range(1025))
    with pytest.raises(contract.CanonicalMaterialLimitError):
        contract.maybe_dual_write_canonical_action(
            {"ai_action": _legacy_action(decision="allow")},
            canonical_action=canonical,
            enabled=True,
        )


def test_exact_binding_limits_reject_before_hmac(monkeypatch) -> None:
    oversized_values = [
        "x" * 16385,
        list(range(1025)),
        {f"key-{index}": index for index in range(1025)},
        set(range(1025)),
        {f"part-{index}": "x" * 15000 for index in range(5)},
    ]
    deep: object = "leaf"
    for _ in range(18):
        deep = {"next": deep}
    oversized_values.append(deep)

    called = False

    def fail_if_called(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("HMAC must not run for rejected material")

    monkeypatch.setattr(contract.hmac, "new", fail_if_called)
    for value in oversized_values:
        with pytest.raises(contract.CanonicalMaterialLimitError):
            contract.canonical_field_hash(
                "tenant-limit",
                "parameters",
                value,
                binding_key="binding-key-012345678901234567890123456789",
            )
    assert called is False


def test_set_hash_material_is_stable_across_python_hash_seeds() -> None:
    script = """
import json
from app.core.control_engine.canonical_action import canonical_field_hash, canonical_field_material

value = {
    "scopes": {"write", "read", "admin", "audit"},
    "mixed": frozenset({None, False, 7, 1.5, "7", "alpha"}),
}
print(json.dumps({
    "material": canonical_field_material(value),
    "hash": canonical_field_hash("tenant-seed", "parameters", value),
}, sort_keys=True, separators=(",", ":")))
"""
    outputs: list[str] = []
    for seed in ("1", "2", "3", "8675309"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=os.fspath(Path(__file__).resolve().parents[1]),
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(completed.stdout.strip())

    assert len(set(outputs)) == 1


def test_full_canonical_payload_set_lists_are_stable_across_hash_seeds() -> None:
    script = """
import json
from app.core.control_engine.canonical_action import build_canonical_ai_action_v1, canonical_action_hash

source = {
    "tenant_id": "tenant-seed-payload",
    "action_id": "action-seed-payload",
    "chain_id": "chain-seed-payload",
    "timestamp": "2026-07-17T10:15:00Z",
    "authority": {"permission_scope": {"tool.write", "tool.read", "tool.audit"}},
    "actor": {"delegation_chain": frozenset({"agent-c", "agent-a", "agent-b"})},
    "policy": {"decision": "allow", "matched_rules": {"RULE-C", "RULE-A", "RULE-B"}},
}
payload = build_canonical_ai_action_v1(source)
print(json.dumps({
    "payload": payload,
    "rehash": canonical_action_hash(payload),
}, sort_keys=True, separators=(",", ":")))
"""
    outputs: list[str] = []
    for seed in ("1", "2", "3", "8675309"):
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", script],
            cwd=os.fspath(Path(__file__).resolve().parents[1]),
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        outputs.append(completed.stdout.strip())

    assert len(set(outputs)) == 1
    payload = json.loads(outputs[0])["payload"]
    assert payload["authority"]["permission_scope"] == ["tool.audit", "tool.read", "tool.write"]
    assert payload["actor"]["delegation_chain"] == ["agent-a", "agent-b", "agent-c"]
    assert payload["policy"]["matched_rules"] == ["RULE-A", "RULE-B", "RULE-C"]


def test_list_and_tuple_hash_material_preserve_order() -> None:
    assert contract.canonical_field_material(["read", "write"]) == ["read", "write"]
    assert contract.canonical_field_material(("write", "read")) == ["write", "read"]
    assert contract.canonical_field_hash("tenant-order", "parameters", ["read", "write"]) != (
        contract.canonical_field_hash("tenant-order", "parameters", ["write", "read"])
    )
    with pytest.raises(TypeError, match="unsupported canonical hash material"):
        contract.canonical_field_material(object())


def test_caller_supplied_material_hashes_are_never_trusted() -> None:
    legacy = _legacy_action(decision="allow")
    legacy["action"].update(
        {
            "parameter_hash": "a" * 64,
            "parameter_hash_binding": "f" * 64,
            "target_resource_hash": "b" * 64,
            "destination_hash": "c" * 64,
        }
    )
    action = contract.adapt_sdk_action(
        legacy,
        path_evidence=_inline_proof(),
        parameters={"record_id": 417},
    )

    assert action["action"]["parameter_hash"] != "a" * 64
    assert action["action"]["target_resource_hash"] != "b" * 64
    assert action["action"]["destination_hash"] != "c" * 64


def test_tenant_action_and_chain_are_required_at_contract_boundary() -> None:
    base = _legacy_action()
    for missing_path in ("tenant_id", "action_id", "chain_id"):
        payload = dict(base)
        if missing_path == "chain_id":
            payload["context"] = {**base["context"], "chain_id": ""}
        else:
            payload[missing_path] = ""
        with pytest.raises(ValueError, match=missing_path):
            contract.build_canonical_ai_action_v1(
                payload,
                path_evidence=_inline_proof(prevented=True),
            )


def test_adapters_reject_missing_chain_instead_of_synthesizing_from_action() -> None:
    legacy = _legacy_action()
    legacy["context"] = {key: value for key, value in legacy["context"].items() if key != "chain_id"}
    legacy.pop("chain_id", None)
    legacy["correlation_id"] = "correlation-is-not-an-authority-chain"

    with pytest.raises(ValueError, match="chain_id"):
        contract.adapt_llm_gateway_action(
            legacy,
            path_evidence=_inline_proof(prevented=True),
        )


def test_missing_dimensions_are_explicit_unknown_never_silent_trust() -> None:
    minimal = {
        "tenant_id": "tenant-minimal",
        "action_id": "action-minimal",
        "chain_id": "chain-minimal",
        "timestamp": "2026-07-17T10:15:00Z",
    }
    action = contract.build_canonical_ai_action_v1(minimal)

    assert action["actor"]["identity_id"] == "unknown"
    assert action["authority"]["verified"] == "unknown"
    assert action["purpose"]["purpose_status"] == "unknown"
    assert action["surface"]["surface_type"] == "unknown"
    assert action["action"]["action_type"] == "unknown"
    assert action["content"]["input_sensitivity"] == "unknown"
    assert action["approval"]["approval_status"] == "unknown"
    assert action["policy"]["decision"] == "unknown"
    assert action["evidence"]["integrity_status"] == "unknown"


def test_caller_control_mode_forgery_cannot_upgrade_browser_telemetry() -> None:
    forged = _legacy_action(decision="block", control_mode="inline_prevented")
    forged["surface"] = {"surface_type": "browser", "application": "ChatGPT"}

    action = contract.adapt_browser_action(forged)

    assert action["policy"]["control_mode"] == "detected_only"


@pytest.mark.parametrize(
    ("decision", "prevented", "expected"),
    [
        ("block", True, "inline_prevented"),
        ("allow", False, "inline_allowed"),
        ("warn", False, "warned"),
        ("review", False, "review_required"),
    ],
)
def test_inline_modes_require_server_path_evidence(decision: str, prevented: bool, expected: str) -> None:
    action = contract.adapt_mcp_gateway_action(
        _legacy_action(decision=decision),
        path_evidence=_inline_proof(prevented=prevented),
    )
    assert action["policy"]["control_mode"] == expected


def test_block_without_pre_execution_proof_is_not_prevented() -> None:
    action = contract.adapt_llm_gateway_action(
        _legacy_action(decision="block"),
        path_evidence=contract.ControlPathEvidence(telemetry_observation=True),
    )
    assert action["policy"]["control_mode"] == "detected_only"


def test_inline_path_claim_without_collector_capability_is_incomplete() -> None:
    action = contract.adapt_llm_gateway_action(
        _legacy_action(decision="block"),
        path_evidence=contract.ControlPathEvidence(
            inline_pre_execution=True,
            execution_prevented=True,
        ),
    )
    assert action["policy"]["control_mode"] == "incomplete"


def test_gateway_response_stage_block_is_detected_not_pre_execution_prevented() -> None:
    response_action = contract.adapt_llm_gateway_action(
        _legacy_action(decision="block"),
        path_evidence=contract.gateway_control_path_evidence(
            request_stage="response",
            event_type="llm_intercept",
            decision="block",
        ),
    )
    request_action = contract.adapt_llm_gateway_action(
        _legacy_action(decision="block"),
        path_evidence=contract.gateway_control_path_evidence(
            request_stage="request",
            event_type="llm_intercept",
            decision="block",
        ),
    )
    proven_request_action = contract.adapt_llm_gateway_action(
        _legacy_action(decision="block"),
        path_evidence=contract.gateway_control_path_evidence(
            request_stage="request",
            event_type="llm_intercept",
            decision="block",
            enforcement_outcome="pre_execution_stopped",
        ),
    )

    assert response_action["policy"]["control_mode"] == "detected_only"
    assert request_action["policy"]["control_mode"] == "incomplete"
    assert proven_request_action["policy"]["control_mode"] == "inline_prevented"


def test_post_stage_and_authorization_only_override_prevention_claims() -> None:
    for evidence in (
        contract.gateway_control_path_evidence(
            request_stage="response",
            event_type="mcp_authorize",
            decision="block",
            enforcement_outcome="pre_execution_stopped",
        ),
        contract.gateway_control_path_evidence(
            request_stage="authorize",
            event_type="mcp_authorize",
            decision="block",
            enforcement_outcome="pre_execution_stopped",
        ),
    ):
        action = contract.adapt_mcp_gateway_action(_legacy_action(decision="block"), path_evidence=evidence)
        assert action["policy"]["control_mode"] != "inline_prevented"


def test_shadow_mode_requires_server_owned_would_block_result() -> None:
    shadow_allow = contract.derive_control_mode(
        decision="allow",
        path_evidence=contract.ControlPathEvidence(shadow_evaluation=True),
    )
    shadow_block = contract.derive_control_mode(
        decision="allow",
        path_evidence=contract.ControlPathEvidence(
            shadow_evaluation=True,
            shadow_would_block=True,
        ),
    )
    contradictory = contract.derive_control_mode(
        decision="block",
        path_evidence=contract.ControlPathEvidence(execution_prevented=True),
    )

    assert shadow_allow != "shadow_would_block"
    assert shadow_block == "shadow_would_block"
    assert contradictory == "incomplete"


def test_serialization_is_bounded_redacted_and_does_not_store_raw_parameters() -> None:
    legacy = _legacy_action(decision="allow")
    legacy["purpose"] = {
        "declared_purpose": "Contact jane@example.com using token=super-secret-token-value " + ("x" * 5000)
    }
    action = contract.adapt_sdk_action(
        legacy,
        path_evidence=_inline_proof(),
        parameters={
            "authorization": "Bearer this-token-must-never-be-stored",
            "email": "jane@example.com",
            "prompt_text": "password=correct-horse-battery-staple",
        },
    )
    serialized = json.dumps(action, sort_keys=True)

    assert "this-token-must-never-be-stored" not in serialized
    assert "correct-horse-battery-staple" not in serialized
    assert "jane@example.com" not in serialized
    assert "parameters" not in action["action"]
    assert action["action"]["parameter_hash"] != "unknown"
    assert len(action["purpose"]["declared_purpose"]) <= 528


@pytest.mark.parametrize(
    ("adapter", "surface"),
    [
        (contract.adapt_llm_gateway_action, "llm_gateway"),
        (contract.adapt_mcp_gateway_action, "mcp_gateway"),
        (contract.adapt_runtime_control_action, "runtime_control"),
        (contract.adapt_browser_action, "browser"),
        (contract.adapt_sdk_action, "sdk"),
        (contract.adapt_internal_mcp_action, "internal_mcp"),
    ],
)
def test_surface_adapters_emit_parity_dimensions(adapter, surface: str) -> None:
    proof = (
        contract.ControlPathEvidence(telemetry_observation=True)
        if surface == "browser"
        else _inline_proof(prevented=True)
    )
    action = adapter(_legacy_action(), path_evidence=proof)

    assert action["adapter"] == surface
    assert action["tenant_id"] == "tenant-17"
    assert action["action_id"] == "legacy-action-17"
    assert action["chain_id"] == "chain-17"
    assert {
        "actor",
        "authority",
        "purpose",
        "surface",
        "action",
        "content",
        "approval",
        "policy",
        "evidence",
    }.issubset(action)


def test_dual_write_flag_off_is_exact_legacy_noop() -> None:
    metadata = {"ai_action": _legacy_action(), "legacy_only": {"keep": True}}
    output = contract.maybe_dual_write_canonical_action(metadata, enabled=False)

    assert output is metadata
    assert output == {"ai_action": _legacy_action(), "legacy_only": {"keep": True}}


def test_dual_write_requires_prebuilt_canonical_payload_when_enabled() -> None:
    with pytest.raises(ValueError, match="canonical_action is required"):
        contract.maybe_dual_write_canonical_action(
            {"ai_action": _legacy_action()},
            enabled=True,
        )


def test_flag_on_dual_write_has_reconcilable_counts_and_detects_tampering() -> None:
    legacy = _legacy_action()
    canonical = contract.adapt_runtime_control_action(
        legacy,
        path_evidence=_inline_proof(prevented=True),
    )
    metadata = contract.maybe_dual_write_canonical_action(
        {"ai_action": legacy},
        canonical_action=canonical,
        enabled=True,
    )
    counts = contract.canonical_reconciliation_counts([metadata])

    assert counts == {
        "legacy_total": 1,
        "canonical_total": 1,
        "matched": 1,
        "missing": 0,
        "hash_mismatch": 0,
    }

    metadata["canonical_ai_action_v1"]["action"]["action_type"] = "forged"
    tampered = contract.canonical_reconciliation_counts([metadata])
    assert tampered["hash_mismatch"] == 1
    assert tampered["matched"] == 0


def test_projection_reconciliation_compares_correlated_payloads() -> None:
    legacy = _legacy_action()
    canonical = contract.adapt_runtime_control_action(
        legacy,
        path_evidence=_inline_proof(prevented=True),
    )
    runtime = contract.maybe_dual_write_canonical_action(
        {"ai_action": legacy}, canonical_action=canonical, enabled=True
    )
    activity = deepcopy(runtime)

    assert contract.canonical_projection_reconciliation_counts([runtime], [activity]) == {
        "runtime_total": 1,
        "activity_total": 1,
        "correlated_total": 1,
        "matched": 1,
        "missing_runtime": 0,
        "missing_activity": 0,
        "hash_mismatch": 0,
        "schema_mismatch": 0,
        "control_mode_mismatch": 0,
        "duplicate_runtime": 0,
        "duplicate_activity": 0,
    }

    missing = contract.canonical_projection_reconciliation_counts([runtime], [])
    assert missing["missing_activity"] == 1
    assert missing["matched"] == 0

    activity["canonical_ai_action_v1"]["policy"]["control_mode"] = "detected_only"
    activity["canonical_ai_action_v1"]["schema_version"] = "9.9"
    activity_hash = contract.canonical_action_hash(activity["canonical_ai_action_v1"])
    activity["canonical_ai_action_v1"]["canonical_action_hash"] = activity_hash
    activity["canonical_ai_action_hash"] = activity_hash
    mismatch = contract.canonical_projection_reconciliation_counts([runtime], [activity])
    assert mismatch["hash_mismatch"] == 1
    assert mismatch["schema_mismatch"] == 1
    assert mismatch["control_mode_mismatch"] == 1
    assert mismatch["matched"] == 0


def test_projection_reconciliation_tenant_scopes_and_surfaces_duplicates() -> None:
    tenant_17 = contract.adapt_runtime_control_action(
        _legacy_action(), path_evidence=_inline_proof(prevented=True)
    )
    tenant_18_source = _legacy_action()
    tenant_18_source["tenant_id"] = "tenant-18"
    tenant_18 = contract.adapt_runtime_control_action(
        tenant_18_source, path_evidence=_inline_proof(prevented=True)
    )
    runtime_17 = contract.maybe_dual_write_canonical_action(
        {"ai_action": _legacy_action()}, canonical_action=tenant_17, enabled=True
    )
    runtime_18 = contract.maybe_dual_write_canonical_action(
        {"ai_action": tenant_18_source}, canonical_action=tenant_18, enabled=True
    )
    activity_17 = deepcopy(runtime_17)

    report = contract.canonical_projection_reconciliation_counts(
        [runtime_18, runtime_17, deepcopy(runtime_17)],
        [activity_17],
    )

    assert report["runtime_total"] == 2
    assert report["activity_total"] == 1
    assert report["missing_activity"] == 1
    assert report["duplicate_runtime"] == 1
    assert report["duplicate_activity"] == 0
    assert report["matched"] == 0


def test_flag_on_persists_reconcilable_runtime_and_activity_projections(tmp_path, monkeypatch) -> None:
    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'canonical-action.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", True)
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        registration = client.post(
            "/auth/register",
            json={
                "email": "canonical-persistence@example.com",
                "password": "Password123!",
                "full_name": "Canonical Persistence",
            },
        )
        assert registration.status_code == 200, registration.text
        identity = registration.json()
        headers = {
            "Authorization": f"Bearer {identity['access_token']}",
            "X-Tenant-ID": identity["tenants"][0]["id"],
        }
        response = client.post(
            "/telemetry/browser",
            headers=headers,
            json={
                "correlation_id": "canonical-persistence-chain",
                "event_type": "browser_automation_blocked",
                "domain": "workflow.example.internal",
                "url": "https://workflow.example.internal/checkout?token=must-not-persist",
                "action_taken": "block:high_risk_action",
                "action_type": "checkout",
                "automation_suspected": True,
                "browser": "chrome",
                "application": "Workflow",
                "endpoint_id": "canonical-endpoint",
                "severity": "high",
            },
        )
        assert response.status_code == 200, response.text
        runtime_event_id = response.json()["runtime_event_id"]

        with session_local() as db:
            runtime = db.get(RuntimeEvent, runtime_event_id)
            activity = db.scalar(
                select(AIAction).where(AIAction.runtime_event_id == runtime_event_id)
            )
            assert runtime is not None
            assert activity is not None
            metadata_rows = [runtime.metadata_json, activity.metadata_json]
            counts = contract.canonical_reconciliation_counts(metadata_rows)
            assert counts == {
                "legacy_total": 2,
                "canonical_total": 2,
                "matched": 2,
                "missing": 0,
                "hash_mismatch": 0,
            }
            assert runtime.metadata_json["canonical_ai_action_v1"]["policy"]["control_mode"] == "inline_prevented"
            assert runtime.metadata_json["canonical_ai_action_v1"] == activity.metadata_json["canonical_ai_action_v1"]
            projection_counts = contract.canonical_projection_reconciliation_counts(
                [runtime.metadata_json], [activity.metadata_json]
            )
            assert projection_counts["matched"] == 1
            assert projection_counts["hash_mismatch"] == 0
            canonical_payloads = [row["canonical_ai_action_v1"] for row in metadata_rows]
            assert "must-not-persist" not in json.dumps(canonical_payloads, sort_keys=True)
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_flag_on_source_managed_browser_failure_owner_rolls_back_and_retry_is_single_pair(
    tmp_path, monkeypatch
) -> None:
    from sqlalchemy import event as sqlalchemy_event

    from app.services.runtime_intelligence import runtime_event_normalizer as normalizer
    from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'canonical-action-atomic.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    payload = RuntimeEventIngestPayload(
        tenant_id="tenant-canonical-atomic",
        source_surface="browser",
        event_type="browser_automation_blocked",
        app_id="canonical-atomic-app",
        correlation_id="canonical-atomic-retry",
        risk_score=12.0,
        metadata={
            "decision": "allow",
            "action_type": "read_record",
            "operational_telemetry": True,
            "activity_audit_managed_by_source": True,
        },
    )
    original_record_activity_event = normalizer.record_activity_event

    def fail_activity_projection(*args, **kwargs):
        raise RuntimeError("injected canonical activity projection failure")

    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", True)
    monkeypatch.setattr(normalizer, "record_activity_event", fail_activity_projection)
    try:
        with session_local() as db:
            rollback_count = 0

            @sqlalchemy_event.listens_for(db, "after_rollback")
            def count_owner_rollbacks(session) -> None:
                nonlocal rollback_count
                rollback_count += 1

            with pytest.raises(RuntimeError, match="canonical activity projection"):
                normalizer.ingest_runtime_event(db, payload=payload)

            assert rollback_count == 0
            db.rollback()
            assert rollback_count == 1
            assert db.scalars(select(RuntimeEvent)).all() == []
            assert db.scalars(select(AIAction)).all() == []

            monkeypatch.setattr(normalizer, "record_activity_event", original_record_activity_event)
            runtime = normalizer.ingest_runtime_event(db, payload=payload)
            assert runtime is not None
            db.commit()

            runtime_rows = db.scalars(select(RuntimeEvent)).all()
            activity_rows = db.scalars(select(AIAction)).all()
            assert len(runtime_rows) == 1
            assert len(activity_rows) == 1
            assert activity_rows[0].runtime_event_id == runtime_rows[0].event_id
            assert (
                activity_rows[0].metadata_json["canonical_ai_action_v1"]
                == runtime_rows[0].metadata_json["canonical_ai_action_v1"]
            )
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_flag_on_source_managed_browser_missing_activity_row_raises_for_owner_rollback(
    tmp_path, monkeypatch
) -> None:
    from sqlalchemy import event as sqlalchemy_event

    from app.services.activity_audit_service import ActivityAuditRecord
    from app.services.runtime_intelligence import runtime_event_normalizer as normalizer
    from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'canonical-action-source-missing.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    payload = RuntimeEventIngestPayload(
        tenant_id="tenant-source-missing",
        source_surface="browser",
        event_type="browser_automation_blocked",
        app_id="source-managed-app",
        correlation_id="source-managed-missing",
        risk_score=90.0,
        metadata={
            "decision": "block",
            "action_type": "browser_automation",
            "operational_telemetry": True,
            "activity_audit_managed_by_source": True,
        },
    )

    def return_without_persisting(*args, **kwargs) -> ActivityAuditRecord:
        return ActivityAuditRecord(
            user_registry_id=None,
            endpoint_id="missing-endpoint",
            session_id="missing-session",
            action_id="missing-action",
            alert_id=None,
            prompt_storage_mode=None,
        )

    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", True)
    monkeypatch.setattr(normalizer, "record_activity_event", return_without_persisting)
    try:
        with session_local() as db:
            rollback_count = 0

            @sqlalchemy_event.listens_for(db, "after_rollback")
            def count_owner_rollbacks(session) -> None:
                nonlocal rollback_count
                rollback_count += 1

            with pytest.raises(contract.CanonicalProjectionError, match="did not match RuntimeEvent"):
                normalizer.ingest_runtime_event(db, payload=payload)

            assert rollback_count == 0
            db.rollback()
            assert rollback_count == 1
            assert db.scalars(select(RuntimeEvent)).all() == []
            assert db.scalars(select(AIAction)).all() == []
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_flag_off_source_managed_browser_missing_activity_row_remains_best_effort(
    tmp_path, monkeypatch
) -> None:
    from app.services.runtime_intelligence import runtime_event_normalizer as normalizer
    from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'canonical-action-source-legacy.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    payload = RuntimeEventIngestPayload(
        tenant_id="tenant-source-legacy",
        source_surface="browser",
        event_type="browser_event",
        correlation_id="source-managed-legacy",
        metadata={
            "decision": "allow",
            "operational_telemetry": True,
            "activity_audit_managed_by_source": True,
        },
    )
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    try:
        with session_local() as db:
            runtime = normalizer.ingest_runtime_event(db, payload=payload)
            assert runtime is not None
            db.commit()
            assert len(db.scalars(select(RuntimeEvent)).all()) == 1
            assert db.scalars(select(AIAction)).all() == []
            assert "canonical_ai_action_v1" not in runtime.metadata_json
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_browser_transaction_owner_rolls_back_and_rethrows_canonical_projection_error(
    tmp_path,
) -> None:
    from sqlalchemy import event as sqlalchemy_event

    from app.api.routers.extension import _run_extension_write_with_sqlite_retry
    from app.services.runtime_intelligence.schemas import RuntimeEventIngestPayload

    engine = create_engine(
        f"sqlite+pysqlite:///{tmp_path / 'canonical-action-browser-owner.sqlite3'}",
        connect_args={"check_same_thread": False},
    )
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    try:
        with session_local() as db:
            rollback_count = 0

            @sqlalchemy_event.listens_for(db, "after_rollback")
            def count_owner_rollbacks(session) -> None:
                nonlocal rollback_count
                rollback_count += 1

            def fail_projection() -> None:
                payload = RuntimeEventIngestPayload(
                    tenant_id="tenant-browser-owner",
                    source_surface="browser",
                    event_type="browser_event",
                )
                db.add(
                    RuntimeEvent(
                        tenant_id=payload.tenant_id,
                        source_surface=payload.source_surface,
                        event_type=payload.event_type,
                        evidence_node_ids=[],
                        metadata_json={},
                    )
                )
                db.flush()
                raise contract.CanonicalProjectionError("canonical browser projection failed")

            with pytest.raises(contract.CanonicalProjectionError, match="browser projection"):
                _run_extension_write_with_sqlite_retry(
                    db,
                    fail_projection,
                    busy_detail="database busy",
                )

            assert rollback_count == 1
            assert db.scalars(select(RuntimeEvent)).all() == []
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
