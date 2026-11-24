from __future__ import annotations

from app.services.guardian_policy_engine import (
    canonical_guardian_policy,
    evaluate_data_transfer_policy,
    evaluate_guardian_policies,
    framework_mapping_is_valid,
    normalize_framework_mapping,
)


def test_framework_mapping_from_control_ids_is_normalized_for_required_frameworks() -> None:
    mapping = normalize_framework_mapping({"control_ids": ["CTRL-001"]})
    assert mapping["nist_ai_rmf"] == ["CTRL-001"]
    assert mapping["iso_42001"] == ["CTRL-001"]
    assert mapping["eu_ai_act"] == ["CTRL-001"]
    assert framework_mapping_is_valid(mapping) is True


def test_framework_mapping_without_required_frameworks_is_invalid() -> None:
    assert framework_mapping_is_valid({"owasp_genai": ["LLM01"]}) is False


def test_canonical_policy_engine_aggregates_to_most_restrictive_decision() -> None:
    block_policy = canonical_guardian_policy(
        policy_id="policy.block",
        policy_name="Block policy",
        policy_version="1.0.0",
        tenant_id="tenant-1",
        conditions={"action": {"type": "prompt"}, "data": {"contains_sensitive": True}},
        decision={"mode": "block", "confidence_threshold": 0.8, "strictness": "high"},
        framework_mapping={"control_ids": ["CTRL-BLOCK"]},
    )
    warn_policy = canonical_guardian_policy(
        policy_id="policy.warn",
        policy_name="Warn policy",
        policy_version="1.0.0",
        tenant_id="tenant-1",
        conditions={"action": {"type": "prompt"}},
        decision={"mode": "warn", "confidence_threshold": 0.6, "strictness": "medium"},
        framework_mapping={"control_ids": ["CTRL-WARN"]},
    )

    decision = evaluate_guardian_policies(
        policies=[warn_policy, block_policy],
        context={
            "action_type": "prompt",
            "contains_sensitive": True,
            "source_type": "api",
            "source_classification": "internal",
        },
    )
    assert decision.decision == "block"
    assert decision.policy is not None
    assert decision.policy["policy_id"] == "policy.block"


def test_data_transfer_sensitive_external_ai_blocks() -> None:
    decision = evaluate_data_transfer_policy(
        source_classification="protected",
        source_surface="internal_app",
        destination_surface="ai_tool",
        destination_domain="chat.openai.com",
        destination_ai_system_id=None,
        destination_discovery_status="unknown",
        destination_app_name="ChatGPT",
        destination_is_external=True,
        platform_mode="enforce",
    )
    assert decision.decision == "block"
    assert decision.reason_code == "protected_to_public_ai_block"
    assert decision.policy is not None


def test_data_transfer_sensitive_file_upload_external_ai_blocks_via_guardian_contract() -> None:
    decision = evaluate_data_transfer_policy(
        source_classification="protected",
        source_surface="document",
        destination_surface="ai_tool",
        destination_domain="chat.openai.com",
        destination_ai_system_id=None,
        destination_discovery_status="unknown",
        destination_app_name="ChatGPT",
        destination_is_external=True,
        platform_mode="enforce",
        action_type="file_upload",
    )
    assert decision.decision == "block"
    assert decision.reason_code == "sensitive_file_upload"
    assert decision.policy is not None
    assert decision.policy["policy_id"] == "guardian.data_transfer.sensitive_file_upload_to_public_ai_block"
    assert "action.type" in (decision.matched_conditions or [])


def test_data_transfer_sensitive_email_requires_justification() -> None:
    decision = evaluate_data_transfer_policy(
        source_classification="protected",
        source_surface="document",
        destination_surface="email",
        destination_domain="mail.google.com",
        destination_ai_system_id=None,
        destination_discovery_status="unknown",
        destination_app_name="Gmail",
        destination_is_external=True,
        platform_mode="enforce",
    )
    assert decision.decision == "require_justification"
    assert decision.policy is not None


def test_data_transfer_sensitive_file_upload_email_requires_justification_via_guardian_contract() -> None:
    decision = evaluate_data_transfer_policy(
        source_classification="protected",
        source_surface="document",
        destination_surface="email",
        destination_domain="mail.google.com",
        destination_ai_system_id=None,
        destination_discovery_status="unknown",
        destination_app_name="Gmail",
        destination_is_external=True,
        platform_mode="enforce",
        action_type="file_upload",
    )
    assert decision.decision == "require_justification"
    assert decision.reason_code == "sensitive_file_upload_requires_justification"
    assert decision.policy is not None
    assert decision.policy["policy_id"] == "guardian.data_transfer.sensitive_file_upload_to_external_collaboration_requires_justification"
    assert "action.type" in (decision.matched_conditions or [])


def test_data_transfer_sensitive_approved_email_still_requires_justification() -> None:
    decision = evaluate_data_transfer_policy(
        source_classification="protected",
        source_surface="document",
        destination_surface="email",
        destination_domain="mail.google.com",
        destination_ai_system_id="ai-system-gmail",
        destination_discovery_status="approved",
        destination_app_name="Gmail",
        destination_is_external=True,
        platform_mode="enforce",
    )
    assert decision.decision in {"require_justification", "block"}
    assert decision.reason_code in {
        "protected_to_external_collaboration_requires_justification",
        "protected_to_external_warn",
    }
    assert decision.policy is not None


def test_data_transfer_no_sensitive_internal_allows() -> None:
    decision = evaluate_data_transfer_policy(
        source_classification="public",
        source_surface="document",
        destination_surface="saas",
        destination_domain="wiki.acme.ai",
        destination_ai_system_id=None,
        destination_discovery_status="unknown",
        destination_app_name="Internal Wiki",
        destination_is_external=False,
        platform_mode="enforce",
    )
    assert decision.decision == "allow"
