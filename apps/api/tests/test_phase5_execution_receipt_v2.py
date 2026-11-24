from __future__ import annotations

from datetime import datetime, timezone


NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)


def _action(*, unresolved: list[str] | None = None) -> dict[str, object]:
    return {
        "schema_version": "2.0", "tenant_id": "tenant-exec", "action_id": "action-exec", "chain_id": "chain-exec", "correlation_id": "correlation-exec",
        "parent_action_id": None, "actor_principal": "user:a", "executing_principal": "agent:a", "represented_subjects": [], "resource_scopes": [],
        "authority_context": "authority:a", "business_purpose": "purpose:a", "environment": "production", "provider_runtime_context": "runtime:a",
        "action_semantics": {"action_class": "consequential", "operation": "write", "object_type": "object", "tool_or_service_ref": "tool:a", "tool_fingerprint": "f" * 64, "safe_parameters": {}, "represented_subject_refs": [], "resource_refs": [], "counterparty_refs": [], "target_refs": ["target:a"], "destination_refs": ["destination:a"], "values_or_quantities": [], "authority_ref": "authority:a", "business_purpose_ref": "purpose:a", "side_effect": "external_write", "persistence": "none", "environment": "production", "reversibility": "none", "expected_outcome_ref": "outcome:exec"},
        "domain_profile_ref": "profile:a", "domain_profile_hash": "a" * 64, "materiality_profile_ref": "materiality:a", "materiality_profile_hash": "b" * 64, "resolver_versions": {}, "policy_version_id": "policy:a", "policy_epoch": 1, "control_plan_id": "plan:a", "control_plan_digest": "c" * 64, "approval_requirement": "not_required", "delegation_digest": "d" * 64, "action_plan_binding": {"binding_type": "STANDALONE", "action_plan_id": None, "action_plan_digest": None, "action_plan_step_id": None, "action_plan_step_digest": None}, "unresolved_material": unresolved or [], "evidence_refs": [], "created_at": "2026-08-25T00:00:00.000000Z",
    }


def _provider():
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="execution_receipt_signing", tenant_id="tenant-exec", key_id="receipt", secret=b"r" * 32)
    provider.add_key(purpose="execution_comparison_signing", tenant_id="tenant-exec", key_id="comparison", secret=b"c" * 32)
    return provider


def test_execution_receipt_is_signed_and_provider_success_is_not_execution_proof() -> None:
    from app.services.action_integrity.execution_proof import issue_execution_receipt_v2, verify_execution_receipt_v2
    receipt = issue_execution_receipt_v2(_provider(), tenant_id="tenant-exec", attempt_id="attempt-1", permit_id="permit-1", authorized=_action(), executed=_action(), terminal_state="SUCCEEDED", evidence_quality="PROVIDER_REPORTED", issued_at=NOW)
    assert receipt["terminal_state"] == "UNVERIFIED"
    assert verify_execution_receipt_v2(_provider(), receipt)  # same tenant/purpose/key material verifies
    provider = _provider()
    receipt = issue_execution_receipt_v2(provider, tenant_id="tenant-exec", attempt_id="attempt-1", permit_id="permit-1", authorized=_action(), executed=_action(), terminal_state="EXECUTED", evidence_quality="HAWK_RUNTIME_OBSERVED", issued_at=NOW)
    assert verify_execution_receipt_v2(provider, receipt)
    receipt["attempt_id"] = "tampered"
    assert not verify_execution_receipt_v2(provider, receipt)
