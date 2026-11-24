from __future__ import annotations


def test_provider_reported_execution_does_not_claim_independent_outcome() -> None:
    from app.services.action_integrity.execution_proof import normalize_evidence_quality, normalize_execution_state
    assert normalize_execution_state("SUCCEEDED", execution_evidence=False) == "UNVERIFIED"
    assert normalize_evidence_quality("PROVIDER_REPORTED") == "PROVIDER_REPORTED"


def test_outcome_contract_and_verdict_are_signed_and_provider_success_is_insufficient() -> None:
    from datetime import datetime, timedelta, timezone
    import pytest
    from app.services.action_integrity.complex_actions import issue_expected_outcome_contract, issue_outcome_verification
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="outcome_verification_signing", tenant_id="tenant-outcome", key_id="outcome", secret=b"o" * 32)
    contract = issue_expected_outcome_contract(provider, tenant_id="tenant-outcome", action_id="action", expected_state_hash="a" * 64, verification_deadline=now + timedelta(minutes=1), issued_at=now)
    with pytest.raises(PermissionError, match="provider success"):
        issue_outcome_verification(provider, tenant_id="tenant-outcome", action_id="action", attempt_id="attempt", outcome_contract_id=contract["outcome_contract_id"], result="SATISFIED", verification_source_refs=["provider"], evidence_quality="PROVIDER_REPORTED", evaluated_at=now)
    verdict = issue_outcome_verification(provider, tenant_id="tenant-outcome", action_id="action", attempt_id="attempt", outcome_contract_id=contract["outcome_contract_id"], result="SATISFIED", verification_source_refs=["target:evidence"], evidence_quality="INDEPENDENTLY_VERIFIED", evaluated_at=now)
    assert verdict["result"] == "SATISFIED" and verdict["signature"]


def test_outcome_contract_and_verdict_reject_tamper_wrong_purpose_and_wrong_tenant_key() -> None:
    from datetime import datetime, timedelta, timezone

    from app.services.action_integrity.complex_actions import (
        issue_expected_outcome_contract,
        issue_outcome_verification,
        verify_expected_outcome_contract,
        verify_outcome_verification,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    now = datetime(2026, 8, 25, tzinfo=timezone.utc)
    provider = LocalSigningKeyProvider(development=True)
    provider.add_key(purpose="outcome_verification_signing", tenant_id="tenant-outcome", key_id="outcome", secret=b"o" * 32)
    provider.add_key(purpose="outcome_verification_signing", tenant_id="tenant-other", key_id="other", secret=b"p" * 32)
    contract = issue_expected_outcome_contract(provider, tenant_id="tenant-outcome", action_id="action", expected_state_hash="a" * 64, verification_deadline=now + timedelta(minutes=1), issued_at=now)
    verdict = issue_outcome_verification(provider, tenant_id="tenant-outcome", action_id="action", attempt_id="attempt", outcome_contract_id=contract["outcome_contract_id"], result="SATISFIED", verification_source_refs=["target:evidence"], evidence_quality="INDEPENDENTLY_VERIFIED", evaluated_at=now)
    assert verify_expected_outcome_contract(provider, contract)
    assert verify_outcome_verification(provider, verdict)
    contract["action_id"] = "tampered"
    verdict["result"] = "VIOLATED"
    assert not verify_expected_outcome_contract(provider, contract)
    assert not verify_outcome_verification(provider, verdict)
    assert not verify_outcome_verification(provider, {**issue_outcome_verification(provider, tenant_id="tenant-outcome", action_id="action", attempt_id="attempt-2", outcome_contract_id="contract", result="UNKNOWN", verification_source_refs=["target:evidence"], evidence_quality="INDEPENDENTLY_VERIFIED", evaluated_at=now), "tenant_id": "tenant-other"})
