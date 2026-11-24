from __future__ import annotations

import hashlib
import hmac

import pytest
from pydantic import ValidationError


CUSTOMER = "hmac-sha256:" + "1" * 64
ACCOUNT = "hmac-sha256:" + "2" * 64
BENEFICIARY = "hmac-sha256:" + "3" * 64
TOOL = "a" * 64
RECEIPT = "11111111-1111-1111-1111-111111111111"
ATTESTATION_KEY = "bank-response-attestation-key-material-0001"


def _claims() -> dict:
    return {
        "currency": "AED",
        "total_amount": "327.50",
        "transaction_count": 11,
        "period_start": "2026-08-01",
        "period_end": "2026-08-14",
        "fee_amount": "2.50",
        "interest_or_charge_amount": "0.00",
        "transaction_category": "utilities",
        "beneficiary_fingerprint": BENEFICIARY,
        "status": "complete",
        "source_field": "ledger.month_to_date",
    }


def _envelope() -> dict:
    from app.services.banking_response_assurance_service import (
        compute_banking_result_digest,
    )

    body = {
        "ai_transaction_id": "transaction-001",
        "action_id": "action-001",
        "customer_fingerprint": CUSTOMER,
        "account_fingerprint": ACCOUNT,
        "tool_fingerprint": TOOL,
        "result_schema": "bank.account_summary",
        "result_version": "1.0.0",
        "approved_fields": list(_claims()),
        "field_classifications": {field: "confidential" for field in _claims()},
        "claims": _claims(),
        "execution_status": "success",
    }
    return {**body, "result_digest": compute_banking_result_digest(body)}


def _request(
    *,
    candidate: dict | None = None,
    mismatch_action: str = "safe_fallback",
    regeneration_attempt: int = 0,
) -> dict:
    return {
        "decision_receipt_id": RECEIPT,
        "authorized_customer_fingerprint": CUSTOMER,
        "authorized_account_fingerprint": ACCOUNT,
        "trusted_result": _envelope(),
        "candidate_claims": candidate or _claims(),
        "regeneration_attempt": regeneration_attempt,
        "policy": {
            "allowed_response_fields": list(_claims()),
            "mismatch_action": mismatch_action,
            "excess_field_action": "redact",
            "max_regenerations": 1,
        },
        "evidence_source": {
            "claimed_grade": "provider_reported",
            "source_id": "foundry-function-result",
        },
    }


def test_exact_structured_claims_are_allowed_without_storing_values() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
    )

    result = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(_request()),
        attestation_keys={},
    )

    assert result.decision == "allow"
    assert result.assurance == "limited_claim_check"
    assert result.evidence_grade == "provider_reported"
    assert result.compared_fields == tuple(sorted(_claims()))
    assert result.mismatch_fields == ()
    assert "327.50" not in result.model_dump_json()
    assert CUSTOMER not in result.model_dump_json()
    assert ACCOUNT not in result.model_dump_json()


@pytest.mark.parametrize(
    ("field", "wrong_value"),
    (
        ("currency", "USD"),
        ("total_amount", "3275.00"),
        ("transaction_count", 12),
        ("period_start", "2026-07-01"),
        ("fee_amount", "25.00"),
        ("interest_or_charge_amount", "10.00"),
        ("transaction_category", "cash"),
        ("beneficiary_fingerprint", "hmac-sha256:" + "4" * 64),
        ("status", "pending"),
        ("source_field", "model.guess"),
    ),
)
def test_financial_claim_mismatch_returns_deterministic_safe_fallback(
    field: str,
    wrong_value: object,
) -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
    )

    candidate = _claims()
    candidate[field] = wrong_value
    result = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(_request(candidate=candidate)),
        attestation_keys={},
    )

    assert result.decision == "safe_fallback"
    assert result.reason_code == "BANKING_STRUCTURED_CLAIM_MISMATCH"
    assert field in result.mismatch_fields
    assert result.safe_response == _claims()
    assert result.should_regenerate is False


def test_cross_customer_or_account_claim_is_blocked() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
    )

    candidate = {
        **_claims(),
        "customer_fingerprint": "hmac-sha256:" + "9" * 64,
        "account_fingerprint": ACCOUNT,
    }
    result = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(_request(candidate=candidate)),
        attestation_keys={},
    )

    assert result.decision == "block"
    assert result.reason_code == "RESPONSE_SUBJECT_BOUNDARY_VIOLATION"
    assert result.safe_response is None


def test_excess_fields_are_redacted_without_provider_retry() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
    )

    candidate = {**_claims(), "internal_risk_flag": "secret"}
    result = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(_request(candidate=candidate)),
        attestation_keys={},
    )

    assert result.decision == "redact"
    assert result.redacted_fields == ("internal_risk_flag",)
    assert result.safe_response == _claims()
    assert result.should_regenerate is False


def test_regeneration_is_bounded_to_one_attempt() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
    )

    candidate = {**_claims(), "total_amount": "999.00"}
    first = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(
            _request(candidate=candidate, mismatch_action="regenerate")
        ),
        attestation_keys={},
    )
    second = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(
            _request(
                candidate=candidate,
                mismatch_action="regenerate",
                regeneration_attempt=1,
            )
        ),
        attestation_keys={},
    )

    assert (first.decision, first.should_regenerate) == ("regenerate", True)
    assert (second.decision, second.should_regenerate) == ("safe_fallback", False)


def test_signed_bank_attestation_is_required_for_confirmed_grade() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
        sign_banking_evidence_attestation,
    )

    payload = _request()
    payload["evidence_source"] = {
        "claimed_grade": "bank_service_confirmed",
        "source_id": "bank-ledger-service",
        "key_id": "bank-response-key",
        "attestation": sign_banking_evidence_attestation(
            claimed_grade="bank_service_confirmed",
            source_id="bank-ledger-service",
            ai_transaction_id="transaction-001",
            action_id="action-001",
            decision_receipt_id=RECEIPT,
            result_digest=payload["trusted_result"]["result_digest"],
            secret=ATTESTATION_KEY,
        ),
    }
    confirmed = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(payload),
        attestation_keys={"bank-response-key": ATTESTATION_KEY},
    )
    payload["evidence_source"]["attestation"] = "0" * 64
    forged = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(payload),
        attestation_keys={"bank-response-key": ATTESTATION_KEY},
    )

    assert confirmed.evidence_grade == "bank_service_confirmed"
    assert confirmed.assurance == "structured_verified"
    assert forged.evidence_grade == "provider_reported"
    assert forged.assurance == "limited_claim_check"


def test_invalid_result_digest_blocks_and_fails_closed() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
    )

    payload = _request()
    payload["trusted_result"]["result_digest"] = "f" * 64
    result = assure_banking_response(
        BankingResponseAssuranceRequest.model_validate(payload),
        attestation_keys={},
    )

    assert result.decision == "block"
    assert result.reason_code == "TRUSTED_RESULT_DIGEST_MISMATCH"
    assert result.assurance == "unverified"


def test_evidence_projection_contains_only_hashes_fields_and_receipt_references() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
        assure_banking_response,
        build_banking_response_evidence_node,
    )

    request = BankingResponseAssuranceRequest.model_validate(_request())
    result = assure_banking_response(request, attestation_keys={})
    node = build_banking_response_evidence_node(
        tenant_id="tenant-a",
        request=request,
        result=result,
    )
    serialized = str(node.payload)

    assert node.signal_type == "banking.response_assurance"
    assert node.payload["decision_receipt_id"] == RECEIPT
    assert node.payload["trusted_result_digest"] == request.trusted_result.result_digest
    assert CUSTOMER not in serialized
    assert ACCOUNT not in serialized
    assert "327.50" not in serialized
    assert "utilities" not in serialized


def test_raw_identifiers_and_unbounded_claims_are_rejected() -> None:
    from app.services.banking_response_assurance_service import (
        BankingResponseAssuranceRequest,
    )

    payload = _request()
    payload["authorized_customer_fingerprint"] = "customer-001"
    with pytest.raises(ValidationError):
        BankingResponseAssuranceRequest.model_validate(payload)

    payload = _request()
    payload["candidate_claims"] = {f"field-{index}": index for index in range(130)}
    with pytest.raises(ValidationError):
        BankingResponseAssuranceRequest.model_validate(payload)
