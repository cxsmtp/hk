from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import math
import re
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.db.models.evidence import EvidenceNode


MAX_RESPONSE_FIELDS = 128
MAX_RESPONSE_ENCODED_BYTES = 65_536
_FINGERPRINT = re.compile(r"^(?:hmac-sha256:)?[a-f0-9]{64}$")
_SUPPORTED_CLAIMS = frozenset(
    {
        "currency",
        "total_amount",
        "transaction_count",
        "period_start",
        "period_end",
        "fee_amount",
        "interest_or_charge_amount",
        "transaction_category",
        "beneficiary_fingerprint",
        "status",
        "source_field",
    }
)
_SCOPE_FIELDS = frozenset({"customer_fingerprint", "account_fingerprint"})
_DECIMAL_FIELDS = frozenset(
    {"total_amount", "fee_amount", "interest_or_charge_amount"}
)
_DATE_FIELDS = frozenset({"period_start", "period_end"})


def _canonical_json(value: Any) -> bytes:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
        default=str,
    ).encode("utf-8")
    if len(encoded) > MAX_RESPONSE_ENCODED_BYTES:
        raise ValueError("banking response material exceeds maximum size")
    return encoded


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _fingerprint(value: str, *, field: str) -> str:
    token = str(value or "").strip().lower()
    if not _FINGERPRINT.fullmatch(token):
        raise ValueError(f"{field} must be a pseudonymous SHA-256 fingerprint")
    return token


def _validate_claim(field: str, value: Any) -> None:
    if field in _DECIMAL_FIELDS:
        try:
            decimal_value = Decimal(str(value))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(f"{field} must be a decimal value") from exc
        if not decimal_value.is_finite():
            raise ValueError(f"{field} must be finite")
        return
    if field == "transaction_count":
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("transaction_count must be a non-negative integer")
        return
    if field in _DATE_FIELDS:
        try:
            date.fromisoformat(str(value))
        except ValueError as exc:
            raise ValueError(f"{field} must be an ISO date") from exc
        return
    if field == "currency":
        token = str(value or "").strip()
        if len(token) != 3 or not token.isalpha() or token != token.upper():
            raise ValueError("currency must be an uppercase ISO-style code")
        return
    if field == "beneficiary_fingerprint":
        _fingerprint(str(value), field=field)
        return
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise ValueError(f"{field} must be a bounded non-empty string")


def _validate_claim_map(value: dict[str, Any], *, allow_scope: bool) -> dict[str, Any]:
    if len(value) > MAX_RESPONSE_FIELDS:
        raise ValueError("banking response has too many fields")
    _canonical_json(value)
    for field, claim in value.items():
        if not isinstance(field, str) or not field or len(field) > 128:
            raise ValueError("banking response field name is invalid")
        if field in _SCOPE_FIELDS:
            if not allow_scope:
                raise ValueError("scope fingerprints do not belong in trusted claims")
            _fingerprint(str(claim), field=field)
        elif field in _SUPPORTED_CLAIMS:
            _validate_claim(field, claim)
        elif not allow_scope:
            raise ValueError(f"unsupported trusted banking claim: {field}")
    return value


class BankingStructuredResultEnvelope(BaseModel):
    """Typed, digest-bound result emitted by a trusted banking function."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    ai_transaction_id: str = Field(min_length=1, max_length=64)
    action_id: str = Field(min_length=1, max_length=64)
    customer_fingerprint: str
    account_fingerprint: str
    tool_fingerprint: str
    result_schema: str = Field(min_length=1, max_length=128)
    result_version: str = Field(min_length=1, max_length=64)
    approved_fields: tuple[str, ...] = Field(min_length=1, max_length=MAX_RESPONSE_FIELDS)
    field_classifications: dict[str, str]
    claims: dict[str, Any]
    result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    execution_status: Literal["success", "failure"]

    @field_validator(
        "customer_fingerprint",
        "account_fingerprint",
        "tool_fingerprint",
    )
    @classmethod
    def _pseudonymous_fingerprint(cls, value: str, info: Any) -> str:
        return _fingerprint(value, field=info.field_name)

    @field_validator("approved_fields")
    @classmethod
    def _approved_claim_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value) or any(field not in _SUPPORTED_CLAIMS for field in value):
            raise ValueError("approved response fields must be unique supported claims")
        return value

    @field_validator("claims")
    @classmethod
    def _trusted_claims(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_claim_map(value, allow_scope=False)

    @model_validator(mode="after")
    def _classification_and_claim_coverage(self) -> "BankingStructuredResultEnvelope":
        approved = set(self.approved_fields)
        if not approved.issubset(self.claims):
            raise ValueError("trusted result is missing an approved claim")
        if set(self.field_classifications) != approved:
            raise ValueError("field classifications must exactly cover approved fields")
        if any(
            not isinstance(value, str) or not value.strip() or len(value) > 64
            for value in self.field_classifications.values()
        ):
            raise ValueError("field classification is invalid")
        return self

    def digest_material(self) -> dict[str, Any]:
        """Returns exact material covered by the trusted result digest."""

        return self.model_dump(mode="json", exclude={"result_digest"})


class BankingResponseAssurancePolicy(BaseModel):
    """Server-selected deterministic response policy; never model-authored."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed_response_fields: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_RESPONSE_FIELDS,
    )
    mismatch_action: Literal["safe_fallback", "regenerate", "block"] = "safe_fallback"
    excess_field_action: Literal["redact", "block"] = "redact"
    max_regenerations: Literal[0, 1] = 0

    @field_validator("allowed_response_fields")
    @classmethod
    def _supported_fields(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value) or any(field not in _SUPPORTED_CLAIMS for field in value):
            raise ValueError("response policy contains unsupported or duplicate fields")
        return value


class BankingEvidenceSource(BaseModel):
    """Claimed evidence source; stronger grades require a valid server-keyed attestation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claimed_grade: Literal[
        "provider_reported",
        "hawk_runtime_observed",
        "bank_service_confirmed",
        "externally_verified",
    ] = "provider_reported"
    source_id: str = Field(min_length=1, max_length=128)
    key_id: str | None = Field(default=None, min_length=1, max_length=64)
    attestation: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class BankingResponseAssuranceRequest(BaseModel):
    """Exact trusted source and candidate structured response submitted for comparison."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_receipt_id: str = Field(min_length=1, max_length=36)
    authorized_customer_fingerprint: str
    authorized_account_fingerprint: str
    trusted_result: BankingStructuredResultEnvelope
    candidate_claims: dict[str, Any]
    regeneration_attempt: int = Field(default=0, ge=0, le=1)
    policy: BankingResponseAssurancePolicy
    evidence_source: BankingEvidenceSource

    @field_validator("authorized_customer_fingerprint", "authorized_account_fingerprint")
    @classmethod
    def _authorized_fingerprint(cls, value: str, info: Any) -> str:
        return _fingerprint(value, field=info.field_name)

    @field_validator("candidate_claims")
    @classmethod
    def _candidate_claims(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_claim_map(value, allow_scope=True)


class BankingResponseAssuranceResult(BaseModel):
    """Deterministic release decision plus privacy-safe comparison metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    decision: Literal["allow", "redact", "regenerate", "safe_fallback", "block"]
    reason_code: str
    assurance: Literal[
        "structured_verified",
        "limited_claim_check",
        "unverified",
        "not_covered",
    ]
    evidence_grade: Literal[
        "provider_reported",
        "hawk_runtime_observed",
        "bank_service_confirmed",
        "externally_verified",
    ]
    compared_fields: tuple[str, ...] = ()
    mismatch_fields: tuple[str, ...] = ()
    redacted_fields: tuple[str, ...] = ()
    safe_response: dict[str, Any] | None = None
    should_regenerate: bool = False
    trusted_result_digest: str
    candidate_response_hash: str
    decision_receipt_id: str


def compute_banking_result_digest(material: Mapping[str, Any]) -> str:
    """Computes the deterministic digest emitted by the trusted function envelope."""

    body = dict(material)
    body.pop("result_digest", None)
    return _sha256(body)


def _attestation_material(
    *,
    claimed_grade: str,
    source_id: str,
    ai_transaction_id: str,
    action_id: str,
    decision_receipt_id: str,
    result_digest: str,
) -> dict[str, str]:
    return {
        "schema": "hawk.banking_evidence_attestation/1.0",
        "claimed_grade": claimed_grade,
        "source_id": source_id,
        "ai_transaction_id": ai_transaction_id,
        "action_id": action_id,
        "decision_receipt_id": decision_receipt_id,
        "result_digest": result_digest,
    }


def sign_banking_evidence_attestation(
    *,
    claimed_grade: str,
    source_id: str,
    ai_transaction_id: str,
    action_id: str,
    decision_receipt_id: str,
    result_digest: str,
    secret: str,
) -> str:
    """Signs test/bank-service evidence material; production keys remain server managed."""

    if len(secret) < 32:
        raise ValueError("banking evidence attestation key is too short")
    return hmac.new(
        secret.encode("utf-8"),
        _canonical_json(
            _attestation_material(
                claimed_grade=claimed_grade,
                source_id=source_id,
                ai_transaction_id=ai_transaction_id,
                action_id=action_id,
                decision_receipt_id=decision_receipt_id,
                result_digest=result_digest,
            )
        ),
        hashlib.sha256,
    ).hexdigest()


def _evidence_grade(
    request: BankingResponseAssuranceRequest,
    *,
    attestation_keys: Mapping[str, str],
) -> str:
    source = request.evidence_source
    if source.claimed_grade not in {"bank_service_confirmed", "externally_verified"}:
        return "provider_reported"
    secret = attestation_keys.get(str(source.key_id or ""))
    if not secret or len(secret) < 32 or not source.attestation:
        return "provider_reported"
    expected = sign_banking_evidence_attestation(
        claimed_grade=source.claimed_grade,
        source_id=source.source_id,
        ai_transaction_id=request.trusted_result.ai_transaction_id,
        action_id=request.trusted_result.action_id,
        decision_receipt_id=request.decision_receipt_id,
        result_digest=request.trusted_result.result_digest,
        secret=secret,
    )
    return (
        source.claimed_grade
        if hmac.compare_digest(expected, source.attestation)
        else "provider_reported"
    )


def _normalized_claim(field: str, value: Any) -> Any:
    if field in _DECIMAL_FIELDS:
        return Decimal(str(value)).normalize()
    if field in _DATE_FIELDS:
        return date.fromisoformat(str(value))
    if field == "currency":
        return str(value).upper()
    return value


def _result(
    request: BankingResponseAssuranceRequest,
    *,
    decision: str,
    reason_code: str,
    assurance: str,
    evidence_grade: str,
    compared_fields: tuple[str, ...] = (),
    mismatch_fields: tuple[str, ...] = (),
    redacted_fields: tuple[str, ...] = (),
    safe_response: dict[str, Any] | None = None,
    should_regenerate: bool = False,
) -> BankingResponseAssuranceResult:
    return BankingResponseAssuranceResult(
        decision=decision,
        reason_code=reason_code,
        assurance=assurance,
        evidence_grade=evidence_grade,
        compared_fields=compared_fields,
        mismatch_fields=mismatch_fields,
        redacted_fields=redacted_fields,
        safe_response=safe_response,
        should_regenerate=should_regenerate,
        trusted_result_digest=request.trusted_result.result_digest,
        candidate_response_hash=_sha256(request.candidate_claims),
        decision_receipt_id=request.decision_receipt_id,
    )


def assure_banking_response(
    request: BankingResponseAssuranceRequest,
    *,
    attestation_keys: Mapping[str, str],
) -> BankingResponseAssuranceResult:
    """Deterministically compares structured response claims before release."""

    grade = _evidence_grade(request, attestation_keys=attestation_keys)
    trusted = request.trusted_result
    expected_digest = compute_banking_result_digest(trusted.digest_material())
    if not hmac.compare_digest(expected_digest, trusted.result_digest):
        return _result(
            request,
            decision="block",
            reason_code="TRUSTED_RESULT_DIGEST_MISMATCH",
            assurance="unverified",
            evidence_grade=grade,
        )
    if trusted.execution_status != "success":
        return _result(
            request,
            decision="block",
            reason_code="TRUSTED_RESULT_EXECUTION_FAILED",
            assurance="unverified",
            evidence_grade=grade,
        )
    candidate_customer = request.candidate_claims.get("customer_fingerprint")
    candidate_account = request.candidate_claims.get("account_fingerprint")
    if (
        trusted.customer_fingerprint != request.authorized_customer_fingerprint
        or trusted.account_fingerprint != request.authorized_account_fingerprint
        or (
            candidate_customer is not None
            and candidate_customer != request.authorized_customer_fingerprint
        )
        or (
            candidate_account is not None
            and candidate_account != request.authorized_account_fingerprint
        )
    ):
        return _result(
            request,
            decision="block",
            reason_code="RESPONSE_SUBJECT_BOUNDARY_VIOLATION",
            assurance="unverified",
            evidence_grade=grade,
        )

    allowed = tuple(sorted(request.policy.allowed_response_fields))
    if not set(allowed).issubset(trusted.approved_fields):
        return _result(
            request,
            decision="block",
            reason_code="RESPONSE_POLICY_NOT_COVERED_BY_TRUSTED_RESULT",
            assurance="not_covered",
            evidence_grade=grade,
        )
    mismatch = tuple(
        field
        for field in allowed
        if field not in request.candidate_claims
        or _normalized_claim(field, request.candidate_claims[field])
        != _normalized_claim(field, trusted.claims[field])
    )
    excess = tuple(
        sorted(set(request.candidate_claims) - set(allowed) - _SCOPE_FIELDS)
    )
    assurance = (
        "structured_verified"
        if grade in {"bank_service_confirmed", "externally_verified"}
        else "limited_claim_check"
    )
    safe_trusted = {field: trusted.claims[field] for field in allowed}
    if mismatch:
        if (
            request.policy.mismatch_action == "regenerate"
            and request.regeneration_attempt < request.policy.max_regenerations
        ):
            return _result(
                request,
                decision="regenerate",
                reason_code="BANKING_STRUCTURED_CLAIM_MISMATCH",
                assurance=assurance,
                evidence_grade=grade,
                compared_fields=allowed,
                mismatch_fields=mismatch,
                should_regenerate=True,
            )
        if request.policy.mismatch_action == "block":
            return _result(
                request,
                decision="block",
                reason_code="BANKING_STRUCTURED_CLAIM_MISMATCH",
                assurance=assurance,
                evidence_grade=grade,
                compared_fields=allowed,
                mismatch_fields=mismatch,
            )
        return _result(
            request,
            decision="safe_fallback",
            reason_code="BANKING_STRUCTURED_CLAIM_MISMATCH",
            assurance=assurance,
            evidence_grade=grade,
            compared_fields=allowed,
            mismatch_fields=mismatch,
            safe_response=safe_trusted,
        )
    if excess:
        if request.policy.excess_field_action == "block":
            return _result(
                request,
                decision="block",
                reason_code="BANKING_RESPONSE_EXCESS_FIELDS",
                assurance=assurance,
                evidence_grade=grade,
                compared_fields=allowed,
                redacted_fields=excess,
            )
        return _result(
            request,
            decision="redact",
            reason_code="BANKING_RESPONSE_EXCESS_FIELDS",
            assurance=assurance,
            evidence_grade=grade,
            compared_fields=allowed,
            redacted_fields=excess,
            safe_response={field: request.candidate_claims[field] for field in allowed},
        )
    return _result(
        request,
        decision="allow",
        reason_code="BANKING_STRUCTURED_RESPONSE_MATCHED",
        assurance=assurance,
        evidence_grade=grade,
        compared_fields=allowed,
    )


def build_banking_response_evidence_node(
    *,
    tenant_id: str,
    request: BankingResponseAssuranceRequest,
    result: BankingResponseAssuranceResult,
) -> EvidenceNode:
    """Builds an existing EvidenceNode containing no raw response claims or PII."""

    return EvidenceNode(
        tenant_id=tenant_id,
        correlation_id=request.trusted_result.ai_transaction_id,
        node_type="banking_response_assurance",
        signal_type="banking.response_assurance",
        label="Banking structured response assurance",
        payload={
            "schema": "hawk.banking_response_assurance/1.0",
            "ai_transaction_id": request.trusted_result.ai_transaction_id,
            "action_id": request.trusted_result.action_id,
            "decision_receipt_id": request.decision_receipt_id,
            "trusted_result_digest": result.trusted_result_digest,
            "candidate_response_hash": result.candidate_response_hash,
            "decision": result.decision,
            "reason_code": result.reason_code,
            "assurance": result.assurance,
            "evidence_grade": result.evidence_grade,
            "compared_fields": list(result.compared_fields),
            "mismatch_fields": list(result.mismatch_fields),
            "redacted_fields": list(result.redacted_fields),
            "should_regenerate": result.should_regenerate,
        },
    )
