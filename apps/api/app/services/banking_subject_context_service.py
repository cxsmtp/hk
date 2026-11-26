from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from typing import Any, Mapping

import jwt
from jwt import PyJWTError as JWTError
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.banking_transaction import BankingSubjectBinding
from app.services.subject_execution_context_service import (
    AuthorizedResourceScope,
    SubjectExecutionContext,
    validate_subject_liveness,
)


MAX_ASSERTION_BYTES = 16_384
MAX_ASSERTION_LIFETIME_SECONDS = 600


class BankingSubjectContextError(ValueError):
    """Fail-closed bank assertion validation error with no secret material."""


class BankingSubjectClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=64)
    subject_type: str = Field(min_length=1, max_length=64)
    customer_subject_id: str = Field(min_length=1, max_length=256)
    authenticated_principal_id: str = Field(min_length=1, max_length=256)
    mobile_session_id: str = Field(min_length=1, max_length=128)
    channel: str = Field(min_length=1, max_length=64)
    approved_account_ids: tuple[str, ...] = Field(min_length=1, max_length=100)
    approved_resource_scope: tuple[str, ...] = Field(min_length=1, max_length=100)
    approved_resource_scopes: tuple[AuthorizedResourceScope, ...] = Field(
        min_length=1,
        max_length=100,
    )
    device_trust_reference: str = Field(min_length=1, max_length=256)
    purpose_id: str = Field(min_length=1, max_length=128)
    authority_scope: tuple[str, ...] = Field(min_length=1, max_length=100)
    auth_time: int
    provenance: str = Field(min_length=1, max_length=64)
    trust_level: str = Field(min_length=1, max_length=64)
    source_system: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=128)
    iss: str = Field(min_length=1, max_length=512)
    aud: str | tuple[str, ...]
    kid: str = Field(min_length=1, max_length=128)
    iat: int
    exp: int
    nonce: str = Field(min_length=16, max_length=256)

    @field_validator(
        "approved_account_ids",
        "approved_resource_scope",
        "authority_scope",
    )
    @classmethod
    def _unique_nonempty_scope(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(str(item).strip() for item in value)
        if any(not item or len(item) > 512 for item in normalized):
            raise ValueError("banking scope values must be non-empty and bounded")
        if len(set(normalized)) != len(normalized):
            raise ValueError("banking scope values must be unique")
        return normalized


class ValidatedBankingSubject(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    ai_transaction_id: str
    context_digest: str
    subject_type: str
    customer_subject_hash: str
    authenticated_principal_hash: str
    mobile_session_hash: str
    approved_account_hashes: tuple[str, ...]
    approved_resource_hashes: tuple[str, ...]
    resource_scope_hashes: tuple[dict[str, Any], ...]
    device_trust_hash: str
    channel: str
    purpose_id: str
    authority_scope: tuple[str, ...]
    auth_time: datetime
    identity_provenance: str
    trust_level: str
    source_system: str
    policy_version: str
    issuer: str
    expires_at: datetime


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _hmac_hex(secret: str, value: Any) -> str:
    return hmac.new(
        secret.encode("utf-8"),
        _canonical_json(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def fingerprint_banking_value(
    *, tenant_id: str, kind: str, value: str, settings_obj: Any
) -> str:
    secret = str(
        getattr(settings_obj, "banking_subject_pseudonymization_key", "") or ""
    ).strip()
    if len(secret) < 32:
        raise BankingSubjectContextError("banking pseudonymization key is unavailable")
    normalized = str(value or "").strip()
    if not normalized:
        raise BankingSubjectContextError("banking authority value is missing")
    digest = _hmac_hex(
        secret,
        {"tenant_id": tenant_id, "kind": str(kind).strip(), "value": normalized},
    )
    return f"hmac-sha256:{digest}"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _trusted_issuer_config(settings_obj: Any, issuer: str) -> Mapping[str, Any]:
    try:
        trust = json.loads(str(getattr(settings_obj, "banking_subject_trust_json", "{}")))
    except json.JSONDecodeError as exc:
        raise BankingSubjectContextError("banking subject trust is invalid") from exc
    config = trust.get(issuer) if isinstance(trust, dict) else None
    if not isinstance(config, dict):
        raise BankingSubjectContextError("banking subject issuer is not trusted")
    return config


def validate_and_bind_banking_subject_context(
    db: Session,
    *,
    tenant_id: str,
    ai_transaction_id: str,
    compact_assertion: str,
    settings_obj: Any,
    now: datetime | None = None,
) -> ValidatedBankingSubject:
    if not bool(getattr(settings_obj, "banking_transaction_integrity_enabled", False)):
        raise BankingSubjectContextError("banking transaction integrity is disabled")
    token = compact_assertion if isinstance(compact_assertion, str) else ""
    if not token or len(token.encode("utf-8")) > MAX_ASSERTION_BYTES:
        raise BankingSubjectContextError("banking subject assertion is invalid")
    transaction_id = str(ai_transaction_id or "").strip()
    if not transaction_id or len(transaction_id) > 64:
        raise BankingSubjectContextError("banking transaction ID is invalid")
    evaluated_at = _utc(now or datetime.now(timezone.utc))

    try:
        header = jwt.get_unverified_header(token)
        unverified = jwt.decode(token, options={"verify_signature": False})
        algorithm = str(header.get("alg") or "")
        key_id = str(header.get("kid") or "").strip()
        issuer = str(unverified.get("iss") or "").strip()
        if algorithm != "ES256" or not key_id or not issuer:
            raise BankingSubjectContextError("banking subject assertion metadata is invalid")
        issuer_config = _trusted_issuer_config(settings_obj, issuer)
        audience = issuer_config.get("audience")
        keys = issuer_config.get("keys")
        public_key = keys.get(key_id) if isinstance(keys, dict) else None
        if not isinstance(audience, str) or not audience.strip() or not isinstance(public_key, str):
            raise BankingSubjectContextError("banking subject signing key is not trusted")
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["ES256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["aud", "exp", "iat", "iss"]},
        )
        claims = BankingSubjectClaims.model_validate(decoded)
    except BankingSubjectContextError:
        raise
    except (JWTError, ValidationError, TypeError, ValueError, AttributeError) as exc:
        raise BankingSubjectContextError("banking subject assertion verification failed") from exc

    if claims.kid != key_id or claims.tenant_id != tenant_id:
        raise BankingSubjectContextError("banking subject assertion binding is invalid")
    if claims.iat > int(evaluated_at.timestamp()) + 30:
        raise BankingSubjectContextError("banking subject assertion issue time is invalid")
    if claims.auth_time > claims.iat:
        raise BankingSubjectContextError("banking subject authentication time is invalid")
    if claims.exp - claims.iat > MAX_ASSERTION_LIFETIME_SECONDS:
        raise BankingSubjectContextError("banking subject assertion lifetime exceeds policy")

    secret = str(
        getattr(settings_obj, "banking_subject_pseudonymization_key", "") or ""
    ).strip()
    if len(secret) < 32:
        raise BankingSubjectContextError("banking pseudonymization key is unavailable")
    canonical_claims = claims.model_dump(mode="json")
    context_digest = _hmac_hex(
        secret,
        {"tenant_id": tenant_id, "claims": canonical_claims},
    )
    nonce_hash = _hmac_hex(
        secret,
        {"tenant_id": tenant_id, "issuer": claims.iss, "nonce": claims.nonce},
    )
    expires_at = datetime.fromtimestamp(claims.exp, tz=timezone.utc)
    try:
        execution_context = SubjectExecutionContext(
            tenant_id=claims.tenant_id,
            subject_type=claims.subject_type,
            subject_id=claims.customer_subject_id,
            authenticated_principal_id=claims.authenticated_principal_id,
            session_id=claims.mobile_session_id,
            channel=claims.channel,
            device_trust_ref=claims.device_trust_reference,
            approved_resource_scopes=claims.approved_resource_scopes,
            approved_account_ids=claims.approved_account_ids,
            purpose_id=claims.purpose_id,
            authority_scope=claims.authority_scope,
            auth_time=datetime.fromtimestamp(claims.auth_time, tz=timezone.utc),
            issued_at=datetime.fromtimestamp(claims.iat, tz=timezone.utc),
            expires_at=expires_at,
            nonce=claims.nonce,
            provenance=claims.provenance,
            trust_level=claims.trust_level,
            source_system=claims.source_system,
            policy_version=claims.policy_version,
        )
    except ValidationError as exc:
        raise BankingSubjectContextError(
            "banking subject execution context is invalid"
        ) from exc
    liveness = validate_subject_liveness(execution_context, now=evaluated_at)
    if not liveness.active:
        raise BankingSubjectContextError(liveness.reason_code.lower())
    existing = db.scalar(
        select(BankingSubjectBinding).where(
            BankingSubjectBinding.tenant_id == tenant_id,
            BankingSubjectBinding.issuer == claims.iss,
            BankingSubjectBinding.nonce_hash == nonce_hash,
        )
    )
    if existing is None:
        db.add(
            BankingSubjectBinding(
                tenant_id=tenant_id,
                issuer=claims.iss,
                nonce_hash=nonce_hash,
                context_digest=context_digest,
                ai_transaction_id=transaction_id,
                expires_at=expires_at,
                last_seen_at=evaluated_at,
            )
        )
        db.flush()
    else:
        if (
            existing.context_digest != context_digest
            or existing.ai_transaction_id != transaction_id
            or _utc(existing.expires_at) <= evaluated_at
        ):
            raise BankingSubjectContextError("banking subject assertion replay detected")
        existing.last_seen_at = evaluated_at
        db.flush()

    return ValidatedBankingSubject(
        tenant_id=tenant_id,
        ai_transaction_id=transaction_id,
        context_digest=context_digest,
        subject_type=claims.subject_type,
        customer_subject_hash=fingerprint_banking_value(
            tenant_id=tenant_id,
            kind="customer_subject",
            value=claims.customer_subject_id,
            settings_obj=settings_obj,
        ),
        authenticated_principal_hash=fingerprint_banking_value(
            tenant_id=tenant_id,
            kind="authenticated_principal",
            value=claims.authenticated_principal_id,
            settings_obj=settings_obj,
        ),
        mobile_session_hash=fingerprint_banking_value(
            tenant_id=tenant_id,
            kind="mobile_session",
            value=claims.mobile_session_id,
            settings_obj=settings_obj,
        ),
        approved_account_hashes=tuple(
            fingerprint_banking_value(
                tenant_id=tenant_id,
                kind="account",
                value=value,
                settings_obj=settings_obj,
            )
            for value in claims.approved_account_ids
        ),
        approved_resource_hashes=tuple(
            fingerprint_banking_value(
                tenant_id=tenant_id,
                kind="resource",
                value=value,
                settings_obj=settings_obj,
            )
            for value in claims.approved_resource_scope
        ),
        resource_scope_hashes=tuple(
            {
                "resource_type": scope.resource_type,
                "resource_reference_hash": fingerprint_banking_value(
                    tenant_id=tenant_id,
                    kind=scope.resource_type,
                    value=scope.resource_reference,
                    settings_obj=settings_obj,
                ),
                "relationship_to_subject": scope.relationship_to_subject,
                "allowed_operations": list(scope.allowed_operations),
                "expires_at": _utc(scope.expires_at).isoformat(),
                "source_of_authority": scope.source_of_authority,
            }
            for scope in execution_context.approved_resource_scopes
        ),
        device_trust_hash=fingerprint_banking_value(
            tenant_id=tenant_id,
            kind="device_trust",
            value=claims.device_trust_reference,
            settings_obj=settings_obj,
        ),
        channel=claims.channel,
        purpose_id=claims.purpose_id,
        authority_scope=claims.authority_scope,
        auth_time=datetime.fromtimestamp(claims.auth_time, tz=timezone.utc),
        identity_provenance=claims.provenance,
        trust_level=claims.trust_level,
        source_system=claims.source_system,
        policy_version=claims.policy_version,
        issuer=claims.iss,
        expires_at=expires_at,
    )
