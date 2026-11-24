"""Generic authoritative subject and resource scope for regulated AI actions.

The models in this module are in-memory authorization inputs. They deliberately
contain no credential or token fields and do not create a parallel identity
store. Provider-specific adapters project verified identity evidence into these
contracts before the existing Hawk authorization kernel is invoked.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


AuthoritativeProvenance = Literal[
    "bank_api_gateway",
    "authenticated_mobile_backend",
    "verified_entra_claims",
    "verified_oidc_claims",
    "bank_identity_service",
    "trusted_session_broker",
]

IdentityType = Literal[
    "end_user",
    "mobile_customer",
    "published_agent",
    "project_managed_identity",
    "oauth_passthrough_user",
    "service_principal",
    "application_identity",
    "shared_credential",
    "anonymous",
    "unknown",
]

IdentityQuality = Literal[
    "verified_end_user",
    "dedicated_agent_identity",
    "project_shared_identity",
    "application_identity",
    "shared_credential",
    "anonymous",
    "unknown",
]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _bounded_unique(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    normalized = tuple(str(value or "").strip() for value in values)
    if not normalized or any(not value or len(value) > 512 for value in normalized):
        raise ValueError(f"{field_name} must contain bounded non-empty values")
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field_name} values must be unique")
    return normalized


class AuthorizedResourceScope(BaseModel):
    """One resource boundary issued by an authoritative enterprise system."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_type: str = Field(min_length=1, max_length=64)
    resource_reference: str = Field(min_length=1, max_length=512, repr=False)
    relationship_to_subject: str = Field(min_length=1, max_length=64)
    allowed_operations: tuple[str, ...] = Field(min_length=1, max_length=100)
    expires_at: datetime
    source_of_authority: AuthoritativeProvenance

    @field_validator("allowed_operations")
    @classmethod
    def _operations_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _bounded_unique(value, field_name="allowed_operations")


class SubjectExecutionContext(BaseModel):
    """Immutable subject authority propagated across one regulated transaction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str = Field(min_length=1, max_length=64)
    subject_type: str = Field(min_length=1, max_length=64)
    subject_id: str = Field(min_length=1, max_length=256, repr=False)
    authenticated_principal_id: str = Field(min_length=1, max_length=256, repr=False)
    session_id: str = Field(min_length=1, max_length=128, repr=False)
    channel: str = Field(min_length=1, max_length=64)
    device_trust_ref: str = Field(min_length=1, max_length=256, repr=False)
    approved_resource_scopes: tuple[AuthorizedResourceScope, ...] = Field(
        min_length=1,
        max_length=100,
    )
    approved_account_ids: tuple[str, ...] = Field(min_length=1, max_length=100, repr=False)
    purpose_id: str = Field(min_length=1, max_length=128)
    authority_scope: tuple[str, ...] = Field(min_length=1, max_length=100)
    auth_time: datetime
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(min_length=16, max_length=256, repr=False)
    provenance: str = Field(min_length=1, max_length=64)
    trust_level: str = Field(min_length=1, max_length=64)
    source_system: str = Field(min_length=1, max_length=128)
    policy_version: str = Field(min_length=1, max_length=128)
    revoked_at: datetime | None = None

    @field_validator("approved_account_ids", "authority_scope")
    @classmethod
    def _scope_values_are_unique(cls, value: tuple[str, ...], info) -> tuple[str, ...]:
        return _bounded_unique(value, field_name=info.field_name)

    @field_validator("provenance")
    @classmethod
    def _provenance_is_authoritative(cls, value: str) -> str:
        authoritative = {
            "bank_api_gateway",
            "authenticated_mobile_backend",
            "verified_entra_claims",
            "verified_oidc_claims",
            "bank_identity_service",
            "trusted_session_broker",
        }
        if value not in authoritative:
            raise ValueError("subject context requires authoritative provenance")
        return value

    @model_validator(mode="after")
    def _time_and_tenant_bindings_are_valid(self) -> "SubjectExecutionContext":
        auth_time = _utc(self.auth_time)
        issued_at = _utc(self.issued_at)
        expires_at = _utc(self.expires_at)
        if auth_time > issued_at or issued_at >= expires_at:
            raise ValueError("subject context time binding is invalid")
        if self.revoked_at is not None and _utc(self.revoked_at) < auth_time:
            raise ValueError("subject context revocation precedes authentication")
        for scope in self.approved_resource_scopes:
            if not scope.resource_type or not scope.resource_reference:
                raise ValueError("subject resource scope is invalid")
            # JWT NumericDate expiry is second-granular, while an authoritative
            # resource scope may arrive as an ISO timestamp with microseconds.
            # Treat timestamps in the same UTC second as the same boundary, but
            # never permit a scope to extend into a later second.
            if int(_utc(scope.expires_at).timestamp()) > int(expires_at.timestamp()):
                raise ValueError("resource scope exceeds subject context lifetime")
        return self


class ExecutionIdentity(BaseModel):
    """Server-derived attribution quality for one execution identity."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: str
    identity_type: IdentityType
    principal_reference: str = Field(min_length=1, max_length=256, repr=False)
    authentication_mode: str = Field(min_length=1, max_length=64)
    source_system: str = Field(min_length=1, max_length=128)
    provenance: AuthoritativeProvenance
    identity_quality: IdentityQuality
    authoritative: bool
    shared_authority: bool


class ResourceAuthorizationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    authorized: bool
    reason_code: str
    matched_scope: AuthorizedResourceScope | None = None


class SubjectLivenessResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    active: bool
    reason_code: str


def validate_subject_liveness(
    context: SubjectExecutionContext,
    *,
    now: datetime | None = None,
) -> SubjectLivenessResult:
    evaluated_at = _utc(now or datetime.now(timezone.utc))
    if context.revoked_at is not None and _utc(context.revoked_at) <= evaluated_at:
        return SubjectLivenessResult(
            active=False,
            reason_code="SUBJECT_CONTEXT_REVOKED",
        )
    if _utc(context.expires_at) <= evaluated_at:
        return SubjectLivenessResult(
            active=False,
            reason_code="SUBJECT_CONTEXT_EXPIRED",
        )
    if _utc(context.issued_at) > evaluated_at:
        return SubjectLivenessResult(
            active=False,
            reason_code="SUBJECT_CONTEXT_NOT_YET_VALID",
        )
    return SubjectLivenessResult(active=True, reason_code="SUBJECT_CONTEXT_ACTIVE")


def authorize_scoped_resource(
    context: SubjectExecutionContext,
    *,
    resource_type: str,
    resource_reference: str,
    operation: str,
    now: datetime | None = None,
) -> ResourceAuthorizationResult:
    evaluated_at = _utc(now or datetime.now(timezone.utc))
    liveness = validate_subject_liveness(context, now=evaluated_at)
    if not liveness.active:
        return ResourceAuthorizationResult(
            authorized=False,
            reason_code=liveness.reason_code,
        )
    normalized_type = str(resource_type or "").strip()
    normalized_reference = str(resource_reference or "").strip()
    normalized_operation = str(operation or "").strip()
    matching_resource = [
        scope
        for scope in context.approved_resource_scopes
        if scope.resource_type == normalized_type
        and scope.resource_reference == normalized_reference
    ]
    if not matching_resource:
        return ResourceAuthorizationResult(
            authorized=False,
            reason_code="RESOURCE_OUTSIDE_SUBJECT_SCOPE",
        )
    live_scope = [
        scope for scope in matching_resource if _utc(scope.expires_at) > evaluated_at
    ]
    if not live_scope:
        return ResourceAuthorizationResult(
            authorized=False,
            reason_code="RESOURCE_SCOPE_EXPIRED",
        )
    matched = next(
        (
            scope
            for scope in live_scope
            if normalized_operation in scope.allowed_operations
        ),
        None,
    )
    if matched is None:
        return ResourceAuthorizationResult(
            authorized=False,
            reason_code="OPERATION_OUTSIDE_SUBJECT_SCOPE",
        )
    return ResourceAuthorizationResult(
        authorized=True,
        reason_code="RESOURCE_SCOPE_MATCHED",
        matched_scope=matched,
    )


def attenuate_authority(
    *,
    parent_authority: tuple[str, ...],
    requested_child_authority: tuple[str, ...],
) -> tuple[str, ...]:
    parent = set(_bounded_unique(parent_authority, field_name="parent_authority"))
    child = _bounded_unique(
        requested_child_authority,
        field_name="requested_child_authority",
    )
    if not set(child).issubset(parent):
        raise ValueError("AUTHORITY_EXPANSION")
    return tuple(sorted(child))


_IDENTITY_QUALITY: dict[str, tuple[IdentityQuality, bool, bool]] = {
    "end_user": ("verified_end_user", True, False),
    "mobile_customer": ("verified_end_user", True, False),
    "oauth_passthrough_user": ("verified_end_user", True, False),
    "published_agent": ("dedicated_agent_identity", True, False),
    "project_managed_identity": ("project_shared_identity", True, True),
    "service_principal": ("application_identity", True, False),
    "application_identity": ("application_identity", True, False),
    "shared_credential": ("shared_credential", False, True),
    "anonymous": ("anonymous", False, True),
    "unknown": ("unknown", False, True),
}


def resolve_execution_identity(
    *,
    tenant_id: str,
    identity_type: str,
    principal_reference: str,
    authentication_mode: str,
    source_system: str,
    provenance: AuthoritativeProvenance,
) -> ExecutionIdentity:
    normalized_type = str(identity_type or "").strip()
    if normalized_type not in _IDENTITY_QUALITY:
        normalized_type = "unknown"
    quality, authoritative, shared = _IDENTITY_QUALITY[normalized_type]
    return ExecutionIdentity(
        tenant_id=tenant_id,
        identity_type=normalized_type,
        principal_reference=principal_reference,
        authentication_mode=authentication_mode,
        source_system=source_system,
        provenance=provenance,
        identity_quality=quality,
        authoritative=authoritative,
        shared_authority=shared,
    )


__all__ = [
    "AuthorizedResourceScope",
    "ExecutionIdentity",
    "ResourceAuthorizationResult",
    "SubjectExecutionContext",
    "SubjectLivenessResult",
    "attenuate_authority",
    "authorize_scoped_resource",
    "resolve_execution_identity",
    "validate_subject_liveness",
]
