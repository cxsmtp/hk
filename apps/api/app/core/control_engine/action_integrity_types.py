"""Vertical-neutral, immutable value objects used by Phase 5 authority checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum


class ReferenceState(StrEnum):
    RESOLVED = "RESOLVED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class BoundedReference:
    state: ReferenceState
    value: str | None
    reason_code: str | None = None
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.state is ReferenceState.RESOLVED:
            if not self.value or self.reason_code is not None:
                raise ValueError("resolved references require a value and no reason")
        elif self.value is not None or not self.reason_code:
            raise ValueError("unknown references require a reason and no value")
        if any(not item or len(item) > 256 for item in self.evidence_refs):
            raise ValueError("evidence references must be bounded")


def require_aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class PrincipalContext:
    tenant_id: str
    principal_id: str
    principal_type: str
    authoritative_identity_ref: BoundedReference
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.principal_id or not self.principal_type:
            raise ValueError("principal fields are required")
        if require_aware_utc(self.expires_at, field="expires_at") <= require_aware_utc(self.issued_at, field="issued_at"):
            raise ValueError("principal expiry must follow issue time")


@dataclass(frozen=True, slots=True)
class RepresentedSubjectContext:
    tenant_id: str
    subject_id: str
    subject_type: str
    authoritative_source_ref: BoundedReference


@dataclass(frozen=True, slots=True)
class ResourceScope:
    tenant_id: str
    resource_id: str
    resource_type: str
    permitted_operations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorityContext:
    tenant_id: str
    authority_id: str
    action_classes: tuple[str, ...]
    delegation_permitted: bool
    delegation_depth_limit: int
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.delegation_depth_limit < 0:
            raise ValueError("delegation depth cannot be negative")
        if require_aware_utc(self.expires_at, field="expires_at") <= require_aware_utc(self.issued_at, field="issued_at"):
            raise ValueError("authority expiry must follow issue time")


@dataclass(frozen=True, slots=True)
class ValueOrQuantity:
    semantic_type: str
    value: str
    unit: str | None = None
    currency: str | None = None


@dataclass(frozen=True, slots=True)
class ActionSemantics:
    action_class: str
    operation: str
    object_type: str
    tool_or_service_ref: str
    tool_fingerprint: str
    side_effect: str
    persistence: str
    reversibility: str
