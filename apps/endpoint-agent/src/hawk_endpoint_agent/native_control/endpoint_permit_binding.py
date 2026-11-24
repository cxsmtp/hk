"""Verifier-gated Claude Code authority bound to the existing endpoint broker.

The endpoint cannot assert that a Decision Receipt or composed Control Plan
exists. A trusted composition-layer verifier must resolve those persisted,
signed server records before this module can issue an opaque broker permit.
No policy evaluation occurs here or during consumption.

This binding remains EXPERIMENTAL until a verified operating-system floor
consumes it on a real endpoint and proves non-execution for denied operations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable, Mapping, Protocol

from ..endpoint_floor.contracts import EndpointPrimitive
from ..endpoint_floor.permits import (
    EndpointExecutionPermitRequest,
    EndpointPermitBroker,
    EndpointPermitDecision,
    EndpointPermitIssueResult,
    EndpointPermitStep,
)


_CLAUDE_PROVIDER = "anthropic"
_CLAUDE_PRODUCT = "claude_code"
_CLAUDE_PRE_TOOL_EVENT = "PreToolUse"
_CLAUDE_SOURCE_CONTROL_POINT = "claude_code:pre_tool_use"
_MAXIMUM_NATIVE_PERMIT_LIFETIME = timedelta(seconds=30)
_UNKNOWN_EXACT_VALUES = {
    "unknown",
    "none",
    "null",
    "unavailable",
    "not_available",
    "not_applicable",
    "n/a",
}
_UNKNOWN_PRIMITIVES = {
    EndpointPrimitive.FILE_UNKNOWN,
    EndpointPrimitive.PROCESS_UNKNOWN,
    EndpointPrimitive.NETWORK_UNKNOWN,
    EndpointPrimitive.UNKNOWN_TRANSFER,
    EndpointPrimitive.UNKNOWN_LOCAL_SERVICE,
}


def _required(value: str, *, field: str, maximum: int = 256) -> str:
    normalized = str(value or "").replace("\x00", "").strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{field} is required")
    return normalized


def _exact_required(value: str, *, field: str, maximum: int = 256) -> str:
    normalized = _required(value, field=field, maximum=maximum)
    if normalized.casefold() in _UNKNOWN_EXACT_VALUES:
        raise ValueError(f"{field} must contain an exact value")
    return normalized


def _exact_rights(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) > 32:
        raise ValueError("requested_rights must contain exact bounded values")
    rights = tuple(
        sorted(
            {
                _exact_required(value, field="requested_right", maximum=128)
                for value in values
            }
        )
    )
    if not rights:
        raise ValueError("requested_rights must contain exact bounded values")
    return rights


def _normalize_consequence(
    *,
    primitive: EndpointPrimitive,
    requested_rights: tuple[str, ...],
    target_identity: str | None,
    destination_identity: str | None,
) -> tuple[tuple[str, ...], str | None, str | None]:
    if primitive in _UNKNOWN_PRIMITIVES:
        raise ValueError("primitive must contain an exact value")
    rights = _exact_rights(requested_rights)
    target = (
        _exact_required(target_identity, field="target_identity", maximum=1024)
        if target_identity is not None
        else None
    )
    destination = (
        _exact_required(destination_identity, field="destination_identity", maximum=1024)
        if destination_identity is not None
        else None
    )
    if (
        primitive.value.startswith("file_")
        or primitive.value.startswith("process_")
    ) and target is None:
        raise ValueError("target_identity is required for this exact primitive")
    if destination is None:
        raise ValueError("destination_identity is required for every exact consequence")
    return rights, target, destination


def _sha256(value: str, *, field: str) -> str:
    normalized = _required(value, field=field, maximum=64)
    if len(normalized) != 64 or any(character not in "0123456789abcdef" for character in normalized):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return normalized


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class NativeAuthorityClaim:
    """Untrusted lookup key; existence and integrity are resolved elsewhere."""

    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    primitive: EndpointPrimitive
    requested_rights: tuple[str, ...]
    target_identity: str | None
    destination_identity: str | None
    policy_version: str
    policy_epoch: int
    control_plan_id: str
    control_plan_digest: str
    decision_receipt_id: str
    decision_receipt_binding_hash: str

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "device_id",
            "process_instance_id",
            "action_id",
            "policy_version",
            "control_plan_id",
            "decision_receipt_id",
        ):
            object.__setattr__(self, field, _exact_required(getattr(self, field), field=field))
        for field in (
            "canonical_action_hash",
            "control_plan_digest",
            "decision_receipt_binding_hash",
        ):
            object.__setattr__(self, field, _sha256(getattr(self, field), field=field))
        if type(self.policy_epoch) is not int or self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")
        rights, target, destination = _normalize_consequence(
            primitive=self.primitive,
            requested_rights=self.requested_rights,
            target_identity=self.target_identity,
            destination_identity=self.destination_identity,
        )
        object.__setattr__(self, "requested_rights", rights)
        object.__setattr__(self, "target_identity", target)
        object.__setattr__(self, "destination_identity", destination)


@dataclass(frozen=True, slots=True)
class VerifiedNativeEndpointAuthority:
    """Projection of an existing verified Decision Receipt and exact plan.

    Only the injected trusted verifier should create this projection in live
    composition. It is not accepted directly by the local issuance API.
    """

    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    primitive: EndpointPrimitive
    requested_rights: tuple[str, ...]
    target_identity: str | None
    destination_identity: str | None
    control_plan_id: str
    control_plan_digest: str
    decision_receipt_id: str
    decision_receipt_binding_hash: str
    authority_reference: str
    purpose_reference: str
    policy_version: str
    policy_epoch: int
    decision_issued_at: datetime
    decision_expires_at: datetime
    verification_reference: str

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "device_id",
            "process_instance_id",
            "action_id",
            "control_plan_id",
            "decision_receipt_id",
            "authority_reference",
            "purpose_reference",
            "policy_version",
            "verification_reference",
        ):
            object.__setattr__(self, field, _exact_required(getattr(self, field), field=field))
        for field in (
            "canonical_action_hash",
            "control_plan_digest",
            "decision_receipt_binding_hash",
        ):
            object.__setattr__(self, field, _sha256(getattr(self, field), field=field))
        if type(self.policy_epoch) is not int or self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")
        rights, target, destination = _normalize_consequence(
            primitive=self.primitive,
            requested_rights=self.requested_rights,
            target_identity=self.target_identity,
            destination_identity=self.destination_identity,
        )
        object.__setattr__(self, "requested_rights", rights)
        object.__setattr__(self, "target_identity", target)
        object.__setattr__(self, "destination_identity", destination)
        issued = _aware_utc(self.decision_issued_at, field="decision_issued_at")
        expires = _aware_utc(self.decision_expires_at, field="decision_expires_at")
        if expires <= issued:
            raise ValueError("decision receipt expiry must follow issuance")
        object.__setattr__(self, "decision_issued_at", issued)
        object.__setattr__(self, "decision_expires_at", expires)

    @property
    def claim(self) -> NativeAuthorityClaim:
        return NativeAuthorityClaim(
            tenant_id=self.tenant_id,
            device_id=self.device_id,
            process_instance_id=self.process_instance_id,
            action_id=self.action_id,
            canonical_action_hash=self.canonical_action_hash,
            primitive=self.primitive,
            requested_rights=self.requested_rights,
            target_identity=self.target_identity,
            destination_identity=self.destination_identity,
            policy_version=self.policy_version,
            policy_epoch=self.policy_epoch,
            control_plan_id=self.control_plan_id,
            control_plan_digest=self.control_plan_digest,
            decision_receipt_id=self.decision_receipt_id,
            decision_receipt_binding_hash=self.decision_receipt_binding_hash,
        )


class NativeAuthorityVerifier(Protocol):
    """Trusted API/DB boundary resolving persisted signed Hawk authority."""

    def resolve(self, claim: NativeAuthorityClaim) -> VerifiedNativeEndpointAuthority | None:
        ...


def _wire_datetime(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ValueError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} is invalid") from exc
    return _aware_utc(parsed, field=field)


@dataclass(frozen=True, slots=True)
class CallableNativeAuthorityVerifier:
    """Fail-closed endpoint caller for the trusted API composition boundary.

    The transport is deliberately injected so production can use the existing
    authenticated endpoint channel without coupling this package to one HTTP
    client. The response is accepted only when it reconstructs the exact claim
    sent by the endpoint; malformed or rebound projections return no authority.
    """

    transport: Callable[[dict[str, object]], Mapping[str, object] | None]

    def resolve(self, claim: NativeAuthorityClaim) -> VerifiedNativeEndpointAuthority | None:
        payload: dict[str, object] = {
            "tenant_id": claim.tenant_id,
            "device_id": claim.device_id,
            "process_instance_id": claim.process_instance_id,
            "action_id": claim.action_id,
            "canonical_action_hash": claim.canonical_action_hash,
            "primitive": claim.primitive.value,
            "requested_rights": list(claim.requested_rights),
            "target_identity": claim.target_identity,
            "destination_identity": claim.destination_identity,
            "policy_version": claim.policy_version,
            "policy_epoch": claim.policy_epoch,
            "control_plan_id": claim.control_plan_id,
            "control_plan_digest": claim.control_plan_digest,
            "decision_receipt_id": claim.decision_receipt_id,
            "decision_receipt_binding_hash": claim.decision_receipt_binding_hash,
        }
        try:
            raw = self.transport(payload)
            if not isinstance(raw, Mapping):
                return None
            raw_rights = raw.get("requested_rights")
            if not isinstance(raw_rights, list) or not all(
                isinstance(value, str) for value in raw_rights
            ):
                return None
            authority = VerifiedNativeEndpointAuthority(
                tenant_id=str(raw.get("tenant_id") or ""),
                device_id=str(raw.get("device_id") or ""),
                process_instance_id=str(raw.get("process_instance_id") or ""),
                action_id=str(raw.get("action_id") or ""),
                canonical_action_hash=str(raw.get("canonical_action_hash") or ""),
                primitive=EndpointPrimitive(str(raw.get("primitive") or "")),
                requested_rights=tuple(raw_rights),
                target_identity=(
                    str(raw["target_identity"])
                    if raw.get("target_identity") is not None
                    else None
                ),
                destination_identity=(
                    str(raw["destination_identity"])
                    if raw.get("destination_identity") is not None
                    else None
                ),
                control_plan_id=str(raw.get("control_plan_id") or ""),
                control_plan_digest=str(raw.get("control_plan_digest") or ""),
                decision_receipt_id=str(raw.get("decision_receipt_id") or ""),
                decision_receipt_binding_hash=str(
                    raw.get("decision_receipt_binding_hash") or ""
                ),
                authority_reference=str(raw.get("authority_reference") or ""),
                purpose_reference=str(raw.get("purpose_reference") or ""),
                policy_version=str(raw.get("policy_version") or ""),
                policy_epoch=raw.get("policy_epoch"),  # type: ignore[arg-type]
                decision_issued_at=_wire_datetime(
                    raw.get("decision_issued_at"), field="decision_issued_at"
                ),
                decision_expires_at=_wire_datetime(
                    raw.get("decision_expires_at"), field="decision_expires_at"
                ),
                verification_reference=str(raw.get("verification_reference") or ""),
            )
        except (KeyError, TypeError, ValueError):
            return None
        return authority if authority.claim == claim else None


@dataclass(frozen=True, slots=True)
class NativeEndpointOperation:
    """OS-observed consequence material; it carries no policy or receipt claims."""

    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    primitive: EndpointPrimitive
    requested_rights: tuple[str, ...]
    target_identity: str | None
    destination_identity: str | None

    def __post_init__(self) -> None:
        for field in (
            "tenant_id",
            "device_id",
            "process_instance_id",
            "action_id",
        ):
            object.__setattr__(self, field, _exact_required(getattr(self, field), field=field))
        object.__setattr__(
            self,
            "canonical_action_hash",
            _sha256(self.canonical_action_hash, field="canonical_action_hash"),
        )
        rights, target, destination = _normalize_consequence(
            primitive=self.primitive,
            requested_rights=self.requested_rights,
            target_identity=self.target_identity,
            destination_identity=self.destination_identity,
        )
        object.__setattr__(self, "requested_rights", rights)
        object.__setattr__(self, "target_identity", target)
        object.__setattr__(self, "destination_identity", destination)


@dataclass(frozen=True, slots=True)
class ClaudeCodePreToolUsePermitBinding:
    """Untrusted native callback lookup material plus one exact OS consequence."""

    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    primitive: EndpointPrimitive
    requested_rights: tuple[str, ...]
    target_identity: str | None
    destination_identity: str | None
    control_plan_id: str
    control_plan_digest: str
    decision_receipt_id: str
    decision_receipt_binding_hash: str
    policy_version: str
    policy_epoch: int
    provider: str = _CLAUDE_PROVIDER
    product: str = _CLAUDE_PRODUCT
    provider_event: str = _CLAUDE_PRE_TOOL_EVENT

    def __post_init__(self) -> None:
        if (
            self.provider != _CLAUDE_PROVIDER
            or self.product != _CLAUDE_PRODUCT
            or self.provider_event != _CLAUDE_PRE_TOOL_EVENT
        ):
            raise ValueError("claude_code_pre_tool_use_required")
        for field in (
            "tenant_id",
            "device_id",
            "process_instance_id",
            "action_id",
            "policy_version",
            "control_plan_id",
            "decision_receipt_id",
        ):
            object.__setattr__(self, field, _exact_required(getattr(self, field), field=field))
        for field in (
            "canonical_action_hash",
            "control_plan_digest",
            "decision_receipt_binding_hash",
        ):
            object.__setattr__(self, field, _sha256(getattr(self, field), field=field))
        if type(self.policy_epoch) is not int or self.policy_epoch <= 0:
            raise ValueError("policy_epoch must be positive")
        rights, target, destination = _normalize_consequence(
            primitive=self.primitive,
            requested_rights=self.requested_rights,
            target_identity=self.target_identity,
            destination_identity=self.destination_identity,
        )
        object.__setattr__(self, "requested_rights", rights)
        object.__setattr__(self, "target_identity", target)
        object.__setattr__(self, "destination_identity", destination)

    @property
    def authority_claim(self) -> NativeAuthorityClaim:
        return NativeAuthorityClaim(
            tenant_id=self.tenant_id,
            device_id=self.device_id,
            process_instance_id=self.process_instance_id,
            action_id=self.action_id,
            canonical_action_hash=self.canonical_action_hash,
            primitive=self.primitive,
            requested_rights=self.requested_rights,
            target_identity=self.target_identity,
            destination_identity=self.destination_identity,
            policy_version=self.policy_version,
            policy_epoch=self.policy_epoch,
            control_plan_id=self.control_plan_id,
            control_plan_digest=self.control_plan_digest,
            decision_receipt_id=self.decision_receipt_id,
            decision_receipt_binding_hash=self.decision_receipt_binding_hash,
        )

    def issue_to(
        self,
        broker: EndpointPermitBroker,
        *,
        verifier: NativeAuthorityVerifier,
        now: datetime,
    ) -> EndpointPermitIssueResult:
        """Resolve server authority and issue one broker-owned opaque permit."""

        current = _aware_utc(now, field="now")
        authority = verifier.resolve(self.authority_claim)
        if authority is None:
            raise ValueError("verified_native_authority_required")
        if authority.claim != self.authority_claim:
            raise ValueError("verified_native_authority_mismatch")
        if not authority.decision_issued_at <= current < authority.decision_expires_at:
            raise ValueError("verified_native_authority_not_current")
        expires_at = min(
            authority.decision_expires_at,
            current + _MAXIMUM_NATIVE_PERMIT_LIFETIME,
        )
        issued = broker.issue(
            EndpointExecutionPermitRequest(
                tenant_id=self.tenant_id,
                device_id=self.device_id,
                process_instance_id=self.process_instance_id,
                action_id=self.action_id,
                canonical_action_hash=self.canonical_action_hash,
                steps=(
                    EndpointPermitStep(
                        step_id="claude_code_pre_tool_use_consequence",
                        primitive=self.primitive,
                        requested_rights=self.requested_rights,
                        stable_resource_identity=self.target_identity,
                        destination_identity=self.destination_identity,
                    ),
                ),
                authority_reference=authority.authority_reference,
                purpose_reference=authority.purpose_reference,
                policy_version=authority.policy_version,
                policy_epoch=authority.policy_epoch,
                issued_at=current,
                expires_at=expires_at,
                source_control_point=_CLAUDE_SOURCE_CONTROL_POINT,
                control_plan_id=authority.control_plan_id,
                control_plan_digest=authority.control_plan_digest,
                decision_receipt_id=authority.decision_receipt_id,
                decision_receipt_binding_hash=authority.decision_receipt_binding_hash,
            ),
            now=current,
        )
        evidence = dict(issued.evidence)
        evidence["authority_verification_reference"] = authority.verification_reference
        evidence["verification_status"] = "experimental"
        evidence["os_floor_consumption_verified"] = False
        return EndpointPermitIssueResult(
            accepted=issued.accepted,
            permit_id=issued.permit_id,
            permit_digest=issued.permit_digest,
            expires_at=issued.expires_at,
            evidence=evidence,
        )

    def consume_from(
        self,
        broker: EndpointPermitBroker,
        permit_id: str,
        operation: NativeEndpointOperation,
        *,
        now: datetime,
    ) -> EndpointPermitDecision:
        """Match and consume once; trusted plan/receipt material stays broker-owned."""

        decision = broker.consume_bound_operation(
            permit_id,
            tenant_id=operation.tenant_id,
            device_id=operation.device_id,
            process_instance_id=operation.process_instance_id,
            action_id=operation.action_id,
            canonical_action_hash=operation.canonical_action_hash,
            primitive=operation.primitive,
            requested_rights=operation.requested_rights,
            stable_resource_identity=operation.target_identity,
            destination_identity=operation.destination_identity,
            now=now,
        )
        evidence = dict(decision.evidence)
        evidence.update(
            {
                "native_to_endpoint_binding": _CLAUDE_SOURCE_CONTROL_POINT,
                "policy_re_evaluated": False,
                "verification_status": "experimental",
                "os_floor_consumption_verified": False,
            }
        )
        return EndpointPermitDecision(
            allowed=decision.allowed,
            reason=decision.reason,
            evidence=evidence,
        )
