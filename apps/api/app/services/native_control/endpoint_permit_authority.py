"""Resolve one exact Claude native decision into endpoint-permit authority.

This module is a composition boundary, not a second policy engine. It verifies
the existing persisted signed Decision Receipt and the existing immutable
native Control Plan, then binds those records to endpoint consequence material
supplied by an already-authenticated endpoint channel.

The capability remains EXPERIMENTAL until a real OS floor consumes the permit
and proves the denied consequence did not execute.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from uuid import NAMESPACE_URL, uuid5

from app.db.models.evidence import DecisionReceipt, EvidenceNode
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlSelection,
)
from app.services.native_control.selection_service import verify_control_plan_material
from app.services.receipt_service import EXECUTABLE_DECISIONS, verify_decision_receipt


_UNKNOWN = frozenset(
    {"unknown", "none", "null", "unavailable", "not_available", "not_applicable", "n/a"}
)
_CLAUDE_ACTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "FILE_READ": ("file_read", ("read_data",)),
    "FILE_WRITE": ("file_write", ("write_data",)),
    "COMMAND_EXECUTION": ("process_execute", ("execute",)),
}
_ENDPOINT_CAPABILITY_BY_PRIMITIVE = {
    "file_read": "file_read_control",
    "file_write": "file_write_control",
    "process_execute": "process_exec_control",
}
_MINIMUM_EXACT_ENDPOINT_ASSURANCE = 5
_AUTHORITY_BINDING_SIGNAL = "native_endpoint_permit_authority_bound"
_CAPABILITY_LEVEL_RANK = {
    "unknown": 0,
    "unavailable": 1,
    "observe": 2,
    "external": 3,
    "inline": 4,
    "inline_bound": 5,
}

# No authenticated endpoint route is registered yet. Keep this explicit so an
# internal resolver is not mistaken for a remotely callable production path.
PRODUCTION_NATIVE_ENDPOINT_PERMIT_ROUTE_AVAILABLE = False


def _exact(value: object, *, field: str, maximum: int = 1024) -> str:
    text = str(value or "").replace("\x00", "").strip()
    if not text or len(text) > maximum or text.casefold() in _UNKNOWN:
        raise ValueError(f"{field} must contain an exact value")
    return text


def _sha256(value: object, *, field: str) -> str:
    text = _exact(value, field=field, maximum=64)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return text


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _rights(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) > 32:
        raise ValueError("requested_rights must be a bounded tuple")
    return tuple(sorted({_exact(value, field="requested_right", maximum=128) for value in values}))


@dataclass(frozen=True, slots=True)
class TrustedEndpointConsequence:
    """Endpoint identity/consequence established by authenticated composition.

    This value must be built only after validating the endpoint credential,
    device identity and callback binding. It is intentionally separate from the
    client request so a client cannot select another device or process.
    """

    tenant_id: str
    device_id: str
    process_instance_id: str
    primitive: str
    requested_rights: tuple[str, ...]
    target_identity: str | None
    destination_identity: str | None

    def __post_init__(self) -> None:
        for field in ("tenant_id", "device_id", "process_instance_id", "primitive"):
            object.__setattr__(self, field, _exact(getattr(self, field), field=field))
        object.__setattr__(self, "requested_rights", _rights(self.requested_rights))
        if self.target_identity is not None:
            object.__setattr__(
                self, "target_identity", _exact(self.target_identity, field="target_identity")
            )
        if self.destination_identity is not None:
            object.__setattr__(
                self,
                "destination_identity",
                _exact(self.destination_identity, field="destination_identity"),
            )
        if self.destination_identity is None:
            raise ValueError("destination_identity is required for every exact consequence")


@dataclass(frozen=True, slots=True)
class NativeEndpointAuthorityRequest:
    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    primitive: str
    requested_rights: tuple[str, ...]
    target_identity: str | None
    destination_identity: str | None
    policy_version: str
    policy_epoch: int
    control_plan_id: str
    control_plan_digest: str
    decision_receipt_id: str
    decision_receipt_binding_hash: str


@dataclass(frozen=True, slots=True)
class VerifiedNativeEndpointAuthorityProjection:
    tenant_id: str
    device_id: str
    process_instance_id: str
    action_id: str
    canonical_action_hash: str
    primitive: str
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

    def as_wire(self) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "process_instance_id": self.process_instance_id,
            "action_id": self.action_id,
            "canonical_action_hash": self.canonical_action_hash,
            "primitive": self.primitive,
            "requested_rights": list(self.requested_rights),
            "target_identity": self.target_identity,
            "destination_identity": self.destination_identity,
            "control_plan_id": self.control_plan_id,
            "control_plan_digest": self.control_plan_digest,
            "decision_receipt_id": self.decision_receipt_id,
            "decision_receipt_binding_hash": self.decision_receipt_binding_hash,
            "authority_reference": self.authority_reference,
            "purpose_reference": self.purpose_reference,
            "policy_version": self.policy_version,
            "policy_epoch": self.policy_epoch,
            "decision_issued_at": self.decision_issued_at.isoformat(),
            "decision_expires_at": self.decision_expires_at.isoformat(),
            "verification_reference": self.verification_reference,
        }


def native_endpoint_receipt_binding_hash(
    *,
    trusted: TrustedEndpointConsequence,
    action_id: str,
    canonical_action_hash: str,
    policy_version: str,
    policy_epoch: int,
    control_plan_id: str,
    control_plan_digest: str,
    decision_receipt_id: str,
    decision_receipt_signature: str,
) -> str:
    if type(policy_epoch) is not int or policy_epoch <= 0:
        raise ValueError("policy_epoch must be a positive persisted plan epoch")
    material = {
        "tenant_id": trusted.tenant_id,
        "device_id": trusted.device_id,
        "process_instance_id": trusted.process_instance_id,
        "action_id": _exact(action_id, field="action_id"),
        "canonical_action_hash": _sha256(
            canonical_action_hash, field="canonical_action_hash"
        ),
        "primitive": trusted.primitive,
        "requested_rights": list(trusted.requested_rights),
        "target_identity": trusted.target_identity,
        "destination_identity": trusted.destination_identity,
        "policy_version": _exact(policy_version, field="policy_version"),
        "policy_epoch": policy_epoch,
        "control_plan_id": _exact(control_plan_id, field="control_plan_id"),
        "control_plan_digest": _sha256(control_plan_digest, field="control_plan_digest"),
        "decision_receipt_id": _exact(decision_receipt_id, field="decision_receipt_id"),
        "decision_receipt_signature": _sha256(
            decision_receipt_signature, field="decision_receipt_signature"
        ),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _canonical_payload(
    db: Session, *, receipt: DecisionReceipt, tenant_id: str
) -> Mapping[str, object] | None:
    node = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == receipt.canonical_action_evidence_node_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    payload = dict(node.payload or {}) if node is not None else {}
    canonical = payload.get("canonical_action")
    return canonical if isinstance(canonical, Mapping) else None


def _exact_request_matches_trusted(
    request: NativeEndpointAuthorityRequest, trusted: TrustedEndpointConsequence
) -> bool:
    try:
        return (
            _exact(request.tenant_id, field="tenant_id") == trusted.tenant_id
            and _exact(request.device_id, field="device_id") == trusted.device_id
            and _exact(request.process_instance_id, field="process_instance_id")
            == trusted.process_instance_id
            and _exact(request.primitive, field="primitive") == trusted.primitive
            and _rights(request.requested_rights) == trusted.requested_rights
            and request.target_identity == trusted.target_identity
            and request.destination_identity == trusted.destination_identity
            and type(request.policy_epoch) is int
            and request.policy_epoch > 0
        )
    except (TypeError, ValueError):
        return False


def _positive_epoch(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


def _signed_native_plan(canonical: Mapping[str, object]) -> Mapping[str, object] | None:
    policy = canonical.get("policy")
    if not isinstance(policy, Mapping):
        return None
    plan = policy.get("native_control_plan")
    return plan if isinstance(plan, Mapping) else None


def _has_valid_endpoint_floor_composition(
    *,
    selection: NativeControlSelection,
    semantic_integration: NativeControlIntegration,
    floor_integrations: Mapping[
        str, tuple[NativeControlIntegration, ControlCapabilityProfileRecord]
    ],
    verified_plan: Mapping[str, object],
    primitive: str,
    now: datetime,
) -> bool:
    required_capability = _ENDPOINT_CAPABILITY_BY_PRIMITIVE.get(primitive)
    if required_capability is None:
        return False
    minimum_assurance = verified_plan.get("minimum_assurance")
    if (
        type(minimum_assurance) is not int
        or minimum_assurance < _MINIMUM_EXACT_ENDPOINT_ASSURANCE
        or selection.assurance_level != minimum_assurance
    ):
        return False
    semantic_primary = verified_plan.get("semantic_primary_control_point_id")
    if (
        not isinstance(semantic_primary, str)
        or not semantic_primary
        or semantic_primary != selection.semantic_primary_control_point_id
        or semantic_primary != selection.primary_control_point_id
        or semantic_integration.id != semantic_primary
        or semantic_integration.tenant_id != selection.tenant_id
        or str(semantic_integration.provider or "").casefold() != "anthropic"
        or str(semantic_integration.product or "").casefold() != "claude_code"
        or str(semantic_integration.integration_method or "").casefold() != "native_hook"
        or str(semantic_integration.execution_location or "").upper() != "LOCAL_ENDPOINT"
        or str(semantic_integration.environment or "").casefold() != "production"
        or str(semantic_integration.state or "").casefold() not in {"monitoring", "enforcing"}
        or str(semantic_integration.health_state or "").casefold() != "healthy"
    ):
        return False
    runtime = verified_plan.get("provider_runtime_context")
    if not isinstance(runtime, Mapping) or (
        str(runtime.get("provider") or "").casefold() != "anthropic"
        or str(runtime.get("product") or "").casefold() != "claude_code"
        or str(runtime.get("control_method") or "").casefold() != "native_hook"
        or str(runtime.get("lifecycle_stage") or "").casefold() != "before_tool"
    ):
        return False
    requirements = verified_plan.get("mandatory_enforcement_floor_requirements")
    selected = verified_plan.get("mandatory_enforcement_floors")
    satisfied = verified_plan.get("satisfied_capabilities")
    if (
        not isinstance(requirements, list)
        or not requirements
        or not isinstance(selected, list)
        or not selected
        or not isinstance(satisfied, list)
        or required_capability not in satisfied
        or requirements != list(selection.mandatory_enforcement_floor_requirements or [])
        or selected != list(selection.selected_mandatory_floors or [])
        or satisfied != list(selection.satisfied_capabilities or [])
    ):
        return False
    selected_by_floor = {
        str(item.get("floor_id")): str(item.get("control_point_id"))
        for item in selected
        if isinstance(item, Mapping)
        and item.get("floor_id")
        and item.get("control_point_id")
    }
    for requirement in requirements:
        if not isinstance(requirement, Mapping):
            continue
        methods = requirement.get("allowed_methods")
        floor_id = str(requirement.get("floor_id") or "")
        control_point_id = selected_by_floor.get(floor_id)
        floor_record = floor_integrations.get(str(control_point_id or ""))
        if floor_record is None:
            continue
        floor_integration, floor_profile = floor_record
        minimum_level = str(requirement.get("minimum_level") or "")
        profile_claim = dict(floor_profile.capabilities or {}).get(required_capability)
        runtime_claim = dict(floor_integration.capability_snapshot or {}).get(
            required_capability
        )
        if not isinstance(profile_claim, Mapping) or not isinstance(runtime_claim, Mapping):
            continue
        minimum_rank = _CAPABILITY_LEVEL_RANK.get(minimum_level, -1)
        if (
            floor_integration.tenant_id != selection.tenant_id
            or floor_integration.id != control_point_id
            or floor_integration.capability_profile_id != floor_profile.id
            or str(floor_integration.provider or "").casefold()
            != str(floor_profile.provider or "").casefold()
            or str(floor_integration.product or "").casefold()
            != str(floor_profile.product or "").casefold()
            or str(floor_integration.integration_method or "").casefold()
            != "endpoint_runtime"
            or str(floor_profile.integration_method or "").casefold()
            != "endpoint_runtime"
            or str(floor_integration.execution_location or "").upper()
            != "LOCAL_ENDPOINT"
            or str(floor_integration.environment or "").casefold() != "production"
            or str(floor_integration.state or "").casefold()
            not in {"monitoring", "enforcing"}
            or str(floor_integration.health_state or "").casefold() != "healthy"
            or str(floor_integration.policy_version or "") != selection.policy_version
            or floor_integration.policy_fresh_until is None
            or _utc(floor_integration.policy_fresh_until) <= now
            or floor_integration.last_validated_at is None
            or str(floor_integration.degradation_mode or "").casefold() != "fail_closed"
            or not floor_profile.active
            or str(floor_profile.verification_status or "").casefold() != "verified"
            or floor_profile.verified_at is None
            or not bool(dict(floor_profile.security_properties or {}).get("pre_execution_capable"))
            or minimum_rank < 0
            or _CAPABILITY_LEVEL_RANK.get(str(profile_claim.get("level") or ""), -1)
            < minimum_rank
            or _CAPABILITY_LEVEL_RANK.get(str(runtime_claim.get("level") or ""), -1)
            < minimum_rank
            or str(profile_claim.get("verification_status") or "").casefold()
            != "verified"
            or str(runtime_claim.get("verification_status") or "").casefold()
            != "verified"
        ):
            continue
        if (
            requirement.get("capability") == required_capability
            and requirement.get("minimum_level") in {"inline", "inline_bound"}
            and isinstance(methods, list)
            and "endpoint_runtime" in methods
            and floor_id in selected_by_floor
        ):
            return True
    return False


def _binding_record_material(
    *,
    request: NativeEndpointAuthorityRequest,
    binding_hash: str,
) -> dict[str, object]:
    return {
        "schema_version": "native-endpoint-permit-authority/1.0",
        "tenant_id": request.tenant_id,
        "device_id": request.device_id,
        "process_instance_id": request.process_instance_id,
        "action_id": request.action_id,
        "canonical_action_hash": request.canonical_action_hash,
        "primitive": request.primitive,
        "requested_rights": list(request.requested_rights),
        "target_identity": request.target_identity,
        "destination_identity": request.destination_identity,
        "policy_version": request.policy_version,
        "policy_epoch": request.policy_epoch,
        "control_plan_id": request.control_plan_id,
        "control_plan_digest": request.control_plan_digest,
        "decision_receipt_id": request.decision_receipt_id,
        "decision_receipt_binding_hash": binding_hash,
    }


def _persist_idempotent_authority_binding(
    db: Session,
    *,
    request: NativeEndpointAuthorityRequest,
    binding_hash: str,
) -> bool:
    # One immutable plan/action may authorize only one endpoint consequence,
    # even if a provider callback produces multiple otherwise-valid receipts.
    record_id = str(
        uuid5(
            NAMESPACE_URL,
            "hawk:native-endpoint-permit-authority:"
            f"{request.tenant_id}:{request.action_id}:"
            f"{request.control_plan_id}:{request.control_plan_digest}",
        )
    )
    expected = _binding_record_material(request=request, binding_hash=binding_hash)
    existing = db.get(EvidenceNode, record_id)
    if existing is not None:
        return (
            existing.tenant_id == request.tenant_id
            and existing.signal_type == _AUTHORITY_BINDING_SIGNAL
            and dict(existing.payload or {}) == expected
        )
    try:
        with db.begin_nested():
            db.add(
                EvidenceNode(
                    id=record_id,
                    tenant_id=request.tenant_id,
                    correlation_id=request.action_id[:64],
                    node_type="native_endpoint_permit_authority_binding",
                    signal_type=_AUTHORITY_BINDING_SIGNAL,
                    label="Native decision bound to one endpoint consequence",
                    payload=expected,
                )
            )
            db.flush()
    except IntegrityError:
        existing = db.get(EvidenceNode, record_id)
        return existing is not None and dict(existing.payload or {}) == expected
    return True


def resolve_native_endpoint_permit_authority(
    db: Session,
    *,
    request: NativeEndpointAuthorityRequest,
    trusted: TrustedEndpointConsequence,
    settings_obj: Any,
    now: datetime,
) -> VerifiedNativeEndpointAuthorityProjection | None:
    """Verify existing authority and bind it to one trusted endpoint consequence."""

    current = _utc(now)
    if not _exact_request_matches_trusted(request, trusted):
        return None
    try:
        action_id = _exact(request.action_id, field="action_id")
        canonical_action_hash = _sha256(
            request.canonical_action_hash, field="canonical_action_hash"
        )
        policy_version = _exact(request.policy_version, field="policy_version")
        plan_id = _exact(request.control_plan_id, field="control_plan_id")
        plan_digest = _sha256(request.control_plan_digest, field="control_plan_digest")
        receipt_id = _exact(request.decision_receipt_id, field="decision_receipt_id")
        claimed_binding_hash = _sha256(
            request.decision_receipt_binding_hash,
            field="decision_receipt_binding_hash",
        )
    except (TypeError, ValueError):
        return None

    receipt = db.scalar(
        select(DecisionReceipt).where(
            DecisionReceipt.tenant_id == trusted.tenant_id,
            DecisionReceipt.receipt_id == receipt_id,
            DecisionReceipt.action_id == action_id,
            DecisionReceipt.canonical_action_hash == canonical_action_hash,
        )
    )
    if (
        receipt is None
        or receipt.decision not in EXECUTABLE_DECISIONS
        or receipt.policy_snapshot_id != policy_version
        or not verify_decision_receipt(
            receipt,
            tenant_id=trusted.tenant_id,
            settings_obj=settings_obj,
            now=current,
            db=db,
        )
    ):
        return None

    canonical = _canonical_payload(db, receipt=receipt, tenant_id=trusted.tenant_id)
    if canonical is None:
        return None
    signed_plan = _signed_native_plan(canonical)
    if signed_plan is None:
        return None

    selection = db.scalar(
        select(NativeControlSelection).where(
            NativeControlSelection.tenant_id == trusted.tenant_id,
            NativeControlSelection.action_id == action_id,
            NativeControlSelection.control_plan_id == plan_id,
            NativeControlSelection.control_plan_digest == plan_digest,
            NativeControlSelection.policy_version == policy_version,
        )
    )
    if (
        selection is None
        or selection.control_requirement_unsatisfied
        or bool(selection.unsatisfied_mandatory_floors)
    ):
        return None
    semantic_integration = db.scalar(
        select(NativeControlIntegration).where(
            NativeControlIntegration.tenant_id == trusted.tenant_id,
            NativeControlIntegration.id == selection.primary_control_point_id,
        )
    )
    if semantic_integration is None:
        return None
    selected_floor_ids = {
        str(item.get("control_point_id") or "")
        for item in list(selection.selected_mandatory_floors or [])
        if isinstance(item, Mapping) and item.get("control_point_id")
    }
    floor_integrations: dict[
        str, tuple[NativeControlIntegration, ControlCapabilityProfileRecord]
    ] = {}
    if selected_floor_ids:
        rows = db.scalars(
            select(NativeControlIntegration).where(
                NativeControlIntegration.tenant_id == trusted.tenant_id,
                NativeControlIntegration.id.in_(selected_floor_ids),
            )
        ).all()
        for integration in rows:
            if integration.capability_profile_id is None:
                continue
            profile = db.get(
                ControlCapabilityProfileRecord,
                integration.capability_profile_id,
            )
            if profile is not None:
                floor_integrations[integration.id] = (integration, profile)
    try:
        verified_plan = verify_control_plan_material(
            selection.control_plan_material,
            expected_digest=plan_digest,
            expected_plan_id=plan_id,
            expected_canonical_action_hash=selection.canonical_action_hash,
            now=current,
        )
    except ValueError:
        return None
    if (
        _utc(selection.plan_issued_at)
        != _utc(datetime.fromisoformat(str(verified_plan["issued_at"]).replace("Z", "+00:00")))
        or _utc(selection.plan_expires_at)
        != _utc(datetime.fromisoformat(str(verified_plan["expires_at"]).replace("Z", "+00:00")))
    ):
        return None
    persisted_epoch = _positive_epoch(verified_plan.get("policy_epoch"))
    signed_epoch = _positive_epoch(signed_plan.get("policy_epoch"))
    if (
        persisted_epoch is None
        or signed_epoch != persisted_epoch
        or request.policy_epoch != persisted_epoch
    ):
        return None
    signed_plan_fields = (
        "plan_id",
        "canonical_action_hash",
        "policy_version",
        "policy_epoch",
        "semantic_primary_control_point_id",
        "provider_runtime_context",
        "mandatory_enforcement_floor_requirements",
        "mandatory_enforcement_floors",
        "satisfied_capabilities",
        "minimum_assurance",
        "failure_behavior",
    )
    # The V1 receipt projection signs the stable semantic plan fields above.
    # Retry-time plan timestamps and the digest that covers their full V2
    # envelope are verified against the immutable persisted selection and are
    # then bound into the endpoint request below.  Requiring the digest to also
    # be present in the stable V1 projection would reject every valid receipt
    # produced by the retry-safe projection.
    if any(signed_plan.get(field) != verified_plan.get(field) for field in signed_plan_fields):
        return None
    surface = canonical.get("surface")
    action = canonical.get("action")
    if not isinstance(surface, Mapping) or not isinstance(action, Mapping):
        return None
    if (
        str(surface.get("provider") or "").casefold() != "anthropic"
        or str(surface.get("product") or "").casefold() != "claude_code"
        or str(surface.get("provider_event") or "") != "PreToolUse"
    ):
        return None
    expected = _CLAUDE_ACTIONS.get(str(action.get("action_type") or "").upper())
    if expected is None:
        return None
    expected_primitive, expected_rights = expected
    if (
        trusted.primitive != expected_primitive
        or trusted.requested_rights != expected_rights
        or trusted.target_identity != receipt.target_resource_hash
        or trusted.destination_identity != receipt.destination_hash
    ):
        return None
    if not _has_valid_endpoint_floor_composition(
        selection=selection,
        semantic_integration=semantic_integration,
        floor_integrations=floor_integrations,
        verified_plan=verified_plan,
        primitive=expected_primitive,
        now=current,
    ):
        return None

    binding_hash = native_endpoint_receipt_binding_hash(
        trusted=trusted,
        action_id=action_id,
        canonical_action_hash=canonical_action_hash,
        policy_version=policy_version,
        policy_epoch=persisted_epoch,
        control_plan_id=plan_id,
        control_plan_digest=plan_digest,
        decision_receipt_id=receipt_id,
        decision_receipt_signature=receipt.signature,
    )
    if binding_hash != claimed_binding_hash:
        return None
    if not _persist_idempotent_authority_binding(
        db,
        request=request,
        binding_hash=binding_hash,
    ):
        return None

    return VerifiedNativeEndpointAuthorityProjection(
        tenant_id=trusted.tenant_id,
        device_id=trusted.device_id,
        process_instance_id=trusted.process_instance_id,
        action_id=action_id,
        canonical_action_hash=canonical_action_hash,
        primitive=trusted.primitive,
        requested_rights=trusted.requested_rights,
        target_identity=trusted.target_identity,
        destination_identity=trusted.destination_identity,
        control_plan_id=plan_id,
        control_plan_digest=plan_digest,
        decision_receipt_id=receipt_id,
        decision_receipt_binding_hash=binding_hash,
        authority_reference=f"authority-sha256:{receipt.authority_hash}",
        purpose_reference=f"purpose-sha256:{receipt.purpose_hash}",
        policy_version=policy_version,
        policy_epoch=persisted_epoch,
        decision_issued_at=_utc(receipt.issued_at),
        decision_expires_at=_utc(receipt.expires_at),
        verification_reference=f"verified-decision-receipt:{receipt.receipt_id}",
    )


__all__ = [
    "NativeEndpointAuthorityRequest",
    "PRODUCTION_NATIVE_ENDPOINT_PERMIT_ROUTE_AVAILABLE",
    "TrustedEndpointConsequence",
    "VerifiedNativeEndpointAuthorityProjection",
    "native_endpoint_receipt_binding_hash",
    "resolve_native_endpoint_permit_authority",
]
