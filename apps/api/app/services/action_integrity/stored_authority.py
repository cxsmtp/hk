"""Durable signed domain-profile authority for Phase 5 issuance paths."""

from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import (
    DomainSemanticProfileV2,
    DecisionReceiptV2Extension,
    TenantActionIntegrityRollout,
    TenantDomainProfileSelectionProjectionV2,
    TenantDomainProfileSelectionV2,
    TenantPolicyEpoch,
)
from app.db.models.evidence import DecisionReceipt
from app.db.models.native_control import NativeControlSelection
from app.services.native_control.selection_service import verify_control_plan_material

from .canonical_v2 import canonical_action_hash_v2, domain_hash
from .materiality import material_fields_hash
from .signing import SigningKeyProvider, active_key_id, sign_object, verify_signed_object


PROFILE_DOMAIN = "hawk:domain-semantic-profile:v1"
SELECTION_DOMAIN = "hawk:tenant-domain-profile-selection:v1"
PROFILE_SIGNING_PURPOSE = "domain_profile_signing"
SELECTION_SIGNING_PURPOSE = "domain_profile_selection_signing"
DECISION_DOMAIN = "hawk:decision-receipt-extension:v2"
DECISION_SIGNING_PURPOSE = "decision_receipt_signing"


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def approval_is_required(action: Mapping[str, Any]) -> bool:
    """Interpret approval policy with a single explicit no-approval value."""
    requirement = action.get("approval_requirement")
    if requirement == "not_required":
        return False
    if requirement in {"required", "approve"}:
        return True
    raise PermissionError("action approval requirement is missing or unsupported")


def _same_instant(left: datetime | None, right: object) -> bool:
    if not isinstance(left, datetime) or not isinstance(right, str):
        return False
    try:
        return _utc(left) == _utc(datetime.fromisoformat(right.replace("Z", "+00:00")))
    except ValueError:
        return False


def _profile_content_hash(*, tenant_id: str, profile_id: str, version: str, content: Mapping[str, Any]) -> str:
    return domain_hash(
        "hawk:domain-semantic-profile-content:v1",
        {"tenant_id": tenant_id, "profile_id": profile_id, "version": version, "content": dict(content)},
    )


def _selection_hash(value: Mapping[str, Any]) -> str:
    unsigned = {
        key: item
        for key, item in value.items()
        if key not in {"selection_hash", "algorithm", "signing_key_id", "signature"}
    }
    return domain_hash("hawk:tenant-domain-profile-selection-hash:v1", unsigned)


def _profile_envelope(
    *,
    tenant_id: str,
    profile_id: str,
    version: str,
    content_hash: str,
    status: str,
    content: Mapping[str, Any],
    issued_at: datetime,
    effective_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "authority_binding_version": 1,
        "tenant_id": tenant_id,
        "profile_id": profile_id,
        "version": version,
        "content_hash": content_hash,
        "status": status,
        "content": dict(content),
        "issued_at": issued_at.isoformat(),
        "effective_at": effective_at.isoformat(),
        "expires_at": expires_at.isoformat(),
    }


def _selection_envelope(
    *,
    tenant_id: str,
    selection_id: str,
    selection_generation: int,
    selection_sequence: int,
    profile: DomainSemanticProfileV2,
    prior_selection_id: str | None,
    prior_selection_hash: str | None,
    policy_epoch: int,
    issued_at: datetime,
    effective_at: datetime,
    expires_at: datetime,
    selected_by_principal_ref: str,
    reason_code: str,
) -> dict[str, Any]:
    value = {
        "schema_version": "1.0",
        "authority_binding_version": 1,
        "tenant_id": tenant_id,
        "selection_id": selection_id,
        "selection_generation": selection_generation,
        "selection_sequence": selection_sequence,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "profile_content_hash": profile.content_hash,
        "prior_selection_id": prior_selection_id,
        "prior_selection_hash": prior_selection_hash,
        "policy_epoch": policy_epoch,
        "issued_at": issued_at.isoformat(),
        "effective_at": effective_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "selected_by_principal_ref": selected_by_principal_ref,
        "reason_code": reason_code,
    }
    value["selection_hash"] = _selection_hash(value)
    return value


def issue_domain_semantic_profile_v1(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    profile_id: str,
    version: str,
    status: str,
    content: Mapping[str, Any],
    issued_at: datetime,
    effective_at: datetime,
    expires_at: datetime,
) -> DomainSemanticProfileV2:
    """Persist one immutable V1 profile and its complete signed envelope."""
    issued_at, effective_at, expires_at = map(_utc, (issued_at, effective_at, expires_at))
    if (
        not tenant_id
        or not profile_id
        or not version
        or not isinstance(content, Mapping)
        or status.lower() != "reviewed"
        or not (issued_at <= effective_at < expires_at)
    ):
        raise ValueError("invalid domain semantic profile authority")
    content_hash = _profile_content_hash(
        tenant_id=tenant_id,
        profile_id=profile_id,
        version=version,
        content=content,
    )
    existing = db.scalar(
        select(DomainSemanticProfileV2)
        .where(
            DomainSemanticProfileV2.tenant_id == tenant_id,
            DomainSemanticProfileV2.profile_id == profile_id,
            DomainSemanticProfileV2.version == version,
        )
        .with_for_update()
    )
    if existing is not None:
        if existing.content_hash != content_hash or not _profile_is_valid(existing, provider=provider):
            raise ValueError("domain semantic profile version is immutable")
        return existing
    key_id = active_key_id(provider, purpose=PROFILE_SIGNING_PURPOSE, tenant_id=tenant_id)
    envelope = sign_object(
        provider,
        purpose=PROFILE_SIGNING_PURPOSE,
        domain=PROFILE_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value=_profile_envelope(
            tenant_id=tenant_id,
            profile_id=profile_id,
            version=version,
            content_hash=content_hash,
            status=status,
            content=content,
            issued_at=issued_at,
            effective_at=effective_at,
            expires_at=expires_at,
        ),
    )
    profile = DomainSemanticProfileV2(
        tenant_id=tenant_id,
        profile_id=profile_id,
        version=version,
        content_hash=content_hash,
        status=status,
        content=dict(content),
        authority_binding_version=1,
        issued_at=issued_at,
        effective_at=effective_at,
        expires_at=expires_at,
        algorithm=str(envelope["algorithm"]),
        signing_key_id=str(envelope["signing_key_id"]),
        signature=str(envelope["signature"]),
        signed_envelope=envelope,
    )
    db.add(profile)
    return profile


def _profile_is_valid(
    profile: DomainSemanticProfileV2,
    *,
    provider: SigningKeyProvider,
    current_authority: bool = True,
) -> bool:
    envelope = dict(profile.signed_envelope or {})
    try:
        key_state = provider.metadata(
            purpose=PROFILE_SIGNING_PURPOSE,
            tenant_id=profile.tenant_id,
            key_id=profile.signing_key_id,
        ).get("state")
    except (KeyError, ValueError):
        return False
    return (
        profile.authority_binding_version == 1
        and profile.issued_at is not None
        and key_state != "revoked"
        and (not current_authority or key_state == "active")
        and verify_signed_object(
            provider,
            purpose=PROFILE_SIGNING_PURPOSE,
            domain=PROFILE_DOMAIN,
            tenant_id=profile.tenant_id,
            value=envelope,
            current_authority=current_authority,
        )
        and envelope.get("schema_version") == "1.0"
        and envelope.get("authority_binding_version") == 1
        and envelope.get("profile_id") == profile.profile_id
        and envelope.get("version") == profile.version
        and envelope.get("content_hash") == profile.content_hash
        and envelope.get("status") == profile.status
        and envelope.get("content") == profile.content
        and _same_instant(profile.issued_at, envelope.get("issued_at"))
        and _same_instant(profile.effective_at, envelope.get("effective_at"))
        and _same_instant(profile.expires_at, envelope.get("expires_at"))
        and envelope.get("algorithm") == profile.algorithm
        and envelope.get("signing_key_id") == profile.signing_key_id
        and envelope.get("signature") == profile.signature
    )


def _selection_is_valid(
    selection: TenantDomainProfileSelectionV2,
    *,
    provider: SigningKeyProvider,
    current_authority: bool = True,
) -> bool:
    envelope = dict(selection.signed_envelope or {})
    try:
        key_state = provider.metadata(
            purpose=SELECTION_SIGNING_PURPOSE,
            tenant_id=selection.tenant_id,
            key_id=selection.signing_key_id,
        ).get("state")
    except (KeyError, ValueError):
        return False
    return (
        selection.authority_binding_version == 1
        and selection.selection_hash is not None
        and selection.issued_at is not None
        and selection.effective_at is not None
        and selection.expires_at is not None
        and selection.selected_by_principal_ref is not None
        and selection.reason_code is not None
        and key_state != "revoked"
        and (not current_authority or key_state == "active")
        and verify_signed_object(
            provider,
            purpose=SELECTION_SIGNING_PURPOSE,
            domain=SELECTION_DOMAIN,
            tenant_id=selection.tenant_id,
            value=envelope,
            current_authority=current_authority,
        )
        and envelope.get("schema_version") == "1.0"
        and envelope.get("authority_binding_version") == 1
        and envelope.get("selection_id") == selection.selection_id
        and envelope.get("selection_hash") == selection.selection_hash == _selection_hash(envelope)
        and envelope.get("selection_generation") == selection.selection_generation
        and envelope.get("selection_sequence") == selection.selection_sequence
        and envelope.get("profile_id") == selection.profile_id
        and envelope.get("profile_version") == selection.profile_version
        and envelope.get("profile_content_hash") == selection.profile_content_hash
        and envelope.get("prior_selection_id") == selection.prior_selection_id
        and envelope.get("prior_selection_hash") == selection.prior_selection_hash
        and envelope.get("policy_epoch") == selection.policy_epoch
        and _same_instant(selection.issued_at, envelope.get("issued_at"))
        and _same_instant(selection.effective_at, envelope.get("effective_at"))
        and _same_instant(selection.expires_at, envelope.get("expires_at"))
        and envelope.get("selected_by_principal_ref") == selection.selected_by_principal_ref
        and envelope.get("reason_code") == selection.reason_code
        and envelope.get("algorithm") == selection.algorithm
        and envelope.get("signing_key_id") == selection.signing_key_id
        and envelope.get("signature") == selection.signature
    )


def _current_rollout_and_epoch(db: Session, *, tenant_id: str) -> tuple[TenantActionIntegrityRollout, TenantPolicyEpoch]:
    rollout = db.scalar(
        select(TenantActionIntegrityRollout)
        .where(TenantActionIntegrityRollout.tenant_id == tenant_id)
        .with_for_update()
    )
    epoch = db.scalar(
        select(TenantPolicyEpoch)
        .where(TenantPolicyEpoch.tenant_id == tenant_id)
        .with_for_update()
    )
    if rollout is None or epoch is None:
        raise PermissionError("tenant has no stored rollout/epoch authority")
    if (
        str(rollout.mode).upper() != "AUTHORITATIVE"
        or rollout.policy_epoch <= 0
        or rollout.policy_epoch != epoch.epoch
    ):
        raise PermissionError("tenant rollout/epoch authority is not current")
    return rollout, epoch


def append_profile_selection_v1(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    profile: DomainSemanticProfileV2,
    policy_epoch: int,
    selected_by_principal_ref: str,
    reason_code: str,
    issued_at: datetime,
    effective_at: datetime,
    expires_at: datetime,
) -> TenantDomainProfileSelectionV2:
    """Append a signed V1 selection and CAS the tenant's sole current head."""
    issued_at, effective_at, expires_at = map(_utc, (issued_at, effective_at, expires_at))
    if (
        profile.tenant_id != tenant_id
        or not _profile_is_valid(profile, provider=provider)
        or not selected_by_principal_ref
        or not reason_code
        or not (issued_at <= effective_at < expires_at <= _utc(profile.expires_at))
    ):
        raise ValueError("invalid domain profile selection authority")
    rollout, epoch = _current_rollout_and_epoch(db, tenant_id=tenant_id)
    if policy_epoch != rollout.policy_epoch or policy_epoch != epoch.epoch:
        raise PermissionError("profile selection policy epoch is not current")
    projection = db.scalar(
        select(TenantDomainProfileSelectionProjectionV2)
        .where(TenantDomainProfileSelectionProjectionV2.tenant_id == tenant_id)
        .with_for_update()
    )
    if projection is None:
        generation, sequence, prior_id, prior_hash, state_version = 1, 1, None, None, 1
    else:
        if projection.current_selection_generation != 1 or policy_epoch <= projection.policy_epoch:
            raise PermissionError("profile selection policy epoch must advance")
        generation = projection.current_selection_generation
        sequence = projection.current_selection_sequence + 1
        prior_id, prior_hash = projection.current_selection_id, projection.current_selection_hash
        state_version = projection.state_version + 1
    selection_id = str(uuid4())
    unsigned = _selection_envelope(
        tenant_id=tenant_id,
        selection_id=selection_id,
        selection_generation=generation,
        selection_sequence=sequence,
        profile=profile,
        prior_selection_id=prior_id,
        prior_selection_hash=prior_hash,
        policy_epoch=policy_epoch,
        issued_at=issued_at,
        effective_at=effective_at,
        expires_at=expires_at,
        selected_by_principal_ref=selected_by_principal_ref,
        reason_code=reason_code,
    )
    key_id = active_key_id(provider, purpose=SELECTION_SIGNING_PURPOSE, tenant_id=tenant_id)
    envelope = sign_object(
        provider,
        purpose=SELECTION_SIGNING_PURPOSE,
        domain=SELECTION_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value=unsigned,
    )
    selection = TenantDomainProfileSelectionV2(
        tenant_id=tenant_id,
        selection_id=selection_id,
        selection_hash=str(envelope["selection_hash"]),
        selection_generation=generation,
        selection_sequence=sequence,
        profile_id=profile.profile_id,
        profile_version=profile.version,
        profile_content_hash=profile.content_hash,
        prior_selection_id=prior_id,
        prior_selection_hash=prior_hash,
        policy_epoch=policy_epoch,
        authority_binding_version=1,
        issued_at=issued_at,
        effective_at=effective_at,
        expires_at=expires_at,
        selected_by_principal_ref=selected_by_principal_ref,
        reason_code=reason_code,
        algorithm=str(envelope["algorithm"]),
        signing_key_id=str(envelope["signing_key_id"]),
        signature=str(envelope["signature"]),
        signed_envelope=envelope,
    )
    db.add(selection)
    db.flush()
    if projection is None:
        db.add(
            TenantDomainProfileSelectionProjectionV2(
                tenant_id=tenant_id,
                current_selection_id=selection.selection_id,
                current_selection_hash=selection.selection_hash,
                current_selection_generation=selection.selection_generation,
                current_selection_sequence=selection.selection_sequence,
                profile_id=selection.profile_id,
                profile_version=selection.profile_version,
                profile_content_hash=selection.profile_content_hash,
                policy_epoch=selection.policy_epoch,
                state_version=state_version,
                updated_at=issued_at,
            )
        )
    else:
        projection.current_selection_id = selection.selection_id
        projection.current_selection_hash = selection.selection_hash
        projection.current_selection_generation = selection.selection_generation
        projection.current_selection_sequence = selection.selection_sequence
        projection.profile_id = selection.profile_id
        projection.profile_version = selection.profile_version
        projection.profile_content_hash = selection.profile_content_hash
        projection.policy_epoch = selection.policy_epoch
        projection.state_version = state_version
        projection.updated_at = issued_at
    return selection


def require_current_profile_selection_v1(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    now: datetime,
) -> TenantDomainProfileSelectionV2:
    """Lock and fold every signed selection before using the current profile."""
    now = _utc(now)
    rollout, epoch = _current_rollout_and_epoch(db, tenant_id=tenant_id)
    projection = db.scalar(
        select(TenantDomainProfileSelectionProjectionV2)
        .where(TenantDomainProfileSelectionProjectionV2.tenant_id == tenant_id)
        .with_for_update()
    )
    if (
        projection is None
        or projection.current_selection_generation != 1
        or projection.policy_epoch != rollout.policy_epoch
        or projection.policy_epoch != epoch.epoch
    ):
        raise PermissionError("tenant has no current profile selection projection")
    selections = list(
        db.scalars(
            select(TenantDomainProfileSelectionV2)
            .where(
                TenantDomainProfileSelectionV2.tenant_id == tenant_id,
                TenantDomainProfileSelectionV2.selection_generation == 1,
            )
            .order_by(TenantDomainProfileSelectionV2.selection_sequence.asc())
            .with_for_update()
        )
    )
    if not selections:
        raise PermissionError("profile selection history is missing")
    previous: TenantDomainProfileSelectionV2 | None = None
    for expected_sequence, selection in enumerate(selections, start=1):
        profile = db.scalar(
            select(DomainSemanticProfileV2)
            .where(
                DomainSemanticProfileV2.tenant_id == tenant_id,
                DomainSemanticProfileV2.profile_id == selection.profile_id,
                DomainSemanticProfileV2.version == selection.profile_version,
                DomainSemanticProfileV2.content_hash == selection.profile_content_hash,
            )
            .with_for_update()
        )
        if (
            profile is None
            or not _profile_is_valid(profile, provider=provider, current_authority=False)
            or not _selection_is_valid(selection, provider=provider, current_authority=False)
            or selection.selection_generation != 1
            or selection.selection_sequence != expected_sequence
            or selection.policy_epoch <= 0
            or (previous is None and (selection.prior_selection_id is not None or selection.prior_selection_hash is not None))
            or (
                previous is not None
                and (
                    selection.prior_selection_id != previous.selection_id
                    or selection.prior_selection_hash != previous.selection_hash
                    or selection.policy_epoch <= previous.policy_epoch
                )
            )
        ):
            raise PermissionError("profile selection history is invalid")
        previous = selection
    current = selections[-1]
    if (
        projection.current_selection_id != current.selection_id
        or projection.current_selection_hash != current.selection_hash
        or projection.current_selection_generation != current.selection_generation
        or projection.current_selection_sequence != current.selection_sequence
        or projection.profile_id != current.profile_id
        or projection.profile_version != current.profile_version
        or projection.profile_content_hash != current.profile_content_hash
        or projection.policy_epoch != current.policy_epoch
        or projection.state_version != current.selection_sequence
        or current.issued_at is None
        or current.effective_at is None
        or current.expires_at is None
            or not (
                _utc(current.issued_at)
                <= _utc(current.effective_at)
                <= now
                < _utc(current.expires_at)
            )
    ):
        raise PermissionError("profile selection projection does not match current authority")
    profile = db.scalar(
        select(DomainSemanticProfileV2)
        .where(
            DomainSemanticProfileV2.tenant_id == tenant_id,
            DomainSemanticProfileV2.profile_id == current.profile_id,
            DomainSemanticProfileV2.version == current.profile_version,
            DomainSemanticProfileV2.content_hash == current.profile_content_hash,
        )
        .with_for_update()
    )
    if (
        profile is None
        or not _selection_is_valid(current, provider=provider, current_authority=True)
        or not _profile_is_valid(profile, provider=provider, current_authority=True)
        or profile.issued_at is None
        or profile.status.lower() != "reviewed"
        or not (
            _utc(profile.issued_at)
            <= _utc(profile.effective_at)
            <= now
            < _utc(profile.expires_at)
        )
    ):
        raise PermissionError("current domain profile is not eligible")
    return current


@dataclass(frozen=True, slots=True)
class StoredActionAuthorityV1:
    """The locked, re-read records that an issuance/claim must bind exactly."""

    profile: DomainSemanticProfileV2
    selection: TenantDomainProfileSelectionV2
    native_selection: NativeControlSelection


def require_current_decision_authority_v1(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    decision_receipt_id: str,
    action: Mapping[str, Any],
    now: datetime,
) -> tuple[DecisionReceiptV2Extension, StoredActionAuthorityV1]:
    """Lock a V1 decision extension and re-read every bound authority record."""
    decision = db.scalar(
        select(DecisionReceiptV2Extension)
        .where(
            DecisionReceiptV2Extension.tenant_id == tenant_id,
            DecisionReceiptV2Extension.receipt_id == decision_receipt_id,
        )
        .with_for_update()
    )
    base_receipt = db.scalar(
        select(DecisionReceipt)
        .where(
            DecisionReceipt.tenant_id == tenant_id,
            DecisionReceipt.receipt_id == decision_receipt_id,
        )
        .with_for_update()
    )
    if (
        decision is None
        or base_receipt is None
        or decision.authority_binding_version != 1
        or not decision.profile_selection_id
        or not decision.profile_selection_hash
        or not decision.control_selection_id
        or not decision.control_plan_id
        or not decision.authoritative_decision
        or not decision.authority_status
        or decision.decision_version is None
        or decision.decision_version <= 0
    ):
        raise PermissionError("decision receipt has no complete V1 authority binding")
    approval_required = approval_is_required(action)
    expected_decision = "REQUIRE_APPROVAL" if approval_required else "ALLOW"
    if (
        str(decision.authoritative_decision).upper() != expected_decision
        or str(decision.authority_status).upper() != "CURRENT"
    ):
        raise PermissionError("decision receipt is not currently eligible to authorize execution")
    authority = require_current_action_authority_v1(
        db,
        provider=provider,
        tenant_id=tenant_id,
        action=action,
        profile_selection_id=decision.profile_selection_id,
        profile_selection_hash=decision.profile_selection_hash,
        control_selection_id=decision.control_selection_id,
        now=now,
    )
    envelope = dict(decision.signed_envelope or {})
    native = authority.native_selection
    if (
        not verify_signed_object(
            provider,
            purpose=DECISION_SIGNING_PURPOSE,
            domain=DECISION_DOMAIN,
            tenant_id=tenant_id,
            value=envelope,
            current_authority=True,
        )
        or now >= _utc(decision.expires_at)
        or decision.action_id != action.get("action_id")
        or base_receipt.action_id != decision.action_id
        or base_receipt.expires_at != decision.expires_at
        or decision.canonical_action_hash != canonical_action_hash_v2(action)
        or decision.material_fields_hash != material_fields_hash(action)
        or decision.policy_epoch != authority.selection.policy_epoch
        or decision.control_plan_digest != native.control_plan_digest
        or decision.control_plan_id != native.control_plan_id
        or envelope.get("authority_binding_version") != 1
        or envelope.get("receipt_id") != decision.receipt_id
        or envelope.get("tenant_id") != tenant_id
        or envelope.get("action_id") != decision.action_id
        or envelope.get("canonical_action") != dict(action)
        or envelope.get("phase5_canonical_action_hash_domain") != "hawk:canonical-ai-action:v2"
        or envelope.get("phase5_canonical_action_hash") != decision.canonical_action_hash
        or envelope.get("base_receipt_canonical_action_hash_domain") != "hawk:decision-receipt-canonical-action:v1"
        or envelope.get("base_receipt_canonical_action_hash") != base_receipt.canonical_action_hash
        or envelope.get("native_authorization_action_hash_domain") != "hawk:native-control-authorization-request:v1"
        or envelope.get("native_authorization_action_hash") != native.canonical_action_hash
        or envelope.get("canonical_action_hash") != decision.canonical_action_hash
        or envelope.get("material_fields_hash") != decision.material_fields_hash
        or envelope.get("profile_selection_id") != decision.profile_selection_id
        or envelope.get("profile_selection_hash") != decision.profile_selection_hash
        or envelope.get("control_selection_id") != decision.control_selection_id
        or envelope.get("control_plan_id") != decision.control_plan_id
        or envelope.get("control_plan_digest") != decision.control_plan_digest
        or envelope.get("native_action_id") != native.action_id
        or envelope.get("native_canonical_action_hash") != native.canonical_action_hash
        or envelope.get("native_plan_issued_at") != _utc(native.plan_issued_at).isoformat()
        or envelope.get("native_plan_expires_at") != _utc(native.plan_expires_at).isoformat()
        or envelope.get("authoritative_decision") != decision.authoritative_decision
        or envelope.get("authority_status") != decision.authority_status
        or envelope.get("decision_version") != decision.decision_version
        or envelope.get("algorithm") != decision.algorithm
        or envelope.get("signing_key_id") != decision.signing_key_id
        or envelope.get("signature") != decision.signature
    ):
        raise PermissionError("decision receipt does not match current stored authority")
    return decision, authority


def bind_generic_action_to_current_decision_authority_v1(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    decision_receipt_id: str | None,
    generic_action: Mapping[str, Any],
    now: datetime,
) -> tuple[str, dict[str, Any]]:
    """Return the exact signed action for a generic seam, after route binding.

    Generic seams own only their route material.  The profile/control fields
    and exact issuance timestamp must come from the signed stored decision,
    never request echoes or locally manufactured defaults.  The complete
    candidate is then re-verified against that decision before it is returned.
    """
    if decision_receipt_id:
        candidates = [
            db.scalar(
                select(DecisionReceiptV2Extension)
                .where(
                    DecisionReceiptV2Extension.tenant_id == tenant_id,
                    DecisionReceiptV2Extension.receipt_id == decision_receipt_id,
                )
                .with_for_update()
            )
        ]
    else:
        # No caller-provided receipt ID is trusted.  A generic production seam
        # may only transport the unique current signed decision already
        # persisted for its server-constructed action ID.
        candidates = list(
            db.scalars(
                select(DecisionReceiptV2Extension)
                .where(
                    DecisionReceiptV2Extension.tenant_id == tenant_id,
                    DecisionReceiptV2Extension.action_id == generic_action.get("action_id"),
                    DecisionReceiptV2Extension.authority_binding_version == 1,
                    DecisionReceiptV2Extension.authority_status == "CURRENT",
                )
                .with_for_update()
            ).all()
        )
    matches: list[tuple[str, dict[str, Any]]] = []
    for decision in candidates:
        if decision is None:
            continue
        envelope = dict(decision.signed_envelope or {})
        signed_action = envelope.get("canonical_action")
        if not isinstance(signed_action, Mapping):
            continue
        candidate = dict(generic_action)
        # These are the only generic-builder omissions. Every route-derived
        # semantic field remains from `generic_action`, so complete signature
        # verification proves the decision belongs to this exact seam call.
        for field in (
            "domain_profile_ref",
            "domain_profile_hash",
            "control_plan_id",
            "control_plan_digest",
            "created_at",
        ):
            candidate[field] = signed_action.get(field)
        try:
            require_current_decision_authority_v1(
                db,
                provider=provider,
                tenant_id=tenant_id,
                decision_receipt_id=decision.receipt_id,
                action=candidate,
                now=now,
            )
        except PermissionError:
            continue
        matches.append((decision.receipt_id, candidate))
    if len(matches) != 1:
        raise PermissionError("generic execution has no unique current stored decision")
    return matches[0]


def require_current_action_authority_v1(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    action: Mapping[str, Any],
    profile_selection_id: str,
    profile_selection_hash: str,
    control_selection_id: str,
    now: datetime,
) -> StoredActionAuthorityV1:
    """Re-read current profile and native-control records; never trust action echoes."""
    selection = require_current_profile_selection_v1(
        db,
        provider=provider,
        tenant_id=tenant_id,
        now=now,
    )
    profile = db.scalar(
        select(DomainSemanticProfileV2)
        .where(
            DomainSemanticProfileV2.tenant_id == tenant_id,
            DomainSemanticProfileV2.profile_id == selection.profile_id,
            DomainSemanticProfileV2.version == selection.profile_version,
            DomainSemanticProfileV2.content_hash == selection.profile_content_hash,
        )
        .with_for_update()
    )
    if profile is None:
        raise PermissionError("current domain profile is missing")
    if (
        action.get("tenant_id") != tenant_id
        or action.get("domain_profile_ref") != profile.profile_id
        or action.get("domain_profile_hash") != profile.content_hash
        or profile_selection_id != selection.selection_id
        or profile_selection_hash != selection.selection_hash
        or int(action.get("policy_epoch") or 0) != selection.policy_epoch
    ):
        raise PermissionError("action does not exactly bind the current profile selection")
    if not control_selection_id:
        raise PermissionError("action lacks a native control selection binding")
    native = db.scalar(
        select(NativeControlSelection)
        .where(
            NativeControlSelection.tenant_id == tenant_id,
            NativeControlSelection.selection_id == control_selection_id,
        )
        .with_for_update()
    )
    if native is None:
        raise PermissionError("native control selection is missing")
    now = _utc(now)
    if (
        native.action_id != action.get("action_id")
        or native.control_plan_id != action.get("control_plan_id")
        or native.control_plan_digest != action.get("control_plan_digest")
        or native.canonical_action_hash is None
        or native.control_plan_id is None
        or native.control_plan_digest is None
        or native.plan_issued_at is None
        or native.plan_expires_at is None
        or native.control_requirement_unsatisfied
        or now < _utc(native.plan_issued_at)
        or now >= _utc(native.plan_expires_at)
    ):
        raise PermissionError("native control selection does not match current action authority")
    try:
        verified_plan = verify_control_plan_material(
            native.control_plan_material,
            expected_digest=native.control_plan_digest,
            expected_plan_id=native.control_plan_id,
            expected_canonical_action_hash=native.canonical_action_hash,
            now=now,
        )
    except ValueError as exc:
        raise PermissionError("native control plan material is invalid") from exc
    if (
        _utc(native.plan_issued_at) != _utc(datetime.fromisoformat(str(verified_plan["issued_at"]).replace("Z", "+00:00")))
        or _utc(native.plan_expires_at) != _utc(datetime.fromisoformat(str(verified_plan["expires_at"]).replace("Z", "+00:00")))
    ):
        raise PermissionError("native control plan timestamps do not match signed material")
    # Phase 4 native selections intentionally retain the pre-decision native
    # authorization hash, which is not the Phase 5 final canonical-action
    # hash.  Their exact association is instead established by the signed V1
    # decision envelope (both hashes, native action ID, and plan identity are
    # checked by `require_current_decision_authority_v1`).
    return StoredActionAuthorityV1(profile=profile, selection=selection, native_selection=native)
