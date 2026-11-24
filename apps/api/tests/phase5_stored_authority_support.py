"""Reusable durable V1 authority setup for Phase 5 permit tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
from typing import Any, Mapping

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db.models.action_integrity import (
    DecisionReceiptV2Extension,
    DomainSemanticProfileV2,
    TenantDomainProfileSelectionProjectionV2,
    TenantDomainProfileSelectionV2,
)
from app.db.models.evidence import DecisionReceipt, EvidenceNode
from app.db.models.native_control import NativeControlSelection
from app.services.action_integrity.canonical_v2 import canonical_action_hash_v2
from app.services.action_integrity.materiality import material_fields_hash
from app.services.action_integrity.signing import LocalSigningKeyProvider, active_key_id, sign_object
from app.services.action_integrity.stored_authority import (
    DECISION_DOMAIN,
    append_profile_selection_v1,
    issue_domain_semantic_profile_v1,
)


@dataclass(frozen=True, slots=True)
class StoredAuthorityFixture:
    action: dict[str, Any]
    decision_receipt_id: str
    profile_selection_id: str
    profile_selection_hash: str
    control_selection_id: str


def add_stored_authority_keys(provider: LocalSigningKeyProvider, *, tenant_id: str) -> None:
    for purpose, key_id, secret in (
        ("domain_profile_signing", "profile", b"p" * 32),
        ("domain_profile_selection_signing", "selection", b"s" * 32),
        ("decision_receipt_signing", "decision", b"d" * 32),
        ("execution_permit_signing", "permit", b"e" * 32),
    ):
        provider.add_key(purpose=purpose, tenant_id=tenant_id, key_id=key_id, secret=secret)


def seed_stored_allow_authority(
    db: Session,
    *,
    provider: LocalSigningKeyProvider,
    tenant_id: str,
    action: Mapping[str, Any],
    now: datetime,
    decision_receipt_id: str = "decision-stored-1",
    authoritative_decision: str = "ALLOW",
    authority_status: str = "CURRENT",
) -> StoredAuthorityFixture:
    """Create profile→selection→native row→signed V1 decision around one action."""
    profile = db.scalar(
        select(DomainSemanticProfileV2).where(
            DomainSemanticProfileV2.tenant_id == tenant_id,
            DomainSemanticProfileV2.profile_id == "profile:stored",
            DomainSemanticProfileV2.version == "1",
        )
    )
    if profile is None:
        profile = issue_domain_semantic_profile_v1(
            db, provider=provider, tenant_id=tenant_id, profile_id="profile:stored", version="1", status="reviewed",
            content={"materiality": "stored"}, issued_at=now, effective_at=now, expires_at=now + timedelta(minutes=10),
        )
    projection = db.scalar(
        select(TenantDomainProfileSelectionProjectionV2).where(
            TenantDomainProfileSelectionProjectionV2.tenant_id == tenant_id,
        )
    )
    selection = (
        db.scalar(
            select(TenantDomainProfileSelectionV2).where(
                TenantDomainProfileSelectionV2.tenant_id == tenant_id,
                TenantDomainProfileSelectionV2.selection_id == projection.current_selection_id,
            )
        )
        if projection is not None
        else None
    )
    if selection is None:
        selection = append_profile_selection_v1(
            db, provider=provider, tenant_id=tenant_id, profile=profile, policy_epoch=1,
            selected_by_principal_ref="user:owner", reason_code="stored-test", issued_at=now,
            effective_at=now, expires_at=now + timedelta(minutes=5),
        )
    fixture_suffix = hashlib.sha256(decision_receipt_id.encode("utf-8")).hexdigest()[:16]
    native_authorization_hash = "a" * 64
    plan_id = f"plan:stored:{fixture_suffix}"
    plan_issued_at, plan_expires_at = now - timedelta(seconds=1), now + timedelta(minutes=4, seconds=59)
    plan_material = {
        "plan_id": plan_id,
        "canonical_action_hash": native_authorization_hash,
        "issued_at": plan_issued_at.isoformat(),
        "expires_at": plan_expires_at.isoformat(),
    }
    plan_digest = hashlib.sha256(
        json.dumps(plan_material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    plan_material["plan_digest"] = plan_digest
    bound_action = dict(action)
    bound_action.update(
        domain_profile_ref=profile.profile_id,
        domain_profile_hash=profile.content_hash,
        policy_epoch=1,
        control_plan_id=plan_id,
        control_plan_digest=plan_digest,
    )
    native_selection_id = f"native-selection-{fixture_suffix}"
    db.execute(NativeControlSelection.__table__.insert().values(
        selection_id=native_selection_id, tenant_id=tenant_id, action_id=str(bound_action["action_id"]),
        canonical_action_hash=native_authorization_hash, control_plan_id=plan_id,
        control_plan_digest=plan_digest, control_plan_material=plan_material, plan_issued_at=plan_issued_at,
        plan_expires_at=plan_expires_at, selection_reason="stored-test", assurance_level=1,
        selector_version="stored-test", matrix_version="stored-test", policy_version="policy:stored", input_digest="i" * 64,
        control_requirement_unsatisfied=False,
    ))
    native = db.get(NativeControlSelection, native_selection_id)
    assert native is not None
    evidence = EvidenceNode(
        tenant_id=tenant_id,
        node_type="phase5_test",
        signal_type="decision",
        label="stored authority decision",
        payload={},
    )
    db.add(evidence)
    db.flush()
    db.add(DecisionReceipt(
        receipt_id=decision_receipt_id,
        tenant_id=tenant_id,
        action_id=native.action_id,
        chain_id=str(bound_action["chain_id"]),
        canonical_action_hash=canonical_action_hash_v2(bound_action),
        actor_hash="a" * 64,
        authority_hash="b" * 64,
        purpose_hash="c" * 64,
        tool_fingerprint="d" * 64,
        parameter_hash="e" * 64,
        target_resource_hash="f" * 64,
        destination_hash="0" * 64,
        side_effect_class="external_write",
        approval_binding_hash="g" * 64,
        approval_binding_id=None,
        policy_snapshot_id="policy:stored",
        decision="allow",
        control_mode="inline_allowed",
        transformations=[],
        expires_at=now + timedelta(minutes=4),
        issued_at=now,
        signature="s" * 43,
        signing_key_id="decision",
        collector_id="phase5:stored-test",
        canonical_action_evidence_node_id=evidence.id,
        policy_snapshot_evidence_node_id=None,
        evidence_bundle_id=None,
        evidence_node_id=None,
        idempotency_key=f"stored:{decision_receipt_id}",
    ))
    db.flush()
    decision_value = {
        "schema_version": "2.0", "authority_binding_version": 1, "receipt_id": decision_receipt_id,
        "tenant_id": tenant_id, "action_id": native.action_id, "canonical_action": bound_action,
        "phase5_canonical_action_hash_domain": "hawk:canonical-ai-action:v2",
        "phase5_canonical_action_hash": canonical_action_hash_v2(bound_action),
        "base_receipt_canonical_action_hash_domain": "hawk:decision-receipt-canonical-action:v1",
        "base_receipt_canonical_action_hash": canonical_action_hash_v2(bound_action),
        "native_authorization_action_hash_domain": "hawk:native-control-authorization-request:v1",
        "native_authorization_action_hash": native_authorization_hash,
        "canonical_action_hash": canonical_action_hash_v2(bound_action),
        "material_fields_hash": material_fields_hash(bound_action), "policy_epoch": 1, "control_plan_id": plan_id,
        "control_plan_digest": plan_digest, "expires_at": (now + timedelta(minutes=4)).isoformat(), "issued_at": now.isoformat(),
        "profile_selection_id": selection.selection_id, "profile_selection_hash": selection.selection_hash,
        "control_selection_id": native.selection_id, "native_action_id": native.action_id,
        "native_canonical_action_hash": native.canonical_action_hash,
        "native_plan_issued_at": native.plan_issued_at.replace(tzinfo=now.tzinfo).isoformat(),
        "native_plan_expires_at": native.plan_expires_at.replace(tzinfo=now.tzinfo).isoformat(),
        "authoritative_decision": authoritative_decision, "authority_status": authority_status, "decision_version": 1,
    }
    signed = sign_object(
        provider, purpose="decision_receipt_signing", domain=DECISION_DOMAIN, tenant_id=tenant_id,
        key_id=active_key_id(provider, purpose="decision_receipt_signing", tenant_id=tenant_id), value=decision_value,
    )
    db.add(DecisionReceiptV2Extension(
        receipt_id=decision_receipt_id, tenant_id=tenant_id, action_id=native.action_id,
        canonical_action_hash=canonical_action_hash_v2(bound_action), material_fields_hash=material_fields_hash(bound_action), policy_epoch=1,
        control_plan_digest=plan_digest, expires_at=now + timedelta(minutes=4), algorithm=signed["algorithm"],
        signing_key_id=signed["signing_key_id"], signature=signed["signature"], signed_envelope=signed,
        authority_binding_version=1, profile_selection_id=selection.selection_id, profile_selection_hash=selection.selection_hash,
        control_selection_id=native.selection_id, control_plan_id=plan_id, authoritative_decision=authoritative_decision,
        authority_status=authority_status, decision_version=1,
    ))
    return StoredAuthorityFixture(
        action=bound_action,
        decision_receipt_id=decision_receipt_id,
        profile_selection_id=selection.selection_id,
        profile_selection_hash=selection.selection_hash,
        control_selection_id=native.selection_id,
    )
