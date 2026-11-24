"""Transactional writers for the durable Phase 5 lifecycle evidence graph."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import (
    ActionExecutionTransitionV2,
    ActionPlanStepV2,
    ActionPlanV2,
    DecisionReceiptV2Extension,
    DelegationContextV2,
    ExecutionComparisonV2,
    ExecutionPermitAttemptV2,
    ExecutionPermitV2,
    ExecutionReceiptV2Extension,
    ExpectedOutcomeV2,
    OutcomeVerificationV2,
    PersistentEffectTransitionV2,
    PersistentEffectV2,
)
from app.db.models.evidence import DecisionReceipt, EvidenceNode, ExecutionReceipt

from .canonical_v2 import canonical_action_hash_v2, domain_hash
from .complex_actions import delegated_child_is_attenuated, issue_action_plan
from .complex_actions import (
    PERSISTENT_EFFECT_TRANSITION_DOMAIN,
    issue_persistent_effect_transition,
    next_execution_state,
    next_persistent_effect_state,
)
from .execution_proof import (
    EXECUTION_COMPARISON_DOMAIN,
    EXECUTION_RECEIPT_DOMAIN,
    compare_authorized_to_executed,
    issue_execution_receipt_v2,
    signed_execution_comparison,
)
from .signing import verify_signed_object
from .materiality import material_fields_hash
from .signing import SigningKeyProvider, active_key_id, sign_object


DECISION_RECEIPT_DOMAIN = "hawk:decision-receipt-extension:v2"
DELEGATION_DOMAIN = "hawk:delegation-context:v2"
EFFECT_DOMAIN = "hawk:persistent-effect:v1"
EXPECTED_OUTCOME_DOMAIN = "hawk:expected-outcome-contract:v1"
OUTCOME_DOMAIN = "hawk:outcome-verification:v1"
# Temporary compatibility for the paused Coverage projection.  It remains
# fail-closed for outcome rows because those use outcome_verification_signing;
# new code must bind each lifecycle artifact to its exact signing purpose.
LIFECYCLE_EVIDENCE_PURPOSE = "persistent_effect_signing"
OUTCOME_RESULTS = frozenset({"SATISFIED", "VIOLATED", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE"})
PERSISTENT_EFFECT_STATES = frozenset({"CREATED", "ACTIVE", "MODIFIED", "EXPIRED", "REVOKED", "DELETED", "ORPHANED", "UNKNOWN", "VERIFIED_RECOVERED"})


def _utc_iso(value: datetime) -> str:
    return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()


def require_tenant_evidence_nodes(
    db: Session, *, tenant_id: str, evidence_refs: list[str] | tuple[str, ...], minimum: int = 1
) -> list[str]:
    """Return only tenant-owned EvidenceNode IDs; strings are not evidence.

    This is deliberately a reusable guard rather than a new lifecycle ledger:
    callers must bind observed facts to the existing evidence graph.
    """
    requested = sorted({str(value) for value in evidence_refs if value})
    if len(requested) < minimum:
        raise ValueError("observed lifecycle fact requires tenant-valid evidence")
    found = list(db.scalars(select(EvidenceNode.id).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id.in_(requested))).all())
    if len(found) != len(requested):
        raise PermissionError("lifecycle evidence is missing or belongs to another tenant")
    return sorted(found)


def _record_execution_observation_evidence(
    db: Session, *, tenant_id: str, action_id: str, attempt_id: str, result: str, difference_hashes: list[Mapping[str, Any]], unresolved_fields: list[str]
) -> EvidenceNode:
    """Persist one bounded evidence-graph node for the immutable comparison."""
    node = EvidenceNode(
        tenant_id=tenant_id,
        correlation_id=attempt_id[:64],
        node_type="action_execution_comparison_v2",
        signal_type="action.execution.comparison",
        label="Phase 5 execution comparison",
        payload={"action_id": action_id, "attempt_id": attempt_id, "result": result, "difference_hashes": [dict(item) for item in difference_hashes], "unresolved_fields": list(unresolved_fields)},
    )
    db.add(node)
    db.flush()
    return node


def append_action_execution_transition_v2(
    db: Session, *, provider: SigningKeyProvider, tenant_id: str, attempt_id: str,
    expected_state: str, expected_version: int, to_state: str, source: str,
    evidence_refs: list[str], observed_at: datetime, received_at: datetime,
    idempotency_key: str, verified_non_invocation: bool = False, execution_evidence: bool = False,
    source_event_ref: str | None = None, reason_code: str | None = None,
) -> ActionExecutionTransitionV2:
    """CAS-append one signed execution transition; duplicate callbacks are idempotent."""
    from app.db.models.action_integrity import ExecutionPermitAttemptV2
    evidence_ids = require_tenant_evidence_nodes(db, tenant_id=tenant_id, evidence_refs=evidence_refs)
    attempt = db.scalar(select(ExecutionPermitAttemptV2).where(ExecutionPermitAttemptV2.tenant_id == tenant_id, ExecutionPermitAttemptV2.attempt_id == attempt_id).with_for_update())
    if attempt is None:
        raise PermissionError("execution attempt is unavailable for this tenant")
    duplicate = db.scalar(select(ActionExecutionTransitionV2).where(ActionExecutionTransitionV2.tenant_id == tenant_id, ActionExecutionTransitionV2.idempotency_key == idempotency_key))
    if duplicate is not None:
        if duplicate.attempt_id == attempt_id and duplicate.to_state == to_state and duplicate.evidence_refs == evidence_ids:
            return duplicate
        raise PermissionError("conflicting execution transition idempotency key")
    if attempt.status != expected_state or attempt.state_version != expected_version or attempt.next_sequence < 1:
        raise PermissionError("execution transition compare-and-set failed")
    next_execution_state(current_state=expected_state, requested_state=to_state, verified_non_invocation=verified_non_invocation, execution_evidence=execution_evidence)
    previous = db.scalar(select(ActionExecutionTransitionV2).where(ActionExecutionTransitionV2.tenant_id == tenant_id, ActionExecutionTransitionV2.attempt_id == attempt_id).order_by(ActionExecutionTransitionV2.sequence.desc()).with_for_update())
    if (attempt.next_sequence == 1) != (previous is None):
        raise PermissionError("execution transition history is inconsistent")
    previous_hash = domain_hash("hawk:execution-transition-envelope-hash:v1", dict(previous.signed_envelope)) if previous else None
    key_id = active_key_id(provider, purpose="execution_transition_signing", tenant_id=tenant_id)
    signed = sign_object(provider, purpose="execution_transition_signing", domain="hawk:execution-transition:v1", tenant_id=tenant_id, key_id=key_id, value={
        "schema_version": "1.0", "transition_id": str(uuid4()), "tenant_id": tenant_id, "action_id": attempt.action_id, "attempt_id": attempt_id,
        "sequence": attempt.next_sequence, "from_state": expected_state, "to_state": to_state, "prior_state_version": expected_version, "new_state_version": expected_version + 1,
        "source": source, "source_event_ref": source_event_ref, "evidence_refs": evidence_ids, "observed_at": _utc_iso(observed_at), "received_at": _utc_iso(received_at), "reason_code": reason_code, "idempotency_key": idempotency_key,
        "supersedes_transition_id": None, "prior_transition_id": previous.id if previous else None, "prior_transition_hash": previous_hash,
    })
    transition = ActionExecutionTransitionV2(id=str(signed["transition_id"]), tenant_id=tenant_id, action_id=attempt.action_id, attempt_id=attempt_id, sequence=attempt.next_sequence, from_state=expected_state, to_state=to_state, prior_state_version=expected_version, new_state_version=expected_version + 1, source=source, source_event_ref=source_event_ref, evidence_refs=evidence_ids, observed_at=observed_at, received_at=received_at, reason_code=reason_code, idempotency_key=idempotency_key, supersedes_transition_id=None, prior_transition_id=previous.id if previous else None, prior_transition_hash=previous_hash, algorithm=str(signed["algorithm"]), signing_key_id=str(signed["signing_key_id"]), signature=str(signed["signature"]), signed_envelope=signed)
    db.add(transition)
    attempt.status, attempt.state_version, attempt.next_sequence = to_state, expected_version + 1, attempt.next_sequence + 1
    return transition


def reconstruct_action_execution_history_v2(db: Session, *, provider: SigningKeyProvider, tenant_id: str, attempt_id: str) -> tuple[str, int]:
    """Fail closed unless every signed event exactly reconstructs the attempt projection."""
    attempt = db.scalar(select(ExecutionPermitAttemptV2).where(ExecutionPermitAttemptV2.tenant_id == tenant_id, ExecutionPermitAttemptV2.attempt_id == attempt_id).with_for_update())
    if attempt is None:
        raise PermissionError("execution attempt is unavailable for this tenant")
    if not attempt.decision_receipt_id or not attempt.execution_permit_id:
        raise PermissionError("execution attempt has no stored decision and permit bridge")
    decision = db.scalar(
        select(DecisionReceiptV2Extension)
        .where(
            DecisionReceiptV2Extension.tenant_id == tenant_id,
            DecisionReceiptV2Extension.receipt_id == attempt.decision_receipt_id,
        )
        .with_for_update()
    )
    permit = db.scalar(
        select(ExecutionPermitV2)
        .where(
            ExecutionPermitV2.tenant_id == tenant_id,
            ExecutionPermitV2.permit_id == attempt.execution_permit_id,
        )
        .with_for_update()
    )
    if (
        decision is None
        or permit is None
        or decision.action_id != attempt.action_id
        or decision.canonical_action_hash != attempt.canonical_action_hash
        or decision.material_fields_hash != attempt.material_fields_hash
        or permit.attempt_id != attempt.attempt_id
        or permit.action_id != attempt.action_id
        or permit.decision_receipt_id != attempt.decision_receipt_id
        or permit.canonical_action_hash != attempt.canonical_action_hash
        or permit.material_fields_hash != attempt.material_fields_hash
    ):
        raise PermissionError("execution attempt stored decision and permit bridge is inconsistent")
    rows = list(db.scalars(select(ActionExecutionTransitionV2).where(ActionExecutionTransitionV2.tenant_id == tenant_id, ActionExecutionTransitionV2.attempt_id == attempt_id).order_by(ActionExecutionTransitionV2.sequence)).all())
    state, version, prior_id, prior_hash = "PERMIT_ISSUED", 0, None, None
    for sequence, row in enumerate(rows, 1):
        envelope = dict(row.signed_envelope)
        if not verify_signed_object(provider, purpose="execution_transition_signing", domain="hawk:execution-transition:v1", tenant_id=tenant_id, value=envelope, current_authority=False):
            raise PermissionError("execution transition signature is invalid")
        if not (row.sequence == sequence and row.from_state == state and row.prior_state_version == version and row.new_state_version == version + 1 and row.prior_transition_id == prior_id and row.prior_transition_hash == prior_hash and envelope.get("transition_id") == row.id and envelope.get("evidence_refs") == row.evidence_refs):
            raise PermissionError("execution transition history is inconsistent")
        require_tenant_evidence_nodes(db, tenant_id=tenant_id, evidence_refs=list(row.evidence_refs))
        state, version = row.to_state, row.new_state_version
        prior_id, prior_hash = row.id, domain_hash("hawk:execution-transition-envelope-hash:v1", envelope)
    if attempt.status != state or attempt.state_version != version or attempt.next_sequence != len(rows) + 1:
        raise PermissionError("execution attempt projection does not match signed history")
    return state, version


def append_persistent_effect_transition_v2(
    db: Session, *, provider: SigningKeyProvider, tenant_id: str, effect_id: str,
    expected_state: str, expected_version: int, to_state: str, evidence_refs: list[str], evidence_quality: str,
    observed_at: datetime, idempotency_key: str, remediation_verified: bool = False,
) -> PersistentEffectTransitionV2:
    """CAS-append signed effect history and update only its derived projection."""
    evidence_ids = require_tenant_evidence_nodes(db, tenant_id=tenant_id, evidence_refs=evidence_refs)
    effect = db.scalar(select(PersistentEffectV2).where(PersistentEffectV2.tenant_id == tenant_id, PersistentEffectV2.id == effect_id).with_for_update())
    if effect is None:
        raise PermissionError("persistent effect is unavailable for this tenant")
    duplicate = db.scalar(select(PersistentEffectTransitionV2).where(PersistentEffectTransitionV2.tenant_id == tenant_id, PersistentEffectTransitionV2.idempotency_key == idempotency_key))
    if duplicate is not None:
        if duplicate.effect_id == effect_id and duplicate.to_state == to_state:
            return duplicate
        raise PermissionError("conflicting persistent effect idempotency key")
    if effect.state != expected_state or effect.state_version != expected_version:
        raise PermissionError("persistent effect transition compare-and-set failed")
    next_persistent_effect_state(current_state=expected_state, requested_state=to_state, evidence_quality=evidence_quality, remediation_verified=remediation_verified)
    previous = db.scalar(select(PersistentEffectTransitionV2).where(PersistentEffectTransitionV2.tenant_id == tenant_id, PersistentEffectTransitionV2.effect_id == effect_id).order_by(PersistentEffectTransitionV2.sequence.desc()).with_for_update())
    sequence = int(effect.history_head_sequence) + 1
    if (sequence == 1) != (previous is None):
        raise PermissionError("persistent effect transition history is inconsistent")
    prior_hash = domain_hash("hawk:persistent-effect-transition-envelope-hash:v1", dict(previous.signed_envelope)) if previous else None
    signed = issue_persistent_effect_transition(provider, tenant_id=tenant_id, effect_id=effect_id, sequence=sequence, current_state=expected_state, requested_state=to_state, prior_state_version=expected_version, prior_transition_id=previous.id if previous else None, prior_transition_hash=prior_hash, evidence_quality=evidence_quality, observed_at=observed_at, received_at=observed_at, idempotency_key=idempotency_key, evidence_refs=evidence_ids, recovery_basis="REMEDIATION_EXECUTION" if remediation_verified else "NONE", remediation_verified=remediation_verified)
    if not verify_signed_object(provider, purpose="persistent_effect_signing", domain=PERSISTENT_EFFECT_TRANSITION_DOMAIN, tenant_id=tenant_id, value=signed, current_authority=True):
        raise RuntimeError("persistent effect transition signing failed")
    signed_envelope = dict(signed)
    transition = PersistentEffectTransitionV2(id=str(signed_envelope["transition_id"]), tenant_id=tenant_id, effect_id=effect_id, sequence=sequence, from_state=expected_state, to_state=to_state, prior_state_version=expected_version, new_state_version=expected_version + 1, prior_transition_id=previous.id if previous else None, prior_transition_hash=prior_hash, transition_kind="STATE_CHANGE", observed_object_hash=None, evidence_quality=evidence_quality, verification_source_refs=evidence_ids, last_verified_at=None, verification_valid_until=None, recovery_basis="REMEDIATION_EXECUTION" if remediation_verified else "NONE", remediation_action_id=None, remediation_attempt_id=None, remediation_execution_receipt_id=None, remediation_outcome_verification_id=None, reason_code=None, idempotency_key=idempotency_key, observed_at=observed_at, received_at=observed_at, algorithm=str(signed_envelope["algorithm"]), signing_key_id=str(signed_envelope["signing_key_id"]), signature=str(signed_envelope["signature"]), signed_envelope=signed_envelope)
    db.add(transition)
    if not verify_signed_object(provider, purpose="persistent_effect_signing", domain=PERSISTENT_EFFECT_TRANSITION_DOMAIN, tenant_id=tenant_id, value=dict(transition.signed_envelope), current_authority=True):
        raise RuntimeError("persistent effect transition envelope changed after signing")
    effect.state, effect.state_version = to_state, expected_version + 1
    effect.history_head_transition_id, effect.history_head_transition_hash, effect.history_head_sequence = transition.id, domain_hash("hawk:persistent-effect-transition-envelope-hash:v1", dict(transition.signed_envelope)), sequence
    effect.evidence_quality = evidence_quality
    effect.recovery_requires_remediation = bool(effect.recovery_requires_remediation or to_state == "MODIFIED")
    if to_state in {"EXPIRED", "REVOKED", "DELETED", "VERIFIED_RECOVERED"}:
        effect.terminal_at = observed_at
    return transition


def reconstruct_persistent_effect_history_v2(
    db: Session, *, provider: SigningKeyProvider, tenant_id: str, effect_id: str,
) -> tuple[str, int]:
    """Rebuild an effect projection exclusively from its signed append-only history."""
    effect = db.scalar(
        select(PersistentEffectV2)
        .where(PersistentEffectV2.tenant_id == tenant_id, PersistentEffectV2.id == effect_id)
        .with_for_update()
    )
    if effect is None:
        raise PermissionError("persistent effect is unavailable for this tenant")
    rows = list(
        db.scalars(
            select(PersistentEffectTransitionV2)
            .where(PersistentEffectTransitionV2.tenant_id == tenant_id, PersistentEffectTransitionV2.effect_id == effect_id)
            .order_by(PersistentEffectTransitionV2.sequence)
        ).all()
    )
    state, version, prior_id, prior_hash = "CREATED", 0, None, None
    for sequence, row in enumerate(rows, start=1):
        envelope = dict(row.signed_envelope)
        if not verify_signed_object(
            provider,
            purpose="persistent_effect_signing",
            domain=PERSISTENT_EFFECT_TRANSITION_DOMAIN,
            tenant_id=tenant_id,
            value=envelope,
            current_authority=False,
        ):
            raise PermissionError("persistent effect transition signature is invalid")
        signed_row_matches = (
            envelope.get("schema_version") == "1.0"
            and envelope.get("tenant_id") == row.tenant_id == tenant_id
            and envelope.get("effect_id") == row.effect_id == effect_id
            and envelope.get("sequence") == row.sequence
            and envelope.get("from_state") == row.from_state
            and envelope.get("to_state") == row.to_state
            and envelope.get("prior_state_version") == row.prior_state_version
            and envelope.get("new_state_version") == row.new_state_version
            and envelope.get("prior_transition_id") == row.prior_transition_id
            and envelope.get("prior_transition_hash") == row.prior_transition_hash
            and envelope.get("transition_kind") == row.transition_kind
            and envelope.get("observed_object_hash") == row.observed_object_hash
            and envelope.get("evidence_quality") == row.evidence_quality
            and envelope.get("verification_source_refs") == row.verification_source_refs
            and envelope.get("last_verified_at") == (_utc_iso(row.last_verified_at) if row.last_verified_at else None)
            and envelope.get("verification_valid_until") == (_utc_iso(row.verification_valid_until) if row.verification_valid_until else None)
            and envelope.get("recovery_basis") == row.recovery_basis
            and envelope.get("remediation_action_id") == row.remediation_action_id
            and envelope.get("remediation_attempt_id") == row.remediation_attempt_id
            and envelope.get("remediation_execution_receipt_id") == row.remediation_execution_receipt_id
            and envelope.get("remediation_outcome_verification_id") == row.remediation_outcome_verification_id
            and envelope.get("reason_code") == row.reason_code
            and envelope.get("idempotency_key") == row.idempotency_key
            and envelope.get("observed_at") == _utc_iso(row.observed_at)
            and envelope.get("received_at") == _utc_iso(row.received_at)
            and envelope.get("algorithm") == row.algorithm
            and envelope.get("signing_key_id") == row.signing_key_id
            and envelope.get("signature") == row.signature
        )
        if not (
            row.sequence == sequence
            and row.from_state == state
            and row.prior_state_version == version
            and row.new_state_version == version + 1
            and row.prior_transition_id == prior_id
            and row.prior_transition_hash == prior_hash
            and envelope.get("transition_id") == row.id
            and signed_row_matches
        ):
            raise PermissionError("persistent effect transition history is inconsistent")
        require_tenant_evidence_nodes(
            db, tenant_id=tenant_id, evidence_refs=list(row.verification_source_refs)
        )
        next_persistent_effect_state(
            current_state=state,
            requested_state=row.to_state,
            evidence_quality=row.evidence_quality,
            remediation_verified=row.recovery_basis == "REMEDIATION_EXECUTION",
        )
        state, version = row.to_state, row.new_state_version
        prior_id, prior_hash = row.id, domain_hash(
            "hawk:persistent-effect-transition-envelope-hash:v1", envelope
        )
    if not (
        effect.state == state
        and effect.state_version == version
        and effect.history_head_sequence == len(rows)
        and effect.history_head_transition_id == prior_id
        and effect.history_head_transition_hash == prior_hash
    ):
        raise PermissionError("persistent effect projection does not match signed history")
    effect.reconstruction_status = "VERIFIED"
    return state, version


def persistent_effect_current_truth_v2(db: Session, *, provider: SigningKeyProvider, tenant_id: str, effect_id: str, evaluation_time: datetime) -> str:
    """Return evidence-verified truth only while independently verified evidence is current."""
    try:
        reconstruct_persistent_effect_history_v2(
            db, provider=provider, tenant_id=tenant_id, effect_id=effect_id
        )
    except PermissionError:
        return "UNKNOWN"
    effect = db.scalar(select(PersistentEffectV2).where(PersistentEffectV2.tenant_id == tenant_id, PersistentEffectV2.id == effect_id).with_for_update())
    if effect is None or effect.reconstruction_status != "VERIFIED":
        return "UNKNOWN"
    if effect.state not in {"ACTIVE", "VERIFIED_RECOVERED"} or effect.evidence_quality != "INDEPENDENTLY_VERIFIED":
        return "UNKNOWN"
    if effect.last_verified_at is None or effect.verification_valid_until is None:
        return "UNKNOWN"
    now = evaluation_time.replace(tzinfo=timezone.utc) if evaluation_time.tzinfo is None else evaluation_time
    if effect.last_verified_at > now or now > min(effect.verification_valid_until, effect.expires_at):
        return "UNKNOWN"
    return effect.state


def persist_decision_receipt_v2_extension(
    db: Session,
    *,
    provider: SigningKeyProvider,
    receipt: DecisionReceipt,
    action: Mapping[str, Any],
    profile_selection_id: str,
    profile_selection_hash: str,
    control_selection_id: str,
) -> DecisionReceiptV2Extension:
    """Attach signed V2 material to an already durable production decision receipt."""
    if receipt.tenant_id != action.get("tenant_id"):
        raise ValueError("decision receipt/action tenant mismatch")
    base_receipt = db.scalar(
        select(DecisionReceipt)
        .where(DecisionReceipt.tenant_id == receipt.tenant_id, DecisionReceipt.receipt_id == receipt.receipt_id)
        .with_for_update()
    )
    if base_receipt is None or base_receipt.action_id != receipt.action_id:
        raise ValueError("base decision receipt is not durable or does not match the decision extension")
    existing = db.get(DecisionReceiptV2Extension, receipt.receipt_id)
    if existing is not None:
        return existing
    from .stored_authority import require_current_action_authority_v1

    authority = require_current_action_authority_v1(
        db,
        provider=provider,
        tenant_id=receipt.tenant_id,
        action=action,
        profile_selection_id=profile_selection_id,
        profile_selection_hash=profile_selection_hash,
        control_selection_id=control_selection_id,
        now=receipt.issued_at,
    )
    native = authority.native_selection
    authoritative_decision = str(receipt.decision).upper()
    if not authoritative_decision:
        raise ValueError("decision receipt authority decision is required")
    key_id = active_key_id(provider, purpose="decision_receipt_signing", tenant_id=receipt.tenant_id)
    envelope = sign_object(provider, purpose="decision_receipt_signing", domain=DECISION_RECEIPT_DOMAIN, tenant_id=receipt.tenant_id, key_id=key_id, value={
        "schema_version": "2.0", "receipt_id": receipt.receipt_id, "tenant_id": receipt.tenant_id, "action_id": receipt.action_id,
        # The generic final seam must be able to reconstruct this exact,
        # server-authored action without inventing profile/control bindings or
        # a replacement request timestamp.  Selection IDs remain outside the
        # canonical semantic action and are attested separately below.
        "canonical_action": dict(action),
        "phase5_canonical_action_hash_domain": "hawk:canonical-ai-action:v2",
        "phase5_canonical_action_hash": canonical_action_hash_v2(action),
        "base_receipt_canonical_action_hash_domain": "hawk:decision-receipt-canonical-action:v1",
        "base_receipt_canonical_action_hash": base_receipt.canonical_action_hash,
        "native_authorization_action_hash_domain": "hawk:native-control-authorization-request:v1",
        "native_authorization_action_hash": native.canonical_action_hash,
        "canonical_action_hash": canonical_action_hash_v2(action), "material_fields_hash": material_fields_hash(action),
        "policy_epoch": int(action["policy_epoch"]), "control_plan_digest": str(action["control_plan_digest"]),
        "expires_at": receipt.expires_at.isoformat(), "issued_at": receipt.issued_at.isoformat(),
        "authority_binding_version": 1,
        "profile_selection_id": authority.selection.selection_id,
        "profile_selection_hash": authority.selection.selection_hash,
        "control_selection_id": native.selection_id,
        "control_plan_id": native.control_plan_id,
        "native_action_id": native.action_id,
        "native_canonical_action_hash": native.canonical_action_hash,
        "native_plan_issued_at": _utc_iso(native.plan_issued_at),
        "native_plan_expires_at": _utc_iso(native.plan_expires_at),
        "authoritative_decision": authoritative_decision,
        "authority_status": "CURRENT",
        "decision_version": 1,
    })
    row = DecisionReceiptV2Extension(receipt_id=receipt.receipt_id, tenant_id=receipt.tenant_id, action_id=receipt.action_id,
        canonical_action_hash=str(envelope["canonical_action_hash"]), material_fields_hash=str(envelope["material_fields_hash"]),
        policy_epoch=int(envelope["policy_epoch"]), control_plan_digest=str(envelope["control_plan_digest"]), expires_at=receipt.expires_at,
        algorithm=str(envelope["algorithm"]), signing_key_id=str(envelope["signing_key_id"]), signature=str(envelope["signature"]), signed_envelope=envelope,
        authority_binding_version=1, profile_selection_id=authority.selection.selection_id,
        profile_selection_hash=authority.selection.selection_hash, control_selection_id=native.selection_id,
        control_plan_id=native.control_plan_id, authoritative_decision=authoritative_decision,
        authority_status="CURRENT", decision_version=1)
    db.add(row)
    return row


def persist_execution_receipt_v2_and_comparison(
    db: Session, *, provider: SigningKeyProvider, execution_receipt: ExecutionReceipt, authorized: Mapping[str, Any],
    executed: Mapping[str, Any], permit_id: str | None, issued_at: datetime, evidence_quality: str = "HAWK_RUNTIME_OBSERVED",
    effect_closure: Mapping[str, Any] | None = None,
) -> tuple[ExecutionReceiptV2Extension, ExecutionComparisonV2]:
    """Persist V2 execution/compare rows only beside a real base receipt."""
    if execution_receipt.tenant_id != authorized.get("tenant_id") or execution_receipt.tenant_id != executed.get("tenant_id"):
        raise ValueError("execution receipt/action tenant mismatch")
    existing = db.get(ExecutionReceiptV2Extension, execution_receipt.receipt_id)
    terminal_state = {"success": "EXECUTED", "failure": "UNVERIFIED", "unverified": "UNVERIFIED", "blocked": "BLOCKED"}.get(
        str(execution_receipt.execution_status).lower(),
        "UNKNOWN",
    )
    envelope = existing.signed_envelope if existing is not None else issue_execution_receipt_v2(
        provider, tenant_id=execution_receipt.tenant_id, attempt_id=execution_receipt.execution_attempt_id, permit_id=permit_id,
        authorized=authorized, executed=executed, terminal_state=terminal_state, evidence_quality=evidence_quality,
        issued_at=issued_at, effect_closure=effect_closure,
    )
    if existing is None:
        existing = ExecutionReceiptV2Extension(receipt_id=execution_receipt.receipt_id, tenant_id=execution_receipt.tenant_id,
            attempt_id=execution_receipt.execution_attempt_id, permit_id=permit_id, canonical_action_hash=str(envelope["canonical_action_hash"]),
            actual_material_fields_hash=str(envelope["actual_material_fields_hash"]), terminal_state=str(envelope["terminal_state"]), evidence_quality=str(envelope["evidence_quality"]),
            algorithm=str(envelope["algorithm"]), signing_key_id=str(envelope["signing_key_id"]), signature=str(envelope["signature"]), signed_envelope=dict(envelope),
            effect_reservation_id=(effect_closure or {}).get("reservation_id"),
            effect_closure_state=(effect_closure or {}).get("state"),
            provider_effect_ref=(effect_closure or {}).get("provider_effect_ref"),
            effect_evidence_refs=list((effect_closure or {}).get("evidence_refs") or []),
            recovery_sequence=(effect_closure or {}).get("recovery_sequence"))
        db.add(existing)
    comparison = db.scalar(select(ExecutionComparisonV2).where(ExecutionComparisonV2.tenant_id == execution_receipt.tenant_id, ExecutionComparisonV2.attempt_id == execution_receipt.execution_attempt_id))
    if comparison is None:
        signed = signed_execution_comparison(provider, tenant_id=execution_receipt.tenant_id, attempt_id=execution_receipt.execution_attempt_id, authorized=authorized, executed=executed, issued_at=issued_at)
        plain = compare_authorized_to_executed(authorized, executed)
        comparison = ExecutionComparisonV2(id=str(signed["comparison_id"]), tenant_id=execution_receipt.tenant_id, attempt_id=execution_receipt.execution_attempt_id,
            decision_receipt_id=execution_receipt.decision_receipt_id, execution_receipt_id=execution_receipt.receipt_id, result=str(signed["result"]),
            material_differences=list(plain["drift_fields"]), unresolved_fields=list(signed["unresolved_fields"]), algorithm=str(signed["algorithm"]),
            signing_key_id=str(signed["signing_key_id"]), signature=str(signed["signature"]), signed_envelope=signed)
        db.add(comparison)
        if plain["result"] in {"DRIFTED", "UNVERIFIED"}:
            evidence = _record_execution_observation_evidence(
                db, tenant_id=execution_receipt.tenant_id, action_id=str(authorized["action_id"]),
                attempt_id=execution_receipt.execution_attempt_id, result=str(plain["result"]),
                difference_hashes=list(plain["difference_hashes"]), unresolved_fields=list(plain["unresolved_fields"]),
            )
            # The catalogue owns severity/deduplication; the lifecycle only
            # supplies factual comparison evidence and never makes a policy decision.
            from app.services.native_control.findings import record_native_control_finding
            if plain["result"] == "UNVERIFIED":
                record_native_control_finding(
                    db, tenant_id=execution_receipt.tenant_id, finding_type="EXECUTION_UNVERIFIED", integration_id=None,
                    action_id=str(authorized["action_id"]), provider="phase5", policy_version=str(authorized.get("policy_version_id") or ""),
                    evidence_node_ids=[evidence.id], reason_codes=["execution_evidence_unresolved"], material_field_or_effect="execution",
                    evidence_kinds=["missing_or_insufficient_execution_evidence"], authority_refs=[str(execution_receipt.receipt_id)],
                    profile_ref=str(authorized.get("domain_profile_ref") or "phase5"), lifecycle_ref=comparison.id, evidence_classification="unverified",
                )
            else:
                record_native_control_finding(
                    db, tenant_id=execution_receipt.tenant_id, finding_type="EXECUTION_DRIFT_DETECTED", integration_id=None,
                    action_id=str(authorized["action_id"]), provider="phase5", policy_version=str(authorized.get("policy_version_id") or ""),
                    evidence_node_ids=[evidence.id], reason_codes=["execution_material_drift"], material_field_or_effect="execution",
                    evidence_kinds=["comparator_result", "execution_evidence"], authority_refs=[str(execution_receipt.receipt_id)],
                    profile_ref=str(authorized.get("domain_profile_ref") or "phase5"), lifecycle_ref=comparison.id, evidence_classification="independent",
                )
    return existing, comparison


def persist_action_plan_v2(db: Session, *, provider: SigningKeyProvider, tenant_id: str, parent_action_id: str, steps: list[Mapping[str, Any]], issued_at: datetime, expires_at: datetime) -> ActionPlanV2:
    signed = issue_action_plan(provider, tenant_id=tenant_id, parent_action_id=parent_action_id, steps=steps, issued_at=issued_at, expires_at=expires_at)
    row = ActionPlanV2(tenant_id=tenant_id, parent_action_id=parent_action_id, plan_id=str(signed["plan_id"]), plan_version=int(signed["plan_version"]), plan_digest=str(signed["plan_digest"]), resource_boundary_hash=signed.get("resource_boundary_hash"), target_boundary_hash=signed.get("target_boundary_hash"), destination_boundary_hash=signed.get("destination_boundary_hash"), max_total_executions=int(signed["max_total_executions"]), completion_rule=str(signed["completion_rule"]), compensation_action_refs=list(signed["compensation_action_refs"]), expires_at=expires_at, algorithm=str(signed["algorithm"]), signing_key_id=str(signed["signing_key_id"]), signature=str(signed["signature"]), signed_envelope=signed)
    db.add(row)
    db.flush()
    for step in signed["steps"]:
        db.add(ActionPlanStepV2(tenant_id=tenant_id, plan_id=row.plan_id, step_id=str(step["step_id"]), step_sequence=int(step["sequence"]), step_digest=str(step["step_digest"]), child_action_id=str(step["child_action_id"]), authority_mode=str(step["authority_mode"]), unbound_material_fields_hash=str(step["unbound_material_fields_hash"]), expected_child_action_class=step.get("expected_child_action_class"), required=bool(step["required"]), permitted_predecessor_step_ids=list(step["permitted_predecessor_step_ids"]), max_executions=int(step["max_executions"]), resource_boundary_hash=step.get("resource_boundary_hash"), target_boundary_hash=step.get("target_boundary_hash"), destination_boundary_hash=step.get("destination_boundary_hash"), compensation_action_ref=step.get("compensation_action_ref")))
    return row


def register_delegated_child_v2(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    parent_action_id: str,
    delegated_action_id: str,
    parent_delegation_context_id: str | None,
    parent_scope: Mapping[str, Any],
    child_scope: Mapping[str, Any],
    source_principal_ref: str,
    destination_principal_ref: str,
    expires_at: datetime,
    issued_at: datetime | None = None,
) -> DelegationContextV2:
    """Register an immutable V1 lineage binding; activation is a separate event."""
    from .delegation_lifecycle import (
        canonical_delegation_scope_v1,
        intersect_delegation_scopes_v1,
        require_active_delegation_ancestry,
    )

    source_scope = canonical_delegation_scope_v1(dict(parent_scope))
    requested_child_scope = canonical_delegation_scope_v1(dict(child_scope))
    effective_scope = intersect_delegation_scopes_v1(source_scope, requested_child_scope)
    if effective_scope != requested_child_scope or not delegated_child_is_attenuated(source_scope, requested_child_scope):
        raise PermissionError("delegated child widens parent authority")
    if not delegated_action_id or len(delegated_action_id) > 64:
        raise ValueError("delegated action identifier is invalid")
    now = (issued_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at.astimezone(timezone.utc)
    if expires_at <= now:
        raise ValueError("delegation context expiry is invalid")
    depth = 1
    if parent_delegation_context_id is not None:
        parent = require_active_delegation_ancestry(
            db,
            provider=provider,
            tenant_id=tenant_id,
            delegation_context_id=parent_delegation_context_id,
            now=now,
        )
        if parent.delegated_action_id != parent_action_id:
            raise PermissionError("delegation parent delegated action does not match this child")
        parent_effective_scope = canonical_delegation_scope_v1(
            dict(parent.signed_envelope or {}).get("effective_scope")
        )
        if source_scope != parent_effective_scope:
            raise PermissionError("delegation parent scope does not match signed effective scope")
        effective_scope = intersect_delegation_scopes_v1(parent_effective_scope, requested_child_scope)
        if effective_scope != requested_child_scope or not delegated_child_is_attenuated(parent_effective_scope, requested_child_scope):
            raise PermissionError("delegated child widens parent authority")
        if expires_at > parent.expires_at:
            raise PermissionError("delegated child outlives its parent context")
        depth = parent.depth + 1
    context_id = str(uuid4())
    key_id = active_key_id(provider, purpose="delegation_context_signing", tenant_id=tenant_id)
    signed = sign_object(provider, purpose="delegation_context_signing", domain=DELEGATION_DOMAIN, tenant_id=tenant_id, key_id=key_id, value={"schema_version": "2.1", "lineage_binding_version": 1, "delegation_context_id": context_id, "tenant_id": tenant_id, "parent_action_id": parent_action_id, "delegated_action_id": delegated_action_id, "parent_delegation_ref": parent_delegation_context_id, "source_principal_ref": source_principal_ref, "destination_principal_ref": destination_principal_ref, "effective_scope": effective_scope, "authority_scope_hash": domain_hash("hawk:delegated-scope:v1", effective_scope), "depth": depth, "state": "REGISTERED", "state_version": 0, "issued_at": now.isoformat(), "expires_at": expires_at.isoformat()})
    context = DelegationContextV2(tenant_id=tenant_id, delegation_context_id=context_id, parent_action_id=parent_action_id, parent_delegation_context_id=parent_delegation_context_id, delegated_action_id=delegated_action_id, lineage_binding_version=1, source_principal_ref=source_principal_ref, destination_principal_ref=destination_principal_ref, authority_scope_hash=str(signed["authority_scope_hash"]), depth=depth, state="REGISTERED", state_version=0, history_head_event_id=None, history_head_event_hash=None, history_head_sequence=0, reconstruction_status="VERIFIED", expires_at=expires_at, algorithm=str(signed["algorithm"]), signing_key_id=str(signed["signing_key_id"]), signature=str(signed["signature"]), signed_envelope=signed)
    db.add(context)
    return context


def persist_expected_outcome_v2(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    action_id: str,
    expected_state_hash: str | None,
    verification_deadline: datetime,
    issued_at: datetime,
    evidence_refs: list[str] | None = None,
    outcome_contract_id: str | None = None,
) -> ExpectedOutcomeV2:
    """Freeze the expected outcome before an execution observation exists."""
    contract_id = outcome_contract_id or str(uuid4())
    key_id = active_key_id(provider, purpose="outcome_verification_signing", tenant_id=tenant_id)
    signed = sign_object(
        provider,
        purpose="outcome_verification_signing",
        domain=EXPECTED_OUTCOME_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value={
            "schema_version": "2.0",
            "outcome_contract_id": contract_id,
            "tenant_id": tenant_id,
            "action_id": action_id,
            "expected_state_hash": expected_state_hash,
            "verification_deadline": verification_deadline.isoformat(),
            "issued_at": issued_at.isoformat(),
            "evidence_refs": list(evidence_refs or []),
        },
    )
    row = ExpectedOutcomeV2(
        tenant_id=tenant_id,
        outcome_contract_id=contract_id,
        action_id=action_id,
        expected_state_hash=expected_state_hash,
        verification_deadline=verification_deadline,
        algorithm=str(signed["algorithm"]),
        signing_key_id=str(signed["signing_key_id"]),
        signature=str(signed["signature"]),
        signed_envelope=signed,
    )
    db.add(row)
    return row


def persist_persistent_effect_v2(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    action_id: str,
    attempt_id: str,
    execution_receipt_id: str | None,
    downstream_object_hash: str,
    expected_object_state_hash: str,
    state: str,
    expires_at: datetime,
    issued_at: datetime,
    evidence_refs: list[str] | None = None,
) -> PersistentEffectV2:
    """Persist a signed durable effect fact from the post-seam observation."""
    evidence_refs = require_tenant_evidence_nodes(db, tenant_id=tenant_id, evidence_refs=list(evidence_refs or []))
    state = {"APPLIED": "ACTIVE"}.get(str(state).upper(), str(state).upper())
    if state not in PERSISTENT_EFFECT_STATES:
        raise ValueError("persistent effect state is invalid")
    effect_id = str(uuid4())
    key_id = active_key_id(provider, purpose="persistent_effect_signing", tenant_id=tenant_id)
    signed = sign_object(
        provider,
        purpose="persistent_effect_signing",
        domain=EFFECT_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value={
            "schema_version": "2.0",
            "effect_id": effect_id,
            "tenant_id": tenant_id,
            "action_id": action_id,
            "attempt_id": attempt_id,
            "execution_receipt_id": execution_receipt_id,
            "downstream_object_hash": downstream_object_hash,
            "expected_object_state_hash": expected_object_state_hash,
            "state": state,
            "state_version": 0,
            "expires_at": expires_at.isoformat(),
            "issued_at": issued_at.isoformat(),
            "evidence_refs": list(evidence_refs or []),
        },
    )
    row = PersistentEffectV2(
        id=effect_id,
        tenant_id=tenant_id,
        action_id=action_id,
        attempt_id=attempt_id,
        execution_receipt_id=execution_receipt_id,
        downstream_object_hash=downstream_object_hash,
        expected_object_state_hash=expected_object_state_hash,
        state=state,
        state_version=0,
        expires_at=expires_at,
        algorithm=str(signed["algorithm"]),
        signing_key_id=str(signed["signing_key_id"]),
        signature=str(signed["signature"]),
        signed_envelope=signed,
    )
    db.add(row)
    return row


def persist_outcome_verification_v2(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    action_id: str,
    attempt_id: str,
    outcome_contract_id: str,
    execution_receipt_id: str | None,
    result: str,
    verification_source_set_hash: str,
    evidence_quality: str,
    evaluated_at: datetime,
    evidence_refs: list[str] | None = None,
) -> OutcomeVerificationV2:
    """Persist a signed outcome evaluation using independently collected evidence."""
    evidence_refs = require_tenant_evidence_nodes(db, tenant_id=tenant_id, evidence_refs=list(evidence_refs or []))
    result = {"MATCHED": "UNKNOWN"}.get(str(result).upper(), str(result).upper())
    if result not in OUTCOME_RESULTS:
        raise ValueError("outcome verification result is invalid")
    if evidence_quality == "PROVIDER_REPORTED" and result == "SATISFIED":
        raise PermissionError("provider success cannot independently satisfy an outcome")
    verification_id = str(uuid4())
    key_id = active_key_id(provider, purpose="outcome_verification_signing", tenant_id=tenant_id)
    signed = sign_object(
        provider,
        purpose="outcome_verification_signing",
        domain=OUTCOME_DOMAIN,
        tenant_id=tenant_id,
        key_id=key_id,
        value={
            "schema_version": "2.0",
            "verification_id": verification_id,
            "tenant_id": tenant_id,
            "action_id": action_id,
            "attempt_id": attempt_id,
            "outcome_contract_id": outcome_contract_id,
            "execution_receipt_id": execution_receipt_id,
            "result": result,
            "verification_source_set_hash": verification_source_set_hash,
            "evidence_quality": evidence_quality,
            "evaluated_at": evaluated_at.isoformat(),
            "evidence_refs": list(evidence_refs or []),
        },
    )
    row = OutcomeVerificationV2(
        id=verification_id,
        tenant_id=tenant_id,
        verification_id=verification_id,
        action_id=action_id,
        attempt_id=attempt_id,
        outcome_contract_id=outcome_contract_id,
        execution_receipt_id=execution_receipt_id,
        result=result,
        verification_source_set_hash=verification_source_set_hash,
        evidence_quality=evidence_quality,
        evaluated_at=evaluated_at,
        algorithm=str(signed["algorithm"]),
        signing_key_id=str(signed["signing_key_id"]),
        signature=str(signed["signature"]),
        signed_envelope=signed,
    )
    db.add(row)
    return row
