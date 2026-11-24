"""Conservative, event-led Action Detail read projection.

The Action Detail route deliberately does *not* rediscover an action chain.
Its sole route key is a tenant-scoped ``RuntimeEvent.event_id``.  Every
subsequent authority lookup is made only through an explicit identifier stored
on that event in ``metadata_json.action_integrity_refs``.  Missing links remain
UNKNOWN; coincident action IDs, chain IDs, retries, and timestamps are never a
join strategy.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import (
    ApprovalBindingV2Extension,
    ActionExecutionTransitionV2,
    DecisionReceiptV2Extension,
    ExecutionComparisonV2,
    ExecutionPermitAttemptV2,
    ExecutionPermitTransitionV2,
    ExecutionPermitV2,
    ExecutionReceiptV2Extension,
    OutcomeVerificationV2,
    PersistentEffectV2,
)
from app.db.models.evidence import DecisionReceipt, EvidenceNode
from app.db.models.native_control import NativeControlSelection
from app.db.models.policy import ApprovalRequest
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.action_integrity.approval_binding import BINDING_DOMAIN
from app.services.action_integrity.execution_authority import PERMIT_DOMAIN, TRANSITION_DOMAIN
from app.services.action_integrity.execution_proof import EXECUTION_COMPARISON_DOMAIN, EXECUTION_RECEIPT_DOMAIN
from app.services.action_integrity.lifecycle_persistence import DECISION_RECEIPT_DOMAIN, EFFECT_DOMAIN, OUTCOME_DOMAIN
from app.services.action_integrity.signing import verify_signed_object


TIMELINE_STAGES = (
    "REQUEST", "ACTOR_RESOLUTION", "REPRESENTED_SUBJECT_RESOLUTION", "PURPOSE",
    "PROPOSED_ACTION", "DOMAIN_SEMANTICS", "POLICY", "APPROVAL", "PERMIT",
    "EXECUTION", "TARGET_CONFIRMATION", "COMPARISON", "OUTCOME", "PERSISTENT_EFFECT",
)

# Frozen registry §12 card contract.  Every card is an explicit evidence value;
# no section may collapse into a single opaque wrapper.
ACTION_DETAIL_SECTION_FIELDS = {
    "context": (
        "actor_principal", "executing_identity", "represented_subjects", "business_purpose", "authority", "delegation",
    ),
    "action": (
        "operation", "tool_or_service", "safe_parameters", "resources", "targets", "destinations",
        "values_or_quantities", "side_effect", "persistence", "reversibility",
    ),
    "control": (
        "requirements", "control_plan", "mandatory_floors", "assurance", "rejected_controls", "blind_spots",
    ),
    "authorisation": (
        "policy", "decision", "approval_request", "approval_binding", "decision_receipt", "execution_permits",
    ),
    "execution": (
        "observed_semantics", "execution_receipts", "evidence_quality", "material_integrity", "execution_state",
        "drift_fields", "outcome_integrity",
    ),
}

_MAX_REFERENCE_LENGTH = 128


def _unknown(reason: str) -> dict[str, Any]:
    return {"state": "UNKNOWN", "value": None, "evidence_refs": [], "occurred_at": None, "reason_code": reason}


def _unknown_array(reason: str) -> dict[str, Any]:
    """An explicit UNKNOWN whose value keeps a frozen array-card shape."""
    return {"state": "UNKNOWN", "value": [], "evidence_refs": [], "occurred_at": None, "reason_code": reason}


def _array_card(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Keep §12 list cards list-shaped in both observed and unknown states."""
    if observation.get("state") != "OBSERVED":
        return _unknown_array(str(observation.get("reason_code") or "authority_not_persisted"))
    if not isinstance(observation.get("value"), list):
        return _unknown_array("authority_array_cardinality_invalid")
    return dict(observation)


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return (value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)).isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _safe_ref(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > _MAX_REFERENCE_LENGTH:
        return None
    return candidate


def _safe_ref_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    refs = [_safe_ref(item) for item in value]
    if any(item is None for item in refs):
        return []
    return [str(item) for item in refs if item is not None]


def _refs(event: RuntimeEvent) -> dict[str, Any]:
    metadata = event.metadata_json if isinstance(event.metadata_json, Mapping) else {}
    refs = metadata.get("action_integrity_refs")
    return dict(refs) if isinstance(refs, Mapping) else {}


def _stage_evidence_ids(
    db: Session,
    *,
    tenant_id: str,
    event: RuntimeEvent,
    refs: Mapping[str, Any],
    stage: str,
    event_source: bool = False,
) -> list[str]:
    """Return only an exact, wholly tenant-valid evidence set for one stage."""
    evidence_map = refs.get("evidence_node_ids")
    raw = evidence_map.get(stage) if isinstance(evidence_map, Mapping) else None
    if raw is None and event_source:
        raw = event.evidence_node_ids
    return _evidence_ids(db, tenant_id=tenant_id, raw=raw)


def _evidence_ids(db: Session, *, tenant_id: str, raw: Any) -> list[str]:
    """Resolve an exact evidence list without silently dropping bad IDs."""
    requested = _safe_ref_list(raw)
    if not requested:
        return []
    unique = list(dict.fromkeys(requested))
    rows = db.scalars(
        select(EvidenceNode.id).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id.in_(unique))
    ).all()
    resolved = {str(row) for row in rows}
    # A partial or cross-tenant set is not usable evidence for an OBSERVED
    # claim.  It is safer to show UNKNOWN than silently omit a bad reference.
    if len(resolved) != len(unique):
        return []
    return unique


def _observed(value: Any, *, evidence_refs: list[str], occurred_at: datetime | str | None, source_missing_reason: str) -> dict[str, Any]:
    if not evidence_refs:
        return _unknown("tenant_valid_evidence_not_persisted")
    if occurred_at is None:
        return _unknown(source_missing_reason)
    return {
        "state": "OBSERVED",
        "value": _json_value(value),
        "evidence_refs": evidence_refs,
        "occurred_at": _json_value(occurred_at),
        "reason_code": None,
    }


def _verified_v2_stage(
    db: Session,
    *,
    row: Any,
    purpose: str,
    domain: str,
    value: Any,
    evidence_refs: list[str],
    occurred_at: datetime | str | None,
    displayed_material: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """A signed V2 row becomes display evidence only after exact verification."""
    if row is None:
        return _unknown("authority_not_persisted")
    provider = db.info.get("phase5_signing_provider")
    envelope = dict(getattr(row, "signed_envelope", {}) or {})
    tenant_id = str(getattr(row, "tenant_id", ""))
    if provider is None or not tenant_id or not verify_signed_object(
        provider, purpose=purpose, domain=domain, tenant_id=tenant_id, value=envelope, current_authority=False,
    ):
        return _unknown("invalid_signed_evidence")
    if (
        envelope.get("tenant_id") != tenant_id
        or envelope.get("algorithm") != getattr(row, "algorithm", None)
        or envelope.get("signing_key_id") != getattr(row, "signing_key_id", None)
        or envelope.get("signature") != getattr(row, "signature", None)
    ):
        return _unknown("invalid_signed_evidence")
    # Every material value shown to the user must be carried by the verified
    # envelope and equal the durable row.  Optional comparison aliases are
    # explicitly mapped (for example persisted material_differences is the
    # signed drift_fields), rather than accepting a missing field by default.
    for envelope_field, row_field in (displayed_material or {}).items():
        if envelope_field not in envelope:
            return _unknown("invalid_signed_evidence")
        persisted = getattr(row, row_field, None)
        if _json_value(envelope[envelope_field]) != _json_value(persisted):
            return _unknown("invalid_signed_evidence")
    return _observed(value, evidence_refs=evidence_refs, occurred_at=occurred_at, source_missing_reason="authority_timestamp_not_persisted")


def _exact_row(db: Session, model: Any, *, tenant_id: str, field: str, reference: str | None) -> Any | None:
    if reference is None:
        return None
    return db.scalar(select(model).where(model.tenant_id == tenant_id, getattr(model, field) == reference).limit(1))


def _reference_value(refs: Mapping[str, Any], *names: str) -> str | None:
    for name in names:
        value = _safe_ref(refs.get(name))
        if value is not None:
            return value
    return None


def _unknown_unless(condition: bool, reason: str, observed: dict[str, Any]) -> dict[str, Any]:
    return observed if condition else _unknown(reason)


def _stage_source_ref(observation: Mapping[str, Any], ref: str | None, prefix: str) -> str:
    if observation.get("state") != "OBSERVED" or ref is None:
        return ""
    return f"{prefix}:{ref}"


def _timeline_item(
    *, event: RuntimeEvent, ordinal: int, stage: str, observation: Mapping[str, Any], source_ref: str,
    timeline_event_id: str | None = None, sequence: int = 1,
) -> dict[str, Any]:
    return {
        "timeline_event_id": timeline_event_id or f"{event.event_id}:{ordinal}",
        "event_type": stage,
        "stage_ordinal": ordinal,
        "state": observation["state"],
        "value": observation["value"],
        "occurred_at": observation["occurred_at"] if observation["state"] == "OBSERVED" else None,
        "sequence": sequence,
        "source_authority_ref": source_ref,
        "evidence_node_ids": list(observation["evidence_refs"]) if observation["state"] == "OBSERVED" else [],
        "api_references": [],
        "browser_hrefs": [],
        "reason_code": observation["reason_code"],
    }


def _explicit_execution_transition_item(
    db: Session,
    *, tenant_id: str, event: RuntimeEvent, ordinal: int, entry: Mapping[str, Any], permit: ExecutionPermitV2 | None,
) -> dict[str, Any]:
    """Render one explicitly event-bound durable execution transition.

    This accepts no free-form metadata as proof: the event must name a signed,
    tenant-owned `ActionExecutionTransitionV2` that belongs to the exact permit
    already bound to this RuntimeEvent.
    """
    transition_id = _safe_ref(entry.get("authority_id"))
    sequence = entry.get("sequence") if isinstance(entry.get("sequence"), int) and entry.get("sequence") >= 0 else 0
    if entry.get("authority_type") != "execution_transition" or transition_id is None or permit is None:
        return _timeline_item(
            event=event, ordinal=ordinal, stage="EXECUTION", observation=_unknown("timeline_authority_not_referenced"),
            source_ref="", timeline_event_id=f"{event.event_id}:EXECUTION:{transition_id or 'invalid'}", sequence=sequence,
        )
    transition = _exact_row(db, ActionExecutionTransitionV2, tenant_id=tenant_id, field="id", reference=transition_id)
    # Runtime-event metadata names the authority only.  The transition's own
    # signed envelope is the sole source for its timestamp and evidence set.
    evidence = _evidence_ids(
        db,
        tenant_id=tenant_id,
        raw=list(transition.evidence_refs) if transition is not None else None,
    )
    transition_ok = bool(
        transition is not None
        and transition.attempt_id == permit.attempt_id
        and transition.action_id == permit.action_id
    )
    observation = _unknown_unless(
        transition_ok,
        "timeline_authority_reference_mismatch",
        _verified_v2_stage(
            db,
            row=transition,
            purpose="execution_transition_signing",
            domain="hawk:execution-transition:v1",
            value={
                "transition_id": transition.id if transition is not None else None,
                "action_id": transition.action_id if transition is not None else None,
                "attempt_id": transition.attempt_id if transition is not None else None,
                "sequence": transition.sequence if transition is not None else None,
                "from_state": transition.from_state if transition is not None else None,
                "to_state": transition.to_state if transition is not None else None,
            },
            evidence_refs=evidence,
            occurred_at=transition.observed_at if transition is not None else None,
            displayed_material={
                "transition_id": "id", "action_id": "action_id", "attempt_id": "attempt_id", "sequence": "sequence",
                "from_state": "from_state", "to_state": "to_state",
                "observed_at": "observed_at", "evidence_refs": "evidence_refs",
            },
        ),
    )
    return _timeline_item(
        event=event,
        ordinal=ordinal,
        stage="EXECUTION",
        observation=observation,
        source_ref=_stage_source_ref(observation, transition_id, "execution_transition"),
        timeline_event_id=f"{event.event_id}:EXECUTION:{transition_id}",
        sequence=transition.sequence if transition is not None else sequence,
    )


def build_action_detail(db: Session, *, tenant_id: str, runtime_event_id: str) -> dict[str, Any] | None:
    """Build an event-led read view without writing a new source of authority."""
    event = db.scalar(
        select(RuntimeEvent).where(RuntimeEvent.tenant_id == tenant_id, RuntimeEvent.event_id == runtime_event_id)
    )
    if event is None:
        return None

    refs = _refs(event)
    metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, Mapping) else {}
    canonical_action_id = _reference_value(refs, "canonical_action_id")
    selection_id = _reference_value(refs, "control_selection_id")
    decision_receipt_id = _reference_value(refs, "decision_receipt_id")
    approval_request_id = _reference_value(refs, "approval_request_id")
    approval_binding_id = _reference_value(refs, "approval_binding_id")
    permit_id = _reference_value(refs, "execution_permit_id", "permit_id")
    execution_receipt_id = _reference_value(refs, "execution_receipt_id")
    comparison_id = _reference_value(refs, "execution_comparison_id", "comparison_id")
    effect_id = _reference_value(refs, "persistent_effect_id", "effect_id")
    outcome_id = _reference_value(refs, "outcome_verification_id", "verification_id")

    context_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="context", event_source=True)
    action_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="action")
    control_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="control")
    decision_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="decision")
    approval_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="approval")
    permit_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="permit")
    execution_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="execution")
    comparison_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="comparison")
    effect_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="persistent_effect")
    outcome_evidence = _stage_evidence_ids(db, tenant_id=tenant_id, event=event, refs=refs, stage="outcome")

    context = _observed(
        {
            "source_surface": event.source_surface,
            "chain_id": event.chain_id,
            "correlation_id": event.correlation_id,
            "principal": event.user_id or event.agent_id,
            "event_type": event.event_type,
        },
        evidence_refs=context_evidence,
        occurred_at=event.created_at,
        source_missing_reason="runtime_event_timestamp_not_persisted",
    )

    canonical = metadata.get("canonical_action") if isinstance(metadata.get("canonical_action"), Mapping) else None
    event_declares_action = event.entity_type in {"action", "canonical_action"}
    canonical_matches_event = not event_declares_action or canonical_action_id == _safe_ref(event.entity_id)
    action = (
        _observed(canonical, evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted")
        if canonical_action_id and canonical is not None and canonical_matches_event
        else _unknown("canonical_action_reference_mismatch" if canonical_action_id and not canonical_matches_event else "canonical_action_not_referenced")
    )

    selection = _exact_row(db, NativeControlSelection, tenant_id=tenant_id, field="selection_id", reference=selection_id)
    selection_ok = bool(
        selection is not None
        and canonical_action_id is not None
        and str(selection.action_id) == canonical_action_id
    )
    control_selection = _unknown_unless(
        selection_ok,
        "control_selection_reference_mismatch" if selection_id else "control_selection_not_referenced",
        _observed(
            {
                "selection_id": selection.selection_id if selection is not None else None,
                "control_plan_id": selection.control_plan_id if selection is not None else None,
                "control_plan_digest": selection.control_plan_digest if selection is not None else None,
                "rejected_control_ids": list(getattr(selection, "rejected_control_ids", []) or []),
                "blind_spots": list(getattr(selection, "blind_spots", []) or []),
            },
            evidence_refs=control_evidence,
            occurred_at=selection.selected_at if selection is not None else None,
            source_missing_reason="control_selection_timestamp_not_persisted",
        ),
    )

    policy = (
        _observed(
            {"decision": event.decision, "policy_version_id": event.policy_version_id},
            evidence_refs=decision_evidence,
            occurred_at=event.created_at,
            source_missing_reason="runtime_event_timestamp_not_persisted",
        )
        if event.decision
        else _unknown("policy_decision_not_persisted")
    )

    decision = _exact_row(db, DecisionReceiptV2Extension, tenant_id=tenant_id, field="receipt_id", reference=decision_receipt_id)
    base_decision = _exact_row(db, DecisionReceipt, tenant_id=tenant_id, field="receipt_id", reference=decision_receipt_id)
    decision_ok = bool(
        decision is not None
        and base_decision is not None
        and canonical_action_id is not None
        and decision.action_id == canonical_action_id
        and base_decision.action_id == canonical_action_id
        and (selection_id is None or decision.control_selection_id == selection_id)
    )
    decision_stage = _unknown_unless(
        decision_ok,
        "decision_receipt_reference_mismatch" if decision_receipt_id else "decision_receipt_not_referenced",
        _verified_v2_stage(
            db,
            row=decision,
            purpose="decision_receipt_signing",
            domain=DECISION_RECEIPT_DOMAIN,
            value={
                "receipt_id": decision_receipt_id,
                "action_id": canonical_action_id,
                "policy_epoch": decision.policy_epoch if decision is not None else None,
                "authoritative_decision": decision.authoritative_decision if decision is not None else None,
            },
            evidence_refs=decision_evidence,
            occurred_at=(decision.signed_envelope or {}).get("issued_at") if decision is not None else None,
            displayed_material={
                "receipt_id": "receipt_id",
                "action_id": "action_id",
                "canonical_action_hash": "canonical_action_hash",
                "material_fields_hash": "material_fields_hash",
                "policy_epoch": "policy_epoch",
                "control_plan_digest": "control_plan_digest",
                "expires_at": "expires_at",
                "authoritative_decision": "authoritative_decision",
            },
        ),
    )

    approval = _exact_row(db, ApprovalRequest, tenant_id=tenant_id, field="id", reference=approval_request_id)
    approval_ok = bool(
        approval is not None
        and decision_receipt_id is not None
        and approval.decision_receipt_id == decision_receipt_id
    )
    approval_request = _unknown_unless(
        approval_ok,
        "approval_request_reference_mismatch" if approval_request_id else "approval_request_not_referenced",
        _observed(
            {"approval_request_id": approval_request_id, "status": approval.status if approval is not None else None, "decision_version": approval.decision_version if approval is not None else None},
            evidence_refs=approval_evidence,
            occurred_at=approval.created_at if approval is not None else None,
            source_missing_reason="approval_request_timestamp_not_persisted",
        ),
    )

    binding = _exact_row(db, ApprovalBindingV2Extension, tenant_id=tenant_id, field="binding_id", reference=approval_binding_id)
    binding_ok = bool(
        binding is not None
        and approval_request_id is not None
        and decision_receipt_id is not None
        and binding.approval_request_id == approval_request_id
        and binding.decision_receipt_id == decision_receipt_id
        and (selection_id is None or binding.control_selection_id == selection_id)
    )
    approval_binding = _unknown_unless(
        binding_ok,
        "approval_binding_reference_mismatch" if approval_binding_id else "approval_binding_not_referenced",
        _verified_v2_stage(
            db,
            row=binding,
            purpose="approval_binding_signing",
            domain=BINDING_DOMAIN,
            value={"approval_binding_id": approval_binding_id, "approval_request_id": approval_request_id, "decision_receipt_id": decision_receipt_id, "expires_at": binding.expires_at if binding is not None else None},
            evidence_refs=approval_evidence,
            occurred_at=(binding.signed_envelope or {}).get("issued_at") if binding is not None else None,
            displayed_material={
                "approval_binding_id": "binding_id",
                "approval_request_id": "approval_request_id",
                "decision_receipt_id": "decision_receipt_id",
                "canonical_action_hash": "canonical_action_hash",
                "material_fields_hash": "material_fields_hash",
                "policy_epoch": "policy_epoch",
                "control_plan_digest": "control_plan_digest",
                "expires_at": "expires_at",
            },
        ),
    )

    permit = _exact_row(db, ExecutionPermitV2, tenant_id=tenant_id, field="permit_id", reference=permit_id)
    permit_ok = bool(
        permit is not None
        and canonical_action_id is not None
        and decision_receipt_id is not None
        and permit.action_id == canonical_action_id
        and permit.decision_receipt_id == decision_receipt_id
        and (selection_id is None or permit.control_selection_id == selection_id)
        and (approval_binding_id is None or permit.approval_binding_id == approval_binding_id)
    )
    permit_stage = _unknown_unless(
        permit_ok,
        "execution_permit_reference_mismatch" if permit_id else "execution_permit_not_referenced",
        _verified_v2_stage(
            db,
            row=permit,
            purpose="execution_permit_signing",
            domain=PERMIT_DOMAIN,
            value={"permit_id": permit_id, "attempt_id": permit.attempt_id if permit is not None else None, "action_id": permit.action_id if permit is not None else None, "decision_receipt_id": decision_receipt_id, "policy_epoch": permit.policy_epoch if permit is not None else None},
            evidence_refs=permit_evidence,
            occurred_at=(permit.signed_envelope or {}).get("issued_at") if permit is not None else None,
            displayed_material={
                "permit_id": "permit_id",
                "attempt_id": "attempt_id",
                "action_id": "action_id",
                "canonical_action_hash": "canonical_action_hash",
                "material_fields_hash": "material_fields_hash",
                "decision_receipt_id": "decision_receipt_id",
                "policy_epoch": "policy_epoch",
            },
        ),
    )

    claim = (
        db.scalar(
            select(ExecutionPermitTransitionV2)
            .where(
                ExecutionPermitTransitionV2.tenant_id == tenant_id,
                ExecutionPermitTransitionV2.permit_id == permit_id,
                ExecutionPermitTransitionV2.to_state == "CLAIMED",
            )
            .order_by(ExecutionPermitTransitionV2.sequence.asc())
            .limit(1)
        )
        if permit_ok and permit_id is not None
        else None
    )
    claim_stage = (
        _verified_v2_stage(
            db,
            row=claim,
            purpose="execution_permit_signing",
            domain=TRANSITION_DOMAIN,
            value={"claim_id": claim.claim_id if claim is not None else None, "permit_id": permit_id, "sequence": claim.sequence if claim is not None else None, "to_state": claim.to_state if claim is not None else None},
            evidence_refs=execution_evidence,
            occurred_at=(claim.signed_envelope or {}).get("observed_at") if claim is not None else None,
            displayed_material={
                "permit_id": "permit_id",
                "claim_id": "claim_id",
                "sequence": "sequence",
                "to_state": "to_state",
            },
        )
        if claim is not None
        else _unknown("execution_permit_not_claimed")
    )

    attempt = _exact_row(db, ExecutionPermitAttemptV2, tenant_id=tenant_id, field="attempt_id", reference=permit.attempt_id if permit_ok and permit is not None else None)
    attempt_stage = _unknown_unless(
        bool(
            attempt is not None
            and permit is not None
            and decision_receipt_id is not None
            and attempt.action_id == permit.action_id
            and attempt.canonical_action_hash == permit.canonical_action_hash
            and attempt.material_fields_hash == permit.material_fields_hash
            and attempt.decision_receipt_id == decision_receipt_id
            and attempt.execution_permit_id == permit.permit_id
        ),
        "execution_attempt_not_persisted",
        _observed(
            {"attempt_id": attempt.attempt_id if attempt is not None else None, "status": attempt.status if attempt is not None else None},
            evidence_refs=execution_evidence,
            occurred_at=attempt.created_at if attempt is not None else None,
            source_missing_reason="execution_attempt_timestamp_not_persisted",
        ),
    )

    receipt = _exact_row(db, ExecutionReceiptV2Extension, tenant_id=tenant_id, field="receipt_id", reference=execution_receipt_id)
    receipt_ok = bool(receipt is not None and permit is not None and receipt.permit_id == permit.permit_id and receipt.attempt_id == permit.attempt_id)
    receipt_stage = _unknown_unless(
        receipt_ok,
        "execution_receipt_reference_mismatch" if execution_receipt_id else "execution_receipt_not_referenced",
        _verified_v2_stage(
            db,
            row=receipt,
            purpose="execution_receipt_signing",
            domain=EXECUTION_RECEIPT_DOMAIN,
            value={"receipt_id": execution_receipt_id, "attempt_id": receipt.attempt_id if receipt is not None else None, "permit_id": receipt.permit_id if receipt is not None else None, "terminal_state": receipt.terminal_state if receipt is not None else None, "evidence_quality": receipt.evidence_quality if receipt is not None else None},
            evidence_refs=execution_evidence,
            occurred_at=(receipt.signed_envelope or {}).get("issued_at") if receipt is not None else None,
            displayed_material={
                "receipt_id": "receipt_id",
                "attempt_id": "attempt_id",
                "permit_id": "permit_id",
                "canonical_action_hash": "canonical_action_hash",
                "actual_material_fields_hash": "actual_material_fields_hash",
                "terminal_state": "terminal_state",
                "evidence_quality": "evidence_quality",
            },
        ),
    )

    comparison = _exact_row(db, ExecutionComparisonV2, tenant_id=tenant_id, field="id", reference=comparison_id)
    comparison_ok = bool(
        comparison is not None
        and decision_receipt_id is not None
        and execution_receipt_id is not None
        and comparison.decision_receipt_id == decision_receipt_id
        and comparison.execution_receipt_id == execution_receipt_id
        and permit is not None
        and comparison.attempt_id == permit.attempt_id
    )
    comparison_stage = _unknown_unless(
        comparison_ok,
        "execution_comparison_reference_mismatch" if comparison_id else "execution_comparison_not_referenced",
        _verified_v2_stage(
            db,
            row=comparison,
            purpose="execution_comparison_signing",
            domain=EXECUTION_COMPARISON_DOMAIN,
            value={"comparison_id": comparison.id if comparison is not None else None, "result": comparison.result if comparison is not None else None, "drift_fields": comparison.material_differences if comparison is not None else None, "unresolved_fields": comparison.unresolved_fields if comparison is not None else None},
            evidence_refs=comparison_evidence,
            occurred_at=(comparison.signed_envelope or {}).get("issued_at") if comparison is not None else None,
            displayed_material={
                "comparison_id": "id",
                "attempt_id": "attempt_id",
                "result": "result",
                "drift_fields": "material_differences",
                "unresolved_fields": "unresolved_fields",
            },
        ),
    )

    effect = _exact_row(db, PersistentEffectV2, tenant_id=tenant_id, field="id", reference=effect_id)
    effect_ok = bool(effect is not None and permit is not None and effect.action_id == permit.action_id and effect.attempt_id == permit.attempt_id and (execution_receipt_id is None or effect.execution_receipt_id == execution_receipt_id))
    effect_stage = _unknown_unless(
        effect_ok,
        "persistent_effect_reference_mismatch" if effect_id else "persistent_effect_not_referenced",
        _verified_v2_stage(
            db,
            row=effect,
            purpose="persistent_effect_signing",
            domain=EFFECT_DOMAIN,
            value={"effect_id": effect.id if effect is not None else None, "state": effect.state if effect is not None else None, "attempt_id": effect.attempt_id if effect is not None else None},
            evidence_refs=effect_evidence,
            occurred_at=(effect.signed_envelope or {}).get("issued_at") if effect is not None else None,
            displayed_material={
                "effect_id": "id",
                "action_id": "action_id",
                "attempt_id": "attempt_id",
                "execution_receipt_id": "execution_receipt_id",
                "downstream_object_hash": "downstream_object_hash",
                "expected_object_state_hash": "expected_object_state_hash",
                "state": "state",
                "state_version": "state_version",
            },
        ),
    )

    outcome = _exact_row(db, OutcomeVerificationV2, tenant_id=tenant_id, field="verification_id", reference=outcome_id)
    outcome_ok = bool(outcome is not None and permit is not None and outcome.action_id == permit.action_id and outcome.attempt_id == permit.attempt_id and (execution_receipt_id is None or outcome.execution_receipt_id == execution_receipt_id))
    outcome_stage = _unknown_unless(
        outcome_ok,
        "outcome_verification_reference_mismatch" if outcome_id else "outcome_verification_not_referenced",
        _verified_v2_stage(
            db,
            row=outcome,
            purpose="outcome_verification_signing",
            domain=OUTCOME_DOMAIN,
            value={"verification_id": outcome.verification_id if outcome is not None else None, "result": outcome.result if outcome is not None else None, "attempt_id": outcome.attempt_id if outcome is not None else None},
            evidence_refs=outcome_evidence,
            occurred_at=outcome.evaluated_at if outcome is not None else None,
            displayed_material={
                "verification_id": "verification_id",
                "action_id": "action_id",
                "attempt_id": "attempt_id",
                "outcome_contract_id": "outcome_contract_id",
                "execution_receipt_id": "execution_receipt_id",
                "result": "result",
                "verification_source_set_hash": "verification_source_set_hash",
                "evidence_quality": "evidence_quality",
                "evaluated_at": "evaluated_at",
            },
        ),
    )

    canonical_map = dict(canonical or {}) if action["state"] == "OBSERVED" else {}
    semantic_map = dict(canonical_map.get("action_semantics") or {}) if isinstance(canonical_map.get("action_semantics"), Mapping) else {}
    actor_stage = _observed(canonical_map.get("actor_principal"), evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted") if canonical_map.get("actor_principal") else _unknown("actor_not_persisted")
    represented_stage = _observed(canonical_map.get("represented_subjects"), evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted") if canonical_map.get("represented_subjects") else _unknown("represented_subjects_not_persisted")
    purpose_stage = _observed(canonical_map.get("business_purpose"), evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted") if canonical_map.get("business_purpose") else _unknown("business_purpose_not_persisted")
    domain_stage = _observed({"domain_profile_ref": canonical_map.get("domain_profile_ref"), "domain_profile_hash": canonical_map.get("domain_profile_hash")}, evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted") if canonical_map.get("domain_profile_ref") and canonical_map.get("domain_profile_hash") else _unknown("domain_semantics_not_persisted")

    def canonical_field(*names: str) -> dict[str, Any]:
        for name in names:
            if name in canonical_map and canonical_map[name] is not None:
                return _observed(canonical_map[name], evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted")
            if name in semantic_map and semantic_map[name] is not None:
                return _observed(semantic_map[name], evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted")
        return _unknown("canonical_action_field_not_persisted")

    def canonical_list_field(*names: str) -> dict[str, Any]:
        for name in names:
            if name in canonical_map and isinstance(canonical_map[name], list):
                return _observed(canonical_map[name], evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted")
            if name in semantic_map and isinstance(semantic_map[name], list):
                return _observed(semantic_map[name], evidence_refs=action_evidence, occurred_at=event.created_at, source_missing_reason="runtime_event_timestamp_not_persisted")
        return _unknown_array("canonical_action_list_field_not_persisted")

    def as_singleton_list(observation: Mapping[str, Any]) -> dict[str, Any]:
        if observation["state"] != "OBSERVED":
            return _unknown_array(str(observation["reason_code"] or "authority_not_persisted"))
        return _observed(
            [observation["value"]], evidence_refs=list(observation["evidence_refs"]), occurred_at=observation["occurred_at"],
            source_missing_reason="authority_timestamp_not_persisted",
        )

    def selection_field(value: Any) -> dict[str, Any]:
        if not selection_ok or selection is None:
            return _unknown("control_selection_not_referenced")
        return _observed(value, evidence_refs=control_evidence, occurred_at=selection.selected_at, source_missing_reason="control_selection_timestamp_not_persisted")

    def selection_list_field(value: Any) -> dict[str, Any]:
        return _array_card(selection_field(value))

    # §12 has fixed card names and cardinality.  The individual cards below
    # retain the same evidence gate as the original source fact.
    context_cards = {
        "actor_principal": canonical_field("actor_principal"),
        "executing_identity": canonical_field("executing_identity", "executing_principal"),
        "represented_subjects": canonical_list_field("represented_subjects"),
        "business_purpose": canonical_field("business_purpose"),
        "authority": canonical_field("authority", "authority_context", "authority_ref"),
        "delegation": canonical_field("delegation"),
    }
    action_cards = {
        "operation": canonical_field("operation", "action_type"),
        "tool_or_service": canonical_field("tool_or_service", "tool_or_service_ref", "tool", "service"),
        "safe_parameters": canonical_field("safe_parameters", "redacted_parameters"),
        "resources": canonical_list_field("resources", "resource_refs", "resource_scopes"),
        "targets": canonical_list_field("targets", "target_refs"),
        "destinations": canonical_list_field("destinations", "destination_refs"),
        "values_or_quantities": canonical_list_field("values_or_quantities"),
        "side_effect": canonical_field("side_effect"),
        "persistence": canonical_field("persistence"),
        "reversibility": canonical_field("reversibility"),
    }
    control_cards = {
        "requirements": selection_list_field(selection.required_capabilities if selection is not None else None),
        "control_plan": selection_field({"control_plan_id": selection.control_plan_id, "control_plan_digest": selection.control_plan_digest} if selection is not None else None),
        "mandatory_floors": selection_list_field(selection.mandatory_enforcement_floor_requirements if selection is not None else None),
        "assurance": selection_field(selection.assurance_level if selection is not None else None),
        "rejected_controls": selection_list_field(selection.rejected_candidates if selection is not None else None),
        "blind_spots": selection_list_field(selection.known_blind_spots if selection is not None else None),
    }
    authorisation_cards = {
        "policy": policy,
        "decision": decision_stage,
        "approval_request": approval_request,
        "approval_binding": approval_binding,
        "decision_receipt": decision_stage,
        "execution_permits": _array_card(as_singleton_list(permit_stage)),
    }
    execution_cards = {
        "observed_semantics": receipt_stage if receipt_stage["state"] == "OBSERVED" else attempt_stage,
        "execution_receipts": _array_card(as_singleton_list(receipt_stage)),
        "evidence_quality": _observed(
            receipt.evidence_quality if receipt is not None else None,
            evidence_refs=execution_evidence,
            occurred_at=(receipt.signed_envelope or {}).get("issued_at") if receipt is not None else None,
            source_missing_reason="execution_receipt_timestamp_not_persisted",
        ) if receipt_stage["state"] == "OBSERVED" else _unknown(receipt_stage["reason_code"]),
        "material_integrity": comparison_stage,
        "execution_state": _observed(
            receipt.terminal_state if receipt is not None else None,
            evidence_refs=execution_evidence,
            occurred_at=(receipt.signed_envelope or {}).get("issued_at") if receipt is not None else None,
            source_missing_reason="execution_receipt_timestamp_not_persisted",
        ) if receipt_stage["state"] == "OBSERVED" else _unknown(receipt_stage["reason_code"]),
        "drift_fields": _array_card(_observed(
            comparison.material_differences if comparison is not None else None,
            evidence_refs=comparison_evidence,
            occurred_at=(comparison.signed_envelope or {}).get("issued_at") if comparison is not None else None,
            source_missing_reason="execution_comparison_timestamp_not_persisted",
        ) if comparison_stage["state"] == "OBSERVED" else _unknown_array(str(comparison_stage["reason_code"] or "authority_not_persisted"))),
        "outcome_integrity": outcome_stage,
    }

    # Outcome verification proves an outcome only.  A distinct durable target
    # confirmation authority is not yet part of the approved model, so this
    # stage deliberately remains unknown rather than borrowing outcome proof.
    target_confirmation = _unknown(
        "target_confirmation_authority_not_referenced"
        if _reference_value(refs, "target_confirmation_id") is None
        else "target_confirmation_authority_unsupported"
    )

    timeline_sources: tuple[tuple[str, Mapping[str, Any], str], ...] = (
        ("REQUEST", context, _stage_source_ref(context, event.event_id, "runtime_event")),
        ("ACTOR_RESOLUTION", actor_stage, _stage_source_ref(actor_stage, canonical_action_id, "canonical_action")),
        ("REPRESENTED_SUBJECT_RESOLUTION", represented_stage, _stage_source_ref(represented_stage, canonical_action_id, "canonical_action")),
        ("PURPOSE", purpose_stage, _stage_source_ref(purpose_stage, canonical_action_id, "canonical_action")),
        ("PROPOSED_ACTION", action, _stage_source_ref(action, canonical_action_id, "canonical_action")),
        ("DOMAIN_SEMANTICS", domain_stage, _stage_source_ref(domain_stage, canonical_action_id, "canonical_action")),
        ("POLICY", policy, _stage_source_ref(policy, event.event_id, "runtime_event")),
        ("APPROVAL", approval_binding if approval_binding["state"] == "OBSERVED" else approval_request, _stage_source_ref(approval_binding if approval_binding["state"] == "OBSERVED" else approval_request, approval_binding_id if approval_binding["state"] == "OBSERVED" else approval_request_id, "approval")),
        ("PERMIT", permit_stage, _stage_source_ref(permit_stage, permit_id, "execution_permit")),
        ("EXECUTION", receipt_stage if receipt_stage["state"] == "OBSERVED" else attempt_stage, _stage_source_ref(receipt_stage if receipt_stage["state"] == "OBSERVED" else attempt_stage, execution_receipt_id if receipt_stage["state"] == "OBSERVED" else (permit.attempt_id if permit is not None else None), "execution")),
        ("TARGET_CONFIRMATION", target_confirmation, ""),
        ("COMPARISON", comparison_stage, _stage_source_ref(comparison_stage, comparison_id, "execution_comparison")),
        ("OUTCOME", outcome_stage, _stage_source_ref(outcome_stage, outcome_id, "outcome_verification")),
        ("PERSISTENT_EFFECT", effect_stage, _stage_source_ref(effect_stage, effect_id, "persistent_effect")),
    )
    explicit_timeline = refs.get("timeline_events")
    explicit_by_stage: dict[str, list[Mapping[str, Any]]] = {}
    if isinstance(explicit_timeline, list):
        for item in explicit_timeline:
            if isinstance(item, Mapping) and item.get("stage") in TIMELINE_STAGES:
                explicit_by_stage.setdefault(str(item["stage"]), []).append(item)

    timeline: list[dict[str, Any]] = []
    for ordinal, (stage, observation, source_ref) in enumerate(timeline_sources, start=1):
        entries = explicit_by_stage.get(stage, [])
        # The primary durable authority for this stage is never replaced by
        # supplemental history.  Extra signed transitions append beside it.
        timeline.append(_timeline_item(event=event, ordinal=ordinal, stage=stage, observation=observation, source_ref=source_ref))
        if not entries:
            continue
        # A stage can intentionally have multiple independently durable events.
        # Only the explicit execution-transition form is currently modeled; all
        # other unrecognized forms remain explicit unknowns, not raw metadata.
        for index, entry in enumerate(entries):
            if stage == "EXECUTION":
                timeline.append(_explicit_execution_transition_item(db, tenant_id=tenant_id, event=event, ordinal=ordinal, entry=entry, permit=permit))
            else:
                unknown = _unknown("timeline_authority_type_unsupported")
                timeline.append(_timeline_item(
                    event=event, ordinal=ordinal, stage=stage, observation=unknown, source_ref="",
                    timeline_event_id=f"{event.event_id}:{stage}:unsupported:{index}",
                    sequence=entry.get("sequence") if isinstance(entry.get("sequence"), int) and entry.get("sequence") >= 0 else 0,
                ))
    timeline.sort(key=lambda item: (
        item["stage_ordinal"], item["sequence"],
        item["occurred_at"] is None, item["occurred_at"] or "", item["timeline_event_id"],
    ))
    identity = {
        "runtime_event_id": event.event_id,
        "tenant_id": event.tenant_id,
        "canonical_action_id": canonical_action_id,
        "action_id": canonical_action_id,
        "chain_id": event.chain_id,
        "decision_receipt_id": decision_receipt_id,
        "execution_receipt_ids": [execution_receipt_id] if execution_receipt_id else [],
        "control_selection_action_id": canonical_action_id if selection_ok else None,
        "control_plan_id": selection.control_plan_id if selection_ok else None,
        "approval_request_id": approval_request_id,
        "approval_binding_id": approval_binding_id,
        "execution_permit_ids": [permit_id] if permit_id else [],
        "evidence_node_ids": sorted({item for stage in timeline for item in stage["evidence_node_ids"]}),
        "finding_ids": _safe_ref_list(refs.get("finding_ids")),
    }
    encoded_runtime_event_id = quote(event.event_id, safe="")
    return {
        "schema_version": "1.0",
        "identity": identity,
        "context": context_cards,
        "action": action_cards,
        "control": control_cards,
        "authorisation": authorisation_cards,
        "execution": execution_cards,
        "timeline": timeline,
        "api_references": [{"relation": "ACTION_DETAIL", "authority_type": "ActionIntegrityDetail", "authority_id": event.event_id, "method": "GET", "api_path": f"/action-integrity/actions/{encoded_runtime_event_id}"}],
        "browser_hrefs": [{"relation": "ACTION_DETAIL", "route_key_type": "runtime_event_id", "route_key": event.event_id, "href": f"/runtime-intelligence/action-trace/{encoded_runtime_event_id}"}],
    }


def materialize_action_detail(db: Session, *, tenant_id: str, runtime_event_id: str) -> dict[str, Any] | None:
    """Compatibility name for the composed read; it persists no UI authority."""
    return build_action_detail(db, tenant_id=tenant_id, runtime_event_id=runtime_event_id)
