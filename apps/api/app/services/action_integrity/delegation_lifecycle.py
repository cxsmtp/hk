"""Fail-closed V1 delegation context folds and append-only lifecycle events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import DelegationContextV2, DelegationLifecycleEventV2

from .canonical_v2 import domain_hash
from .signing import SigningKeyProvider, active_key_id, sign_object, verify_signed_object


DELEGATION_CONTEXT_DOMAIN = "hawk:delegation-context:v2"
DELEGATION_EVENT_DOMAIN = "hawk:delegation-lifecycle-event:v1"
DELEGATION_SIGNING_PURPOSE = "delegation_context_signing"
_TERMINAL_STATES = {"REVOKED", "EXPIRED"}
_MAX_DELEGATION_ANCESTRY_DEPTH = 64
_LEGAL_EVENTS = {
    ("REGISTERED", "ISSUED", "ACTIVE"),
    ("REGISTERED", "REVOKED", "REVOKED"),
    ("REGISTERED", "EXPIRED", "EXPIRED"),
    ("ACTIVE", "REVOKED", "REVOKED"),
    ("ACTIVE", "EXPIRED", "EXPIRED"),
}


@dataclass(frozen=True, slots=True)
class DelegationLifecycleFold:
    state: str
    state_version: int
    history_head_event_id: str | None
    history_head_event_hash: str | None
    history_head_sequence: int


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _same_instant(left: object, right: object) -> bool:
    if isinstance(left, datetime) and isinstance(right, datetime):
        return _utc(left) == _utc(right)
    if isinstance(left, datetime) and isinstance(right, str):
        try:
            return _utc(left) == _utc(datetime.fromisoformat(right.replace("Z", "+00:00")))
        except ValueError:
            return False
    return left == right


def canonical_delegation_scope_v1(scope: object) -> dict[str, object]:
    """Return the bounded V1 delegation scope used in signed lineage.

    The scope is deliberately small and deterministic.  It is authority
    material, not advisory metadata: descendants must be bounded by this
    signed effective scope rather than a caller-supplied re-description.
    """
    if not isinstance(scope, dict):
        raise ValueError("delegation scope is invalid")
    try:
        resources = sorted({str(value) for value in scope["resources"] if str(value)})
        operations = sorted({str(value) for value in scope["operations"] if str(value)})
        max_value = Decimal(str(scope["max_value"]))
    except (KeyError, TypeError, InvalidOperation) as exc:
        raise ValueError("delegation scope is invalid") from exc
    if not resources or not operations or not max_value.is_finite() or max_value < 0:
        raise ValueError("delegation scope is invalid")
    return {
        "resources": resources,
        "operations": operations,
        "max_value": format(max_value.normalize(), "f"),
    }


def intersect_delegation_scopes_v1(
    parent_scope: object, child_scope: object,
) -> dict[str, object]:
    """Return the non-widening authority intersection for one delegation edge."""
    parent = canonical_delegation_scope_v1(parent_scope)
    child = canonical_delegation_scope_v1(child_scope)
    resources = sorted(set(parent["resources"]).intersection(child["resources"]))
    operations = sorted(set(parent["operations"]).intersection(child["operations"]))
    maximum = min(Decimal(str(parent["max_value"])), Decimal(str(child["max_value"])))
    if not resources or not operations:
        raise PermissionError("delegated child widens parent authority")
    return {
        "resources": resources,
        "operations": operations,
        "max_value": format(maximum.normalize(), "f"),
    }


def _invalid(context: DelegationContextV2, message: str) -> None:
    context.reconstruction_status = "INVALID"
    raise PermissionError(message)


def _verify_historical_lineage_signature(
    context: DelegationContextV2,
    *,
    provider: SigningKeyProvider,
    domain: str,
    envelope: dict[str, Any],
    label: str,
) -> None:
    """Keep cryptographic reconstruction separate from present eligibility."""
    if not verify_signed_object(
        provider,
        purpose=DELEGATION_SIGNING_PURPOSE,
        domain=domain,
        tenant_id=context.tenant_id,
        value=envelope,
        current_authority=False,
    ):
        _invalid(context, f"{label} signature is invalid")
    key_id = envelope.get("signing_key_id")
    try:
        metadata = provider.metadata(
            purpose=DELEGATION_SIGNING_PURPOSE,
            tenant_id=context.tenant_id,
            key_id=str(key_id),
        )
    except (KeyError, ValueError):
        _invalid(context, f"{label} signing key is unavailable")
    if metadata.get("state") == "revoked":
        _invalid(context, f"{label} signing key is revoked")


def _verify_context(context: DelegationContextV2, *, provider: SigningKeyProvider) -> None:
    if context.lineage_binding_version != 1:
        _invalid(context, "legacy delegation context is ineligible")
    envelope = dict(context.signed_envelope or {})
    _verify_historical_lineage_signature(
        context,
        provider=provider,
        domain=DELEGATION_CONTEXT_DOMAIN,
        envelope=envelope,
        label="delegation context",
    )
    try:
        effective_scope = canonical_delegation_scope_v1(envelope.get("effective_scope"))
    except ValueError:
        _invalid(context, "delegation context has no valid effective scope")
        return
    if not (
        envelope.get("schema_version") == "2.1"
        and envelope.get("lineage_binding_version") == 1
        and envelope.get("delegation_context_id") == context.delegation_context_id
        and envelope.get("tenant_id") == context.tenant_id
        and envelope.get("parent_action_id") == context.parent_action_id
        and envelope.get("delegated_action_id") == context.delegated_action_id
        and envelope.get("parent_delegation_ref") == context.parent_delegation_context_id
        and envelope.get("source_principal_ref") == context.source_principal_ref
        and envelope.get("destination_principal_ref") == context.destination_principal_ref
        and envelope.get("authority_scope_hash") == context.authority_scope_hash
        and domain_hash("hawk:delegated-scope:v1", effective_scope) == context.authority_scope_hash
        and envelope.get("effective_scope") == effective_scope
        and envelope.get("depth") == context.depth
        and envelope.get("state") == "REGISTERED"
        and envelope.get("state_version") == 0
        and _same_instant(context.expires_at, envelope.get("expires_at"))
        and envelope.get("algorithm") == context.algorithm
        and envelope.get("signing_key_id") == context.signing_key_id
        and envelope.get("signature") == context.signature
    ):
        _invalid(context, "delegation context projection does not match signed lineage")
    if context.parent_delegation_context_id is None:
        if context.depth != 1:
            _invalid(context, "root delegation context has invalid depth")
    elif context.depth <= 1 or context.parent_delegation_context_id == context.delegation_context_id:
        _invalid(context, "delegation context lineage is invalid")


def fresh_delegation_context_fold(
    db: Session,
    *,
    provider: SigningKeyProvider,
    context: DelegationContextV2,
) -> DelegationLifecycleFold:
    """Reconstruct the context projection from its signed immutable chain."""
    _verify_context(context, provider=provider)
    events = list(
        db.scalars(
            select(DelegationLifecycleEventV2)
            .where(
                DelegationLifecycleEventV2.tenant_id == context.tenant_id,
                DelegationLifecycleEventV2.delegation_context_id == context.delegation_context_id,
            )
            .order_by(DelegationLifecycleEventV2.sequence.asc())
            .with_for_update()
        ).all()
    )
    state, state_version = "REGISTERED", 0
    prior_id: str | None = None
    prior_hash: str | None = None
    for sequence, event in enumerate(events, start=1):
        envelope = dict(event.signed_envelope or {})
        _verify_historical_lineage_signature(
            context,
            provider=provider,
            domain=DELEGATION_EVENT_DOMAIN,
            envelope=envelope,
            label="delegation lifecycle",
        )
        if (state, event.event_type, event.to_state) not in _LEGAL_EVENTS:
            _invalid(context, "delegation lifecycle edge is invalid")
        if event.event_type == "ISSUED" and sequence != 1:
            _invalid(context, "delegation issue is only valid as the first event")
        affected = list(event.affected_unconsumed_descendant_refs or [])
        if event.event_type != "REVOKED" and affected:
            _invalid(context, "only revocation may name descendants")
        if affected != sorted(set(affected)):
            _invalid(context, "delegation descendant references are not deterministic")
        same_row = (
            envelope.get("schema_version") == "2.1"
            and envelope.get("event_id") == event.id
            and envelope.get("tenant_id") == event.tenant_id == context.tenant_id
            and envelope.get("delegation_context_id") == event.delegation_context_id == context.delegation_context_id
            and envelope.get("sequence") == event.sequence == sequence
            and envelope.get("prior_event_id") == event.prior_event_id == prior_id
            and envelope.get("prior_event_hash") == event.prior_event_hash == prior_hash
            and envelope.get("from_state") == event.from_state == state
            and envelope.get("to_state") == event.to_state
            and envelope.get("prior_state_version") == event.prior_state_version == state_version
            and envelope.get("new_state_version") == event.new_state_version == state_version + 1
            and envelope.get("event_type") == event.event_type
            and envelope.get("affected_unconsumed_descendant_refs") == affected
            and envelope.get("reason_code") == event.reason_code
            and envelope.get("idempotency_key") == event.idempotency_key
            and _same_instant(event.observed_at, envelope.get("observed_at"))
            and envelope.get("evidence_refs") == list(event.evidence_refs or [])
            and envelope.get("algorithm") == event.algorithm
            and envelope.get("signing_key_id") == event.signing_key_id
            and envelope.get("signature") == event.signature
        )
        if not same_row:
            _invalid(context, "delegation lifecycle projection does not match signed event")
        state, state_version = event.to_state, event.new_state_version
        prior_id = event.id
        prior_hash = domain_hash("hawk:delegation-lifecycle-event-envelope-hash:v1", envelope)
        if state in _TERMINAL_STATES and sequence != len(events):
            _invalid(context, "delegation lifecycle continues after a terminal state")
    fold = DelegationLifecycleFold(state, state_version, prior_id, prior_hash, len(events))
    if not (
        context.state == fold.state
        and context.state_version == fold.state_version
        and context.history_head_event_id == fold.history_head_event_id
        and context.history_head_event_hash == fold.history_head_event_hash
        and context.history_head_sequence == fold.history_head_sequence
        and context.reconstruction_status == "VERIFIED"
    ):
        _invalid(context, "delegation lifecycle cache does not match its history")
    return fold


def _locked_context(
    db: Session,
    *,
    tenant_id: str,
    delegation_context_id: str,
) -> DelegationContextV2:
    context = db.scalar(
        select(DelegationContextV2)
        .where(
            DelegationContextV2.tenant_id == tenant_id,
            DelegationContextV2.delegation_context_id == delegation_context_id,
        )
        .with_for_update()
    )
    if context is None:
        raise PermissionError("delegation context is not available for this tenant")
    return context


def require_active_delegation_ancestry(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    delegation_context_id: str,
    now: datetime,
) -> DelegationContextV2:
    """Lock and verify a complete active parent lineage without cycles."""
    now = _utc(now)
    seen: set[str] = set()
    current_id: str | None = delegation_context_id
    lineage_ids: list[str] = []
    # Parent/delegated-action IDs are immutable V1 material.  Discover the
    # ancestry first, then acquire locks root-to-leaf so a claim follows the
    # same context-before-permit order as ancestor revocation.
    while current_id is not None:
        if current_id in seen:
            raise PermissionError("delegation ancestry contains a cycle")
        if len(lineage_ids) >= _MAX_DELEGATION_ANCESTRY_DEPTH:
            raise PermissionError("delegation ancestry exceeds the maximum depth")
        seen.add(current_id)
        lineage_ids.append(current_id)
        context = db.scalar(
            select(DelegationContextV2).where(
                DelegationContextV2.tenant_id == tenant_id,
                DelegationContextV2.delegation_context_id == current_id,
            )
        )
        if context is None:
            raise PermissionError("delegation context is not available for this tenant")
        current_id = context.parent_delegation_context_id

    locked: dict[str, DelegationContextV2] = {}
    for context_id in reversed(lineage_ids):
        context = _locked_context(db, tenant_id=tenant_id, delegation_context_id=context_id)
        locked[context_id] = context
        fold = fresh_delegation_context_fold(db, provider=provider, context=context)
        if fold.state != "ACTIVE" or now >= _utc(context.expires_at):
            raise PermissionError("delegation ancestry is inactive, expired, or revoked")
    for child_id, parent_id in zip(lineage_ids, lineage_ids[1:]):
        child, parent = locked[child_id], locked[parent_id]
        if child.parent_action_id != parent.delegated_action_id or child.depth != parent.depth + 1:
            _invalid(child, "delegation ancestry parent binding is invalid")
    return locked[delegation_context_id]


def require_active_delegated_action_authority(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    delegated_action_id: str,
    now: datetime,
) -> DelegationContextV2 | None:
    """Require current lineage only when an action has a registered V1 edge."""
    # This is immutable V1 identity discovery only.  Do not lock the leaf
    # here: require_active_delegation_ancestry acquires the entire lineage in
    # deterministic root-to-leaf order, matching revocation.
    context = db.scalar(
        select(DelegationContextV2)
        .where(
            DelegationContextV2.tenant_id == tenant_id,
            DelegationContextV2.delegated_action_id == delegated_action_id,
        )
    )
    if context is None:
        return None
    return require_active_delegation_ancestry(
        db,
        provider=provider,
        tenant_id=tenant_id,
        delegation_context_id=context.delegation_context_id,
        now=now,
    )


def _append_event(
    db: Session,
    *,
    provider: SigningKeyProvider,
    context: DelegationContextV2,
    fold: DelegationLifecycleFold,
    event_type: str,
    to_state: str,
    affected_unconsumed_descendant_refs: list[str],
    reason_code: str | None,
    observed_at: datetime,
    evidence_refs: list[str] | None = None,
) -> DelegationLifecycleEventV2:
    if (fold.state, event_type, to_state) not in _LEGAL_EVENTS:
        raise PermissionError("illegal delegation lifecycle transition")
    if event_type == "ISSUED" and fold.history_head_sequence != 0:
        raise PermissionError("delegation issue is only valid as the first event")
    if event_type != "REVOKED" and affected_unconsumed_descendant_refs:
        raise PermissionError("only revocation may name descendants")
    affected = sorted(set(affected_unconsumed_descendant_refs))
    event_id = str(uuid4())
    key_id = active_key_id(provider, purpose=DELEGATION_SIGNING_PURPOSE, tenant_id=context.tenant_id)
    envelope = sign_object(
        provider,
        purpose=DELEGATION_SIGNING_PURPOSE,
        domain=DELEGATION_EVENT_DOMAIN,
        tenant_id=context.tenant_id,
        key_id=key_id,
        value={
            "schema_version": "2.1",
            "event_id": event_id,
            "tenant_id": context.tenant_id,
            "delegation_context_id": context.delegation_context_id,
            "sequence": fold.history_head_sequence + 1,
            "prior_event_id": fold.history_head_event_id,
            "prior_event_hash": fold.history_head_event_hash,
            "from_state": fold.state,
            "to_state": to_state,
            "prior_state_version": fold.state_version,
            "new_state_version": fold.state_version + 1,
            "event_type": event_type,
            "affected_unconsumed_descendant_refs": affected,
            "reason_code": reason_code,
            "idempotency_key": f"delegation:{event_type.lower()}:{event_id}",
            "observed_at": _utc(observed_at).isoformat(),
            "evidence_refs": list(evidence_refs or []),
        },
    )
    event = DelegationLifecycleEventV2(
        id=event_id,
        tenant_id=context.tenant_id,
        delegation_context_id=context.delegation_context_id,
        sequence=fold.history_head_sequence + 1,
        event_type=event_type,
        from_state=fold.state,
        to_state=to_state,
        prior_state_version=fold.state_version,
        new_state_version=fold.state_version + 1,
        prior_event_id=fold.history_head_event_id,
        prior_event_hash=fold.history_head_event_hash,
        affected_unconsumed_descendant_refs=affected,
        idempotency_key=str(envelope["idempotency_key"]),
        reason_code=reason_code,
        observed_at=_utc(observed_at),
        evidence_refs=list(evidence_refs or []),
        algorithm=str(envelope["algorithm"]),
        signing_key_id=str(envelope["signing_key_id"]),
        signature=str(envelope["signature"]),
        signed_envelope=envelope,
    )
    db.add(event)
    context.state = to_state
    context.state_version = fold.state_version + 1
    context.history_head_event_id = event_id
    context.history_head_event_hash = domain_hash("hawk:delegation-lifecycle-event-envelope-hash:v1", envelope)
    context.history_head_sequence = fold.history_head_sequence + 1
    return event


def issue_delegation_context_v2(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    delegation_context_id: str,
    observed_at: datetime,
) -> DelegationContextV2:
    """Activate a freshly verified V1 context after its complete ancestry is live."""
    now = _utc(observed_at)
    discovered = db.scalar(
        select(DelegationContextV2).where(
            DelegationContextV2.tenant_id == tenant_id,
            DelegationContextV2.delegation_context_id == delegation_context_id,
        )
    )
    if discovered is None:
        raise PermissionError("delegation context is not available for this tenant")
    parent: DelegationContextV2 | None = None
    if discovered.parent_delegation_context_id is not None:
        # Acquire ancestors before the child context to match the lock ordering
        # used by registration, claims, and ancestor revocation.
        parent = require_active_delegation_ancestry(
            db,
            provider=provider,
            tenant_id=tenant_id,
            delegation_context_id=discovered.parent_delegation_context_id,
            now=now,
        )
    context = _locked_context(db, tenant_id=tenant_id, delegation_context_id=delegation_context_id)
    fold = fresh_delegation_context_fold(db, provider=provider, context=context)
    if fold.state != "REGISTERED" or now >= _utc(context.expires_at):
        raise PermissionError("delegation context is expired or no longer issuable")
    if parent is not None:
        if parent.delegated_action_id != context.parent_action_id or context.depth != parent.depth + 1:
            _invalid(context, "delegation parent lineage does not bind this child")
    _append_event(
        db,
        provider=provider,
        context=context,
        fold=fold,
        event_type="ISSUED",
        to_state="ACTIVE",
        affected_unconsumed_descendant_refs=[],
        reason_code="delegation_issued",
        observed_at=now,
    )
    return context


def _lock_descendants(
    db: Session,
    *,
    tenant_id: str,
    root: DelegationContextV2,
) -> list[DelegationContextV2]:
    """Lock the exact descendant tree breadth-first in deterministic order."""
    ordered = [root]
    seen = {root.delegation_context_id}
    frontier = [root.delegation_context_id]
    while frontier:
        descendants = list(
            db.scalars(
                select(DelegationContextV2)
                .where(
                    DelegationContextV2.tenant_id == tenant_id,
                    DelegationContextV2.parent_delegation_context_id.in_(frontier),
                )
                .order_by(DelegationContextV2.depth.asc(), DelegationContextV2.delegation_context_id.asc())
                .with_for_update()
            ).all()
        )
        next_frontier: list[str] = []
        for descendant in descendants:
            if descendant.delegation_context_id in seen:
                raise PermissionError("delegation lineage contains a cycle")
            seen.add(descendant.delegation_context_id)
            ordered.append(descendant)
            next_frontier.append(descendant.delegation_context_id)
        frontier = next_frontier
    return ordered


def revoke_delegation_context_v2(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    delegation_context_id: str,
    reason_code: str,
    observed_at: datetime,
) -> list[str]:
    """Atomically revoke a verified context and its exact unconsumed descendants."""
    now = _utc(observed_at)
    root = _locked_context(db, tenant_id=tenant_id, delegation_context_id=delegation_context_id)
    contexts = _lock_descendants(db, tenant_id=tenant_id, root=root)
    folds: dict[str, DelegationLifecycleFold] = {}
    for context in contexts:
        fold = fresh_delegation_context_fold(db, provider=provider, context=context)
        if context is root and (fold.state in _TERMINAL_STATES or now >= _utc(context.expires_at)):
            raise PermissionError("delegation context is expired or already revoked")
        if context is not root and (fold.state in _TERMINAL_STATES or now >= _utc(context.expires_at)):
            # A terminal descendant cannot block revocation of live siblings.
            # Its existing terminal history remains immutable, while any still
            # unconsumed action-linked authority is revoked below.
            continue
        folds[context.delegation_context_id] = fold
    live_contexts = [context for context in contexts if context.delegation_context_id in folds]
    affected_action_ids = {
        str(context.delegated_action_id)
        for context in contexts
        if context.delegated_action_id is not None
    }
    # The existing approval/permit state machines own their own signed terminal
    # transitions.  Lock and append those first, then bind the exact resulting
    # affected set into the root delegation revocation event.
    from .execution_authority import ExecutionPermitAuthority

    authority_refs = ExecutionPermitAuthority(
        db,
        signing_provider=provider,
        now=lambda: now,
    ).revoke_unconsumed_authority_for_actions(
        tenant_id=tenant_id,
        action_ids=affected_action_ids,
        reason_code=reason_code,
        observed_at=now,
        source_delegation_context_ids=[root.delegation_context_id],
    )
    descendant_refs = sorted(
        [context.delegation_context_id for context in live_contexts if context is not root]
        + authority_refs
    )
    for context in sorted(live_contexts, key=lambda item: (-item.depth, item.delegation_context_id)):
        _append_event(
            db,
            provider=provider,
            context=context,
            fold=folds[context.delegation_context_id],
            event_type="REVOKED",
            to_state="REVOKED",
            affected_unconsumed_descendant_refs=descendant_refs if context is root else [],
            reason_code=reason_code,
            observed_at=now,
        )
    return [context.delegation_context_id for context in live_contexts]
