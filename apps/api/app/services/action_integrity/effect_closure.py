"""Durable closure of consequential provider effects.

This module extends the existing V2 permit authority.  It deliberately does
not evaluate policy or create a second execution engine: the permit remains the
authorization source, while a signed reservation keeps that authority fenced
until the provider effect is resolved.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import ApprovalBindingV2Extension, DecisionReceiptV2Extension, ExecutionPermitV2
from app.db.models.evidence import ExecutionReceipt
from app.db.models.execution_effect import (
    EffectDeliveryFenceV2,
    EffectReservationTransitionV2,
    EffectReservationV2,
    ExecutionPermitEffectBindingV2,
)

from .approval_binding import variation_matches
from .canonical_v2 import canonical_action_hash_v2, domain_hash
from .execution_authority import ExecutionPermitAuthority
from .lifecycle_persistence import persist_execution_receipt_v2_and_comparison
from .materiality import material_fields_hash
from .signing import SigningKeyProvider, active_key_id, sign_object, verify_signed_object


RESERVATION_TRANSITION_DOMAIN = "hawk:effect-reservation-transition:v1"
PERMIT_BINDING_DOMAIN = "hawk:execution-permit-effect-binding:v1"
_UNRESOLVED_STATES = frozenset({"RESERVED", "PREPARED", "COMMITTING", "AMBIGUOUS"})
_TERMINAL_OUTCOMES = frozenset({"COMMITTED", "CERTIFIED_NO_EFFECT", "FAILED", "CANCELLED"})


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _semantics(action: Mapping[str, Any]) -> Mapping[str, Any]:
    value = action.get("action_semantics")
    if not isinstance(value, Mapping):
        raise ValueError("effect action semantics are missing")
    return value


def effect_manifest(*, action: Mapping[str, Any], provider_ref: str) -> dict[str, Any]:
    """Return only deterministic, security-relevant and non-secret material."""
    semantics = _semantics(action)
    safe_parameters = semantics.get("safe_parameters")
    if not isinstance(safe_parameters, Mapping):
        raise ValueError("safe effect parameters are missing")
    manifest = {
        "schema_version": "1.0",
        "tenant_id": action.get("tenant_id"),
        "actor_principal_ref": action.get("actor_principal"),
        "executing_principal_ref": action.get("executing_principal"),
        "represented_subject_refs": list(action.get("represented_subjects") or []),
        "authority_ref": semantics.get("authority_ref") or action.get("authority_context"),
        "business_purpose_ref": semantics.get("business_purpose_ref") or action.get("business_purpose"),
        "provider_ref": provider_ref,
        "operation": semantics.get("operation"),
        "object_type": semantics.get("object_type"),
        "tool_or_service_ref": semantics.get("tool_or_service_ref"),
        "tool_fingerprint": semantics.get("tool_fingerprint"),
        "safe_parameters": dict(safe_parameters),
        "resource_refs": list(semantics.get("resource_refs") or []),
        "target_refs": list(semantics.get("target_refs") or []),
        "destination_refs": list(semantics.get("destination_refs") or []),
        "values_or_quantities": list(semantics.get("values_or_quantities") or []),
        "side_effect": semantics.get("side_effect"),
        "persistence": semantics.get("persistence"),
        "expected_outcome_ref": semantics.get("expected_outcome_ref"),
        "policy_epoch": action.get("policy_epoch"),
    }
    if any(value is None for value in manifest.values()):
        raise ValueError("effect manifest contains unresolved material")
    return manifest


def _manifest_hash(*, action: Mapping[str, Any], provider_ref: str) -> str:
    return domain_hash("hawk:effect-manifest:v1", effect_manifest(action=action, provider_ref=provider_ref))


def _effect_identity_hash(*, action: Mapping[str, Any], provider_ref: str) -> str:
    # Deliberately excludes request/action IDs.  A replacement action ID cannot
    # evade an unresolved materially equivalent effect.
    return domain_hash("hawk:effect-identity:v1", effect_manifest(action=action, provider_ref=provider_ref))


def classify_effect_manifest(
    *,
    expected_action: Mapping[str, Any],
    candidate_action: Mapping[str, Any],
    provider_ref: str,
    variation_authorized: bool,
) -> str:
    if _manifest_hash(action=expected_action, provider_ref=provider_ref) == _manifest_hash(
        action=candidate_action, provider_ref=provider_ref
    ):
        return "EXACT"
    return "TYPED_SEMANTIC_EQUIVALENT" if variation_authorized else "MISMATCH"


@dataclass(frozen=True, slots=True)
class ProviderEffectResult:
    state: str
    provider_effect_ref: str | None
    evidence_ref: str


class EffectProvider(Protocol):
    def commit(self, *, idempotency_key: str, manifest: Mapping[str, Any]) -> ProviderEffectResult: ...
    def query(self, *, idempotency_key: str, provider_effect_ref: str | None) -> ProviderEffectResult: ...


class SyntheticEffectProvider:
    """Safe deterministic P0 provider; it never contacts an external system."""

    def __init__(self, *, mode: str = "normal") -> None:
        if mode not in {"normal", "ambiguous_committed", "ambiguous_no_effect", "ambiguous_unresolved"}:
            raise ValueError("unsupported synthetic effect mode")
        self.mode = mode
        self._effects: dict[str, str] = {}
        self._commits = 0

    @property
    def effect_count(self) -> int:
        return len(self._effects)

    def commit(self, *, idempotency_key: str, manifest: Mapping[str, Any]) -> ProviderEffectResult:
        provider_ref = self._effects.get(idempotency_key)
        if provider_ref is None and self.mode in {"normal", "ambiguous_committed"}:
            provider_ref = f"synthetic-effect:{domain_hash('hawk:synthetic-provider-effect:v1', {'key': idempotency_key})[:24]}"
            self._effects[idempotency_key] = provider_ref
            self._commits += 1
        if self.mode == "normal":
            return ProviderEffectResult("COMMITTED", provider_ref, f"evidence:synthetic-committed:{idempotency_key}")
        return ProviderEffectResult("AMBIGUOUS", provider_ref, f"evidence:synthetic-ambiguous:{idempotency_key}")

    def query(self, *, idempotency_key: str, provider_effect_ref: str | None) -> ProviderEffectResult:
        actual = self._effects.get(idempotency_key)
        if actual is not None:
            return ProviderEffectResult("COMMITTED", actual, f"evidence:synthetic-query-committed:{idempotency_key}")
        if self.mode == "ambiguous_no_effect":
            return ProviderEffectResult(
                "CERTIFIED_NO_EFFECT", None, f"evidence:synthetic-query-no-effect:{idempotency_key}"
            )
        return ProviderEffectResult("AMBIGUOUS", provider_effect_ref, f"evidence:synthetic-query-ambiguous:{idempotency_key}")


class EffectClosureService:
    def __init__(
        self,
        db: Session,
        *,
        signing_provider: SigningKeyProvider,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._db = db
        self._signing_provider = signing_provider
        self._now = now or (lambda: datetime.now(timezone.utc))

    def _reservation(self, *, tenant_id: str, reservation_id: str, lock: bool = False) -> EffectReservationV2:
        # Durable execution/recovery transitions may commit through an isolated
        # session.  Force the caller's identity-map projection to refresh before
        # verifying the append-only transition history, otherwise a valid newer
        # history head can be compared with a stale in-memory reservation.
        statement = (
            select(EffectReservationV2)
            .where(EffectReservationV2.id == reservation_id)
            .execution_options(populate_existing=True)
        )
        if lock:
            statement = statement.with_for_update()
        row = self._db.scalar(statement)
        if row is None:
            raise LookupError("effect reservation not found")
        if row.tenant_id != tenant_id:
            raise PermissionError("effect reservation tenant mismatch")
        self._verify_history(row, lock=lock)
        return row

    def _verify_history(self, reservation: EffectReservationV2, *, lock: bool) -> None:
        statement = (
            select(EffectReservationTransitionV2)
            .where(
                EffectReservationTransitionV2.tenant_id == reservation.tenant_id,
                EffectReservationTransitionV2.reservation_id == reservation.id,
            )
            .order_by(EffectReservationTransitionV2.sequence.asc())
        )
        if lock:
            statement = statement.with_for_update()
        transitions = list(self._db.scalars(statement).all())
        if not transitions:
            reservation.reconstruction_status = "INVALID"
            raise PermissionError("effect reservation history is missing")
        previous: EffectReservationTransitionV2 | None = None
        previous_hash: str | None = None
        for sequence, transition in enumerate(transitions, start=1):
            envelope = dict(transition.signed_envelope or {})
            valid = (
                transition.sequence == sequence
                and transition.prior_transition_id == (previous.id if previous else None)
                and transition.prior_transition_hash == previous_hash
                and transition.prior_state_version == sequence - 1
                and transition.new_state_version == sequence
                and verify_signed_object(
                    self._signing_provider,
                    purpose="effect_reservation_signing",
                    domain=RESERVATION_TRANSITION_DOMAIN,
                    tenant_id=reservation.tenant_id,
                    value=envelope,
                    current_authority=False,
                )
            )
            if not valid:
                reservation.reconstruction_status = "INVALID"
                raise PermissionError("effect reservation history is invalid")
            previous = transition
            previous_hash = domain_hash("hawk:effect-reservation-transition-envelope-hash:v1", envelope)
        if (
            reservation.state_version != len(transitions)
            or reservation.state != transitions[-1].to_state
            or reservation.history_head_transition_id != transitions[-1].id
            or reservation.history_head_transition_hash != previous_hash
            or reservation.history_head_sequence != len(transitions)
        ):
            reservation.reconstruction_status = "INVALID"
            raise PermissionError("effect reservation projection is invalid")

    def _append_transition(
        self,
        reservation: EffectReservationV2,
        *,
        expected_version: int,
        to_state: str,
        reason_code: str,
        worker_ref: str | None = None,
        provider_effect_ref: str | None = None,
        execution_receipt_id: str | None = None,
        evidence_quality: str = "HAWK_RUNTIME_OBSERVED",
        evidence_refs: tuple[str, ...] = (),
    ) -> EffectReservationV2:
        if reservation.state_version != expected_version:
            raise PermissionError("stale effect reservation version")
        transition_id = str(uuid4())
        now = _utc(self._now())
        new_version = expected_version + 1
        key_id = active_key_id(
            self._signing_provider, purpose="effect_reservation_signing", tenant_id=reservation.tenant_id
        )
        envelope = sign_object(
            self._signing_provider,
            purpose="effect_reservation_signing",
            domain=RESERVATION_TRANSITION_DOMAIN,
            tenant_id=reservation.tenant_id,
            key_id=key_id,
            value={
                "schema_version": "1.0",
                "transition_id": transition_id,
                "tenant_id": reservation.tenant_id,
                "reservation_id": reservation.id,
                "sequence": reservation.history_head_sequence + 1,
                "from_state": reservation.state,
                "to_state": to_state,
                "prior_state_version": expected_version,
                "new_state_version": new_version,
                "prior_transition_id": reservation.history_head_transition_id,
                "prior_transition_hash": reservation.history_head_transition_hash,
                "worker_ref": worker_ref,
                "provider_effect_ref": provider_effect_ref,
                "execution_receipt_id": execution_receipt_id,
                "evidence_quality": evidence_quality,
                "evidence_refs": list(evidence_refs),
                "reason_code": reason_code,
                "idempotency_key": f"effect-transition:{reservation.id}:{new_version}",
                "observed_at": now.isoformat(),
            },
        )
        transition = EffectReservationTransitionV2(
            id=transition_id,
            tenant_id=reservation.tenant_id,
            reservation_id=reservation.id,
            sequence=reservation.history_head_sequence + 1,
            from_state=reservation.state,
            to_state=to_state,
            prior_state_version=expected_version,
            new_state_version=new_version,
            prior_transition_id=reservation.history_head_transition_id,
            prior_transition_hash=reservation.history_head_transition_hash,
            worker_ref=worker_ref,
            provider_effect_ref=provider_effect_ref,
            execution_receipt_id=execution_receipt_id,
            evidence_quality=evidence_quality,
            evidence_refs=list(evidence_refs),
            reason_code=reason_code,
            idempotency_key=f"effect-transition:{reservation.id}:{new_version}",
            observed_at=now,
            algorithm=str(envelope["algorithm"]),
            signing_key_id=str(envelope["signing_key_id"]),
            signature=str(envelope["signature"]),
            signed_envelope=envelope,
        )
        self._db.add(transition)
        reservation.state = to_state
        reservation.state_version = new_version
        reservation.history_head_transition_id = transition_id
        reservation.history_head_transition_hash = domain_hash(
            "hawk:effect-reservation-transition-envelope-hash:v1", envelope
        )
        reservation.history_head_sequence += 1
        reservation.worker_ref = worker_ref or reservation.worker_ref
        reservation.provider_effect_ref = provider_effect_ref or reservation.provider_effect_ref
        reservation.evidence_refs = [*list(reservation.evidence_refs or []), *evidence_refs]
        if to_state in _TERMINAL_OUTCOMES:
            reservation.closure_outcome = to_state
            reservation.terminal_at = now
        return reservation

    def get(self, *, tenant_id: str, reservation_id: str) -> EffectReservationV2:
        return self._reservation(tenant_id=tenant_id, reservation_id=reservation_id)

    def reserve(
        self,
        *,
        tenant_id: str,
        action: Mapping[str, Any],
        permit_id: str,
        decision_receipt_id: str,
        provider_ref: str,
        predecessor_reservation_id: str | None = None,
        successor_reason: str | None = None,
        no_effect_evidence_refs: tuple[str, ...] = (),
    ) -> EffectReservationV2:
        now = _utc(self._now())
        permit = self._db.scalar(
            select(ExecutionPermitV2)
            .where(ExecutionPermitV2.tenant_id == tenant_id, ExecutionPermitV2.permit_id == permit_id)
            .with_for_update()
        )
        authority = ExecutionPermitAuthority(self._db, signing_provider=self._signing_provider, now=self._now)
        if (
            permit is None
            or permit.state != "ISSUED"
            or permit.reconstruction_status != "VERIFIED"
            or not authority._fresh_permit_fold(permit)
            or permit.decision_receipt_id != decision_receipt_id
            or permit.action_id != action.get("action_id")
            or permit.canonical_action_hash != canonical_action_hash_v2(action)
            or permit.material_fields_hash != material_fields_hash(action)
            or permit.policy_epoch != int(action.get("policy_epoch") or 0)
        ):
            raise PermissionError("execution permit does not authorize this effect reservation")
        if _utc(permit.expires_at) <= now:
            raise PermissionError("execution permit is expired")

        manifest = effect_manifest(action=action, provider_ref=provider_ref)
        manifest_hash = domain_hash("hawk:effect-manifest:v1", manifest)
        identity_hash = domain_hash("hawk:effect-identity:v1", manifest)
        predecessor: EffectReservationV2 | None = None
        if predecessor_reservation_id:
            predecessor = self._reservation(
                tenant_id=tenant_id, reservation_id=predecessor_reservation_id, lock=True
            )

        fence = self._db.scalar(
            select(EffectDeliveryFenceV2)
            .where(
                EffectDeliveryFenceV2.tenant_id == tenant_id,
                EffectDeliveryFenceV2.effect_identity_hash == identity_hash,
            )
            .with_for_update()
        )
        if fence is not None:
            prior = predecessor
            if prior is None and fence.last_reservation_id:
                prior = self._reservation(
                    tenant_id=tenant_id, reservation_id=fence.last_reservation_id, lock=True
                )
            if prior is not None and prior.effect_identity_hash == identity_hash:
                if prior.state in _UNRESOLVED_STATES:
                    raise PermissionError("unresolved equivalent effect blocks successor authority")
                if prior.closure_outcome == "COMMITTED" or prior.state == "COMMITTED":
                    raise PermissionError("committed equivalent effect blocks ordinary retry")
                if prior.closure_outcome == "CERTIFIED_NO_EFFECT" or prior.state == "CERTIFIED_NO_EFFECT":
                    supplied = set(no_effect_evidence_refs)
                    required = set(prior.evidence_refs or [])
                    if not predecessor_reservation_id or not supplied or not supplied.intersection(required):
                        raise PermissionError("certified no-effect successor lacks linked evidence")
            elif fence.state in _UNRESOLVED_STATES:
                raise PermissionError("unresolved equivalent effect blocks successor authority")
        else:
            fence = EffectDeliveryFenceV2(
                id=str(uuid4()), tenant_id=tenant_id, effect_identity_hash=identity_hash,
                state="RESERVED", state_version=1,
            )
            self._db.add(fence)

        reservation_id = str(uuid4())
        transition_id = str(uuid4())
        key_id = active_key_id(
            self._signing_provider, purpose="effect_reservation_signing", tenant_id=tenant_id
        )
        initial = sign_object(
            self._signing_provider,
            purpose="effect_reservation_signing",
            domain=RESERVATION_TRANSITION_DOMAIN,
            tenant_id=tenant_id,
            key_id=key_id,
            value={
                "schema_version": "1.0", "transition_id": transition_id, "tenant_id": tenant_id,
                "reservation_id": reservation_id, "sequence": 1, "from_state": "NONE", "to_state": "RESERVED",
                "prior_state_version": 0, "new_state_version": 1, "prior_transition_id": None,
                "prior_transition_hash": None, "worker_ref": None, "provider_effect_ref": None,
                "execution_receipt_id": None, "evidence_quality": "HAWK_RUNTIME_OBSERVED", "evidence_refs": [],
                "reason_code": "authority_and_material_reserved",
                "idempotency_key": f"effect-transition:{reservation_id}:1", "observed_at": now.isoformat(),
            },
        )
        initial_hash = domain_hash("hawk:effect-reservation-transition-envelope-hash:v1", initial)
        semantics = _semantics(action)
        reservation = EffectReservationV2(
            id=reservation_id, tenant_id=tenant_id, fence_id=fence.id, action_id=str(action["action_id"]),
            canonical_action_hash=permit.canonical_action_hash, material_fields_hash=permit.material_fields_hash,
            decision_receipt_id=decision_receipt_id, approval_binding_id=permit.approval_binding_id,
            execution_permit_id=permit.permit_id, attempt_id=permit.attempt_id,
            actor_principal_ref=str(action["actor_principal"]), executing_principal_ref=str(action["executing_principal"]),
            represented_subject_refs=list(action.get("represented_subjects") or []),
            authority_ref=str(semantics.get("authority_ref") or action["authority_context"]), provider_ref=provider_ref,
            resource_refs=list(semantics.get("resource_refs") or []), target_refs=list(semantics.get("target_refs") or []),
            destination_refs=list(semantics.get("destination_refs") or []),
            value_hashes=[domain_hash("hawk:effect-value:v1", value) for value in semantics.get("values_or_quantities") or []],
            side_effect=str(semantics["side_effect"]), persistence=str(semantics["persistence"]),
            effect_identity_hash=identity_hash, manifest_hash=manifest_hash, effect_manifest=manifest,
            manifest_match_mode="EXACT", policy_epoch=permit.policy_epoch, state="RESERVED", state_version=1,
            expires_at=permit.expires_at,
            provider_idempotency_key=f"effect:{tenant_id}:{identity_hash}",
            predecessor_reservation_id=predecessor_reservation_id, successor_reason=successor_reason,
            prior_terminal_state=(predecessor.closure_outcome or predecessor.state) if predecessor else None,
            no_effect_evidence_refs=list(no_effect_evidence_refs), material_differences=[], evidence_refs=[],
            history_head_transition_id=transition_id, history_head_transition_hash=initial_hash, history_head_sequence=1,
        )
        transition = EffectReservationTransitionV2(
            id=transition_id, tenant_id=tenant_id, reservation_id=reservation_id, sequence=1,
            from_state="NONE", to_state="RESERVED", prior_state_version=0, new_state_version=1,
            evidence_quality="HAWK_RUNTIME_OBSERVED", evidence_refs=[], reason_code="authority_and_material_reserved",
            idempotency_key=f"effect-transition:{reservation_id}:1", observed_at=now,
            algorithm=str(initial["algorithm"]), signing_key_id=str(initial["signing_key_id"]),
            signature=str(initial["signature"]), signed_envelope=initial,
        )
        binding_key = active_key_id(
            self._signing_provider, purpose="effect_reservation_signing", tenant_id=tenant_id
        )
        binding_envelope = sign_object(
            self._signing_provider,
            purpose="effect_reservation_signing",
            domain=PERMIT_BINDING_DOMAIN,
            tenant_id=tenant_id,
            key_id=binding_key,
            value={
                "schema_version": "1.0", "binding_id": str(uuid4()), "tenant_id": tenant_id,
                "permit_id": permit.permit_id, "reservation_id": reservation_id,
                "manifest_hash": manifest_hash, "effect_identity_hash": identity_hash,
                "policy_epoch": permit.policy_epoch, "created_at": now.isoformat(),
            },
        )
        binding = ExecutionPermitEffectBindingV2(
            id=str(binding_envelope["binding_id"]), tenant_id=tenant_id, permit_id=permit.permit_id,
            reservation_id=reservation_id, manifest_hash=manifest_hash, effect_identity_hash=identity_hash,
            policy_epoch=permit.policy_epoch, algorithm=str(binding_envelope["algorithm"]),
            signing_key_id=str(binding_envelope["signing_key_id"]), signature=str(binding_envelope["signature"]),
            signed_envelope=binding_envelope,
        )
        self._db.add_all([reservation, transition, binding])
        fence.state = "RESERVED"
        fence.active_reservation_id = reservation_id
        fence.last_reservation_id = reservation_id
        if fence.state_version != 1 or fence.created_at is not None:
            fence.state_version += 1
        self._db.flush()
        return reservation

    def _variation_authorized(
        self, *, reservation: EffectReservationV2, candidate_action: Mapping[str, Any]
    ) -> bool:
        if not reservation.approval_binding_id:
            return False
        binding = self._db.scalar(
            select(ApprovalBindingV2Extension).where(
                ApprovalBindingV2Extension.tenant_id == reservation.tenant_id,
                ApprovalBindingV2Extension.binding_id == reservation.approval_binding_id,
            )
        )
        return bool(
            binding
            and variation_matches(
                dict(binding.permitted_variation_envelope or {}),
                candidate=candidate_action,
                provider=self._signing_provider,
                now=_utc(self._now()),
            )
        )

    def prepare(
        self,
        *,
        tenant_id: str,
        reservation_id: str,
        candidate_action: Mapping[str, Any],
        expected_version: int,
    ) -> EffectReservationV2:
        reservation = self._reservation(tenant_id=tenant_id, reservation_id=reservation_id, lock=True)
        if reservation.state != "RESERVED":
            raise PermissionError("effect reservation is not reservable")
        decision = self._db.get(DecisionReceiptV2Extension, reservation.decision_receipt_id)
        expected_action = dict((decision.signed_envelope or {}).get("canonical_action") or {}) if decision else {}
        mode = classify_effect_manifest(
            expected_action=expected_action,
            candidate_action=candidate_action,
            provider_ref=reservation.provider_ref,
            variation_authorized=self._variation_authorized(
                reservation=reservation, candidate_action=candidate_action
            ),
        )
        if mode == "MISMATCH":
            raise PermissionError("effect manifest mismatch invalidates reservation")
        reservation.manifest_match_mode = mode
        return self._append_transition(
            reservation, expected_version=expected_version, to_state="PREPARED",
            reason_code="effect_manifest_prepared",
        )

    def begin_committing(
        self,
        *,
        tenant_id: str,
        reservation_id: str,
        expected_version: int,
        worker_ref: str,
    ) -> EffectReservationV2:
        reservation = self._reservation(tenant_id=tenant_id, reservation_id=reservation_id, lock=True)
        if reservation.state != "PREPARED":
            raise PermissionError("effect reservation is not prepared")
        permit = self._db.scalar(
            select(ExecutionPermitV2)
            .where(
                ExecutionPermitV2.tenant_id == tenant_id,
                ExecutionPermitV2.permit_id == reservation.execution_permit_id,
            )
            .with_for_update()
        )
        now = _utc(self._now())
        if permit is None or permit.state != "CLAIMED" or permit.claimed_by_ref != worker_ref:
            raise PermissionError("stale worker cannot commit this effect")
        if _utc(permit.expires_at) <= now or not permit.claim_lease_expires_at or _utc(permit.claim_lease_expires_at) <= now:
            raise PermissionError("execution permit is expired")
        authority = ExecutionPermitAuthority(self._db, signing_provider=self._signing_provider, now=self._now)
        if not authority._fresh_permit_fold(permit):
            raise PermissionError("execution permit history is invalid")
        fence = self._db.scalar(
            select(EffectDeliveryFenceV2)
            .where(EffectDeliveryFenceV2.tenant_id == tenant_id, EffectDeliveryFenceV2.id == reservation.fence_id)
            .with_for_update()
        )
        if fence is None or fence.active_reservation_id != reservation.id:
            raise PermissionError("effect delivery fence is not held by this reservation")
        result = self._append_transition(
            reservation, expected_version=expected_version, to_state="COMMITTING",
            reason_code="provider_effect_boundary_entered", worker_ref=worker_ref,
        )
        fence.state = "COMMITTING"
        fence.state_version += 1
        return result

    def _execution_receipt(
        self,
        *,
        reservation: EffectReservationV2,
        closure_state: str,
        provider_effect_ref: str | None,
        evidence_ref: str,
        recovery_sequence: int,
    ) -> str:
        decision = self._db.get(DecisionReceiptV2Extension, reservation.decision_receipt_id)
        action = dict((decision.signed_envelope or {}).get("canonical_action") or {}) if decision else {}
        if not action:
            raise PermissionError("authorized action is unavailable for execution receipt")
        semantics = _semantics(action)
        receipt_id = str(uuid4())
        attempt = f"{reservation.attempt_id}:effect:{recovery_sequence}"
        status = "success" if closure_state == "COMMITTED" else ("failure" if closure_state in {"FAILED", "CERTIFIED_NO_EFFECT"} else "unverified")
        receipt = ExecutionReceipt(
            receipt_id=receipt_id, schema_version="1.0", tenant_id=reservation.tenant_id,
            action_id=reservation.action_id, decision_receipt_id=reservation.decision_receipt_id,
            execution_attempt_id=attempt, actual_chain_id=action.get("chain_id"),
            actual_actor_hash=domain_hash("hawk:effect-receipt-actor:v1", action.get("actor_principal")),
            actual_purpose_hash=domain_hash("hawk:effect-receipt-purpose:v1", action.get("business_purpose")),
            actual_tool_fingerprint=str(semantics.get("tool_fingerprint")),
            actual_parameter_hash=domain_hash("hawk:effect-receipt-parameters:v1", semantics.get("safe_parameters")),
            actual_target_resource_hash=domain_hash("hawk:effect-receipt-target:v1", semantics.get("target_refs") or []),
            actual_destination_hash=domain_hash("hawk:effect-receipt-destination:v1", semantics.get("destination_refs") or []),
            actual_authority_hash=domain_hash("hawk:effect-receipt-authority:v1", semantics.get("authority_ref")),
            actual_side_effect_class=str(semantics.get("side_effect")),
            actual_policy_snapshot_id=str(action.get("policy_version_id") or ""), downstream_objects=[],
            execution_status=status, executed_at=_utc(self._now()), collector_id="effect-closure-v1",
            signature=domain_hash("hawk:base-effect-execution-receipt:v1", {"receipt_id": receipt_id, "state": closure_state}),
            signing_key_id="effect-closure-v1",
            idempotency_key=domain_hash("hawk:base-effect-execution-idempotency:v1", {"reservation_id": reservation.id, "sequence": recovery_sequence}),
        )
        self._db.add(receipt)
        self._db.flush()
        extension, _ = persist_execution_receipt_v2_and_comparison(
            self._db, provider=self._signing_provider, execution_receipt=receipt,
            authorized=action, executed=action, permit_id=reservation.execution_permit_id,
            issued_at=_utc(self._now()), evidence_quality="TARGET_SERVICE_CONFIRMED" if closure_state in {"COMMITTED", "CERTIFIED_NO_EFFECT"} else "PROVIDER_REPORTED",
            effect_closure={
                "reservation_id": reservation.id, "state": closure_state,
                "provider_effect_ref": provider_effect_ref, "evidence_refs": [evidence_ref],
                "recovery_sequence": recovery_sequence,
            },
        )
        return extension.receipt_id

    def _record_result(
        self,
        *,
        tenant_id: str,
        reservation_id: str,
        expected_version: int,
        outcome: str,
        provider_effect_ref: str | None,
        evidence_ref: str,
        recovery: bool,
    ) -> EffectReservationV2:
        if outcome not in {"COMMITTED", "AMBIGUOUS", "CERTIFIED_NO_EFFECT", "FAILED"}:
            raise ValueError("unsupported effect closure outcome")
        reservation = self._reservation(tenant_id=tenant_id, reservation_id=reservation_id, lock=True)
        required_state = "AMBIGUOUS" if recovery else "COMMITTING"
        if reservation.state_version != expected_version:
            raise PermissionError("stale recovery or delivery result")
        if reservation.state != required_state:
            raise PermissionError("stale recovery cannot overwrite terminal state")
        receipt_id = self._execution_receipt(
            reservation=reservation, closure_state=outcome, provider_effect_ref=provider_effect_ref,
            evidence_ref=evidence_ref, recovery_sequence=reservation.history_head_sequence + 1,
        )
        result = self._append_transition(
            reservation, expected_version=expected_version, to_state=outcome,
            reason_code="provider_recovery_result" if recovery else "provider_delivery_result",
            worker_ref=reservation.worker_ref, provider_effect_ref=provider_effect_ref,
            execution_receipt_id=receipt_id,
            evidence_quality="TARGET_SERVICE_CONFIRMED" if outcome in {"COMMITTED", "CERTIFIED_NO_EFFECT"} else "PROVIDER_REPORTED",
            evidence_refs=(evidence_ref,),
        )
        result.last_execution_receipt_id = receipt_id
        fence = self._db.scalar(
            select(EffectDeliveryFenceV2)
            .where(EffectDeliveryFenceV2.tenant_id == tenant_id, EffectDeliveryFenceV2.id == result.fence_id)
            .with_for_update()
        )
        if fence is None:
            raise PermissionError("effect delivery fence is missing")
        fence.state = outcome
        fence.state_version += 1
        fence.last_reservation_id = result.id
        fence.active_reservation_id = result.id if outcome in {"AMBIGUOUS", "COMMITTED"} else None
        permit_state = "UNKNOWN" if outcome == "AMBIGUOUS" else "CONSUMED"
        permit = self._db.get(ExecutionPermitV2, result.execution_permit_id)
        if permit is not None and permit.state == "CLAIMED":
            finalized = ExecutionPermitAuthority(
                self._db, signing_provider=self._signing_provider, now=self._now
            )._finalize_in_current_transaction(
                result.execution_permit_id, tenant_id=tenant_id, to_state=permit_state,
                reason_code=f"effect_closure_{outcome.lower()}",
            )
            if not finalized:
                raise RuntimeError("effect outcome lacks durable permit finalization")
        return result

    def execute_durably(
        self,
        *,
        tenant_id: str,
        reservation_id: str,
        expected_version: int,
        worker_ref: str,
        provider: EffectProvider,
    ) -> EffectReservationV2:
        bind = self._db.get_bind()
        with Session(bind=bind, expire_on_commit=False) as independent:
            with independent.begin():
                service = EffectClosureService(independent, signing_provider=self._signing_provider, now=self._now)
                existing = service._reservation(tenant_id=tenant_id, reservation_id=reservation_id, lock=True)
                if existing.state in _TERMINAL_OUTCOMES:
                    return existing
                committing = service.begin_committing(
                    tenant_id=tenant_id, reservation_id=reservation_id,
                    expected_version=expected_version, worker_ref=worker_ref,
                )
                idempotency_key = committing.provider_idempotency_key
                manifest = dict(committing.effect_manifest)
                committing_version = committing.state_version
        # The COMMITTING transition is committed before crossing the provider
        # boundary.  No timeout can roll authority back to PREPARED.
        provider_result = provider.commit(idempotency_key=idempotency_key, manifest=manifest)
        with Session(bind=bind, expire_on_commit=False) as independent:
            with independent.begin():
                service = EffectClosureService(independent, signing_provider=self._signing_provider, now=self._now)
                return service._record_result(
                    tenant_id=tenant_id, reservation_id=reservation_id,
                    expected_version=committing_version, outcome=provider_result.state,
                    provider_effect_ref=provider_result.provider_effect_ref,
                    evidence_ref=provider_result.evidence_ref, recovery=False,
                )

    def recover_durably(
        self,
        *,
        tenant_id: str,
        reservation_id: str,
        expected_version: int,
        provider: EffectProvider,
    ) -> EffectReservationV2:
        bind = self._db.get_bind()
        with Session(bind=bind, expire_on_commit=False) as independent:
            reservation = EffectClosureService(
                independent, signing_provider=self._signing_provider, now=self._now
            )._reservation(tenant_id=tenant_id, reservation_id=reservation_id)
            if reservation.state_version != expected_version or reservation.state != "AMBIGUOUS":
                raise PermissionError("stale recovery cannot overwrite terminal state")
            idempotency_key = reservation.provider_idempotency_key
            provider_effect_ref = reservation.provider_effect_ref
        # Exactly one bounded inquiry.  Remaining ambiguity is persisted; no
        # internal polling or ordinary resubmission occurs.
        provider_result = provider.query(
            idempotency_key=idempotency_key, provider_effect_ref=provider_effect_ref
        )
        with Session(bind=bind, expire_on_commit=False) as independent:
            with independent.begin():
                return EffectClosureService(
                    independent, signing_provider=self._signing_provider, now=self._now
                )._record_result(
                    tenant_id=tenant_id, reservation_id=reservation_id,
                    expected_version=expected_version, outcome=provider_result.state,
                    provider_effect_ref=provider_result.provider_effect_ref,
                    evidence_ref=provider_result.evidence_ref, recovery=True,
                )

    def record_recovery_result(
        self,
        *,
        tenant_id: str,
        reservation_id: str,
        expected_version: int,
        outcome: str,
        provider_effect_ref: str | None,
        evidence_ref: str,
    ) -> EffectReservationV2:
        return self._record_result(
            tenant_id=tenant_id, reservation_id=reservation_id, expected_version=expected_version,
            outcome=outcome, provider_effect_ref=provider_effect_ref,
            evidence_ref=evidence_ref, recovery=True,
        )

    def cancel(
        self, *, tenant_id: str, reservation_id: str, expected_version: int
    ) -> EffectReservationV2:
        reservation = self._reservation(tenant_id=tenant_id, reservation_id=reservation_id, lock=True)
        if reservation.state not in {"RESERVED", "PREPARED"}:
            raise PermissionError("cancellation is denied after the commit boundary")
        result = self._append_transition(
            reservation, expected_version=expected_version, to_state="CANCELLED",
            reason_code="cancelled_before_provider_boundary",
        )
        fence = self._db.get(EffectDeliveryFenceV2, result.fence_id)
        if fence:
            fence.state, fence.active_reservation_id = "CANCELLED", None
            fence.state_version += 1
        return result

    def terminalize(
        self, *, tenant_id: str, reservation_id: str, expected_version: int
    ) -> EffectReservationV2:
        reservation = self._reservation(tenant_id=tenant_id, reservation_id=reservation_id, lock=True)
        if reservation.state not in _TERMINAL_OUTCOMES:
            raise PermissionError("only resolved effect outcomes may become terminal")
        return self._append_transition(
            reservation, expected_version=expected_version, to_state="TERMINAL",
            reason_code="effect_closure_terminalized", evidence_refs=tuple(reservation.evidence_refs or []),
        )
