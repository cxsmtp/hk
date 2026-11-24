"""Database-backed, single-use V2 execution authority."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
import unicodedata
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import (
    ApprovalAuthorityEventV2,
    ApprovalAuthorityProjectionV2,
    ApprovalBindingV2Extension,
    ExecutionPermitAttemptV2,
    ExecutionPermitTransitionV2,
    ExecutionPermitV2,
    TenantActionIntegrityRollout,
)
from app.db.models.policy import ApprovalRequest

from .approval_binding import BINDING_DOMAIN, VARIATION_DOMAIN, variation_matches
from .canonical_v2 import canonical_action_hash_v2, domain_hash
from .materiality import material_fields_hash
from .signing import KmsHsmSigningKeyProvider, SigningKeyProvider, active_key_id, sign_object, verify_signed_object


PERMIT_DOMAIN = "hawk:execution-permit:v1"
TRANSITION_DOMAIN = "hawk:execution-permit-transition:v1"
APPROVAL_USE_EVENT_DOMAIN = "hawk:approval-authority-event:v1"
APPROVAL_DECISION_EVENT_DOMAIN = "hawk:approval-decision-event:v2"


@dataclass(frozen=True, slots=True)
class ExecutionPermit:
    permit_id: str
    tenant_id: str
    action_hash: str
    material_hash: str
    expires_at: datetime
    attempt_id: str | None = None


class ApprovalRequiredError(PermissionError):
    """The generic lifecycle has durably created or found a V2 approval request."""

    def __init__(self, approval_request_id: str) -> None:
        self.approval_request_id = approval_request_id
        super().__init__(f"V2 approval is required before execution: {approval_request_id}")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _bounded_reference(*, label: str, value: str, maximum_bytes: int) -> str:
    """Reject lossy or ambiguous authority identifiers before canonicalization."""
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or value != unicodedata.normalize("NFC", value)
        or len(value.encode("utf-8")) > maximum_bytes
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _row_envelope(row: ExecutionPermitV2) -> dict[str, Any]:
    return dict(row.signed_envelope or {})


def _same_instant(left: object, right: object) -> bool:
    """Compare persisted timestamps without trusting driver-specific offsets."""
    if isinstance(left, datetime) and isinstance(right, datetime):
        return _utc(left) == _utc(right)
    if isinstance(left, datetime) and isinstance(right, str):
        try:
            return _utc(left) == _utc(datetime.fromisoformat(right.replace("Z", "+00:00")))
        except ValueError:
            return False
    return left == right


class ExecutionPermitAuthority:
    """The sole generic server permit issuer and final claimant.

    It deliberately accepts a SQLAlchemy session rather than retaining any
    process-local permit state.  Issuance atomically consumes one approval use;
    claim atomically moves the permit to CLAIMED before an external invocation.
    A claimed permit never becomes reusable after a lease or process crash.
    """

    def __init__(self, db: Session, *, signing_provider: SigningKeyProvider, now: Callable[[], datetime] | None = None) -> None:
        self._db = db
        self._signing_provider = signing_provider
        self._now = now or (lambda: datetime.now(timezone.utc))

    def _fresh_approval_fold(
        self,
        *,
        tenant_id: str,
        approval_request_id: str,
        binding: ApprovalBindingV2Extension,
        projection: ApprovalAuthorityProjectionV2,
    ) -> ApprovalAuthorityEventV2:
        """Verify the complete immutable history before consuming current authority."""
        events = list(
            self._db.scalars(
                select(ApprovalAuthorityEventV2)
                .where(
                    ApprovalAuthorityEventV2.tenant_id == tenant_id,
                    ApprovalAuthorityEventV2.approval_request_id == approval_request_id,
                )
                .order_by(ApprovalAuthorityEventV2.sequence.asc())
                .with_for_update()
            ).all()
        )
        if not events:
            projection.reconstruction_status = "INVALID"
            raise PermissionError("approval authority history is missing")
        uses, state_version, state = 0, 0, "APPROVED"
        previous: ApprovalAuthorityEventV2 | None = None
        previous_hash: str | None = None
        for expected_sequence, event in enumerate(events, start=1):
            envelope = dict(event.signed_envelope or {})
            domain = APPROVAL_DECISION_EVENT_DOMAIN if event.event_type == "DECIDED" else APPROVAL_USE_EVENT_DOMAIN
            valid = verify_signed_object(
                self._signing_provider,
                purpose="approval_binding_signing",
                domain=domain,
                tenant_id=tenant_id,
                value=envelope,
                current_authority=True,
            )
            same_row = (
                envelope.get("event_id") == event.id
                and envelope.get("tenant_id") == tenant_id
                and envelope.get("approval_request_id") == approval_request_id
                and envelope.get("approval_binding_id") == event.binding_id
                and envelope.get("sequence") == event.sequence == expected_sequence
                and envelope.get("algorithm") == event.algorithm
                and envelope.get("signing_key_id") == event.signing_key_id
                and envelope.get("signature") == event.signature
            )
            if not valid or not same_row:
                projection.reconstruction_status = "INVALID"
                raise PermissionError("approval authority history is invalid")
            if expected_sequence == 1:
                if (
                    event.event_type != "DECIDED"
                    or event.decision != "approve"
                    or event.binding_id != binding.binding_id
                    or envelope.get("prior_event_id") is not None
                    or envelope.get("prior_event_hash") is not None
                ):
                    projection.reconstruction_status = "INVALID"
                    raise PermissionError("approval authority history has an invalid initial decision")
            else:
                if (
                    previous is None
                    or envelope.get("prior_event_id") != previous.id
                    or envelope.get("prior_event_hash") != previous_hash
                    or envelope.get("prior_state_version") != state_version
                    or envelope.get("new_state_version") != state_version + 1
                    or event.binding_id != binding.binding_id
                ):
                    projection.reconstruction_status = "INVALID"
                    raise PermissionError("approval authority history has a broken transition")
                if event.event_type == "USE_CONSUMED":
                    if (
                        state != "APPROVED"
                        or envelope.get("prior_uses_consumed") != uses
                        or envelope.get("new_uses_consumed") != uses + 1
                    ):
                        projection.reconstruction_status = "INVALID"
                        raise PermissionError("approval authority history has an invalid use transition")
                    uses += 1
                    state_version += 1
                    state = "EXHAUSTED" if uses == binding.use_limit else "APPROVED"
                elif event.event_type == "REVOKED":
                    if (
                        state != "APPROVED"
                        or envelope.get("prior_uses_consumed") != uses
                        or envelope.get("new_uses_consumed") != uses
                    ):
                        projection.reconstruction_status = "INVALID"
                        raise PermissionError("approval authority history has an invalid revocation")
                    state_version += 1
                    state = "REVOKED"
                else:
                    projection.reconstruction_status = "INVALID"
                    raise PermissionError("approval authority history has an unknown transition")
                if envelope.get("to_state") != state:
                    projection.reconstruction_status = "INVALID"
                    raise PermissionError("approval authority history has an invalid state")
                if state in {"EXHAUSTED", "REVOKED"} and expected_sequence != len(events):
                    projection.reconstruction_status = "INVALID"
                    raise PermissionError("approval authority history continues after a terminal state")
            previous = event
            previous_hash = domain_hash("hawk:approval-authority-event-envelope-hash:v1", envelope)
        if (
            uses > binding.use_limit
            or projection.state != state
            or projection.uses_consumed != uses
            or projection.state_version != state_version
            or projection.history_head_event_id != previous.id
            or projection.history_head_event_hash != previous_hash
            or projection.history_head_sequence != len(events)
            or projection.reconstruction_status != "VERIFIED"
        ):
            projection.reconstruction_status = "INVALID"
            raise PermissionError("approval authority projection does not match its history")
        return previous

    def _consume_approval(
        self,
        *,
        tenant_id: str,
        approval_request_id: str,
        permit_id: str,
        attempt_id: str,
        action: Mapping[str, Any],
        decision_receipt_id: str,
        evaluated_at: datetime,
    ) -> ApprovalBindingV2Extension:
        binding = self._db.scalar(
            select(ApprovalBindingV2Extension)
            .where(
                ApprovalBindingV2Extension.tenant_id == tenant_id,
                ApprovalBindingV2Extension.approval_request_id == approval_request_id,
            )
            .with_for_update()
        )
        projection = self._db.scalar(
            select(ApprovalAuthorityProjectionV2)
            .where(
                ApprovalAuthorityProjectionV2.tenant_id == tenant_id,
                ApprovalAuthorityProjectionV2.approval_request_id == approval_request_id,
            )
            .with_for_update()
        )
        if binding is None or projection is None or projection.reconstruction_status != "VERIFIED" or projection.state != "APPROVED":
            raise PermissionError("approval authority is not currently eligible")
        if _utc(binding.expires_at) <= evaluated_at or projection.uses_consumed >= binding.use_limit:
            raise PermissionError("approval authority is expired or exhausted")
        if not verify_signed_object(self._signing_provider, purpose="approval_binding_signing", domain=BINDING_DOMAIN, tenant_id=tenant_id, value=dict(binding.signed_envelope or {}), current_authority=True):
            projection.reconstruction_status = "INVALID"
            raise PermissionError("approval binding signature is invalid")
        if str(binding.binding_id) != str((binding.signed_envelope or {}).get("approval_binding_id")) or binding.binding_hash != domain_hash("hawk:approval-binding-envelope-hash:v1", dict(binding.signed_envelope or {})):
            projection.reconstruction_status = "INVALID"
            raise PermissionError("approval binding projection does not match signed authority")
        signed_binding = dict(binding.signed_envelope or {})
        if (
            binding.authority_binding_version != 1
            or binding.decision_receipt_id != decision_receipt_id
            or signed_binding.get("decision_receipt_id") != decision_receipt_id
            or signed_binding.get("control_selection_id") != binding.control_selection_id
        ):
            projection.reconstruction_status = "INVALID"
            raise PermissionError("approval binding is not bound to the current decision/native selection")
        if not variation_matches(dict(binding.permitted_variation_envelope or {}), candidate=action, provider=self._signing_provider, now=evaluated_at):
            raise PermissionError("candidate action exceeds its permitted variation")
        if canonical_action_hash_v2(action) != binding.canonical_action_hash or material_fields_hash(action) != binding.material_fields_hash:
            # Exact-only is the only currently-issued V2 envelope form.  Keep
            # this explicit rather than treating a missing matcher as a wildcard.
            raise PermissionError("approval binding material does not match candidate action")

        prior = self._fresh_approval_fold(
            tenant_id=tenant_id,
            approval_request_id=approval_request_id,
            binding=binding,
            projection=projection,
        )
        event_id = str(uuid4())
        event_hash = projection.history_head_event_hash
        key_id = active_key_id(self._signing_provider, purpose="approval_binding_signing", tenant_id=tenant_id)
        event = sign_object(
            self._signing_provider,
            purpose="approval_binding_signing",
            domain=APPROVAL_USE_EVENT_DOMAIN,
            tenant_id=tenant_id,
            key_id=key_id,
            value={
                "schema_version": "1.0",
                "event_id": event_id,
                "tenant_id": tenant_id,
                "approval_binding_id": binding.binding_id,
                "approval_request_id": approval_request_id,
                "execution_permit_id": permit_id,
                "attempt_id": attempt_id,
                "sequence": prior.sequence + 1,
                "prior_event_id": prior.id,
                "prior_event_hash": event_hash,
                "from_state": projection.state,
                "to_state": "EXHAUSTED" if projection.uses_consumed + 1 == binding.use_limit else "APPROVED",
                "prior_state_version": projection.state_version,
                "new_state_version": projection.state_version + 1,
                "prior_uses_consumed": projection.uses_consumed,
                "new_uses_consumed": projection.uses_consumed + 1,
                "event_type": "USE_CONSUMED",
                "reason_code": "permit_issued",
                "idempotency_key": f"permit:{permit_id}",
                "observed_at": evaluated_at.isoformat(),
            },
        )
        self._db.add(
            ApprovalAuthorityEventV2(
                id=event_id,
                tenant_id=tenant_id,
                approval_request_id=approval_request_id,
                binding_id=binding.binding_id,
                sequence=prior.sequence + 1,
                event_type="USE_CONSUMED",
                decision=None,
                request_version=prior.request_version,
                body_hash=domain_hash("hawk:approval-authority-use:v1", event),
                prior_event_id=prior.id,
                prior_event_hash=event_hash,
                idempotency_key=f"permit:{permit_id}",
                reason_code="permit_issued",
                observed_at=evaluated_at,
                algorithm=str(event["algorithm"]),
                signing_key_id=str(event["signing_key_id"]),
                signature=str(event["signature"]),
                signed_envelope=event,
            )
        )
        projection.uses_consumed += 1
        projection.state_version += 1
        projection.state = "EXHAUSTED" if projection.uses_consumed == binding.use_limit else "APPROVED"
        projection.history_head_event_id = event_id
        projection.history_head_event_hash = domain_hash("hawk:approval-authority-event-envelope-hash:v1", event)
        projection.history_head_sequence = prior.sequence + 1
        return binding

    def issue(
        self,
        *,
        tenant_id: str,
        action: Mapping[str, Any],
        expires_at: datetime,
        rollout_mode: str,
        approval_request_id: str | None = None,
        decision_receipt_id: str | None = None,
        integration_ref: str = "server",
    ) -> ExecutionPermit:
        issued_at = _utc(self._now())
        expires_at = _utc(expires_at)
        if str(rollout_mode) != "AUTHORITATIVE":
            raise PermissionError("V2 permits may only be issued in AUTHORITATIVE mode")
        if action.get("tenant_id") != tenant_id or expires_at <= issued_at or int(action.get("policy_epoch") or 0) <= 0:
            raise ValueError("invalid permit authority inputs")
        if action.get("unresolved_material"):
            raise PermissionError("unresolved material cannot authorize execution")
        action_id = action.get("action_id")
        if not isinstance(action_id, str) or not action_id:
            raise ValueError("permit action identifier is required")
        # A generic action with no delegation edge remains valid.  When its
        # exact action ID is a V1 delegated edge, lock and revalidate the full
        # lineage before an approval can be consumed or a permit can be born.
        from .delegation_lifecycle import require_active_delegated_action_authority

        require_active_delegated_action_authority(
            self._db,
            provider=self._signing_provider,
            tenant_id=tenant_id,
            delegated_action_id=action_id,
            now=issued_at,
        )
        if not decision_receipt_id:
            raise PermissionError("V1 execution permits require a stored decision receipt")
        from .stored_authority import require_current_decision_authority_v1

        decision_extension, stored_authority = require_current_decision_authority_v1(
            self._db,
            provider=self._signing_provider,
            tenant_id=tenant_id,
            decision_receipt_id=decision_receipt_id,
            action=action,
            now=issued_at,
        )
        native = stored_authority.native_selection
        expires_at = min(
            expires_at,
            _utc(decision_extension.expires_at),
            _utc(stored_authority.selection.expires_at),
            _utc(native.plan_expires_at),
        )
        if expires_at <= issued_at:
            raise PermissionError("permit expiry outlives stored authority")
        permit_id, attempt_id = str(uuid4()), str(uuid4())
        binding: ApprovalBindingV2Extension | None = None
        from .stored_authority import approval_is_required

        if approval_is_required(action):
            if not approval_request_id:
                raise PermissionError("approval-required action has no approval request")
            request = self._db.scalar(
                select(ApprovalRequest)
                .where(
                    ApprovalRequest.tenant_id == tenant_id,
                    ApprovalRequest.id == approval_request_id,
                )
                .with_for_update()
            )
            request_payload = request.request_payload if request is not None and isinstance(request.request_payload, Mapping) else {}
            if str(request_payload.get("decision_receipt_id") or "") != decision_receipt_id:
                raise PermissionError("approval request is not bound to the current decision receipt")
            binding = self._consume_approval(
                tenant_id=tenant_id,
                approval_request_id=approval_request_id,
                permit_id=permit_id,
                attempt_id=attempt_id,
                action=action,
                decision_receipt_id=decision_receipt_id,
                evaluated_at=issued_at,
            )
            if (
                binding.profile_selection_id != stored_authority.selection.selection_id
                or binding.profile_selection_hash != stored_authority.selection.selection_hash
                or binding.control_selection_id != native.selection_id
                or binding.control_plan_digest != native.control_plan_digest
            ):
                raise PermissionError("approval binding does not match current stored authority")
        action_hash, fields_hash = canonical_action_hash_v2(action), material_fields_hash(action)
        key_id = active_key_id(self._signing_provider, purpose="execution_permit_signing", tenant_id=tenant_id)
        plan = action.get("action_plan_binding") if isinstance(action.get("action_plan_binding"), Mapping) else {}
        envelope = sign_object(
            self._signing_provider,
            purpose="execution_permit_signing",
            domain=PERMIT_DOMAIN,
            tenant_id=tenant_id,
            key_id=key_id,
            value={
                "schema_version": "1.0",
                "permit_id": permit_id,
                "tenant_id": tenant_id,
                "action_id": str(action.get("action_id")),
                "attempt_id": attempt_id,
                "decision_receipt_id": decision_receipt_id,
                "authority_source_action_id": str(action.get("action_id")),
                "authority_source_canonical_action_hash": action_hash,
                "canonical_action_hash": action_hash,
                "material_fields_hash": fields_hash,
                "approval_binding_id": binding.binding_id if binding else None,
                "permitted_variation_envelope_id": binding.permitted_variation_envelope_id if binding else None,
                "permitted_variation_hash": binding.permitted_variation_hash if binding else None,
                "action_plan_binding_type": str(plan.get("binding_type", "STANDALONE")),
                "action_plan_id": plan.get("action_plan_id"),
                "action_plan_digest": plan.get("action_plan_digest"),
                "action_plan_step_id": plan.get("action_plan_step_id"),
                "action_plan_step_digest": plan.get("action_plan_step_digest"),
                "integration_ref": integration_ref,
                "control_plan_digest": str(action.get("control_plan_digest")),
                "policy_epoch": int(action.get("policy_epoch")),
                "authority_binding_version": 1,
                "profile_selection_id": stored_authority.selection.selection_id,
                "profile_selection_hash": stored_authority.selection.selection_hash,
                "control_selection_id": native.selection_id,
                "control_plan_id": native.control_plan_id,
                "authoritative_decision": decision_extension.authoritative_decision,
                "authority_status": decision_extension.authority_status,
                "decision_version": decision_extension.decision_version,
                "native_action_id": native.action_id,
                "native_canonical_action_hash": native.canonical_action_hash,
                "native_plan_issued_at": _utc(native.plan_issued_at).isoformat(),
                "native_plan_expires_at": _utc(native.plan_expires_at).isoformat(),
                "issued_at": issued_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "nonce": str(uuid4()),
                "use_limit": 1,
            },
        )
        # The attempt is a first-class, tenant-scoped binding between the
        # signed decision and the permit.  Write both references in the same
        # transaction as permit issuance; leaving either nullable would let a
        # plausible action history be projected without its authority chain.
        self._db.add(
            ExecutionPermitAttemptV2(
                tenant_id=tenant_id,
                attempt_id=attempt_id,
                action_id=str(action.get("action_id")),
                canonical_action_hash=action_hash,
                material_fields_hash=fields_hash,
                status="ISSUED",
                action_plan_id=plan.get("action_plan_id"),
                action_plan_step_id=plan.get("action_plan_step_id"),
                decision_receipt_id=decision_receipt_id,
                execution_permit_id=permit_id,
            )
        )
        self._db.add(
            ExecutionPermitV2(
                permit_id=permit_id,
                tenant_id=tenant_id,
                action_id=str(action.get("action_id")),
                attempt_id=attempt_id,
                decision_receipt_id=decision_receipt_id,
                approval_binding_id=binding.binding_id if binding else None,
                permitted_variation_hash=binding.permitted_variation_hash if binding else None,
                canonical_action_hash=action_hash,
                material_fields_hash=fields_hash,
                policy_epoch=int(action.get("policy_epoch")),
                control_plan_digest=str(action.get("control_plan_digest")),
                action_plan_binding_type=str(plan.get("binding_type", "STANDALONE")),
                action_plan_id=plan.get("action_plan_id"),
                action_plan_digest=plan.get("action_plan_digest"),
                action_plan_step_id=plan.get("action_plan_step_id"),
                action_plan_step_digest=plan.get("action_plan_step_digest"),
                algorithm=str(envelope["algorithm"]),
                signing_key_id=str(envelope["signing_key_id"]),
                signature=str(envelope["signature"]),
                signed_envelope=envelope,
                authority_binding_version=1,
                profile_selection_id=stored_authority.selection.selection_id,
                profile_selection_hash=stored_authority.selection.selection_hash,
                control_selection_id=native.selection_id,
                control_plan_id=native.control_plan_id,
                authoritative_decision=decision_extension.authoritative_decision,
                authority_status=decision_extension.authority_status,
                decision_version=decision_extension.decision_version,
                state="ISSUED",
                state_version=0,
                expires_at=expires_at,
                created_at=issued_at,
            )
        )
        return ExecutionPermit(permit_id, tenant_id, action_hash, fields_hash, expires_at, attempt_id)

    def issue_durably(self, **kwargs: Any) -> ExecutionPermit:
        """Issue authority and consume approval in an independent committed unit."""
        bind = self._db.get_bind()
        with Session(bind=bind, expire_on_commit=False) as independent_db:
            with independent_db.begin():
                authority = ExecutionPermitAuthority(
                    independent_db,
                    signing_provider=self._signing_provider,
                    now=self._now,
                )
                return authority.issue(**kwargs)

    def _fresh_permit_fold(self, permit: ExecutionPermitV2) -> bool:
        """Reconstruct the permit state from signed immutable authority rows."""
        attempt = self._db.scalar(
            select(ExecutionPermitAttemptV2)
            .where(
                ExecutionPermitAttemptV2.tenant_id == permit.tenant_id,
                ExecutionPermitAttemptV2.attempt_id == permit.attempt_id,
            )
            .with_for_update()
        )
        if attempt is None or not (
            attempt.action_id == permit.action_id
            and attempt.canonical_action_hash == permit.canonical_action_hash
            and attempt.material_fields_hash == permit.material_fields_hash
            and attempt.action_plan_id == permit.action_plan_id
            and attempt.action_plan_step_id == permit.action_plan_step_id
            and attempt.decision_receipt_id == permit.decision_receipt_id
            and attempt.execution_permit_id == permit.permit_id
        ):
            permit.reconstruction_status = "INVALID"
            return False
        envelope = _row_envelope(permit)
        if not verify_signed_object(
            self._signing_provider,
            purpose="execution_permit_signing",
            domain=PERMIT_DOMAIN,
            tenant_id=permit.tenant_id,
            value=envelope,
            current_authority=True,
        ):
            permit.reconstruction_status = "INVALID"
            return False
        if not (
            envelope.get("permit_id") == permit.permit_id
            and envelope.get("tenant_id") == permit.tenant_id
            and envelope.get("attempt_id") == permit.attempt_id
            and envelope.get("canonical_action_hash") == permit.canonical_action_hash
            and envelope.get("material_fields_hash") == permit.material_fields_hash
            and envelope.get("policy_epoch") == permit.policy_epoch
            and str(envelope.get("control_plan_digest")) == str(permit.control_plan_digest)
            and envelope.get("authority_binding_version") == permit.authority_binding_version == 1
            and envelope.get("profile_selection_id") == permit.profile_selection_id
            and envelope.get("profile_selection_hash") == permit.profile_selection_hash
            and envelope.get("control_selection_id") == permit.control_selection_id
            and envelope.get("control_plan_id") == permit.control_plan_id
            and envelope.get("authoritative_decision") == permit.authoritative_decision
            and envelope.get("authority_status") == permit.authority_status
            and envelope.get("decision_version") == permit.decision_version
            and envelope.get("algorithm") == permit.algorithm
            and envelope.get("signing_key_id") == permit.signing_key_id
            and envelope.get("signature") == permit.signature
            and _same_instant(permit.expires_at, envelope.get("expires_at"))
        ):
            permit.reconstruction_status = "INVALID"
            return False
        transitions = list(
            self._db.scalars(
                select(ExecutionPermitTransitionV2)
                .where(
                    ExecutionPermitTransitionV2.tenant_id == permit.tenant_id,
                    ExecutionPermitTransitionV2.permit_id == permit.permit_id,
                )
                .order_by(ExecutionPermitTransitionV2.sequence.asc())
                .with_for_update()
            ).all()
        )
        state, state_version = "ISSUED", 0
        prior_id: str | None = None
        prior_hash: str | None = None
        claim_id: str | None = None
        claimed_by_ref: str | None = None
        claim_lease_expires_at: datetime | None = None
        for sequence, transition in enumerate(transitions, start=1):
            signed = dict(transition.signed_envelope or {})
            valid = verify_signed_object(
                self._signing_provider,
                purpose="execution_permit_signing",
                domain=TRANSITION_DOMAIN,
                tenant_id=permit.tenant_id,
                value=signed,
                current_authority=True,
            )
            same_row = (
                signed.get("transition_id") == transition.id
                and signed.get("tenant_id") == transition.tenant_id
                and signed.get("permit_id") == transition.permit_id
                and signed.get("sequence") == transition.sequence == sequence
                and signed.get("from_state") == transition.from_state == state
                and signed.get("to_state") == transition.to_state
                and signed.get("prior_state_version") == transition.prior_state_version == state_version
                and signed.get("new_state_version") == transition.new_state_version == state_version + 1
                and signed.get("prior_transition_id") == prior_id
                and signed.get("prior_transition_hash") == prior_hash
                and signed.get("claim_id") == transition.claim_id
                and signed.get("claimed_by_ref") == transition.claimed_by_ref
                and _same_instant(transition.claim_lease_expires_at, signed.get("claim_lease_expires_at"))
                and signed.get("executor_invocation_state") == transition.executor_invocation_state
                and signed.get("reason_code") == transition.reason_code
                and signed.get("idempotency_key") == transition.idempotency_key
                and _same_instant(transition.observed_at, signed.get("observed_at"))
                and signed.get("algorithm") == transition.algorithm
                and signed.get("signing_key_id") == transition.signing_key_id
                and signed.get("signature") == transition.signature
            )
            if not valid or not same_row:
                permit.reconstruction_status = "INVALID"
                return False
            if (state, transition.to_state) not in {
                ("ISSUED", "CLAIMED"),
                ("ISSUED", "REVOKED"),
                ("CLAIMED", "CONSUMED"),
                ("CLAIMED", "UNKNOWN"),
            }:
                permit.reconstruction_status = "INVALID"
                return False
            if transition.to_state == "REVOKED" and (
                transition.claim_id is not None
                or transition.claimed_by_ref is not None
                or transition.claim_lease_expires_at is not None
                or transition.executor_invocation_state != "NOT_INVOKED"
            ):
                permit.reconstruction_status = "INVALID"
                return False
            if state == "CLAIMED" and (
                transition.claim_id != claim_id
                or transition.claimed_by_ref != claimed_by_ref
                or not _same_instant(transition.claim_lease_expires_at, claim_lease_expires_at)
                or (
                    transition.to_state == "CONSUMED"
                    and transition.executor_invocation_state != "INVOKED"
                )
                or (
                    transition.to_state == "UNKNOWN"
                    and transition.executor_invocation_state not in {"UNKNOWN", "UNVERIFIED"}
                )
            ):
                permit.reconstruction_status = "INVALID"
                return False
            state, state_version = transition.to_state, transition.new_state_version
            prior_id = transition.id
            prior_hash = domain_hash("hawk:execution-permit-transition-envelope-hash:v1", signed)
            claim_id = transition.claim_id
            claimed_by_ref = transition.claimed_by_ref
            claim_lease_expires_at = transition.claim_lease_expires_at
        if not (
            permit.state == state
            and permit.state_version == state_version
            and permit.claim_id == claim_id
            and permit.claimed_by_ref == claimed_by_ref
            and _same_instant(permit.claim_lease_expires_at, claim_lease_expires_at)
            and permit.reconstruction_status == "VERIFIED"
        ):
            permit.reconstruction_status = "INVALID"
            return False
        return True

    def revoke_unconsumed_authority_for_actions(
        self,
        *,
        tenant_id: str,
        action_ids: set[str],
        reason_code: str,
        observed_at: datetime,
        source_delegation_context_ids: list[str],
    ) -> list[str]:
        """Append signed revocations for exact delegated-action authorities.

        Delegation is linked only through the tenant-scoped canonical action ID:
        approval requests carry it in their frozen canonical action and permits
        carry it in their first-class action_id column.  Hashes are deliberately
        not used as a lookup key.  The caller owns one surrounding transaction.
        """
        actions = {action_id for action_id in action_ids if isinstance(action_id, str) and action_id}
        if not actions:
            return []
        now = _utc(observed_at)
        source_ids = sorted(set(source_delegation_context_ids))
        affected: list[str] = []

        requests = list(
            self._db.scalars(
                select(ApprovalRequest)
                .where(
                    ApprovalRequest.tenant_id == tenant_id,
                    ApprovalRequest.request_payload["canonical_action"]["action_id"].as_string().in_(sorted(actions)),
                )
                .order_by(ApprovalRequest.id.asc())
                .with_for_update()
            ).all()
        )
        for request in requests:
            payload = request.request_payload if isinstance(request.request_payload, Mapping) else {}
            action = payload.get("canonical_action") if isinstance(payload, Mapping) else None
            if not isinstance(action, Mapping) or action.get("action_id") not in actions:
                continue
            if action.get("tenant_id") != tenant_id:
                raise PermissionError("delegation-linked approval has a cross-tenant canonical action")
            if request.authority_schema_version != "2.0" or request.status != "approved":
                # Pending, denied, legacy, and otherwise non-approved requests
                # are not unconsumed authority.  Do not synthesize a new
                # authority transition for them.
                continue
            binding = self._db.scalar(
                select(ApprovalBindingV2Extension)
                .where(
                    ApprovalBindingV2Extension.tenant_id == tenant_id,
                    ApprovalBindingV2Extension.approval_request_id == request.id,
                )
                .with_for_update()
            )
            projection = self._db.scalar(
                select(ApprovalAuthorityProjectionV2)
                .where(
                    ApprovalAuthorityProjectionV2.tenant_id == tenant_id,
                    ApprovalAuthorityProjectionV2.approval_request_id == request.id,
                )
                .with_for_update()
            )
            if binding is None or projection is None:
                raise PermissionError("delegation-linked approval authority is incomplete")
            prior = self._fresh_approval_fold(
                tenant_id=tenant_id,
                approval_request_id=request.id,
                binding=binding,
                projection=projection,
            )
            if projection.state != "APPROVED" or now >= _utc(binding.expires_at):
                # EXHAUSTED/REVOKED/expired authority has no remaining use to
                # invalidate. Its verified history remains untouched.
                continue
            event_id = str(uuid4())
            key_id = active_key_id(self._signing_provider, purpose="approval_binding_signing", tenant_id=tenant_id)
            event = sign_object(
                self._signing_provider,
                purpose="approval_binding_signing",
                domain=APPROVAL_USE_EVENT_DOMAIN,
                tenant_id=tenant_id,
                key_id=key_id,
                value={
                    "schema_version": "1.0",
                    "event_id": event_id,
                    "tenant_id": tenant_id,
                    "approval_binding_id": binding.binding_id,
                    "approval_request_id": request.id,
                    "execution_permit_id": None,
                    "attempt_id": None,
                    "sequence": prior.sequence + 1,
                    "prior_event_id": prior.id,
                    "prior_event_hash": projection.history_head_event_hash,
                    "from_state": projection.state,
                    "to_state": "REVOKED",
                    "prior_state_version": projection.state_version,
                    "new_state_version": projection.state_version + 1,
                    "prior_uses_consumed": projection.uses_consumed,
                    "new_uses_consumed": projection.uses_consumed,
                    "event_type": "REVOKED",
                    "reason_code": reason_code,
                    "source_delegation_context_ids": source_ids,
                    "idempotency_key": f"delegation-revocation:{source_ids[0] if source_ids else 'root'}:approval:{request.id}",
                    "observed_at": now.isoformat(),
                },
            )
            self._db.add(
                ApprovalAuthorityEventV2(
                    id=event_id,
                    tenant_id=tenant_id,
                    approval_request_id=request.id,
                    binding_id=binding.binding_id,
                    sequence=prior.sequence + 1,
                    event_type="REVOKED",
                    decision=None,
                    request_version=prior.request_version,
                    body_hash=domain_hash("hawk:approval-authority-revocation:v1", event),
                    prior_event_id=prior.id,
                    prior_event_hash=projection.history_head_event_hash,
                    idempotency_key=str(event["idempotency_key"]),
                    reason_code=reason_code,
                    observed_at=now,
                    algorithm=str(event["algorithm"]),
                    signing_key_id=str(event["signing_key_id"]),
                    signature=str(event["signature"]),
                    signed_envelope=event,
                )
            )
            projection.state = "REVOKED"
            projection.state_version += 1
            projection.history_head_event_id = event_id
            projection.history_head_event_hash = domain_hash("hawk:approval-authority-event-envelope-hash:v1", event)
            projection.history_head_sequence = prior.sequence + 1
            affected.append(f"approval_request:{request.id}")

        permits = list(
            self._db.scalars(
                select(ExecutionPermitV2)
                .where(
                    ExecutionPermitV2.tenant_id == tenant_id,
                    ExecutionPermitV2.action_id.in_(sorted(actions)),
                )
                .order_by(ExecutionPermitV2.permit_id.asc())
                .with_for_update()
            ).all()
        )
        for permit in permits:
            if permit.state != "ISSUED" or now >= _utc(permit.expires_at):
                continue
            if not self._fresh_permit_fold(permit):
                raise PermissionError("delegation-linked permit history is invalid")
            if permit.state != "ISSUED" or permit.state_version != 0:
                raise PermissionError("delegation-linked permit has an invalid unconsumed state")
            transitions = list(
                self._db.scalars(
                    select(ExecutionPermitTransitionV2)
                    .where(
                        ExecutionPermitTransitionV2.tenant_id == tenant_id,
                        ExecutionPermitTransitionV2.permit_id == permit.permit_id,
                    )
                    .order_by(ExecutionPermitTransitionV2.sequence.asc())
                    .with_for_update()
                ).all()
            )
            if transitions:
                raise PermissionError("delegation-linked permit has unexpected transition history")
            attempt = self._db.scalar(
                select(ExecutionPermitAttemptV2)
                .where(
                    ExecutionPermitAttemptV2.tenant_id == tenant_id,
                    ExecutionPermitAttemptV2.attempt_id == permit.attempt_id,
                )
                .with_for_update()
            )
            if attempt is None or not (
                attempt.action_id == permit.action_id
                and attempt.canonical_action_hash == permit.canonical_action_hash
                and attempt.material_fields_hash == permit.material_fields_hash
                and attempt.decision_receipt_id == permit.decision_receipt_id
                and attempt.execution_permit_id == permit.permit_id
            ):
                raise PermissionError("delegation-linked permit attempt is invalid")
            transition_id = str(uuid4())
            key_id = active_key_id(self._signing_provider, purpose="execution_permit_signing", tenant_id=tenant_id)
            transition = sign_object(
                self._signing_provider,
                purpose="execution_permit_signing",
                domain=TRANSITION_DOMAIN,
                tenant_id=tenant_id,
                key_id=key_id,
                value={
                    "schema_version": "1.0",
                    "transition_id": transition_id,
                    "tenant_id": tenant_id,
                    "permit_id": permit.permit_id,
                    "attempt_id": permit.attempt_id,
                    "sequence": 1,
                    "from_state": "ISSUED",
                    "to_state": "REVOKED",
                    "prior_state_version": 0,
                    "new_state_version": 1,
                    "prior_transition_id": None,
                    "prior_transition_hash": None,
                    "claim_id": None,
                    "claimed_by_ref": None,
                    "claimed_at": None,
                    "claim_lease_expires_at": None,
                    "executor_invocation_state": "NOT_INVOKED",
                    "reason_code": reason_code,
                    "source": "delegation_revocation",
                    "source_delegation_context_ids": source_ids,
                    "evidence_refs": [],
                    "idempotency_key": f"delegation-revocation:{source_ids[0] if source_ids else 'root'}:permit:{permit.permit_id}",
                    "observed_at": now.isoformat(),
                    "received_at": now.isoformat(),
                },
            )
            self._db.add(
                ExecutionPermitTransitionV2(
                    id=transition_id,
                    tenant_id=tenant_id,
                    permit_id=permit.permit_id,
                    sequence=1,
                    from_state="ISSUED",
                    to_state="REVOKED",
                    prior_state_version=0,
                    new_state_version=1,
                    claim_id=None,
                    claimed_by_ref=None,
                    claim_lease_expires_at=None,
                    executor_invocation_state="NOT_INVOKED",
                    reason_code=reason_code,
                    idempotency_key=str(transition["idempotency_key"]),
                    observed_at=now,
                    algorithm=str(transition["algorithm"]),
                    signing_key_id=str(transition["signing_key_id"]),
                    signature=str(transition["signature"]),
                    signed_envelope=transition,
                )
            )
            permit.state = "REVOKED"
            permit.state_version = 1
            permit.claim_id = None
            permit.claimed_by_ref = None
            permit.claim_lease_expires_at = None
            attempt.status = "REVOKED"
            affected.append(f"execution_permit:{permit.permit_id}")
        return sorted(affected)

    def _claim_in_current_transaction(
        self,
        permit_id: str,
        *,
        tenant_id: str,
        action: Mapping[str, Any],
        claimed_by_ref: str,
        rollout_mode: str = "AUTHORITATIVE",
    ) -> bool:
        now = _utc(self._now())
        if rollout_mode != "AUTHORITATIVE" or action.get("tenant_id") != tenant_id:
            return False
        action_id = action.get("action_id")
        if not isinstance(action_id, str) or not action_id:
            return False
        # Context/ancestry locks are acquired before the permit row.  This is
        # the same root-to-descendant order used by delegation revocation, so a
        # revocation already holding lineage locks cannot be bypassed by a
        # concurrent claim of a formerly valid permit.
        from .delegation_lifecycle import require_active_delegated_action_authority

        try:
            require_active_delegated_action_authority(
                self._db,
                provider=self._signing_provider,
                tenant_id=tenant_id,
                delegated_action_id=action_id,
                now=now,
            )
            # Collective-bound actions must have passed the aggregate
            # constraints and still have a live signed delegation root at the
            # exact permit-consumption seam. Non-collective actions are a
            # no-op here and retain the existing Phase 5 behavior.
            from app.services.agent_collective_security import require_collective_action_authority

            require_collective_action_authority(
                self._db,
                signing_provider=self._signing_provider,
                tenant_id=tenant_id,
                action=action,
                now=now,
            )
        except PermissionError:
            return False
        permit = self._db.scalar(
            select(ExecutionPermitV2)
            .where(ExecutionPermitV2.tenant_id == tenant_id, ExecutionPermitV2.permit_id == permit_id)
            .with_for_update()
        )
        if (
            permit is not None
            and permit.state == "CLAIMED"
            and permit.claim_lease_expires_at is not None
            and now >= _utc(permit.claim_lease_expires_at)
        ):
            # Crash/timeout recovery is terminal only: an expired claimed
            # permit becomes signed UNKNOWN and can never return to ISSUED.
            self._finalize_in_current_transaction(
                permit_id,
                tenant_id=tenant_id,
                to_state="UNKNOWN",
                reason_code="expired_claim_recovery",
            )
            return False
        if permit is None or permit.state != "ISSUED" or permit.state_version != 0 or permit.reconstruction_status != "VERIFIED" or now >= _utc(permit.expires_at):
            return False
        if permit.action_id != action_id:
            return False
        if canonical_action_hash_v2(action) != permit.canonical_action_hash or material_fields_hash(action) != permit.material_fields_hash or int(action.get("policy_epoch") or 0) != permit.policy_epoch or str(action.get("control_plan_digest")) != str(permit.control_plan_digest):
            return False
        if not permit.decision_receipt_id:
            return False
        from .stored_authority import require_current_decision_authority_v1

        try:
            decision_extension, stored_authority = require_current_decision_authority_v1(
                self._db,
                provider=self._signing_provider,
                tenant_id=tenant_id,
                decision_receipt_id=permit.decision_receipt_id,
                action=action,
                now=now,
            )
        except PermissionError:
            return False
        if (
            permit.authority_binding_version != 1
            or permit.profile_selection_id != stored_authority.selection.selection_id
            or permit.profile_selection_hash != stored_authority.selection.selection_hash
            or permit.control_selection_id != stored_authority.native_selection.selection_id
            or permit.control_plan_id != stored_authority.native_selection.control_plan_id
            or permit.authoritative_decision != decision_extension.authoritative_decision
            or permit.authority_status != decision_extension.authority_status
            or permit.decision_version != decision_extension.decision_version
        ):
            return False
        if not self._fresh_permit_fold(permit):
            return False
        transition_id, claim_id = str(uuid4()), str(uuid4())
        lease = min(_utc(permit.expires_at), now + timedelta(seconds=30))
        key_id = active_key_id(self._signing_provider, purpose="execution_permit_signing", tenant_id=tenant_id)
        transition = sign_object(
            self._signing_provider,
            purpose="execution_permit_signing",
            domain=TRANSITION_DOMAIN,
            tenant_id=tenant_id,
            key_id=key_id,
            value={
                "schema_version": "1.0", "transition_id": transition_id, "tenant_id": tenant_id, "permit_id": permit_id,
                "attempt_id": permit.attempt_id, "sequence": 1, "from_state": "ISSUED", "to_state": "CLAIMED",
                "prior_state_version": 0, "new_state_version": 1, "prior_transition_id": None, "prior_transition_hash": None,
                "claim_id": claim_id, "claimed_by_ref": claimed_by_ref, "claimed_at": now.isoformat(),
                "claim_lease_expires_at": lease.isoformat(), "executor_invocation_state": "NOT_INVOKED",
                "reason_code": "final_seam_claim", "source": claimed_by_ref, "evidence_refs": [],
                "idempotency_key": f"claim:{claim_id}", "observed_at": now.isoformat(), "received_at": now.isoformat(),
            },
        )
        self._db.add(ExecutionPermitTransitionV2(id=transition_id, tenant_id=tenant_id, permit_id=permit_id, sequence=1, from_state="ISSUED", to_state="CLAIMED", prior_state_version=0, new_state_version=1, claim_id=claim_id, claimed_by_ref=claimed_by_ref, claim_lease_expires_at=lease, executor_invocation_state="NOT_INVOKED", reason_code="final_seam_claim", idempotency_key=f"claim:{claim_id}", observed_at=now, algorithm=str(transition["algorithm"]), signing_key_id=str(transition["signing_key_id"]), signature=str(transition["signature"]), signed_envelope=transition))
        permit.state, permit.state_version, permit.claim_id, permit.claimed_by_ref, permit.claim_lease_expires_at = "CLAIMED", 1, claim_id, claimed_by_ref, lease
        attempt = self._db.scalar(select(ExecutionPermitAttemptV2).where(ExecutionPermitAttemptV2.tenant_id == tenant_id, ExecutionPermitAttemptV2.attempt_id == permit.attempt_id).with_for_update())
        if attempt is not None:
            attempt.status = "CLAIMED"
        return True

    def claim(self, permit_id: str, *, tenant_id: str, action: Mapping[str, Any], claimed_by_ref: str, rollout_mode: str = "AUTHORITATIVE") -> bool:
        """Claim within the caller transaction for explicit state-machine tests.

        Production final seams use :meth:`claim_durably` through ``execute`` so
        callback failures cannot roll the transition back.
        """
        return self._claim_in_current_transaction(
            permit_id,
            tenant_id=tenant_id,
            action=action,
            claimed_by_ref=claimed_by_ref,
            rollout_mode=rollout_mode,
        )

    def claim_durably(self, permit_id: str, *, tenant_id: str, action: Mapping[str, Any], claimed_by_ref: str, rollout_mode: str = "AUTHORITATIVE") -> bool:
        """Commit a final-seam claim in an independent database transaction."""
        bind = self._db.get_bind()
        with Session(bind=bind, expire_on_commit=False) as independent_db:
            with independent_db.begin():
                authority = ExecutionPermitAuthority(
                    independent_db,
                    signing_provider=self._signing_provider,
                    now=self._now,
                )
                return authority._claim_in_current_transaction(
                    permit_id,
                    tenant_id=tenant_id,
                    action=action,
                    claimed_by_ref=claimed_by_ref,
                    rollout_mode=rollout_mode,
                )

    def _finalize_in_current_transaction(
        self,
        permit_id: str,
        *,
        tenant_id: str,
        to_state: str,
        reason_code: str,
    ) -> bool:
        if to_state not in {"CONSUMED", "UNKNOWN"}:
            raise ValueError("invalid terminal permit state")
        now = _utc(self._now())
        permit = self._db.scalar(
            select(ExecutionPermitV2)
            .where(ExecutionPermitV2.tenant_id == tenant_id, ExecutionPermitV2.permit_id == permit_id)
            .with_for_update()
        )
        if (
            permit is None
            or permit.state != "CLAIMED"
            or permit.state_version != 1
            or permit.reconstruction_status != "VERIFIED"
            or not self._fresh_permit_fold(permit)
        ):
            return False
        prior = self._db.scalar(
            select(ExecutionPermitTransitionV2)
            .where(
                ExecutionPermitTransitionV2.tenant_id == tenant_id,
                ExecutionPermitTransitionV2.permit_id == permit_id,
            )
            .order_by(ExecutionPermitTransitionV2.sequence.desc())
            .with_for_update()
        )
        if prior is None or prior.to_state != "CLAIMED":
            return False
        transition_id = str(uuid4())
        key_id = active_key_id(self._signing_provider, purpose="execution_permit_signing", tenant_id=tenant_id)
        executor_state = "INVOKED" if to_state == "CONSUMED" else "UNKNOWN"
        transition = sign_object(
            self._signing_provider,
            purpose="execution_permit_signing",
            domain=TRANSITION_DOMAIN,
            tenant_id=tenant_id,
            key_id=key_id,
            value={
                "schema_version": "1.0", "transition_id": transition_id, "tenant_id": tenant_id, "permit_id": permit_id,
                "attempt_id": permit.attempt_id, "sequence": prior.sequence + 1, "from_state": "CLAIMED", "to_state": to_state,
                "prior_state_version": permit.state_version, "new_state_version": permit.state_version + 1,
                "prior_transition_id": prior.id,
                "prior_transition_hash": domain_hash("hawk:execution-permit-transition-envelope-hash:v1", dict(prior.signed_envelope or {})),
                "claim_id": permit.claim_id, "claimed_by_ref": permit.claimed_by_ref,
                "claimed_at": None, "claim_lease_expires_at": permit.claim_lease_expires_at.isoformat() if permit.claim_lease_expires_at else None,
                "executor_invocation_state": executor_state, "reason_code": reason_code,
                "source": "final_seam_completion", "evidence_refs": [],
                "idempotency_key": f"terminal:{permit_id}:{to_state}", "observed_at": now.isoformat(), "received_at": now.isoformat(),
            },
        )
        self._db.add(
            ExecutionPermitTransitionV2(
                id=transition_id, tenant_id=tenant_id, permit_id=permit_id, sequence=prior.sequence + 1,
                from_state="CLAIMED", to_state=to_state, prior_state_version=permit.state_version,
                new_state_version=permit.state_version + 1, claim_id=permit.claim_id,
                claimed_by_ref=permit.claimed_by_ref, claim_lease_expires_at=permit.claim_lease_expires_at,
                executor_invocation_state=executor_state, reason_code=reason_code,
                idempotency_key=f"terminal:{permit_id}:{to_state}", observed_at=now,
                algorithm=str(transition["algorithm"]), signing_key_id=str(transition["signing_key_id"]),
                signature=str(transition["signature"]), signed_envelope=transition,
            )
        )
        permit.state = to_state
        permit.state_version += 1
        attempt = self._db.scalar(
            select(ExecutionPermitAttemptV2)
            .where(ExecutionPermitAttemptV2.tenant_id == tenant_id, ExecutionPermitAttemptV2.attempt_id == permit.attempt_id)
            .with_for_update()
        )
        if attempt is not None:
            attempt.status = to_state
        return True

    def finalize_durably(self, permit_id: str, *, tenant_id: str, to_state: str, reason_code: str) -> bool:
        """Persist the terminal executor outcome independently of caller work."""
        bind = self._db.get_bind()
        with Session(bind=bind, expire_on_commit=False) as independent_db:
            with independent_db.begin():
                authority = ExecutionPermitAuthority(
                    independent_db,
                    signing_provider=self._signing_provider,
                    now=self._now,
                )
                return authority._finalize_in_current_transaction(
                    permit_id,
                    tenant_id=tenant_id,
                    to_state=to_state,
                    reason_code=reason_code,
                )

    def execute(self, permit_id: str, *, tenant_id: str, action: Mapping[str, Any], claimed_by_ref: str, executor: Callable[[], Any], rollout_mode: str = "AUTHORITATIVE") -> tuple[bool, Any | None]:
        if not self.claim_durably(permit_id, tenant_id=tenant_id, action=action, claimed_by_ref=claimed_by_ref, rollout_mode=rollout_mode):
            return False, None
        try:
            result = executor()
        except BaseException as exc:
            # A failed/uncertain callback is durably terminal and never
            # returns the permit to ISSUED, even when the caller rethrows.
            finalized = self.finalize_durably(
                permit_id,
                tenant_id=tenant_id,
                to_state="UNKNOWN",
                reason_code="executor_exception_or_uncertain_dispatch",
            )
            if not finalized:
                raise RuntimeError("permit callback failed without a durable UNKNOWN transition") from exc
            raise
        if not self.finalize_durably(
            permit_id,
            tenant_id=tenant_id,
            to_state="CONSUMED",
            reason_code="executor_completed",
        ):
            raise RuntimeError("permit callback completed without a durable terminal transition")
        return True, result


class AuthoritativeExecutionSeamAdapter:
    """Thin final-executor adapter; it contains no policy evaluator."""

    def __init__(self, authority: ExecutionPermitAuthority, *, seam_ref: str) -> None:
        self._authority = authority
        self._seam_ref = seam_ref

    def invoke(self, *, permit_id: str | None, tenant_id: str, action: Mapping[str, Any], rollout_mode: str, executor: Callable[[], Any]) -> tuple[bool, Any | None]:
        if rollout_mode in {"DISABLED", "OBSERVE", "SHADOW"}:
            return True, executor()
        if rollout_mode != "AUTHORITATIVE" or not permit_id:
            return False, None
        return self._authority.execute(permit_id, tenant_id=tenant_id, action=action, claimed_by_ref=self._seam_ref, executor=executor, rollout_mode=rollout_mode)


@dataclass(frozen=True, slots=True)
class TrustedExecutionAuthorityHandle:
    """Server-internal hand-off from V2 enforcement to a final callback."""

    permit_id: str | None
    attempt_id: str | None
    tenant_id: str
    action: Mapping[str, Any]
    rollout_mode: str


def _rollout_mode(db: Session, *, tenant_id: str) -> tuple[str, int]:
    rollout = db.scalar(
        select(TenantActionIntegrityRollout).where(
            TenantActionIntegrityRollout.tenant_id == tenant_id,
        )
    )
    if rollout is None:
        return "DISABLED", 1
    mode = str(rollout.mode or "DISABLED").upper()
    if mode not in {"DISABLED", "OBSERVE", "SHADOW", "AUTHORITATIVE"}:
        raise PermissionError("invalid persisted Phase 5 rollout mode")
    return mode, int(rollout.policy_epoch)


def current_rollout_configuration(db: Session, *, tenant_id: str) -> tuple[str, int]:
    """Read rollout state without enrolling the caller transaction in authority IO."""
    with Session(bind=db.get_bind(), expire_on_commit=False) as read_db:
        return _rollout_mode(read_db, tenant_id=tenant_id)


def build_trusted_execution_action(
    *,
    tenant_id: str,
    action_id: str,
    chain_id: str,
    actor_principal: str,
    executing_principal: str,
    operation: str,
    tool_or_service_ref: str,
    tool_fingerprint: str,
    parameter_hash: str,
    target_ref: str,
    policy_epoch: int,
    approval_requirement: str,
    policy_version_id: str,
    now: datetime,
) -> dict[str, Any]:
    """Build the closed V2 material from server-trusted generic-route data."""
    action_id = _bounded_reference(label="action_id", value=action_id, maximum_bytes=64)
    chain_id = _bounded_reference(label="chain_id", value=chain_id, maximum_bytes=64)
    actor_principal = _bounded_reference(label="actor_principal", value=actor_principal, maximum_bytes=255)
    executing_principal = _bounded_reference(label="executing_principal", value=executing_principal, maximum_bytes=255)
    operation = _bounded_reference(label="operation", value=operation, maximum_bytes=128)
    tool_or_service_ref = _bounded_reference(label="tool_or_service_ref", value=tool_or_service_ref, maximum_bytes=255)
    tool_fingerprint = _bounded_reference(label="tool_fingerprint", value=tool_fingerprint, maximum_bytes=255)
    parameter_hash = _bounded_reference(label="parameter_hash", value=parameter_hash, maximum_bytes=255)
    target_ref = _bounded_reference(label="target_ref", value=target_ref, maximum_bytes=255)
    policy_version_id = _bounded_reference(label="policy_version_id", value=policy_version_id, maximum_bytes=64)
    approval_requirement = _bounded_reference(
        label="approval_requirement",
        value=approval_requirement,
        maximum_bytes=32,
    )
    return {
        "schema_version": "2.0",
        "tenant_id": tenant_id,
        "action_id": action_id,
        "chain_id": chain_id,
        # Generic adapters do not receive a separate caller-controlled trace.
        # Their already server-validated chain is the stable correlation key.
        "correlation_id": chain_id,
        "parent_action_id": None,
        "actor_principal": actor_principal,
        "executing_principal": executing_principal,
        "represented_subjects": [],
        "resource_scopes": [target_ref],
        "authority_context": "authority:server-verified",
        "business_purpose": "purpose:generic-execution",
        "environment": "production",
        "provider_runtime_context": "runtime:generic-route",
        "action_semantics": {
            "action_class": "consequential",
            "operation": operation,
            "object_type": "generic_execution",
            "tool_or_service_ref": tool_or_service_ref,
            "tool_fingerprint": tool_fingerprint,
            "safe_parameters": {"parameter_hash": parameter_hash},
            "represented_subject_refs": [],
            "resource_refs": [target_ref],
            "counterparty_refs": [],
            "target_refs": [target_ref],
            "destination_refs": [],
            "values_or_quantities": [],
            "authority_ref": "authority:server-verified",
            "business_purpose_ref": "purpose:generic-execution",
            "side_effect": "external_write",
            # These are conservative server classifications, not caller
            # guesses.  A generic final seam must be canonicalizable once the
            # stored profile/control bindings are supplied.
            "persistence": "persistent",
            "environment": "production",
            "reversibility": "compensatable",
            "expected_outcome_ref": "outcome:generic-execution",
        },
        # Generic seams cannot fabricate a profile or composed control plan.
        # AUTHORITATIVE mode rejects these missing values unless a caller
        # supplies real persisted authority through its decision/approval path.
        "domain_profile_ref": None,
        "domain_profile_hash": None,
        "materiality_profile_ref": "phase5-p0",
        "materiality_profile_hash": domain_hash("hawk:phase5:materiality-profile:v1", {"version": "1.0"}),
        "resolver_versions": {},
        "policy_version_id": policy_version_id,
        "policy_epoch": policy_epoch,
        "control_plan_id": None,
        "control_plan_digest": None,
        "approval_requirement": approval_requirement,
        "delegation_digest": domain_hash("hawk:phase5:generic-delegation:v1", {"chain_id": chain_id}),
        "action_plan_binding": {
            "binding_type": "STANDALONE",
            "action_plan_id": None,
            "action_plan_digest": None,
            "action_plan_step_id": None,
            "action_plan_step_digest": None,
        },
        "unresolved_material": [],
        "evidence_refs": [],
        "created_at": _utc(now).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }


def _matching_v2_approval_request(
    db: Session,
    *,
    tenant_id: str,
    action: Mapping[str, Any],
) -> ApprovalRequest | None:
    action_hash = canonical_action_hash_v2(action)
    execution_intent = dict(action)
    # The request-time timestamp is evidence, not an execution material
    # capability.  A retry must reuse the frozen approved action rather than
    # manufacture a new canonical action solely because time advanced.
    execution_intent.pop("created_at", None)
    execution_intent_hash = domain_hash("hawk:phase5:approval-execution-intent:v1", execution_intent)
    rows = db.scalars(
        select(ApprovalRequest)
        .where(
            ApprovalRequest.tenant_id == tenant_id,
            ApprovalRequest.authority_schema_version == "2.0",
            ApprovalRequest.status.in_(("pending", "approved")),
        )
        .order_by(ApprovalRequest.created_at.desc())
    ).all()
    for request in rows:
        payload = request.request_payload if isinstance(request.request_payload, Mapping) else {}
        candidate = payload.get("canonical_action")
        if isinstance(candidate, Mapping) and canonical_action_hash_v2(candidate) == action_hash:
            return request
        if isinstance(candidate, Mapping):
            candidate_intent = dict(candidate)
            candidate_intent.pop("created_at", None)
            if domain_hash("hawk:phase5:approval-execution-intent:v1", candidate_intent) == execution_intent_hash:
                return request
    return None


def _create_v2_approval_request(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    action: Mapping[str, Any],
    signing_provider: SigningKeyProvider,
    decision_receipt_id: str | None,
    now: datetime,
) -> ApprovalRequest:
    if not ai_system_id:
        raise PermissionError("approval-required V2 action lacks an ai_system_id")
    if not decision_receipt_id:
        raise PermissionError("approval-required V2 action lacks a stored decision receipt")
    from .stored_authority import require_current_decision_authority_v1

    decision, authority = require_current_decision_authority_v1(
        db,
        provider=signing_provider,
        tenant_id=tenant_id,
        decision_receipt_id=decision_receipt_id,
        action=action,
        now=_utc(now),
    )
    request = ApprovalRequest(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        decision_receipt_id=decision.receipt_id,
        request_payload={
            "canonical_action": dict(action),
            "decision_receipt_id": decision.receipt_id,
            "profile_selection_id": authority.selection.selection_id,
            "profile_selection_hash": authority.selection.selection_hash,
            "control_selection_id": authority.native_selection.selection_id,
            "use_limit": 1,
        },
        required_roles=["owner"],
        sla_minutes=60,
        default_if_timeout="deny",
        status="pending",
        authority_schema_version="2.0",
        decision_version=1,
    )
    db.add(request)
    db.flush()
    return request


def install_execution_authority(
    db: Session,
    *,
    tenant_id: str,
    action: Mapping[str, Any],
    seam_ref: str,
    signing_provider: SigningKeyProvider,
    ai_system_id: str | None = None,
    approval_request_id: str | None = None,
    decision_receipt_id: str | None = None,
    profile_selection_id: str | None = None,
    profile_selection_hash: str | None = None,
    control_selection_id: str | None = None,
    now: Callable[[], datetime] | None = None,
) -> TrustedExecutionAuthorityHandle | None:
    """Install the only trusted generic final-seam authority hand-off.

    The rollout mode is read from durable tenant state, never request input.
    AUTHORITATIVE authority is issued/approval-consumed in its own committed
    transaction before a seam can execute.  Other modes deliberately retain
    legacy execution but cannot accidentally carry a permit handle.
    """
    bind = db.get_bind()
    mode, policy_epoch = current_rollout_configuration(db, tenant_id=tenant_id)
    db.info["phase5_rollout_mode"] = mode
    db.info.pop("phase5_execution_authority", None)
    db.info.pop("phase5_execution_seam_adapter", None)
    if mode != "AUTHORITATIVE":
        return None
    if action.get("tenant_id") != tenant_id or int(action.get("policy_epoch") or 0) != policy_epoch:
        raise PermissionError("authoritative lifecycle action does not match current tenant policy epoch")
    action_copy = dict(action)
    evaluated_at = _utc((now or (lambda: datetime.now(timezone.utc)))())
    from .stored_authority import approval_is_required

    approval_required = approval_is_required(action_copy)
    selected_request_id = approval_request_id
    if approval_required and not selected_request_id:
        with Session(bind=bind, expire_on_commit=False) as read_db:
            existing = _matching_v2_approval_request(read_db, tenant_id=tenant_id, action=action_copy)
        if existing is None:
            # Persist the request independently so clients can decide it on
            # the V2 approval endpoint even when this execution rolls back.
            with Session(bind=bind, expire_on_commit=False) as approval_db:
                with approval_db.begin():
                    created = _create_v2_approval_request(
                        approval_db,
                        tenant_id=tenant_id,
                        ai_system_id=ai_system_id,
                        action=action_copy,
                        signing_provider=signing_provider,
                        decision_receipt_id=decision_receipt_id,
                        now=evaluated_at,
                    )
                    selected_request_id = created.id
            raise ApprovalRequiredError(str(selected_request_id))
        selected_request_id = existing.id
        existing_payload = existing.request_payload if isinstance(existing.request_payload, Mapping) else {}
        existing_action = existing_payload.get("canonical_action")
        if isinstance(existing_action, Mapping):
            # A matching V2 request is the authoritative frozen action.  This
            # preserves its approval-bound timestamp/hash across retries.
            action_copy = dict(existing_action)
        if existing.status != "approved":
            raise ApprovalRequiredError(existing.id)
    authority = ExecutionPermitAuthority(db, signing_provider=signing_provider, now=now)
    permit = authority.issue_durably(
        tenant_id=tenant_id,
        action=action_copy,
        expires_at=evaluated_at + timedelta(minutes=5),
        rollout_mode=mode,
        approval_request_id=selected_request_id,
        decision_receipt_id=decision_receipt_id,
        integration_ref=seam_ref,
    )
    handle = TrustedExecutionAuthorityHandle(
        permit_id=permit.permit_id,
        attempt_id=permit.attempt_id,
        tenant_id=tenant_id,
        action=action_copy,
        rollout_mode=mode,
    )
    db.info["phase5_execution_authority"] = handle
    db.info["phase5_execution_seam_adapter"] = AuthoritativeExecutionSeamAdapter(authority, seam_ref=seam_ref)
    return handle


_PRE_SEAM_FALLBACKS = frozenset(
    {
        "agui.actual_executor",
        "endpoint.platform_invocation",
        "itsm.http_post",
        "remediation.apply",
        "remediation.rollback",
    }
)


def _persist_generic_final_execution_evidence(
    db: Session,
    *,
    handle: TrustedExecutionAuthorityHandle,
    seam_ref: str,
    execution_status: str,
    signing_provider: SigningKeyProvider,
    observed_at: datetime,
) -> None:
    """Persist unverified provider-reported evidence for a generic final seam.

    Generic adapters do not own a second canonical-action representation.  The
    only receipt-compatible pre-action material is re-read from the immutable
    canonical EvidenceNode linked to the already verified decision receipt.
    """
    if seam_ref not in _PRE_SEAM_FALLBACKS or not handle.permit_id or not handle.attempt_id:
        return
    from app.core.config import settings
    from app.db.models.action_integrity import ExecutionPermitV2
    from app.db.models.evidence import DecisionReceipt, EvidenceNode
    from app.services.action_integrity.lifecycle_persistence import (
        persist_execution_receipt_v2_and_comparison,
    )
    from app.services.receipt_service import create_execution_receipt

    if not bool(getattr(settings, "decision_execution_receipts_enabled", False)):
        return
    with Session(bind=db.get_bind(), expire_on_commit=False) as evidence_db:
        with evidence_db.begin():
            permit = evidence_db.scalar(
                select(ExecutionPermitV2).where(
                    ExecutionPermitV2.tenant_id == handle.tenant_id,
                    ExecutionPermitV2.permit_id == handle.permit_id,
                )
            )
            if permit is None or not permit.decision_receipt_id:
                raise PermissionError("generic final seam lacks a durable decision binding")
            decision = evidence_db.scalar(
                select(DecisionReceipt).where(
                    DecisionReceipt.tenant_id == handle.tenant_id,
                    DecisionReceipt.receipt_id == permit.decision_receipt_id,
                )
            )
            canonical_node = (
                evidence_db.scalar(
                    select(EvidenceNode).where(
                        EvidenceNode.tenant_id == handle.tenant_id,
                        EvidenceNode.id == decision.canonical_action_evidence_node_id,
                    )
                )
                if decision is not None
                else None
            )
            payload = dict(canonical_node.payload or {}) if canonical_node is not None else {}
            canonical_action = payload.get("canonical_action")
            if not isinstance(canonical_action, Mapping):
                raise PermissionError("generic final seam decision canonical action is unavailable")
            execution_receipt, _ = create_execution_receipt(
                evidence_db,
                tenant_id=handle.tenant_id,
                decision_receipt_id=permit.decision_receipt_id,
                actual_canonical_action=canonical_action,
                execution_status=execution_status,
                collector_id=f"phase5:{seam_ref}",
                settings_obj=settings,
                executed_at=observed_at,
                execution_attempt_id=handle.attempt_id,
            )
            # A generic callback return has no independent observation of the
            # actual action.  Keep its operation result separate from signed
            # lifecycle proof, which must remain explicitly unresolved.
            persist_execution_receipt_v2_and_comparison(
                evidence_db,
                provider=signing_provider,
                execution_receipt=execution_receipt,
                authorized=handle.action,
                executed={
                    **dict(handle.action),
                    "unresolved_material": ["generic_provider_execution_unverified"],
                },
                permit_id=handle.permit_id,
                issued_at=observed_at,
                evidence_quality="PROVIDER_REPORTED",
            )


def _persist_generic_pre_seam_decision(
    db: Session,
    *,
    provider: SigningKeyProvider,
    tenant_id: str,
    seam_ref: str,
    action: Mapping[str, Any],
    policy_epoch: int,
    now: datetime,
) -> str:
    """Use the existing kernel/native/receipt path once for a route with no decision.

    This is deliberately a fallback for server-owned adapters that have no
    prior authorization result.  Callers with a stored decision must use that
    exact decision; this function is never a retry or repair mechanism.
    """
    from app.core.config import settings
    from app.core.control_engine.authorization import apply_trusted_pre_action_rollout
    from app.services.action_integrity.lifecycle_persistence import (
        persist_decision_receipt_v2_extension,
    )
    from app.services.action_integrity.stored_authority import (
        require_current_profile_selection_v1,
    )
    from app.services.native_control.selection_service import apply_native_selection_to_rollout
    from app.services.receipt_service import persist_pre_execution_decision_in_transaction

    rollout = apply_trusted_pre_action_rollout(
        tenant_id=tenant_id,
        # Generic adapters are all server-side runtime consequences.  They use
        # the existing runtime-control hook rather than expanding the kernel's
        # public surface registry for each product adapter.
        surface="runtime_control",
        action_id=str(action["action_id"]),
        chain_id=str(action["chain_id"]),
        collector_id=f"phase5:{seam_ref}",
        trusted_pre_action_governance_check={
            "actor": {"principal_ref": action["actor_principal"]},
            "authority": {
                "authority_type": "server_verified",
                "authority_source": "phase5_pre_seam",
                "verified": True,
            },
                "surface": {
                    "application": seam_ref,
                    "provider": action["action_semantics"]["tool_or_service_ref"],
                    "asset_status": "registered",
                    "environment": "production",
                },
            "action": {
                "action_type": action["action_semantics"]["operation"],
                "action_risk": "high",
                "tool_name": action["action_semantics"]["tool_or_service_ref"],
                "tool_version": "phase5",
                "tool_fingerprint_id": action["action_semantics"]["tool_fingerprint"],
                "parameter_hash": action["action_semantics"]["safe_parameters"]["parameter_hash"],
                "target_resource": action["resource_scopes"][0],
                "data_destination": action["resource_scopes"][0],
                "side_effect_class": action["action_semantics"]["side_effect"],
            },
            "policy": {"policy_snapshot_id": action["policy_version_id"], "control_ids": []},
        },
        legacy_decision="allow",
        legacy_reason="phase5_generic_pre_seam",
        legacy_control_mode="inline_allowed",
        policy_snapshot_id=str(action["policy_version_id"]),
        settings_obj=settings,
    )
    rollout = apply_native_selection_to_rollout(
        db,
        rollout=rollout,
        settings_obj=settings,
        now=now,
        trusted_provider=str(action["action_semantics"]["tool_or_service_ref"]),
    )
    if (
        not rollout.enforced
        or rollout.request is None
        or rollout.v2_response is None
        or str(rollout.v2_response.decision).lower() not in {"allow", "require_approval"}
    ):
        decision = str(rollout.v2_response.decision) if rollout.v2_response is not None else "missing"
        reason = str(rollout.v2_response.reason) if rollout.v2_response is not None else "missing"
        raise PermissionError(
            f"authoritative generic execution has no enforceable pre-seam authorization: {decision}:{reason}"
        )
    control_selection_id = str(rollout.request.path_evidence.get("native_control_selection_id") or "")
    if not control_selection_id:
        raise PermissionError("authoritative generic execution has no selected native control path")
    from app.db.models.native_control import NativeControlSelection

    native = db.scalar(
        select(NativeControlSelection).where(
            NativeControlSelection.tenant_id == tenant_id,
            NativeControlSelection.selection_id == control_selection_id,
            NativeControlSelection.action_id == action["action_id"],
        )
    )
    if native is None or native.control_requirement_unsatisfied:
        raise PermissionError("authoritative generic execution native control requirement is unsatisfied")
    profile_selection = require_current_profile_selection_v1(
        db,
        provider=provider,
        tenant_id=tenant_id,
        now=now,
    )
    bound_action = dict(action)
    bound_action.update(
        domain_profile_ref=profile_selection.profile_id,
        domain_profile_hash=profile_selection.profile_content_hash,
        policy_epoch=policy_epoch,
        control_plan_id=native.control_plan_id,
        control_plan_digest=native.control_plan_digest,
    )
    receipt, _ = persist_pre_execution_decision_in_transaction(
        db,
        request=rollout.request,
        response=rollout.v2_response,
        settings_obj=settings,
        issued_at=now,
    )
    if receipt is None:
        raise PermissionError("authoritative generic execution receipt persistence is disabled")
    persist_decision_receipt_v2_extension(
        db,
        provider=provider,
        receipt=receipt,
        action=bound_action,
        profile_selection_id=profile_selection.selection_id,
        profile_selection_hash=profile_selection.selection_hash,
        control_selection_id=native.selection_id,
    )
    db.flush()
    # The permit issuer uses an independent transaction; make its decision,
    # profile selection, and native plan visible before the seam is unlocked.
    db.commit()
    return receipt.receipt_id


def install_generic_seam_authority(
    db: Session | None,
    *,
    tenant_id: str | None,
    seam_ref: str,
    action_id: str,
    chain_id: str,
    actor_principal: str,
    executing_principal: str,
    operation: str,
    tool_or_service_ref: str,
    parameter_hash: str,
    target_ref: str,
    ai_system_id: str | None = None,
    approval_requirement: str = "not_required",
    decision_receipt_id: str | None = None,
    now: Callable[[], datetime] | None = None,
) -> TrustedExecutionAuthorityHandle | None:
    """Route every closed production seam through the persisted rollout gate."""
    if db is None:
        return None
    if not tenant_id:
        if str(db.info.get("phase5_rollout_mode", "DISABLED")) == "AUTHORITATIVE":
            raise PermissionError("authoritative execution requires tenant-scoped authority material")
        return None
    mode, epoch = current_rollout_configuration(db, tenant_id=tenant_id)
    db.info["phase5_rollout_mode"] = mode
    if mode != "AUTHORITATIVE":
        db.info.pop("phase5_execution_authority", None)
        db.info.pop("phase5_execution_seam_adapter", None)
        return None
    evaluated_at = _utc((now or (lambda: datetime.now(timezone.utc)))())
    action = build_trusted_execution_action(
        tenant_id=tenant_id,
        action_id=action_id,
        chain_id=chain_id,
        actor_principal=actor_principal,
        executing_principal=executing_principal,
        operation=operation,
        tool_or_service_ref=tool_or_service_ref,
        tool_fingerprint=domain_hash("hawk:closed-seam-fingerprint:v1", {"seam": seam_ref, "tool": tool_or_service_ref}),
        parameter_hash=parameter_hash,
        target_ref=target_ref,
        policy_epoch=epoch,
        approval_requirement=approval_requirement,
        policy_version_id="phase5:persisted-rollout",
        now=evaluated_at,
    )
    provider = db.info.get("phase5_signing_provider") or KmsHsmSigningKeyProvider()
    from .stored_authority import bind_generic_action_to_current_decision_authority_v1
    from app.db.models.action_integrity import DecisionReceiptV2Extension

    existing_decision = db.scalar(
        select(DecisionReceiptV2Extension.receipt_id).where(
            DecisionReceiptV2Extension.tenant_id == tenant_id,
            DecisionReceiptV2Extension.action_id == action["action_id"],
            DecisionReceiptV2Extension.authority_binding_version == 1,
        )
    )
    if decision_receipt_id is not None or existing_decision is not None:
        # Binding verifies signed current authority under row locks.  Close
        # that read transaction before the durable permit issuer opens its own
        # transaction and revalidates the same authority; otherwise
        # PostgreSQL correctly deadlocks the issuer behind our own lock.
        with Session(bind=db.get_bind(), expire_on_commit=False) as binding_db:
            decision_receipt_id, action = bind_generic_action_to_current_decision_authority_v1(
                binding_db,
                provider=provider,
                tenant_id=tenant_id,
                decision_receipt_id=decision_receipt_id,
                generic_action=action,
                now=evaluated_at,
            )
    elif seam_ref in _PRE_SEAM_FALLBACKS:
        decision_receipt_id = _persist_generic_pre_seam_decision(
            db,
            provider=provider,
            tenant_id=tenant_id,
            seam_ref=seam_ref,
            action=action,
            policy_epoch=epoch,
            now=evaluated_at,
        )
        with Session(bind=db.get_bind(), expire_on_commit=False) as binding_db:
            decision_receipt_id, action = bind_generic_action_to_current_decision_authority_v1(
                binding_db,
                provider=provider,
                tenant_id=tenant_id,
                decision_receipt_id=decision_receipt_id,
                generic_action=action,
                now=evaluated_at,
            )
    else:
        raise PermissionError("generic execution has no stored decision authority")
    return install_execution_authority(
        db,
        tenant_id=tenant_id,
        action=action,
        seam_ref=seam_ref,
        signing_provider=provider,
        ai_system_id=ai_system_id,
        decision_receipt_id=decision_receipt_id,
        now=now,
    )


def invoke_final_seam(db: Session | None, *, seam_ref: str, executor: Callable[[], Any]) -> Any:
    """Invoke a protected callback with an internal, never request-derived handle.

    In an explicitly authoritative request, a missing/malformed handle fails
    before the callback. Disabled/observe/shadow contexts preserve their legacy
    execution behavior and cannot accidentally mint V2 authority here.
    """
    # The secure gateway also supports an explicitly database-free legacy mode;
    # no V2 rollout/handle can exist there, so retain that behavior unchanged.
    if db is None:
        return executor()
    mode = str(db.info.get("phase5_rollout_mode", "DISABLED"))
    handle = db.info.get("phase5_execution_authority")
    adapter = db.info.get("phase5_execution_seam_adapter")
    if handle is None:
        if mode == "AUTHORITATIVE":
            raise PermissionError("authoritative execution is missing a trusted permit handle")
        return executor()
    if not isinstance(handle, TrustedExecutionAuthorityHandle) or not isinstance(adapter, AuthoritativeExecutionSeamAdapter):
        raise PermissionError("untrusted execution authority handle")
    if handle.rollout_mode != mode or adapter._seam_ref != seam_ref:
        raise PermissionError("execution authority handle is not bound to this seam")
    try:
        allowed, result = adapter.invoke(
            permit_id=handle.permit_id,
            tenant_id=handle.tenant_id,
            action=handle.action,
            rollout_mode=handle.rollout_mode,
            executor=executor,
        )
    except BaseException:
        _persist_generic_final_execution_evidence(
            db,
            handle=handle,
            seam_ref=seam_ref,
            execution_status="failure",
            signing_provider=adapter._authority._signing_provider,
            observed_at=_utc(adapter._authority._now()),
        )
        raise
    if not allowed:
        raise PermissionError("execution permit was not eligible at the final seam")
    _persist_generic_final_execution_evidence(
        db,
        handle=handle,
        seam_ref=seam_ref,
        execution_status="unverified",
        signing_provider=adapter._authority._signing_provider,
        observed_at=_utc(adapter._authority._now()),
    )
    return result
