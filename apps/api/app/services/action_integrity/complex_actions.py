"""Generic complex-action helpers; child authority can only be attenuated."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from datetime import datetime
from typing import Any, Mapping
from uuid import uuid4

from .canonical_v2 import domain_hash
from .signing import SigningKeyProvider, active_key_id, sign_object, verify_signed_object


ACTION_PLAN_DOMAIN = "hawk:action-plan:v1"
ACTION_PLAN_HASH_DOMAIN = "hawk:action-plan-envelope-hash:v1"
ACTION_PLAN_STEP_DOMAIN = "hawk:action-plan-step:v1"
PERSISTENT_EFFECT_TRANSITION_DOMAIN = "hawk:persistent-effect-transition:v1"
EXPECTED_OUTCOME_DOMAIN = "hawk:expected-outcome-contract:v1"
OUTCOME_VERIFICATION_DOMAIN = "hawk:outcome-verification:v1"
_EFFECT_EDGES = {
    "CREATED": {"ACTIVE", "MODIFIED", "EXPIRED", "REVOKED", "DELETED", "ORPHANED", "UNKNOWN"},
    "ACTIVE": {"MODIFIED", "EXPIRED", "REVOKED", "DELETED", "ORPHANED", "UNKNOWN"},
    "MODIFIED": {"VERIFIED_RECOVERED", "EXPIRED", "REVOKED", "DELETED", "ORPHANED", "UNKNOWN"},
    "ORPHANED": {"VERIFIED_RECOVERED", "REVOKED", "DELETED", "UNKNOWN"},
    "UNKNOWN": {"VERIFIED_RECOVERED", "EXPIRED", "REVOKED", "DELETED"},
}
_EFFECT_TERMINAL = frozenset({"EXPIRED", "REVOKED", "DELETED", "VERIFIED_RECOVERED"})
_EXECUTION_EDGES = {
    "PROPOSED": {"AWAITING_POLICY"},
    "AWAITING_POLICY": {"AWAITING_APPROVAL", "AUTHORISED", "BLOCKED"},
    "AWAITING_APPROVAL": {"AUTHORISED", "BLOCKED", "CANCELLED", "EXPIRED"},
    "AUTHORISED": {"PERMIT_ISSUED", "CANCELLED", "EXPIRED"},
    "PERMIT_ISSUED": {"EXECUTION_STARTED", "QUEUED", "BLOCKED", "CANCELLED", "EXPIRED", "UNVERIFIED", "UNKNOWN"},
    "QUEUED": {"EXECUTION_STARTED", "IN_PROGRESS", "EXECUTED", "PARTIALLY_EXECUTED", "FAILED", "CANCELLED", "EXPIRED", "DRIFTED", "UNVERIFIED", "UNKNOWN"},
    "EXECUTION_STARTED": {"IN_PROGRESS", "EXECUTED", "PARTIALLY_EXECUTED", "FAILED", "CANCELLED", "DRIFTED", "UNVERIFIED", "UNKNOWN"},
    "IN_PROGRESS": {"EXECUTED", "PARTIALLY_EXECUTED", "FAILED", "CANCELLED", "DRIFTED", "UNVERIFIED", "UNKNOWN"},
    "UNVERIFIED": {"BLOCKED", "EXECUTED", "PARTIALLY_EXECUTED", "FAILED", "CANCELLED", "EXPIRED", "DRIFTED", "UNKNOWN"},
    "UNKNOWN": {"BLOCKED", "EXECUTED", "PARTIALLY_EXECUTED", "FAILED", "CANCELLED", "EXPIRED", "DRIFTED"},
}


def issue_action_plan(
    provider: SigningKeyProvider,
    *,
    tenant_id: str,
    parent_action_id: str,
    steps: list[Mapping[str, Any]],
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Issue an ordered immutable plan with step digests before child binding."""
    if not tenant_id or not parent_action_id or issued_at >= expires_at or not steps:
        raise ValueError("invalid action-plan inputs")
    plan_id = str(uuid4())
    normalized_steps: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sequence, raw in enumerate(steps, start=1):
        step = dict(raw)
        step_id = str(step.get("step_id") or "")
        child_action_id = str(step.get("child_action_id") or "")
        mode = str(step.get("authority_mode") or "")
        unbound = str(step.get("unbound_material_fields_hash") or "")
        max_executions = step.get("max_executions", 1)
        predecessors = list(step.get("permitted_predecessor_step_ids") or [])
        if (
            not step_id or step_id in seen or not child_action_id
            or mode not in {"SEPARATE_DECISION", "SCOPED_PARENT_PERMIT"}
            or len(unbound) != 64 or any(char not in "0123456789abcdef" for char in unbound.lower())
            or not isinstance(max_executions, int) or not 1 <= max_executions <= 100
            or predecessors != sorted(set(str(value) for value in predecessors))
            or any(predecessor not in seen for predecessor in predecessors)
        ):
            raise ValueError("invalid action-plan step")
        seen.add(step_id)
        normalized_steps.append({
            "step_id": step_id, "sequence": sequence, "child_action_id": child_action_id,
            "authority_mode": mode, "unbound_material_fields_hash": unbound,
            "required": bool(step.get("required", True)),
            "max_executions": max_executions,
            "permitted_predecessor_step_ids": predecessors,
            "expected_child_action_class": step.get("expected_child_action_class"),
            "resource_boundary_hash": step.get("resource_boundary_hash"),
            "target_boundary_hash": step.get("target_boundary_hash"),
            "destination_boundary_hash": step.get("destination_boundary_hash"),
            "compensation_action_ref": step.get("compensation_action_ref"),
        })
    if len(normalized_steps) > 100:
        raise ValueError("action-plan exceeds maximum step count")
    unsigned = {
        "schema_version": "1.0", "plan_id": plan_id, "tenant_id": tenant_id, "parent_action_id": parent_action_id,
        "plan_version": 1, "issued_at": issued_at.isoformat(), "expires_at": expires_at.isoformat(), "steps": normalized_steps,
        "resource_boundary_hash": None, "target_boundary_hash": None, "destination_boundary_hash": None,
        "max_total_executions": len(normalized_steps), "completion_rule": "ALL_REQUIRED", "compensation_action_refs": [],
    }
    key_id = active_key_id(provider, purpose="action_plan_signing", tenant_id=tenant_id)
    signed = sign_object(provider, purpose="action_plan_signing", domain=ACTION_PLAN_DOMAIN, tenant_id=tenant_id, key_id=key_id, value=unsigned)
    signed["plan_digest"] = domain_hash(ACTION_PLAN_HASH_DOMAIN, signed)
    for step in signed["steps"]:
        step["step_digest"] = domain_hash(
            ACTION_PLAN_STEP_DOMAIN,
            {"action_plan_digest": signed["plan_digest"], "parent_action_id": parent_action_id, "plan_id": plan_id, "plan_version": 1, "step": dict(step), "tenant_id": tenant_id},
        )
    return signed


def verify_action_plan(provider: SigningKeyProvider, plan: Mapping[str, Any]) -> bool:
    tenant_id = plan.get("tenant_id")
    if not isinstance(tenant_id, str) or not verify_signed_object(provider, purpose="action_plan_signing", domain=ACTION_PLAN_DOMAIN, tenant_id=tenant_id, value=dict(plan), current_authority=True):
        # Step digests are intentionally outside the signed body only after the
        # signed plan digest is made. Reconstruct the pre-step signed envelope.
        raw = dict(plan)
        raw.pop("plan_digest", None)
        raw["steps"] = [{key: value for key, value in dict(step).items() if key != "step_digest"} for step in raw.get("steps", [])]
        if not isinstance(tenant_id, str) or not verify_signed_object(provider, purpose="action_plan_signing", domain=ACTION_PLAN_DOMAIN, tenant_id=tenant_id, value=raw, current_authority=True):
            return False
    unsigned = dict(plan)
    digest = unsigned.pop("plan_digest", None)
    unsigned["steps"] = [{key: value for key, value in dict(step).items() if key != "step_digest"} for step in unsigned.get("steps", [])]
    if digest != domain_hash(ACTION_PLAN_HASH_DOMAIN, unsigned):
        return False
    for expected_sequence, step in enumerate(plan.get("steps", []), start=1):
        if not isinstance(step, Mapping) or step.get("sequence") != expected_sequence:
            return False
        raw_step = {key: value for key, value in dict(step).items() if key != "step_digest"}
        expected = domain_hash(ACTION_PLAN_STEP_DOMAIN, {"action_plan_digest": digest, "parent_action_id": plan.get("parent_action_id"), "plan_id": plan.get("plan_id"), "plan_version": plan.get("plan_version"), "step": raw_step, "tenant_id": tenant_id})
        if step.get("step_digest") != expected:
            return False
    return True


def next_persistent_effect_state(*, current_state: str, requested_state: str, evidence_quality: str, remediation_verified: bool = False) -> str:
    """Apply the closed durable-effect DAG without turning uncertainty into success."""
    if current_state in _EFFECT_TERMINAL or requested_state not in _EFFECT_EDGES.get(current_state, set()):
        raise ValueError("illegal persistent-effect transition")
    if requested_state == "VERIFIED_RECOVERED" and (evidence_quality != "INDEPENDENTLY_VERIFIED" or not remediation_verified):
        raise ValueError("verified recovery requires independent remediation evidence")
    return requested_state


def next_execution_state(*, current_state: str, requested_state: str, verified_non_invocation: bool = False, execution_evidence: bool = False) -> str:
    """Validate the frozen async execution DAG before a durable callback is folded."""
    if requested_state not in _EXECUTION_EDGES.get(current_state, set()):
        raise ValueError("illegal execution lifecycle transition")
    if requested_state == "BLOCKED" and not verified_non_invocation:
        raise ValueError("blocked execution requires verified non-invocation")
    if requested_state in {"EXECUTED", "PARTIALLY_EXECUTED"} and not execution_evidence:
        raise ValueError("executed state requires execution evidence")
    return requested_state


def validate_planned_child(
    plan: Mapping[str, Any],
    *,
    child_action_id: str,
    step_id: str,
    unbound_material_fields_hash: str,
    completed_step_ids: set[str] | None = None,
    step_execution_count: int = 0,
    plan_execution_count: int = 0,
    now: datetime | None = None,
) -> Mapping[str, Any]:
    """Return the exact declared step or fail closed before child execution."""
    expires_at = datetime.fromisoformat(str(plan["expires_at"]).replace("Z", "+00:00"))
    if now is not None and now >= expires_at:
        raise PermissionError("action plan is expired")
    steps = list(plan.get("steps") or [])
    step = next((candidate for candidate in steps if candidate.get("step_id") == step_id), None)
    if step is None or step.get("child_action_id") != child_action_id:
        raise PermissionError("planned child is not declared by the signed action plan")
    if step.get("unbound_material_fields_hash") != unbound_material_fields_hash:
        raise PermissionError("planned child material does not match the signed step")
    completed = completed_step_ids or set()
    if not set(step.get("permitted_predecessor_step_ids") or []).issubset(completed):
        raise PermissionError("planned child predecessor requirement is not complete")
    if step_execution_count >= int(step.get("max_executions", 1)) or plan_execution_count >= int(plan.get("max_total_executions", len(steps))):
        raise PermissionError("planned child execution limit reached")
    return step


def issue_persistent_effect_transition(
    provider: SigningKeyProvider,
    *,
    tenant_id: str,
    effect_id: str,
    sequence: int,
    current_state: str,
    requested_state: str,
    prior_state_version: int,
    prior_transition_id: str | None,
    prior_transition_hash: str | None,
    evidence_quality: str,
    observed_at: datetime,
    idempotency_key: str,
    evidence_refs: list[str] | None = None,
    observed_object_hash: str | None = None,
    last_verified_at: datetime | None = None,
    verification_valid_until: datetime | None = None,
    recovery_basis: str = "NONE",
    remediation_action_id: str | None = None,
    remediation_attempt_id: str | None = None,
    remediation_execution_receipt_id: str | None = None,
    remediation_outcome_verification_id: str | None = None,
    reason_code: str | None = None,
    received_at: datetime | None = None,
    remediation_verified: bool = False,
) -> dict[str, Any]:
    """Create the append-only signed transition envelope; no projection authority."""
    effect_id = str(effect_id)
    verification_source_refs = sorted({str(value) for value in evidence_refs or []})
    if sequence < 1 or prior_state_version < 0 or not idempotency_key:
        raise ValueError("invalid persistent effect transition inputs")
    if sequence == 1 and (prior_transition_id is not None or prior_transition_hash is not None):
        raise ValueError("first effect transition must not name a predecessor")
    if sequence > 1 and (not prior_transition_id or not prior_transition_hash):
        raise ValueError("effect transition predecessor is required")
    next_persistent_effect_state(current_state=current_state, requested_state=requested_state, evidence_quality=evidence_quality, remediation_verified=remediation_verified)
    key_id = active_key_id(provider, purpose="persistent_effect_signing", tenant_id=tenant_id)
    return sign_object(provider, purpose="persistent_effect_signing", domain=PERSISTENT_EFFECT_TRANSITION_DOMAIN, tenant_id=tenant_id, key_id=key_id, value={
        "schema_version": "1.0", "transition_id": str(uuid4()), "tenant_id": tenant_id, "effect_id": effect_id,
        "sequence": sequence, "from_state": current_state, "to_state": requested_state,
        "prior_state_version": prior_state_version, "new_state_version": prior_state_version + 1,
        "prior_transition_id": prior_transition_id, "prior_transition_hash": prior_transition_hash,
        "transition_kind": "STATE_CHANGE", "observed_object_hash": observed_object_hash,
        "evidence_quality": evidence_quality,
        "verification_source_refs": verification_source_refs,
        "last_verified_at": last_verified_at.isoformat() if last_verified_at else None,
        "verification_valid_until": verification_valid_until.isoformat() if verification_valid_until else None,
        "recovery_basis": recovery_basis,
        "remediation_action_id": remediation_action_id,
        "remediation_attempt_id": remediation_attempt_id,
        "remediation_execution_receipt_id": remediation_execution_receipt_id,
        "remediation_outcome_verification_id": remediation_outcome_verification_id,
        "reason_code": reason_code,
        "idempotency_key": idempotency_key,
        "observed_at": observed_at.isoformat(),
        "received_at": (received_at or observed_at).isoformat(),
    })


def issue_expected_outcome_contract(
    provider: SigningKeyProvider,
    *, tenant_id: str, action_id: str, expected_state_hash: str | None,
    verification_deadline: datetime, issued_at: datetime,
) -> dict[str, Any]:
    if verification_deadline <= issued_at:
        raise ValueError("outcome verification deadline is invalid")
    key_id = active_key_id(provider, purpose="outcome_verification_signing", tenant_id=tenant_id)
    return sign_object(provider, purpose="outcome_verification_signing", domain=EXPECTED_OUTCOME_DOMAIN, tenant_id=tenant_id, key_id=key_id, value={
        "schema_version": "1.0", "outcome_contract_id": str(uuid4()), "tenant_id": tenant_id,
        "action_id": action_id, "expected_state_hash": expected_state_hash,
        "verification_deadline": verification_deadline.isoformat(), "issued_at": issued_at.isoformat(), "evidence_refs": [],
    })


def issue_outcome_verification(
    provider: SigningKeyProvider,
    *, tenant_id: str, action_id: str, attempt_id: str, outcome_contract_id: str,
    result: str, verification_source_refs: list[str], evidence_quality: str, evaluated_at: datetime,
) -> dict[str, Any]:
    if result not in {"SATISFIED", "VIOLATED", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE"}:
        raise ValueError("outcome verification result is invalid")
    if result == "SATISFIED" and (evidence_quality == "PROVIDER_REPORTED" or not verification_source_refs):
        raise PermissionError("provider success cannot prove an outcome")
    key_id = active_key_id(provider, purpose="outcome_verification_signing", tenant_id=tenant_id)
    sources = sorted(set(verification_source_refs))
    return sign_object(provider, purpose="outcome_verification_signing", domain=OUTCOME_VERIFICATION_DOMAIN, tenant_id=tenant_id, key_id=key_id, value={
        "schema_version": "1.0", "verification_id": str(uuid4()), "tenant_id": tenant_id, "action_id": action_id,
        "attempt_id": attempt_id, "outcome_contract_id": outcome_contract_id, "result": result,
        "verification_source_refs": sources, "verification_source_set_hash": domain_hash("hawk:outcome-verification-sources:v1", sources),
        "evidence_quality": evidence_quality, "evaluated_at": evaluated_at.isoformat(),
    })


def verify_expected_outcome_contract(
    provider: SigningKeyProvider, contract: Mapping[str, Any]
) -> bool:
    """Verify only the frozen outcome-contract signature domain and tenant."""
    tenant_id = contract.get("tenant_id")
    return (
        isinstance(tenant_id, str)
        and verify_signed_object(
            provider,
            purpose="outcome_verification_signing",
            domain=EXPECTED_OUTCOME_DOMAIN,
            tenant_id=tenant_id,
            value=dict(contract),
            current_authority=False,
        )
    )


def verify_outcome_verification(
    provider: SigningKeyProvider, verdict: Mapping[str, Any]
) -> bool:
    """Verify a signed verdict without treating the provider result as proof."""
    tenant_id = verdict.get("tenant_id")
    if not isinstance(tenant_id, str) or verdict.get("result") not in {
        "SATISFIED", "VIOLATED", "PARTIAL", "UNKNOWN", "NOT_APPLICABLE"
    }:
        return False
    return verify_signed_object(
        provider,
        purpose="outcome_verification_signing",
        domain=OUTCOME_VERIFICATION_DOMAIN,
        tenant_id=tenant_id,
        value=dict(verdict),
        current_authority=False,
    )


def delegated_child_is_attenuated(parent: Mapping[str, Any], child: Mapping[str, Any]) -> bool:
    try:
        parent_resources = set(parent["resources"])
        parent_operations = set(parent["operations"])
        return set(child["resources"]).issubset(parent_resources) and set(child["operations"]).issubset(parent_operations) and Decimal(str(child["max_value"])) <= Decimal(str(parent["max_value"]))
    except (KeyError, InvalidOperation):
        return False
