"""Signed V2 approval authority and exact permitted-variation envelopes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping
from uuid import uuid4

from .canonical_v2 import canonical_action_hash_v2, domain_hash
from .materiality import material_fields, material_fields_hash
from .signing import SigningKeyProvider, active_key_id, sign_object, verify_signed_object


VARIATION_DOMAIN = "hawk:permitted-variation-envelope:v1"
VARIATION_HASH_DOMAIN = "hawk:permitted-variation-envelope-hash:v1"
BINDING_DOMAIN = "hawk:approval-binding:v2"
BINDING_HASH_DOMAIN = "hawk:approval-binding-envelope-hash:v1"
_ONE_OF_PATHS = {
    "action_semantics.operation",
    "action_semantics.safe_parameters",
    "resource_scopes[*]",
    "action_semantics.counterparty_refs[*]",
    "action_semantics.target_refs[*]",
    "action_semantics.destination_refs[*]",
    "action_semantics.values_or_quantities[*]",
}


@dataclass(frozen=True, slots=True)
class ApprovalBindingV2:
    approval_request_id: str
    tenant_id: str
    decision_receipt_id: str
    control_selection_id: str
    canonical_action_hash: str
    material_fields_hash: str
    policy_epoch: int
    expires_at: datetime
    use_limit: int = 1

    def eligible(self, *, tenant_id: str, policy_epoch: int, now: datetime) -> bool:
        return self.tenant_id == tenant_id and self.policy_epoch == policy_epoch and self.use_limit > 0 and now < self.expires_at

    @property
    def binding_hash(self) -> str:
        return domain_hash(
            BINDING_HASH_DOMAIN,
            {
                "approval_request_id": self.approval_request_id,
                "tenant_id": self.tenant_id,
                "decision_receipt_id": self.decision_receipt_id,
                "control_selection_id": self.control_selection_id,
                "canonical_action_hash": self.canonical_action_hash,
                "material_fields_hash": self.material_fields_hash,
                "policy_epoch": self.policy_epoch,
                "expires_at": self.expires_at.isoformat(),
                "use_limit": self.use_limit,
            },
        )


@dataclass(frozen=True, slots=True)
class IssuedApprovalBinding:
    binding: dict[str, Any]
    variation: dict[str, Any]
    binding_hash: str
    variation_hash: str


def _profile_parts(action: Mapping[str, Any], request_payload: Mapping[str, Any]) -> tuple[str, str, str, str, str, str]:
    profile = str(action.get("domain_profile_ref") or "")
    profile_version = str(request_payload.get("domain_profile_version") or "1.0")
    profile_hash = str(action.get("domain_profile_hash") or "")
    materiality = str(action.get("materiality_profile_ref") or "")
    materiality_version = str(request_payload.get("materiality_profile_version") or "1.0")
    materiality_hash = str(action.get("materiality_profile_hash") or "")
    if not all((profile, profile_hash, materiality, materiality_hash)):
        raise ValueError("approval request does not contain a complete profile binding")
    return profile, profile_version, profile_hash, materiality, materiality_version, materiality_hash


def issue_exact_approval_binding(
    provider: SigningKeyProvider,
    *,
    tenant_id: str,
    approval_request_id: str,
    action: Mapping[str, Any],
    request_payload: Mapping[str, Any],
    approver_principal_ref: str,
    approver_role: str,
    issued_at: datetime,
    expires_at: datetime,
    use_limit: int = 1,
) -> IssuedApprovalBinding:
    """Create the immutable exact-only variation and approval envelopes together."""
    if action.get("tenant_id") != tenant_id or not (1 <= use_limit <= 100) or issued_at >= expires_at:
        raise ValueError("invalid approval binding inputs")
    profile, profile_version, profile_hash, materiality, materiality_version, materiality_hash = _profile_parts(action, request_payload)
    action_hash = canonical_action_hash_v2(action)
    fields_hash = material_fields_hash(action)
    selection_id = str(request_payload.get("profile_selection_id") or "")
    selection_hash = str(request_payload.get("profile_selection_hash") or "")
    decision_receipt_id = str(request_payload.get("decision_receipt_id") or "")
    control_selection_id = str(request_payload.get("control_selection_id") or "")
    control_plan_id = str(action.get("control_plan_id") or "")
    control_plan_digest = str(action.get("control_plan_digest") or "")
    if not all((decision_receipt_id, selection_id, selection_hash, control_selection_id, control_plan_id, control_plan_digest)):
        raise ValueError("approval request does not contain current selection/control-plan bindings")

    variation_key = active_key_id(provider, purpose="permitted_variation_signing", tenant_id=tenant_id)
    variation = sign_object(
        provider,
        purpose="permitted_variation_signing",
        domain=VARIATION_DOMAIN,
        tenant_id=tenant_id,
        key_id=variation_key,
        value={
            "schema_version": "1.0",
            "envelope_id": str(uuid4()),
            "tenant_id": tenant_id,
            "approval_request_id": approval_request_id,
            "decision_receipt_id": decision_receipt_id,
            "base_canonical_action_hash": action_hash,
            "base_material_fields_hash": fields_hash,
            "materiality_profile_id": materiality,
            "materiality_profile_version": materiality_version,
            "materiality_profile_hash": materiality_hash,
            "domain_profile_id": profile,
            "domain_profile_version": profile_version,
            "domain_profile_hash": profile_hash,
            "profile_selection_id": selection_id,
            "profile_selection_hash": selection_hash,
            "control_selection_id": control_selection_id,
            "policy_version_id": str(action.get("policy_version_id") or ""),
            "policy_epoch": int(action.get("policy_epoch") or 0),
            "control_plan_id": control_plan_id,
            "control_plan_digest": control_plan_digest,
            "matchers": [],
            "not_before": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "use_limit": use_limit,
            "issued_at": issued_at.isoformat(),
        },
    )
    variation_hash = domain_hash(VARIATION_HASH_DOMAIN, variation)
    binding_key = active_key_id(provider, purpose="approval_binding_signing", tenant_id=tenant_id)
    rendering = request_payload.get("trusted_approval_rendering") or {
        "canonical_action_hash": action_hash,
        "material_fields_hash": fields_hash,
        "operation": action.get("action_semantics", {}).get("operation") if isinstance(action.get("action_semantics"), Mapping) else None,
    }
    binding = sign_object(
        provider,
        purpose="approval_binding_signing",
        domain=BINDING_DOMAIN,
        tenant_id=tenant_id,
        key_id=binding_key,
        value={
            "schema_version": "2.0",
            "approval_binding_id": str(uuid4()),
            "approval_request_id": approval_request_id,
            "tenant_id": tenant_id,
            "authority_binding_version": 1,
            "decision_receipt_id": decision_receipt_id,
            "approver_principal_ref": approver_principal_ref,
            "approver_role": approver_role,
            "canonical_action_hash": action_hash,
            "domain_profile_id": profile,
            "domain_profile_version": profile_version,
            "domain_profile_hash": profile_hash,
            "profile_selection_id": selection_id,
            "profile_selection_hash": selection_hash,
            "control_selection_id": control_selection_id,
            "materiality_profile_id": materiality,
            "materiality_profile_version": materiality_version,
            "materiality_profile_hash": materiality_hash,
            "material_fields_hash": fields_hash,
            "authority_scope_hash": domain_hash("hawk:approval-authority-scope:v1", {"action": action_hash, "fields": fields_hash}),
            "permitted_variation_envelope_id": variation["envelope_id"],
            "permitted_variation_hash": variation_hash,
            "trusted_approval_rendering_hash": domain_hash("hawk:trusted-approval-rendering:v1", rendering),
            "untrusted_agent_context_hash": domain_hash("hawk:untrusted-agent-context:v1", request_payload.get("untrusted_agent_context") or {}),
            "policy_version_id": str(action.get("policy_version_id") or ""),
            "policy_epoch": int(action.get("policy_epoch") or 0),
            "control_plan_id": control_plan_id,
            "control_plan_digest": control_plan_digest,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "nonce": str(uuid4()),
            "use_limit": use_limit,
            "approval_decision": "APPROVED",
        },
    )
    return IssuedApprovalBinding(binding=binding, variation=variation, binding_hash=domain_hash(BINDING_HASH_DOMAIN, binding), variation_hash=variation_hash)


def variation_matches(
    envelope: Mapping[str, Any],
    *,
    candidate: Mapping[str, Any],
    provider: SigningKeyProvider,
    now: datetime,
) -> bool:
    """Validate the frozen exact/ONE_OF language against complete material fields."""
    tenant_id = str(envelope.get("tenant_id") or "")
    if not tenant_id or candidate.get("tenant_id") != tenant_id or not verify_signed_object(provider, purpose="permitted_variation_signing", domain=VARIATION_DOMAIN, tenant_id=tenant_id, value=dict(envelope), current_authority=True):
        return False
    try:
        if not (datetime.fromisoformat(str(envelope["not_before"])).astimezone() <= now.astimezone() < datetime.fromisoformat(str(envelope["expires_at"])).astimezone()):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    fields = material_fields(candidate)
    if material_fields_hash(candidate) == envelope.get("base_material_fields_hash") and canonical_action_hash_v2(candidate) == envelope.get("base_canonical_action_hash"):
        return True
    matchers = envelope.get("matchers")
    if not isinstance(matchers, list) or len(matchers) > 16:
        return False
    declared: dict[str, Mapping[str, Any]] = {}
    for matcher in matchers:
        if not isinstance(matcher, Mapping) or not isinstance(matcher.get("path"), str) or matcher["path"] in declared:
            return False
        path = matcher["path"]
        kind = matcher.get("matcher_kind")
        if kind == "ONE_OF":
            allowed = matcher.get("allowed_field_hashes")
            if path not in _ONE_OF_PATHS or not isinstance(allowed, list) or not (1 <= len(allowed) <= 16) or sorted(allowed) != allowed or len(set(allowed)) != len(allowed):
                return False
        elif kind != "EXACT":
            return False
        declared[path] = matcher
    base_fields = request_fields = envelope.get("base_fields")
    # V1 exact-only envelopes carry no base-field map: action hash equality is the
    # only valid candidate in that representation. New variable envelopes must
    # include every base field explicitly, avoiding implicit wildcard semantics.
    if not isinstance(base_fields, Mapping) or set(base_fields) != set(fields):
        return False
    for path, field_hash in fields.items():
        matcher = declared.get(path)
        if matcher is None:
            if field_hash != base_fields[path]:
                return False
        elif matcher["matcher_kind"] == "EXACT":
            if matcher.get("exact_field_hash") != base_fields[path] or field_hash != base_fields[path] or matcher.get("allowed_field_hashes") not in ([], None):
                return False
        elif field_hash not in matcher["allowed_field_hashes"]:
            return False
    return True
