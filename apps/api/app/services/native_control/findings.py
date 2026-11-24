from __future__ import annotations

from datetime import datetime, timezone
import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.finding import Finding


# Frozen Phase 5 producer contract (CODEX_INTERFACE_REGISTRY §15).  This is a
# registry only: producers remain responsible for making the underlying policy,
# authority, permit, or execution decision.  Evidence labels are bounded
# references/classes, never raw request or secret material.
PHASE5_FINDING_CATALOG: dict[str, dict[str, object]] = {
    "SUBJECT_BOUNDARY_VIOLATION": {"severity": "high", "required_evidence": ("resolved_subject", "violating_request"), "recommended_action": "Block the violating request and revalidate the represented subject boundary."},
    "RESOURCE_SCOPE_VIOLATION": {"severity": "high", "required_evidence": ("resolved_resource_scope", "violating_request"), "recommended_action": "Block the violating request and revalidate the exact resource scope."},
    "PURPOSE_MISMATCH": {"severity": "high", "required_evidence": ("current_purpose", "policy_decision"), "recommended_action": "Require reauthorization with a verified current business purpose."},
    "AUTHORITY_EXCEEDED": {"severity": "high", "required_evidence": ("current_authority", "policy_decision"), "recommended_action": "Block the action and restore an authority scope that covers the requested operation."},
    "DELEGATION_AUTHORITY_EXPANDED": {"severity": "critical", "required_evidence": ("parent_child_edge", "authority_diff"), "recommended_action": "Revoke the expanded delegation and investigate the parent-to-child authority change."},
    "TOOL_FINGERPRINT_CHANGED": {"severity": "high", "required_evidence": ("authorized_fingerprint", "actual_fingerprint"), "recommended_action": "Stop the changed tool route and require a fresh decision for the exact fingerprint."},
    "ACTION_PARAMETER_DRIFT": {"severity": "high", "required_evidence": ("authorized_actual_field_diff",), "recommended_action": "Contain the action and require reauthorization for the changed material parameter."},
    "ACTION_TARGET_DRIFT": {"severity": "high", "required_evidence": ("authorized_actual_field_diff",), "recommended_action": "Contain the action and require reauthorization for the changed target."},
    "ACTION_DESTINATION_DRIFT": {"severity": "high", "required_evidence": ("authorized_actual_field_diff",), "recommended_action": "Contain the action and require reauthorization for the changed destination."},
    "ACTION_VALUE_DRIFT": {"severity": "high", "required_evidence": ("authorized_actual_field_diff",), "recommended_action": "Contain the action and require reauthorization for the changed value or quantity."},
    "APPROVAL_INVALIDATED": {"severity": "high", "required_evidence": ("approval_binding", "invalidating_material_or_currentness_change"), "recommended_action": "Invalidate the approval and require a new approval decision against current material."},
    "EXECUTION_PERMIT_MISMATCH": {"severity": "critical", "required_evidence": ("execution_permit", "recomputed_material_diff"), "recommended_action": "Block execution and issue no replacement permit until current material is reauthorized."},
    "EXECUTION_DRIFT_DETECTED": {"severity": "critical", "required_evidence": ("comparator_result", "execution_evidence"), "recommended_action": "Contain the action and invalidate authorization or approval."},
    "EXECUTION_UNVERIFIED": {"severity": "medium", "required_evidence": ("missing_or_insufficient_execution_evidence",), "recommended_action": "Keep outcome status unknown and collect independent execution evidence."},
    "PERSISTENT_EFFECT_CREATED": {"severity": "medium", "required_evidence": ("effect_receipt", "verification_history"), "recommended_action": "Track the persistent effect until verified lifecycle evidence resolves it."},
    "PERSISTENT_EFFECT_DRIFT": {"severity": "high", "required_evidence": ("effect_receipt", "verification_history"), "recommended_action": "Contain the drifting persistent effect and require verified remediation evidence."},
    "CONTROL_PLAN_DOWNGRADED": {"severity": "critical", "required_evidence": ("authorized_current_plan_diff",), "recommended_action": "Block the downgraded route and restore the authorized current control plan."},
    "DOMAIN_INVARIANT_FAILED": {"severity": "high", "required_evidence": ("invariant_profile_version", "normalized_inputs"), "recommended_action": "Block the violating action and correct or reselect the reviewed domain profile."},
    "OUTCOME_MISMATCH": {"severity": "high", "required_evidence": ("expected_actual_outcome_evidence",), "recommended_action": "Contain the mismatch and require verified outcome remediation."},
    "UNKNOWN_ACTION_SEMANTICS": {"severity": "medium", "required_evidence": ("unresolved_material_reason_codes",), "recommended_action": "Do not authorize consequential execution until action semantics are resolved."},
}


FINDING_PROFILES: dict[str, tuple[str, str]] = {
    "PROVIDER_CONTROL_DISABLED": ("high", "Restore or explicitly decommission the provider control; recalculate coverage."),
    "PROVIDER_CONTROL_TAMPERED": ("critical", "Disable Enforce, restore the approved provider configuration, and revalidate."),
    "PROVIDER_VERSION_UNSUPPORTED": ("high", "Use an exactly reviewed provider version or an eligible verified fallback."),
    "PROVIDER_CONTROL_UNHEALTHY": ("high", "Restore authenticated provider control health before enabling enforcement."),
    "PROVIDER_CONTROL_DOWNGRADED": ("high", "Restore the stronger provider control; do not approve weaker failover implicitly."),
    "DIRECT_PROVIDER_BYPASS": ("critical", "Contain the direct provider route and restore the required verified control path."),
    "REMOTE_EXECUTION_COVERAGE_GAP": ("high", "Deploy a verified target-side control or mark remote execution as not covered."),
    "TOOL_CLASS_COVERAGE_GAP": ("high", "Add a verified control for the affected tool class or block that class."),
    "MODEL_ROUTE_DRIFT": ("critical", "Reject the changed model route and revalidate the exact provider, model, and deployment binding."),
    "HOSTED_TOOL_OPAQUE": ("high", "Treat the hosted tool as opaque until target-side evidence proves its execution boundary."),
    "PROVIDER_CONTRACT_CHANGED": ("high", "Review the changed provider contract and rerun conformance and real acceptance."),
    "PROVIDER_VALIDATION_FAILED": ("high", "Keep Monitor mode, repair the failed provider checks, and validate again."),
    "PROTOCOL_COMPATIBILITY_OVERCLAIM": ("high", "Remove inherited capability claims and validate this exact compatible runtime independently."),
    "CONFIGURATION_SCOPE_WEAK": ("high", "Bind configuration to the exact tenant, provider, product, runtime, route, and deployment."),
    "ACCOUNT_CONTEXT_UNKNOWN": ("high", "Require independently authenticated account context before consequential authorization."),
    "NATIVE_CONTROL_DISABLED": ("high", "Restore or explicitly decommission the control point; recalculate coverage."),
    "NATIVE_CONTROL_TAMPERED": ("critical", "Disable enforcement, restore the approved configuration, and revalidate."),
    "NATIVE_CONTROL_VERSION_UNSUPPORTED": ("high", "Move to a verified provider/adapter version or use an eligible fallback."),
    "NATIVE_CONTROL_CALLBACK_UNHEALTHY": ("high", "Restore authenticated callback health before enabling enforcement."),
    "NATIVE_CONTROL_REPLAY_REJECTED": ("high", "Investigate credential misuse and rotate the integration credential if needed."),
    "NATIVE_CONTROL_RUNTIME_BINDING_MISMATCH": ("high", "Reject the callback, restore the enrolled provider and adapter version, then validate again."),
    "NATIVE_CONTROL_EXACT_ADAPTER_UNAVAILABLE": ("high", "Keep the integration out of Enforce until one reviewed exact provider adapter and version are installed."),
    "NATIVE_CONTROL_POLICY_STALE": ("high", "Refresh the signed policy snapshot before enforcement continues."),
    "NATIVE_CONTROL_BYPASS_DETECTED": ("critical", "Contain the bypass path and deploy an eligible verified control point."),
    "CONTROL_POINT_DOWNGRADED": ("high", "Restore the stronger control point; do not approve weaker failover implicitly."),
    "CONTROL_REQUIREMENT_UNSATISFIED": ("high", "Deploy or repair a verified control point satisfying the action requirements."),
    "CONTROL_CAPABILITY_CHANGED": ("high", "Review the provider capability change and re-run safe validation."),
    "CONTROL_VALIDATION_FAILED": ("high", "Keep monitor mode, repair failed checks, and validate again."),
    "EXECUTION_DRIFT_DETECTED": ("critical", "Contain the action and invalidate authorization or approval."),
    "APPROVAL_BINDING_INVALIDATED": ("critical", "Require reauthorization against the changed canonical action."),
    "PROVIDER_POLICY_INVALID": ("high", "Reject the provider policy as a safety floor, restore the reviewed policy, and revalidate."),
    "HOOK_OUTPUT_INTEGRITY_FAILURE": ("critical", "Disable native Enforce, restore the hardened serializer/helper, and rerun real-binary validation."),
    "PROJECT_HOOK_CONFLICT": ("critical", "Keep Enforce ineligible until the competing security-sensitive hook is removed or explicitly verified."),
    "TOOL_SELECTION_CONTROL_WEAKENED": ("high", "Do not count tool filtering as exact authorization; repair or remove the widening hook."),
}

FINDING_PROFILES.update({
    code: (str(definition["severity"]), str(definition["recommended_action"]))
    for code, definition in PHASE5_FINDING_CATALOG.items()
})

FINDING_TYPE_ALIASES: dict[str, str] = {
    "NATIVE_CONTROL_DISABLED": "PROVIDER_CONTROL_DISABLED",
    "NATIVE_CONTROL_TAMPERED": "PROVIDER_CONTROL_TAMPERED",
    "NATIVE_CONTROL_VERSION_UNSUPPORTED": "PROVIDER_VERSION_UNSUPPORTED",
    "NATIVE_CONTROL_CALLBACK_UNHEALTHY": "PROVIDER_CONTROL_UNHEALTHY",
    "CONTROL_POINT_DOWNGRADED": "PROVIDER_CONTROL_DOWNGRADED",
    "NATIVE_CONTROL_BYPASS_DETECTED": "DIRECT_PROVIDER_BYPASS",
    "CONTROL_CAPABILITY_CHANGED": "PROVIDER_CONTRACT_CHANGED",
    "CONTROL_VALIDATION_FAILED": "PROVIDER_VALIDATION_FAILED",
    # Historical name retained only for lookup/deduplication compatibility.
    "APPROVAL_BINDING_INVALIDATED": "APPROVAL_INVALIDATED",
}


def canonical_finding_type(finding_type: str) -> str:
    return FINDING_TYPE_ALIASES.get(finding_type, finding_type)


_PHASE4_REASON_FINDINGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "PROVIDER_VERSION_UNSUPPORTED",
        ("provider_version_unsupported", "unsupported_provider_version"),
    ),
    (
        "PROVIDER_CONTRACT_CHANGED",
        ("contract_hash_mismatch", "contract_drift", "contract_changed"),
    ),
    (
        "MODEL_ROUTE_DRIFT",
        (
            "model_mismatch",
            "model_provider_mismatch",
            "route_identity_mismatch",
            "deployment_identity_mismatch",
            "deployment_reference_mismatch",
            "model_route_drift",
        ),
    ),
    (
        "REMOTE_EXECUTION_COVERAGE_GAP",
        ("remote_execution", "remote_runtime", "remote_agent"),
    ),
    (
        "TOOL_CLASS_COVERAGE_GAP",
        ("tool_class_unsupported", "action_class_not_accepted", "tool_control_unavailable"),
    ),
    (
        "HOSTED_TOOL_OPAQUE",
        ("hosted_tool", "hosted_execution_opaque", "hosted_mcp_unavailable"),
    ),
    (
        "DIRECT_PROVIDER_BYPASS",
        ("direct_provider_bypass", "alternate_route_bypass", "provider_bypass"),
    ),
    (
        "PROTOCOL_COMPATIBILITY_OVERCLAIM",
        ("protocol_compatibility", "compatible_protocol", "compatibility_overclaim"),
    ),
    (
        "CONFIGURATION_SCOPE_WEAK",
        ("configuration_scope", "deployment_scope_weak", "tenant_scope_weak"),
    ),
    (
        "ACCOUNT_CONTEXT_UNKNOWN",
        ("account_context", "tenant_context_required", "account_mode_not_reviewed"),
    ),
)


def phase4_finding_types_for_reason_codes(
    reason_codes: list[str] | tuple[str, ...],
) -> tuple[str, ...]:
    normalized = tuple(str(value or "").strip().lower() for value in reason_codes)
    return tuple(
        finding_type
        for finding_type, patterns in _PHASE4_REASON_FINDINGS
        if any(pattern in reason for reason in normalized for pattern in patterns)
    )


def _equivalent_finding_types(finding_type: str) -> tuple[str, ...]:
    canonical = canonical_finding_type(finding_type)
    return tuple(
        sorted(
            {
                canonical,
                *(
                    legacy
                    for legacy, replacement in FINDING_TYPE_ALIASES.items()
                    if replacement == canonical
                ),
            }
        )
    )


def _finding_dedupe_key(
    *,
    tenant_id: str,
    finding_type: str,
    integration_id: str | None,
    action_id: str | None,
    material_field_or_effect: str | None = None,
) -> str:
    canonical = canonical_finding_type(finding_type)
    phase5_dimension = str(material_field_or_effect or "none")
    identity = "|".join(
        (
            tenant_id,
            canonical,
            str(action_id or "state"),
            phase5_dimension,
            # Frozen Phase 5 codes dedupe only by tenant+code+action+field/effect.
            "phase5" if canonical in PHASE5_FINDING_CATALOG else str(integration_id or "none"),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:64]


def find_open_native_control_finding(
    db: Session,
    *,
    tenant_id: str,
    finding_type: str,
    integration_id: str | None,
    action_id: str | None,
    material_field_or_effect: str | None = None,
    now: datetime | None = None,
) -> Finding | None:
    """Return one canonical open incident and retain superseded rows as history."""

    canonical = canonical_finding_type(finding_type)
    action_key = action_id[:64] if action_id else None
    dedupe_key = _finding_dedupe_key(
        tenant_id=tenant_id, finding_type=canonical, integration_id=integration_id,
        action_id=action_id, material_field_or_effect=material_field_or_effect,
    )
    if canonical in PHASE5_FINDING_CATALOG:
        candidates = list(db.scalars(select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.finding_type.in_(_equivalent_finding_types(canonical)),
            Finding.canonical_action_id == action_key,
            Finding.status.in_(["open", "reviewing"]),
        )))
        material_tag = f"material:{material_field_or_effect}"
        # Historic rows predate the field/effect dimension; merge them into the
        # canonical record rather than allowing an alias/dedupe split to persist.
        rows = [row for row in candidates if material_tag in (row.related_control_ids or []) or not any(str(item).startswith("material:") for item in (row.related_control_ids or []))]
    else:
        rows = list(
            db.scalars(
                select(Finding).where(
                    Finding.tenant_id == tenant_id,
                    Finding.finding_type.in_(_equivalent_finding_types(canonical)),
                    Finding.application == integration_id,
                    Finding.canonical_action_id == action_key,
                    Finding.status.in_(["open", "reviewing"]),
                )
            )
        )
    if not rows:
        return None
    current = now or datetime.now(timezone.utc)
    primary = next((row for row in rows if row.finding_type == canonical), rows[0])
    for duplicate in rows:
        if duplicate is primary:
            continue
        primary.occurrence_count = int(primary.occurrence_count or 1) + int(
            duplicate.occurrence_count or 1
        )
        primary.first_seen_at = min(primary.first_seen_at, duplicate.first_seen_at)
        primary.last_seen_at = max(primary.last_seen_at, duplicate.last_seen_at, current)
        primary.evidence_node_ids = sorted(
            {*(primary.evidence_node_ids or []), *(duplicate.evidence_node_ids or [])}
        )
        primary.related_event_ids = sorted(
            {*(primary.related_event_ids or []), *(duplicate.related_event_ids or [])}
        )
        primary.related_control_ids = sorted(
            {*(primary.related_control_ids or []), *(duplicate.related_control_ids or [])}
        )
        duplicate.status = "resolved"
        duplicate.last_seen_at = current
    severity, recommended_action = FINDING_PROFILES[canonical]
    primary.finding_type = canonical
    primary.severity = severity
    primary.recommended_action = recommended_action
    primary.related_control_ids = sorted(
        {*(primary.related_control_ids or []), canonical}
    )
    primary.dedupe_key = _finding_dedupe_key(
        tenant_id=tenant_id,
        finding_type=canonical,
        integration_id=integration_id,
        action_id=action_id,
        material_field_or_effect=material_field_or_effect,
    )
    return primary


def record_native_control_finding(
    db: Session,
    *,
    tenant_id: str,
    finding_type: str,
    integration_id: str | None,
    action_id: str | None,
    provider: str,
    policy_version: str | None,
    evidence_node_ids: list[str],
    reason_codes: list[str] | tuple[str, ...],
    material_field_or_effect: str | None = None,
    evidence_kinds: list[str] | tuple[str, ...] = (),
    authority_refs: list[str] | tuple[str, ...] = (),
    profile_ref: str | None = None,
    lifecycle_ref: str | None = None,
    evidence_classification: str = "incomplete",
) -> Finding:
    finding_type = canonical_finding_type(finding_type)
    if finding_type not in FINDING_PROFILES:
        raise ValueError("native_control_finding_type_invalid")
    severity, recommended_action = FINDING_PROFILES[finding_type]
    phase5 = PHASE5_FINDING_CATALOG.get(finding_type)
    if phase5 is not None:
        required_kinds = set(phase5["required_evidence"])
        if not evidence_node_ids or not required_kinds.issubset({str(kind) for kind in evidence_kinds}):
            raise ValueError("phase5_finding_required_evidence_missing")
        if not action_id or not material_field_or_effect:
            raise ValueError("phase5_finding_dedupe_dimension_missing")
        if not authority_refs or not profile_ref or not lifecycle_ref:
            raise ValueError("phase5_finding_authority_metadata_missing")
        if evidence_classification not in {"incomplete", "provider_reported", "independent", "unverified"}:
            raise ValueError("phase5_finding_evidence_classification_invalid")
    dedupe_key = _finding_dedupe_key(
        tenant_id=tenant_id,
        finding_type=finding_type,
        integration_id=integration_id,
        action_id=action_id,
        material_field_or_effect=material_field_or_effect,
    )
    now = datetime.now(timezone.utc)
    existing = find_open_native_control_finding(
        db,
        tenant_id=tenant_id,
        finding_type=finding_type,
        integration_id=integration_id,
        action_id=action_id,
        material_field_or_effect=material_field_or_effect,
        now=now,
    )
    if existing is not None:
        existing.occurrence_count = int(existing.occurrence_count or 1) + 1
        existing.last_seen_at = now
        existing.evidence_node_ids = sorted(
            {*(existing.evidence_node_ids or []), *(str(value) for value in evidence_node_ids if value)}
        )
        existing.related_control_ids = sorted({
            *(existing.related_control_ids or []), finding_type,
            f"material:{material_field_or_effect}" if material_field_or_effect else "",
            *(f"authority:{ref}" for ref in authority_refs if ref),
            f"profile:{profile_ref}" if profile_ref else "",
            f"lifecycle:{lifecycle_ref}" if lifecycle_ref else "",
        } - {""})
        return existing
    finding = Finding(
        tenant_id=tenant_id,
        source_surface="connector",
        ai_tool=f"native_control:{provider}"[:128],
        application=integration_id,
        severity=severity,
        finding_type=finding_type,
        risk_category="native_control_integrity",
        decision="block" if finding_type in {
            "CONTROL_REQUIREMENT_UNSATISFIED",
            "PROVIDER_CONTROL_TAMPERED",
            "DIRECT_PROVIDER_BYPASS",
            "MODEL_ROUTE_DRIFT",
            "NATIVE_CONTROL_TAMPERED",
            "HOOK_OUTPUT_INTEGRITY_FAILURE",
            "PROJECT_HOOK_CONFLICT",
        } else "review",
        status="open",
        recommended_action=recommended_action,
        policy_id=(policy_version or None),
        evidence_node_ids=sorted({str(value) for value in evidence_node_ids if value}),
        related_event_ids=[action_id] if action_id else [],
        related_control_ids=sorted({
            finding_type,
            f"material:{material_field_or_effect}" if material_field_or_effect else "",
            *(f"authority:{ref}" for ref in authority_refs if ref),
            f"profile:{profile_ref}" if profile_ref else "",
            f"lifecycle:{lifecycle_ref}" if lifecycle_ref else "",
        } - {""}),
        evidence_status=evidence_classification,
        canonical_action_id=(action_id[:64] if action_id else None),
        dedupe_key=dedupe_key,
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    if reason_codes:
        finding.recommended_action = (
            f"{recommended_action} Reason codes: {', '.join(sorted(set(reason_codes)))}."
        )
    db.add(finding)
    return finding
