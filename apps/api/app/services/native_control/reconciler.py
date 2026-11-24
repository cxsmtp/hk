from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlValidation,
    NativeWorkloadCredential,
)
from app.services.native_control.findings import (
    canonical_finding_type,
    find_open_native_control_finding,
    record_native_control_finding,
)
from app.services.native_control.health import health_snapshot
from app.services.native_control.integrity import integration_configuration_fingerprint
from app.services.native_control.metrics import native_control_metrics
from app.services.native_control.versioning import version_in_verified_range


VALIDATION_WINDOW = timedelta(minutes=15)


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _open_finding(db: Session, integration: NativeControlIntegration, finding_type: str) -> Finding | None:
    return find_open_native_control_finding(
        db,
        tenant_id=integration.tenant_id,
        finding_type=finding_type,
        integration_id=integration.id,
        action_id=None,
    )


def _sync_finding(
    db: Session,
    *,
    integration: NativeControlIntegration,
    finding_type: str,
    active: bool,
    reason_codes: list[str],
    evidence_ref: str | None,
    now: datetime,
) -> bool:
    existing = _open_finding(db, integration, finding_type)
    if active and existing is None:
        record_native_control_finding(
            db,
            tenant_id=integration.tenant_id,
            finding_type=finding_type,
            integration_id=integration.id,
            action_id=None,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[evidence_ref.removeprefix("evidence:")] if evidence_ref else [],
            reason_codes=reason_codes,
        )
        return True
    elif not active and existing is not None:
        existing.status = "resolved"
        existing.last_seen_at = now
    return False


def reconcile_native_control_integration(
    db: Session,
    *,
    integration: NativeControlIntegration,
    now: datetime,
) -> dict[str, object]:
    current = _utc(now)
    profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
    credential = db.scalar(
        select(NativeWorkloadCredential)
        .where(
            NativeWorkloadCredential.tenant_id == integration.tenant_id,
            NativeWorkloadCredential.integration_instance_id == integration.id,
            NativeWorkloadCredential.status == "active",
            NativeWorkloadCredential.expires_at > current,
        )
        .order_by(NativeWorkloadCredential.credential_epoch.desc())
    )
    snapshot = (
        health_snapshot(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id=credential.credential_id,
            credential_epoch=credential.credential_epoch,
            now=current,
        )
        if credential
        else None
    )
    validation = db.scalar(
        select(NativeControlValidation)
        .where(
            NativeControlValidation.tenant_id == integration.tenant_id,
            NativeControlValidation.integration_instance_id == integration.id,
        )
        .order_by(NativeControlValidation.validated_at.desc(), NativeControlValidation.id.desc())
    )
    validation_current = bool(
        validation
        and credential
        and validation.result == "passed"
        and validation.credential_id == credential.credential_id
        and validation.credential_epoch == credential.credential_epoch
        and _utc(validation.validated_at) + VALIDATION_WINDOW >= current
    )
    configuration_valid = bool(
        integration.expected_configuration_fingerprint
        and integration_configuration_fingerprint(integration)
        == integration.expected_configuration_fingerprint
    )
    provider_version_supported = bool(
        profile
        and version_in_verified_range(
            integration.provider_version,
            profile.tested_min_version,
            profile.tested_max_version,
        )
    )
    adapter_version_supported = bool(profile and integration.adapter_version == profile.adapter_version)
    policy_fresh = _utc(integration.policy_fresh_until) >= current
    callback_authenticated = bool(snapshot and snapshot.callback_authenticated)
    evidence_flowing = bool(snapshot and snapshot.evidence_flowing)
    latency_measured = bool(snapshot and snapshot.observed_latency_ms is not None)
    profile_verified = bool(profile and profile.active and profile.verification_status == "verified")
    capability_changed = bool(
        profile
        and {
            key: value
            for key, value in dict(integration.capability_snapshot or {}).items()
            if key != "native_policy"
        }
        != dict(profile.capabilities or {})
    )
    existing_reasons = {str(value) for value in integration.health_reasons or []}
    bypass_detected = bool(existing_reasons.intersection({"bypass_detected", "active_bypass_detected"}))
    execution_drift = "execution_drift_detected" in existing_reasons
    approval_invalidated = "approval_binding_invalidated" in existing_reasons
    provider_policy_invalid = "provider_policy_invalid" in existing_reasons
    hook_output_integrity_failure = "hook_output_integrity_failure" in existing_reasons
    project_hook_conflict = bool(
        existing_reasons.intersection({"project_hook_conflict", "competing_hook_detected"})
    )
    tool_selection_weakened = "tool_selection_control_weakened" in existing_reasons

    conditions: dict[str, tuple[bool, list[str]]] = {
        "NATIVE_CONTROL_DISABLED": (integration.state == "disabled", ["control_disabled"]),
        "NATIVE_CONTROL_TAMPERED": (not configuration_valid, ["configuration_integrity_invalid"]),
        "NATIVE_CONTROL_VERSION_UNSUPPORTED": (
            not provider_version_supported or not adapter_version_supported,
            [
                *([] if provider_version_supported else ["provider_version_unsupported"]),
                *([] if adapter_version_supported else ["adapter_version_unsupported"]),
            ],
        ),
        "NATIVE_CONTROL_CALLBACK_UNHEALTHY": (
            not callback_authenticated or not evidence_flowing or not latency_measured,
            list(snapshot.reason_codes if snapshot else ("callback_not_observed", "evidence_not_flowing", "latency_not_measured")),
        ),
        "NATIVE_CONTROL_POLICY_STALE": (not policy_fresh, ["policy_stale"]),
        "NATIVE_CONTROL_BYPASS_DETECTED": (bypass_detected, ["bypass_detected"]),
        "CONTROL_CAPABILITY_CHANGED": (capability_changed, ["capability_snapshot_changed"]),
        "EXECUTION_DRIFT_DETECTED": (execution_drift, ["execution_drift_detected"]),
        "APPROVAL_BINDING_INVALIDATED": (approval_invalidated, ["approval_binding_invalidated"]),
        "PROVIDER_POLICY_INVALID": (provider_policy_invalid, ["provider_policy_invalid"]),
        "HOOK_OUTPUT_INTEGRITY_FAILURE": (
            hook_output_integrity_failure,
            ["hook_output_integrity_failure"],
        ),
        "PROJECT_HOOK_CONFLICT": (project_hook_conflict, ["project_hook_conflict"]),
        "TOOL_SELECTION_CONTROL_WEAKENED": (
            tool_selection_weakened,
            ["tool_selection_control_weakened"],
        ),
    }
    evidence_ref = snapshot.evidence_refs[-1] if snapshot and snapshot.evidence_refs else None
    for finding_type, (active, reasons) in conditions.items():
        opened = _sync_finding(
            db,
            integration=integration,
            finding_type=finding_type,
            active=active,
            reason_codes=reasons,
            evidence_ref=evidence_ref,
            now=current,
        )
        if opened:
            metric_name = {
                "PROVIDER_CONTRACT_CHANGED": "provider_contract_drift_total",
                "DIRECT_PROVIDER_BYPASS": "provider_bypass_total",
                "EXECUTION_DRIFT_DETECTED": "execution_drift_total",
            }.get(canonical_finding_type(finding_type))
            if metric_name is not None:
                native_control_metrics.increment(
                    metric_name,
                    provider=integration.provider,
                    method=integration.integration_method,
                    outcome="failed",
                )

    readiness = {
        "profile_verified": profile_verified,
        "configuration_integrity_valid": configuration_valid,
        "provider_version_supported": provider_version_supported,
        "adapter_version_supported": adapter_version_supported,
        "policy_fresh": policy_fresh,
        "validation_current": validation_current,
        "callback_authenticated": callback_authenticated,
        "evidence_flowing": evidence_flowing,
        "latency_measured": latency_measured,
        "capability_unchanged": not capability_changed,
        "bypass_absent": not bypass_detected,
    }
    reasons = [name for name, value in readiness.items() if not value]
    healthy = all(readiness.values()) and integration.state != "disabled"
    previous_health = integration.health_state
    previous_state = integration.state
    if healthy:
        integration.health_state = "healthy"
        integration.health_reasons = []
        if integration.state in {"degraded", "unhealthy"}:
            if integration.degradation_mode in {"fail_closed", "require_exception"} and integration.mode == "enforce":
                integration.state = "enforcing"
            else:
                integration.state = "monitoring"
                integration.mode = "monitor"
    else:
        integration.health_state = "tampered" if not configuration_valid else "degraded"
        integration.health_reasons = reasons
        if integration.state in {"monitoring", "enforcing"}:
            integration.state = "degraded"
            if not (
                previous_state == "enforcing"
                and integration.mode == "enforce"
                and integration.degradation_mode in {"fail_closed", "require_exception"}
            ):
                integration.mode = "monitor"
    integration.last_health_check_at = current
    if previous_health != integration.health_state or previous_state != integration.state:
        db.add(
            EvidenceNode(
                tenant_id=integration.tenant_id,
                correlation_id=integration.id[:64],
                node_type="native_control_health",
                signal_type="native_control_health_transition",
                label=f"Native control health transition: {integration.display_name}",
                payload={
                    "integration_id": integration.id,
                    "previous_health": previous_health,
                    "health_state": integration.health_state,
                    "previous_state": previous_state,
                    "state": integration.state,
                    "reason_codes": reasons,
                    "observed_latency_ms": snapshot.observed_latency_ms if snapshot else None,
                },
            )
        )
    return {
        "integration_id": integration.id,
        "health_state": integration.health_state,
        "state": integration.state,
        "reason_codes": reasons,
        "observed_latency_ms": snapshot.observed_latency_ms if snapshot else None,
        "finding_conditions": sorted(name for name, (active, _) in conditions.items() if active),
    }


def reconcile_tenant_native_controls(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
) -> dict[str, object]:
    integrations = list(
        db.scalars(
            select(NativeControlIntegration)
            .where(NativeControlIntegration.tenant_id == tenant_id)
            .order_by(NativeControlIntegration.id)
        ).all()
    )
    results = [
        reconcile_native_control_integration(db, integration=row, now=now)
        for row in integrations
    ]
    return {
        "tenant_id": tenant_id,
        "reconciled": len(results),
        "healthy": sum(1 for row in results if row["health_state"] == "healthy"),
        "degraded": sum(1 for row in results if row["health_state"] != "healthy"),
        "items": results,
    }
