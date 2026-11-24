from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import DeploymentEndpoint
from app.db.models.control_coverage import DeploymentSurface
from app.db.models.monitoring import Connector
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlValidation,
    NativeWorkloadCredential,
)
from app.db.models.runtime_intelligence import RuntimeEvent
from app.core.config import settings
from app.services.health_freshness import (
    HEARTBEAT_OFFLINE_AGE,
    HEARTBEAT_WARNING_AGE,
)
from app.services.deployment_family_contracts import deployment_family_for_surface
from app.services.provider_catalog import provider_surface_capability
from app.services.native_control.versioning import version_in_verified_range
from app.services.native_control.provider_flags import provider_enforcement_enabled
from app.services.native_control.route_binding import (
    current_route_surfaces_for_integration,
    kernel_enforcement_active_for_surfaces,
)
from app.services.native_control.integrity import integration_configuration_fingerprint


_DISCOVERY_VALUES = {"none", "partial", "full", "unknown"}
_YES_NO_VALUES = {"yes", "no", "unknown"}
_EVIDENCE_VALUES = {"none", "partial", "full", "unknown"}
_CONTAINMENT_VALUES = {"none", "surface", "end_to_end", "unknown"}
_SUPPORT_VALUES = {"supported", "unsupported", "unknown"}


@dataclass(frozen=True)
class SurfaceCandidate:
    source_kind: str
    source_id: str
    name: str
    surface_type: str
    deployment_mode: str
    environment: str
    enabled: bool
    status: str
    last_seen_at: datetime
    last_heartbeat_at: datetime | None
    capability_metadata: Mapping[str, object]
    capability_sources: tuple[str, ...]
    metadata: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class SurfaceHealth:
    status: str
    reason: str


def _normalized_choice(value: object, allowed: set[str]) -> str:
    token = str(value or "unknown").strip().lower().replace("-", "_")
    return token if token in allowed else "unknown"


def derive_capability_profile(metadata: Mapping[str, object]) -> dict[str, str]:
    if not metadata:
        return {
            "discovery": "unknown",
            "inline_authorization": "unknown",
            "evidence_generation": "unknown",
            "containment": "unknown",
            "bypass_detection": "unknown",
            "identity_attribution": "unknown",
            "runtime_governance": "unknown",
        }

    monitoring_only = metadata.get("monitoring_only") is True
    return {
        "discovery": _normalized_choice(
            metadata.get("discovery") or ("partial" if monitoring_only else "unknown"),
            _DISCOVERY_VALUES,
        ),
        "inline_authorization": (
            "no"
            if monitoring_only
            else _normalized_choice(metadata.get("inline_authorization"), _YES_NO_VALUES)
        ),
        "evidence_generation": _normalized_choice(metadata.get("evidence"), _EVIDENCE_VALUES),
        "containment": (
            "none"
            if monitoring_only
            else _normalized_choice(metadata.get("containment"), _CONTAINMENT_VALUES)
        ),
        "bypass_detection": _normalized_choice(metadata.get("bypass_detection"), _SUPPORT_VALUES),
        "identity_attribution": _normalized_choice(metadata.get("identity_attribution"), _SUPPORT_VALUES),
        "runtime_governance": _normalized_choice(metadata.get("runtime_governance"), _SUPPORT_VALUES),
    }


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def derive_health(
    *,
    enabled: bool,
    status: str,
    last_heartbeat_at: datetime | None,
    now: datetime,
) -> SurfaceHealth:
    normalized = str(status or "unknown").strip().lower()
    if not enabled or normalized in {"inactive", "disabled", "offline"}:
        return SurfaceHealth("offline", "registration_inactive")
    if normalized not in {"active", "healthy", "warning", "degraded"}:
        return SurfaceHealth("unknown", "registration_or_heartbeat_unknown")
    heartbeat = _aware(last_heartbeat_at)
    current = _aware(now)
    if heartbeat is None or current is None:
        return SurfaceHealth("unknown", "heartbeat_missing")
    age = max(timedelta(0), current - heartbeat)
    if age > HEARTBEAT_OFFLINE_AGE:
        return SurfaceHealth("offline", "heartbeat_expired")
    if age > HEARTBEAT_WARNING_AGE or normalized == "degraded":
        return SurfaceHealth("degraded", "heartbeat_stale_or_source_degraded")
    if normalized == "warning":
        return SurfaceHealth("warning", "source_warning")
    return SurfaceHealth("healthy", "heartbeat_current")


def connector_surface_candidates(db: Session, *, tenant_id: str, now: datetime) -> list[SurfaceCandidate]:
    del now
    rows = db.scalars(select(Connector).where(Connector.tenant_id == tenant_id)).all()
    candidates: list[SurfaceCandidate] = []
    for row in rows:
        config = dict(row.config or {})
        metadata = dict(row.metadata_json or {})
        connector_type = str(row.connector_type or "connector").strip().lower()
        if "siem" in connector_type or connector_type in {"sentinel", "splunk"}:
            surface_type = "siem_connector"
        elif "mdm" in connector_type or connector_type in {"intune", "jamf"}:
            surface_type = "mdm_discovery"
        elif "webhook" in connector_type:
            surface_type = "webhook"
        else:
            surface_type = "saas_connector"
        capability_metadata: dict[str, object] = {
            "monitoring_only": bool(config.get("monitoring_only", True)),
            "discovery": config.get("discovery_capability") or ("partial" if row.enabled else "none"),
            "evidence": config.get("evidence_generation") or ("partial" if int(row.last_signal_count or 0) > 0 else "none"),
            "containment": config.get("containment_capability") or "none",
            "bypass_detection": config.get("bypass_detection") or "unknown",
            "identity_attribution": config.get("identity_attribution") or "unknown",
            "runtime_governance": config.get("runtime_governance") or "unknown",
        }
        last_seen = _aware(row.last_run_at) or _aware(row.updated_at) or _aware(row.created_at)
        assert last_seen is not None
        candidates.append(
            SurfaceCandidate(
                source_kind="connector",
                source_id=str(row.id),
                name=row.name,
                surface_type=surface_type,
                deployment_mode=str(config.get("deployment_mode") or "connector"),
                environment=str(config.get("environment") or "unknown"),
                enabled=bool(row.enabled),
                status=str(row.status or "unknown"),
                last_seen_at=last_seen,
                last_heartbeat_at=_aware(row.last_run_at),
                capability_metadata=capability_metadata,
                capability_sources=(f"connector:{row.id}",),
                metadata={"provider_key": row.provider_key, "is_stub": bool(row.is_stub), **metadata},
            )
        )
    return candidates


def endpoint_surface_candidates(db: Session, *, tenant_id: str, now: datetime) -> list[SurfaceCandidate]:
    del now
    rows = db.scalars(select(DeploymentEndpoint).where(DeploymentEndpoint.tenant_id == tenant_id)).all()
    candidates: list[SurfaceCandidate] = []
    for row in rows:
        metadata = dict(row.metadata_json or {})
        browser_managed = bool(row.extension_version or metadata.get("extension_version"))
        surface_type = "browser_extension" if browser_managed else "endpoint_discovery"
        last_seen = _aware(row.last_seen_at)
        assert last_seen is not None
        candidates.append(
            SurfaceCandidate(
                source_kind="deployment_endpoint",
                source_id=str(row.endpoint_id),
                name=str(row.hostname or row.endpoint_id),
                surface_type=surface_type,
                deployment_mode="managed_extension" if browser_managed else "endpoint_metadata",
                environment=str(metadata.get("environment") or "unknown"),
                enabled=str(row.status or "active").lower() not in {"inactive", "disabled", "offline"},
                status=str(row.status or "unknown"),
                last_seen_at=last_seen,
                last_heartbeat_at=last_seen,
                capability_metadata={
                    "monitoring_only": not browser_managed,
                    "discovery": "full" if browser_managed else "partial",
                    "inline_authorization": "yes" if browser_managed else "no",
                    "evidence": "full" if browser_managed else "partial",
                    "containment": "surface" if browser_managed else "none",
                    "bypass_detection": metadata.get("bypass_detection") or "unknown",
                    "identity_attribution": "supported" if row.user_id else "unknown",
                    "runtime_governance": "unknown",
                },
                capability_sources=(f"deployment_endpoint:{row.endpoint_id}",),
                metadata={
                    "device_type": row.device_type,
                    "browser_type": row.browser_type,
                    "extension_version": row.extension_version,
                },
            )
        )
    return candidates


def _runtime_surface_type(source: str) -> str:
    return {
        "browser": "browser_extension",
        "gateway": "llm_gateway",
        "mcp": "mcp_gateway",
        "sdk": "sdk",
        "proxy": "local_proxy",
        "foundry": "azure_apim",
        "copilot": "saas_connector",
        "endpoint": "endpoint_discovery",
        "dns": "network_discovery",
    }.get(source, source or "unknown")


def runtime_surface_candidates(db: Session, *, tenant_id: str, now: datetime) -> list[SurfaceCandidate]:
    del now
    rows = db.scalars(select(RuntimeEvent).where(RuntimeEvent.tenant_id == tenant_id)).all()
    latest: dict[tuple[str, str], RuntimeEvent] = {}
    for row in rows:
        source = str(row.source_surface or "unknown").strip().lower()
        metadata = dict(row.metadata_json or {})
        source_id = str(
            metadata.get("deployment_surface_id")
            or metadata.get("gateway_id")
            or metadata.get("sdk_registration_id")
            or metadata.get("mcp_server_id")
            or source
        ).strip()
        key = (source, source_id)
        previous = latest.get(key)
        if previous is None or (_aware(row.created_at) or datetime.min.replace(tzinfo=timezone.utc)) > (
            _aware(previous.created_at) or datetime.min.replace(tzinfo=timezone.utc)
        ):
            latest[key] = row

    candidates: list[SurfaceCandidate] = []
    for (source, source_id), row in latest.items():
        metadata = dict(row.metadata_json or {})
        provider_id = str(metadata.get("provider_id") or "unknown")
        provider = provider_surface_capability(provider_id, source_surface=source)
        mode = str(provider.get("surface_policy_mode") or "unsupported")
        enforceable = mode == "enforceable" and bool(provider.get("enforcement_supported_for_source"))
        monitoring_only = mode == "monitoring_only" or not enforceable
        observed_at = _aware(row.created_at)
        assert observed_at is not None
        candidates.append(
            SurfaceCandidate(
                source_kind="runtime_observation",
                source_id=f"{source}:{source_id}",
                name=str(metadata.get("deployment_surface_name") or metadata.get("gateway_name") or source_id),
                surface_type=_runtime_surface_type(source),
                deployment_mode="inline" if enforceable else "monitor_only",
                environment=str(metadata.get("environment") or "unknown"),
                enabled=True,
                status="active",
                last_seen_at=observed_at,
                last_heartbeat_at=observed_at,
                capability_metadata={
                    "monitoring_only": monitoring_only,
                    "discovery": "partial",
                    "inline_authorization": "yes" if enforceable else "no",
                    "evidence": "partial" if (row.evidence_bundle_id or row.evidence_node_ids) else "none",
                    "containment": "surface" if enforceable else "none",
                    "bypass_detection": metadata.get("bypass_detection") or "unknown",
                    "identity_attribution": "supported" if (row.user_id or row.agent_id) else "unknown",
                    "runtime_governance": "supported" if row.ai_system_id else "unknown",
                },
                capability_sources=(f"runtime_event:{row.event_id}", f"provider_catalog:{provider_id}"),
                metadata={"provider_id": provider_id, "source_surface": source},
            )
        )
    return candidates


def _native_claim_covered(
    capabilities: Mapping[str, object],
    dimensions: tuple[str, ...],
    accepted_levels: set[str],
) -> bool:
    for dimension in dimensions:
        raw = capabilities.get(dimension)
        claim = raw if isinstance(raw, Mapping) else {}
        if (
            str(claim.get("verification_status") or "") == "verified"
            and str(claim.get("level") or "") in accepted_levels
        ):
            return True
    return False


def native_control_surface_candidates(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
) -> list[SurfaceCandidate]:
    rows = db.scalars(
        select(NativeControlIntegration).where(NativeControlIntegration.tenant_id == tenant_id)
    ).all()
    candidates: list[SurfaceCandidate] = []
    current = _aware(now) or datetime.now(timezone.utc)
    for row in rows:
        profile = db.get(ControlCapabilityProfileRecord, row.capability_profile_id)
        validation = db.scalar(
            select(NativeControlValidation)
            .where(
                NativeControlValidation.tenant_id == tenant_id,
                NativeControlValidation.integration_instance_id == row.id,
            )
            .order_by(NativeControlValidation.validated_at.desc(), NativeControlValidation.id.desc())
        )
        validated_at = _aware(validation.validated_at) if validation else None
        active_credential = db.scalar(
            select(NativeWorkloadCredential).where(
                NativeWorkloadCredential.tenant_id == tenant_id,
                NativeWorkloadCredential.integration_instance_id == row.id,
                NativeWorkloadCredential.status == "active",
                NativeWorkloadCredential.expires_at > current,
            )
        )
        active_workload_identity = active_credential is not None
        validation_current = bool(
            validation
            and validation.result == "passed"
            and validated_at
            and current - validated_at <= timedelta(minutes=15)
            and active_credential
            and validation.credential_id == active_credential.credential_id
            and validation.credential_epoch == active_credential.credential_epoch
        )
        profile_verified = bool(profile and profile.verification_status == "verified" and profile.active)
        provider_version_valid = bool(
            profile
            and version_in_verified_range(
                row.provider_version,
                profile.tested_min_version,
                profile.tested_max_version,
            )
        )
        adapter_version_valid = bool(profile and row.adapter_version == profile.adapter_version)
        current_route_surfaces = current_route_surfaces_for_integration(
            settings,
            tenant_id=row.tenant_id,
            integration_id=row.id,
            integration_method=row.integration_method,
            provider=row.provider,
            provider_version=row.provider_version,
            adapter_version=row.adapter_version,
            product=row.product,
        )
        route_binding_current = bool(current_route_surfaces)
        enforcement_feature_active = bool(
            settings.native_control_framework
            and settings.trusted_control_selector
            and settings.native_control_enforce
            and provider_enforcement_enabled(settings, row.provider)
            and kernel_enforcement_active_for_surfaces(
                settings,
                tenant_id=row.tenant_id,
                surfaces=current_route_surfaces,
            )
        )
        configuration_valid = bool(
            row.expected_configuration_fingerprint
            and integration_configuration_fingerprint(row)
            == row.expected_configuration_fingerprint
        )
        policy_fresh = bool(_aware(row.policy_fresh_until) and (_aware(row.policy_fresh_until) or current) >= current)
        active_verified = bool(
            row.state in {"monitoring", "enforcing"}
            and row.health_state == "healthy"
            and profile_verified
            and validation_current
            and active_workload_identity
            and configuration_valid
            and policy_fresh
            and provider_version_valid
            and adapter_version_valid
            and route_binding_current
        )
        capabilities = dict(row.capability_snapshot or {})
        if active_verified:
            discovery = "full" if _native_claim_covered(capabilities, ("discovery",), {"observe", "external", "inline", "inline_bound"}) else "unknown"
            inline = (
                "yes"
                if row.state == "enforcing"
                and row.mode == "enforce"
                and route_binding_current
                and enforcement_feature_active
                and _native_claim_covered(
                    capabilities,
                    ("prompt_control", "tool_control", "mcp_control", "command_control"),
                    {"inline", "inline_bound"},
                )
                else "unknown"
            )
            evidence = (
                "full"
                if _native_claim_covered(capabilities, ("post_execution_verification",), {"inline_bound"})
                else "partial"
                if _native_claim_covered(capabilities, ("post_execution_visibility",), {"observe", "external", "inline", "inline_bound"})
                else "unknown"
            )
            containment = "surface" if _native_claim_covered(
                capabilities,
                ("containment",),
                {"external", "inline", "inline_bound"},
            ) else "unknown"
            bypass = "supported" if _native_claim_covered(
                capabilities,
                ("bypass_detection",),
                {"observe", "external", "inline", "inline_bound"},
            ) else "unknown"
            identity = "supported" if _native_claim_covered(
                capabilities,
                ("identity",),
                {"observe", "external", "inline", "inline_bound"},
            ) else "unknown"
        else:
            discovery = inline = evidence = containment = bypass = identity = "unknown"
        evidence_refs = tuple(
            [f"control_profile:{profile.id}" if profile else "control_profile:unknown"]
            + ([str(value) for value in validation.evidence_refs] if validation else [])
        )
        candidates.append(
            SurfaceCandidate(
                source_kind="native_control",
                source_id=row.id,
                name=row.display_name,
                surface_type=row.integration_method,
                deployment_mode=row.mode,
                environment=row.environment,
                enabled=row.state not in {"disabled", "unsupported"},
                status=("healthy" if active_verified else "degraded" if row.health_state == "degraded" else "unknown"),
                last_seen_at=_aware(row.updated_at) or current,
                last_heartbeat_at=_aware(row.last_health_check_at or row.last_validated_at),
                capability_metadata={
                    "discovery": discovery,
                    "inline_authorization": inline,
                    "evidence": evidence,
                    "containment": containment,
                    "bypass_detection": bypass,
                    "identity_attribution": identity,
                    "runtime_governance": (
                        "supported" if active_verified and row.deployment_family in {"runtime", "endpoint"} else "unknown"
                    ),
                },
                capability_sources=evidence_refs,
                metadata={
                    "deployment_family": row.deployment_family,
                    "provider": row.provider,
                    "product": row.product,
                    "matrix_version": profile.matrix_version if profile else "unknown",
                    "verification_status": profile.verification_status if profile else "unverified",
                    "known_blind_spots": list(row.known_blind_spots or []),
                },
            )
        )
    return candidates


def collect_surface_candidates(db: Session, *, tenant_id: str, now: datetime) -> list[SurfaceCandidate]:
    return [
        *connector_surface_candidates(db, tenant_id=tenant_id, now=now),
        *endpoint_surface_candidates(db, tenant_id=tenant_id, now=now),
        *runtime_surface_candidates(db, tenant_id=tenant_id, now=now),
        *native_control_surface_candidates(db, tenant_id=tenant_id, now=now),
    ]


def _merge_capability_profiles(candidates: Sequence[SurfaceCandidate]) -> dict[str, str]:
    profiles = [derive_capability_profile(candidate.capability_metadata) for candidate in candidates]
    keys = profiles[0].keys() if profiles else derive_capability_profile({}).keys()
    return {
        key: next(iter(values)) if len(values := {profile[key] for profile in profiles}) == 1 else "unknown"
        for key in keys
    }


def reconcile_deployment_surfaces(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
    candidates: Sequence[SurfaceCandidate] | None = None,
) -> list[DeploymentSurface]:
    source_candidates = list(candidates) if candidates is not None else collect_surface_candidates(db, tenant_id=tenant_id, now=now)
    grouped: dict[tuple[str, str], list[SurfaceCandidate]] = {}
    for candidate in source_candidates:
        source_kind = str(candidate.source_kind or "").strip().lower()
        source_id = str(candidate.source_id or "").strip()
        if not source_kind or not source_id:
            continue
        grouped.setdefault((source_kind, source_id), []).append(candidate)

    rows: list[DeploymentSurface] = []
    for (source_kind, source_id), group in sorted(grouped.items()):
        latest = max(group, key=lambda item: _aware(item.last_seen_at) or datetime.min.replace(tzinfo=timezone.utc))
        row = db.scalar(
            select(DeploymentSurface).where(
                DeploymentSurface.tenant_id == tenant_id,
                DeploymentSurface.source_kind == source_kind,
                DeploymentSurface.source_id == source_id,
            )
        )
        if row is None:
            row = DeploymentSurface(
                tenant_id=tenant_id,
                source_kind=source_kind,
                source_id=source_id,
                name=latest.name,
                surface_type=latest.surface_type,
                first_seen_at=min(_aware(item.last_seen_at) or _aware(now) for item in group),
            )
            db.add(row)
        health = derive_health(
            enabled=latest.enabled,
            status=latest.status,
            last_heartbeat_at=latest.last_heartbeat_at,
            now=now,
        )
        row.name = latest.name
        row.surface_type = latest.surface_type
        row.deployment_mode = latest.deployment_mode
        row.environment = latest.environment
        row.status = latest.status
        row.capability_profile = _merge_capability_profiles(group)
        row.capability_sources = sorted({source for item in group for source in item.capability_sources})
        row.health_status = health.status
        row.health_reason = health.reason
        family = str(latest.metadata.get("deployment_family") or "unknown").strip().lower()
        if family not in {"browser", "endpoint", "runtime", "saas_api"}:
            family = deployment_family_for_surface(latest.surface_type).value
        row.deployment_family = family
        row.provider = str(latest.metadata.get("provider") or "").strip() or None
        authorization = str(row.capability_profile.get("inline_authorization") or "unknown")
        row.control_capability = (
            "inline"
            if health.status == "healthy" and authorization == "yes"
            else "monitor_only"
            if health.status in {"healthy", "warning"} and authorization == "no"
            else "unknown"
        )
        evidence = str(row.capability_profile.get("evidence_generation") or "unknown")
        row.evidence_capability = {
            "full": "complete",
            "partial": "partial",
            "none": "none",
        }.get(evidence, "unknown")
        containment = str(row.capability_profile.get("containment") or "unknown")
        row.containment_capability = {
            "end_to_end": "direct",
            "surface": "surface_limited",
            "none": "none",
        }.get(containment, "unknown")
        bypass = str(row.capability_profile.get("bypass_detection") or "unknown")
        row.bypass_detection_capability = bypass if bypass in {"supported", "unsupported"} else "unknown"
        row.last_seen_at = max(_aware(item.last_seen_at) or _aware(now) for item in group)
        row.last_heartbeat_at = _aware(latest.last_heartbeat_at)
        row.metadata_json = dict(latest.metadata)
        rows.append(row)
    db.flush()
    return rows
