from __future__ import annotations

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.control_engine.authorization import (
    AuthorizationRequest,
    AuthorizationRolloutOutcome,
    authorize_ai_action,
)
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.evidence import DecisionReceipt, EvidenceNode, ExecutionReceipt
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlHealthObservation,
    NativeControlIntegration,
    NativeControlLogicalActionClaim,
    NativeControlReplay,
    NativeControlSelection,
    NativeControlValidation,
    NativeWorkloadCredential,
    REAL_ACCEPTANCE_STATES,
)
from app.db.session import get_db
from app.services.endpoint_identity_service import HARDWARE_KEY_PROVIDERS, public_key_thumbprint
from app.services.native_control.adapters import ADAPTERS, ProviderEventContext
from app.services.native_control.adapter_contract import AdapterMaturity
from app.services.native_control.adapter_registry import NativeControlAdapterRegistry
from app.services.native_control.live_adapter_dispatch import (
    ExactAdapterDispatch,
    ExactAdapterDispatchError,
    dispatch_live_callback_adapter,
)
from app.services.native_control.contracts import (
    ControlMethod,
    HealthState,
    IntegrationMode,
    IntegrationState,
    VerificationStatus,
)
from app.services.native_control.envelope import (
    ReplayStore,
    WorkloadCredential,
    parse_envelope_json,
    validate_trusted_envelope,
)
from app.services.native_control.manifests import ProviderCapabilityManifest, build_default_registry
from app.services.native_control.integrity import (
    configuration_fingerprint,
    integration_configuration_fingerprint,
)
from app.services.native_control.findings import record_native_control_finding
from app.services.native_control.health import health_snapshot, record_health_observation
from app.services.native_control.selection_service import apply_native_selection_to_rollout
from app.services.receipt_service import (
    persist_execution_incomplete_isolated,
    persist_execution_receipt_isolated,
    persist_pre_execution_decision_in_transaction,
)
from app.services.native_control.metrics import native_control_metrics
from app.services.native_control.provider_flags import provider_enforcement_enabled
from app.services.native_control.route_binding import (
    current_route_surfaces_for_integration,
    kernel_enforcement_active_for_surfaces,
)
from app.services.native_control.service import (
    IntegrationFacts,
    NativeValidationResult,
    derive_native_coverage,
    transition_integration,
)
from app.services.native_control.versioning import version_in_verified_range
from app.services.native_control.claude_surfaces import claude_surface_controls
from app.services.native_control.validation_runner import run_safe_synthetic_validation
from app.services.native_control.reference_adapters import build_reference_registry
from app.services.native_control.acceptance_versions import (
    REAL_BINARY_ACCEPTANCE_VERSION,
    acceptance_version_is_current,
)
from app.services.github_repository_access_service import (
    observe_github_repository_runtime,
    resolve_repository_control_floor,
)
from app.services.native_control.claude_adapter import ClaudeAdapter
from app.services.native_control.cursor_adapter import CursorAdapter
from app.services.native_control.gemini_cli_adapter import GeminiCliAdapter
from app.services.native_control.openai_adapters import (
    CodexNativeControlAdapter,
    OpenAIAgentsSDKControlAdapter,
    OpenAIDirectAPIControlAdapter,
)
from app.services.native_control.chatgpt_desktop_composite import ChatGPTAction
from app.services.native_control.chatgpt_desktop_service import (
    get_chatgpt_desktop_assets,
    resolve_chatgpt_desktop_control_plan,
)
from app.services.hmair.discovery_context_provider import DiscoveryContextProvider


router = APIRouter(tags=["native-controls"])
REGISTRY = build_default_registry()
VALIDATION_VERSION = "native-control-validation/1.0"
SERVER_VALIDATION_VERSION = "native-control-server-validation/1.0"
VALIDATION_TTL = timedelta(minutes=15)
_REAL_BINARY_EVIDENCE_VERSION = "native-control-real-binary-evidence/1.0"
DEPLOYMENT_FAMILIES = {"browser", "endpoint", "runtime", "saas_api"}
_EMPTY_PROVIDER_TOOL_USE_HASH = hashlib.sha256(b"").hexdigest()
def _require_framework() -> None:
    if not settings.native_control_framework:
        raise HTTPException(status_code=404, detail="Not found")


FrameworkDependency = Depends(_require_framework)


def _foundation_registry() -> NativeControlAdapterRegistry:
    if not settings.native_control_adapter_framework:
        raise HTTPException(status_code=404, detail="Not found")
    registry = NativeControlAdapterRegistry(environment=settings.env)
    if settings.native_control_reference_adapters:
        for adapter in build_reference_registry(environment=settings.env).adapters():
            registry.register(adapter)
    registry.register(ClaudeAdapter())
    registry.register(CursorAdapter())
    registry.register(GeminiCliAdapter())
    registry.register(OpenAIAgentsSDKControlAdapter())
    registry.register(CodexNativeControlAdapter())
    registry.register(OpenAIDirectAPIControlAdapter())
    return registry


_PROVIDER_ADAPTER_METHODS = {
    "native_hook",
    "sdk_middleware",
    "agent_middleware",
    "tool_loop_intercept",
    "api_intercept",
}

# These integration methods carry a provider-specific synchronous callback
# contract.  They must resolve through one exact provider/product/version
# adapter before Hawk may describe the callback as native semantic control.
# Gateway and endpoint-runtime callbacks retain their existing product routes;
# they are never silently relabelled as exact provider adapter control here.
_EXACT_ADAPTER_CALLBACK_METHODS = {
    "native_hook",
    "sdk_middleware",
    "agent_middleware",
    "tool_loop_intercept",
    "api_intercept",
}


def _requires_exact_callback_adapter(integration: NativeControlIntegration) -> bool:
    return str(integration.integration_method or "").strip().lower() in _EXACT_ADAPTER_CALLBACK_METHODS


def _adapter_enforcement_eligible(integration) -> bool:
    """Provider adapter enforcement requires the new production conformance gate."""

    if str(integration.integration_method or "").strip() not in _PROVIDER_ADAPTER_METHODS:
        return True
    if not (
        settings.native_control_adapter_framework
        and settings.native_control_adapter_enforcement
    ):
        return False
    try:
        registry = _foundation_registry()
    except HTTPException:
        return False
    for adapter in registry.adapters():
        descriptor = adapter.descriptor
        manifest = adapter.manifest
        if descriptor.maturity is not AdapterMaturity.PRODUCTION:
            continue
        if manifest.verification_status is not VerificationStatus.VERIFIED:
            continue
        if descriptor.provider_family != str(integration.provider or "").strip().lower():
            continue
        if descriptor.product_family != str(integration.product or "").strip().lower():
            continue
        if descriptor.adapter_version != str(integration.adapter_version or "").strip():
            continue
        if not version_in_verified_range(
            integration.provider_version,
            manifest.provider_version_min,
            manifest.provider_version_max,
        ):
            continue
        return True
    return False


def _adapter_catalog_item(adapter) -> dict[str, object]:
    descriptor = adapter.descriptor
    manifest = adapter.manifest
    surface_coverage = []
    if descriptor.provider_family == "anthropic" and descriptor.product_family == "claude_code":
        surface_coverage = [
            {
                "surface": row.surface,
                "control_method": row.control_method,
                "native_hook_capable": row.native_hook_capable,
                "enrollment_scope": row.enrollment_scope,
                "residual_gap": row.residual_gap,
            }
            for row in claude_surface_controls()
        ]
    return {
        "adapter_id": descriptor.adapter_id,
        "provider_family": descriptor.provider_family,
        "product_family": descriptor.product_family,
        "adapter_version": descriptor.adapter_version,
        "deployment_families_supported": [value.value for value in descriptor.deployment_families_supported],
        "enforcement_methods_supported": [value.value for value in descriptor.enforcement_methods_supported],
        "event_schema_version": descriptor.event_schema_version,
        "minimum_hawk_version": descriptor.minimum_hawk_version,
        "maturity": descriptor.maturity.value,
        "description": descriptor.description,
        "verification_status": manifest.verification_status.value,
        "provider_version_range": {
            "minimum": manifest.provider_version_min,
            "maximum": manifest.provider_version_max,
            "exact_verified_versions": list(manifest.exact_verified_versions),
            "compatible_versions_require_signed_runtime_validation": bool(
                manifest.provider_version_max == "*"
                or manifest.provider_version_min != manifest.provider_version_max
            ),
        },
        "production_eligible": bool(
            descriptor.maturity is AdapterMaturity.PRODUCTION
            and manifest.verification_status is VerificationStatus.VERIFIED
        ),
        "surface_coverage": surface_coverage,
        "capabilities": {
            dimension.value: {
                "level": claim.level.value,
                "verification_status": claim.verification_status.value,
                "evidence_refs": list(claim.evidence_refs),
            }
            for dimension, claim in sorted(manifest.capabilities.items(), key=lambda row: row[0].value)
        },
        "blind_spots": [
            {
                "id": item.id,
                "control_dimension": item.control_dimension.value,
                "scope": item.scope,
                "condition": item.condition,
                "impact": item.impact,
                "detection_method": item.detection_method,
                "mitigation": item.mitigation,
                "evidence": list(item.evidence),
            }
            for item in manifest.known_blind_spots
        ],
    }


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _manifest_fingerprint(manifest: ProviderCapabilityManifest) -> str:
    body = json.dumps(manifest.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _reviewed_adapter_contract_fields(
    manifest: ProviderCapabilityManifest,
) -> tuple[str, list[str], list[str], str | None]:
    """Return persisted profile facts from one unambiguous reviewed adapter.

    The provider capability catalog is intentionally broad.  Exact callback
    routes need a narrower static contract (action, method, runtime and
    lifecycle facts) before *separate* per-integration acceptance can be
    considered.  Ambiguity and unavailable adapter frameworks stay unknown;
    neither can be repaired by catalog metadata alone.
    """

    try:
        adapters = _foundation_registry().adapters()
    except HTTPException:
        return "unknown", [], [], None
    candidates = [
        adapter
        for adapter in adapters
        if adapter.descriptor.provider_family == manifest.provider
        and adapter.descriptor.product_family == manifest.product
        and adapter.descriptor.adapter_version == manifest.adapter_version
        and manifest.method in adapter.descriptor.enforcement_methods_supported
    ]
    if len(candidates) != 1:
        return "unknown", [], [], None
    contract = candidates[0].manifest
    if not contract.is_reviewed_contract:
        return "unknown", [], [], None
    runtimes = tuple(contract.supported_runtimes)
    runtime = runtimes[0] if len(runtimes) == 1 else "unknown"
    return (
        runtime,
        sorted(action.value for action in contract.supported_action_classes),
        sorted(method.value for method in contract.supported_control_methods),
        contract.contract_fingerprint,
    )


def _profile_for_manifest(
    db: Session,
    manifest: ProviderCapabilityManifest,
    *,
    allow_admin_reratify: bool = False,
) -> ControlCapabilityProfileRecord:
    fingerprint = _manifest_fingerprint(manifest)
    row = db.scalar(
        select(ControlCapabilityProfileRecord).where(
            ControlCapabilityProfileRecord.manifest_id == manifest.manifest_id,
            ControlCapabilityProfileRecord.manifest_version == manifest.manifest_version,
        )
    )
    (
        reviewed_runtime,
        reviewed_action_classes,
        reviewed_control_methods,
        reviewed_contract_hash,
    ) = _reviewed_adapter_contract_fields(manifest)
    payload = manifest.as_dict()
    verified_at = datetime.fromisoformat(manifest.verified_at) if manifest.verified_at else None
    security_properties = {
        **dict(payload["security_properties"]),
        "required_permissions": payload["required_permissions"],
        "deployment_requirements": payload["deployment_requirements"],
        "failure_modes": payload["failure_modes"],
        "privacy_implications": payload["privacy_implications"],
        "fallback_methods": payload["fallback_methods"],
    }
    health_requirements = [
        "callback_authenticated",
        "provider_version_compatible",
        "adapter_version_compatible",
        "configuration_integrity_valid",
        "policy_fresh",
        "safe_validation_passed",
    ]
    degradation_modes = ["fail_closed", "monitor_only"]
    if row is not None:
        reratified = False
        if row.manifest_fingerprint != fingerprint:
            if not (
                allow_admin_reratify
                and manifest.verification_status is VerificationStatus.VERIFIED
                and reviewed_contract_hash
            ):
                raise HTTPException(status_code=409, detail="Provider manifest changed without a version increment")
            # Legacy rows from early native-control rollouts persisted the
            # provider manifest identity before exact adapter contract fields
            # were materialized.  The explicit admin real-binary acceptance
            # route is the only path allowed to re-ratify that stored
            # fingerprint, and only when Hawk's shipped manifest is verified
            # and backed by one reviewed exact adapter contract.
            reratified = True
        if reratified:
            # Re-ratification is a complete profile projection, not a partial
            # fingerprint repair. This executes only inside the admin real-
            # binary acceptance transaction. Any later failed acceptance check
            # raises and rolls back these in-memory changes with the request.
            row.matrix_version = REGISTRY.matrix_version
            row.provider = manifest.provider
            row.product = manifest.product
            row.runtime = reviewed_runtime
            row.integration_method = manifest.method.value
            row.adapter_version = manifest.adapter_version
            row.tested_min_version = manifest.supported_versions[0] if manifest.supported_versions else None
            row.tested_max_version = manifest.supported_versions[-1] if manifest.supported_versions else None
            row.current_verified_version = (
                manifest.supported_versions[-1]
                if manifest.verified_at and manifest.supported_versions
                else None
            )
            row.verification_status = manifest.verification_status.value
            row.verification_source = "; ".join(manifest.verification_evidence)[:512]
            row.verified_at = verified_at
            row.capabilities = payload["capability_matrix"]
            row.security_properties = security_properties
            row.health_requirements = health_requirements
            row.degradation_modes = degradation_modes
            row.known_blind_spots = payload["known_blind_spots"]
            row.documentation_references = [payload["official_documentation_reference"]]
            row.supported_action_classes = list(reviewed_action_classes)
            row.supported_control_methods = list(reviewed_control_methods)
            row.contract_hash = reviewed_contract_hash
            row.manifest_fingerprint = fingerprint
            row.active = True
            db.flush()
            return row
        # Older persisted profiles predate exact adapter contract persistence.
        # The broad provider manifest version deliberately does not pretend to
        # version a provider-specific callback contract. Reconcile only the
        # reviewed static fields, and leave each integration's prior hash
        # untouched so its real acceptance becomes stale until Configure
        # explicitly rebinds it. Unknown/null legacy rows never qualify.
        if reviewed_contract_hash and (
            row.runtime != reviewed_runtime
            or sorted(str(value) for value in (row.supported_action_classes or []))
            != reviewed_action_classes
            or sorted(str(value) for value in (row.supported_control_methods or []))
            != reviewed_control_methods
            or row.contract_hash != reviewed_contract_hash
        ):
            row.runtime = reviewed_runtime
            row.supported_action_classes = list(reviewed_action_classes)
            row.supported_control_methods = list(reviewed_control_methods)
            row.contract_hash = reviewed_contract_hash
            db.flush()
        return row
    row = ControlCapabilityProfileRecord(
        manifest_id=manifest.manifest_id,
        manifest_version=manifest.manifest_version,
        matrix_version=REGISTRY.matrix_version,
        provider=manifest.provider,
        product=manifest.product,
        runtime=reviewed_runtime,
        integration_method=manifest.method.value,
        adapter_version=manifest.adapter_version,
        tested_min_version=manifest.supported_versions[0] if manifest.supported_versions else None,
        tested_max_version=manifest.supported_versions[-1] if manifest.supported_versions else None,
        current_verified_version=manifest.supported_versions[-1] if manifest.verified_at and manifest.supported_versions else None,
        verification_status=manifest.verification_status.value,
        verification_source="; ".join(manifest.verification_evidence)[:512],
        verified_at=verified_at,
        capabilities=payload["capability_matrix"],
        security_properties=security_properties,
        health_requirements=health_requirements,
        degradation_modes=degradation_modes,
        known_blind_spots=payload["known_blind_spots"],
        documentation_references=[payload["official_documentation_reference"]],
        supported_action_classes=reviewed_action_classes,
        supported_control_methods=reviewed_control_methods,
        contract_hash=reviewed_contract_hash,
        manifest_fingerprint=fingerprint,
        active=True,
    )
    db.add(row)
    db.flush()
    return row


def _rebind_current_integration_profile(
    db: Session,
    integration: NativeControlIntegration,
    *,
    allow_admin_reratify: bool = False,
) -> ControlCapabilityProfileRecord:
    """Bind an explicitly reconfigured integration to Hawk's current reviewed manifest.

    Version and adapter compatibility remain independently enforced by
    ``_facts``. Rebinding therefore cannot promote an incompatible runtime; it
    only replaces stale persisted catalog metadata after an administrator
    enters the Configure lifecycle.
    """

    try:
        manifest = REGISTRY.get(
            integration.provider,
            integration.product,
            ControlMethod(integration.integration_method),
        )
    except (KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail="Provider/product/control method manifest is unavailable",
        ) from exc
    profile = _profile_for_manifest(db, manifest, allow_admin_reratify=allow_admin_reratify)
    integration.capability_profile_id = profile.id
    # Changing/rebinding a reviewed static contract invalidates any prior
    # deployed acceptance. The next Enforce request therefore needs a fresh
    # immutable real acceptance bound to this hash.
    integration.contract_hash = profile.contract_hash
    native_policy = dict((integration.capability_snapshot or {}).get("native_policy") or {})
    if _requires_exact_callback_adapter(integration):
        reviewed_runtime = str(profile.runtime or "unknown").strip().lower()
        if not reviewed_runtime or reviewed_runtime == "unknown" or not profile.contract_hash:
            raise HTTPException(
                status_code=409,
                detail="Reviewed exact adapter runtime contract is unavailable",
            )
        # Reconfiguration is the explicit upgrade boundary for legacy rows
        # created before runtime/deployment facts were persisted. The values
        # are derived from Hawk's reviewed contract and administrator-owned
        # integration record, never from a provider callback.
        integration.runtime = reviewed_runtime
        integration.execution_location = _EXECUTION_LOCATION_BY_DEPLOYMENT_FAMILY[
            integration.deployment_family
        ]
        integration.deployment_reference = (
            f"hawk-native:{integration.tenant_id}:{integration.provider}:"
            f"{integration.product}:{integration.environment}:{integration.instance_key}"
        )
        integration.configuration_fingerprint = configuration_fingerprint(
            tenant_id=integration.tenant_id,
            provider=integration.provider,
            product=integration.product,
            method=integration.integration_method,
            instance_key=integration.instance_key,
            environment=integration.environment,
            provider_version=integration.provider_version,
            adapter_version=integration.adapter_version,
            policy_version=integration.policy_version,
            runtime=integration.runtime,
            model_provider=integration.model_provider,
            model=integration.model,
            execution_location=integration.execution_location,
            deployment_reference=integration.deployment_reference,
            trusted_workload_authority=native_policy.get("trusted_workload_authority") is True,
        )
        integration.expected_configuration_fingerprint = integration.configuration_fingerprint
    manifest_payload = manifest.as_dict()
    integration.capability_snapshot = {
        **dict(manifest_payload["capability_matrix"]),
        "native_policy": native_policy,
    }
    integration.known_blind_spots = list(manifest.known_blind_spots)
    return profile


def _effective_manifest_payload(
    db: Session,
    manifest: ProviderCapabilityManifest,
) -> dict[str, object]:
    """Expose catalog capability and persisted selector truth in one labeled row."""

    payload = manifest.as_dict()
    profile = db.scalar(
        select(ControlCapabilityProfileRecord).where(
            ControlCapabilityProfileRecord.manifest_id == manifest.manifest_id,
            ControlCapabilityProfileRecord.manifest_version == manifest.manifest_version,
        )
    )
    if profile is None:
        return {
            **payload,
            "profile_source": "catalog_only",
            "profile_active": False,
            "effective_for_selection": False,
            "persisted_profile_id": None,
        }
    return {
        **payload,
        "matrix_version": profile.matrix_version,
        "capability_matrix": dict(profile.capabilities or {}),
        "security_properties": dict(profile.security_properties or {}),
        "verification_status": profile.verification_status,
        "verified_at": profile.verified_at.isoformat() if profile.verified_at else None,
        "adapter_version": profile.adapter_version,
        "known_blind_spots": list(profile.known_blind_spots or []),
        "profile_source": "persisted_selector_profile",
        "profile_active": bool(profile.active),
        "effective_for_selection": bool(
            profile.active and profile.verification_status == VerificationStatus.VERIFIED.value
        ),
        "persisted_profile_id": profile.id,
    }


class IntegrationCreateRequest(BaseModel):
    provider: str = Field(min_length=1, max_length=64)
    product: str = Field(min_length=1, max_length=128)
    model_provider: str = Field(default="unknown", min_length=1, max_length=128)
    model: str = Field(default="unknown", min_length=1, max_length=255)
    method: str = Field(min_length=1, max_length=64)
    instance_key: str = Field(min_length=1, max_length=128)
    display_name: str = Field(min_length=1, max_length=255)
    environment: str = Field(min_length=1, max_length=64)
    deployment_family: Literal["browser", "endpoint", "runtime", "saas_api"]
    provider_version: str = Field(min_length=1, max_length=64)
    adapter_version: str = Field(min_length=1, max_length=64)
    policy_version: str = Field(min_length=1, max_length=64)
    policy_fresh_until: datetime
    degradation_mode: Literal[
        "fail_closed",
        "fail_open_with_evidence",
        "local_policy_only",
        "block_high_risk_only",
        "require_exception",
        "monitor_only",
    ] = "fail_closed"
    # This is an explicit Hawk administrator configuration, not a provider
    # callback claim. Without it, an enrolled workload proves transport only;
    # it does not become an action authority for consequential requests.
    trusted_workload_authority: bool = False

    @field_validator(
        "provider",
        "product",
        "model_provider",
        "model",
        "method",
        mode="after",
    )
    @classmethod
    def _normalize(cls, value: str) -> str:
        return value.strip().lower()


_EXECUTION_LOCATION_BY_DEPLOYMENT_FAMILY = {
    "browser": "LOCAL_ENDPOINT",
    "endpoint": "LOCAL_ENDPOINT",
    "runtime": "CUSTOMER_RUNTIME",
    "saas_api": "CUSTOMER_CLOUD",
}


def _enrich_native_request_with_discovery_context(
    db: Session,
    request,
):
    """Attach only verified Discovery references before authorization.

    Discovery is intentionally a read-only context provider. It cannot choose
    a decision, control method, route binding, identity, or policy result. A
    failed/disabled/partial lookup preserves the adapter's explicit Unknown
    asset state. Only an available, reference-backed result upgrades that
    single context hint to ``verified`` for the existing policy engine.
    """

    if not settings.discovery_context_provider:
        return request

    def known(value: object) -> str | None:
        """Do not turn an adapter's Unknown placeholder into a lookup key."""

        if not isinstance(value, str):
            return None
        normalized = value.strip()
        return normalized if normalized and normalized.casefold() not in {"unknown", "none", "null"} else None

    try:
        context = DiscoveryContextProvider(db).get_context_for_ai_action(
            tenant=request.tenant_id,
            runtime=known(request.runtime.get("runtime")),
            application=known(request.discovery_context.get("product")),
            tool=known(request.tool.get("name")),
            model=known(request.discovery_context.get("model")),
            provider=known(request.discovery_context.get("provider")),
            as_of=_now(),
        )
    except Exception:
        return request
    if not isinstance(context, dict):
        return request
    asset_ref = context.get("ai_asset_ref")
    asset_approval = context.get("asset_approval")
    approved_status = (
        str(asset_approval.get("approved_status") or "unknown").strip().lower()
        if isinstance(asset_approval, dict)
        else "unknown"
    )
    active_lifecycle = (
        str(asset_approval.get("lifecycle_status") or "unknown").strip().lower()
        if isinstance(asset_approval, dict)
        else "unknown"
    )
    # Do not lower global Discovery completeness thresholds: an action only
    # needs a specific, current tenant asset approval reference. Other
    # discovery dimensions remain independently partial/unknown.
    current_verification_refs = [
        ref
        for ref in list(context.get("verification_refs") or [])[:32]
        if isinstance(ref, str) and ref.startswith("verification_assertion:")
    ]
    available = (
        isinstance(asset_ref, str)
        and asset_ref.startswith("discovery_asset:")
        # Verification proves Discovery's identity assertion; it does not
        # approve that asset for use. Only an explicit governed asset state
        # may enrich a policy request as a verified target.
        and approved_status in {"approved", "registered", "sanctioned", "managed"}
        and active_lifecycle == "active"
        and bool(current_verification_refs)
    )
    return request.model_copy(
        deep=True,
        update={
            "discovery_context": {
                **dict(request.discovery_context or {}),
                # References, timestamps and confidence remain owned by
                # Discovery. Hawk's authorization stays in the existing
                # canonical request/policy path.
                "asset_intelligence_ref": asset_ref if available else None,
                "asset_version": context.get("asset_version") if available else None,
                "last_discovery": context.get("last_discovery") if available else None,
                "last_verification": context.get("last_verification") if available else None,
                "verification_refs": current_verification_refs,
                "evidence_refs": list(context.get("evidence_refs") or [])[:32],
                "control_coverage_reference": list(
                    (context.get("control_coverage") or {}).get("assertion_refs") or []
                )[:32],
                "asset_approval_reference": (
                    asset_approval.get("evidence_ref") if available else None
                ),
                "asset_status": "verified" if available else "unknown",
            },
        },
    )


def _trusted_initial_deployment_scope(
    *,
    tenant_id: str,
    request: IntegrationCreateRequest,
    profile: ControlCapabilityProfileRecord,
) -> tuple[str, str, str]:
    """Derive, never provider-accept, exact callback deployment facts.

    An administrator configures the Hawk integration; provider callback bodies
    never select its runtime, location or deployment reference. Exact adapter
    routes must have a single reviewed runtime at enrollment. The deterministic
    reference is stable across restarts and included in integrity/acceptance
    bindings without becoming an application bearer credential.
    """

    runtime = str(profile.runtime or "unknown").strip().lower()
    # An experimental/unsupported provider route may still be enrolled for
    # signed Monitor evidence. It is deliberately given Unknown static scope
    # and can never pass real-acceptance/Enforce gates until a reviewed
    # contract exists. Do not prevent the administrator from observing it.
    execution_location = _EXECUTION_LOCATION_BY_DEPLOYMENT_FAMILY[request.deployment_family]
    deployment_reference = (
        f"hawk-native:{tenant_id}:{request.provider}:{request.product}:"
        f"{request.environment}:{request.instance_key}"
    )
    return runtime or "unknown", execution_location, deployment_reference


class ChatGPTDesktopControlPlanRequest(BaseModel):
    endpoint_id: str = Field(min_length=1, max_length=128)
    action: ChatGPTAction

    @field_validator("endpoint_id", mode="after")
    @classmethod
    def _normalize_endpoint_id(cls, value: str) -> str:
        return value.strip()


class CredentialCreateRequest(BaseModel):
    credential_id: str = Field(min_length=8, max_length=128)
    credential_epoch: int = Field(ge=1, le=2_147_483_647)
    public_key_pem: str = Field(min_length=100, max_length=2048)
    environment: str = Field(min_length=1, max_length=64)
    allowed_event_types: list[str] = Field(min_length=1, max_length=32)
    expires_at: datetime

    @field_validator("allowed_event_types")
    @classmethod
    def _events(cls, values: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))
        if not normalized or any(len(value) > 128 for value in normalized):
            raise ValueError("Invalid event types")
        return normalized


class CredentialRevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=255)


class ValidationRequest(BaseModel):
    envelope_base64: str = Field(min_length=4, max_length=90_000)
    payload_base64: str = Field(min_length=4, max_length=90_000)


class NativeCallbackRequest(BaseModel):
    envelope_base64: str = Field(min_length=4, max_length=90_000)
    payload_base64: str = Field(min_length=4, max_length=90_000)


_NATIVE_CALLBACK_EVENTS = {
    "before_agent",
    "after_agent",
    "before_tool",
    "before_tool_selection",
    "permission_request",
    "after_tool",
    "after_tool_failure",
    "before_model",
    "after_model",
    "session_start",
    "session_end",
    "config_change",
    "before_shell",
    "after_shell",
    "before_mcp",
    "after_mcp",
    "before_file_read",
    "after_file_edit",
    "subagent_start",
    "subagent_stop",
    "subagent_context_start",
    "subagent_context_stop",
    "pre_compact",
    "post_compact",
    "stop",
    "interrupt",
    "after_agent_response",
    "after_agent_thought",
    "workspace_open",
    "pre_compress",
    "notification",
}
_NATIVE_PRE_ACTION_EVENTS = {
    "before_agent",
    "before_tool",
    "before_model",
    "before_shell",
    "before_mcp",
    "before_file_read",
    "subagent_start",
}
_NATIVE_POST_ACTION_EVENTS = {
    "after_tool",
    "after_tool_failure",
    "after_model",
    "after_shell",
    "after_mcp",
    "after_file_edit",
}
_MAX_NATIVE_CALLBACK_HISTORY = 32
_HIGH_RISK_NATIVE_ACTIONS = {
    "admin", "command", "delete", "email_send", "execute", "file_write",
    "payment", "purchase", "shell", "tool_execution", "upload", "write",
}
_SENSITIVE_NATIVE_CLASSIFICATIONS = {
    "credential", "credentials", "pii", "restricted", "secret", "secrets", "sensitive",
}


def _native_baseline_decision(integration: NativeControlIntegration, request) -> tuple[str, list[str]]:
    """Derive baseline controls from Hawk-normalized callback material only."""

    policy = dict((integration.capability_snapshot or {}).get("native_policy") or {})
    blocked_actions = {
        str(value).strip().lower()
        for value in policy.get("blocked_action_types") or _HIGH_RISK_NATIVE_ACTIONS
        if str(value).strip()
    }
    classifications = {
        str(value).strip().lower()
        for value in request.data_context.get("classifications") or []
        if str(value).strip()
    }
    action_values = {
        str(request.action.get("action_type") or "unknown").strip().lower(),
        str(request.action.get("action_class") or "unknown").strip().lower(),
    }
    reasons: list[str] = []
    if classifications.intersection(_SENSITIVE_NATIVE_CLASSIFICATIONS):
        reasons.append("sensitive_data_classification")
    if request.side_effect_context.get("persistent_side_effect") is True:
        reasons.append("persistent_side_effect")
    if action_values.intersection(blocked_actions):
        reasons.append("blocked_action_type")
    return ("block" if reasons else "allow", reasons)


def _native_callback_material(request) -> tuple[str, dict[str, str]]:
    """Hash the canonical pre/post binding material without retaining content.

    A provider event ID is a correlation hint, not proof that a post callback
    represents the same consequential action. These fields are already
    normalized/bounded by the exact adapter and are the same fields selected
    into Hawk's canonical decision receipt.
    """

    fields = {
        "actor_hash": hashlib.sha256(
            json.dumps(dict(request.actor or {}), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "authority_hash": hashlib.sha256(
            json.dumps(dict(request.authority or {}), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "action_type": str(request.action.get("action_type") or "unknown"),
        "action_class": str(request.action.get("action_class") or "unknown"),
        "tool_fingerprint": str(request.tool.get("fingerprint_id") or "unknown"),
        "parameter_hash": str(request.parameters.get("parameter_hash") or "unknown"),
        "target_resource_hash": str(request.target.get("resource_hash") or "unknown"),
        "destination_hash": str(request.target.get("destination_hash") or "unknown"),
        "side_effect_class": str(
            request.side_effect_context.get("side_effect_class") or "unknown"
        ),
        "persistent_side_effect": str(
            request.side_effect_context.get("persistent_side_effect") is True
        ).lower(),
        # These are privacy-safe, server-normalized digests.  They prevent a
        # PermissionRequest/Post callback from attaching to a same-looking
        # tool invocation that has a different provider approval or tool-use
        # identity.  Raw provider identifiers never enter the canonical
        # material or evidence payload.
        "approval_binding_hash": str(
            request.approval_context.get("approval_action_hash") or "unknown"
        ),
        "provider_action_identity_hash": str(
            request.approval_context.get("provider_action_identity_hash")
            or "unknown"
        ),
    }
    material_hash = hashlib.sha256(
        json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return material_hash, fields


def _privacy_safe_callback_binding_hash(kind: str, value: object) -> str:
    """Digest a signed provider correlation value before it enters Hawk state."""

    raw = str(value or "").strip()
    if not raw or raw.lower() == "unknown":
        return "unknown"
    return hashlib.sha256(
        json.dumps(
            {"schema": "hawk.native-control.callback-binding/1.0", "kind": kind, "value": raw},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _privacy_safe_callback_material_hash(kind: str, material: dict[str, object]) -> str:
    """Digest structured callback identity material without persisting raw values."""

    normalized = {
        str(key): str(value).strip()
        for key, value in material.items()
        if str(value or "").strip()
        and str(value or "").strip().lower() != "unknown"
    }
    if not normalized:
        return "unknown"
    return hashlib.sha256(
        json.dumps(
            {
                "schema": "hawk.native-control.callback-binding/1.0",
                "kind": kind,
                "material": normalized,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _provider_action_identity_hash(
    *,
    provider_event: dict,
    provider_event_id: str,
) -> str:
    """Bind one logical provider tool/action without retaining its raw ID.

    The reviewed signed callback schema exposes ``provider_tool_use_hash``
    when the provider proves a tool-use identity.  If it is absent, only the
    exact signed provider event can be correlated; a different
    PermissionRequest/Post event deliberately requires reauthorization rather
    than borrowing a same-looking action under the broader session ID.  Do
    not use an adapter's convenient correlation/session fallback here.
    """

    raw_identity = provider_event.get("provider_tool_use_hash")
    if raw_identity == _EMPTY_PROVIDER_TOOL_USE_HASH:
        raw_identity = None
    digest = _privacy_safe_callback_binding_hash("provider_tool_use", raw_identity)
    if digest != "unknown":
        return digest
    prompt_material_hash = _privacy_safe_callback_binding_hash(
        "prompt_material",
        provider_event.get("prompt")
        or provider_event.get("input")
        or provider_event.get("messages"),
    )
    prompt_hash = str(provider_event.get("prompt_hash") or "").strip()
    has_prompt_material = (
        bool(prompt_hash) and prompt_hash.lower() != "unknown"
    ) or prompt_material_hash != "unknown"
    prompt_event = str(
        provider_event.get("provider_event_type")
        or provider_event.get("hook_event_name")
        or provider_event.get("event_type")
        or ""
    )
    prompt_semantics = (
        str(provider_event.get("action_type") or "").strip().lower()
        in {"prompt", "model_request"}
        or prompt_event in {"before_model", "UserPromptSubmit", "BeforeModel", "beforeSubmitPrompt"}
    )
    if has_prompt_material and prompt_semantics:
        prompt_identity = _privacy_safe_callback_material_hash(
            "provider_prompt_action",
            {
                "provider_event_type": prompt_event,
                "action_type": provider_event.get("action_type"),
                "prompt_hash": prompt_hash,
                "prompt_material_hash": prompt_material_hash,
                "provider_session_hash": provider_event.get("provider_session_hash"),
            },
        )
        if prompt_identity != "unknown":
            return prompt_identity
    # No unproven session-level fallback: preserve only single-envelope
    # identity. A distinct lifecycle event cannot cross-bind to it.
    return _privacy_safe_callback_binding_hash(
        "provider_event_fallback", provider_event_id
    )


def _native_callback_material_drift(
    expected: object,
    actual: dict[str, str],
) -> list[str]:
    if not isinstance(expected, dict):
        return ["canonical_material_missing"]
    return sorted(
        key
        for key, value in actual.items()
        if str(expected.get(key) or "unknown") != value
    )


def _callback_authorization_context_fingerprint(
    integration: NativeControlIntegration,
    *,
    enforce_mode_active: bool,
    enforcement_ready: bool,
    authority_facts: dict[str, bool],
) -> str:
    """Bind retry reuse to the exact monitor/enforce authority boundary."""

    material = {
        "integration_configuration_fingerprint": integration_configuration_fingerprint(
            integration
        ),
        "state": integration.state,
        "mode": integration.mode,
        "degradation_mode": integration.degradation_mode,
        "health_state": integration.health_state,
        "enforce_mode_active": bool(enforce_mode_active),
        "enforcement_ready": bool(enforcement_ready),
        "authority_facts": dict(sorted(authority_facts.items())),
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _logical_action_contract_hash(integration: NativeControlIntegration) -> str:
    """Return a strict, stable contract binding for a logical action claim.

    Reviewed integrations carry their immutable 64-character contract hash.
    A newly configured Monitor integration legitimately has no reviewed
    contract yet; its claim remains replay-safe by binding a deterministic
    digest of that explicit unconfigured value and the server-side
    configuration fingerprint.  The raw placeholder never reaches the claim
    column, and it cannot satisfy an Enforce acceptance later.
    """

    raw_contract = str(integration.contract_hash or "").strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", raw_contract):
        return raw_contract
    return hashlib.sha256(
        json.dumps(
            {
                "schema": "hawk.native-control.logical-claim-contract/1.0",
                "configured_contract": raw_contract or "unconfigured",
                "configuration_fingerprint": integration_configuration_fingerprint(
                    integration
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _claim_logical_provider_action(
    db: Session,
    *,
    integration: NativeControlIntegration,
    provider_event_id: str,
    logical_action_identity_hash: str | None = None,
    canonical_material_hash: str,
    policy_snapshot_id: str,
    contract_hash: str,
    configuration_fingerprint: str,
) -> tuple[NativeControlLogicalActionClaim, bool]:
    """Atomically reserve one provider logical action before policy evaluation.

    A fresh provider envelope retry is *not* a transport replay.  The unique
    claim is deliberately content-minimal and transaction-bound: it stores
    only stable hashes and current binding references, while the canonical
    Hawk action, receipt and evidence remain in their existing systems.
    """

    provider_event_hash = hashlib.sha256(provider_event_id.encode("utf-8")).hexdigest()
    logical_claim_hash = (
        logical_action_identity_hash
        if isinstance(logical_action_identity_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", logical_action_identity_hash)
        else provider_event_hash
    )
    claim = NativeControlLogicalActionClaim(
        tenant_id=integration.tenant_id,
        integration_instance_id=integration.id,
        provider_event_id_hash=logical_claim_hash,
        canonical_material_hash=canonical_material_hash,
        policy_snapshot_id=policy_snapshot_id[:64],
        contract_hash=contract_hash,
        configuration_fingerprint=configuration_fingerprint,
    )
    try:
        # The database unique constraint, rather than an evidence lookup,
        # serializes simultaneous provider retries.
        with db.begin_nested():
            db.add(claim)
            db.flush()
        return claim, True
    except IntegrityError:
        existing = db.scalar(
            select(NativeControlLogicalActionClaim).where(
                NativeControlLogicalActionClaim.tenant_id == integration.tenant_id,
                NativeControlLogicalActionClaim.integration_instance_id == integration.id,
                NativeControlLogicalActionClaim.provider_event_id_hash == logical_claim_hash,
            )
        )
        if existing is None:
            # Do not race a half-visible claim into a second policy decision.
            raise HTTPException(
                status_code=409,
                detail="Logical native action claim is not yet available; retry with a new provider callback",
            )
        return existing, False


def _mark_logical_action_claim_conflicted(
    db: Session,
    *,
    claim: NativeControlLogicalActionClaim,
    conflicting_material_hash: str,
) -> None:
    """Make a logical-action material conflict permanently fail safe."""

    if claim.conflicted_at is None:
        claim.conflicted_at = _now()
        claim.conflict_material_hash = conflicting_material_hash
        db.flush()


def _bound_pre_action_for_logical_claim(
    db: Session,
    *,
    integration: NativeControlIntegration,
    claim: NativeControlLogicalActionClaim,
    current_policy_snapshot_id: str,
    current_configuration_fingerprint: str,
    route_binding_current: bool,
    require_reviewed_contract_binding: bool,
) -> tuple[EvidenceNode | None, list[str]]:
    """Return only a current receipt/plan-bound pre-action reuse candidate.

    Claims stop parallel policy evaluation; the existing evidence, receipt,
    and persisted selection remain the sole proof that a reuse is safe.
    """

    current = _now()
    if claim.conflicted_at is not None:
        return None, ["provider_event_id_historical_conflict"]
    if claim.policy_snapshot_id != current_policy_snapshot_id[:64]:
        return None, ["provider_event_id_policy_snapshot_changed"]
    if claim.contract_hash != _logical_action_contract_hash(integration):
        return None, ["provider_event_id_contract_changed"]
    if claim.configuration_fingerprint != current_configuration_fingerprint:
        return None, ["provider_event_id_configuration_changed"]

    candidates = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == integration.tenant_id,
            EvidenceNode.node_type == "native_control_callback",
            EvidenceNode.payload["integration_id"].as_string() == integration.id,
            or_(
                EvidenceNode.payload["logical_action_claim_id"].as_string()
                == claim.id,
                EvidenceNode.payload["provider_event_id_hash"].as_string()
                == claim.provider_event_id_hash,
            ),
        )
        .order_by(EvidenceNode.created_at.asc(), EvidenceNode.id.asc())
        .limit(_MAX_NATIVE_CALLBACK_HISTORY + 1)
    ).all()
    if len(candidates) > _MAX_NATIVE_CALLBACK_HISTORY:
        return None, ["provider_event_id_history_ambiguous"]
    for candidate in candidates:
        payload = candidate.payload if isinstance(candidate.payload, dict) else {}
        if payload.get("provider_event_type") not in _NATIVE_PRE_ACTION_EVENTS:
            continue
        if payload.get("canonical_material_hash") != claim.canonical_material_hash:
            return None, ["provider_event_id_historical_conflict"]
        if payload.get("policy_snapshot_id") != current_policy_snapshot_id:
            return None, ["provider_event_id_policy_snapshot_changed"]
        if payload.get("logical_action_contract_hash") != claim.contract_hash:
            return None, ["provider_event_id_contract_changed"]
        if payload.get("callback_authorization_context_fingerprint") != current_configuration_fingerprint:
            return None, ["provider_event_id_configuration_changed"]
        if payload.get("route_binding_current") is not route_binding_current:
            return None, ["provider_event_id_route_binding_changed"]
        receipt_id = payload.get("decision_receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            # Pre-action observations without a receipt have never become an
            # authorization authority.  Keep looking inside the bounded
            # history for the one receipt/plan-bound event for this logical
            # provider action; if none exists the final pending/unbound
            # result below remains fail closed.
            continue
        receipt = db.scalar(
            select(DecisionReceipt).where(
                DecisionReceipt.tenant_id == integration.tenant_id,
                DecisionReceipt.receipt_id == receipt_id,
            )
        )
        if receipt is None or _aware(receipt.expires_at) <= current:
            return None, ["provider_event_id_prior_receipt_not_current"]
        if receipt.policy_snapshot_id != current_policy_snapshot_id:
            return None, ["provider_event_id_prior_receipt_policy_changed"]
        selection_id = payload.get("native_control_selection_id")
        if not isinstance(selection_id, str) or not selection_id:
            # A deduplicated transport retry inherits the already-issued
            # receipt for audit visibility, but it intentionally does not
            # create another selector plan.  It is informational evidence,
            # not a second authority candidate, and must not shadow the
            # original bound pre-action when timestamps tie.
            continue
        selection = db.scalar(
            select(NativeControlSelection).where(
                NativeControlSelection.tenant_id == integration.tenant_id,
                NativeControlSelection.selection_id == selection_id,
            )
        )
        expected_contract = (
            (selection.contract_hashes or {}).get(f"integration:{integration.id}")
            if selection is not None
            else None
        )
        raw_contract = str(integration.contract_hash or "").strip().lower()
        integration_has_reviewed_contract = bool(
            re.fullmatch(r"[0-9a-f]{64}", raw_contract)
        )
        if (
            selection is None
            or _aware(selection.plan_expires_at) <= current
            or selection.policy_version != current_policy_snapshot_id
            or (
                require_reviewed_contract_binding
                and
                integration_has_reviewed_contract
                and expected_contract != raw_contract
            )
            or (
                require_reviewed_contract_binding
                and
                not integration_has_reviewed_contract
                and expected_contract is not None
            )
            or selection.control_plan_id != payload.get("native_control_plan_id")
            or selection.control_plan_digest != payload.get("native_control_plan_digest")
        ):
            return None, ["provider_event_id_prior_route_binding_not_current"]
        return candidate, []
    return None, ["provider_event_id_claim_pending_or_unbound"]


def _has_prior_pre_action_evidence_for_logical_claim(
    db: Session,
    *,
    integration: NativeControlIntegration,
    claim: NativeControlLogicalActionClaim,
) -> bool:
    """Detect pre-0064 logical actions that have no atomic claim row yet."""

    candidate = db.scalar(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == integration.tenant_id,
            EvidenceNode.node_type == "native_control_callback",
            EvidenceNode.payload["integration_id"].as_string() == integration.id,
            or_(
                EvidenceNode.payload["logical_action_claim_id"].as_string()
                == claim.id,
                EvidenceNode.payload["provider_event_id_hash"].as_string()
                == claim.provider_event_id_hash,
            ),
        )
        .where(EvidenceNode.payload["provider_event_type"].as_string().in_(
            _NATIVE_PRE_ACTION_EVENTS
        ))
        .order_by(EvidenceNode.created_at.asc(), EvidenceNode.id.asc())
        .limit(1)
    )
    return candidate is not None


def _assert_current_callback_receipt_binding(
    db: Session,
    *,
    integration: NativeControlIntegration,
    credential: NativeWorkloadCredential,
    request: AuthorizationRequest,
    expected_enforce_mode_active: bool,
    expected_authorization_context_fingerprint: str,
    expected_exact_native_callback_enforcement_ready: bool,
    requires_exact_adapter: bool,
) -> None:
    """Reject a receipt when its persisted selection no longer matches reality.

    The callback creates its selection and its DecisionReceipt in one caller
    transaction so PostgreSQL can see the uncommitted selection.  That fixes
    visibility, but does not excuse a stale authorization: immediately before
    receipt issuance we re-read the integration and compare its approved
    runtime/contract facts to the selected plan.  This is deliberately narrow
    to the native callback path; it neither changes the receipt model nor
    creates a second policy decision.
    """

    current = _now()
    # A concurrent administrator/configuration update must win over a stale
    # in-memory integration object before a receipt becomes durable. On
    # PostgreSQL this lock is held through the outer callback commit, closing
    # the read-then-commit race with an administrator changing the route,
    # model, deployment, policy, health or lifecycle mode. SQLite treats this
    # as its normal transaction serialization boundary.
    locked = db.scalar(
        select(NativeControlIntegration)
        .where(
            NativeControlIntegration.tenant_id == integration.tenant_id,
            NativeControlIntegration.id == integration.id,
        )
        .with_for_update()
    )
    if locked is None:
        raise HTTPException(status_code=409, detail="Native callback integration is unavailable")
    db.refresh(locked)
    integration = locked

    current_facts = _facts(db, integration)
    current_validation = _latest_validation(db, integration.tenant_id, integration.id)
    current_active_credential = _active_credential(
        db, integration.tenant_id, integration.id
    )
    current_validation_current = bool(
        current_facts.validation is NativeValidationResult.PASSED
        and _aware(current_facts.validation_valid_until) >= current
    )
    current_callback_credential_acceptance = bool(
        current_facts.real_acceptance_current
        and current_validation is not None
        and current_active_credential is not None
        and current_active_credential.credential_id == credential.credential_id
        and current_active_credential.credential_epoch == credential.credential_epoch
        and current_validation.credential_id == credential.credential_id
        and current_validation.credential_epoch == credential.credential_epoch
    )
    current_exact_adapter_ready = bool(
        (not requires_exact_adapter or _adapter_enforcement_eligible(integration))
        and expected_exact_native_callback_enforcement_ready
    )
    current_enforcement_ready = bool(
        integration.state == IntegrationState.ENFORCING.value
        and integration.mode == IntegrationMode.ENFORCE.value
        and current_facts.profile_active
        and current_facts.profile_verification is VerificationStatus.VERIFIED
        and integration.health_state == HealthState.HEALTHY.value
        and current_validation_current
        and _aware(integration.policy_fresh_until) >= current
        and current_facts.configuration_integrity_valid
        and current_facts.provider_version_supported
        and current_facts.adapter_version_supported
        and current_facts.route_binding_current
        and current_facts.enforcement_feature_active
        and current_facts.active_workload_identity
        and current_facts.callback_authenticated
        and current_facts.evidence_flowing
        and current_facts.measured_latency_ms is not None
        and current_facts.real_acceptance_current
        and current_callback_credential_acceptance
        and current_exact_adapter_ready
    )
    current_enforce_mode_active = bool(
        integration.state == IntegrationState.ENFORCING.value
        and integration.mode == IntegrationMode.ENFORCE.value
    )
    current_real_accepted_degraded_route_active = bool(
        integration.state == IntegrationState.DEGRADED.value
        and current_facts.profile_active
        and current_facts.profile_verification is VerificationStatus.VERIFIED
        and current_validation_current
        and _aware(integration.policy_fresh_until) >= current
        and current_facts.configuration_integrity_valid
        and current_facts.provider_version_supported
        and current_facts.adapter_version_supported
        and current_facts.route_binding_current
        and current_facts.enforcement_feature_active
        and current_facts.active_workload_identity
        and current_facts.callback_authenticated
        and current_facts.evidence_flowing
        and current_facts.measured_latency_ms is not None
        and current_facts.real_acceptance_current
        and current_callback_credential_acceptance
        and current_exact_adapter_ready
    )
    current_authoritative_route_active = bool(
        current_enforce_mode_active or current_real_accepted_degraded_route_active
    )
    current_degradation_requires_block = bool(
        current_authoritative_route_active
        and not current_enforcement_ready
        and (
            integration.degradation_mode in {"fail_closed", "require_exception"}
            or (
                integration.degradation_mode == "block_high_risk_only"
                and str(request.policy_profile.get("base_decision") or "") == "block"
            )
        )
    )
    current_authority_facts = {
        "profile_verified": (
            current_facts.profile_active
            and current_facts.profile_verification is VerificationStatus.VERIFIED
        ),
        "validation_current": current_validation_current,
        "policy_fresh": _aware(integration.policy_fresh_until) >= current,
        "configuration_integrity_valid": current_facts.configuration_integrity_valid,
        "provider_version_supported": current_facts.provider_version_supported,
        "adapter_version_supported": current_facts.adapter_version_supported,
        "route_binding_current": current_facts.route_binding_current,
        "enforcement_feature_active": current_facts.enforcement_feature_active,
        "active_workload_identity": current_facts.active_workload_identity,
        "callback_authenticated": current_facts.callback_authenticated,
        "evidence_flowing": current_facts.evidence_flowing,
        "measured_latency_available": current_facts.measured_latency_ms is not None,
        "real_acceptance_current": current_facts.real_acceptance_current,
        "callback_credential_acceptance_current": current_callback_credential_acceptance,
        "exact_native_callback_enforcement_ready": current_exact_adapter_ready,
        "real_accepted_degraded_route_active": current_real_accepted_degraded_route_active,
        "degraded_enforce": (
            current_authoritative_route_active and not current_enforcement_ready
        ),
        # Receipt issuance does not itself turn a degraded callback into an
        # enforcement claim. This bit binds the same monotonic rule used by
        # the response path without accepting raw provider state.
        "degradation_requires_block": current_degradation_requires_block,
    }
    current_context_fingerprint = _callback_authorization_context_fingerprint(
        integration,
        enforce_mode_active=current_authoritative_route_active,
        enforcement_ready=current_enforcement_ready,
        authority_facts=(current_authority_facts if current_authoritative_route_active else {}),
    )
    if (
        current_authoritative_route_active != expected_enforce_mode_active
        or current_context_fingerprint != expected_authorization_context_fingerprint
    ):
        raise HTTPException(
            status_code=409,
            detail="Native callback authorization context changed before receipt issuance",
        )
    selection_id = request.path_evidence.get("native_control_selection_id")
    if not isinstance(selection_id, str) or not selection_id:
        raise HTTPException(status_code=409, detail="Native callback receipt selection is missing")
    selection = db.scalar(
        select(NativeControlSelection).where(
            NativeControlSelection.tenant_id == integration.tenant_id,
            NativeControlSelection.selection_id == selection_id,
            NativeControlSelection.action_id == request.action_id,
        )
    )
    if selection is None:
        raise HTTPException(status_code=409, detail="Native callback receipt selection is unavailable")
    if (
        _aware(selection.plan_expires_at) <= current
        or selection.policy_version != request.policy_snapshot_id
        or selection.control_plan_id != request.path_evidence.get("native_control_plan_id")
        or selection.control_plan_digest != request.path_evidence.get("native_control_plan_digest")
    ):
        raise HTTPException(status_code=409, detail="Native callback receipt binding is no longer current")
    raw_contract = str(integration.contract_hash or "").strip().lower()
    selected_contract = (selection.contract_hashes or {}).get(
        f"integration:{integration.id}"
    )
    if current_authoritative_route_active and (
        (
            re.fullmatch(r"[0-9a-f]{64}", raw_contract)
            and selected_contract != raw_contract
        )
        or (
            not re.fullmatch(r"[0-9a-f]{64}", raw_contract)
            and selected_contract is not None
        )
    ):
        raise HTTPException(status_code=409, detail="Native callback receipt contract is no longer current")

    runtime = selection.provider_runtime_context if isinstance(
        selection.provider_runtime_context, dict
    ) else {}
    # These attributes originate only from the persisted server-side
    # integration.  Provider callback payloads do not participate in this
    # comparison, so a provider cannot retain an old receipt by presenting an
    # old model/deployment identity.
    expected_runtime = {
        "provider": str(integration.provider or "unknown").strip().lower(),
        "product": str(integration.product or "unknown").strip().lower(),
        "runtime": str(integration.runtime or "unknown").strip(),
        "provider_version": str(integration.provider_version or "unknown").strip(),
        "adapter_version": str(integration.adapter_version or "unknown").strip(),
        "environment": str(integration.environment or "unknown").strip(),
        "model_provider": str(integration.model_provider or "unknown").strip(),
        "model": str(integration.model or "unknown").strip(),
        "deployment_identity": f"integration:{integration.instance_key}",
        "deployment_reference": str(integration.deployment_reference or "unknown").strip(),
        "route_identity": f"native-control:{integration.id}",
    }
    # A Monitor-only callback may intentionally have no trusted route yet and
    # therefore records an observation-only selection with unknown runtime
    # fields.  It is not an execution authority.  Once Enforce is requested,
    # every server-bound runtime attribute must still match immediately before
    # issuing the authoritative receipt.
    if current_authoritative_route_active and any(
        str(runtime.get(field) or "unknown") != value
        for field, value in expected_runtime.items()
    ):
        raise HTTPException(status_code=409, detail="Native callback runtime binding is no longer current")

    # Monitoring receipts record a non-authoritative observation.  An exact
    # adapter in Enforce, however, must prove that the active credential has
    # a current real acceptance tied to this exact contract immediately before
    # a pre-action receipt is issued.  A rotated credential can therefore
    # never inherit the old credential's acceptance.
    if requires_exact_adapter and current_authoritative_route_active:
        if not current_callback_credential_acceptance:
            raise HTTPException(
                status_code=409,
                detail="Native callback receipt acceptance is no longer current",
            )


def _record_callback_outcome_metrics(
    integration: NativeControlIntegration,
    *,
    effective_decision: str,
    would_decision: str,
    deduplicated: bool,
    authorization_outcome: bool = True,
) -> None:
    """Emit bounded Phase 4 callback telemetry without inventing a decision."""

    metric_fields = {
        "provider": integration.provider,
        "method": integration.integration_method,
    }
    native_control_metrics.increment(
        "provider_adapter_events_total",
        outcome=("allowed" if effective_decision == "allow" else "other"),
        **metric_fields,
    )
    if not authorization_outcome:
        return
    if effective_decision == "block":
        outcome_metric = "provider_adapter_block_total"
        outcome = "blocked"
    elif would_decision == "block":
        outcome_metric = "provider_adapter_would_block_total"
        outcome = "blocked"
    else:
        outcome_metric = "provider_adapter_allow_total"
        outcome = "allowed"
    native_control_metrics.increment(outcome_metric, outcome=outcome, **metric_fields)
    if deduplicated:
        native_control_metrics.increment(
            "provider_adapter_deduplicated_total",
            outcome="allowed",
            **metric_fields,
        )


def _requires_fail_closed_unknown_exact_action(integration: NativeControlIntegration) -> bool:
    return bool(
        integration.state
        in {IntegrationState.ENFORCING.value, IntegrationState.DEGRADED.value}
        and integration.degradation_mode in {"fail_closed", "block_high_risk_only", "require_exception"}
    )


def _integration_or_404(db: Session, tenant_id: str, integration_id: str) -> NativeControlIntegration:
    row = db.scalar(
        select(NativeControlIntegration).where(
            NativeControlIntegration.id == integration_id,
            NativeControlIntegration.tenant_id == tenant_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Control point not found")
    return row


def _latest_validation(db: Session, tenant_id: str, integration_id: str) -> NativeControlValidation | None:
    return db.scalar(
        select(NativeControlValidation)
        .where(
            NativeControlValidation.tenant_id == tenant_id,
            NativeControlValidation.integration_instance_id == integration_id,
        )
        .order_by(NativeControlValidation.validated_at.desc(), NativeControlValidation.id.desc())
    )


def _normalized_scope(values: object) -> set[str]:
    if not isinstance(values, list):
        return set()
    return {
        str(value).strip()
        for value in values
        if isinstance(value, str) and str(value).strip() and str(value).strip().lower() != "unknown"
    }


def _latest_real_validation_is_bound_to_current_contract(
    db: Session,
    integration: NativeControlIntegration,
    profile: ControlCapabilityProfileRecord | None,
) -> bool:
    """Return true only for the latest immutable, real acceptance of this exact deployment.

    Profile/catalog compatibility is useful selection context, but it is not
    evidence that an installed integration exercised its actual runtime,
    action, lifecycle, and deployment binding.  A newer synthetic or failed
    validation deliberately replaces that authority until a new real
    acceptance is recorded.
    """

    validation = _latest_validation(db, integration.tenant_id, integration.id)
    credential = _active_credential(db, integration.tenant_id, integration.id)
    if validation is None or credential is None or profile is None:
        return False
    expected_contract_hash = str(integration.contract_hash or "").strip()
    profile_contract_hash = str(profile.contract_hash or "").strip()
    expected_actions = _normalized_scope(profile.supported_action_classes)
    expected_methods = {str(integration.integration_method or "").strip()}
    profile_methods = _normalized_scope(profile.supported_control_methods)
    accepted_actions = _normalized_scope(validation.action_classes)
    accepted_methods = _normalized_scope(validation.control_methods)
    accepted_lifecycle = _normalized_scope(validation.lifecycle_events)
    credential_lifecycle = _normalized_scope(credential.allowed_event_types)
    return bool(
        validation.acceptance_state in REAL_ACCEPTANCE_STATES
        and acceptance_version_is_current(
            acceptance_state=validation.acceptance_state,
            validation_version=validation.validation_version,
        )
        and validation.safe_synthetic is False
        and validation.result == NativeValidationResult.PASSED.value
        and validation.allow_result == "passed"
        and validation.block_result == "passed"
        and validation.non_execution_result == "passed"
        and validation.tenant_id == integration.tenant_id
        and validation.integration_instance_id == integration.id
        and validation.credential_id == credential.credential_id
        and validation.credential_epoch == credential.credential_epoch
        and validation.deployment_environment == integration.environment
        and validation.provider == integration.provider == profile.provider
        and validation.product == integration.product == profile.product
        and validation.runtime == integration.runtime
        and validation.model_provider == integration.model_provider
        and validation.model == integration.model
        and validation.route_identity == f"native-control:{integration.id}"
        and validation.deployment_identity == f"integration:{integration.instance_key}"
        and validation.execution_location == integration.execution_location
        and validation.deployment_reference == integration.deployment_reference
        and validation.provider_version == integration.provider_version
        and validation.adapter_version == integration.adapter_version == profile.adapter_version
        and expected_contract_hash
        and expected_contract_hash == profile_contract_hash == validation.contract_hash
        and profile.integration_method == integration.integration_method
        and expected_actions
        and accepted_actions == expected_actions
        and expected_methods == profile_methods
        and accepted_methods == expected_methods
        and accepted_lifecycle
        and accepted_lifecycle == credential_lifecycle
        and bool(str(validation.acceptance_run_id or "").strip())
        and bool(validation.evidence_refs)
    )


def _live_route_observed(
    db: Session,
    *,
    tenant_id: str,
    integration_id: str,
    now: datetime,
) -> bool:
    rows = db.scalars(
        select(NativeControlSelection)
        .where(
            NativeControlSelection.tenant_id == tenant_id,
            NativeControlSelection.selected_at >= now - VALIDATION_TTL,
        )
        .order_by(NativeControlSelection.selected_at.desc())
        .limit(100)
    ).all()
    selected_route_observed = any(
        row.primary_control_point_id == integration_id
        or integration_id in (row.secondary_observation_points or [])
        or any(
            isinstance(item, dict) and item.get("control_point_id") == integration_id
            for item in (row.rejected_candidates or [])
        )
        for row in rows
    )
    if selected_route_observed:
        return True
    # A successfully authenticated callback from this exact integration is
    # direct route evidence even when the selector conservatively rejected the
    # not-yet-validated control point.
    return db.scalar(
        select(NativeControlHealthObservation.id)
        .where(
            NativeControlHealthObservation.tenant_id == tenant_id,
            NativeControlHealthObservation.integration_instance_id == integration_id,
            NativeControlHealthObservation.callback_authenticated.is_(True),
            NativeControlHealthObservation.observed_at >= now - VALIDATION_TTL,
            NativeControlHealthObservation.expires_at >= now,
        )
        .order_by(NativeControlHealthObservation.observed_at.desc())
        .limit(1)
    ) is not None


def _active_credential(db: Session, tenant_id: str, integration_id: str) -> NativeWorkloadCredential | None:
    now = _now()
    return db.scalar(
        select(NativeWorkloadCredential)
        .where(
            NativeWorkloadCredential.tenant_id == tenant_id,
            NativeWorkloadCredential.integration_instance_id == integration_id,
            NativeWorkloadCredential.status == "active",
            NativeWorkloadCredential.expires_at > now,
        )
        .order_by(NativeWorkloadCredential.credential_epoch.desc())
    )


def _version_supported(integration: NativeControlIntegration, profile: ControlCapabilityProfileRecord) -> bool:
    return version_in_verified_range(
        integration.provider_version,
        profile.tested_min_version,
        profile.tested_max_version,
    )


def _facts(db: Session, integration: NativeControlIntegration) -> IntegrationFacts:
    profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
    validation = _latest_validation(db, integration.tenant_id, integration.id)
    active_credential = _active_credential(db, integration.tenant_id, integration.id)
    real_acceptance_current = _latest_real_validation_is_bound_to_current_contract(
        db,
        integration,
        profile,
    )
    validation_matches_active_credential = bool(
        validation
        and active_credential
        and validation.credential_id == active_credential.credential_id
        and validation.credential_epoch == active_credential.credential_epoch
    )
    validation_result = (
        NativeValidationResult(validation.result)
        if validation and validation_matches_active_credential
        else NativeValidationResult.UNKNOWN
    )
    validated_at = validation.validated_at if validation else None
    current_route_surfaces = current_route_surfaces_for_integration(
        settings,
        tenant_id=integration.tenant_id,
        integration_id=integration.id,
        integration_method=integration.integration_method,
        provider=integration.provider,
        provider_version=integration.provider_version,
        adapter_version=integration.adapter_version,
        product=integration.product,
    )
    route_binding_current = bool(current_route_surfaces)
    measured_health = (
        health_snapshot(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id=active_credential.credential_id,
            credential_epoch=active_credential.credential_epoch,
            now=_now(),
        )
        if active_credential
        else None
    )
    return IntegrationFacts(
        state=IntegrationState(integration.state),
        mode=IntegrationMode(integration.mode),
        profile_verification=VerificationStatus(profile.verification_status if profile else "unverified"),
        profile_active=bool(profile and profile.active),
        health=HealthState(integration.health_state),
        validation=validation_result,
        validated_at=validated_at,
        validation_valid_until=_aware(validated_at) + VALIDATION_TTL if validated_at else None,
        policy_fresh_until=integration.policy_fresh_until,
        configuration_integrity_valid=(
            bool(integration.expected_configuration_fingerprint)
            and integration_configuration_fingerprint(integration)
            == integration.expected_configuration_fingerprint
        ),
        provider_version_supported=bool(profile and _version_supported(integration, profile)),
        adapter_version_supported=bool(
            profile and integration.adapter_version == profile.adapter_version
        ),
        route_binding_current=route_binding_current,
        enforcement_feature_active=bool(
            settings.native_control_framework
            and settings.trusted_control_selector
            and settings.native_control_enforce
            and provider_enforcement_enabled(settings, integration.provider)
            and _adapter_enforcement_eligible(integration)
            and kernel_enforcement_active_for_surfaces(
                settings,
                tenant_id=integration.tenant_id,
                surfaces=current_route_surfaces,
            )
        ),
        active_workload_identity=active_credential is not None,
        real_acceptance_current=real_acceptance_current,
        callback_authenticated=bool(measured_health and measured_health.callback_authenticated),
        evidence_flowing=bool(measured_health and measured_health.evidence_flowing),
        measured_latency_ms=(measured_health.observed_latency_ms if measured_health else None),
    )


def _integration_response(db: Session, row: NativeControlIntegration) -> dict[str, object]:
    facts = _facts(db, row)
    current = _now()
    # This response is evaluated outside an individual callback.  It can only
    # use persisted integration facts and the reviewed static adapter contract;
    # per-callback dispatch state belongs exclusively to the signed callback
    # path below.  A callback route that fell back to generic observation cannot
    # satisfy this condition because it has no matching reviewed adapter.
    exact_adapter_contract_ready = bool(
        not _requires_exact_callback_adapter(row)
        or _adapter_enforcement_eligible(row)
    )
    profile = (
        db.get(ControlCapabilityProfileRecord, row.capability_profile_id)
        if row.capability_profile_id
        else None
    )
    real_acceptance_current = facts.real_acceptance_current
    validation_current = bool(
        facts.validation is NativeValidationResult.PASSED
        and _aware(facts.validation_valid_until) >= current
    )
    policy_fresh = _aware(facts.policy_fresh_until) >= current
    authoritative = bool(
        row.state == IntegrationState.ENFORCING.value
        and row.mode == IntegrationMode.ENFORCE.value
        and facts.health is HealthState.HEALTHY
        and facts.profile_active
        and facts.profile_verification is VerificationStatus.VERIFIED
        and validation_current
        and facts.real_acceptance_current
        and policy_fresh
        and facts.configuration_integrity_valid
        and facts.provider_version_supported
        and facts.adapter_version_supported
        and facts.active_workload_identity
        and facts.callback_authenticated
        and facts.evidence_flowing
        and facts.measured_latency_ms is not None
        and exact_adapter_contract_ready
        and real_acceptance_current
        and facts.enforcement_feature_active
        and facts.route_binding_current
    )
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "display_name": row.display_name,
        "provider": row.provider,
        "product": row.product,
        "model_provider": row.model_provider,
        "model": row.model,
        "method": row.integration_method,
        "deployment_family": row.deployment_family,
        "environment": row.environment,
        "state": row.state,
        "mode": row.mode,
        "health_state": row.health_state,
        "health_reasons": list(row.health_reasons or []),
        "provider_version": row.provider_version,
        "adapter_version": row.adapter_version,
        "policy_version": row.policy_version,
        "policy_fresh_until": row.policy_fresh_until,
        "degradation_mode": row.degradation_mode,
        "capabilities": dict(row.capability_snapshot or {}),
        "known_blind_spots": list(row.known_blind_spots or []),
        "last_validated_at": row.last_validated_at,
        "validation_current": validation_current,
        "policy_fresh": policy_fresh,
        "configuration_integrity_valid": facts.configuration_integrity_valid,
        "provider_version_compatible": facts.provider_version_supported,
        "adapter_version_compatible": facts.adapter_version_supported,
        "callback_authenticated": facts.callback_authenticated,
        "evidence_flowing": facts.evidence_flowing,
        "observed_latency_ms": facts.measured_latency_ms,
        "real_acceptance_current": real_acceptance_current,
        "authoritative": authoritative,
        "route_binding_current": facts.route_binding_current,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _record_control_point_downgrade(
    db: Session,
    integration: NativeControlIntegration,
    *,
    previous_state: str,
    reason_code: str,
) -> None:
    evidence = EvidenceNode(
        tenant_id=integration.tenant_id,
        correlation_id=integration.id[:64],
        node_type="control_point_downgrade",
        signal_type="control_point_downgraded",
        label=f"Native control point downgraded: {integration.display_name}",
        payload={
            "integration_id": integration.id,
            "provider": integration.provider,
            "previous_state": previous_state,
            "current_state": integration.state,
            "reason_code": reason_code,
            "policy_version": integration.policy_version,
        },
    )
    db.add(evidence)
    db.flush()
    record_native_control_finding(
        db,
        tenant_id=integration.tenant_id,
        finding_type="CONTROL_POINT_DOWNGRADED",
        integration_id=integration.id,
        action_id=None,
        provider=integration.provider,
        policy_version=integration.policy_version,
        evidence_node_ids=[evidence.id],
        reason_codes=[reason_code],
    )
    native_control_metrics.increment(
        "control_plan_downgrade_total",
        provider=integration.provider,
        method=integration.integration_method,
        outcome="downgraded",
    )


class _DatabaseReplayStore(ReplayStore):
    def __init__(self, db: Session, credential_id: str) -> None:
        self.db = db
        self.credential_id = credential_id

    def claim(
        self,
        *,
        tenant_id: str,
        integration_id: str,
        event_id: str,
        nonce: str,
        expires_at: datetime,
        now: datetime,
    ) -> bool:
        event_hash = hashlib.sha256(event_id.encode("utf-8")).hexdigest()
        nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        existing = self.db.scalar(
            select(NativeControlReplay.id).where(
                NativeControlReplay.tenant_id == tenant_id,
                NativeControlReplay.integration_instance_id == integration_id,
                or_(
                    NativeControlReplay.event_id_hash == event_hash,
                    NativeControlReplay.nonce_hash == nonce_hash,
                ),
            )
        )
        if existing:
            return False
        try:
            with self.db.begin_nested():
                self.db.add(
                    NativeControlReplay(
                        tenant_id=tenant_id,
                        integration_instance_id=integration_id,
                        event_id_hash=event_hash,
                        nonce_hash=nonce_hash,
                        credential_id=self.credential_id,
                        expires_at=expires_at,
                    )
                )
                self.db.flush()
        except IntegrityError:
            return False
        return True


@router.get("/native-controls/chatgpt-desktop/assets", dependencies=[FrameworkDependency])
def list_chatgpt_desktop_assets(
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Return server-projected ChatGPT assets without trusting aggregate claims."""

    return get_chatgpt_desktop_assets(db, tenant_id=ctx.tenant.id)


@router.post("/native-controls/chatgpt-desktop/control-plan", dependencies=[FrameworkDependency])
def get_chatgpt_desktop_control_plan(
    request: ChatGPTDesktopControlPlanRequest,
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Resolve an action-specific plan from tenant evidence, not client posture."""

    result = resolve_chatgpt_desktop_control_plan(
        db,
        tenant_id=ctx.tenant.id,
        endpoint_id=request.endpoint_id,
        action=request.action,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="ChatGPT Desktop endpoint not observed")
    return result


@router.get("/native-controls/adapters", dependencies=[FrameworkDependency])
def list_native_control_adapters(
    _ctx: TenantContext = Depends(require_permission("deployments.view")),
) -> dict[str, object]:
    registry = _foundation_registry()
    items = [_adapter_catalog_item(adapter) for adapter in registry.adapters()]
    return {
        "source": "hawk_shipped_registry",
        "items": items,
        "total": len(items),
        "reference_adapters_production_eligible": False,
    }


@router.get("/native-controls/adapters/{adapter_id}", dependencies=[FrameworkDependency])
def get_native_control_adapter(
    adapter_id: str,
    _ctx: TenantContext = Depends(require_permission("deployments.view")),
) -> dict[str, object]:
    registry = _foundation_registry()
    try:
        return _adapter_catalog_item(registry.get(adapter_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Adapter not found") from exc


@router.get("/native-controls/adapters/{adapter_id}/capabilities", dependencies=[FrameworkDependency])
def get_native_control_adapter_capabilities(
    adapter_id: str,
    _ctx: TenantContext = Depends(require_permission("deployments.view")),
) -> dict[str, object]:
    registry = _foundation_registry()
    try:
        item = _adapter_catalog_item(registry.get(adapter_id))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Adapter not found") from exc
    return {
        "adapter_id": adapter_id,
        "verification_status": item["verification_status"],
        "production_eligible": item["production_eligible"],
        "capabilities": item["capabilities"],
        "blind_spots": item["blind_spots"],
    }


@router.get("/control-capabilities/providers", dependencies=[FrameworkDependency])
def list_provider_capabilities(
    _ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if not settings.control_capability_matrix:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "matrix_version": REGISTRY.matrix_version,
        "source_of_truth": "persisted profile when present; catalog otherwise",
        "providers": [_effective_manifest_payload(db, manifest) for manifest in REGISTRY.manifests],
    }


@router.get("/control-capabilities/providers/{provider}", dependencies=[FrameworkDependency])
def get_provider_capabilities(
    provider: str,
    _ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if not settings.control_capability_matrix:
        raise HTTPException(status_code=404, detail="Not found")
    rows = REGISTRY.for_provider(provider)
    if not rows:
        raise HTTPException(status_code=404, detail="Provider not found")
    return {
        "matrix_version": REGISTRY.matrix_version,
        "source_of_truth": "persisted profile when present; catalog otherwise",
        "provider": provider.lower(),
        "manifests": [_effective_manifest_payload(db, row) for row in rows],
    }


@router.post("/native-controls/integrations", status_code=201, dependencies=[FrameworkDependency])
def create_integration(
    request: IntegrationCreateRequest,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        manifest = REGISTRY.get(request.provider, request.product, ControlMethod(request.method))
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=422, detail="Provider/product/control method manifest is unavailable") from exc
    profile = _profile_for_manifest(db, manifest)
    runtime, execution_location, deployment_reference = _trusted_initial_deployment_scope(
        tenant_id=ctx.tenant.id,
        request=request,
        profile=profile,
    )
    fingerprint = configuration_fingerprint(
        tenant_id=ctx.tenant.id,
        provider=request.provider,
        product=request.product,
        method=request.method,
        instance_key=request.instance_key,
        environment=request.environment,
        provider_version=request.provider_version,
        adapter_version=request.adapter_version,
        policy_version=request.policy_version,
        runtime=runtime,
        model_provider=request.model_provider,
        model=request.model,
        execution_location=execution_location,
        deployment_reference=deployment_reference,
        trusted_workload_authority=request.trusted_workload_authority,
    )
    row = NativeControlIntegration(
        tenant_id=ctx.tenant.id,
        capability_profile_id=profile.id,
        instance_key=request.instance_key,
        display_name=request.display_name,
        provider=request.provider,
        product=request.product,
        model_provider=request.model_provider,
        model=request.model,
        runtime=runtime,
        execution_location=execution_location,
        deployment_reference=deployment_reference,
        integration_method=request.method,
        deployment_family=request.deployment_family,
        environment=request.environment,
        state=IntegrationState.CONFIGURING.value,
        mode=IntegrationMode.DISCOVER.value,
        health_state=HealthState.UNVERIFIED.value,
        health_reasons=["validation_required"],
        provider_version=request.provider_version,
        adapter_version=request.adapter_version,
        # This is a reviewed static contract hash, not a deployment claim.
        # Enforce still requires a later immutable real acceptance record for
        # this integration, active credential, runtime and lifecycle scope.
        contract_hash=profile.contract_hash,
        configuration_fingerprint=fingerprint,
        expected_configuration_fingerprint=fingerprint,
        policy_version=request.policy_version,
        policy_fresh_until=request.policy_fresh_until,
        degradation_mode=request.degradation_mode,
        capability_snapshot={
            **manifest.as_dict()["capability_matrix"],
            "native_policy": {
                "trusted_workload_authority": request.trusted_workload_authority is True,
            },
        },
        known_blind_spots=list(manifest.known_blind_spots),
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Integration instance already exists") from exc
    db.refresh(row)
    return _integration_response(db, row)


@router.get("/control-points", dependencies=[FrameworkDependency])
def list_control_points(
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    rows = db.scalars(
        select(NativeControlIntegration)
        .where(NativeControlIntegration.tenant_id == ctx.tenant.id)
        .order_by(NativeControlIntegration.display_name, NativeControlIntegration.id)
    ).all()
    return {"items": [_integration_response(db, row) for row in rows], "total": len(rows)}


@router.get("/control-points/{integration_id}", dependencies=[FrameworkDependency])
def get_control_point(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return _integration_response(db, _integration_or_404(db, ctx.tenant.id, integration_id))


@router.post(
    "/native-controls/integrations/{integration_id}/credentials",
    status_code=201,
    dependencies=[FrameworkDependency],
)
def register_workload_credential(
    integration_id: str,
    request: CredentialCreateRequest,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    integration = db.scalar(
        select(NativeControlIntegration)
        .where(
            NativeControlIntegration.id == integration_id,
            NativeControlIntegration.tenant_id == ctx.tenant.id,
        )
        .with_for_update()
    )
    if integration is None:
        raise HTTPException(status_code=404, detail="Control point not found")
    if request.environment != integration.environment:
        raise HTTPException(status_code=422, detail="Credential environment does not match integration")
    if _aware(request.expires_at) <= _now() or _aware(request.expires_at) > _now() + timedelta(days=90):
        raise HTTPException(status_code=422, detail="Credential expiry must be in the next 90 days")
    thumbprint = public_key_thumbprint(request.public_key_pem)
    latest = db.scalar(
        select(NativeWorkloadCredential)
        .where(
            NativeWorkloadCredential.tenant_id == ctx.tenant.id,
            NativeWorkloadCredential.integration_instance_id == integration.id,
        )
        .order_by(NativeWorkloadCredential.credential_epoch.desc())
    )
    if latest is not None and request.credential_epoch <= latest.credential_epoch:
        raise HTTPException(status_code=409, detail="Credential epoch must increase monotonically")
    current_active = _active_credential(db, ctx.tenant.id, integration.id)
    row = NativeWorkloadCredential(
        tenant_id=ctx.tenant.id,
        integration_instance_id=integration.id,
        credential_id=request.credential_id,
        credential_epoch=request.credential_epoch,
        public_key_pem=request.public_key_pem,
        key_thumbprint=thumbprint,
        signature_algorithm="ES256",
        environment=request.environment,
        allowed_event_types=request.allowed_event_types,
        status="rotating" if current_active is not None else "active",
        expires_at=request.expires_at,
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Credential ID or epoch already exists") from exc
    return {
        "credential_id": row.credential_id,
        "credential_epoch": row.credential_epoch,
        "key_thumbprint": row.key_thumbprint,
        "signature_algorithm": row.signature_algorithm,
        "status": row.status,
        "expires_at": row.expires_at,
    }


@router.post(
    "/native-controls/integrations/{integration_id}/credentials/{credential_id}/revoke",
    dependencies=[FrameworkDependency],
)
def revoke_workload_credential(
    integration_id: str,
    credential_id: str,
    request: CredentialRevokeRequest,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    integration = _integration_or_404(db, ctx.tenant.id, integration_id)
    previous_state = integration.state
    credential = db.scalar(
        select(NativeWorkloadCredential).where(
            NativeWorkloadCredential.tenant_id == ctx.tenant.id,
            NativeWorkloadCredential.integration_instance_id == integration.id,
            NativeWorkloadCredential.credential_id == credential_id,
        )
    )
    if credential is None:
        raise HTTPException(status_code=404, detail="Workload credential not found")
    if credential.status != "revoked":
        credential.status = "revoked"
        credential.revoked_at = _now()
        credential.revocation_reason = request.reason.strip()
    db.flush()
    active = _active_credential(db, ctx.tenant.id, integration.id)
    evidence = EvidenceNode(
        tenant_id=ctx.tenant.id,
        correlation_id=integration.id[:64],
        node_type="native_control_credential",
        signal_type="native_control_credential_revoked",
        label=f"Native control workload credential revoked: {integration.display_name}",
        payload={
            "integration_id": integration.id,
            "credential_id": credential.credential_id,
            "credential_epoch": credential.credential_epoch,
            "reason": credential.revocation_reason,
            "replacement_active": active is not None,
        },
    )
    db.add(evidence)
    db.flush()
    if active is None:
        was_controlling = integration.state in {
            IntegrationState.MONITORING.value,
            IntegrationState.ENFORCING.value,
        }
        integration.health_state = HealthState.DEGRADED.value
        integration.health_reasons = sorted(
            {*(integration.health_reasons or []), "callback_authentication_unavailable"}
        )
        if integration.state in {IntegrationState.MONITORING.value, IntegrationState.ENFORCING.value}:
            integration.state = IntegrationState.DEGRADED.value
            integration.mode = IntegrationMode.MONITOR.value
        record_native_control_finding(
            db,
            tenant_id=ctx.tenant.id,
            finding_type="NATIVE_CONTROL_CALLBACK_UNHEALTHY",
            integration_id=integration.id,
            action_id=None,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[evidence.id],
            reason_codes=["callback_authentication_unavailable"],
        )
        if was_controlling:
            _record_control_point_downgrade(
                db,
                integration,
                previous_state=previous_state,
                reason_code="callback_authentication_unavailable",
            )
    db.commit()
    return {
        "credential_id": credential.credential_id,
        "credential_epoch": credential.credential_epoch,
        "status": credential.status,
        "revoked_at": credential.revoked_at,
        "replacement_active": active is not None,
    }


@router.post(
    "/native-controls/callbacks/{integration_id}",
    dependencies=[FrameworkDependency],
)
def receive_native_callback(
    integration_id: str,
    request: NativeCallbackRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Authenticate a provider hook, make a pre-action decision, and record live evidence."""
    try:
        envelope_bytes = base64.b64decode(request.envelope_base64, validate=True)
        envelope = parse_envelope_json(envelope_bytes)
        payload = base64.b64decode(request.payload_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid signed native callback") from exc
    integration = db.scalar(
        select(NativeControlIntegration).where(
            NativeControlIntegration.id == integration_id,
            NativeControlIntegration.tenant_id == envelope.tenant_binding,
        )
    )
    if integration is None or envelope.integration_instance_id != integration.id:
        raise HTTPException(status_code=401, detail="Native callback identity is unavailable")
    if envelope.provider_event_type not in _NATIVE_CALLBACK_EVENTS:
        raise HTTPException(status_code=422, detail="Unsupported native callback event")
    credential_row = db.scalar(
        select(NativeWorkloadCredential).where(
            NativeWorkloadCredential.tenant_id == integration.tenant_id,
            NativeWorkloadCredential.integration_instance_id == integration.id,
            NativeWorkloadCredential.credential_id == envelope.credential_id,
            NativeWorkloadCredential.status.in_(["active", "rotating"]),
        )
    )
    if credential_row is None:
        raise HTTPException(status_code=401, detail="Native callback credential is unavailable")
    credential = WorkloadCredential(
        credential_id=credential_row.credential_id,
        credential_epoch=credential_row.credential_epoch,
        tenant_id=credential_row.tenant_id,
        integration_instance_id=credential_row.integration_instance_id,
        provider=integration.provider,
        product=integration.product,
        environment=credential_row.environment,
        allowed_event_types=tuple(credential_row.allowed_event_types or []),
        public_key_pem=credential_row.public_key_pem,
        expires_at=credential_row.expires_at,
        revoked=credential_row.status == "revoked",
    )
    try:
        validate_trusted_envelope(
            envelope,
            credential=credential,
            payload=payload,
            now=_now(),
            replay_store=_DatabaseReplayStore(db, credential.credential_id),
        )
        provider_event = json.loads(payload)
    except (ValueError, json.JSONDecodeError) as exc:
        failure = str(exc)
        finding_type = (
            "NATIVE_CONTROL_REPLAY_REJECTED"
            if failure == "replay_detected"
            else "NATIVE_CONTROL_CALLBACK_UNHEALTHY"
        )
        record_native_control_finding(
            db,
            tenant_id=integration.tenant_id,
            finding_type=finding_type,
            integration_id=integration.id,
            action_id=envelope.event_id,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[],
            reason_codes=[failure],
        )
        db.commit()
        raise HTTPException(status_code=401, detail=f"Native callback rejected: {exc}") from exc
    if not isinstance(provider_event, dict):
        raise HTTPException(status_code=422, detail="Native callback payload must be an object")
    payload_event_type = str(provider_event.get("provider_event_type") or "").strip().lower()
    if payload_event_type and payload_event_type != envelope.provider_event_type:
        raise HTTPException(status_code=422, detail="Native callback lifecycle binding mismatch")
    if (
        envelope.provider_version != integration.provider_version
        or envelope.adapter_version != integration.adapter_version
    ):
        record_native_control_finding(
            db,
            tenant_id=integration.tenant_id,
            finding_type="NATIVE_CONTROL_RUNTIME_BINDING_MISMATCH",
            integration_id=integration.id,
            action_id=envelope.event_id,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[],
            reason_codes=["provider_or_adapter_version_binding_mismatch"],
        )
        db.commit()
        raise HTTPException(status_code=409, detail="Native callback runtime binding mismatch")
    # Lifecycle is an authenticated envelope fact. Project it into the
    # normalized event only after signature, replay, tenant, integration and
    # credential validation so older provider payload schemas remain usable
    # without trusting an unauthenticated body field.
    provider_event = {
        **provider_event,
        "provider_event_type": envelope.provider_event_type,
    }
    lifecycle_event = envelope.provider_event_type
    before_execution = lifecycle_event in _NATIVE_PRE_ACTION_EVENTS
    provider_permission_context = lifecycle_event == "permission_request"
    profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
    profile_verified = bool(profile and profile.active and profile.verification_status == "verified")
    real_acceptance_current = _latest_real_validation_is_bound_to_current_contract(
        db,
        integration,
        profile,
    )
    latest_validation = _latest_validation(db, integration.tenant_id, integration.id)
    # A real acceptance is credential-bound. During credential rotation, a
    # fresh signing key cannot borrow the prior active key's acceptance just
    # because both keys belong to one integration. It remains telemetry until
    # an immutable real acceptance is recorded for its exact key epoch.
    callback_credential_acceptance_current = bool(
        real_acceptance_current
        and latest_validation is not None
        and latest_validation.credential_id == credential.credential_id
        and latest_validation.credential_epoch == credential.credential_epoch
    )
    requires_exact_adapter = _requires_exact_callback_adapter(integration)
    adapter_dispatch = "generic_compatibility"
    adapter_id: str | None = None
    adapter_resolution = "not_applicable"
    adapter_resolution_reason = "integration_method_uses_existing_product_route"
    adapter_version_state = "not_applicable"
    adapter_ineligibility_reasons: list[str] = []
    adapter_enforcement_eligible = False
    exact_dispatch: ExactAdapterDispatch | None = None
    policy_profile = {
        "dependencies_healthy": True,
        # Policy signals are derived only after exact adapter normalization.
        # Raw provider fields must never run the Hawk baseline first.
        "base_decision": "allow",
        "degraded_behavior": "block",
        "triggered_controls": [],
        # Set to true only after exact contract resolution for native callback
        # methods. A generic normalizer is observation compatibility, never an
        # implicit provider-native route binding.
        "native_route_verified": False,
    }
    native_policy = dict((integration.capability_snapshot or {}).get("native_policy") or {})
    workload_authority_bound = native_policy.get("trusted_workload_authority") is True
    resolved_actor = {
        "identity_id": credential.credential_id,
        "identity_type": "workload",
        # A signed callback proves transport and its source integration. It
        # does not by itself prove end-user/customer authority. A Hawk
        # administrator may bind the enrolled workload as a service authority
        # in the immutable integration configuration; otherwise policy sees
        # authority Unknown and fails safely for consequential work.
        "authority_type": (
            "service_identity" if workload_authority_bound else "unknown"
        ),
        "authority_source": (
            "hawk_integration_authority_binding"
            if workload_authority_bound
            else "unknown"
        ),
    }
    if requires_exact_adapter and settings.native_control_adapter_framework:
        try:
            exact_dispatch = dispatch_live_callback_adapter(
                registry=_foundation_registry(),
                tenant_id=integration.tenant_id,
                integration_id=integration.id,
                instance_key=integration.instance_key,
                provider=integration.provider,
                product=integration.product,
                provider_version=envelope.provider_version,
                adapter_version=envelope.adapter_version,
                environment=integration.environment,
                deployment_family=integration.deployment_family,
                integration_method=integration.integration_method,
                runtime=integration.runtime,
                model_provider=integration.model_provider,
                model=integration.model,
                execution_location=integration.execution_location,
                deployment_reference=integration.deployment_reference,
                credential_id=credential.credential_id,
                event_id=envelope.event_id,
                provider_event_id=envelope.provider_event_id,
                provider_event_type=lifecycle_event,
                nonce=envelope.nonce,
                correlation_id=envelope.correlation_id,
                session_id=envelope.session_id,
                chain_id=envelope.chain_id,
                received_at=_now().isoformat(),
                policy_snapshot_id=integration.policy_version or "native-control-baseline/1.0",
                policy_profile=policy_profile,
                resolved_actor=resolved_actor,
                raw_payload=provider_event,
            )
        except ExactAdapterDispatchError as exc:
            record_native_control_finding(
                db,
                tenant_id=integration.tenant_id,
                finding_type="NATIVE_CONTROL_EXACT_ADAPTER_UNAVAILABLE",
                integration_id=integration.id,
                action_id=envelope.event_id,
                provider=integration.provider,
                policy_version=integration.policy_version,
                evidence_node_ids=[],
                reason_codes=[str(exc)],
            )
            db.commit()
            raise HTTPException(
                status_code=409,
                detail=f"Native callback exact adapter unavailable: {exc}",
            ) from exc
        adapter_resolution = exact_dispatch.resolution.state.value
        adapter_resolution_reason = exact_dispatch.resolution.reason
        adapter_version_state = exact_dispatch.resolution.version_state.value
        adapter_ineligibility_reasons = list(exact_dispatch.resolution.ineligibility_reasons)
        if exact_dispatch.is_exact:
            adapter_dispatch = "exact"
            adapter_id = exact_dispatch.adapter_id
            static_action_eligible = bool(
                exact_dispatch.resolution.enforcement_eligible
                # A PermissionRequest does not perform a new policy decision;
                # it uses the reviewed hook protocol to reuse a correlated
                # prior decision/receipt, even when its own placeholder tool
                # label is not a reviewed action class.
                or provider_permission_context
            )
            adapter_enforcement_eligible = bool(
                static_action_eligible and callback_credential_acceptance_current
            )
            if not callback_credential_acceptance_current:
                adapter_ineligibility_reasons = list(
                    dict.fromkeys(
                        [
                            *adapter_ineligibility_reasons,
                            "callback_credential_acceptance_not_current",
                        ]
                    )
                )
            policy_profile["native_route_verified"] = bool(
                profile_verified
                and _adapter_enforcement_eligible(integration)
                and static_action_eligible
                and callback_credential_acceptance_current
            )
        else:
            # An unknown provider family can retain signed generic telemetry.
            # It cannot produce an exact native adapter control claim or enter
            # enforcement through this callback route.
            adapter_dispatch = "generic_observation_fallback"
            adapter_resolution_reason = "provider_unknown_generic_observation_only"
    elif requires_exact_adapter:
        adapter_dispatch = "generic_observation_fallback"
        adapter_resolution = "framework_disabled"
        adapter_resolution_reason = "exact_adapter_framework_disabled"
    else:
        policy_profile["native_route_verified"] = bool(
            profile_verified and _adapter_enforcement_eligible(integration)
        )
    # The generic path accepts a signed transport envelope only so Hawk can
    # retain bounded discovery/health evidence.  It has no reviewed provider
    # canonicalizer and is therefore not an authorization path: do not turn
    # raw provider metadata into a Hawk decision, selection or receipt.
    generic_observation_only = adapter_dispatch == "generic_observation_fallback"
    native_route_verified = policy_profile.get("native_route_verified") is True
    unknown_exact_action = bool(
        requires_exact_adapter
        and exact_dispatch is not None
        and exact_dispatch.is_exact
        and not exact_dispatch.resolution.enforcement_eligible
        and not provider_permission_context
    )
    fail_closed_unknown_exact_action = bool(
        unknown_exact_action and _requires_fail_closed_unknown_exact_action(integration)
    )
    exact_native_callback_enforcement_ready = bool(
        not requires_exact_adapter
        or (
            exact_dispatch is not None
            and exact_dispatch.is_exact
            and (
                exact_dispatch.resolution.enforcement_eligible
                or provider_permission_context
            )
            and native_route_verified
            and callback_credential_acceptance_current
        )
        # A new/unreviewed consequential dynamic tool must not exploit the
        # telemetry fallback while the configured integration is fail-closed
        # Enforce. It remains unverified, but the reviewed callback protocol
        # can return an inline fail-safe denial.
        or fail_closed_unknown_exact_action
    )
    context = ProviderEventContext(
        tenant_id=integration.tenant_id,
        integration_instance_id=integration.id,
        environment=integration.environment,
        credential_id=credential.credential_id,
        event_id=envelope.event_id,
        correlation_id=envelope.correlation_id,
        session_id=envelope.session_id,
        chain_id=envelope.chain_id,
        provider_version=envelope.provider_version,
        adapter_version=envelope.adapter_version,
        integration_method=integration.integration_method,
        resolved_actor=resolved_actor,
        policy_snapshot_id=integration.policy_version or "native-control-baseline/1.0",
        policy_profile=policy_profile,
    )
    try:
        if exact_dispatch is not None and exact_dispatch.is_exact:
            normalized_event = replace(
                exact_dispatch.normalized_event,
                policy_profile=dict(policy_profile),
            )
            authorization_request = normalized_event.to_authorization_request()
            if (
                native_route_verified
                and callback_credential_acceptance_current
                and exact_native_callback_enforcement_ready
                and exact_dispatch.runtime_context.is_resolved_for_enforcement
                and exact_dispatch.runtime_context.lifecycle_stage in _NATIVE_CALLBACK_EVENTS
            ):
                # Only this authenticated, currently accepted exact route may
                # promote the adapter's lifecycle to a trusted selector fact.
                authorization_request = authorization_request.model_copy(
                    deep=True,
                    update={
                        "path_evidence": {
                            **dict(authorization_request.path_evidence or {}),
                            "native_control_route_binding": {
                                **dict(authorization_request.path_evidence.get("native_control_route_binding") or {}),
                                "runtime_context_verified": True,
                                "lifecycle_stage": exact_dispatch.runtime_context.lifecycle_stage,
                            },
                        }
                    },
                )
        else:
            adapter_type = ADAPTERS.get(integration.provider)
            if adapter_type is None:
                # An unknown provider is an authenticated observation only.
                # Keep it bounded and explicitly unbound rather than turning a
                # signed transport event into a 422 dead end or an exact
                # provider-control claim.
                authorization_request = AuthorizationRequest(
                    tenant_id=integration.tenant_id,
                    environment=integration.environment,
                    collector_id=f"native-observation:{integration.id}",
                    action_id=envelope.provider_event_id,
                    chain_id=envelope.chain_id,
                    surface="runtime_control",
                    actor={
                        "identity_id": credential.credential_id,
                        "identity_type": "workload",
                        "session_id": envelope.session_id,
                    },
                    authority={"verified": False, "authority_type": "unknown", "authority_source": "unknown"},
                    runtime={
                        "environment": integration.environment,
                        "integration_method": integration.integration_method,
                        "runtime": integration.runtime,
                        "execution_location": integration.execution_location,
                        "deployment_reference": integration.deployment_reference,
                        "integration_instance_id": integration.id,
                    },
                    purpose={},
                    action={"action_type": "unknown", "action_class": "unknown_action", "risk_level": "unknown"},
                    tool={"name": "unknown", "version": "unknown", "fingerprint_id": "unknown"},
                    parameters={"parameter_hash": "unknown"},
                    target={"resource": "unknown", "resource_hash": "unknown", "destination": "unknown", "destination_hash": "unknown"},
                    data_context={},
                    approval_context={},
                    side_effect_context={"side_effect_class": "unknown", "persistent_side_effect": False},
                    discovery_context={
                        "provider": integration.provider,
                        "product": integration.product,
                        "provider_version": integration.provider_version or "unknown",
                        "adapter_version": integration.adapter_version,
                        "asset_status": "unknown",
                    },
                    policy_snapshot_id=integration.policy_version or "native-control-baseline/1.0",
                    policy_profile=dict(policy_profile),
                    path_evidence={
                        "collector_inline_capable": False,
                        "inline_pre_execution": False,
                        "native_control_route_binding": {
                            "verified": False,
                            "source": "generic_observation_fallback",
                            "integration_instance_ids": [integration.id],
                            "allowed_methods": [integration.integration_method],
                        },
                    },
                )
            else:
                authorization_request = adapter_type(product=integration.product).normalize_event(
                    context=context,
                    event=provider_event,
                )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Native callback payload rejected: {exc}") from exc
    callback_approval_binding_hash = _privacy_safe_callback_binding_hash(
        "approval_action",
        provider_event.get("approval_action_hash"),
    )
    callback_provider_action_identity_hash = _provider_action_identity_hash(
        provider_event=provider_event,
        provider_event_id=envelope.provider_event_id,
    )
    authorization_request = authorization_request.model_copy(
        deep=True,
        update={
            "approval_context": {
                **dict(authorization_request.approval_context or {}),
                "approval_action_hash": callback_approval_binding_hash,
                "provider_action_identity_hash": callback_provider_action_identity_hash,
            }
        },
    )
    # No provider wire schema may promote its own asset to approved. Preserve
    # the adapter's provider/product facts, then use only the separate trusted
    # Discovery Context Provider below for a reference-backed status.
    authorization_request = authorization_request.model_copy(
        deep=True,
        update={
            "discovery_context": {
                **dict(authorization_request.discovery_context or {}),
                "asset_status": "unknown",
            }
        },
    )
    authorization_request = _enrich_native_request_with_discovery_context(db, authorization_request)
    baseline_decision, baseline_reasons = (
        ("unknown", ["generic_observation_only"])
        if generic_observation_only
        else (
            _native_baseline_decision(integration, authorization_request)
            if before_execution or provider_permission_context
            else ("allow", [])
        )
    )
    if fail_closed_unknown_exact_action:
        baseline_decision = "block"
        baseline_reasons = list(
            dict.fromkeys([*baseline_reasons, "CONTROL_REQUIREMENT_UNSATISFIED"])
        )
        adapter_ineligibility_reasons = list(
            dict.fromkeys(
                [*adapter_ineligibility_reasons, "unreviewed_action_class_fail_closed"]
            )
        )
    repository_operation = str(provider_event.get("repository_operation") or "").upper()
    repository_action_type = str(provider_event.get("action_type") or "").upper()
    repository_candidate = (
        "repository_control_resolution" in provider_event
        or repository_operation in {"READ", "EDIT", "COMMIT", "PULL", "PUSH"}
        or repository_action_type in {"FILE_READ", "FILE_WRITE", "COMMAND_EXECUTION"}
    )
    repository_floor: dict[str, object] | None = None
    if before_execution and repository_candidate:
        try:
            repository_floor = resolve_repository_control_floor(
                db,
                tenant_id=integration.tenant_id,
                native_integration_id=integration.id,
                repository_fields=provider_event,
            )
        except ValueError:
            # Malformed signed repository metadata cannot weaken existing
            # policy. The callback remains in the normal receipt/evidence path.
            repository_floor = {
                "decision": "BLOCK",
                "reason": "repository_runtime_target_unresolved",
                "operation": repository_operation or None,
            }
        if repository_floor and repository_floor.get("decision") == "BLOCK":
            baseline_decision = "block"
            baseline_reasons = list(
                dict.fromkeys(
                    [
                        *baseline_reasons,
                        "repository_control_floor",
                        str(repository_floor.get("reason") or "repository_runtime_blocked"),
                    ]
                )
            )
    policy_profile["base_decision"] = baseline_decision
    policy_profile["triggered_controls"] = baseline_reasons
    authorization_request = authorization_request.model_copy(
        deep=True,
        update={"policy_profile": dict(policy_profile)},
    )
    current_material_hash, current_material_fields = _native_callback_material(
        authorization_request
    )
    facts = _facts(db, integration)
    validation_current = bool(
        facts.validation is NativeValidationResult.PASSED
        and _aware(facts.validation_valid_until) >= _now()
    )
    enforcement_ready = bool(
        integration.state == IntegrationState.ENFORCING.value
        and integration.mode == IntegrationMode.ENFORCE.value
        and profile_verified
        and integration.health_state == HealthState.HEALTHY.value
        and validation_current
        and _aware(integration.policy_fresh_until) >= _now()
        and facts.configuration_integrity_valid
        and facts.provider_version_supported
        and facts.adapter_version_supported
        and facts.route_binding_current
        and facts.enforcement_feature_active
        and facts.active_workload_identity
        and facts.callback_authenticated
        and facts.evidence_flowing
        and facts.measured_latency_ms is not None
        and facts.real_acceptance_current
        and callback_credential_acceptance_current
        and exact_native_callback_enforcement_ready
    )
    enforce_mode_active = bool(
        integration.state == IntegrationState.ENFORCING.value
        and integration.mode == IntegrationMode.ENFORCE.value
    )
    # A real-binary accepted native route may temporarily degrade after it has
    # been put into enforcement.  The live integration can then report
    # DEGRADED/MONITOR while the signed callback path, route binding, accepted
    # credential and fresh policy are still current.  That state must fail
    # closed for pre-action callbacks; otherwise a health transition can turn a
    # known dangerous tool call into a telemetry-only Allow.
    real_accepted_degraded_route_active = bool(
        integration.state == IntegrationState.DEGRADED.value
        and (before_execution or provider_permission_context)
        and profile_verified
        and validation_current
        and _aware(integration.policy_fresh_until) >= _now()
        and facts.configuration_integrity_valid
        and facts.provider_version_supported
        and facts.adapter_version_supported
        and facts.route_binding_current
        and facts.enforcement_feature_active
        and facts.active_workload_identity
        and facts.callback_authenticated
        and facts.evidence_flowing
        and facts.measured_latency_ms is not None
        and facts.real_acceptance_current
        and callback_credential_acceptance_current
        and exact_native_callback_enforcement_ready
    )
    authoritative_route_active = bool(
        enforce_mode_active or real_accepted_degraded_route_active
    )
    requested_enforce = bool(
        authoritative_route_active and (before_execution or provider_permission_context)
    )
    degraded_enforce = requested_enforce and not enforcement_ready
    degradation_mode = integration.degradation_mode
    degradation_requires_block = bool(
        degraded_enforce
        and (
            degradation_mode in {"fail_closed", "require_exception"}
            or (
                degradation_mode == "block_high_risk_only"
                and baseline_decision == "block"
            )
        )
    )
    generic_enforce_requirement_unsatisfied = bool(
        generic_observation_only and requires_exact_adapter and authoritative_route_active
    )
    if degraded_enforce:
        baseline_reasons = list(
            dict.fromkeys(
                [
                    *baseline_reasons,
                    "CONTROL_REQUIREMENT_UNSATISFIED",
                    f"degradation_mode:{degradation_mode}",
                ]
            )
        )
        if degradation_requires_block:
            baseline_decision = "block"
        policy_profile["base_decision"] = baseline_decision
        policy_profile["triggered_controls"] = baseline_reasons
        authorization_request = authorization_request.model_copy(
            deep=True,
            update={"policy_profile": dict(policy_profile)},
        )
        current_material_hash, current_material_fields = _native_callback_material(
            authorization_request
        )
    # A healthy inline route alone earns the ``enforced`` claim. A degraded
    # fail-closed route may issue a monotonic deny response, but without a
    # current real block acceptance it cannot claim the provider actually
    # enforced that response. Never turn that distinction into telemetry
    # Allow.
    can_enforce = before_execution and enforcement_ready
    can_issue_fail_safe_deny = before_execution and degradation_requires_block
    permission_can_block = provider_permission_context and (
        enforcement_ready or degradation_requires_block
    )
    permission_enforced = provider_permission_context and enforcement_ready
    callback_authority_facts = {
        "profile_verified": profile_verified,
        "validation_current": validation_current,
        "policy_fresh": _aware(integration.policy_fresh_until) >= _now(),
        "configuration_integrity_valid": facts.configuration_integrity_valid,
        "provider_version_supported": facts.provider_version_supported,
        "adapter_version_supported": facts.adapter_version_supported,
        "route_binding_current": facts.route_binding_current,
        "enforcement_feature_active": facts.enforcement_feature_active,
        "active_workload_identity": facts.active_workload_identity,
        "callback_authenticated": facts.callback_authenticated,
        "evidence_flowing": facts.evidence_flowing,
        "measured_latency_available": facts.measured_latency_ms is not None,
        "real_acceptance_current": facts.real_acceptance_current,
        "callback_credential_acceptance_current": callback_credential_acceptance_current,
        "exact_native_callback_enforcement_ready": exact_native_callback_enforcement_ready,
        "real_accepted_degraded_route_active": real_accepted_degraded_route_active,
        "degraded_enforce": degraded_enforce,
        "degradation_requires_block": degradation_requires_block,
    }
    # Monitor callbacks cannot gain execution authority merely because a
    # health sample changed. Enforce callbacks bind every readiness fact so a
    # subsequent degradation can never replay a more permissive result.
    callback_authority_facts_for_reuse = (
        callback_authority_facts if authoritative_route_active else {}
    )
    callback_authorization_context_fingerprint = _callback_authorization_context_fingerprint(
        integration,
        enforce_mode_active=authoritative_route_active,
        enforcement_ready=enforcement_ready,
        authority_facts=callback_authority_facts_for_reuse,
    )
    authorization = None
    decision_receipt = None
    canonical_action = None
    deduplicated_pre_action: EvidenceNode | None = None
    logical_action_claim: NativeControlLogicalActionClaim | None = None
    deduplication_conflict = False
    deduplication_drift_fields: list[str] = []
    if before_execution and not generic_observation_only:
        current_policy_snapshot_id = authorization_request.policy_snapshot_id
        logical_action_claim, claim_created = _claim_logical_provider_action(
            db,
            integration=integration,
            provider_event_id=envelope.provider_event_id,
            logical_action_identity_hash=callback_provider_action_identity_hash,
            canonical_material_hash=current_material_hash,
            policy_snapshot_id=current_policy_snapshot_id,
            contract_hash=_logical_action_contract_hash(integration),
            configuration_fingerprint=callback_authorization_context_fingerprint,
        )
        if claim_created and _has_prior_pre_action_evidence_for_logical_claim(
            db,
            integration=integration,
            claim=logical_action_claim,
        ):
            # Existing installations can contain pre-0064 callback evidence
            # but no atomic claim. Reuse is permitted only when the full
            # current receipt/plan/route proof remains valid; otherwise a
            # retry must supply a new provider action ID rather than minting a
            # second policy decision during the upgrade boundary.
            deduplicated_pre_action, deduplication_drift_fields = (
                _bound_pre_action_for_logical_claim(
                    db,
                    integration=integration,
                    claim=logical_action_claim,
                    current_policy_snapshot_id=current_policy_snapshot_id,
                    current_configuration_fingerprint=callback_authorization_context_fingerprint,
                    route_binding_current=bool(facts.route_binding_current),
                    require_reviewed_contract_binding=authoritative_route_active,
                )
            )
            deduplication_conflict = deduplicated_pre_action is None
            if deduplication_conflict:
                _mark_logical_action_claim_conflicted(
                    db,
                    claim=logical_action_claim,
                    conflicting_material_hash=current_material_hash,
                )
        elif not claim_created:
            if logical_action_claim.canonical_material_hash != current_material_hash:
                deduplication_conflict = True
                deduplication_drift_fields = ["canonical_material_hash"]
                _mark_logical_action_claim_conflicted(
                    db,
                    claim=logical_action_claim,
                    conflicting_material_hash=current_material_hash,
                )
            else:
                deduplicated_pre_action, deduplication_drift_fields = (
                    _bound_pre_action_for_logical_claim(
                        db,
                        integration=integration,
                        claim=logical_action_claim,
                        current_policy_snapshot_id=current_policy_snapshot_id,
                        current_configuration_fingerprint=callback_authorization_context_fingerprint,
                        route_binding_current=bool(facts.route_binding_current),
                        require_reviewed_contract_binding=authoritative_route_active,
                    )
                )
                if (
                    deduplicated_pre_action is None
                    and deduplication_drift_fields
                    == ["provider_event_id_claim_pending_or_unbound"]
                ):
                    native_control_metrics.increment(
                        "provider_adapter_errors_total",
                        provider=integration.provider,
                        method=integration.integration_method,
                        outcome="failed",
                    )
                    raise HTTPException(
                        status_code=409,
                        detail="Logical native action is pending durable receipt binding; retry later",
                    )
                deduplication_conflict = deduplicated_pre_action is None
                if deduplication_conflict:
                    _mark_logical_action_claim_conflicted(
                        db,
                        claim=logical_action_claim,
                        conflicting_material_hash=current_material_hash,
                    )
    if (
        before_execution
        and not generic_observation_only
        and deduplicated_pre_action is None
        and not deduplication_conflict
    ):
        # This is the single authoritative policy evaluation for the
        # callback. Selection binds the returned request/response; it never
        # accepts caller-supplied plan fields or creates a second decision.
        authorization = authorize_ai_action(authorization_request)
        rollout = AuthorizationRolloutOutcome(
            authoritative_decision=authorization.decision,
            metadata={},
            v2_response=authorization,
            enforced=can_enforce,
            request=authorization_request,
        )
        rollout = apply_native_selection_to_rollout(
            db,
            rollout=rollout,
            settings_obj=settings,
            now=_now(),
            trusted_provider=integration.provider,
        )
        if rollout.request is None or rollout.v2_response is None:
            raise HTTPException(status_code=409, detail="Native control selection did not bind authorization")
        authorization_request = rollout.request
        authorization = rollout.v2_response
        if not (authoritative_route_active and not enforcement_ready):
            _assert_current_callback_receipt_binding(
                db,
                integration=integration,
                credential=credential,
                request=authorization_request,
                expected_enforce_mode_active=authoritative_route_active,
                expected_authorization_context_fingerprint=(
                    callback_authorization_context_fingerprint
                ),
                expected_exact_native_callback_enforcement_ready=(
                    exact_native_callback_enforcement_ready
                ),
                requires_exact_adapter=requires_exact_adapter,
            )
            decision_receipt, canonical_action = persist_pre_execution_decision_in_transaction(
                db,
                request=authorization_request,
                response=authorization,
                settings_obj=settings,
            )
        current_material_hash, current_material_fields = _native_callback_material(
            authorization_request
        )

    correlation_candidate: EvidenceNode | None = None
    correlated_pre_action: EvidenceNode | None = None
    correlated_logical_action_conflicted = False
    correlated_logical_action_binding_errors: list[str] = []
    material_drift_fields: list[str] = []
    if not before_execution:
        candidates = db.scalars(
            select(EvidenceNode)
            .where(
                EvidenceNode.tenant_id == integration.tenant_id,
                EvidenceNode.correlation_id == envelope.correlation_id[:64],
                EvidenceNode.node_type == "native_control_callback",
            )
            .order_by(EvidenceNode.created_at.desc())
            .limit(_MAX_NATIVE_CALLBACK_HISTORY + 1)
        ).all()
        if len(candidates) > _MAX_NATIVE_CALLBACK_HISTORY:
            correlated_logical_action_binding_errors = [
                "provider_correlation_history_ambiguous"
            ]
        else:
            provider_event_hash = hashlib.sha256(envelope.provider_event_id.encode("utf-8")).hexdigest()
            for candidate in candidates:
                payload_value = candidate.payload if isinstance(candidate.payload, dict) else {}
                if payload_value.get("provider_event_type") not in _NATIVE_PRE_ACTION_EVENTS:
                    continue
                # Permission callbacks may have a distinct provider event ID; the
                # resulting action material must still equal an existing pre gate.
                # Post callbacks require both the provider event correlation hint
                # and canonical material equality.
                if not provider_permission_context and payload_value.get("provider_event_id_hash") != provider_event_hash:
                    continue
                correlation_candidate = candidate
                material_drift_fields = _native_callback_material_drift(
                    payload_value.get("canonical_material_fields"),
                    current_material_fields,
                )
                if not material_drift_fields and payload_value.get("canonical_material_hash") == current_material_hash:
                    correlated_pre_action = candidate
                break
        if correlated_pre_action is not None:
            claim_id = correlated_pre_action.payload.get("logical_action_claim_id")
            if isinstance(claim_id, str) and claim_id:
                prior_claim = db.scalar(
                    select(NativeControlLogicalActionClaim).where(
                        NativeControlLogicalActionClaim.id == claim_id,
                        NativeControlLogicalActionClaim.tenant_id == integration.tenant_id,
                        NativeControlLogicalActionClaim.integration_instance_id == integration.id,
                    )
                )
                if prior_claim is not None and prior_claim.conflicted_at is not None:
                    correlated_logical_action_conflicted = True
                    correlated_pre_action = None
                elif prior_claim is None:
                    # Pre-claim evidence from an older deployment is not a
                    # reusable authorization boundary.  It may still inform
                    # an operator, but PermissionRequest/Post callbacks must
                    # fail safe until a current pre-action claim exists.
                    correlated_logical_action_binding_errors = [
                        "provider_event_id_prior_claim_missing"
                    ]
                    correlated_pre_action = None
                else:
                    (
                        current_pre_action,
                        correlated_logical_action_binding_errors,
                    ) = _bound_pre_action_for_logical_claim(
                        db,
                        integration=integration,
                        claim=prior_claim,
                        current_policy_snapshot_id=authorization_request.policy_snapshot_id,
                        current_configuration_fingerprint=callback_authorization_context_fingerprint,
                        route_binding_current=bool(facts.route_binding_current),
                        require_reviewed_contract_binding=authoritative_route_active,
                    )
                    if current_pre_action is None:
                        correlated_logical_action_conflicted = (
                            "provider_event_id_historical_conflict"
                            in correlated_logical_action_binding_errors
                        )
                        correlated_pre_action = None
                    else:
                        correlated_pre_action = current_pre_action
            else:
                correlated_logical_action_binding_errors = [
                    "provider_event_id_prior_claim_missing"
                ]
                correlated_pre_action = None
    # These fields are part of the authenticated callback evidence for every
    # lifecycle event.  They are meaningful only for PermissionRequest, but
    # must remain explicit false for pre/post callbacks rather than relying on
    # a branch-local value.
    permission_pre_action_correlated = False
    approval_reauthorization_required = False
    if provider_permission_context:
        permission_pre_action_correlated = correlated_pre_action is not None
        approval_reauthorization_required = not permission_pre_action_correlated
        if correlated_pre_action is not None:
            previous = correlated_pre_action.payload
            would_decision = str(
                previous.get("would_decision") or previous.get("decision") or "block"
            )
            # A configured fail-closed degradation is still an enforceable
            # deny boundary.  Conversely an unhealthy Enforce route that is
            # not permitted to deny must remain explicitly monitor-only.
            effective_decision = (
                str(previous.get("decision") or "block")
                if permission_can_block
                else "allow"
            )
            reason = "Reused Hawk pre-action decision bound to exact action material"
            permission_reason_codes = list(previous.get("reason_codes") or [])
        else:
            would_decision = "block"
            effective_decision = "block" if permission_can_block else "allow"
            reason = "Hawk pre-action decision missing or action material changed; reauthorization required"
            permission_reason_codes = (
                ["provider_event_id_historical_conflict"]
                if correlated_logical_action_conflicted
                else (
                    correlated_logical_action_binding_errors
                    or ["hawk_pre_action_binding_missing_or_changed"]
                )
            )
        effective_control_mode = "provider_permission_context"
        effective_enforced = permission_enforced
    elif before_execution and generic_observation_only:
        if degradation_requires_block or generic_enforce_requirement_unsatisfied:
            # A configured Enforce route that loses its reviewed semantic
            # adapter must not silently become observation-only. This is a
            # monotonic control-requirement denial, not a raw-payload policy
            # evaluation, and no selection/receipt is minted from the
            # generic callback.
            would_decision = "block"
            effective_decision = "block"
            effective_control_mode = "control_requirement_unsatisfied"
            effective_enforced = True
            reason = "Hawk blocked the action because the required reviewed native adapter is unavailable"
            permission_reason_codes = [
                "generic_observation_only",
                "CONTROL_REQUIREMENT_UNSATISFIED",
                f"degradation_mode:{degradation_mode}",
            ]
        else:
            would_decision = "unknown"
            effective_decision = "unknown"
            effective_control_mode = "generic_observation"
            effective_enforced = False
            reason = "Signed provider callback retained as generic observation; no reviewed Hawk authorization was issued"
            permission_reason_codes = ["generic_observation_only"]
    elif before_execution:
        permission_pre_action_correlated = False
        approval_reauthorization_required = False
        if deduplicated_pre_action is not None:
            previous = deduplicated_pre_action.payload
            would_decision = str(previous.get("would_decision") or previous.get("decision") or "block")
            effective_decision = str(previous.get("decision") or "block")
            effective_control_mode = "idempotent_replay"
            effective_enforced = bool(previous.get("enforced") is True)
            reason = "Reused Hawk pre-action decision for an identical provider action retry"
            permission_reason_codes = list(previous.get("reason_codes") or [])
        elif deduplication_conflict:
            would_decision = "block"
            effective_decision = (
                "block" if (can_enforce or can_issue_fail_safe_deny) else "allow"
            )
            effective_control_mode = (
                "conflicting_provider_event"
                if can_enforce
                else (
                    "control_requirement_unsatisfied"
                    if can_issue_fail_safe_deny
                    else "telemetry_only"
                )
            )
            effective_enforced = can_enforce or can_issue_fail_safe_deny
            reason = "Provider action identifier cannot reuse a stale, conflicting, or unbound Hawk authorization"
            permission_reason_codes = [
                "provider_event_id_reauthorization_required",
                *deduplication_drift_fields,
            ]
        else:
            assert authorization is not None
            would_decision = authorization.decision
            effective_decision = (
                authorization.decision
                if can_enforce
                else ("block" if can_issue_fail_safe_deny else "allow")
            )
            effective_control_mode = (
                authorization.control_mode
                if can_enforce
                else (
                    "control_requirement_unsatisfied"
                    if can_issue_fail_safe_deny
                    else "telemetry_only"
                )
            )
            effective_enforced = can_enforce or can_issue_fail_safe_deny
            reason = authorization.reason
            permission_reason_codes = baseline_reasons
    else:
        # Post callbacks are evidence only. They never call policy again and
        # cannot turn a prior decision into a new authorization.
        if correlated_pre_action is not None:
            previous = correlated_pre_action.payload
            would_decision = str(previous.get("would_decision") or previous.get("decision") or "block")
            effective_decision = str(previous.get("decision") or "allow")
            reason = "Attached provider-reported execution to exact Hawk pre-action decision"
            permission_reason_codes = list(previous.get("reason_codes") or [])
        else:
            would_decision = "block"
            # A post-action callback cannot authorize or undo anything. Never
            # label an orphan/mutated post as an Allow.
            effective_decision = "unknown"
            reason = "Provider-reported post action is orphaned or materially changed; no execution receipt attached"
            permission_reason_codes = (
                ["provider_event_id_historical_conflict"]
                if correlated_logical_action_conflicted
                else (
                    correlated_logical_action_binding_errors
                    or ["hawk_pre_action_binding_missing_or_changed"]
                )
            )
        effective_control_mode = "provider_reported"
        effective_enforced = False
    input_mutation_detected: bool | None = (
        bool(material_drift_fields) if correlation_candidate is not None else None
    )
    current_parameter_hash = current_material_fields["parameter_hash"]
    execution_evidence_quality = (
        "provider_reported"
        if lifecycle_event in _NATIVE_POST_ACTION_EVENTS
        else "none"
    )
    lifecycle_semantics = {
        "before_agent": "pre_agent_turn_control",
        "after_agent": "provider_reported_agent_response",
        "before_tool": "pre_action_authorization",
        "before_tool_selection": "tool_filtering_only",
        "permission_request": "provider_permission_context",
        "after_tool": "provider_reported_success",
        "after_tool_failure": "provider_reported_failure",
        "before_model": "prompt_submission_context",
        "after_model": "provider_reported_model_completion",
        "session_start": "session_context",
        "session_end": "session_context",
        "config_change": "configuration_integrity_signal",
        "before_shell": "pre_action_shell_authorization",
        "after_shell": "provider_reported_shell_execution",
        "before_mcp": "pre_action_mcp_authorization",
        "after_mcp": "provider_reported_mcp_execution",
        "before_file_read": "pre_action_file_read_authorization",
        "after_file_edit": "provider_reported_file_edit",
        "subagent_start": "pre_action_delegation_authorization",
        "subagent_stop": "delegation_context",
        "subagent_context_start": "provider_reported_delegation_context",
        "subagent_context_stop": "provider_reported_delegation_context",
        "pre_compact": "session_context",
        "post_compact": "session_context",
        "stop": "session_context",
        "interrupt": "session_interrupt_evidence_only",
        "after_agent_response": "provider_reported_response_metadata",
        "after_agent_thought": "metadata_only_no_reasoning_content",
        "workspace_open": "workspace_context",
        "pre_compress": "advisory_compression_context",
        "notification": "provider_notification_observation",
    }[lifecycle_event]
    inherited_receipt_id: str | None = None
    inherited_receipt_decision: str | None = None
    inherited_canonical_action: dict | None = None
    receipt_source_pre_action = deduplicated_pre_action or correlated_pre_action
    if receipt_source_pre_action is not None and isinstance(receipt_source_pre_action.payload, dict):
        candidate_receipt_id = receipt_source_pre_action.payload.get("decision_receipt_id")
        candidate_canonical_action = receipt_source_pre_action.payload.get("canonical_action")
        if isinstance(candidate_receipt_id, str) and isinstance(candidate_canonical_action, dict):
            receipt_row = db.scalar(
                select(DecisionReceipt).where(
                    DecisionReceipt.tenant_id == integration.tenant_id,
                    DecisionReceipt.receipt_id == candidate_receipt_id,
                )
            )
            if receipt_row is not None:
                inherited_receipt_id = candidate_receipt_id
                inherited_canonical_action = dict(candidate_canonical_action)
                inherited_receipt_decision = receipt_row.decision
    execution_receipt_id: str | None = None
    execution_integrity_result_id: str | None = None
    if (
        lifecycle_event in _NATIVE_POST_ACTION_EVENTS
        and correlated_pre_action is not None
        and inherited_receipt_id is not None
        and inherited_canonical_action is not None
    ):
        # SQLite's pre-existing replay row is written in this request. Release
        # that outer writer before the isolated execution-receipt transaction;
        # PostgreSQL retains normal independent transaction behavior.
        if db.get_bind().dialect.name == "sqlite" and db.in_transaction():
            db.commit()
        # A post callback may be emitted even when Hawk's pre-action decision
        # was deny/block/shadow.  That callback cannot retrospectively prove an
        # allowed execution.  Persist only non-execution/incomplete evidence
        # for a non-executable receipt; an execution receipt is reserved for
        # decisions that actually permitted the side effect.
        if inherited_receipt_decision in {"allow", "warn", "redact"}:
            execution_receipt_id, execution_integrity_result_id = persist_execution_receipt_isolated(
                db,
                tenant_id=integration.tenant_id,
                decision_receipt_id=inherited_receipt_id,
                actual_canonical_action=inherited_canonical_action,
                execution_status=(
                    "failure" if lifecycle_event == "after_tool_failure" else "success"
                ),
                collector_id=authorization_request.collector_id,
                settings_obj=settings,
                execution_attempt_id=envelope.event_id,
            )
        else:
            execution_integrity_result_id = persist_execution_incomplete_isolated(
                db,
                tenant_id=integration.tenant_id,
                decision_receipt_id=inherited_receipt_id,
                settings_obj=settings,
                execution_attempt_id=envelope.event_id,
            )
    evidence = EvidenceNode(
        tenant_id=integration.tenant_id,
        correlation_id=envelope.correlation_id[:64],
        node_type="native_control_callback",
        signal_type=(
            "authenticated_provider_observation"
            if generic_observation_only
            else "authenticated_native_adapter"
        ),
        label=f"Native callback: {integration.display_name}",
        payload={
            "integration_id": integration.id,
            "provider": integration.provider,
            "product": integration.product,
            "provider_version": envelope.provider_version,
            "adapter_version": envelope.adapter_version,
            "credential_id": credential.credential_id,
            "credential_epoch": credential.credential_epoch,
            "signature_algorithm": "ES256",
            "provider_event_type": envelope.provider_event_type,
            "adapter_dispatch": adapter_dispatch,
            "adapter_id": adapter_id,
            "adapter_resolution": adapter_resolution,
            "adapter_resolution_reason": adapter_resolution_reason,
            "adapter_version_state": adapter_version_state,
            "adapter_enforcement_eligible": adapter_enforcement_eligible,
            "adapter_ineligibility_reasons": adapter_ineligibility_reasons,
            "provider_runtime_context_fingerprint": (
                exact_dispatch.runtime_context.fingerprint
                if exact_dispatch is not None
                else None
            ),
            "tool_class": str(provider_event.get("tool_class") or "unknown_tool"),
            "lifecycle_semantics": lifecycle_semantics,
            "event_id_hash": hashlib.sha256(envelope.event_id.encode("utf-8")).hexdigest(),
            "provider_event_id_hash": hashlib.sha256(
                envelope.provider_event_id.encode("utf-8")
            ).hexdigest(),
            "logical_action_claim_id": (
                logical_action_claim.id if logical_action_claim is not None else None
            ),
            "policy_snapshot_id": authorization_request.policy_snapshot_id,
            "acceptance_challenge_id_hash": _privacy_safe_callback_binding_hash(
                "real_binary_acceptance_challenge",
                provider_event.get("acceptance_challenge_id"),
            ),
            "integration_contract_hash": integration.contract_hash,
            "logical_action_contract_hash": _logical_action_contract_hash(integration),
            "integration_configuration_fingerprint": integration_configuration_fingerprint(
                integration
            ),
            "callback_authorization_context_fingerprint": (
                callback_authorization_context_fingerprint
            ),
            "route_binding_current": bool(facts.route_binding_current),
            "degraded_enforce": degraded_enforce,
            "degradation_mode": degradation_mode,
            "degradation_requires_block": degradation_requires_block,
            # Only canonical adapter material participates in action/receipt
            # correlation. Raw provider hashes remain telemetry-only.
            "parameter_hash": current_parameter_hash,
            "target_resource_hash": current_material_fields["target_resource_hash"],
            "target_confirmation": (
                "hash_bound"
                if re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(current_material_fields["target_resource_hash"]),
                )
                else "unconfirmed"
            ),
            "destination_hash": current_material_fields["destination_hash"],
            "canonical_material_hash": current_material_hash,
            "canonical_material_fields": current_material_fields,
            "repository_control_resolution": str(provider_event.get("repository_control_resolution") or "unknown"),
            "repository_operation": str(provider_event.get("repository_operation") or "unknown"),
            "repository_command_shape": str(provider_event.get("repository_command_shape") or "unknown"),
            "repository_command_hash": str(provider_event.get("repository_command_hash") or "unknown"),
            "repository_destination_hash": str(provider_event.get("repository_destination_hash") or "unknown"),
            "repository_root_hash": str(provider_event.get("repository_root_hash") or "unknown"),
            "repository_common_dir_hash": str(provider_event.get("repository_common_dir_hash") or "unknown"),
            "repository_target_hash": str(provider_event.get("repository_target_hash") or "unknown"),
            "repository_control_reason": (
                str(repository_floor.get("reason"))
                if repository_floor and repository_floor.get("decision") == "BLOCK"
                else None
            ),
            "response_hash": str(provider_event.get("response_hash") or "unknown"),
            "approval_binding_hash": callback_approval_binding_hash,
            "provider_action_identity_hash": callback_provider_action_identity_hash,
            "provider_permission_context": provider_permission_context,
            "permission_suggestions_hash": str(
                provider_event.get("permission_suggestions_hash") or "unknown"
            ),
            "config_source": str(provider_event.get("config_source") or "unknown"),
            "config_file_path_hash": str(
                provider_event.get("config_file_path_hash") or "unknown"
            ),
            "permission_pre_action_correlated": permission_pre_action_correlated,
            "approval_reauthorization_required": approval_reauthorization_required,
            "decision": effective_decision,
            "would_decision": would_decision,
            "control_mode": effective_control_mode,
            "enforced": effective_enforced,
            "reason_codes": permission_reason_codes,
            "post_action_correlated": (
                correlated_pre_action is not None and not provider_permission_context
            ),
            "correlated_pre_action_evidence_ref": (
                f"evidence:{correlated_pre_action.id}"
                if correlated_pre_action is not None
                else None
            ),
            "input_mutation_detected": input_mutation_detected,
            "material_drift_fields": material_drift_fields,
            "execution_evidence_quality": execution_evidence_quality,
            "evidence_grade": (
                "provider_reported_execution"
                if execution_evidence_quality == "provider_reported"
                else "signed_provider_callback"
            ),
            "decision_receipt_id": (
                decision_receipt.receipt_id if decision_receipt is not None else inherited_receipt_id
            ),
            "execution_receipt_id": execution_receipt_id,
            "execution_integrity_result_id": execution_integrity_result_id,
            "canonical_action": canonical_action or inherited_canonical_action,
            "deduplicated": deduplicated_pre_action is not None,
            "deduplicated_from_evidence_ref": (
                f"evidence:{deduplicated_pre_action.id}"
                if deduplicated_pre_action is not None
                else None
            ),
            "deduplication_conflict": deduplication_conflict,
            "deduplication_drift_fields": deduplication_drift_fields,
            "native_control_selection_id": (
                authorization_request.path_evidence.get("native_control_selection_id")
                if before_execution
                else None
            ),
            "native_control_plan_id": (
                authorization_request.path_evidence.get("native_control_plan_id")
                if before_execution
                else None
            ),
            "native_control_plan_digest": (
                authorization_request.path_evidence.get("native_control_plan_digest")
                if before_execution
                else None
            ),
            "raw_result_retained": False,
        },
    )
    db.add(evidence)
    db.flush()
    if before_execution and repository_candidate:
        try:
            observe_github_repository_runtime(
                db,
                tenant_id=integration.tenant_id,
                native_integration_id=integration.id,
                repository_fields=provider_event,
                signed_evidence_ref=f"evidence:{evidence.id}",
            )
        except ValueError:
            # Keep the authenticated callback evidence even when its optional
            # repository projection is malformed or incomplete.
            pass
    if input_mutation_detected is True:
        record_native_control_finding(
            db,
            tenant_id=integration.tenant_id,
            finding_type="EXECUTION_DRIFT_DETECTED",
            integration_id=integration.id,
            action_id=envelope.provider_event_id,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[
                correlation_candidate.id,
                evidence.id,
            ] if correlation_candidate is not None else [evidence.id],
            reason_codes=["provider_input_changed_between_pre_and_post_hook", *material_drift_fields],
            material_field_or_effect="execution",
            evidence_kinds=["comparator_result", "execution_evidence"],
            authority_refs=[
                str(inherited_receipt_id or authorization_request.policy_snapshot_id)
            ],
            profile_ref=str(
                authorization_request.path_evidence.get("domain_profile_ref")
                or authorization_request.policy_snapshot_id
            ),
            lifecycle_ref=str(execution_integrity_result_id or evidence.id),
            evidence_classification="provider_reported",
        )
    if deduplication_conflict:
        record_native_control_finding(
            db,
            tenant_id=integration.tenant_id,
            # This is a pre-execution identifier/material conflict.  It is not
            # execution evidence, so record the unsatisfied control requirement
            # instead of overstating it as verified execution drift.
            finding_type="CONTROL_REQUIREMENT_UNSATISFIED",
            integration_id=integration.id,
            action_id=envelope.provider_event_id,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[evidence.id],
            reason_codes=[
                "provider_event_id_reauthorization_required",
                *deduplication_drift_fields,
            ],
        )
    if fail_closed_unknown_exact_action:
        record_native_control_finding(
            db,
            tenant_id=integration.tenant_id,
            finding_type="CONTROL_REQUIREMENT_UNSATISFIED",
            integration_id=integration.id,
            action_id=envelope.provider_event_id,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[evidence.id],
            reason_codes=["unreviewed_exact_action_class"],
        )
    latency_ms = max(0, min(300_000, int((_now() - _aware(envelope.issued_at)).total_seconds() * 1000)))
    record_health_observation(
        db,
        tenant_id=integration.tenant_id,
        integration_id=integration.id,
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        # Evidence retains the stable provider tool-use ID for pre/post
        # correlation. Health samples use the unique signed callback event ID
        # so a valid provider retry cannot collide with an earlier sample.
        provider_event_id=f"{envelope.event_id}:{envelope.provider_event_type}",
        provider_event_type=envelope.provider_event_type,
        callback_authenticated=True,
        evidence_flowing=True,
        latency_ms=latency_ms,
        source="signed_native_callback",
        evidence_ref=f"evidence:{evidence.id}",
        observed_at=_now(),
    )
    integration.last_health_check_at = _now()
    db.commit()
    _record_callback_outcome_metrics(
        integration,
        effective_decision=effective_decision,
        would_decision=would_decision,
        deduplicated=deduplicated_pre_action is not None,
        authorization_outcome=(
            not generic_observation_only
            or degradation_requires_block
            or generic_enforce_requirement_unsatisfied
        ),
    )
    return {
        "integration_id": integration.id,
        "event_id": envelope.event_id,
        "decision": effective_decision,
        "would_decision": would_decision,
        "control_mode": effective_control_mode,
        "enforced": effective_enforced,
        "reason": reason,
        "reason_codes": permission_reason_codes,
        "evidence_ref": f"evidence:{evidence.id}",
        "observed_latency_ms": latency_ms,
        "lifecycle_semantics": lifecycle_semantics,
        "provider_permission_context": provider_permission_context,
        "permission_pre_action_correlated": permission_pre_action_correlated,
        "approval_reauthorization_required": approval_reauthorization_required,
        "post_action_correlated": (
            correlated_pre_action is not None and not provider_permission_context
        ),
        "correlated_pre_action_evidence_ref": (
            f"evidence:{correlated_pre_action.id}"
            if correlated_pre_action is not None
            else None
        ),
        "input_mutation_detected": input_mutation_detected,
        "material_drift_fields": material_drift_fields,
        "execution_evidence_quality": execution_evidence_quality,
        "decision_receipt_id": (
            decision_receipt.receipt_id if decision_receipt is not None else inherited_receipt_id
        ),
        "execution_receipt_id": execution_receipt_id,
        "execution_integrity_result_id": execution_integrity_result_id,
        "deduplicated": deduplicated_pre_action is not None,
        "deduplicated_from_evidence_ref": (
            f"evidence:{deduplicated_pre_action.id}"
            if deduplicated_pre_action is not None
            else None
        ),
        "deduplication_conflict": deduplication_conflict,
        "deduplication_drift_fields": deduplication_drift_fields,
        "adapter_dispatch": adapter_dispatch,
        "adapter_id": adapter_id,
        "adapter_resolution": adapter_resolution,
        "adapter_resolution_reason": adapter_resolution_reason,
        "adapter_version_state": adapter_version_state,
        "adapter_enforcement_eligible": adapter_enforcement_eligible,
        "adapter_ineligibility_reasons": adapter_ineligibility_reasons,
        "degraded_enforce": degraded_enforce,
        "degradation_mode": degradation_mode,
        "degradation_requires_block": degradation_requires_block,
    }


@router.post("/native-controls/integrations/{integration_id}/validate", dependencies=[FrameworkDependency])
def validate_integration(
    integration_id: str,
    request: ValidationRequest,
    ctx: TenantContext = Depends(require_permission("deployments.operate")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    integration = _integration_or_404(db, ctx.tenant.id, integration_id)
    previous_state = integration.state
    try:
        transition_integration(_facts(db, integration), IntegrationState.VALIDATING, now=_now())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    try:
        envelope_bytes = base64.b64decode(request.envelope_base64, validate=True)
        envelope = parse_envelope_json(envelope_bytes)
        payload = base64.b64decode(request.payload_base64, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=422, detail="Invalid signed validation envelope") from exc
    credential_row = db.scalar(
        select(NativeWorkloadCredential).where(
            NativeWorkloadCredential.tenant_id == ctx.tenant.id,
            NativeWorkloadCredential.integration_instance_id == integration.id,
            NativeWorkloadCredential.credential_id == envelope.credential_id,
            NativeWorkloadCredential.status.in_(["active", "rotating"]),
        )
    )
    if credential_row is None:
        raise HTTPException(status_code=401, detail="Workload credential is unavailable")
    credential = WorkloadCredential(
        credential_id=credential_row.credential_id,
        credential_epoch=credential_row.credential_epoch,
        tenant_id=credential_row.tenant_id,
        integration_instance_id=credential_row.integration_instance_id,
        provider=integration.provider,
        product=integration.product,
        environment=credential_row.environment,
        allowed_event_types=tuple(credential_row.allowed_event_types or []),
        public_key_pem=credential_row.public_key_pem,
        expires_at=credential_row.expires_at,
        revoked=credential_row.status == "revoked",
    )
    try:
        validate_trusted_envelope(
            envelope,
            credential=credential,
            payload=payload,
            now=_now(),
            replay_store=_DatabaseReplayStore(db, credential.credential_id),
        )
        validation_payload = json.loads(payload)
    except (ValueError, json.JSONDecodeError) as exc:
        failure = str(exc)
        native_control_metrics.increment(
            "provider_adapter_replay_rejections_total"
            if failure == "replay_detected"
            else "provider_adapter_auth_failures_total",
            provider=integration.provider,
            method=integration.integration_method,
            outcome="replay" if failure == "replay_detected" else "failed",
        )
        raise HTTPException(status_code=401, detail=f"Native validation failed: {exc}") from exc
    expected_validation_keys = {
        "validation_version",
        "safe_synthetic",
        "allow_behavior",
        "block_behavior",
        "evidence_callback",
        "post_execution_path",
    }
    if not isinstance(validation_payload, dict) or set(validation_payload) != expected_validation_keys:
        raise HTTPException(status_code=422, detail="Invalid synthetic validation payload")
    behavioral_claims = {
        "safe_synthetic",
        "allow_behavior",
        "block_behavior",
        "evidence_callback",
        "post_execution_path",
    }
    if any(type(validation_payload.get(name)) is not bool for name in behavioral_claims):
        raise HTTPException(status_code=422, detail="Synthetic validation claims must be booleans")
    profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
    route_binding_valid = bool(
        current_route_surfaces_for_integration(
            settings,
            tenant_id=ctx.tenant.id,
            integration_id=integration.id,
            integration_method=integration.integration_method,
            provider=integration.provider,
            provider_version=integration.provider_version,
            adapter_version=integration.adapter_version,
            product=integration.product,
        )
    )
    security_properties = dict(profile.security_properties or {}) if profile else {}
    probe_checks = run_safe_synthetic_validation(
        tenant_id=ctx.tenant.id,
        integration_id=integration.id,
        integration_method=integration.integration_method,
        profile_verified=bool(profile and profile.verification_status == "verified"),
        pre_execution_capable=security_properties.get("pre_execution_capable") is True,
        route_binding_configured=route_binding_valid,
        live_route_observed=_live_route_observed(
            db,
            tenant_id=ctx.tenant.id,
            integration_id=integration.id,
            now=_now(),
        ),
    )
    post_execution_claim = (
        (profile.capabilities or {}).get("post_execution_verification")
        if profile
        else None
    )
    server_allow_behavior = probe_checks.pop("allow_behavior", False)
    server_block_behavior = probe_checks.pop("block_behavior", False)
    checks = {
        "callback_authenticated": True,
        "validation_version": validation_payload.get("validation_version") == VALIDATION_VERSION,
        "validation_event_type": envelope.provider_event_type == "hawk.validation",
        "safe_synthetic": validation_payload["safe_synthetic"] is True,
        **probe_checks,
        "allow_behavior": bool(
            server_allow_behavior and validation_payload["allow_behavior"] is True
        ),
        "block_behavior": bool(
            server_block_behavior and validation_payload["block_behavior"] is True
        ),
        "replay_protection": True,
        "configuration_integrity": bool(
            integration.expected_configuration_fingerprint
            and integration_configuration_fingerprint(integration)
            == integration.expected_configuration_fingerprint
        ),
        "policy_fresh": _aware(integration.policy_fresh_until) >= _now(),
        "provider_version": bool(
            profile
            and envelope.provider_version == integration.provider_version
            and _version_supported(integration, profile)
        ),
        "adapter_version": bool(
            profile
            and envelope.adapter_version == integration.adapter_version
            and integration.adapter_version == profile.adapter_version
        ),
        "evidence_callback": validation_payload["evidence_callback"] is True,
        # A claimed verified post-execution path needs its own observed runner.
        # Profiles without that claim are not failed for an inapplicable check.
        "post_execution_path": bool(
            validation_payload["post_execution_path"] is True
            and not (
                isinstance(post_execution_claim, dict)
                and post_execution_claim.get("verification_status") == "verified"
            )
        ),
        "profile_verified": bool(profile and profile.verification_status == "verified"),
    }
    passed = all(checks.values())
    partial = bool(
        not passed
        and checks.get("live_route_observed") is False
        and all(value for name, value in checks.items() if name != "live_route_observed")
    )
    result = (
        NativeValidationResult.PASSED
        if passed
        else NativeValidationResult.PARTIAL
        if partial
        else NativeValidationResult.FAILED
    )
    reasons = [name for name, value in checks.items() if not value]
    evidence = EvidenceNode(
        tenant_id=ctx.tenant.id,
        correlation_id=envelope.correlation_id[:64],
        node_type="native_control_validation",
        signal_type="safe_synthetic_validation",
        label=f"Native control validation: {integration.display_name}",
        payload={
            "integration_id": integration.id,
            "provider": integration.provider,
            "product": integration.product,
            "method": integration.integration_method,
            "checks": checks,
            "result": result.value,
            "credential_id": credential.credential_id,
            "event_id_hash": hashlib.sha256(envelope.event_id.encode("utf-8")).hexdigest(),
        },
    )
    db.add(evidence)
    db.flush()
    callback_latency_ms = max(
        0,
        min(300_000, int((_now() - _aware(envelope.issued_at)).total_seconds() * 1000)),
    )
    record_health_observation(
        db,
        tenant_id=ctx.tenant.id,
        integration_id=integration.id,
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        provider_event_id=envelope.provider_event_id,
        provider_event_type=envelope.provider_event_type,
        callback_authenticated=True,
        evidence_flowing=True,
        latency_ms=callback_latency_ms,
        source=(
            "endpoint_runtime_probe"
            if integration.integration_method == "endpoint_runtime"
            else "signed_native_callback"
        ),
        evidence_ref=f"evidence:{evidence.id}",
        observed_at=_now(),
    )
    validation = NativeControlValidation(
        tenant_id=ctx.tenant.id,
        integration_instance_id=integration.id,
        validation_version=VALIDATION_VERSION,
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        safe_synthetic=True,
        checks=checks,
        result=result.value,
        reason_codes=reasons,
        evidence_refs=[f"evidence:{evidence.id}"],
        validated_at=_now(),
    )
    db.add(validation)
    native_control_metrics.increment(
        "provider_adapter_validation_total",
        provider=integration.provider,
        method=integration.integration_method,
        outcome="allowed" if passed else "failed",
    )
    if not passed:
        native_control_metrics.increment(
            "provider_adapter_validation_failures_total",
            provider=integration.provider,
            method=integration.integration_method,
            outcome="failed",
        )
        record_native_control_finding(
            db,
            tenant_id=ctx.tenant.id,
            finding_type="CONTROL_VALIDATION_FAILED",
            integration_id=integration.id,
            action_id=envelope.event_id,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[evidence.id],
            reason_codes=reasons,
        )
    integration.state = (
        IntegrationState.VALIDATING.value
        if result in {NativeValidationResult.PASSED, NativeValidationResult.PARTIAL}
        else IntegrationState.DEGRADED.value
    )
    integration.mode = IntegrationMode.MONITOR.value
    integration.health_state = HealthState.HEALTHY.value if passed else HealthState.DEGRADED.value
    integration.health_reasons = reasons
    integration.last_health_check_at = _now()
    integration.last_validated_at = _now()
    if passed and credential_row.status == "rotating":
        previous_credentials = db.scalars(
            select(NativeWorkloadCredential).where(
                NativeWorkloadCredential.tenant_id == ctx.tenant.id,
                NativeWorkloadCredential.integration_instance_id == integration.id,
                NativeWorkloadCredential.id != credential_row.id,
                NativeWorkloadCredential.status.in_(["active", "rotating"]),
            )
        ).all()
        promoted_at = _now()
        for previous in previous_credentials:
            previous.status = "revoked"
            previous.revoked_at = promoted_at
            previous.revocation_reason = f"rotated_to_epoch:{credential_row.credential_epoch}"
        credential_row.status = "active"
    if previous_state in {
        IntegrationState.MONITORING.value,
        IntegrationState.ENFORCING.value,
    } and (not passed or previous_state == IntegrationState.ENFORCING.value):
        _record_control_point_downgrade(
            db,
            integration,
            previous_state=previous_state,
            reason_code=("validation_failed" if not passed else "revalidation_started"),
        )
    db.commit()
    return {
        "integration_id": integration.id,
        "validation_id": validation.id,
        "validation_version": validation.validation_version,
        "safe_synthetic": validation.safe_synthetic,
        "checks": checks,
        "result": result.value,
        "reason_codes": reasons,
        "evidence_refs": validation.evidence_refs,
        "validated_at": validation.validated_at,
    }


@router.post(
    "/native-controls/integrations/{integration_id}/validate/run",
    dependencies=[FrameworkDependency],
)
def run_server_validation(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.operate")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Run a side-effect-free server probe after a real signed callback was observed.

    This does not mint or impersonate a workload signature.  It binds the
    synthetic policy probe to the active credential's recent authenticated
    callback/evidence observations and refuses to pass when that live proof is
    absent or stale.
    """

    integration = _integration_or_404(db, ctx.tenant.id, integration_id)
    if integration.integration_method not in {"endpoint_runtime", "native_hook"}:
        raise HTTPException(
            status_code=422,
            detail="Server validation is available only for endpoint runtime and native hook control points",
        )
    previous_state = integration.state
    try:
        transition_integration(_facts(db, integration), IntegrationState.VALIDATING, now=_now())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    credential = _active_credential(db, ctx.tenant.id, integration.id)
    if credential is None:
        raise HTTPException(status_code=409, detail="active_workload_credential_required")
    profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
    security_properties = dict(profile.security_properties or {}) if profile else {}
    current = _now()
    measured = health_snapshot(
        db,
        tenant_id=ctx.tenant.id,
        integration_id=integration.id,
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        now=current,
    )
    route_binding_valid = bool(
        current_route_surfaces_for_integration(
            settings,
            tenant_id=ctx.tenant.id,
            integration_id=integration.id,
            integration_method=integration.integration_method,
            provider=integration.provider,
            provider_version=integration.provider_version,
            adapter_version=integration.adapter_version,
            product=integration.product,
        )
    )
    live_route_observed = _live_route_observed(
        db,
        tenant_id=ctx.tenant.id,
        integration_id=integration.id,
        now=current,
    )
    probe_checks = run_safe_synthetic_validation(
        tenant_id=ctx.tenant.id,
        integration_id=integration.id,
        integration_method=integration.integration_method,
        profile_verified=bool(profile and profile.active and profile.verification_status == "verified"),
        pre_execution_capable=security_properties.get("pre_execution_capable") is True,
        route_binding_configured=route_binding_valid,
        live_route_observed=live_route_observed,
    )
    checks = {
        "callback_authenticated": measured.callback_authenticated,
        "evidence_flowing": measured.evidence_flowing,
        "latency_measured": measured.observed_latency_ms is not None,
        "credential_active": True,
        "configuration_integrity": bool(
            integration.expected_configuration_fingerprint
            and integration_configuration_fingerprint(integration)
            == integration.expected_configuration_fingerprint
        ),
        "policy_fresh": _aware(integration.policy_fresh_until) >= current,
        "provider_version": bool(profile and _version_supported(integration, profile)),
        "adapter_version": bool(profile and integration.adapter_version == profile.adapter_version),
        "profile_verified": bool(
            profile and profile.active and profile.verification_status == VerificationStatus.VERIFIED.value
        ),
        **probe_checks,
    }
    passed = all(checks.values())
    result = NativeValidationResult.PASSED if passed else NativeValidationResult.FAILED
    reasons = [name for name, value in checks.items() if not value]
    evidence = EvidenceNode(
        tenant_id=ctx.tenant.id,
        correlation_id=f"server-validation:{integration.id}"[:64],
        node_type="native_control_validation",
        signal_type="server_safe_synthetic_validation",
        label=f"Server validation: {integration.display_name}",
        payload={
            "integration_id": integration.id,
            "provider": integration.provider,
            "product": integration.product,
            "method": integration.integration_method,
            "checks": checks,
            "result": result.value,
            "credential_id": credential.credential_id,
            "credential_epoch": credential.credential_epoch,
            "source_health_evidence": list(measured.evidence_refs),
            "observed_latency_ms": measured.observed_latency_ms,
        },
    )
    db.add(evidence)
    db.flush()
    validation = NativeControlValidation(
        tenant_id=ctx.tenant.id,
        integration_instance_id=integration.id,
        validation_version=SERVER_VALIDATION_VERSION,
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        safe_synthetic=True,
        checks=checks,
        result=result.value,
        reason_codes=reasons,
        evidence_refs=[*measured.evidence_refs, f"evidence:{evidence.id}"],
        validated_at=current,
    )
    db.add(validation)
    if not passed:
        record_native_control_finding(
            db,
            tenant_id=ctx.tenant.id,
            finding_type="CONTROL_VALIDATION_FAILED",
            integration_id=integration.id,
            action_id=None,
            provider=integration.provider,
            policy_version=integration.policy_version,
            evidence_node_ids=[evidence.id],
            reason_codes=reasons,
        )
    integration.state = (
        IntegrationState.VALIDATING.value if passed else IntegrationState.DEGRADED.value
    )
    integration.mode = IntegrationMode.MONITOR.value
    integration.health_state = (
        HealthState.HEALTHY.value if passed else HealthState.DEGRADED.value
    )
    integration.health_reasons = reasons
    integration.last_health_check_at = current
    integration.last_validated_at = current
    if previous_state == IntegrationState.ENFORCING.value:
        _record_control_point_downgrade(
            db,
            integration,
            previous_state=previous_state,
            reason_code="server_revalidation_started",
        )
    db.commit()
    return {
        "integration_id": integration.id,
        "validation_id": validation.id,
        "validation_version": validation.validation_version,
        "safe_synthetic": validation.safe_synthetic,
        "checks": checks,
        "result": result.value,
        "reason_codes": reasons,
        "evidence_refs": validation.evidence_refs,
        "validated_at": validation.validated_at,
        "observed_latency_ms": measured.observed_latency_ms,
    }


def _real_binary_acceptance_evidence(
    db: Session,
    *,
    integration: NativeControlIntegration,
    credential: NativeWorkloadCredential,
    current: datetime,
) -> tuple[dict[str, bool], dict[str, EvidenceNode]]:
    """Resolve independently bound allow, block, and non-execution evidence.

    Callback presence is not acceptance proof.  The accepted evidence set must
    contain two distinct, current, credential-epoch-bound signed decisions and
    a separately attested observation that the blocked target did not execute.
    No field supplied by a callback caller is treated as that observation.
    """

    recent = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == integration.tenant_id,
            EvidenceNode.created_at >= current - VALIDATION_TTL,
        )
        .order_by(EvidenceNode.created_at.desc(), EvidenceNode.id.desc())
        .limit(256)
    ).all()
    expected_configuration = integration_configuration_fingerprint(integration)

    def _valid_hash(value: object) -> bool:
        return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))

    def _callback_matches(node: EvidenceNode, outcome: str) -> bool:
        payload = node.payload if isinstance(node.payload, dict) else {}
        if not (
            node.node_type == "native_control_callback"
            and node.signal_type == "authenticated_native_adapter"
            and payload.get("integration_id") == integration.id
            and payload.get("provider") == integration.provider
            and payload.get("product") == integration.product
            and payload.get("provider_version") == integration.provider_version
            and payload.get("adapter_version") == integration.adapter_version
            and payload.get("credential_id") == credential.credential_id
            and payload.get("credential_epoch") == credential.credential_epoch
            and payload.get("signature_algorithm") == "ES256"
            and payload.get("provider_event_type") in _NATIVE_PRE_ACTION_EVENTS
            and payload.get("adapter_dispatch") == "exact"
            and payload.get("adapter_resolution") == "exact_match"
            and payload.get("adapter_enforcement_eligible") is True
            and payload.get("route_binding_current") is True
            and payload.get("integration_contract_hash") == integration.contract_hash
            and payload.get("integration_configuration_fingerprint")
            == expected_configuration
            and payload.get("policy_snapshot_id") == integration.policy_version
            and payload.get("target_confirmation") == "hash_bound"
            and _valid_hash(payload.get("target_resource_hash"))
            and _valid_hash(payload.get("acceptance_challenge_id_hash"))
            and _valid_hash(payload.get("provider_event_id_hash"))
            and payload.get("evidence_grade") == "signed_provider_callback"
            and payload.get("deduplicated") is False
            and payload.get("deduplication_conflict") is False
            and payload.get("decision") == outcome
            and payload.get("would_decision") == outcome
        ):
            return False
        if outcome == "block" and payload.get("enforced") is not True:
            return False
        receipt_id = str(payload.get("decision_receipt_id") or "")
        if not receipt_id:
            return False
        receipt = db.scalar(
            select(DecisionReceipt).where(
                DecisionReceipt.tenant_id == integration.tenant_id,
                DecisionReceipt.receipt_id == receipt_id,
            )
        )
        return bool(
            receipt is not None
            and receipt.decision == outcome
            and receipt.policy_snapshot_id == integration.policy_version
            and receipt.target_resource_hash == payload.get("target_resource_hash")
            and str(receipt.signature or "").strip()
            and str(receipt.signing_key_id or "").strip()
        )

    allow_nodes = [node for node in recent if _callback_matches(node, "allow")]
    block_nodes = [node for node in recent if _callback_matches(node, "block")]
    selected_allow: EvidenceNode | None = None
    selected_block: EvidenceNode | None = None
    for allow_node in allow_nodes:
        allow_payload = allow_node.payload
        for block_node in block_nodes:
            block_payload = block_node.payload
            if (
                allow_node.id != block_node.id
                and allow_node.correlation_id
                and block_node.correlation_id
                and allow_node.correlation_id != block_node.correlation_id
                and allow_payload.get("provider_event_id_hash")
                != block_payload.get("provider_event_id_hash")
                and allow_payload.get("acceptance_challenge_id_hash")
                != block_payload.get("acceptance_challenge_id_hash")
                and allow_payload.get("decision_receipt_id")
                != block_payload.get("decision_receipt_id")
            ):
                selected_allow = allow_node
                selected_block = block_node
                break
        if selected_block is not None:
            break

    allow_ref = f"evidence:{selected_allow.id}" if selected_allow is not None else None
    allow_payload = (
        selected_allow.payload
        if selected_allow is not None and isinstance(selected_allow.payload, dict)
        else {}
    )
    allow_receipt_id = str(allow_payload.get("decision_receipt_id") or "")
    selected_allow_execution: EvidenceNode | None = None
    if selected_allow is not None:
        for node in recent:
            payload = node.payload if isinstance(node.payload, dict) else {}
            execution_receipt_id = str(payload.get("execution_receipt_id") or "")
            if not execution_receipt_id:
                continue
            execution_receipt = db.scalar(
                select(ExecutionReceipt).where(
                    ExecutionReceipt.tenant_id == integration.tenant_id,
                    ExecutionReceipt.receipt_id == execution_receipt_id,
                    ExecutionReceipt.decision_receipt_id == allow_receipt_id,
                )
            )
            if (
                node.node_type == "native_control_callback"
                and node.signal_type == "authenticated_native_adapter"
                and node.correlation_id == selected_allow.correlation_id
                and payload.get("integration_id") == integration.id
                and payload.get("provider") == integration.provider
                and payload.get("product") == integration.product
                and payload.get("provider_version") == integration.provider_version
                and payload.get("adapter_version") == integration.adapter_version
                and payload.get("credential_id") == credential.credential_id
                and payload.get("credential_epoch") == credential.credential_epoch
                and payload.get("signature_algorithm") == "ES256"
                and payload.get("provider_event_type") in _NATIVE_POST_ACTION_EVENTS
                and payload.get("adapter_dispatch") == "exact"
                and payload.get("adapter_resolution") == "exact_match"
                and payload.get("route_binding_current") is True
                and payload.get("integration_contract_hash") == integration.contract_hash
                and payload.get("integration_configuration_fingerprint")
                == expected_configuration
                and payload.get("policy_snapshot_id") == integration.policy_version
                and payload.get("correlated_pre_action_evidence_ref") == allow_ref
                and payload.get("acceptance_challenge_id_hash")
                == allow_payload.get("acceptance_challenge_id_hash")
                and payload.get("decision") == "allow"
                and payload.get("execution_evidence_quality") == "provider_reported"
                and payload.get("evidence_grade") == "provider_reported_execution"
                and payload.get("input_mutation_detected") is False
                and payload.get("target_resource_hash")
                == allow_payload.get("target_resource_hash")
                and payload.get("target_confirmation") == "hash_bound"
                and execution_receipt is not None
                and execution_receipt.actual_target_resource_hash
                == allow_payload.get("target_resource_hash")
            ):
                selected_allow_execution = node
                break

    selected_allow_target_effect: EvidenceNode | None = None
    if selected_allow_execution is not None:
        allow_execution_ref = f"evidence:{selected_allow_execution.id}"
        for node in recent:
            payload = node.payload if isinstance(node.payload, dict) else {}
            expected_effect = {
                "endpoint_observed_execution_effect": (
                    "endpoint_observed",
                    "trusted_endpoint_monitor",
                    "endpoint_observed_exact",
                ),
                "provider_observed_execution_effect": (
                    "provider_observed",
                    "trusted_provider_execution_log",
                    "provider_observed_hash_bound",
                ),
            }.get(node.signal_type)
            if expected_effect is None:
                continue
            if (
                node.node_type == "native_control_execution_effect"
                and node.created_at >= selected_allow_execution.created_at
                and payload.get("evidence_version") == _REAL_BINARY_EVIDENCE_VERSION
                and payload.get("integration_id") == integration.id
                and payload.get("provider") == integration.provider
                and payload.get("product") == integration.product
                and payload.get("provider_version") == integration.provider_version
                and payload.get("adapter_version") == integration.adapter_version
                and payload.get("credential_id") == credential.credential_id
                and payload.get("credential_epoch") == credential.credential_epoch
                and payload.get("policy_snapshot_id") == integration.policy_version
                and payload.get("integration_contract_hash") == integration.contract_hash
                and payload.get("integration_configuration_fingerprint")
                == expected_configuration
                and payload.get("allow_evidence_ref") == allow_ref
                and payload.get("allow_correlation_id") == selected_allow.correlation_id
                and payload.get("allow_execution_evidence_ref") == allow_execution_ref
                and payload.get("allow_decision_receipt_id") == allow_receipt_id
                and payload.get("acceptance_challenge_id_hash")
                == allow_payload.get("acceptance_challenge_id_hash")
                and payload.get("target_resource_hash")
                == allow_payload.get("target_resource_hash")
                and payload.get("execution_observed") is True
                and payload.get("expected_target_state_verified") is True
                and payload.get("evidence_quality") == expected_effect[0]
                and payload.get("observer_class") == expected_effect[1]
                and payload.get("target_confirmation") == expected_effect[2]
                and payload.get("observer_attestation_verified") is True
                and payload.get("server_verified") is True
            ):
                selected_allow_target_effect = node
                break

    block_ref = f"evidence:{selected_block.id}" if selected_block is not None else None
    block_payload = (
        selected_block.payload
        if selected_block is not None and isinstance(selected_block.payload, dict)
        else {}
    )
    block_receipt_id = str(block_payload.get("decision_receipt_id") or "")
    correlated_execution = False
    if selected_block is not None:
        correlated_execution = db.scalar(
            select(ExecutionReceipt.receipt_id).where(
                ExecutionReceipt.tenant_id == integration.tenant_id,
                ExecutionReceipt.decision_receipt_id == block_receipt_id,
            ).limit(1)
        ) is not None
        if not correlated_execution:
            for node in recent:
                payload = node.payload if isinstance(node.payload, dict) else {}
                if (
                    node.node_type == "native_control_callback"
                    and payload.get("correlated_pre_action_evidence_ref") == block_ref
                    and (
                        payload.get("execution_evidence_quality") == "provider_reported"
                        or bool(payload.get("execution_receipt_id"))
                    )
                ):
                    correlated_execution = True
                    break

    selected_non_execution: EvidenceNode | None = None
    if selected_block is not None and not correlated_execution:
        expected_quality = {
            "endpoint_observed_non_execution": (
                "endpoint_observed",
                "trusted_endpoint_monitor",
                "endpoint_observed_exact",
            ),
            "provider_observed_non_execution": (
                "provider_observed",
                "trusted_provider_execution_log",
                "provider_observed_hash_bound",
            ),
        }
        for node in recent:
            payload = node.payload if isinstance(node.payload, dict) else {}
            quality = expected_quality.get(node.signal_type)
            if quality is None:
                continue
            if (
                node.node_type == "native_control_non_execution"
                and node.created_at >= selected_block.created_at
                and payload.get("evidence_version") == _REAL_BINARY_EVIDENCE_VERSION
                and payload.get("integration_id") == integration.id
                and payload.get("provider") == integration.provider
                and payload.get("product") == integration.product
                and payload.get("provider_version") == integration.provider_version
                and payload.get("adapter_version") == integration.adapter_version
                and payload.get("credential_id") == credential.credential_id
                and payload.get("credential_epoch") == credential.credential_epoch
                and payload.get("policy_snapshot_id") == integration.policy_version
                and payload.get("integration_contract_hash") == integration.contract_hash
                and payload.get("integration_configuration_fingerprint")
                == expected_configuration
                and payload.get("block_evidence_ref") == block_ref
                and payload.get("block_decision_receipt_id") == block_receipt_id
                and payload.get("block_correlation_id") == selected_block.correlation_id
                and payload.get("acceptance_challenge_id_hash")
                == block_payload.get("acceptance_challenge_id_hash")
                and payload.get("target_resource_hash")
                == block_payload.get("target_resource_hash")
                and payload.get("execution_observed") is False
                and not payload.get("execution_receipt_id")
                and payload.get("evidence_quality") == quality[0]
                and payload.get("observer_class") == quality[1]
                and payload.get("target_confirmation") == quality[2]
                and payload.get("observer_attestation_verified") is True
                and payload.get("server_verified") is True
            ):
                selected_non_execution = node
                break

    distinct_pair = selected_allow is not None and selected_block is not None
    checks = {
        "signed_allow_receipt_observed": bool(allow_nodes),
        "signed_block_receipt_observed": bool(block_nodes),
        "distinct_acceptance_challenges": distinct_pair,
        "credential_epoch_bound": distinct_pair,
        "target_hash_bound": distinct_pair,
        "allow_execution_receipt_observed": selected_allow_execution is not None,
        "attested_allow_target_effect_observed": selected_allow_target_effect is not None,
        "block_execution_absent": bool(selected_block is not None and not correlated_execution),
        "attested_non_execution_observed": selected_non_execution is not None,
    }
    selected: dict[str, EvidenceNode] = {}
    if selected_allow is not None:
        selected["allow"] = selected_allow
    if selected_block is not None:
        selected["block"] = selected_block
    if selected_allow_execution is not None:
        selected["allow_execution"] = selected_allow_execution
    if selected_allow_target_effect is not None:
        selected["allow_target_effect"] = selected_allow_target_effect
    if selected_non_execution is not None:
        selected["non_execution"] = selected_non_execution
    return checks, selected


@router.post(
    "/native-controls/integrations/{integration_id}/accept-real-binary",
    dependencies=[FrameworkDependency],
)
def accept_real_binary(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Bind a real local native-control binary after recent signed callback proof.

    Safe synthetic validation proves policy logic.  This endpoint is the
    explicit operator action that promotes an observed, signed local binary
    into real deployment acceptance for the active credential epoch.  It
    deliberately refuses to mint acceptance from catalog metadata alone.
    """

    integration = db.scalar(
        select(NativeControlIntegration)
        .where(
            NativeControlIntegration.id == integration_id,
            NativeControlIntegration.tenant_id == ctx.tenant.id,
        )
        .with_for_update()
    )
    if integration is None:
        raise HTTPException(status_code=404, detail="Control point not found")
    if integration.integration_method != ControlMethod.NATIVE_HOOK.value:
        raise HTTPException(status_code=422, detail="Real binary acceptance is only available for native hooks")
    if integration.deployment_family not in {"browser", "endpoint"}:
        raise HTTPException(status_code=422, detail="Real binary acceptance requires a local endpoint deployment")
    if not provider_enforcement_enabled(settings, integration.provider):
        raise HTTPException(status_code=404, detail="Not found")

    profile = _rebind_current_integration_profile(db, integration, allow_admin_reratify=True)
    credential = _active_credential(db, ctx.tenant.id, integration.id)
    if credential is None:
        raise HTTPException(status_code=409, detail="active_workload_credential_required")
    endpoint_identity = db.scalar(
        select(EndpointDeviceIdentity).where(
            EndpointDeviceIdentity.tenant_id == ctx.tenant.id,
            EndpointDeviceIdentity.key_thumbprint == credential.key_thumbprint,
            EndpointDeviceIdentity.key_provider.in_(tuple(HARDWARE_KEY_PROVIDERS)),
            EndpointDeviceIdentity.status == "active",
            EndpointDeviceIdentity.revoked_at.is_(None),
            EndpointDeviceIdentity.assigned_user_id.is_not(None),
        )
    )

    current = _now()
    measured = health_snapshot(
        db,
        tenant_id=ctx.tenant.id,
        integration_id=integration.id,
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        now=current,
    )
    route_binding_valid = bool(
        current_route_surfaces_for_integration(
            settings,
            tenant_id=ctx.tenant.id,
            integration_id=integration.id,
            integration_method=integration.integration_method,
            provider=integration.provider,
            provider_version=integration.provider_version,
            adapter_version=integration.adapter_version,
            product=integration.product,
        )
    )
    policy_fresh_renewed = False
    if _aware(integration.policy_fresh_until) < current and str(
        integration.policy_version or ""
    ).strip():
        # This admin-only route is an explicit acceptance boundary.  A stale
        # policy snapshot must not silently enforce, but an administrator who
        # is accepting the observed real local binary may re-certify the
        # currently bound policy snapshot for the same short validation window
        # used by native-control health evidence.
        integration.policy_fresh_until = current + VALIDATION_TTL
        policy_fresh_renewed = True
    acceptance_evidence_checks, acceptance_evidence = _real_binary_acceptance_evidence(
        db,
        integration=integration,
        credential=credential,
        current=current,
    )
    checks = {
        "callback_authenticated": measured.callback_authenticated,
        "evidence_flowing": measured.evidence_flowing,
        "latency_measured": measured.observed_latency_ms is not None,
        "credential_active": True,
        "hardware_endpoint_identity_bound": endpoint_identity is not None,
        "profile_verified": bool(profile.active and profile.verification_status == VerificationStatus.VERIFIED.value),
        "provider_version": _version_supported(integration, profile),
        "adapter_version": integration.adapter_version == profile.adapter_version,
        "route_binding_current": route_binding_valid,
        "configuration_integrity": bool(
            integration.expected_configuration_fingerprint
            and integration_configuration_fingerprint(integration)
            == integration.expected_configuration_fingerprint
        ),
        "policy_fresh": _aware(integration.policy_fresh_until) >= current,
        "policy_fresh_renewed": policy_fresh_renewed,
        "model_scope_bound": bool(
            str(integration.model_provider or "").strip().lower() not in {"", "unknown"}
            and str(integration.model or "").strip().lower() not in {"", "unknown"}
        ),
        "adapter_enforcement_eligible": _adapter_enforcement_eligible(integration),
        **acceptance_evidence_checks,
        "accepted_configuration_fingerprint": integration_configuration_fingerprint(
            integration
        ),
        "accepted_policy_version": integration.policy_version,
        "accepted_contract_hash": integration.contract_hash,
        "accepted_route_identity": f"native-control:{integration.id}",
        "accepted_deployment_identity": f"integration:{integration.instance_key}",
    }
    allow_result = (
        "passed"
        if checks["signed_allow_receipt_observed"]
        and checks["allow_execution_receipt_observed"]
        and checks["attested_allow_target_effect_observed"]
        else "failed"
    )
    block_result = (
        "passed"
        if checks["signed_block_receipt_observed"]
        and checks["distinct_acceptance_challenges"]
        else "failed"
    )
    non_execution_result = (
        "passed"
        if checks["block_execution_absent"]
        and checks["attested_non_execution_observed"]
        else "failed"
    )
    reasons = [
        name
        for name, passed in checks.items()
        if not passed and name not in {"policy_fresh_renewed"}
    ]
    if reasons:
        raise HTTPException(status_code=409, detail={"code": "real_binary_acceptance_failed", "reasons": reasons})

    evidence = EvidenceNode(
        tenant_id=ctx.tenant.id,
        correlation_id=f"real-binary:{integration.id}"[:64],
        node_type="native_control_validation",
        signal_type="real_binary_acceptance",
        label=f"Real binary accepted: {integration.display_name}",
        payload={
            "integration_id": integration.id,
            "provider": integration.provider,
            "product": integration.product,
            "method": integration.integration_method,
            "credential_id": credential.credential_id,
            "credential_epoch": credential.credential_epoch,
            "endpoint_identity_id": endpoint_identity.id,
            "endpoint_key_provider": endpoint_identity.key_provider,
            "provider_version": integration.provider_version,
            "adapter_version": integration.adapter_version,
            "contract_hash": integration.contract_hash,
            "checks": checks,
            "source_health_evidence": list(measured.evidence_refs),
            "allow_evidence": f"evidence:{acceptance_evidence['allow'].id}",
            "allow_execution_evidence": (
                f"evidence:{acceptance_evidence['allow_execution'].id}"
            ),
            "allow_target_effect_evidence": (
                f"evidence:{acceptance_evidence['allow_target_effect'].id}"
            ),
            "block_evidence": f"evidence:{acceptance_evidence['block'].id}",
            "non_execution_evidence": (
                f"evidence:{acceptance_evidence['non_execution'].id}"
            ),
            "observed_latency_ms": measured.observed_latency_ms,
        },
    )
    db.add(evidence)
    db.flush()
    acceptance_run_id = (
        f"real-binary:{integration.id}:{credential.credential_id}:"
        f"{credential.credential_epoch}:{current.strftime('%Y%m%dT%H%M%S%fZ')}"
    )[:128]
    validation = NativeControlValidation(
        tenant_id=ctx.tenant.id,
        integration_instance_id=integration.id,
        validation_version=REAL_BINARY_ACCEPTANCE_VERSION,
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        safe_synthetic=False,
        acceptance_state="REAL_BINARY_ACCEPTED",
        deployment_environment=integration.environment,
        provider=integration.provider,
        product=integration.product,
        runtime=integration.runtime,
        model_provider=integration.model_provider,
        model=integration.model,
        route_identity=f"native-control:{integration.id}",
        deployment_identity=f"integration:{integration.instance_key}",
        execution_location=integration.execution_location,
        deployment_reference=integration.deployment_reference,
        action_classes=list(profile.supported_action_classes or []),
        control_methods=[integration.integration_method],
        lifecycle_events=list(credential.allowed_event_types or []),
        provider_version=integration.provider_version,
        adapter_version=integration.adapter_version,
        contract_hash=integration.contract_hash,
        acceptance_run_id=acceptance_run_id,
        allow_result=allow_result,
        block_result=block_result,
        non_execution_result=non_execution_result,
        checks=checks,
        result=NativeValidationResult.PASSED.value,
        reason_codes=[],
        evidence_refs=[
            *measured.evidence_refs,
            f"evidence:{acceptance_evidence['allow'].id}",
            f"evidence:{acceptance_evidence['allow_execution'].id}",
            f"evidence:{acceptance_evidence['allow_target_effect'].id}",
            f"evidence:{acceptance_evidence['block'].id}",
            f"evidence:{acceptance_evidence['non_execution'].id}",
            f"evidence:{evidence.id}",
        ],
        validated_at=current,
    )
    db.add(validation)
    integration.state = IntegrationState.MONITORING.value
    integration.mode = IntegrationMode.MONITOR.value
    integration.health_state = HealthState.HEALTHY.value
    integration.health_reasons = []
    integration.last_health_check_at = current
    integration.last_validated_at = current
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="real_binary_acceptance_already_recorded") from exc
    return {
        "integration_id": integration.id,
        "validation_id": validation.id,
        "validation_version": validation.validation_version,
        "acceptance_state": validation.acceptance_state,
        "safe_synthetic": validation.safe_synthetic,
        "checks": checks,
        "result": validation.result,
        "evidence_refs": validation.evidence_refs,
        "validated_at": validation.validated_at,
        "observed_latency_ms": measured.observed_latency_ms,
    }


def _transition(
    db: Session,
    integration: NativeControlIntegration,
    target: IntegrationState,
) -> dict[str, object]:
    previous_state = integration.state
    try:
        next_facts = transition_integration(_facts(db, integration), target, now=_now())
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    integration.state = next_facts.state.value
    integration.mode = next_facts.mode.value
    if target is IntegrationState.DISABLED:
        integration.disabled_at = _now()
    elif target is IntegrationState.CONFIGURING:
        integration.disabled_at = None
    if previous_state == IntegrationState.ENFORCING.value and target is not IntegrationState.ENFORCING:
        _record_control_point_downgrade(
            db,
            integration,
            previous_state=previous_state,
            reason_code=f"state_transition:{previous_state}:{target.value}",
        )
    db.commit()
    db.refresh(integration)
    return _integration_response(db, integration)


@router.post("/native-controls/integrations/{integration_id}/configure", dependencies=[FrameworkDependency])
def configure_integration(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    integration = _integration_or_404(db, ctx.tenant.id, integration_id)
    _rebind_current_integration_profile(db, integration)
    return _transition(
        db,
        integration,
        IntegrationState.CONFIGURING,
    )


@router.post("/native-controls/integrations/{integration_id}/monitor", dependencies=[FrameworkDependency])
def enable_monitor(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.operate")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if not settings.native_control_monitor:
        raise HTTPException(status_code=404, detail="Not found")
    return _transition(db, _integration_or_404(db, ctx.tenant.id, integration_id), IntegrationState.MONITORING)


@router.post("/native-controls/integrations/{integration_id}/enforce", dependencies=[FrameworkDependency])
def enable_enforce(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    if not settings.native_control_enforce:
        raise HTTPException(status_code=404, detail="Not found")
    integration = _integration_or_404(db, ctx.tenant.id, integration_id)
    if not provider_enforcement_enabled(settings, integration.provider):
        raise HTTPException(status_code=404, detail="Not found")
    return _transition(db, integration, IntegrationState.ENFORCING)


@router.post("/native-controls/integrations/{integration_id}/disable", dependencies=[FrameworkDependency])
def disable_integration(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return _transition(db, _integration_or_404(db, ctx.tenant.id, integration_id), IntegrationState.DISABLED)


@router.get("/control-points/{integration_id}/health", dependencies=[FrameworkDependency])
def get_control_point_health(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    row = _integration_or_404(db, ctx.tenant.id, integration_id)
    facts = _facts(db, row)
    profile = db.get(ControlCapabilityProfileRecord, row.capability_profile_id)
    latest_selection = db.scalar(
        select(NativeControlSelection)
        .where(
            NativeControlSelection.tenant_id == ctx.tenant.id,
            NativeControlSelection.primary_control_point_id == row.id,
        )
        .order_by(
            NativeControlSelection.selected_at.desc(),
            NativeControlSelection.selection_id.desc(),
        )
    )
    current = _now()
    validation_current = bool(
        facts.validation is NativeValidationResult.PASSED
        and _aware(facts.validation_valid_until) >= current
    )
    policy_fresh = _aware(row.policy_fresh_until) >= current
    active_for_enforcement = bool(
        row.state == IntegrationState.ENFORCING.value
        and row.mode == IntegrationMode.ENFORCE.value
        and facts.health is HealthState.HEALTHY
        and facts.profile_active
        and facts.profile_verification is VerificationStatus.VERIFIED
        and validation_current
        and policy_fresh
        and facts.configuration_integrity_valid
        and facts.provider_version_supported
        and facts.adapter_version_supported
        and facts.active_workload_identity
        and facts.callback_authenticated
        and facts.evidence_flowing
        and facts.measured_latency_ms is not None
        and facts.enforcement_feature_active
        and facts.route_binding_current
        and facts.real_acceptance_current
    )
    return {
        "integration_id": row.id,
        "health_state": row.health_state,
        "reason_codes": list(
            dict.fromkeys(
                [
                    *(row.health_reasons or []),
                    *([] if facts.callback_authenticated else ["callback_not_observed"]),
                    *([] if facts.evidence_flowing else ["evidence_not_flowing"]),
                    *([] if facts.measured_latency_ms is not None else ["latency_not_measured"]),
                ]
            )
        ),
        "callback_health": "authenticated_recently" if facts.callback_authenticated else "unverified",
        "evidence_flowing": facts.evidence_flowing,
        "policy_fresh": policy_fresh,
        "validation_current": validation_current,
        "real_acceptance_current": facts.real_acceptance_current,
        "configuration_integrity_valid": facts.configuration_integrity_valid,
        "provider_version_compatible": facts.provider_version_supported,
        "adapter_version_compatible": facts.adapter_version_supported,
        "active_for_enforcement": active_for_enforcement,
        "enforcement_feature_active": facts.enforcement_feature_active,
        "route_binding_current": facts.route_binding_current,
        "profile_active": facts.profile_active,
        "profile_verification": facts.profile_verification.value,
        "adapter_version": row.adapter_version,
        "last_health_check_at": row.last_health_check_at,
        "last_validated_at": row.last_validated_at,
        "last_action_id": latest_selection.action_id if latest_selection else None,
        "last_selection_reason": latest_selection.selection_reason if latest_selection else None,
        "current_assurance": int(latest_selection.assurance_level) if latest_selection else None,
        "expected_latency_ms": (
            int((profile.security_properties or {}).get("expected_latency_ms", 0))
            if profile
            else None
        ),
        "observed_latency_ms": facts.measured_latency_ms,
    }


@router.get("/native-controls/integrations/{integration_id}/coverage", dependencies=[FrameworkDependency])
def get_native_coverage(
    integration_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    row = _integration_or_404(db, ctx.tenant.id, integration_id)
    dimensions = derive_native_coverage(
        _facts(db, row),
        dict(row.capability_snapshot or {}),
        now=_now(),
    )
    return {
        "integration_id": row.id,
        "matrix_version": REGISTRY.matrix_version,
        "dimensions": dimensions,
        "known_blind_spots": list(row.known_blind_spots or []),
        "known_estate_limitation": (
            "Coverage describes this verified control point and observed paths only; unobserved estate is not in the denominator."
        ),
    }


@router.get("/control-selections/{action_id}", dependencies=[FrameworkDependency])
def get_control_selection(
    action_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    row = db.scalar(
        select(NativeControlSelection)
        .where(
            NativeControlSelection.tenant_id == ctx.tenant.id,
            NativeControlSelection.action_id == action_id,
        )
        .order_by(NativeControlSelection.selected_at.desc())
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Control selection not found")
    return {
        "selection_id": row.selection_id,
        "action_id": row.action_id,
        "primary_control_point": row.primary_control_point_id,
        "secondary_observation_points": row.secondary_observation_points,
        "containment_points": row.containment_points,
        "rejected_candidates": row.rejected_candidates,
        "selection_reason": row.selection_reason,
        "required_capabilities": row.required_capabilities,
        "satisfied_capabilities": row.satisfied_capabilities,
        "unsatisfied_capabilities": row.unsatisfied_capabilities,
        "assurance_level": row.assurance_level,
        "coverage_implications": row.coverage_implications,
        "known_blind_spots": row.known_blind_spots,
        "selector_version": row.selector_version,
        "matrix_version": row.matrix_version,
        "policy_version": row.policy_version,
        "control_profile_version": row.control_profile_version,
        "timestamp": row.selected_at,
    }
