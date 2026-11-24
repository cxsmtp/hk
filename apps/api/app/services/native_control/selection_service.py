from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.control_engine.authorization import (
    AuthorizationRequest,
    AuthorizationRolloutOutcome,
)
from app.db.models.evidence import EvidenceNode
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlIntegration,
    NativeControlSelection,
    NativeControlValidation,
    NativeWorkloadCredential,
    REAL_ACCEPTANCE_STATES,
)
from app.services.native_control.contracts import (
    ActionClass,
    CapabilityClaim,
    CapabilityDimension,
    CapabilityLevel,
    ControlCapabilityProfile,
    ControlMethod,
    ControlPointCandidate,
    ControlPointHealth,
    DegradationMode,
    HealthState,
    MandatoryEnforcementFloorRequirement,
    ProviderRuntimeContext,
    RejectedCandidate,
    RuntimeLocation,
    SecurityProperties,
    SelectionContext,
    VerificationStatus,
)
from app.services.native_control.requirements import derive_control_requirements
from app.services.native_control.findings import (
    phase4_finding_types_for_reason_codes,
    record_native_control_finding,
)
from app.services.native_control.metrics import native_control_metrics
from app.services.native_control.integrity import integration_configuration_fingerprint
from app.services.native_control.health import health_snapshot
from app.services.native_control.provider_flags import provider_enforcement_enabled
from app.services.native_control.providers import canonical_provider
from app.services.native_control.route_binding import (
    configured_route_binding,
    configured_route_bindings,
)
from app.services.native_control.selector import TrustedControlPointSelector
from app.services.native_control.openai_action_matrix import (
    OPENAI_ACTION_SCOPED_DIMENSIONS,
    OpenAIActionClass,
    build_openai_action_control_matrix,
)
from app.services.native_control.acceptance_versions import acceptance_version_is_current


VALIDATION_TTL = timedelta(minutes=15)
_TRUSTED_BINDING_SOURCES = {
    "authenticated_native_adapter",
    "hawk_gateway_route",
    "hawk_endpoint_route",
    "hawk_runtime_route",
}
_TRUSTED_CONTROL_METHODS = {item.value for item in ControlMethod}
_OPENAI_ACTION_MATRIX = build_openai_action_control_matrix()
_MAX_MANDATORY_FLOORS = 16
_MAX_PLAN_TEXT = 128
_CONTROL_PLAN_TTL = timedelta(minutes=5)


def verify_control_plan_material(
    material: object,
    *,
    expected_digest: str | None,
    expected_plan_id: str | None,
    expected_canonical_action_hash: str | None,
    now: datetime,
) -> dict[str, object]:
    if not isinstance(material, dict):
        raise ValueError("control plan material is invalid")
    try:
        bounded = json.loads(
            json.dumps(material, sort_keys=True, separators=(",", ":"))
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("control plan material is invalid") from exc
    digest = bounded.pop("plan_digest", None)
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("control plan digest is invalid")
    recomputed = hashlib.sha256(
        json.dumps(bounded, sort_keys=True, separators=(",", ":"), default=str).encode(
            "utf-8"
        )
    ).hexdigest()
    if digest != recomputed or digest != expected_digest:
        raise ValueError("control plan digest mismatch")
    if bounded.get("plan_id") != expected_plan_id:
        raise ValueError("control plan id mismatch")
    if bounded.get("canonical_action_hash") != expected_canonical_action_hash:
        raise ValueError("control plan canonical action mismatch")
    issued_at = _parse_plan_time(bounded.get("issued_at"), field="issued_at")
    expires_at = _parse_plan_time(bounded.get("expires_at"), field="expires_at")
    if expires_at <= issued_at or expires_at - issued_at > _CONTROL_PLAN_TTL:
        raise ValueError("control plan lifetime is invalid")
    if _utc(now) < issued_at - timedelta(seconds=1):
        raise ValueError("control plan is not yet valid")
    if _utc(now) >= expires_at:
        raise ValueError("control plan expired")
    return {**bounded, "plan_digest": digest}


def _stable_plan_authority_material(material: object) -> dict[str, object]:
    """Return plan authority without evaluation-clock-derived identifiers."""

    if not isinstance(material, dict):
        raise ValueError("control plan material is invalid")
    try:
        stable = json.loads(
            json.dumps(material, sort_keys=True, separators=(",", ":"))
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("control plan material is invalid") from exc
    for field in (
        "issued_at",
        "expires_at",
        "expiry",
        "selector_plan_id",
        "plan_digest",
    ):
        stable.pop(field, None)
    return stable


def _assert_existing_selection_authority(
    existing: NativeControlSelection,
    *,
    canonical_action_hash: str,
    provider_runtime_context: ProviderRuntimeContext,
    input_digest: str,
    contract_hashes: dict[str, str],
    control_plan_id: str,
    control_plan_material: dict[str, object],
) -> None:
    """Fail closed instead of silently reusing stale immutable authority."""

    try:
        verified_existing = verify_control_plan_material(
            existing.control_plan_material,
            expected_digest=existing.control_plan_digest,
            expected_plan_id=existing.control_plan_id,
            expected_canonical_action_hash=existing.canonical_action_hash,
            # Reuse comparison verifies immutable authority. Current validity
            # is evaluated separately by the rollout/receipt path so an
            # expired idempotency key becomes an explicit invalid plan rather
            # than an authority-mismatch exception.
            now=_utc(existing.plan_issued_at),
        )
        issued_at = _parse_plan_time(
            verified_existing.get("issued_at"), field="issued_at"
        )
        expires_at = _parse_plan_time(
            verified_existing.get("expires_at"), field="expires_at"
        )
        matches = (
            existing.control_plan_id == control_plan_id
            and existing.canonical_action_hash == canonical_action_hash
            and existing.provider_runtime_context
            == provider_runtime_context.canonical_material()
            and existing.provider_runtime_fingerprint
            == provider_runtime_context.fingerprint
            and existing.input_digest == input_digest
            and dict(existing.contract_hashes or {}) == contract_hashes
            and _utc(existing.plan_issued_at) == issued_at
            and _utc(existing.plan_expires_at) == expires_at
            and _stable_plan_authority_material(verified_existing)
            == _stable_plan_authority_material(control_plan_material)
        )
    except ValueError as exc:
        raise ValueError("native control selection authority mismatch") from exc
    if not matches:
        raise ValueError("native control selection authority mismatch")


def _parse_plan_time(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError(f"control plan {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"control plan {field} is invalid") from exc
    return _utc(parsed)


def _plan_text(value: object, *, default: str = "unknown") -> str:
    text = str(value or "").strip()
    if not text or len(text) > _MAX_PLAN_TEXT or any(char in text for char in "\r\n\x00"):
        return default
    return text


def _utc(value: datetime | None) -> datetime:
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _claim(payload: dict[str, object]) -> CapabilityClaim:
    try:
        level = CapabilityLevel(str(payload.get("level") or "unknown"))
    except ValueError:
        level = CapabilityLevel.UNKNOWN
    try:
        verification = VerificationStatus(str(payload.get("verification_status") or "unverified"))
    except ValueError:
        verification = VerificationStatus.UNVERIFIED
    # Phase 6 assurance is a conservative overlay on the existing capability
    # claim. A stale or unknown regression state cannot remain VERIFIED, and a
    # proven regression is BROKEN until targeted revalidation succeeds.
    assurance_state = str(payload.get("assurance_state") or "").strip().lower()
    if assurance_state == "regressed":
        verification = VerificationStatus.BROKEN
    elif assurance_state in {"stale", "unknown"} and verification is VerificationStatus.VERIFIED:
        verification = VerificationStatus.UNVERIFIED
    refs = tuple(str(value) for value in payload.get("evidence_refs") or [] if str(value))
    return CapabilityClaim(level=level, verification_status=verification, evidence_refs=refs)


def _security(payload: dict[str, object]) -> SecurityProperties:
    def score(name: str) -> int:
        try:
            return min(100, max(0, int(payload.get(name, 0))))
        except (TypeError, ValueError):
            return 0

    try:
        latency = max(0, int(payload.get("expected_latency_ms", 0)))
    except (TypeError, ValueError):
        latency = 0
    return SecurityProperties(
        pre_execution_capable=payload.get("pre_execution_capable") is True,
        post_execution_capable=payload.get("post_execution_capable") is True,
        blocking_strength=score("blocking_strength"),
        action_fidelity=score("action_fidelity"),
        identity_quality=score("identity_quality"),
        parameter_fidelity=score("parameter_fidelity"),
        target_fidelity=score("target_fidelity"),
        destination_fidelity=score("destination_fidelity"),
        result_fidelity=score("result_fidelity"),
        bypass_resistance=score("bypass_resistance"),
        tamper_resistance=score("tamper_resistance"),
        expected_latency_ms=latency,
        availability_profile=str(payload.get("availability_profile") or "unknown"),
        required_permissions=tuple(str(value) for value in payload.get("required_permissions") or []),
        privacy_impact=str(payload.get("privacy_impact") or "unknown"),
    )


def _latest_validation(db: Session, integration: NativeControlIntegration) -> NativeControlValidation | None:
    return db.scalar(
        select(NativeControlValidation)
        .where(
            NativeControlValidation.tenant_id == integration.tenant_id,
            NativeControlValidation.integration_instance_id == integration.id,
        )
        .order_by(NativeControlValidation.validated_at.desc(), NativeControlValidation.id.desc())
    )


def _credential(db: Session, integration: NativeControlIntegration, now: datetime) -> NativeWorkloadCredential | None:
    return db.scalar(
        select(NativeWorkloadCredential)
        .where(
            NativeWorkloadCredential.tenant_id == integration.tenant_id,
            NativeWorkloadCredential.integration_instance_id == integration.id,
            NativeWorkloadCredential.status == "active",
            NativeWorkloadCredential.expires_at > now,
        )
        .order_by(NativeWorkloadCredential.credential_epoch.desc())
    )


def _normalized_acceptance_scope(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {
        str(item).strip().lower()
        for item in value
        if isinstance(item, str)
        and str(item).strip()
        and str(item).strip().lower() != "unknown"
    }


def _real_acceptance_rejection_reasons(
    db: Session,
    *,
    integration: NativeControlIntegration,
    profile: ControlCapabilityProfileRecord,
    runtime_context: ProviderRuntimeContext,
    now: datetime,
) -> tuple[str, ...]:
    """Require the latest immutable real acceptance for this exact route.

    A passed synthetic validation proves only the fixture.  Eligibility binds
    the current credential, deployment, provider contract and exact action
    lifecycle before the candidate reaches the selector.
    """

    validation = _latest_validation(db, integration)
    credential = _credential(db, integration, now)
    if validation is None:
        return ("deployment_acceptance_not_current",)
    reasons: list[str] = []
    if validation.acceptance_state not in REAL_ACCEPTANCE_STATES:
        reasons.append("deployment_acceptance_not_current")
    if not acceptance_version_is_current(
        acceptance_state=validation.acceptance_state,
        validation_version=validation.validation_version,
    ):
        reasons.append("deployment_acceptance_version_obsolete")
    if validation.safe_synthetic is not False:
        reasons.append("deployment_acceptance_synthetic")
    expected_acceptance_state = {
        RuntimeLocation.LOCAL_ENDPOINT: "REAL_BINARY_ACCEPTED",
        RuntimeLocation.PROVIDER_HOSTED: "REAL_ENTERPRISE_TENANT_ACCEPTED",
        RuntimeLocation.REMOTE_AGENT: "REAL_ENTERPRISE_TENANT_ACCEPTED",
        RuntimeLocation.CUSTOMER_RUNTIME: "REAL_CLOUD_RUNTIME_ACCEPTED",
        RuntimeLocation.CUSTOMER_CLOUD: "REAL_CLOUD_RUNTIME_ACCEPTED",
        RuntimeLocation.MIXED: "REAL_CLOUD_RUNTIME_ACCEPTED",
    }.get(runtime_context.runtime_location)
    if expected_acceptance_state is None or validation.acceptance_state != expected_acceptance_state:
        reasons.append("deployment_acceptance_state_mismatch")
    if (
        validation.result != "passed"
        or validation.allow_result != "passed"
        or validation.block_result != "passed"
        or validation.non_execution_result != "passed"
    ):
        reasons.append("deployment_acceptance_outcomes_incomplete")
    if credential is None:
        reasons.append("deployment_acceptance_credential_inactive")
    elif (
        validation.credential_id != credential.credential_id
        or validation.credential_epoch != credential.credential_epoch
    ):
        reasons.append("deployment_acceptance_credential_mismatch")
    if (
        validation.tenant_id != integration.tenant_id
        or validation.integration_instance_id != integration.id
    ):
        reasons.append("deployment_acceptance_route_mismatch")
    if validation.deployment_environment != integration.environment:
        reasons.append("deployment_acceptance_environment_mismatch")
    if (
        validation.provider != integration.provider
        or integration.provider != profile.provider
        or validation.product != integration.product
        or integration.product != profile.product
    ):
        reasons.append("deployment_acceptance_provider_product_mismatch")
    if (
        validation.runtime != integration.runtime
        or integration.runtime != profile.runtime
        or validation.runtime != runtime_context.runtime
    ):
        reasons.append("deployment_acceptance_runtime_mismatch")
    if (
        validation.model_provider != integration.model_provider
        or validation.model_provider != runtime_context.model_provider
    ):
        reasons.append("deployment_acceptance_model_provider_mismatch")
    if validation.model != integration.model or validation.model != runtime_context.model:
        reasons.append("deployment_acceptance_model_mismatch")
    if validation.route_identity != runtime_context.route_identity:
        reasons.append("deployment_acceptance_route_identity_mismatch")
    if validation.deployment_identity != runtime_context.deployment_identity:
        reasons.append("deployment_acceptance_deployment_identity_mismatch")
    if (
        validation.execution_location != integration.execution_location
        or runtime_context.runtime_location
        != _runtime_location_from_integration(integration)
    ):
        reasons.append("deployment_acceptance_location_mismatch")
    if (
        validation.deployment_reference != integration.deployment_reference
        or validation.deployment_reference != runtime_context.deployment_reference
    ):
        reasons.append("deployment_acceptance_deployment_mismatch")
    if validation.provider_version != integration.provider_version:
        reasons.append("deployment_acceptance_provider_version_mismatch")
    if (
        validation.adapter_version != integration.adapter_version
        or integration.adapter_version != profile.adapter_version
        or validation.adapter_version != runtime_context.adapter_version
    ):
        reasons.append("deployment_acceptance_adapter_version_mismatch")
    expected_contract_hash = str(integration.contract_hash or "").strip()
    if (
        not re.fullmatch(r"[0-9a-f]{64}", expected_contract_hash)
        or validation.contract_hash != expected_contract_hash
        or profile.contract_hash != expected_contract_hash
    ):
        reasons.append("deployment_acceptance_contract_hash_mismatch")
    accepted_actions = _normalized_acceptance_scope(validation.action_classes)
    profile_actions = _normalized_acceptance_scope(profile.supported_action_classes)
    if (
        not profile_actions
        or accepted_actions != profile_actions
        or runtime_context.action_class.value not in accepted_actions
    ):
        reasons.append("deployment_acceptance_action_class_mismatch")
    accepted_methods = _normalized_acceptance_scope(validation.control_methods)
    profile_methods = _normalized_acceptance_scope(profile.supported_control_methods)
    expected_methods = {str(integration.integration_method or "").strip().lower()}
    if (
        accepted_methods != expected_methods
        or profile_methods != expected_methods
        or runtime_context.control_method.value not in accepted_methods
    ):
        reasons.append("deployment_acceptance_control_method_mismatch")
    accepted_lifecycle = _normalized_acceptance_scope(validation.lifecycle_events)
    credential_lifecycle = (
        _normalized_acceptance_scope(credential.allowed_event_types)
        if credential is not None
        else set()
    )
    if (
        not accepted_lifecycle
        or accepted_lifecycle != credential_lifecycle
        or runtime_context.lifecycle_stage.lower() not in accepted_lifecycle
    ):
        reasons.append("deployment_acceptance_lifecycle_mismatch")
    if not str(validation.acceptance_run_id or "").strip() or not validation.evidence_refs:
        reasons.append("deployment_acceptance_evidence_incomplete")
    return tuple(dict.fromkeys(reasons))


def _candidate(
    db: Session,
    integration: NativeControlIntegration,
    profile: ControlCapabilityProfileRecord,
    *,
    now: datetime,
    action_class: str | None = None,
) -> ControlPointCandidate:
    claims: dict[CapabilityDimension, CapabilityClaim] = {}
    for name, payload in dict(profile.capabilities or {}).items():
        try:
            dimension = CapabilityDimension(str(name))
        except ValueError:
            continue
        if isinstance(payload, dict):
            claims[dimension] = _claim(payload)
    response_coverage = "unknown"
    action_blind_spots: tuple[str, ...] = ()
    if profile.provider == "openai" and action_class:
        try:
            action_profile = _OPENAI_ACTION_MATRIX.resolve(
                profile.product,
                OpenAIActionClass(action_class),
                ControlMethod(profile.integration_method),
            )
        except (KeyError, ValueError):
            action_profile = None
        if action_profile is not None:
            unknown_claim = CapabilityClaim(
                level=CapabilityLevel.UNKNOWN,
                verification_status=VerificationStatus.UNVERIFIED,
            )
            for dimension in OPENAI_ACTION_SCOPED_DIMENSIONS:
                claims[dimension] = action_profile.capabilities.get(
                    dimension,
                    unknown_claim,
                )
            response_coverage = action_profile.response_coverage.value
            action_blind_spots = action_profile.blind_spots
    validation = _latest_validation(db, integration)
    credential = _credential(db, integration, now)
    measured_health = (
        health_snapshot(
            db,
            tenant_id=integration.tenant_id,
            integration_id=integration.id,
            credential_id=credential.credential_id,
            credential_epoch=credential.credential_epoch,
            now=now,
        )
        if credential
        else None
    )
    validation_current = bool(
        validation
        and validation.result == "passed"
        and credential
        and validation.credential_id == credential.credential_id
        and validation.credential_epoch == credential.credential_epoch
        and _utc(validation.validated_at) + VALIDATION_TTL >= _utc(now)
    )
    visible_fields: list[str] = []
    for dimension, field in (
        (CapabilityDimension.IDENTITY, "identity"),
        (CapabilityDimension.PARAMETER_BINDING, "parameters"),
        (CapabilityDimension.TARGET_BINDING, "target"),
        (CapabilityDimension.DESTINATION_BINDING, "destination"),
        (CapabilityDimension.POST_EXECUTION_VERIFICATION, "result"),
    ):
        claim = claims.get(dimension)
        if (
            claim is not None
            and claim.verification_status is VerificationStatus.VERIFIED
            and claim.level not in {CapabilityLevel.UNKNOWN, CapabilityLevel.UNAVAILABLE}
        ):
            visible_fields.append(field)
    blocking_dimensions = (
        CapabilityDimension.PROMPT_CONTROL,
        CapabilityDimension.TOOL_CONTROL,
        CapabilityDimension.MCP_CONTROL,
        CapabilityDimension.COMMAND_CONTROL,
    )
    blocking = integration.state == "enforcing" and integration.mode == "enforce" and any(
        (claim := claims.get(dimension)) is not None
        and claim.verification_status is VerificationStatus.VERIFIED
        and claim.level in {CapabilityLevel.INLINE, CapabilityLevel.INLINE_BOUND}
        for dimension in blocking_dimensions
    )
    try:
        degradation = DegradationMode(integration.degradation_mode)
    except ValueError:
        degradation = DegradationMode.FAIL_CLOSED
    profile_contract = ControlCapabilityProfile(
        profile_id=profile.id,
        profile_version=profile.manifest_version,
        provider=profile.provider,
        product=profile.product,
        integration_method=ControlMethod(profile.integration_method),
        adapter_version=profile.adapter_version,
        tested_min_version=profile.tested_min_version,
        tested_max_version=profile.tested_max_version,
        current_verified_version=profile.current_verified_version,
        verification_status=VerificationStatus(profile.verification_status),
        verification_source=profile.verification_source,
        capabilities=claims,
        security_properties=_security(dict(profile.security_properties or {})),
        health_requirements=tuple(str(value) for value in profile.health_requirements or []),
        degradation_modes=tuple(
            DegradationMode(value)
            for value in profile.degradation_modes or []
            if value in {item.value for item in DegradationMode}
        ),
        known_blind_spots=(
            *(str(value) for value in profile.known_blind_spots or []),
            *action_blind_spots,
        ),
        documentation_references=tuple(str(value) for value in profile.documentation_references or []),
    )
    return ControlPointCandidate(
        control_point_id=integration.id,
        integration_instance_id=integration.id,
        tenant_id=integration.tenant_id,
        profile=profile_contract,
        health=ControlPointHealth(
            state=HealthState(integration.health_state),
            callback_authenticated=bool(measured_health and measured_health.callback_authenticated),
            validation_current=validation_current,
            evidence_flowing=bool(measured_health and measured_health.evidence_flowing),
            configuration_integrity_valid=(
                bool(integration.expected_configuration_fingerprint)
                and integration_configuration_fingerprint(integration)
                == integration.expected_configuration_fingerprint
            ),
            policy_fresh=_utc(integration.policy_fresh_until) >= _utc(now),
            observed_latency_ms=(
                measured_health.observed_latency_ms
                if measured_health and measured_health.observed_latency_ms is not None
                else 300_001
            ),
            reason_codes=tuple(
                dict.fromkeys(
                    [
                        *(str(value) for value in integration.health_reasons or []),
                        *((measured_health.reason_codes if measured_health else ("callback_not_observed", "evidence_not_flowing", "latency_not_measured"))),
                    ]
                )
            ),
        ),
        provider_version=str(integration.provider_version or "unknown"),
        adapter_version=str(integration.adapter_version or "unknown"),
        policy_version=str(integration.policy_version or "unknown"),
        policy_binding_mode=(
            "authoritative_per_action"
            if integration.integration_method == ControlMethod.GATEWAY_INLINE.value
            else "pinned_snapshot"
        ),
        tenant_binding_valid=True,
        exposed_lifecycle_events=tuple(str(value) for value in (credential.allowed_event_types if credential else [])),
        visible_action_fields=tuple(visible_fields),
        blocking_semantics=blocking,
        current_degradation_mode=degradation,
        response_coverage=response_coverage,
    )


def _required_event(request: AuthorizationRequest) -> str:
    action_type = str(request.action.get("action_type") or "").strip().lower()
    return (
        "before_model"
        if action_type in {"prompt", "model_request", "chat_completion", "response", "model_response"}
        else "before_tool"
    )


def _bound_route(request: AuthorizationRequest) -> tuple[tuple[str, ...], str, tuple[str, ...]]:
    binding = request.path_evidence.get("native_control_route_binding")
    if not isinstance(binding, dict):
        return (), "unverified", ()
    if binding.get("verified") is not True:
        return (), "unverified", ()
    source = str(binding.get("source") or "")
    if source not in _TRUSTED_BINDING_SOURCES:
        return (), "unverified", ()
    raw_ids = binding.get("integration_instance_ids")
    if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > 8:
        return (), "unverified", ()
    raw_methods = binding.get("allowed_methods")
    if not isinstance(raw_methods, list) or not raw_methods or len(raw_methods) > 4:
        return (), "unverified", ()
    methods = tuple(dict.fromkeys(str(value or "").strip() for value in raw_methods))
    if not methods or any(value not in _TRUSTED_CONTROL_METHODS for value in methods):
        return (), "unverified", ()
    values: list[str] = []
    for value in raw_ids:
        token = str(value or "").strip()
        if not token or len(token) > 64:
            return (), "unverified", ()
        if token not in values:
            values.append(token)
    return tuple(values), source, methods


def _bound_control_point_ids(request: AuthorizationRequest) -> tuple[str, ...]:
    return _bound_route(request)[0]


def _trusted_route_enterprise_modes(
    request: AuthorizationRequest,
    *,
    bound_ids: tuple[str, ...],
    route_binding_source: str,
) -> tuple[str, str]:
    """Return account/tenant modes only from a verified enterprise route binding.

    Discovery, prompts and client-supplied runtime data may describe a provider
    account, but they cannot grant the enterprise route scope required by the
    Anthropic provider controls.  The control-plane route binding is the only
    source allowed to carry these mode assertions.
    """

    binding = request.path_evidence.get("native_control_route_binding")
    if (
        not bound_ids
        or route_binding_source not in _TRUSTED_BINDING_SOURCES
        or not isinstance(binding, dict)
        or binding.get("verified") is not True
        or binding.get("enterprise_identity_verified") is not True
    ):
        return "unknown", "unknown"
    return (
        _plan_text(binding.get("enterprise_account_mode")).lower(),
        _plan_text(binding.get("enterprise_tenant_mode")).lower(),
    )


def _canonical_provider_runtime_contract(
    *,
    provider: str,
    product: str,
    method: str,
) -> Any | None:
    """Return the reviewed provider contract matching an exact control method."""

    if provider != "anthropic":
        return None
    try:
        control_method = ControlMethod(method)
    except ValueError:
        return None
    from app.services.native_control.anthropic_enterprise import (
        anthropic_enterprise_control_profiles,
    )

    for enterprise_profile in anthropic_enterprise_control_profiles():
        contract = enterprise_profile.contract
        if (
            contract.provider == provider
            and contract.product == product
            and enterprise_profile.method is control_method
        ):
            return enterprise_profile
    return None


def _canonical_provider_runtime_requirements(
    *,
    provider: str,
    product: str,
    method: str,
) -> dict[str, list[str]]:
    """Project reviewed provider scope constraints without inventing new ones."""

    enterprise_profile = _canonical_provider_runtime_contract(
        provider=provider,
        product=product,
        method=method,
    )
    if enterprise_profile is None:
        return {}
    contract = enterprise_profile.contract
    return {
        "required_account_modes": list(contract.required_account_modes),
        "required_tenant_modes": list(contract.required_tenant_modes),
    }


def _canonical_provider_runtime_ineligibility_reasons(
    *,
    provider: str,
    product: str,
    method: str,
    runtime_context: ProviderRuntimeContext,
) -> tuple[str, ...]:
    """Preserve provider-contract truth after a route scope is authenticated."""

    enterprise_profile = _canonical_provider_runtime_contract(
        provider=provider,
        product=product,
        method=method,
    )
    if enterprise_profile is None:
        return ()
    return enterprise_profile.enforcement_ineligibility_reasons(runtime_context)


def _enterprise_scope_rejection_reasons(
    requirements: dict[str, list[str]],
    runtime_context: ProviderRuntimeContext,
) -> tuple[str, ...]:
    """Reject an enterprise control before it enters the trusted selector."""

    if not requirements:
        return ()
    reasons: list[str] = []
    account_modes = set(requirements.get("required_account_modes") or [])
    tenant_modes = set(requirements.get("required_tenant_modes") or [])
    if not account_modes or runtime_context.account_mode not in account_modes:
        reasons.append("enterprise_account_context_required")
    if not tenant_modes or runtime_context.tenant_mode not in tenant_modes:
        reasons.append("enterprise_tenant_context_required")
    return tuple(reasons)


def _action_class(request: AuthorizationRequest) -> ActionClass:
    raw = _plan_text(
        request.action.get("action_class") or request.action.get("action_type"),
        default="unknown_action",
    ).lower()
    aliases = {
        "tool_execution": ActionClass.FUNCTION_TOOL,
        "tool_call": ActionClass.FUNCTION_TOOL,
        "mcp_tool": ActionClass.MCP,
        "command_execution": ActionClass.COMMAND,
        "shell_command": ActionClass.COMMAND,
        "file_read": ActionClass.FILE_READ,
        "read_file": ActionClass.FILE_READ,
        "file_write": ActionClass.FILE_WRITE,
        "write_file": ActionClass.FILE_WRITE,
        "network_request": ActionClass.NETWORK_ACTION,
        "network_connection": ActionClass.NETWORK_ACTION,
        "http_request": ActionClass.NETWORK_ACTION,
        "api_call": ActionClass.API_ACTION,
        "agent_action": ActionClass.DELEGATION,
        "prompt": ActionClass.PROMPT,
        "model_request": ActionClass.MODEL_REQUEST,
        "model_response": ActionClass.MODEL_RESPONSE,
        "response": ActionClass.MODEL_RESPONSE,
        "persistent_side_effect": ActionClass.PERSISTENT_SIDE_EFFECT,
    }
    if raw in aliases:
        return aliases[raw]
    try:
        return ActionClass(raw)
    except ValueError:
        return ActionClass.UNKNOWN_ACTION


def _runtime_location_from_integration(
    integration: NativeControlIntegration | None,
) -> RuntimeLocation:
    """Resolve location only from the route-bound server integration."""

    if integration is None:
        return RuntimeLocation.UNKNOWN
    try:
        return RuntimeLocation(str(integration.execution_location).strip().lower())
    except ValueError:
        return RuntimeLocation.UNKNOWN


def _trusted_route_runtime_lifecycle(
    request: AuthorizationRequest,
    *,
    bound_ids: tuple[str, ...],
    route_binding_source: str,
) -> tuple[str, bool]:
    """Read lifecycle evidence only from a verified authenticated binding."""

    binding = request.path_evidence.get("native_control_route_binding")
    if (
        not bound_ids
        or route_binding_source not in _TRUSTED_BINDING_SOURCES
        or not isinstance(binding, dict)
        or binding.get("verified") is not True
        or binding.get("runtime_context_verified") is not True
    ):
        return "unknown", False
    lifecycle_stage = _plan_text(binding.get("lifecycle_stage"))
    return lifecycle_stage, lifecycle_stage != "unknown"


def _trusted_semantic_runtime_integration(
    integrations: list[NativeControlIntegration],
) -> NativeControlIntegration | None:
    """Return one exact semantic route, or no runtime fact when ambiguous.

    Endpoint floors intentionally coexist with a semantic control point.  They
    do not define a provider runtime contract.  Multiple semantic controls with
    different deployment facts are ambiguous and must not be collapsed into a
    synthetic provider context.
    """

    semantic = [
        integration
        for integration in integrations
        if integration.integration_method != ControlMethod.ENDPOINT_RUNTIME.value
    ]
    if not semantic:
        return None
    facts = {
        (
            canonical_provider(integration.provider),
            _plan_text(integration.product).lower(),
            _plan_text(integration.runtime),
            _plan_text(integration.model_provider),
            _plan_text(integration.model),
            str(integration.execution_location).strip().upper(),
            _plan_text(integration.deployment_reference),
            _plan_text(integration.provider_version),
            _plan_text(integration.adapter_version),
            _plan_text(integration.environment),
        )
        for integration in semantic
    }
    if len(facts) != 1:
        return None
    return semantic[0]


def _provider_runtime_context(
    request: AuthorizationRequest,
    *,
    integration: NativeControlIntegration | None,
    bound_ids: tuple[str, ...],
    route_binding_source: str,
) -> ProviderRuntimeContext:
    """Build a contract context from verified route and integration facts only.

    Discovery can enrich an AI Action, but it is not an authorization source.
    Consequently discovery/runtime request fields never populate this contract.
    A missing or ambiguous server integration stays explicitly unknown so the
    reviewed provider contract can reject it without inventing a route.
    """

    route_identity = (
        f"native-control:{integration.id}"
        if integration is not None
        else "unknown"
    )
    route_ref = (
        f"native_control_route_binding:{route_binding_source}"
        if bound_ids and route_binding_source in _TRUSTED_BINDING_SOURCES
        else "unknown"
    )
    account_mode, tenant_mode = _trusted_route_enterprise_modes(
        request,
        bound_ids=bound_ids,
        route_binding_source=route_binding_source,
    )
    lifecycle_stage, runtime_binding_verified = _trusted_route_runtime_lifecycle(
        request,
        bound_ids=bound_ids,
        route_binding_source=route_binding_source,
    )
    try:
        control_method = (
            ControlMethod(integration.integration_method)
            if integration is not None
            else ControlMethod.OBSERVE_ONLY
        )
    except ValueError:
        control_method = ControlMethod.OBSERVE_ONLY
    return ProviderRuntimeContext(
        provider=(
            canonical_provider(integration.provider)
            if integration is not None
            else "unknown"
        ),
        product=(
            _plan_text(integration.product).lower()
            if integration is not None
            else "unknown"
        ),
        runtime=(
            _plan_text(integration.runtime)
            if integration is not None
            else "unknown"
        ),
        action_class=_action_class(request),
        runtime_location=_runtime_location_from_integration(integration),
        provider_version=(
            _plan_text(integration.provider_version)
            if integration is not None
            else "unknown"
        ),
        adapter_version=(
            _plan_text(integration.adapter_version)
            if integration is not None
            else "unknown"
        ),
        control_method=control_method,
        environment=(
            _plan_text(integration.environment)
            if integration is not None
            else "unknown"
        ),
        application="unknown",
        application_version="unknown",
        runtime_version="unknown",
        model_provider=(
            _plan_text(integration.model_provider)
            if integration is not None
            else "unknown"
        ),
        model=(
            _plan_text(integration.model)
            if integration is not None
            else "unknown"
        ),
        route_identity=route_identity,
        deployment_identity=(
            f"integration:{integration.instance_key}"
            if integration is not None
            else "unknown"
        ),
        deployment_reference=(
            _plan_text(integration.deployment_reference)
            if integration is not None
            else "unknown"
        ),
        lifecycle_stage=lifecycle_stage,
        account_mode=account_mode,
        tenant_mode=tenant_mode,
        route_evidence_ref=route_ref,
        route_evidence_fresh=bool(integration is not None and runtime_binding_verified),
    )


def _canonical_action_hash(request: AuthorizationRequest) -> str:
    """Hash the normalized material selected before the policy response exists.

    This is intentionally distinct from the final decision-receipt action hash:
    the latter also binds Hawk's decision. Excluding prior plan bindings preserves
    idempotence when a retry carries already-bound path evidence.
    """

    ignored_path_keys = {
        "native_control_selection_id",
        "native_primary_control_point",
        "native_selector_version",
        "native_matrix_version",
        "native_control_profile_version",
        "native_control_assurance",
        "native_control_requirement_satisfied",
        "native_control_provider_enforce_enabled",
        "native_control_plan",
        "native_control_plan_id",
        "native_control_plan_digest",
        "native_control_plan_canonical_action_hash",
    }
    # Trace IDs correlate observations for one transport attempt. They are not
    # action authority and legitimately change when the same action ID is
    # retried. Session/runtime identity remains material.
    runtime_material = {
        key: value
        for key, value in dict(request.runtime or {}).items()
        if key != "trace_id"
    }
    material = {
        "tenant_id": request.tenant_id,
        "action_id": request.action_id,
        "chain_id": request.chain_id,
        "environment": request.environment,
        "surface": request.surface,
        "actor": dict(request.actor or {}),
        "authority": dict(request.authority or {}),
        "purpose": dict(request.purpose or {}),
        "action": dict(request.action or {}),
        "tool": dict(request.tool or {}),
        "parameters": dict(request.parameters or {}),
        "target": dict(request.target or {}),
        "side_effect_context": dict(request.side_effect_context or {}),
        "discovery_context": dict(request.discovery_context or {}),
        "runtime": runtime_material,
        "policy_snapshot_id": request.policy_snapshot_id,
        "policy_profile": dict(request.policy_profile or {}),
        "path_evidence": {
            key: value
            for key, value in dict(request.path_evidence or {}).items()
            if key not in ignored_path_keys
        },
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def canonical_native_control_action_hash(request: AuthorizationRequest) -> str:
    """Expose the persisted selection binding to receipt verification."""

    return _canonical_action_hash(request)


def _mandatory_floor_requirements(
    request: AuthorizationRequest,
) -> tuple[MandatoryEnforcementFloorRequirement, ...]:
    """Read only explicit existing-policy floor requirements.

    No client or discovery signal can silently manufacture a mandatory OS floor.
    Conversely, a malformed policy declaration produces an unsatisfiable floor so
    enforced rollouts fail closed rather than silently falling back to semantics.
    """

    raw = request.policy_profile.get("mandatory_enforcement_floors")
    if raw in (None, (), [], {}):
        return ()
    if not isinstance(raw, list) or not raw or len(raw) > _MAX_MANDATORY_FLOORS:
        return (
            MandatoryEnforcementFloorRequirement(
                floor_id="invalid_mandatory_floor_policy",
                capability=CapabilityDimension.NETWORK_CONTROL,
            ),
        )
    values: list[MandatoryEnforcementFloorRequirement] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            return (
                MandatoryEnforcementFloorRequirement(
                    floor_id=f"invalid_mandatory_floor_{index}",
                    capability=CapabilityDimension.NETWORK_CONTROL,
                ),
            )
        floor_id = _plan_text(item.get("floor_id"), default=f"invalid_mandatory_floor_{index}")
        try:
            capability = CapabilityDimension(_plan_text(item.get("capability"), default=""))
            minimum_level = CapabilityLevel(
                _plan_text(item.get("minimum_level"), default=CapabilityLevel.INLINE.value)
            )
            raw_methods = item.get("allowed_methods", [ControlMethod.ENDPOINT_RUNTIME.value])
            if not isinstance(raw_methods, list) or not raw_methods:
                raise ValueError("allowed_methods_invalid")
            methods = tuple(ControlMethod(_plan_text(value, default="")) for value in raw_methods)
            maximum_latency_ms = int(item.get("maximum_latency_ms", 25))
            if maximum_latency_ms < 1 or maximum_latency_ms > 5_000:
                raise ValueError("maximum_latency_invalid")
        except (TypeError, ValueError):
            return (
                MandatoryEnforcementFloorRequirement(
                    floor_id=f"invalid_mandatory_floor_{index}",
                    capability=CapabilityDimension.NETWORK_CONTROL,
                ),
            )
        if floor_id in seen_ids:
            return (
                MandatoryEnforcementFloorRequirement(
                    floor_id="duplicate_mandatory_floor_policy",
                    capability=CapabilityDimension.NETWORK_CONTROL,
                ),
            )
        seen_ids.add(floor_id)
        values.append(
            MandatoryEnforcementFloorRequirement(
                floor_id=floor_id,
                capability=capability,
                minimum_level=minimum_level,
                allowed_methods=methods,
                maximum_latency_ms=maximum_latency_ms,
            )
        )
    return tuple(sorted(values, key=lambda item: item.floor_id))


def _floor_requirements_material(
    floors: tuple[MandatoryEnforcementFloorRequirement, ...],
) -> list[dict[str, object]]:
    return [
        {
            "floor_id": item.floor_id,
            "capability": item.capability.value,
            "minimum_level": item.minimum_level.value,
            "allowed_methods": [method.value for method in item.allowed_methods],
            "maximum_latency_ms": item.maximum_latency_ms,
        }
        for item in floors
    ]


def _selector_input_digest(
    *,
    request: AuthorizationRequest,
    context: SelectionContext,
    requirement: object,
    candidates: list[ControlPointCandidate],
) -> str:
    context_material = asdict(context)
    # Evaluation time is plan validity metadata, not selector authority. An
    # idempotent retry must compare the same authoritative input even though
    # its wall clock advanced.
    context_material.pop("evaluated_at", None)
    context_material.pop("plan_expires_at", None)
    payload = {
        "request": {
            "tenant_id": request.tenant_id,
            "environment": request.environment,
            "action_id": request.action_id,
            "surface": request.surface,
            "action": dict(request.action or {}),
            "target": dict(request.target or {}),
            "discovery_context": dict(request.discovery_context or {}),
            "path_evidence": dict(request.path_evidence or {}),
            "policy_snapshot_id": request.policy_snapshot_id,
        },
        "context": context_material,
        "requirement": asdict(requirement),
        "candidates": [asdict(row) for row in candidates],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def select_and_persist_authorization(
    db: Session,
    *,
    request: AuthorizationRequest,
    now: datetime,
):
    bound_ids, route_binding_source, allowed_methods = _bound_route(request)
    canonical_action_hash = _canonical_action_hash(request)
    integrations = (
        db.scalars(
            select(NativeControlIntegration).where(
                NativeControlIntegration.tenant_id == request.tenant_id,
                NativeControlIntegration.id.in_(bound_ids),
                NativeControlIntegration.integration_method.in_(allowed_methods),
                NativeControlIntegration.environment == request.environment,
                NativeControlIntegration.state.in_(["monitoring", "enforcing"]),
            )
    ).all()
        if bound_ids
        else []
    )
    shared_runtime_integration = _trusted_semantic_runtime_integration(integrations)
    runtime_context = _provider_runtime_context(
        request,
        integration=shared_runtime_integration,
        bound_ids=bound_ids,
        route_binding_source=route_binding_source,
    )
    provider = runtime_context.provider
    product = runtime_context.product
    provider_version = runtime_context.provider_version
    adapter_version = runtime_context.adapter_version
    candidates: list[ControlPointCandidate] = []
    enterprise_rejections: list[RejectedCandidate] = []
    provider_runtime_requirements: dict[str, list[str]] = {}
    runtime_contexts_by_control_point: dict[str, ProviderRuntimeContext] = {}
    raw_action_class = str(
        request.action.get("action_class")
        or request.discovery_context.get("tool_class")
        or ""
    ).strip().lower()
    action_class = raw_action_class or None
    matrix_versions: set[str] = set()
    for integration in integrations:
        profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
        if profile is None or not profile.active:
            continue
        matrix_versions.add(profile.matrix_version)
        candidate_runtime_context = _provider_runtime_context(
            request,
            integration=integration,
            bound_ids=bound_ids,
            route_binding_source=route_binding_source,
        )
        runtime_contexts_by_control_point[integration.id] = candidate_runtime_context
        requirements_for_candidate = _canonical_provider_runtime_requirements(
            provider=profile.provider,
            product=profile.product,
            method=profile.integration_method,
        )
        if requirements_for_candidate:
            provider_runtime_requirements = requirements_for_candidate
        scope_reasons = _enterprise_scope_rejection_reasons(
            requirements_for_candidate,
            candidate_runtime_context,
        )
        if scope_reasons:
            enterprise_rejections.append(
                RejectedCandidate(
                    control_point_id=integration.id,
                    reason_codes=scope_reasons,
                )
            )
            continue
        acceptance_reasons = _real_acceptance_rejection_reasons(
            db,
            integration=integration,
            profile=profile,
            runtime_context=candidate_runtime_context,
            now=now,
        )
        if acceptance_reasons:
            enterprise_rejections.append(
                RejectedCandidate(
                    control_point_id=integration.id,
                    reason_codes=acceptance_reasons,
                )
            )
            continue
        contract_reasons = _canonical_provider_runtime_ineligibility_reasons(
            provider=profile.provider,
            product=profile.product,
            method=profile.integration_method,
            runtime_context=candidate_runtime_context,
        )
        if contract_reasons:
            enterprise_rejections.append(
                RejectedCandidate(
                    control_point_id=integration.id,
                    reason_codes=contract_reasons,
                )
            )
            continue
        candidates.append(
            _candidate(
                db,
                integration,
                profile,
                now=now,
                action_class=action_class,
            )
        )
    matrix_version = sorted(matrix_versions)[-1] if matrix_versions else "control-capability-matrix/unknown"
    plan_issued_at = _utc(now)
    plan_expires_at = plan_issued_at + _CONTROL_PLAN_TTL
    context = SelectionContext(
        tenant_id=request.tenant_id,
        action_id=request.action_id,
        policy_version=request.policy_snapshot_id,
        matrix_version=matrix_version,
        provider=provider,
        product=product,
        provider_version=provider_version,
        adapter_version=adapter_version,
        route_binding_source=route_binding_source,
        allowed_control_methods=allowed_methods,
        required_lifecycle_event=_required_event(request),
        current_bypass_state=str(request.path_evidence.get("bypass_state") or "unknown"),
        policy_fresh=True,
        evaluated_at=plan_issued_at.isoformat(),
        plan_expires_at=plan_expires_at.isoformat(),
    )
    requirement = derive_control_requirements(request)
    mandatory_floors = _mandatory_floor_requirements(request)
    selector = TrustedControlPointSelector()
    semantic_result = selector.select(context, requirement, candidates)
    plan = selector.resolve_control_plan(
        context,
        requirement,
        mandatory_floors,
        candidates,
    )
    # Selector plans identify an evaluated route/candidate set.  Bind that
    # plan to the full pre-decision canonical action so distinct target,
    # parameter, or authenticated-route material cannot reuse one selection.
    rejected_candidates = tuple(
        sorted(
            {
                (row.control_point_id, row.reason_codes): row
                for row in (*semantic_result.rejected_candidates, *enterprise_rejections)
            }.values(),
            key=lambda row: row.control_point_id,
        )
    )
    plan_reason_codes = tuple(
        dict.fromkeys(
            (
                *plan.reason_codes,
                *(
                    reason
                    for rejection in enterprise_rejections
                    for reason in rejection.reason_codes
                ),
            )
        )
    )
    # Action IDs are idempotency keys.  A retry of the same canonical action
    # must resolve the same immutable plan instead of minting a second plan
    # merely because the evaluation clock advanced.  A materially different
    # plan changes this binding; an expired plan requires a new AI Action ID.
    control_plan_binding = {
        "canonical_action_hash": canonical_action_hash,
        "semantic_primary_control": plan.semantic_primary_control,
        "mandatory_enforcement_floors": list(plan.mandatory_enforcement_floors),
        "secondary_context_points": list(plan.secondary_context_points),
        "verification_points": list(plan.verification_points),
        "containment_points": list(plan.containment_points),
        "unsatisfied_mandatory_floors": list(plan.unsatisfied_mandatory_floors),
        "rejected_candidates": [
            {
                "control_point_id": row.control_point_id,
                "reason_codes": list(row.reason_codes),
            }
            for row in rejected_candidates
        ],
        "reason_codes": list(plan_reason_codes),
        "selector_version": plan.selector_version,
        "matrix_version": plan.matrix_version,
        "policy_version": plan.policy_version,
    }
    control_plan_id = hashlib.sha256(
        json.dumps(
            control_plan_binding,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()[:36]
    # The selector's legacy result remains the return shape for existing callers,
    # while the composed plan is authoritative for selection persistence and
    # enforcement. A semantic primary cannot satisfy a missing mandatory floor.
    result = replace(
        semantic_result,
        selection_id=control_plan_id,
        primary_control_point=(
            None if plan.control_requirement_unsatisfied else plan.semantic_primary_control
        ),
        secondary_observation_points=plan.secondary_context_points,
        containment_points=plan.containment_points,
        selection_reason=(
            "CONTROL_REQUIREMENT_UNSATISFIED"
            if plan.control_requirement_unsatisfied
            else semantic_result.selection_reason
        ),
        required_capabilities=plan.required_capabilities,
        satisfied_capabilities=plan.satisfied_capabilities,
        unsatisfied_capabilities=plan.unsatisfied_capabilities,
        assurance_level=plan.minimum_assurance,
        coverage_implications=plan.coverage_implications,
        known_blind_spots=plan.blind_spots,
        selector_version=plan.selector_version,
        matrix_version=plan.matrix_version,
        policy_version=plan.policy_version,
        control_profile_version=semantic_result.control_profile_version,
        rejected_candidates=rejected_candidates,
    )
    persisted_runtime_context = runtime_contexts_by_control_point.get(
        plan.semantic_primary_control or result.primary_control_point,
        runtime_context,
    )
    # Profiles are projections, so their persisted contract hashes remain the
    # only contract source recorded here. The plan does not upgrade any profile.
    profile_contract_hashes: dict[str, str] = {}
    for integration in integrations:
        profile = db.get(ControlCapabilityProfileRecord, integration.capability_profile_id)
        profile_hash = getattr(profile, "contract_hash", None) if profile is not None else None
        if isinstance(profile_hash, str) and len(profile_hash) == 64:
            profile_contract_hashes[f"profile:{profile.id}"] = profile_hash
        contract_hash = getattr(integration, "contract_hash", None)
        if isinstance(contract_hash, str) and len(contract_hash) == 64:
            profile_contract_hashes[f"integration:{integration.id}"] = contract_hash
    plan_material = {
        "schema_version": "native-control-composed-plan/1.0",
        "plan_id": control_plan_id,
        "selector_plan_id": plan.plan_id,
        "canonical_action_hash": canonical_action_hash,
        "provider_runtime_context": persisted_runtime_context.canonical_material(),
        "provider_runtime_fingerprint": persisted_runtime_context.fingerprint,
        "provider_runtime_requirements": provider_runtime_requirements,
        "issued_at": plan_issued_at.isoformat(),
        "expires_at": plan_expires_at.isoformat(),
        "mandatory_enforcement_floor_requirements": _floor_requirements_material(
            mandatory_floors
        ),
        "mandatory_enforcement_floors": [
            {"floor_id": floor_id, "control_point_id": control_point_id}
            for floor_id, control_point_id in plan.mandatory_enforcement_floors
        ],
        "semantic_primary_control_point_id": plan.semantic_primary_control,
        "secondary_context_points": list(plan.secondary_context_points),
        "verification_points": list(plan.verification_points),
        "containment_points": list(plan.containment_points),
        "unsatisfied_mandatory_floors": list(plan.unsatisfied_mandatory_floors),
        "rejected_mandatory_floor_candidates": {
            floor_id: [
                {
                    "control_point_id": rejected.control_point_id,
                    "reason_codes": list(rejected.reason_codes),
                }
                for rejected in rows
            ]
            for floor_id, rows in plan.rejected_mandatory_floor_candidates.items()
        },
        "control_requirement_unsatisfied": plan.control_requirement_unsatisfied,
        "reason_codes": list(plan_reason_codes),
        "selection_reason": result.selection_reason,
        "rejected_candidates": [
            {
                "control_point_id": row.control_point_id,
                "reason_codes": list(row.reason_codes),
            }
            for row in result.rejected_candidates
        ],
        "required_capabilities": [item.value for item in plan.required_capabilities],
        "satisfied_capabilities": [item.value for item in plan.satisfied_capabilities],
        "unsatisfied_capabilities": [item.value for item in plan.unsatisfied_capabilities],
        "minimum_assurance": int(plan.minimum_assurance),
        "degradation_policy": dict(plan.degradation_policy),
        "failure_behavior": requirement.acceptable_degradation_modes[0].value,
        "expiry": plan.expiry,
        "blind_spots": list(plan.blind_spots),
        "selector_version": plan.selector_version,
        "matrix_version": plan.matrix_version,
        "policy_version": plan.policy_version,
        "semantic_control_profile_version": semantic_result.control_profile_version,
        "contract_hashes": dict(sorted(profile_contract_hashes.items())),
    }
    policy_epoch = request.policy_profile.get("policy_epoch")
    if type(policy_epoch) is int and policy_epoch > 0:
        # Endpoint permits require a numeric policy epoch that is carried in
        # both the digest-verified persisted plan and the signed receipt plan.
        # Absence keeps that proof path unavailable; caller values are never
        # substituted later by the endpoint-authority resolver.
        plan_material["policy_epoch"] = policy_epoch
    plan_digest = hashlib.sha256(
        json.dumps(plan_material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
    plan_material["plan_digest"] = plan_digest
    selected_candidate = next(
        (row for row in candidates if row.control_point_id == result.primary_control_point),
        None,
    )
    native_control_metrics.increment(
        "control_plan_resolution_total",
        provider=provider,
        method=(selected_candidate.profile.integration_method.value if selected_candidate else "unknown"),
        outcome="selected" if result.primary_control_point else "rejected",
    )
    if result.primary_control_point is None:
        native_control_metrics.increment(
            "control_plan_unsatisfied_total",
            provider=provider,
            method="unknown",
            outcome="rejected",
        )
    previous = (
        db.scalar(
            select(NativeControlSelection)
            .where(
                NativeControlSelection.tenant_id == request.tenant_id,
                NativeControlSelection.primary_control_point_id.in_(bound_ids),
            )
            .order_by(
                NativeControlSelection.selected_at.desc(),
                NativeControlSelection.selection_id.desc(),
            )
        )
        if bound_ids
        else None
    )
    input_digest = _selector_input_digest(
        request=request,
        context=context,
        requirement=requirement,
        candidates=candidates,
    )
    authoritative_contract_hashes = dict(sorted(profile_contract_hashes.items()))
    existing = db.scalar(
        select(NativeControlSelection).where(
            NativeControlSelection.tenant_id == request.tenant_id,
            NativeControlSelection.selection_id == result.selection_id,
        )
    )
    if existing is not None:
        _assert_existing_selection_authority(
            existing,
            canonical_action_hash=canonical_action_hash,
            provider_runtime_context=persisted_runtime_context,
            input_digest=input_digest,
            contract_hashes=authoritative_contract_hashes,
            control_plan_id=control_plan_id,
            control_plan_material=plan_material,
        )
    inserted = False
    if existing is None:
        try:
            with db.begin_nested():
                selection_values: dict[str, object] = {
                    "selection_id": result.selection_id,
                    "tenant_id": request.tenant_id,
                    "action_id": request.action_id,
                    "primary_control_point_id": result.primary_control_point,
                    "secondary_observation_points": list(result.secondary_observation_points),
                    "containment_points": list(result.containment_points),
                    "rejected_candidates": [
                        {
                            "control_point_id": row.control_point_id,
                            "reason_codes": list(row.reason_codes),
                        }
                        for row in result.rejected_candidates
                    ],
                    "selection_reason": result.selection_reason,
                    "required_capabilities": [
                        value.value for value in result.required_capabilities
                    ],
                    "satisfied_capabilities": [
                        value.value for value in result.satisfied_capabilities
                    ],
                    "unsatisfied_capabilities": [
                        value.value for value in result.unsatisfied_capabilities
                    ],
                    "assurance_level": int(result.assurance_level),
                    "coverage_implications": dict(result.coverage_implications),
                    "known_blind_spots": list(result.known_blind_spots),
                    "selector_version": result.selector_version,
                    "matrix_version": result.matrix_version,
                    "policy_version": result.policy_version,
                    "control_profile_version": result.control_profile_version,
                    "input_digest": input_digest,
                    "selected_at": now,
                }
                selection_values.update(
                    {
                        "canonical_action_hash": canonical_action_hash,
                        "provider_runtime_context": persisted_runtime_context.canonical_material(),
                        "provider_runtime_fingerprint": persisted_runtime_context.fingerprint,
                        "control_plan_id": control_plan_id,
                        "control_plan_digest": plan_digest,
                        "control_plan_material": plan_material,
                        "mandatory_enforcement_floor_requirements": plan_material[
                            "mandatory_enforcement_floor_requirements"
                        ],
                        "selected_mandatory_floors": plan_material[
                            "mandatory_enforcement_floors"
                        ],
                        "semantic_primary_control_point_id": plan.semantic_primary_control,
                        "secondary_context_points": list(plan.secondary_context_points),
                        "verification_points": list(plan.verification_points),
                        "unsatisfied_mandatory_floors": list(plan.unsatisfied_mandatory_floors),
                        "rejected_mandatory_floor_candidates": plan_material[
                            "rejected_mandatory_floor_candidates"
                        ],
                        "control_requirement_unsatisfied": plan.control_requirement_unsatisfied,
                        "control_plan_reason_codes": list(plan_reason_codes),
                        "degradation_policy": dict(plan.degradation_policy),
                        "failure_behavior": requirement.acceptable_degradation_modes[0].value,
                        "plan_issued_at": plan_issued_at,
                        "plan_expires_at": plan_expires_at,
                        "contract_hashes": authoritative_contract_hashes,
                    }
                )
                db.add(NativeControlSelection(**selection_values))
                db.flush()
            inserted = True
        except IntegrityError:
            inserted = False
            existing = db.scalar(
                select(NativeControlSelection).where(
                    NativeControlSelection.tenant_id == request.tenant_id,
                    NativeControlSelection.selection_id == result.selection_id,
                )
            )
            if existing is None:
                raise ValueError("native control selection authority mismatch")
            _assert_existing_selection_authority(
                existing,
                canonical_action_hash=canonical_action_hash,
                provider_runtime_context=persisted_runtime_context,
                input_digest=input_digest,
                contract_hashes=authoritative_contract_hashes,
                control_plan_id=control_plan_id,
                control_plan_material=plan_material,
            )
    if inserted:
        selection_evidence = EvidenceNode(
                tenant_id=request.tenant_id,
                correlation_id=result.selection_id[:64],
                node_type="control_point_selection",
                signal_type="trusted_control_point_selected" if result.primary_control_point else "control_requirement_unsatisfied",
                label=(
                    f"Trusted control point selected for {request.action_id}"
                    if result.primary_control_point
                    else f"Control requirement unsatisfied for {request.action_id}"
                ),
                payload={
                    "action_id": request.action_id,
                    "selection_id": result.selection_id,
                    "control_plan_id": control_plan_id,
                    "control_plan_digest": plan_digest,
                    "canonical_action_hash": canonical_action_hash,
                    "primary_control_point": result.primary_control_point,
                    "semantic_primary_control_point": plan.semantic_primary_control,
                    "mandatory_enforcement_floors": plan_material[
                        "mandatory_enforcement_floors"
                    ],
                    "unsatisfied_mandatory_floors": list(
                        plan.unsatisfied_mandatory_floors
                    ),
                    "control_requirement_unsatisfied": plan.control_requirement_unsatisfied,
                    "rejected_candidates": [
                        {"control_point_id": row.control_point_id, "reason_codes": list(row.reason_codes)}
                        for row in result.rejected_candidates
                    ],
                    "selector_version": result.selector_version,
                    "matrix_version": result.matrix_version,
                    "policy_version": result.policy_version,
                    "assurance_level": int(result.assurance_level),
                },
            )
        db.add(selection_evidence)
        db.flush()
        if result.primary_control_point is None:
            finding_reason_codes = list(plan_reason_codes) or [
                value.value for value in result.unsatisfied_capabilities
            ]
            record_native_control_finding(
                db,
                tenant_id=request.tenant_id,
                finding_type="CONTROL_REQUIREMENT_UNSATISFIED",
                integration_id=None,
                action_id=request.action_id,
                provider=provider,
                policy_version=request.policy_snapshot_id,
                evidence_node_ids=[selection_evidence.id],
                reason_codes=finding_reason_codes,
            )
            for finding_type in phase4_finding_types_for_reason_codes(
                finding_reason_codes
            ):
                record_native_control_finding(
                    db,
                    tenant_id=request.tenant_id,
                    finding_type=finding_type,
                    integration_id=None,
                    action_id=request.action_id,
                    provider=provider,
                    policy_version=request.policy_snapshot_id,
                    evidence_node_ids=[selection_evidence.id],
                    reason_codes=finding_reason_codes,
                )
                if finding_type == "PROVIDER_CONTRACT_CHANGED":
                    native_control_metrics.increment(
                        "provider_contract_drift_total",
                        provider=provider,
                        method="unknown",
                        outcome="failed",
                    )
                elif finding_type == "DIRECT_PROVIDER_BYPASS":
                    native_control_metrics.increment(
                        "provider_bypass_total",
                        provider=provider,
                        method="unknown",
                        outcome="failed",
                    )
        if (
            previous is not None
            and previous.primary_control_point_id
            and previous.primary_control_point_id != result.primary_control_point
            and (
                result.primary_control_point is None
                or int(result.assurance_level) < int(previous.assurance_level)
            )
        ):
            downgrade_evidence = EvidenceNode(
                    tenant_id=request.tenant_id,
                    correlation_id=result.selection_id[:64],
                    node_type="control_point_downgrade",
                    signal_type="control_point_downgraded",
                    label=f"Trusted control point downgraded for {request.action_id}",
                    payload={
                        "action_id": request.action_id,
                        "selection_id": result.selection_id,
                        "previous_control_point": previous.primary_control_point_id,
                        "selected_control_point": result.primary_control_point,
                        "previous_assurance_level": int(previous.assurance_level),
                        "selected_assurance_level": int(result.assurance_level),
                        "unsatisfied_capabilities": [
                            value.value for value in result.unsatisfied_capabilities
                        ],
                        "selector_version": result.selector_version,
                        "matrix_version": result.matrix_version,
                        "policy_version": result.policy_version,
                    },
                )
            db.add(downgrade_evidence)
            db.flush()
            record_native_control_finding(
                db,
                tenant_id=request.tenant_id,
                finding_type="CONTROL_POINT_DOWNGRADED",
                integration_id=previous.primary_control_point_id,
                action_id=request.action_id,
                provider=provider,
                policy_version=request.policy_snapshot_id,
                evidence_node_ids=[downgrade_evidence.id],
                reason_codes=list(plan_reason_codes)
                or [value.value for value in result.unsatisfied_capabilities],
            )
            native_control_metrics.increment(
                "control_plan_downgrade_total",
                provider=provider,
                method="unknown",
                outcome="downgraded",
            )
        db.flush()
    return result


def apply_native_selection_to_rollout(
    db: Session,
    *,
    rollout: AuthorizationRolloutOutcome,
    settings_obj: object,
    now: datetime | None = None,
    trusted_provider: str | None = None,
) -> AuthorizationRolloutOutcome:
    """Bind a trusted control-point selection into the existing authorization result.

    This wrapper never evaluates a second policy system. It replays Hawk's existing
    deterministic authorization kernel only to bind the selection into path evidence.
    When the default-off native enforce flag is active, an unsatisfied control
    requirement is added as a fail-closed base decision before the receipt is issued.
    """

    if (
        not bool(getattr(settings_obj, "native_control_framework", False))
        or not bool(getattr(settings_obj, "trusted_control_selector", False))
        or rollout.request is None
        or rollout.v2_response is None
    ):
        return rollout
    evaluated_at = now or datetime.now(timezone.utc)
    request_for_selection = rollout.request
    configured_bindings = configured_route_bindings(
        settings_obj,
        rollout.request.surface,
        tenant_id=rollout.request.tenant_id,
    )
    configured_binding = configured_route_binding(
        settings_obj,
        rollout.request.surface,
        tenant_id=rollout.request.tenant_id,
        provider=trusted_provider,
    )
    route_integrations: list[NativeControlIntegration] = []
    if configured_binding is not None:
        route_integrations = list(
            db.scalars(
                select(NativeControlIntegration).where(
                    NativeControlIntegration.tenant_id == rollout.request.tenant_id,
                    NativeControlIntegration.id.in_(configured_binding.integration_instance_ids),
                    NativeControlIntegration.integration_method.in_(
                        configured_binding.allowed_methods
                    ),
                )
            ).all()
        )
    route_providers = {binding.provider for binding in configured_bindings}
    trusted_route_provider = configured_binding.provider if configured_binding else "unknown"
    if (
        configured_binding is not None
        and not _bound_control_point_ids(rollout.request)
    ):
        action_type = str(
            request_for_selection.action.get("action_type") or ""
        ).strip().lower()
        lifecycle_stage = (
            "before_model_request"
            if action_type in {"prompt", "model_request", "chat_completion"}
            else "before_tool"
        )
        request_for_selection = rollout.request.model_copy(
            deep=True,
            update={
                "path_evidence": {
                    **dict(rollout.request.path_evidence or {}),
                    "native_control_route_binding": {
                        "verified": True,
                        "source": configured_binding.source,
                        "integration_instance_ids": list(
                            configured_binding.integration_instance_ids
                        ),
                        "allowed_methods": list(configured_binding.allowed_methods),
                        # These originate from the configured server route,
                        # not caller discovery.  They satisfy the same
                        # trusted runtime contract as an authenticated native
                        # adapter binding.
                        "runtime_context_verified": True,
                        "lifecycle_stage": lifecycle_stage,
                    },
                },
                "discovery_context": {
                    **dict(rollout.request.discovery_context or {}),
                    "provider": trusted_route_provider,
                    "provider_version": configured_binding.provider_version,
                    "adapter_version": configured_binding.adapter_version,
                    "product": configured_binding.product,
                },
            },
        )
    selection = select_and_persist_authorization(db, request=request_for_selection, now=evaluated_at)
    selection_payload = selection.as_dict()
    selection_record = db.get(NativeControlSelection, selection.selection_id)
    plan_material = (
        dict(selection_record.control_plan_material or {})
        if selection_record is not None
        else {}
    )
    plan_current = False
    plan_failure_reason: str | None = None
    if selection_record is None:
        plan_failure_reason = "NATIVE_CONTROL_PLAN_INVALID"
    else:
        try:
            verified_plan = verify_control_plan_material(
                plan_material,
                expected_digest=selection_record.control_plan_digest,
                expected_plan_id=selection_record.control_plan_id,
                expected_canonical_action_hash=selection_record.canonical_action_hash,
                now=evaluated_at,
            )
            material_issued_at = _parse_plan_time(
                verified_plan.get("issued_at"), field="issued_at"
            )
            material_expires_at = _parse_plan_time(
                verified_plan.get("expires_at"), field="expires_at"
            )
            if (
                _utc(selection_record.plan_issued_at) != material_issued_at
                or _utc(selection_record.plan_expires_at) != material_expires_at
            ):
                raise ValueError("control plan timestamp binding mismatch")
            plan_current = True
        except ValueError:
            plan_failure_reason = "NATIVE_CONTROL_PLAN_INVALID"
    selection_payload.update(
        {
            "plan_current": plan_current,
            "plan_failure_reason": plan_failure_reason,
        }
    )
    provider = canonical_provider(str(request_for_selection.discovery_context.get("provider") or "unknown"))
    enforce_enabled = bool(getattr(settings_obj, "native_control_enforce", False))
    provider_enabled = (
        any(provider_enforcement_enabled(settings_obj, item) for item in route_providers)
        if configured_bindings
        else provider_enforcement_enabled(settings_obj, provider)
    )
    requirement_satisfied = bool(
        selection_record is not None
        and plan_current
        and selection_record.control_requirement_unsatisfied is False
        and selection.primary_control_point is not None
    )
    path_evidence = {
        **dict(request_for_selection.path_evidence or {}),
        "native_control_selection_id": selection.selection_id,
        "native_primary_control_point": selection.primary_control_point,
        "native_selector_version": selection.selector_version,
        "native_matrix_version": selection.matrix_version,
        "native_control_profile_version": selection.control_profile_version,
        "native_control_assurance": int(selection.assurance_level),
        "native_control_requirement_satisfied": requirement_satisfied,
        "native_control_provider_enforce_enabled": provider_enabled,
        "native_control_plan_id": (
            selection_record.control_plan_id
            if selection_record is not None
            else selection.selection_id
        ),
        "native_control_plan_digest": (
            selection_record.control_plan_digest
            if selection_record is not None
            else None
        ),
        "native_control_plan_canonical_action_hash": (
            selection_record.canonical_action_hash
            if selection_record is not None
            else None
        ),
        "native_control_plan": plan_material,
    }
    bound_request = request_for_selection.model_copy(
        deep=True,
        update={"path_evidence": path_evidence},
    )
    bound_response = rollout.v2_response
    failure_rule: str | None = None
    if enforce_enabled and provider_enabled:
        if plan_failure_reason is not None:
            failure_rule = plan_failure_reason
        elif not requirement_satisfied:
            failure_rule = "CONTROL_REQUIREMENT_UNSATISFIED"
    if failure_rule is not None:
        response_payload = bound_response.model_dump(exclude={"response_hash"})
        response_payload.update(
            {
                "decision": "block",
                "control_mode": "inline_prevented",
                "reason": failure_rule.lower(),
                "matched_rules": tuple(sorted({*bound_response.matched_rules, failure_rule})),
                "evidence_required": tuple(
                    sorted({*bound_response.evidence_required, "native_control_selection"})
                ),
                "cache_ttl": 0,
            }
        )
        response_hash = hashlib.sha256(
            json.dumps(
                response_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                default=str,
            ).encode("utf-8")
        ).hexdigest()
        bound_response = bound_response.__class__(**response_payload, response_hash=response_hash)
    return AuthorizationRolloutOutcome(
        authoritative_decision=bound_response.decision,
        metadata={**dict(rollout.metadata or {}), "native_control_selection": selection_payload},
        v2_response=bound_response,
        enforced=rollout.enforced,
        request=bound_request,
    )
