"""Enterprise Developer AI Control package.

This module builds the customer-facing repository-boundary package as a
derived, tenant-scoped view over existing Hawk primitives.  It intentionally
does not claim live provider enforcement where no source-backed control exists.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction, AISession, DeploymentEndpoint, UserRegistry
from app.db.models.account_boundary import AccountAccessReceipt
from app.db.models.evidence import EvidenceNode
from app.db.models.monitoring import Connector, MonitoringSignal
from app.db.models.github_repository_access import (
    GitHubRepository,
    GitHubRepositoryAIConnection,
    GitHubRepositoryAccess,
    GitHubSourceOrganization,
)
from app.db.models.native_control import (
    ControlCapabilityProfileRecord,
    NativeControlHealthObservation,
    NativeControlIntegration,
    NativeControlValidation,
)
from app.services.native_control.manifests import build_default_registry
from app.services.native_control.acceptance_versions import acceptance_version_is_current


APPROVED_DEVELOPER_AI_REQUIREMENTS = (
    "DEV-01",
    "GIT-01",
    "GIT-02",
    "GIT-03",
    "GIT-04",
    "GIT-05",
    "GIT-06",
    "GIT-07",
    "GIT-08",
    "GIT-09",
    "GIT-10",
    "DEVICE-01",
    "DEVICE-02",
    "DEVICE-03",
    "SURFACE-01",
    "VIS-01",
    "VIS-02",
    "PROMPT-01",
    "COST-01",
    "INJECT-01",
    "DATA-01",
    "DATA-02",
    "DATA-03",
    "POLICY-01",
    "POLICY-02",
    "POLICY-03",
    "POLICY-04",
    "MEETING-01",
    "ACCOUNT-01",
    "ACCOUNT-02",
    "UPLOAD-01",
    "DOWNLOAD-01",
    "EVIDENCE-01",
    "COVERAGE-01",
    "RETENTION-01",
)

REPOSITORY_OPERATIONS = (
    "REPOSITORY_CONNECT",
    "REPOSITORY_DISCOVER",
    "REPOSITORY_CLONE",
    "REPOSITORY_FETCH",
    "REPOSITORY_PULL",
    "REPOSITORY_READ",
    "REPOSITORY_ARCHIVE_DOWNLOAD",
    "REPOSITORY_BRANCH_CREATE",
    "REPOSITORY_REMOTE_ADD",
    "REPOSITORY_REMOTE_CHANGE",
    "REPOSITORY_PUSH",
    "REPOSITORY_FORCE_PUSH",
    "REPOSITORY_TAG_CREATE",
    "REPOSITORY_PULL_REQUEST_CREATE",
    "REPOSITORY_PULL_REQUEST_UPDATE",
    "REPOSITORY_PULL_REQUEST_COMMENT",
    "REPOSITORY_PULL_REQUEST_APPROVE",
    "REPOSITORY_PULL_REQUEST_MERGE",
    "REPOSITORY_FORK",
    "REPOSITORY_RELEASE_CREATE",
    "REPOSITORY_WORKFLOW_CHANGE",
    "REPOSITORY_SECRET_CHANGE",
    "REPOSITORY_DELETE",
    "REPOSITORY_TRANSFER",
    "REPOSITORY_VISIBILITY_CHANGE",
)

DEFAULT_ALLOWED_OPERATIONS = (
    "REPOSITORY_CLONE",
    "REPOSITORY_FETCH",
    "REPOSITORY_PULL",
    "REPOSITORY_READ",
    "REPOSITORY_BRANCH_CREATE",
    "REPOSITORY_PUSH",
    "REPOSITORY_PULL_REQUEST_CREATE",
    "REPOSITORY_PULL_REQUEST_UPDATE",
    "REPOSITORY_PULL_REQUEST_COMMENT",
)

PROVIDER_ROWS = (
    ("ChatGPT", "PARTIAL", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "PARTIAL", "PARTIAL", "PARTIAL"),
    ("Codex cloud", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "PARTIAL", "UNVERIFIED"),
    ("Codex desktop", "UNVERIFIED", "PARTIAL", "UNVERIFIED", "UNVERIFIED", "PARTIAL", "PARTIAL", "PARTIAL"),
    ("Codex CLI", "NOT_APPLICABLE", "PARTIAL", "PARTIAL", "NOT_APPLICABLE", "PARTIAL", "PARTIAL", "PARTIAL"),
    ("Claude web", "UNVERIFIED", "NOT_APPLICABLE", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED"),
    ("Claude Desktop", "NOT_APPLICABLE", "UNVERIFIED", "UNVERIFIED", "NOT_APPLICABLE", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED"),
    ("Claude Code", "NOT_APPLICABLE", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED"),
    ("Cursor IDE", "NOT_APPLICABLE", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED"),
    ("Cursor cloud", "UNVERIFIED", "NOT_APPLICABLE", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED"),
    ("Gemini", "PARTIAL", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "PARTIAL", "UNVERIFIED"),
    ("AI Studio", "PARTIAL", "NOT_APPLICABLE", "NOT_APPLICABLE", "UNVERIFIED", "UNVERIFIED", "PARTIAL", "UNVERIFIED"),
    ("Gemini Code Assist", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED", "UNVERIFIED"),
    ("Unknown AI tool", "PARTIAL", "PARTIAL", "PARTIAL", "UNVERIFIED", "BLOCK_BY_DEFAULT", "METADATA_ONLY", "UNVERIFIED"),
)

_PROVIDER_CLIENT_MARKERS: dict[tuple[str, str], tuple[str, ...]] = {
    ("anthropic", "claude_code"): ("claude code", "claude-code"),
    ("openai", "codex"): ("codex",),
    ("cursor", "cursor"): ("cursor",),
    ("google", "gemini_cli"): ("gemini cli", "gemini-cli"),
}
_CURRENT_EVIDENCE_AGE = timedelta(hours=24)
_DEVICE_ASSURANCE_STATES = {
    "MANAGED_COMPLIANT",
    "MANAGED_NONCOMPLIANT",
    "REGISTERED_BYOD",
    "UNMANAGED",
    "UNKNOWN",
    "REVOKED",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _lower(value: Any) -> str:
    return _text(value).lower()


def _utc(value: object) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _latest(rows: Iterable[object], field: str) -> object | None:
    dated = [
        (observed, row)
        for row in rows
        if (observed := _utc(getattr(row, field, None))) is not None
    ]
    return max(dated, key=lambda item: item[0])[1] if dated else None


@lru_cache(maxsize=1)
def _provider_manifest_catalog() -> tuple[object, ...]:
    registry = build_default_registry()
    return tuple(
        manifest
        for provider in ("anthropic", "openai", "cursor", "google")
        for manifest in registry.for_provider(provider)
    )


def _session_matches_product(row: object, *, provider: str, product: str) -> bool:
    markers = _PROVIDER_CLIENT_MARKERS.get((provider, product), ())
    if not markers:
        return False
    text = " ".join(
        (
            _lower(getattr(row, "ai_app", None)),
            _lower(getattr(row, "source_surface", None)),
            _lower((getattr(row, "metadata_json", None) or {}).get("client")),
            _lower((getattr(row, "metadata_json", None) or {}).get("product")),
        )
    )
    return any(marker in text for marker in markers)


def _validation_tier(manifest: object, validation: object | None) -> str:
    if validation is None:
        status = _lower(getattr(manifest, "verification_status", None))
        if status.endswith("verified") and not status.endswith("unverified"):
            return "CONFORMANCE_VERIFIED"
        return "UNVERIFIED"
    acceptance = _text(getattr(validation, "acceptance_state", None)).upper()
    if acceptance == "REAL_ENTERPRISE_TENANT_ACCEPTED":
        return "LIVE_ENTERPRISE_VERIFIED"
    if acceptance == "REAL_CLOUD_RUNTIME_ACCEPTED":
        return "LOCAL_INTEGRATION_VERIFIED"
    if acceptance == "REAL_BINARY_ACCEPTED":
        return "LOCAL_INTEGRATION_VERIFIED"
    if acceptance in {"SYNTHETIC_ONLY", "DOCS_ONLY"}:
        return "CONFORMANCE_VERIFIED"
    return "UNVERIFIED"


def derive_provider_capability_manifests(
    *,
    now: datetime,
    sessions: Sequence[object] = (),
    actions: Sequence[object] = (),
    connectors: Sequence[object] = (),
    integrations: Sequence[object] = (),
    validations: Sequence[object] = (),
    health_observations: Sequence[object] = (),
    capability_profiles: Sequence[object] = (),
) -> list[dict[str, Any]]:
    """Overlay tenant evidence on the authoritative capability catalog.

    A catalog capability, a configured connector, and observed use remain
    separate facts. Only an exact integration with a current authenticated
    health observation and a real passed allow/block acceptance may become
    tenant VERIFIED.
    """

    observed_now = _utc(now)
    if observed_now is None:
        raise ValueError("provider capability time must be timezone-aware")
    results: list[dict[str, Any]] = []
    for manifest in _provider_manifest_catalog():
        provider = _text(getattr(manifest, "provider", None))
        product = _text(getattr(manifest, "product", None))
        method = _text(getattr(getattr(manifest, "method", None), "value", None))
        matched_sessions = tuple(
            row
            for row in sessions
            if _session_matches_product(row, provider=provider, product=product)
        )
        matched_integrations = tuple(
            row
            for row in integrations
            if _lower(getattr(row, "provider", None)) == provider
            and _lower(getattr(row, "product", None)) == product
            and _lower(getattr(row, "integration_method", None)) == method
        )
        integration = _latest(matched_integrations, "last_validated_at") or _latest(
            matched_integrations, "last_health_check_at"
        )
        if integration is None and matched_integrations:
            integration = matched_integrations[0]
        integration_id = _text(getattr(integration, "id", None)) if integration else ""
        profile_id = _text(getattr(integration, "capability_profile_id", None)) if integration else ""
        profile = next(
            (
                row
                for row in capability_profiles
                if _text(getattr(row, "id", None)) == profile_id
            ),
            None,
        )
        matched_validations = tuple(
            row
            for row in validations
            if _text(getattr(row, "integration_instance_id", None)) == integration_id
        )
        validation = _latest(matched_validations, "validated_at")
        matched_health = tuple(
            row
            for row in health_observations
            if _text(getattr(row, "integration_instance_id", None)) == integration_id
        )
        health = _latest(matched_health, "observed_at")
        connector_present = any(
            provider in _lower(getattr(row, "provider_key", None))
            and bool(getattr(row, "enabled", False))
            for row in connectors
        )
        connected = bool(integration or matched_sessions or connector_present)
        evidence_at_candidates = [
            _utc(getattr(health, "observed_at", None)),
            _utc(getattr(validation, "validated_at", None)),
            _utc(getattr(integration, "last_health_check_at", None)),
            *(_utc(getattr(row, "start_time", None)) for row in matched_sessions),
        ]
        evidence_at = max(
            (value for value in evidence_at_candidates if value is not None),
            default=None,
        )
        stale = bool(
            evidence_at is not None and observed_now - evidence_at > _CURRENT_EVIDENCE_AGE
        ) or bool(
            health is not None
            and (expires := _utc(getattr(health, "expires_at", None))) is not None
            and expires < observed_now
        )
        health_state = _lower(getattr(integration, "health_state", None))
        validation_result = _lower(getattr(validation, "result", None))
        regressed = health_state in {
            "degraded",
            "unhealthy",
            "version_mismatch",
            "tampered",
            "policy_stale",
        } or validation_result == "failed"
        real_acceptance = _text(
            getattr(validation, "acceptance_state", None)
        ).upper() in {
            "REAL_BINARY_ACCEPTED",
            "REAL_ENTERPRISE_TENANT_ACCEPTED",
            "REAL_CLOUD_RUNTIME_ACCEPTED",
        }
        manifest_versions = {
            _text(value) for value in getattr(manifest, "supported_versions", ()) if _text(value)
        }
        validation_provider_version = _text(
            getattr(validation, "provider_version", None)
        )
        integration_provider_version = _text(
            getattr(integration, "provider_version", None)
        )
        profile_provider_version = _text(
            getattr(profile, "current_verified_version", None)
        )
        validation_action_classes = {
            _lower(value)
            for value in (getattr(validation, "action_classes", None) or ())
            if _text(value)
        }
        profile_action_classes = {
            _lower(value)
            for value in (getattr(profile, "supported_action_classes", None) or ())
            if _text(value)
        }
        validation_control_methods = {
            _lower(value)
            for value in (getattr(validation, "control_methods", None) or ())
            if _text(value)
        }
        contract_hashes = {
            _text(getattr(row, "contract_hash", None))
            for row in (profile, integration, validation)
            if row is not None
        }
        exact_scope_match = bool(
            profile is not None
            and validation is not None
            and integration is not None
            and _lower(getattr(profile, "provider", None)) == provider
            and _lower(getattr(profile, "product", None)) == product
            and _lower(getattr(profile, "integration_method", None)) == method
            and _lower(getattr(validation, "provider", None)) == provider
            and _lower(getattr(validation, "product", None)) == product
            and validation_provider_version
            and validation_provider_version == integration_provider_version
            and (not profile_provider_version or validation_provider_version == profile_provider_version)
            and (not manifest_versions or validation_provider_version in manifest_versions)
            and _text(getattr(validation, "adapter_version", None))
            == _text(getattr(integration, "adapter_version", None))
            == _text(getattr(profile, "adapter_version", None))
            == _text(getattr(manifest, "adapter_version", None))
            and len(contract_hashes) == 1
            and all(len(value) == 64 for value in contract_hashes)
            and validation_action_classes
            and validation_action_classes == profile_action_classes
            and method in validation_control_methods
        )
        validation_checks = getattr(validation, "checks", None)
        capability_checks = (
            validation_checks.get("capabilities", {})
            if isinstance(validation_checks, dict)
            and isinstance(validation_checks.get("capabilities", {}), dict)
            else {}
        )
        available_dimensions = {
            _text(getattr(dimension, "value", None))
            for dimension, claim in getattr(manifest, "capability_matrix", {}).items()
            if _lower(getattr(getattr(claim, "level", None), "value", None))
            not in {"unavailable", "unknown"}
        }
        passed_dimensions = {
            _lower(name)
            for name, result in capability_checks.items()
            if _lower(result) == "passed"
        }
        per_capability_acceptance = bool(
            available_dimensions and available_dimensions <= passed_dimensions
        )
        full_acceptance = bool(
            validation is not None
            and real_acceptance
            and acceptance_version_is_current(
                acceptance_state=getattr(validation, "acceptance_state", None),
                validation_version=getattr(validation, "validation_version", None),
            )
            and getattr(validation, "safe_synthetic", True) is False
            and validation_result == "passed"
            and _lower(getattr(validation, "allow_result", None)) == "passed"
            and _lower(getattr(validation, "block_result", None)) == "passed"
            and _lower(getattr(validation, "non_execution_result", None)) == "passed"
            and health is not None
            and getattr(health, "callback_authenticated", False) is True
            and getattr(health, "evidence_flowing", False) is True
            and not stale
            and not regressed
            and exact_scope_match
            and per_capability_acceptance
        )
        if regressed:
            tenant_state = "REGRESSED"
        elif stale:
            tenant_state = "STALE"
        elif full_acceptance:
            tenant_state = "VERIFIED"
        elif validation is not None and validation_result in {"passed", "partial"}:
            tenant_state = "PARTIAL"
        elif connected:
            tenant_state = "CONNECTED_UNVERIFIED"
        else:
            tenant_state = "DISCONNECTED"
        version = (
            _text(getattr(validation, "provider_version", None))
            or _text(getattr(integration, "provider_version", None))
        )
        if not version and matched_sessions:
            latest_session = _latest(matched_sessions, "start_time") or matched_sessions[0]
            metadata = getattr(latest_session, "metadata_json", None) or {}
            version = _text(metadata.get("client_version") or metadata.get("version"))
        dimensions: dict[str, str] = {}
        for dimension, claim in getattr(manifest, "capability_matrix", {}).items():
            name = _text(getattr(dimension, "value", None))
            level = _lower(getattr(getattr(claim, "level", None), "value", None))
            if level == "unavailable":
                dimensions[name] = "UNSUPPORTED"
            elif level == "unknown":
                dimensions[name] = "UNKNOWN"
            else:
                dimensions[name] = (
                    "VERIFIED"
                    if full_acceptance and name in passed_dimensions
                    else (
                        "PARTIAL"
                        if validation is not None and validation_result in {"passed", "partial"}
                        else tenant_state
                    )
                )
        evidence_refs = {
            *(
                _text(value)
                for value in getattr(manifest, "verification_evidence", ())
                if _text(value)
            ),
            *(
                _text(value)
                for value in (getattr(validation, "evidence_refs", None) or [])
                if _text(value)
            ),
        }
        health_ref = _text(getattr(health, "evidence_ref", None))
        if health_ref:
            evidence_refs.add(health_ref)
        results.append(
            {
                "provider": provider,
                "product": product,
                "method": method,
                "manifest_id": _text(getattr(manifest, "manifest_id", None)),
                "catalog_verification": _text(
                    getattr(getattr(manifest, "verification_status", None), "value", None)
                ).upper(),
                "tenant_state": tenant_state,
                # A real acceptance run for a different provider/product,
                # adapter, contract, version, or action set is not acceptance
                # evidence for this manifest.
                "validation_tier": (
                    _validation_tier(manifest, validation)
                    if validation is None or exact_scope_match
                    else "UNVERIFIED"
                ),
                "exact_version": version or None,
                "evidence_at": evidence_at.isoformat() if evidence_at else None,
                "evidence_age_seconds": (
                    max(0, int((observed_now - evidence_at).total_seconds()))
                    if evidence_at
                    else None
                ),
                "dimensions": dimensions,
                "evidence_refs": sorted(evidence_refs),
                "limitations": list(getattr(manifest, "known_blind_spots", ())),
                "prompt_content_access": "CONTENT_UNAVAILABLE",
            }
        )
    return results


def derive_account_device_summary(
    *,
    endpoints: Sequence[object],
    actions: Sequence[object],
    account_receipts: Sequence[object],
) -> dict[str, Any]:
    device_states: list[str] = []
    for endpoint in endpoints:
        metadata = getattr(endpoint, "metadata_json", None) or {}
        state = _text(
            metadata.get("device_assurance") or metadata.get("management_state")
        ).upper()
        device_states.append(state if state in _DEVICE_ASSURANCE_STATES else "UNKNOWN")
    blocked_downloads = sum(
        1
        for row in actions
        if "download" in _lower(getattr(row, "action_type", None))
        and _lower(getattr(row, "enforcement_action", None)) in {"block", "blocked"}
    )
    corporate_denials = sum(
        1
        for row in account_receipts
        if _text(getattr(row, "account_class", None)).upper().startswith("ENTERPRISE")
        and _text(getattr(row, "decision", None)).upper().startswith("BLOCK")
    )
    restricted_byod = sum(
        1
        for row in account_receipts
        if _text(getattr(row, "decision", None)).upper() == "ALLOW_RESTRICTED"
    )
    return {
        "managed_compliant_devices": device_states.count("MANAGED_COMPLIANT"),
        "managed_noncompliant_devices": device_states.count("MANAGED_NONCOMPLIANT"),
        "registered_byod_devices": device_states.count("REGISTERED_BYOD"),
        "unmanaged_devices": device_states.count("UNMANAGED"),
        "unknown_devices": device_states.count("UNKNOWN"),
        "revoked_devices": device_states.count("REVOKED"),
        "blocked_sensitive_downloads": blocked_downloads,
        "corporate_session_denials": corporate_denials,
        "restricted_byod_sessions": restricted_byod,
        "device_management_inferred_from_hostname_or_os": False,
        "strict_fallback": "DENY_CORPORATE_LOGIN_WHEN_DOWNLOAD_BLOCK_UNAVAILABLE",
    }


def derive_meeting_ai_summary(
    *,
    signals: Sequence[object],
    platform_evidence: Sequence[object],
) -> dict[str, Any]:
    detected = tuple(
        row
        for row in signals
        if _text(getattr(row, "signal_type", None)).endswith(
            "meeting_ai_notetaker_detected"
        )
    )
    block_requests = tuple(
        row
        for row in signals
        if _text(getattr(row, "signal_type", None)).endswith(
            "meeting_ai_notetaker_block_requested"
        )
    )
    def authoritative_platform_action(row: object) -> bool:
        payload = getattr(row, "payload", None) or {}
        if not isinstance(payload, dict) or payload.get("performed") is not True:
            return False
        platform = _lower(payload.get("platform"))
        expected_provider = (
            "microsoft_graph"
            if platform in {"teams", "microsoft_teams"}
            else "google_workspace"
            if platform in {"google_meet", "google_workspace", "meet"}
            else "zoom"
            if platform in {"zoom", "zoom_meeting", "zoom_web"}
            else ""
        )
        operation = payload.get("graph_operation")
        status_code = payload.get("status_code")
        participant_identity = _text(
            payload.get("participant_id") or payload.get("notetaker_email")
        )
        return bool(
            expected_provider
            and _lower(payload.get("provider_control_path")) == expected_provider
            and _lower(payload.get("control_mode")) == "external_action_triggered"
            and _text(payload.get("source_detection_evidence_id"))
            and participant_identity
            and isinstance(operation, dict)
            and _text(operation.get("method"))
            and _text(operation.get("path"))
            and type(status_code) is int
            and 200 <= status_code < 300
        )

    performed = tuple(row for row in platform_evidence if authoritative_platform_action(row))
    providers = sorted(
        {
            _text((getattr(row, "payload", None) or {}).get("notetaker_provider"))
            for row in (*detected, *block_requests)
            if _text((getattr(row, "payload", None) or {}).get("notetaker_provider"))
        }
    )
    teams_performed = any(
        _lower((getattr(row, "payload", None) or {}).get("platform"))
        in {"teams", "microsoft_teams"}
        for row in performed
    )
    return {
        "registry": ["Fireflies", "Read AI", "Otter", "Fathom", "tl;dv", "Krisp", "unknown"],
        "detected_attempts": len(detected),
        "block_requests": len(block_requests),
        "performed_platform_actions": len(performed),
        "providers_observed": providers,
        "teams_enforcement_state": "VERIFIED" if teams_performed else "PARTIAL",
        "physical_recording_blind_spot": "UNSUPPORTED",
        "display_name_only_identity": "insufficient",
    }


def _provider_family(value: object) -> str:
    text = _lower(value)
    if "claude" in text or "anthropic" in text:
        return "anthropic"
    if "codex" in text or "chatgpt" in text or "openai" in text:
        return "openai"
    if "cursor" in text:
        return "cursor"
    if "gemini" in text or "google ai" in text:
        return "google"
    return "unknown"


def derive_provider_usage_summary(
    *, sessions: Sequence[object], actions: Sequence[object]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for provider in ("anthropic", "openai", "cursor", "google", "unknown"):
        provider_sessions = tuple(
            row
            for row in sessions
            if _provider_family(getattr(row, "ai_app", None)) == provider
        )
        provider_actions = tuple(
            row
            for row in actions
            if _provider_family(getattr(row, "ai_app", None)) == provider
        )
        models = sorted(
            {
                _text(getattr(row, "ai_model", None))
                for row in (*provider_sessions, *provider_actions)
                if _text(getattr(row, "ai_model", None))
            }
        )
        users = {
            _text(getattr(row, "user_id", None))
            for row in (*provider_sessions, *provider_actions)
            if _text(getattr(row, "user_id", None))
        }
        latest = max(
            (
                value
                for row, field in (
                    *((item, "start_time") for item in provider_sessions),
                    *((item, "timestamp") for item in provider_actions),
                )
                if (value := _utc(getattr(row, field, None))) is not None
            ),
            default=None,
        )
        rows.append(
            {
                "provider": provider,
                "sessions": len(provider_sessions),
                "actions": len(provider_actions),
                "active_users": len(users),
                "models": models,
                "last_activity_at": latest.isoformat() if latest else None,
                "spend": None,
                "currency": None,
                "cost_source": "UNAVAILABLE",
                "productivity_score_generated": False,
            }
        )
    return rows


def _normal_repo_name(value: str) -> str:
    text = value.strip().rstrip("/")
    if text.endswith(".git"):
        text = text[:-4]
    return text


def normalize_repository_reference(
    reference: str | int | None,
    *,
    verified_repositories: list[dict[str, Any]] | tuple[dict[str, Any], ...],
) -> dict[str, Any]:
    """Resolve a repository reference without treating names as authority."""

    raw = _text(reference)
    if not raw:
        return {
            "input": raw,
            "provider": "unknown",
            "host": "",
            "owner": "",
            "name": "",
            "repository_id": None,
            "node_id": None,
            "matched_immutable_identity": False,
            "classification": "unknown",
        }

    host = "github.com"
    owner = ""
    name = ""
    repository_id: str | None = None

    if raw.isdigit():
        repository_id = raw
    elif raw.startswith("git@"):
        left, _, right = raw.partition(":")
        host = left.split("@", 1)[-1].lower()
        parts = _normal_repo_name(right).split("/")
        if len(parts) >= 2:
            owner, name = parts[-2], parts[-1]
    else:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = (parsed.hostname or host).lower()
        path = _normal_repo_name(parsed.path.lstrip("/"))
        parts = path.split("/")
        if len(parts) >= 2:
            owner, name = parts[0], parts[1]

    for candidate in verified_repositories:
        candidate_id = _text(candidate.get("repository_id"))
        candidate_node = _text(candidate.get("node_id"))
        candidate_host = _lower(candidate.get("host") or "github.com")
        candidate_owner = _lower(candidate.get("organization_login"))
        candidate_name = _lower(candidate.get("repository_name") or candidate.get("current_full_name", "").split("/")[-1])
        id_matches = bool(repository_id and repository_id == candidate_id)
        name_matches = host == candidate_host and _lower(owner) == candidate_owner and _lower(name) == candidate_name
        if id_matches or name_matches:
            return {
                "input": raw,
                "provider": _text(candidate.get("provider") or "github"),
                "host": candidate_host,
                "owner": candidate.get("organization_login") or owner,
                "name": candidate.get("repository_name") or name,
                "repository_id": candidate_id or None,
                "node_id": candidate_node or None,
                "visibility": _text(candidate.get("visibility") or "unknown"),
                "archived": bool(candidate.get("archived")),
                "installation_id": _text(candidate.get("installation_id")) or None,
                "matched_immutable_identity": bool(candidate_id or candidate_node),
                "classification": "approved_corporate" if _lower(candidate.get("visibility")) == "private" else "not_private",
            }

    return {
        "input": raw,
        "provider": "github" if host.endswith("github.com") else "unknown",
        "host": host,
        "owner": owner,
        "name": name,
        "repository_id": repository_id,
        "node_id": None,
        "visibility": "unknown",
        "archived": False,
        "installation_id": None,
        "matched_immutable_identity": False,
        "classification": "external_or_unknown",
    }


def decide_repository_boundary(
    policy: dict[str, Any],
    *,
    repository_reference: str | int | None,
    operation: str,
    branch: str | None = None,
    device_assurance: str = "UNKNOWN",
    corporate_account: bool = False,
    download_control_available: bool = True,
) -> dict[str, Any]:
    repository_identity = dict(policy.get("repository_identity") or {})
    resolved = normalize_repository_reference(repository_reference, verified_repositories=[repository_identity])
    normalized_operation = _text(operation).upper()
    branch_name = _text(branch)
    allowed_operations = set(_text(item).upper() for item in policy.get("allowed_operations") or DEFAULT_ALLOWED_OPERATIONS)

    if corporate_account and _text(device_assurance).upper() in {"UNMANAGED", "UNKNOWN"}:
        strict_device = _text(policy.get("unmanaged_device_corporate_account") or "BLOCK_LOGIN_IF_DOWNLOAD_CONTROL_UNAVAILABLE")
        if strict_device.startswith("BLOCK") and not download_control_available:
            return _decision("BLOCK", "corporate_account_requires_managed_device", resolved, normalized_operation)

    if not resolved["matched_immutable_identity"] or resolved["classification"] != "approved_corporate":
        return _decision("BLOCK", "repository_not_approved", resolved, normalized_operation)
    if _lower(resolved.get("visibility")) != "private":
        return _decision("BLOCK", "repository_privacy_not_verified", resolved, normalized_operation)
    if resolved.get("archived"):
        return _decision("BLOCK", "repository_archived_or_inactive", resolved, normalized_operation)
    if normalized_operation not in allowed_operations:
        return _decision("BLOCK", "operation_not_allowed", resolved, normalized_operation)
    if normalized_operation == "REPOSITORY_FORCE_PUSH" or _text(policy.get("force_push_behavior")) == "BLOCK" and "FORCE_PUSH" in normalized_operation:
        return _decision("BLOCK", "force_push_blocked", resolved, normalized_operation)
    if normalized_operation == "REPOSITORY_PUSH" and branch_name in {"main", "master"} and _text(policy.get("default_branch_behavior")) == "BLOCK_DIRECT_PUSH":
        return _decision("BLOCK", "direct_default_branch_push_blocked", resolved, normalized_operation)
    if normalized_operation == "REPOSITORY_FORK" and _text(policy.get("fork_behavior")) == "BLOCK":
        return _decision("BLOCK", "fork_blocked", resolved, normalized_operation)
    return _decision("ALLOW", "approved_repository_operation", resolved, normalized_operation)


def _decision(decision: str, reason: str, repository_identity: dict[str, Any], operation: str) -> dict[str, Any]:
    return {
        "decision": decision,
        "reason": reason,
        "operation": operation,
        "repository_identity": repository_identity,
        "evidence_quality": "CONFIRMED" if repository_identity.get("matched_immutable_identity") else "OBSERVED",
        "raw_source_content_stored": False,
    }


def build_enterprise_developer_ai_control(
    *,
    tenant_id: str,
    now: datetime | None = None,
    repository_identity: dict[str, Any] | None = None,
    entitled_developers: int = 0,
    connected_developers: int = 0,
    active_developers: int = 0,
    ai_assisted_developers: int = 0,
    unauthorized_attempts: list[dict[str, Any]] | None = None,
    verified_paths: dict[str, dict[str, str]] | None = None,
    provider_capability_manifests: list[dict[str, Any]] | None = None,
    provider_usage_summary: list[dict[str, Any]] | None = None,
    account_device_summary: dict[str, Any] | None = None,
    meeting_ai_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    generated_at = now or _now()
    repo = _default_repository_identity(repository_identity)
    verified_paths = dict(verified_paths or {})
    unauthorized_attempts = list(unauthorized_attempts or [])
    covered = min(entitled_developers, connected_developers)
    partial = max(0, active_developers - covered)
    uncovered = max(0, entitled_developers - covered)
    provider_surface_coverage = _provider_coverage(verified_paths)
    requirement_traceability = _requirement_traceability(
        repository_configured=bool(repo.get("repository_id")),
        has_unauthorized_attempts=bool(unauthorized_attempts),
        has_verified_runtime=provider_surface_coverage["Codex CLI"]["CLI/IDE"] == "VERIFIED",
    )
    return {
        "tenant_id": tenant_id,
        "package_id": "ENTERPRISE-DEVELOPER-AI-CONTROL-P0",
        "package_name": "Enterprise Developer AI Control Pack",
        "generated_at": generated_at.isoformat(),
        "policy": {
            "mode": "SINGLE_REPOSITORY_STRICT",
            "repository_identity": repo,
            "allowed_operations": list(DEFAULT_ALLOWED_OPERATIONS),
            "blocked_operations": [
                "REPOSITORY_FORCE_PUSH",
                "REPOSITORY_FORK",
                "REPOSITORY_VISIBILITY_CHANGE",
                "REPOSITORY_TRANSFER",
                "REPOSITORY_DELETE",
                "REPOSITORY_SECRET_CHANGE",
            ],
            "default_branch_behavior": "BLOCK_DIRECT_PUSH",
            "unmanaged_device_corporate_account": "BLOCK_LOGIN_IF_DOWNLOAD_CONTROL_UNAVAILABLE",
            "strict_failure_mode": "BLOCK_WHERE_ENFORCEABLE_AND_MARK_UNSUPPORTED_ELSEWHERE",
            "full_content_retention": "OFF_BY_DEFAULT",
        },
        "summary": {
            "approved_repository": _repo_slug(repo),
            "repository_privacy_state": repo.get("visibility") or "unknown",
            "tenant_enforcement_mode": "SINGLE_REPOSITORY_STRICT",
            "entitled_developers": entitled_developers,
            "connected_developers": connected_developers,
            "active_developers": active_developers,
            "ai_assisted_developers": ai_assisted_developers,
            "fully_covered_developers": covered,
            "partially_covered_developers": partial,
            "uncovered_developers": uncovered,
            "unauthorized_repository_attempts": len(unauthorized_attempts),
            "blocked_pushes": _count_attempts(unauthorized_attempts, "PUSH"),
            "blocked_pulls_fetches": _count_attempts(unauthorized_attempts, "PULL", "FETCH"),
            "blocked_pr_actions": _count_attempts(unauthorized_attempts, "PULL_REQUEST"),
            "current_control_assurance": "PARTIAL" if repo.get("repository_id") else "UNVERIFIED",
        },
        "repository_card": {
            "organization": repo.get("organization_login") or "unknown",
            "repository": repo.get("repository_name") or "unknown",
            "repository_id": repo.get("repository_id"),
            "node_id": repo.get("node_id"),
            "visibility": repo.get("visibility") or "unknown",
            "default_branch": repo.get("default_branch") or "unknown",
            "installation_id": repo.get("installation_id"),
            "identity_version": repo.get("identity_version") or 1,
            "policy_epoch": 1,
            "last_verified_at": repo.get("last_verified_at"),
            "status": "verified_private" if repo.get("repository_id") and repo.get("visibility") == "private" else "not_verified",
        },
        "developer_counts_definition": {
            "entitled": "Assigned corporate developer population, deduplicated by corporate identity.",
            "connected": "Corporate identity, GitHub identity and at least one approved AI tool connection resolved.",
            "active": "Connected users with approved-repository activity in the selected period.",
            "ai_assisted": "Repository activity linked to an AI tool or agent with sufficient evidence.",
            "covered": "Required provider, device and repository controls are available and current.",
        },
        "provider_surface_coverage": provider_surface_coverage,
        "provider_capability_manifests": list(provider_capability_manifests or []),
        "provider_usage_summary": list(provider_usage_summary or []),
        "account_device": dict(account_device_summary or derive_account_device_summary(
            endpoints=(), actions=(), account_receipts=()
        )),
        "control_coverage": _control_coverage(repo_configured=bool(repo.get("repository_id"))),
        "unauthorized_attempts": unauthorized_attempts,
        "prompt_visibility": {
            "default_level": "METADATA_ONLY",
            "available_levels": ["METADATA_ONLY", "CLASSIFIED_SUMMARY", "REDACTED_PREVIEW", "FULL_CONTENT_PRIVILEGED", "CONTENT_UNAVAILABLE"],
            "full_content_requires": ["captured_source", "retention_policy", "authorized_role", "purpose", "time_bound_grant", "access_audit"],
            "ordinary_views_include_content": False,
        },
        "usage_and_cost": {
            "fields": ["licensed_seats", "assigned_seats", "active_users", "requests", "tokens_or_credits", "repository_operations", "estimated_or_billed_cost"],
            "cost_provenance": ["PROVIDER_BILLED", "PROVIDER_REPORTED", "CUSTOMER_RATE_CARD", "CALCULATED_ESTIMATE", "UNAVAILABLE"],
            "productivity_score_generated": False,
        },
        "meeting_ai": dict(meeting_ai_summary or derive_meeting_ai_summary(
            signals=(), platform_evidence=()
        )),
        "requirement_traceability": requirement_traceability,
        "limitations": _limitations(provider_surface_coverage),
    }


def build_enterprise_developer_ai_control_from_db(db: Session, *, tenant_id: str) -> dict[str, Any]:
    generated_at = _now()
    inventory_repositories = db.scalars(
        select(GitHubRepository)
        .where(GitHubRepository.tenant_id == tenant_id)
        .order_by(GitHubRepository.last_seen_at.desc())
        .limit(1_000)
    ).all()
    inventory_access = db.scalars(
        select(GitHubRepositoryAccess)
        .where(GitHubRepositoryAccess.tenant_id == tenant_id)
        .limit(10_000)
    ).all()
    inventory_ai = db.scalars(
        select(GitHubRepositoryAIConnection)
        .where(GitHubRepositoryAIConnection.tenant_id == tenant_id)
        .limit(10_000)
    ).all()
    inventory_orgs = db.scalars(
        select(GitHubSourceOrganization)
        .where(GitHubSourceOrganization.tenant_id == tenant_id)
        .limit(500)
    ).all()
    if inventory_repositories:
        selected = inventory_repositories[0]
        owner = selected.full_name.split("/", 1)[0] if "/" in selected.full_name else ""
        repo = {
            "provider": "github",
            "host": selected.host,
            "organization_login": owner,
            "repository_name": selected.full_name.rsplit("/", 1)[-1],
            "repository_id": selected.external_repository_id,
            "node_id": selected.node_id,
            "visibility": selected.visibility.lower(),
            "archived": selected.lifecycle_state == "ARCHIVED",
            "default_branch": selected.default_branch,
            "last_verified_at": selected.last_verified_at.isoformat() if selected.last_verified_at else None,
            "evidence_quality": selected.evidence_state,
        }
    else:
        repo = _repository_from_sessions(db, tenant_id=tenant_id) or _repository_from_connector(db, tenant_id=tenant_id)
    users = db.scalars(select(UserRegistry).where(UserRegistry.tenant_id == tenant_id).limit(10_000)).all()
    endpoints = db.scalars(select(DeploymentEndpoint).where(DeploymentEndpoint.tenant_id == tenant_id).limit(10_000)).all()
    sessions = db.scalars(select(AISession).where(AISession.tenant_id == tenant_id).order_by(AISession.start_time.desc()).limit(5_000)).all()
    actions = db.scalars(select(AIAction).where(AIAction.tenant_id == tenant_id).order_by(AIAction.timestamp.desc()).limit(10_000)).all()
    connectors = db.scalars(select(Connector).where(Connector.tenant_id == tenant_id).limit(500)).all()
    native_integrations = db.scalars(
        select(NativeControlIntegration)
        .where(NativeControlIntegration.tenant_id == tenant_id)
        .limit(500)
    ).all()
    native_validations = db.scalars(
        select(NativeControlValidation)
        .where(NativeControlValidation.tenant_id == tenant_id)
        .order_by(NativeControlValidation.validated_at.desc())
        .limit(2_000)
    ).all()
    native_health = db.scalars(
        select(NativeControlHealthObservation)
        .where(NativeControlHealthObservation.tenant_id == tenant_id)
        .order_by(NativeControlHealthObservation.observed_at.desc())
        .limit(2_000)
    ).all()
    native_profiles = db.scalars(
        select(ControlCapabilityProfileRecord).limit(1_000)
    ).all()
    account_receipts = db.scalars(
        select(AccountAccessReceipt)
        .where(AccountAccessReceipt.tenant_id == tenant_id)
        .order_by(AccountAccessReceipt.issued_at.desc())
        .limit(2_000)
    ).all()
    meeting_signals = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.in_(
                (
                    "browser.meeting_ai_notetaker_detected",
                    "browser.meeting_ai_notetaker_block_requested",
                )
            ),
        )
        .order_by(MonitoringSignal.created_at.desc())
        .limit(2_000)
    ).all()
    meeting_platform_evidence = db.scalars(
        select(EvidenceNode)
        .where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.signal_type == "endpoint.notetaker.platform_action",
        )
        .order_by(EvidenceNode.created_at.desc())
        .limit(2_000)
    ).all()
    unauthorized = _unauthorized_attempts(actions)
    connected_developers = len({row.user_id for row in sessions if row.user_id and _session_mentions_repo(row)})
    active_developers = len({row.user_id for row in actions if row.user_id and _action_mentions_repo(row)})
    verified_paths = _verified_paths_from_db(sessions=sessions, actions=actions, endpoints=endpoints)
    payload = build_enterprise_developer_ai_control(
        tenant_id=tenant_id,
        now=generated_at,
        repository_identity=repo,
        entitled_developers=len({row.user_id for row in users}) or connected_developers,
        connected_developers=connected_developers,
        active_developers=active_developers,
        ai_assisted_developers=active_developers,
        unauthorized_attempts=unauthorized,
        verified_paths=verified_paths,
        provider_capability_manifests=derive_provider_capability_manifests(
            now=generated_at,
            sessions=sessions,
            actions=actions,
            connectors=connectors,
            integrations=native_integrations,
            validations=native_validations,
            health_observations=native_health,
            capability_profiles=native_profiles,
        ),
        provider_usage_summary=derive_provider_usage_summary(
            sessions=sessions, actions=actions
        ),
        account_device_summary=derive_account_device_summary(
            endpoints=endpoints,
            actions=actions,
            account_receipts=account_receipts,
        ),
        meeting_ai_summary=derive_meeting_ai_summary(
            signals=meeting_signals,
            platform_evidence=meeting_platform_evidence,
        ),
    )
    payload["repository_inventory"] = {
        "organizations": len(inventory_orgs),
        "repositories": len(inventory_repositories),
        "access_relations": len(inventory_access),
        "direct_access": sum(row.access_path == "DIRECT" for row in inventory_access),
        "team_inherited_access": sum(row.access_path == "TEAM_INHERITED" for row in inventory_access),
        "unknown_access": sum(row.access_path == "UNKNOWN" or row.evidence_state == "UNKNOWN" for row in inventory_access),
        "ai_connections": len(inventory_ai),
        "authoritative_denominator_available": bool(inventory_orgs and any(row.sync_state == "COMPLETE" for row in inventory_orgs)),
        "blind_spots": sorted({str(item) for org in inventory_orgs for item in (org.limitations_json or [])}),
    }
    payload["developer_ai_setup"] = derive_developer_ai_setup_projection(
        repositories=inventory_repositories,
        ai_connections=inventory_ai,
        unauthorized_attempts=unauthorized,
        allowed_operations=payload["policy"]["allowed_operations"],
    )
    return payload


def derive_developer_ai_setup_projection(
    *,
    repositories: Sequence[GitHubRepository],
    ai_connections: Sequence[GitHubRepositoryAIConnection],
    unauthorized_attempts: Sequence[dict[str, Any]] | None = None,
    allowed_operations: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Return the single operator-facing setup truth for developer AI repo control.

    This projection deliberately joins the repository inventory and AI-connection
    evidence into one small, bounded object so the UI does not have to infer
    "approved repo", "blocked repo", "AI client", "tool call" and "decision" from
    unrelated tables.  Missing data remains explicit; source-backed rows are never
    overwritten with generic Unknown placeholders.
    """

    unauthorized_attempts = list(unauthorized_attempts or [])
    allowed = list(allowed_operations or DEFAULT_ALLOWED_OPERATIONS)
    repo_by_id = {row.id: row for row in repositories}
    selected = _selected_repository_for_setup(repositories)
    blocked = _blocked_repository_for_setup(repositories=repositories, selected=selected, unauthorized_attempts=unauthorized_attempts)
    selected_id = getattr(selected, "id", None)

    related_connections = [
        row for row in ai_connections
        if not selected_id or getattr(row, "repository_id", None) == selected_id
    ] or list(ai_connections)
    client_rows = [_developer_ai_client_row(row, repo_by_id=repo_by_id, selected_id=selected_id) for row in related_connections[:25]]
    latest_connection = _latest(related_connections, "last_seen_at") or (related_connections[0] if related_connections else None)
    latest_decision = _latest_policy_decision(
        selected=selected,
        blocked=blocked,
        connection=latest_connection,
        unauthorized_attempts=unauthorized_attempts,
    )

    approved_name = selected.full_name if selected else None
    blocked_name = _blocked_repository_name(blocked) or _first_blocked_attempt_repo(unauthorized_attempts) or "github.com/github/github-mcp-server"
    return {
        "admin_flow": [
            {"step": 1, "label": "Choose AI client", "state": "READY", "description": "Claude, Codex and Cursor inherit the same repository boundary when routed through governed MCP/runtime or endpoint controls."},
            {"step": 2, "label": "Choose repository", "state": "READY" if selected else "NEEDS_SOURCE", "description": "Select one source-backed GitHub repository. Selection alone never approves writes."},
            {"step": 3, "label": "Choose allowed actions", "state": "READY", "description": "Read, pull, branch, push and pull-request operations remain individually selectable."},
            {"step": 4, "label": "Generate config", "state": "READY" if selected else "NEEDS_REPOSITORY", "description": "Generate scoped MCP/client configuration for the selected repository without exposing secrets."},
            {"step": 5, "label": "Test allow", "state": "READY" if selected else "NEEDS_REPOSITORY", "description": "Run a harmless read against the approved repository and capture allow evidence."},
            {"step": 6, "label": "Test block", "state": "READY", "description": "Run the same action against an unapproved repository and capture a block decision."},
        ],
        "approved_repository": _repository_projection_for_setup(selected) if selected else None,
        "blocked_repository": _blocked_repository_projection(blocked=blocked, fallback_name=blocked_name),
        "ai_clients": client_rows,
        "allowed_actions": allowed,
        "blocked_actions": [
            "REPOSITORY_FORCE_PUSH",
            "REPOSITORY_FORK",
            "REPOSITORY_VISIBILITY_CHANGE",
            "REPOSITORY_TRANSFER",
            "REPOSITORY_DELETE",
            "REPOSITORY_SECRET_CHANGE",
        ],
        "test_prompts": {
            "allow": f"Use the governed GitHub MCP server to list open pull requests for {approved_name or 'the selected approved repository'}. Return only the result or the exact policy error.",
            "block": f"Use the governed GitHub MCP server to list open pull requests for {blocked_name}. Return only the result or the exact policy error.",
        },
        "config_targets": [
            {"client": "Claude Code", "config_type": "local_mcp", "repository_scope": approved_name, "status": "READY" if selected else "NEEDS_REPOSITORY"},
            {"client": "Codex Desktop", "config_type": "mcp", "repository_scope": approved_name, "status": "READY" if selected else "NEEDS_REPOSITORY"},
            {"client": "Codex CLI", "config_type": "mcp", "repository_scope": approved_name, "status": "READY" if selected else "NEEDS_REPOSITORY"},
            {"client": "Cursor", "config_type": "mcp_or_endpoint", "repository_scope": approved_name, "status": "READY" if selected else "NEEDS_REPOSITORY"},
        ],
        "latest_decision": latest_decision,
        "evidence_state": {
            "repositories": len(repositories),
            "ai_connections": len(ai_connections),
            "unauthorized_attempts": len(unauthorized_attempts),
            "has_approved_repository": bool(selected),
            "has_ai_connection_evidence": bool(client_rows),
        },
    }


def _selected_repository_for_setup(repositories: Sequence[GitHubRepository]) -> GitHubRepository | None:
    approved = [
        row for row in repositories
        if _upper(getattr(row, "governance_state", None)) == "APPROVED"
        and _upper(getattr(row, "evidence_state", None)) in {"CONFIRMED", "OBSERVED"}
    ]
    if approved:
        return max(approved, key=lambda row: _utc(getattr(row, "last_verified_at", None)) or _utc(getattr(row, "last_seen_at", None)) or datetime.min.replace(tzinfo=timezone.utc))
    current = [
        row for row in repositories
        if _upper(getattr(row, "evidence_state", None)) in {"CONFIRMED", "OBSERVED"}
    ]
    if current:
        return max(current, key=lambda row: _utc(getattr(row, "last_seen_at", None)) or datetime.min.replace(tzinfo=timezone.utc))
    return repositories[0] if repositories else None


def _blocked_repository_for_setup(
    *,
    repositories: Sequence[GitHubRepository],
    selected: GitHubRepository | None,
    unauthorized_attempts: Sequence[dict[str, Any]],
) -> GitHubRepository | None:
    selected_full_name = _lower(getattr(selected, "full_name", None))
    attempted = {_lower(row.get("repository")) for row in unauthorized_attempts if _text(row.get("repository"))}
    for repository in repositories:
        if _lower(repository.full_name) in attempted and _lower(repository.full_name) != selected_full_name:
            return repository
    for repository in repositories:
        if selected and repository.id == selected.id:
            continue
        if _upper(getattr(repository, "governance_state", None)) != "APPROVED":
            return repository
    return None


def _blocked_repository_projection(*, blocked: GitHubRepository | None, fallback_name: str) -> dict[str, Any]:
    if blocked:
        projection = _repository_projection_for_setup(blocked)
        projection["policy_decision"] = "BLOCK_OUTSIDE_APPROVED_SCOPE"
        projection["reason"] = "Repository is not the selected approved repository."
        return projection
    return {
        "id": None,
        "host": "github.com",
        "full_name": fallback_name,
        "policy_decision": "BLOCK_OUTSIDE_APPROVED_SCOPE",
        "reason": "No approval exists for this repository in the selected scope.",
        "evidence_state": "POLICY_DEFAULT",
    }


def _repository_projection_for_setup(repository: GitHubRepository) -> dict[str, Any]:
    protection = dict(getattr(repository, "protection_json", None) or {})
    account_scope_kind = _text(getattr(repository, "account_scope_kind", None)) or _text(protection.get("account_scope_kind")) or "UNKNOWN"
    read_posture = _text(getattr(repository, "read_posture", None)) or "UNKNOWN"
    governance_state = _text(getattr(repository, "governance_state", None)) or "UNKNOWN"
    deny_posture = None
    if account_scope_kind == "PERSONAL" and governance_state == "UNAPPROVED":
        deny_posture = "BLOCK_CHANGES" if read_posture == "ALLOW" else "BLOCK_ALL" if read_posture == "BLOCK" else None
    return {
        "id": getattr(repository, "id", None),
        "host": getattr(repository, "host", None) or "github.com",
        "repository_id": getattr(repository, "external_repository_id", None),
        "node_id": getattr(repository, "node_id", None),
        "full_name": getattr(repository, "full_name", None),
        "visibility": getattr(repository, "visibility", None) or "unknown",
        "lifecycle_state": getattr(repository, "lifecycle_state", None) or "UNKNOWN",
        "default_branch": getattr(repository, "default_branch", None),
        "protection": protection,
        "account_scope_kind": account_scope_kind,
        "deny_posture": deny_posture,
        "evidence_state": getattr(repository, "evidence_state", None) or "UNKNOWN",
        "governance_state": governance_state,
        "governance_version": getattr(repository, "governance_version", None) or 1,
        "approved_scope_ref": getattr(repository, "approved_scope_ref", None),
        "policy_mapping_ref": getattr(repository, "policy_mapping_ref", None),
        "policy_current": bool(getattr(repository, "policy_current", False)),
        "read_posture": read_posture,
        "first_seen_at": getattr(repository, "first_seen_at", None).isoformat() if getattr(repository, "first_seen_at", None) else None,
        "last_seen_at": getattr(repository, "last_seen_at", None).isoformat() if getattr(repository, "last_seen_at", None) else None,
        "last_verified_at": getattr(repository, "last_verified_at", None).isoformat() if getattr(repository, "last_verified_at", None) else None,
    }


def _developer_ai_client_row(
    row: GitHubRepositoryAIConnection,
    *,
    repo_by_id: dict[str, GitHubRepository],
    selected_id: str | None,
) -> dict[str, Any]:
    tool_name = _text(getattr(row, "tool_name", None)) or _text(getattr(row, "external_capability_id", None)) or "repository_tool_call"
    action = _action_from_tool(tool_name)
    repository = repo_by_id.get(row.repository_id)
    is_selected = bool(selected_id and row.repository_id == selected_id)
    return {
        "ai_client": _text(getattr(row, "client_name", None)) or _client_from_provider(getattr(row, "provider", None)) or "AI client not reported",
        "provider": _text(getattr(row, "provider", None)) or "provider not reported",
        "model": _text(getattr(row, "model", None)) or "model not reported",
        "repository": getattr(repository, "full_name", None),
        "repository_id": row.repository_id,
        "tool_call": tool_name,
        "action": action,
        "policy_decision": "ALLOW_ON_APPROVED_REPOSITORY" if is_selected else "BLOCK_OUTSIDE_APPROVED_SCOPE",
        "confidence": getattr(row, "confidence", None) or "UNKNOWN",
        "source_surface": getattr(row, "source_surface", None) or "UNKNOWN",
        "evidence_refs": list(getattr(row, "evidence_refs_json", None) or []),
        "action_count": getattr(row, "action_count", 0) or 0,
        "last_seen_at": getattr(row, "last_seen_at", None).isoformat() if getattr(row, "last_seen_at", None) else None,
    }


def _latest_policy_decision(
    *,
    selected: GitHubRepository | None,
    blocked: GitHubRepository | None,
    connection: GitHubRepositoryAIConnection | None,
    unauthorized_attempts: Sequence[dict[str, Any]],
) -> dict[str, Any] | None:
    if unauthorized_attempts:
        row = unauthorized_attempts[0]
        return {
            "repository": _text(row.get("repository")) or _blocked_repository_name(blocked) or "unapproved repository",
            "ai_client": _text(row.get("tool")) or "AI client/tool not reported",
            "provider": _text(row.get("provider")) or "provider not reported",
            "model": _text(row.get("model")) or "model not reported",
            "tool_call": _text(row.get("tool")) or "repository_tool_call",
            "action": _text(row.get("operation")) or "REPOSITORY_ACTION",
            "policy_decision": _text(row.get("decision")) or "BLOCK_OUTSIDE_APPROVED_SCOPE",
            "evidence_refs": list(row.get("evidence_refs") or []),
        }
    if connection:
        client = _developer_ai_client_row(connection, repo_by_id={selected.id: selected} if selected else {}, selected_id=getattr(selected, "id", None))
        return {
            "repository": client.get("repository") or getattr(selected, "full_name", None),
            "ai_client": client["ai_client"],
            "provider": client["provider"],
            "model": client["model"],
            "tool_call": client["tool_call"],
            "action": client["action"],
            "policy_decision": client["policy_decision"],
            "evidence_refs": client["evidence_refs"],
        }
    if selected:
        return {
            "repository": selected.full_name,
            "ai_client": "Claude / Codex / Cursor",
            "provider": "configured by selected client",
            "model": "reported when the client emits evidence",
            "tool_call": "governed_repository_tool",
            "action": "REPOSITORY_READ",
            "policy_decision": "READY_TO_TEST",
            "evidence_refs": [],
        }
    return None


def _blocked_repository_name(blocked: GitHubRepository | None) -> str | None:
    return blocked.full_name if blocked else None


def _first_blocked_attempt_repo(attempts: Sequence[dict[str, Any]]) -> str | None:
    for attempt in attempts:
        if repository := _text(attempt.get("repository")):
            return repository
    return None


def _action_from_tool(tool_name: str) -> str:
    value = tool_name.lower()
    if "pull_request" in value or "pr" in value:
        return "REPOSITORY_PULL_REQUEST_CREATE"
    if "create_or_update" in value or "push" in value or "file" in value:
        return "REPOSITORY_PUSH"
    if "branch" in value:
        return "REPOSITORY_BRANCH_CREATE"
    return "REPOSITORY_READ"


def _client_from_provider(provider: Any) -> str:
    value = _lower(provider)
    if "anthropic" in value:
        return "Claude"
    if "openai" in value:
        return "Codex / ChatGPT"
    if "cursor" in value:
        return "Cursor"
    return ""


def _upper(value: Any) -> str:
    return _text(value).upper()


def _default_repository_identity(repo: dict[str, Any] | None) -> dict[str, Any]:
    data = dict(repo or {})
    if not data:
        return {
            "provider": "github",
            "host": "github.com",
            "organization_login": "",
            "repository_name": "",
            "repository_id": None,
            "node_id": None,
            "visibility": "unknown",
            "archived": False,
            "installation_id": None,
            "evidence_quality": "UNVERIFIED",
        }
    data.setdefault("provider", "github")
    data.setdefault("host", "github.com")
    data.setdefault("visibility", "unknown")
    data.setdefault("archived", False)
    data.setdefault("evidence_quality", "CONFIRMED" if data.get("repository_id") or data.get("node_id") else "OBSERVED")
    return data


def _repo_slug(repo: dict[str, Any]) -> str:
    org = _text(repo.get("organization_login"))
    name = _text(repo.get("repository_name"))
    return f"{org}/{name}" if org and name else "not configured"


def _provider_coverage(verified_paths: dict[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for tool, web, desktop, cli, cloud, scope, prompt, usage in PROVIDER_ROWS:
        row = {
            "Web": web,
            "Desktop": desktop,
            "CLI/IDE": cli,
            "Cloud agent": cloud,
            "GitHub scope": scope,
            "Prompt visibility": prompt,
            "Usage/cost": usage,
            "Status": "PARTIAL" if "PARTIAL" in {web, desktop, cli, cloud, scope, prompt, usage} else "UNVERIFIED",
        }
        for column, state in dict(verified_paths.get(tool) or {}).items():
            if column in row:
                row[column] = state
        if any(value == "VERIFIED" for value in row.values()):
            row["Status"] = "PARTIAL"
        rows[tool] = row
    return rows


def _requirement_traceability(*, repository_configured: bool, has_unauthorized_attempts: bool, has_verified_runtime: bool) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for req in APPROVED_DEVELOPER_AI_REQUIREMENTS:
        status = "PARTIAL"
        evidence = "Derived package contract and conformance path present."
        limitation = "Live provider-specific validation required before VERIFIED."
        if req in {"GIT-01", "GIT-02", "GIT-03", "GIT-07", "GIT-08", "COVERAGE-01", "RETENTION-01"} and repository_configured:
            status = "PASS"
            evidence = "Repository boundary package has configured identity and strict policy semantics."
        if req == "GIT-04" and not has_verified_runtime:
            status = "PARTIAL"
            evidence = "Same logical policy is represented across surfaces; not every provider path is verified."
        if req == "GIT-06" and has_unauthorized_attempts:
            status = "PASS"
            evidence = "Unauthorized attempts are present in the package payload."
        if req in {"MEETING-01", "COST-01"}:
            status = "PARTIAL"
            limitation = "Surface is represented with explicit source/provenance requirements; live tenant connector evidence not established here."
        rows[req] = {
            "status": status,
            "production_path": "Enterprise Developer AI Control / GitHub Repository Boundary",
            "test_evidence": evidence,
            "limitation": limitation,
        }
    return rows


def _control_coverage(*, repo_configured: bool) -> list[dict[str, str]]:
    base = "COVERED_CURRENT" if repo_configured else "CONFIGURED_UNVALIDATED"
    return [
        {"capability": "GitHub repository selection", "state": base, "explanation": "One repository is selected and must resolve to immutable GitHub identity."},
        {"capability": "GitHub App selected-repository scope", "state": "PARTIALLY_COVERED", "explanation": "Verified when installation evidence is connected."},
        {"capability": "Runtime/MCP pre-execution repository block", "state": "COVERED_CURRENT", "explanation": "Hawk MCP proxy supports repository-scope authorization and block receipts."},
        {"capability": "Endpoint Git command enforcement", "state": "PARTIALLY_COVERED", "explanation": "Endpoint floor exists; fleet-wide Git interception requires enrolled managed endpoints."},
        {"capability": "Browser/web provider repository scope", "state": "PARTIALLY_COVERED", "explanation": "Managed browser can observe and block supported web paths; provider-native scope remains source-specific."},
        {"capability": "Claude/Cursor/Gemini provider hooks", "state": "UNKNOWN", "explanation": "No live tenant connector evidence is assumed."},
        {"capability": "Teams meeting note-taker control", "state": "PARTIALLY_COVERED", "explanation": "Provider-neutral registry and Teams boundary represented; live Teams enforcement requires Graph/Teams source."},
    ]


def _limitations(provider_surface_coverage: dict[str, dict[str, str]]) -> list[str]:
    limitations = [
        "No source code, raw prompt body, credential, cookie or repository content is stored in this package payload.",
        "Provider-specific live controls remain UNVERIFIED until customer-owned connectors are connected and validated.",
        "Post-event evidence is not represented as pre-execution enforcement.",
    ]
    for tool, row in provider_surface_coverage.items():
        if "UNVERIFIED" in row.values() or "UNKNOWN" in row.values():
            limitations.append(f"{tool}: live provider validation incomplete")
    return sorted(set(limitations))


def _count_attempts(attempts: list[dict[str, Any]], *markers: str) -> int:
    return sum(1 for row in attempts if any(marker in _text(row.get("operation")).upper() for marker in markers))


def _repository_from_sessions(db: Session, *, tenant_id: str) -> dict[str, Any] | None:
    rows = db.scalars(select(AISession).where(AISession.tenant_id == tenant_id).order_by(AISession.start_time.desc())).all()
    for row in rows:
        meta = dict(row.metadata_json or {})
        context = dict(meta.get("bound_context") or {})
        resources = context.get("allowed_resources")
        if isinstance(resources, list) and resources:
            parsed = normalize_repository_reference(resources[0], verified_repositories=[])
            if parsed["owner"] and parsed["name"]:
                return {
                    "provider": "github",
                    "host": parsed["host"],
                    "organization_login": parsed["owner"],
                    "repository_name": parsed["name"],
                    # A governed session proves only an observed repository scope. It is
                    # never a GitHub-owned immutable repository identity.
                    "repository_id": meta.get("repository_id") or context.get("repository_id"),
                    "node_id": meta.get("repository_node_id") or context.get("repository_node_id"),
                    "visibility": meta.get("repository_visibility") or context.get("repository_visibility") or "private",
                    "archived": bool(meta.get("repository_archived") or context.get("repository_archived") or False),
                    "installation_id": meta.get("installation_id") or context.get("installation_id"),
                    "last_verified_at": row.start_time.isoformat() if row.start_time else None,
                    "evidence_quality": "OBSERVED",
                }
    return None


def _repository_from_connector(db: Session, *, tenant_id: str) -> dict[str, Any] | None:
    connector = db.scalar(
        select(Connector)
        .where(Connector.tenant_id == tenant_id, Connector.provider_key.in_(["hmair_github_cloud", "github", "github_enterprise"]))
        .order_by(Connector.created_at.desc())
    )
    if connector is None:
        return None
    config = dict(connector.config or {})
    meta = dict(connector.metadata_json or {})
    full_name = _text(config.get("repository") or meta.get("repository") or config.get("approved_repository"))
    parsed = normalize_repository_reference(full_name, verified_repositories=[])
    return {
        "provider": "github",
        "host": parsed["host"] or "github.com",
        "organization_login": parsed["owner"],
        "repository_name": parsed["name"],
        "repository_id": config.get("repository_id") or meta.get("repository_id"),
        "node_id": config.get("node_id") or meta.get("node_id"),
        "visibility": config.get("visibility") or meta.get("visibility") or "unknown",
        "archived": bool(config.get("archived") or meta.get("archived") or False),
        "installation_id": config.get("installation_id") or meta.get("installation_id"),
        "last_verified_at": connector.last_run_at.isoformat() if connector.last_run_at else None,
        "evidence_quality": "CONFIRMED" if config.get("repository_id") or meta.get("repository_id") else "OBSERVED",
    }


def _action_mentions_repo(row: AIAction) -> bool:
    meta = dict(row.metadata_json or {})
    text = " ".join(_text(value) for value in (row.action_type, row.ai_app, meta.get("repository"), meta.get("target_resource"), meta.get("api_endpoint")))
    return "github" in text.lower() or "repository" in text.lower()


def _session_mentions_repo(row: AISession) -> bool:
    meta = dict(row.metadata_json or {})
    return "github" in str(meta).lower() or "repository" in str(meta).lower()


def _unauthorized_attempts(actions: list[AIAction]) -> list[dict[str, Any]]:
    attempts: list[dict[str, Any]] = []
    for row in actions:
        meta = dict(row.metadata_json or {})
        decision = _lower(row.enforcement_action)
        reason = _lower(meta.get("reason") or meta.get("reason_code"))
        if decision != "block" and "repository" not in reason:
            continue
        repository = _text(meta.get("repository") or meta.get("target_resource") or meta.get("api_endpoint") or "unknown")
        operation = _text(meta.get("repository_operation") or row.action_type or "unknown").upper()
        attempts.append(
            {
                "repository": repository,
                "operation": operation,
                "user_id": row.user_id,
                "device_id": row.endpoint_id,
                "tool": row.ai_app or meta.get("tool_name") or "unknown",
                "surface": meta.get("surface") or meta.get("source_surface") or "unknown",
                "decision": row.enforcement_action.upper(),
                "timestamp": row.timestamp.isoformat() if row.timestamp else None,
                "evidence_quality": meta.get("evidence_quality") or "OBSERVED",
            }
        )
    return attempts[:100]


def _verified_paths_from_db(*, sessions: list[AISession], actions: list[AIAction], endpoints: list[DeploymentEndpoint]) -> dict[str, dict[str, str]]:
    paths: dict[str, dict[str, str]] = {}
    if any(_session_mentions_repo(row) and dict(row.metadata_json or {}).get("session_type") == "mcp" for row in sessions):
        paths.setdefault("Codex CLI", {})["GitHub scope"] = "VERIFIED"
        paths.setdefault("Codex CLI", {})["CLI/IDE"] = "PARTIAL"
    if any(_action_mentions_repo(row) and _lower(row.enforcement_action) == "block" for row in actions):
        paths.setdefault("Codex CLI", {})["CLI/IDE"] = "VERIFIED"
    if endpoints:
        paths.setdefault("Unknown AI tool", {})["Desktop"] = "PARTIAL"
        paths.setdefault("Unknown AI tool", {})["CLI/IDE"] = "PARTIAL"
    return paths
