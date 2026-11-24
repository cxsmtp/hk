from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, MutableMapping
from urllib.parse import urlsplit


SUPPORTED_PRODUCTION_TOPOLOGY = "single_node_compose"
PRODUCTION_PROTOCOL_VERSION = "1.0"
MAX_SECRET_FILE_BYTES = 65_536
DEFAULT_SECRET_FILE_KEYS = frozenset(
    {
        "DATABASE_URL",
        "REDIS_URL",
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "SECRET_KEY",
        "SECRET_KEY_LOCK_PEPPER",
        "CONNECTOR_SECRETS_KEY",
        "CONNECTOR_SECRETS_KDF_SALT",
        "ENFORCEMENT_PAYLOADS_KEY",
        "ONPREM_BUNDLE_SIGNING_SECRET",
        "CANONICAL_ACTION_BINDING_KEY",
        "RECEIPT_SIGNING_KEYS_JSON",
        "BANKING_SUBJECT_PSEUDONYMIZATION_KEY",
        "BANKING_SUBJECT_TRUST_JSON",
        "BANKING_EVIDENCE_ATTESTATION_KEYS_JSON",
        "SIEM_PSEUDONYMIZATION_KEY",
        "ACCOUNT_BOUNDARY_PSEUDONYMIZATION_KEY",
    }
)
REQUIRED_PRODUCTION_SECRET_REFERENCES = frozenset(
    {
        "DATABASE_URL",
        "REDIS_URL",
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "SECRET_KEY",
        "SECRET_KEY_LOCK_PEPPER",
        "CONNECTOR_SECRETS_KEY",
        "CONNECTOR_SECRETS_KDF_SALT",
        "ENFORCEMENT_PAYLOADS_KEY",
        "ONPREM_BUNDLE_SIGNING_SECRET",
    }
)
_IDENTIFIER_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")
_COMPONENT_TYPES = frozenset({"api", "worker", "celery_beat", "web"})


def validate_initial_admin_password(password: str) -> None:
    weak = {"password123!", "password", "changeme", "change-me"}
    if (
        len(password) < 20
        or len(password) > 512
        or password.casefold() in weak
        or not re.search(r"[a-z]", password)
        or not re.search(r"[A-Z]", password)
        or not re.search(r"[0-9]", password)
        or not re.search(r"[^A-Za-z0-9]", password)
    ):
        raise ValueError("Initial administrator password does not meet the production bootstrap policy.")


def load_secret_file_environment(
    *,
    environ: MutableMapping[str, str] | None = None,
    allowed_keys: set[str] | frozenset[str] = DEFAULT_SECRET_FILE_KEYS,
) -> dict[str, str]:
    """Resolve a bounded allowlist of ``*_FILE`` references before Settings loads.

    Only source metadata is returned. Secret values are placed in the supplied
    process environment and are never included in diagnostics or return values.
    """

    target = os.environ if environ is None else environ
    sources: dict[str, str] = {}
    for key in sorted(allowed_keys):
        file_key = f"{key}_FILE"
        direct_value = str(target.get(key) or "")
        file_value = str(target.get(file_key) or "").strip()
        if direct_value and file_value:
            raise ValueError(f"Refusing both {key} and {file_key}; configure one secret source.")
        if not file_value:
            if direct_value:
                sources[key] = "environment"
            continue

        path = Path(file_value)
        if not path.is_absolute():
            raise ValueError(f"{file_key} must use an absolute path.")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ValueError(f"{file_key} is not readable.") from exc
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{file_key} must reference a regular non-symlink file.")
        if metadata.st_size <= 0 or metadata.st_size > MAX_SECRET_FILE_BYTES:
            raise ValueError(f"{file_key} size is outside the supported bound.")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"{file_key} must not be group/world writable.")
        try:
            raw_value = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise ValueError(f"{file_key} is not a valid UTF-8 secret file.") from exc
        secret_value = raw_value.rstrip("\r\n")
        if not secret_value or "\x00" in secret_value:
            raise ValueError(f"{file_key} contains invalid secret material.")
        target[key] = secret_value
        sources[key] = "file"
    return sources


@dataclass(frozen=True)
class ProductionConfigurationReport:
    ready: bool
    topology: str
    deployment_id: str
    reason_codes: tuple[str, ...]
    public_summary: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "ready": self.ready,
            "topology": self.topology,
            "deployment_id": self.deployment_id,
            "reason_codes": list(self.reason_codes),
            "public_summary": dict(self.public_summary),
        }


def _setting(settings_object: object, name: str, default: object = "") -> object:
    return getattr(settings_object, name, default)


def _csv(value: object) -> tuple[str, ...]:
    return tuple(item.strip().rstrip("/") for item in str(value or "").split(",") if item.strip())


def _is_https_url(value: object) -> bool:
    parsed = urlsplit(str(value or ""))
    return parsed.scheme == "https" and bool(parsed.hostname)


def _valid_identifier(value: object) -> bool:
    return bool(_IDENTIFIER_RE.fullmatch(str(value or "").strip()))


def validate_production_configuration(
    settings_object: object,
    *,
    secret_sources: Mapping[str, str],
) -> ProductionConfigurationReport:
    reasons: list[str] = []
    topology = str(_setting(settings_object, "deployment_topology") or "").strip()
    deployment_id = str(_setting(settings_object, "deployment_id") or "").strip()
    deployment_region = str(_setting(settings_object, "deployment_region") or "").strip()
    data_location = str(_setting(settings_object, "deployment_data_location") or "").strip()

    if str(_setting(settings_object, "env") or "").strip().lower() not in {"prod", "production"}:
        reasons.append("production_environment_required")
    if topology != SUPPORTED_PRODUCTION_TOPOLOGY:
        reasons.append("unsupported_topology")
    if not _valid_identifier(deployment_id):
        reasons.append("invalid_deployment_id")
    if not _valid_identifier(deployment_region):
        reasons.append("invalid_deployment_region")
    if not _valid_identifier(data_location):
        reasons.append("invalid_data_location")
    if not str(_setting(settings_object, "database_url") or "").startswith(("postgresql://", "postgresql+")):
        reasons.append("postgresql_required")
    if not _is_https_url(_setting(settings_object, "web_origin")):
        reasons.append("https_web_origin_required")
    if not _is_https_url(_setting(settings_object, "api_base_url")):
        reasons.append("https_api_base_url_required")

    origins = _csv(_setting(settings_object, "cors_origins"))
    if any(origin == "*" or origin.endswith("://*") for origin in origins):
        reasons.append("wildcard_cors_forbidden")
    if str(_setting(settings_object, "web_origin") or "").rstrip("/") not in origins:
        reasons.append("web_origin_missing_from_cors")
    trusted_hosts = _csv(_setting(settings_object, "trusted_hosts"))
    if not trusted_hosts or "*" in trusted_hosts:
        reasons.append("wildcard_trusted_host_forbidden")
    api_hostname = urlsplit(str(_setting(settings_object, "api_base_url") or "")).hostname
    if api_hostname and api_hostname not in trusted_hosts:
        reasons.append("api_host_missing_from_trusted_hosts")
    max_request_body_bytes = int(_setting(settings_object, "max_request_body_bytes", 0) or 0)
    if max_request_body_bytes < 1024 or max_request_body_bytes > 16_777_216:
        reasons.append("request_body_limit_out_of_bounds")
    if bool(_setting(settings_object, "demo_mode", False)):
        reasons.append("demo_mode_forbidden")
    if bool(_setting(settings_object, "pilot_mode", False)):
        reasons.append("pilot_mode_forbidden")
    if bool(_setting(settings_object, "self_registration_enabled", False)):
        reasons.append("self_registration_forbidden")
    if bool(_setting(settings_object, "gateway_intercept_minimal_mode", False)):
        reasons.append("minimal_gateway_mode_forbidden")
    if not bool(_setting(settings_object, "control_plane_strict_dependency_checks", False)):
        reasons.append("strict_dependencies_required")
    if not bool(_setting(settings_object, "fail_secure_mode", False)):
        reasons.append("fail_secure_required")
    if not bool(_setting(settings_object, "mcp_persisted_sessions_required", False)):
        reasons.append("mcp_persisted_sessions_required")
    if not bool(_setting(settings_object, "governance_strict_mode", False)):
        reasons.append("strict_governance_required")
    if not bool(_setting(settings_object, "secret_key_lock_enabled", False)):
        reasons.append("secret_key_lock_required")
    if bool(_setting(settings_object, "account_boundary_enforce", False)):
        if not (bool(_setting(settings_object, "ai_account_boundary", False)) and bool(_setting(settings_object, "account_session_permits", False)) and bool(_setting(settings_object, "account_boundary_simulate", False))):
            reasons.append("account_boundary_enforce_prerequisites_required")
        if not secret_sources.get("ACCOUNT_BOUNDARY_PSEUDONYMIZATION_KEY") == "file":
            reasons.append("account_boundary_pseudonymization_secret_reference_required")
        if not bool(_setting(settings_object, "fail_secure_mode", False)) or not bool(_setting(settings_object, "governance_strict_mode", False)):
            reasons.append("account_boundary_enforce_fail_secure_required")
    heartbeat_max_age = int(_setting(settings_object, "control_plane_heartbeat_max_age_seconds", 0) or 0)
    if heartbeat_max_age < 15 or heartbeat_max_age > 300:
        reasons.append("heartbeat_freshness_out_of_bounds")

    for key in sorted(REQUIRED_PRODUCTION_SECRET_REFERENCES):
        if secret_sources.get(key) != "file":
            reasons.append(f"secret_reference_required:{key}")

    component_type = str(_setting(settings_object, "component_type") or "").strip()
    component_version = str(_setting(settings_object, "component_version") or "").strip()
    protocol_version = str(_setting(settings_object, "component_protocol_version") or "").strip()
    if component_type not in _COMPONENT_TYPES:
        reasons.append("unsupported_component_type")
    try:
        _parse_version(component_version)
    except ValueError:
        reasons.append("invalid_component_version")
    if protocol_version != PRODUCTION_PROTOCOL_VERSION:
        reasons.append("component_protocol_mismatch")

    return ProductionConfigurationReport(
        ready=not reasons,
        topology=topology,
        deployment_id=deployment_id,
        reason_codes=tuple(sorted(set(reasons))),
        public_summary={
            "environment": str(_setting(settings_object, "env") or "").strip().lower(),
            "deployment_id": deployment_id,
            "deployment_region": deployment_region,
            "deployment_data_location": data_location,
            "topology": topology,
            "component_type": component_type,
            "component_version": component_version,
            "component_protocol_version": protocol_version,
        },
    )


def _parse_version(value: str) -> tuple[int, int, int]:
    token = str(value or "").strip()
    parts = token.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ValueError("component version must be numeric major.minor.patch")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


@dataclass(frozen=True)
class ComponentHandshake:
    component_type: str
    component_version: str
    protocol_version: str
    deployment_id: str
    capability_version: str


@dataclass(frozen=True)
class ComponentCompatibilityResult:
    accepted: bool
    status: str
    reason_code: str
    capability_verified: bool


@dataclass(frozen=True)
class ComponentCompatibilityContract:
    deployment_id: str
    protocol_version: str
    minimum_versions: Mapping[str, str]

    def evaluate(self, handshake: ComponentHandshake) -> ComponentCompatibilityResult:
        if handshake.deployment_id != self.deployment_id:
            return ComponentCompatibilityResult(False, "incompatible", "deployment_mismatch", False)
        if handshake.protocol_version != self.protocol_version:
            return ComponentCompatibilityResult(False, "incompatible", "protocol_mismatch", False)
        minimum = self.minimum_versions.get(handshake.component_type)
        if minimum is None:
            return ComponentCompatibilityResult(False, "unknown", "unknown_component_type", False)
        try:
            actual_version = _parse_version(handshake.component_version)
            minimum_version = _parse_version(minimum)
        except ValueError:
            return ComponentCompatibilityResult(False, "incompatible", "invalid_component_version", False)
        if actual_version[0] != minimum_version[0] or actual_version < minimum_version:
            return ComponentCompatibilityResult(False, "incompatible", "component_version_too_old", False)
        capability_verified = handshake.capability_version == "phase9/1.0"
        return ComponentCompatibilityResult(
            True,
            "compatible" if capability_verified else "degraded",
            "compatible" if capability_verified else "unknown_capability_version",
            capability_verified,
        )


def compatibility_contract_from_settings(settings_object: object) -> ComponentCompatibilityContract:
    try:
        minimum_versions = json.loads(str(_setting(settings_object, "minimum_component_versions_json") or "{}"))
    except json.JSONDecodeError as exc:
        raise ValueError("MINIMUM_COMPONENT_VERSIONS_JSON must be valid JSON.") from exc
    if not isinstance(minimum_versions, dict) or set(minimum_versions) != _COMPONENT_TYPES:
        raise ValueError("MINIMUM_COMPONENT_VERSIONS_JSON must pin api, worker, celery_beat, and web.")
    normalized: dict[str, str] = {}
    for component_type, version in minimum_versions.items():
        if not isinstance(version, str):
            raise ValueError("Minimum component versions must be strings.")
        _parse_version(version)
        normalized[str(component_type)] = version
    return ComponentCompatibilityContract(
        deployment_id=str(_setting(settings_object, "deployment_id") or ""),
        protocol_version=str(_setting(settings_object, "component_protocol_version") or ""),
        minimum_versions=normalized,
    )


def build_component_registration(settings_object: object) -> dict[str, str]:
    component_type = str(_setting(settings_object, "component_type") or "").strip()
    if component_type not in _COMPONENT_TYPES:
        raise ValueError("Component type is not supported by the Phase 9 topology.")
    component_version = str(_setting(settings_object, "component_version") or "").strip()
    _parse_version(component_version)
    protocol_version = str(_setting(settings_object, "component_protocol_version") or "").strip()
    if protocol_version != PRODUCTION_PROTOCOL_VERSION:
        raise ValueError("Component protocol version is incompatible.")
    deployment_id = str(_setting(settings_object, "deployment_id") or "").strip()
    if not _valid_identifier(deployment_id):
        raise ValueError("Deployment identity is invalid.")
    return {
        "schema_version": "phase9/1.0",
        "deployment_id": deployment_id,
        "component_type": component_type,
        "component_version": component_version,
        "protocol_version": protocol_version,
        "capability_version": "phase9/1.0",
    }


@dataclass(frozen=True)
class ProductionCheck:
    ok: bool
    critical: bool
    status: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "critical": self.critical, "status": self.status, "detail": self.detail}


@dataclass(frozen=True)
class ProductionReadinessReport:
    ready: bool
    status: str
    checks: Mapping[str, ProductionCheck]

    def to_dict(self) -> dict[str, object]:
        return {
            "ready": self.ready,
            "status": self.status,
            "checks": {name: check.to_dict() for name, check in sorted(self.checks.items())},
        }


def summarize_readiness(checks: Mapping[str, ProductionCheck]) -> ProductionReadinessReport:
    critical_failure = any(check.critical and not check.ok for check in checks.values())
    optional_failure = any(not check.critical and not check.ok for check in checks.values())
    status = "unhealthy" if critical_failure else "degraded" if optional_failure else "ready"
    return ProductionReadinessReport(ready=not critical_failure, status=status, checks=dict(checks))
