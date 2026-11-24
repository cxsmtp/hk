from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from app.core.config import settings
from app.services.connector_secret_service import decrypt_connector_secrets

_EXTENSION_ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://", "edge-extension://")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")


@dataclass(frozen=True)
class HardeningCheck:
    id: str
    label: str
    status: str
    severity: str
    message: str
    remediation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "label": self.label,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "remediation": self.remediation,
        }


def _ok(check_id: str, label: str, message: str, remediation: str = "") -> HardeningCheck:
    return HardeningCheck(check_id, label, "ok", "info", message, remediation)


def _warn(check_id: str, label: str, message: str, remediation: str) -> HardeningCheck:
    return HardeningCheck(check_id, label, "warning", "medium", message, remediation)


def _fail(check_id: str, label: str, message: str, remediation: str) -> HardeningCheck:
    return HardeningCheck(check_id, label, "failed", "high", message, remediation)


def _manual(check_id: str, label: str, message: str, remediation: str) -> HardeningCheck:
    return HardeningCheck(check_id, label, "manual_required", "medium", message, remediation)


def _is_postgres(url: str) -> bool:
    return str(url or "").lower().startswith(("postgresql://", "postgresql+psycopg2://", "postgresql+asyncpg://"))


def _uses_https(url: str) -> bool:
    raw = str(url or "").strip()
    if not raw:
        return False
    try:
        return urlsplit(raw).scheme.lower() == "https"
    except ValueError:
        return False


def _normalized_url(value: Any) -> str:
    return str(value or "").strip().rstrip("/")


def validate_oidc_configuration() -> list[str]:
    """Validate enabled OIDC metadata before any provider is exposed."""
    if not settings.company_sso_enabled:
        return []
    errors: list[str] = []
    try:
        providers = json.loads(settings.oidc_providers_json or "[]")
        bindings = json.loads(settings.oidc_bindings_json or "[]")
    except json.JSONDecodeError:
        return ["oidc_configuration_invalid_json"]
    if not isinstance(providers, list) or not providers:
        errors.append("oidc_providers_required")
        providers = []
    keys: set[str] = set()
    provider_issuers: dict[str, str] = {}
    for row in providers:
        if not isinstance(row, dict):
            errors.append("oidc_provider_malformed")
            continue
        required = ("key", "kind", "display_name", "workspace_slug", "issuer", "client_id", "tenant_id")
        if any(not isinstance(row.get(field), str) or not row[field].strip() for field in required):
            errors.append("oidc_provider_incomplete")
            continue
        key = row["key"].strip()
        issuer = row["issuer"].strip().rstrip("/")
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", key) is None or any(ord(char) < 32 for char in row["display_name"]):
            errors.append("oidc_provider_name_invalid")
        if key in keys:
            errors.append("oidc_provider_duplicate")
        keys.add(key)
        parsed = urlsplit(issuer)
        if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.query or parsed.fragment:
            errors.append("oidc_issuer_https_required")
        kind = row["kind"].lower()
        if kind not in {"entra", "okta"}:
            errors.append("oidc_provider_kind_invalid")
        if kind == "entra" and any(part.lower() in {"common", "organizations", "consumers"} for part in parsed.path.split("/")):
            errors.append("oidc_entra_authority_must_be_tenant_specific")
        provider_issuers[key] = issuer
    for field in ("oidc_callback_url", "oidc_frontend_url"):
        parsed = urlsplit(str(getattr(settings, field, "")))
        if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.query:
            errors.append(f"{field}_https_required")
    try:
        secrets = decrypt_connector_secrets(settings.oidc_provider_secrets_json)
    except Exception:
        secrets = {}
        errors.append("oidc_provider_secrets_invalid")
    if not isinstance(secrets, dict) or any(key not in secrets for key in keys):
        errors.append("oidc_provider_secrets_incomplete")
    if not isinstance(bindings, list):
        errors.append("oidc_bindings_invalid")
    else:
        seen_bindings: set[tuple[str, str, str]] = set()
        for row in bindings:
            if not isinstance(row, dict) or not all(isinstance(row.get(field), str) and row[field].strip() for field in ("provider_key", "issuer", "subject", "user_id", "tenant_id")):
                errors.append("oidc_binding_incomplete")
                continue
            identity = (row["provider_key"], row["issuer"], row["subject"])
            if identity in seen_bindings:
                errors.append("oidc_binding_duplicate")
            seen_bindings.add(identity)
            provider_row = next((candidate for candidate in providers if isinstance(candidate, dict) and candidate.get("key") == row["provider_key"]), None)
            if row["provider_key"] not in provider_issuers or provider_issuers.get(row["provider_key"]) != row["issuer"] or not provider_row or provider_row.get("tenant_id") != row["tenant_id"]:
                errors.append("oidc_binding_provider_mismatch")
    return sorted(set(errors))


def _first_nonempty(payload: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _extension_bool(payload: dict[str, Any], key: str) -> bool:
    return _as_bool(payload.get(key))


def _valid_build_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[a-fA-F0-9]{12,64}", str(value or "").strip()))


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    raw = str(value or "").strip()
    if not _SEMVER_RE.fullmatch(raw):
        return None
    core = raw.split("-", 1)[0].split("+", 1)[0]
    try:
        major, minor, patch = core.split(".")
        return int(major), int(minor), int(patch)
    except ValueError:
        return None


def _version_at_least(actual: str, minimum: str) -> bool | None:
    actual_tuple = _version_tuple(actual)
    minimum_tuple = _version_tuple(minimum)
    if actual_tuple is None or minimum_tuple is None:
        return None
    return actual_tuple >= minimum_tuple


def _split_csv(raw: str | None) -> list[str]:
    return [item.strip().rstrip("/") for item in str(raw or "").split(",") if item.strip()]


def _is_wildcard_origin(origin: str) -> bool:
    normalized = str(origin or "").strip().rstrip("/")
    if normalized == "*":
        return True
    return any(normalized == f"{prefix}*" for prefix in _EXTENSION_ORIGIN_PREFIXES)


def _is_explicit_extension_origin(origin: str) -> bool:
    normalized = str(origin or "").strip().rstrip("/")
    return any(
        normalized.startswith(prefix)
        and normalized != f"{prefix}*"
        and len(normalized) > len(prefix)
        for prefix in _EXTENSION_ORIGIN_PREFIXES
    )


def _has_extension_origin_wildcard(raw: str | None) -> bool:
    return any(_is_wildcard_origin(origin) for origin in _split_csv(raw))


def _has_explicit_extension_origin(raw: str | None) -> bool:
    return any(_is_explicit_extension_origin(origin) for origin in _split_csv(raw))


def evaluate_deployment_hardening(
    extension_payload: dict[str, Any] | None = None,
    *,
    expected_tenant_id: str | None = None,
) -> dict[str, Any]:
    """Return operator and machine-checkable readiness signals for a 50-user pilot.

    Some items, such as disk encryption and firewall scope, are machine/operator
    controls outside the API process. Those are intentionally reported as
    attestations instead of silently passing.
    """

    extension_payload = extension_payload or {}
    checks: list[HardeningCheck] = []

    checks.append(
        _ok("database_postgresql", "PostgreSQL database", "DATABASE_URL is PostgreSQL.")
        if _is_postgres(settings.database_url)
        else _fail(
            "database_postgresql",
            "PostgreSQL database",
            "DATABASE_URL is not PostgreSQL.",
            "Run the pilot on local PostgreSQL, not SQLite.",
        )
    )
    checks.append(
        _ok("secret_key_strength", "Strong SECRET_KEY", "SECRET_KEY passes pilot strength checks.")
        if len(str(settings.secret_key or "")) >= 32
        else _fail(
            "secret_key_strength",
            "Strong SECRET_KEY",
            "SECRET_KEY is shorter than 32 characters.",
            "Generate a fresh 32+ byte secret and keep the secret-key lock file.",
        )
    )
    checks.append(
        _ok("secret_key_lock", "SECRET_KEY lock", "SECRET_KEY lock is enabled.")
        if settings.secret_key_lock_enabled
        else _warn(
            "secret_key_lock",
            "SECRET_KEY lock",
            "SECRET_KEY lock is disabled.",
            "Enable SECRET_KEY_LOCK_ENABLED=true before pilot deployment.",
        )
    )

    api_url = settings.api_base_url or ""
    https_ok = _uses_https(api_url) or _uses_https(settings.web_origin)
    if settings.require_https_for_pilot and not https_ok:
        checks.append(
            _fail(
                "https_enabled",
                "HTTPS enabled",
                "HTTPS is required but API_BASE_URL/WEB_ORIGIN are not HTTPS.",
                "Put the API behind HTTPS or set REQUIRE_HTTPS_FOR_PILOT=false only for a closed local lab.",
            )
        )
    else:
        checks.append(
            _ok("https_enabled", "HTTPS enabled", "HTTPS configured or not required for this local pilot.")
            if https_ok
            else _warn(
                "https_enabled",
                "HTTPS enabled",
                "API appears to be running over HTTP.",
                "Use HTTPS for 50-user pilots when possible, even on an internal network.",
            )
        )

    if _has_extension_origin_wildcard(settings.cors_origins) or _has_extension_origin_wildcard(settings.extension_cors_origins):
        checks.append(
            _fail(
                "extension_cors_origins",
                "Extension CORS origins",
                "Extension CORS origins include a wildcard.",
                "Pin exact extension origins with EXTENSION_CORS_ORIGINS=chrome-extension://<id>.",
            )
        )
    elif _has_explicit_extension_origin(settings.extension_cors_origins):
        checks.append(
            _ok(
                "extension_cors_origins",
                "Extension CORS origins",
                "Extension CORS origins are explicitly pinned.",
            )
        )
    else:
        checks.append(
            _warn(
                "extension_cors_origins",
                "Extension CORS origins",
                "EXTENSION_CORS_ORIGINS is not configured.",
                "Set EXTENSION_CORS_ORIGINS=chrome-extension://<id> for managed Chrome/Edge/Brave pilot extensions.",
            )
        )

    checks.append(
        _ok("disk_encryption", "Disk encryption", "Disk encryption is operator-attested.")
        if settings.disk_encryption_confirmed
        else _manual(
            "disk_encryption",
            "Disk encryption",
            "The API cannot verify host disk encryption from inside the process.",
            "Confirm FileVault/BitLocker is enabled and set DISK_ENCRYPTION_CONFIRMED=true.",
        )
    )
    checks.append(
        _ok("network_restricted", "API network restriction", "API port restriction is operator-attested.")
        if settings.api_network_restriction_confirmed
        else _manual(
            "network_restricted",
            "API network restriction",
            "The API cannot verify firewall scope from inside the process.",
            "Restrict port 8000/your API port to the internal pilot network and set API_NETWORK_RESTRICTION_CONFIRMED=true.",
        )
    )
    checks.append(
        _ok("backup_configured", "PostgreSQL backup", "Backup is operator-attested.")
        if settings.backup_configured
        else _manual(
            "backup_configured",
            "PostgreSQL backup",
            "No backup attestation configured.",
            "Schedule encrypted pg_dump backups and set BACKUP_CONFIGURED=true.",
        )
    )

    checks.append(
        _ok("sensitive_raw_prompt_logging_off", "Sensitive raw prompt logging", "Sensitive raw prompt logging is disabled.")
        if not settings.prompt_logging_allow_sensitive_raw
        else _fail(
            "sensitive_raw_prompt_logging_off",
            "Sensitive raw prompt logging",
            "Sensitive raw prompt logging is enabled.",
            "Set PROMPT_LOGGING_ALLOW_SENSITIVE_RAW=false before pilot deployment.",
        )
    )
    for check_id, label, enabled, remediation in (
        (
            "fail_secure_mode",
            "Fail-secure mode",
            settings.fail_secure_mode,
            "Set FAIL_SECURE_MODE=true for production-like pilot behavior.",
        ),
        (
            "governance_strict_mode",
            "Governance strict mode",
            settings.governance_strict_mode,
            "Set GOVERNANCE_STRICT_MODE=true before expanding beyond a closed lab.",
        ),
        (
            "strict_dependency_checks",
            "Strict dependency checks",
            settings.control_plane_strict_dependency_checks,
            "Set CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS=true when Redis/Celery are running.",
        ),
    ):
        checks.append(
            _ok(check_id, label, f"{label} is enabled.")
            if enabled
            else _warn(check_id, label, f"{label} is not enabled.", remediation)
        )

    retention_days = (settings.evidence_retention_days, settings.report_retention_days)
    retention_message = (
        f"Evidence retention={settings.evidence_retention_days}d, "
        f"report retention={settings.report_retention_days}d."
    )
    if any(days <= 0 for days in retention_days):
        checks.append(
            _fail(
                "retention_policy",
                "Evidence/report retention",
                "Evidence/report retention is not configured.",
                "Set EVIDENCE_RETENTION_DAYS and REPORT_RETENTION_DAYS to positive values.",
            )
        )
    elif any(days < 30 for days in retention_days):
        checks.append(
            _warn(
                "retention_policy",
                "Evidence/report retention",
                f"{retention_message} This is short for investigation and executive reporting.",
                "Use at least 30 days for pilots; 90 days is the recommended local pilot default.",
            )
        )
    elif any(days > 365 for days in retention_days):
        checks.append(
            _warn(
                "retention_policy",
                "Evidence/report retention",
                f"{retention_message} This is long for a local pilot privacy baseline.",
                "Use 90 days unless legal or customer policy explicitly requires longer.",
            )
        )
    else:
        checks.append(
            _ok(
                "retention_policy",
                "Evidence/report retention",
                retention_message,
            )
        )

    incognito_policy = str(settings.incognito_policy or "").strip().lower()
    checks.append(
        _ok("incognito_policy", "Incognito policy", f"Incognito policy is {incognito_policy}.")
        if incognito_policy in {"disabled", "enabled_monitored"}
        else _warn(
            "incognito_policy",
            "Incognito policy",
            "Incognito policy is not explicit.",
            "Use INCOGNITO_POLICY=disabled or enabled_monitored and configure Chrome/Edge policy accordingly.",
        )
    )

    if extension_payload:
        managed = _extension_bool(extension_payload, "enterprise_managed")
        locked = _extension_bool(extension_payload, "policy_locked")
        build_hash = str(extension_payload.get("extension_build_hash") or "").strip()
        version = str(extension_payload.get("extension_version") or "").strip()
        minimum_version = _first_nonempty(extension_payload, ("minimum_extension_version", "minimumExtensionVersion"))
        source_maps_included = extension_payload.get("source_maps_included")
        dev_files_included = extension_payload.get("dev_files_included")
        checks.append(
            _ok("extension_managed", "Managed extension mode", "Latest heartbeat reports enterprise_managed=true.")
            if managed
            else _fail(
                "extension_managed",
                "Managed extension mode",
                "Latest heartbeat is not enterprise-managed.",
                "Deploy the extension through managed browser policy before expanding to 50 users.",
            )
        )
        checks.append(
            _ok("extension_policy_locked", "Extension policy locked", "Latest heartbeat reports policy_locked=true.")
            if locked
            else _fail(
                "extension_policy_locked",
                "Extension policy locked",
                "Latest heartbeat does not report policy_locked=true.",
                "Lock API URL and tenant ID using managed storage policy.",
            )
        )
        checks.append(
            _ok("extension_build_hash", "Extension version/hash", f"Extension {version or 'unknown'} hash {build_hash}.")
            if _valid_build_hash(build_hash) and version
            else _warn(
                "extension_build_hash",
                "Extension version/hash",
                "Latest heartbeat is missing a valid production build hash/version.",
                "Use npm run package:pilot and deploy the packaged folder/zip.",
            )
        )
        version_floor = _version_at_least(version, minimum_version)
        if version_floor is True:
            checks.append(
                _ok(
                    "extension_version_floor",
                    "Extension version floor",
                    f"Extension {version} satisfies minimum managed version {minimum_version}.",
                )
            )
        elif version_floor is False:
            checks.append(
                _fail(
                    "extension_version_floor",
                    "Extension version floor",
                    f"Extension {version} is older than managed minimum {minimum_version}.",
                    "Redeploy the latest packaged extension and ask users to reload/sync.",
                )
            )
        else:
            checks.append(
                _warn(
                    "extension_version_floor",
                    "Extension version floor",
                    "Latest heartbeat is missing or has an invalid minimum extension version.",
                    "Deploy the managed pilot package that reports minimum_extension_version.",
                )
            )
        if source_maps_included is False and dev_files_included is False:
            checks.append(
                _ok(
                    "extension_package_hygiene",
                    "Extension package hygiene",
                    "Latest heartbeat attests source maps and dev files were excluded.",
                )
            )
        elif source_maps_included is True or dev_files_included is True:
            checks.append(
                _fail(
                    "extension_package_hygiene",
                    "Extension package hygiene",
                    "Latest heartbeat reports source maps or dev files in the deployed extension.",
                    "Rebuild with npm run package:pilot and redeploy the clean package.",
                )
            )
        else:
            checks.append(
                _warn(
                    "extension_package_hygiene",
                    "Extension package hygiene",
                    "Latest heartbeat does not attest package hygiene.",
                    "Upgrade to the packaged extension that reports source_maps_included=false and dev_files_included=false.",
                )
            )
        reported_api_url = _normalized_url(
            _first_nonempty(extension_payload, ("api_base_url", "backend_url", "backendUrl"))
        )
        expected_api_url = _normalized_url(settings.api_base_url)
        if expected_api_url:
            if reported_api_url == expected_api_url:
                checks.append(
                    _ok(
                        "extension_api_url_match",
                        "Extension API URL",
                        "Latest heartbeat is pointed at the configured API URL.",
                    )
                )
            elif reported_api_url:
                checks.append(
                    _fail(
                        "extension_api_url_match",
                        "Extension API URL",
                        f"Latest heartbeat API URL is {reported_api_url}, expected {expected_api_url}.",
                        "Update managed browser policy and extension settings to the active API URL.",
                    )
                )
            else:
                checks.append(
                    _warn(
                        "extension_api_url_match",
                        "Extension API URL",
                        "Latest heartbeat did not report an API URL.",
                        "Upgrade/deploy the packaged extension that reports api_base_url/backendUrl in heartbeat.",
                    )
                )
        if expected_tenant_id:
            reported_tenant_id = _first_nonempty(extension_payload, ("tenant_id", "tenantId"))
            if reported_tenant_id == expected_tenant_id:
                checks.append(
                    _ok(
                        "extension_tenant_match",
                        "Extension tenant",
                        "Latest heartbeat tenant matches the active tenant.",
                    )
                )
            elif reported_tenant_id:
                checks.append(
                    _fail(
                        "extension_tenant_match",
                        "Extension tenant",
                        f"Latest heartbeat tenant is {reported_tenant_id}, expected {expected_tenant_id}.",
                        "Update managed browser policy tenant_id and ask users to sync/reload the extension.",
                    )
                )
            else:
                checks.append(
                    _warn(
                        "extension_tenant_match",
                        "Extension tenant",
                        "Latest heartbeat did not report tenant_id.",
                        "Upgrade/deploy the packaged extension that reports tenant_id in heartbeat.",
                    )
                )
    else:
        checks.append(
            _manual(
                "extension_heartbeat",
                "Extension heartbeat",
                "No extension heartbeat is available yet.",
                "Install the managed extension on at least one pilot machine and verify heartbeat.",
            )
        )

    if settings.company_sso_enabled:
        oidc_errors = validate_oidc_configuration()
        if oidc_errors:
            checks.append(
                _fail(
                    "oidc_configuration",
                    "OIDC configuration",
                    "Company SSO is enabled but its OIDC configuration is incomplete or unsafe.",
                    "Correct the OIDC provider, callback, secret, and exact binding configuration before enabling SSO.",
                )
            )
            checks.append(_fail("password_rotation_or_sso", "Password rotation / SSO", "Company SSO configuration failed hardening.", "Correct OIDC configuration before enabling company SSO."))
        else:
            checks.append(_ok("oidc_configuration", "OIDC configuration", "Enabled OIDC providers passed configuration hardening."))
            checks.append(_ok("password_rotation_or_sso", "Password rotation / SSO", "Company SSO is enabled."))
    elif settings.pilot_password_rotation_required:
        checks.append(
            _manual(
                "password_rotation_or_sso",
                "Password rotation / SSO",
                "Company SSO is not enabled and pilot password rotation is required.",
                "Rotate pilot passwords before deployment or move users to SSO.",
            )
        )
    else:
        checks.append(
            _warn(
                "password_rotation_or_sso",
                "Password rotation / SSO",
                "Company SSO is not enabled.",
                "Use company SSO for enterprise deployment.",
            )
        )

    counts = {
        "ok": sum(1 for item in checks if item.status == "ok"),
        "warning": sum(1 for item in checks if item.status == "warning"),
        "failed": sum(1 for item in checks if item.status == "failed"),
        "manual_required": sum(1 for item in checks if item.status == "manual_required"),
    }
    status = "ok"
    if counts["failed"]:
        status = "failed"
    elif counts["warning"] or counts["manual_required"]:
        status = "degraded"

    return {
        "status": status,
        "summary": counts,
        "checks": [item.as_dict() for item in checks],
    }
