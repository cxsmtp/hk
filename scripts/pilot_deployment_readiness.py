#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_EXTENSION_FILES = (
    "manifest.json",
    "options.html",
    "dist/service-worker.js",
    "dist/content-script.js",
    "dist/options.js",
    "build-info.json",
)

FORBIDDEN_EXTENSION_DIRS = {"src", "tests", "node_modules", ".git", "__MACOSX"}
FORBIDDEN_EXTENSION_FILENAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"}
FORBIDDEN_EXTENSION_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".zip"}
BUILD_HASH_RE = re.compile(r"^[a-fA-F0-9]{12,64}$")
TENANT_ID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
EXTENSION_ORIGIN_PREFIXES = ("chrome-extension://", "moz-extension://", "edge-extension://")
WEAK_SECRET_VALUES = {
    "",
    "change-me",
    "changeme",
    "dev",
    "secret",
    "supersecret",
    "password",
    "password123",
    "replace",
}


@dataclass(frozen=True)
class ReadinessCheck:
    category: str
    check_id: str
    status: str
    severity: str
    message: str
    remediation: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "category": self.category,
            "id": self.check_id,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "remediation": self.remediation,
        }


def _ok(category: str, check_id: str, message: str) -> ReadinessCheck:
    return ReadinessCheck(category, check_id, "ok", "info", message)


def _warn(category: str, check_id: str, message: str, remediation: str) -> ReadinessCheck:
    return ReadinessCheck(category, check_id, "warning", "medium", message, remediation)


def _fail(category: str, check_id: str, message: str, remediation: str) -> ReadinessCheck:
    return ReadinessCheck(category, check_id, "failed", "high", message, remediation)


def _warn_or_fail(
    strict: bool,
    category: str,
    check_id: str,
    message: str,
    remediation: str,
) -> ReadinessCheck:
    if strict:
        return _fail(category, check_id, message, remediation)
    return _warn(category, check_id, message, remediation)


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        raise FileNotFoundError(f".env file not found: {path}")
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key:
            values[key] = value
    return values


def _as_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _is_postgres(url: str | None) -> bool:
    return str(url or "").lower().startswith(("postgresql://", "postgresql+psycopg2://", "postgresql+asyncpg://"))


def _is_sqlite(url: str | None) -> bool:
    raw = str(url or "").lower()
    return raw.startswith("sqlite:") or raw.endswith(".db") or raw.endswith(".sqlite") or raw.endswith(".sqlite3")


def _is_redis(url: str | None) -> bool:
    return str(url or "").lower().startswith(("redis://", "rediss://"))


def _is_http_url(url: str | None) -> bool:
    try:
        parsed = urlparse(str(url or ""))
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _secret_is_strong(secret: str | None) -> bool:
    raw = str(secret or "").strip()
    return len(raw) >= 32 and raw.lower() not in WEAK_SECRET_VALUES and "replace" not in raw.lower()


def _contains_origin(raw: str | None, expected: str | None) -> bool:
    if not expected:
        return True
    origins = [item.strip() for item in str(raw or "").split(",") if item.strip()]
    return expected in origins


def _split_csv(raw: str | None) -> list[str]:
    return [item.strip().rstrip("/") for item in str(raw or "").split(",") if item.strip()]


def _is_wildcard_origin(origin: str) -> bool:
    normalized = str(origin or "").strip().rstrip("/")
    if normalized == "*":
        return True
    return any(normalized == f"{prefix}*" for prefix in EXTENSION_ORIGIN_PREFIXES)


def _is_explicit_extension_origin(origin: str) -> bool:
    normalized = str(origin or "").strip().rstrip("/")
    return any(
        normalized.startswith(prefix)
        and normalized != f"{prefix}*"
        and len(normalized) > len(prefix)
        for prefix in EXTENSION_ORIGIN_PREFIXES
    )


def _has_extension_origin_wildcard(raw: str | None) -> bool:
    return any(_is_wildcard_origin(origin) for origin in _split_csv(raw))


def _has_explicit_extension_origin(raw: str | None) -> bool:
    return any(_is_explicit_extension_origin(origin) for origin in _split_csv(raw))


def evaluate_api_env(
    env: dict[str, str],
    *,
    expected_api_url: str | None = None,
    expected_web_origin: str | None = None,
    require_https: bool = False,
    strict_50_user: bool = False,
) -> list[ReadinessCheck]:
    checks: list[ReadinessCheck] = []

    checks.append(
        _ok("api", "pilot_env", "ENV is pilot.")
        if env.get("ENV", env.get("ENVIRONMENT", "")).lower() == "pilot"
        else _fail("api", "pilot_env", "ENV is not set to pilot.", "Set ENV=pilot for the 50-user local pilot.")
    )
    checks.append(
        _ok("api", "pilot_mode", "PILOT_MODE=true.")
        if _as_bool(env.get("PILOT_MODE"))
        else _fail("api", "pilot_mode", "PILOT_MODE is not true.", "Set PILOT_MODE=true.")
    )
    checks.append(
        _ok("api", "demo_mode_off", "DEMO_MODE is disabled or unset.")
        if not _as_bool(env.get("DEMO_MODE"))
        else _fail("api", "demo_mode_off", "DEMO_MODE is enabled.", "Set DEMO_MODE=false before pilot deployment.")
    )

    database_url = env.get("DATABASE_URL")
    if _is_postgres(database_url):
        checks.append(_ok("api", "database_postgresql", "DATABASE_URL uses PostgreSQL."))
    elif _is_sqlite(database_url):
        checks.append(
            _fail(
                "api",
                "database_postgresql",
                "DATABASE_URL points to SQLite/local file storage.",
                "Use local PostgreSQL for a 50-user pilot.",
            )
        )
    else:
        checks.append(
            _fail(
                "api",
                "database_postgresql",
                "DATABASE_URL is missing or not PostgreSQL.",
                "Set DATABASE_URL=postgresql+psycopg2://...",
            )
        )

    checks.append(
        _ok("api", "secret_key_strength", "SECRET_KEY is present and long enough.")
        if _secret_is_strong(env.get("SECRET_KEY"))
        else _fail(
            "api",
            "secret_key_strength",
            "SECRET_KEY is missing, weak, default, or shorter than 32 characters.",
            "Generate a fresh 32+ byte SECRET_KEY.",
        )
    )
    checks.append(
        _ok("api", "secret_key_lock", "SECRET_KEY lock is enabled.")
        if _as_bool(env.get("SECRET_KEY_LOCK_ENABLED"))
        else _fail("api", "secret_key_lock", "SECRET_KEY lock is not enabled.", "Set SECRET_KEY_LOCK_ENABLED=true.")
    )

    api_base_url = env.get("API_BASE_URL")
    if _is_http_url(api_base_url):
        checks.append(_ok("api", "api_base_url", f"API_BASE_URL is {api_base_url}."))
    else:
        checks.append(_fail("api", "api_base_url", "API_BASE_URL is missing or invalid.", "Set API_BASE_URL to the API host URL."))
    if expected_api_url and api_base_url != expected_api_url:
        checks.append(
            _fail(
                "api",
                "api_base_url_expected",
                f"API_BASE_URL is {api_base_url or 'unset'}, expected {expected_api_url}.",
                "Update API_BASE_URL or rerun the readiness check with the correct expected URL.",
            )
        )
    elif expected_api_url:
        checks.append(_ok("api", "api_base_url_expected", "API_BASE_URL matches the expected pilot URL."))

    web_origin = env.get("WEB_ORIGIN")
    if _is_http_url(web_origin):
        checks.append(_ok("api", "web_origin", f"WEB_ORIGIN is {web_origin}."))
    else:
        checks.append(_fail("api", "web_origin", "WEB_ORIGIN is missing or invalid.", "Set WEB_ORIGIN to the admin UI origin."))
    if expected_web_origin and web_origin != expected_web_origin:
        checks.append(
            _fail(
                "api",
                "web_origin_expected",
                f"WEB_ORIGIN is {web_origin or 'unset'}, expected {expected_web_origin}.",
                "Update WEB_ORIGIN for the Mac UI origin.",
            )
        )
    elif expected_web_origin:
        checks.append(_ok("api", "web_origin_expected", "WEB_ORIGIN matches the expected pilot UI origin."))
    if expected_web_origin and env.get("CORS_ORIGINS"):
        checks.append(
            _ok("api", "cors_origin_expected", "CORS_ORIGINS includes the expected UI origin.")
            if _contains_origin(env.get("CORS_ORIGINS"), expected_web_origin)
            else _fail(
                "api",
                "cors_origin_expected",
                "CORS_ORIGINS does not include the expected UI origin.",
                "Add the Mac UI origin to CORS_ORIGINS.",
            )
        )

    extension_cors_origins = env.get("EXTENSION_CORS_ORIGINS")
    if _has_extension_origin_wildcard(env.get("CORS_ORIGINS")) or _has_extension_origin_wildcard(extension_cors_origins):
        checks.append(
            _fail(
                "api",
                "extension_cors_origins",
                "Extension CORS origins use a wildcard.",
                "Set EXTENSION_CORS_ORIGINS to exact chrome-extension://<id> origins.",
            )
        )
    elif _has_explicit_extension_origin(extension_cors_origins):
        checks.append(_ok("api", "extension_cors_origins", "Extension CORS origins are explicitly pinned."))
    else:
        checks.append(
            _fail(
                "api",
                "extension_cors_origins",
                "EXTENSION_CORS_ORIGINS is missing or has no explicit extension ID.",
                "Set EXTENSION_CORS_ORIGINS=chrome-extension://<id> for the managed pilot extension.",
            )
        )

    api_scheme = urlparse(api_base_url or "").scheme
    web_scheme = urlparse(web_origin or "").scheme
    if require_https or _as_bool(env.get("REQUIRE_HTTPS_FOR_PILOT")) or strict_50_user:
        checks.append(
            _ok("api", "https_required", "HTTPS is required and configured for API/UI origins.")
            if api_scheme == "https" and web_scheme == "https"
            else _fail(
                "api",
                "https_required",
                "HTTPS is required but API_BASE_URL/WEB_ORIGIN are not both HTTPS.",
                "Put API and UI behind HTTPS or disable this only for a closed lab.",
            )
        )
    elif api_scheme == "https" and web_scheme == "https":
        checks.append(_ok("api", "https_preferred", "API and UI use HTTPS."))
    else:
        checks.append(
            _warn_or_fail(
                strict_50_user,
                "api",
                "https_preferred",
                "API/UI are using HTTP.",
                "Use HTTPS for the pilot when possible, even internally.",
            )
        )

    attestations = (
        ("disk_encryption", "DISK_ENCRYPTION_CONFIRMED", "Confirm FileVault/BitLocker and set DISK_ENCRYPTION_CONFIRMED=true."),
        (
            "api_network_restricted",
            "API_NETWORK_RESTRICTION_CONFIRMED",
            "Restrict the API port to the pilot LAN and set API_NETWORK_RESTRICTION_CONFIRMED=true.",
        ),
        ("backup_configured", "BACKUP_CONFIGURED", "Schedule encrypted PostgreSQL backups and set BACKUP_CONFIGURED=true."),
    )
    for check_id, key, remediation in attestations:
        checks.append(
            _ok("api", check_id, f"{key}=true.")
            if _as_bool(env.get(key))
            else _fail("api", check_id, f"{key} is not true.", remediation)
        )

    for key, check_id in (("EVIDENCE_RETENTION_DAYS", "evidence_retention"), ("REPORT_RETENTION_DAYS", "report_retention")):
        try:
            days = int(env.get(key, "0"))
        except ValueError:
            days = 0
        if 30 <= days <= 90:
            checks.append(_ok("api", check_id, f"{key}={days}."))
        elif 1 <= days < 30:
            checks.append(
                _warn(
                    "api",
                    check_id,
                    f"{key}={days}, below the recommended audit/reporting floor.",
                    f"Use {key}=90 for the pilot, or at least 30 days for credible investigation history.",
                )
            )
        elif days > 90:
            checks.append(_warn("api", check_id, f"{key}={days}, above the recommended pilot default.", f"Use {key}=90 unless legal requires longer."))
        else:
            checks.append(_fail("api", check_id, f"{key} is missing or invalid.", f"Set {key}=90 for the pilot."))

    incognito_policy = env.get("INCOGNITO_POLICY", "").lower()
    checks.append(
        _ok("api", "incognito_policy", f"INCOGNITO_POLICY={incognito_policy}.")
        if incognito_policy in {"disabled", "enabled_monitored"}
        else _fail(
            "api",
            "incognito_policy",
            "INCOGNITO_POLICY is missing or not explicit.",
            "Set INCOGNITO_POLICY=disabled or enabled_monitored and align browser policy.",
        )
    )

    for key, check_id in (
        ("FAIL_SECURE_MODE", "fail_secure"),
        ("GOVERNANCE_STRICT_MODE", "governance_strict"),
        ("CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS", "strict_dependency_checks"),
    ):
        checks.append(
            _ok("api", check_id, f"{key}=true.")
            if _as_bool(env.get(key))
            else _warn_or_fail(
                strict_50_user,
                "api",
                check_id,
                f"{key} is not true.",
                f"Set {key}=true for production-like pilot behavior.",
            )
        )

    checks.append(
        _ok("api", "sensitive_raw_prompt_logging_off", "Sensitive raw prompt logging is disabled.")
        if not _as_bool(env.get("PROMPT_LOGGING_ALLOW_SENSITIVE_RAW"))
        else _fail(
            "api",
            "sensitive_raw_prompt_logging_off",
            "PROMPT_LOGGING_ALLOW_SENSITIVE_RAW=true.",
            "Set PROMPT_LOGGING_ALLOW_SENSITIVE_RAW=false before pilot deployment.",
        )
    )

    for key, check_id in (
        ("REDIS_URL", "redis_url"),
        ("CELERY_BROKER_URL", "celery_broker"),
        ("CELERY_RESULT_BACKEND", "celery_result_backend"),
    ):
        value = env.get(key)
        checks.append(
            _ok("api", check_id, f"{key} is configured.")
            if _is_redis(value)
            else _warn_or_fail(
                strict_50_user,
                "api",
                check_id,
                f"{key} is missing or not Redis.",
                f"Set {key}=redis://127.0.0.1:6379/0 for local pilot workers.",
            )
        )

    return checks


def _read_json(path: Path) -> dict[str, object]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def evaluate_extension_package(
    extension_dir: Path,
    *,
    expected_api_url: str | None = None,
    expected_tenant_id: str | None = None,
    strict_50_user: bool = False,
) -> list[ReadinessCheck]:
    checks: list[ReadinessCheck] = []

    if not extension_dir.exists():
        return [
            _fail(
                "extension",
                "package_exists",
                f"Extension package directory does not exist: {extension_dir}",
                "Run npm run package:pilot and point this script at the generated package folder.",
            )
        ]
    checks.append(_ok("extension", "package_exists", f"Extension package exists: {extension_dir}"))

    for rel_path in REQUIRED_EXTENSION_FILES:
        file_path = extension_dir / rel_path
        checks.append(
            _ok("extension", f"required_file_{rel_path}", f"Found {rel_path}.")
            if file_path.exists()
            else _fail("extension", f"required_file_{rel_path}", f"Missing {rel_path}.", "Rebuild with npm run package:pilot.")
        )

    files = [path for path in extension_dir.rglob("*") if path.is_file()]
    bad_metadata = []
    bad_dev_dirs = []
    bad_source_files = []
    bad_source_map_markers = []
    bad_sensitive_files = []
    token_like_files = []
    for file_path in files:
        rel = file_path.relative_to(extension_dir)
        parts = set(rel.parts)
        lower_name = file_path.name.lower()
        if file_path.name.startswith("._") or file_path.name == ".DS_Store":
            bad_metadata.append(str(rel))
        if parts.intersection(FORBIDDEN_EXTENSION_DIRS):
            bad_dev_dirs.append(str(rel))
        if lower_name in FORBIDDEN_EXTENSION_FILENAMES or file_path.suffix.lower() in FORBIDDEN_EXTENSION_SUFFIXES:
            bad_sensitive_files.append(str(rel))
        if file_path.suffix.lower() in {".map", ".ts", ".tsx"}:
            bad_source_files.append(str(rel))
        if file_path.suffix.lower() == ".js":
            body = file_path.read_text(encoding="utf-8", errors="ignore")
            if "sourceMappingURL=" in body:
                bad_source_map_markers.append(str(rel))
            if re.search(r"(accessToken|refreshToken|Authorization\\s*:|Bearer\\s+[A-Za-z0-9_-]{20,})", body):
                token_like_files.append(str(rel))

    checks.append(
        _ok("extension", "no_macos_metadata", "No AppleDouble/.DS_Store metadata found.")
        if not bad_metadata
        else _fail("extension", "no_macos_metadata", f"Metadata files found: {', '.join(bad_metadata[:5])}", "Delete metadata files before sharing.")
    )
    checks.append(
        _ok("extension", "no_dev_dirs", "No dev/source dependency directories included.")
        if not bad_dev_dirs
        else _fail("extension", "no_dev_dirs", f"Dev directories included: {', '.join(bad_dev_dirs[:5])}", "Package only runtime files.")
    )
    checks.append(
        _ok("extension", "no_sensitive_artifacts", "No env/key/certificate/archive artifacts found.")
        if not bad_sensitive_files
        else _fail(
            "extension",
            "no_sensitive_artifacts",
            f"Sensitive deployment artifacts included: {', '.join(bad_sensitive_files[:5])}",
            "Remove env files, keys, certificates, and nested archives from the extension package.",
        )
    )
    checks.append(
        _ok("extension", "no_source_or_sourcemaps", "No TypeScript or sourcemap files included.")
        if not bad_source_files
        else _fail("extension", "no_source_or_sourcemaps", f"Source/sourcemap files included: {', '.join(bad_source_files[:5])}", "Rebuild the packaged pilot extension.")
    )
    checks.append(
        _ok("extension", "no_source_mapping_url", "No sourceMappingURL markers found.")
        if not bad_source_map_markers
        else _fail(
            "extension",
            "no_source_mapping_url",
            f"sourceMappingURL markers found: {', '.join(bad_source_map_markers[:5])}",
            "Disable source map output and rebuild.",
        )
    )
    checks.append(
        _ok("extension", "no_token_literals", "No obvious token/Authorization literals found in packaged JS.")
        if not token_like_files
        else _warn(
            "extension",
            "no_token_literals",
            f"Token-like literals found in JS: {', '.join(token_like_files[:5])}",
            "Review these files to confirm tokens are not hard-coded or logged.",
        )
    )

    try:
        manifest = _read_json(extension_dir / "manifest.json")
        version = str(manifest.get("version") or "")
        name = str(manifest.get("name") or "")
        checks.append(_ok("extension", "manifest_valid", f"Manifest valid: {name} {version}.") if name and version else _fail("extension", "manifest_valid", "Manifest missing name/version.", "Fix manifest.json and rebuild."))
    except Exception as exc:  # noqa: BLE001 - CLI needs user-readable validation.
        checks.append(_fail("extension", "manifest_valid", f"manifest.json is invalid: {exc}", "Fix manifest.json and rebuild."))

    try:
        build_info = _read_json(extension_dir / "build-info.json")
        build_hash = str(build_info.get("build_hash") or "")
        source_maps = build_info.get("source_maps_included")
        dev_files = build_info.get("dev_files_included")
        if BUILD_HASH_RE.fullmatch(build_hash) and source_maps is False and dev_files is False:
            checks.append(_ok("extension", "build_info_hardened", f"Build hash {build_hash}; source/dev files excluded."))
        else:
            checks.append(
                _fail(
                    "extension",
                    "build_info_hardened",
                    "build-info.json does not attest hardened package output.",
                    "Rebuild with npm run package:pilot.",
                )
            )
    except Exception as exc:  # noqa: BLE001
        checks.append(_fail("extension", "build_info_hardened", f"build-info.json is invalid: {exc}", "Rebuild with npm run package:pilot."))

    managed_candidates = [extension_dir / "managed-config.json", extension_dir / "policy.json", extension_dir / "pilot-managed-policy.json"]
    managed_payload: dict[str, object] | None = None
    managed_path: Path | None = None
    for candidate in managed_candidates:
        if candidate.exists():
            try:
                managed_payload = _read_json(candidate)
                managed_path = candidate
                break
            except Exception:
                managed_payload = None
                managed_path = candidate
                break
    if managed_payload is None:
        checks.append(
            _warn_or_fail(
                strict_50_user,
                "extension",
                "managed_policy_file",
                "No managed policy JSON was found next to the package.",
                "Deploy Chrome/Edge managed storage separately and lock api_base_url, tenant_id, policy_locked, and enterprise_managed.",
            )
        )
    else:
        checks.append(_ok("extension", "managed_policy_file", f"Managed policy file found: {managed_path.name if managed_path else 'unknown'}"))
        api_url = str(managed_payload.get("api_base_url") or managed_payload.get("backendUrl") or "")
        tenant_id = str(managed_payload.get("tenant_id") or managed_payload.get("tenantId") or "")
        minimum_extension_version = str(
            managed_payload.get("minimum_extension_version") or managed_payload.get("minimumExtensionVersion") or ""
        )
        incognito_policy = str(managed_payload.get("incognito_policy") or managed_payload.get("incognitoPolicy") or "").lower()
        policy_locked = _as_bool(str(managed_payload.get("policy_locked") or managed_payload.get("policyLocked") or ""))
        enterprise_managed = _as_bool(str(managed_payload.get("enterprise_managed") or managed_payload.get("enterpriseManaged") or ""))
        checks.append(
            _ok("extension", "managed_policy_locked", "Managed policy locks user-editable settings.")
            if policy_locked and enterprise_managed
            else _fail(
                "extension",
                "managed_policy_locked",
                "Managed policy does not set policy_locked=true and enterprise_managed=true.",
                "Update managed browser policy before pilot rollout.",
            )
        )
        checks.append(
            _ok("extension", "managed_api_url_valid", "Managed policy pins a valid API URL.")
            if _is_http_url(api_url)
            else _fail(
                "extension",
                "managed_api_url_valid",
                "Managed policy API URL is missing or invalid.",
                "Set api_base_url to the active local Hawk API URL.",
            )
        )
        checks.append(
            _ok("extension", "managed_tenant_valid", "Managed policy pins a valid tenant ID.")
            if TENANT_ID_RE.fullmatch(tenant_id)
            else _fail(
                "extension",
                "managed_tenant_valid",
                "Managed policy tenant_id is missing or invalid.",
                "Set tenant_id to the active pilot tenant UUID.",
            )
        )
        checks.append(
            _ok("extension", "managed_minimum_extension_version", f"Managed policy requires extension {minimum_extension_version} or newer.")
            if SEMVER_RE.fullmatch(minimum_extension_version)
            else _fail(
                "extension",
                "managed_minimum_extension_version",
                "Managed policy does not define a valid minimum_extension_version.",
                "Repackage with npm run package:pilot so stale extensions can be detected.",
            )
        )
        if incognito_policy:
            checks.append(
                _ok("extension", "managed_incognito_policy", f"Managed policy incognito posture is {incognito_policy}.")
                if incognito_policy in {"disabled", "enabled_monitored"}
                else _fail(
                    "extension",
                    "managed_incognito_policy",
                    f"Managed policy incognito posture is invalid: {incognito_policy}.",
                    "Use incognito_policy=disabled or enabled_monitored.",
                )
            )
        if expected_api_url:
            checks.append(
                _ok("extension", "managed_api_url_expected", "Managed policy API URL matches expected URL.")
                if api_url == expected_api_url
                else _fail(
                    "extension",
                    "managed_api_url_expected",
                    f"Managed policy API URL is {api_url or 'unset'}, expected {expected_api_url}.",
                    "Update managed browser policy API URL.",
                )
            )
        if expected_tenant_id:
            checks.append(
                _ok("extension", "managed_tenant_expected", "Managed policy tenant ID matches expected tenant.")
                if tenant_id == expected_tenant_id
                else _fail(
                    "extension",
                    "managed_tenant_expected",
                    f"Managed policy tenant is {tenant_id or 'unset'}, expected {expected_tenant_id}.",
                    "Update managed browser policy tenant_id.",
                )
            )

    return checks


def summarize(checks: list[ReadinessCheck]) -> dict[str, object]:
    counts = {
        "ok": sum(1 for item in checks if item.status == "ok"),
        "warning": sum(1 for item in checks if item.status == "warning"),
        "failed": sum(1 for item in checks if item.status == "failed"),
    }
    status = "failed" if counts["failed"] else "degraded" if counts["warning"] else "ok"
    return {"status": status, "summary": counts, "checks": [item.as_dict() for item in checks]}


def print_human(payload: dict[str, object]) -> None:
    print(f"Pilot deployment readiness: {payload['status']}")
    summary = payload["summary"]
    if isinstance(summary, dict):
        print(f"Checks: ok={summary.get('ok', 0)} warning={summary.get('warning', 0)} failed={summary.get('failed', 0)}")
    print("")
    checks = payload["checks"]
    if not isinstance(checks, list):
        return
    for raw_check in checks:
        if not isinstance(raw_check, dict):
            continue
        marker = {"ok": "OK", "warning": "WARN", "failed": "FAIL"}.get(str(raw_check.get("status")), "INFO")
        print(f"[{marker}] {raw_check.get('category')}:{raw_check.get('id')} - {raw_check.get('message')}")
        remediation = str(raw_check.get("remediation") or "")
        if remediation:
            print(f"      fix: {remediation}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Hawk local pilot readiness before 50-user rollout.")
    parser.add_argument("--api-env", type=Path, default=Path("apps/api/.env"), help="Path to API .env file.")
    parser.add_argument("--extension-dir", type=Path, help="Path to packaged pilot extension folder.")
    parser.add_argument("--expected-api-url", help="Expected API URL, for example http://192.168.102.35:8000.")
    parser.add_argument("--expected-web-origin", help="Expected web UI origin, for example http://192.168.102.10:3000.")
    parser.add_argument("--expected-tenant-id", help="Expected tenant ID in managed extension policy.")
    parser.add_argument("--require-https", action="store_true", help="Fail unless API and UI origins are HTTPS.")
    parser.add_argument(
        "--strict-50-user",
        action="store_true",
        help="Promote rollout-critical warnings to failures for 50-user pilot deployment gates.",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checks: list[ReadinessCheck] = []
    try:
        env = parse_env_file(args.api_env)
    except Exception as exc:  # noqa: BLE001
        checks.append(_fail("api", "env_file", str(exc), "Create the API .env before running readiness."))
        env = {}
    if env:
        checks.extend(
            evaluate_api_env(
                env,
                expected_api_url=args.expected_api_url,
                expected_web_origin=args.expected_web_origin,
                require_https=args.require_https,
                strict_50_user=args.strict_50_user,
            )
        )
    if args.extension_dir:
        checks.extend(
            evaluate_extension_package(
                args.extension_dir,
                expected_api_url=args.expected_api_url,
                expected_tenant_id=args.expected_tenant_id,
                strict_50_user=args.strict_50_user,
            )
        )
    else:
        checks.append(
            _warn_or_fail(
                args.strict_50_user,
                "extension",
                "extension_package_not_checked",
                "No --extension-dir supplied; extension package was not checked.",
                "Run with --extension-dir pointing at the exact folder you will share with pilot users.",
            )
        )

    payload = summarize(checks)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print_human(payload)
    return 1 if payload["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
