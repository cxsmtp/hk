from __future__ import annotations

import hashlib
import json
import os
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.fernet import Fernet, InvalidToken

from app.services.production_hardening import (
    DEFAULT_SECRET_FILE_KEYS,
    load_secret_file_environment,
    validate_production_configuration,
)

_SECRET_KEY_LOCK_VERSION = 1
_API_ROOT_DIR = Path(__file__).resolve().parents[2]
_CONFIG_SECRET_SOURCES = load_secret_file_environment(allowed_keys=DEFAULT_SECRET_FILE_KEYS)


def siem_pseudonymization_key_is_obviously_predictable(value: str) -> bool:
    token = str(value or "").strip().casefold()
    if not token:
        return False
    placeholder_fragments = (
        "changeme",
        "change-me",
        "placeholder",
        "replace-with",
        "replace_me",
        "replace-me",
        "not-a-real",
        "example-key",
        "sample-key",
        "your-secret",
        "your_key",
        "password",
    )
    if any(fragment in token for fragment in placeholder_fragments):
        return True
    if len(set(token)) <= 4:
        return True
    for period in range(1, min(8, len(token) // 2) + 1):
        if len(token) % period == 0 and token == token[:period] * (len(token) // period):
            return True

    compact = "".join(character for character in token if character.isalnum())
    for cycle in ("0123456789", "abcdefghijklmnopqrstuvwxyz"):
        if len(compact) < len(cycle):
            continue
        for candidate_cycle in (cycle, cycle[::-1]):
            for offset in range(len(candidate_cycle)):
                rotated = candidate_cycle[offset:] + candidate_cycle[:offset]
                expected = (rotated * ((len(compact) // len(rotated)) + 1))[: len(compact)]
                if compact == expected:
                    return True
    return False


def parse_control_coverage_rollout(value: str) -> dict[str, bool]:
    duplicate_tenants: set[str] = set()

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for tenant_id, enabled in pairs:
            if tenant_id in decoded:
                duplicate_tenants.add(tenant_id)
            decoded[tenant_id] = enabled
        return decoded

    try:
        payload = json.loads(str(value or "{}"), object_pairs_hook=_object)
    except json.JSONDecodeError as exc:
        raise ValueError("CONTROL_COVERAGE_ROLLOUT must be valid JSON.") from exc
    if not isinstance(payload, dict) or duplicate_tenants:
        raise ValueError("CONTROL_COVERAGE_ROLLOUT must be a JSON object with unique tenant IDs.")
    normalized: dict[str, bool] = {}
    for tenant_id, enabled in payload.items():
        normalized_tenant = str(tenant_id or "").strip()
        if not normalized_tenant or len(normalized_tenant) > 128 or normalized_tenant in normalized:
            raise ValueError("CONTROL_COVERAGE_ROLLOUT tenant IDs must be unique, non-empty, and at most 128 characters.")
        if not isinstance(enabled, bool):
            raise ValueError("CONTROL_COVERAGE_ROLLOUT values must be booleans.")
        normalized[normalized_tenant] = enabled
    return normalized


def parse_maturity_curve_rollout(value: str) -> dict[str, bool]:
    """Parse the explicit tenant allow-list for Maturity Curve writes/API.

    Keeping this separate from Control Coverage prevents a global feature flag
    from accidentally materializing tenant-derived policy intelligence.
    """

    duplicate_tenants: set[str] = set()

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for tenant_id, enabled in pairs:
            if tenant_id in decoded:
                duplicate_tenants.add(tenant_id)
            decoded[tenant_id] = enabled
        return decoded

    try:
        payload = json.loads(str(value or "{}"), object_pairs_hook=_object)
    except json.JSONDecodeError as exc:
        raise ValueError("MATURITY_CURVE_POLICY_INTELLIGENCE_ROLLOUT must be valid JSON.") from exc
    if not isinstance(payload, dict) or duplicate_tenants:
        raise ValueError("MATURITY_CURVE_POLICY_INTELLIGENCE_ROLLOUT must be a JSON object with unique tenant IDs.")
    normalized: dict[str, bool] = {}
    for tenant_id, enabled in payload.items():
        normalized_tenant = str(tenant_id or "").strip()
        if not normalized_tenant or len(normalized_tenant) > 128 or normalized_tenant in normalized:
            raise ValueError(
                "MATURITY_CURVE_POLICY_INTELLIGENCE_ROLLOUT tenant IDs must be unique, non-empty, and at most 128 characters."
            )
        if not isinstance(enabled, bool):
            raise ValueError("MATURITY_CURVE_POLICY_INTELLIGENCE_ROLLOUT values must be booleans.")
        normalized[normalized_tenant] = enabled
    return normalized


def parse_policy_pack_platform_rollout(value: str) -> dict[str, bool]:
    """Parse the explicit tenant allow-list for Policy Pack Platform APIs.

    A global switch alone is deliberately insufficient because pack application
    can materialize customer policy configuration. This keeps rollout tenant
    scoped and prevents a UI-only entitlement bypass.
    """

    duplicate_tenants: set[str] = set()

    def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        decoded: dict[str, object] = {}
        for tenant_id, enabled in pairs:
            if tenant_id in decoded:
                duplicate_tenants.add(tenant_id)
            decoded[tenant_id] = enabled
        return decoded

    try:
        payload = json.loads(str(value or "{}"), object_pairs_hook=_object)
    except json.JSONDecodeError as exc:
        raise ValueError("POLICY_PACK_PLATFORM_ROLLOUT must be valid JSON.") from exc
    if not isinstance(payload, dict) or duplicate_tenants:
        raise ValueError("POLICY_PACK_PLATFORM_ROLLOUT must be a JSON object with unique tenant IDs.")
    normalized: dict[str, bool] = {}
    for tenant_id, enabled in payload.items():
        normalized_tenant = str(tenant_id or "").strip()
        if not normalized_tenant or len(normalized_tenant) > 128 or normalized_tenant in normalized:
            raise ValueError("POLICY_PACK_PLATFORM_ROLLOUT tenant IDs must be unique, non-empty, and at most 128 characters.")
        if not isinstance(enabled, bool):
            raise ValueError("POLICY_PACK_PLATFORM_ROLLOUT values must be booleans.")
        normalized[normalized_tenant] = enabled
    return normalized


def parse_provider_signal_retention_rollout(value: str) -> dict[str, bool]:
    """Parse the explicit tenant allow-list for provider-signal retention.

    Candidate reporting is harmless, but destructive execution remains disabled
    until both the global switch and this tenant-specific allow-list agree.
    """

    return parse_control_coverage_rollout(value)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "AI Control Plane API"
    env: str = "dev"
    pilot_mode: bool = False
    demo_mode: bool = False
    self_registration_enabled: bool = False
    deployment_id: str = "local-development"
    deployment_region: str = "local-development"
    deployment_data_location: str = "local-development"
    deployment_topology: str = "development"
    component_type: str = "api"
    # Logs (app/core/log_config.py): one line per event on stdout. LOG_FORMAT=json (one JSON object a line, as
    # deploy/compose.yaml sets it) or text (easier to read on a laptop); LOG_LEVEL=DEBUG|INFO|WARNING|ERROR.
    log_format: str = "text"
    log_level: str = "INFO"
    component_version: str = "0.1.0"
    component_protocol_version: str = "1.0"
    minimum_component_versions_json: str = (
        '{"api":"0.1.0","worker":"0.1.0","celery_beat":"0.1.0","web":"0.1.0"}'
    )
    # First run (deploy/README.md, app/services/first_run_service.py): the API's own data folder (0700) holds the
    # generated first administrator's password (0600) until they choose their own; it is never in a backup.
    hawk_data_dir: str = ".runtime/data"
    # Make the first administrator when the API starts on an empty database (deploy/compose.yaml turns it on).
    first_run_access: bool = False

    database_url: str  # Supply DATABASE_URL through the deployment environment.
    redis_url: str = "redis://redis:6379/0"
    sqlite_lock_timeout_seconds: int = 8
    sqlite_busy_timeout_ms: int = 8000
    sqlite_dashboard_fast_timeout_ms: int = 500
    sqlite_interaction_eval_busy_timeout_ms: int = 400

    secret_key: str
    secret_key_lock_enabled: bool = True
    secret_key_lock_file: str = ".runtime/secret_key.lock"
    secret_key_lock_pepper: str = ""
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_minutes: int = 60 * 24 * 7
    # Sign-in (docs/sign-in.md, ported from CxMissionZero): a sign-in that is not used for this long ends. Hawk's
    # console keeps a 30-minute access token and a rotating refresh token; a refresh token that was not used (rotated)
    # for SESSION_IDLE_MINUTES is refused, so the person signs in again.
    session_idle_minutes: int = 480
    # Where sign-in tickets, password reset links, pending two-step setups and the sign-in limits are kept: "redis"
    # (REDIS_URL; every API process sees the same) or "memory" (one process only: tests and local runs).
    sign_in_store: str = "redis"
    # The email server, for password reset links (CxMissionZero's SMTP_* variables, same names and defaults).
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_secure: bool = False
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""
    smtp_from_name: str = "Hawk AI"

    web_origin: str = "http://localhost:3000"
    cors_origins: str = ""
    extension_cors_origins: str = ""
    api_base_url: str = ""
    trusted_hosts: str = "localhost,127.0.0.1,testserver"
    max_request_body_bytes: int = 2_097_152
    require_https_for_pilot: bool = False
    disk_encryption_confirmed: bool = False
    api_network_restriction_confirmed: bool = False
    backup_configured: bool = False
    evidence_retention_days: int = 90
    report_retention_days: int = 90
    provider_signal_retention_execution_enabled: bool = False
    provider_signal_retention_rollout: str = "{}"
    incognito_policy: str = "disabled"
    company_sso_enabled: bool = False
    # OIDC metadata is public configuration; client secrets and binding records
    # are kept in separate encrypted configuration values.
    oidc_providers_json: str = "[]"
    oidc_provider_secrets_json: str = ""
    oidc_bindings_json: str = "[]"
    oidc_callback_url: str = ""
    oidc_frontend_url: str = ""
    # CxMissionZero keeps a single sign-on round trip ten minutes (SSO_FLOW_TTL_MS).
    oidc_state_ttl_seconds: int = 600
    oidc_ticket_ttl_seconds: int = 60
    oidc_cache_ttl_seconds: int = 300
    oidc_cache_max_bytes: int = 262144
    pilot_password_rotation_required: bool = True
    celery_broker_url: str = "redis://redis:6379/1"
    celery_result_backend: str = "redis://redis:6379/2"
    # Allows a bounded operational recovery to defer the heavyweight hourly
    # coverage aggregation without disabling ordinary 15-minute monitoring.
    monitoring_hourly_coverage_enabled: bool = True
    connector_secrets_key: str
    connector_secrets_kdf_salt: str
    connector_secrets_kdf_iterations: int = 390000
    outbound_destination_allowlist: str = "{}"
    enforcement_payloads_key: str = ""
    llm_router_mode: str = "council"
    llm_provider: str = "openai"
    llm_api_key: str = ""
    llm_base_url: Optional[str] = None
    llm_api_version: Optional[str] = None
    llm_model: str = ""
    openai_api_key: str = ""
    openai_model: str = ""
    openai_base_url: Optional[str] = None
    openai_reasoning_effort: Optional[str] = None
    anthropic_api_key: str = ""
    anthropic_model: str = ""
    gemini_api_key: str = ""
    gemini_model: str = ""
    llm_timeout_secs: int = 30
    llm_temperature: float = 0.0
    llm_max_tokens: int = 1200

    @field_validator("openai_reasoning_effort")
    @classmethod
    def _validate_openai_reasoning_effort(cls, value: str | None) -> str | None:
        if value is not None and value != "none":
            raise ValueError("OPENAI_REASONING_EFFORT supports only 'none'.")
        return value

    @field_validator("log_format", mode="before")
    @classmethod
    def _normalize_log_format(cls, value: object) -> str:
        # A typo never stops the start: anything but "text" is the JSON a deployment reads.
        return "text" if str(value or "").strip().lower() == "text" else "json"

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalize_log_level(cls, value: object) -> str:
        text = str(value or "").strip().upper()
        return text if text in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"} else "INFO"
    enforcement_contract_mode: str = "v1"
    llm_intercept_qps_per_tenant: int = 10
    mcp_authorize_qps_per_tenant: int = 20
    mcp_persisted_sessions_required: bool = False
    rate_limit_window_seconds: float = 1.0
    gateway_intercept_minimal_mode: bool = False
    fail_secure_mode: bool = True
    governance_strict_mode: bool = True
    event_dual_write_legacy: bool = True
    canonical_ai_action_dual_write_enabled: bool = False
    discovery_context_provider: bool = False
    canonical_action_binding_key: str = ""
    authorization_kernel_v2_enabled: bool = False
    authorization_kernel_shadow_compare_enabled: bool = False
    authorization_kernel_v2_enforce: bool = False
    authorization_kernel_v2_enforce_rollout: str = "{}"
    decision_execution_receipts_enabled: bool = False
    receipt_signing_active_key_id: str = ""
    receipt_signing_keys_json: str = "{}"
    banking_transaction_integrity_enabled: bool = False
    banking_subject_trust_json: str = "{}"
    banking_subject_pseudonymization_key: str = ""
    banking_transaction_policy_profile_json: str = "{}"
    banking_evidence_attestation_keys_json: str = "{}"
    ai_account_boundary: bool = False
    account_session_permits: bool = False
    account_boundary_simulate: bool = False
    account_boundary_enforce: bool = False
    account_boundary_pseudonymization_key: str = ""
    siem_export_enabled: bool = False
    siem_pseudonymization_key: str = ""
    auditor_tenant_snapshot_enabled: bool = False
    control_coverage_materialization_enabled: bool = False
    control_coverage_snapshot_enabled: bool = False
    control_coverage_api_enabled: bool = False
    control_coverage_ui_enabled: bool = False
    control_coverage_rollout: str = "{}"
    maturity_curve_policy_intelligence: bool = False
    maturity_curve_policy_intelligence_rollout: str = "{}"
    maturity_curve_materialization_interval_minutes: int = 60
    policy_pack_platform_enabled: bool = False
    policy_pack_platform_rollout: str = "{}"
    deployment_family_experience_enabled: bool = False
    deployment_family_coverage_enabled: bool = False
    native_control_framework: bool = False
    native_control_adapter_framework: bool = False
    native_control_reference_adapters: bool = False
    native_control_adapter_enforcement: bool = False
    control_capability_matrix: bool = False
    trusted_control_selector: bool = False
    native_control_monitor: bool = False
    native_control_enforce: bool = False
    native_control_anthropic: bool = False
    native_control_cursor: bool = False
    native_control_openai: bool = False
    native_control_google: bool = False
    native_control_microsoft: bool = False
    native_control_azure: bool = False
    native_control_aws: bool = False
    native_control_meta: bool = False
    native_control_kimi: bool = False
    native_control_qwen: bool = False
    native_control_deepseek: bool = False
    native_control_route_bindings_json: str = "{}"
    control_coverage_default_window_days: int = 30
    control_coverage_snapshot_interval_minutes: int = 15
    hmair_core: bool = False
    hmair_active_scan: bool = False
    hmair_endpoint: bool = False
    hmair_browser: bool = False
    hmair_mcp_runtime: bool = False
    hmair_cloud: bool = False
    hmair_saas: bool = False
    hmair_identity: bool = False
    hmair_repository: bool = False
    hmair_network: bool = False
    hmair_database: bool = False
    # A connector source is eligible for Deep Scan only when its individual
    # surface flag, customer-owned connection, and typed source contract are
    # also present.  This remains default-off to prevent empty scan claims.
    hmair_connector_sources: bool = False
    # Each customer-owned source also needs its explicit source flag.  These
    # switches are intentionally independent from HMAIR_CONNECTOR_SOURCES so
    # that connecting one provider cannot activate another provider's scans.
    hmair_microsoft365_source: bool = False
    hmair_github_cloud_source: bool = False
    hmair_github_ghes_source: bool = False
    hmair_fingerprinting: bool = False
    hmair_usage_attribution: bool = False
    hmair_shadow_ai: bool = False
    hmair_reachability: bool = False
    hmair_max_concurrent_assignments: int = 8
    hmair_observation_batch_size: int = 500
    cie_core: bool = False
    cie_genome: bool = False
    cie_marketplace: bool = False
    cie_dependency_graph: bool = False
    cie_drift: bool = False
    platform_mode_default: str = "enforce"
    control_plane_strict_dependency_checks: bool = True
    control_plane_heartbeat_max_age_seconds: int = 120
    asymmetry_small_prompt_threshold_chars: int = 160
    asymmetry_large_output_threshold_chars: int = 1200
    asymmetry_output_ratio_threshold: float = 8.0
    asymmetry_tool_call_threshold: int = 4
    onprem_bundle_signing_secret: str
    runtime_intelligence_enabled: bool = True
    runtime_intelligence_schedule_simulations: bool = False
    runtime_intelligence_correlation_window_minutes: int = 60
    runtime_intelligence_repeat_threshold: int = 3
    runtime_recommendation_long_window_days: int = 30
    runtime_remediation_confidence_threshold: float = 0.5
    runtime_semantic_drift_threshold: float = 0.45
    ai_iam_auto_quarantine_new_agents: bool = True
    shadow_ai_auto_promote_confidence_threshold: float = 0.8
    remediation_auto_apply_enabled: bool = True
    remediation_high_risk_requires_approval: bool = True
    remediation_emit_lifecycle_signals: bool = True
    remediation_default_cooldown_minutes: int = 60
    sensitive_detection_async_ocr_enabled: bool = False
    sensitive_detection_async_ocr_min_bytes: int = 400000
    sensitive_detection_async_ocr_timeout_seconds: float = 2.0
    simulation_browser_execution_enabled: bool = False
    simulation_browser_execution_timeout_seconds: int = 45
    simulation_evidence_dir: str = "./evidence"
    extension_backend_allow_confirmation_enabled: bool = False
    prompt_logging_medium_sensitivity_threshold: float = 0.35
    prompt_logging_high_sensitivity_threshold: float = 0.75
    prompt_logging_allow_sensitive_raw: bool = False
    jira_base_url: str = ""
    jira_project_key: str = "SEC"
    jira_issue_type: str = "Task"
    jira_user_email: str = ""
    jira_api_token: str = ""
    servicenow_base_url: str = ""
    servicenow_username: str = ""
    servicenow_password: str = ""
    servicenow_table: str = "incident"

    @field_validator("secret_key", "connector_secrets_key", "connector_secrets_kdf_salt", "onprem_bundle_signing_secret")
    @classmethod
    def _validate_required_secret(cls, value: str) -> str:
        token = str(value or "").strip()
        if not token:
            raise ValueError("Required secret/config value must be set via environment and cannot be empty.")
        return token

    @field_validator("connector_secrets_kdf_iterations")
    @classmethod
    def _validate_kdf_iterations(cls, value: int) -> int:
        if int(value) < 100_000:
            raise ValueError("CONNECTOR_SECRETS_KDF_ITERATIONS must be >= 100000.")
        return int(value)

    @field_validator("control_coverage_default_window_days")
    @classmethod
    def _validate_control_coverage_window(cls, value: int) -> int:
        if not 1 <= int(value) <= 90:
            raise ValueError("CONTROL_COVERAGE_DEFAULT_WINDOW_DAYS must be between 1 and 90.")
        return int(value)

    @field_validator("control_coverage_snapshot_interval_minutes")
    @classmethod
    def _validate_control_coverage_interval(cls, value: int) -> int:
        if not 5 <= int(value) <= 1440:
            raise ValueError("CONTROL_COVERAGE_SNAPSHOT_INTERVAL_MINUTES must be between 5 and 1440.")
        return int(value)

    @field_validator("maturity_curve_materialization_interval_minutes")
    @classmethod
    def _validate_maturity_curve_interval(cls, value: int) -> int:
        if not 5 <= int(value) <= 1440:
            raise ValueError("MATURITY_CURVE_MATERIALIZATION_INTERVAL_MINUTES must be between 5 and 1440.")
        return int(value)

    @field_validator("hmair_max_concurrent_assignments")
    @classmethod
    def _validate_hmair_concurrency(cls, value: int) -> int:
        if not 1 <= int(value) <= 100:
            raise ValueError(
                "HMAIR_MAX_CONCURRENT_ASSIGNMENTS must be between 1 and 100."
            )
        return int(value)

    @field_validator("hmair_observation_batch_size")
    @classmethod
    def _validate_hmair_batch_size(cls, value: int) -> int:
        if not 1 <= int(value) <= 5000:
            raise ValueError(
                "HMAIR_OBSERVATION_BATCH_SIZE must be between 1 and 5000."
            )
        return int(value)

    @model_validator(mode="after")
    def _validate_key_separation(self) -> "Settings":
        if self.connector_secrets_key == self.secret_key:
            raise ValueError("CONNECTOR_SECRETS_KEY must be distinct from SECRET_KEY.")
        if self.company_sso_enabled:
            try:
                providers = json.loads(self.oidc_providers_json or "[]")
                bindings = json.loads(self.oidc_bindings_json or "[]")
            except (TypeError, json.JSONDecodeError) as exc:
                raise ValueError("OIDC configuration must be valid JSON when COMPANY_SSO_ENABLED is true.") from exc
            if not isinstance(providers, list) or not providers or not self.oidc_provider_secrets_json.strip():
                raise ValueError("OIDC providers and encrypted secrets are required when COMPANY_SSO_ENABLED is true.")
            keys = set()
            for row in providers:
                if not isinstance(row, dict) or not all(isinstance(row.get(field), str) and row[field].strip() for field in ("key", "kind", "display_name", "workspace_slug", "issuer", "client_id", "tenant_id")):
                    raise ValueError("OIDC provider configuration is incomplete.")
                if row["key"] in keys:
                    raise ValueError("OIDC provider keys must be unique.")
                keys.add(row["key"])
                issuer = urlsplit(row["issuer"])
                if issuer.scheme.lower() != "https" or issuer.query or issuer.fragment:
                    raise ValueError("OIDC issuers must be exact HTTPS origins.")
                if row["kind"].lower() == "entra" and any(part.lower() in {"common", "organizations", "consumers"} for part in issuer.path.split("/")):
                    raise ValueError("Entra OIDC authority must be tenant-specific.")
            # Bindings are optional since accounts link by (issuer, subject) at the first sign-in (docs/sign-in.md);
            # those listed must still be well formed.
            if not isinstance(bindings, list) or any(not isinstance(row, dict) for row in bindings):
                raise ValueError("OIDC bindings must be a list of objects.")
            if any(row.get("provider_key") not in keys for row in bindings):
                raise ValueError("OIDC bindings must reference enabled providers.")
            derived = hashlib.pbkdf2_hmac("sha256", self.connector_secrets_key.encode(), self.connector_secrets_kdf_salt.encode(), self.connector_secrets_kdf_iterations, dklen=32)
            try:
                secrets_payload = json.loads(Fernet(base64.urlsafe_b64encode(derived)).decrypt(self.oidc_provider_secrets_json.encode()).decode())
            except (InvalidToken, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError("OIDC provider secrets must be valid encrypted configuration.") from exc
            if not isinstance(secrets_payload, dict) or any(not isinstance(secrets_payload.get(key), dict) or not secrets_payload[key].get("client_secret") for key in keys):
                raise ValueError("OIDC provider secrets are incomplete.")
            identities: set[tuple[str, str, str]] = set()
            providers_by_key = {row["key"]: row for row in providers}
            for binding in bindings:
                fields = ("provider_key", "issuer", "subject", "user_id", "tenant_id")
                if not all(isinstance(binding.get(field), str) and binding[field].strip() for field in fields):
                    raise ValueError("OIDC bindings are incomplete.")
                identity = (binding["provider_key"], binding["issuer"], binding["subject"])
                if identity in identities:
                    raise ValueError("OIDC bindings must be unique.")
                identities.add(identity)
                provider = providers_by_key[binding["provider_key"]]
                if binding["issuer"].rstrip("/") != provider["issuer"].rstrip("/") or binding["tenant_id"] != provider["tenant_id"]:
                    raise ValueError("OIDC binding issuer and tenant must match provider configuration.")
            for field in ("oidc_callback_url", "oidc_frontend_url"):
                value = urlsplit(str(getattr(self, field)))
                if value.scheme.lower() != "https" or value.query or value.fragment:
                    raise ValueError("OIDC callback and frontend URLs must be fixed HTTPS URLs.")
        hmair_active_surface_enabled = any(
            (
                self.hmair_endpoint,
                self.hmair_browser,
                self.hmair_mcp_runtime,
                self.hmair_cloud,
                self.hmair_saas,
                self.hmair_identity,
                self.hmair_repository,
                self.hmair_network,
                self.hmair_database,
            )
        )
        hmair_capability_enabled = any(
            (
                self.hmair_fingerprinting,
                self.hmair_usage_attribution,
                self.hmair_shadow_ai,
                self.hmair_reachability,
                self.hmair_connector_sources,
            )
        )
        if (
            self.hmair_active_scan
            or hmair_active_surface_enabled
            or hmair_capability_enabled
        ) and not self.hmair_core:
            raise ValueError(
                "HMAIR_CORE must be enabled before HMAIR active scan or surface flags."
            )
        if self.hmair_active_scan and not hmair_active_surface_enabled:
            raise ValueError(
                "HMAIR_ACTIVE_SCAN requires at least one enabled HMAIR surface."
            )
        cie_children = (
            self.cie_genome,
            self.cie_marketplace,
            self.cie_dependency_graph,
            self.cie_drift,
        )
        if any(cie_children) and not self.cie_core:
            raise ValueError(
                "CIE_CORE must be enabled before CIE child features."
            )
        if self.cie_drift and not self.cie_genome:
            raise ValueError("CIE_DRIFT requires CIE_GENOME.")
        registration_env = self.env.strip().lower()
        if self.self_registration_enabled and (
            registration_env not in {"dev", "development", "test", "demo"}
            or self.pilot_mode
        ):
            raise ValueError(
                "SELF_REGISTRATION_ENABLED requires a recognized dev, test, or demo ENV "
                "and cannot be combined with PILOT_MODE."
            )
        siem_pseudonymization_key = str(self.siem_pseudonymization_key or "").strip()
        if self.siem_export_enabled:
            if len(siem_pseudonymization_key) < 32:
                raise ValueError(
                    "SIEM_PSEUDONYMIZATION_KEY must contain at least 32 characters "
                    "when SIEM export is enabled."
                )
            if siem_pseudonymization_key_is_obviously_predictable(
                siem_pseudonymization_key
            ):
                raise ValueError(
                    "SIEM_PSEUDONYMIZATION_KEY must not use obvious predictable "
                    "or placeholder material."
                )
            existing_application_secrets = {
                str(value or "").strip()
                for value in (
                    self.secret_key,
                    self.secret_key_lock_pepper,
                    self.connector_secrets_key,
                    self.connector_secrets_kdf_salt,
                    self.enforcement_payloads_key,
                    self.canonical_action_binding_key,
                    self.onprem_bundle_signing_secret,
                    self.llm_api_key,
                    self.openai_api_key,
                    self.anthropic_api_key,
                    self.gemini_api_key,
                    self.jira_api_token,
                    self.servicenow_password,
                )
                if str(value or "").strip()
            }
            try:
                receipt_keys = json.loads(str(self.receipt_signing_keys_json or "{}"))
            except json.JSONDecodeError:
                receipt_keys = {}
            if isinstance(receipt_keys, dict):
                existing_application_secrets.update(
                    str(value).strip()
                    for value in receipt_keys.values()
                    if isinstance(value, str) and value.strip()
                )
            if siem_pseudonymization_key in existing_application_secrets:
                raise ValueError(
                    "SIEM_PSEUDONYMIZATION_KEY must be distinct from existing application secrets."
                )
        if self.gateway_intercept_minimal_mode and not self.demo_mode:
            raise ValueError("GATEWAY_INTERCEPT_MINIMAL_MODE requires DEMO_MODE=true.")
        coverage_rollout = parse_control_coverage_rollout(self.control_coverage_rollout)
        if self.control_coverage_snapshot_enabled and not self.control_coverage_materialization_enabled:
            raise ValueError(
                "CONTROL_COVERAGE_SNAPSHOT_ENABLED requires CONTROL_COVERAGE_MATERIALIZATION_ENABLED=true."
            )
        if (
            self.control_coverage_materialization_enabled or self.control_coverage_snapshot_enabled
        ) and not any(coverage_rollout.values()):
            raise ValueError("Control Coverage writes require an explicit tenant rollout.")
        maturity_rollout = parse_maturity_curve_rollout(self.maturity_curve_policy_intelligence_rollout)
        if self.maturity_curve_policy_intelligence and not any(maturity_rollout.values()):
            raise ValueError(
                "MATURITY_CURVE_POLICY_INTELLIGENCE requires an explicit tenant rollout."
            )
        policy_pack_rollout = parse_policy_pack_platform_rollout(self.policy_pack_platform_rollout)
        if self.policy_pack_platform_enabled and not any(policy_pack_rollout.values()):
            raise ValueError("POLICY_PACK_PLATFORM_ENABLED requires an explicit tenant rollout.")
        provider_signal_retention_rollout = parse_provider_signal_retention_rollout(
            self.provider_signal_retention_rollout
        )
        if self.provider_signal_retention_execution_enabled and not any(
            provider_signal_retention_rollout.values()
        ):
            raise ValueError(
                "PROVIDER_SIGNAL_RETENTION_EXECUTION_ENABLED requires an explicit tenant rollout."
            )
        binding_key = str(self.canonical_action_binding_key or "").strip()
        if self.canonical_ai_action_dual_write_enabled:
            if not binding_key:
                raise ValueError("CANONICAL_ACTION_BINDING_KEY is required when canonical dual-write is enabled.")
            if len(binding_key) < 32:
                raise ValueError("CANONICAL_ACTION_BINDING_KEY must contain at least 32 characters.")
        if self.authorization_kernel_shadow_compare_enabled and not self.authorization_kernel_v2_enabled:
            raise ValueError("AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED requires AUTHORIZATION_KERNEL_V2_ENABLED=true.")
        if self.authorization_kernel_v2_enforce:
            if not self.authorization_kernel_v2_enabled:
                raise ValueError("AUTHORIZATION_KERNEL_V2_ENFORCE requires AUTHORIZATION_KERNEL_V2_ENABLED=true.")
            if not self.authorization_kernel_shadow_compare_enabled:
                raise ValueError(
                    "AUTHORIZATION_KERNEL_V2_ENFORCE requires AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED=true."
                )
            from app.core.control_engine.authorization import (
                PRE_SIDE_EFFECT_ENFORCEABLE_SURFACES,
                parse_enforcement_rollout,
            )

            enforcement_rollout = parse_enforcement_rollout(self.authorization_kernel_v2_enforce_rollout)
            if not enforcement_rollout:
                raise ValueError("AUTHORIZATION_KERNEL_V2_ENFORCE requires an explicit tenant/surface rollout.")
            unsupported = sorted(
                {
                    surface
                    for surfaces in enforcement_rollout.values()
                    for surface in surfaces
                    if surface not in PRE_SIDE_EFFECT_ENFORCEABLE_SURFACES
                }
            )
            if unsupported:
                raise ValueError(
                    "AUTHORIZATION_KERNEL_V2_ENFORCE selected surface without a pre-side-effect "
                    f"authorization hook: {', '.join(unsupported)}"
                )
        if self.authorization_kernel_v2_enabled:
            if not binding_key:
                raise ValueError("CANONICAL_ACTION_BINDING_KEY is required when authorization kernel v2 is enabled.")
            if len(binding_key) < 32:
                raise ValueError("CANONICAL_ACTION_BINDING_KEY must contain at least 32 characters.")
        if binding_key and binding_key in {
            str(self.secret_key or ""),
            str(self.connector_secrets_key or ""),
            str(self.onprem_bundle_signing_secret or ""),
        }:
            raise ValueError("CANONICAL_ACTION_BINDING_KEY must be distinct from existing application secrets.")
        if self.decision_execution_receipts_enabled:
            if not (
                self.authorization_kernel_v2_enabled
                and self.authorization_kernel_shadow_compare_enabled
                and self.authorization_kernel_v2_enforce
            ):
                raise ValueError(
                    "DECISION_EXECUTION_RECEIPTS_ENABLED requires AUTHORIZATION_KERNEL_V2_ENABLED, "
                    "AUTHORIZATION_KERNEL_SHADOW_COMPARE_ENABLED, and AUTHORIZATION_KERNEL_V2_ENFORCE."
                )
            from app.core.control_engine.authorization import parse_enforcement_rollout

            if not parse_enforcement_rollout(self.authorization_kernel_v2_enforce_rollout):
                raise ValueError(
                    "DECISION_EXECUTION_RECEIPTS_ENABLED requires an explicit authorization-kernel rollout."
                )
            active_receipt_key_id = str(self.receipt_signing_active_key_id or "").strip()
            if not active_receipt_key_id:
                raise ValueError(
                    "RECEIPT_SIGNING_ACTIVE_KEY_ID is required when decision/execution receipts are enabled."
                )
            try:
                duplicate_receipt_key_ids: set[str] = set()

                def _receipt_keyring_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
                    decoded: dict[str, object] = {}
                    for key_id, secret in pairs:
                        if key_id in decoded:
                            duplicate_receipt_key_ids.add(key_id)
                        decoded[key_id] = secret
                    return decoded

                receipt_keys = json.loads(
                    str(self.receipt_signing_keys_json or "{}"),
                    object_pairs_hook=_receipt_keyring_object,
                )
            except json.JSONDecodeError as exc:
                raise ValueError("RECEIPT_SIGNING_KEYS_JSON must be valid JSON.") from exc
            if not isinstance(receipt_keys, dict) or not receipt_keys or duplicate_receipt_key_ids:
                raise ValueError("RECEIPT_SIGNING_KEYS_JSON must contain a signing keyring.")
            normalized_receipt_keys: dict[str, str] = {}
            for key_id, secret in receipt_keys.items():
                if not isinstance(key_id, str) or not isinstance(secret, str):
                    raise ValueError("Receipt signing key IDs and key material must be strings.")
                normalized_key_id = key_id.strip()
                normalized_secret = secret.strip()
                if not normalized_key_id or len(normalized_key_id) > 64:
                    raise ValueError("Receipt signing key IDs must be non-empty and at most 64 characters.")
                if normalized_key_id in normalized_receipt_keys:
                    raise ValueError("Receipt signing key IDs must be unique after normalization.")
                if len(normalized_secret) < 32:
                    raise ValueError("Receipt signing keys must contain at least 32 characters.")
                normalized_receipt_keys[normalized_key_id] = normalized_secret
            if active_receipt_key_id not in normalized_receipt_keys:
                raise ValueError("RECEIPT_SIGNING_ACTIVE_KEY_ID is not present in the receipt keyring.")
            if len(set(normalized_receipt_keys.values())) != len(normalized_receipt_keys):
                raise ValueError("Receipt signing key material must not be reused across key IDs.")
            existing_secrets = {
                str(self.secret_key or ""),
                str(self.connector_secrets_key or ""),
                str(self.onprem_bundle_signing_secret or ""),
                binding_key,
            }
            if any(secret in existing_secrets for secret in normalized_receipt_keys.values()):
                raise ValueError("Receipt signing keys must be distinct from existing application secrets.")
        if self.banking_transaction_integrity_enabled:
            if not self.decision_execution_receipts_enabled:
                raise ValueError(
                    "BANKING_TRANSACTION_INTEGRITY_ENABLED requires "
                    "DECISION_EXECUTION_RECEIPTS_ENABLED=true."
                )
            banking_key = str(self.banking_subject_pseudonymization_key or "").strip()
            if len(banking_key) < 32:
                raise ValueError(
                    "BANKING_SUBJECT_PSEUDONYMIZATION_KEY must contain at least 32 characters."
                )
            if banking_key in {
                str(self.secret_key or ""),
                str(self.connector_secrets_key or ""),
                str(self.onprem_bundle_signing_secret or ""),
                binding_key,
            }:
                raise ValueError(
                    "BANKING_SUBJECT_PSEUDONYMIZATION_KEY must be distinct from existing secrets."
                )
            try:
                banking_trust = json.loads(str(self.banking_subject_trust_json or "{}"))
                banking_profile = json.loads(
                    str(self.banking_transaction_policy_profile_json or "{}")
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    "Banking subject trust and policy profile settings must be valid JSON."
                ) from exc
            if not isinstance(banking_trust, dict) or not banking_trust:
                raise ValueError(
                    "BANKING_SUBJECT_TRUST_JSON must contain at least one trusted issuer."
                )
            for issuer, issuer_config in banking_trust.items():
                if (
                    not isinstance(issuer, str)
                    or not issuer.strip()
                    or not isinstance(issuer_config, dict)
                ):
                    raise ValueError(
                        "Each banking trust issuer must have an object configuration."
                    )
                audience = issuer_config.get("audience")
                keys = issuer_config.get("keys")
                if not isinstance(audience, str) or not audience.strip():
                    raise ValueError(
                        "Each banking trust issuer must declare one audience."
                    )
                if not isinstance(keys, dict) or not keys:
                    raise ValueError(
                        "Each banking trust issuer must declare at least one ES256 key."
                    )
                if any(
                    not isinstance(key_id, str)
                    or not key_id.strip()
                    or not isinstance(public_key, str)
                    or "BEGIN PUBLIC KEY" not in public_key
                    for key_id, public_key in keys.items()
                ):
                    raise ValueError(
                        "Banking trust keys must map key IDs to PEM public keys."
                    )
            if not isinstance(banking_profile, dict) or not banking_profile:
                raise ValueError(
                    "BANKING_TRANSACTION_POLICY_PROFILE_JSON must contain a server-owned profile."
                )
            policy_snapshot_id = banking_profile.get("policy_snapshot_id")
            if not isinstance(policy_snapshot_id, str) or not policy_snapshot_id.strip():
                raise ValueError("Banking policy profile must pin one policy snapshot ID.")
            for field_name in (
                "approved_ai_system_ids",
                "approved_destinations",
                "approved_workload_identities",
                "approved_workload_identity_types",
                "approved_workload_authentication_modes",
                "approved_operation_types",
                "allowed_purpose_ids",
            ):
                configured_values = banking_profile.get(field_name)
                if (
                    not isinstance(configured_values, list)
                    or not configured_values
                    or any(
                        not isinstance(item, str) or not item.strip()
                        for item in configured_values
                    )
                    or len(set(configured_values)) != len(configured_values)
                ):
                    raise ValueError(
                        f"Banking policy profile {field_name} must be a non-empty unique string list."
                    )
            approved_tools = banking_profile.get("approved_tools")
            if not isinstance(approved_tools, dict) or not approved_tools:
                raise ValueError("Banking policy profile must pin approved tool fingerprints.")
            for tool_name, tool_config in approved_tools.items():
                if not isinstance(tool_name, str) or not tool_name.strip() or not isinstance(tool_config, dict):
                    raise ValueError("Each approved banking tool must have an object configuration.")
                tool_version = tool_config.get("version")
                tool_fingerprint = tool_config.get("schema_fingerprint")
                if not isinstance(tool_version, str) or not tool_version.strip():
                    raise ValueError("Each approved banking tool must pin a version.")
                if (
                    not isinstance(tool_fingerprint, str)
                    or len(tool_fingerprint) != 64
                    or any(character not in "0123456789abcdef" for character in tool_fingerprint)
                ):
                    raise ValueError(
                        "Each approved banking tool must pin a lowercase SHA-256 schema fingerprint."
                    )
                target_binding = tool_config.get("target_binding")
                if not isinstance(target_binding, dict):
                    raise ValueError(
                        "Each approved banking tool must declare one target binding."
                    )
                account_argument = target_binding.get("account_argument")
                resource = target_binding.get("resource")
                customer_source = target_binding.get("customer_source")
                resource_type = target_binding.get("resource_type")
                operation = target_binding.get("operation")
                if (
                    not isinstance(account_argument, str)
                    or not account_argument.strip()
                    or len(account_argument) > 128
                ):
                    raise ValueError(
                        "Each banking target binding must name one account argument."
                    )
                if (
                    not isinstance(resource, str)
                    or not resource.strip()
                    or len(resource) > 512
                ):
                    raise ValueError(
                        "Each banking target binding must pin one resource."
                    )
                if customer_source != "signed_subject":
                    raise ValueError(
                        "Banking target bindings must derive the customer from the signed subject."
                    )
                if (
                    not isinstance(resource_type, str)
                    or not resource_type.strip()
                    or len(resource_type) > 64
                ):
                    raise ValueError(
                        "Each banking target binding must pin one resource type."
                    )
                if (
                    not isinstance(operation, str)
                    or not operation.strip()
                    or len(operation) > 128
                ):
                    raise ValueError(
                        "Each banking target binding must pin one operation."
                    )
        if self.ai_account_boundary or self.account_session_permits or self.account_boundary_simulate or self.account_boundary_enforce:
            account_boundary_key = str(self.account_boundary_pseudonymization_key or "").strip()
            if len(account_boundary_key) < 32:
                raise ValueError("ACCOUNT_BOUNDARY_PSEUDONYMIZATION_KEY must contain at least 32 characters when Account Boundary is enabled.")
            configured_receipt_secrets: set[str] = set()
            try:
                receipt_keyring = json.loads(str(self.receipt_signing_keys_json or "{}"))
                if isinstance(receipt_keyring, dict):
                    configured_receipt_secrets = {str(value).strip() for value in receipt_keyring.values() if isinstance(value, str) and value.strip()}
            except json.JSONDecodeError:
                pass
            if account_boundary_key in {
                str(self.secret_key or ""), str(self.connector_secrets_key or ""), str(self.onprem_bundle_signing_secret or ""), binding_key,
                str(self.enforcement_payloads_key or ""), str(self.banking_subject_pseudonymization_key or ""), str(self.siem_pseudonymization_key or ""), str(self.secret_key_lock_pepper or ""),
            } | configured_receipt_secrets:
                raise ValueError("ACCOUNT_BOUNDARY_PSEUDONYMIZATION_KEY must be distinct from existing secrets.")
        if self.account_boundary_enforce and not (
            self.ai_account_boundary and self.account_session_permits and self.account_boundary_simulate and self.fail_secure_mode and self.governance_strict_mode
        ):
            raise ValueError("ACCOUNT_BOUNDARY_ENFORCE requires all Account Boundary prerequisite flags and strict fail-secure posture.")
        if self.env.lower() in {"pilot", "prod", "production"} or self.pilot_mode:
            weak_values = {
                "changeme",
                "password",
                "password123",
                "secret",
                "test-secret-key",
                "dev-secret",
                "hawk-secret",
            }
            secret = str(self.secret_key or "").strip()
            if len(secret) < 32 or secret.lower() in weak_values:
                raise ValueError("SECRET_KEY must be a high-entropy value of at least 32 characters for pilot/production.")
        if self.deployment_topology == "single_node_compose":
            production_report = validate_production_configuration(
                self,
                secret_sources=_CONFIG_SECRET_SOURCES,
            )
            if not production_report.ready:
                raise ValueError(
                    "Production configuration preflight failed: "
                    + ",".join(production_report.reason_codes)
                )
        return self


def _resolve_lock_file_path(path_value: str) -> Path:
    path = Path(path_value).expanduser()
    if path.is_absolute():
        return path
    return _API_ROOT_DIR / path


def _secret_key_fingerprint(secret_key: str, pepper: str = "") -> str:
    material = f"v{_SECRET_KEY_LOCK_VERSION}:{pepper}:{secret_key}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _read_lock_payload(lock_file: Path) -> dict[str, str]:
    raw = lock_file.read_text(encoding="utf-8").strip()
    if not raw:
        raise ValueError("SECRET_KEY lock file is empty.")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        payload = {"fingerprint": raw}
    if not isinstance(payload, dict):
        raise ValueError("SECRET_KEY lock file format is invalid.")
    return payload


def _write_lock_payload(lock_file: Path, payload: dict[str, str]) -> None:
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    try:
        fd = os.open(lock_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(body)
        handle.write("\n")
    os.chmod(lock_file, 0o600)


def ensure_secret_key_lock(current: Settings) -> None:
    if not current.secret_key_lock_enabled:
        return

    lock_file = _resolve_lock_file_path(current.secret_key_lock_file)
    expected = _secret_key_fingerprint(current.secret_key, current.secret_key_lock_pepper)
    payload = {
        "version": str(_SECRET_KEY_LOCK_VERSION),
        "algorithm": "sha256",
        "fingerprint": expected,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    if not lock_file.exists():
        _write_lock_payload(lock_file, payload)

    persisted = _read_lock_payload(lock_file)
    persisted_fingerprint = str(persisted.get("fingerprint", "")).strip()
    if not persisted_fingerprint:
        raise ValueError("SECRET_KEY lock file is missing fingerprint.")
    if persisted_fingerprint != expected:
        raise ValueError(
            "SECRET_KEY changed from locked value. Refusing startup to prevent JWT/session invalidation. "
            f"Lock file: {lock_file}"
        )


settings = Settings()
ensure_secret_key_lock(settings)


def configured_secret_sources() -> dict[str, str]:
    return dict(_CONFIG_SECRET_SOURCES)
