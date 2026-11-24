from __future__ import annotations

from app.core.config import Settings, settings
from app.services.deployment_hardening_service import evaluate_deployment_hardening
from app.services.deployment_hardening_service import validate_oidc_configuration
from app.services.connector_secret_service import encrypt_connector_secrets


def _valid_oidc_fixture(monkeypatch) -> None:
    monkeypatch.setattr(settings, "oidc_providers_json", '[{"key":"entra","kind":"entra","display_name":"Microsoft","workspace_slug":"acme","issuer":"https://login.microsoftonline.com/tenant/v2.0","client_id":"client","tenant_id":"t1"}]')
    monkeypatch.setattr(settings, "oidc_provider_secrets_json", encrypt_connector_secrets({"entra": {"client_secret": "secret"}}))
    monkeypatch.setattr(settings, "oidc_bindings_json", '[{"provider_key":"entra","issuer":"https://login.microsoftonline.com/tenant/v2.0","subject":"subject","user_id":"u1","tenant_id":"t1"}]')
    monkeypatch.setattr(settings, "oidc_callback_url", "https://api.example.test/auth/oidc/callback")
    monkeypatch.setattr(settings, "oidc_frontend_url", "https://app.example.test/login/oidc/callback")


def test_enabled_sso_rejects_flag_only_and_common_authority(monkeypatch) -> None:
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    monkeypatch.setattr(settings, "oidc_providers_json", '[{"key":"entra","kind":"entra","display_name":"Microsoft","workspace_slug":"acme","issuer":"https://login.microsoftonline.com/common/v2.0","client_id":"client","tenant_id":"t1"}]')
    monkeypatch.setattr(settings, "oidc_provider_secrets_json", "")
    monkeypatch.setattr(settings, "oidc_bindings_json", "[]")
    monkeypatch.setattr(settings, "oidc_callback_url", "http://localhost/callback")
    monkeypatch.setattr(settings, "oidc_frontend_url", "http://localhost/login")
    errors = validate_oidc_configuration()
    assert "oidc_entra_authority_must_be_tenant_specific" in errors
    assert "oidc_provider_secrets_incomplete" in errors
    assert "oidc_callback_url_https_required" in errors


def test_settings_accepts_complete_encrypted_oidc_configuration(monkeypatch) -> None:
    _valid_oidc_fixture(monkeypatch)
    configured = Settings(
        secret_key=settings.secret_key,
        connector_secrets_key=settings.connector_secrets_key,
        connector_secrets_kdf_salt=settings.connector_secrets_kdf_salt,
        onprem_bundle_signing_secret=settings.onprem_bundle_signing_secret,
        company_sso_enabled=True,
        oidc_providers_json=settings.oidc_providers_json,
        oidc_provider_secrets_json=settings.oidc_provider_secrets_json,
        oidc_bindings_json=settings.oidc_bindings_json,
        oidc_callback_url=settings.oidc_callback_url,
        oidc_frontend_url=settings.oidc_frontend_url,
    )
    assert configured.company_sso_enabled is True


def test_deployment_hardening_marks_managed_locked_extension_ready(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot")
    monkeypatch.setattr(settings, "secret_key", "x" * 64)
    monkeypatch.setattr(settings, "secret_key_lock_enabled", True)
    monkeypatch.setattr(settings, "api_base_url", "https://hawk-api.local")
    monkeypatch.setattr(settings, "require_https_for_pilot", True)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", True)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", True)
    monkeypatch.setattr(settings, "backup_configured", True)
    monkeypatch.setattr(settings, "evidence_retention_days", 90)
    monkeypatch.setattr(settings, "report_retention_days", 90)
    monkeypatch.setattr(settings, "incognito_policy", "disabled")
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    _valid_oidc_fixture(monkeypatch)
    monkeypatch.setattr(settings, "prompt_logging_allow_sensitive_raw", False)
    monkeypatch.setattr(settings, "fail_secure_mode", True)
    monkeypatch.setattr(settings, "governance_strict_mode", True)
    monkeypatch.setattr(settings, "control_plane_strict_dependency_checks", True)
    monkeypatch.setattr(settings, "cors_origins", "https://hawk-ui.local")
    monkeypatch.setattr(settings, "extension_cors_origins", "chrome-extension://abcdefghijklmnop")

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": True,
            "policy_locked": True,
            "extension_version": "0.1.8",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "abcdef1234567890",
            "source_maps_included": False,
            "dev_files_included": False,
            "api_base_url": "https://hawk-api.local",
            "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        },
        expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
    )

    assert payload["status"] == "ok"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["database_postgresql"]["status"] == "ok"
    assert checks["extension_managed"]["status"] == "ok"
    assert checks["extension_cors_origins"]["status"] == "ok"
    assert checks["extension_policy_locked"]["status"] == "ok"
    assert checks["extension_build_hash"]["status"] == "ok"
    assert checks["extension_version_floor"]["status"] == "ok"
    assert checks["extension_package_hygiene"]["status"] == "ok"
    assert checks["extension_api_url_match"]["status"] == "ok"
    assert checks["extension_tenant_match"]["status"] == "ok"


def test_deployment_hardening_flags_unmanaged_extension_and_manual_controls(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "sqlite:///hawk.db")
    monkeypatch.setattr(settings, "secret_key", "short")
    monkeypatch.setattr(settings, "secret_key_lock_enabled", False)
    monkeypatch.setattr(settings, "api_base_url", "http://192.168.1.5:8000")
    monkeypatch.setattr(settings, "require_https_for_pilot", False)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", False)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", False)
    monkeypatch.setattr(settings, "backup_configured", False)
    monkeypatch.setattr(settings, "evidence_retention_days", 0)
    monkeypatch.setattr(settings, "report_retention_days", 0)
    monkeypatch.setattr(settings, "incognito_policy", "not_configured")
    monkeypatch.setattr(settings, "company_sso_enabled", False)
    monkeypatch.setattr(settings, "pilot_password_rotation_required", True)

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": False,
            "policy_locked": False,
            "extension_version": "0.1.8",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "dev",
            "source_maps_included": True,
            "dev_files_included": True,
        }
    )

    assert payload["status"] == "failed"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["database_postgresql"]["status"] == "failed"
    assert checks["secret_key_strength"]["status"] == "failed"
    assert checks["disk_encryption"]["status"] == "manual_required"
    assert checks["backup_configured"]["status"] == "manual_required"
    assert checks["extension_managed"]["status"] == "failed"
    assert checks["extension_policy_locked"]["status"] == "failed"
    assert checks["extension_package_hygiene"]["status"] == "failed"


def test_deployment_hardening_flags_extension_api_and_tenant_mismatch(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot")
    monkeypatch.setattr(settings, "secret_key", "x" * 64)
    monkeypatch.setattr(settings, "secret_key_lock_enabled", True)
    monkeypatch.setattr(settings, "api_base_url", "https://hawk-api.local")
    monkeypatch.setattr(settings, "require_https_for_pilot", True)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", True)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", True)
    monkeypatch.setattr(settings, "backup_configured", True)
    monkeypatch.setattr(settings, "evidence_retention_days", 90)
    monkeypatch.setattr(settings, "report_retention_days", 90)
    monkeypatch.setattr(settings, "incognito_policy", "disabled")
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    _valid_oidc_fixture(monkeypatch)

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": True,
            "policy_locked": True,
            "extension_version": "0.1.8",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "abcdef1234567890",
            "source_maps_included": False,
            "dev_files_included": False,
            "api_base_url": "http://old-api.local:8000",
            "tenant_id": "wrong-tenant",
        },
        expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
    )

    assert payload["status"] == "failed"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["extension_api_url_match"]["status"] == "failed"
    assert checks["extension_tenant_match"]["status"] == "failed"


def test_deployment_hardening_flags_stale_extension_below_managed_version_floor(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot")
    monkeypatch.setattr(settings, "secret_key", "x" * 64)
    monkeypatch.setattr(settings, "secret_key_lock_enabled", True)
    monkeypatch.setattr(settings, "api_base_url", "https://hawk-api.local")
    monkeypatch.setattr(settings, "require_https_for_pilot", True)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", True)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", True)
    monkeypatch.setattr(settings, "backup_configured", True)
    monkeypatch.setattr(settings, "evidence_retention_days", 90)
    monkeypatch.setattr(settings, "report_retention_days", 90)
    monkeypatch.setattr(settings, "incognito_policy", "disabled")
    monkeypatch.setattr(settings, "company_sso_enabled", True)

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": True,
            "policy_locked": True,
            "extension_version": "0.1.7",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "abcdef1234567890",
            "source_maps_included": False,
            "dev_files_included": False,
            "api_base_url": "https://hawk-api.local",
            "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        },
        expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
    )

    assert payload["status"] == "failed"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["extension_version_floor"]["status"] == "failed"


def test_deployment_hardening_warns_when_retention_is_too_short_for_audit(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot")
    monkeypatch.setattr(settings, "secret_key", "x" * 64)
    monkeypatch.setattr(settings, "secret_key_lock_enabled", True)
    monkeypatch.setattr(settings, "api_base_url", "https://hawk-api.local")
    monkeypatch.setattr(settings, "require_https_for_pilot", True)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", True)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", True)
    monkeypatch.setattr(settings, "backup_configured", True)
    monkeypatch.setattr(settings, "evidence_retention_days", 7)
    monkeypatch.setattr(settings, "report_retention_days", 7)
    monkeypatch.setattr(settings, "incognito_policy", "disabled")
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    _valid_oidc_fixture(monkeypatch)
    _valid_oidc_fixture(monkeypatch)

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": True,
            "policy_locked": True,
            "extension_version": "0.1.8",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "abcdef1234567890",
            "source_maps_included": False,
            "dev_files_included": False,
            "api_base_url": "https://hawk-api.local",
            "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        },
        expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
    )

    assert payload["status"] == "degraded"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["retention_policy"]["status"] == "warning"


def test_deployment_hardening_rejects_string_false_flags_and_weak_hash(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot")
    monkeypatch.setattr(settings, "secret_key", "x" * 64)
    monkeypatch.setattr(settings, "secret_key_lock_enabled", True)
    monkeypatch.setattr(settings, "api_base_url", "https://hawk-api.local")
    monkeypatch.setattr(settings, "require_https_for_pilot", True)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", True)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", True)
    monkeypatch.setattr(settings, "backup_configured", True)
    monkeypatch.setattr(settings, "evidence_retention_days", 90)
    monkeypatch.setattr(settings, "report_retention_days", 90)
    monkeypatch.setattr(settings, "incognito_policy", "disabled")
    monkeypatch.setattr(settings, "company_sso_enabled", True)

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": "false",
            "policy_locked": "false",
            "extension_version": "0.1.8",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "short",
            "source_maps_included": True,
            "dev_files_included": False,
            "api_base_url": "https://hawk-api.local",
            "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        },
        expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
    )

    assert payload["status"] == "failed"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["extension_managed"]["status"] == "failed"
    assert checks["extension_policy_locked"]["status"] == "failed"
    assert checks["extension_build_hash"]["status"] == "warning"
    assert checks["extension_package_hygiene"]["status"] == "failed"


def test_deployment_hardening_flags_sensitive_raw_logging_and_strict_mode_gaps(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot")
    monkeypatch.setattr(settings, "secret_key", "x" * 64)
    monkeypatch.setattr(settings, "secret_key_lock_enabled", True)
    monkeypatch.setattr(settings, "api_base_url", "https://hawk-api.local")
    monkeypatch.setattr(settings, "require_https_for_pilot", True)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", True)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", True)
    monkeypatch.setattr(settings, "backup_configured", True)
    monkeypatch.setattr(settings, "prompt_logging_allow_sensitive_raw", True)
    monkeypatch.setattr(settings, "fail_secure_mode", False)
    monkeypatch.setattr(settings, "governance_strict_mode", False)
    monkeypatch.setattr(settings, "control_plane_strict_dependency_checks", False)
    monkeypatch.setattr(settings, "evidence_retention_days", 90)
    monkeypatch.setattr(settings, "report_retention_days", 90)
    monkeypatch.setattr(settings, "incognito_policy", "disabled")
    monkeypatch.setattr(settings, "company_sso_enabled", True)

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": True,
            "policy_locked": True,
            "extension_version": "0.1.8",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "abcdef1234567890",
            "source_maps_included": False,
            "dev_files_included": False,
            "api_base_url": "https://hawk-api.local",
            "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        },
        expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
    )

    assert payload["status"] == "failed"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["sensitive_raw_prompt_logging_off"]["status"] == "failed"
    assert checks["fail_secure_mode"]["status"] == "warning"
    assert checks["governance_strict_mode"]["status"] == "warning"
    assert checks["strict_dependency_checks"]["status"] == "warning"


def test_deployment_hardening_flags_wildcard_extension_cors_origins(monkeypatch) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+psycopg2://postgres:pw@127.0.0.1:5432/hawk_pilot")
    monkeypatch.setattr(settings, "secret_key", "x" * 64)
    monkeypatch.setattr(settings, "secret_key_lock_enabled", True)
    monkeypatch.setattr(settings, "api_base_url", "https://hawk-api.local")
    monkeypatch.setattr(settings, "web_origin", "https://hawk-ui.local")
    monkeypatch.setattr(settings, "require_https_for_pilot", True)
    monkeypatch.setattr(settings, "disk_encryption_confirmed", True)
    monkeypatch.setattr(settings, "api_network_restriction_confirmed", True)
    monkeypatch.setattr(settings, "backup_configured", True)
    monkeypatch.setattr(settings, "prompt_logging_allow_sensitive_raw", False)
    monkeypatch.setattr(settings, "fail_secure_mode", True)
    monkeypatch.setattr(settings, "governance_strict_mode", True)
    monkeypatch.setattr(settings, "control_plane_strict_dependency_checks", True)
    monkeypatch.setattr(settings, "evidence_retention_days", 90)
    monkeypatch.setattr(settings, "report_retention_days", 90)
    monkeypatch.setattr(settings, "incognito_policy", "disabled")
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    monkeypatch.setattr(settings, "cors_origins", "https://hawk-ui.local,chrome-extension://*")
    monkeypatch.setattr(settings, "extension_cors_origins", "chrome-extension://*")

    payload = evaluate_deployment_hardening(
        {
            "enterprise_managed": True,
            "policy_locked": True,
            "extension_version": "0.1.8",
            "minimum_extension_version": "0.1.8",
            "extension_build_hash": "abcdef1234567890",
            "source_maps_included": False,
            "dev_files_included": False,
            "api_base_url": "https://hawk-api.local",
            "tenant_id": "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
        },
        expected_tenant_id="5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
    )

    assert payload["status"] == "failed"
    checks = {item["id"]: item for item in payload["checks"]}
    assert checks["extension_cors_origins"]["status"] == "failed"
