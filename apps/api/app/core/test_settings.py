from __future__ import annotations

import os


APP_TEST_SETTINGS_APPLIED = "APP_TEST_SETTINGS_APPLIED"
TEST_PROFILE_ENV = "TEST_PROFILE"


def get_test_profile() -> str:
    return os.getenv(TEST_PROFILE_ENV, "unit").strip().lower() or "unit"


def apply_test_settings() -> None:
    if os.getenv(APP_TEST_SETTINGS_APPLIED) == "1":
        return

    profile = get_test_profile()
    default_sqlite = "sqlite+pysqlite:///:memory:"
    configured_database_url = os.getenv("DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    database_url = configured_database_url or default_sqlite

    # Unit tests default to SQLite if DATABASE_URL is not explicitly provided.
    if profile == "unit" and not configured_database_url:
        database_url = default_sqlite

    os.environ.setdefault("ENV", "test")
    os.environ.setdefault("DATABASE_URL", database_url)
    os.environ.setdefault("TEST_DATABASE_URL", database_url)
    os.environ.setdefault("REDIS_URL", os.getenv("TEST_REDIS_URL", "redis://redis:6379/0"))
    os.environ.setdefault("CELERY_BROKER_URL", os.getenv("TEST_CELERY_BROKER_URL", "redis://redis:6379/1"))
    os.environ.setdefault("CELERY_RESULT_BACKEND", os.getenv("TEST_CELERY_RESULT_BACKEND", "redis://redis:6379/2"))
    os.environ.setdefault("SECRET_KEY", os.getenv("TEST_SECRET_KEY", "test-secret-key"))
    os.environ.setdefault("SECRET_KEY_LOCK_ENABLED", os.getenv("TEST_SECRET_KEY_LOCK_ENABLED", "false"))
    os.environ.setdefault(
        "SELF_REGISTRATION_ENABLED",
        os.getenv("TEST_SELF_REGISTRATION_ENABLED", "true"),
    )
    os.environ.setdefault(
        "CONNECTOR_SECRETS_KEY",
        os.getenv("TEST_CONNECTOR_SECRETS_KEY", "test-connector-secrets-key"),
    )
    os.environ.setdefault(
        "CONNECTOR_SECRETS_KDF_SALT",
        os.getenv("TEST_CONNECTOR_SECRETS_KDF_SALT", "test-connector-kdf-salt"),
    )
    os.environ.setdefault(
        "ONPREM_BUNDLE_SIGNING_SECRET",
        os.getenv("TEST_ONPREM_BUNDLE_SIGNING_SECRET", "test-onprem-signing-secret"),
    )
    os.environ.setdefault(
        "CANONICAL_ACTION_BINDING_KEY",
        os.getenv("TEST_CANONICAL_ACTION_BINDING_KEY", "test-canonical-action-binding-key-0123456789"),
    )
    os.environ.setdefault(
        "CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS",
        os.getenv("TEST_CONTROL_PLANE_STRICT", "false"),
    )
    os.environ.setdefault("HMAIR_CORE", "false")
    os.environ.setdefault("HMAIR_ACTIVE_SCAN", "false")
    os.environ.setdefault("HMAIR_ENDPOINT", "false")
    os.environ.setdefault("HMAIR_BROWSER", "false")
    os.environ.setdefault("HMAIR_MCP_RUNTIME", "false")
    os.environ.setdefault("HMAIR_CLOUD", "false")
    os.environ.setdefault("HMAIR_SAAS", "false")
    os.environ.setdefault("HMAIR_IDENTITY", "false")
    os.environ.setdefault("HMAIR_REPOSITORY", "false")
    os.environ.setdefault("HMAIR_NETWORK", "false")
    os.environ.setdefault("HMAIR_DATABASE", "false")
    os.environ.setdefault("HMAIR_CONNECTOR_SOURCES", "false")
    os.environ.setdefault("HMAIR_MICROSOFT365_SOURCE", "false")
    os.environ.setdefault("HMAIR_GITHUB_CLOUD_SOURCE", "false")
    os.environ.setdefault("HMAIR_GITHUB_GHES_SOURCE", "false")
    os.environ.setdefault("HMAIR_FINGERPRINTING", "false")
    os.environ.setdefault("HMAIR_USAGE_ATTRIBUTION", "false")
    os.environ.setdefault("HMAIR_SHADOW_AI", "false")
    os.environ.setdefault("HMAIR_REACHABILITY", "false")
    os.environ.setdefault("HMAIR_MAX_CONCURRENT_ASSIGNMENTS", "8")
    os.environ.setdefault("HMAIR_OBSERVATION_BATCH_SIZE", "500")
    os.environ.setdefault("CIE_CORE", "false")
    os.environ.setdefault("CIE_GENOME", "false")
    os.environ.setdefault("CIE_MARKETPLACE", "false")
    os.environ.setdefault("CIE_DEPENDENCY_GRAPH", "false")
    os.environ.setdefault("CIE_DRIFT", "false")
    os.environ.setdefault("DISCOVERY_CONTEXT_PROVIDER", "false")
    os.environ.setdefault(APP_TEST_SETTINGS_APPLIED, "1")
