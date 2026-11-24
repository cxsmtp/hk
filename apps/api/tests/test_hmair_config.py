from __future__ import annotations

import os
from collections.abc import Callable

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.test_settings import APP_TEST_SETTINGS_APPLIED, apply_test_settings


HMAIR_FLAG_FIELDS = (
    "hmair_core",
    "hmair_active_scan",
    "hmair_endpoint",
    "hmair_browser",
    "hmair_mcp_runtime",
    "hmair_cloud",
    "hmair_saas",
    "hmair_identity",
    "hmair_repository",
    "hmair_network",
    "hmair_database",
    "hmair_connector_sources",
    "hmair_microsoft365_source",
    "hmair_github_cloud_source",
    "hmair_github_ghes_source",
    "hmair_fingerprinting",
    "hmair_usage_attribution",
    "hmair_shadow_ai",
    "hmair_reachability",
)

HMAIR_SCAN_SURFACE_FIELDS = (
    "hmair_endpoint",
    "hmair_browser",
    "hmair_mcp_runtime",
    "hmair_cloud",
    "hmair_saas",
    "hmair_identity",
    "hmair_repository",
    "hmair_network",
    "hmair_database",
)

HMAIR_CAPABILITY_FIELDS = (
    "hmair_fingerprinting",
    "hmair_usage_attribution",
    "hmair_shadow_ai",
    "hmair_reachability",
    "hmair_connector_sources",
)

HMAIR_CORE_DEPENDENT_FIELDS = HMAIR_SCAN_SURFACE_FIELDS + HMAIR_CAPABILITY_FIELDS

HMAIR_NUMERIC_DEFAULTS = {
    "hmair_max_concurrent_assignments": 8,
    "hmair_observation_batch_size": 500,
}

HMAIR_ENV_NAMES = tuple(field.upper() for field in HMAIR_FLAG_FIELDS) + tuple(
    field.upper() for field in HMAIR_NUMERIC_DEFAULTS
)

SettingsFactory = Callable[..., Settings]


@pytest.fixture()
def settings_factory(monkeypatch: pytest.MonkeyPatch) -> SettingsFactory:
    for env_name in HMAIR_ENV_NAMES:
        monkeypatch.delenv(env_name, raising=False)

    def _factory(**overrides: object) -> Settings:
        return Settings(
            _env_file=None,
            secret_key="hmair-test-jwt-secret",
            connector_secrets_key="hmair-test-connector-secret",
            connector_secrets_kdf_salt="hmair-test-kdf-salt",
            onprem_bundle_signing_secret="hmair-test-onprem-secret",
            **overrides,
        )

    return _factory


def test_hmair_flags_default_off(settings_factory: SettingsFactory) -> None:
    settings = settings_factory()

    for field in HMAIR_FLAG_FIELDS:
        assert getattr(settings, field) is False


def test_hmair_declares_exact_flag_and_numeric_field_types() -> None:
    hmair_boolean_fields = {
        name
        for name, field in Settings.model_fields.items()
        if name.startswith("hmair_") and field.annotation is bool
    }
    hmair_integer_fields = {
        name
        for name, field in Settings.model_fields.items()
        if name.startswith("hmair_") and field.annotation is int
    }

    assert hmair_boolean_fields == set(HMAIR_FLAG_FIELDS)
    assert hmair_integer_fields == set(HMAIR_NUMERIC_DEFAULTS)


def test_hmair_numeric_settings_have_conservative_defaults(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()

    for field, expected in HMAIR_NUMERIC_DEFAULTS.items():
        assert getattr(settings, field) == expected
        assert type(getattr(settings, field)) is int


@pytest.mark.parametrize(
    ("field", "invalid_value", "expected_error"),
    (
        (
            "hmair_max_concurrent_assignments",
            0,
            "HMAIR_MAX_CONCURRENT_ASSIGNMENTS must be between 1 and 100",
        ),
        (
            "hmair_max_concurrent_assignments",
            101,
            "HMAIR_MAX_CONCURRENT_ASSIGNMENTS must be between 1 and 100",
        ),
        (
            "hmair_observation_batch_size",
            0,
            "HMAIR_OBSERVATION_BATCH_SIZE must be between 1 and 5000",
        ),
        (
            "hmair_observation_batch_size",
            5001,
            "HMAIR_OBSERVATION_BATCH_SIZE must be between 1 and 5000",
        ),
    ),
)
def test_hmair_numeric_settings_reject_out_of_range_values(
    settings_factory: SettingsFactory,
    field: str,
    invalid_value: int,
    expected_error: str,
) -> None:
    with pytest.raises(ValidationError, match=expected_error):
        settings_factory(**{field: invalid_value})


@pytest.mark.parametrize(
    ("field", "valid_values"),
    (
        ("hmair_max_concurrent_assignments", (1, 100)),
        ("hmair_observation_batch_size", (1, 5000)),
    ),
)
def test_hmair_numeric_settings_accept_inclusive_boundaries(
    settings_factory: SettingsFactory,
    field: str,
    valid_values: tuple[int, int],
) -> None:
    for value in valid_values:
        settings = settings_factory(**{field: value})
        assert getattr(settings, field) == value


@pytest.mark.parametrize("dependent_field", HMAIR_CORE_DEPENDENT_FIELDS)
def test_hmair_surface_or_capability_requires_core(
    settings_factory: SettingsFactory,
    dependent_field: str,
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(**{dependent_field: True})


def test_hmair_active_scan_requires_core(
    settings_factory: SettingsFactory,
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(hmair_active_scan=True, hmair_endpoint=True)


def test_hmair_active_scan_requires_an_enabled_surface(
    settings_factory: SettingsFactory,
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(hmair_core=True, hmair_active_scan=True)


@pytest.mark.parametrize("capability_field", HMAIR_CAPABILITY_FIELDS)
def test_hmair_capability_does_not_satisfy_active_scan_surface_requirement(
    settings_factory: SettingsFactory,
    capability_field: str,
) -> None:
    with pytest.raises(ValidationError):
        settings_factory(
            hmair_core=True,
            hmair_active_scan=True,
            **{capability_field: True},
        )


def test_hmair_core_allows_passive_surface_enablement(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory(hmair_core=True, hmair_repository=True)

    assert settings.hmair_core is True
    assert settings.hmair_active_scan is False
    assert settings.hmair_repository is True


@pytest.mark.parametrize("surface_field", HMAIR_SCAN_SURFACE_FIELDS)
def test_hmair_active_scan_accepts_core_with_each_enabled_surface(
    settings_factory: SettingsFactory,
    surface_field: str,
) -> None:
    settings = settings_factory(
        hmair_core=True,
        hmair_active_scan=True,
        **{surface_field: True},
    )

    assert settings.hmair_core is True
    assert settings.hmair_active_scan is True
    assert getattr(settings, surface_field) is True


@pytest.mark.parametrize("field", HMAIR_FLAG_FIELDS)
def test_hmair_boolean_fields_parse_from_environment(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: SettingsFactory,
    field: str,
) -> None:
    if field != "hmair_core":
        monkeypatch.setenv("HMAIR_CORE", "true")
    if field == "hmair_active_scan":
        monkeypatch.setenv("HMAIR_ENDPOINT", "true")
    monkeypatch.setenv(field.upper(), "true")

    settings = settings_factory()

    assert getattr(settings, field) is True


def test_hmair_numeric_settings_parse_from_environment(
    monkeypatch: pytest.MonkeyPatch,
    settings_factory: SettingsFactory,
) -> None:
    monkeypatch.setenv("HMAIR_MAX_CONCURRENT_ASSIGNMENTS", "37")
    monkeypatch.setenv("HMAIR_OBSERVATION_BATCH_SIZE", "1250")

    settings = settings_factory()

    assert settings.hmair_max_concurrent_assignments == 37
    assert settings.hmair_observation_batch_size == 1250


def test_test_settings_publish_hmair_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(APP_TEST_SETTINGS_APPLIED, raising=False)
    for env_name in HMAIR_ENV_NAMES:
        monkeypatch.delenv(env_name, raising=False)

    apply_test_settings()

    for field in HMAIR_FLAG_FIELDS:
        assert os.getenv(field.upper()) == "false"
    for field, expected in HMAIR_NUMERIC_DEFAULTS.items():
        assert os.getenv(field.upper()) == str(expected)


def test_test_settings_preserve_explicit_hmair_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(APP_TEST_SETTINGS_APPLIED, raising=False)
    monkeypatch.setenv("HMAIR_CORE", "true")
    monkeypatch.setenv("HMAIR_ENDPOINT", "true")
    monkeypatch.setenv("HMAIR_MAX_CONCURRENT_ASSIGNMENTS", "16")
    monkeypatch.setenv("HMAIR_OBSERVATION_BATCH_SIZE", "750")

    apply_test_settings()
    parsed = Settings(_env_file=None)

    assert parsed.hmair_core is True
    assert parsed.hmair_endpoint is True
    assert parsed.hmair_max_concurrent_assignments == 16
    assert parsed.hmair_observation_batch_size == 750


def test_hmair_defaults_preserve_fail_secure_non_hmair_settings(
    settings_factory: SettingsFactory,
) -> None:
    settings = settings_factory()

    assert settings.fail_secure_mode is True
    assert settings.governance_strict_mode is True
