from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.test_settings import APP_TEST_SETTINGS_APPLIED, apply_test_settings


CIE_FLAGS = (
    "cie_core",
    "cie_genome",
    "cie_marketplace",
    "cie_dependency_graph",
    "cie_drift",
)


def _settings(**overrides: object) -> Settings:
    return Settings(
        _env_file=None,
        secret_key="cie-test-jwt-secret",
        connector_secrets_key="cie-test-connector-secret",
        connector_secrets_kdf_salt="cie-test-kdf-salt",
        onprem_bundle_signing_secret="cie-test-onprem-secret",
        **overrides,
    )


def test_cie_flags_default_off(monkeypatch: pytest.MonkeyPatch) -> None:
    for field in CIE_FLAGS:
        monkeypatch.delenv(field.upper(), raising=False)
    settings = _settings()
    assert {field: getattr(settings, field) for field in CIE_FLAGS} == {
        field: False for field in CIE_FLAGS
    }


@pytest.mark.parametrize("child", CIE_FLAGS[1:])
def test_cie_children_require_core(
    monkeypatch: pytest.MonkeyPatch, child: str
) -> None:
    for field in CIE_FLAGS:
        monkeypatch.delenv(field.upper(), raising=False)
    with pytest.raises(ValidationError, match="CIE_CORE"):
        _settings(**{child: True})


def test_cie_drift_requires_genome(monkeypatch: pytest.MonkeyPatch) -> None:
    for field in CIE_FLAGS:
        monkeypatch.delenv(field.upper(), raising=False)
    with pytest.raises(ValidationError, match="CIE_DRIFT requires CIE_GENOME"):
        _settings(cie_core=True, cie_drift=True)


def test_test_settings_publish_cie_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(APP_TEST_SETTINGS_APPLIED, raising=False)
    for field in CIE_FLAGS:
        monkeypatch.delenv(field.upper(), raising=False)
    apply_test_settings()
    assert {field: os.environ[field.upper()] for field in CIE_FLAGS} == {
        field: "false" for field in CIE_FLAGS
    }

