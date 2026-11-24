from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings, ensure_secret_key_lock
from app.services.connector_secret_service import decrypt_connector_secrets, encrypt_connector_secrets
from app.services.enforcement_payload_crypto_service import (
    PROMPT_ENCRYPTION_PREFIX,
    decrypt_enforcement_prompt,
    encrypt_enforcement_prompt,
)


def test_settings_requires_secret_key_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_requires_separate_connector_and_onprem_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONNECTOR_SECRETS_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)

    monkeypatch.setenv("CONNECTOR_SECRETS_KEY", "connector-key")
    monkeypatch.delenv("ONPREM_BUNDLE_SIGNING_SECRET", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_rejects_connector_key_equal_to_jwt_secret() -> None:
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            secret_key="same-secret",
            connector_secrets_key="same-secret",
            connector_secrets_kdf_salt="kdf-salt",
            onprem_bundle_signing_secret="onprem-secret",
        )


def test_settings_rejects_gateway_minimal_mode_outside_demo() -> None:
    with pytest.raises(ValidationError, match="GATEWAY_INTERCEPT_MINIMAL_MODE requires DEMO_MODE=true"):
        Settings(
            _env_file=None,
            secret_key="jwt-secret",
            connector_secrets_key="connector-secret",
            connector_secrets_kdf_salt="kdf-salt",
            onprem_bundle_signing_secret="onprem-secret",
            gateway_intercept_minimal_mode=True,
            demo_mode=False,
        )


def test_enforcement_prompt_storage_encrypts_and_round_trips() -> None:
    prompt = "Summarize customer data and include SSN 123-45-6789"
    encrypted = encrypt_enforcement_prompt(prompt)

    assert encrypted.startswith(PROMPT_ENCRYPTION_PREFIX)
    assert prompt not in encrypted
    assert decrypt_enforcement_prompt(encrypted) == prompt


def test_connector_secret_storage_encrypts_and_round_trips() -> None:
    payload = {"api_key": "secret-value", "username": "svc_user"}
    encrypted = encrypt_connector_secrets(payload)
    assert encrypted is not None
    assert "secret-value" not in encrypted
    assert decrypt_connector_secrets(encrypted) == payload


def test_secret_key_lock_file_is_fingerprint_only(tmp_path: Path) -> None:
    lock_file = tmp_path / "secret_key.lock"
    settings = Settings(
        _env_file=None,
        secret_key="jwt-secret-value",
        secret_key_lock_enabled=True,
        secret_key_lock_file=str(lock_file),
        connector_secrets_key="connector-secret-value",
        connector_secrets_kdf_salt="kdf-salt",
        onprem_bundle_signing_secret="onprem-secret-value",
    )

    ensure_secret_key_lock(settings)

    payload = json.loads(lock_file.read_text(encoding="utf-8"))
    assert payload.get("fingerprint")
    assert "jwt-secret-value" not in lock_file.read_text(encoding="utf-8")


def test_secret_key_lock_rejects_key_drift(tmp_path: Path) -> None:
    lock_file = tmp_path / "secret_key.lock"
    baseline = Settings(
        _env_file=None,
        secret_key="jwt-secret-a",
        secret_key_lock_enabled=True,
        secret_key_lock_file=str(lock_file),
        connector_secrets_key="connector-secret-a",
        connector_secrets_kdf_salt="kdf-salt-a",
        onprem_bundle_signing_secret="onprem-secret-a",
    )
    ensure_secret_key_lock(baseline)

    changed = Settings(
        _env_file=None,
        secret_key="jwt-secret-b",
        secret_key_lock_enabled=True,
        secret_key_lock_file=str(lock_file),
        connector_secrets_key="connector-secret-b",
        connector_secrets_kdf_salt="kdf-salt-b",
        onprem_bundle_signing_secret="onprem-secret-b",
    )
    with pytest.raises(ValueError, match="SECRET_KEY changed from locked value"):
        ensure_secret_key_lock(changed)
