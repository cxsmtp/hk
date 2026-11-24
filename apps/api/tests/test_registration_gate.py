from __future__ import annotations

from time import perf_counter

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError

from app.api.routers import auth as auth_router
from app.core.config import Settings
from app.db.session import get_db
from app.main import app


_GENERIC_REGISTRATION_FAILURE = "Unable to process registration request"
_AUTH_MIN_EXPECTED_SECONDS = 0.22


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "secret_key": "jwt-secret-value",
        "secret_key_lock_enabled": False,
        "connector_secrets_key": "connector-secret-value",
        "connector_secrets_kdf_salt": "connector-kdf-salt",
        "onprem_bundle_signing_secret": "onprem-signing-secret-value",
    }
    values.update(overrides)
    return Settings(**values)


def test_self_registration_is_disabled_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SELF_REGISTRATION_ENABLED", raising=False)

    configured = _settings()

    assert configured.self_registration_enabled is False


@pytest.mark.parametrize("env", ("dev", "development", "test", "demo"))
def test_self_registration_requires_explicit_opt_in_in_recognized_bootstrap_environments(
    env: str,
) -> None:
    configured = _settings(env=env, self_registration_enabled=True)

    assert configured.self_registration_enabled is True


@pytest.mark.parametrize(
    "env",
    ("staging", "qa", "unknown", "pilot", "prod", "production"),
)
def test_self_registration_cannot_be_enabled_outside_recognized_bootstrap_environments(
    env: str,
) -> None:
    with pytest.raises(
        ValidationError,
        match="SELF_REGISTRATION_ENABLED requires a recognized dev, test, or demo ENV",
    ):
        _settings(
            env=env,
            self_registration_enabled=True,
            secret_key="production-jwt-secret-value-with-at-least-32-characters",
        )


def test_self_registration_cannot_be_enabled_in_pilot_mode() -> None:
    with pytest.raises(
        ValidationError,
        match="SELF_REGISTRATION_ENABLED requires a recognized dev, test, or demo ENV",
    ):
        _settings(
            pilot_mode=True,
            self_registration_enabled=True,
            secret_key="production-jwt-secret-value-with-at-least-32-characters",
        )


def test_disabled_registration_fails_before_side_effects_and_normalizes_timing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailOnDatabaseUse:
        def __getattr__(self, name: str):
            raise AssertionError(f"registration touched the database through {name}")

    def override_get_db():
        yield FailOnDatabaseUse()

    def fail_side_effect(*_args, **_kwargs):
        raise AssertionError("registration invoked a side effect while disabled")

    monkeypatch.setattr(auth_router.settings, "self_registration_enabled", False)
    monkeypatch.setattr(auth_router, "get_password_hash", fail_side_effect)
    monkeypatch.setattr(auth_router, "write_audit_log", fail_side_effect)
    monkeypatch.setattr(auth_router, "issue_tokens", fail_side_effect)
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app, raise_server_exceptions=False)
    try:
        started = perf_counter()
        response = client.post(
            "/auth/register",
            json={
                "email": "registration-disabled@example.com",
                "password": "Password123!",
                "full_name": "Registration Disabled",
            },
        )
        elapsed = perf_counter() - started
    finally:
        client.close()
        app.dependency_overrides.clear()

    assert response.status_code == 403
    assert response.json() == {"detail": _GENERIC_REGISTRATION_FAILURE}
    assert elapsed >= _AUTH_MIN_EXPECTED_SECONDS
