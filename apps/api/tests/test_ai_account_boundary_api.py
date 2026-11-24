from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-account-boundary-signing")
os.environ.setdefault("CONNECTOR_SECRETS_KEY", "test-connector-secrets-key")
os.environ.setdefault("CONNECTOR_SECRETS_KDF_SALT", "test-connector-secrets-salt")


def test_identity_api_rejects_client_asserted_enterprise_claims() -> None:
    from app.api.routers.account_boundary import VerifyAccountIdentityRequest

    with pytest.raises(ValidationError):
        VerifyAccountIdentityRequest.model_validate(
            {
                "provider": "openai",
                "provider_subject_ref": "client-subject",
                "verification_method": "provider_admin_api",
                "enterprise_membership": True,
                "organisation_ids": ["forged-org"],
            }
        )


def test_selector_api_rejects_client_asserted_capability_or_route_health() -> None:
    from app.api.routers.account_boundary import SelectBoundaryPlanRequest

    with pytest.raises(ValidationError):
        SelectBoundaryPlanRequest.model_validate(
            {
                "provider": "openai",
                "product": "chatgpt",
                "surface": "browser",
                "required_assurance": "AB4",
                "device_managed": True,
                "provider_capabilities": ["WORKSPACE_SESSION_BOUND"],
                "route_healthy": True,
            }
        )


def test_device_download_api_rejects_client_asserted_account_or_device_authority() -> None:
    from app.api.routers.account_boundary import DecideDeviceDownloadRequest

    base = {
        "session_id": "session-1",
        "data_classification": "CONFIDENTIAL",
    }
    for field, value in (
        ("control_point", "managed_browser"),
        ("corporate_account", True),
        ("device_assurance", "MANAGED_COMPLIANT"),
        ("download_control_available", True),
    ):
        with pytest.raises(ValidationError):
            DecideDeviceDownloadRequest.model_validate({**base, field: value})


def test_router_returns_service_unavailable_when_authority_is_not_configured(monkeypatch) -> None:
    from app.api.routers import account_boundary
    from types import SimpleNamespace

    monkeypatch.setattr(account_boundary, "settings", SimpleNamespace(ai_account_boundary=True))
    with pytest.raises(account_boundary.HTTPException) as exc_info:
        account_boundary._service(SimpleNamespace(info={}))
    assert exc_info.value.status_code == 503


def test_router_uses_request_scoped_signer_and_identity_schema_has_no_client_membership_fields(monkeypatch) -> None:
    from types import SimpleNamespace
    from app.api.routers import account_boundary
    from app.api.routers.account_boundary import VerifyAccountIdentityRequest, _service
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    with pytest.raises(ValidationError):
        VerifyAccountIdentityRequest.model_validate({"integration_id": "i", "provider_subject_ref": "s", "organisation_ids": ["forged"]})
    provider = LocalSigningKeyProvider(development=True)
    monkeypatch.setattr(account_boundary, "settings", SimpleNamespace(ai_account_boundary=True, account_boundary_pseudonymization_key="x" * 32))
    service = _service(SimpleNamespace(info={"account_boundary_signing_provider": provider}))
    assert service.signing_provider is provider
