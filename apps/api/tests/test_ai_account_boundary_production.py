from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-account-boundary-signing")
os.environ.setdefault("CONNECTOR_SECRETS_KEY", "test-connector-secrets-key")
os.environ.setdefault("CONNECTOR_SECRETS_KDF_SALT", "test-connector-secrets-salt")


NOW = datetime(2026, 8, 29, 8, tzinfo=timezone.utc)


@pytest.fixture()
def db_sessions(tmp_path):
    from app.db import models as _models  # noqa: F401
    from app.db.session import Base

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'account-boundary-production.sqlite3'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield sessions
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def _tenant(db, slug: str):
    from app.db.models.tenant import Tenant

    row = Tenant(name=slug, slug=slug, is_active=True)
    db.add(row)
    db.flush()
    return row


def _service_for(tenant_id: str):
    from app.services.account_boundary import AccountBoundaryService
    from app.services.account_boundary_signing import (
        ACCOUNT_ACCESS_RECEIPT_PURPOSE,
        ACCOUNT_SESSION_PERMIT_PURPOSE,
        VALIDATION_PURPOSE,
    )
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.account_boundary_adapters import AccountBoundaryAdapterRegistry, IntegrationValidationResult

    class DeterministicAuthoritativeAdapter:
        def validate_integration(self, **_kwargs):
            return IntegrationValidationResult(status="PASS", route_health="HEALTHY", provider_version="test/1", capabilities=("WORKSPACE_SESSION_BOUND",), valid_for_seconds=7200)
        def verify_identity(self, **_kwargs):
            from app.services.account_boundary_adapters import IdentityVerificationResult
            return IdentityVerificationResult(account_class="ENTERPRISE_MANAGED_USER", organisation_ids=("org-bank", "org-approved"), workspace_ids=("workspace-bank",))

    provider = LocalSigningKeyProvider(development=True)
    for index, purpose in enumerate((ACCOUNT_SESSION_PERMIT_PURPOSE, ACCOUNT_ACCESS_RECEIPT_PURPOSE, VALIDATION_PURPOSE)):
        provider.add_key(
            purpose=purpose,
            tenant_id=tenant_id,
            key_id=f"key-{index}",
            secret=(f"{purpose}-{tenant_id}".encode() + b"x" * 64)[:48],
        )
    return AccountBoundaryService(
        pseudonymization_key="account-boundary-pseudonymization-key-0123456789",
        signing_provider=provider,
        adapter_registry=AccountBoundaryAdapterRegistry({"openai": DeterministicAuthoritativeAdapter()}),
    )


def test_service_requires_distinct_pseudonymization_key_and_signing_provider() -> None:
    from app.services.account_boundary import AccountBoundaryService

    with pytest.raises(ValueError, match="pseudonymization"):
        AccountBoundaryService(signing_provider=object())
    with pytest.raises(ValueError, match="signing provider"):
        AccountBoundaryService(pseudonymization_key="x" * 32)


def test_client_claimed_enterprise_and_capabilities_never_select_enterprise_control(db_sessions) -> None:
    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-claims")
        service = _service_for(tenant.id)
        identity = service.verify_account_identity(
            db,
            tenant_id=tenant.id,
            provider="openai",
            provider_subject_ref="subject:client-claimed",
            email="analyst@bank.example",
            organisation_ids=["org-bank"],
            workspace_ids=["workspace-bank"],
            tenant_ids=[],
            subscription_class="enterprise",
            enterprise_membership=True,
            verification_method="provider_admin_api",
            evidence_refs=["client:forged"],
            verified_at=NOW,
        )
        assert identity.account_class == "UNKNOWN"
        plan = service.select_boundary_plan(
            db,
            tenant_id=tenant.id,
            provider="openai",
            product="chatgpt",
            surface="browser",
            required_assurance="AB4",
            device_managed=True,
            provider_capabilities=["WORKSPACE_SESSION_BOUND"],
            route_healthy=True,
        )
        assert plan["achieved_assurance"] == "AB0"
        assert plan["truth"] == "no_current_server_validation"


def test_signed_permit_rejects_envelope_tamper_replay_and_exact_binding(db_sessions) -> None:
    from app.db.models.account_boundary import AccountBoundaryValidation

    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-permits")
        service = _service_for(tenant.id)
        integration = service.create_integration(
            db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"]
        )
        validation = service.validate_integration(db, tenant_id=tenant.id, integration_id=integration.id, surface="desktop", checked_at=NOW)
        identity = service.record_server_verified_identity(
            db,
            tenant_id=tenant.id,
            integration_id=integration.id,
            provider_subject_ref="subject:verified",
            email="analyst@bank.example",
            organisation_ids=["org-bank"],
            workspace_ids=["workspace-bank"],
            verified_at=NOW,
        )
        session = service.create_account_session(
            db, tenant_id=tenant.id, provider="openai", product="chatgpt", surface="desktop",
            user_identity_ref="user:analyst", account_identity_id=identity.id, device_id="device:1",
            process_instance="process:1", browser_profile=None, tab_or_app_session="app:1",
            organisation_id="org-bank", workspace_id="workspace-bank", policy_version="p1", issued_at=NOW,
            integration_id=integration.id,
        )
        permit = service.issue_session_permit(
            db, tenant_id=tenant.id, session_id=session.id, device_id="device:1", process_instance="process:1",
            allowed_destination_scope=["chatgpt.com"], allowed_data_classes=["internal"],
            allowed_business_purposes=["analysis"], policy_epoch=7, issued_at=NOW, ttl_seconds=60,
        )
        assert permit.signed_envelope["signature"] == permit.signature
        permit.signed_envelope["surface"] = "browser"
        assert service.verify_session_permit(
            db, tenant_id=tenant.id, permit_id=permit.id, device_id="device:1", process_instance="process:1",
            provider="openai", product="chatgpt", surface="desktop", destination="chatgpt.com", data_class="internal", business_purpose="analysis", policy_epoch=7,
            checked_at=NOW + timedelta(seconds=1),
        ) == {"valid": False, "reason": "envelope_mismatch"}
        permit.signed_envelope = dict(permit.signed_envelope, surface="desktop")
        permit.signature = "tampered"
        assert service.verify_session_permit(
            db, tenant_id=tenant.id, permit_id=permit.id, device_id="device:1", process_instance="process:1",
            provider="openai", product="chatgpt", surface="desktop", destination="chatgpt.com", data_class="internal", business_purpose="analysis", policy_epoch=7,
            checked_at=NOW + timedelta(seconds=2),
        ) == {"valid": False, "reason": "envelope_mismatch"}


def test_permit_is_single_use_and_revalidation_revokes_on_policy_or_route_drift(db_sessions) -> None:
    from app.db.models.account_boundary import AccountBoundaryValidation

    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-revalidate")
        service = _service_for(tenant.id)
        integration = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        service.validate_integration(db, tenant_id=tenant.id, integration_id=integration.id, surface="desktop", checked_at=NOW)
        integration.lifecycle_state = "VALIDATE"
        identity = service.record_server_verified_identity(
            db, tenant_id=tenant.id, integration_id=integration.id, provider_subject_ref="subject:verified",
            email=None, organisation_ids=["org-bank"], workspace_ids=[], verified_at=NOW,
        )
        session = service.create_account_session(
            db, tenant_id=tenant.id, provider="openai", product="chatgpt", surface="desktop", user_identity_ref="user:analyst",
            account_identity_id=identity.id, device_id="device:1", process_instance="process:1", browser_profile=None,
            tab_or_app_session="app:1", organisation_id="org-bank", workspace_id=None, policy_version="p1", issued_at=NOW,
            integration_id=integration.id,
        )
        permit = service.issue_session_permit(
            db, tenant_id=tenant.id, session_id=session.id, device_id="device:1", process_instance="process:1",
            allowed_destination_scope=["chatgpt.com"], allowed_data_classes=["internal"], allowed_business_purposes=["analysis"],
            policy_epoch=7, issued_at=NOW, ttl_seconds=60,
        )
        assert service.verify_session_permit(
            db, tenant_id=tenant.id, permit_id=permit.id, device_id="device:1", process_instance="process:1",
                provider="openai", product="chatgpt", surface="desktop", destination="chatgpt.com", data_class="internal", business_purpose="analysis", policy_epoch=7,
            checked_at=NOW + timedelta(seconds=1),
        )["valid"] is True
        assert service.verify_session_permit(
            db, tenant_id=tenant.id, permit_id=permit.id, device_id="device:1", process_instance="process:1",
                provider="openai", product="chatgpt", surface="desktop", destination="chatgpt.com", data_class="internal", business_purpose="analysis", policy_epoch=7,
            checked_at=NOW + timedelta(seconds=2),
        ) == {"valid": False, "reason": "permit_consumed"}
        service.revalidate_session(
            db, tenant_id=tenant.id, session_id=session.id, policy_version="p2", checked_at=NOW + timedelta(seconds=3)
        )
        assert permit.revoked is True


def test_provider_manifest_keeps_all_approved_families_unverified() -> None:
    service = _service_for("manifest-tenant")
    manifests = service.provider_capability_manifests()
    assert {"windsurf", "perplexity", "replit", "notion", "slack", "atlassian", "salesforce", "zoom", "servicenow", "grok", "poe", "deepseek", "kimi", "qwen", "mistral"} <= set(manifests)
    assert all(value["verification_status"] == "UNVERIFIED" for value in manifests.values())


def test_validation_requires_exact_signed_integration_envelope_and_every_surface(db_sessions) -> None:
    from app.db.models.account_boundary import AccountBoundaryValidation

    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-validation")
        service = _service_for(tenant.id)
        integration = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["browser", "desktop"])
        other = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["browser"])
        db.add(AccountBoundaryValidation(
            tenant_id=tenant.id, integration_id=integration.id, provider="openai", product="chatgpt", surface="browser",
            validation_type="server_owned", status="PASS", measured_at=NOW, valid_until=NOW + timedelta(hours=1), route_health="HEALTHY", provider_version="test/1", result={"capabilities": []},
        ))
        db.flush()
        integration.lifecycle_state = "VALIDATE"
        assert service.select_boundary_plan(db, tenant_id=tenant.id, integration_id=integration.id, provider="openai", product="chatgpt", surface="browser", required_assurance="AB4", device_managed=True)["truth"] == "no_current_server_validation"
        with pytest.raises(PermissionError, match="current_passing_validation_required"):
            service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=integration.id, target_state="MONITOR")
        assert service._current_validation(db, tenant_id=tenant.id, integration_id=other.id, provider="openai", product="chatgpt", surface="browser", checked_at=NOW) is None


def test_auth_transaction_requires_state_nonce_and_cannot_be_replayed(db_sessions) -> None:
    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-oauth")
        service = _service_for(tenant.id)
        with pytest.raises(ValueError, match="state"):
            service.start_auth_transaction(db, tenant_id=tenant.id, user_identity_ref="u", device_id="d", application_asset_id=None, application_family="app", provider="openai", product="chatgpt", surface="browser", auth_protocol="oidc", state=None, nonce="n", started_at=NOW)
        tx = service.start_auth_transaction(db, tenant_id=tenant.id, user_identity_ref="u", device_id="d", application_asset_id=None, application_family="app", provider="openai", product="chatgpt", surface="browser", auth_protocol="oidc", state="state", nonce="nonce", started_at=NOW)
        service.correlate_auth_event(db, tenant_id=tenant.id, auth_transaction_id=tx.auth_transaction_id, issuer=None, client_id=None, redirect_uri=None, state="state", nonce="nonce", occurred_at=NOW + timedelta(seconds=1))
        with pytest.raises(PermissionError, match="replayed"):
            service.correlate_auth_event(db, tenant_id=tenant.id, auth_transaction_id=tx.auth_transaction_id, issuer=None, client_id=None, redirect_uri=None, state="state", nonce="nonce", occurred_at=NOW + timedelta(seconds=2))


def test_permit_requires_data_class_and_business_purpose_without_consuming_on_mismatch(db_sessions) -> None:
    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-permit-scope")
        service = _service_for(tenant.id)
        integration = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        service.validate_integration(db, tenant_id=tenant.id, integration_id=integration.id, surface="desktop", checked_at=NOW)
        identity = service.record_server_verified_identity(db, tenant_id=tenant.id, integration_id=integration.id, provider_subject_ref="s", email=None, verified_at=NOW)
        session = service.create_account_session(db, tenant_id=tenant.id, integration_id=integration.id, provider="openai", product="chatgpt", surface="desktop", user_identity_ref="u", account_identity_id=identity.id, device_id="d", process_instance="p", browser_profile=None, tab_or_app_session=None, organisation_id="org-bank", workspace_id=None, policy_version="v", issued_at=NOW)
        permit = service.issue_session_permit(db, tenant_id=tenant.id, session_id=session.id, device_id="d", process_instance="p", allowed_destination_scope=["chatgpt.com"], allowed_data_classes=["internal"], allowed_business_purposes=["analysis"], policy_epoch=1, issued_at=NOW, ttl_seconds=60)
        denied = service.verify_session_permit(db, tenant_id=tenant.id, permit_id=permit.id, device_id="d", process_instance="p", provider="openai", product="chatgpt", surface="desktop", destination="chatgpt.com", data_class="restricted", business_purpose="analysis", policy_epoch=1, checked_at=NOW + timedelta(seconds=1))
        assert denied == {"valid": False, "reason": "data_class_mismatch"}
        assert permit.consumed_count == 0


def test_permit_from_non_current_authority_is_rejected_without_consuming(db_sessions) -> None:
    from app.services.account_boundary_signing import ACCOUNT_SESSION_PERMIT_PURPOSE

    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-rotated-permit")
        service = _service_for(tenant.id)
        integration = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        service.validate_integration(db, tenant_id=tenant.id, integration_id=integration.id, surface="desktop", checked_at=NOW)
        identity = service.record_server_verified_identity(db, tenant_id=tenant.id, integration_id=integration.id, provider_subject_ref="subject", email=None, verified_at=NOW)
        session = service.create_account_session(db, tenant_id=tenant.id, integration_id=integration.id, provider="openai", product="chatgpt", surface="desktop", user_identity_ref="user", account_identity_id=identity.id, device_id="device", process_instance="process", browser_profile=None, tab_or_app_session=None, organisation_id="org-bank", workspace_id=None, policy_version="policy", issued_at=NOW)
        permit = service.issue_session_permit(db, tenant_id=tenant.id, session_id=session.id, device_id="device", process_instance="process", allowed_destination_scope=["chatgpt.com"], allowed_data_classes=["internal"], allowed_business_purposes=["analysis"], policy_epoch=1, issued_at=NOW, ttl_seconds=60)

        service.signing_provider.set_state(purpose=ACCOUNT_SESSION_PERMIT_PURPOSE, tenant_id=tenant.id, key_id=permit.signing_key_id, state="verify_only")
        rejected = service.verify_session_permit(db, tenant_id=tenant.id, permit_id=permit.id, device_id="device", process_instance="process", provider="openai", product="chatgpt", surface="desktop", destination="chatgpt.com", data_class="internal", business_purpose="analysis", policy_epoch=1, checked_at=NOW + timedelta(seconds=1))

        assert rejected == {"valid": False, "reason": "invalid_signature"}
        assert permit.consumed_count == 0


def test_same_provider_sibling_cannot_change_bound_partner_decision_or_permit_revocation(db_sessions) -> None:
    from app.services.account_boundary_adapters import AccountBoundaryAdapterRegistry, IdentityVerificationResult, IntegrationValidationResult
    from app.services.account_boundary import AccountBoundaryService
    from app.services.account_boundary_signing import ACCOUNT_ACCESS_RECEIPT_PURPOSE, ACCOUNT_SESSION_PERMIT_PURPOSE, VALIDATION_PURPOSE
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    class PartnerAdapter:
        def validate_integration(self, **_kwargs):
            return IntegrationValidationResult(status="PASS", route_health="HEALTHY", provider_version="test/1", capabilities=("WORKSPACE_SESSION_BOUND",), valid_for_seconds=7200)

        def verify_identity(self, **_kwargs):
            return IdentityVerificationResult(account_class="PARTNER_ENTERPRISE", organisation_ids=("org-partner",), workspace_ids=())

    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-sibling")
        provider = LocalSigningKeyProvider(development=True)
        for index, purpose in enumerate((ACCOUNT_SESSION_PERMIT_PURPOSE, ACCOUNT_ACCESS_RECEIPT_PURPOSE, VALIDATION_PURPOSE)):
            provider.add_key(purpose=purpose, tenant_id=tenant.id, key_id=f"key-{index}", secret=(f"{purpose}-{tenant.id}".encode() + b"x" * 64)[:48])
        service = AccountBoundaryService(pseudonymization_key="account-boundary-pseudonymization-key-0123456789", signing_provider=provider, adapter_registry=AccountBoundaryAdapterRegistry({"openai": PartnerAdapter()}))
        sibling = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        bound = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        service.validate_integration(db, tenant_id=tenant.id, integration_id=sibling.id, surface="desktop", checked_at=NOW)
        service.validate_integration(db, tenant_id=tenant.id, integration_id=bound.id, surface="desktop", checked_at=NOW)
        for state in ("SIMULATE", "VALIDATE", "MONITOR"):
            service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=bound.id, target_state=state, checked_at=NOW)
        service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=bound.id, target_state="ENFORCE", enforcement_enabled=True, checked_at=NOW)
        identity = service.record_server_verified_identity(db, tenant_id=tenant.id, integration_id=bound.id, provider_subject_ref="partner", email=None, verified_at=NOW)
        bound_session = service.create_account_session(db, tenant_id=tenant.id, integration_id=bound.id, provider="openai", product="chatgpt", surface="desktop", user_identity_ref="partner", account_identity_id=identity.id, device_id="bound-device", process_instance="bound-process", browser_profile=None, tab_or_app_session=None, organisation_id="org-partner", workspace_id=None, policy_version="policy", issued_at=NOW)
        sibling_identity = service.record_server_verified_identity(db, tenant_id=tenant.id, integration_id=sibling.id, provider_subject_ref="sibling-partner", email=None, verified_at=NOW)
        sibling_session = service.create_account_session(db, tenant_id=tenant.id, integration_id=sibling.id, provider="openai", product="chatgpt", surface="desktop", user_identity_ref="sibling-partner", account_identity_id=sibling_identity.id, device_id="sibling-device", process_instance="sibling-process", browser_profile=None, tab_or_app_session=None, organisation_id="org-partner", workspace_id=None, policy_version="policy", issued_at=NOW)
        bound_permit = service.issue_session_permit(db, tenant_id=tenant.id, session_id=bound_session.id, device_id="bound-device", process_instance="bound-process", allowed_destination_scope=["chatgpt.com"], allowed_data_classes=["internal"], allowed_business_purposes=["analysis"], policy_epoch=1, issued_at=NOW, ttl_seconds=60)
        sibling_permit = service.issue_session_permit(db, tenant_id=tenant.id, session_id=sibling_session.id, device_id="sibling-device", process_instance="sibling-process", allowed_destination_scope=["chatgpt.com"], allowed_data_classes=["internal"], allowed_business_purposes=["analysis"], policy_epoch=1, issued_at=NOW, ttl_seconds=60)

        decision = service.decide_account_access(db, tenant_id=tenant.id, session_id=bound_session.id, required_assurance="AB4", control_point="desktop", policy_id="policy", policy_version="policy", decided_at=NOW + timedelta(seconds=1))
        service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=bound.id, target_state="DISABLED", checked_at=NOW + timedelta(seconds=2))

        assert identity.account_class == "PARTNER_ENTERPRISE"
        assert decision["decision"] == "ALLOW_PARTNER"
        assert bound_permit.revoked is True
        assert sibling_permit.revoked is False


def test_client_observation_cannot_assert_trusted_partner_class(db_sessions) -> None:
    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-client-class")
        service = _service_for(tenant.id)
        identity = service.verify_account_identity(db, tenant_id=tenant.id, provider="openai", provider_subject_ref="client", email="partner@example.com", organisation_ids=["org-partner"], workspace_ids=[], tenant_ids=[], subscription_class="enterprise", enterprise_membership=True, verification_method="client", evidence_refs=[], verified_at=NOW)

        assert identity.account_class == "UNKNOWN"


def test_lifecycle_requires_enforcement_flag_and_keeps_mode_synchronized(db_sessions) -> None:
    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-lifecycle-mode")
        service = _service_for(tenant.id)
        integration = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        service.validate_integration(db, tenant_id=tenant.id, integration_id=integration.id, surface="desktop", checked_at=NOW)
        for state in ("SIMULATE", "VALIDATE", "MONITOR"):
            service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=integration.id, target_state=state, checked_at=NOW)
        assert integration.mode == "monitor"
        with pytest.raises(PermissionError, match="enforcement_enabled_required"):
            service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=integration.id, target_state="ENFORCE", checked_at=NOW)

        service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=integration.id, target_state="ENFORCE", enforcement_enabled=True, checked_at=NOW)
        assert integration.mode == "enforce"
        service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=integration.id, target_state="DISABLED", checked_at=NOW)
        assert integration.mode == "disabled"


def test_server_verified_external_identity_creates_unapproved_session_and_blocks(db_sessions) -> None:
    from app.services.account_boundary_adapters import AccountBoundaryAdapterRegistry, IdentityVerificationResult, IntegrationValidationResult
    from app.services.account_boundary import AccountBoundaryService
    from app.services.account_boundary_signing import ACCOUNT_ACCESS_RECEIPT_PURPOSE, ACCOUNT_SESSION_PERMIT_PURPOSE, VALIDATION_PURPOSE
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    class ExternalAdapter:
        def validate_integration(self, **_kwargs):
            return IntegrationValidationResult(status="PASS", route_health="HEALTHY", provider_version="test/1", capabilities=("WORKSPACE_SESSION_BOUND",), valid_for_seconds=7200)

        def verify_identity(self, **_kwargs):
            return IdentityVerificationResult(account_class="EXTERNAL_ENTERPRISE", organisation_ids=("org-external",), workspace_ids=())

    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-external")
        provider = LocalSigningKeyProvider(development=True)
        for index, purpose in enumerate((ACCOUNT_SESSION_PERMIT_PURPOSE, ACCOUNT_ACCESS_RECEIPT_PURPOSE, VALIDATION_PURPOSE)):
            provider.add_key(purpose=purpose, tenant_id=tenant.id, key_id=f"key-{index}", secret=(f"{purpose}-{tenant.id}".encode() + b"x" * 64)[:48])
        service = AccountBoundaryService(pseudonymization_key="account-boundary-pseudonymization-key-0123456789", signing_provider=provider, adapter_registry=AccountBoundaryAdapterRegistry({"openai": ExternalAdapter()}))
        integration = service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        service.validate_integration(db, tenant_id=tenant.id, integration_id=integration.id, surface="desktop", checked_at=NOW)
        for state in ("SIMULATE", "VALIDATE", "MONITOR"):
            service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=integration.id, target_state=state, checked_at=NOW)
        service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=integration.id, target_state="ENFORCE", enforcement_enabled=True, checked_at=NOW)
        identity = service.record_server_verified_identity(db, tenant_id=tenant.id, integration_id=integration.id, provider_subject_ref="external", email=None, verified_at=NOW)
        session = service.create_account_session(db, tenant_id=tenant.id, integration_id=integration.id, provider="openai", product="chatgpt", surface="desktop", user_identity_ref="external", account_identity_id=identity.id, device_id="device", process_instance="process", browser_profile=None, tab_or_app_session=None, organisation_id="org-external", workspace_id=None, policy_version="policy", issued_at=NOW)
        decision = service.decide_account_access(db, tenant_id=tenant.id, session_id=session.id, required_assurance="AB4", control_point="desktop", policy_id="policy", policy_version="policy", decided_at=NOW + timedelta(seconds=1))

        assert session.session_state == "EXTERNAL_UNAPPROVED"
        assert decision["decision"] == "BLOCK_EXTERNAL_TENANT"


def test_sibling_reverification_drifts_original_session_and_revokes_permit(db_sessions) -> None:
    from app.services.account_boundary_adapters import AccountBoundaryAdapterRegistry, IdentityVerificationResult, IntegrationValidationResult
    from app.services.account_boundary import AccountBoundaryService
    from app.services.account_boundary_signing import ACCOUNT_ACCESS_RECEIPT_PURPOSE, ACCOUNT_SESSION_PERMIT_PURPOSE, VALIDATION_PURPOSE
    from app.services.action_integrity.signing import LocalSigningKeyProvider

    class PartnerAdapter:
        def validate_integration(self, **_kwargs):
            return IntegrationValidationResult(status="PASS", route_health="HEALTHY", provider_version="test/1", capabilities=("WORKSPACE_SESSION_BOUND",), valid_for_seconds=7200)

        def verify_identity(self, **_kwargs):
            return IdentityVerificationResult(account_class="PARTNER_ENTERPRISE", organisation_ids=("org-partner",), workspace_ids=())

    class EnterpriseAdapter(PartnerAdapter):
        def verify_identity(self, **_kwargs):
            return IdentityVerificationResult(account_class="ENTERPRISE_MANAGED_USER", organisation_ids=("org-sibling",), workspace_ids=())

    with db_sessions.begin() as db:
        tenant = _tenant(db, "account-boundary-provenance")
        provider = LocalSigningKeyProvider(development=True)
        for index, purpose in enumerate((ACCOUNT_SESSION_PERMIT_PURPOSE, ACCOUNT_ACCESS_RECEIPT_PURPOSE, VALIDATION_PURPOSE)):
            provider.add_key(purpose=purpose, tenant_id=tenant.id, key_id=f"key-{index}", secret=(f"{purpose}-{tenant.id}".encode() + b"x" * 64)[:48])
        partner_service = AccountBoundaryService(pseudonymization_key="account-boundary-pseudonymization-key-0123456789", signing_provider=provider, adapter_registry=AccountBoundaryAdapterRegistry({"openai": PartnerAdapter()}))
        enterprise_service = AccountBoundaryService(pseudonymization_key="account-boundary-pseudonymization-key-0123456789", signing_provider=provider, adapter_registry=AccountBoundaryAdapterRegistry({"openai": EnterpriseAdapter()}))
        bound = partner_service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        sibling = partner_service.create_integration(db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"])
        partner_service.validate_integration(db, tenant_id=tenant.id, integration_id=bound.id, surface="desktop", checked_at=NOW)
        partner_service.validate_integration(db, tenant_id=tenant.id, integration_id=sibling.id, surface="desktop", checked_at=NOW)
        for state in ("SIMULATE", "VALIDATE", "MONITOR"):
            partner_service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=bound.id, target_state=state, checked_at=NOW)
        partner_service.advance_lifecycle(db, tenant_id=tenant.id, integration_id=bound.id, target_state="ENFORCE", enforcement_enabled=True, checked_at=NOW)
        identity = partner_service.record_server_verified_identity(db, tenant_id=tenant.id, integration_id=bound.id, provider_subject_ref="shared-subject", email=None, verified_at=NOW)
        session = partner_service.create_account_session(db, tenant_id=tenant.id, integration_id=bound.id, provider="openai", product="chatgpt", surface="desktop", user_identity_ref="partner", account_identity_id=identity.id, device_id="device", process_instance="process", browser_profile=None, tab_or_app_session=None, organisation_id="org-partner", workspace_id=None, policy_version="policy", issued_at=NOW)
        permit = partner_service.issue_session_permit(db, tenant_id=tenant.id, session_id=session.id, device_id="device", process_instance="process", allowed_destination_scope=["chatgpt.com"], allowed_data_classes=["internal"], allowed_business_purposes=["analysis"], policy_epoch=1, issued_at=NOW, ttl_seconds=60)

        enterprise_service.record_server_verified_identity(db, tenant_id=tenant.id, integration_id=sibling.id, provider_subject_ref="shared-subject", email=None, verified_at=NOW + timedelta(seconds=1))
        permit_result = partner_service.verify_session_permit(db, tenant_id=tenant.id, permit_id=permit.id, device_id="device", process_instance="process", provider="openai", product="chatgpt", surface="desktop", destination="chatgpt.com", data_class="internal", business_purpose="analysis", policy_epoch=1, checked_at=NOW + timedelta(seconds=2))
        decision = partner_service.decide_account_access(db, tenant_id=tenant.id, session_id=session.id, required_assurance="AB4", control_point="desktop", policy_id="policy", policy_version="policy", decided_at=NOW + timedelta(seconds=2))

        assert session.session_state == "DRIFTED"
        assert permit.revoked is True
        assert permit.consumed_count == 0
        assert permit_result == {"valid": False, "reason": "session_identity_mismatch"}
        assert decision["decision"] == "BLOCK_UNKNOWN"
