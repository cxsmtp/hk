from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-account-boundary-signing")
os.environ.setdefault("CONNECTOR_SECRETS_KEY", "test-connector-secrets-key")
os.environ.setdefault("CONNECTOR_SECRETS_KDF_SALT", "test-connector-secrets-salt")


NOW = datetime(2026, 8, 29, 8, tzinfo=timezone.utc)


@pytest.fixture()
def account_boundary_db(tmp_path):
    from app.db import models as _models  # noqa: F401
    from app.db.session import Base

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'account_boundary.sqlite3'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        yield sessions
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()


def _tenant(db, name: str = "Account Boundary Tenant"):
    from app.db.models.tenant import Tenant

    row = Tenant(name=name, slug=name.lower().replace(" ", "-"), is_active=True)
    db.add(row)
    db.flush()
    return row


def _service():
    from app.services.account_boundary import AccountBoundaryService
    from app.services.action_integrity.signing import LocalSigningKeyProvider
    from app.services.account_boundary_adapters import AccountBoundaryAdapterRegistry, IntegrationValidationResult

    class DeterministicAuthoritativeAdapter:
        def validate_integration(self, **_kwargs):
            return IntegrationValidationResult(status="PASS", route_health="HEALTHY", provider_version="test/1", capabilities=("WORKSPACE_SESSION_BOUND",), valid_for_seconds=7200)
        def verify_identity(self, **_kwargs):
            from app.services.account_boundary_adapters import IdentityVerificationResult
            return IdentityVerificationResult(account_class="ENTERPRISE_MANAGED_USER", organisation_ids=("org-approved",), workspace_ids=("workspace-bank",))

    return AccountBoundaryService(
        pseudonymization_key="account-boundary-pseudonymization-key-0123456789",
        signing_provider=LocalSigningKeyProvider(development=True),
        adapter_registry=AccountBoundaryAdapterRegistry({"openai": DeterministicAuthoritativeAdapter()}),
    )


def _add_signing_keys(service, tenant_id: str):
    from app.services.account_boundary_signing import (
        ACCOUNT_ACCESS_RECEIPT_PURPOSE,
        ACCOUNT_SESSION_PERMIT_PURPOSE,
        VALIDATION_PURPOSE,
    )

    for index, purpose in enumerate((ACCOUNT_SESSION_PERMIT_PURPOSE, ACCOUNT_ACCESS_RECEIPT_PURPOSE, VALIDATION_PURPOSE)):
        service.signing_provider.add_key(
            purpose=purpose,
            tenant_id=tenant_id,
            key_id=f"legacy-{index}",
            secret=(f"{purpose}-{tenant_id}".encode() + b"x" * 64)[:48],
        )


def test_auth_transaction_rejects_referrer_only_and_preserves_shared_idp(account_boundary_db):
    from app.db.models.account_boundary import AIAuthTransaction
    from app.services.account_boundary import AccountBoundaryService

    service = _service()
    with account_boundary_db.begin() as db:
        tenant = _tenant(db)
        transaction = service.start_auth_transaction(
            db,
            tenant_id=tenant.id,
            user_identity_ref="user:analyst",
            device_id="device:mac-1",
            application_asset_id="asset:chatgpt",
            application_family="chatgpt",
            provider="openai",
            product="chatgpt",
            surface="browser",
            initiating_browser_profile="profile:managed-ai",
            initiating_tab_or_navigation_id="tab:100",
            auth_protocol="oidc",
            expected_issuer="https://accounts.google.com",
            expected_client_id="chatgpt-enterprise-client",
            expected_redirect_uri="https://chatgpt.com/auth/callback",
            state="opaque-state",
            nonce="opaque-nonce",
            intended_enterprise_org_ids=["org-approved"],
            intended_workspace_ids=["workspace-bank"],
            policy_id="account-policy",
            policy_version="v12",
            started_at=NOW,
        )

        result = service.correlate_auth_event(
            db,
            tenant_id=tenant.id,
            auth_transaction_id=transaction.auth_transaction_id,
            issuer="https://accounts.google.com",
            client_id="chatgpt-enterprise-client",
            redirect_uri="https://chatgpt.com/auth/callback",
            state="opaque-state",
            nonce="opaque-nonce",
            referrer="https://chatgpt.com/login",
            callback_process_instance=None,
            callback_browser_profile="profile:managed-ai",
            callback_tab_or_navigation_id="tab:100",
            occurred_at=NOW + timedelta(seconds=10),
        )
        assert result["state"] == "AUTH_BOUND"
        assert result["shared_idp_domain_blocked"] is False

        with pytest.raises(PermissionError, match="replayed"):
            service.correlate_auth_event(
                db,
                tenant_id=tenant.id,
                auth_transaction_id=transaction.auth_transaction_id,
                issuer="https://accounts.google.com",
                client_id="wrong-client",
                redirect_uri="https://chatgpt.com/auth/callback",
                state="opaque-state",
                nonce="opaque-nonce",
                referrer="https://chatgpt.com/login",
                callback_browser_profile="profile:managed-ai",
                callback_tab_or_navigation_id="tab:100",
                occurred_at=NOW + timedelta(seconds=11),
            )

        saved = db.scalar(select(AIAuthTransaction).where(AIAuthTransaction.tenant_id == tenant.id))
        assert saved is not None
        assert saved.state_hash != "opaque-state"
        assert saved.nonce_hash != "opaque-nonce"


def test_email_domain_does_not_create_enterprise_membership(account_boundary_db):
    from app.services.account_boundary import AccountBoundaryService

    service = _service()
    with account_boundary_db.begin() as db:
        tenant = _tenant(db)
        personal = service.verify_account_identity(
            db,
            tenant_id=tenant.id,
            provider="google",
            provider_subject_ref="google-subject-1",
            email="analyst@bank.example",
            organisation_ids=[],
            workspace_ids=[],
            tenant_ids=[],
            subscription_class="personal",
            enterprise_membership=False,
            verification_method="email_domain_observed",
            evidence_refs=["evidence:login-page"],
            verified_at=NOW,
        )
        assert personal.account_class == "UNKNOWN"
        assert personal.enterprise_membership is False
        assert personal.email_hash != "analyst@bank.example"

        enterprise = service.verify_account_identity(
            db,
            tenant_id=tenant.id,
            provider="google",
            provider_subject_ref="google-subject-1",
            email="analyst@bank.example",
            organisation_ids=["workspace-bank"],
            workspace_ids=["workspace-bank"],
            tenant_ids=[],
            subscription_class="enterprise",
            enterprise_membership=True,
            verification_method="provider_admin_api",
            evidence_refs=["evidence:admin-api"],
            verified_at=NOW + timedelta(seconds=1),
        )
        assert enterprise.account_class == "UNKNOWN"
        assert enterprise.verification_status == "UNKNOWN"


def test_device_download_decision_uses_persisted_account_and_endpoint_facts(
    account_boundary_db,
):
    from app.db.models.account_boundary import (
        AIAccountIdentity,
        AIAccountSession,
        AccountAccessReceipt,
    )
    from app.db.models.control_coverage import DeploymentSurface

    service = _service()
    with account_boundary_db.begin() as db:
        tenant = _tenant(db, "Device Download Tenant")
        _add_signing_keys(service, tenant.id)
        identity = AIAccountIdentity(
            tenant_id=tenant.id,
            provider="openai",
            provider_subject_ref="subject:enterprise-download",
            account_class="ENTERPRISE_MANAGED_USER",
            organisation_ids=["org-approved"],
            workspace_ids=["workspace-bank"],
            tenant_ids=[],
            enterprise_membership=True,
            role_refs=[],
            verification_method="provider_admin_api",
            verification_status="VERIFIED",
            verified_at=NOW,
            expires_at=NOW + timedelta(hours=2),
            evidence_refs=["evidence:provider-admin"],
        )
        db.add(identity)
        db.flush()
        session = AIAccountSession(
            account_session_id="session-enterprise-download",
            tenant_id=tenant.id,
            provider="openai",
            product="chatgpt",
            surface="browser",
            user_identity_ref="user:download-owner",
            account_identity_ref=identity.id,
            device_id="unregistered-personal-device",
            browser_profile="profile:personal",
            organisation_id="org-approved",
            workspace_id="workspace-bank",
            assurance_level="AB4",
            verification_method="provider_admin_api",
            issued_at=NOW,
            last_verified_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            policy_version="v1",
            session_state="ENTERPRISE_VERIFIED",
            evidence_refs=["evidence:session"],
        )
        db.add(session)
        db.flush()

        result = service.decide_device_download(
            db,
            tenant_id=tenant.id,
            session_id=session.id,
            data_classification="CONFIDENTIAL",
            policy_id="account-device-policy",
            policy_version="v1",
            decided_at=NOW + timedelta(minutes=5),
        )

        assert result["decision"] == "BLOCK_UNKNOWN"
        assert result["reason"] == "corporate_session_denied_download_control_gap"
        assert result["device_assurance"] == "UNMANAGED"
        assert result["enforcement_available"] is False
        assert result["enforcement_status"] == "GAP"
        assert result["control_point"] == "unavailable"
        assert session.session_state == "BYPASS_SUSPECTED"
        assert session.drift_state == "DOWNLOAD_CONTROL_UNAVAILABLE"
        receipt = db.scalar(
            select(AccountAccessReceipt).where(
                AccountAccessReceipt.tenant_id == tenant.id,
                AccountAccessReceipt.id == result["receipt_id"],
            )
        )
        assert receipt is not None
        assert receipt.safe_payload["data_classification"] == "CONFIDENTIAL"
        assert receipt.safe_payload["enforcement_status"] == "GAP"
        assert receipt.control_point == "unavailable"
        assert "inline_download_control_unavailable" in receipt.blind_spots
        assert "corporate_account" not in receipt.safe_payload

        controlled_session = AIAccountSession(
            account_session_id="session-enterprise-download-controlled",
            tenant_id=tenant.id,
            provider="openai",
            product="chatgpt",
            surface="browser",
            user_identity_ref="user:download-owner",
            account_identity_ref=identity.id,
            device_id="unregistered-personal-device",
            browser_profile="profile:personal",
            organisation_id="org-approved",
            workspace_id="workspace-bank",
            assurance_level="AB4",
            verification_method="provider_admin_api",
            issued_at=NOW,
            last_verified_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            policy_version="v1",
            session_state="ENTERPRISE_VERIFIED",
            evidence_refs=["evidence:session"],
        )
        db.add_all(
            [
                controlled_session,
                DeploymentSurface(
                    tenant_id=tenant.id,
                    source_kind="managed_browser",
                    source_id="browser-download-control",
                    name="Managed browser download control",
                    surface_type="browser_extension",
                    deployment_mode="inline",
                    deployment_family="browser",
                    hosting_mode="hybrid",
                    environment="production",
                    status="active",
                    capability_profile={"download_control": "inline_bound"},
                    capability_sources=["managed-browser:server-owned"],
                    control_capability="inline",
                    evidence_capability="complete",
                    containment_capability="direct",
                    bypass_detection_capability="supported",
                    health_status="healthy",
                    health_reason="verified_heartbeat",
                    first_seen_at=NOW,
                    last_seen_at=NOW + timedelta(minutes=6),
                    last_heartbeat_at=NOW + timedelta(minutes=6),
                    last_health_check_at=NOW + timedelta(minutes=6),
                ),
            ]
        )
        db.flush()

        controlled = service.decide_device_download(
            db,
            tenant_id=tenant.id,
            session_id=controlled_session.id,
            data_classification="CONFIDENTIAL",
            policy_id="account-device-policy",
            policy_version="v1",
            decided_at=NOW + timedelta(minutes=6),
        )
        assert controlled["decision"] == "BLOCK_UNKNOWN"
        assert controlled["reason"] == "managed_device_assurance_required"
        assert controlled["enforcement_available"] is True
        assert controlled["enforcement_status"] == "CURRENT"
        assert controlled["control_point"] == "browser-download-control"


def test_selector_and_permit_are_scoped_and_replay_safe(account_boundary_db):
    from app.services.account_boundary import AccountBoundaryService

    service = _service()
    with account_boundary_db.begin() as db:
        tenant = _tenant(db)
        _add_signing_keys(service, tenant.id)
        integration = service.create_integration(
            db, tenant_id=tenant.id, provider="openai", product="chatgpt", surfaces=["desktop"]
        )
        service.validate_integration(db, tenant_id=tenant.id, integration_id=integration.id, surface="desktop", checked_at=NOW)
        account = service.record_server_verified_identity(
            db,
            tenant_id=tenant.id,
            integration_id=integration.id,
            provider_subject_ref="subject:enterprise",
            email="user@bank.example",
            organisation_ids=["org-approved"],
            workspace_ids=["workspace-bank"],
            verified_at=NOW,
        )
        session = service.create_account_session(
            db,
            tenant_id=tenant.id,
            provider="openai",
            product="chatgpt",
            surface="desktop",
            user_identity_ref="user:analyst",
            account_identity_id=account.id,
            device_id="device:mac-1",
            process_instance="proc:chatgpt:1",
            browser_profile=None,
            tab_or_app_session="app-session:1",
            organisation_id="org-approved",
            workspace_id="workspace-bank",
            integration_id=integration.id,
            policy_version="v12",
            issued_at=NOW,
        )
        plan = service.select_boundary_plan(
            db,
            tenant_id=tenant.id,
            integration_id=integration.id,
            provider="openai",
            product="chatgpt",
            surface="desktop",
            required_assurance="AB4",
            device_managed=True,
            checked_at=NOW,
        )
        assert plan["achieved_assurance"] == "AB4"
        assert plan["primary_account_control"] == "WORKSPACE_SESSION_BOUND"

        permit = service.issue_session_permit(
            db,
            tenant_id=tenant.id,
            session_id=session.id,
            device_id="device:mac-1",
            process_instance="proc:chatgpt:1",
            allowed_destination_scope=["chatgpt.com"],
            allowed_data_classes=["internal"],
            allowed_business_purposes=["security-analysis"],
            policy_epoch=12,
            issued_at=NOW,
            ttl_seconds=60,
        )
        ok = service.verify_session_permit(
            db,
            tenant_id=tenant.id,
            permit_id=permit.id,
            device_id="device:mac-1",
            process_instance="proc:chatgpt:1",
            provider="openai",
            product="chatgpt",
            surface="desktop",
            destination="chatgpt.com",
            data_class="internal",
            business_purpose="security-analysis",
            policy_epoch=12,
            checked_at=NOW + timedelta(seconds=5),
        )
        assert ok["valid"] is True

        replay = service.verify_session_permit(
            db,
            tenant_id=tenant.id,
            permit_id=permit.id,
            device_id="device:other",
            process_instance="proc:chatgpt:1",
            provider="openai",
            product="chatgpt",
            surface="desktop",
            destination="chatgpt.com",
            data_class="internal",
            business_purpose="security-analysis",
            policy_epoch=12,
            checked_at=NOW + timedelta(seconds=6),
        )
        assert replay["valid"] is False
        assert replay["reason"] == "permit_consumed"


def test_personal_account_blocks_and_provider_manifests_default_unverified(account_boundary_db):
    from app.db.models.account_boundary import AccountAccessReceipt
    from app.services.account_boundary import AccountBoundaryService

    service = _service()
    with account_boundary_db.begin() as db:
        tenant = _tenant(db)
        _add_signing_keys(service, tenant.id)
        personal = service.verify_account_identity(
            db,
            tenant_id=tenant.id,
            provider="openai",
            provider_subject_ref="subject:personal",
            email="user@gmail.com",
            organisation_ids=[],
            workspace_ids=[],
            tenant_ids=[],
            subscription_class="free",
            enterprise_membership=False,
            verification_method="provider_session_observed",
            evidence_refs=["evidence:browser"],
            verified_at=NOW,
        )
        session = service.create_account_session(
            db,
            tenant_id=tenant.id,
            provider="openai",
            product="chatgpt",
            surface="browser",
            user_identity_ref="user:analyst",
            account_identity_id=personal.id,
            device_id="device:mac-1",
            process_instance=None,
            browser_profile="profile:managed-ai",
            tab_or_app_session="tab:101",
            organisation_id=None,
            workspace_id=None,
            policy_version="v12",
            issued_at=NOW,
        )
        decision = service.decide_account_access(
            db,
            tenant_id=tenant.id,
            session_id=session.id,
            required_assurance="AB4",
            control_point="browser",
            policy_id="account-policy",
            policy_version="v12",
            decided_at=NOW,
        )
        assert decision["decision"] == "BLOCK_PERSONAL"
        receipt = db.scalar(select(AccountAccessReceipt).where(AccountAccessReceipt.tenant_id == tenant.id))
        assert receipt is not None
        assert receipt.decision == "BLOCK_PERSONAL"
        assert receipt.signature

        providers = service.provider_capability_manifests()
        assert providers["cursor"]["capabilities"]["PROVIDER_SERVER_RESTRICTION"]["verification"] == "UNVERIFIED"
        assert providers["openai"]["capabilities"]["PROVIDER_SERVER_RESTRICTION"]["verification"] == "UNVERIFIED"
