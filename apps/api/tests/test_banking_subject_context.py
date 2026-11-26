from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.models.tenant import Tenant
from app.db.session import Base


ISSUER = "https://bank.example/auth"
AUDIENCE = "hawk-bank-foundry"
KEY_ID = "bank-key-1"
PSEUDONYMIZATION_KEY = "bank-pseudonymization-key-material-00000001"


@pytest.fixture()
def subject_context_env():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = session_local()
    db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
    db.commit()
    settings_obj = SimpleNamespace(
        banking_transaction_integrity_enabled=True,
        banking_subject_trust_json=json.dumps(
            {
                ISSUER: {
                    "audience": AUDIENCE,
                    "keys": {KEY_ID: public_pem},
                }
            }
        ),
        banking_subject_pseudonymization_key=PSEUDONYMIZATION_KEY,
    )
    try:
        yield {
            "db": db,
            "private_pem": private_pem,
            "public_pem": public_pem,
            "settings": settings_obj,
        }
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _issue_assertion(
    private_pem: str,
    *,
    audience: str = AUDIENCE,
    key_id: str = KEY_ID,
    nonce: str = "nonce-0000000001",
    customer_subject_id: str = "customer-001",
    approved_account_ids: tuple[str, ...] = ("acct-001",),
    approved_resource_scope: tuple[str, ...] = ("bank.customer/current/summary",),
    provenance: str = "bank_api_gateway",
    expires_delta: timedelta = timedelta(minutes=5),
) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "tenant_id": "tenant-a",
        "subject_type": "customer",
        "customer_subject_id": customer_subject_id,
        "authenticated_principal_id": "principal-001",
        "mobile_session_id": "mobile-session-001",
        "channel": "mobile_banking",
        "approved_account_ids": list(approved_account_ids),
        "approved_resource_scope": list(approved_resource_scope),
        "approved_resource_scopes": [
            {
                "resource_type": "account",
                "resource_reference": account_id,
                "relationship_to_subject": "owner",
                "allowed_operations": ["read_summary", "list_transactions"],
                "expires_at": (now + expires_delta).isoformat(),
                "source_of_authority": "bank_api_gateway",
            }
            for account_id in approved_account_ids
        ],
        "device_trust_reference": "device-trust-001",
        "purpose_id": "own-account-summary",
        "authority_scope": ["account.read_summary", "account.list_transactions"],
        "auth_time": int((now - timedelta(minutes=1)).timestamp()),
        "provenance": provenance,
        "trust_level": "hardware_bound_session",
        "source_system": "bank-mobile-api",
        "policy_version": "bank-policy-v2",
        "iss": ISSUER,
        "aud": audience,
        "kid": key_id,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "nonce": nonce,
    }
    return jwt.encode(claims, private_pem, algorithm="ES256", headers={"kid": key_id})


def test_nonce_is_bound_to_one_context_and_transaction() -> None:
    from app.db.models.banking_transaction import BankingSubjectBinding

    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = session_local()
    try:
        db.add(Tenant(id="tenant-a", name="Tenant A", slug="tenant-a"))
        db.commit()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        db.add(
            BankingSubjectBinding(
                tenant_id="tenant-a",
                issuer="https://bank.example/auth",
                nonce_hash="n" * 64,
                context_digest="c" * 64,
                ai_transaction_id="txn-001",
                expires_at=expires_at,
            )
        )
        db.commit()
        db.add(
            BankingSubjectBinding(
                tenant_id="tenant-a",
                issuer="https://bank.example/auth",
                nonce_hash="n" * 64,
                context_digest="x" * 64,
                ai_transaction_id="txn-002",
                expires_at=expires_at,
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()
    finally:
        db.rollback()
        db.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_valid_assertion_returns_only_pseudonymous_bound_context(subject_context_env) -> None:
    from app.services.banking_subject_context_service import (
        validate_and_bind_banking_subject_context,
    )

    token = _issue_assertion(subject_context_env["private_pem"])
    result = validate_and_bind_banking_subject_context(
        subject_context_env["db"],
        tenant_id="tenant-a",
        ai_transaction_id="txn-001",
        compact_assertion=token,
        settings_obj=subject_context_env["settings"],
    )
    repeated = validate_and_bind_banking_subject_context(
        subject_context_env["db"],
        tenant_id="tenant-a",
        ai_transaction_id="txn-001",
        compact_assertion=token,
        settings_obj=subject_context_env["settings"],
    )

    serialized = result.model_dump_json()
    assert result == repeated
    assert result.customer_subject_hash.startswith("hmac-sha256:")
    assert len(result.approved_account_hashes) == 1
    assert len(result.approved_resource_hashes) == 1
    assert result.subject_type == "customer"
    assert result.authenticated_principal_hash.startswith("hmac-sha256:")
    assert result.identity_provenance == "bank_api_gateway"
    assert result.trust_level == "hardware_bound_session"
    assert result.policy_version == "bank-policy-v2"
    assert result.authority_scope == (
        "account.read_summary",
        "account.list_transactions",
    )
    assert result.resource_scope_hashes[0]["resource_type"] == "account"
    assert "customer-001" not in serialized
    assert "acct-001" not in serialized
    assert "mobile-session-001" not in serialized
    assert token not in serialized


def test_prompt_provenance_cannot_become_authoritative_subject(subject_context_env) -> None:
    from app.services.banking_subject_context_service import (
        BankingSubjectContextError,
        validate_and_bind_banking_subject_context,
    )

    token = _issue_assertion(
        subject_context_env["private_pem"],
        provenance="prompt",
    )

    with pytest.raises(BankingSubjectContextError):
        validate_and_bind_banking_subject_context(
            subject_context_env["db"],
            tenant_id="tenant-a",
            ai_transaction_id="txn-untrusted-provenance",
            compact_assertion=token,
            settings_obj=subject_context_env["settings"],
        )


@pytest.mark.parametrize("mutation", ["wrong_audience", "unknown_key", "expired", "bad_signature"])
def test_invalid_bank_assertion_fails_closed(subject_context_env, mutation: str) -> None:
    from app.services.banking_subject_context_service import (
        BankingSubjectContextError,
        validate_and_bind_banking_subject_context,
    )

    private_pem = subject_context_env["private_pem"]
    kwargs = {}
    if mutation == "wrong_audience":
        kwargs["audience"] = "wrong-audience"
    elif mutation == "unknown_key":
        kwargs["key_id"] = "unknown-bank-key"
    elif mutation == "expired":
        kwargs["expires_delta"] = timedelta(seconds=-1)
    elif mutation == "bad_signature":
        other_key = ec.generate_private_key(ec.SECP256R1())
        private_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
    token = _issue_assertion(private_pem, **kwargs)

    with pytest.raises(BankingSubjectContextError):
        validate_and_bind_banking_subject_context(
            subject_context_env["db"],
            tenant_id="tenant-a",
            ai_transaction_id="txn-001",
            compact_assertion=token,
            settings_obj=subject_context_env["settings"],
        )


def test_nonce_reuse_with_different_transaction_is_rejected(subject_context_env) -> None:
    from app.services.banking_subject_context_service import (
        BankingSubjectContextError,
        validate_and_bind_banking_subject_context,
    )

    token = _issue_assertion(subject_context_env["private_pem"])
    validate_and_bind_banking_subject_context(
        subject_context_env["db"],
        tenant_id="tenant-a",
        ai_transaction_id="txn-001",
        compact_assertion=token,
        settings_obj=subject_context_env["settings"],
    )
    with pytest.raises(BankingSubjectContextError, match="replay"):
        validate_and_bind_banking_subject_context(
            subject_context_env["db"],
            tenant_id="tenant-a",
            ai_transaction_id="txn-002",
            compact_assertion=token,
            settings_obj=subject_context_env["settings"],
        )
