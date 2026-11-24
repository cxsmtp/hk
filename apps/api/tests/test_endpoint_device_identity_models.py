from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.endpoint_identity import (
    EndpointAuthChallenge,
    EndpointDeviceIdentity,
    EndpointEnrollmentAuthorization,
    EndpointProofReplay,
)
from app.db.models.tenant import Tenant
from app.db.models.user import User
from app.db.session import Base


def _seed(db: Session) -> tuple[Tenant, User]:
    tenant = Tenant(name="Bank", slug="bank", is_active=True)
    user = User(
        email="bank-owner@example.com",
        hashed_password="not-used",
        full_name="Bank Owner",
        is_active=True,
    )
    db.add_all([tenant, user])
    db.flush()
    return tenant, user


def test_endpoint_identity_schema_contains_public_state_only() -> None:
    names = {column.name for column in EndpointDeviceIdentity.__table__.columns}
    assert {"public_key_pem", "key_thumbprint", "scopes", "status"} <= names
    assert names.isdisjoint(
        {"private_key", "api_key", "agent_token", "access_token", "refresh_token"}
    )


def test_endpoint_identity_and_single_use_state_persist() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    now = datetime.now(timezone.utc)

    with Session(engine) as db:
        tenant, user = _seed(db)
        identity = EndpointDeviceIdentity(
            tenant_id=tenant.id,
            endpoint_id="mac-bank-001",
            assigned_user_id=user.id,
            public_key_pem="-----BEGIN PUBLIC KEY-----\nPUBLIC\n-----END PUBLIC KEY-----",
            key_thumbprint="a" * 64,
            key_provider="macos_secure_enclave",
            status="active",
            scopes=["endpoint:policy:read"],
            enrolled_by_user_id=user.id,
        )
        authorization = EndpointEnrollmentAuthorization(
            tenant_id=tenant.id,
            endpoint_id="mac-bank-001",
            assigned_user_id=user.id,
            code_hash="b" * 64,
            nonce_hash="c" * 64,
            scopes=["endpoint:policy:read"],
            expires_at=now + timedelta(minutes=5),
            issued_by_user_id=user.id,
        )
        db.add_all([identity, authorization])
        db.flush()
        challenge = EndpointAuthChallenge(
            device_identity_id=identity.id,
            nonce_hash="d" * 64,
            expires_at=now + timedelta(seconds=60),
        )
        replay = EndpointProofReplay(
            device_identity_id=identity.id,
            proof_hash="e" * 64,
            expires_at=now + timedelta(minutes=2),
        )
        db.add_all([challenge, replay])
        db.commit()

        assert identity.tenant_id == tenant.id
        assert authorization.consumed_at is None
        assert challenge.consumed_at is None
        assert replay.proof_hash == "e" * 64

    Base.metadata.drop_all(engine)
    engine.dispose()


def test_endpoint_identity_is_unique_per_tenant_and_endpoint() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        tenant, user = _seed(db)
        common = {
            "tenant_id": tenant.id,
            "endpoint_id": "mac-bank-001",
            "assigned_user_id": user.id,
            "public_key_pem": "public",
            "key_provider": "macos_secure_enclave",
            "status": "active",
            "scopes": [],
            "enrolled_by_user_id": user.id,
        }
        db.add(EndpointDeviceIdentity(key_thumbprint="1" * 64, **common))
        db.flush()
        db.add(EndpointDeviceIdentity(key_thumbprint="2" * 64, **common))
        with pytest.raises(IntegrityError):
            db.flush()

    Base.metadata.drop_all(engine)
    engine.dispose()
