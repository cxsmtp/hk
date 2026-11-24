from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.models.endpoint_identity import (
    EndpointDeviceIdentity,
    EndpointEnrollmentAuthorization,
)
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.core.endpoint_auth import validate_endpoint_request
from app.core.security import decode_endpoint_access_token
from app.services.endpoint_identity_service import (
    DEFAULT_ENDPOINT_SCOPES,
    build_auth_statement,
    build_enrollment_statement,
    complete_enrollment,
    create_auth_challenge,
    create_enrollment_authorization,
    exchange_challenge_for_token,
    public_key_thumbprint,
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _proof(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    access_token: str,
    method: str,
    url: str,
    jti: str = "proof-01",
) -> str:
    numbers = private_key.public_key().public_numbers()
    header = {
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(numbers.x.to_bytes(32, "big")),
            "y": _b64url(numbers.y.to_bytes(32, "big")),
        },
    }
    claims = {
        "htm": method.upper(),
        "htu": url,
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "jti": jti,
        "ath": _b64url(hashlib.sha256(access_token.encode("ascii")).digest()),
    }
    signing_input = (
        f"{_b64url(json.dumps(header, sort_keys=True, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(claims, sort_keys=True, separators=(',', ':')).encode())}"
    )
    der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return f"{signing_input}.{_b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    tenant = Tenant(name="Bank", slug="bank-auth", is_active=True)
    user = User(
        email="device-user@example.com",
        hashed_password="not-used",
        full_name="Device User",
        is_active=True,
    )
    session.add_all([tenant, user])
    session.flush()
    session.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role="owner"))
    session.commit()
    session.info["tenant_id"] = tenant.id
    session.info["user_id"] = user.id
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def _public_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _enroll(db: Session) -> tuple[EndpointDeviceIdentity, ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = _public_pem(private_key)
    issued = create_enrollment_authorization(
        db,
        tenant_id=db.info["tenant_id"],
        endpoint_id="mac-bank-001",
        assigned_user_id=db.info["user_id"],
        issued_by_user_id=db.info["user_id"],
        scopes=list(DEFAULT_ENDPOINT_SCOPES),
    )
    timestamp = int(datetime.now(timezone.utc).timestamp())
    statement = build_enrollment_statement(
        authorization_id=issued["authorization_id"],
        tenant_id=db.info["tenant_id"],
        endpoint_id="mac-bank-001",
        key_provider="macos_secure_enclave",
        public_key_thumbprint=public_key_thumbprint(public_pem),
        nonce=issued["enrollment_nonce"],
        timestamp=timestamp,
    )
    signature = private_key.sign(statement, ec.ECDSA(hashes.SHA256()))
    identity = complete_enrollment(
        db,
        authorization_id=issued["authorization_id"],
        enrollment_code=issued["enrollment_code"],
        enrollment_nonce=issued["enrollment_nonce"],
        tenant_id=db.info["tenant_id"],
        endpoint_id="mac-bank-001",
        key_provider="macos_secure_enclave",
        public_key_pem=public_pem,
        timestamp=timestamp,
        signature_b64=_b64url(signature),
    )
    return identity, private_key


def test_enrollment_stores_hashes_and_public_key_only(db: Session) -> None:
    identity, _ = _enroll(db)
    authorization = db.scalar(select(EndpointEnrollmentAuthorization))

    assert identity.status == "active"
    assert identity.key_provider == "macos_secure_enclave"
    assert authorization is not None
    assert authorization.consumed_at is not None
    assert authorization.code_hash != ""
    assert "BEGIN PUBLIC KEY" in identity.public_key_pem
    assert not hasattr(identity, "private_key")


def test_backend_rejects_self_reported_development_key_provider(db: Session) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = _public_pem(private_key)
    issued = create_enrollment_authorization(
        db,
        tenant_id=db.info["tenant_id"],
        endpoint_id="mac-dev-rejected",
        assigned_user_id=db.info["user_id"],
        issued_by_user_id=db.info["user_id"],
    )
    with pytest.raises(HTTPException) as exc:
        complete_enrollment(
            db,
            authorization_id=issued["authorization_id"],
            enrollment_code=issued["enrollment_code"],
            enrollment_nonce=issued["enrollment_nonce"],
            tenant_id=db.info["tenant_id"],
            endpoint_id="mac-dev-rejected",
            key_provider="development_ephemeral",
            public_key_pem=public_pem,
            timestamp=int(datetime.now(timezone.utc).timestamp()),
            signature_b64=_b64url(b"not-used"),
        )
    assert exc.value.status_code == 422
    authorization = db.get(
        EndpointEnrollmentAuthorization, issued["authorization_id"]
    )
    assert authorization is not None
    assert authorization.consumed_at is None


def test_enrollment_code_is_single_use(db: Session) -> None:
    identity, private_key = _enroll(db)
    authorization = db.scalar(select(EndpointEnrollmentAuthorization))
    assert authorization is not None
    timestamp = int(datetime.now(timezone.utc).timestamp())
    statement = build_enrollment_statement(
        authorization_id=authorization.id,
        tenant_id=identity.tenant_id,
        endpoint_id="mac-bank-002",
        key_provider="macos_secure_enclave",
        public_key_thumbprint=identity.key_thumbprint,
        nonce="wrong-and-unavailable",
        timestamp=timestamp,
    )
    signature = private_key.sign(statement, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(HTTPException) as exc:
        complete_enrollment(
            db,
            authorization_id=authorization.id,
            enrollment_code="already-consumed",
            enrollment_nonce="wrong-and-unavailable",
            tenant_id=identity.tenant_id,
            endpoint_id="mac-bank-002",
            key_provider="macos_secure_enclave",
            public_key_pem=identity.public_key_pem,
            timestamp=timestamp,
            signature_b64=_b64url(signature),
        )
    assert exc.value.status_code == 401


def test_revoked_endpoint_can_rotate_hardware_identity_in_place(db: Session) -> None:
    identity, old_key = _enroll(db)
    original_identity_id = identity.id
    identity.status = "revoked"
    identity.revoked_at = datetime.now(timezone.utc)
    identity.revoked_by_user_id = db.info["user_id"]
    identity.revocation_reason = "device_key_lost"
    db.commit()

    new_key = ec.generate_private_key(ec.SECP256R1())
    new_public_pem = _public_pem(new_key)
    issued = create_enrollment_authorization(
        db,
        tenant_id=db.info["tenant_id"],
        endpoint_id=identity.endpoint_id,
        assigned_user_id=db.info["user_id"],
        issued_by_user_id=db.info["user_id"],
        scopes=list(DEFAULT_ENDPOINT_SCOPES),
    )
    timestamp = int(datetime.now(timezone.utc).timestamp())
    statement = build_enrollment_statement(
        authorization_id=issued["authorization_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        key_provider="macos_secure_enclave",
        public_key_thumbprint=public_key_thumbprint(new_public_pem),
        nonce=issued["enrollment_nonce"],
        timestamp=timestamp,
    )
    rotated = complete_enrollment(
        db,
        authorization_id=issued["authorization_id"],
        enrollment_code=issued["enrollment_code"],
        enrollment_nonce=issued["enrollment_nonce"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        key_provider="macos_secure_enclave",
        public_key_pem=new_public_pem,
        timestamp=timestamp,
        signature_b64=_b64url(new_key.sign(statement, ec.ECDSA(hashes.SHA256()))),
    )

    assert rotated.id == original_identity_id
    assert rotated.status == "active"
    assert rotated.public_key_pem == new_public_pem
    assert rotated.revoked_at is None
    assert rotated.revoked_by_user_id is None
    assert rotated.revocation_reason is None
    assert rotated.key_thumbprint != public_key_thumbprint(_public_pem(old_key))


def test_signed_challenge_issues_five_minute_scoped_token(db: Session) -> None:
    identity, private_key = _enroll(db)
    challenge = create_auth_challenge(
        db,
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
    )
    statement = build_auth_statement(
        challenge_id=challenge["challenge_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        nonce=challenge["nonce"],
    )
    signature = private_key.sign(statement, ec.ECDSA(hashes.SHA256()))
    token = exchange_challenge_for_token(
        db,
        challenge_id=challenge["challenge_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        nonce=challenge["nonce"],
        signature_b64=_b64url(signature),
    )

    assert token["token_type"] == "DPoP"
    assert 250 <= token["expires_in"] <= 300
    assert token["scope"] == list(DEFAULT_ENDPOINT_SCOPES)
    assert token["access_token"]
    claims = decode_endpoint_access_token(token["access_token"])
    assert claims["type"] == "endpoint_access"
    assert claims["tenant_id"] == identity.tenant_id
    assert claims["endpoint_id"] == identity.endpoint_id
    assert claims["aud"] == "hawk-endpoint-api"
    assert claims["iss"] == "hawk-api"
    assert claims["nbf"] <= claims["iat"] <= claims["exp"]
    assert claims["exp"] - claims["iat"] == 300
    assert claims["cnf"]["jkt"] == identity.key_thumbprint

    with pytest.raises(HTTPException) as exc:
        exchange_challenge_for_token(
            db,
            challenge_id=challenge["challenge_id"],
            tenant_id=identity.tenant_id,
            endpoint_id=identity.endpoint_id,
            nonce=challenge["nonce"],
            signature_b64=_b64url(signature),
        )
    assert exc.value.status_code == 401


def test_invalid_challenge_signature_is_rejected(db: Session) -> None:
    identity, _ = _enroll(db)
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    challenge = create_auth_challenge(
        db,
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
    )
    statement = build_auth_statement(
        challenge_id=challenge["challenge_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        nonce=challenge["nonce"],
    )
    signature = attacker_key.sign(statement, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(HTTPException) as exc:
        exchange_challenge_for_token(
            db,
            challenge_id=challenge["challenge_id"],
            tenant_id=identity.tenant_id,
            endpoint_id=identity.endpoint_id,
            nonce=challenge["nonce"],
            signature_b64=_b64url(signature),
        )
    assert exc.value.status_code == 401


def test_dpop_proof_is_scope_tenant_and_replay_bound(db: Session) -> None:
    identity, private_key = _enroll(db)
    challenge = create_auth_challenge(
        db, tenant_id=identity.tenant_id, endpoint_id=identity.endpoint_id
    )
    statement = build_auth_statement(
        challenge_id=challenge["challenge_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        nonce=challenge["nonce"],
    )
    token_result = exchange_challenge_for_token(
        db,
        challenge_id=challenge["challenge_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        nonce=challenge["nonce"],
        signature_b64=_b64url(private_key.sign(statement, ec.ECDSA(hashes.SHA256()))),
    )
    access_token = token_result["access_token"]
    url = "https://hawk.bank/endpoint-agent/policy"
    proof = _proof(
        private_key,
        access_token=access_token,
        method="GET",
        url=url,
    )

    principal = validate_endpoint_request(
        db,
        access_token=access_token,
        proof=proof,
        method="GET",
        url=url,
        tenant_id=identity.tenant_id,
        required_scope="endpoint:policy:read",
    )
    assert principal.identity.id == identity.id
    assert principal.user.id == db.info["user_id"]

    for index, wrong_url in enumerate((
        "https://other.hawk.bank/endpoint-agent/policy",
        "http://hawk.bank/endpoint-agent/policy",
        "https://hawk.bank/endpoint-agent/other",
    )):
        mismatched_proof = _proof(
            private_key,
            access_token=access_token,
            method="GET",
            url=wrong_url,
            jti=f"wrong-htu-{index}",
        )
        with pytest.raises(HTTPException) as htu_error:
            validate_endpoint_request(
                db,
                access_token=access_token,
                proof=mismatched_proof,
                method="GET",
                url=url,
                tenant_id=identity.tenant_id,
                required_scope="endpoint:policy:read",
            )
        assert htu_error.value.status_code == 401

    with pytest.raises(HTTPException) as replay:
        validate_endpoint_request(
            db,
            access_token=access_token,
            proof=proof,
            method="GET",
            url=url,
            tenant_id=identity.tenant_id,
            required_scope="endpoint:policy:read",
        )
    assert replay.value.status_code == 401


def test_dpop_rejects_wrong_method_scope_and_revoked_device(db: Session) -> None:
    identity, private_key = _enroll(db)
    challenge = create_auth_challenge(
        db, tenant_id=identity.tenant_id, endpoint_id=identity.endpoint_id
    )
    statement = build_auth_statement(
        challenge_id=challenge["challenge_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        nonce=challenge["nonce"],
    )
    token_result = exchange_challenge_for_token(
        db,
        challenge_id=challenge["challenge_id"],
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        nonce=challenge["nonce"],
        signature_b64=_b64url(private_key.sign(statement, ec.ECDSA(hashes.SHA256()))),
    )
    access_token = token_result["access_token"]
    url = "https://hawk.bank/endpoint-agent/policy"
    wrong_method = _proof(
        private_key,
        access_token=access_token,
        method="POST",
        url=url,
        jti="wrong-method",
    )
    with pytest.raises(HTTPException) as method_error:
        validate_endpoint_request(
            db,
            access_token=access_token,
            proof=wrong_method,
            method="GET",
            url=url,
            tenant_id=identity.tenant_id,
            required_scope="endpoint:policy:read",
        )
    assert method_error.value.status_code == 401

    valid = _proof(
        private_key,
        access_token=access_token,
        method="GET",
        url=url,
        jti="wrong-scope",
    )
    with pytest.raises(HTTPException) as scope_error:
        validate_endpoint_request(
            db,
            access_token=access_token,
            proof=valid,
            method="GET",
            url=url,
            tenant_id=identity.tenant_id,
            required_scope="endpoint:admin",
        )
    assert scope_error.value.status_code == 403

    identity.status = "revoked"
    identity.revoked_at = datetime.now(timezone.utc)
    db.commit()
    revoked = _proof(
        private_key,
        access_token=access_token,
        method="GET",
        url=url,
        jti="revoked",
    )
    with pytest.raises(HTTPException) as revoked_error:
        validate_endpoint_request(
            db,
            access_token=access_token,
            proof=revoked,
            method="GET",
            url=url,
            tenant_id=identity.tenant_id,
            required_scope="endpoint:policy:read",
        )
    assert revoked_error.value.status_code == 401
