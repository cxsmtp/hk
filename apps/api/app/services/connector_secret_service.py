from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


def _fernet() -> Fernet:
    # KMS stub: production can replace PBKDF2 derivation with managed key envelope flow.
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        settings.connector_secrets_key.encode("utf-8"),
        settings.connector_secrets_kdf_salt.encode("utf-8"),
        settings.connector_secrets_kdf_iterations,
        dklen=32,
    )
    key = base64.urlsafe_b64encode(derived)
    return Fernet(key)


def encrypt_connector_secrets(payload: dict[str, Any] | None) -> str | None:
    if not payload:
        return None
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    token = _fernet().encrypt(raw)
    return token.decode("utf-8")


def decrypt_connector_secrets(encrypted_payload: str | None) -> dict[str, Any]:
    if not encrypted_payload:
        return {}
    try:
        decrypted = _fernet().decrypt(encrypted_payload.encode("utf-8"))
    except InvalidToken as exc:
        raise ValueError("Unable to decrypt connector secrets payload") from exc
    return json.loads(decrypted.decode("utf-8"))
