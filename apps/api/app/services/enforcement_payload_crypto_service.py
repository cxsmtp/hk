from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings


PROMPT_ENCRYPTION_PREFIX = "enc:v1:"


def _fernet() -> Fernet:
    # Keep the key source explicit and environment-controlled.
    source = settings.enforcement_payloads_key or settings.connector_secrets_key
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        source.encode("utf-8"),
        settings.connector_secrets_kdf_salt.encode("utf-8"),
        settings.connector_secrets_kdf_iterations,
        dklen=32,
    )
    key = base64.urlsafe_b64encode(derived)
    return Fernet(key)


def encrypt_enforcement_prompt(prompt: str | None) -> str:
    raw = str(prompt or "").encode("utf-8")
    token = _fernet().encrypt(raw).decode("utf-8")
    return f"{PROMPT_ENCRYPTION_PREFIX}{token}"


def decrypt_enforcement_prompt(payload: str | None) -> str:
    token = str(payload or "")
    if not token:
        return ""
    if not token.startswith(PROMPT_ENCRYPTION_PREFIX):
        return token
    cipher_text = token[len(PROMPT_ENCRYPTION_PREFIX) :]
    try:
        decrypted = _fernet().decrypt(cipher_text.encode("utf-8"))
    except InvalidToken:
        return ""
    return decrypted.decode("utf-8")
