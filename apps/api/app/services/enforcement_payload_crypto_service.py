from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.services.pci_controls import scrub_pan


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
    """The prompt, encrypted for the enforcement record. A card number in it is masked first (``[card ending 1111]``,
    app/services/pci_controls.py): encryption is not a reason to keep a full PAN (PCI DSS 3.3, 3.4). Hashes of the
    prompt (``prompt_hash``) are computed by the callers from the original text, before this."""

    raw = str(scrub_pan(str(prompt or ""), boundary="db:enforcement_prompt")).encode("utf-8")
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


def encrypt_transient_payload(value: str | None) -> str:
    """Content that has to pass through the task queue (a file for OCR): encrypted with the same key, never masked
    (the worker needs it as it is), so the broker and the result backend never hold it in the clear."""

    raw = str(value or "").encode("utf-8")
    return f"{PROMPT_ENCRYPTION_PREFIX}{_fernet().encrypt(raw).decode('utf-8')}"


def decrypt_transient_payload(payload: str | None) -> str:
    return decrypt_enforcement_prompt(payload)
