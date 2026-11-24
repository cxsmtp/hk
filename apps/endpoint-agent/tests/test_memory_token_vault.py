from __future__ import annotations

import time

import pytest

from hawk_endpoint_agent.auth.memory_vault import (
    ExpiredTokenError,
    MemoryTokenVault,
)


def test_token_is_encrypted_between_uses_and_repr_is_redacted() -> None:
    vault = MemoryTokenVault()
    token = "bank-endpoint-access-token-sensitive"
    vault.store(token, expires_at=time.time() + 300)

    assert token.encode() not in vault.encrypted_bytes
    assert token not in repr(vault)
    assert vault.has_token is True

    first_ciphertext = vault.encrypted_bytes
    vault.store(token, expires_at=time.time() + 300)
    assert vault.encrypted_bytes != first_ciphertext
    vault.close()


def test_use_returns_mutable_buffer_and_wipes_it_on_exit() -> None:
    vault = MemoryTokenVault()
    vault.store("short-lived-token", expires_at=time.time() + 300)

    with vault.use() as token_buffer:
        assert isinstance(token_buffer, bytearray)
        assert bytes(token_buffer) == b"short-lived-token"
    assert token_buffer == bytearray(len(token_buffer))
    vault.close()


def test_expired_token_is_unavailable() -> None:
    vault = MemoryTokenVault()
    vault.store("expired", expires_at=time.time() - 1)

    with pytest.raises(ExpiredTokenError):
        with vault.use():
            pass
    assert vault.has_token is False
    vault.close()


def test_close_wipes_wrapping_key_and_ciphertext() -> None:
    vault = MemoryTokenVault()
    vault.store("sensitive", expires_at=time.time() + 300)
    vault.close()

    assert vault.has_token is False
    assert vault.encrypted_bytes == b""
    assert vault.key_is_zeroized is True
