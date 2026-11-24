"""Encrypted, process-local storage for short-lived endpoint access tokens.

The token is AES-GCM encrypted between requests. The per-process wrapping key is
never serialized and is locked against swapping where the operating system permits.
DPoP remains the primary protection against token replay; this vault is an additive
memory-exposure control, not a claim to resist a fully privileged local attacker.
"""

from __future__ import annotations

import ctypes
import os
import threading
import time
from contextlib import contextmanager
from typing import Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ExpiredTokenError(RuntimeError):
    """Raised when no current endpoint token is available."""


def _wipe(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0


class MemoryTokenVault:
    """Keep one short-lived token encrypted under an ephemeral wrapping key."""

    def __init__(self, *, clock=time.time) -> None:
        self._lock = threading.RLock()
        self._wrapping_key = bytearray(os.urandom(32))
        self._nonce = b""
        self._ciphertext = b""
        self._expires_at = 0.0
        self._closed = False
        self._clock = clock
        self._key_locked = self._lock_key_memory()

    def _lock_key_memory(self) -> bool:
        try:
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._wrapping_key))
            if os.name == "nt":
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.VirtualLock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                kernel32.VirtualLock.restype = ctypes.c_int
                return bool(
                    kernel32.VirtualLock(
                        ctypes.c_void_p(address),
                        ctypes.c_size_t(len(self._wrapping_key)),
                    )
                )
            libc = ctypes.CDLL(None, use_errno=True)
            return libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(len(self._wrapping_key))) == 0
        except (AttributeError, OSError, TypeError):
            return False

    def _unlock_key_memory(self) -> None:
        if not self._key_locked:
            return
        try:
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._wrapping_key))
            if os.name == "nt":
                kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel32.VirtualUnlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
                kernel32.VirtualUnlock.restype = ctypes.c_int
                kernel32.VirtualUnlock(
                    ctypes.c_void_p(address),
                    ctypes.c_size_t(len(self._wrapping_key)),
                )
            else:
                libc = ctypes.CDLL(None, use_errno=True)
                libc.munlock(
                    ctypes.c_void_p(address),
                    ctypes.c_size_t(len(self._wrapping_key)),
                )
        except (AttributeError, OSError, TypeError):
            pass
        self._key_locked = False

    @staticmethod
    def _aad(expires_at: float) -> bytes:
        return f"hawk-endpoint-token-v1:{expires_at:.6f}".encode("ascii")

    def store(self, token: str | bytes | bytearray, *, expires_at: float) -> None:
        if not isinstance(expires_at, (int, float)) or expires_at <= 0:
            raise ValueError("expires_at must be a positive Unix timestamp")
        plaintext = bytearray(token.encode("utf-8") if isinstance(token, str) else token)
        if not plaintext:
            raise ValueError("token must not be empty")
        with self._lock:
            if self._closed:
                _wipe(plaintext)
                raise RuntimeError("token vault is closed")
            nonce = os.urandom(12)
            try:
                ciphertext = AESGCM(bytes(self._wrapping_key)).encrypt(
                    nonce, bytes(plaintext), self._aad(float(expires_at))
                )
            finally:
                _wipe(plaintext)
            self._nonce = nonce
            self._ciphertext = ciphertext
            self._expires_at = float(expires_at)

    @property
    def has_token(self) -> bool:
        with self._lock:
            if self._closed or not self._ciphertext:
                return False
            if self._expires_at <= self._clock():
                self._clear_ciphertext()
                return False
            return True

    @property
    def expires_at(self) -> float:
        with self._lock:
            return self._expires_at

    @property
    def encrypted_bytes(self) -> bytes:
        with self._lock:
            return bytes(self._ciphertext)

    @property
    def key_is_zeroized(self) -> bool:
        with self._lock:
            return all(value == 0 for value in self._wrapping_key)

    @property
    def memory_locked(self) -> bool:
        return self._key_locked

    @contextmanager
    def use(self) -> Iterator[bytearray]:
        with self._lock:
            if not self.has_token:
                raise ExpiredTokenError("endpoint access token unavailable")
            decrypted = AESGCM(bytes(self._wrapping_key)).decrypt(
                self._nonce,
                self._ciphertext,
                self._aad(self._expires_at),
            )
            plaintext = bytearray(decrypted)
            del decrypted
        try:
            yield plaintext
        finally:
            _wipe(plaintext)

    def _clear_ciphertext(self) -> None:
        self._nonce = b""
        self._ciphertext = b""
        self._expires_at = 0.0

    def clear(self) -> None:
        with self._lock:
            self._clear_ciphertext()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._clear_ciphertext()
            self._unlock_key_memory()
            _wipe(self._wrapping_key)
            self._closed = True

    def __enter__(self) -> "MemoryTokenVault":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return (
            "MemoryTokenVault("
            f"has_token={self.has_token}, memory_locked={self.memory_locked}, "
            f"closed={self._closed})"
        )

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
