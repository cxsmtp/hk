"""Challenge-based, proof-of-possession endpoint authentication session."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator

from .device_key import (
    DeviceKeyError,
    DeviceKeyProvider,
    DevicePublicIdentity,
    build_device_key_provider,
)
from .dpop import build_dpop_proof
from .memory_vault import MemoryTokenVault
from ..local_broker_auth import LocalBrokerAuthenticator


class EndpointAuthError(RuntimeError):
    """Authentication failed without exposing credentials or signed material."""


class EndpointAuthUnavailable(EndpointAuthError):
    """The authentication service could not be reached."""


class EndpointReenrollmentRequired(EndpointAuthError):
    """The registered identity is missing, invalid, or revoked."""


class EndpointAuthHttpError(EndpointAuthError):
    def __init__(self, status: int, body: Any) -> None:
        super().__init__(f"endpoint authentication HTTP {status}")
        self.status = status
        self.body = body


@dataclass(frozen=True)
class EnrollmentBundle:
    authorization_id: str
    enrollment_code: str
    enrollment_nonce: str

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "EnrollmentBundle":
        fields = {
            name: str(value.get(name) or "").strip()
            for name in ("authorization_id", "enrollment_code", "enrollment_nonce")
        }
        if any(not item for item in fields.values()):
            raise ValueError("enrollment bundle is incomplete")
        return cls(**fields)


AuthTransport = Callable[[str, str, dict[str, Any], dict[str, str]], dict[str, Any]]


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class EndpointAuthSession:
    """Own the device key, encrypted token vault, and serialized renewal flow."""

    def __init__(
        self,
        *,
        config: Any,
        provider: DeviceKeyProvider | None = None,
        vault: MemoryTokenVault | None = None,
        transport: AuthTransport | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._config = config
        self._base = str(config.api_base_url).rstrip("/")
        self._provider = provider or build_device_key_provider(
            provider_name=config.key_provider,
            security_profile=config.security_profile,
            helper_path=config.identity_helper_path,
            helper_sha256=getattr(config, "identity_helper_sha256", ""),
            key_tag=config.device_key_tag,
        )
        self.vault = vault or MemoryTokenVault(clock=clock)
        self._transport = transport or self._default_transport
        self._clock = clock
        self._renew_lock = threading.Lock()
        self._identity: DevicePublicIdentity | None = None
        self._state = "re_enrollment_required"
        self._last_error = ""
        self._scopes: tuple[str, ...] = ()

    def _public_identity(self) -> DevicePublicIdentity:
        if self._identity is None:
            self._identity = self._provider.ensure_key(self._config.endpoint_id)
        return self._identity

    def _default_transport(
        self,
        method: str,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str],
    ) -> dict[str, Any]:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": "application/json", **headers},
        )
        try:
            with urllib.request.urlopen(
                request, timeout=float(self._config.http_timeout_seconds)
            ) as response:
                raw = response.read().decode("utf-8")
                value = json.loads(raw) if raw else {}
                if not isinstance(value, dict):
                    raise EndpointAuthError("authentication response was not an object")
                return value
        except urllib.error.HTTPError as exc:
            try:
                body_value = json.loads(exc.read().decode("utf-8") or "{}")
            except Exception:  # noqa: BLE001
                body_value = {"detail": "non-json authentication error"}
            raise EndpointAuthHttpError(exc.code, body_value) from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            raise EndpointAuthUnavailable("endpoint authentication service unavailable") from exc

    def enroll(self, bundle: EnrollmentBundle) -> dict[str, Any]:
        identity = self._public_identity()
        timestamp = int(self._clock())
        statement = _canonical(
            {
                "authorization_id": bundle.authorization_id,
                "endpoint_id": self._config.endpoint_id,
                "key_provider": identity.provider,
                "nonce": bundle.enrollment_nonce,
                "public_key_thumbprint": identity.key_thumbprint,
                "tenant_id": self._config.tenant_id,
                "timestamp": timestamp,
                "version": "hawk-enroll-v1",
            }
        )
        signature = _b64url(self._provider.sign(statement))
        response = self._transport(
            "POST",
            f"{self._base}/endpoint-agent/enroll",
            {
                "authorization_id": bundle.authorization_id,
                "enrollment_code": bundle.enrollment_code,
                "enrollment_nonce": bundle.enrollment_nonce,
                "tenant_id": self._config.tenant_id,
                "endpoint_id": self._config.endpoint_id,
                "key_provider": identity.provider,
                "public_key_pem": identity.public_key_pem,
                "timestamp": timestamp,
                "signature": signature,
            },
            {},
        )
        self._state = "re_enrollment_required"
        self._last_error = ""
        return response

    def renew(self, *, force: bool = False) -> None:
        margin = max(0, int(self._config.auth_renewal_margin_seconds))
        if (
            not force
            and self.vault.has_token
            and self.vault.expires_at - self._clock() > margin
        ):
            return
        with self._renew_lock:
            if (
                not force
                and self.vault.has_token
                and self.vault.expires_at - self._clock() > margin
            ):
                return
            self._state = "renewing"
            try:
                challenge = self._transport(
                    "POST",
                    f"{self._base}/endpoint-agent/auth/challenge",
                    {
                        "tenant_id": self._config.tenant_id,
                        "endpoint_id": self._config.endpoint_id,
                    },
                    {},
                )
                challenge_id = str(challenge.get("challenge_id") or "")
                nonce = str(challenge.get("nonce") or "")
                if not challenge_id or not nonce:
                    raise EndpointAuthError("authentication challenge was incomplete")
                statement = _canonical(
                    {
                        "challenge_id": challenge_id,
                        "endpoint_id": self._config.endpoint_id,
                        "nonce": nonce,
                        "tenant_id": self._config.tenant_id,
                        "version": "hawk-auth-v1",
                    }
                )
                token_response = self._transport(
                    "POST",
                    f"{self._base}/endpoint-agent/auth/token",
                    {
                        "challenge_id": challenge_id,
                        "tenant_id": self._config.tenant_id,
                        "endpoint_id": self._config.endpoint_id,
                        "nonce": nonce,
                        "signature": _b64url(self._provider.sign(statement)),
                    },
                    {},
                )
                token = str(token_response.get("access_token") or "")
                token_type = str(token_response.get("token_type") or "")
                expires_in = int(token_response.get("expires_in") or 0)
                if not token or token_type.lower() != "dpop" or not 1 <= expires_in <= 300:
                    raise EndpointAuthError("endpoint token response was invalid")
                self.vault.store(token, expires_at=self._clock() + expires_in)
                token = ""
                self._scopes = tuple(
                    str(scope) for scope in token_response.get("scope") or []
                )
                self._state = "healthy"
                self._last_error = ""
            except EndpointAuthHttpError as exc:
                self.vault.clear()
                if exc.status in {401, 404, 409}:
                    self._state = "re_enrollment_required"
                    self._last_error = "identity_unavailable"
                    raise EndpointReenrollmentRequired(
                        "endpoint identity requires re-enrollment"
                    ) from exc
                self._state = "offline_cached"
                self._last_error = f"http_{exc.status}"
                raise
            except EndpointAuthUnavailable:
                self._state = "offline_cached"
                self._last_error = "backend_unavailable"
                raise
            except DeviceKeyError as exc:
                self.vault.clear()
                self._state = "re_enrollment_required"
                self._last_error = "device_identity_unavailable"
                raise EndpointReenrollmentRequired(
                    "endpoint device identity requires re-enrollment"
                ) from exc
            except Exception:
                self.vault.clear()
                self._state = "re_enrollment_required"
                self._last_error = "authentication_failed"
                raise

    @contextmanager
    def authenticated_headers(self, method: str, url: str) -> Iterator[dict[str, str]]:
        self.renew()
        identity = self._public_identity()
        token_text = ""
        with self.vault.use() as token_buffer:
            try:
                proof = build_dpop_proof(
                    provider=self._provider,
                    public_key_pem=identity.public_key_pem,
                    method=method,
                    url=url,
                    access_token=token_buffer,
                )
                token_text = token_buffer.decode("ascii")
                yield {
                    "Authorization": f"DPoP {token_text}",
                    "DPoP": proof,
                }
            finally:
                token_text = ""

    def invalidate(self) -> None:
        self.vault.clear()

    def local_broker_authenticator(self) -> LocalBrokerAuthenticator:
        """Return a signer bound to the enrolled device key, never its secret."""
        return LocalBrokerAuthenticator(
            endpoint_id=self._config.endpoint_id,
            provider=self._provider,
            identity=self._public_identity(),
            clock=self._clock,
        )

    def status(self) -> dict[str, Any]:
        key_status = self._provider.status()
        return {
            "state": self._state,
            "last_error": self._last_error or None,
            "token_encrypted": self.vault.has_token,
            "token_expires_at": self.vault.expires_at or None,
            "scopes": list(self._scopes),
            "key_provider": key_status.provider,
            "key_available": key_status.available,
            "hardware_backed": key_status.hardware_backed,
            "signed_helper": key_status.signed_helper,
        }

    def close(self) -> None:
        self.vault.close()

    def __repr__(self) -> str:
        return (
            "EndpointAuthSession("
            f"state={self._state!r}, endpoint_id={self._config.endpoint_id!r}, "
            f"token_encrypted={self.vault.has_token})"
        )
