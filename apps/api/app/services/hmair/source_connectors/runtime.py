"""Ephemeral authenticated transports for an already-encrypted source connection."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
import ipaddress
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services import connector_activity, trust_store
import jwt

from app.services.hmair.source_connectors.contracts import (
    HMAIRSourceConnectionInput,
    HMAIRSourceProvider,
)
from app.services.hmair.source_connectors.http import (
    SOURCE_TIMEOUT,
    SafeSourceHTTPClient,
    SafeSourceHTTPError,
)


class AuthenticatedSourceHTTP:
    def __init__(
        self,
        *,
        client: httpx.Client,
        allowed_origins: tuple[str, ...],
        authorization: str,
    ) -> None:
        self._client = client
        self._allowed_origins = allowed_origins
        self._authorization = authorization
        self._safe = SafeSourceHTTPClient(allowed_origins=allowed_origins, client=client)

    def get_json(self, url: str, *, headers: Mapping[str, str], **kwargs: Any) -> Any:
        return self._safe.get_json(
            url,
            headers={"Authorization": self._authorization, **dict(headers)},
            **kwargs,
        )

    def get_ndjson(
        self, url: str, *, headers: Mapping[str, str], **kwargs: Any
    ) -> tuple[Mapping[str, Any], ...]:
        origin = self._public_https_origin(url)
        safe = SafeSourceHTTPClient(allowed_origins=(origin,), client=self._client)
        return safe.get_ndjson(
            url,
            headers={"Authorization": self._authorization, **dict(headers)},
            **kwargs,
        )

    @staticmethod
    def _public_https_origin(url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise SafeSourceHTTPError("source_download_url_invalid")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        else:
            if address.is_private or address.is_loopback or address.is_link_local:
                raise SafeSourceHTTPError("source_download_url_invalid")
        port = f":{parsed.port}" if parsed.port not in {None, 443} else ""
        return f"https://{parsed.hostname.lower().rstrip('.')}{port}"

    def close(self) -> None:
        self._client.close()


def _client(client: httpx.Client | None) -> httpx.Client:
    return client or httpx.Client(
        verify=trust_store.outbound_ssl_context(),
        follow_redirects=False,
        timeout=SOURCE_TIMEOUT,
        # Connector API activity (app/services/connector_activity.py).
        event_hooks=connector_activity.httpx_hooks("discovery source"),
    )


def _m365_transport(
    connection: HMAIRSourceConnectionInput, *, client: httpx.Client
) -> AuthenticatedSourceHTTP:
    credentials = connection.credentials
    token_client = SafeSourceHTTPClient(
        allowed_origins=("https://login.microsoftonline.com",), client=client
    )
    try:
        token_payload = token_client.post_form_json(
            f"https://login.microsoftonline.com/{credentials['tenant_id']}/oauth2/v2.0/token",
            form={
                "client_id": credentials["client_id"],
                "client_secret": credentials["client_secret"],
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            },
        )
    except (KeyError, SafeSourceHTTPError):
        raise SafeSourceHTTPError("source_authentication_failed") from None
    access_token = token_payload.get("access_token") if isinstance(token_payload, Mapping) else None
    if not isinstance(access_token, str) or not access_token:
        raise SafeSourceHTTPError("source_authentication_failed")
    return AuthenticatedSourceHTTP(
        client=client,
        allowed_origins=("https://graph.microsoft.com",),
        authorization=f"Bearer {access_token}",
    )


def _github_installation_token_is_read_only(token_payload: Mapping[str, Any]) -> bool:
    """True when the installation token's granted permissions are all read-only.

    GitHub returns the granted permissions with every installation token; an
    absent or malformed permissions object is treated as unverifiable.
    """
    permissions = token_payload.get("permissions")
    if not isinstance(permissions, Mapping) or not permissions:
        return False
    return all(isinstance(level, str) and level.strip().lower() == "read" for level in permissions.values())


def _github_cloud_transport(
    connection: HMAIRSourceConnectionInput, *, client: httpx.Client
) -> AuthenticatedSourceHTTP:
    credentials = connection.credentials
    try:
        now = datetime.now(UTC)
        assertion = jwt.encode(
            {
                "iat": int((now - timedelta(seconds=30)).timestamp()),
                "exp": int((now + timedelta(minutes=9)).timestamp()),
                "iss": credentials["app_id"],
            },
            credentials["private_key_pem"],
            algorithm="RS256",
        )
        token_client = SafeSourceHTTPClient(
            allowed_origins=("https://api.github.com",), client=client
        )
        token_payload = token_client.post_form_json(
            f"https://api.github.com/app/installations/{credentials['installation_id']}/access_tokens",
            form={},
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {assertion}",
                "X-GitHub-Api-Version": "2026-03-10",
            },
            accepted_statuses=frozenset({201}),
        )
    except (KeyError, SafeSourceHTTPError, ValueError):
        raise SafeSourceHTTPError("source_authentication_failed") from None
    access_token = token_payload.get("token") if isinstance(token_payload, Mapping) else None
    if not isinstance(access_token, str) or not access_token:
        raise SafeSourceHTTPError("source_authentication_failed")
    if not _github_installation_token_is_read_only(token_payload):
        # Inventory only reads. A token able to write or administer anything
        # is refused rather than held, so Hawk's own connector can never be
        # the path by which repositories are changed.
        raise SafeSourceHTTPError("source_token_scope_excessive")
    return AuthenticatedSourceHTTP(
        client=client,
        allowed_origins=("https://api.github.com",),
        authorization=f"Bearer {access_token}",
    )


def source_http_for_connection(
    connection: HMAIRSourceConnectionInput,
    *,
    client: httpx.Client | None = None,
) -> AuthenticatedSourceHTTP:
    """Create an ephemeral TLS-verified transport; no token is persisted."""

    resolved_client = _client(client)
    try:
        if connection.provider_key is HMAIRSourceProvider.MICROSOFT365:
            return _m365_transport(connection, client=resolved_client)
        if connection.provider_key is HMAIRSourceProvider.GITHUB_CLOUD:
            return _github_cloud_transport(connection, client=resolved_client)
        if connection.provider_key is HMAIRSourceProvider.GITHUB_GHES:
            return AuthenticatedSourceHTTP(
                client=resolved_client,
                allowed_origins=(connection.target_identifier,),
                authorization=f"Bearer {connection.credentials['access_token']}",
            )
    except Exception:
        resolved_client.close()
        raise
    resolved_client.close()
    raise SafeSourceHTTPError("source_provider_unsupported")


__all__ = ["AuthenticatedSourceHTTP", "source_http_for_connection"]
