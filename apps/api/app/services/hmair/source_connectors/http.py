"""Bounded TLS-verified HTTP access for HMAIR source connectors."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from typing import Any
from urllib.parse import urlparse

import httpx

from app.services import connector_activity, trust_store


MAX_SOURCE_BODY_BYTES = 10 * 1024 * 1024
MAX_SOURCE_PAGE_RECORDS = 10_000
SOURCE_TIMEOUT = httpx.Timeout(60.0, connect=10.0, read=30.0, write=30.0)


class SafeSourceHTTPError(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class SafeSourceHTTPClient:
    """Reject redirects, non-HTTPS URLs, oversized bodies, and loose pages."""

    def __init__(self, *, allowed_origins: Iterable[str], client: httpx.Client | None = None) -> None:
        self._allowed_origins = frozenset(self._origin(value) for value in allowed_origins)
        self._client = client or httpx.Client(
            verify=trust_store.outbound_ssl_context(),
            follow_redirects=False,
            timeout=SOURCE_TIMEOUT,
            # Connector API activity (app/services/connector_activity.py).
            event_hooks=connector_activity.httpx_hooks("discovery source"),
        )
        self._owns_client = client is None

    def __enter__(self) -> "SafeSourceHTTPClient":
        return self

    def __exit__(self, *_: object) -> None:
        if self._owns_client:
            self._client.close()

    @staticmethod
    def _origin(value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise SafeSourceHTTPError("source_url_not_https")
        port = f":{parsed.port}" if parsed.port not in {None, 443} else ""
        return f"https://{parsed.hostname.lower().rstrip('.')}{port}"

    def _validate_url(self, url: str) -> None:
        if self._origin(url) not in self._allowed_origins:
            raise SafeSourceHTTPError("source_url_origin_not_allowed")

    def get_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None = None,
        accepted_statuses: frozenset[int] = frozenset({200}),
    ) -> Any:
        return self._json_body(
            self._get_response(
                url,
                headers=headers,
                params=params,
                accepted_statuses=accepted_statuses,
            )
        )

    def get_ndjson(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        accepted_statuses: frozenset[int] = frozenset({200}),
    ) -> tuple[Mapping[str, Any], ...]:
        response = self._get_response(
            url,
            headers=headers,
            params=None,
            accepted_statuses=accepted_statuses,
        )
        body = self._body(response)
        try:
            rows = tuple(
                json.loads(line)
                for line in body.decode("utf-8").splitlines()
                if line.strip()
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise SafeSourceHTTPError("source_ndjson_malformed") from None
        if len(rows) > MAX_SOURCE_PAGE_RECORDS or any(
            not isinstance(row, Mapping) for row in rows
        ):
            raise SafeSourceHTTPError("source_ndjson_schema_invalid")
        return rows

    def post_form_json(
        self,
        url: str,
        *,
        form: Mapping[str, str],
        headers: Mapping[str, str] | None = None,
        accepted_statuses: frozenset[int] = frozenset({200}),
    ) -> Any:
        self._validate_url(url)
        try:
            response = self._client.post(
                url,
                data=dict(form),
                headers=dict(headers or {}),
            )
        except httpx.HTTPError:
            raise SafeSourceHTTPError("source_http_unavailable") from None
        if response.is_redirect:
            raise SafeSourceHTTPError("source_redirect_not_allowed")
        if response.status_code not in accepted_statuses:
            raise SafeSourceHTTPError(f"source_http_{response.status_code}")
        return self._json_body(response)

    def _get_response(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        params: Mapping[str, str] | None,
        accepted_statuses: frozenset[int],
    ) -> httpx.Response:
        self._validate_url(url)
        try:
            response = self._client.get(url, headers=dict(headers), params=params)
        except httpx.HTTPError:
            raise SafeSourceHTTPError("source_http_unavailable") from None
        if response.is_redirect:
            raise SafeSourceHTTPError("source_redirect_not_allowed")
        if response.status_code not in accepted_statuses:
            raise SafeSourceHTTPError(f"source_http_{response.status_code}")
        return response

    @staticmethod
    def _json_body(response: httpx.Response) -> Any:
        body = SafeSourceHTTPClient._body(response)
        try:
            return json.loads(body)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            raise SafeSourceHTTPError("source_json_malformed") from None

    @staticmethod
    def _body(response: httpx.Response) -> bytes:
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > MAX_SOURCE_BODY_BYTES:
                    raise SafeSourceHTTPError("source_body_too_large")
            except ValueError:
                raise SafeSourceHTTPError("source_content_length_invalid") from None
        body = response.content
        if len(body) > MAX_SOURCE_BODY_BYTES:
            raise SafeSourceHTTPError("source_body_too_large")
        return body
