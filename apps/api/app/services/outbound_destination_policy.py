from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from typing import Any, Callable, Collection, Iterable, Mapping
from urllib import request as urllib_request
from urllib.parse import urljoin, urlsplit

import httpcore
import httpx


class OutboundDestinationPolicyError(ValueError):
    """A credentialed request destination is not safe or authorized."""


Resolver = Callable[[str, int], Iterable[Any]]


@dataclass(frozen=True)
class ValidatedDestination:
    url: str
    origin: str
    hostname: str
    port: int
    addresses: tuple[str, ...]

    @property
    def approved_address(self) -> str:
        return self.addresses[0]


def canonical_origin(url: str) -> str:
    origin, _hostname, _port = _canonical_destination(url)
    return origin


def _canonical_destination(url: str) -> tuple[str, str, int]:
    value = str(url or "").strip()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise OutboundDestinationPolicyError("malformed_destination") from exc
    if parsed.scheme.lower() != "https":
        raise OutboundDestinationPolicyError("https_required")
    if not parsed.netloc or not parsed.hostname:
        raise OutboundDestinationPolicyError("malformed_destination")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundDestinationPolicyError("userinfo_not_allowed")
    if parsed.fragment:
        raise OutboundDestinationPolicyError("fragment_not_allowed")
    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise OutboundDestinationPolicyError("malformed_hostname") from exc
    if not hostname:
        raise OutboundDestinationPolicyError("malformed_hostname")
    if ":" not in hostname:
        labels = hostname.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or re.fullmatch(r"[a-z0-9-]+", label) is None
            for label in labels
        ):
            raise OutboundDestinationPolicyError("malformed_hostname")
    resolved_port = port or 443
    if not 1 <= resolved_port <= 65535:
        raise OutboundDestinationPolicyError("invalid_port")
    host_for_origin = f"[{hostname}]" if ":" in hostname else hostname
    suffix = "" if resolved_port == 443 else f":{resolved_port}"
    return f"https://{host_for_origin}{suffix}", hostname, resolved_port


def _canonical_allowlist_origin(value: str) -> str:
    origin, _hostname, _port = _canonical_destination(value)
    parsed = urlsplit(str(value or "").strip())
    if parsed.path not in {"", "/"} or parsed.query:
        raise OutboundDestinationPolicyError("allowlist_entry_must_be_origin")
    return origin


def _system_resolver(hostname: str, port: int) -> tuple[str, ...]:
    answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    return tuple(str(answer[4][0]) for answer in answers)


def _answer_addresses(answers: Iterable[Any]) -> tuple[str, ...]:
    addresses: set[str] = set()
    for answer in answers:
        if isinstance(answer, str):
            addresses.add(answer)
        elif isinstance(answer, (tuple, list)) and len(answer) >= 5:
            socket_address = answer[4]
            if isinstance(socket_address, (tuple, list)) and socket_address:
                addresses.add(str(socket_address[0]))
    return tuple(sorted(addresses))


def _validated_public_addresses(hostname: str, port: int, resolver: Resolver) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            addresses = _answer_addresses(resolver(hostname, port))
        except Exception as exc:
            raise OutboundDestinationPolicyError("dns_resolution_failed") from exc
        if not addresses:
            raise OutboundDestinationPolicyError("dns_resolution_failed")
    else:
        addresses = (str(literal),)
    for address in addresses:
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as exc:
            raise OutboundDestinationPolicyError("dns_returned_invalid_address") from exc
        if (
            not parsed_address.is_global
            or parsed_address.is_loopback
            or parsed_address.is_private
            or parsed_address.is_link_local
            or parsed_address.is_reserved
            or parsed_address.is_multicast
            or parsed_address.is_unspecified
        ):
            raise OutboundDestinationPolicyError(f"non_public_address:{parsed_address}")
    return addresses


class OutboundDestinationPolicy:
    """Server-owned, source-specific authority for credentialed HTTP egress."""

    def __init__(
        self,
        allowed_origins: Mapping[str, Collection[str]],
        *,
        resolver: Resolver | None = None,
    ) -> None:
        self._resolver = resolver or _system_resolver
        self._allowed_origins = {
            str(source).strip().lower(): frozenset(
                _canonical_allowlist_origin(origin) for origin in origins
            )
            for source, origins in allowed_origins.items()
            if str(source).strip()
        }

    def validate(self, url: str, *, source: str) -> ValidatedDestination:
        source_key = str(source or "").strip().lower()
        origin, hostname, port = _canonical_destination(url)
        if origin not in self._allowed_origins.get(source_key, frozenset()):
            raise OutboundDestinationPolicyError(
                f"destination_not_allowed:{source_key}:{origin}"
            )
        addresses = _validated_public_addresses(hostname, port, self._resolver)
        return ValidatedDestination(
            url=str(url),
            origin=origin,
            hostname=hostname,
            port=port,
            addresses=addresses,
        )


def parse_administrator_allowlist(raw_value: str) -> dict[str, tuple[str, ...]]:
    value = str(raw_value or "").strip()
    if not value:
        return {}
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise OutboundDestinationPolicyError("administrator_allowlist_invalid_json") from exc
    if not isinstance(payload, dict):
        raise OutboundDestinationPolicyError("administrator_allowlist_must_be_object")
    parsed: dict[str, tuple[str, ...]] = {}
    for source, origins in payload.items():
        source_key = str(source or "").strip().lower()
        if not source_key or not isinstance(origins, list):
            raise OutboundDestinationPolicyError("administrator_allowlist_invalid_source")
        parsed[source_key] = tuple(str(origin) for origin in origins)
    return parsed


def build_outbound_destination_policy(
    built_in_allowed_origins: Mapping[str, Collection[str]],
    *,
    administrator_allowlist: str | None = None,
    resolver: Resolver | None = None,
) -> OutboundDestinationPolicy:
    if administrator_allowlist is None:
        from app.core.config import settings

        administrator_allowlist = settings.outbound_destination_allowlist
    merged: dict[str, list[str]] = {
        str(source).strip().lower(): [str(origin) for origin in origins]
        for source, origins in built_in_allowed_origins.items()
    }
    for source, origins in parse_administrator_allowlist(administrator_allowlist).items():
        merged.setdefault(source, []).extend(origins)
    return OutboundDestinationPolicy(merged, resolver=resolver)


_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _normalized_header_name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1").strip().lower()
    return str(value).strip().lower()


def _header_names(headers: Any) -> Iterable[Any]:
    if headers is None:
        return ()
    if hasattr(headers, "keys"):
        return headers.keys()
    return (item[0] for item in headers if isinstance(item, (tuple, list)) and item)


def _reject_host_header(headers: Any) -> None:
    if any(_normalized_header_name(name) == "host" for name in _header_names(headers)):
        raise OutboundDestinationPolicyError("host_header_not_allowed")


def _without_headers(headers: Any, names: Collection[str]) -> Any:
    rejected = {name.strip().lower() for name in names}
    if hasattr(headers, "items"):
        return {
            name: value
            for name, value in headers.items()
            if _normalized_header_name(name) not in rejected
        }
    return [
        item
        for item in headers
        if not isinstance(item, (tuple, list))
        or not item
        or _normalized_header_name(item[0]) not in rejected
    ]


class PinnedNetworkBackend(httpcore.NetworkBackend):
    """Connect to one validated IP while httpcore retains the URL host for TLS."""

    def __init__(
        self,
        *,
        expected_hostname: str,
        approved_address: str,
        delegate: httpcore.NetworkBackend | None = None,
    ) -> None:
        self.expected_hostname = expected_hostname
        self.approved_address = approved_address
        self._delegate = delegate or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ):
        requested_host = host.decode("ascii") if isinstance(host, bytes) else str(host)
        if requested_host.rstrip(".").lower() != self.expected_hostname:
            raise OutboundDestinationPolicyError("pinned_transport_hostname_changed")
        return self._delegate.connect_tcp(
            self.approved_address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    def connect_unix_socket(self, path: str, timeout=None, socket_options=None):
        raise OutboundDestinationPolicyError("unix_socket_not_allowed")

    def sleep(self, seconds: float) -> None:
        self._delegate.sleep(seconds)


class PinnedHTTPTransport(httpx.HTTPTransport):
    """One-destination transport whose pool can connect only to one approved IP."""

    def __init__(
        self,
        destination: ValidatedDestination,
        *,
        verify: Any = True,
    ) -> None:
        self.hostname = destination.hostname
        self.approved_address = destination.approved_address
        ssl_context = httpx.create_ssl_context(verify=verify, trust_env=True)
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=1,
            max_keepalive_connections=0,
            keepalive_expiry=0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(
                expected_hostname=destination.hostname,
                approved_address=destination.approved_address,
            ),
        )


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to an IP with certificate checks for the URL host."""

    def __init__(self, host: str, *, approved_address: str, **kwargs: Any) -> None:
        self.approved_address = approved_address
        super().__init__(host, **kwargs)

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self.approved_address, self.port),
            self.timeout,
            self.source_address,
        )
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        if self._tunnel_host:
            raise OutboundDestinationPolicyError("proxy_tunnel_not_allowed")
        server_hostname = self.host
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=server_hostname,
        )


class PinnedHTTPSHandler(urllib_request.HTTPSHandler):
    def __init__(
        self,
        *,
        policy: OutboundDestinationPolicy,
        source: str,
        context: Any,
    ) -> None:
        super().__init__(context=context)
        self._policy = policy
        self._source = source
        self._context = context

    def https_open(self, request):  # noqa: ANN001
        _reject_host_header(request.header_items())
        destination = self._policy.validate(request.full_url, source=self._source)

        def connection_factory(host: str, **kwargs: Any) -> PinnedHTTPSConnection:
            return PinnedHTTPSConnection(
                host,
                approved_address=destination.approved_address,
                **kwargs,
            )

        return self.do_open(
            connection_factory,
            request,
            context=self._context,
        )


def request_with_redirect_validation(
    method: str,
    url: str,
    *,
    source: str,
    policy: OutboundDestinationPolicy,
    max_redirects: int = 5,
    timeout: float = 30.0,
    verify: Any = True,
    client_factory: Callable[..., Any] | None = None,
    transport_factory: Callable[..., Any] = PinnedHTTPTransport,
    allowed_redirect_statuses: Collection[int] | None = None,
    **request_kwargs: Any,
) -> Any:
    current_url = str(url)
    current_method = str(method or "GET").upper()
    current_kwargs = dict(request_kwargs)
    _reject_host_header(current_kwargs.get("headers"))
    current = policy.validate(current_url, source=source)
    credential_origin = current.origin
    resolved_client_factory = client_factory or httpx.Client
    permitted_redirect_statuses = (
        _REDIRECT_STATUSES
        if allowed_redirect_statuses is None
        else frozenset(allowed_redirect_statuses)
    )
    for redirect_count in range(max_redirects + 1):
        if current.origin != credential_origin:
            raise OutboundDestinationPolicyError("credential_redirect_origin_changed")
        transport = transport_factory(current, verify=verify)
        with resolved_client_factory(transport=transport, timeout=timeout) as client:
            response = client.request(
                current_method,
                current_url,
                follow_redirects=False,
                **current_kwargs,
            )
        status_code = int(getattr(response, "status_code", 0))
        if status_code not in _REDIRECT_STATUSES:
            return response
        if status_code not in permitted_redirect_statuses:
            raise OutboundDestinationPolicyError("redirect_status_not_allowed")
        location = str(getattr(response, "headers", {}).get("Location") or "").strip()
        if not location:
            raise OutboundDestinationPolicyError("redirect_missing_location")
        if redirect_count >= max_redirects:
            raise OutboundDestinationPolicyError("too_many_redirects")
        current_url = urljoin(current_url, location)
        current = policy.validate(current_url, source=source)
        if current.origin != credential_origin:
            raise OutboundDestinationPolicyError("credential_redirect_origin_changed")
        switch_to_get = (
            status_code in {302, 303} and current_method != "HEAD"
        ) or (status_code == 301 and current_method == "POST")
        if switch_to_get:
            current_method = "GET"
            for body_key in ("content", "data", "files", "json"):
                current_kwargs.pop(body_key, None)
            if "headers" in current_kwargs:
                current_kwargs["headers"] = _without_headers(
                    current_kwargs["headers"],
                    {"content-length", "transfer-encoding"},
                )
    raise OutboundDestinationPolicyError("too_many_redirects")


class ValidatingHTTPRedirectHandler(urllib_request.HTTPRedirectHandler):
    def __init__(self, *, policy: OutboundDestinationPolicy, source: str) -> None:
        super().__init__()
        self._policy = policy
        self._source = source

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        current = self._policy.validate(req.full_url, source=self._source)
        target = urljoin(req.full_url, str(newurl))
        redirected = self._policy.validate(target, source=self._source)
        if redirected.origin != current.origin:
            raise OutboundDestinationPolicyError("credential_redirect_origin_changed")
        return super().redirect_request(req, fp, code, msg, headers, target)
