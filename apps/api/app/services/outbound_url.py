"""Addresses this server calls out to (a connector's service, an identity provider, a certificate's issuer link):
https only, with plain http just for a test double on this machine; never a link-local or cloud instance-metadata
address (169.254.169.254 and friends), where a request could read the host's own cloud credentials; and never with a
user name or password inside the address. Ported from CxMissionZero's src/outbound-url.js.

Private networks (10.x, 192.168.x, …) are not refused here: on-premises services live there. Hawk's credentialed
connector calls go further (app/services/outbound_destination_policy.py: an allowlist per connector, the name
resolved once and the connection pinned to a public address); this guard is what every outbound address passes, the
proxy route included, where the proxy resolves the name.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

LOOPBACK = re.compile(r"^(localhost|127(\.\d{1,3}){3}|::1)$", re.IGNORECASE)
#: Names the clouds give their metadata services.
METADATA_NAMES = frozenset({"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"})
#: Metadata addresses outside 169.254/16: Alibaba Cloud, Azure's wire server, AWS over IPv6.
METADATA_ADDRESSES = frozenset({"100.100.100.200", "168.63.129.16", "fd00:ec2::254"})


def _mapped_ipv4(address: str) -> str:
    """An IPv4 address an IPv6 one carries (::ffff:a.b.c.d, or its hex form ::ffff:a9fe:a9fe)."""

    try:
        ip = ipaddress.IPv6Address(address)
    except ValueError:
        return ""
    return str(ip.ipv4_mapped) if ip.ipv4_mapped else ""


def blocked_host(hostname: str | None) -> bool:
    """A host name (as urlsplit().hostname gives it) the server must never call."""

    host = str(hostname or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host:
        return True
    if host in METADATA_NAMES or host in METADATA_ADDRESSES:
        return True
    host = _mapped_ipv4(host) or host
    if host in METADATA_ADDRESSES:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 4:
        a, b = (int(x) for x in host.split(".")[:2])
        return a == 0 or (a == 169 and b == 254)
    return ip.is_unspecified or ip.is_link_local


def outbound_url_problem(value: str | None, *, allow_loopback_http: bool = True) -> str:
    """Why the server must not call ``value`` ('' when it may)."""

    try:
        url = urlsplit(str(value or "").strip())
        hostname = url.hostname or ""
        url.port  # noqa: B018 - raises on a broken port
    except ValueError:
        return "is not a web address"
    if not url.scheme or not url.netloc:
        return "is not a web address"
    if url.username is not None or url.password is not None:
        return "must not carry a user name or password"
    local = bool(LOOPBACK.match(hostname))
    if url.scheme.lower() != "https" and not (url.scheme.lower() == "http" and allow_loopback_http and local):
        return "must be an https address"
    if blocked_host(hostname):
        return "points at a link-local or cloud metadata address, which the server never calls"
    return ""


class OutboundUrlError(ValueError):
    status_code = 400


def check_outbound_url(value: str | None, *, label: str = "address", allow_loopback_http: bool = True) -> str:
    """``value`` when the server may call it; otherwise an OutboundUrlError that says why."""

    problem = outbound_url_problem(value, allow_loopback_http=allow_loopback_http)
    if problem:
        raise OutboundUrlError(f"The {label} {problem}.")
    return str(value).strip()
