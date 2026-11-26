"""How Hawk AI's front proxy (Caddy) is told what Settings → HTTPS decided.

CxMissionZero is one process: it serves HTTPS itself and changes its own TLS context. Hawk runs several containers and
terminates TLS in its front proxy (deploy/compose.yaml, infra/Dockerfile.proxy). So the API owns the HTTPS state
(app/services/https_manager.py) and drives the proxy this way, the one deviation from CxMissionZero's design:

- The API writes the proxy's whole configuration, a Caddyfile, and the certificate in use (with its key) into a folder
  shared with the proxy only (HAWK_PROXY_DIR, the ``hawk-proxy-config`` volume, mounted read-only in the proxy). Each
  file is written whole and flushed, then renamed into place; the certificate files are named after the certificate,
  so a new one is a new path.
- The proxy runs ``caddy run --watch`` on that Caddyfile: Caddy sees the change within a second and reloads with no
  restart, keeping open connections. A configuration Caddy cannot load leaves the one before in use.
- Caddy's admin API stays off: nothing on the network can reconfigure the proxy.

Ports (the proxy's, published by deploy/compose.yaml):
- 8443 (PORT, default 3000): HTTPS in the modes 'https' and 'both'; plain http sent there is answered with a 308
  redirect to https by Caddy's ``http_redirect`` listener wrapper. Plain http in the mode 'http'.
- 8080 (HTTP_REDIRECT_PORT, default 80): plain http. In 'https' it only redirects to https (308), except Let's
  Encrypt's checks; in 'both' and 'http' it serves Hawk AI. CxMissionZero answers both protocols on one port (the
  first byte of each connection decides); Caddy cannot serve plain http on its TLS port, so "http next to HTTPS"
  is on this second port.
- 8081: the container's health check.
"""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Mapping
from pathlib import Path

from app.services.state_file import write_bytes_atomic
from app.services.tls_service import Pem

CADDYFILE = "Caddyfile"
CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
#: The evidence signing public keys (app/services/evidence_signing.py WELL_KNOWN_PATH), answered by the API.
EVIDENCE_KEYS_PATH = "/.well-known/hawk-evidence-keys.json"

_RANGES = {
    "loopback": ["127.0.0.0/8", "::1/128"],
    "linklocal": ["169.254.0.0/16", "fe80::/10"],
    "uniquelocal": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"],
}


class ProxySettingError(ValueError):
    pass


def trust_proxy_ranges(value: str | None, serving_https: bool) -> list[str]:
    """Whose X-Forwarded-For / -Proto / -Host to believe (TRUST_PROXY), as CxMissionZero reads it: ``loopback``,
    ``linklocal``, ``uniquelocal``, IPs or CIDRs (comma-separated), ``on`` (everyone) or ``off`` (nobody). Unset: only
    a proxy on this machine (``loopback``), and nobody when Hawk serves HTTPS itself, because then it faces the clients
    directly. Applied at the front proxy: the API only ever hears from it."""

    text = str(value or "").strip()
    if not text:
        return [] if serving_https else list(_RANGES["loopback"])
    if re.match(r"^(off|false|no|0|none)$", text, re.I):
        return []
    if re.match(r"^(on|true|yes|all)$", text, re.I):
        return ["0.0.0.0/0", "::/0"]
    if re.match(r"^\d+$", text):
        raise ProxySettingError("TRUST_PROXY as a number of hops is not supported by Hawk's proxy: name the proxy's address or network instead.")
    out: list[str] = []
    for part in (p.strip() for p in text.split(",")):
        if not part:
            continue
        if part.lower() in _RANGES:
            out.extend(_RANGES[part.lower()])
            continue
        try:
            out.append(str(ipaddress.ip_network(part, strict=False)))
        except ValueError as error:
            raise ProxySettingError(f'TRUST_PROXY: "{part}" is not an address, a CIDR, loopback, linklocal or uniquelocal.') from error
    return list(dict.fromkeys(out))


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_caddyfile(
    *,
    mode: str,
    cert_file: str | None,
    key_file: str | None,
    min_version: str = "TLSv1.2",
    hsts: str = "",
    trusted: list[str] | None = None,
    https_port: int = 443,
    note: str = "",
) -> str:
    """The proxy's configuration for one HTTPS state. ``hsts`` is the Strict-Transport-Security value ('' for none)."""

    secure = mode in ("https", "both") and bool(cert_file and key_file)
    trusted = trusted or []
    trust_line = f"\t\ttrusted_proxies static {' '.join(trusted)}\n" if trusted else ""
    port = "" if https_port == 443 else f":{https_port}"
    protocols = "tls1.3" if min_version == "TLSv1.3" else "tls1.2 tls1.3"
    lines = [
        "# Written by the Hawk AI API (app/services/https_proxy.py) from Settings → HTTPS. Do not edit: it is rewritten",
        "# at every change. To change HTTPS, use Settings → HTTPS, or: docker compose exec api python -m app.cli.https",
        f"# {note}".rstrip(),
        "{",
        "\tadmin off",
        "\tauto_https off",
        "\tskip_install_trust",
        "\tpersist_config off",
        "\tservers :8443 {",
    ]
    if secure:
        lines += ["\t\tlistener_wrappers {", "\t\t\thttp_redirect", "\t\t\ttls", "\t\t}"]
    lines += [trust_line.rstrip("\n")] if trust_line else []
    lines += ["\t}", "\tservers :8080 {"]
    lines += [trust_line.rstrip("\n")] if trust_line else []
    lines += [
        "\t}",
        "}",
        "",
        "(acme_challenge) {",
        "\t# Let's Encrypt's check (HTTP-01), answered by the API in every mode.",
        f"\t@acme path {CHALLENGE_PREFIX}*",
        "\thandle @acme {",
        "\t\treverse_proxy api:8000 {",
        "\t\t\theader_up Host api",
        "\t\t}",
        "\t}",
        "}",
        "",
        "(hawk) {",
        "\timport acme_challenge",
        "\t# The public keys evidence is signed with (app/services/evidence_signing.py), for auditors without an account.",
        f"\thandle {EVIDENCE_KEYS_PATH} {{",
        "\t\treverse_proxy api:8000",
        "\t}",
        "\thandle_path /api/* {",
        "\t\treverse_proxy api:8000",
        "\t}",
        "\thandle {",
        "\t\treverse_proxy web:3000",
        "\t}",
        "\theader {",
        "\t\tX-Content-Type-Options nosniff",
        "\t\tX-Frame-Options DENY",
        "\t\tReferrer-Policy no-referrer",
        "\t\t-Server",
        "\t}",
        "}",
        "",
    ]
    if secure:
        lines += [
            "https://:8443 {",
            f"\ttls {_quote(str(cert_file))} {_quote(str(key_file))} {{",
            f"\t\tprotocols {protocols}",
            "\t}",
            "\timport hawk",
        ]
        if hsts:
            lines.append(f"\theader Strict-Transport-Security {_quote(hsts)}")
        lines += ["}", ""]
    else:
        lines += ["http://:8443 {", "\timport hawk", "}", ""]
    if mode == "https" and secure:
        lines += [
            "http://:8080 {",
            "\timport acme_challenge",
            "\thandle {",
            f"\t\tredir https://{{host}}{port}{{uri}} 308",
            "\t}",
            "}",
            "",
        ]
    else:
        lines += ["http://:8080 {", "\timport hawk", "}", ""]
    lines += ["# The container's health check only (not published).", "http://:8081 {", '\trespond "ok" 200', "}", ""]
    return "\n".join(lines)


def render_stopped(reason: str) -> str:
    """No HTTPS and no plain http either: the certificate cannot be used, so nothing is served (CxMissionZero stops
    rather than fall back to plain http). The health check fails with the reason."""

    reason = " ".join(str(reason).split())[:300].replace("`", "'")
    return "\n".join(
        [
            "# Written by the Hawk AI API: HTTPS is not set up correctly, so nothing is served (never plain http instead).",
            f"# {reason}",
            "{",
            "\tadmin off",
            "\tauto_https off",
            "\tpersist_config off",
            "}",
            "",
            "http://:8081 {",
            f"\trespond `HTTPS is not set up correctly: {reason}` 503",
            "}",
            "",
        ]
    )


class ProxyConfig:
    """The folder shared with the proxy (HAWK_PROXY_DIR). Without one (tests, a local run without the proxy) nothing
    is written."""

    def __init__(self, directory: str | Path | None) -> None:
        self.directory = Path(directory) if directory else None

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "ProxyConfig":
        return cls(str(env.get("HAWK_PROXY_DIR") or "").strip() or None)

    @property
    def enabled(self) -> bool:
        return self.directory is not None

    def write(self, *, mode: str, pem: Pem | None, fingerprint: str, **options) -> None:
        if not self.directory:
            return
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        cert_file = key_file = None
        if pem is not None and mode != "http":
            stem = f"live-{fingerprint[:16] or 'none'}"
            cert_file, key_file = self.directory / f"{stem}.crt", self.directory / f"{stem}.key"
            write_bytes_atomic(cert_file, pem.cert, mode=0o644)
            write_bytes_atomic(key_file, pem.key, mode=0o600)
        text = render_caddyfile(mode=mode, cert_file=str(cert_file) if cert_file else None, key_file=str(key_file) if key_file else None, **options)
        write_bytes_atomic(self.directory / CADDYFILE, text.encode("utf-8"), mode=0o644)
        self._tidy(keep={p.name for p in (cert_file, key_file) if p})

    def write_stopped(self, reason: str) -> None:
        if not self.directory:
            return
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_bytes_atomic(self.directory / CADDYFILE, render_stopped(reason).encode("utf-8"), mode=0o644)
        self._tidy(keep=set())

    def _tidy(self, keep: set[str]) -> None:
        """Certificates no longer named in the configuration are removed (keys never linger)."""

        assert self.directory is not None
        for path in self.directory.glob("live-*"):
            if path.name not in keep:
                try:
                    path.unlink()
                except OSError:
                    pass

    def caddyfile(self) -> str:
        if not self.directory:
            return ""
        try:
            return (self.directory / CADDYFILE).read_text(encoding="utf-8")
        except OSError:
            return ""
