"""How Hawk AI reaches the internet: directly, or through a company proxy, and what a network team needs to allow.
Ported from CxMissionZero's src/network.js (docs/network.md).

The proxy is set under Settings → Network & proxy (saved in the data folder as network.json, 0600, with no last good
copy: it holds the proxy's password) or with the usual HTTPS_PROXY / HTTP_PROXY / NO_PROXY environment variables; the
page's setting wins. It is put into each process's environment when it starts (:func:`apply_to_environment`, called by
the API and the Celery worker and beat), so every outbound HTTPS client there uses it. MZ's launcher restarts the server
by itself after a change; Hawk runs as several containers, so a change takes effect when api, worker and beat are
restarted (``docker compose -f deploy/compose.yaml restart api worker beat``), and the page says so.

SOCKS, NTLM and Kerberos are not supported (basic authentication only). Email (SMTP) always goes direct.

The check opens the same tunnel by hand, step by step, so it can say where it stopped: the proxy, the tunnel to the
host (with what a 407 or a 403 means), the certificate, or the service's answer.
"""

from __future__ import annotations

import base64
import os
import re
import socket
import ssl
from pathlib import Path
from typing import Any, Mapping, MutableMapping
from urllib.parse import quote, unquote, urlsplit

from app.services.state_file import StateFileError, read_state, write_state

NETWORK_FILE = "network.json"
#: Always reached directly: this machine and the other containers of the stack.
ALWAYS_DIRECT = ["localhost", "127.0.0.1", "::1", "api", "web", "worker", "beat", "proxy", "postgres", "redis"]
_PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "NO_PROXY", "no_proxy")
SERVER_NAME = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", re.IGNORECASE)
RESTART = "docker compose -f deploy/compose.yaml restart api worker beat"


class NetworkError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def data_dir() -> Path:
    from app.core.config import settings

    return Path(str(settings.hawk_data_dir or ".runtime/data"))


def read_network(directory: Path | None = None) -> dict[str, Any] | None:
    """The saved proxy (password included: server side only), or None. A damaged file is said once and not used."""

    try:
        saved = read_state((directory or data_dir()) / NETWORK_FILE, fallback=None, holds="the proxy this server goes out through")
    except StateFileError as error:
        print(f"! [network] The saved proxy cannot be read, so none is used. {str(error).splitlines()[0]}", flush=True)
        return None
    return saved if isinstance(saved, dict) and isinstance(saved.get("proxy"), dict) and saved["proxy"].get("url") else None


def save_network(value: dict[str, Any] | None, directory: Path | None = None) -> None:
    file = (directory or data_dir()) / NETWORK_FILE
    if not value:
        for name in (file, Path(f"{file}.bak")):
            try:
                name.unlink()
            except FileNotFoundError:
                pass
        return
    # No .bak of the settings before: they hold the proxy's password, and one changed or taken out on purpose must not
    # stay on the disk.
    write_state(file, value, keep_last=False)


def clean_proxy(*, url: Any = "", username: Any = "", password: Any = "", no_proxy: Any = "") -> dict[str, str]:
    """A proxy as typed: http(s)://host:port, no path. Raises NetworkError with a reason."""

    raw = str(url or "").strip()
    try:
        parsed = urlsplit(raw if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.IGNORECASE) else f"http://{raw}")
        port = parsed.port
    except ValueError as error:
        raise NetworkError("Give the proxy as host:port, for example proxy.acme.local:8080.") from error
    if parsed.scheme.lower() not in ("http", "https"):
        raise NetworkError("The proxy must be an http:// or https:// address (a SOCKS proxy is not supported).")
    if parsed.username or parsed.password:
        raise NetworkError("Give the proxy's user name and password in their own fields, not in the address.")
    if not parsed.hostname or (parsed.path and parsed.path != "/"):
        raise NetworkError("Give the proxy as host:port, without a path.")
    hosts: list[str] = []
    for h in re.split(r"[\s,;]+", str(no_proxy or "")):
        h = h.strip().lower()
        if h and h not in hosts:
            hosts.append(h)
    if any(not re.fullmatch(r"[a-z0-9.*:\[\]-]+", h) for h in hosts):
        raise NetworkError("Hosts that skip the proxy: names or addresses separated by commas, for example .acme.local, 10.0.0.5.")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return {
        "url": f"{parsed.scheme.lower()}://{host}:{port or (443 if parsed.scheme.lower() == 'https' else 80)}",
        "username": str(username or "").strip(),
        "password": str(password or ""),
        "noProxy": ",".join(hosts),
    }


def proxy_with_auth(proxy: Mapping[str, Any]) -> str:
    """The proxy address with its sign-in, as the proxy variables carry it."""

    if not proxy.get("username"):
        return str(proxy["url"])
    parts = urlsplit(str(proxy["url"]))
    return f"{parts.scheme}://{quote(str(proxy['username']), safe='')}:{quote(str(proxy.get('password') or ''), safe='')}@{parts.netloc}"


def _from_env(env: Mapping[str, str], name: str) -> str:
    return env.get(name) or env.get(name.lower()) or ""


def proxy_environment(env: Mapping[str, str] | None = None, directory: Path | None = None) -> dict[str, str]:
    """What a process adds to its environment at start: the saved proxy (it wins), or the container's own HTTPS_PROXY
    with this stack's own hosts added to NO_PROXY. Nothing when neither is set."""

    env = os.environ if env is None else env
    saved = (read_network(directory) or {}).get("proxy")
    proxy = proxy_with_auth(saved) if saved else (_from_env(env, "HTTPS_PROXY") or _from_env(env, "HTTP_PROXY"))
    if not proxy:
        return {}
    rules = (saved["noProxy"] if saved else _from_env(env, "NO_PROXY")).split(",")
    no_proxy = ",".join(dict.fromkeys([*ALWAYS_DIRECT, *(r.strip() for r in rules if r.strip())]))
    return {"HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy, "NO_PROXY": no_proxy, "no_proxy": no_proxy}


#: What this process's environment held before :func:`apply_to_environment` (the container's own proxy settings).
_applied: dict[str, Any] = {"at_start": None}


def apply_to_environment(env: MutableMapping[str, str] | None = None, directory: Path | None = None) -> dict[str, str]:
    """Called once when api, worker and beat start: the proxy into this process's environment (httpx, urllib and
    boto3 read it from there) and into Hawk's own outbound clients (:func:`proxy_for`), and the trusted certificates'
    bundle (app/services/trust_store.py) for clients that read SSL_CERT_FILE."""

    env = os.environ if env is None else env
    if _applied["at_start"] is None:
        _applied["at_start"] = {name: env.get(name) or "" for name in _PROXY_VARS}
    source = _applied["at_start"]
    added = proxy_environment(source, directory)
    if not added:
        for name in _PROXY_VARS:
            if not source.get(name):
                env.pop(name, None)
    env.update(added)
    use_proxy(added.get("HTTPS_PROXY", ""), added.get("NO_PROXY", ""))
    try:
        from app.services import trust_store

        bundle = trust_store.store(directory).write_bundle()
        if bundle:
            env["SSL_CERT_FILE"] = str(bundle)
            env["REQUESTS_CA_BUNDLE"] = str(bundle)
    except Exception as error:  # noqa: BLE001 - a trust problem is reported where it is used, never stops a start
        print(f"! [trust] The trusted certificates could not be applied: {error}", flush=True)
    return added


def _shown(raw: str) -> tuple[str, str]:
    try:
        p = urlsplit(raw)
        return (f"{p.scheme}://{p.hostname}:{p.port}" if p.port else f"{p.scheme}://{p.hostname}"), unquote(p.username or "")
    except ValueError:
        return raw, ""


def active_proxy(env: Mapping[str, str] | None = None, directory: Path | None = None) -> dict[str, Any] | None:
    """The proxy this server uses (no password), where it came from, and whether this process runs with it."""

    saved = (read_network(directory) or {}).get("proxy")
    running = _shown(_active["proxy"])[0] if _active["proxy"] else ""
    if saved:
        return {"url": saved["url"], "username": saved.get("username", ""), "noProxy": saved.get("noProxy", ""), "source": "settings", "running": running == saved["url"]}
    container = _applied["at_start"] if _applied["at_start"] is not None else (os.environ if env is None else env)
    raw = _from_env(container, "HTTPS_PROXY") or _from_env(container, "HTTP_PROXY")
    if not raw:
        return None
    shown, username = _shown(raw)
    return {"url": shown, "username": username, "noProxy": _from_env(container, "NO_PROXY"), "source": "environment", "running": running == shown}


def bypasses(host: str, no_proxy: str = "") -> bool:
    """Whether ``host`` skips the proxy (NO_PROXY rules: exact, .suffix, *.suffix, or *)."""

    h = str(host).lower().strip("[]")
    for rule in [*ALWAYS_DIRECT, *str(no_proxy).split(",")]:
        rule = re.sub(r":\d+$", "", rule.strip().lower())
        if not rule:
            continue
        bare = re.sub(r"^\*?\.", "", rule)
        if rule == "*" or h == bare:
            return True
        suffix = rule[1:] if rule.startswith("*") else rule
        if suffix.startswith(".") and h.endswith(suffix):
            return True
    return False


#: The proxy Hawk's own outbound clients use: what :func:`apply_to_environment` found at this process's start (the
#: saved proxy, or the container's HTTPS_PROXY). Not read from the environment at each call, so a process that never
#: applied it (a test, a one-off command) goes direct.
_active: dict[str, str] = {"proxy": "", "no_proxy": ""}


def use_proxy(proxy: str = "", no_proxy: str = "") -> None:
    _active["proxy"], _active["no_proxy"] = proxy or "", no_proxy or ""


def proxy_for(host: str, env: Mapping[str, str] | None = None) -> str:
    """The proxy (with sign-in) this process sends ``host`` through; '' for direct. With ``env``: from that
    environment instead."""

    if env is not None:
        proxy = _from_env(env, "HTTPS_PROXY") or _from_env(env, "HTTP_PROXY")
        return proxy if proxy and not bypasses(host, _from_env(env, "NO_PROXY")) else ""
    proxy = _active["proxy"]
    return proxy if proxy and not bypasses(host, _active["no_proxy"]) else ""


# ---------------------------------------------------------------------------------------------------------------------
# The check, one step at a time
# ---------------------------------------------------------------------------------------------------------------------


class StepError(Exception):
    def __init__(self, step: str, message: str, *, status: int = 0, code: str = "") -> None:
        super().__init__(message)
        self.step = step
        self.status = status
        self.code = code


def open_tunnel(proxy: str, host: str, port: int, *, timeout: float = 10.0) -> socket.socket:
    """A raw connection to host:port: through ``proxy`` (an HTTP CONNECT tunnel, with its basic sign-in) or directly.
    Errors say which step failed: "proxy" (not reached), "tunnel" (refused) or "direct"."""

    if not proxy:
        try:
            return socket.create_connection((host, port), timeout=timeout)
        except socket.timeout as error:
            raise StepError("direct", f"{host}:{port} did not answer within {round(timeout)} seconds", code="ETIMEDOUT") from error
        except OSError as error:
            raise StepError("direct", f"{host}:{port}: {error.strerror or error}", code=str(getattr(error, 'errno', '') or '')) from error
    p = urlsplit(proxy)
    proxy_host, proxy_port = p.hostname or "", p.port or (443 if p.scheme == "https" else 80)
    label = f"{proxy_host}:{proxy_port}"
    try:
        sock: socket.socket = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        if p.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=proxy_host)
    except socket.timeout as error:
        raise StepError("proxy", f"The proxy {label} did not answer within {round(timeout)} seconds.", code="ETIMEDOUT") from error
    except OSError as error:
        raise StepError("proxy", f"The proxy {label} could not be reached: {error.strerror or error}.", code=str(getattr(error, 'errno', '') or '')) from error
    headers = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if p.username:
        token = base64.b64encode(f"{unquote(p.username)}:{unquote(p.password or '')}".encode("utf-8")).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    try:
        sock.sendall(("\r\n".join(headers) + "\r\n\r\n").encode("latin-1"))
        answer = b""
        while b"\r\n\r\n" not in answer and len(answer) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            answer += chunk
    except socket.timeout as error:
        sock.close()
        raise StepError("proxy", f"The proxy {label} did not answer within {round(timeout)} seconds.", code="ETIMEDOUT") from error
    except OSError as error:
        sock.close()
        raise StepError("proxy", f"The proxy {label} could not be reached: {error.strerror or error}.") from error
    status_line = answer.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})\s*(.*)", status_line)
    if not match:
        sock.close()
        raise StepError("proxy", f"The proxy {label} did not answer as an HTTP proxy.")
    status, reason = int(match.group(1)), match.group(2).strip()
    if status != 200:
        sock.close()
        shown = f"{status} {reason}".strip()
        raise StepError("tunnel", f"The proxy refused the connection to {host}:{port} ({shown}).", status=status)
    return sock


#: OpenSSL's verify codes, by the names Node (and so CxMissionZero's page) gives them.
VERIFY_CODES = {
    2: "UNABLE_TO_GET_ISSUER_CERT",
    9: "CERT_NOT_YET_VALID",
    10: "CERT_HAS_EXPIRED",
    18: "DEPTH_ZERO_SELF_SIGNED_CERT",
    19: "SELF_SIGNED_CERT_IN_CHAIN",
    20: "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    21: "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    27: "CERT_UNTRUSTED",
    62: "ERR_TLS_CERT_ALTNAME_INVALID",
}


def verify_code_name(error: BaseException) -> str:
    code = getattr(error, "verify_code", None)
    if isinstance(code, int):
        return VERIFY_CODES.get(code, f"X509_V_ERR_{code}")
    return type(error).__name__


def check_route(*, proxy: str = "", host: str, port: int = 443, pathname: str = "/", timeout: float = 10.0, context: ssl.SSLContext | None = None) -> dict[str, Any]:
    """Check the way to an HTTPS host, one step at a time: the proxy (when there is one), the tunnel, the certificate,
    and an answer. Never raises; says where it stopped."""

    from app.services import trust_store

    steps: list[dict[str, Any]] = []
    label = urlsplit(proxy).netloc.rpartition("@")[2] if proxy else ""
    try:
        sock = open_tunnel(proxy, host, port, timeout=timeout)
        if proxy:
            steps.append({"step": "proxy", "ok": True, "detail": f"Reached the proxy {label}."})
        steps.append({"step": "tunnel", "ok": True, "detail": f"The proxy opened a connection to {host}:{port}." if proxy else f"Connected to {host}:{port} directly."})
    except StepError as error:
        if proxy and error.step == "tunnel":
            steps.append({"step": "proxy", "ok": True, "detail": f"Reached the proxy {label}."})
        steps.append({"step": "tunnel" if error.step == "direct" else error.step, "ok": False, "detail": str(error), "status": error.status, "code": error.code})
        return {"ok": False, "host": host, "port": port, "steps": steps}
    ctx = context or trust_store.outbound_ssl_context()
    try:
        secure = ctx.wrap_socket(sock, server_hostname=None if _is_ip(host) else host)
    except ssl.SSLCertVerificationError as error:
        sock.close()
        code = verify_code_name(error)
        issuer = ""
        try:
            seen = trust_store.inspect(host, port, proxy=proxy, timeout=timeout)
            issuer = trust_store.describe(seen["chain"][0])["issuer"] if seen["chain"] else ""
        except Exception:  # noqa: BLE001
            pass
        steps.append({"step": "certificate", "ok": False, "code": code, "issuer": issuer, "detail": f"{host}'s certificate{f', issued by {chr(34)}{issuer}{chr(34)},' if issuer else ''} is not trusted here ({code})."})
        return {"ok": False, "host": host, "port": port, "steps": steps}
    except (OSError, ssl.SSLError) as error:
        sock.close()
        steps.append({"step": "certificate", "ok": False, "detail": f"No secure connection with {host}: {getattr(error, 'reason', None) or error}."})
        return {"ok": False, "host": host, "port": port, "steps": steps}
    steps.append({"step": "certificate", "ok": True, "detail": f"{host}'s certificate is trusted."})
    try:
        secure.settimeout(timeout)
        secure.sendall(f"GET {pathname} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nUser-Agent: Hawk-AI-network-check\r\nConnection: close\r\n\r\n".encode("latin-1"))
        first = secure.recv(4096).split(b"\r\n", 1)[0].decode("latin-1", "replace")
        match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", first)
        status = int(match.group(1)) if match else 0
        error_text = "" if match else "no HTTP answer"
    except OSError as error:
        status, error_text = 0, str(error)
    finally:
        try:
            secure.close()
        except OSError:
            pass
    if error_text or status >= 500:
        steps.append({"step": "answer", "ok": False, "detail": f"{host} did not answer properly ({error_text or status})."})
        return {"ok": False, "host": host, "port": port, "steps": steps}
    steps.append({"step": "answer", "ok": True, "detail": f"{host} answered ({status}).", "status": status})
    return {"ok": True, "host": host, "port": port, "steps": steps}


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def check_target(typed: Any) -> dict[str, Any]:
    """The address typed to check: host[:port], with or without https://."""

    text_value = re.sub(r"/.*$", "", re.sub(r"^https?://", "", str(typed or "").strip(), flags=re.IGNORECASE)).lower()
    host, _, port = text_value.partition(":")
    from app.services.outbound_url import blocked_host

    if not SERVER_NAME.match(host) or blocked_host(host):
        raise NetworkError("Give the address of a service to check, for example graph.microsoft.com.")
    try:
        number = int(port) if port else 443
    except ValueError as error:
        raise NetworkError("Give the address of a service to check, for example graph.microsoft.com.") from error
    if not 1 <= number <= 65535:
        raise NetworkError("Give the address of a service to check, for example graph.microsoft.com.")
    return {"host": host, "port": number}


# ---------------------------------------------------------------------------------------------------------------------
# What the network team needs to allow
# ---------------------------------------------------------------------------------------------------------------------


def requirements(
    *,
    connectors: list[dict[str, Any]],
    catalogue: list[dict[str, Any]],
    smtp: dict[str, Any] | None = None,
    sso: list[dict[str, Any]] | None = None,
    lets_encrypt: bool = False,
    inbound_port: int = 3000,
    proxy: dict[str, Any] | None = None,
    backup_mail: dict[str, Any] | None = None,
) -> list[dict[str, str]]:
    """Every connection this server makes or takes, for a network team: what, where, port, through the proxy or not,
    and why. From this server's own settings (MZ's requirements())."""

    via = "Through the proxy" if proxy else "Direct"
    rows: list[dict[str, str]] = []

    def add(direction: str, what: str, host: str, port: Any, route: str, why: str) -> None:
        rows.append({"direction": direction, "what": what, "host": host, "port": str(port), "route": route, "why": why})

    add("In", "People's browsers, and links in emailed messages", "this server", inbound_port, "Direct", "The console, sign-in and the API on the same address.")
    seen: set[tuple[str, str]] = set()
    for c in connectors:
        key = (c["what"], c["host"])
        if key in seen:
            continue
        seen.add(key)
        add("Out", c["what"], c["host"], c.get("port", 443), via, c.get("why") or "A connector you set up: what it reads from the service.")
    for c in catalogue:
        key = (c["what"], c["host"])
        if key in seen:
            continue
        seen.add(key)
        add("Out", c["what"], c["host"], c.get("port", 443), via, "Only if you connect it.")
    for s in sso or []:
        add("Out", "Identity provider (single sign-on)", s["host"], s.get("port", 443), via, "People signing in with single sign-on. The provider may keep its keys and token address on other hosts of its own: its discovery document names them.")
    if smtp and smtp.get("host"):
        add("Out", "Email server", smtp["host"], smtp.get("port") or 587, "Direct (mail does not go through a web proxy)", "Password reset links, support requests and notices.")
    if backup_mail and backup_mail.get("host"):
        add("Out", "Mailbox for backups", backup_mail["host"], backup_mail.get("port") or 993, "Direct", "Backups sent by email.")
    if lets_encrypt:
        add("Out", "Let's Encrypt", "acme-v02.api.letsencrypt.org", 443, via, "This server's HTTPS certificate.")
        add("In", "Let's Encrypt validation", "this server", 80, "Direct", "Proves the server name when the certificate is issued and renewed.")
    add("Out", "Certificate authorities (rarely)", "the address in a server's certificate", 80, via, "Only when a server leaves out its intermediate certificate.")
    return rows


def requirements_text(rows: list[dict[str, str]], *, proxy: dict[str, Any] | None = None, server_name: str = "") -> str:
    """The sheet as plain text, ready to paste into a ticket or an email to the network team."""

    lines = [
        f"Network requirements for Hawk AI{f' ({server_name})' if server_name else ''}",
        "",
        f"Outgoing web traffic goes through the proxy {proxy['url']}." if proxy else "Outgoing web traffic goes directly (no proxy configured).",
        "",
        "Please allow:",
        *(f"- {'Incoming to' if r['direction'] == 'In' else 'Outgoing to'} {r['host']}, port {r['port']} ({r['route']}): {r['what']}. {r['why']}" for r in rows),
        "",
        "For the proxy (if there is one):",
        "- Allow this server's IP address to the hosts above on port 443 (HTTP CONNECT).",
        "- Without HTTPS inspection for these hosts (or tell us, and we trust the proxy's certificate in the app).",
        "- Without Windows-integrated sign-in (NTLM/Kerberos): allow by IP address, or give a user name and password for basic authentication.",
        "",
        "All traffic is encrypted (HTTPS / TLS 1.2 or later); nothing else is sent anywhere.",
    ]
    return "\n".join(lines)
