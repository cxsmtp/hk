"""Which certificate authorities Hawk AI trusts when it calls out over HTTPS (connectors, single sign-on, the mail
server): the public ones (certifi's bundle and the container's own store) and the ones an administrator added, kept in
the data folder (trust/certificates.json). Ported from CxMissionZero's src/trust.js and src/routes/trust.js.

Applied at once, with no restart and no environment variable: every outbound client of Hawk's connectors builds its
TLS context from :func:`outbound_ssl_context`, which reads the saved list again when it changes (the api and the
worker share the data folder). Clients that read SSL_CERT_FILE get trust/bundle.pem from their next start
(app/services/network_proxy.py ``apply_to_environment``).

Two reasons a certificate is "not trusted", and what this does about each:
- The server left out an intermediate certificate (browsers fetch it themselves; Python does not). It is fetched from
  the address the certificate names (its "CA Issuers" link, AIA), and kept only if it chains to a root already
  trusted. Nothing to ask: it changes no one's trust. Audited.
- A company proxy inspects HTTPS and signs with its own root. Its root is found (through the same links) and shown to
  an administrator, who trusts it with a click ("Trust and connect"), or uploads it. Never trusted without that.

Unlike Node, Python 3.11's ssl module gives only the server's own certificate of what it presented, not the rest of
the chain: intermediates and roots are found through the AIA links, or come from an upload.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import os
import re
import socket
import ssl
import threading
from pathlib import Path
from typing import Any, Callable

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID, NameOID

from app.services.state_file import read_state, write_state

UNTRUSTED = {
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "UNABLE_TO_GET_ISSUER_CERT",
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "SELF_SIGNED_CERT_IN_CHAIN",
    "DEPTH_ZERO_SELF_SIGNED_CERT",
    "CERT_UNTRUSTED",
}
MAX_SAVED = 50
MAX_DOWNLOAD = 64 * 1024
HOPS = 4

VENDORS = [
    (r"zscaler", "Zscaler"),
    (r"netskope", "Netskope"),
    (r"palo ?alto|pan-?os|globalprotect|prisma", "Palo Alto Networks"),
    (r"forti(net|gate|proxy)", "Fortinet"),
    (r"umbrella|cisco", "Cisco"),
    (r"blue ?coat|symantec web|proxysg", "Symantec / Blue Coat"),
    (r"forcepoint|websense", "Forcepoint"),
    (r"sophos", "Sophos"),
    (r"check ?point", "Check Point"),
    (r"mcafee|skyhigh", "Skyhigh / McAfee"),
    (r"cloudflare", "Cloudflare"),
    (r"iboss", "iboss"),
    (r"menlo", "Menlo Security"),
    (r"barracuda", "Barracuda"),
    (r"watchguard", "WatchGuard"),
    (r"sonicwall", "SonicWall"),
    (r"kaspersky", "Kaspersky"),
    (r"eset", "ESET"),
    (r"avast|avg ", "Avast"),
    (r"bitdefender", "Bitdefender"),
    (r"trend ?micro", "Trend Micro"),
    (r"squid", "Squid"),
]


def is_untrusted_code(code: str | None) -> bool:
    return str(code or "") in UNTRUSTED


class TrustError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


# ---------------------------------------------------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------------------------------------------------


def _attr(name: x509.Name, oid: Any) -> str:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else ""


def name_of(name: x509.Name) -> str:
    return _attr(name, NameOID.COMMON_NAME) or _attr(name, NameOID.ORGANIZATION_NAME) or name.rfc4514_string()


def fingerprint256(cert: x509.Certificate) -> str:
    """As Node writes it (and so the page shows it): upper-case hex pairs separated by colons."""

    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except x509.ExtensionNotFound:
        return False


def issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except Exception:  # noqa: BLE001 - not its issuer
        return False


def is_self_signed(cert: x509.Certificate) -> bool:
    return cert.issuer == cert.subject and issued_by(cert, cert)


def expired(cert: x509.Certificate, now: dt.datetime | None = None) -> bool:
    now = now or dt.datetime.now(dt.timezone.utc)
    return cert.not_valid_after_utc < now or cert.not_valid_before_utc > now + dt.timedelta(days=1)


def to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def describe(cert: x509.Certificate) -> dict[str, Any]:
    """What an administrator is shown about a certificate (nothing secret: certificates are public)."""

    text = f"{cert.subject.rfc4514_string()}\n{cert.issuer.rfc4514_string()}"
    vendor = next((label for pattern, label in VENDORS if re.search(pattern, text, re.IGNORECASE)), "")
    return {
        "subject": name_of(cert.subject),
        "organization": _attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "issuer": name_of(cert.issuer),
        "fingerprint256": fingerprint256(cert),
        "validFrom": cert.not_valid_before_utc.isoformat().replace("+00:00", "Z"),
        "validTo": cert.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
        "ca": is_ca(cert),
        "selfSigned": is_self_signed(cert),
        "vendor": vendor,
    }


def parse_certificates(data: bytes | str) -> list[x509.Certificate]:
    """The certificates in a PEM bundle, or one DER certificate (also base64 of DER, as .cer files often are)."""

    raw = data.encode("latin-1") if isinstance(data, str) else bytes(data)
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", raw)
    if blocks:
        out = []
        for block in blocks:
            try:
                out.append(x509.load_pem_x509_certificate(block))
            except ValueError:
                continue
        return out
    der = raw
    if re.fullmatch(rb"[A-Za-z0-9+/=\s]+", raw or b"-"):
        try:
            der = base64.b64decode(re.sub(rb"\s+", b"", raw), validate=True)
        except ValueError:
            der = raw
    try:
        return [x509.load_der_x509_certificate(der)]
    except ValueError:
        return []


def ca_issuers_urls(cert: x509.Certificate) -> list[str]:
    """"CA Issuers" links (http/https) in a certificate's Authority Information Access."""

    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    out = []
    for desc in aia:
        if desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS and isinstance(desc.access_location, x509.UniformResourceIdentifier):
            url = desc.access_location.value
            if re.match(r"^https?://", url, re.IGNORECASE):
                out.append(url)
    return out


# ---------------------------------------------------------------------------------------------------------------------
# Following an issuer link: never to instance metadata, nor to this server itself
# ---------------------------------------------------------------------------------------------------------------------

_NEVER = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "fe80::/10", "fd00:ec2::254/128", "ff00::/8")]
_METADATA = re.compile(r"^(169\.254\.\d+\.\d+|fd00:ec2::254|metadata\.google\.internal|metadata)$", re.IGNORECASE)


def followable_address(address: str, *, allow_loopback: bool = False) -> bool:
    """Whether an issuer link may be followed to this IP address (company networks' 10.x, 192.168.x… stay allowed: a
    company CA publishes its certificates there). ``allow_loopback``: tests' own local servers only."""

    try:
        ip = ipaddress.ip_address(str(address).strip("[]"))
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if allow_loopback and ip.is_loopback:
        return True
    return not any(ip in net for net in _NEVER if net.version == ip.version)


def _refused(url: str, why: str) -> TrustError:
    return TrustError(f"{url} is not followed ({why})")


def fetch_issuer(url: str, *, timeout: float = 8.0, redirects: int = 2, allow_loopback: bool = False, resolver: Callable[[str], list[str]] | None = None) -> x509.Certificate:
    """A certificate from a "CA Issuers" link: http(s) only, never to this server or instance metadata, at most 64 KB,
    a few seconds, two redirects (each checked the same way). Through the company proxy when one is used (the proxy
    resolves the name); directly, the connection goes only to the address that was checked."""

    import httpcore
    import httpx

    from app.services import network_proxy
    from app.services.outbound_destination_policy import PinnedNetworkBackend

    try:
        target = httpx.URL(url)
    except Exception as error:  # noqa: BLE001
        raise _refused(url, "not an address") from error
    if target.scheme not in ("http", "https"):
        raise _refused(url, "only http and https")
    host = target.host.strip("[]")
    if _METADATA.match(host):
        raise _refused(url, "instance metadata")
    proxy = network_proxy.proxy_for(host)
    if not proxy:
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            try:
                addresses = (resolver or (lambda h: sorted({a[4][0] for a in socket.getaddrinfo(h, None, type=socket.SOCK_STREAM)})))(host)
            except OSError:
                addresses = []
        if not addresses:
            raise _refused(url, "its name does not resolve")
        if any(not followable_address(a, allow_loopback=allow_loopback) for a in addresses):
            raise _refused(url, "a local, link-local or metadata address")
        transport: Any = httpx.HTTPTransport()
        transport._pool = httpcore.ConnectionPool(  # noqa: SLF001 - the pool, pinned to the checked address
            ssl_context=outbound_ssl_context(),
            network_backend=PinnedNetworkBackend(expected_hostname=host.lower(), approved_address=addresses[0]),
        )
        client = httpx.Client(transport=transport, timeout=timeout, follow_redirects=False, trust_env=False)
    else:
        client = httpx.Client(proxy=proxy, timeout=timeout, follow_redirects=False, trust_env=False, verify=outbound_ssl_context())
    with client:
        with client.stream("GET", url, headers={"Accept": "application/pkix-cert, application/x-x509-ca-cert, */*"}) as response:
            if 300 <= response.status_code < 400 and response.headers.get("location") and redirects > 0:
                following = str(target.join(response.headers["location"]))
                return fetch_issuer(following, timeout=timeout, redirects=redirects - 1, allow_loopback=allow_loopback, resolver=resolver)
            if response.status_code != 200:
                raise TrustError(f"{url} answered {response.status_code}")
            body = b""
            for chunk in response.iter_bytes():
                body += chunk
                if len(body) > MAX_DOWNLOAD:
                    raise TrustError(f"{url} is larger than a certificate")
    certs = parse_certificates(body)
    if not certs:
        raise TrustError(f"{url} did not hold a certificate")
    return certs[0]


# ---------------------------------------------------------------------------------------------------------------------
# Looking at what a server presents
# ---------------------------------------------------------------------------------------------------------------------


def _connect(host: str, port: int, proxy: str, timeout: float) -> socket.socket:
    from app.services import network_proxy

    return network_proxy.open_tunnel(proxy, host, port, timeout=timeout)


def inspect(host: str, port: int = 443, *, proxy: str | None = None, timeout: float = 10.0, context: ssl.SSLContext | None = None) -> dict[str, Any]:
    """Connect to host:port and read the certificate it presents, without trusting it; whether it is trusted here, and
    why not. Nothing is sent but the handshake. Through the company proxy when this server uses one."""

    from app.services import network_proxy

    proxy = network_proxy.proxy_for(host) if proxy is None else proxy
    server_name = None if _is_ip(host) else host
    # Is it trusted here? The handshake as every outbound client makes it.
    authorized, error = True, ""
    sock = _connect(host, port, proxy, timeout)
    try:
        (context or outbound_ssl_context()).wrap_socket(sock, server_hostname=server_name).close()
    except ssl.SSLCertVerificationError as failure:
        authorized, error = False, network_proxy.verify_code_name(failure)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    # What it presents: read without checking it (only the handshake; nothing is sent).
    look = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    look.check_hostname = False
    look.verify_mode = ssl.CERT_NONE
    sock = _connect(host, port, proxy, timeout)
    try:
        with look.wrap_socket(sock, server_hostname=server_name) as secure:
            der = secure.getpeercert(binary_form=True)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    chain = [x509.load_der_x509_certificate(der)] if der else []
    return {"host": host, "port": port, "authorized": authorized, "error": error, "chain": chain}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------------------------------------------------


def _base_pems() -> list[str]:
    text = Path(certifi.where()).read_text(encoding="ascii", errors="ignore")
    return re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----\n?", text)


_base_cache: list[x509.Certificate] | None = None


def _base_certs() -> list[x509.Certificate]:
    global _base_cache
    if _base_cache is None:
        out = []
        for pem in _base_pems():
            try:
                out.append(x509.load_pem_x509_certificate(pem.encode("ascii")))
            except ValueError:
                continue
        _base_cache = out
    return _base_cache


class TrustStore:
    def __init__(self, directory: Path | None = None) -> None:
        from app.services.network_proxy import data_dir

        self.dir = (directory or data_dir()) / "trust"
        self.file = self.dir / "certificates.json"

    # -- the saved list ------------------------------------------------------------------------------------------------

    def saved(self) -> list[dict[str, Any]]:
        value = read_state(self.file, fallback=[], holds="the certificates an administrator added to trust")
        out = []
        for entry in value if isinstance(value, list) else []:
            try:
                x509.load_pem_x509_certificate(str(entry.get("pem", "")).encode("ascii"))
                out.append(entry)
            except (ValueError, AttributeError):
                continue
        return out

    def _save(self, entries: list[dict[str, Any]]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        write_state(self.file, entries)
        self.write_bundle()
        _context_cache.clear()

    def list(self) -> list[dict[str, Any]]:
        """The certificates an administrator added (or that were fetched to complete a chain), newest first."""

        out = []
        for entry in self.saved():
            cert = x509.load_pem_x509_certificate(entry["pem"].encode("ascii"))
            meta = {k: v for k, v in entry.items() if k != "pem"}
            out.append({**meta, **describe(cert), "expired": expired(cert)})
        return sorted(out, key=lambda e: str(e.get("addedAt") or ""), reverse=True)

    def extra_pems(self) -> list[str]:
        return [e["pem"] for e in self.saved() if not expired(x509.load_pem_x509_certificate(e["pem"].encode("ascii")))]

    def write_bundle(self) -> Path | None:
        """trust/bundle.pem: the public roots and the added ones, for clients that read SSL_CERT_FILE. None (and no
        file) when nothing was added."""

        bundle = self.dir / "bundle.pem"
        extra = self.extra_pems()
        if not extra:
            try:
                bundle.unlink()
            except FileNotFoundError:
                pass
            return None
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = bundle.with_name(f".bundle.{os.getpid()}.tmp")
        tmp.write_text("".join(_base_pems()) + "\n" + "\n".join(extra) + "\n", encoding="ascii")
        os.chmod(tmp, 0o644)
        os.replace(tmp, bundle)
        return bundle

    def trusted(self) -> list[x509.Certificate]:
        return [*_base_certs(), *(x509.load_pem_x509_certificate(p.encode("ascii")) for p in self.extra_pems())]

    def anchored(self, cert: x509.Certificate) -> bool:
        """Whether ``cert`` is trusted here, or issued by a trusted certificate."""

        fp = fingerprint256(cert)
        for t in self.trusted():
            if t.subject == cert.subject and fingerprint256(t) == fp:
                return True
            if t.subject == cert.issuer and issued_by(cert, t):
                return True
        return False

    def add(self, certs: list[x509.Certificate], *, source: str, host: str = "", by: str = "", now: dt.datetime | None = None) -> list[dict[str, Any]]:
        """Add certificate authorities. Only CA certificates that have not expired; a server's own certificate is refused
        with a reason."""

        entries = self.saved()
        known = {fingerprint256(x509.load_pem_x509_certificate(e["pem"].encode("ascii"))) for e in entries}
        base = {fingerprint256(c) for c in _base_certs()}
        added = []
        for cert in certs:
            if not is_ca(cert):
                raise TrustError(f'"{name_of(cert.subject)}" is a server\'s own certificate, not a certificate authority. Give the root certificate it was issued by ("{name_of(cert.issuer)}").')
            if expired(cert):
                raise TrustError(f'"{name_of(cert.subject)}" expired on {cert.not_valid_after_utc.date().isoformat()}.')
            fp = fingerprint256(cert)
            if fp in known or fp in base:
                continue
            known.add(fp)
            entries.append({"pem": to_pem(cert), "source": source, "host": host, "addedBy": by, "addedAt": (now or dt.datetime.now(dt.timezone.utc)).isoformat(timespec="milliseconds").replace("+00:00", "Z")})
            added.append(describe(cert))
        if len(entries) > MAX_SAVED:
            raise TrustError(f"At most {MAX_SAVED} certificates can be added. Remove ones no longer needed first.")
        if added:
            self._save(entries)
        return added

    def remove(self, fp: str) -> dict[str, Any] | None:
        entries = self.saved()
        for entry in entries:
            cert = x509.load_pem_x509_certificate(entry["pem"].encode("ascii"))
            if fingerprint256(cert) == fp:
                self._save([e for e in entries if e is not entry])
                return describe(cert)
        return None

    # -- completing a chain --------------------------------------------------------------------------------------------

    def complete(self, chain: list[x509.Certificate], *, fetch: Callable[[str], x509.Certificate] = fetch_issuer) -> dict[str, Any]:
        """Follow "CA Issuers" links up from the top of what a server presented, until a certificate trusted here, a
        self-signed root, or nothing more to follow."""

        fetched: list[x509.Certificate] = []
        top = chain[-1] if chain else None
        hop = 0
        while top is not None and hop < HOPS and not self.anchored(top) and not is_self_signed(top):
            following = None
            for url in ca_issuers_urls(top):
                try:
                    cert = fetch(url)
                except Exception:  # noqa: BLE001 - the next link
                    continue
                if issued_by(top, cert):
                    following = cert
                    break
            if following is None:
                break
            fetched.append(following)
            top = following
            hop += 1
        return {"fetched": fetched, "top": top, "anchored": bool(top is not None and self.anchored(top))}

    def diagnose(self, host: str, port: int = 443, *, repair: bool = True, fetch: Callable[[str], x509.Certificate] = fetch_issuer, look: Callable[..., dict[str, Any]] = inspect) -> dict[str, Any]:
        """Why host:port's certificate is not trusted, and what to do: "trusted", "repaired" (missing intermediates
        fetched and kept, now trusted), "needs-consent" (a private root to show an administrator), "needs-upload" (its
        root could not be found), or "other" (expired, wrong name: not a trust question)."""

        seen = look(host, port)
        if seen["authorized"]:
            return {"status": "trusted", "host": host, "port": port}
        presented = [describe(c) for c in seen["chain"]]
        if not is_untrusted_code(seen["error"]):
            return {"status": "other", "host": host, "port": port, "error": seen["error"], "presented": presented}
        done = self.complete(seen["chain"], fetch=fetch)
        if done["anchored"]:
            trusted = {fingerprint256(t) for t in self.trusted()}
            intermediates = [c for c in done["fetched"] if is_ca(c) and fingerprint256(c) not in trusted]
            if not repair or not intermediates:
                return {"status": "repairable", "host": host, "port": port, "error": seen["error"], "presented": presented, "intermediates": [describe(c) for c in intermediates]}
            added = self.add(intermediates, source="intermediate", host=host)
            again = look(host, port)
            if again["authorized"]:
                return {"status": "repaired", "host": host, "port": port, "added": added}
            for a in added:
                self.remove(a["fingerprint256"])
            return {"status": "needs-upload", "host": host, "port": port, "error": again["error"], "presented": presented, "issuer": name_of(seen["chain"][-1].issuer) if seen["chain"] else ""}
        root = next((c for c in [*seen["chain"], *done["fetched"]] if is_ca(c) and is_self_signed(c)), None)
        if root is not None and not expired(root):
            intermediates = [c for c in done["fetched"] if c is not root and is_ca(c)]
            return {"status": "needs-consent", "host": host, "port": port, "error": seen["error"], "presented": presented, "candidate": describe(root), "intermediates": [describe(c) for c in intermediates]}
        top = done["top"] or (seen["chain"][-1] if seen["chain"] else None)
        return {
            "status": "needs-upload",
            "host": host,
            "port": port,
            "error": seen["error"],
            "presented": presented,
            "issuer": name_of(top.issuer) if top is not None else "",
            "vendor": next((p["vendor"] for p in presented if p["vendor"]), ""),
        }

    def trust_presented(self, host: str, port: int, fp: str, *, by: str = "", fetch: Callable[[str], x509.Certificate] = fetch_issuer, look: Callable[..., dict[str, Any]] = inspect) -> dict[str, Any]:
        """An administrator trusts the root host:port's network presents, by its fingerprint: looked up again here
        (never taken from the browser), so only what was shown can be trusted. Kept only if host:port is then trusted."""

        found = self.diagnose(host, port, repair=True, fetch=fetch, look=look)
        if found["status"] in ("trusted", "repaired"):
            return {**found, "added": found.get("added", [])}
        if found["status"] != "needs-consent" or found["candidate"]["fingerprint256"] != fp:
            raise TrustError(f"{host} no longer presents that certificate. Try connecting again to see what it presents now.", 409)
        seen = look(host, port)
        done = self.complete(seen["chain"], fetch=fetch)
        wanted = {fp, *(i["fingerprint256"] for i in found["intermediates"])}
        certs = [c for c in [*seen["chain"], *done["fetched"]] if is_ca(c) and fingerprint256(c) in wanted]
        added = self.add(certs, source="detected", host=host, by=by)
        again = look(host, port)
        if not again["authorized"]:
            for a in added:
                self.remove(a["fingerprint256"])
            raise TrustError(f"{host} is still not trusted with that certificate ({again['error'] or 'unknown reason'}). Upload your company's root certificate instead.", 422)
        return {"status": "trusted", "host": host, "port": port, "added": added}

    def upload(self, data: bytes | str, *, by: str = "", chain: list[x509.Certificate] | None = None, host: str = "") -> list[dict[str, Any]]:
        """An administrator uploads certificate authorities (PEM bundle, or DER / base64 DER). With what a failing
        server presented (``chain``), only the certificates that complete its chain are kept, so a whole exported store
        (every certificate Windows trusts) can be given as it is."""

        certs = parse_certificates(data)
        if not certs:
            raise TrustError("That file holds no certificate. Upload a .pem, .crt or .cer file.")
        if chain:
            needed: list[x509.Certificate] = []
            top = chain[-1]
            hop = 0
            while top is not None and hop < HOPS and not self.anchored(top) and not is_self_signed(top):
                issuer = next((c for c in certs if is_ca(c) and issued_by(top, c) and c not in needed), None)
                if issuer is None:
                    break
                needed.append(issuer)
                top = issuer
                hop += 1
            if not needed:
                raise TrustError(f"None of the {len(certs)} certificate(s) in that file issued {host or 'the server'}'s certificate, which is issued by \"{name_of(chain[-1].issuer)}\". Upload the certificate with that name.")
            return self.add(needed, source="uploaded", host=host, by=by)
        trusted = {fingerprint256(t) for t in self.trusted()}
        usable = [c for c in certs if is_ca(c) and not expired(c) and fingerprint256(c) not in trusted]
        if not usable and any(not is_ca(c) for c in certs):
            return self.add([c for c in certs if not is_ca(c)][:1], source="uploaded", by=by)  # says why
        if len(usable) > MAX_SAVED - len(self.saved()):
            raise TrustError(f"That file holds {len(usable)} certificates not trusted yet. Upload it where the connection failed, so only the ones it needs are kept, or upload just your company's root certificate.")
        return self.add(usable, source="uploaded", by=by)


def store(directory: Path | None = None) -> TrustStore:
    return TrustStore(directory)


# ---------------------------------------------------------------------------------------------------------------------
# The TLS context every outbound client uses
# ---------------------------------------------------------------------------------------------------------------------

def add_trusted(context: Any, directory: Path | None = None) -> Any:
    """Add the certificates an administrator trusts to a TLS context made elsewhere (httpx's, which honours
    SSL_CERT_FILE): read from the saved list each time, so a change applies at once."""

    try:
        extra = TrustStore(directory).extra_pems()
    except Exception:  # noqa: BLE001 - a damaged list is reported on the page; the public roots still work
        extra = []
    if extra and hasattr(context, "load_verify_locations"):
        context.load_verify_locations(cadata="\n".join(extra))
    return context


_context_lock = threading.Lock()
_context_cache: dict[str, Any] = {}


def outbound_ssl_context(directory: Path | None = None) -> ssl.SSLContext:
    """Public roots (certifi, and the container's own store), plus the certificates an administrator added: read
    again whenever the saved list changes, so trusting one applies at once in every process."""

    trust = TrustStore(directory)
    try:
        stat = trust.file.stat()
        stamp = f"{trust.file}:{stat.st_mtime_ns}:{stat.st_size}"
    except FileNotFoundError:
        stamp = f"{trust.file}:none"
    with _context_lock:
        cached = _context_cache.get("context")
        if cached is not None and _context_cache.get("stamp") == stamp:
            return cached
        context = ssl.create_default_context(cafile=certifi.where())
        try:
            context.load_default_certs()
        except ssl.SSLError:
            pass
        try:
            extra = trust.extra_pems() if stamp.endswith(":none") is False else []
        except Exception:  # noqa: BLE001 - a damaged list is reported on the page; the public roots still work
            extra = []
        if extra:
            context.load_verify_locations(cadata="\n".join(extra))
        _context_cache["context"] = context
        _context_cache["stamp"] = stamp
        return context
