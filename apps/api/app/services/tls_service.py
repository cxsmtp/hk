"""Certificates for Hawk AI's HTTPS, ported from CxMissionZero's src/tls.js.

Certificates, in order of preference:
  1. TLS_CERT_FILE + TLS_KEY_FILE (PEM; the certificate file may carry the chain), with TLS_KEY_PASSPHRASE when the
     key is encrypted;
  2. TLS_PFX_FILE (+ TLS_PFX_PASSPHRASE): a .pfx / .p12 export, as Windows and many company CAs hand them out;
  3. otherwise a self-signed certificate made here and kept in <HAWK_DATA_DIR>/tls, for trying it out or a closed
     network. Browsers warn about it until it is trusted.

HTTPS (the switch): ``on`` = always HTTPS, with 1 or 2 when given, else 3 (deploy/compose.yaml's default, so a
production install never serves plain http by accident); ``off`` = plain http; ``both`` = both side by side; unset =
HTTPS only when a certificate option above is given.

Hawk terminates TLS in its front proxy (Caddy), not in the API: these files are checked here and handed to the proxy
(app/services/https_proxy.py).
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

#: The self-signed certificate is valid this long (about 13 months, as browsers allow at most 398 days).
SELF_SIGNED_DAYS = 397
#: ... and made again when it has fewer days left than this.
SELF_SIGNED_RENEW_DAYS = 30
SELF_SIGNED_ORGANISATION = "Hawk AI (self-signed)"

_TRUE = re.compile(r"^(1|true|yes|on)$", re.I)
_NAME = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


class CertificateError(ValueError):
    """A certificate, key or password that cannot be used, with a reason a person can act on."""


def is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(str(name).strip("[]"))
        return True
    except ValueError:
        return False


def _env(env: Mapping[str, str], name: str) -> str:
    return str(env.get(name) or "").strip()


def start_mode(env: Mapping[str, str] = os.environ) -> str:
    """How HTTPS starts when nothing was chosen on the Settings page yet: 'http', 'both' or 'https'."""

    mode = _env(env, "HTTPS").lower()
    if re.match(r"^(off|false|no|0)$", mode):
        return "http"
    # Let's Encrypt from the start: http and https side by side until its certificate is in (then HTTPS only).
    if _env(env, "LETSENCRYPT_DOMAIN"):
        return "both"
    if mode == "both":
        return "both"
    if re.match(r"^(on|true|yes|1)$", mode):
        return "https"
    if mode:
        raise CertificateError(f'HTTPS must be on, off or both, not "{env.get("HTTPS")}".')
    given = _env(env, "TLS_CERT_FILE") or _env(env, "TLS_KEY_FILE") or _env(env, "TLS_PFX_FILE") or _TRUE.match(_env(env, "TLS_SELF_SIGNED"))
    return "https" if given else "http"


@dataclass
class Pem:
    """A certificate chain (server certificate first) and its unencrypted private key, both PEM."""

    cert: bytes
    key: bytes
    kind: str = "pem"


@dataclass
class GivenCertificate:
    files: list[str]
    load: Callable[[], Pem] = field(repr=False)


def environment_certificate(env: Mapping[str, str] = os.environ) -> GivenCertificate | None:
    """The certificate the deployment names (TLS_CERT_FILE + TLS_KEY_FILE, or TLS_PFX_FILE), or None."""

    cert_file, key_file, pfx_file = _env(env, "TLS_CERT_FILE"), _env(env, "TLS_KEY_FILE"), _env(env, "TLS_PFX_FILE")
    if cert_file or key_file:
        if not cert_file or not key_file:
            raise CertificateError("HTTPS needs both TLS_CERT_FILE and TLS_KEY_FILE.")
        passphrase = str(env.get("TLS_KEY_PASSPHRASE") or "")

        def load_pem() -> Pem:
            cert = Path(cert_file).read_bytes()
            key = Path(key_file).read_bytes()
            return Pem(cert=cert, key=_unlocked_key(key, passphrase, "TLS_KEY_PASSPHRASE"))

        return GivenCertificate(files=[cert_file, key_file], load=load_pem)
    if pfx_file:
        passphrase = str(env.get("TLS_PFX_PASSPHRASE") or "")
        return GivenCertificate(files=[pfx_file], load=lambda: pfx_to_pem(Path(pfx_file).read_bytes(), passphrase))
    return None


def _unlocked_key(key_pem: bytes, passphrase: str, option: str) -> bytes:
    try:
        key = serialization.load_pem_private_key(key_pem, password=passphrase.encode() if passphrase else None)
    except (TypeError, ValueError) as error:
        if "encrypted" in str(error).lower() or "password" in str(error).lower() or "decrypt" in str(error).lower():
            raise CertificateError(f"The private key did not open: wrong {option}?") from error
        raise CertificateError(f"The private key could not be read: {error}") from error
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def pfx_to_pem(data: bytes, passphrase: str = "") -> Pem:
    """A .pfx / .p12 as PEM: the server certificate, the certificates that came with it, and the key."""

    try:
        key, cert, extra = pkcs12.load_key_and_certificates(data, passphrase.encode() if passphrase else None)
    except (TypeError, ValueError) as error:
        message = str(error).lower()
        if "password" in message or "mac" in message or "decrypt" in message or "invalid" in message:
            raise CertificateError("The .pfx file did not open: wrong TLS_PFX_PASSPHRASE?") from error
        raise CertificateError(f"The .pfx file could not be used: {error}") from error
    if key is None or cert is None:
        raise CertificateError("The .pfx file holds no certificate with its private key.")
    chain = cert.public_bytes(serialization.Encoding.PEM) + b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (extra or []))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return Pem(cert=chain, key=key_pem, kind="pfx")


def self_signed_names(env: Mapping[str, str] = os.environ, extra: list[str] | None = None) -> list[str]:
    """The names a self-signed certificate covers: this machine (localhost), HAWK_HOST, TLS_HOSTNAMES, the public
    address (PUBLIC_URL / WEB_ORIGIN) and ``extra``."""

    names = {"localhost", "127.0.0.1"}
    for name in [_env(env, "HAWK_HOST"), *str(env.get("TLS_HOSTNAMES") or "").split(","), *(extra or [])]:
        if str(name).strip():
            names.add(str(name).strip().lower())
    for option in ("PUBLIC_URL", "WEB_ORIGIN"):
        host = _url_host(_env(env, option))
        if host:
            names.add(host)
    return sorted(n for n in names if n)


def _url_host(url: str) -> str:
    match = re.match(r"^[a-z]+://(\[[^\]]+\]|[^/:?#]+)", url or "", re.I)
    return match.group(1).strip("[]").lower() if match else ""


def load_chain(cert_pem: bytes) -> list[x509.Certificate]:
    blocks = re.findall(rb"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", cert_pem)
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def public_key_matches(cert: x509.Certificate, key) -> bool:
    def raw(public) -> bytes:
        return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    try:
        return raw(cert.public_key()) == raw(key.public_key())
    except Exception:  # noqa: BLE001 - an unsupported key type is simply no match
        return False


def san_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [*san.get_values_for_type(x509.DNSName), *(str(ip) for ip in san.get_values_for_type(x509.IPAddress))]


def common_name(name: x509.Name) -> str:
    values = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if values:
        return str(values[0].value)
    return name.rfc4514_string().split(",")[0]


def describe_certificate(pem: Pem) -> str:
    """"CN=hawk.acme.io, valid until 2027-05-01 (DNS:hawk.acme.io)" for the log. Raises when the certificate and key
    cannot be served (no certificate, a key that does not open or does not belong to it)."""

    chain = load_chain(pem.cert)
    if not chain:
        raise CertificateError("The certificate file has no PEM certificate in it.")
    try:
        key = serialization.load_pem_private_key(pem.key, password=None)
    except (TypeError, ValueError) as error:
        raise CertificateError(f"The private key could not be read: {error}") from error
    leaf = chain[0]
    if not public_key_matches(leaf, key):
        raise CertificateError("The private key does not belong to the certificate.")
    names = ", ".join(f"{'IP' if is_ip(n) else 'DNS'}:{n}" for n in san_names(leaf))
    return f"{leaf.subject.rfc4514_string()}, valid until {leaf.not_valid_after_utc.date().isoformat()}{f' ({names})' if names else ''}"


# ---------------------------------------------------------------------------
# Self-signed certificate and certificate requests
# ---------------------------------------------------------------------------


def ensure_self_signed(directory: Path, names: list[str], now: dt.datetime | None = None) -> tuple[Path, Path]:
    """The self-signed certificate in ``directory``, made (again) when missing, expiring or for other names."""

    now = now or dt.datetime.now(dt.timezone.utc)
    cert_file, key_file = directory / "self-signed.crt", directory / "self-signed.key"
    try:
        existing = x509.load_pem_x509_certificate(cert_file.read_bytes())
        have = {n.lower() for n in san_names(existing)}
        covered = all((str(ipaddress.ip_address(n)) if is_ip(n) else n) in have for n in names)
        if covered and existing.not_valid_after_utc - now > dt.timedelta(days=SELF_SIGNED_RENEW_DAYS) and key_file.exists():
            return cert_file, key_file
    except (OSError, ValueError):
        pass
    cert, key = self_signed_certificate(names, now)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    from app.services.state_file import write_bytes_atomic

    write_bytes_atomic(key_file, key, mode=0o600)
    write_bytes_atomic(cert_file, cert, mode=0o644)
    return cert_file, key_file


def _general_names(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for name in names:
        if is_ip(name):
            out.append(x509.IPAddress(ipaddress.ip_address(name.strip("[]"))))
        else:
            out.append(x509.DNSName(name))
    return out


def _subject(cn: str, organisation: str = "") -> x509.Name:
    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if organisation:
        attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organisation))
    return x509.Name(attributes)


def make_certificate(
    *,
    subject: x509.Name,
    public_key,
    signer_key,
    issuer: x509.Name | None = None,
    names: list[str] | None = None,
    ca: bool = False,
    now: dt.datetime | None = None,
    days: int = SELF_SIGNED_DAYS,
    not_before: dt.datetime | None = None,
    server_auth: bool = True,
) -> bytes:
    """A certificate for ``public_key``, signed by ``signer_key`` on behalf of ``issuer`` (itself when left out:
    self-signed). ``ca`` makes a certificate authority. For self-signed certificates, and in tests for whole chains."""

    now = now or dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - dt.timedelta(seconds=60))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(_general_names(names)), critical=False)
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server_auth else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    cert = builder.sign(signer_key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def self_signed_certificate(names: list[str], now: dt.datetime | None = None) -> tuple[bytes, bytes]:
    """A self-signed ECDSA P-256 certificate for ``names`` (DNS names and IP addresses), valid for 397 days."""

    key = ec.generate_private_key(ec.SECP256R1())
    cn = next((n for n in names if not is_ip(n)), "localhost")
    cert = make_certificate(subject=_subject(cn, SELF_SIGNED_ORGANISATION), public_key=key.public_key(), signer_key=key, names=names, now=now)
    return cert, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@dataclass
class CertificateRequest:
    csr: str
    key: bytes
    names: list[str]


def certificate_request(names: list[str], organisation: str = "") -> CertificateRequest:
    """A certificate signing request (CSR) for IT or a certificate authority: a new RSA 2048 key (kept on this server)
    and a request for ``names``, the first one that is not an IP address as its common name."""

    clean: list[str] = []
    for name in names:
        value = str(name).strip().lower()
        if value and value not in clean:
            clean.append(value)
    if not clean:
        raise CertificateError("Give at least one name, e.g. hawk.company.com.")
    for name in clean:
        if not is_ip(name) and not _NAME.match(name):
            raise CertificateError(f'"{name}" is not a server name.')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cn = next((n for n in clean if not is_ip(n)), clean[0])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_subject(cn, organisation))
        .add_extension(x509.SubjectAlternativeName(_general_names(clean)), critical=False)
        .sign(key, hashes.SHA256())
    )
    return CertificateRequest(
        csr=csr.public_bytes(serialization.Encoding.PEM).decode(),
        key=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        names=clean,
    )
