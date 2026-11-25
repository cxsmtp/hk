"""HTTPS run from Settings → HTTPS (owners and admins), so moving a running Hawk AI from http to https needs no new
command and no restart, and never cuts anyone off. Ported from CxMissionZero's src/https-manager.js.

The modes:
  'http'   plain http only (a laptop, or behind a reverse proxy that does HTTPS);
  'both'   http and https side by side: try HTTPS, while http keeps working;
  'https'  https only: http answers with a redirect to https.

Certificates, in order of preference: one uploaded on the Settings page (PEM files or a .pfx, or the certificate IT
returned for a request made here); the one the deployment names (TLS_CERT_FILE / TLS_PFX_FILE); otherwise a
self-signed one. Every certificate is checked before use: it is served on a private loopback port and connected to,
the way a browser would, so a wrong key, a missing intermediate, a name people use that it does not cover, or an
expired date is reported before anyone meets it.

The choices live in <HAWK_DATA_DIR>/https.json (0600, with the certificate files in <HAWK_DATA_DIR>/tls); HTTPS=on|off|
both only sets the starting point until an owner or admin changes it here. Lost access?
``docker compose exec api python -m app.cli.https both`` puts http back next to https, within 5 seconds.

Hawk serves HTTPS from its front proxy: what is decided here is handed to it by app/services/https_proxy.py.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import logging
import os
import re
import socket
import ssl
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from app.services import tls_service
from app.services.https_proxy import ProxyConfig, trust_proxy_ranges
from app.services.state_file import read_state, write_bytes_atomic, write_state
from app.services.tls_service import CertificateError, Pem, common_name, is_ip, load_chain, public_key_matches, san_names

log = logging.getLogger("hawk.https")

MODES = ("http", "both", "https")
HSTS_AGES = (86_400, 604_800, 15_768_000, 31_536_000)  # a day, a week, half a year, a year
MIN_VERSIONS = ("TLSv1.2", "TLSv1.3")
MAX_FILE_BYTES = 256 * 1024
#: Expiry is flagged this many days ahead.
EXPIRY_WARNING_DAYS = 30
#: How often the saved choices (app.cli.https) and the certificate files are looked at.
WATCH_SECONDS = 5
FILE_MODE = 0o600
STATE_HOLDS = "the HTTPS choices: the mode, the TLS version and HSTS"
MODE_NAMES = {"http": "HTTP only", "both": "HTTP and HTTPS side by side", "https": "HTTPS only (http redirects to https)"}

#: OpenSSL's verification results, by number (what Node names them in CxMissionZero).
_VERIFY = {
    2: "UNABLE_TO_GET_ISSUER_CERT",
    9: "CERT_NOT_YET_VALID",
    10: "CERT_HAS_EXPIRED",
    18: "DEPTH_ZERO_SELF_SIGNED_CERT",
    19: "SELF_SIGNED_CERT_IN_CHAIN",
    20: "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    21: "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
}


class HttpsError(Exception):
    """A refusal the page can act on: ``status`` for the answer, and what to ask next (confirm, a password, open
    the page over https)."""

    def __init__(self, status: int, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.status = status
        self.extra = extra

    def body(self) -> dict[str, Any]:
        out: dict[str, Any] = {"error": str(self)}
        for key in ("report", "needsConfirm", "needsHttps", "needsPassphrase", "precheck"):
            if self.extra.get(key):
                out[key] = self.extra[key]
        return out


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _days_until(when: dt.datetime, now: dt.datetime) -> int:
    return int((when - now).total_seconds() // 86_400)


def fingerprint(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Reading what was uploaded
# ---------------------------------------------------------------------------


@dataclass
class _Upload:
    name: str
    cert: x509.Certificate | None = None
    pem: bytes = b""
    encrypted: bool = False


def _is_pkcs12(data: bytes) -> bool:
    """A PKCS#12 file starts with a DER SEQUENCE holding INTEGER 3 (its version)."""

    if len(data) < 6 or data[0] != 0x30:
        return False
    length_bytes = data[1] & 0x7F if data[1] & 0x80 else 0
    at = 2 + length_bytes
    return data[at : at + 3] == b"\x02\x01\x03"


def read_uploads(files: Any, passphrase: str = "") -> dict[str, Any]:
    """Sort uploaded files into certificates, private keys and a .pfx, whatever their names: PEM files (one or several
    blocks: server, chain, bundle, key), DER .cer / .crt files as Windows exports them, and .pfx / .p12 files."""

    certs: list[_Upload] = []
    keys: list[_Upload] = []
    notes: list[str] = []
    pfx: tuple[str, bytes] | None = None
    if not isinstance(files, list) or not files:
        raise HttpsError(400, "Choose the certificate files first.")
    if len(files) > 10:
        raise HttpsError(400, "At most 10 files at once.")
    for item in files:
        item = item if isinstance(item, dict) else {}
        name = str(item.get("name") or "file")[:120]
        try:
            data = base64.b64decode(str(item.get("data") or ""), validate=False)
        except (binascii.Error, ValueError):
            data = b""
        if not data:
            continue
        if len(data) > MAX_FILE_BYTES:
            raise HttpsError(400, f"{name} is larger than 256 KB, so it is not a certificate file.")
        text = data.decode("latin-1")
        if "-----BEGIN " in text:
            blocks = list(re.finditer(r"-----BEGIN ([A-Z0-9 ]+)-----[\s\S]+?-----END \1-----", text))
            if not blocks:
                notes.append(f"{name}: the file looks cut short (no complete BEGIN … END block).")
            for block in blocks:
                pem, label = block.group(0), block.group(1)
                if label in ("CERTIFICATE", "TRUSTED CERTIFICATE"):
                    try:
                        cert = x509.load_pem_x509_certificate(pem.replace("TRUSTED CERTIFICATE", "CERTIFICATE").encode("latin-1"))
                    except ValueError as error:
                        raise HttpsError(400, f"{name}: a certificate in it could not be read ({error}).") from error
                    certs.append(_Upload(name=name, cert=cert, pem=_pem(cert)))
                elif label.endswith("PRIVATE KEY"):
                    keys.append(_Upload(name=name, pem=pem.encode("latin-1"), encrypted=label.startswith("ENCRYPTED") or "Proc-Type: 4,ENCRYPTED" in pem))
                elif label.endswith("CERTIFICATE REQUEST"):
                    notes.append(f"{name} is a certificate request (CSR). That is what IT signs; upload the certificate they send back.")
                else:
                    notes.append(f'{name}: a "{label}" block is not needed and was left out.')
            continue
        try:
            cert = x509.load_der_x509_certificate(data)  # a binary (DER) .cer / .crt
            certs.append(_Upload(name=name, cert=cert, pem=_pem(cert)))
            continue
        except ValueError:
            pass
        if re.search(r"\.(pfx|p12)$", name, re.I) or _is_pkcs12(data):
            if pfx:
                raise HttpsError(400, "Upload one .pfx at a time.")
            pfx = (name, data)
            continue
        raise HttpsError(400, f"{name} is not a certificate, a private key or a .pfx file.")
    if pfx:
        pfx_name, pfx_data = pfx
        if certs or keys:
            notes.append(f"{pfx_name} already holds the certificate and its key; the other files were not needed.")
        try:
            pem = tls_service.pfx_to_pem(pfx_data, passphrase)
        except CertificateError as error:
            if "did not open" in str(error):
                raise HttpsError(
                    400,
                    f"{pfx_name} did not open with that password." if passphrase else f"{pfx_name} is protected by a password: enter it, then check again.",
                    needsPassphrase=True,
                ) from error
            raise HttpsError(400, f"{pfx_name} could not be used: {error}") from error
        return {"kind": "pfx", "name": pfx_name, "pem": pem, "notes": notes}
    return {"kind": "pem", "certs": certs, "keys": keys, "notes": notes}


def _open_key(entry: _Upload, passphrase: str):
    try:
        return serialization.load_pem_private_key(entry.pem, password=passphrase.encode() if passphrase else None)
    except (TypeError, ValueError) as error:
        message = str(error).lower()
        if entry.encrypted or "password" in message or "encrypted" in message or "decrypt" in message:
            raise HttpsError(
                400,
                f"The private key in {entry.name} did not open with that password." if passphrase else f"The private key in {entry.name} is protected by a password: enter it, then check again.",
                needsPassphrase=True,
            ) from error
        raise HttpsError(400, f"The private key in {entry.name} could not be read: {error}") from error


def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    if child.issuer != parent.subject:
        return False
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:  # noqa: BLE001 - not its issuer
        return False


def _self_issued(cert: x509.Certificate) -> bool:
    return _issued_by(cert, cert)


def assemble_pem(read: dict[str, Any], *, passphrase: str = "", request_key: bytes | None = None) -> dict[str, Any]:
    """The server certificate (the one the key belongs to), then the certificates that issued it, in order; a root at
    the top is kept apart (browsers have their own). Certificates that are not part of the chain are left out, and
    said so."""

    certs: list[_Upload] = read["certs"]
    keys: list[_Upload] = read["keys"]
    notes: list[str] = read["notes"]
    if not certs:
        raise HttpsError(400, "Only a private key was given: add the certificate (.crt, .cer or .pem)." if keys else "No certificate in these files.")
    opened = [(entry, _open_key(entry, passphrase), False) for entry in keys]
    if not opened and request_key:
        opened.append((_Upload(name="the request made here"), serialization.load_pem_private_key(request_key, password=None), True))
    if not opened:
        raise HttpsError(
            400,
            "The private key is missing. Add the .key file that belongs to this certificate, upload a .pfx that holds both, or create the request here first so the key is already on this server.",
        )
    leaf: _Upload | None = None
    key_used = None
    for entry, key, from_request in opened:
        leaf = next((c for c in certs if c.cert is not None and public_key_matches(c.cert, key)), None)
        if leaf:
            key_used = (entry, key, from_request)
            break
    if not leaf or key_used is None:
        if any(from_request for _, _, from_request in opened) and not keys:
            raise HttpsError(400, "This certificate was not made for the request created here. Add the private key it was made for, or send IT the request from this page.")
        raise HttpsError(400, "The private key does not belong to any of these certificates. They are probably from different requests: ask IT for the matching pair.")
    chain = [leaf]
    root: _Upload | None = None
    used = {id(leaf)}
    current = leaf
    while True:
        issuer = next((c for c in certs if id(c) not in used and c.cert is not None and current.cert is not None and _issued_by(current.cert, c.cert)), None)
        if issuer is None:
            break
        used.add(id(issuer))
        if issuer.cert is not None and _self_issued(issuer.cert):
            root = issuer
            break
        chain.append(issuer)
        current = issuer
    extra = len(certs) - len(used)
    if extra:
        notes.append(f"{extra} certificate{' was' if extra == 1 else 's were'} not part of this certificate's chain and {'was' if extra == 1 else 'were'} left out.")
    key_pem = key_used[1].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return {
        "pem": Pem(cert=b"".join(c.pem for c in chain), key=key_pem),
        "root": root.pem if root else b"",
        "fromRequest": bool(key_used[2]),
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Checking a certificate the way a browser would
# ---------------------------------------------------------------------------


def _public_roots() -> str | None:
    try:
        import certifi

        return certifi.where()
    except ImportError:  # pragma: no cover - certifi ships with the API
        return None


def _handshake(pem: Pem, *, servername: str | None, min_version: str, trust: list[bytes | str]) -> dict[str, Any]:
    """Serve ``pem`` on a private loopback port for a moment and connect to it: once to see it answer, then once per
    set of trusted roots in ``trust`` (a CA file path or PEM text), stopping at the first that verifies."""

    minimum = ssl.TLSVersion.TLSv1_3 if min_version == "TLSv1.3" else ssl.TLSVersion.TLSv1_2
    with tempfile.TemporaryDirectory(prefix="hawk-tls-") as tmp:
        cert_file, key_file = Path(tmp) / "server.crt", Path(tmp) / "server.key"
        cert_file.write_bytes(pem.cert)
        key_file.write_bytes(pem.key)
        os.chmod(key_file, 0o600)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = minimum
        # Served only to be looked at: a weak key is reported by the checks below, not refused by OpenSSL here.
        server_context.set_ciphers("DEFAULT:@SECLEVEL=0")
        try:
            server_context.load_cert_chain(str(cert_file), str(key_file))
        except ssl.SSLError as error:
            if "KEY_VALUES_MISMATCH" in str(error).upper() or "key values mismatch" in str(error).lower():
                raise HttpsError(400, "The private key does not belong to the certificate.") from error
            raise HttpsError(400, f"The certificate could not be served: {error}") from error
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        stop = threading.Event()

        def serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                conn.settimeout(5)
                try:
                    with server_context.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
                except (OSError, ssl.SSLError):
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        thread = threading.Thread(target=serve, name="hawk-tls-check", daemon=True)
        thread.start()
        sni = servername if servername and not is_ip(servername) else None

        def connect(verify: bytes | str | None) -> tuple[bool, int | None, str, str]:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = minimum
            context.check_hostname = False
            context.set_ciphers("DEFAULT:@SECLEVEL=0")
            if verify is None:
                context.verify_mode = ssl.CERT_NONE
            else:
                context.verify_mode = ssl.CERT_REQUIRED
                if isinstance(verify, bytes):
                    context.load_verify_locations(cadata=verify.decode("ascii", "ignore"))
                else:
                    context.load_verify_locations(cafile=verify)
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname=sni) as tls:
                        return True, None, "", str(tls.version() or "")
            except ssl.SSLCertVerificationError as error:
                return False, error.verify_code, str(error.verify_message or ""), ""
            except (OSError, ssl.SSLError) as error:
                raise HttpsError(400, f"The certificate could not be served: {error}") from error

        try:
            _, _, _, protocol = connect(None)
            result = {"authorized": False, "error": "", "protocol": protocol, "trusted_by": -1}
            for index, roots in enumerate(trust):
                ok, code, message, _ = connect(roots)
                if ok:
                    result.update(authorized=True, error="", trusted_by=index)
                    break
                if index == 0:
                    result["error"] = _VERIFY.get(code or -1, message or f"error {code}")
            return result
        finally:
            stop.set()
            listener.close()
            thread.join(timeout=2)


def _covered(cert_names: list[str], host: str) -> bool:
    host = host.lower().strip("[]")
    if is_ip(host):
        import ipaddress

        try:
            wanted = ipaddress.ip_address(host)
            return any(is_ip(n) and ipaddress.ip_address(n) == wanted for n in cert_names)
        except ValueError:
            return False
    for name in (n.lower() for n in cert_names if not is_ip(n)):
        if name == host:
            return True
        if name.startswith("*.") and host.endswith(name[1:]) and "." not in host[: -len(name) + 1]:
            return True
    return False


def _key_type(public) -> tuple[str, bool]:
    """('RSA 2048-bit', too weak?)."""

    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519

    if isinstance(public, rsa.RSAPublicKey):
        return f"RSA {public.key_size}-bit", public.key_size < 2048
    if isinstance(public, ec.EllipticCurvePublicKey):
        curve = {"secp256r1": "prime256v1"}.get(public.curve.name, public.curve.name)
        return f"EC {curve}", False
    if isinstance(public, ed25519.Ed25519PublicKey):
        return "ED25519", False
    if isinstance(public, ed448.Ed448PublicKey):
        return "ED448", False
    return type(public).__name__.upper(), False


def inspect_certificate(
    pem: Pem,
    *,
    hosts: list[str] | None = None,
    root: bytes = b"",
    min_version: str = "TLSv1.2",
    kind: str = "pem",
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Everything worth knowing before putting a certificate to use: what it is, and a list of checks (ok / warn /
    error). ``hosts`` are the names people use to reach this server."""

    now = now or _now()
    hosts = hosts or []
    chain = load_chain(pem.cert)
    if not chain:
        raise HttpsError(400, "The certificate could not be read back.")
    leaf = chain[0]
    try:
        key = serialization.load_pem_private_key(pem.key, password=None)
    except (TypeError, ValueError) as error:
        raise HttpsError(400, f"The certificate could not be served: {error}") from error
    if not public_key_matches(leaf, key):
        raise HttpsError(400, "The private key does not belong to the certificate.")
    trust_sets: list[bytes | str] = []
    roots = _public_roots()
    if roots:
        trust_sets.append(roots)
    if root:
        trust_sets.append(root)
    result = _handshake(pem, servername=next((h for h in hosts if not is_ip(h)), None), min_version=min_version, trust=trust_sets)

    checks: list[dict[str, str]] = []

    def add(check_id: str, level: str, title: str, detail: str = "") -> None:
        checks.append({"id": check_id, "level": level, "title": title, "detail": detail})

    add("key", "ok", "The private key belongs to the certificate", f"Answers HTTPS with {result['protocol']}.")

    # Dates
    valid_from, valid_to = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    days = _days_until(valid_to, now)
    if valid_from > now:
        add("dates", "error", f"Not valid until {valid_from.date().isoformat()}", "Browsers refuse it until then.")
    elif days < 0:
        add("dates", "error", f"Expired on {valid_to.date().isoformat()}", "Ask IT for a renewed certificate.")
    elif days < EXPIRY_WARNING_DAYS:
        add("dates", "warn", f"Expires in {days} day{'' if days == 1 else 's'}", "Ask IT for the renewal now; upload it here when it comes, with no restart.")
    else:
        add("dates", "ok", f"Valid until {valid_to.date().isoformat()} ({days} days)")

    # Names
    names = san_names(leaf)
    wanted = list(dict.fromkeys(str(h).strip().lower() for h in hosts if str(h).strip()))
    missing = [h for h in wanted if not _covered(names, h)]
    if not names:
        add("names", "error", "It names no server (no Subject Alternative Name)", "Browsers ignore the old common name. Ask IT to put the server name into the Subject Alternative Name.")
    elif not wanted:
        add("names", "ok", f"Covers {', '.join(names)}")
    elif not missing:
        add("names", "ok", f"Covers {', '.join(wanted)}", f"All names in it: {', '.join(names)}.")
    else:
        local = all(re.match(r"^(localhost|127\.0\.0\.1|::1)$", h) for h in missing)
        add(
            "names",
            "warn",
            f"Does not cover {', '.join(missing)}",
            f"Fine: that is this machine's own name. Use {names[0]} to reach it with no warning."
            if local
            else f"Browsers warn at an address that is not in it. It covers: {', '.join(names)}. Use one of those names, or ask IT to add the others.",
        )

    # Who vouches for it
    top = chain[-1]
    self_signed = len(chain) == 1 and _self_issued(leaf)
    issuer = common_name(leaf.issuer)
    error = result["error"]
    if error == "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" and len(chain) == 1:
        # Only the server certificate, and nothing here knows its issuer: what Node (CxMissionZero) reports as
        # UNABLE_TO_VERIFY_LEAF_SIGNATURE ("unable to verify the first certificate").
        error = "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
    if self_signed or error == "DEPTH_ZERO_SELF_SIGNED_CERT":
        trust = "self-signed"
        add("trust", "warn", "Self-signed: nobody vouches for it", "Every browser warns until it is trusted on that machine. Fine to try HTTPS out; for everyone, use a certificate from IT.")
    elif result["authorized"]:
        trust = "public" if result["trusted_by"] == 0 and roots else "company"
        if trust == "public":
            add("trust", "ok", f"Trusted everywhere: issued by {issuer}")
        else:
            root_subject = common_name(x509.load_pem_x509_certificate(root).subject) if root else common_name(top.issuer)
            add("trust", "ok", f"Issued by your certificate authority {root_subject}", "Trusted on machines that trust that authority, usually every company machine. The browser check below confirms it for yours.")
    elif error in ("CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID"):
        trust = "dates"
    elif error == "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
        trust = "incomplete"
        add(
            "trust",
            "warn",
            f"Issued by {issuer}, but its chain is missing",
            'Only the server certificate was given. Add the intermediate certificates IT sent with it (often a "chain" or "bundle" file); without them some machines cannot verify it. Company machines may already have them.',
        )
    elif re.search(r"UNABLE_TO_GET_ISSUER_CERT|SELF_SIGNED_CERT_IN_CHAIN", error):
        trust = "company"
        add(
            "trust",
            "ok",
            f"Issued by your certificate authority {common_name(top.issuer) or common_name(top.subject)}",
            "A private (company) authority: trusted on machines that trust it, usually every company machine. The browser check below confirms it for yours.",
        )
    else:
        trust = "unknown"
        add("trust", "warn", f"Could not be verified ({error})", "Browsers may warn about it.")

    # Key strength and purpose
    key_type, weak = _key_type(leaf.public_key())
    if weak:
        add("strength", "error", f"{key_type} key: too weak", "Browsers refuse RSA keys under 2048 bits. Ask IT for a new certificate with a 2048-bit (or larger) key.")
    else:
        add("strength", "ok", f"{key_type} key")
    try:
        usage = list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        usage = []
    if usage and ExtendedKeyUsageOID.SERVER_AUTH not in usage and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in usage:
        add("usage", "error", "Not a web server certificate", "Its usage leaves out server authentication, so browsers refuse it. Ask IT for a server (web) certificate.")
    try:
        is_ca = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    if is_ca:
        add("usage", "warn", "This is a certificate authority, not a server certificate", "Check you picked the server certificate, not the CA file.")

    return {
        "kind": kind,
        "usable": not any(c["level"] == "error" for c in checks),
        "trust": trust,
        "summary": {
            "subject": common_name(leaf.subject),
            "names": names,
            "issuer": issuer,
            "validFrom": _iso(valid_from),
            "validTo": _iso(valid_to),
            "daysLeft": days,
            "selfSigned": self_signed,
            "keyType": key_type,
            "fingerprint": fingerprint(leaf),
            "chain": [{"subject": common_name(c.subject), "issuer": common_name(c.issuer), "validTo": c.not_valid_after_utc.date().isoformat()} for c in chain],
        },
        "checks": checks,
    }


# ---------------------------------------------------------------------------
# The manager
# ---------------------------------------------------------------------------


@dataclass
class _Active:
    source: str  # uploaded | environment | self-signed
    files: list[str]
    load: Callable[[], Pem]
    self_signed: bool
    root: bytes = b""


class HttpsManager:
    def __init__(self, *, data_dir: str | Path, env: Mapping[str, str] | None = None, proxy: ProxyConfig | None = None) -> None:
        self.data_dir = Path(data_dir)
        self.dir = self.data_dir / "tls"
        self.file = self.data_dir / "https.json"
        self.env = dict(os.environ if env is None else env)
        self.proxy = proxy if proxy is not None else ProxyConfig.from_env(self.env)
        self._lock = threading.RLock()
        self._stamp = ""
        self._cert_stamp = ""
        self._report: tuple[str, dict[str, Any]] | None = None
        self._timer: threading.Thread | None = None
        self._stop = threading.Event()
        self.state = self._read()
        self.active = self._resolve()

    # --- state -------------------------------------------------------------

    def _defaults(self) -> dict[str, Any]:
        given = bool(tls_service.environment_certificate(self.env))
        return {
            "mode": tls_service.start_mode(self.env),
            "minVersion": "TLSv1.2",
            # A certificate given to the deployment keeps HSTS on (as in CxMissionZero); one chosen here starts without it.
            "hsts": {"enabled": given, "maxAge": 31_536_000 if given else 86_400, "includeSubDomains": given},
            "selfSignedNames": [],
            "uploaded": None,
            "previous": None,
            "request": None,
            "lastBrowserCheck": None,
            "changedAt": "",
            "changedBy": "",
        }

    def _file_stamp(self) -> str:
        try:
            stat = self.file.stat()
        except OSError:
            return ""
        return f"{stat.st_mtime_ns}:{stat.st_size}"

    def _read(self) -> dict[str, Any]:
        defaults = self._defaults()
        self._stamp = self._file_stamp()
        # No file yet: nothing chosen on the Settings page. A damaged file is never "nothing chosen": taken for that,
        # a server set to HTTPS only could come back answering plain http (app/services/state_file.py).
        raw = read_state(self.file, fallback=None, holds=STATE_HOLDS)
        if not isinstance(raw, dict):
            return {**defaults, "saved": False}
        return {
            **defaults,
            **raw,
            "mode": raw.get("mode") if raw.get("mode") in MODES else defaults["mode"],
            "minVersion": raw.get("minVersion") if raw.get("minVersion") in MIN_VERSIONS else "TLSv1.2",
            "hsts": {**defaults["hsts"], **(raw.get("hsts") or {})},
            "saved": True,
        }

    def _save(self, by: str | None = None) -> None:
        self.state = {**self.state, "changedAt": _iso(_now()), "changedBy": by if by is not None else self.state.get("changedBy", ""), "saved": True}
        stored = {k: v for k, v in self.state.items() if k != "saved"}
        write_state(self.file, stored, mode=FILE_MODE)
        self._stamp = self._file_stamp()

    @property
    def mode(self) -> str:
        return str(self.state["mode"])

    # --- certificates ------------------------------------------------------

    def _uploaded_dir(self, which: str = "uploaded") -> Path:
        return self.dir / which

    def _resolve(self) -> _Active | None:
        up = self.state.get("uploaded")
        if up:
            directory = self._uploaded_dir()
            cert, key = directory / "server.crt", directory / "server.key"
            if cert.exists() and key.exists():
                root_file = directory / "root.crt"
                return _Active(
                    source="uploaded",
                    files=[str(cert), str(key)],
                    load=lambda: Pem(cert=cert.read_bytes(), key=key.read_bytes(), kind=str(up.get("kind") or "pem")),
                    self_signed=False,
                    root=root_file.read_bytes() if root_file.exists() else b"",
                )
            log.warning("! [https] The uploaded certificate files are missing; using the next certificate available.")
        given = tls_service.environment_certificate(self.env)
        if given:
            return _Active(source="environment", files=given.files, load=given.load, self_signed=False)
        return None

    def _certificate(self, make: bool | None = None) -> _Active | None:
        """The certificate in use, made (self-signed) when there is none and HTTPS is on."""

        if self.active:
            return self.active
        if make is None:
            make = self.mode != "http"
        if not make:
            return None
        names = tls_service.self_signed_names(self.env, self.state.get("selfSignedNames") or [])
        cert, key = tls_service.ensure_self_signed(self.dir, names)
        self.active = _Active(
            source="self-signed",
            files=[str(cert), str(key)],
            load=lambda: Pem(cert=cert.read_bytes(), key=key.read_bytes()),
            self_signed=True,
        )
        return self.active

    def served_names(self) -> list[str]:
        active = self._certificate(make=False)
        if not active:
            return []
        try:
            chain = load_chain(active.load().cert)
        except (OSError, CertificateError, ValueError):
            return []
        return [n.lower() for n in san_names(chain[0])] if chain else []

    @property
    def self_signed(self) -> bool:
        active = self._certificate(make=False)
        return bool(active.self_signed) if active else self.mode != "http"

    def context(self) -> Pem | None:
        """The certificate the proxy serves, or None when HTTPS is off and nothing is set up."""

        active = self._certificate()
        return active.load() if active else None

    def check(self) -> None:
        """At start: fail with the reason when the certificate in use cannot be served (a wrong file, key or
        password). The proxy then serves nothing, never plain http instead."""

        with self._lock:
            try:
                self._apply()
            except Exception as error:
                self.proxy.write_stopped(str(error))
                raise

    def _certificate_stamp(self) -> str:
        active = self.active
        if not active:
            return ""
        parts = []
        for file in active.files:
            try:
                parts.append(str(os.stat(file).st_mtime_ns))
            except OSError:
                parts.append("0")
        return "|".join(parts)

    def _apply(self) -> None:
        """Check the certificate in use and hand it to the proxy."""

        pem = self.context() if self.mode != "http" else None
        self._report = None
        self._cert_stamp = self._certificate_stamp()
        fp = ""
        if pem is not None:
            tls_service.describe_certificate(pem)  # raises, with a readable reason, before anything is replaced
            chain = load_chain(pem.cert)
            fp = fingerprint(chain[0]).replace(":", "").lower()
        self.proxy.write(
            mode=self.mode,
            pem=pem,
            fingerprint=fp,
            min_version=self.state["minVersion"],
            hsts=self.hsts_header(),
            trusted=trust_proxy_ranges(self.env.get("TRUST_PROXY"), self.mode != "http"),
            https_port=int(str(self.env.get("HTTPS_PUBLIC_PORT") or "443").strip() or 443),
            note=f"mode {self.mode}; certificate {self.active.source if self.active and pem is not None else 'none'} {fp[:16]}",
        )

    def active_report(self, hosts: list[str] | None = None) -> dict[str, Any] | None:
        """The active certificate, checked (cached until it or the names change)."""

        hosts = hosts or []
        active = self._certificate(make=False)
        if not active:
            return None
        key = f"{self._cert_stamp}|{self.state['minVersion']}|{','.join(hosts)}|{active.source}"
        if self._report and self._report[0] == key:
            return self._report[1]
        try:
            pem = active.load()
            value = {"source": active.source, **inspect_certificate(pem, hosts=hosts, root=active.root, min_version=self.state["minVersion"], kind=pem.kind)}
        except (HttpsError, CertificateError, OSError, ValueError) as error:
            value = {"source": active.source, "usable": False, "error": str(error), "checks": [{"id": "key", "level": "error", "title": str(error), "detail": ""}]}
        self._report = (key, value)
        return value

    def _prepare(self, files: Any, passphrase: str) -> dict[str, Any]:
        read = read_uploads(files, passphrase)
        if read["kind"] == "pfx":
            return {"kind": "pfx", "pem": read["pem"], "root": b"", "notes": read["notes"], "fromRequest": False}
        request_key_file = self.dir / "request.key"
        request_key = request_key_file.read_bytes() if request_key_file.exists() else None
        assembled = assemble_pem(read, passphrase=passphrase, request_key=request_key)
        return {"kind": "pem", **assembled}

    def inspect(self, *, files: Any, passphrase: str = "", hosts: list[str] | None = None) -> dict[str, Any]:
        """Check uploaded files without changing anything."""

        prepared = self._prepare(files, passphrase)
        report = inspect_certificate(prepared["pem"], hosts=hosts, root=prepared["root"], min_version=self.state["minVersion"], kind=prepared["kind"])
        return {**report, "notes": prepared["notes"], "fromRequest": prepared["fromRequest"]}

    def install(self, *, files: Any, passphrase: str = "", hosts: list[str] | None = None, confirm: bool = False, by: str = "") -> dict[str, Any]:
        """Put an uploaded certificate to use, at once, with no restart. The one it replaces is kept, so "Put the
        previous one back" undoes it. With HTTPS only, a certificate with warnings needs ``confirm``."""

        prepared = self._prepare(files, passphrase)
        report = inspect_certificate(prepared["pem"], hosts=hosts, root=prepared["root"], min_version=self.state["minVersion"], kind=prepared["kind"])
        report["notes"] = prepared["notes"]
        if not report["usable"]:
            first = next((c for c in report["checks"] if c["level"] == "error"), None)
            raise HttpsError(400, first["title"] if first else "This certificate cannot be used.", report=report)
        with self._lock:
            if self.mode == "https" and not confirm and any(c["level"] == "warn" for c in report["checks"]):
                raise HttpsError(409, "Everyone uses HTTPS now, and this certificate has warnings: confirm to use it anyway.", report=report, needsConfirm=True)
            staging = self._uploaded_dir("staging")
            _remove_tree(staging)
            staging.mkdir(parents=True, mode=0o700)
            write_bytes_atomic(staging / "server.crt", prepared["pem"].cert, mode=0o644)
            write_bytes_atomic(staging / "server.key", prepared["pem"].key, mode=FILE_MODE)
            if prepared["root"]:
                write_bytes_atomic(staging / "root.crt", prepared["root"], mode=0o644)
            previous = self._uploaded_dir("previous")
            _remove_tree(previous)
            if self._uploaded_dir().exists():
                os.replace(self._uploaded_dir(), previous)
            os.replace(staging, self._uploaded_dir())
            was = self.state.get("uploaded")
            self.state["previous"] = dict(was) if was else None
            summary = report["summary"]
            self.state["uploaded"] = {
                "kind": prepared["kind"],
                "at": _iso(_now()),
                "by": by,
                "subject": summary["subject"],
                "names": list(summary.get("names") or [])[:100],
                "validTo": summary["validTo"],
                "fingerprint": summary["fingerprint"],
            }
            if prepared["fromRequest"]:
                for name in ("request.key", "request.csr"):
                    try:
                        (self.dir / name).unlink()
                    except FileNotFoundError:
                        pass
                self.state["request"] = None
            self.active = self._resolve()
            self._apply()
            self._save(by)
        return report

    def restore_previous(self, *, by: str = "") -> None:
        """Swap the certificate in use with the one it replaced."""

        with self._lock:
            previous = self.state.get("previous")
            previous_dir = self._uploaded_dir("previous")
            if not previous or not previous_dir.exists():
                raise HttpsError(400, "There is no previous certificate to put back.")
            valid_to = _parse_iso(previous.get("validTo"))
            if valid_to and valid_to < _now():
                raise HttpsError(400, "The previous certificate has expired.")
            swap = self._uploaded_dir("swap")
            _remove_tree(swap)
            if self._uploaded_dir().exists():
                os.replace(self._uploaded_dir(), swap)
            os.replace(previous_dir, self._uploaded_dir())
            if swap.exists():
                os.replace(swap, previous_dir)
            self.state["previous"] = self.state.get("uploaded")
            self.state["uploaded"] = previous
            self.active = self._resolve()
            self._apply()
            self._save(by)

    def remove_uploaded(self, *, confirm: bool = False, by: str = "") -> str:
        """Stop using the uploaded certificate: back to the deployment's, or a self-signed one."""

        with self._lock:
            if not self.state.get("uploaded"):
                raise HttpsError(400, "No certificate was uploaded here.")
            fallback = "environment" if tls_service.environment_certificate(self.env) else "self-signed"
            if self.mode == "https" and fallback == "self-signed" and not confirm:
                raise HttpsError(409, "Everyone uses HTTPS now: without this certificate a self-signed one is used and every browser warns. Confirm to go ahead.", needsConfirm=True)
            previous = self._uploaded_dir("previous")
            _remove_tree(previous)
            os.replace(self._uploaded_dir(), previous)
            self.state["previous"] = self.state.get("uploaded")
            self.state["uploaded"] = None
            self.active = self._resolve()
            self._apply()
            self._save(by)
            return fallback

    def self_sign(self, *, names: list[str] | None = None, by: str = "") -> None:
        """A new self-signed certificate covering ``names`` too (used while no other certificate is set)."""

        clean = list(dict.fromkeys(str(n).strip().lower() for n in (names or []) if re.match(r"^[a-z0-9.:*-]{1,253}$", str(n).strip().lower())))[:20]
        with self._lock:
            self.state["selfSignedNames"] = clean
            try:
                (self.dir / "self-signed.crt").unlink()
            except FileNotFoundError:
                pass
            if not self.state.get("uploaded") and not tls_service.environment_certificate(self.env):
                self.active = None
            self._certificate(make=True)
            self._apply()
            self._save(by)

    def create_request(self, *, names: list[str] | None = None, organisation: str = "", by: str = "") -> str:
        """A certificate request for IT; its key stays here, and is paired with the certificate when it comes back."""

        try:
            made = tls_service.certificate_request(list(names or []), str(organisation)[:64])
        except CertificateError as error:
            raise HttpsError(400, str(error)) from error
        with self._lock:
            write_bytes_atomic(self.dir / "request.key", made.key, mode=FILE_MODE)
            write_bytes_atomic(self.dir / "request.csr", made.csr.encode(), mode=0o644)
            self.state["request"] = {"names": made.names, "organization": str(organisation)[:64], "at": _iso(_now()), "by": by}
            self._save(by)
        return made.csr

    def request_csr(self) -> str:
        try:
            return (self.dir / "request.csr").read_text()
        except OSError:
            return ""

    # --- modes and hardening ----------------------------------------------

    def set_mode(self, mode: str, *, secure: bool = False, confirm: bool = False, system: bool = False, by: str = "") -> str:
        """``secure``: the request asking for it arrived over HTTPS. Switching to HTTPS only needs that: it shows
        HTTPS works from the admin's own browser before http goes away."""

        if mode not in MODES:
            raise HttpsError(400, f'Unknown mode "{mode}".')
        with self._lock:
            current = self.mode
            if mode == current:
                return mode
            if mode == "https":
                # ``system``: the server itself, with a certificate browsers trust (LETSENCRYPT_DOMAIN), needs no browser to prove it.
                if not secure and not system:
                    raise HttpsError(409, "Open this page over HTTPS and switch there: that proves HTTPS works from your browser before http goes away.", needsHttps=True)
                active = self._certificate(make=True)
                if active and active.self_signed and not confirm:
                    raise HttpsError(409, "The certificate is self-signed: after the switch every browser warns until it trusts it. Confirm to go ahead, or upload your certificate first.", needsConfirm=True)
            if mode == "http" and current == "https":
                if self.state["hsts"].get("enabled"):
                    raise HttpsError(409, "HSTS is on: browsers that saw it refuse plain http for a while. Turn HSTS off first, then go back to HTTP + HTTPS.")
                if not confirm:
                    raise HttpsError(409, "This turns HTTPS off for everyone. Confirm to go ahead.", needsConfirm=True)
            self.state["mode"] = mode
            if mode != "http":
                self._certificate(make=True)
            self._apply()
            self._save(by)
            return mode

    def set_hardening(self, *, hsts: dict[str, Any] | None = None, min_version: str | None = None, by: str = "") -> None:
        with self._lock:
            if min_version is not None:
                if min_version not in MIN_VERSIONS:
                    raise HttpsError(400, "The lowest TLS version is TLSv1.2 or TLSv1.3.")
                self.state["minVersion"] = min_version
            if hsts is not None:
                following = {**self.state["hsts"], **hsts}
                following["enabled"] = bool(following.get("enabled"))
                following["includeSubDomains"] = bool(following.get("includeSubDomains"))
                try:
                    age = int(following.get("maxAge"))
                except (TypeError, ValueError):
                    age = 0
                following["maxAge"] = age if age in HSTS_AGES else 86_400
                if following["enabled"] and self.mode != "https":
                    raise HttpsError(409, "Turn on HSTS after switching to HTTPS only.")
                active = self._certificate(make=True)
                if following["enabled"] and active and active.self_signed:
                    raise HttpsError(409, "Not with a self-signed certificate: browsers would refuse the site outright instead of warning. Upload your certificate first.")
                self.state["hsts"] = following
            self._apply()
            self._save(by)

    def hsts_header(self) -> str:
        """The Strict-Transport-Security header for responses over HTTPS, or ''. Never with a self-signed certificate."""

        hsts = self.state["hsts"]
        if not hsts.get("enabled") or self.mode != "https" or self.self_signed:
            return ""
        return f"max-age={hsts['maxAge']}{'; includeSubDomains' if hsts.get('includeSubDomains') else ''}"

    def record_browser_check(self, *, ok: Any, url: Any, by: str) -> None:
        with self._lock:
            self.state["lastBrowserCheck"] = {"ok": bool(ok), "url": str(url or "")[:300], "by": by, "at": _iso(_now())}
            self._save()

    def status(self, hosts: list[str] | None = None) -> dict[str, Any]:
        """What the Settings page shows (no passphrase, no key)."""

        s = self.state
        uploaded, previous, request = s.get("uploaded"), s.get("previous"), s.get("request")
        certificate = self.active_report(hosts or [])
        expiring = bool(certificate and certificate.get("summary") and certificate["summary"]["daysLeft"] < EXPIRY_WARNING_DAYS)
        return {
            "mode": s["mode"],
            "startMode": tls_service.start_mode(self.env),
            "chosenHere": bool(s.get("saved")),
            "minVersion": s["minVersion"],
            "hsts": s["hsts"],
            "hstsActive": bool(self.hsts_header()),
            "hstsAges": list(HSTS_AGES),
            "selfSignedNames": s.get("selfSignedNames") or [],
            "environmentCertificate": bool(tls_service.environment_certificate(self.env)),
            "uploaded": {k: uploaded.get(k) for k in ("kind", "at", "by", "subject", "validTo")} if uploaded else None,
            "previous": {k: previous.get(k) for k in ("subject", "validTo", "at")} if previous and self._uploaded_dir("previous").exists() else None,
            "request": {**request, "available": (self.dir / "request.csr").exists()} if request else None,
            "lastBrowserCheck": s.get("lastBrowserCheck"),
            "changedAt": s.get("changedAt") or "",
            "changedBy": s.get("changedBy") or "",
            "certificate": certificate,
            "expiring": expiring,
            "proxy": self.proxy.enabled,
        }

    # --- watching -----------------------------------------------------------

    def poll(self) -> str:
        """One look: https.json changed by app.cli.https (the way back in when the page cannot be reached), or the
        certificate files changed (a renewal, no restart needed). Returns what happened ('' for nothing)."""

        with self._lock:
            try:
                if self._file_stamp() != self._stamp:
                    try:
                        self.state = self._read()
                    except Exception as error:  # noqa: BLE001 - the choices in use stay as they are
                        log.warning("! [https] https.json changed outside this page and cannot be used (the choices in use are kept): %s", error)
                        return "unreadable"
                    self.active = self._resolve()
                    self._apply()
                    log.warning("[https] Settings changed outside this page: %s.", self.mode)
                    return "settings"
                if self.active and self._certificate_stamp() != self._cert_stamp:
                    self._apply()
                    log.warning("[https] Certificate files changed: the new certificate is in use.")
                    return "certificate"
            except Exception as error:  # noqa: BLE001 - the proxy keeps the certificate it has
                self._cert_stamp = self._certificate_stamp()
                log.warning("! [https] The changed certificate could not be used (still serving the previous one): %s", error)
                return "failed"
        return ""

    def watch(self, interval: float = WATCH_SECONDS) -> None:
        if self._timer and self._timer.is_alive():
            return
        self._stop.clear()

        def loop() -> None:
            while not self._stop.wait(interval):
                self.poll()

        self._timer = threading.Thread(target=loop, name="hawk-https-watch", daemon=True)
        self._timer.start()

    def stop(self) -> None:
        self._stop.set()

    def describe(self) -> dict[str, Any]:
        """For the log at start: what is served, with which certificate."""

        active = self._certificate(make=False)
        digest = hashlib.sha256("|".join(active.files).encode()).hexdigest()[:8] if active else ""
        return {"mode": self.mode, "source": active.source if active else "none", "selfSigned": bool(active and active.self_signed), "fingerprint": digest}


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def set_mode_offline(data_dir: str | Path, mode: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Read the saved choices and change them, for app.cli.https (the server picks it up within seconds). Returns the
    choices (before, after)."""

    if mode not in MODES:
        raise ValueError(f"Use one of: {', '.join(MODES)}.")
    file = Path(data_dir) / "https.json"
    # A damaged https.json is not taken for an empty one here either: the last good copy, or a refusal that says what to do.
    before = read_state(file, fallback={}, holds=STATE_HOLDS)
    state = {**before, "mode": mode, "changedAt": _iso(_now()), "changedBy": "app.cli.https"}
    if mode != "https" and state.get("hsts"):
        state["hsts"] = {**state["hsts"], "enabled": False}
    elif mode != "https":
        # Not chosen on the page yet: HSTS is off too (a certificate given to the deployment turns it on by default).
        state["hsts"] = {"enabled": False, "maxAge": 86_400, "includeSubDomains": False}
    write_state(file, state, mode=FILE_MODE)
    return before, state


__all__ = [
    "EXPIRY_WARNING_DAYS",
    "HSTS_AGES",
    "HttpsError",
    "HttpsManager",
    "MODES",
    "MODE_NAMES",
    "assemble_pem",
    "inspect_certificate",
    "read_uploads",
    "set_mode_offline",
]
