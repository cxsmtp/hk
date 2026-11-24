"""Local certificate authority for TLS interception.

Generates a CA (to be pushed to the fleet trust store via MDM) and mints per-host
leaf certificates on demand, signed by that CA, so the proxy can terminate TLS for
AI hosts and inspect the plaintext. Uses the optional ``cryptography`` dependency;
if it is absent, ``available()`` is False and the proxy stays at host-level control.

Keys are written 0600. The CA private key never leaves the endpoint; only the CA
*certificate* (public) is exported for trust-store distribution.
"""

from __future__ import annotations

import datetime
import os
import threading
from pathlib import Path


def cryptography_available() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


class CertificateAuthority:
    def __init__(self, ca_dir: str) -> None:
        self._dir = Path(ca_dir).expanduser()
        self._leaf_dir = self._dir / "leaf"
        self.ca_cert_path = self._dir / "hawk-endpoint-ca.crt"
        self.ca_key_path = self._dir / "hawk-endpoint-ca.key"
        self._lock = threading.Lock()
        self._ca_cert = None
        self._ca_key = None

    # -- capability --------------------------------------------------------
    def available(self) -> bool:
        return cryptography_available()

    def status(self) -> dict[str, object]:
        return {
            "cryptography_available": cryptography_available(),
            "ca_present": self.ca_cert_path.exists(),
            "ca_cert_path": str(self.ca_cert_path),
            "note": "trust this CA on the endpoint (MDM) to enable content inspection",
        }

    # -- CA lifecycle ------------------------------------------------------
    def ensure_ca(self) -> None:
        if not self.available():
            raise RuntimeError("cryptography is required for TLS interception (pip install 'hawk-endpoint-agent[tls]')")
        with self._lock:
            if self.ca_cert_path.exists() and self.ca_key_path.exists():
                self._load_ca()
                return
            self._generate_ca()

    def export_ca_pem(self) -> str:
        """Return the CA certificate PEM to distribute to the fleet trust store."""
        self.ensure_ca()
        return self.ca_cert_path.read_text(encoding="utf-8")

    def _generate_ca(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hawk AI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Hawk Endpoint Agent Root CA"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False, data_encipherment=False,
                    key_agreement=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        self._dir.mkdir(parents=True, exist_ok=True)
        self._write(self.ca_key_path, key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        self._write(self.ca_cert_path, cert.public_bytes(serialization.Encoding.PEM))
        self._ca_cert, self._ca_key = cert, key

    def _load_ca(self) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
        self._ca_key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)

    # -- leaf minting ------------------------------------------------------
    def leaf_cert(self, host: str) -> tuple[Path, Path]:
        """Return (cert_path, key_path) for ``host``, minting + caching if needed."""
        self.ensure_ca()
        safe = host.replace("*", "_wildcard_").replace("/", "_")
        cert_path = self._leaf_dir / f"{safe}.crt"
        key_path = self._leaf_dir / f"{safe}.key"
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path
        with self._lock:
            if cert_path.exists() and key_path.exists():
                return cert_path, key_path
            self._mint_leaf(host, cert_path, key_path)
        return cert_path, key_path

    def _mint_leaf(self, host: str, cert_path: Path, key_path: Path) -> None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        if self._ca_cert is None or self._ca_key is None:
            self._load_ca()
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )
        self._leaf_dir.mkdir(parents=True, exist_ok=True)
        self._write(key_path, leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        self._write(cert_path, cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
