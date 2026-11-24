"""Exact-certificate Windows trust-store lifecycle."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .command import CERTUTIL_EXE, CommandResult, require_success


_THUMBPRINT = re.compile(r"^[A-F0-9]{40}$")


class Runner(Protocol):
    def run(
        self, argv: Sequence[str], *, timeout: float = 30.0
    ) -> CommandResult: ...


def _mode(value: str) -> str:
    mode = str(value).strip().lower()
    if mode not in {"user_pilot", "managed_machine"}:
        raise ValueError("unsupported Windows deployment mode")
    return mode


class WindowsTrust:
    def __init__(self, runner: Runner) -> None:
        self._runner = runner

    def certificate_thumbprint(self, certificate_path: Path | str) -> str:
        path = Path(certificate_path)
        try:
            encoded = path.read_bytes()
            certificate = (
                x509.load_pem_x509_certificate(encoded)
                if b"-----BEGIN CERTIFICATE-----" in encoded
                else x509.load_der_x509_certificate(encoded)
            )
        except (OSError, ValueError) as exc:
            raise ValueError("invalid Windows trust certificate") from exc
        return certificate.fingerprint(hashes.SHA1()).hex().upper()

    @staticmethod
    def _prefix(deployment_mode: str) -> tuple[str, ...]:
        return (
            (CERTUTIL_EXE, "-user")
            if _mode(deployment_mode) == "user_pilot"
            else (CERTUTIL_EXE,)
        )

    def install(self, deployment_mode: str, certificate_path: Path | str) -> str:
        path = Path(certificate_path)
        thumbprint = self.certificate_thumbprint(path)
        require_success(
            self._runner.run(
                [*self._prefix(deployment_mode), "-addstore", "Root", str(path)]
            ),
            "install Hawk trust anchor",
        )
        return thumbprint

    def remove(self, deployment_mode: str, thumbprint: str) -> None:
        exact = str(thumbprint).strip().upper()
        if _THUMBPRINT.fullmatch(exact) is None:
            raise ValueError("invalid certificate thumbprint")
        require_success(
            self._runner.run(
                [*self._prefix(deployment_mode), "-delstore", "Root", exact]
            ),
            "remove exact Hawk trust anchor",
        )
