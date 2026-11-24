"""Bounded lifecycle for the signed Hawk Windows endpoint-floor package."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from .command import (
    FLTMC_EXE,
    PNPUTIL_EXE,
    CommandResult,
    WindowsDeploymentError,
    require_success,
)


_FILTER_NAME = "HawkEndpointFloor"
_PUBLISHED_INF = re.compile(r"(?i)\b(oem\d+\.inf)\b")


class Runner(Protocol):
    def run(
        self, argv: Sequence[str], *, timeout: float = 30.0
    ) -> CommandResult: ...


@dataclass(frozen=True, slots=True)
class WindowsNativePackage:
    root: Path
    inf_path: Path
    driver_path: Path
    service_executable: Path
    certificate_path: Path | None = None

    @classmethod
    def from_directory(cls, root: Path | str) -> "WindowsNativePackage":
        package_root = Path(root).resolve()
        if not package_root.is_dir():
            raise ValueError("Windows native package directory does not exist")
        required = {
            "inf_path": package_root / "HawkEndpointFloor.inf",
            "driver_path": package_root / "HawkEndpointFloor.sys",
            "service_executable": package_root / "HawkEndpointService.exe",
        }
        if any(not path.is_file() for path in required.values()):
            raise ValueError("Windows native package is incomplete")
        certificate = package_root / "HawkEndpointCA.cer"
        return cls(
            root=package_root,
            **required,
            certificate_path=certificate if certificate.is_file() else None,
        )


@dataclass(frozen=True, slots=True)
class NativeDriverInstallResult:
    changed: bool
    published_inf: str


class WindowsNativeDriver:
    """Install one signed driver that owns file, process, and WFP floors.

    Authenticode and kernel-policy verification are mandatory in the managed
    PowerShell installer.  This class intentionally performs only fixed,
    shell-free PnP/filter lifecycle operations for transactional orchestration.
    """

    def __init__(self, runner: Runner) -> None:
        self._runner = runner

    @staticmethod
    def _published_inf(output: str) -> str:
        matches = sorted(set(_PUBLISHED_INF.findall(str(output or ""))))
        if len(matches) != 1:
            raise WindowsDeploymentError(
                "Windows driver installation did not return one published INF"
            )
        return matches[0].lower()

    def status(self) -> bool:
        result = self._runner.run([FLTMC_EXE, "filters"])
        return result.ok and any(
            line.split() and line.split()[0].casefold() == _FILTER_NAME.casefold()
            for line in result.stdout.splitlines()
        )

    def install(self, package: WindowsNativePackage) -> NativeDriverInstallResult:
        if self.status():
            return NativeDriverInstallResult(changed=False, published_inf="")
        added = require_success(
            self._runner.run(
                [PNPUTIL_EXE, "/add-driver", str(package.inf_path), "/install"]
            ),
            "stage Hawk endpoint floor driver",
        )
        published = self._published_inf(added.stdout)
        loaded = self._runner.run([FLTMC_EXE, "load", _FILTER_NAME])
        if not loaded.ok:
            self._runner.run(
                [
                    PNPUTIL_EXE,
                    "/delete-driver",
                    published,
                    "/uninstall",
                    "/force",
                ]
            )
            raise WindowsDeploymentError(
                f"load Hawk endpoint floor failed ({loaded.error_code})"
            )
        return NativeDriverInstallResult(changed=True, published_inf=published)

    def remove(self, published_inf: str) -> None:
        exact = str(published_inf or "").strip().lower()
        if _PUBLISHED_INF.fullmatch(exact) is None:
            raise ValueError("invalid published Windows driver INF")
        self._runner.run([FLTMC_EXE, "unload", _FILTER_NAME])
        require_success(
            self._runner.run(
                [
                    PNPUTIL_EXE,
                    "/delete-driver",
                    exact,
                    "/uninstall",
                    "/force",
                ]
            ),
            "remove Hawk endpoint floor driver",
        )
