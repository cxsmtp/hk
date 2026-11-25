"""Hawk AI's version, from the one VERSION file at the root of the repository (ported from CxMissionZero's
src/version.js, which reads package.json).

It is shown as ``HK-xx.xx.xx`` bottom-left on every screen of the console (the web image reads the same file when it
is built), returned by /health, and logged when the API starts.
"""

from __future__ import annotations

from pathlib import Path

#: The VERSION file: the repository root in a checkout, /workspace in the images (infra/Dockerfile.api, Dockerfile.web).
VERSION_FILE = Path(__file__).resolve().parents[3] / "VERSION"


def display_version(semver: str) -> str:
    """"1.2.3" → "HK-01.02.03": the version shown in the console's corner and the log."""

    parts: list[int] = []
    for piece in str(semver or "").strip().split(".")[:3]:
        digits = ""
        for char in piece:
            if not char.isdigit():
                break
            digits += char
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return "HK-" + ".".join(f"{n:02d}" for n in parts)


def _read_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


#: This build's version, from VERSION.
PACKAGE_VERSION = _read_version()
APP_VERSION = display_version(PACKAGE_VERSION)
