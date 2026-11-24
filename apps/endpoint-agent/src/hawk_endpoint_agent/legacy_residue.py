"""Exact-path cleanup for obsolete pre-device-identity bootstrap files."""

from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path

LEGACY_BOOTSTRAP_FILES = (
    "agent-token",
    "operator-token",
    "tenant-id",
)


@dataclass(frozen=True)
class LegacyResidueCleanup:
    removed: tuple[str, ...]
    refused: tuple[str, ...]
    residue_present: bool


def _entry_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def cleanup_legacy_bootstrap_files(root: str | Path) -> LegacyResidueCleanup:
    """Remove only known regular files without reading their contents."""

    bootstrap = Path(root).expanduser()
    removed: list[str] = []
    refused: list[str] = []

    for name in LEGACY_BOOTSTRAP_FILES:
        candidate = bootstrap / name
        try:
            mode = candidate.lstat().st_mode
        except FileNotFoundError:
            continue
        except OSError:
            refused.append(name)
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            refused.append(name)
            continue
        try:
            candidate.unlink()
        except OSError:
            refused.append(name)
        else:
            removed.append(name)

    residue_present = any(
        _entry_exists(bootstrap / name) for name in LEGACY_BOOTSTRAP_FILES
    )
    return LegacyResidueCleanup(
        removed=tuple(removed),
        refused=tuple(refused),
        residue_present=residue_present,
    )

