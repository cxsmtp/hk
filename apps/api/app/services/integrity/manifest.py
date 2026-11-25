"""The list of every file a release image ships, with its SHA-256 (ported from CxMissionZero's src/integrity/manifest.js).

Written once when the image is built (infra/scripts/integrity.py write, in each Dockerfile's ``integrity`` stage),
signed by the release workflow (a GitHub build attestation of this very file, .github/workflows/release.yml), and
compared with the files on disk whenever the API checks itself (app/services/integrity/service.py).

Hawk AI ships several images, so each list names its image and what it covers (``cover``: the folders walked and the
single files), where CxMissionZero's one image has a fixed set (src/, public/, scripts/, node_modules/ and five files):

    api      /workspace: apps/api, packages, docs/evidence, infra/scripts, VERSION, TERMS.md, LICENSE, CHANGELOG.md
    web      /workspace: apps/web (not node_modules or .next/cache), packages, VERSION
    updater  /app: hawk_updater
    proxy    /: usr/bin/caddy

Regular files only; links are never followed. Not covered: the list itself.

This module uses the standard library only: the image builds load it by its path (infra/scripts/integrity.py).
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

MANIFEST_FILE = "integrity.json"
FORMAT = 1


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cover(manifest: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    cover = manifest.get("cover") if isinstance(manifest.get("cover"), dict) else {}
    as_list = lambda value: [str(v) for v in value] if isinstance(value, list) else []  # noqa: E731
    return as_list(cover.get("trees")), as_list(cover.get("files")), as_list(cover.get("skipDirs"))


def covered_files(root: str | Path, *, trees: Iterable[str], files: Iterable[str], skip_dirs: Iterable[str] = ()) -> list[str]:
    """Every covered file under ``root``, as sorted forward-slash paths."""

    base = Path(root)
    skip = {d.strip("/") for d in skip_dirs}
    out: list[str] = []
    for name in files:
        try:
            if (base / name).is_file() and not (base / name).is_symlink():
                out.append(name)
        except OSError:
            continue

    def walk(rel: str) -> None:
        try:
            entries = list(os.scandir(base / rel))
        except OSError:
            return
        for entry in entries:
            child = f"{rel}/{entry.name}"
            if entry.is_dir(follow_symlinks=False):
                if child not in skip:
                    walk(child)
            elif entry.is_file(follow_symlinks=False) and child != MANIFEST_FILE:
                out.append(child)

    for tree in trees:
        walk(tree.strip("/"))
    return sorted(set(out))


def build_manifest(
    root: str | Path,
    *,
    image: str = "",
    version: str = "",
    commit: str = "",
    repository: str = "",
    trees: Iterable[str] = (),
    files: Iterable[str] = (),
    skip_dirs: Iterable[str] = (),
) -> dict[str, Any]:
    """The manifest of ``root``: deterministic (sorted, no time), so the same files give the same bytes."""

    trees, files, skip_dirs = list(trees), list(files), list(skip_dirs)
    listed = {name: sha256((Path(root) / name).read_bytes()) for name in covered_files(root, trees=trees, files=files, skip_dirs=skip_dirs)}
    return {
        "format": FORMAT,
        "image": image,
        "version": version,
        "commit": commit,
        "repository": repository,
        "cover": {"trees": trees, "files": files, "skipDirs": skip_dirs},
        "files": listed,
    }


def manifest_text(manifest: dict[str, Any]) -> str:
    """The manifest as written to disk: the bytes whose SHA-256 the release workflow signs."""

    return json.dumps(manifest, indent=1, ensure_ascii=False) + "\n"


def read_manifest(root: str | Path) -> dict[str, Any] | None:
    """The manifest next to the running code, with the SHA-256 of its exact bytes; None when there is none."""

    try:
        text = (Path(root) / MANIFEST_FILE).read_bytes()
    except OSError:
        return None
    digest = sha256(text)
    try:
        manifest = json.loads(text.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"error": "The file list cannot be read.", "digest": digest}
    if not isinstance(manifest, dict) or manifest.get("format") != FORMAT or not isinstance(manifest.get("files"), dict):
        return {"error": "The file list is not in a known format.", "digest": digest}
    return {"manifest": manifest, "digest": digest}


def _escapes(name: str) -> bool:
    parts = name.replace("\\", "/").split("/")
    return os.path.isabs(name) or ".." in parts


def compare_files(root: str | Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """The files on disk against the manifest: changed (different content), missing (listed, not there) and extra
    (there, not listed). ``ok`` only when all three are empty."""

    listed: dict[str, str] = manifest.get("files") or {}
    changed: list[str] = []
    missing: list[str] = []
    base = Path(root)
    for name, digest in listed.items():
        # A name that would leave the folder is never read: it counts as changed.
        if _escapes(name):
            changed.append(name)
            continue
        try:
            data = (base / name).read_bytes()
        except OSError:
            missing.append(name)
            continue
        if sha256(data) != digest:
            changed.append(name)
    trees, files, skip_dirs = _cover(manifest)
    extra = [name for name in covered_files(root, trees=trees, files=files, skip_dirs=skip_dirs) if name not in listed]
    changed.sort()
    missing.sort()
    return {"ok": not changed and not missing and not extra, "checked": len(listed), "changed": changed, "missing": missing, "extra": extra}
