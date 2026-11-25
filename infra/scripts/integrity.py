#!/usr/bin/env python3
"""The list of every file a Hawk AI image ships, with its SHA-256 (ported from CxMissionZero's scripts/integrity.mjs).

    python infra/scripts/integrity.py write <folder> --image api --version 0.1.0 --commit <sha> --repository owner/name \
        --tree apps/api --tree packages --file VERSION [--skip-dir apps/web/node_modules]
        writes <folder>/integrity.json (each Dockerfile's integrity stage does this; .github/workflows/release.yml signs it)
    python infra/scripts/integrity.py check <folder>
        compares the files with their list; exits 1 when any is changed, missing or added

Standard library only: it loads apps/api/app/services/integrity/manifest.py by its path, so an image build needs only
these two files (infra/Dockerfile.web, Dockerfile.proxy and Dockerfile.updater copy them into a Python stage).
In the running API: docker compose -f deploy/compose.yaml exec api python -m app.cli.integrity check --origin
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
MANIFEST = HERE.parents[2] / "apps" / "api" / "app" / "services" / "integrity" / "manifest.py"


def _manifest_module():
    spec = importlib.util.spec_from_file_location("hawk_integrity_manifest", MANIFEST)
    if spec is None or spec.loader is None:
        raise SystemExit(f"Cannot load {MANIFEST}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _parse(rest: list[str]) -> tuple[list[str], dict[str, list[str]]]:
    options: dict[str, list[str]] = {}
    folders: list[str] = []
    i = 0
    while i < len(rest):
        if rest[i].startswith("--"):
            options.setdefault(rest[i][2:], []).append(rest[i + 1] if i + 1 < len(rest) else "")
            i += 2
        else:
            folders.append(rest[i])
            i += 1
    return folders, options


def main(argv: list[str]) -> int:
    m = _manifest_module()
    if not argv or argv[0] not in {"write", "check"}:
        print("Usage: integrity.py write|check <folder> [--image x --version x --commit sha --repository owner/name --tree d --file f --skip-dir d]")
        return 2
    folders, options = _parse(argv[1:])
    root = Path(folders[0] if folders else ".").resolve()

    def one(name: str) -> str:
        return (options.get(name) or [""])[-1]

    if argv[0] == "write":
        version = one("version")
        if not version and (root / "VERSION").is_file():
            version = (root / "VERSION").read_text(encoding="utf-8").strip()
        manifest = m.build_manifest(
            root,
            image=one("image"),
            version=version,
            commit=one("commit"),
            repository=one("repository"),
            trees=options.get("tree", []),
            files=options.get("file", []),
            skip_dirs=options.get("skip-dir", []),
        )
        (root / m.MANIFEST_FILE).write_text(m.manifest_text(manifest), encoding="utf-8")
        print(f"{len(manifest['files'])} files listed in {root / m.MANIFEST_FILE}.")
        return 0
    read = m.read_manifest(root)
    if read is None:
        print(f"No {m.MANIFEST_FILE} in {root}: this copy was not built by the release workflow.")
        return 1
    if read.get("error"):
        print(read["error"])
        return 1
    result = m.compare_files(root, read["manifest"])
    print(f"{read['manifest'].get('image') or 'image'} {read['manifest'].get('version')}: {result['checked']} files listed; list SHA-256 {read['digest']}.")
    if result["ok"]:
        print("Every file matches the list.")
        return 0
    for title, names in (("Changed", result["changed"]), ("Missing", result["missing"]), ("Not in the list", result["extra"])):
        if names:
            print(f"{title} ({len(names)}): {', '.join(names[:20])}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
