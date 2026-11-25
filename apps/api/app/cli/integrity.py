"""The running image's files against their signed list (ported from CxMissionZero's scripts/integrity.mjs check).

    python -m app.cli.integrity check [folder] [--origin]
    docker compose -f deploy/compose.yaml exec api python -m app.cli.integrity check --origin

Without --origin only the files are compared with integrity.json (no network). With --origin the list's build
attestation is also fetched from api.github.com and checked (app/services/integrity/). The updater runs this in the new
api image before it switches to it.

Exit codes: 0 every file matches (and, with --origin, the list is signed by the release workflow); 1 files changed;
2 no file list (a development copy); 3 not signed by the release workflow; 4 not confirmed yet (GitHub unreachable).
"""

from __future__ import annotations

import sys
from pathlib import Path

from app.services.integrity.manifest import compare_files, read_manifest
from app.services.integrity.service import IntegrityService, app_root, label

EXIT_OK, EXIT_CHANGED, EXIT_NO_LIST, EXIT_NOT_SIGNED, EXIT_UNCONFIRMED = 0, 1, 2, 3, 4


def main(argv: list[str] | None = None, *, service: IntegrityService | None = None) -> int:
    args = sys.argv[1:] if argv is None else list(argv)
    if not args or args[0] != "check":
        print("Usage: python -m app.cli.integrity check [folder] [--origin]", file=sys.stderr)
        return EXIT_NO_LIST
    origin = "--origin" in args
    folders = [a for a in args[1:] if not a.startswith("--")]
    root = Path(folders[0]) if folders else app_root()
    read = read_manifest(root)
    if read is None:
        print("No integrity.json here: this copy was not built by the release workflow (a development copy).")
        return EXIT_NO_LIST
    if read.get("error"):
        print(read["error"])
        return EXIT_CHANGED
    manifest = read["manifest"]
    result = compare_files(root, manifest)
    commit = str(manifest.get("commit") or "")
    print(f"{label(str(manifest.get('version') or ''))} ({manifest.get('image') or 'image'}{f', commit {commit[:12]}' if commit else ''}): {result['checked']} files listed; list SHA-256 {read['digest']}.")
    if not result["ok"]:
        for title, names in (("Changed", result["changed"]), ("Missing", result["missing"]), ("Not in the list", result["extra"])):
            if names:
                print(f"{title} ({len(names)}): {', '.join(names[:20])}{', …' if len(names) > 20 else ''}")
        return EXIT_CHANGED
    print("Every file matches the list.")
    if not origin:
        return EXIT_OK
    service = service or IntegrityService(app_dir=root)
    verdict = service.verify_origin(read["digest"])
    if verdict.get("ok"):
        print(f"Signed by {verdict.get('workflow')} (commit {str(verdict.get('commit') or '')[:12]}, Sigstore log entry {verdict.get('logIndex')}).")
        return EXIT_OK
    if verdict.get("reachable") is False:
        print(f"Who built it is not confirmed yet: {verdict.get('reason')}.")
        return EXIT_UNCONFIRMED
    print(f"Not signed by the release workflow: {verdict.get('reason')}.")
    return EXIT_NOT_SIGNED


if __name__ == "__main__":
    raise SystemExit(main())
