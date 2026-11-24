#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path


def iter_files(root: Path):
    if not root.exists():
        return
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def main() -> int:
    parser = argparse.ArgumentParser(description="Prune local Hawk evidence/report artifacts by age.")
    parser.add_argument("--root", action="append", required=True, help="Artifact/evidence/report directory to prune.")
    parser.add_argument("--days", type=int, required=True, help="Delete files older than this many days.")
    parser.add_argument("--execute", action="store_true", help="Actually delete files. Default is dry-run.")
    args = parser.parse_args()

    if args.days <= 0:
        raise SystemExit("--days must be positive")

    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    deleted = 0
    scanned = 0
    for root_value in args.root:
        root = Path(root_value).expanduser().resolve()
        for path in iter_files(root) or []:
            scanned += 1
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if modified >= cutoff:
                continue
            print(f"{'delete' if args.execute else 'would_delete'} {path}")
            if args.execute:
                path.unlink()
            deleted += 1

    print(
        f"{'pruned' if args.execute else 'dry_run'} scanned={scanned} "
        f"matched={deleted} cutoff={cutoff.isoformat()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
