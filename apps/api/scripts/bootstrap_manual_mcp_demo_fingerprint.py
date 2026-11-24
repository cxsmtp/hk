#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


API_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.services.manual_mcp_demo_bootstrap import (  # noqa: E402
    ManualMcpBootstrapError,
    approve_manual_demo_fingerprint,
    validate_local_sqlite_url,
)


CONTRACT_PATH = (
    REPOSITORY_ROOT
    / "packages"
    / "hawk-mcp-proxy"
    / "examples"
    / "manual-terminal"
    / "tool-contract.json"
)
FIXTURE_WARNING = "LOCAL DEMO FIXTURE — NOT A PRODUCTION APPROVAL"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Approve the exact Hawk manual MCP demo fingerprint in a local SQLite database.",
    )
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--owner-email", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        database_url = validate_local_sqlite_url(args.database_url)
    except ManualMcpBootstrapError:
        print(
            "Bootstrap requires an existing local SQLite file under /private/tmp.",
            file=sys.stderr,
        )
        return 2

    engine = create_engine(database_url)
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    try:
        with session_local() as db:
            result = approve_manual_demo_fingerprint(
                db,
                tenant_id=str(args.tenant_id).strip(),
                owner_email=str(args.owner_email).strip().lower(),
                contract_path=CONTRACT_PATH,
            )
    except ManualMcpBootstrapError:
        print("Manual MCP fixture bootstrap failed safely.", file=sys.stderr)
        return 1
    finally:
        engine.dispose()

    print(FIXTURE_WARNING)
    print(f"Fingerprint ID: {result.fingerprint_id}")
    print(f"Tenant ID: {result.tenant_id}")
    print(f"Idempotent: {str(result.idempotent).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
