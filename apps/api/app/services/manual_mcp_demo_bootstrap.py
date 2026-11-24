from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import MetaData, Table, select, update
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


EXPECTED_SERVER_ID = "manual-terminal-lab"
EXPECTED_TOOL_NAME = "write_demo_marker"
EXPECTED_TOOL_VERSION = "1.0.0"


class ManualMcpBootstrapError(ValueError):
    pass


@dataclass(frozen=True)
class ManualMcpBootstrapResult:
    fingerprint_id: str
    tenant_id: str
    approved_by: str
    idempotent: bool


@dataclass(frozen=True)
class BootstrapTables:
    tool_fingerprints: Table
    users: Table
    user_tenant_roles: Table


def canonical_hash(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def validate_local_sqlite_url(raw_url: str) -> URL:
    try:
        url = make_url(str(raw_url or ""))
    except Exception as exc:
        raise ManualMcpBootstrapError(
            "A valid local SQLite database URL is required"
        ) from exc
    database = str(url.database or "").strip()
    path = Path(database).expanduser()
    private_tmp = Path("/private/tmp").resolve()
    if (
        url.get_backend_name() != "sqlite"
        or not database
        or database == ":memory:"
        or not path.is_absolute()
    ):
        raise ManualMcpBootstrapError(
            "An existing absolute local SQLite file under /private/tmp is required"
        )
    resolved = path.resolve()
    if not resolved.is_relative_to(private_tmp) or not resolved.is_file():
        raise ManualMcpBootstrapError(
            "An existing absolute local SQLite file under /private/tmp is required"
        )
    return url.set(database=str(resolved))


def approve_manual_demo_fingerprint(
    db: Session,
    *,
    tenant_id: str,
    owner_email: str,
    contract_path: Path,
) -> ManualMcpBootstrapResult:
    contract, expected_hashes = _load_exact_contract(contract_path)
    tables = _reflect_tables(db)
    rows = _find_matching_fingerprints(
        db,
        tables.tool_fingerprints,
        str(tenant_id or "").strip(),
    )
    if len(rows) != 1:
        raise ManualMcpBootstrapError(
            "Expected exactly one demo fingerprint for the tenant"
        )
    row = rows[0]
    actual_hashes = {
        "manifest_hash": row["manifest_hash"],
        "description_hash": row["description_hash"],
        "schema_hash": row["schema_hash"],
        "examples_hash": row["examples_hash"],
    }
    if actual_hashes != expected_hashes:
        raise ManualMcpBootstrapError(
            "Demo fingerprint hashes do not match the fixed tool contract"
        )

    users = tables.users
    roles = tables.user_tenant_roles
    owner = db.execute(
        select(users)
        .select_from(users.join(roles, roles.c.user_id == users.c.id))
        .where(
            users.c.email == str(owner_email or "").strip().lower(),
            users.c.is_active.is_(True),
            roles.c.tenant_id == str(tenant_id or "").strip(),
            roles.c.role == "owner",
        )
    ).mappings().first()
    if owner is None:
        raise ManualMcpBootstrapError(
            "An active tenant owner is required for the local demo fixture"
        )

    if row["trust_status"] == "approved":
        if row["approved_hash"] != row["manifest_hash"]:
            raise ManualMcpBootstrapError(
                "Approved demo fingerprint no longer matches its approved hash"
            )
        return ManualMcpBootstrapResult(
            fingerprint_id=row["id"],
            tenant_id=row["tenant_id"],
            approved_by=str(row["approved_by"] or owner["id"]),
            idempotent=True,
        )
    if row["trust_status"] != "unknown":
        raise ManualMcpBootstrapError(
            "Demo fingerprint trust state is not bootstrappable"
        )

    try:
        db.execute(
            update(tables.tool_fingerprints)
            .where(tables.tool_fingerprints.c.id == row["id"])
            .values(
                trust_status="approved",
                approved_hash=row["manifest_hash"],
                approved_by=owner["id"],
                approved_at=datetime.now(timezone.utc),
            )
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return ManualMcpBootstrapResult(
        fingerprint_id=row["id"],
        tenant_id=row["tenant_id"],
        approved_by=owner["id"],
        idempotent=False,
    )


def _reflect_tables(db: Session) -> BootstrapTables:
    metadata = MetaData()
    try:
        return BootstrapTables(
            tool_fingerprints=Table(
                "tool_fingerprints",
                metadata,
                autoload_with=db.get_bind(),
            ),
            users=Table("users", metadata, autoload_with=db.get_bind()),
            user_tenant_roles=Table(
                "user_tenant_roles",
                metadata,
                autoload_with=db.get_bind(),
            ),
        )
    except SQLAlchemyError as exc:
        raise ManualMcpBootstrapError(
            "Required local Hawk tables are unavailable"
        ) from exc


def _find_matching_fingerprints(
    db: Session,
    table: Table,
    tenant_id: str,
) -> list[Any]:
    return list(
        db.execute(
            select(table).where(
                table.c.tenant_id == tenant_id,
                table.c.mcp_server_id == EXPECTED_SERVER_ID,
                table.c.tool_name == EXPECTED_TOOL_NAME,
                table.c.tool_version == EXPECTED_TOOL_VERSION,
            )
        ).mappings()
    )


def _load_exact_contract(contract_path: Path) -> tuple[dict[str, Any], dict[str, str]]:
    try:
        contract = json.loads(Path(contract_path).read_text(encoding="utf-8"))
        tool = contract["tool"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ManualMcpBootstrapError(
            "The fixed manual MCP tool contract is unavailable or invalid"
        ) from exc
    if (
        contract.get("mcpServerId") != EXPECTED_SERVER_ID
        or tool.get("name") != EXPECTED_TOOL_NAME
        or tool.get("version") != EXPECTED_TOOL_VERSION
        or not isinstance(tool.get("description"), str)
        or not isinstance(tool.get("inputSchema"), dict)
        or not isinstance(tool.get("examples"), list)
    ):
        raise ManualMcpBootstrapError(
            "The fixed manual MCP tool contract does not match the expected identity"
        )
    return contract, {
        "manifest_hash": canonical_hash(tool),
        "description_hash": canonical_hash(tool["description"]),
        "schema_hash": canonical_hash(tool["inputSchema"]),
        "examples_hash": canonical_hash(tool["examples"]),
    }
