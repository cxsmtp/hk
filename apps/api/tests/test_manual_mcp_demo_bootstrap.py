from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.models.policy import ToolFingerprint
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base
from app.services.manual_mcp_demo_bootstrap import (
    ManualMcpBootstrapError,
    approve_manual_demo_fingerprint,
    validate_local_sqlite_url,
)
from app.services import manual_mcp_demo_bootstrap as bootstrap_service


CONTRACT_PATH = (
    Path(__file__).resolve().parents[3]
    / "packages"
    / "hawk-mcp-proxy"
    / "examples"
    / "manual-terminal"
    / "tool-contract.json"
)
CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_manual_mcp_demo_fingerprint.py"


@pytest.fixture()
def db(tmp_path: Path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'bootstrap.sqlite3'}")
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session = session_local()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture()
def seeded_owner(db: Session) -> tuple[Tenant, User]:
    tenant = Tenant(name="Manual MCP Tenant", slug="manual-mcp-tenant")
    owner = User(
        email="owner@acme.ai",
        hashed_password="not-used-by-bootstrap",
        full_name="Manual MCP Owner",
        is_active=True,
    )
    db.add_all([tenant, owner])
    db.flush()
    db.add(UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"))
    db.commit()
    return tenant, owner


def test_approve_exact_demo_fingerprint_sets_only_exact_authority(
    db: Session,
    seeded_owner: tuple[Tenant, User],
) -> None:
    tenant, owner = seeded_owner
    row = _seed_fingerprint(db, tenant_id=tenant.id, trust_status="unknown")

    result = approve_manual_demo_fingerprint(
        db,
        tenant_id=tenant.id,
        owner_email=owner.email,
        contract_path=CONTRACT_PATH,
    )

    db.refresh(row)
    assert result.fingerprint_id == row.id
    assert result.idempotent is False
    assert row.trust_status == "approved"
    assert row.approved_hash == row.manifest_hash
    assert row.approved_by == owner.id
    assert row.approved_at is not None


def test_bootstrap_is_idempotent_for_same_approved_hash(
    db: Session,
    seeded_owner: tuple[Tenant, User],
) -> None:
    tenant, owner = seeded_owner
    row = _seed_fingerprint(db, tenant_id=tenant.id, trust_status="unknown")
    first = approve_manual_demo_fingerprint(
        db,
        tenant_id=tenant.id,
        owner_email=owner.email,
        contract_path=CONTRACT_PATH,
    )
    first_approved_at = row.approved_at

    second = approve_manual_demo_fingerprint(
        db,
        tenant_id=tenant.id,
        owner_email=owner.email,
        contract_path=CONTRACT_PATH,
    )

    db.refresh(row)
    assert first.idempotent is False
    assert second.idempotent is True
    assert row.approved_at == first_approved_at


def test_rejects_hash_mismatch(
    db: Session,
    seeded_owner: tuple[Tenant, User],
) -> None:
    tenant, owner = seeded_owner
    row = _seed_fingerprint(db, tenant_id=tenant.id, trust_status="unknown")
    row.schema_hash = "tampered"
    db.commit()

    with pytest.raises(ManualMcpBootstrapError, match="fingerprint hashes do not match"):
        approve_manual_demo_fingerprint(
            db,
            tenant_id=tenant.id,
            owner_email=owner.email,
            contract_path=CONTRACT_PATH,
        )


@pytest.mark.parametrize("trust_status", ["changed", "blocked"])
def test_rejects_non_bootstrappable_trust_state(
    db: Session,
    seeded_owner: tuple[Tenant, User],
    trust_status: str,
) -> None:
    tenant, owner = seeded_owner
    _seed_fingerprint(db, tenant_id=tenant.id, trust_status=trust_status)

    with pytest.raises(ManualMcpBootstrapError, match="trust state"):
        approve_manual_demo_fingerprint(
            db,
            tenant_id=tenant.id,
            owner_email=owner.email,
            contract_path=CONTRACT_PATH,
        )


def test_rejects_missing_or_wrong_tenant_fingerprint(
    db: Session,
    seeded_owner: tuple[Tenant, User],
) -> None:
    tenant, owner = seeded_owner
    _seed_fingerprint(db, tenant_id=tenant.id, trust_status="unknown")

    with pytest.raises(ManualMcpBootstrapError, match="exactly one demo fingerprint"):
        approve_manual_demo_fingerprint(
            db,
            tenant_id="00000000-0000-0000-0000-000000000000",
            owner_email=owner.email,
            contract_path=CONTRACT_PATH,
        )


def test_rejects_user_without_owner_role(
    db: Session,
    seeded_owner: tuple[Tenant, User],
) -> None:
    tenant, _owner = seeded_owner
    viewer = User(
        email="viewer@acme.ai",
        hashed_password="not-used-by-bootstrap",
        full_name="Viewer",
        is_active=True,
    )
    db.add(viewer)
    db.flush()
    db.add(UserTenantRole(user_id=viewer.id, tenant_id=tenant.id, role="viewer"))
    _seed_fingerprint(db, tenant_id=tenant.id, trust_status="unknown")
    db.commit()

    with pytest.raises(ManualMcpBootstrapError, match="active tenant owner"):
        approve_manual_demo_fingerprint(
            db,
            tenant_id=tenant.id,
            owner_email=viewer.email,
            contract_path=CONTRACT_PATH,
        )


def test_rejects_ambiguous_fingerprint_query(
    db: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        bootstrap_service,
        "_find_matching_fingerprints",
        lambda *_args, **_kwargs: [{}, {}],
    )
    with pytest.raises(ManualMcpBootstrapError, match="exactly one demo fingerprint"):
        approve_manual_demo_fingerprint(
            db,
            tenant_id="tenant-1",
            owner_email="owner@acme.ai",
            contract_path=CONTRACT_PATH,
        )


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://localhost/hawk",
        "sqlite+pysqlite:///relative.db",
        "sqlite+pysqlite:///:memory:",
        "sqlite+pysqlite:////Users/example/hawk.db",
        "sqlite+pysqlite:////private/tmp/hawk-file-does-not-exist.db",
    ],
)
def test_validate_local_sqlite_url_rejects_unsafe_targets(database_url: str) -> None:
    with pytest.raises(ManualMcpBootstrapError, match="local SQLite"):
        validate_local_sqlite_url(database_url)


def test_validate_local_sqlite_url_accepts_existing_private_tmp_file() -> None:
    with NamedTemporaryFile(
        prefix="hawk-mcp-bootstrap-test-",
        suffix=".db",
        dir="/private/tmp",
    ) as database:
        url = f"sqlite+pysqlite:///{database.name}"
        assert validate_local_sqlite_url(url).database == database.name


def test_bootstrap_cli_help_is_available_without_database_access() -> None:
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "--help"],
        check=False,
        capture_output=True,
        text=True,
        env=_standalone_cli_env(),
        cwd=Path(__file__).resolve().parents[3],
    )
    assert result.returncode == 0
    assert "--database-url" in result.stdout
    assert "--tenant-id" in result.stdout
    assert "--owner-email" in result.stdout


def test_bootstrap_cli_approves_only_the_seeded_private_tmp_fingerprint() -> None:
    with NamedTemporaryFile(
        prefix="hawk-mcp-bootstrap-cli-",
        suffix=".db",
        dir="/private/tmp",
        delete=False,
    ) as database:
        database_path = Path(database.name)
    database_path.unlink(missing_ok=True)
    engine = create_engine(f"sqlite+pysqlite:///{database_path}")
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)
    try:
        with session_local() as session:
            tenant = Tenant(name="CLI Tenant", slug=f"cli-{database_path.stem}")
            owner = User(
                email="owner@acme.ai",
                hashed_password="not-used-by-bootstrap",
                full_name="CLI Owner",
                is_active=True,
            )
            session.add_all([tenant, owner])
            session.flush()
            session.add(UserTenantRole(user_id=owner.id, tenant_id=tenant.id, role="owner"))
            row = _seed_fingerprint(
                session,
                tenant_id=tenant.id,
                trust_status="unknown",
            )
            tenant_id = tenant.id
            fingerprint_id = row.id

        database_url = f"sqlite+pysqlite:///{database_path}"
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "--database-url",
                database_url,
                "--tenant-id",
                tenant_id,
                "--owner-email",
                "owner@acme.ai",
            ],
            check=False,
            capture_output=True,
            text=True,
            cwd=Path(__file__).resolve().parents[3],
            env=_standalone_cli_env(),
        )

        assert result.returncode == 0, result.stderr
        assert "LOCAL DEMO FIXTURE — NOT A PRODUCTION APPROVAL" in result.stdout
        assert f"Fingerprint ID: {fingerprint_id}" in result.stdout
        assert database_url not in result.stdout
        with session_local() as session:
            approved = session.get(ToolFingerprint, fingerprint_id)
            assert approved is not None
            assert approved.trust_status == "approved"
            assert approved.approved_hash == approved.manifest_hash
    finally:
        engine.dispose()
        database_path.unlink(missing_ok=True)


def _seed_fingerprint(
    db: Session,
    *,
    tenant_id: str,
    trust_status: str,
) -> ToolFingerprint:
    contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    tool = contract["tool"]
    row = ToolFingerprint(
        tenant_id=tenant_id,
        mcp_server_id=contract["mcpServerId"],
        tool_name=tool["name"],
        tool_version=tool["version"],
        manifest_hash=_canonical_hash(tool),
        description_hash=_canonical_hash(tool["description"]),
        schema_hash=_canonical_hash(tool["inputSchema"]),
        examples_hash=_canonical_hash(tool["examples"]),
        trust_status=trust_status,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _canonical_hash(value: object) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _standalone_cli_env() -> dict[str, str]:
    clean = dict(os.environ)
    for name in [
        "APP_TEST_SETTINGS_APPLIED",
        "CONNECTOR_SECRETS_KDF_SALT",
        "ONPREM_BUNDLE_SIGNING_SECRET",
        "TEST_CONNECTOR_SECRETS_KDF_SALT",
        "TEST_ONPREM_BUNDLE_SIGNING_SECRET",
    ]:
        clean.pop(name, None)
    return clean
