from __future__ import annotations

from datetime import UTC, datetime
import hashlib

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.models.github_repository_access import (
    GitHubRepository,
    GitHubRepositoryRuntimeBinding,
    GitHubSourceOrganization,
)
from app.db.session import Base
from app.services.github_repository_access_service import resolve_repository_control_floor


def test_repository_runtime_binding_defaults_block_without_raw_workspace_paths() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    try:
        assert "operation_controls_json" in GitHubRepository.__table__.c
        default = GitHubRepository.__table__.c.operation_controls_json.default.arg(None)
        assert default == {"READ": "BLOCK", "EDIT": "BLOCK", "COMMIT": "BLOCK", "PULL": "BLOCK", "PUSH": "BLOCK"}
        assert "canonical_root_sha256" in GitHubRepositoryRuntimeBinding.__table__.c
        assert "common_dir_sha256" in GitHubRepositoryRuntimeBinding.__table__.c
        assert GitHubRepositoryRuntimeBinding.__table__.c.repository_id.nullable is True
        assert "path" not in {column.name for column in GitHubRepositoryRuntimeBinding.__table__.c}
        unique_columns = {
            tuple(column.name for column in constraint.columns)
            for constraint in GitHubRepositoryRuntimeBinding.__table__.constraints
            if constraint.__class__.__name__ == "UniqueConstraint"
        }
        assert ("tenant_id", "native_integration_id", "canonical_root_sha256", "common_dir_sha256") in unique_columns
        checks = " ".join(str(constraint.sqltext) for constraint in GitHubRepositoryRuntimeBinding.__table__.constraints if hasattr(constraint, "sqltext"))
        assert "EXACT_FOLDER" in checks
        assert "ALL_WORKTREES" not in checks
        assert "repository_id IS NULL" in checks
        assert "repository_id IS NOT NULL" in checks
    finally:
        db.close()


def test_runtime_floor_is_exact_tenant_integration_folder_and_destination_scoped(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    root_hash = "1" * 64
    common_hash = "2" * 64
    target_hash = "3" * 64
    fields = {
        "repository_control_resolution": "resolved",
        "repository_operation": "PUSH",
        "repository_root_hash": root_hash,
        "repository_common_dir_hash": common_hash,
        "repository_target_hash": target_hash,
        "repository_destination_hash": "4" * 64,
    }
    try:
        assert resolve_repository_control_floor(
            db,
            tenant_id="tenant-a",
            native_integration_id="integration-a",
            repository_fields=fields,
        ) is None

        now = datetime.now(UTC)
        source = GitHubSourceOrganization(
            id="source-a",
            tenant_id="tenant-a",
            host="github.com",
            external_organization_id="org-a",
            login="example-org",
        )
        repository = GitHubRepository(
            id="repo-a",
            tenant_id="tenant-a",
            source_organization_id=source.id,
            host="github.com",
            external_repository_id="R_1",
            full_name="example-org/private-repo",
            evidence_state="CONFIRMED",
            visibility="PRIVATE",
            lifecycle_state="ACTIVE",
            first_seen_at=now,
            last_seen_at=now,
            last_verified_at=now,
            operation_controls_json={
                "READ": "ALLOW",
                "EDIT": "ALLOW",
                "COMMIT": "ALLOW",
                "PULL": "ALLOW",
                "PUSH": "ALLOW",
            },
        )
        binding = GitHubRepositoryRuntimeBinding(
            id="binding-a",
            tenant_id="tenant-a",
            repository_id=repository.id,
            native_integration_id="integration-a",
            canonical_root_sha256=root_hash,
            common_dir_sha256=common_hash,
            scope="EXACT_FOLDER",
            state="ACTIVE",
            signed_evidence_ref="evidence:evidence-a",
        )
        db.add_all([source, repository, binding])
        db.flush()

        assert resolve_repository_control_floor(
            db,
            tenant_id="tenant-b",
            native_integration_id="integration-a",
            repository_fields=fields,
        ) is None
        assert resolve_repository_control_floor(
            db,
            tenant_id="tenant-a",
            native_integration_id="integration-b",
            repository_fields=fields,
        ) is None

        mismatched_hash = resolve_repository_control_floor(
            db,
            tenant_id="tenant-a",
            native_integration_id="integration-a",
            repository_fields={**fields, "repository_root_hash": "5" * 64},
        )
        assert mismatched_hash["decision"] == "BLOCK"
        assert mismatched_hash["reason"] == "repository_runtime_binding_required"

        binding.state = "REVOKED"
        revoked = resolve_repository_control_floor(
            db,
            tenant_id="tenant-a",
            native_integration_id="integration-a",
            repository_fields=fields,
        )
        assert revoked["decision"] == "BLOCK"
        assert revoked["reason"] == "repository_runtime_binding_required"
        binding.state = "ACTIVE"

        monkeypatch.setattr(
            "app.services.github_repository_access_service._repository_governance_is_current",
            lambda *_args, **_kwargs: True,
        )
        destination_mismatch = resolve_repository_control_floor(
            db,
            tenant_id="tenant-a",
            native_integration_id="integration-a",
            repository_fields=fields,
        )
        assert destination_mismatch["decision"] == "BLOCK"
        assert destination_mismatch["reason"] == "repository_destination_mismatch"

        expected_destination_hash = hashlib.sha256(
            b"github.com/example-org/private-repo"
        ).hexdigest()
        allowed = resolve_repository_control_floor(
            db,
            tenant_id="tenant-a",
            native_integration_id="integration-a",
            repository_fields={**fields, "repository_destination_hash": expected_destination_hash},
        )
        assert allowed == {
            "decision": "UNCHANGED",
            "reason": "repository_operation_allowed",
            "operation": "PUSH",
        }
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("operation", ["READ", "EDIT", "COMMIT", "PULL", "PUSH"])
def test_each_repository_operation_control_is_blocked_by_default_and_allowed_only_after_exact_floor(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = Session(engine)
    now = datetime.now(UTC)
    root_hash, common_hash = "a" * 64, "b" * 64
    source = GitHubSourceOrganization(id="source-ops", tenant_id="tenant-ops", host="github.com", external_organization_id="org-ops", login="ops")
    repository = GitHubRepository(id="repo-ops", tenant_id="tenant-ops", source_organization_id=source.id, host="github.com", external_repository_id="R_ops", full_name="ops/repo", evidence_state="CONFIRMED", visibility="PRIVATE", lifecycle_state="ACTIVE", first_seen_at=now, last_seen_at=now, last_verified_at=now, operation_controls_json={key: "BLOCK" for key in ("READ", "EDIT", "COMMIT", "PULL", "PUSH")})
    binding = GitHubRepositoryRuntimeBinding(id="binding-ops", tenant_id="tenant-ops", repository_id=repository.id, native_integration_id="integration-ops", canonical_root_sha256=root_hash, common_dir_sha256=common_hash, scope="EXACT_FOLDER", state="ACTIVE", signed_evidence_ref="evidence:ops")
    db.add_all([source, repository, binding])
    db.flush()
    fields = {"repository_control_resolution": "resolved", "repository_operation": operation, "repository_root_hash": root_hash, "repository_common_dir_hash": common_hash, "repository_target_hash": "c" * 64}
    if operation in {"PULL", "PUSH"}:
        fields["repository_destination_hash"] = hashlib.sha256(b"github.com/ops/repo").hexdigest()
    try:
        blocked = resolve_repository_control_floor(db, tenant_id="tenant-ops", native_integration_id="integration-ops", repository_fields=fields)
        assert blocked == {"decision": "BLOCK", "reason": "repository_operation_blocked", "operation": operation}
        repository.operation_controls_json = {key: ("ALLOW" if key == operation else "BLOCK") for key in ("READ", "EDIT", "COMMIT", "PULL", "PUSH")}
        monkeypatch.setattr("app.services.github_repository_access_service._repository_governance_is_current", lambda *_args, **_kwargs: True)
        allowed = resolve_repository_control_floor(db, tenant_id="tenant-ops", native_integration_id="integration-ops", repository_fields=fields)
        assert allowed == {"decision": "UNCHANGED", "reason": "repository_operation_allowed", "operation": operation}
    finally:
        db.close()
        engine.dispose()
