"""AI agent posture on governed GitHub repositories: default deny, branches, paths, size, secrets, rate, evidence."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.db.models.activity_audit import AIAction, AISession
from app.db.models.evidence import EvidenceNode
from app.db.models.github_repository_access import GitHubRepository
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackDefinition, PolicyPackInstance
from app.db.session import Base
from app.services.github_repository_access_service import (
    derive_github_repository_ai_connections,
    evaluate_github_repository_mutation,
    normalize_github_agent_policy,
    persist_github_inventory_unit,
    resolve_current_repository_identity,
    save_github_repository_agent_policy,
    serialize_github_projection,
)
from app.services.policy_pack_platform.service import _normalize_assignment_targets


def _db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


def _seed(db: Session, *, full_name: str = "acme/app", repository_id: str = "R_1", organization_id: str = "O_1", protection: dict | None = None, default_branch: str | None = "main", governed: bool = True) -> GitHubRepository:
    repository = persist_github_inventory_unit(
        db,
        tenant_id="tenant-a",
        connection_id=None,
        record={
            "record_kind": "github_repository",
            "observed_at": datetime(2026, 9, 13, tzinfo=UTC),
            "identifiers": {"host": "github.com", "organization_id": organization_id, "organization_login": full_name.split("/")[0], "repository_id": repository_id},
            "metadata": {
                "full_name": full_name, "visibility": "PRIVATE", "lifecycle_state": "ACTIVE", "evidence_state": "CONFIRMED",
                "default_branch": default_branch or "", "protection": protection or {},
            },
        },
    )
    if governed:
        suffix = repository_id
        pack = PolicyPack(id=f"pack-{suffix}", tenant_id="tenant-a", name="GitHub", description="test", status="active")
        version = PolicyVersion(id=f"policy-{suffix}", tenant_id="tenant-a", pack_id=pack.id, version="1", scope={}, enforcement_defaults={}, guardian_contracts=[], contract_json={})
        definition = PolicyPackDefinition(id=f"definition-{suffix}", publisher_ref=f"test-{suffix}", stable_pack_id="DEV-GITHUB", version="1", name="GitHub", description="test", state="PUBLISHED")
        instance = PolicyPackInstance(id=f"instance-{suffix}", tenant_id="tenant-a", definition_id=definition.id, source_pack_id="DEV-GITHUB", source_pack_version="1", runtime_policy_pack_id=pack.id, effective_policy_version_id=version.id, owner_ref="owner", state="ENFORCED")
        assignment = PolicyPackAssignment(id=f"scope-{suffix}", tenant_id="tenant-a", instance_id=instance.id, assignment_key=f"repository-{suffix}", targets=_normalize_assignment_targets({"application": ["github"], "deployment_surface": ["mcp_gateway"], "resource": [repository.id]}), active=True)
        db.add_all([pack, version, definition, instance, assignment])
        repository.governance_state = "APPROVED"
        repository.approved_scope_ref = assignment.id
        repository.policy_mapping_ref = version.id
        repository.policy_current = True
        repository.read_posture = "ALLOW"
    db.flush()
    return repository


def _policy(db: Session, repository: GitHubRepository, **policy: object) -> None:
    save_github_repository_agent_policy(db, tenant_id="tenant-a", repository_id=repository.id, policy=policy, expected_governance_version=repository.governance_version)
    db.refresh(repository)


def _push(db: Session, *, files: list[dict[str, str]] | None = None, branch: str | None = "feature/agent", action: str = "REPOSITORY_PUSH", resource: str = "github.com/acme/app", agent_id: str = "agent-1", **extra: object) -> dict[str, object]:
    parameters: dict[str, object] = {"owner": "acme", "repo": "app"}
    if files is not None:
        parameters["files"] = files
    return evaluate_github_repository_mutation(db, tenant_id="tenant-a", action=action, resource=resource, branch=branch, actor_id="actor-1", agent_id=agent_id, change_parameters=parameters, **extra)


SAFE_FILE = [{"path": "src/app.py", "content": "print('ok')\n"}]


@pytest.mark.parametrize("resource", ["github.com/acme/unknown", "github.com/other-org/app", "github.com/acme/a%", "github.com/acme/ap_", "github.com/%/%", "github.com/acme/app%20", "example.com/acme/app"])
def test_unknown_repositories_organizations_and_wildcard_names_are_denied(resource: str) -> None:
    db = _db()
    try:
        _seed(db)
        result = _push(db, files=SAFE_FILE, resource=resource)
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "repository_resolution_unavailable"
        read = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource=resource)
        assert read["reason"] == "repository_resolution_unavailable"
    finally:
        db.close()


def test_repository_identity_uses_exact_case_insensitive_equality_and_refuses_ambiguity() -> None:
    db = _db()
    try:
        _seed(db)
        assert resolve_current_repository_identity(db, tenant_id="tenant-a", host="GitHub.com", owner="ACME", repository="App") is not None
        assert resolve_current_repository_identity(db, tenant_id="tenant-a", host="github.com", owner="acme", repository="%") is None
        assert resolve_current_repository_identity(db, tenant_id="tenant-b", host="github.com", owner="acme", repository="app") is None
        _seed(db, repository_id="R_dup", organization_id="O_2", governed=False)
        assert resolve_current_repository_identity(db, tenant_id="tenant-a", host="github.com", owner="acme", repository="app") is None
    finally:
        db.close()


def test_derived_ai_connections_skip_malformed_evidence_references() -> None:
    db = _db()
    try:
        _seed(db)
        db.add(AISession(session_id="session-1", tenant_id="tenant-a", source_surface="runtime"))
        db.add(AIAction(action_id="action-1", tenant_id="tenant-a", session_id="session-1", action_type="tool_call", evidence_bundle_id="x' OR '1'='1", metadata_json={"repository": "github.com/acme/app"}))
        db.flush()
        assert derive_github_repository_ai_connections(db, tenant_id="tenant-a") == 0
    finally:
        db.close()


@pytest.mark.parametrize("action", ["REPOSITORY_FORK", "REPOSITORY_VISIBILITY_CHANGE", "REPOSITORY_DELETE", "REPOSITORY_TRANSFER", "REPOSITORY_FORCE_PUSH", "REPOSITORY_SECRET_CHANGE", "REPOSITORY_BRANCH_PROTECTION_CHANGE", "REPOSITORY_COLLABORATOR_CHANGE", "REPOSITORY_SETTINGS_CHANGE"])
def test_fork_visibility_deletion_and_admin_actions_are_always_blocked(action: str) -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY")
        result = _push(db, files=SAFE_FILE, action=action, approval_binding_id="any")
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "repository_admin_action_blocked"
    finally:
        db.close()


def test_unknown_repository_actions_are_denied() -> None:
    db = _db()
    try:
        _seed(db)
        assert _push(db, files=SAFE_FILE, action="REPOSITORY_SOMETHING_NEW")["reason"] == "repository_action_unsupported"
    finally:
        db.close()


@pytest.mark.parametrize(
    ("branch", "protection", "policy", "reason"),
    [
        ("main", {}, {}, "repository_protected_branch_direct_push"),
        ("refs/heads/main", {}, {}, "repository_protected_branch_direct_push"),
        ("release", {"protected_branches": ["release"]}, {}, "repository_protected_branch_direct_push"),
        ("release/2026.11", {}, {"protected_branches": ["release/*"]}, "repository_protected_branch_direct_push"),
        (None, {}, {}, "repository_branch_unresolved"),
        ("../main", {}, {}, "repository_branch_invalid"),
        ("feature/x.lock", {}, {}, "repository_branch_invalid"),
    ],
)
def test_agents_never_push_directly_to_protected_or_default_branches(branch: str | None, protection: dict, policy: dict, reason: str) -> None:
    db = _db()
    try:
        repository = _seed(db, protection=protection)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY", **policy)
        result = _push(db, files=SAFE_FILE, branch=branch, approval_binding_id="whatever")
        assert result["decision"] == "BLOCK"
        assert result["reason"] == reason
    finally:
        db.close()


def test_unverified_default_branch_fails_closed_for_pushes() -> None:
    db = _db()
    try:
        _seed(db, default_branch=None)
        assert _push(db, files=SAFE_FILE)["reason"] == "repository_default_branch_unverified"
    finally:
        db.close()


def test_pull_request_only_posture_allows_the_pull_request_flow_without_per_action_approval() -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY")
        assert _push(db, files=SAFE_FILE)["decision"] == "ALLOW"
        assert _push(db, files=SAFE_FILE)["reason"] == "repository_pull_request_flow_allowed"
        assert _push(db, action="REPOSITORY_BRANCH_CREATE", branch="feature/new")["decision"] == "ALLOW"
        assert _push(db, action="REPOSITORY_PULL_REQUEST_CREATE", branch="feature/new")["decision"] == "ALLOW"
        merge = _push(db, action="REPOSITORY_PULL_REQUEST_MERGE", branch=None)
        assert merge["decision"] == "HOLD_FOR_APPROVAL"
        assert merge["reason"] == "repository_approval_required"
        incomplete = _push(db, files=None)
        assert incomplete["decision"] == "HOLD_FOR_APPROVAL"
        assert incomplete["reason"] == "repository_change_context_incomplete"
    finally:
        db.close()


def test_default_posture_holds_every_write_for_a_bound_approval() -> None:
    db = _db()
    try:
        _seed(db)
        result = _push(db, files=SAFE_FILE)
        assert result["decision"] == "HOLD_FOR_APPROVAL"
        assert result["reason"] == "repository_approval_required"
        assert result["canonical_action"]["paths"] == ["src/app.py"]
        assert "print('ok')" not in str(result["canonical_action"])
    finally:
        db.close()


def test_read_only_posture_blocks_writes_but_not_reads() -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="READ_ONLY")
        assert _push(db, files=SAFE_FILE)["reason"] == "repository_write_not_permitted"
        assert evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/acme/app")["decision"] == "ALLOW"
    finally:
        db.close()


@pytest.mark.parametrize("path", [".github/workflows/deploy.yml", ".github/CODEOWNERS", "CODEOWNERS", "infra/main.tf", "envs/prod.tfvars", "terraform/modules/vpc/main.tf", ".gitlab-ci.yml"])
def test_ci_codeowners_and_infrastructure_paths_need_approval_even_in_pull_request_mode(path: str) -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY")
        result = _push(db, files=[{"path": path, "content": "x: 1\n"}])
        assert result["decision"] == "HOLD_FOR_APPROVAL"
        assert result["reason"] == "repository_protected_path_requires_approval"
        assert path in result["evidence"]["approval_paths"] or path.lstrip("./") in result["evidence"]["approval_paths"]
    finally:
        db.close()


@pytest.mark.parametrize("path", [".env", "config/.env.production", "deploy/key.pem", "home/.ssh/id_rsa", "secrets.yaml", "credentials.json", ".npmrc", "state/terraform.tfstate"])
def test_secret_files_are_never_changed_by_agents(path: str) -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY")
        result = _push(db, files=[{"path": path, "content": "placeholder\n"}], approval_binding_id="any")
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "repository_secret_file_change_blocked"
    finally:
        db.close()


def test_admin_blocked_and_approval_paths_extend_the_built_in_rules() -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY", blocked_paths=["vendor/*"], approval_required_paths=["db/migrations/*"])
        assert _push(db, files=[{"path": "vendor/lib.js", "content": "x"}])["reason"] == "repository_secret_file_change_blocked"
        assert _push(db, files=[{"path": "db/migrations/0001.sql", "content": "x"}])["reason"] == "repository_protected_path_requires_approval"
    finally:
        db.close()


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", ".git/config", "C:/windows/system.ini", "a/\x00b"])
def test_traversal_absolute_and_git_internal_paths_are_refused(path: str) -> None:
    db = _db()
    try:
        _seed(db)
        result = _push(db, files=[{"path": path, "content": "x"}])
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "repository_path_invalid"
    finally:
        db.close()


@pytest.mark.parametrize(
    "content",
    [
        "token = 'ghp_" + "a" * 36 + "'\n",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
        "aws_access_key_id = AKIA" + "ABCDEFGHIJKLMNOP" + "\n",
        "password: hunter2hunter2hunter2\n",
        "const key = 'sk-" + "b" * 32 + "';\n",
    ],
)
def test_secrets_in_the_change_are_detected_before_push_and_never_stored(content: str) -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY")
        result = _push(db, files=[{"path": "src/config.py", "content": content}], approval_binding_id="any")
        assert result["decision"] == "BLOCK"
        assert result["reason"] == "repository_secret_in_change"
        assert result["evidence"]["secret_scan"]["findings"]
        node = db.get(EvidenceNode, result["evidence_ref"])
        assert node is not None and content.strip().splitlines()[0] not in str(node.payload)
    finally:
        db.close()


def test_secrets_in_pull_request_text_are_detected() -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY")
        result = evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_PULL_REQUEST_CREATE", resource="github.com/acme/app", branch="feature/a", agent_id="agent-1", change_parameters={"title": "fix", "body": "use ghp_" + "c" * 36})
        assert result["reason"] == "repository_secret_in_change"
    finally:
        db.close()


def test_change_size_limits_hold_large_changes_and_declared_stats_only_tighten() -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY", max_files_changed=2, max_bytes_changed=100)
        many = [{"path": f"src/f{index}.py", "content": "x"} for index in range(3)]
        assert _push(db, files=many)["reason"] == "repository_change_size_requires_approval"
        assert _push(db, files=[{"path": "src/big.py", "content": "x" * 101}])["reason"] == "repository_change_size_requires_approval"
        declared = _push(db, files=SAFE_FILE, change_context={"files_changed": 50, "bytes_changed": 1})
        assert declared["reason"] == "repository_change_size_requires_approval"
        understated = _push(db, files=[{"path": "src/big.py", "content": "x" * 101}], change_context={"files_changed": 0, "bytes_changed": 0})
        assert understated["reason"] == "repository_change_size_requires_approval"
        assert _push(db, files=SAFE_FILE)["decision"] == "ALLOW"
    finally:
        db.close()


def test_mutations_are_rate_limited_per_agent() -> None:
    db = _db()
    try:
        repository = _seed(db)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY", max_mutations_per_minute=2)
        assert _push(db, files=SAFE_FILE)["decision"] == "ALLOW"
        assert _push(db, files=SAFE_FILE)["decision"] == "ALLOW"
        limited = _push(db, files=SAFE_FILE)
        assert limited["decision"] == "BLOCK"
        assert limited["reason"] == "repository_agent_rate_limited"
        assert limited["evidence"]["rate"]["recent_mutations"] == 2
        assert _push(db, files=SAFE_FILE, agent_id="agent-2")["decision"] == "ALLOW"
        for _ in range(5):
            assert evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/acme/app", agent_id="agent-3")["decision"] == "ALLOW"
        assert _push(db, files=SAFE_FILE, agent_id="agent-3")["decision"] == "ALLOW"
    finally:
        db.close()


def test_every_decision_including_refusals_and_reads_has_evidence() -> None:
    db = _db()
    try:
        _seed(db)
        results = [
            _push(db, files=SAFE_FILE, resource="github.com/acme/missing"),
            _push(db, files=SAFE_FILE, action="REPOSITORY_FORK"),
            _push(db, files=SAFE_FILE),
            evaluate_github_repository_mutation(db, tenant_id="tenant-a", action="REPOSITORY_READ", resource="github.com/acme/app"),
        ]
        for result in results:
            node = db.get(EvidenceNode, result["evidence_ref"])
            assert node is not None and node.tenant_id == "tenant-a"
            assert node.payload["reason"] == result["reason"]
            assert node.payload["schema"] == "hawk.github_repository_decision.v1"
            assert node.payload["checks"]
        assert db.scalar(select(EvidenceNode).where(EvidenceNode.signal_type == "github_repository.agent_read_decision")) is not None
    finally:
        db.close()


def test_agent_policy_validation_and_governance() -> None:
    db = _db()
    try:
        assert normalize_github_agent_policy({})["write_mode"] == "APPROVAL_REQUIRED"
        for bad in ({"write_mode": "ALLOW_ALL"}, {"unknown": 1}, {"max_files_changed": 0}, {"max_bytes_changed": 10_000_000}, {"max_mutations_per_minute": True}, {"blocked_paths": ["../x"]}, {"protected_branches": ["bad branch"]}):
            with pytest.raises(ValueError):
                normalize_github_agent_policy(bad)
        ungoverned = _seed(db, full_name="acme/ungoverned", repository_id="R_9", governed=False)
        with pytest.raises(ValueError, match="PULL_REQUEST_ONLY requires"):
            save_github_repository_agent_policy(db, tenant_id="tenant-a", repository_id=ungoverned.id, policy={"write_mode": "PULL_REQUEST_ONLY"}, expected_governance_version=ungoverned.governance_version)
        repository = _seed(db)
        with pytest.raises(ValueError, match="governance version conflict"):
            save_github_repository_agent_policy(db, tenant_id="tenant-a", repository_id=repository.id, policy={}, expected_governance_version=repository.governance_version + 5)
        _policy(db, repository, write_mode="PULL_REQUEST_ONLY", protected_branches=["release/*"])
        projection = serialize_github_projection(repository)
        assert projection["agent_policy"]["write_mode"] == "PULL_REQUEST_ONLY"
        assert projection["agent_policy"]["protected_branches"] == ["release/*"]
        # A stored policy that no longer validates falls back to read-only.
        repository.agent_policy_json = {"write_mode": "SOMETHING_ELSE"}
        db.flush()
        assert _push(db, files=SAFE_FILE)["reason"] == "repository_write_not_permitted"
    finally:
        db.close()
