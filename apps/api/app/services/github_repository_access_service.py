"""Safe persistence and bounded queries for the GitHub repository projection."""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase
import hashlib
import hmac
import json
import re
import secrets
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.db.models.github_repository_access import (
    GitHubRepository,
    GitHubRepositoryAIConnection,
    GitHubRepositoryAccess,
    GitHubRepositoryMutationApproval,
    GitHubRepositoryRuntimeBinding,
    GitHubSourceOrganization,
)
from app.db.models.native_control import NativeControlIntegration
from app.db.models.activity_audit import AIAction, AISession
from app.db.models.evidence import EvidenceNode
from app.db.models.policy import ApprovalRequest
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.policy_pack_platform import PolicyPackAssignment, PolicyPackDefinition, PolicyPackInstance
from app.services.audit_service import write_audit_log

_EVIDENCE_STATES = frozenset({"CONFIRMED", "OBSERVED", "CORRELATED", "INFERRED", "UNKNOWN"})
_UNSAFE_KEY_TOKENS = frozenset({"prompt", "content", "code", "diff", "secret", "token", "credential", "privatekey", "cookie"})


def _text(value: object, default: str = "") -> str:
    return str(value or default).strip()


def _normalized_key(value: object) -> str:
    return "".join(character for character in _text(value).lower() if character.isalnum())


def _reject_unsafe_key(value: object) -> None:
    normalized = _normalized_key(value)
    if any(token in normalized for token in _UNSAFE_KEY_TOKENS):
        raise ValueError("unsafe projection field")


def _safe_value(value: object) -> Any:
    if isinstance(value, Mapping):
        return _safe_mapping(value)
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value[:64]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise ValueError("projection metadata must be scalar or bounded mapping")


def _safe_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, Any] = {}
    for key, item in value.items():
        _reject_unsafe_key(key)
        result[_text(key)] = _safe_value(item)
    return result


def _at(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    return datetime.now(UTC)


def _state(value: object) -> str:
    result = _text(value, "UNKNOWN").upper()
    return result if result in _EVIDENCE_STATES else "UNKNOWN"


def _organization(db: Session, *, tenant_id: str, connection_id: str | None, identifiers: Mapping[str, Any], metadata: Mapping[str, Any], seen_at: datetime) -> GitHubSourceOrganization:
    host = _text(identifiers.get("host"), "github.com").lower()
    organization_id = _text(
        identifiers.get("organization_hash"),
        _text(identifiers.get("organization_id"), _text(identifiers.get("organization_login"), "unknown")),
    )
    login = _text(identifiers.get("organization_login"), organization_id)
    row = db.scalar(select(GitHubSourceOrganization).where(GitHubSourceOrganization.tenant_id == tenant_id, GitHubSourceOrganization.host == host, GitHubSourceOrganization.external_organization_id == organization_id))
    if row is None:
        row = GitHubSourceOrganization(tenant_id=tenant_id, connection_id=connection_id, host=host, external_organization_id=organization_id, login=login)
        db.add(row)
    row.connection_id = connection_id or row.connection_id
    row.login = login or row.login
    installation_ref = _text(identifiers.get("installation_hash")) or _text(identifiers.get("installation_id"))
    if installation_ref:
        row.installation_id = installation_ref
    if "capabilities" in metadata:
        row.capabilities_json = dict(metadata.get("capabilities") or {})
    if "selected_repository_scope" in metadata:
        row.selected_repository_scope = _text(metadata.get("selected_repository_scope"), "UNKNOWN").upper()
    if "sync_state" in metadata:
        row.sync_state = _text(metadata.get("sync_state"), "UNKNOWN").upper()
    row.last_complete_at = seen_at if row.sync_state == "COMPLETE" else row.last_complete_at
    if "limitations" in metadata:
        row.limitations_json = list(metadata.get("limitations") or [])[:64]
    db.flush()
    return row


def _repository(db: Session, *, tenant_id: str, connection_id: str | None, identifiers: Mapping[str, Any], metadata: Mapping[str, Any], seen_at: datetime) -> GitHubRepository:
    source = _organization(db, tenant_id=tenant_id, connection_id=connection_id, identifiers=identifiers, metadata=metadata, seen_at=seen_at)
    host = _text(identifiers.get("host"), source.host).lower()
    external_id = _text(identifiers.get("repository_hash")) or _text(identifiers.get("repository_id"))
    if not external_id:
        raise ValueError("repository identifier is required")
    row = db.scalar(select(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.host == host, GitHubRepository.source_organization_id == source.id, GitHubRepository.external_repository_id == external_id))
    if row is None:
        row = GitHubRepository(tenant_id=tenant_id, source_organization_id=source.id, host=host, external_repository_id=external_id, full_name=_text(metadata.get("full_name"), "unknown/unknown"), first_seen_at=seen_at, last_seen_at=seen_at)
        db.add(row)
    row.source_organization_id = source.id
    row.node_id = (
        _text(metadata.get("github_node_hash"))
        or _text(metadata.get("github_node_id"))
        or _text(identifiers.get("node_hash"))
        or _text(identifiers.get("node_id"))
        or None
    )
    row.full_name = _text(metadata.get("full_name"), row.full_name)
    row.visibility = _text(metadata.get("visibility"), "UNKNOWN").upper()
    row.lifecycle_state = _text(metadata.get("lifecycle_state"), "UNKNOWN").upper()
    row.default_branch = _text(metadata.get("default_branch")) or None
    row.protection_json = dict(metadata.get("protection") or {})
    row.evidence_state = _state(metadata.get("evidence_state"))
    # Discovery records are evidence only. Governance is exclusively changed
    # through the owner/admin decision path below.
    row.last_seen_at = seen_at
    row.last_verified_at = seen_at if row.evidence_state == "CONFIRMED" else row.last_verified_at
    db.flush()
    return row


def _lookup_repository(db: Session, *, tenant_id: str, identifier: str, host: str | None = None, organization_id: str | None = None) -> GitHubRepository:
    row = db.scalar(select(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.id == identifier))
    if row is None and host and organization_id:
        source = db.scalar(select(GitHubSourceOrganization).where(GitHubSourceOrganization.tenant_id == tenant_id, GitHubSourceOrganization.host == host.lower(), GitHubSourceOrganization.external_organization_id == organization_id))
        if source is not None:
            row = db.scalar(select(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.host == host.lower(), GitHubRepository.source_organization_id == source.id, GitHubRepository.external_repository_id == identifier))
    if row is None:
        raise ValueError("repository not found for tenant")
    return row


def persist_github_inventory_unit(db: Session, *, tenant_id: str, connection_id: str | None, record: Mapping[str, object]) -> object:
    identifiers = _safe_mapping(record.get("identifiers"))
    metadata = _safe_mapping(record.get("metadata"))
    kind = _text(record.get("record_kind"))
    seen_at = _at(record.get("observed_at"))
    if kind == "github_organization":
        return _organization(db, tenant_id=tenant_id, connection_id=connection_id, identifiers=identifiers, metadata=metadata, seen_at=seen_at)
    if kind in {"github_repository", "github_repository_protection"}:
        return _repository(db, tenant_id=tenant_id, connection_id=connection_id, identifiers=identifiers, metadata=metadata, seen_at=seen_at)
    repository = _lookup_repository(
        db,
        tenant_id=tenant_id,
        identifier=_text(identifiers.get("repository_hash")) or _text(identifiers.get("repository_id")),
        host=_text(identifiers.get("host")) or None,
        organization_id=(_text(identifiers.get("organization_hash")) or _text(identifiers.get("organization_id")) or None),
    )
    if kind == "github_repository_access":
        principal = _text(identifiers.get("principal_hash")) or _text(identifiers.get("principal_id"))
        path = _text(identifiers.get("access_path"), "UNKNOWN").upper()
        row = db.scalar(select(GitHubRepositoryAccess).where(GitHubRepositoryAccess.tenant_id == tenant_id, GitHubRepositoryAccess.repository_id == repository.id, GitHubRepositoryAccess.external_principal_id == principal, GitHubRepositoryAccess.access_path == path))
        if row is None:
            row = GitHubRepositoryAccess(tenant_id=tenant_id, repository_id=repository.id, external_principal_id=principal, access_path=path, principal_type="UNKNOWN", permission="UNKNOWN")
            db.add(row)
        row.principal_type = _text(metadata.get("principal_type"), "UNKNOWN").upper()
        row.permission = _text(metadata.get("permission"), "UNKNOWN").upper()
        row.source_team_id = _text(identifiers.get("team_hash")) or _text(identifiers.get("team_id")) or None
        row.mapped_user_id = _text(metadata.get("mapped_user_id")) or None
        row.mapped_group_id = _text(metadata.get("mapped_group_id")) or None
        row.evidence_state = _state(metadata.get("evidence_state"))
        db.flush()
        return row
    if kind == "github_repository_ai_connection":
        surface = _text(metadata.get("source_surface"), "UNKNOWN").upper()
        ai_system_id = _text(metadata.get("ai_system_id")) or None
        agent_id = _text(metadata.get("agent_id")) or None
        capability_id = _text(metadata.get("external_capability_id")) or None
        row = db.scalar(select(GitHubRepositoryAIConnection).where(GitHubRepositoryAIConnection.tenant_id == tenant_id, GitHubRepositoryAIConnection.repository_id == repository.id, GitHubRepositoryAIConnection.ai_system_id == ai_system_id, GitHubRepositoryAIConnection.agent_id == agent_id, GitHubRepositoryAIConnection.external_capability_id == capability_id, GitHubRepositoryAIConnection.source_surface == surface))
        if row is None:
            row = GitHubRepositoryAIConnection(tenant_id=tenant_id, repository_id=repository.id, ai_system_id=ai_system_id, agent_id=agent_id, external_capability_id=capability_id, source_surface=surface, first_seen_at=seen_at, last_seen_at=seen_at)
            db.add(row)
        row.user_id = _text(metadata.get("user_id")) or None
        row.ai_asset_id = _text(metadata.get("ai_asset_id")) or None
        row.provider = _text(metadata.get("provider")) or None
        row.model = _text(metadata.get("model")) or None
        row.client_name = _text(metadata.get("client_name")) or None
        row.relationship_state = _state(metadata.get("relationship_state"))
        row.confidence = _state(metadata.get("confidence"))
        row.mcp_server_id = _text(metadata.get("mcp_server_id")) or None
        row.tool_name = _text(metadata.get("tool_name")) or None
        row.tool_schema_fingerprint = _text(metadata.get("tool_schema_fingerprint")) or None
        row.evidence_refs_json = list(metadata.get("evidence_refs") or [])[:64]
        row.action_count = max(0, int(metadata.get("action_count") or 0))
        row.last_seen_at = seen_at
        db.flush()
        return row
    raise ValueError("unsupported GitHub inventory record kind")


def _encode_cursor(row_id: str) -> str:
    return urlsafe_b64encode(json.dumps({"id": row_id}, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None) -> str | None:
    if cursor is None:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        identifier = payload.get("id") if isinstance(payload, Mapping) else None
        if not isinstance(identifier, str) or not identifier:
            raise ValueError
        return identifier
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("invalid cursor") from None


def _bounded_page(db: Session, statement: Any, model: Any, *, limit: int, cursor: str | None) -> dict[str, object]:
    bounded = max(1, min(int(limit), 200))
    after_id = _decode_cursor(cursor)
    if after_id:
        statement = statement.where(model.id > after_id)
    rows = list(db.scalars(statement.order_by(model.id.asc()).limit(bounded + 1)))
    page = rows[:bounded]
    return {
        "items": page,
        "next_cursor": _encode_cursor(str(page[-1].id)) if len(rows) > bounded and page else None,
        "limit": bounded,
    }


def list_github_organizations(db: Session, *, tenant_id: str, limit: int = 100, cursor: str | None = None) -> dict[str, object]:
    return _bounded_page(db, select(GitHubSourceOrganization).where(GitHubSourceOrganization.tenant_id == tenant_id), GitHubSourceOrganization, limit=limit, cursor=cursor)


def list_github_repositories(db: Session, *, tenant_id: str, limit: int = 100, cursor: str | None = None, filters: Mapping[str, object] | None = None) -> dict[str, object]:
    statement = select(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id)
    filters = filters or {}
    if visibility := _text(filters.get("visibility")):
        statement = statement.where(GitHubRepository.visibility == visibility.upper())
    if host := _text(filters.get("host")):
        statement = statement.where(GitHubRepository.host == host.lower())
    if source_organization_id := _text(filters.get("source_organization_id")):
        statement = statement.where(GitHubRepository.source_organization_id == source_organization_id)
    return _bounded_page(db, statement, GitHubRepository, limit=limit, cursor=cursor)


def get_github_repository_detail(db: Session, *, tenant_id: str, repository_id: str) -> GitHubRepository:
    return _lookup_repository(db, tenant_id=tenant_id, identifier=repository_id)


def get_github_repository_detail_payload(db: Session, *, tenant_id: str, repository_id: str, limit: int = 100) -> dict[str, object]:
    repository = get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository_id)
    return {
        "repository": serialize_github_projection(repository),
        "runtime_bindings": list_github_runtime_bindings(db, tenant_id=tenant_id, repository_id=repository.id, limit=limit),
        "access_relationships": serialize_github_page(list_github_developers(db, tenant_id=tenant_id, limit=limit, filters={"repository_id": repository.id})),
        "ai_connections": serialize_github_page(list_github_ai_connections(db, tenant_id=tenant_id, limit=limit, filters={"repository_id": repository.id})),
    }


_RUNTIME_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_OPERATIONS = frozenset({"READ", "EDIT", "COMMIT", "PULL", "PUSH"})


def list_github_runtime_bindings(db: Session, *, tenant_id: str, repository_id: str | None = None, limit: int = 100) -> dict[str, object]:
    statement = select(GitHubRepositoryRuntimeBinding).where(GitHubRepositoryRuntimeBinding.tenant_id == tenant_id)
    if repository_id:
        statement = statement.where(GitHubRepositoryRuntimeBinding.repository_id == repository_id)
    rows = list(db.scalars(statement.order_by(GitHubRepositoryRuntimeBinding.id.asc()).limit(max(1, min(int(limit), 200)))))
    return {"items": [serialize_github_projection(row) for row in rows], "next_cursor": None, "limit": max(1, min(int(limit), 200))}


def _validate_runtime_hash(value: str, field: str) -> str:
    normalized = _text(value).lower()
    if not _RUNTIME_HASH_RE.fullmatch(normalized):
        raise ValueError(f"{field} must be a lowercase SHA-256 hash")
    return normalized


def bind_github_repository_runtime(
    db: Session,
    *,
    tenant_id: str,
    repository_id: str,
    observation_id: str,
    actor_id: str | None,
    expected_governance_version: int,
) -> GitHubRepositoryRuntimeBinding:
    repository = get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository_id)
    observation = db.scalar(
        select(GitHubRepositoryRuntimeBinding).where(
            GitHubRepositoryRuntimeBinding.tenant_id == tenant_id,
            GitHubRepositoryRuntimeBinding.id == observation_id,
            GitHubRepositoryRuntimeBinding.repository_id.is_(None),
            GitHubRepositoryRuntimeBinding.state == "OBSERVED",
            GitHubRepositoryRuntimeBinding.scope == "EXACT_FOLDER",
        )
    )
    if observation is None:
        raise ValueError("signed repository observation is not available in this tenant")
    integration = db.scalar(
        select(NativeControlIntegration).where(
            NativeControlIntegration.tenant_id == tenant_id,
            NativeControlIntegration.id == observation.native_integration_id,
        )
    )
    evidence_id = observation.signed_evidence_ref.removeprefix("evidence:")
    evidence = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == evidence_id,
        )
    )
    evidence_payload = evidence.payload if evidence is not None and isinstance(evidence.payload, Mapping) else {}
    if (
        integration is None
        or str(integration.state).lower() in {"disabled", "unhealthy"}
        or evidence is None
        or evidence_payload.get("integration_id") != integration.id
        or evidence_payload.get("repository_root_hash") != observation.canonical_root_sha256
        or evidence_payload.get("repository_common_dir_hash") != observation.common_dir_sha256
    ):
        raise ValueError("signed repository observation evidence is unavailable")
    if (
        repository.evidence_state != "CONFIRMED"
        or repository.visibility != "PRIVATE"
        or repository.lifecycle_state != "ACTIVE"
        or not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository)
    ):
        raise ValueError("active runtime binding requires current confirmed private repository governance")
    result = db.execute(
        update(GitHubRepositoryRuntimeBinding)
        .where(
            GitHubRepositoryRuntimeBinding.tenant_id == tenant_id,
            GitHubRepositoryRuntimeBinding.id == observation.id,
            GitHubRepositoryRuntimeBinding.state == "OBSERVED",
            GitHubRepositoryRuntimeBinding.repository_id.is_(None),
        )
        .values(repository_id=repository.id, state="ACTIVE", actor_id=actor_id)
    )
    if result.rowcount != 1:
        raise ValueError("repository observation is no longer available")
    result = db.execute(update(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.id == repository.id, GitHubRepository.governance_version == expected_governance_version).values(governance_version=expected_governance_version + 1))
    if result.rowcount != 1:
        raise ValueError("governance version conflict")
    db.flush()
    db.refresh(observation)
    return observation


def revoke_github_repository_runtime(db: Session, *, tenant_id: str, binding_id: str, expected_governance_version: int, actor_id: str | None) -> GitHubRepositoryRuntimeBinding:
    binding = db.scalar(select(GitHubRepositoryRuntimeBinding).where(GitHubRepositoryRuntimeBinding.tenant_id == tenant_id, GitHubRepositoryRuntimeBinding.id == binding_id))
    if binding is None:
        raise ValueError("runtime binding not found")
    repository = get_github_repository_detail(db, tenant_id=tenant_id, repository_id=binding.repository_id)
    result = db.execute(update(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.id == repository.id, GitHubRepository.governance_version == expected_governance_version).values(governance_version=expected_governance_version + 1))
    if result.rowcount != 1:
        raise ValueError("governance version conflict")
    binding.state = "REVOKED"
    binding.actor_id = actor_id
    db.flush()
    return binding


def observe_github_repository_runtime(
    db: Session,
    *,
    tenant_id: str,
    native_integration_id: str,
    repository_fields: Mapping[str, object],
    signed_evidence_ref: str,
) -> GitHubRepositoryRuntimeBinding | None:
    """Persist only hash identities carried by an authenticated callback."""
    resolution = _text(repository_fields.get("repository_control_resolution")).lower()
    operation = _text(repository_fields.get("repository_operation")).upper()
    if resolution not in {"resolved", "blocked"} or operation not in _RUNTIME_OPERATIONS:
        return None
    root_hash = _validate_runtime_hash(_text(repository_fields.get("repository_root_hash")), "repository_root_hash")
    common_hash = _validate_runtime_hash(_text(repository_fields.get("repository_common_dir_hash")), "repository_common_dir_hash")
    _validate_runtime_hash(_text(repository_fields.get("repository_target_hash")), "repository_target_hash")
    evidence_ref = _text(signed_evidence_ref)
    if not evidence_ref.startswith("evidence:"):
        raise ValueError("signed callback evidence reference is required")
    integration = db.scalar(
        select(NativeControlIntegration).where(
            NativeControlIntegration.tenant_id == tenant_id,
            NativeControlIntegration.id == native_integration_id,
        )
    )
    if integration is None:
        raise ValueError("signed native integration is not available in this tenant")
    current = db.scalar(
        select(GitHubRepositoryRuntimeBinding).where(
            GitHubRepositoryRuntimeBinding.tenant_id == tenant_id,
            GitHubRepositoryRuntimeBinding.native_integration_id == integration.id,
            GitHubRepositoryRuntimeBinding.canonical_root_sha256 == root_hash,
            GitHubRepositoryRuntimeBinding.common_dir_sha256 == common_hash,
        )
    )
    if current is None:
        current = GitHubRepositoryRuntimeBinding(
            tenant_id=tenant_id,
            repository_id=None,
            native_integration_id=integration.id,
            canonical_root_sha256=root_hash,
            common_dir_sha256=common_hash,
            scope="EXACT_FOLDER",
            state="OBSERVED",
            signed_evidence_ref=evidence_ref,
        )
        db.add(current)
    else:
        # Re-observation refreshes evidence, never reactivates or resurrects a
        # revoked binding.
        current.signed_evidence_ref = evidence_ref
    db.flush()
    return current


def resolve_repository_control_floor(
    db: Session,
    *,
    tenant_id: str,
    native_integration_id: str,
    repository_fields: Mapping[str, object],
) -> dict[str, object] | None:
    """Return a monotonic floor for one explicit signed local operation."""
    history = list(
        db.scalars(
            select(GitHubRepositoryRuntimeBinding).where(
                GitHubRepositoryRuntimeBinding.tenant_id == tenant_id,
                GitHubRepositoryRuntimeBinding.native_integration_id == native_integration_id,
            )
        )
    )
    if not history:
        return None

    def block(reason: str, operation: str | None = None) -> dict[str, object]:
        return {"decision": "BLOCK", "reason": reason, "operation": operation}

    resolution = _text(repository_fields.get("repository_control_resolution")).lower()
    operation = _text(repository_fields.get("repository_operation")).upper()
    if resolution != "resolved" or operation not in _RUNTIME_OPERATIONS:
        return block("repository_runtime_target_unresolved", operation or None)
    try:
        root_hash = _validate_runtime_hash(_text(repository_fields.get("repository_root_hash")), "repository_root_hash")
        common_hash = _validate_runtime_hash(_text(repository_fields.get("repository_common_dir_hash")), "repository_common_dir_hash")
        _validate_runtime_hash(_text(repository_fields.get("repository_target_hash")), "repository_target_hash")
    except ValueError:
        return block("repository_runtime_target_unresolved", operation)
    binding = next(
        (
            row
            for row in history
            if row.canonical_root_sha256 == root_hash
            and row.common_dir_sha256 == common_hash
        ),
        None,
    )
    if binding is None or binding.scope != "EXACT_FOLDER" or binding.state != "ACTIVE" or not binding.repository_id:
        return block("repository_runtime_binding_required", operation)
    repository = db.scalar(
        select(GitHubRepository).where(
            GitHubRepository.tenant_id == tenant_id,
            GitHubRepository.id == binding.repository_id,
        )
    )
    if repository is None:
        return block("repository_governance_not_current", operation)
    controls = repository.operation_controls_json if isinstance(repository.operation_controls_json, Mapping) else {}
    if str(controls.get(operation, "BLOCK")).upper() != "ALLOW":
        return block("repository_operation_blocked", operation)
    if (
        repository.evidence_state != "CONFIRMED"
        or repository.visibility != "PRIVATE"
        or repository.lifecycle_state != "ACTIVE"
        or repository.last_verified_at is None
        or _at(repository.last_verified_at) > datetime.now(UTC)
        or not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository)
    ):
        return block("repository_governance_not_current", operation)
    if operation in {"PUSH", "PULL"}:
        destination_hash = _text(repository_fields.get("repository_destination_hash")).lower()
        expected_destination_hash = hashlib.sha256(
            f"{repository.host.lower()}/{repository.full_name.lower()}".encode("utf-8")
        ).hexdigest()
        if not _RUNTIME_HASH_RE.fullmatch(destination_hash) or destination_hash != expected_destination_hash:
            return block("repository_destination_mismatch", operation)
    return {"decision": "UNCHANGED", "reason": "repository_operation_allowed", "operation": operation}


def save_github_repository_operation_controls(db: Session, *, tenant_id: str, repository_id: str, controls: Mapping[str, object], expected_governance_version: int, actor_user_id: str | None = None) -> GitHubRepository:
    repository = get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository_id)
    if set(controls) != _RUNTIME_OPERATIONS:
        raise ValueError("all five repository operation controls are required")
    normalized = {operation: str(controls[operation]).upper() for operation in _RUNTIME_OPERATIONS}
    if set(normalized.values()) - {"ALLOW", "BLOCK"}:
        raise ValueError("repository operation controls must be ALLOW or BLOCK")
    if "ALLOW" in normalized.values() and (
        repository.evidence_state != "CONFIRMED"
        or repository.visibility != "PRIVATE"
        or repository.lifecycle_state != "ACTIVE"
        or repository.last_verified_at is None
        or _at(repository.last_verified_at) > datetime.now(UTC)
        or not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository)
    ):
        raise ValueError("ALLOW requires current confirmed private repository governance")
    result = db.execute(update(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.id == repository.id, GitHubRepository.governance_version == expected_governance_version).values(operation_controls_json=normalized, governance_version=expected_governance_version + 1))
    if result.rowcount != 1:
        raise ValueError("governance version conflict")
    write_audit_log(db, tenant_id=tenant_id, actor_user_id=actor_user_id, actor_type="human", action="github_repository.operation_controls_updated", resource_type="github_repository", resource_id=repository.id, payload={"operations": normalized, "governance_version": expected_governance_version + 1})
    db.flush()
    return get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository.id)


def _assignment_matches_repository(assignment: PolicyPackAssignment, repository_id: str) -> bool:
    targets = assignment.targets if isinstance(assignment.targets, Mapping) else {}
    values = targets.get("resource")
    return isinstance(values, list) and repository_id in {str(value) for value in values}


def _current_repository_policy_assignment(db: Session, *, tenant_id: str, repository: GitHubRepository, assignment_id: str) -> tuple[PolicyPackAssignment, PolicyPackInstance, PolicyVersion] | None:
    assignment = db.scalar(select(PolicyPackAssignment).where(PolicyPackAssignment.tenant_id == tenant_id, PolicyPackAssignment.id == assignment_id, PolicyPackAssignment.active.is_(True)))
    if assignment is None or not _assignment_matches_repository(assignment, repository.id):
        return None
    instance = db.scalar(select(PolicyPackInstance).where(PolicyPackInstance.tenant_id == tenant_id, PolicyPackInstance.id == assignment.instance_id, PolicyPackInstance.state.in_({"APPROVAL_ENFORCED", "ENFORCED"})))
    if instance is None or not instance.runtime_policy_pack_id or not instance.effective_policy_version_id:
        return None
    definition = db.scalar(select(PolicyPackDefinition).where(PolicyPackDefinition.id == instance.definition_id, PolicyPackDefinition.state == "PUBLISHED"))
    if definition is None:
        return None
    version = db.scalar(select(PolicyVersion).where(PolicyVersion.tenant_id == tenant_id, PolicyVersion.id == instance.effective_policy_version_id, PolicyVersion.pack_id == instance.runtime_policy_pack_id))
    pack = db.scalar(select(PolicyPack).where(PolicyPack.tenant_id == tenant_id, PolicyPack.id == instance.runtime_policy_pack_id, PolicyPack.status.in_({"active", "published"})))
    return (assignment, instance, version) if version is not None and pack is not None else None


def _repository_account_scope_kind(repository: GitHubRepository) -> str:
    protection = repository.protection_json if isinstance(repository.protection_json, Mapping) else {}
    scope = _text(protection.get("account_scope_kind"), "ORGANIZATION").upper()
    return scope if scope in {"ORGANIZATION", "PERSONAL"} else "UNKNOWN"


def update_github_repository_governance(
    db: Session,
    *,
    tenant_id: str,
    repository_id: str,
    decision: str,
    expected_governance_version: int,
    assignment_id: str | None,
    actor_user_id: str | None,
    deny_posture: str | None = None,
) -> GitHubRepository:
    repository = get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository_id)
    requested = _text(decision).upper()
    if requested not in {"APPROVED", "UNAPPROVED"}:
        raise ValueError("invalid governance decision")
    requested_deny_posture = _text(deny_posture).upper() or None
    if requested_deny_posture is not None and requested_deny_posture not in {"BLOCK_CHANGES", "BLOCK_ALL"}:
        raise ValueError("invalid personal repository deny posture")
    if requested == "APPROVED" and requested_deny_posture is not None:
        raise ValueError("deny posture is only valid with UNAPPROVED")
    if requested_deny_posture is not None and _repository_account_scope_kind(repository) != "PERSONAL":
        raise ValueError("deny posture requires a source-backed personal GitHub repository")
    values: dict[str, object] = {"governance_state": "UNAPPROVED", "approved_scope_ref": None, "policy_mapping_ref": None, "policy_current": False, "read_posture": "BLOCK", "governance_version": expected_governance_version + 1}
    if requested_deny_posture == "BLOCK_CHANGES":
        values["read_posture"] = "ALLOW"
    if requested == "APPROVED":
        if repository.evidence_state != "CONFIRMED" or repository.visibility != "PRIVATE" or repository.lifecycle_state != "ACTIVE" or not assignment_id:
            raise ValueError("current repository policy assignment required")
        current = _current_repository_policy_assignment(db, tenant_id=tenant_id, repository=repository, assignment_id=assignment_id)
        if current is None:
            raise ValueError("current repository policy assignment required")
        assignment, _instance, version = current
        values.update({"governance_state": "APPROVED", "approved_scope_ref": assignment.id, "policy_mapping_ref": version.id, "policy_current": True, "read_posture": repository.read_posture})
    result = db.execute(update(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.id == repository.id, GitHubRepository.governance_version == expected_governance_version).values(**values))
    if result.rowcount != 1:
        raise ValueError("governance version conflict")
    write_audit_log(db, tenant_id=tenant_id, actor_user_id=actor_user_id, actor_type="human", action="github_repository.governance_updated", resource_type="github_repository", resource_id=repository.id, payload={"decision": requested, "deny_posture": requested_deny_posture, "governance_version": expected_governance_version + 1, "assignment_id": assignment_id if requested == "APPROVED" else None})
    db.flush()
    return get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository.id)


def _repository_governance_is_current(db: Session, *, tenant_id: str, repository: GitHubRepository) -> bool:
    if repository.governance_state != "APPROVED" or not repository.policy_current or not repository.approved_scope_ref or not repository.policy_mapping_ref:
        return False
    current = _current_repository_policy_assignment(db, tenant_id=tenant_id, repository=repository, assignment_id=repository.approved_scope_ref)
    return current is not None and current[2].id == repository.policy_mapping_ref


def list_github_developers(db: Session, *, tenant_id: str, limit: int = 100, cursor: str | None = None, filters: Mapping[str, object] | None = None) -> dict[str, object]:
    statement = select(GitHubRepositoryAccess).where(GitHubRepositoryAccess.tenant_id == tenant_id)
    filters = filters or {}
    if access_path := _text(filters.get("access_path")):
        statement = statement.where(GitHubRepositoryAccess.access_path == access_path.upper())
    if principal_type := _text(filters.get("principal_type")):
        statement = statement.where(GitHubRepositoryAccess.principal_type == principal_type.upper())
    if repository_id := _text(filters.get("repository_id")):
        statement = statement.where(GitHubRepositoryAccess.repository_id == repository_id)
    return _bounded_page(db, statement, GitHubRepositoryAccess, limit=limit, cursor=cursor)


def list_github_ai_connections(db: Session, *, tenant_id: str, limit: int = 100, cursor: str | None = None, filters: Mapping[str, object] | None = None) -> dict[str, object]:
    statement = select(GitHubRepositoryAIConnection).where(GitHubRepositoryAIConnection.tenant_id == tenant_id)
    filters = filters or {}
    if provider := _text(filters.get("provider")):
        statement = statement.where(GitHubRepositoryAIConnection.provider == provider)
    if model := _text(filters.get("model")):
        statement = statement.where(GitHubRepositoryAIConnection.model == model)
    if agent_id := _text(filters.get("agent_id")):
        statement = statement.where(GitHubRepositoryAIConnection.agent_id == agent_id)
    if repository_id := _text(filters.get("repository_id")):
        statement = statement.where(GitHubRepositoryAIConnection.repository_id == repository_id)
    return _bounded_page(db, statement, GitHubRepositoryAIConnection, limit=limit, cursor=cursor)


_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?::[0-9]{1,5})?$")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98})$")
_REPOSITORY_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_REFERENCE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def resolve_current_repository_identity(db: Session, *, tenant_id: str, host: str, owner: str, repository: str) -> GitHubRepository | None:
    """Resolve exactly one tenant repository by host and full name, or nothing.

    The full name is compared for case-insensitive *equality*, never as a LIKE
    pattern: a caller-supplied ``%`` or ``_`` must not widen the match to some
    other repository (CWE-943). Inputs outside GitHub's own name grammar and
    ambiguous matches resolve to nothing, so callers fail closed.
    """
    normalized_host = _text(host).lower()
    normalized_owner = _text(owner)
    normalized_name = _text(repository)
    if (
        not _HOST_RE.fullmatch(normalized_host)
        or not _OWNER_RE.fullmatch(normalized_owner)
        or not _REPOSITORY_NAME_RE.fullmatch(normalized_name)
        or normalized_name in {".", ".."}
    ):
        return None
    expected = f"{normalized_owner}/{normalized_name}".lower()
    rows = list(
        db.scalars(
            select(GitHubRepository)
            .where(
                GitHubRepository.tenant_id == tenant_id,
                GitHubRepository.host == normalized_host,
                func.lower(GitHubRepository.full_name) == expected,
            )
            .limit(2)
        )
    )
    return rows[0] if len(rows) == 1 else None


def derive_github_repository_ai_connections(db: Session, *, tenant_id: str, limit: int = 200) -> int:
    """Project only signed/action evidence that names a current repository identity.

    This deliberately does not infer a relationship from a model or client alone.
    A caller must have stored an evidence reference and a repository locator.
    """
    bounded = max(1, min(int(limit), 200))
    actions = list(
        db.scalars(
            select(AIAction)
            .where(AIAction.tenant_id == tenant_id, AIAction.evidence_bundle_id.is_not(None))
            .order_by(AIAction.action_id.asc())
            .limit(bounded)
        )
    )
    derived = 0
    for action in actions:
        metadata = action.metadata_json if isinstance(action.metadata_json, Mapping) else {}
        # The evidence reference comes from a row of this tenant and is bound as
        # a query parameter (never interpolated); it is also checked against the
        # bounded identifier grammar and the lookup is tenant-scoped, so another
        # tenant's evidence can never be read here (CWE-943 review).
        evidence_bundle_id = action.evidence_bundle_id
        if not isinstance(evidence_bundle_id, str) or not _REFERENCE_ID_RE.fullmatch(evidence_bundle_id):
            continue
        evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id == evidence_bundle_id))
        evidence_payload = evidence.payload if evidence is not None and isinstance(evidence.payload, Mapping) else {}
        source_binding = evidence_payload.get("source_binding") if isinstance(evidence_payload.get("source_binding"), Mapping) else {}
        if (
            evidence is None
            or evidence.node_type != "source_evidence_bundle"
            or evidence.signal_type != "github_repository_activity"
            or _text(evidence_payload.get("acceptance_state")).upper() != "ACCEPTED"
            or evidence_payload.get("current") is not True
            or _text(source_binding.get("tenant_id")) != tenant_id
            or _text(source_binding.get("action_id")) != action.action_id
        ):
            continue
        repository_locator = _text(source_binding.get("repository"))
        locator = _repository_locator(repository_locator)
        if locator is None:
            continue
        host, owner, name = locator
        repository = resolve_current_repository_identity(db, tenant_id=tenant_id, host=host, owner=owner, repository=name)
        if repository is None:
            continue
        session = db.scalar(select(AISession).where(AISession.tenant_id == tenant_id, AISession.session_id == action.session_id))
        if _text(source_binding.get("repository")) != _text(metadata.get("repository")):
            continue
        relationship_state = _state(evidence_payload.get("relationship_state"))
        persist_github_inventory_unit(
            db,
            tenant_id=tenant_id,
            connection_id=None,
            record={
                "record_kind": "github_repository_ai_connection",
                "observed_at": action.timestamp,
                "identifiers": {"repository_id": repository.id},
                "metadata": {
                    "user_id": action.user_id,
                    "provider": _text(metadata.get("provider")) or None,
                    "model": action.ai_model or (session.ai_model if session else None),
                    "client_name": action.ai_app or (session.ai_app if session else None),
                    "agent_id": _text(metadata.get("agent_id")) or None,
                    "mcp_server_id": _text(metadata.get("mcp_server_id")) or None,
                    "external_capability_id": _text(metadata.get("external_capability_id")) or None,
                    "tool_name": _text(metadata.get("tool_name")) or None,
                    "tool_schema_fingerprint": _text(metadata.get("tool_schema_fingerprint")) or None,
                    "source_surface": _text(source_binding.get("source_surface"), session.source_surface if session else "UNKNOWN"),
                    "relationship_state": relationship_state,
                    "confidence": _state(evidence_payload.get("confidence") or relationship_state),
                    "evidence_refs": [str(action.evidence_bundle_id), str(action.action_id)],
                    "action_count": 1,
                },
            },
        )
        derived += 1
    return derived


def _repository_locator(resource: str) -> tuple[str, str, str] | None:
    value = _text(resource).removeprefix("https://").removeprefix("http://").removeprefix("git@").replace(":", "/", 1).rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    parts = [part for part in value.split("/") if part]
    if len(parts) < 3:
        return None
    return parts[-3].lower(), parts[-2], parts[-1]


# ---------------------------------------------------------------------------
# AI agent repository mutations: posture, change rules and bound approvals
# ---------------------------------------------------------------------------

_READ_ACTIONS = frozenset({"REPOSITORY_READ", "REPOSITORY_PULL", "REPOSITORY_CLONE", "REPOSITORY_FETCH"})
# Never performed by an AI agent, approved or not: they change who can see,
# own or protect the repository, or rewrite its history.
_ALWAYS_BLOCKED_ACTIONS = frozenset({
    "REPOSITORY_FORCE_PUSH", "REPOSITORY_DELETE", "REPOSITORY_TRANSFER", "REPOSITORY_VISIBILITY_CHANGE",
    "REPOSITORY_FORK", "REPOSITORY_ARCHIVE", "REPOSITORY_CREATE", "REPOSITORY_SECRET_CHANGE",
    "REPOSITORY_ADMIN_CHANGE", "REPOSITORY_SETTINGS_CHANGE", "REPOSITORY_COLLABORATOR_CHANGE",
    "REPOSITORY_BRANCH_PROTECTION_CHANGE", "REPOSITORY_RULESET_CHANGE", "REPOSITORY_WEBHOOK_CHANGE",
    "REPOSITORY_DEPLOY_KEY_CHANGE", "REPOSITORY_REMOTE_ADD", "REPOSITORY_REMOTE_CHANGE",
})
# The pull-request flow: allowed without a per-action approval only under the
# PULL_REQUEST_ONLY posture, and only away from protected branches and paths.
_PULL_REQUEST_FLOW_ACTIONS = frozenset({
    "REPOSITORY_BRANCH_CREATE", "REPOSITORY_PUSH", "REPOSITORY_PULL_REQUEST_CREATE",
    "REPOSITORY_PULL_REQUEST_UPDATE", "REPOSITORY_PULL_REQUEST_COMMENT",
})
# Always need a bound approval (they land, publish or bless changes).
_APPROVAL_ONLY_ACTIONS = frozenset({
    "REPOSITORY_PULL_REQUEST_MERGE", "REPOSITORY_PULL_REQUEST_APPROVE", "REPOSITORY_WORKFLOW_CHANGE",
    "REPOSITORY_TAG_CREATE", "REPOSITORY_RELEASE_CREATE", "REPOSITORY_BRANCH_DELETE",
})
_WRITE_ACTIONS = _PULL_REQUEST_FLOW_ACTIONS | _APPROVAL_ONLY_ACTIONS
_BRANCH_TARGET_ACTIONS = frozenset({"REPOSITORY_PUSH", "REPOSITORY_BRANCH_CREATE", "REPOSITORY_BRANCH_DELETE"})

_WRITE_MODES = frozenset({"APPROVAL_REQUIRED", "PULL_REQUEST_ONLY", "READ_ONLY"})
_DEFAULT_AGENT_POLICY: dict[str, Any] = {
    "write_mode": "APPROVAL_REQUIRED",
    "protected_branches": [],
    "approval_required_paths": [],
    "blocked_paths": [],
    "max_files_changed": 100,
    "max_bytes_changed": 1_000_000,
    "max_mutations_per_minute": 30,
}
_AGENT_POLICY_BOUNDS = {"max_files_changed": (1, 1000), "max_bytes_changed": (1, 5_000_000), "max_mutations_per_minute": (1, 600)}
_RATE_WINDOW_SECONDS = 60
_MAX_CHANGE_PATHS = 1000
_MAX_SCANNED_CHANGE_BYTES = 5_000_000

# Files whose change by an agent is refused outright (credentials and state).
_BLOCKED_PATH_PATTERNS = (
    ".env", ".env.*", "*/.env", "*/.env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "*.kdbx",
    "id_rsa*", "*/id_rsa*", "id_dsa*", "*/id_dsa*", "id_ecdsa*", "*/id_ecdsa*", "id_ed25519*", "*/id_ed25519*",
    ".ssh/*", "*/.ssh/*", ".npmrc", "*/.npmrc", ".pypirc", "*/.pypirc", ".netrc", "*/.netrc", ".git-credentials",
    "*/.git-credentials", ".dockercfg", "*/.dockercfg", ".docker/config.json", "*/.docker/config.json",
    "credentials.json", "*/credentials.json", "secrets.*", "*/secrets.*", "*.secrets", "*.tfstate", "*.tfstate.*",
)
# Files that steer CI, code ownership or infrastructure: held for approval.
_APPROVAL_PATH_PATTERNS = (
    ".github/workflows/*", ".github/actions/*", ".github/codeowners", "codeowners", "docs/codeowners",
    ".gitlab-ci.yml", ".circleci/*", "jenkinsfile", "azure-pipelines.yml", ".buildkite/*",
    "*.tf", "*.tfvars", "*.hcl", "terraform/*", "*/terraform/*", "*.bicep", "cdk.json", "pulumi.yaml", "pulumi.*.yaml",
    "cloudformation/*", "*/cloudformation/*", "infra/*", "iac/*", "k8s/*", "kubernetes/*", "helm/*", "charts/*",
)
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_GLOB_RE = re.compile(r"^[A-Za-z0-9._/*?\[\]-]{1,512}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_EXTRA_SECRET_PATTERNS = (
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
)

_APPROVAL_MAC_DOMAIN = "github_repository_mutation_approval"
_APPROVAL_MAC_VERSION = "ghrma-v1"
_APPROVAL_DEFAULT_TTL_SECONDS = 900
_APPROVAL_MAX_TTL_SECONDS = 3600


def _bounded_int(value: object, *, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not (low <= value <= high):
        raise ValueError("agent policy limit out of range")
    return value


def _normalized_patterns(value: object, *, field: str, pattern: re.Pattern[str]) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)) or len(value) > 64:
        raise ValueError(f"{field} must be a list of at most 64 patterns")
    result: list[str] = []
    for item in value:
        text = _text(item)
        if not pattern.fullmatch(text) or ".." in text:
            raise ValueError(f"{field} contains an invalid pattern")
        result.append(text.lower() if pattern is _GLOB_RE else text)
    return sorted(set(result))


def normalize_github_agent_policy(policy: Mapping[str, object] | None) -> dict[str, Any]:
    """Validate an owner/admin agent policy; it may only add to the built-in rules."""
    raw = dict(policy or {})
    unknown = set(raw) - set(_DEFAULT_AGENT_POLICY)
    if unknown:
        raise ValueError("unknown agent policy field")
    result = dict(_DEFAULT_AGENT_POLICY)
    write_mode = _text(raw.get("write_mode"), _DEFAULT_AGENT_POLICY["write_mode"]).upper()
    if write_mode not in _WRITE_MODES:
        raise ValueError("write_mode must be APPROVAL_REQUIRED, PULL_REQUEST_ONLY or READ_ONLY")
    result["write_mode"] = write_mode
    result["protected_branches"] = _normalized_patterns(raw.get("protected_branches"), field="protected_branches", pattern=re.compile(r"^[A-Za-z0-9._/*?-]{1,255}$"))
    result["approval_required_paths"] = _normalized_patterns(raw.get("approval_required_paths"), field="approval_required_paths", pattern=_GLOB_RE)
    result["blocked_paths"] = _normalized_patterns(raw.get("blocked_paths"), field="blocked_paths", pattern=_GLOB_RE)
    for key, (low, high) in _AGENT_POLICY_BOUNDS.items():
        if key in raw and raw[key] is not None:
            result[key] = _bounded_int(raw[key], low=low, high=high)
    return result


def _agent_policy(repository: GitHubRepository) -> dict[str, Any]:
    stored = repository.agent_policy_json if isinstance(repository.agent_policy_json, Mapping) else {}
    try:
        return normalize_github_agent_policy(stored)
    except ValueError:
        # A stored policy that no longer validates falls back to the strictest
        # posture rather than to an unvalidated one.
        return {**_DEFAULT_AGENT_POLICY, "write_mode": "READ_ONLY"}


def save_github_repository_agent_policy(db: Session, *, tenant_id: str, repository_id: str, policy: Mapping[str, object], expected_governance_version: int, actor_user_id: str | None = None) -> GitHubRepository:
    repository = get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository_id)
    normalized = normalize_github_agent_policy(policy)
    if normalized["write_mode"] == "PULL_REQUEST_ONLY" and (
        repository.evidence_state != "CONFIRMED"
        or repository.visibility != "PRIVATE"
        or repository.lifecycle_state != "ACTIVE"
        or not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository)
    ):
        raise ValueError("PULL_REQUEST_ONLY requires current confirmed private repository governance")
    # Bumping the governance version also invalidates every outstanding bound
    # approval for this repository (the version is part of each approval MAC).
    result = db.execute(update(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.id == repository.id, GitHubRepository.governance_version == expected_governance_version).values(agent_policy_json=normalized, governance_version=expected_governance_version + 1))
    if result.rowcount != 1:
        raise ValueError("governance version conflict")
    write_audit_log(db, tenant_id=tenant_id, actor_user_id=actor_user_id, actor_type="human", action="github_repository.agent_policy_updated", resource_type="github_repository", resource_id=repository.id, payload={"agent_policy": normalized, "governance_version": expected_governance_version + 1})
    db.flush()
    return get_github_repository_detail(db, tenant_id=tenant_id, repository_id=repository.id)


def _normalized_branch(value: object) -> tuple[str | None, bool]:
    """Return (branch, valid). ``None`` with valid=True means no branch was given."""
    if value is None or _text(value) == "":
        return None, True
    branch = _text(value).removeprefix("refs/heads/")
    if not _BRANCH_RE.fullmatch(branch) or ".." in branch or branch.startswith(("/", "-", ".")) or branch.endswith(("/", ".lock", ".")) or "//" in branch:
        return None, False
    return branch, True


def _normalized_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    path = value.strip().replace("\\", "/")
    if not path or len(path) > 1024 or "\x00" in path or path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        return None
    parts = [part for part in path.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts) or parts[0].lower() == ".git":
        return None
    return "/".join(parts)


def _content_fingerprint(pairs: list[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(pairs):
        digest.update(json.dumps([path, hashlib.sha256(content.encode("utf-8")).hexdigest()], separators=(",", ":")).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def github_repository_change_context(parameters: Mapping[str, object] | None, declared: Mapping[str, object] | None = None) -> dict[str, Any]:
    """Derive the change facts used for decisions from the tool arguments.

    Declared stats (sent by the Hawk MCP proxy) can only make the result
    stricter: counts take the larger of declared and computed, paths are the
    union. Contents are used for the secret scan and the fingerprint only and
    are never returned or stored.
    """
    params = parameters if isinstance(parameters, Mapping) else {}
    claims = declared if isinstance(declared, Mapping) else {}
    raw_paths: list[object] = []
    pairs: list[tuple[str, str]] = []
    texts: list[str] = []
    invalid_paths = 0
    if "path" in params:
        raw_paths.append(params.get("path"))
        if isinstance(params.get("content"), str):
            normalized = _normalized_path(params.get("path"))
            if normalized:
                pairs.append((normalized, str(params["content"])))
    files = params.get("files")
    if isinstance(files, list):
        for item in files[: _MAX_CHANGE_PATHS + 1]:
            if not isinstance(item, Mapping):
                invalid_paths += 1
                continue
            raw_paths.append(item.get("path"))
            normalized = _normalized_path(item.get("path"))
            if normalized and isinstance(item.get("content"), str):
                pairs.append((normalized, str(item["content"])))
    declared_paths = claims.get("paths")
    if isinstance(declared_paths, list):
        raw_paths.extend(declared_paths[: _MAX_CHANGE_PATHS + 1])
    paths: set[str] = set()
    for raw in raw_paths:
        normalized = _normalized_path(raw)
        if normalized is None:
            invalid_paths += 1
        else:
            paths.add(normalized)
    declared_invalid = claims.get("invalid_paths")
    if isinstance(declared_invalid, int) and not isinstance(declared_invalid, bool) and declared_invalid > 0:
        invalid_paths += declared_invalid
    for _path, content in pairs:
        texts.append(content)
    for key in ("body", "title", "message"):
        if isinstance(params.get(key), str):
            texts.append(str(params[key]))
    computed_bytes = sum(len(content.encode("utf-8")) for _path, content in pairs)

    def _declared_int(key: str) -> int:
        value = claims.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    declared_sha = _text(claims.get("content_sha256")).lower()
    content_sha256 = _content_fingerprint(pairs) if pairs else (declared_sha if _SHA256_RE.fullmatch(declared_sha) else None)
    return {
        "paths": sorted(paths)[:_MAX_CHANGE_PATHS],
        "paths_truncated": len(paths) > _MAX_CHANGE_PATHS,
        "invalid_paths": invalid_paths,
        "files_changed": max(len(paths), _declared_int("files_changed")),
        "bytes_changed": max(computed_bytes, _declared_int("bytes_changed")),
        "content_sha256": content_sha256,
        "_texts": texts,
    }


def _secret_findings(texts: list[str]) -> dict[str, int]:
    """Count secret detections with the platform DLP detectors; never return values."""
    from app.services.ai_iam_service import SECRET_PATTERNS
    from app.services.sensitive_data_detection_service import LONG_SECRET_PATTERN

    findings: dict[str, int] = {}
    budget = _MAX_SCANNED_CHANGE_BYTES
    detectors = (("dlp_prefixed_secret", LONG_SECRET_PATTERN), *((f"dlp_secret_pattern_{index}", pattern) for index, pattern in enumerate(SECRET_PATTERNS)), *((f"credential_format_{index}", pattern) for index, pattern in enumerate(_EXTRA_SECRET_PATTERNS)))
    for text in texts:
        if budget <= 0:
            findings["scan_budget_exhausted"] = 1
            break
        sample = text[:budget]
        budget -= len(sample)
        for name, pattern in detectors:
            count = sum(1 for _ in pattern.finditer(sample))
            if count:
                findings[name] = findings.get(name, 0) + count
    return findings


def _path_matches(path: str, patterns: tuple[str, ...] | list[str]) -> bool:
    lowered = path.lower()
    return any(fnmatchcase(lowered, pattern) for pattern in patterns)


def _protected_branches(repository: GitHubRepository, policy: Mapping[str, Any]) -> list[str]:
    protection = repository.protection_json if isinstance(repository.protection_json, Mapping) else {}
    names = [repository.default_branch] if repository.default_branch else []
    discovered = protection.get("protected_branches")
    if isinstance(discovered, list):
        names.extend(_text(item) for item in discovered[:256] if _text(item))
    names.extend(policy.get("protected_branches") or [])
    return sorted(set(names))


def _agent_key(executing_principal: str | None, actor_id: str | None) -> str:
    return hashlib.sha256(f"github-agent:{_text(executing_principal) or _text(actor_id) or 'unidentified'}".encode("utf-8")).hexdigest()


def _recent_mutation_count(db: Session, *, tenant_id: str, agent_key: str, now: datetime) -> int:
    return int(
        db.scalar(
            select(func.count())
            .select_from(EvidenceNode)
            .where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.signal_type == "github_repository.agent_mutation_decision",
                EvidenceNode.correlation_id == agent_key,
                EvidenceNode.created_at >= now - timedelta(seconds=_RATE_WINDOW_SECONDS),
            )
        )
        or 0
    )


def _canonical_repository_action(
    *,
    repository: GitHubRepository,
    host: str,
    action: str,
    branch: str | None,
    actor_id: str | None,
    executing_principal: str | None,
    ai_system_id: str | None,
    provider: str | None,
    model: str | None,
    tool_fingerprint_id: str | None,
    tool_schema_fingerprint: str | None,
    change_digest: str | None,
    change: Mapping[str, Any],
) -> dict[str, Any]:
    """The exact action an approver approves; every field is MAC-bound."""
    return {
        "repository_row_id": repository.id,
        "repository_id": repository.external_repository_id,
        "host": host,
        "target": f"{host}/{repository.full_name.lower()}",
        "action": action,
        "branch": branch,
        "actor_id": _text(actor_id) or None,
        "executing_principal": _text(executing_principal) or None,
        "ai_system_id": _text(ai_system_id) or None,
        "provider": _text(provider) or None,
        "model": _text(model) or None,
        "tool_fingerprint_id": _text(tool_fingerprint_id) or None,
        "tool_schema_fingerprint": _text(tool_schema_fingerprint) or None,
        "change_digest": _text(change_digest) or None,
        "content_sha256": change.get("content_sha256"),
        "paths": list(change.get("paths") or []),
        "files_changed": int(change.get("files_changed") or 0),
        "bytes_changed": int(change.get("bytes_changed") or 0),
    }


def _approval_mac(*, tenant_id: str, grant_id: str, approval_request_id: str, governance_version: int, nonce: str, expires_at: datetime, canonical_action: Mapping[str, Any]) -> str:
    from app.core.control_engine.canonical_action import canonical_field_hash

    material = {
        "mac_version": _APPROVAL_MAC_VERSION,
        "grant_id": grant_id,
        "approval_request_id": approval_request_id,
        "tenant_id": tenant_id,
        "governance_version": int(governance_version),
        "nonce": nonce,
        "expires_at": _at(expires_at).isoformat(),
        "canonical_action": {key: canonical_action.get(key) for key in sorted(canonical_action)},
    }
    # HMAC-SHA256 under CANONICAL_ACTION_BINDING_KEY with tenant and purpose
    # separation; raises ValueError when the key is not configured.
    return canonical_field_hash(tenant_id, _APPROVAL_MAC_DOMAIN, material)


def issue_github_repository_mutation_approval(db: Session, *, tenant_id: str, approval_request_id: str, issued_by: str | None, approver_role: str | None, ttl_seconds: int = _APPROVAL_DEFAULT_TTL_SECONDS, now: datetime | None = None) -> GitHubRepositoryMutationApproval:
    """Bind an approved held repository mutation to a MAC, a nonce, an expiry and one use.

    The canonical action is the one stored server-side when the gateway held
    the mutation; the approver never types it, and the caller cannot change it.
    """
    issued_at = _at(now or datetime.now(UTC))
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not (60 <= ttl_seconds <= _APPROVAL_MAX_TTL_SECONDS):
        raise ValueError("ttl_seconds must be between 60 and 3600")
    if not _REFERENCE_ID_RE.fullmatch(_text(approval_request_id)):
        raise ValueError("approval request not found")
    request = db.scalar(select(ApprovalRequest).where(ApprovalRequest.tenant_id == tenant_id, ApprovalRequest.id == approval_request_id))
    if request is None:
        raise ValueError("approval request not found")
    if request.status != "approved" or request.decision != "approve":
        raise ValueError("approval request is not approved")
    required_roles = {_text(role).lower() for role in (request.required_roles if isinstance(request.required_roles, list) else []) if _text(role)}
    if not required_roles or _text(approver_role).lower() not in required_roles:
        raise PermissionError("role is not authorized for this approval")
    payload = request.request_payload if isinstance(request.request_payload, Mapping) else {}
    canonical = payload.get("github_repository_action")
    if not isinstance(canonical, Mapping) or not canonical.get("repository_row_id"):
        raise ValueError("approval request is not a held GitHub repository mutation")
    repository = get_github_repository_detail(db, tenant_id=tenant_id, repository_id=_text(canonical.get("repository_row_id")))
    if not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository):
        raise ValueError("repository governance is not current")
    if _text(canonical.get("action")).upper() in _ALWAYS_BLOCKED_ACTIONS:
        raise ValueError("this repository action is never approvable for AI agents")
    existing = db.scalar(select(GitHubRepositoryMutationApproval).where(GitHubRepositoryMutationApproval.tenant_id == tenant_id, GitHubRepositoryMutationApproval.approval_request_id == request.id))
    if existing is not None:
        raise ValueError("approval request already has a bound repository approval")
    grant_id = str(uuid4())
    nonce = secrets.token_hex(32)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    mac = _approval_mac(tenant_id=tenant_id, grant_id=grant_id, approval_request_id=request.id, governance_version=repository.governance_version, nonce=nonce, expires_at=expires_at, canonical_action=canonical)
    grant = GitHubRepositoryMutationApproval(
        id=grant_id, tenant_id=tenant_id, approval_request_id=request.id, repository_id=repository.id,
        action=_text(canonical.get("action")).upper()[:64], action_mac=mac, mac_version=_APPROVAL_MAC_VERSION,
        nonce=nonce, governance_version=repository.governance_version, expires_at=expires_at,
        use_limit=1, uses_consumed=0, state="ACTIVE", issued_by=issued_by,
    )
    db.add(grant)
    write_audit_log(db, tenant_id=tenant_id, actor_user_id=issued_by, actor_type="human", action="github_repository.mutation_approval_issued", resource_type="github_repository", resource_id=repository.id, payload={"approval_binding_id": grant_id, "approval_request_id": request.id, "action": grant.action, "expires_at": expires_at.isoformat(), "governance_version": repository.governance_version})
    db.flush()
    return grant


def revoke_github_repository_mutation_approval(db: Session, *, tenant_id: str, approval_binding_id: str, actor_user_id: str | None) -> GitHubRepositoryMutationApproval:
    grant = db.scalar(select(GitHubRepositoryMutationApproval).where(GitHubRepositoryMutationApproval.tenant_id == tenant_id, GitHubRepositoryMutationApproval.id == approval_binding_id))
    if grant is None:
        raise ValueError("repository approval not found")
    if grant.state == "ACTIVE":
        grant.state = "REVOKED"
        write_audit_log(db, tenant_id=tenant_id, actor_user_id=actor_user_id, actor_type="human", action="github_repository.mutation_approval_revoked", resource_type="github_repository", resource_id=grant.repository_id, payload={"approval_binding_id": grant.id})
    db.flush()
    return grant


def _verify_and_consume_mutation_approval(
    db: Session,
    *,
    tenant_id: str,
    approval_binding_id: str,
    repository: GitHubRepository,
    canonical_action: Mapping[str, Any],
    now: datetime,
) -> str:
    """Verify the approval MAC over the live canonical action and consume it once.

    This is where the approval binding is verified cryptographically (CWE-347):
    nothing caller-supplied or database-stored is compared field by field. The
    MAC is recomputed from the *current request's* canonical action plus the
    grant's nonce, expiry and governance version, compared in constant time,
    and the single use is consumed with a conditional UPDATE so two concurrent
    requests cannot both spend it. Returns "verified" or a failure code.
    """
    if not _REFERENCE_ID_RE.fullmatch(approval_binding_id):
        return "approval_binding_mismatch"
    grant = db.scalar(select(GitHubRepositoryMutationApproval).where(GitHubRepositoryMutationApproval.tenant_id == tenant_id, GitHubRepositoryMutationApproval.id == approval_binding_id))
    if grant is None or grant.repository_id != repository.id or grant.mac_version != _APPROVAL_MAC_VERSION:
        return "approval_binding_mismatch"
    if grant.state != "ACTIVE" or grant.uses_consumed >= grant.use_limit:
        return "approval_binding_consumed"
    if _at(grant.expires_at) <= now:
        return "approval_binding_expired"
    if grant.governance_version != repository.governance_version:
        return "approval_binding_mismatch"
    request = db.scalar(select(ApprovalRequest).where(ApprovalRequest.tenant_id == tenant_id, ApprovalRequest.id == grant.approval_request_id, ApprovalRequest.status == "approved", ApprovalRequest.decision == "approve"))
    if request is None:
        return "approval_binding_mismatch"
    try:
        expected = _approval_mac(tenant_id=tenant_id, grant_id=grant.id, approval_request_id=grant.approval_request_id, governance_version=repository.governance_version, nonce=grant.nonce, expires_at=grant.expires_at, canonical_action=canonical_action)
    except ValueError:
        return "approval_binding_mismatch"
    if not hmac.compare_digest(expected.encode("ascii"), _text(grant.action_mac).encode("ascii")):
        return "approval_binding_mismatch"
    consumed = db.execute(
        update(GitHubRepositoryMutationApproval)
        .where(
            GitHubRepositoryMutationApproval.tenant_id == tenant_id,
            GitHubRepositoryMutationApproval.id == grant.id,
            GitHubRepositoryMutationApproval.state == "ACTIVE",
            GitHubRepositoryMutationApproval.uses_consumed == grant.uses_consumed,
            GitHubRepositoryMutationApproval.uses_consumed < GitHubRepositoryMutationApproval.use_limit,
        )
        .values(uses_consumed=grant.uses_consumed + 1, state="CONSUMED", consumed_at=now)
        .execution_options(synchronize_session=False)
    )
    if consumed.rowcount != 1:
        return "approval_binding_consumed"
    return "verified"


def _record_decision_evidence(db: Session, *, tenant_id: str, result: Mapping[str, Any], evidence: Mapping[str, Any], mutation: bool, agent_key: str, now: datetime) -> str:
    node = EvidenceNode(
        tenant_id=tenant_id,
        correlation_id=agent_key,
        node_type="github_repository_decision",
        signal_type="github_repository.agent_mutation_decision" if mutation else "github_repository.agent_read_decision",
        label=f"GitHub repository {result.get('decision')} {result.get('reason')}"[:255],
        payload={"decision": result.get("decision"), "reason": result.get("reason"), "repository_id": result.get("repository_id"), **dict(evidence)},
        created_at=now,
        updated_at=now,
    )
    db.add(node)
    db.flush()
    return node.id


def evaluate_github_repository_mutation(
    db: Session,
    *,
    tenant_id: str,
    action: str,
    resource: str,
    branch: str | None = None,
    actor_id: str | None = None,
    ai_system_id: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    agent_id: str | None = None,
    tool_fingerprint_id: str | None = None,
    tool_schema_fingerprint: str | None = None,
    change_digest: str | None = None,
    approval_binding_id: str | None = None,
    change_parameters: Mapping[str, Any] | None = None,
    change_context: Mapping[str, Any] | None = None,
    record_evidence: bool = True,
    now: datetime | None = None,
) -> dict[str, object]:
    """Default-deny decision for one AI agent action on a GitHub repository.

    Returns ``decision``, ``reason`` and ``repository_id`` (stable keys and
    reason codes) plus ``evidence`` (every check made) and, when recorded,
    ``evidence_ref``. A HOLD also carries ``canonical_action``: the exact
    action an approver approves and a bound approval is MAC-checked against.
    """
    evaluated_at = _at(now or datetime.now(UTC))
    normalized_action = _text(action).upper()
    # change_parameters: the tool arguments (paths, contents, PR text);
    # change_context: stats declared by the Hawk MCP proxy (can only tighten).
    change = github_repository_change_context(change_parameters, change_context)
    texts = list(change.pop("_texts", []) or [])
    mutation = normalized_action not in _READ_ACTIONS
    agent_key = _agent_key(agent_id, actor_id)
    evidence: dict[str, Any] = {
        "schema": "hawk.github_repository_decision.v1",
        "evaluated_at": evaluated_at.isoformat(),
        "action": normalized_action,
        "target": _text(resource)[:512],
        "actor_id": _text(actor_id) or None,
        "executing_principal": _text(agent_id) or None,
        "ai_system_id": _text(ai_system_id) or None,
        "provider": _text(provider) or None,
        "model": _text(model) or None,
        "tool_fingerprint_id": _text(tool_fingerprint_id) or None,
        "tool_schema_fingerprint": _text(tool_schema_fingerprint) or None,
        "checks": [],
    }
    extra: dict[str, Any] = {}

    def finish(decision: str, reason: str, repository_id: str | None) -> dict[str, object]:
        result: dict[str, object] = {"decision": decision, "reason": reason, "repository_id": repository_id, **extra}
        if record_evidence:
            # A failure to record raises: no decision is returned without evidence.
            result["evidence_ref"] = _record_decision_evidence(db, tenant_id=tenant_id, result=result, evidence=evidence, mutation=mutation, agent_key=agent_key, now=evaluated_at)
        result["evidence"] = evidence
        return result

    def check(name: str, outcome: str, **details: Any) -> None:
        evidence["checks"].append({"check": name, "outcome": outcome, **details})

    locator = _repository_locator(resource)
    if locator is None:
        check("repository_identity", "unresolved")
        return finish("BLOCK", "repository_resolution_unavailable", None)
    host, owner, name = locator
    repository_row = resolve_current_repository_identity(db, tenant_id=tenant_id, host=host, owner=owner, repository=name)
    if repository_row is None:
        # Default deny: an unknown repository or organization is never governed.
        check("repository_identity", "unknown_or_ambiguous")
        return finish("BLOCK", "repository_resolution_unavailable", None)
    repository_id = repository_row.external_repository_id
    evidence.update({"repository_row_id": repository_row.id, "full_name": repository_row.full_name, "host": host, "governance_version": repository_row.governance_version, "policy_mapping_ref": repository_row.policy_mapping_ref, "approved_scope_ref": repository_row.approved_scope_ref})
    check("repository_identity", "resolved")
    if repository_row.evidence_state != "CONFIRMED" or repository_row.visibility != "PRIVATE" or repository_row.lifecycle_state != "ACTIVE":
        check("repository_state", "not_confirmed_private_active", visibility=repository_row.visibility, lifecycle_state=repository_row.lifecycle_state, evidence_state=repository_row.evidence_state)
        return finish("BLOCK", "repository_not_currently_approved", repository_id)
    check("repository_state", "confirmed_private_active")
    if not mutation:
        evidence["read_posture"] = repository_row.read_posture
        if repository_row.read_posture == "BLOCK":
            return finish("BLOCK", "repository_read_blocked", repository_id)
        if (
            repository_row.read_posture == "ALLOW"
            and repository_row.governance_state == "UNAPPROVED"
            and _repository_account_scope_kind(repository_row) == "PERSONAL"
        ):
            return finish("ALLOW", "personal_repository_read_only", repository_id)
        if repository_row.read_posture in {"ALLOW", "APPROVAL_REQUIRED"} and not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository_row):
            return finish("BLOCK", "repository_read_not_currently_approved", repository_id)
        if repository_row.read_posture == "ALLOW":
            return finish("ALLOW", "configured_repository_read", repository_id)
        if repository_row.read_posture == "APPROVAL_REQUIRED":
            return finish("HOLD_FOR_APPROVAL", "repository_read_approval_required", repository_id)
        return finish("BLOCK", "repository_read_posture_unconfigured", repository_id)

    if normalized_action in _ALWAYS_BLOCKED_ACTIONS:
        check("action_class", "admin_or_destructive")
        return finish("BLOCK", "repository_admin_action_blocked", repository_id)
    if normalized_action not in _WRITE_ACTIONS and not normalized_action.startswith("REPOSITORY_PULL_REQUEST_"):
        check("action_class", "unsupported")
        return finish("BLOCK", "repository_action_unsupported", repository_id)
    check("action_class", "write")
    if not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository_row):
        check("governance", "not_current")
        return finish("BLOCK", "repository_not_explicitly_eligible", repository_id)
    check("governance", "current")
    policy = _agent_policy(repository_row)
    evidence["agent_policy"] = policy
    if policy["write_mode"] == "READ_ONLY":
        check("write_posture", "read_only")
        return finish("BLOCK", "repository_write_not_permitted", repository_id)
    check("write_posture", policy["write_mode"].lower())

    recent = _recent_mutation_count(db, tenant_id=tenant_id, agent_key=agent_key, now=evaluated_at)
    evidence["rate"] = {"window_seconds": _RATE_WINDOW_SECONDS, "recent_mutations": recent, "limit": policy["max_mutations_per_minute"]}
    if recent >= policy["max_mutations_per_minute"]:
        check("agent_rate", "exceeded")
        return finish("BLOCK", "repository_agent_rate_limited", repository_id)
    check("agent_rate", "within_limit")

    normalized_branch, branch_valid = _normalized_branch(branch)
    evidence["branch"] = normalized_branch
    if not branch_valid:
        check("branch", "invalid")
        return finish("BLOCK", "repository_branch_invalid", repository_id)
    evidence["change"] = {key: change.get(key) for key in ("files_changed", "bytes_changed", "content_sha256", "invalid_paths", "paths_truncated")}
    evidence["change"]["paths"] = list(change.get("paths") or [])[:64]
    if change.get("invalid_paths") or change.get("paths_truncated"):
        check("paths", "invalid")
        return finish("BLOCK", "repository_path_invalid", repository_id)
    findings = _secret_findings(texts)
    evidence["secret_scan"] = {"detectors": "dlp", "findings": findings}
    if findings:
        check("secret_scan", "secret_detected")
        return finish("BLOCK", "repository_secret_in_change", repository_id)
    check("secret_scan", "clean" if texts else "no_content_supplied")
    paths = list(change.get("paths") or [])
    blocked_paths = [path for path in paths if _path_matches(path, _BLOCKED_PATH_PATTERNS) or _path_matches(path, policy["blocked_paths"])]
    if blocked_paths:
        evidence["blocked_paths"] = blocked_paths[:32]
        check("paths", "secret_or_blocked_file")
        return finish("BLOCK", "repository_secret_file_change_blocked", repository_id)

    approval_reasons: list[str] = []
    if normalized_action in _BRANCH_TARGET_ACTIONS:
        protected = _protected_branches(repository_row, policy)
        evidence["protected_branches"] = protected[:64]
        if normalized_branch is None:
            check("branch", "unresolved")
            return finish("BLOCK", "repository_branch_unresolved", repository_id)
        if not repository_row.default_branch:
            check("branch", "default_branch_unverified")
            return finish("BLOCK", "repository_default_branch_unverified", repository_id)
        if any(fnmatchcase(normalized_branch, pattern) for pattern in protected):
            # Agents change protected and default branches only through a pull
            # request; a direct push is refused even with an approval.
            check("branch", "protected")
            return finish("BLOCK", "repository_protected_branch_direct_push", repository_id)
        check("branch", "unprotected")
    approval_paths = [path for path in paths if _path_matches(path, _APPROVAL_PATH_PATTERNS) or _path_matches(path, policy["approval_required_paths"])]
    if approval_paths or normalized_action == "REPOSITORY_WORKFLOW_CHANGE":
        evidence["approval_paths"] = approval_paths[:32]
        approval_reasons.append("repository_protected_path_requires_approval")
    if int(change.get("files_changed") or 0) > policy["max_files_changed"] or int(change.get("bytes_changed") or 0) > policy["max_bytes_changed"]:
        approval_reasons.append("repository_change_size_requires_approval")
    if normalized_action == "REPOSITORY_PUSH" and not paths:
        approval_reasons.append("repository_change_context_incomplete")
    if normalized_action not in _PULL_REQUEST_FLOW_ACTIONS:
        approval_reasons.append("repository_approval_required")
    if policy["write_mode"] == "APPROVAL_REQUIRED":
        approval_reasons.append("repository_approval_required")
    check("change_rules", "approval_required" if approval_reasons else "pull_request_flow", reasons=sorted(set(approval_reasons)))
    if not approval_reasons:
        return finish("ALLOW", "repository_pull_request_flow_allowed", repository_id)

    canonical = _canonical_repository_action(
        repository=repository_row, host=host, action=normalized_action, branch=normalized_branch, actor_id=actor_id,
        executing_principal=agent_id, ai_system_id=ai_system_id, provider=provider, model=model,
        tool_fingerprint_id=tool_fingerprint_id, tool_schema_fingerprint=tool_schema_fingerprint,
        change_digest=change_digest, change=change,
    )
    if approval_binding_id is None:
        # The more specific reason wins; plain approval is the stable default.
        reason = next(code for code in ("repository_protected_path_requires_approval", "repository_change_size_requires_approval", "repository_approval_required", "repository_change_context_incomplete") if code in approval_reasons)
        extra["canonical_action"] = canonical
        return finish("HOLD_FOR_APPROVAL", reason, repository_id)
    verification = _verify_and_consume_mutation_approval(db, tenant_id=tenant_id, approval_binding_id=_text(approval_binding_id), repository=repository_row, canonical_action=canonical, now=evaluated_at)
    evidence["approval"] = {"approval_binding_id": _text(approval_binding_id)[:64], "verification": verification, "mac_version": _APPROVAL_MAC_VERSION}
    check("approval_binding", verification)
    if verification != "verified":
        return finish("BLOCK", verification, repository_id)
    return finish("ALLOW", "approved_repository_mutation", repository_id)


def serialize_github_projection(row: object) -> dict[str, object]:
    """Expose only the explicit safe projection fields to API callers."""
    if isinstance(row, GitHubSourceOrganization):
        return {"id": row.id, "host": row.host, "organization_id": row.external_organization_id, "login": row.login, "installation_id": row.installation_id, "capabilities": row.capabilities_json, "selected_repository_scope": row.selected_repository_scope, "sync_state": row.sync_state, "last_complete_at": row.last_complete_at, "limitations": row.limitations_json}
    if isinstance(row, GitHubRepository):
        account_scope_kind = _repository_account_scope_kind(row)
        deny_posture = None
        if account_scope_kind == "PERSONAL" and row.governance_state == "UNAPPROVED":
            deny_posture = "BLOCK_CHANGES" if row.read_posture == "ALLOW" else "BLOCK_ALL" if row.read_posture == "BLOCK" else None
        return {"id": row.id, "host": row.host, "repository_id": row.external_repository_id, "node_id": row.node_id, "full_name": row.full_name, "visibility": row.visibility, "lifecycle_state": row.lifecycle_state, "default_branch": row.default_branch, "protection": row.protection_json, "account_scope_kind": account_scope_kind, "deny_posture": deny_posture, "evidence_state": row.evidence_state, "governance_state": row.governance_state, "governance_version": row.governance_version, "approved_scope_ref": row.approved_scope_ref, "policy_mapping_ref": row.policy_mapping_ref, "policy_current": row.policy_current, "read_posture": row.read_posture, "operation_controls": row.operation_controls_json, "agent_policy": _agent_policy(row), "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at, "last_verified_at": row.last_verified_at}
    if isinstance(row, GitHubRepositoryAccess):
        return {"id": row.id, "repository_id": row.repository_id, "external_principal_id": row.external_principal_id, "principal_type": row.principal_type, "access_path": row.access_path, "permission": row.permission, "source_team_id": row.source_team_id, "mapped_user_id": row.mapped_user_id, "mapped_group_id": row.mapped_group_id, "evidence_state": row.evidence_state, "valid_until": row.valid_until}
    if isinstance(row, GitHubRepositoryAIConnection):
        return {"id": row.id, "repository_id": row.repository_id, "user_id": row.user_id, "ai_system_id": row.ai_system_id, "ai_asset_id": row.ai_asset_id, "provider": row.provider, "model": row.model, "client_name": row.client_name, "agent_id": row.agent_id, "mcp_server_id": row.mcp_server_id, "external_capability_id": row.external_capability_id, "tool_name": row.tool_name, "tool_schema_fingerprint": row.tool_schema_fingerprint, "relationship_state": row.relationship_state, "confidence": row.confidence, "source_surface": row.source_surface, "evidence_refs": row.evidence_refs_json, "action_count": row.action_count, "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at}
    if isinstance(row, GitHubRepositoryMutationApproval):
        # The MAC and nonce stay server-side: they are verification material.
        return {"approval_binding_id": row.id, "approval_request_id": row.approval_request_id, "repository_id": row.repository_id, "action": row.action, "state": row.state, "expires_at": row.expires_at, "use_limit": row.use_limit, "uses_consumed": row.uses_consumed, "governance_version": row.governance_version, "consumed_at": row.consumed_at}
    if isinstance(row, GitHubRepositoryRuntimeBinding):
        return {"id": row.id, "repository_id": row.repository_id, "native_integration_id": row.native_integration_id, "canonical_root_sha256": row.canonical_root_sha256, "common_dir_sha256": row.common_dir_sha256, "scope": row.scope, "state": row.state, "signed_evidence_ref": row.signed_evidence_ref, "actor_id": row.actor_id, "created_at": row.created_at, "updated_at": row.updated_at}
    raise ValueError("unsupported GitHub projection row")


def serialize_github_page(page: Mapping[str, object]) -> dict[str, object]:
    return {"items": [serialize_github_projection(row) for row in page.get("items", [])], "next_cursor": page.get("next_cursor"), "limit": page.get("limit")}


__all__ = ["bind_github_repository_runtime", "derive_github_repository_ai_connections", "evaluate_github_repository_mutation", "get_github_repository_detail", "github_repository_change_context", "issue_github_repository_mutation_approval", "normalize_github_agent_policy", "revoke_github_repository_mutation_approval", "save_github_repository_agent_policy", "get_github_repository_detail_payload", "list_github_ai_connections", "list_github_developers", "list_github_organizations", "list_github_repositories", "list_github_runtime_bindings", "observe_github_repository_runtime", "persist_github_inventory_unit", "resolve_current_repository_identity", "resolve_repository_control_floor", "revoke_github_repository_runtime", "save_github_repository_operation_controls", "serialize_github_page", "serialize_github_projection", "update_github_repository_governance"]
