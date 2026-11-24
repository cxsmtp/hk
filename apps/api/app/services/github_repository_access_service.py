"""Safe persistence and bounded queries for the GitHub repository projection."""

from __future__ import annotations

from base64 import urlsafe_b64decode, urlsafe_b64encode
from collections.abc import Mapping
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db.models.github_repository_access import (
    GitHubRepository,
    GitHubRepositoryAIConnection,
    GitHubRepositoryAccess,
    GitHubRepositoryRuntimeBinding,
    GitHubSourceOrganization,
)
from app.db.models.native_control import NativeControlIntegration
from app.db.models.action_integrity import ApprovalAuthorityProjectionV2, ApprovalBindingV2Extension
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


def resolve_current_repository_identity(db: Session, *, tenant_id: str, host: str, owner: str, repository: str) -> GitHubRepository | None:
    expected = f"{owner.strip()}/{repository.strip()}".lower()
    return db.scalar(select(GitHubRepository).where(GitHubRepository.tenant_id == tenant_id, GitHubRepository.host == host.strip().lower(), GitHubRepository.full_name.ilike(expected)))


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
        evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id == action.evidence_bundle_id))
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


def _current_approval_matches(
    db: Session,
    *,
    tenant_id: str,
    approval_binding_id: str | None,
    repository_id: str,
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
    target: str,
    change_digest: str | None,
) -> bool:
    """Resolve immutable current authority server-side; callers provide only a binding reference."""
    if not approval_binding_id:
        return False
    binding = db.scalar(
        select(ApprovalBindingV2Extension).where(
            ApprovalBindingV2Extension.tenant_id == tenant_id,
            ApprovalBindingV2Extension.binding_id == approval_binding_id,
        )
    )
    if binding is None or _at(binding.expires_at) <= datetime.now(UTC):
        return False
    approval = db.scalar(
        select(ApprovalRequest).where(
            ApprovalRequest.tenant_id == tenant_id,
            ApprovalRequest.id == binding.approval_request_id,
            ApprovalRequest.status == "approved",
            ApprovalRequest.decision == "approve",
        )
    )
    projection = db.scalar(
        select(ApprovalAuthorityProjectionV2).where(
            ApprovalAuthorityProjectionV2.tenant_id == tenant_id,
            ApprovalAuthorityProjectionV2.approval_request_id == binding.approval_request_id,
        )
    )
    if approval is None or projection is None or projection.state != "APPROVED" or projection.reconstruction_status != "VERIFIED" or projection.uses_consumed >= binding.use_limit:
        return False
    envelope = dict(binding.permitted_variation_envelope or {})
    signed = dict(binding.signed_envelope or {})
    if signed.get("approval_binding_id") != binding.binding_id or signed.get("tenant_id") != tenant_id or signed.get("approval_decision") != "APPROVED":
        return False
    expected = {
        "repository_id": repository_id,
        "host": host,
        "action": action,
        "branch": branch,
        "actor_id": actor_id,
        "executing_principal": executing_principal,
        "ai_system_id": ai_system_id,
        "provider": provider,
        "model": model,
        "tool_fingerprint_id": tool_fingerprint_id,
        "tool_schema_fingerprint": tool_schema_fingerprint,
        "target": target,
        "change_digest": change_digest,
    }
    return all(_text(envelope.get(key)) == _text(value) for key, value in expected.items())


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
) -> dict[str, object]:
    """Fail closed for governed repository mutations without altering generic MCP flow."""
    normalized_action = _text(action).upper()
    locator = _repository_locator(resource)
    if locator is None:
        return {"decision": "BLOCK", "reason": "repository_resolution_unavailable", "repository_id": None}
    host, owner, name = locator
    repository_row = resolve_current_repository_identity(db, tenant_id=tenant_id, host=host, owner=owner, repository=name)
    if repository_row is None:
        return {"decision": "BLOCK", "reason": "repository_resolution_unavailable", "repository_id": None}
    if repository_row.evidence_state != "CONFIRMED" or repository_row.visibility != "PRIVATE" or repository_row.lifecycle_state != "ACTIVE":
        return {"decision": "BLOCK", "reason": "repository_not_currently_approved", "repository_id": repository_row.external_repository_id}
    is_write = any(marker in normalized_action for marker in ("PUSH", "PULL_REQUEST", "MERGE", "BRANCH_CREATE", "WORKFLOW_CHANGE", "SECRET_CHANGE", "DELETE", "TRANSFER", "VISIBILITY_CHANGE"))
    if not is_write:
        if normalized_action not in {"REPOSITORY_READ", "REPOSITORY_PULL", "REPOSITORY_CLONE", "REPOSITORY_FETCH"}:
            return {"decision": "BLOCK", "reason": "repository_action_unsupported", "repository_id": repository_row.external_repository_id}
        if repository_row.read_posture == "BLOCK":
            return {"decision": "BLOCK", "reason": "repository_read_blocked", "repository_id": repository_row.external_repository_id}
        if (
            repository_row.read_posture == "ALLOW"
            and repository_row.governance_state == "UNAPPROVED"
            and _repository_account_scope_kind(repository_row) == "PERSONAL"
        ):
            return {"decision": "ALLOW", "reason": "personal_repository_read_only", "repository_id": repository_row.external_repository_id}
        if repository_row.read_posture in {"ALLOW", "APPROVAL_REQUIRED"} and not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository_row):
            return {"decision": "BLOCK", "reason": "repository_read_not_currently_approved", "repository_id": repository_row.external_repository_id}
        if repository_row.read_posture == "ALLOW":
            return {"decision": "ALLOW", "reason": "configured_repository_read", "repository_id": repository_row.external_repository_id}
        if repository_row.read_posture == "APPROVAL_REQUIRED":
            return {"decision": "HOLD_FOR_APPROVAL", "reason": "repository_read_approval_required", "repository_id": repository_row.external_repository_id}
        return {"decision": "BLOCK", "reason": "repository_read_posture_unconfigured", "repository_id": repository_row.external_repository_id}
    if not _repository_governance_is_current(db, tenant_id=tenant_id, repository=repository_row):
        return {"decision": "BLOCK", "reason": "repository_not_explicitly_eligible", "repository_id": repository_row.external_repository_id}
    if approval_binding_id is None:
        return {"decision": "HOLD_FOR_APPROVAL", "reason": "repository_approval_required", "repository_id": repository_row.external_repository_id}
    if not _current_approval_matches(
        db,
        tenant_id=tenant_id,
        approval_binding_id=approval_binding_id,
        repository_id=repository_row.external_repository_id,
        host=host,
        action=normalized_action,
        branch=branch,
        actor_id=actor_id,
        executing_principal=agent_id,
        ai_system_id=ai_system_id,
        provider=provider,
        model=model,
        tool_fingerprint_id=tool_fingerprint_id,
        tool_schema_fingerprint=tool_schema_fingerprint,
        target=resource,
        change_digest=change_digest,
    ):
        return {"decision": "BLOCK", "reason": "approval_binding_mismatch", "repository_id": repository_row.external_repository_id}
    return {"decision": "ALLOW", "reason": "approved_repository_mutation", "repository_id": repository_row.external_repository_id}


def serialize_github_projection(row: object) -> dict[str, object]:
    """Expose only the explicit safe projection fields to API callers."""
    if isinstance(row, GitHubSourceOrganization):
        return {"id": row.id, "host": row.host, "organization_id": row.external_organization_id, "login": row.login, "installation_id": row.installation_id, "capabilities": row.capabilities_json, "selected_repository_scope": row.selected_repository_scope, "sync_state": row.sync_state, "last_complete_at": row.last_complete_at, "limitations": row.limitations_json}
    if isinstance(row, GitHubRepository):
        account_scope_kind = _repository_account_scope_kind(row)
        deny_posture = None
        if account_scope_kind == "PERSONAL" and row.governance_state == "UNAPPROVED":
            deny_posture = "BLOCK_CHANGES" if row.read_posture == "ALLOW" else "BLOCK_ALL" if row.read_posture == "BLOCK" else None
        return {"id": row.id, "host": row.host, "repository_id": row.external_repository_id, "node_id": row.node_id, "full_name": row.full_name, "visibility": row.visibility, "lifecycle_state": row.lifecycle_state, "default_branch": row.default_branch, "protection": row.protection_json, "account_scope_kind": account_scope_kind, "deny_posture": deny_posture, "evidence_state": row.evidence_state, "governance_state": row.governance_state, "governance_version": row.governance_version, "approved_scope_ref": row.approved_scope_ref, "policy_mapping_ref": row.policy_mapping_ref, "policy_current": row.policy_current, "read_posture": row.read_posture, "operation_controls": row.operation_controls_json, "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at, "last_verified_at": row.last_verified_at}
    if isinstance(row, GitHubRepositoryAccess):
        return {"id": row.id, "repository_id": row.repository_id, "external_principal_id": row.external_principal_id, "principal_type": row.principal_type, "access_path": row.access_path, "permission": row.permission, "source_team_id": row.source_team_id, "mapped_user_id": row.mapped_user_id, "mapped_group_id": row.mapped_group_id, "evidence_state": row.evidence_state, "valid_until": row.valid_until}
    if isinstance(row, GitHubRepositoryAIConnection):
        return {"id": row.id, "repository_id": row.repository_id, "user_id": row.user_id, "ai_system_id": row.ai_system_id, "ai_asset_id": row.ai_asset_id, "provider": row.provider, "model": row.model, "client_name": row.client_name, "agent_id": row.agent_id, "mcp_server_id": row.mcp_server_id, "external_capability_id": row.external_capability_id, "tool_name": row.tool_name, "tool_schema_fingerprint": row.tool_schema_fingerprint, "relationship_state": row.relationship_state, "confidence": row.confidence, "source_surface": row.source_surface, "evidence_refs": row.evidence_refs_json, "action_count": row.action_count, "first_seen_at": row.first_seen_at, "last_seen_at": row.last_seen_at}
    if isinstance(row, GitHubRepositoryRuntimeBinding):
        return {"id": row.id, "repository_id": row.repository_id, "native_integration_id": row.native_integration_id, "canonical_root_sha256": row.canonical_root_sha256, "common_dir_sha256": row.common_dir_sha256, "scope": row.scope, "state": row.state, "signed_evidence_ref": row.signed_evidence_ref, "actor_id": row.actor_id, "created_at": row.created_at, "updated_at": row.updated_at}
    raise ValueError("unsupported GitHub projection row")


def serialize_github_page(page: Mapping[str, object]) -> dict[str, object]:
    return {"items": [serialize_github_projection(row) for row in page.get("items", [])], "next_cursor": page.get("next_cursor"), "limit": page.get("limit")}


__all__ = ["bind_github_repository_runtime", "derive_github_repository_ai_connections", "evaluate_github_repository_mutation", "get_github_repository_detail", "get_github_repository_detail_payload", "list_github_ai_connections", "list_github_developers", "list_github_organizations", "list_github_repositories", "list_github_runtime_bindings", "observe_github_repository_runtime", "persist_github_inventory_unit", "resolve_current_repository_identity", "resolve_repository_control_floor", "revoke_github_repository_runtime", "save_github_repository_operation_controls", "serialize_github_page", "serialize_github_projection", "update_github_repository_governance"]
