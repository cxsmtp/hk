"""Metadata-only GitHub Enterprise Server audit and repository connector."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
import re
from typing import Any, Protocol

from app.services.hmair.contracts import ObservationType, SourceSurface
from app.services.hmair.source_connectors.contracts import (
    HMAIRNormalizedRecord,
    HMAIRSourceCapability,
    HMAIRSourceCollectionResult,
    HMAIRSourceConnectionInput,
    HMAIRSourceProvider,
)
from app.services.hmair.source_connectors.http import SafeSourceHTTPError


_CONFIRMED_VERSION = re.compile(r"^3\.(?:2[0-9]|[3-9][0-9])(?:\.\d+)?$")
_COPILOT_LIMITATION = "copilot_usage_source_not_confirmed"


class GHESHTTP(Protocol):
    def get_json(self, url: str, **kwargs: Any) -> Any: ...


def _hash_identifier(value: object, *, salt: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return sha256(f"{salt}\x00{value.strip()}".encode("utf-8")).hexdigest()


def _utc(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _scope_slug(connection: HMAIRSourceConnectionInput) -> str | None:
    scope = connection.metadata.get("scope_slug")
    return scope if isinstance(scope, str) and scope else None


def _rows(payload: object) -> tuple[Mapping[str, Any], ...]:
    if isinstance(payload, list):
        return tuple(item for item in payload if isinstance(item, Mapping))[:10_000]
    if isinstance(payload, Mapping) and isinstance(payload.get("items"), list):
        return tuple(item for item in payload["items"] if isinstance(item, Mapping))[:10_000]
    return ()


def _paged_rows(http: GHESHTTP, url: str, *, params: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], bool]:
    """Bounded GHES pagination; complete only after a short terminal page."""
    rows: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        payload = http.get_json(url, headers={}, params={**params, "per_page": 100, "page": page})
        if not isinstance(payload, list):
            return rows, False
        current = [item for item in payload if isinstance(item, Mapping)]
        rows.extend(current[:100])
        if len(payload) < 100:
            return rows, True
    return rows, False


def _repository_inventory_records(
    *, connection: HMAIRSourceConnectionInput, http: GHESHTTP, scope_slug: str, observed_at: datetime
) -> tuple[tuple[HMAIRNormalizedRecord, ...], tuple[str, ...]]:
    base = {
        "host": connection.target_identifier.removeprefix("https://").lower(),
        "organization_id": str(connection.metadata.get("organization_id") or scope_slug),
        "organization_login": scope_slug,
    }
    records = [HMAIRNormalizedRecord(record_id=f"ghes-org-{scope_slug}", record_kind="github_organization", observed_at=observed_at, candidate_asset_type="repository_organization", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers=base, metadata={"selected_repository_scope": str(connection.metadata.get("selected_repository_scope") or "UNKNOWN").upper(), "sync_state": "PARTIAL", "evidence_state": "CONFIRMED", "limitations": ["source_denominator_unavailable"]})]
    limitations = ["source_denominator_unavailable"]
    try:
        repositories, repositories_complete = _paged_rows(http, f"{connection.target_identifier}/api/v3/orgs/{scope_slug}/repos", params={"sort": "updated"})
        members, members_complete = _paged_rows(http, f"{connection.target_identifier}/api/v3/orgs/{scope_slug}/members", params={})
        outside_collaborators, outside_complete = _paged_rows(http, f"{connection.target_identifier}/api/v3/orgs/{scope_slug}/outside_collaborators", params={})
        organization_teams, teams_complete = _paged_rows(http, f"{connection.target_identifier}/api/v3/orgs/{scope_slug}/teams", params={})
    except SafeSourceHTTPError:
        return tuple(records), ("repository_inventory_permission_missing", *limitations)
    if not all((repositories_complete, members_complete, outside_complete, teams_complete)):
        limitations.append("repository_inventory_partial_page")
    team_memberships: list[Mapping[str, Any]] = []
    team_memberships_complete = True
    for team in organization_teams:
        team_id = str(team.get("id") or "").strip()
        if not team_id:
            continue
        records.append(HMAIRNormalizedRecord(record_id=f"ghes-team-{team_id}", record_kind="github_team", observed_at=observed_at, candidate_asset_type="repository_team", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base, "team_id": team_id}, metadata={"team_slug": str(team.get("slug") or ""), "evidence_state": "CONFIRMED"}))
        try:
            team_members, complete = _paged_rows(http, f"{connection.target_identifier}/api/v3/teams/{team_id}/members", params={})
        except SafeSourceHTTPError:
            team_memberships_complete = False
            limitations.append("team_membership_permission_missing")
            continue
        team_memberships_complete = team_memberships_complete and complete
        for member in team_members:
            member_id = str(member.get("id") or "").strip()
            if member_id:
                team_memberships.append(member)
                records.append(HMAIRNormalizedRecord(record_id=f"ghes-team-member-{team_id}-{member_id}", record_kind="github_team_membership", observed_at=observed_at, candidate_asset_type="repository_team_membership", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base, "team_id": team_id, "principal_id": member_id}, metadata={"principal_type": "USER", "evidence_state": "CONFIRMED"}))
    for member in members:
        member_id = str(member.get("id") or "").strip()
        if member_id:
            records.append(HMAIRNormalizedRecord(record_id=f"ghes-org-member-{member_id}", record_kind="github_organization_member", observed_at=observed_at, candidate_asset_type="repository_organization_member", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base, "principal_id": member_id}, metadata={"principal_type": "USER", "evidence_state": "CONFIRMED"}))
    for collaborator in outside_collaborators:
        collaborator_id = str(collaborator.get("id") or "").strip()
        if collaborator_id:
            records.append(HMAIRNormalizedRecord(record_id=f"ghes-outside-collaborator-{collaborator_id}", record_kind="github_outside_collaborator", observed_at=observed_at, candidate_asset_type="repository_outside_collaborator", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base, "principal_id": collaborator_id}, metadata={"principal_type": "USER", "evidence_state": "CONFIRMED"}))
    access_complete = True
    for item in repositories:
        repository_id = str(item.get("id") or "").strip()
        full_name = str(item.get("full_name") or "").strip()
        if not repository_id or not full_name:
            continue
        identifiers = {**base, "repository_id": repository_id}
        if isinstance(item.get("node_id"), str): identifiers["node_id"] = item["node_id"]
        metadata = {"full_name": full_name, "visibility": "PRIVATE" if bool(item.get("private")) else "PUBLIC", "lifecycle_state": "ARCHIVED" if bool(item.get("archived")) else "ACTIVE", "default_branch": str(item.get("default_branch") or ""), "evidence_state": "CONFIRMED"}
        records.append(HMAIRNormalizedRecord(record_id=f"ghes-inventory-{repository_id}", record_kind="github_repository", observed_at=observed_at, candidate_asset_type="repository", observation_type=ObservationType.PACKAGE_REFERENCE, source_surface=SourceSurface.SOURCE_CODE, identifiers=identifiers, metadata=metadata))
        try:
            collaborators, collaborators_complete = _paged_rows(http, f"{connection.target_identifier}/api/v3/repos/{full_name}/collaborators", params={"affiliation": "direct"})
            teams, repo_teams_complete = _paged_rows(http, f"{connection.target_identifier}/api/v3/repos/{full_name}/teams", params={})
        except SafeSourceHTTPError:
            limitations.append("repository_access_permission_missing")
            access_complete = False
            continue
        access_complete = access_complete and collaborators_complete and repo_teams_complete
        for principal in collaborators:
            principal_id = str(principal.get("id") or "").strip()
            if not principal_id: continue
            permissions = principal.get("permissions") if isinstance(principal.get("permissions"), Mapping) else {}
            permission = "ADMIN" if permissions.get("admin") else "WRITE" if permissions.get("push") else "READ"
            records.append(HMAIRNormalizedRecord(record_id=f"ghes-access-direct-{repository_id}-{principal_id}", record_kind="github_repository_access", observed_at=observed_at, candidate_asset_type="repository_access", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base, "repository_id": repository_id, "principal_id": principal_id, "access_path": "DIRECT"}, metadata={"principal_type": "USER", "permission": permission, "evidence_state": "CONFIRMED"}))
        for team in teams:
            team_id = str(team.get("id") or "").strip()
            if not team_id: continue
            records.append(HMAIRNormalizedRecord(record_id=f"ghes-access-team-{repository_id}-{team_id}", record_kind="github_repository_access", observed_at=observed_at, candidate_asset_type="repository_access", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base, "repository_id": repository_id, "principal_id": team_id, "team_id": team_id, "access_path": "TEAM_INHERITED"}, metadata={"principal_type": "TEAM", "permission": str(team.get("permission") or "UNKNOWN").upper(), "evidence_state": "CONFIRMED"}))
    complete = all((repositories_complete, members_complete, outside_complete, teams_complete, team_memberships_complete, access_complete))
    if complete:
        limitations = [item for item in limitations if item != "source_denominator_unavailable"]
    organization_metadata = dict(records[0].metadata)
    organization_metadata.update({"sync_state": "COMPLETE" if complete else "PARTIAL", "capabilities": {"repository_inventory": "available", "denominators": {"repositories": len(repositories), "organization_members": len(members), "outside_collaborators": len(outside_collaborators), "teams": len(organization_teams), "team_memberships": len(team_memberships)}}, "limitations": tuple(dict.fromkeys(limitations))})
    records[0] = HMAIRNormalizedRecord(record_id=records[0].record_id, record_kind=records[0].record_kind, observed_at=records[0].observed_at, candidate_asset_type=records[0].candidate_asset_type, observation_type=records[0].observation_type, source_surface=records[0].source_surface, identifiers=records[0].identifiers, metadata=organization_metadata)
    return tuple(records), tuple(dict.fromkeys(limitations))


class GitHubEnterpriseServerSourceConnector:
    provider_key = HMAIRSourceProvider.GITHUB_GHES

    def validate(
        self,
        connection: HMAIRSourceConnectionInput,
        http: GHESHTTP,
        *,
        now: datetime | None = None,
    ) -> HMAIRSourceCapability:
        if connection.provider_key is not self.provider_key:
            raise ValueError("GHES collector received the wrong source provider")
        validated_at = now or datetime.now(UTC)
        if validated_at.tzinfo is None or validated_at.utcoffset() is None:
            raise ValueError("GHES validation requires a timezone-aware time")
        try:
            meta = http.get_json(f"{connection.target_identifier}/api/v3/meta", headers={})
        except SafeSourceHTTPError:
            return HMAIRSourceCapability(
                provider_key=self.provider_key,
                state="failed",
                allowed_capabilities=(),
                limitations=("instance_metadata_unavailable", _COPILOT_LIMITATION),
            )
        version = meta.get("installed_version") if isinstance(meta, Mapping) else None
        version_confirmed = isinstance(version, str) and _CONFIRMED_VERSION.fullmatch(version)
        return HMAIRSourceCapability(
            provider_key=self.provider_key,
            state="partial",
            allowed_capabilities=("audit_metadata", "repository_metadata", "repository_inventory"),
            fresh_at=validated_at.astimezone(UTC),
            limitations=(
                (_COPILOT_LIMITATION,)
                if version_confirmed
                else ("instance_version_not_confirmed", _COPILOT_LIMITATION)
            ),
        )

    def collect(
        self,
        connection: HMAIRSourceConnectionInput,
        window: tuple[datetime, datetime],
        http: GHESHTTP,
        *,
        identifier_salt: str,
    ) -> HMAIRSourceCollectionResult:
        if connection.provider_key is not self.provider_key:
            raise ValueError("GHES collector received the wrong source provider")
        start, end = window
        if start.tzinfo is None or end.tzinfo is None or start >= end:
            raise ValueError("GHES collection requires an ordered UTC window")
        capability = self.validate(connection, http, now=end)
        scope_slug = _scope_slug(connection)
        if scope_slug is None:
            return HMAIRSourceCollectionResult(
                capability=HMAIRSourceCapability(
                    provider_key=self.provider_key,
                    state="partial",
                    allowed_capabilities=capability.allowed_capabilities,
                    limitations=("scope_slug_missing", *capability.limitations),
                ),
                records=(),
                entra_records=(),
            )
        records: list[HMAIRNormalizedRecord] = []
        limitations = list(capability.limitations)
        if "repository_inventory" in set(connection.requested_capabilities):
            inventory_records, inventory_limitations = _repository_inventory_records(connection=connection, http=http, scope_slug=scope_slug, observed_at=end.astimezone(UTC))
            records.extend(inventory_records)
            limitations.extend(inventory_limitations)
        try:
            audit_rows = _rows(
                http.get_json(
                    f"{connection.target_identifier}/api/v3/enterprises/{scope_slug}/audit-log",
                    headers={},
                    params={
                        "phrase": (
                            f"created:>={start.astimezone(UTC).isoformat()} "
                            f"created:<={end.astimezone(UTC).isoformat()}"
                        )
                    },
                )
            )
        except SafeSourceHTTPError:
            audit_rows = ()
            limitations.append("audit_metadata_unavailable")
        for row in audit_rows:
            actor_hash = _hash_identifier(row.get("actor"), salt=identifier_salt)
            observed_at = _utc(row.get("@timestamp"))
            action = row.get("action")
            if actor_hash is None or observed_at is None or not isinstance(action, str):
                continue
            action_hash = _hash_identifier(action, salt=identifier_salt)
            assert action_hash is not None
            records.append(
                HMAIRNormalizedRecord(
                    record_id=f"ghes-audit-{action_hash[:40]}-{actor_hash[:8]}",
                    record_kind="ghes_audit_metadata",
                    observed_at=observed_at,
                    candidate_asset_type="repository",
                    observation_type=ObservationType.API_CALL,
                    source_surface=SourceSurface.SOURCE_CODE,
                    identifiers={"actor_hash": actor_hash, "provider": "ghes"},
                    metadata={"audit_action_hash": action_hash},
                )
            )
        try:
            repository_rows = _rows(
                http.get_json(
                    f"{connection.target_identifier}/api/v3/orgs/{scope_slug}/repos",
                    headers={},
                    params={"per_page": "100", "sort": "updated"},
                )
            )
        except SafeSourceHTTPError:
            repository_rows = ()
            limitations.append("repository_metadata_unavailable")
        for row in repository_rows:
            repository_hash = _hash_identifier(row.get("full_name"), salt=identifier_salt)
            observed_at = _utc(row.get("updated_at"))
            if repository_hash is None or observed_at is None:
                continue
            records.append(
                HMAIRNormalizedRecord(
                    record_id=f"ghes-repo-{repository_hash[:48]}",
                    record_kind="ghes_repository_metadata",
                    observed_at=observed_at,
                    candidate_asset_type="repository",
                    observation_type=ObservationType.PACKAGE_REFERENCE,
                    source_surface=SourceSurface.SOURCE_CODE,
                    identifiers={"repository_hash": repository_hash, "provider": "ghes"},
                    metadata={"source_class": "repository_metadata"},
                )
            )
        return HMAIRSourceCollectionResult(
            capability=HMAIRSourceCapability(
                provider_key=self.provider_key,
                state="partial",
                allowed_capabilities=capability.allowed_capabilities,
                fresh_at=end.astimezone(UTC),
                limitations=tuple(dict.fromkeys(limitations)),
            ),
            records=tuple(records),
            entra_records=(),
        )


ghes = GitHubEnterpriseServerSourceConnector()

__all__ = ["GitHubEnterpriseServerSourceConnector", "ghes"]
