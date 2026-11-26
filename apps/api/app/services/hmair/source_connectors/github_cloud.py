"""Metadata-only GitHub Enterprise Cloud Copilot metrics connector."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
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


GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
_LIMITATION = "source_denominator_unavailable"


class GitHubCloudHTTP(Protocol):
    def get_json(self, url: str, **kwargs: Any) -> Any: ...

    def get_ndjson(self, url: str, **kwargs: Any) -> tuple[Mapping[str, Any], ...]: ...


def _hash_identifier(value: object, *, salt: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return sha256(f"{salt}\x00{value.strip()}".encode("utf-8")).hexdigest()


def _record_ref(value: str | None) -> str:
    if not value:
        return "unknown"
    return value[:16]


def _report_day(window: tuple[datetime, datetime]) -> str:
    start, end = window
    if start.tzinfo is None or end.tzinfo is None or start >= end:
        raise ValueError("GitHub collection requires an ordered UTC window")
    # The GitHub daily report is a completed day. Do not ask the service for
    # the partially elapsed end day supplied by a scan window.
    return (end.astimezone(UTC).date() - timedelta(days=1)).isoformat()


def _headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def _download_links(payload: object) -> tuple[str, ...]:
    if not isinstance(payload, Mapping):
        return ()
    links = payload.get("download_links")
    if not isinstance(links, list) or not all(isinstance(link, str) for link in links):
        return ()
    return tuple(links[:16])


def _safe_metric(row: Mapping[str, Any], *names: str) -> int | None:
    for name in names:
        value = row.get(name)
        if isinstance(value, int) and value >= 0:
            return value
    return None


def _paged_rows(http: GitHubCloudHTTP, url: str, *, params: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], bool]:
    """Bounded API pagination; a full page limit is explicitly partial, never complete."""
    rows: list[Mapping[str, Any]] = []
    for page in range(1, 101):
        payload = http.get_json(url, headers=_headers(), params={**params, "per_page": 100, "page": page})
        if not isinstance(payload, list):
            return rows, False
        current = [item for item in payload if isinstance(item, Mapping)]
        rows.extend(current[:100])
        if len(payload) < 100:
            return rows, True
    return rows, False


def _installation_repositories(
    http: GitHubCloudHTTP,
) -> tuple[list[Mapping[str, Any]], bool, int | None]:
    """Read the repositories selected for one GitHub App installation."""
    rows: list[Mapping[str, Any]] = []
    expected_total: int | None = None
    for page in range(1, 101):
        payload = http.get_json(
            f"{GITHUB_API_ORIGIN}/installation/repositories",
            headers=_headers(),
            params={"per_page": 100, "page": page},
        )
        if not isinstance(payload, Mapping):
            return rows, False, expected_total
        total = payload.get("total_count")
        repositories = payload.get("repositories")
        if not isinstance(total, int) or total < 0 or not isinstance(repositories, list):
            return rows, False, expected_total
        expected_total = total if expected_total is None else expected_total
        if total != expected_total:
            return rows, False, expected_total
        current = [item for item in repositories if isinstance(item, Mapping)]
        rows.extend(current[:100])
        if len(rows) >= expected_total:
            return rows[:expected_total], len(rows) == expected_total, expected_total
        if len(repositories) < 100:
            return rows, False, expected_total
    return rows, False, expected_total


def _account_scope_kind(connection: HMAIRSourceConnectionInput) -> str:
    return str(connection.metadata.get("account_scope_kind") or "ORGANIZATION").upper()


def _repository_inventory_records(
    *,
    connection: HMAIRSourceConnectionInput,
    http: GitHubCloudHTTP,
    observed_at: datetime,
    identifier_salt: str,
) -> tuple[tuple[HMAIRNormalizedRecord, ...], tuple[str, ...]]:
    """Collect only repository/access metadata; never clone or read repository content."""
    account_scope_kind = _account_scope_kind(connection)
    organization = str(
        connection.metadata.get("account_login")
        or connection.metadata.get("organization_login")
        or connection.target_identifier
    ).strip()
    if not organization:
        return (), ("repository_inventory_scope_missing",)
    organization_external_id = str(
        connection.metadata.get("organization_id")
        or (f"personal:{organization}" if account_scope_kind == "PERSONAL" else organization)
    )
    organization_ref = _hash_identifier(organization_external_id, salt=identifier_salt) or "unknown"
    installation_ref = _hash_identifier(str(connection.credentials["installation_id"]), salt=identifier_salt) or "unknown"
    base_identifiers = {
        "host": "github.com",
        "organization_hash": organization_ref,
        "organization_login": organization,
        "installation_hash": installation_ref,
    }
    records = [
        HMAIRNormalizedRecord(
            record_id=f"ghc-org-{organization}",
            record_kind="github_organization",
            observed_at=observed_at,
            candidate_asset_type=("repository_account" if account_scope_kind == "PERSONAL" else "repository_organization"),
            observation_type=ObservationType.API_CALL,
            source_surface=SourceSurface.SOURCE_CODE,
            identifiers=base_identifiers,
            metadata={
                "account_scope_kind": account_scope_kind,
                "selected_repository_scope": str(connection.metadata.get("selected_repository_scope") or "UNKNOWN").upper(),
                "sync_state": "PARTIAL",
                "evidence_state": "CONFIRMED",
                "limitations": [_LIMITATION],
            },
        )
    ]
    try:
        if account_scope_kind == "PERSONAL":
            rows, repositories_complete, installation_total = _installation_repositories(http)
            members: list[Mapping[str, Any]] = []
            outside_collaborators: list[Mapping[str, Any]] = []
            organization_teams: list[Mapping[str, Any]] = []
            members_complete = outside_complete = teams_complete = True
        else:
            installation_total = None
            rows, repositories_complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/orgs/{organization}/repos", params={"sort": "updated"})
            members, members_complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/orgs/{organization}/members", params={})
            outside_collaborators, outside_complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/orgs/{organization}/outside_collaborators", params={})
            organization_teams, teams_complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/orgs/{organization}/teams", params={})
    except SafeSourceHTTPError:
        return tuple(records), ("repository_inventory_permission_missing",)
    limitations: list[str] = [_LIMITATION]
    if not all((repositories_complete, members_complete, outside_complete, teams_complete)):
        limitations.append("repository_inventory_partial_page")
    team_memberships: list[Mapping[str, Any]] = []
    team_memberships_complete = True
    for team in organization_teams:
        team_external_id = str(team.get("id") or "").strip()
        team_id = _hash_identifier(team_external_id, salt=identifier_salt)
        if not team_external_id or not team_id:
            continue
        records.append(HMAIRNormalizedRecord(record_id=f"ghc-team-{_record_ref(team_id)}", record_kind="github_team", observed_at=observed_at, candidate_asset_type="repository_team", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base_identifiers, "team_hash": team_id}, metadata={"team_slug": str(team.get("slug") or ""), "evidence_state": "CONFIRMED"}))
        try:
            members_for_team, complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/teams/{team_external_id}/members", params={})
        except SafeSourceHTTPError:
            team_memberships_complete = False
            limitations.append("team_membership_permission_missing")
            continue
        team_memberships_complete = team_memberships_complete and complete
        for member in members_for_team:
            member_id = _hash_identifier(str(member.get("id") or "").strip(), salt=identifier_salt)
            if member_id:
                team_memberships.append(member)
                records.append(HMAIRNormalizedRecord(record_id=f"ghc-team-member-{_record_ref(team_id)}-{_record_ref(member_id)}", record_kind="github_team_membership", observed_at=observed_at, candidate_asset_type="repository_team_membership", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base_identifiers, "team_hash": team_id, "principal_hash": member_id}, metadata={"principal_type": "USER", "evidence_state": "CONFIRMED"}))
    for member in members:
        member_id = _hash_identifier(str(member.get("id") or "").strip(), salt=identifier_salt)
        if member_id:
            records.append(HMAIRNormalizedRecord(record_id=f"ghc-org-member-{_record_ref(member_id)}", record_kind="github_organization_member", observed_at=observed_at, candidate_asset_type="repository_organization_member", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base_identifiers, "principal_hash": member_id}, metadata={"principal_type": "USER", "evidence_state": "CONFIRMED"}))
    for collaborator in outside_collaborators:
        collaborator_id = _hash_identifier(str(collaborator.get("id") or "").strip(), salt=identifier_salt)
        if collaborator_id:
            records.append(HMAIRNormalizedRecord(record_id=f"ghc-outside-collaborator-{_record_ref(collaborator_id)}", record_kind="github_outside_collaborator", observed_at=observed_at, candidate_asset_type="repository_outside_collaborator", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base_identifiers, "principal_hash": collaborator_id}, metadata={"principal_type": "USER", "evidence_state": "CONFIRMED"}))
    access_complete = True
    for item in rows:
        if not isinstance(item, Mapping):
            continue
        repository_external_id = str(item.get("id") or "").strip()
        repository_id = _hash_identifier(repository_external_id, salt=identifier_salt)
        full_name = str(item.get("full_name") or "").strip()
        if not repository_external_id or not repository_id or not full_name:
            continue
        identifiers = {**base_identifiers, "repository_hash": repository_id}
        # Branch protection awareness for AI agent pushes: the names of the
        # protected branches (no rule contents). Missing permission is a
        # limitation, not a failure: the default branch is always protected
        # for agents regardless.
        try:
            protected_rows, _protected_complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/repos/{full_name}/branches", params={"protected": "true"})
            protected_branches = sorted({str(row.get("name") or "").strip() for row in protected_rows if isinstance(row, Mapping) and row.get("protected") is True and str(row.get("name") or "").strip()})[:256]
        except SafeSourceHTTPError:
            protected_branches = []
            limitations.append("branch_protection_permission_missing")
        metadata = {
            "full_name": full_name,
            "visibility": "PRIVATE" if bool(item.get("private")) else "PUBLIC",
            "lifecycle_state": "ARCHIVED" if bool(item.get("archived")) else "ACTIVE",
            "default_branch": str(item.get("default_branch") or ""),
            "evidence_state": "CONFIRMED",
            "protection": {"account_scope_kind": account_scope_kind, "protected_branches": protected_branches},
        }
        node_hash = _hash_identifier(item.get("node_id"), salt=identifier_salt)
        if node_hash:
            metadata["github_node_hash"] = node_hash
        records.append(HMAIRNormalizedRecord(record_id=f"ghc-repository-{_record_ref(repository_id)}", record_kind="github_repository", observed_at=observed_at, candidate_asset_type="repository", observation_type=ObservationType.PACKAGE_REFERENCE, source_surface=SourceSurface.SOURCE_CODE, identifiers=identifiers, metadata=metadata))
        records.append(HMAIRNormalizedRecord(record_id=f"ghc-protection-{_record_ref(repository_id)}", record_kind="github_repository_protection", observed_at=observed_at, candidate_asset_type="repository", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers=identifiers, metadata={**metadata, "protection": {"default_branch": metadata["default_branch"], "source": "repository_metadata", "account_scope_kind": account_scope_kind, "protected_branches": protected_branches}}))
        owner = item.get("owner") if isinstance(item.get("owner"), Mapping) else {}
        owner_id = _hash_identifier(str(owner.get("id") or "").strip(), salt=identifier_salt)
        if account_scope_kind == "PERSONAL" and owner_id:
            records.append(HMAIRNormalizedRecord(record_id=f"ghc-access-owner-{_record_ref(repository_id)}-{_record_ref(owner_id)}", record_kind="github_repository_access", observed_at=observed_at, candidate_asset_type="repository_access", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base_identifiers, "repository_hash": repository_id, "principal_hash": owner_id, "access_path": "OWNER"}, metadata={"principal_type": "USER", "permission": "ADMIN", "evidence_state": "CONFIRMED"}))
        try:
            collaborators, collaborators_complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/repos/{full_name}/collaborators", params={"affiliation": "direct"})
            if account_scope_kind == "PERSONAL":
                teams: list[Mapping[str, Any]] = []
                repo_teams_complete = True
            else:
                teams, repo_teams_complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/repos/{full_name}/teams", params={})
        except SafeSourceHTTPError:
            limitations.append("repository_access_permission_missing")
            access_complete = False
            continue
        access_complete = access_complete and collaborators_complete and repo_teams_complete
        for principal in collaborators:
            if not isinstance(principal, Mapping) or not str(principal.get("id") or "").strip():
                continue
            principal_id = _hash_identifier(str(principal["id"]), salt=identifier_salt)
            if not principal_id:
                continue
            permissions = principal.get("permissions") if isinstance(principal.get("permissions"), Mapping) else {}
            permission = "ADMIN" if permissions.get("admin") else "WRITE" if permissions.get("push") else "READ"
            records.append(HMAIRNormalizedRecord(record_id=f"ghc-access-direct-{_record_ref(repository_id)}-{_record_ref(principal_id)}", record_kind="github_repository_access", observed_at=observed_at, candidate_asset_type="repository_access", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base_identifiers, "repository_hash": repository_id, "principal_hash": principal_id, "access_path": "DIRECT"}, metadata={"principal_type": "USER", "permission": permission, "evidence_state": "CONFIRMED"}))
        for team in teams:
            if not isinstance(team, Mapping) or not str(team.get("id") or "").strip():
                continue
            team_id = _hash_identifier(str(team["id"]), salt=identifier_salt)
            if not team_id:
                continue
            records.append(HMAIRNormalizedRecord(record_id=f"ghc-access-team-{_record_ref(repository_id)}-{_record_ref(team_id)}", record_kind="github_repository_access", observed_at=observed_at, candidate_asset_type="repository_access", observation_type=ObservationType.API_CALL, source_surface=SourceSurface.SOURCE_CODE, identifiers={**base_identifiers, "repository_hash": repository_id, "principal_hash": team_id, "team_hash": team_id, "access_path": "TEAM_INHERITED"}, metadata={"principal_type": "TEAM", "permission": str(team.get("permission") or "UNKNOWN").upper(), "evidence_state": "CONFIRMED"}))
    complete = all((repositories_complete, members_complete, outside_complete, teams_complete, team_memberships_complete, access_complete))
    if complete:
        limitations = [item for item in limitations if item != _LIMITATION]
    organization_metadata = dict(records[0].metadata)
    owner_count = len({str(item.get("owner", {}).get("id")) for item in rows if isinstance(item.get("owner"), Mapping) and item.get("owner", {}).get("id")})
    direct_collaborator_count = sum(1 for record in records if record.record_kind == "github_repository_access" and record.identifiers.get("access_path") == "DIRECT")
    denominators = (
        {
            "repositories": installation_total if installation_total is not None else len(rows),
            "account_owners": owner_count,
            "direct_collaborators": direct_collaborator_count,
        }
        if account_scope_kind == "PERSONAL"
        else {
            "repositories": len(rows),
            "organization_members": len(members),
            "outside_collaborators": len(outside_collaborators),
            "teams": len(organization_teams),
            "team_memberships": len(team_memberships),
        }
    )
    organization_metadata.update({
        "sync_state": "COMPLETE" if complete else "PARTIAL",
        "account_scope_kind": account_scope_kind,
        "capabilities": {"repository_inventory": "available", "account_scope_kind": account_scope_kind, "denominators": denominators},
        "limitations": tuple(dict.fromkeys(limitations)),
    })
    records[0] = HMAIRNormalizedRecord(record_id=records[0].record_id, record_kind=records[0].record_kind, observed_at=records[0].observed_at, candidate_asset_type=records[0].candidate_asset_type, observation_type=records[0].observation_type, source_surface=records[0].source_surface, identifiers=records[0].identifiers, metadata=organization_metadata)
    return tuple(records), tuple(dict.fromkeys(limitations))


class GitHubCloudSourceConnector:
    provider_key = HMAIRSourceProvider.GITHUB_CLOUD

    def validate(
        self,
        connection: HMAIRSourceConnectionInput,
        http: GitHubCloudHTTP,
        *,
        now: datetime | None = None,
    ) -> HMAIRSourceCapability:
        if connection.provider_key is not self.provider_key:
            raise ValueError("GitHub Cloud collector received the wrong source provider")
        validated_at = now or datetime.now(UTC)
        if validated_at.tzinfo is None or validated_at.utcoffset() is None:
            raise ValueError("GitHub Cloud validation requires a timezone-aware time")
        if "repository_inventory" in set(connection.requested_capabilities):
            try:
                if _account_scope_kind(connection) == "PERSONAL":
                    _rows, complete, denominator = _installation_repositories(http)
                    if denominator is None:
                        raise SafeSourceHTTPError("repository_inventory_invalid_response")
                else:
                    organization = str(connection.metadata.get("organization_login") or connection.target_identifier).strip()
                    _rows, complete = _paged_rows(http, f"{GITHUB_API_ORIGIN}/orgs/{organization}/repos", params={"per_page": 1})
                    denominator = None
            except SafeSourceHTTPError:
                return HMAIRSourceCapability(provider_key=self.provider_key, state="permission_denied", allowed_capabilities=(), limitations=("repository_inventory_permission_missing",))
            return HMAIRSourceCapability(
                provider_key=self.provider_key,
                state=("ready" if complete and denominator is not None else "partial"),
                allowed_capabilities=("repository_inventory",),
                denominator=denominator,
                fresh_at=validated_at.astimezone(UTC),
                limitations=(() if complete and denominator is not None else (_LIMITATION,)),
            )
        completed_day = (
            validated_at.astimezone(UTC).date() - timedelta(days=1)
        ).isoformat()
        url = (
            f"{GITHUB_API_ORIGIN}/enterprises/{connection.target_identifier}"
            "/copilot/metrics/reports/enterprise-1-day"
        )
        try:
            payload = http.get_json(
                url, headers=_headers(), params={"day": completed_day}
            )
        except SafeSourceHTTPError as error:
            if error.reason in {"source_http_403", "source_http_404"}:
                return HMAIRSourceCapability(
                    provider_key=self.provider_key,
                    state="permission_denied",
                    allowed_capabilities=(),
                    limitations=("copilot_metrics_permission_missing",),
                )
            return HMAIRSourceCapability(
                provider_key=self.provider_key,
                state="failed",
                allowed_capabilities=(),
                limitations=("copilot_metrics_validation_unavailable",),
            )
        if not _download_links(payload):
            return HMAIRSourceCapability(
                provider_key=self.provider_key,
                state="partial",
                allowed_capabilities=(),
                limitations=("copilot_metrics_report_unavailable",),
            )
        return HMAIRSourceCapability(
            provider_key=self.provider_key,
            state="partial",
            allowed_capabilities=("copilot_metrics",),
            fresh_at=validated_at.astimezone(UTC),
            limitations=(_LIMITATION,),
        )

    def collect(
        self,
        connection: HMAIRSourceConnectionInput,
        window: tuple[datetime, datetime],
        http: GitHubCloudHTTP,
        *,
        identifier_salt: str,
    ) -> HMAIRSourceCollectionResult:
        if connection.provider_key is not self.provider_key:
            raise ValueError("GitHub Cloud collector received the wrong source provider")
        report_day = _report_day(window)
        headers = _headers()
        records: list[HMAIRNormalizedRecord] = []
        limitations: list[str] = [_LIMITATION]
        if "repository_inventory" in set(connection.requested_capabilities):
            inventory_records, inventory_limitations = _repository_inventory_records(
                connection=connection,
                http=http,
                observed_at=window[1].astimezone(UTC),
                identifier_salt=identifier_salt,
            )
            records.extend(inventory_records)
            limitations.extend(inventory_limitations)
        report_specs = (
            ("users-1-day", "copilot_user_usage", "user_login", "ai_provider_account"),
            ("repos-1-day", "copilot_repository_usage", "repository", "repository"),
        ) if "copilot_metrics" in set(connection.requested_capabilities) else ()
        copilot_metrics_succeeded = False
        for report_name, record_kind, identity_key, asset_type in report_specs:
            url = (
                f"{GITHUB_API_ORIGIN}/enterprises/{connection.target_identifier}"
                f"/copilot/metrics/reports/{report_name}"
            )
            try:
                manifest = http.get_json(url, headers=headers, params={"day": report_day})
                links = _download_links(manifest)
                if not links:
                    raise SafeSourceHTTPError("source_report_link_missing")
                rows = tuple(
                    row
                    for link in links
                    for row in http.get_ndjson(link, headers=headers)
                )[:10_000]
            except SafeSourceHTTPError:
                limitations.append("copilot_report_download_unavailable")
                continue
            copilot_metrics_succeeded = True
            for row in rows:
                external_hash = _hash_identifier(row.get(identity_key), salt=identifier_salt)
                if external_hash is None:
                    continue
                metrics = {
                    name: value
                    for name in ("engaged_users", "pull_request_count", "suggestions_count")
                    if (value := _safe_metric(row, name)) is not None
                }
                records.append(
                    HMAIRNormalizedRecord(
                        record_id=f"ghc-{record_kind}-{external_hash[:40]}",
                        record_kind=record_kind,
                        observed_at=datetime.combine(
                            datetime.fromisoformat(report_day).date(),
                            datetime.min.time(),
                            tzinfo=UTC,
                        ),
                        candidate_asset_type=asset_type,
                        observation_type=(
                            ObservationType.ACTIVE_USER
                            if record_kind == "copilot_user_usage"
                            else ObservationType.AI_SAAS_FEATURE
                        ),
                        source_surface=SourceSurface.SAAS,
                        identifiers={"external_hash": external_hash, "provider": "github"},
                        metadata={"report_day": report_day, **metrics},
                    )
                )
        account_record = next((record for record in records if record.record_kind == "github_organization"), None)
        inventory_complete = bool(account_record and account_record.metadata.get("sync_state") == "COMPLETE")
        denominator_value = None
        if account_record and isinstance(account_record.metadata.get("capabilities"), Mapping):
            denominators = account_record.metadata["capabilities"].get("denominators")
            if isinstance(denominators, Mapping) and isinstance(denominators.get("repositories"), int):
                denominator_value = denominators["repositories"]
        state = "ready" if _account_scope_kind(connection) == "PERSONAL" and inventory_complete and not report_specs else "partial"
        if state == "ready":
            limitations = [item for item in limitations if item != _LIMITATION]
        return HMAIRSourceCollectionResult(
            capability=HMAIRSourceCapability(
                provider_key=self.provider_key,
                state=state,
                allowed_capabilities=(
                    *(("repository_inventory",) if any(record.record_kind == "github_organization" for record in records) else ()),
                    *(("copilot_metrics",) if copilot_metrics_succeeded else ()),
                ),
                denominator=denominator_value if _account_scope_kind(connection) == "PERSONAL" else None,
                fresh_at=window[1].astimezone(UTC),
                limitations=tuple(dict.fromkeys(limitations)),
            ),
            records=tuple(records),
            entra_records=(),
        )


github_cloud = GitHubCloudSourceConnector()

__all__ = ["GitHubCloudSourceConnector", "github_cloud"]
