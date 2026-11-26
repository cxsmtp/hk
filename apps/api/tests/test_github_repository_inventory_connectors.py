from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.services.hmair.source_connectors.contracts import (
    HMAIRSourceConnectionInput,
    HMAIRSourceProvider,
)
from app.services.hmair.source_connectors.github_cloud import GitHubCloudSourceConnector
from app.services.hmair.source_connectors.github_enterprise_server import GitHubEnterpriseServerSourceConnector


class _CloudHTTP:
    def get_json(self, url: str, **_kwargs: Any) -> Any:
        if "/collaborators" in url:
            return [{"id": "U_1", "login": "developer", "permissions": {"push": True}}]
        if "/teams" in url:
            return [{"id": "T_1", "slug": "platform", "permission": "push"}]
        if "/repos" in url:
            return [{"id": "R_1", "node_id": "node-1", "full_name": "acme/app", "private": True, "updated_at": "2026-09-13T00:00:00Z", "default_branch": "main", "archived": False}]
        if "enterprise-1-day" in url:
            return {"download_links": []}
        return {"download_links": []}

    def get_ndjson(self, _url: str, **_kwargs: Any) -> tuple[dict[str, Any], ...]:
        return ()


class _GHESHTTP:
    def get_json(self, url: str, **_kwargs: Any) -> Any:
        if url.endswith("/meta"):
            return {"installed_version": "3.22.1"}
        if "/collaborators" in url:
            return [{"id": "U_2", "login": "admin", "permissions": {"admin": True}}]
        if "/teams" in url:
            return [{"id": "T_2", "slug": "security", "permission": "admin"}]
        if "/orgs/acme/repos" in url:
            return [{"id": "R_2", "node_id": "node-2", "full_name": "acme/server", "private": True, "updated_at": "2026-09-13T00:00:00Z", "default_branch": "main", "archived": False}]
        return []


def _window() -> tuple[datetime, datetime]:
    end = datetime(2026, 9, 14, tzinfo=UTC)
    return end - timedelta(days=1), end


def test_cloud_connector_emits_safe_repository_and_access_inventory_records() -> None:
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_CLOUD,
        display_name="github-cloud",
        target_identifier="acme",
        environment="production",
        authorization_reference="approved",
        requested_capabilities=("repository_inventory",),
        metadata={"organization_login": "acme", "selected_repository_scope": "SELECTED"},
        credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"},
    )
    result = GitHubCloudSourceConnector().collect(connection, _window(), _CloudHTTP(), identifier_salt="tenant-a")
    kinds = {record.record_kind for record in result.records}
    assert {"github_organization", "github_repository", "github_repository_access", "github_repository_protection"} <= kinds
    repository = next(record for record in result.records if record.record_kind == "github_repository")
    assert "repository_hash" in repository.identifiers
    assert repository.identifiers["repository_hash"] != "R_1"
    assert "repository_id" not in repository.identifiers
    assert "content" not in repository.metadata
    assert "repository_inventory" in result.capability.allowed_capabilities


def test_ghes_connector_marks_a_complete_repository_inventory_without_claiming_copilot_coverage() -> None:
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_GHES,
        display_name="github-ghes",
        target_identifier="https://github.acme.test",
        environment="production",
        authorization_reference="approved",
        requested_capabilities=("repository_inventory",),
        metadata={"scope_slug": "acme", "selected_repository_scope": "ALL"},
        credentials={"access_token": "test"},
    )
    result = GitHubEnterpriseServerSourceConnector().collect(connection, _window(), _GHESHTTP(), identifier_salt="tenant-a")
    kinds = {record.record_kind for record in result.records}
    assert {"github_organization", "github_repository", "github_repository_access"} <= kinds
    assert result.capability.state == "partial"
    organization = next(record for record in result.records if record.record_kind == "github_organization")
    assert organization.metadata["sync_state"] == "COMPLETE"
    assert "copilot_usage_source_not_confirmed" in result.capability.limitations


class _PagedCloudHTTP(_CloudHTTP):
    def get_json(self, url: str, **kwargs: Any) -> Any:
        page = int((kwargs.get("params") or {}).get("page", 1))
        if url.endswith("/repos"):
            return ([{"id": "R_1", "full_name": "acme/app", "private": True, "default_branch": "main"}] if page == 1 else [])
        if url.endswith("/members"):
            return ([{"id": "U_member", "login": "member"}] if page == 1 else [])
        if url.endswith("/outside_collaborators"):
            return ([{"id": "U_outside", "login": "outside"}] if page == 1 else [])
        if url.endswith("/teams") and "/repos/" not in url:
            return ([{"id": "T_1", "slug": "platform"}] if page == 1 else [])
        if url.endswith("/members") and "/teams/" in url:
            return ([{"id": "U_team", "login": "team-member"}] if page == 1 else [])
        return super().get_json(url, **kwargs)


class _PersonalInstallationHTTP:
    def __init__(self) -> None:
        self.urls: list[str] = []

    def get_json(self, url: str, **kwargs: Any) -> Any:
        self.urls.append(url)
        page = int((kwargs.get("params") or {}).get("page", 1))
        if url.endswith("/installation/repositories"):
            if page == 1:
                return {
                    "total_count": 1,
                    "repositories": [
                        {
                            "id": "R_personal",
                            "node_id": "node-personal",
                            "full_name": "octocat/demo-private",
                            "private": True,
                            "default_branch": "main",
                            "archived": False,
                            "owner": {"id": "U_owner", "login": "octocat"},
                        }
                    ],
                }
            return {"total_count": 1, "repositories": []}
        if url.endswith("/repos/octocat/demo-private/collaborators"):
            return []
        if url.endswith("/repos/octocat/demo-private/branches"):
            return [{"name": "main", "protected": True}]
        raise AssertionError(f"personal installation used an unsupported endpoint: {url}")

    def get_ndjson(self, _url: str, **_kwargs: Any) -> tuple[dict[str, Any], ...]:
        return ()


def test_personal_github_app_inventory_uses_installation_scope_without_org_or_team_queries() -> None:
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_CLOUD,
        display_name="github-personal",
        target_identifier="octocat",
        environment="production",
        authorization_reference="approved",
        requested_capabilities=("repository_inventory",),
        metadata={
            "account_scope_kind": "PERSONAL",
            "account_login": "octocat",
            "selected_repository_scope": "SELECTED",
        },
        credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"},
    )
    http = _PersonalInstallationHTTP()
    connector = GitHubCloudSourceConnector()

    result = connector.collect(connection, _window(), http, identifier_salt="tenant-a")
    account = next(record for record in result.records if record.record_kind == "github_organization")
    repository = next(record for record in result.records if record.record_kind == "github_repository")
    owner = next(record for record in result.records if record.record_kind == "github_repository_access")

    assert account.metadata["account_scope_kind"] == "PERSONAL"
    assert account.metadata["sync_state"] == "COMPLETE"
    assert account.metadata["capabilities"]["denominators"] == {
        "repositories": 1,
        "account_owners": 1,
        "direct_collaborators": 0,
    }
    assert repository.metadata["protection"]["account_scope_kind"] == "PERSONAL"
    assert list(repository.metadata["protection"]["protected_branches"]) == ["main"]
    assert owner.identifiers["access_path"] == "OWNER"
    assert owner.metadata["permission"] == "ADMIN"
    assert connector.validate(connection, http, now=_window()[1]).denominator == 1
    assert all("/orgs/" not in url and "/teams" not in url and "/outside_collaborators" not in url for url in http.urls)


def test_github_account_scope_kind_rejects_untyped_values() -> None:
    with pytest.raises(ValueError, match="invalid HMAIR contract"):
        HMAIRSourceConnectionInput(
            provider_key=HMAIRSourceProvider.GITHUB_CLOUD,
            display_name="github-personal",
            target_identifier="octocat",
            environment="production",
            authorization_reference="approved",
            requested_capabilities=("repository_inventory",),
            metadata={"account_scope_kind": "individual-ish"},
            credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"},
        )


def test_cloud_inventory_paginates_to_complete_authoritative_denominator_without_copilot_metrics() -> None:
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_CLOUD,
        display_name="github-cloud", target_identifier="acme", environment="production", authorization_reference="approved",
        requested_capabilities=("repository_inventory",), metadata={"organization_login": "acme", "selected_repository_scope": "ALL"},
        credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"},
    )
    connector = GitHubCloudSourceConnector()
    result = connector.collect(connection, _window(), _PagedCloudHTTP(), identifier_salt="tenant-a")
    organization = next(record for record in result.records if record.record_kind == "github_organization")
    kinds = {record.record_kind for record in result.records}
    assert organization.metadata["sync_state"] == "COMPLETE"
    assert organization.metadata["capabilities"]["denominators"]["outside_collaborators"] == 1
    assert {"github_organization_member", "github_outside_collaborator", "github_team", "github_team_membership"} <= kinds
    assert "repository_inventory" in connector.validate(connection, _PagedCloudHTTP(), now=_window()[1]).allowed_capabilities


class _CopilotUnavailableCloudHTTP(_CloudHTTP):
    def get_json(self, url: str, **kwargs: Any) -> Any:
        if "/copilot/metrics/reports/" in url:
            return {"download_links": []}
        return super().get_json(url, **kwargs)


class _CopilotAvailableCloudHTTP(_CloudHTTP):
    def get_json(self, url: str, **kwargs: Any) -> Any:
        if "/copilot/metrics/reports/" in url:
            return {"download_links": ["https://example.invalid/report.ndjson"]}
        return super().get_json(url, **kwargs)


def test_cloud_collect_does_not_advertise_copilot_metrics_when_report_retrieval_fails() -> None:
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_CLOUD, display_name="github-cloud", target_identifier="acme", environment="production", authorization_reference="approved",
        requested_capabilities=("repository_inventory", "copilot_metrics"), metadata={"organization_login": "acme"}, credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"},
    )
    result = GitHubCloudSourceConnector().collect(connection, _window(), _CopilotUnavailableCloudHTTP(), identifier_salt="tenant-a")
    assert "repository_inventory" in result.capability.allowed_capabilities
    assert "copilot_metrics" not in result.capability.allowed_capabilities


def test_cloud_collect_advertises_copilot_metrics_only_after_valid_report_retrieval() -> None:
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_CLOUD, display_name="github-cloud", target_identifier="acme", environment="production", authorization_reference="approved",
        requested_capabilities=("repository_inventory", "copilot_metrics"), metadata={"organization_login": "acme"}, credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"},
    )
    result = GitHubCloudSourceConnector().collect(connection, _window(), _CopilotAvailableCloudHTTP(), identifier_salt="tenant-a")
    assert "copilot_metrics" in result.capability.allowed_capabilities


class _PagedGHESHTTP(_GHESHTTP):
    def get_json(self, url: str, **kwargs: Any) -> Any:
        page = int((kwargs.get("params") or {}).get("page", 1))
        if url.endswith("/repos"):
            return ([{"id": "R_2", "full_name": "acme/server", "private": True, "default_branch": "main"}] if page == 1 else [])
        if url.endswith("/members") and "/teams/" not in url:
            return ([{"id": "U_member", "login": "member"}] if page == 1 else [])
        if url.endswith("/outside_collaborators"):
            return ([{"id": "U_outside", "login": "outside"}] if page == 1 else [])
        if url.endswith("/teams") and "/repos/" not in url:
            return ([{"id": "T_2", "slug": "security"}] if page == 1 else [])
        if "/teams/" in url and url.endswith("/members"):
            return ([{"id": "U_team", "login": "team-member"}] if page == 1 else [])
        return super().get_json(url, **kwargs)


def test_ghes_inventory_paginates_all_identity_units_before_marking_organization_complete() -> None:
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_GHES, display_name="github-ghes", target_identifier="https://github.acme.test", environment="production", authorization_reference="approved",
        requested_capabilities=("repository_inventory",), metadata={"scope_slug": "acme", "selected_repository_scope": "ALL"}, credentials={"access_token": "test"},
    )
    result = GitHubEnterpriseServerSourceConnector().collect(connection, _window(), _PagedGHESHTTP(), identifier_salt="tenant-a")
    organization = next(record for record in result.records if record.record_kind == "github_organization")
    assert organization.metadata["sync_state"] == "COMPLETE"
    assert organization.metadata["capabilities"]["denominators"]["teams"] == 1
    assert {"github_organization_member", "github_outside_collaborator", "github_team", "github_team_membership"} <= {record.record_kind for record in result.records}


@pytest.mark.parametrize("provider", ["cloud", "ghes"])
@pytest.mark.parametrize("inventory_selected", [False, True])
def test_inventory_selection_bounds_membership_requests(provider: str, inventory_selected: bool) -> None:
    cloud = provider == "cloud"
    capabilities = ["copilot_metrics"] if cloud else ["audit_metadata", "repository_metadata"]
    if inventory_selected:
        capabilities.append("repository_inventory")
    connection = HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_CLOUD if cloud else HMAIRSourceProvider.GITHUB_GHES,
        display_name="capability-selection-test",
        target_identifier="acme" if cloud else "https://github.acme.test",
        environment="production",
        authorization_reference="synthetic-test-approval",
        requested_capabilities=tuple(capabilities),
        metadata={"organization_login": "acme", "scope_slug": "acme", "selected_repository_scope": "ALL"},
        credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"} if cloud else {"access_token": "test"},
    )

    class RecordingHTTP:
        def __init__(self) -> None:
            self.urls: list[str] = []
            self.delegate = _PagedCloudHTTP() if cloud else _PagedGHESHTTP()

        def get_json(self, url: str, **kwargs: Any) -> Any:
            self.urls.append(url)
            return self.delegate.get_json(url, **kwargs)

        def get_ndjson(self, _url: str, **_kwargs: Any) -> tuple[dict[str, Any], ...]:
            return ()

    http = RecordingHTTP()
    connector = GitHubCloudSourceConnector() if cloud else GitHubEnterpriseServerSourceConnector()
    result = connector.collect(connection, _window(), http, identifier_salt="synthetic-tenant")
    assert any(url.endswith("/members") for url in http.urls) is inventory_selected
    assert any(url.endswith("/outside_collaborators") for url in http.urls) is inventory_selected
    assert any(url.endswith("/collaborators") for url in http.urls) is inventory_selected
    assert any(record.record_kind == "github_organization" for record in result.records) is inventory_selected
    if cloud:
        assert any(url.endswith("/orgs/acme/repos") for url in http.urls) is inventory_selected
    else:
        # Separately selected audit/repository metadata must still be collected.
        assert any(url.endswith("/audit-log") for url in http.urls)
        assert any(url.endswith("/orgs/acme/repos") for url in http.urls)
