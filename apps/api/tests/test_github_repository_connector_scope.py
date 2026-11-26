"""GitHub source connector: branch protection awareness and read-only installation tokens."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from typing import Any

import httpx
import pytest

from app.services.hmair.source_connectors import runtime
from app.services.hmair.source_connectors.contracts import HMAIRSourceConnectionInput, HMAIRSourceProvider
from app.services.hmair.source_connectors.github_cloud import GitHubCloudSourceConnector
from app.services.hmair.source_connectors.http import SafeSourceHTTPError


def _connection() -> HMAIRSourceConnectionInput:
    return HMAIRSourceConnectionInput(
        provider_key=HMAIRSourceProvider.GITHUB_CLOUD,
        display_name="github-cloud",
        target_identifier="acme",
        environment="production",
        authorization_reference="approved",
        requested_capabilities=("repository_inventory",),
        metadata={"organization_login": "acme", "selected_repository_scope": "SELECTED"},
        credentials={"app_id": "1", "installation_id": "2", "private_key_pem": "test"},
    )


def _window() -> tuple[datetime, datetime]:
    end = datetime(2026, 9, 14, tzinfo=UTC)
    return end - timedelta(days=1), end


class _HTTP:
    def __init__(self, *, branches_forbidden: bool = False) -> None:
        self.branches_forbidden = branches_forbidden
        self.branch_params: list[dict[str, Any]] = []

    def get_json(self, url: str, **kwargs: Any) -> Any:
        if url.endswith("/branches"):
            self.branch_params.append(dict(kwargs.get("params") or {}))
            if self.branches_forbidden:
                raise SafeSourceHTTPError("source_http_403")
            return [{"name": "main", "protected": True}, {"name": "release/1", "protected": True}, {"name": "scratch", "protected": False}]
        if url.endswith("/orgs/acme/repos"):
            return [{"id": "R_1", "node_id": "node-1", "full_name": "acme/app", "private": True, "default_branch": "main", "archived": False}]
        return []

    def get_ndjson(self, _url: str, **_kwargs: Any) -> tuple[dict[str, Any], ...]:
        return ()


def test_cloud_inventory_records_protected_branch_names_for_agent_push_decisions() -> None:
    http = _HTTP()
    result = GitHubCloudSourceConnector().collect(_connection(), _window(), http, identifier_salt="tenant-a")
    repository = next(record for record in result.records if record.record_kind == "github_repository")
    protection = next(record for record in result.records if record.record_kind == "github_repository_protection")
    assert list(repository.metadata["protection"]["protected_branches"]) == ["main", "release/1"]
    assert list(protection.metadata["protection"]["protected_branches"]) == ["main", "release/1"]
    assert http.branch_params and http.branch_params[0]["protected"] == "true"


def test_missing_branch_protection_permission_is_a_limitation_not_a_failure() -> None:
    result = GitHubCloudSourceConnector().collect(_connection(), _window(), _HTTP(branches_forbidden=True), identifier_salt="tenant-a")
    repository = next(record for record in result.records if record.record_kind == "github_repository")
    assert list(repository.metadata["protection"]["protected_branches"]) == []
    assert "branch_protection_permission_missing" in result.capability.limitations


@pytest.mark.parametrize(
    ("permissions", "read_only"),
    [
        ({"metadata": "read", "members": "read", "administration": "read"}, True),
        ({"metadata": "read", "contents": "write"}, False),
        ({"metadata": "read", "administration": "admin"}, False),
        ({}, False),
        (None, False),
        ({"metadata": 1}, False),
    ],
)
def test_installation_token_must_be_read_only(permissions: object, read_only: bool) -> None:
    payload: dict[str, object] = {"token": "t"}
    if permissions is not None:
        payload["permissions"] = permissions
    assert runtime._github_installation_token_is_read_only(payload) is read_only


@pytest.mark.parametrize(
    ("permissions", "accepted"),
    [({"metadata": "read", "contents": "read"}, True), ({"metadata": "read", "contents": "write"}, False)],
)
def test_cloud_transport_refuses_a_write_scoped_installation_token(monkeypatch: pytest.MonkeyPatch, permissions: dict[str, str], accepted: bool) -> None:
    monkeypatch.setattr(runtime.jwt, "encode", lambda *_args, **_kwargs: "app-assertion")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/app/installations/2/access_tokens"
        body = json.dumps({"token": "installation-token", "permissions": permissions}).encode()
        return httpx.Response(201, content=body, headers={"content-type": "application/json"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    if accepted:
        transport = runtime._github_cloud_transport(_connection(), client=client)
        assert isinstance(transport, runtime.AuthenticatedSourceHTTP)
    else:
        with pytest.raises(SafeSourceHTTPError, match="source_token_scope_excessive"):
            runtime._github_cloud_transport(_connection(), client=client)
    client.close()
