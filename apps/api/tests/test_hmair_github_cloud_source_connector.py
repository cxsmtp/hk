from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.hmair.source_connectors.contracts import HMAIRSourceConnectionInput
from app.services.hmair.source_connectors.github_cloud import github_cloud
from app.services.hmair.source_connectors.http import SafeSourceHTTPError


WINDOW = (
    datetime(2026, 9, 3, tzinfo=UTC),
    datetime(2026, 9, 4, tzinfo=UTC),
)


def _connection() -> HMAIRSourceConnectionInput:
    return HMAIRSourceConnectionInput.model_validate(
        {
            "provider_key": "hmair_github_cloud",
            "display_name": "GitHubEnterprise",
            "target_identifier": "enterprise-1",
            "environment": "production",
            "authorization_reference": "CAB-42",
            "requested_capabilities": ["copilot_metrics"],
            "credentials": {
                "app_id": "123",
                "installation_id": "456",
                "private_key_pem": "customer-private-key",
            },
        }
    )


class _ForbiddenHTTP:
    def get_json(self, *_: Any, **__: Any) -> dict[str, object]:
        raise SafeSourceHTTPError("source_http_403")


class _ReportHTTP:
    def get_json(self, url: str, **_: Any) -> dict[str, object]:
        if url.endswith("users-1-day"):
            return {"download_links": ["https://downloads.github.test/users.ndjson"]}
        if url.endswith("repos-1-day"):
            return {"download_links": ["https://downloads.github.test/repos.ndjson"]}
        raise AssertionError(url)

    def get_ndjson(self, url: str, **_: Any) -> tuple[dict[str, object], ...]:
        if url.endswith("users.ndjson"):
            return (
                {
                    "user_login": "alex",
                    "report_day": "2026-09-03",
                    "engaged_users": 1,
                },
            )
        if url.endswith("repos.ndjson"):
            return (
                {
                    "repository": "acme/private-repo",
                    "report_day": "2026-09-03",
                    "pull_request_count": 2,
                },
            )
        raise AssertionError(url)


class _ExpiredDownloadHTTP(_ReportHTTP):
    def get_ndjson(self, *_: Any, **__: Any) -> tuple[dict[str, object], ...]:
        raise SafeSourceHTTPError("source_http_403")


class _ValidationHTTP:
    def get_json(self, url: str, **kwargs: Any) -> dict[str, object]:
        assert url.endswith("enterprise-1-day")
        assert kwargs["params"] == {"day": "2026-09-03"}
        return {"download_links": ["https://downloads.github.test/enterprise.ndjson"]}


def test_requires_authorized_copilot_metrics_permission() -> None:
    result = github_cloud.validate(_connection(), _ForbiddenHTTP())

    assert result.state == "permission_denied"
    assert "copilot_metrics_permission_missing" in result.limitations


def test_parses_report_ndjson_transiently_and_hashes_identifiers() -> None:
    result = github_cloud.collect(
        _connection(), WINDOW, _ReportHTTP(), identifier_salt="tenant-a"
    )

    assert {row.record_kind for row in result.records} == {
        "copilot_user_usage",
        "copilot_repository_usage",
    }
    assert all("content" not in row.metadata for row in result.records)
    assert all("acme/private-repo" not in str(row.model_dump()) for row in result.records)


def test_expired_signed_download_is_not_success() -> None:
    result = github_cloud.collect(
        _connection(), WINDOW, _ExpiredDownloadHTTP(), identifier_salt="tenant-a"
    )

    assert result.capability.state == "partial"
    assert "copilot_report_download_unavailable" in result.capability.limitations


def test_validation_uses_the_previous_completed_utc_day() -> None:
    result = github_cloud.validate(
        _connection(), _ValidationHTTP(), now=datetime(2026, 9, 4, 1, tzinfo=UTC)
    )

    assert result.state == "partial"
    assert result.fresh_at == datetime(2026, 9, 4, 1, tzinfo=UTC)
