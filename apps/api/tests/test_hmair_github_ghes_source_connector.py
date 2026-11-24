from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.services.hmair.source_connectors.contracts import HMAIRSourceConnectionInput
from app.services.hmair.source_connectors.github_enterprise_server import ghes


WINDOW = (
    datetime(2026, 9, 3, tzinfo=UTC),
    datetime(2026, 9, 4, tzinfo=UTC),
)


def _connection() -> HMAIRSourceConnectionInput:
    return HMAIRSourceConnectionInput.model_validate(
        {
            "provider_key": "hmair_github_ghes",
            "display_name": "GHESProduction",
            "target_identifier": "https://ghe.example.test",
            "environment": "production",
            "authorization_reference": "CAB-42",
            "requested_capabilities": ["audit_metadata", "repository_metadata"],
            "metadata": {"scope_slug": "acme"},
            "credentials": {"access_token": "customer-token"},
        }
    )


class _AuditHTTP:
    def get_json(self, url: str, **_: Any) -> object:
        if url.endswith("/api/v3/meta"):
            return {"installed_version": "3.21.0"}
        if url.endswith("/audit-log"):
            return [
                {
                    "@timestamp": "2026-09-03T12:00:00Z",
                    "actor": "alex",
                    "action": "repo.create",
                }
            ]
        if url.endswith("/repos"):
            return [{"full_name": "acme/private-repo", "updated_at": "2026-09-03T12:00:00Z"}]
        raise AssertionError(url)


class _UnknownVersionHTTP(_AuditHTTP):
    def get_json(self, url: str, **kwargs: Any) -> object:
        if url.endswith("/api/v3/meta"):
            return {"installed_version": "99.0.0"}
        return super().get_json(url, **kwargs)


def test_unknown_version_is_partial_and_never_upgrades_coverage() -> None:
    capability = ghes.validate(_connection(), _UnknownVersionHTTP())

    assert capability.state == "partial"
    assert "instance_version_not_confirmed" in capability.limitations


def test_validation_records_when_the_instance_was_last_confirmed() -> None:
    validated_at = datetime(2026, 9, 4, 2, tzinfo=UTC)

    capability = ghes.validate(_connection(), _AuditHTTP(), now=validated_at)

    assert capability.state == "partial"
    assert capability.fresh_at == validated_at


def test_audit_metadata_never_implies_copilot_usage() -> None:
    result = ghes.collect(_connection(), WINDOW, _AuditHTTP(), identifier_salt="tenant-a")

    assert result.records
    assert all(row.record_kind != "copilot_usage" for row in result.records)
    assert "copilot_usage_source_not_confirmed" in result.capability.limitations
    assert all("private-repo" not in str(row.model_dump()) for row in result.records)
