from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from typing import Any

from app.services.hmair.source_connectors.contracts import HMAIRSourceConnectionInput
from app.services.hmair.source_connectors.microsoft365 import microsoft365


WINDOW = (
    datetime(2026, 9, 3, tzinfo=UTC),
    datetime(2026, 9, 4, tzinfo=UTC),
)


def _connection(*, entra: bool = False) -> HMAIRSourceConnectionInput:
    return HMAIRSourceConnectionInput.model_validate(
        {
            "provider_key": "hmair_microsoft365_copilot",
            "display_name": "M365Production",
            "target_identifier": "tenant-0001",
            "environment": "production",
            "authorization_reference": "CAB-42",
            "requested_capabilities": ["copilot_usage"],
            "include_entra_account_evidence": entra,
            "credentials": {
                "tenant_id": "tenant-0001",
                "client_id": "client-0001",
                "client_secret": "customer-secret",
            },
        }
    )


class _ReportHTTP:
    def get_json(self, url: str, **_: Any) -> dict[str, object]:
        assert "getMicrosoft365CopilotUsageUserDetail" in url
        return {
            "licensed_user_count": 2,
            "value": [
                {
                    "userPrincipalName": "alex@example.test",
                    "lastActivityDate": "2026-09-03T12:00:00Z",
                    "copilotChatLastActivityDate": "2026-09-03T12:00:00Z",
                },
                {
                    "userPrincipalName": "casey@example.test",
                    "lastActivityDate": "2026-09-02T12:00:00Z",
                },
            ],
        }


class _SignInHTTP(_ReportHTTP):
    def get_json(self, url: str, **kwargs: Any) -> dict[str, object]:
        if "auditLogs/signIns" not in url:
            return super().get_json(url, **kwargs)
        return {
            "value": [
                {
                    "id": "signin-1",
                    "createdDateTime": "2026-09-03T11:00:00Z",
                    "userPrincipalName": "alex@example.test",
                    "appId": "graph-app-id",
                }
            ]
        }


class _ValidationHTTP:
    def get_json(self, url: str, **kwargs: Any) -> dict[str, object]:
        assert url.endswith(
            "getMicrosoft365CopilotUsageUserDetail(period='D7',version='v2')"
        )
        assert kwargs["params"] == {"$format": "application/json"}
        return {"licensed_user_count": 2, "value": []}


def test_collects_licensed_copilot_usage_without_prompt_content() -> None:
    result = microsoft365.collect(
        _connection(), WINDOW, _ReportHTTP(), identifier_salt="tenant-a"
    )

    assert result.capability.denominator == 2
    assert result.records[0].record_kind == "copilot_usage"
    assert "prompt" not in json.dumps(result.model_dump(mode="json")).lower()
    assert "unlicensed_copilot_chat_not_reported_by_graph" in result.capability.limitations
    assert all("@" not in value for row in result.records for value in row.identifiers.values())


def test_entra_signin_is_account_evidence_not_copilot_usage() -> None:
    result = microsoft365.collect(
        _connection(entra=True), WINDOW, _SignInHTTP(), identifier_salt="tenant-a"
    )

    assert result.entra_records
    assert all(record.record_kind != "copilot_usage" for record in result.entra_records)
    assert {record.record_kind for record in result.entra_records} == {"entra_account_evidence"}


def test_validate_requests_the_documented_json_copilot_report() -> None:
    result = microsoft365.validate(
        _connection(), _ValidationHTTP(), now=datetime(2026, 9, 4, tzinfo=UTC)
    )

    assert result.state == "empty"
    assert result.denominator == 2
    assert result.fresh_at == datetime(2026, 9, 4, tzinfo=UTC)
    assert "unlicensed_copilot_chat_not_reported_by_graph" in result.limitations
