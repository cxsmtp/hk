from __future__ import annotations

import pytest
from pydantic import ValidationError
import httpx

from app.services.hmair.source_connectors.contracts import (
    HMAIRNormalizedRecord,
    HMAIRSourceConnectionInput,
)
from app.services.hmair.source_connectors.registry import source_registry
from app.services.hmair.source_connectors.http import SafeSourceHTTPClient


def _connection_payload() -> dict[str, object]:
    return {
        "provider_key": "hmair_github_ghes",
        "display_name": "Customer GHES",
        "target_identifier": "https://ghe.example.test",
        "environment": "production",
        "authorization_reference": "CAB-42",
        "requested_capabilities": ["audit_metadata"],
        "credentials": {"access_token": "secret-value"},
    }


def test_rejects_credential_in_metadata_and_private_record_field() -> None:
    with pytest.raises(ValidationError):
        HMAIRSourceConnectionInput.model_validate(
            {
                **_connection_payload(),
                "metadata": {"token": "plaintext-is-not-metadata"},
            }
        )

    with pytest.raises(ValidationError):
        HMAIRNormalizedRecord.model_validate(
            {
                "record_id": "record-1",
                "record_kind": "copilot_usage",
                "observed_at": "2026-09-04T00:00:00Z",
                "candidate_asset_type": "ai_application",
                "observation_type": "web_ai_usage",
                "identifiers": {"provider": "microsoft365"},
                "metadata": {"prompt_content": "must never persist"},
            }
        )


def test_registry_never_falls_back_to_legacy_monitoring_provider() -> None:
    with pytest.raises(LookupError):
        source_registry.get("microsoft_365")


def test_bounded_client_parses_ndjson_without_retaining_report_content() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"content-type": "application/x-ndjson"},
                content=b'{"user_hash":"one","count":1}\n{"user_hash":"two","count":2}\n',
                request=request,
            )
        )
    )
    with SafeSourceHTTPClient(
        allowed_origins=["https://downloads.github.test"], client=client
    ) as source_http:
        rows = source_http.get_ndjson(
            "https://downloads.github.test/report.ndjson", headers={}
        )

    assert rows == (
        {"user_hash": "one", "count": 1},
        {"user_hash": "two", "count": 2},
    )


def test_bounded_client_posts_form_without_redirects() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"access_token": "ephemeral-token"},
                request=request,
            )
        )
    )
    with SafeSourceHTTPClient(
        allowed_origins=["https://login.microsoftonline.com"], client=client
    ) as source_http:
        result = source_http.post_form_json(
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            form={"grant_type": "client_credentials"},
        )

    assert result == {"access_token": "ephemeral-token"}
