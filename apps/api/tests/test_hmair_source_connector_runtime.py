from __future__ import annotations

import httpx

from app.services.hmair.source_connectors.contracts import HMAIRSourceConnectionInput
from app.services.hmair.source_connectors.runtime import source_http_for_connection


def test_ghes_runtime_uses_encrypted_connection_material_only_as_request_auth() -> None:
    seen_headers: list[dict[str, str]] = []
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: (
                seen_headers.append(dict(request.headers)),
                httpx.Response(200, json={"installed_version": "3.21.0"}, request=request),
            )[1]
        )
    )
    connection = HMAIRSourceConnectionInput.model_validate(
        {
            "provider_key": "hmair_github_ghes",
            "display_name": "GHESProduction",
            "target_identifier": "https://ghe.example.test",
            "environment": "production",
            "authorization_reference": "CAB-42",
            "requested_capabilities": ["audit_metadata"],
            "credentials": {"access_token": "customer-token"},
        }
    )
    transport = source_http_for_connection(connection, client=client)
    try:
        assert transport.get_json("https://ghe.example.test/api/v3/meta", headers={}) == {
            "installed_version": "3.21.0"
        }
    finally:
        transport.close()

    assert seen_headers[0]["authorization"] == "Bearer customer-token"
