from __future__ import annotations

import json
import ssl
from types import SimpleNamespace
from urllib import error as urllib_error

import pytest

from app.db.models.external_risk import ExternalRiskSource
from app.services.external_risk_intel import source_connector as connector
from app.services.external_risk_intel.transport_security import SecurityDecision
from app.services import outbound_destination_policy


@pytest.fixture(autouse=True)
def _mock_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        outbound_destination_policy,
        "_system_resolver",
        lambda _hostname, _port: ("93.184.216.34",),
    )


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.headers = {"Content-Length": str(len(payload))}
        self.fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(getpeercert=lambda **_kwargs: b"")))

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: ANN001
        return False

    def read(self, _limit: int = -1) -> bytes:
        return self._payload


def _source(
    *,
    source_name: str = "nvd",
    endpoint_url: str | None = None,
    transport_policy: dict | None = None,
    routing_policy: dict | None = None,
    auth_mode: str = "none",
) -> ExternalRiskSource:
    resolved_endpoint = endpoint_url or connector.DEFAULT_SOURCE_ENDPOINTS.get(source_name, "https://example.test/feed")
    return ExternalRiskSource(
        tenant_id="tenant-1",
        source=source_name,
        display_name=source_name.upper(),
        enabled=True,
        endpoint_url=resolved_endpoint,
        auth_mode=auth_mode,
        auth_config={},
        source_trust_policy={},
        egress_policy={},
        redaction_policy={},
        routing_policy=dict(routing_policy or {}),
        transport_policy=dict(transport_policy or {}),
        sync_schedule="0 */6 * * *",
        last_sync_status="never",
    )


def test_fetch_source_records_retries_with_system_trust_store_on_cert_chain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _source()
    monkeypatch.setattr(
        connector,
        "validate_transport_security",
        lambda **_kwargs: SecurityDecision(True, "ok", {"minimum_tls_version": "TLSv1.3"}),
    )

    build_calls: list[bool] = []

    def _fake_build_ssl_context(*, transport_policy, auth_config, use_system_trust_store=False):  # noqa: ANN001,ARG001
        build_calls.append(bool(use_system_trust_store))
        mode = "system" if use_system_trust_store else "configured"
        return SimpleNamespace(mode=mode)

    monkeypatch.setattr(connector, "build_ssl_context", _fake_build_ssl_context)

    payload = b'{"vulnerabilities":[{"cve":{"id":"CVE-2099-2001"}}]}'

    def _fake_urlopen(request, timeout, context):  # noqa: ANN001,ARG001
        if getattr(context, "mode", "") == "configured":
            raise urllib_error.URLError(
                ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
            )
        return _FakeResponse(payload)

    monkeypatch.setattr(
        connector,
        "_open_source_request",
        lambda _source, _request, *, timeout_seconds, context, **_kwargs: _fake_urlopen(
            _request, timeout_seconds, context
        ),
    )
    result = connector.fetch_source_records(src, timeout_seconds=3.0)

    assert build_calls == [False, True]
    assert result.metadata["trust_store_mode"] == "system_trust_store"
    assert len(result.records) == 1


def test_fetch_source_records_surfaces_actionable_hint_on_cert_chain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _source(
        transport_policy={
            "allow_system_trust_store_fallback": False,
            "allow_curl_tls_fallback": False,
        }
    )
    monkeypatch.setattr(
        connector,
        "validate_transport_security",
        lambda **_kwargs: SecurityDecision(True, "ok", {"minimum_tls_version": "TLSv1.3"}),
    )
    monkeypatch.setattr(
        connector,
        "build_ssl_context",
        lambda **_kwargs: SimpleNamespace(mode="configured"),
    )

    def _fake_urlopen(request, timeout, context):  # noqa: ANN001,ARG001
        raise urllib_error.URLError(
            ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")
        )

    monkeypatch.setattr(
        connector,
        "_open_source_request",
        lambda _source, _request, *, timeout_seconds, context, **_kwargs: _fake_urlopen(
            _request, timeout_seconds, context
        ),
    )

    with pytest.raises(connector.ExternalFeedFetchError, match="Hint: provide transport_policy.ca_bundle_path"):
        connector.fetch_source_records(src, timeout_seconds=3.0)


def test_fetch_source_records_uses_curl_tls_fallback_after_ssl_chain_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _source()
    monkeypatch.setattr(
        connector,
        "validate_transport_security",
        lambda **_kwargs: SecurityDecision(True, "ok", {"minimum_tls_version": "TLSv1.3"}),
    )
    monkeypatch.setattr(
        connector,
        "build_ssl_context",
        lambda **_kwargs: SimpleNamespace(mode="configured"),
    )

    def _fake_urlopen(request, timeout, context):  # noqa: ANN001,ARG001
        raise urllib_error.URLError(
            ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")
        )

    monkeypatch.setattr(
        connector,
        "_open_source_request",
        lambda _source, _request, *, timeout_seconds, context, **_kwargs: _fake_urlopen(
            _request, timeout_seconds, context
        ),
    )
    monkeypatch.setattr(
        connector,
        "_fetch_json_via_curl",
        lambda **_kwargs: {"vulnerabilities": [{"cve": {"id": "CVE-2099-9001"}}]},
    )

    result = connector.fetch_source_records(src, timeout_seconds=3.0)
    assert result.metadata["trust_store_mode"] == "curl_tls_fallback"
    assert len(result.records) == 1


def test_fetch_source_records_uses_curl_fallback_after_dns_resolution_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _source()
    monkeypatch.setattr(
        connector,
        "validate_transport_security",
        lambda **_kwargs: SecurityDecision(True, "ok", {"minimum_tls_version": "TLSv1.3"}),
    )
    monkeypatch.setattr(
        connector,
        "build_ssl_context",
        lambda **_kwargs: SimpleNamespace(mode="configured"),
    )

    def _fake_urlopen(request, timeout, context):  # noqa: ANN001,ARG001
        raise urllib_error.URLError(OSError(8, "nodename nor servname provided, or not known"))

    monkeypatch.setattr(
        connector,
        "_open_source_request",
        lambda _source, _request, *, timeout_seconds, context, **_kwargs: _fake_urlopen(
            _request, timeout_seconds, context
        ),
    )
    monkeypatch.setattr(
        connector,
        "_fetch_json_via_curl",
        lambda **_kwargs: {"vulnerabilities": [{"cve": {"id": "CVE-2099-9002"}}]},
    )

    result = connector.fetch_source_records(src, timeout_seconds=3.0)
    assert result.metadata["trust_store_mode"] == "curl_network_fallback"
    assert len(result.records) == 1


def test_fetch_source_records_surfaces_actionable_hint_on_dns_resolution_error(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _source(transport_policy={"allow_curl_tls_fallback": False})
    monkeypatch.setattr(
        connector,
        "validate_transport_security",
        lambda **_kwargs: SecurityDecision(True, "ok", {"minimum_tls_version": "TLSv1.3"}),
    )
    monkeypatch.setattr(
        connector,
        "build_ssl_context",
        lambda **_kwargs: SimpleNamespace(mode="configured"),
    )

    def _fake_urlopen(request, timeout, context):  # noqa: ANN001,ARG001
        raise urllib_error.URLError(OSError(8, "nodename nor servname provided, or not known"))

    monkeypatch.setattr(
        connector,
        "_open_source_request",
        lambda _source, _request, *, timeout_seconds, context, **_kwargs: _fake_urlopen(
            _request, timeout_seconds, context
        ),
    )

    with pytest.raises(
        connector.ExternalFeedFetchError,
        match="Hint: current API runtime cannot resolve or reach external hosts",
    ):
        connector.fetch_source_records(src, timeout_seconds=3.0)


def test_fetch_source_records_does_not_use_curl_fallback_for_authenticated_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    src = _source(auth_mode="bearer")
    src.auth_config = {"bearer_token": "test-token"}
    monkeypatch.setattr(
        connector,
        "validate_transport_security",
        lambda **_kwargs: SecurityDecision(True, "ok", {"minimum_tls_version": "TLSv1.3"}),
    )
    monkeypatch.setattr(
        connector,
        "build_ssl_context",
        lambda **_kwargs: SimpleNamespace(mode="configured"),
    )

    def _fake_urlopen(request, timeout, context):  # noqa: ANN001,ARG001
        raise urllib_error.URLError(
            ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate")
        )

    monkeypatch.setattr(
        connector,
        "_open_source_request",
        lambda _source, _request, *, timeout_seconds, context, **_kwargs: _fake_urlopen(
            _request, timeout_seconds, context
        ),
    )
    called = {"curl": False}

    def _never_call_curl(**_kwargs):  # noqa: ANN003
        called["curl"] = True
        return {"records": []}

    monkeypatch.setattr(connector, "_fetch_json_via_curl", _never_call_curl)

    with pytest.raises(connector.ExternalFeedFetchError, match="Hint: provide transport_policy.ca_bundle_path"):
        connector.fetch_source_records(src, timeout_seconds=3.0)
    assert called["curl"] is False


def test_extract_payload_rows_flattens_osv_querybatch_results() -> None:
    payload = {
        "results": [
            {"vulns": [{"id": "OSV-1"}, {"id": "OSV-2"}]},
            {"vulns": []},
            {"ignored": True},
        ]
    }
    rows = connector._extract_payload_rows("osv", payload)  # noqa: SLF001
    assert [row.get("id") for row in rows] == ["OSV-1", "OSV-2"]


def test_prepare_request_uses_post_for_osv_querybatch() -> None:
    src = _source(
        source_name="osv",
        endpoint_url="https://api.osv.dev/v1/querybatch",
        routing_policy={"osv_querybatch": [{"package": {"name": "openai", "ecosystem": "PyPI"}}]},
    )
    request = connector._prepare_request(src, src.endpoint_url, {"Accept": "application/json"})  # noqa: SLF001
    assert request.get_method() == "POST"
    assert request.data is not None
    body = json.loads(bytes(request.data).decode("utf-8"))
    assert isinstance(body.get("queries"), list) and len(body["queries"]) == 1


def test_prepare_request_adds_nvd_paging_defaults() -> None:
    src = _source(
        source_name="nvd",
        endpoint_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        routing_policy={"nvd_results_per_page": 150},
    )
    request = connector._prepare_request(src, src.endpoint_url, {"Accept": "application/json"})  # noqa: SLF001
    assert "resultsPerPage=150" in request.full_url
    assert "startIndex=0" in request.full_url
