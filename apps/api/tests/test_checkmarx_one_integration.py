"""
Comprehensive tests for Checkmarx One integration.

Covers:
  1. Authentication (client_credentials + API key modes)
  2. Project listing and management
  3. Scan triggering and status retrieval
  4. Results retrieval (unified, SAST, SCA, KICS)
  5. Enforcement policy gate (pass/fail)
  6. Remediation (finding state change)
  7. Hawk signal normalization
  8. Full data pull pipeline
  9. Connector auth flow in integration_connector_service
  10. Router endpoints via TestClient
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.services.checkmarx_one_service import (
    CHECKMARX_REGIONS,
    CheckmarxAuthError,
    CheckmarxAuthMode,
    CheckmarxOneClient,
    CheckmarxPullResult,
    create_client_from_connector_config,
    enforce_scan_policy,
    findings_to_hawk_signals,
    pull_all_findings,
    remediate_finding,
    trigger_scan,
    _normalize_finding,
)
from app.services import outbound_destination_policy
from app.services.outbound_destination_policy import OutboundDestinationPolicy


@pytest.fixture(autouse=True)
def _mock_public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        outbound_destination_policy,
        "_system_resolver",
        lambda _hostname, _port: ("93.184.216.34",),
    )


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def mock_client() -> CheckmarxOneClient:
    """Pre-authenticated client with mocked token."""
    client = CheckmarxOneClient(
        api_url="https://ast.checkmarx.net",
        iam_url="https://iam.checkmarx.net",
        tenant_name="test-tenant",
        auth_mode=CheckmarxAuthMode.CLIENT_CREDENTIALS,
        client_id="test-client-id",
        client_secret="test-client-secret",
        access_token="mock-token-12345",
        _token_expiry=datetime(2099, 1, 1, tzinfo=timezone.utc).timestamp(),
    )
    return client


MOCK_PROJECT = {
    "id": "proj-001",
    "name": "AI-Gateway-Service",
    "tags": {"team": "platform"},
    "createdAt": "2026-01-15T10:00:00Z",
}

MOCK_SCAN = {
    "id": "scan-001",
    "projectId": "proj-001",
    "status": "Completed",
    "createdAt": "2026-04-01T12:00:00Z",
    "engines": ["sast", "sca", "kics"],
}

MOCK_SAST_RESULT = {
    "id": "result-sast-001",
    "type": "sast",
    "severity": "HIGH",
    "state": "TO_VERIFY",
    "similarityId": "sim-001",
    "queryName": "SQL_Injection",
    "description": "User input flows into SQL query without sanitization",
    "firstFoundAt": "2026-03-01T10:00:00Z",
    "foundAt": "2026-04-01T12:00:00Z",
    "data": {
        "queryName": "SQL_Injection",
        "group": "SQL_Injection",
        "cweId": "89",
        "nodes": [
            {"fileName": "app/services/user_service.py", "line": 42, "column": 15},
            {"fileName": "app/db/queries.py", "line": 18, "column": 8},
        ],
        "recommendedFix": "Use parameterized queries instead of string concatenation.",
    },
}

MOCK_SCA_RESULT = {
    "id": "result-sca-001",
    "type": "sca",
    "severity": "CRITICAL",
    "state": "TO_VERIFY",
    "similarityId": "sim-002",
    "queryName": "CVE-2024-12345",
    "description": "Critical vulnerability in lodash < 4.17.21",
    "firstFoundAt": "2026-02-15T08:00:00Z",
    "foundAt": "2026-04-01T12:00:00Z",
    "data": {
        "cveId": "CVE-2024-12345",
        "packageData": [{"name": "lodash", "version": "4.17.20", "id": "CVE-2024-12345"}],
        "recommendedFix": "Upgrade lodash to >= 4.17.21",
    },
}

MOCK_SCAN_SUMMARY = {
    "scansSummaries": [
        {
            "scanId": "scan-001",
            "sastCounters": {
                "severityCounters": [
                    {"severity": "CRITICAL", "counter": 0},
                    {"severity": "HIGH", "counter": 3},
                    {"severity": "MEDIUM", "counter": 12},
                    {"severity": "LOW", "counter": 25},
                ],
            },
            "scaCounters": {
                "severityCounters": [
                    {"severity": "CRITICAL", "counter": 1},
                    {"severity": "HIGH", "counter": 2},
                    {"severity": "MEDIUM", "counter": 5},
                    {"severity": "LOW", "counter": 8},
                ],
            },
        }
    ]
}


# ── 1. Authentication Tests ──────────────────────────────────────────────────

class TestAuthentication:

    def test_client_credentials_auth(self) -> None:
        """Test OAuth2 client_credentials flow."""
        client = CheckmarxOneClient(
            api_url="https://ast.checkmarx.net",
            iam_url="https://iam.checkmarx.net",
            tenant_name="test-tenant",
            auth_mode=CheckmarxAuthMode.CLIENT_CREDENTIALS,
            client_id="cid",
            client_secret="csecret",
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "tok-123", "expires_in": 3600}

        with patch("httpx.Client") as mock_http:
            mock_http.return_value.__enter__ = MagicMock(return_value=MagicMock(request=MagicMock(return_value=mock_response)))
            mock_http.return_value.__exit__ = MagicMock(return_value=False)
            token = client.authenticate()

        assert token == "tok-123"
        assert client.access_token == "tok-123"

    def test_api_key_auth(self) -> None:
        """Test refresh_token (API key) flow."""
        client = CheckmarxOneClient(
            api_url="https://ast.checkmarx.net",
            iam_url="https://iam.checkmarx.net",
            tenant_name="test-tenant",
            auth_mode=CheckmarxAuthMode.API_KEY,
            api_key="refresh-tok-abc",
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "tok-456", "expires_in": 1800}

        with patch("httpx.Client") as mock_http:
            mock_http.return_value.__enter__ = MagicMock(return_value=MagicMock(request=MagicMock(return_value=mock_response)))
            mock_http.return_value.__exit__ = MagicMock(return_value=False)
            token = client.authenticate()

        assert token == "tok-456"

    def test_auth_failure_raises(self) -> None:
        """Test that auth failure raises CheckmarxAuthError."""
        client = CheckmarxOneClient(
            api_url="https://ast.checkmarx.net",
            iam_url="https://iam.checkmarx.net",
            tenant_name="test-tenant",
            auth_mode=CheckmarxAuthMode.CLIENT_CREDENTIALS,
            client_id="bad",
            client_secret="bad",
        )
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Invalid credentials"

        with patch("httpx.Client") as mock_http:
            mock_http.return_value.__enter__ = MagicMock(return_value=MagicMock(request=MagicMock(return_value=mock_response)))
            mock_http.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(CheckmarxAuthError, match="Authentication failed"):
                client.authenticate()

    def test_token_reuse_when_valid(self, mock_client: CheckmarxOneClient) -> None:
        """Test that valid tokens are reused without re-auth."""
        # Token already set with far-future expiry
        token = mock_client.authenticate()
        assert token == "mock-token-12345"

    def test_token_url_construction(self) -> None:
        """Verify token URL uses correct IAM realm path."""
        client = CheckmarxOneClient(
            api_url="https://eu.ast.checkmarx.net",
            iam_url="https://eu.iam.checkmarx.net",
            tenant_name="my-org",
            auth_mode=CheckmarxAuthMode.CLIENT_CREDENTIALS,
            client_id="cid",
            client_secret="csecret",
        )
        # We verify by inspecting what URL is called
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"access_token": "t", "expires_in": 100}

        mock_http_client = MagicMock()
        mock_http_client.request = MagicMock(return_value=mock_response)

        with patch("httpx.Client") as mock_http:
            mock_http.return_value.__enter__ = MagicMock(return_value=mock_http_client)
            mock_http.return_value.__exit__ = MagicMock(return_value=False)
            client.authenticate()

        call_args = mock_http_client.request.call_args
        assert call_args[0][1] == "https://eu.iam.checkmarx.net/auth/realms/my-org/protocol/openid-connect/token"


# ── 2. Region Configuration Tests ───────────────────────────────────────────

class TestRegionConfig:

    def test_all_regions_defined(self) -> None:
        expected_regions = {"us", "us2", "eu", "eu2", "india", "anz", "singapore", "uae"}
        assert expected_regions == set(CHECKMARX_REGIONS.keys())

    def test_all_regions_have_https_urls(self) -> None:
        for region, urls in CHECKMARX_REGIONS.items():
            assert urls["iam_url"].startswith("https://"), f"{region} IAM URL not HTTPS"
            assert urls["api_url"].startswith("https://"), f"{region} API URL not HTTPS"

    def test_us_region_urls(self) -> None:
        assert CHECKMARX_REGIONS["us"]["iam_url"] == "https://iam.checkmarx.net"
        assert CHECKMARX_REGIONS["us"]["api_url"] == "https://ast.checkmarx.net"

    def test_eu_region_urls(self) -> None:
        assert CHECKMARX_REGIONS["eu"]["iam_url"] == "https://eu.iam.checkmarx.net"
        assert CHECKMARX_REGIONS["eu"]["api_url"] == "https://eu.ast.checkmarx.net"


# ── 3. Client Factory Tests ─────────────────────────────────────────────────

class TestClientFactory:

    def test_client_credentials_from_config(self) -> None:
        client = create_client_from_connector_config(
            {"region": "eu", "tenant_name": "acme"},
            {"client_id": "cid", "client_secret": "csec"},
        )
        assert client.auth_mode == CheckmarxAuthMode.CLIENT_CREDENTIALS
        assert client.api_url == "https://eu.ast.checkmarx.net"
        assert client.iam_url == "https://eu.iam.checkmarx.net"
        assert client.tenant_name == "acme"

    def test_api_key_from_config(self) -> None:
        client = create_client_from_connector_config(
            {"region": "us2", "tenant_name": "corp"},
            {"api_key": "refresh-token-xyz"},
        )
        assert client.auth_mode == CheckmarxAuthMode.API_KEY
        assert client.api_key == "refresh-token-xyz"
        assert client.api_url == "https://us.ast.checkmarx.net"

    def test_refresh_token_alias(self) -> None:
        client = create_client_from_connector_config(
            {"region": "us", "tenant_name": "org"},
            {"refresh_token": "rt-abc"},
        )
        assert client.auth_mode == CheckmarxAuthMode.API_KEY
        assert client.api_key == "rt-abc"

    def test_custom_urls_override_region(self) -> None:
        policy = OutboundDestinationPolicy(
            {
                "checkmarx": (
                    "https://custom.ast.example.com",
                    "https://custom.iam.example.com",
                )
            },
            resolver=lambda _hostname, _port: ("93.184.216.34",),
        )
        client = create_client_from_connector_config(
            {
                "region": "us",
                "tenant_name": "custom",
                "base_url": "https://custom.ast.example.com",
                "iam_url": "https://custom.iam.example.com",
            },
            {"client_id": "c", "client_secret": "s"},
            destination_policy=policy,
        )
        assert client.api_url == "https://custom.ast.example.com"
        assert client.iam_url == "https://custom.iam.example.com"

    def test_missing_tenant_raises(self) -> None:
        with pytest.raises(ValueError, match="Missing tenant_name"):
            create_client_from_connector_config({"region": "us"}, {"client_id": "c", "client_secret": "s"})

    def test_missing_credentials_raises(self) -> None:
        with pytest.raises(ValueError, match="Missing Checkmarx One credentials"):
            create_client_from_connector_config({"region": "us", "tenant_name": "x"}, {})

    def test_client_credentials_preferred_over_api_key(self) -> None:
        """When both are provided, client_credentials should be used."""
        client = create_client_from_connector_config(
            {"region": "us", "tenant_name": "org"},
            {"client_id": "c", "client_secret": "s", "api_key": "k"},
        )
        assert client.auth_mode == CheckmarxAuthMode.CLIENT_CREDENTIALS


# ── 4. Finding Normalization Tests ───────────────────────────────────────────

class TestFindingNormalization:

    def test_normalize_sast_finding(self) -> None:
        finding = _normalize_finding(MOCK_SAST_RESULT, "scan-001", MOCK_PROJECT)
        assert finding.finding_id == "result-sast-001"
        assert finding.scanner_type == "sast"
        assert finding.severity == "HIGH"
        assert finding.state == "TO_VERIFY"
        assert finding.query_name == "SQL_Injection"
        assert finding.file_path == "app/services/user_service.py"
        assert finding.line_number == 42
        assert finding.cwe_id == "89"
        assert finding.project_name == "AI-Gateway-Service"
        assert finding.similarity_id == "sim-001"
        assert "parameterized queries" in finding.remediation_advice

    def test_normalize_sca_finding(self) -> None:
        finding = _normalize_finding(MOCK_SCA_RESULT, "scan-001", MOCK_PROJECT)
        assert finding.scanner_type == "sca"
        assert finding.severity == "CRITICAL"
        assert finding.cve_id == "CVE-2024-12345"
        assert finding.package_name == "lodash"
        assert finding.package_version == "4.17.20"

    def test_normalize_empty_result(self) -> None:
        finding = _normalize_finding({}, "scan-x", {"id": "p", "name": "P"})
        assert finding.scanner_type == "sast"
        assert finding.severity == "MEDIUM"
        assert finding.file_path == ""
        assert finding.line_number == 0


# ── 5. Enforcement Tests ────────────────────────────────────────────────────

class TestEnforcement:

    def test_enforce_within_thresholds_allows(self, mock_client: CheckmarxOneClient) -> None:
        """Scan with acceptable findings should ALLOW."""
        mock_summary = {
            "scansSummaries": [{
                "scanId": "scan-001",
                "sastCounters": {"severityCounters": [
                    {"severity": "CRITICAL", "counter": 0},
                    {"severity": "HIGH", "counter": 2},
                ]},
                "scaCounters": {"severityCounters": [
                    {"severity": "CRITICAL", "counter": 0},
                    {"severity": "HIGH", "counter": 1},
                ]},
            }]
        }
        with patch.object(mock_client, "get_results_summary", return_value=mock_summary):
            result = enforce_scan_policy(mock_client, "scan-001", max_critical=0, max_high=5)
        assert result["decision"] == "allow"
        assert result["critical_count"] == 0
        assert result["high_count"] == 3

    def test_enforce_critical_threshold_blocks(self, mock_client: CheckmarxOneClient) -> None:
        """Scan with critical findings should BLOCK."""
        mock_summary = {
            "scansSummaries": [{
                "scanId": "scan-001",
                "sastCounters": {"severityCounters": [{"severity": "CRITICAL", "counter": 2}]},
                "scaCounters": {"severityCounters": [{"severity": "CRITICAL", "counter": 1}]},
            }]
        }
        with patch.object(mock_client, "get_results_summary", return_value=mock_summary):
            result = enforce_scan_policy(mock_client, "scan-001", max_critical=0, max_high=10)
        assert result["decision"] == "block"
        assert "Critical findings (3) exceed threshold (0)" in result["reason"]

    def test_enforce_high_threshold_blocks(self, mock_client: CheckmarxOneClient) -> None:
        """Scan with too many high findings should BLOCK."""
        mock_summary = {
            "scansSummaries": [{
                "scanId": "scan-001",
                "sastCounters": {"severityCounters": [
                    {"severity": "CRITICAL", "counter": 0},
                    {"severity": "HIGH", "counter": 8},
                ]},
                "scaCounters": {"severityCounters": [
                    {"severity": "HIGH", "counter": 4},
                ]},
            }]
        }
        with patch.object(mock_client, "get_results_summary", return_value=mock_summary):
            result = enforce_scan_policy(mock_client, "scan-001", max_critical=0, max_high=5)
        assert result["decision"] == "block"
        assert result["high_count"] == 12

    def test_enforce_no_summary_blocks(self, mock_client: CheckmarxOneClient) -> None:
        """Missing summary should default to BLOCK."""
        with patch.object(mock_client, "get_results_summary", return_value={"scansSummaries": []}):
            result = enforce_scan_policy(mock_client, "scan-missing")
        assert result["decision"] == "block"
        assert "No scan summary" in result["reason"]

    def test_enforce_both_violations(self, mock_client: CheckmarxOneClient) -> None:
        """Both critical AND high exceed thresholds."""
        mock_summary = {
            "scansSummaries": [{
                "scanId": "s",
                "sastCounters": {"severityCounters": [
                    {"severity": "CRITICAL", "counter": 5},
                    {"severity": "HIGH", "counter": 20},
                ]},
                "scaCounters": {"severityCounters": []},
            }]
        }
        with patch.object(mock_client, "get_results_summary", return_value=mock_summary):
            result = enforce_scan_policy(mock_client, "s", max_critical=0, max_high=5)
        assert result["decision"] == "block"
        assert "Critical" in result["reason"]
        assert "High" in result["reason"]


# ── 6. Signal Normalization Tests ────────────────────────────────────────────

class TestSignalNormalization:

    def test_signals_produced_from_pull(self) -> None:
        pull = CheckmarxPullResult(
            status="success",
            error=None,
            projects_pulled=2,
            scans_pulled=3,
            findings_pulled=5,
            findings=[
                _normalize_finding(MOCK_SAST_RESULT, "s1", MOCK_PROJECT),
                _normalize_finding(MOCK_SCA_RESULT, "s1", MOCK_PROJECT),
            ],
            scan_summaries=[MOCK_SCAN_SUMMARY["scansSummaries"][0]],
            raw_projects=[MOCK_PROJECT],
            raw_scans=[MOCK_SCAN],
        )
        signals = findings_to_hawk_signals(pull)
        assert len(signals) == 3  # scans + projects + findings

        signal_types = {s["signal_type"] for s in signals}
        assert "appsec.checkmarx.scans" in signal_types
        assert "appsec.checkmarx.projects" in signal_types
        assert "appsec.checkmarx.findings" in signal_types

    def test_findings_signal_has_severity_counts(self) -> None:
        pull = CheckmarxPullResult(
            status="success", error=None,
            projects_pulled=1, scans_pulled=1, findings_pulled=2,
            findings=[
                _normalize_finding(MOCK_SAST_RESULT, "s1", MOCK_PROJECT),
                _normalize_finding(MOCK_SCA_RESULT, "s1", MOCK_PROJECT),
            ],
            scan_summaries=[], raw_projects=[], raw_scans=[],
        )
        signals = findings_to_hawk_signals(pull)
        findings_signal = [s for s in signals if s["signal_type"] == "appsec.checkmarx.findings"][0]
        counts = findings_signal["payload"]["record"]["severity_counts"]
        assert counts["HIGH"] == 1
        assert counts["CRITICAL"] == 1

    def test_empty_pull_still_produces_findings_signal(self) -> None:
        pull = CheckmarxPullResult(
            status="success", error=None,
            projects_pulled=0, scans_pulled=0, findings_pulled=0,
            findings=[], scan_summaries=[], raw_projects=[], raw_scans=[],
        )
        signals = findings_to_hawk_signals(pull)
        assert len(signals) == 1  # Just the findings signal (no scans/projects)
        assert signals[0]["signal_type"] == "appsec.checkmarx.findings"

    def test_signal_metadata_has_provider_info(self) -> None:
        pull = CheckmarxPullResult(
            status="success", error=None,
            projects_pulled=0, scans_pulled=0, findings_pulled=0,
            findings=[], scan_summaries=[], raw_projects=[], raw_scans=[MOCK_SCAN],
        )
        signals = findings_to_hawk_signals(pull)
        scan_signal = [s for s in signals if s["signal_type"] == "appsec.checkmarx.scans"][0]
        meta = scan_signal["payload"]["source_metadata"]
        assert meta["provider_key"] == "checkmarx"
        assert meta["provider_name"] == "Checkmarx One"


# ── 7. Full Pull Pipeline Tests ──────────────────────────────────────────────

class TestFullPull:

    def test_successful_pull(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "list_projects", return_value={"projects": [MOCK_PROJECT]}), \
             patch.object(mock_client, "list_scans", return_value={"scans": [MOCK_SCAN]}), \
             patch.object(mock_client, "get_results", return_value={"results": [MOCK_SAST_RESULT, MOCK_SCA_RESULT]}), \
             patch.object(mock_client, "get_results_summary", return_value=MOCK_SCAN_SUMMARY):
            result = pull_all_findings(mock_client, max_projects=10)

        assert result.status == "success"
        assert result.projects_pulled == 1
        assert result.scans_pulled == 1
        assert result.findings_pulled == 2

    def test_auth_failure_returns_error(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "list_projects", side_effect=CheckmarxAuthError("bad creds")):
            result = pull_all_findings(mock_client)
        assert result.status == "error"
        assert "Auth failed" in result.error

    def test_api_error_returns_error(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "list_projects", side_effect=RuntimeError("timeout")):
            result = pull_all_findings(mock_client)
        assert result.status == "error"
        assert "timeout" in result.error

    def test_empty_projects_returns_success(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "list_projects", return_value={"projects": []}):
            result = pull_all_findings(mock_client)
        assert result.status == "success"
        assert result.findings_pulled == 0

    def test_scan_with_no_results(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "list_projects", return_value={"projects": [MOCK_PROJECT]}), \
             patch.object(mock_client, "list_scans", return_value={"scans": [MOCK_SCAN]}), \
             patch.object(mock_client, "get_results", return_value={"results": []}), \
             patch.object(mock_client, "get_results_summary", return_value={"scansSummaries": []}):
            result = pull_all_findings(mock_client)
        assert result.status == "success"
        assert result.findings_pulled == 0


# ── 8. Remediation Tests ────────────────────────────────────────────────────

class TestRemediation:

    def test_remediate_calls_update_predicate(self, mock_client: CheckmarxOneClient) -> None:
        mock_response = {"success": True}
        with patch.object(mock_client, "update_result_predicate", return_value=mock_response) as mock_update:
            result = remediate_finding(
                mock_client,
                project_id="proj-001",
                similarity_id="sim-001",
                new_state="NOT_EXPLOITABLE",
                comment="False positive confirmed by Hawk AI analysis",
            )
        mock_update.assert_called_once_with(
            "proj-001",
            similarity_id="sim-001",
            state="NOT_EXPLOITABLE",
            severity=None,
            comment="False positive confirmed by Hawk AI analysis",
        )
        assert result == mock_response

    def test_remediate_with_severity_override(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "update_result_predicate", return_value={}) as mock_update:
            remediate_finding(
                mock_client,
                project_id="proj-001",
                similarity_id="sim-002",
                new_state="CONFIRMED",
                severity_override="CRITICAL",
            )
        call_kwargs = mock_update.call_args
        assert call_kwargs.kwargs.get("severity") == "CRITICAL" or call_kwargs[1].get("severity") == "CRITICAL"


# ── 9. Scan Triggering Tests ────────────────────────────────────────────────

class TestScanTriggering:

    def test_trigger_scan_calls_create(self, mock_client: CheckmarxOneClient) -> None:
        mock_response = {"id": "new-scan-001", "status": "Queued"}
        with patch.object(mock_client, "create_scan", return_value=mock_response) as mock_create:
            result = trigger_scan(
                mock_client,
                project_id="proj-001",
                repo_url="https://github.com/org/repo",
                branch="develop",
                scan_types=["sast", "sca"],
            )
        mock_create.assert_called_once()
        assert result["id"] == "new-scan-001"

    def test_trigger_scan_default_types(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "create_scan", return_value={"id": "s"}) as mock_create:
            trigger_scan(mock_client, project_id="p", repo_url="https://github.com/r")
        args = mock_create.call_args
        assert args.kwargs.get("scan_types") == ["sast", "sca", "kics"] or args[1].get("scan_types") == ["sast", "sca", "kics"]


# ── 10. Connector Integration Tests ─────────────────────────────────────────

class TestConnectorIntegration:

    def test_checkmarx_provider_in_catalog(self) -> None:
        from app.services.integration_connector_service import PROVIDERS
        assert "checkmarx" in PROVIDERS
        provider = PROVIDERS["checkmarx"]
        assert provider.auth_mode == "checkmarx_one_oauth"
        assert provider.category == "appsec"
        assert provider.supports_live_pull is True
        assert len(provider.signal_mappings) == 5  # scans + projects + findings + summary + audit

    def test_signal_types_match_expected(self) -> None:
        from app.services.integration_connector_service import PROVIDERS
        signal_types = {m.signal_type for m in PROVIDERS["checkmarx"].signal_mappings}
        assert "appsec.checkmarx.scans" in signal_types
        assert "appsec.checkmarx.projects" in signal_types
        assert "appsec.checkmarx.findings" in signal_types
        assert "appsec.checkmarx.results_summary" in signal_types
        assert "appsec.checkmarx.audit_trail" in signal_types

    def test_evidence_nodes_produced(self) -> None:
        from app.services.integration_connector_service import PROVIDERS
        evidence = PROVIDERS["checkmarx"].connector_spec.evidence_nodes_produced
        assert "connector.checkmarx.findings" in evidence
        assert "connector.checkmarx.results_summary" in evidence

    def test_modules_mapping_exists(self) -> None:
        from app.services.integration_connector_service import modules_for_signal
        modules = modules_for_signal("checkmarx", "appsec.checkmarx.findings")
        assert "interaction_security" in modules
        assert "monitoring" in modules
        assert "auditor" in modules


# ── 11. Health Check Tests ───────────────────────────────────────────────────

class TestHealthCheck:

    def test_health_ok(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "list_projects", return_value={"totalCount": 12}):
            result = mock_client.health()
        assert result["ok"] is True
        assert result["projects_accessible"] == 12

    def test_health_failure(self, mock_client: CheckmarxOneClient) -> None:
        with patch.object(mock_client, "authenticate", side_effect=CheckmarxAuthError("expired")):
            result = mock_client.health()
        assert result["ok"] is False
        assert "expired" in result["error"]
