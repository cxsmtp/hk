"""
Checkmarx One API integration service.

Implements full lifecycle: authenticate → ingest → monitor → enforce → remediate → test.

Checkmarx One API reference:
  - Auth: POST {iam_url}/auth/realms/{tenant}/protocol/openid-connect/token
  - Scans: GET/POST /api/scans
  - Results: GET /api/results (unified), GET /api/sast-results, GET /api/sca-results
  - Projects: GET/POST/PUT/DELETE /api/projects
  - Reports: POST /api/reports, GET /api/reports/{id}
  - Uploads: POST /api/uploads

Regional IAM + API base URLs:
  US:       iam.checkmarx.net    /   ast.checkmarx.net
  US2:      us.iam.checkmarx.net /   us.ast.checkmarx.net
  EU:       eu.iam.checkmarx.net /   eu.ast.checkmarx.net
  EU2:      eu2.iam.checkmarx.net /  eu2.ast.checkmarx.net
  India:    ind.iam.checkmarx.net /  ind.ast.checkmarx.net
  ANZ:      anz.iam.checkmarx.net /  anz.ast.checkmarx.net
  Singapore: sg.iam.checkmarx.net /  sg.ast.checkmarx.net
  UAE:      mea.iam.checkmarx.net /  mea.ast.checkmarx.net

Auth methods:
  1) OAuth2 client credentials: client_id + client_secret
  2) API key (refresh token): grant_type=refresh_token + client_id=ast-app + refresh_token=<key>
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlencode

import httpx

from app.services.outbound_destination_policy import (
    OutboundDestinationPolicy,
    build_outbound_destination_policy,
    request_with_redirect_validation,
)

logger = logging.getLogger("hawk.checkmarx_one")


# ── Regional configuration ───────────────────────────────────────────────────

CHECKMARX_REGIONS: dict[str, dict[str, str]] = {
    "us": {
        "iam_url": "https://iam.checkmarx.net",
        "api_url": "https://ast.checkmarx.net",
    },
    "us2": {
        "iam_url": "https://us.iam.checkmarx.net",
        "api_url": "https://us.ast.checkmarx.net",
    },
    "eu": {
        "iam_url": "https://eu.iam.checkmarx.net",
        "api_url": "https://eu.ast.checkmarx.net",
    },
    "eu2": {
        "iam_url": "https://eu2.iam.checkmarx.net",
        "api_url": "https://eu2.ast.checkmarx.net",
    },
    "india": {
        "iam_url": "https://ind.iam.checkmarx.net",
        "api_url": "https://ind.ast.checkmarx.net",
    },
    "anz": {
        "iam_url": "https://anz.iam.checkmarx.net",
        "api_url": "https://anz.ast.checkmarx.net",
    },
    "singapore": {
        "iam_url": "https://sg.iam.checkmarx.net",
        "api_url": "https://sg.ast.checkmarx.net",
    },
    "uae": {
        "iam_url": "https://mea.iam.checkmarx.net",
        "api_url": "https://mea.ast.checkmarx.net",
    },
}


def _checkmarx_destination_policy() -> OutboundDestinationPolicy:
    return build_outbound_destination_policy(
        {
            "checkmarx": tuple(
                origin
                for region in CHECKMARX_REGIONS.values()
                for origin in (region["api_url"], region["iam_url"])
            )
        }
    )


class CheckmarxAuthMode(str, Enum):
    CLIENT_CREDENTIALS = "client_credentials"
    API_KEY = "api_key"


class ScanStatus(str, Enum):
    QUEUED = "Queued"
    RUNNING = "Running"
    COMPLETED = "Completed"
    PARTIAL = "Partial"
    FAILED = "Failed"
    CANCELED = "Canceled"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ResultState(str, Enum):
    TO_VERIFY = "TO_VERIFY"
    NOT_EXPLOITABLE = "NOT_EXPLOITABLE"
    CONFIRMED = "CONFIRMED"
    URGENT = "URGENT"
    PROPOSED_NOT_EXPLOITABLE = "PROPOSED_NOT_EXPLOITABLE"


@dataclass
class CheckmarxOneClient:
    """Authenticated Checkmarx One API client."""

    api_url: str
    iam_url: str
    tenant_name: str
    access_token: str = ""
    _token_expiry: float = 0.0

    # Auth credentials — one of the two modes
    auth_mode: CheckmarxAuthMode = CheckmarxAuthMode.CLIENT_CREDENTIALS
    client_id: str = ""
    client_secret: str = ""
    api_key: str = ""  # refresh token for API key mode

    timeout_seconds: int = 30
    destination_policy: OutboundDestinationPolicy | None = field(default=None, repr=False)

    def _request(
        self,
        method: str,
        url: str,
        *,
        destination_source: str = "checkmarx",
        timeout_seconds: float | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        policy = self.destination_policy or _checkmarx_destination_policy()
        return request_with_redirect_validation(
            method,
            url,
            source=destination_source,
            policy=policy,
            timeout=timeout_seconds or self.timeout_seconds,
            client_factory=httpx.Client,
            **kwargs,
        )

    def _is_token_valid(self) -> bool:
        return bool(self.access_token) and self._token_expiry > datetime.now(timezone.utc).timestamp() + 30

    def authenticate(self) -> str:
        """Obtain or refresh access token from Checkmarx One IAM."""
        if self._is_token_valid():
            return self.access_token

        token_url = f"{self.iam_url}/auth/realms/{self.tenant_name}/protocol/openid-connect/token"

        if self.auth_mode == CheckmarxAuthMode.API_KEY:
            form_data = {
                "grant_type": "refresh_token",
                "client_id": "ast-app",
                "refresh_token": self.api_key,
            }
        else:
            form_data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }

        response = self._request("POST", token_url, data=form_data)
        if response.status_code != 200:
            raise CheckmarxAuthError(
                f"Authentication failed ({response.status_code}): {response.text[:500]}"
            )
        payload = response.json()

        self.access_token = str(payload.get("access_token", "")).strip()
        expires_in = int(payload.get("expires_in", 0))
        self._token_expiry = datetime.now(timezone.utc).timestamp() + expires_in

        if not self.access_token:
            raise CheckmarxAuthError("Token response missing access_token")

        logger.info("Checkmarx One authenticated (expires_in=%ds)", expires_in)
        return self.access_token

    def _headers(self) -> dict[str, str]:
        self.authenticate()
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json; version=1.0",
        }

    def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        response = self._request("GET", url, headers=self._headers(), params=params)
        response.raise_for_status()
        return response.json()

    def _post(self, path: str, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        response = self._request("POST", url, headers=self._headers(), json=json_body)
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        return response.json()

    def _put(self, path: str, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        response = self._request("PUT", url, headers=self._headers(), json=json_body)
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        return response.json()

    def _patch(self, path: str, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.api_url}{path}"
        response = self._request("PATCH", url, headers=self._headers(), json=json_body)
        response.raise_for_status()
        if response.status_code == 204:
            return {}
        return response.json()

    def _delete(self, path: str) -> None:
        url = f"{self.api_url}{path}"
        response = self._request("DELETE", url, headers=self._headers())
        response.raise_for_status()

    # ── Projects API ──────────────────────────────────────────────────────

    def list_projects(self, *, limit: int = 20, offset: int = 0, name: str | None = None) -> dict[str, Any]:
        """GET /api/projects — list projects with pagination."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if name:
            params["name"] = name
        return self._get("/api/projects", params=params)

    def get_project(self, project_id: str) -> dict[str, Any]:
        """GET /api/projects/{id}"""
        return self._get(f"/api/projects/{project_id}")

    def create_project(self, name: str, *, groups: list[str] | None = None, tags: dict[str, str] | None = None) -> dict[str, Any]:
        """POST /api/projects"""
        body: dict[str, Any] = {"name": name}
        if groups:
            body["groups"] = groups
        if tags:
            body["tags"] = tags
        return self._post("/api/projects", json_body=body)

    def update_project(self, project_id: str, *, name: str | None = None, tags: dict[str, str] | None = None) -> dict[str, Any]:
        """PUT /api/projects/{id}"""
        body: dict[str, Any] = {}
        if name:
            body["name"] = name
        if tags:
            body["tags"] = tags
        return self._put(f"/api/projects/{project_id}", json_body=body)

    def delete_project(self, project_id: str) -> None:
        """DELETE /api/projects/{id}"""
        self._delete(f"/api/projects/{project_id}")

    # ── Scans API ─────────────────────────────────────────────────────────

    def list_scans(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        project_id: str | None = None,
        statuses: list[str] | None = None,
        sort: str = "-created_at",
    ) -> dict[str, Any]:
        """GET /api/scans — list scans with filtering."""
        params: dict[str, Any] = {"limit": limit, "offset": offset, "sort": sort}
        if project_id:
            params["project-id"] = project_id
        if statuses:
            params["statuses"] = ",".join(statuses)
        return self._get("/api/scans", params=params)

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        """GET /api/scans/{id}"""
        return self._get(f"/api/scans/{scan_id}")

    def create_scan(
        self,
        project_id: str,
        *,
        source_type: str = "zip",
        source_url: str = "",
        source_branch: str = "",
        repo_url: str = "",
        scan_types: list[str] | None = None,
        tags: dict[str, str] | None = None,
        config: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """POST /api/scans — trigger a new scan.

        source_type: "zip" (upload), "git" (repo URL)
        scan_types: ["sast", "sca", "kics", "apisec"]
        config: scanner-specific config overrides
        """
        handler: dict[str, Any] = {}
        if source_type == "git":
            handler = {
                "repoUrl": repo_url,
                "branch": source_branch,
            }
        elif source_url:
            handler = {"uploadUrl": source_url}

        body: dict[str, Any] = {
            "type": source_type,
            "project": {"id": project_id},
            "handler": handler,
        }
        if scan_types:
            body["config"] = config or [{"type": st, "value": {}} for st in scan_types]
        if tags:
            body["tags"] = tags
        return self._post("/api/scans", json_body=body)

    def cancel_scan(self, scan_id: str) -> None:
        """PATCH /api/scans/{id} — cancel running scan."""
        self._patch(f"/api/scans/{scan_id}", json_body={"status": "Canceled"})

    def delete_scan(self, scan_id: str) -> None:
        """DELETE /api/scans/{id}"""
        self._delete(f"/api/scans/{scan_id}")

    def get_scan_workflow(self, scan_id: str) -> dict[str, Any]:
        """GET /api/scans/{id}/workflow — get scan execution workflow steps."""
        return self._get(f"/api/scans/{scan_id}/workflow")

    # ── Upload API ────────────────────────────────────────────────────────

    def generate_upload_link(self) -> dict[str, Any]:
        """POST /api/uploads — get a pre-signed upload URL for source code."""
        return self._post("/api/uploads")

    def upload_source(self, upload_url: str, file_content: bytes) -> None:
        """PUT to the pre-signed upload URL with zip file bytes."""
        response = self._request(
            "PUT",
            upload_url,
            destination_source="checkmarx-upload",
            timeout_seconds=120,
            content=file_content,
            headers={"Content-Type": "application/zip"},
        )
        response.raise_for_status()

    # ── Results API (unified + scanner-specific) ──────────────────────────

    def get_results(
        self,
        scan_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: list[str] | None = None,
        state: list[str] | None = None,
        status: list[str] | None = None,
    ) -> dict[str, Any]:
        """GET /api/results — unified results across all scanners.

        Returns: {"results": [...], "totalCount": N}
        Each result has: id, type (sast/sca/kics), severity, state, status,
                         queryName, description, remediationAdvice, data, ...
        """
        params: dict[str, Any] = {
            "scan-id": scan_id,
            "limit": limit,
            "offset": offset,
        }
        if severity:
            params["severity"] = ",".join(severity)
        if state:
            params["state"] = ",".join(state)
        if status:
            params["status"] = ",".join(status)
        return self._get("/api/results", params=params)

    def get_sast_results(self, scan_id: str, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """GET /api/sast-results — SAST-specific results with code nodes."""
        return self._get("/api/sast-results", params={"scan-id": scan_id, "limit": limit, "offset": offset})

    def get_sca_results(self, scan_id: str, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """GET /api/sca-results — SCA (open source) vulnerability results."""
        return self._get("/api/sca-results", params={"scan-id": scan_id, "limit": limit, "offset": offset})

    def get_kics_results(self, scan_id: str, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """GET /api/kics-results — IaC (KICS) scan results."""
        return self._get("/api/kics-results", params={"scan-id": scan_id, "limit": limit, "offset": offset})

    def get_results_summary(self, scan_ids: list[str]) -> dict[str, Any]:
        """GET /api/scan-summary — aggregated severity counts per scan.

        Returns: {"scansSummaries": [{"scanId": ..., "sastCounters": {...}, "scaCounters": {...}}]}
        """
        params = {"scan-ids": ",".join(scan_ids)}
        return self._get("/api/scan-summary", params=params)

    # ── Result Predicates (triage / state management) ─────────────────────

    def update_result_predicate(
        self,
        project_id: str,
        *,
        similarity_id: str,
        state: str,
        severity: str | None = None,
        comment: str | None = None,
    ) -> dict[str, Any]:
        """PATCH /api/sast-results-predicates/{projectId} — triage a result.

        This is the remediation / action endpoint: change state to
        NOT_EXPLOITABLE, CONFIRMED, URGENT, etc.
        """
        predicate: dict[str, Any] = {
            "similarityId": similarity_id,
            "state": state,
        }
        if severity:
            predicate["severity"] = severity
        if comment:
            predicate["comment"] = comment

        return self._patch(
            f"/api/sast-results-predicates/{project_id}",
            json_body=predicate,
        )

    # ── Reports API ───────────────────────────────────────────────────────

    def create_report(
        self,
        scan_id: str,
        *,
        report_type: str = "cli",
        file_format: str = "pdf",
    ) -> dict[str, Any]:
        """POST /api/reports — generate a scan report.

        report_type: "cli" | "ui"
        file_format: "pdf" | "csv" | "json" | "sarif" | "cyclonedx"
        """
        return self._post("/api/reports", json_body={
            "reportType": report_type,
            "fileFormat": file_format,
            "reportName": f"scan-{scan_id}",
            "data": {
                "scanId": scan_id,
                "projectId": "",
            },
        })

    def get_report_status(self, report_id: str) -> dict[str, Any]:
        """GET /api/reports/{id}"""
        return self._get(f"/api/reports/{report_id}")

    def download_report(self, report_id: str) -> bytes:
        """GET /api/reports/{id}/download"""
        url = f"{self.api_url}/api/reports/{report_id}/download"
        response = self._request("GET", url, headers=self._headers())
        response.raise_for_status()
        return response.content

    # ── Applications API ──────────────────────────────────────────────────

    def list_applications(self, *, limit: int = 20, offset: int = 0) -> dict[str, Any]:
        """GET /api/applications"""
        return self._get("/api/applications", params={"limit": limit, "offset": offset})

    def create_application(self, name: str, *, rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """POST /api/applications"""
        body: dict[str, Any] = {"name": name}
        if rules:
            body["rules"] = rules
        return self._post("/api/applications", json_body=body)

    # ── Audit Trail API ──────────────────────────────────────────────────

    def get_audit_trail(self, *, limit: int = 100, offset: int = 0) -> dict[str, Any]:
        """GET /api/audit — compliance audit trail."""
        return self._get("/api/audit", params={"limit": limit, "offset": offset})

    # ── Health check ─────────────────────────────────────────────────────

    def health(self) -> dict[str, Any]:
        """Quick connectivity + auth check."""
        try:
            self.authenticate()
            projects = self.list_projects(limit=1)
            return {
                "provider": "checkmarx_one",
                "ok": True,
                "projects_accessible": projects.get("totalCount", 0),
            }
        except Exception as exc:
            return {
                "provider": "checkmarx_one",
                "ok": False,
                "error": str(exc),
            }


class CheckmarxAuthError(Exception):
    pass


# ── Factory ──────────────────────────────────────────────────────────────────

def create_client_from_connector_config(
    connector_config: dict[str, Any],
    secrets: dict[str, Any],
    *,
    destination_policy: OutboundDestinationPolicy | None = None,
) -> CheckmarxOneClient:
    """Build a CheckmarxOneClient from Hawk connector config + secrets.

    Expected connector_config keys:
      - region: "us" | "eu" | "eu2" | ... (or provide base_url + iam_url)
      - base_url: override API URL
      - iam_url: override IAM URL
      - tenant_name: Checkmarx tenant name (required)
      - auth_mode: "client_credentials" | "api_key" (default: auto-detect)

    Expected secrets keys:
      For client_credentials: client_id, client_secret
      For api_key: api_key (the refresh token from CxOne portal)
    """
    region = str(connector_config.get("region", "us")).strip().lower()
    region_urls = CHECKMARX_REGIONS.get(region, CHECKMARX_REGIONS["us"])

    api_url = str(connector_config.get("base_url") or region_urls["api_url"]).rstrip("/")
    iam_url = str(connector_config.get("iam_url") or region_urls["iam_url"]).rstrip("/")
    policy = destination_policy or _checkmarx_destination_policy()
    policy.validate(api_url, source="checkmarx")
    policy.validate(iam_url, source="checkmarx")

    tenant_name = str(connector_config.get("tenant_name") or secrets.get("tenant_name") or "").strip()
    if not tenant_name:
        raise ValueError("Missing tenant_name in Checkmarx One connector config.")

    # Auto-detect auth mode
    client_id = str(secrets.get("client_id") or "").strip()
    client_secret = str(secrets.get("client_secret") or "").strip()
    api_key = str(secrets.get("api_key") or secrets.get("refresh_token") or "").strip()

    if client_id and client_secret:
        auth_mode = CheckmarxAuthMode.CLIENT_CREDENTIALS
    elif api_key:
        auth_mode = CheckmarxAuthMode.API_KEY
    else:
        raise ValueError(
            "Missing Checkmarx One credentials. Provide client_id+client_secret or api_key (refresh token)."
        )

    return CheckmarxOneClient(
        api_url=api_url,
        iam_url=iam_url,
        tenant_name=tenant_name,
        auth_mode=auth_mode,
        client_id=client_id,
        client_secret=client_secret,
        api_key=api_key,
        destination_policy=policy,
    )


# ── Hawk platform integration: ingest + monitor + enforce + remediate ────────

@dataclass
class CheckmarxFinding:
    """Normalized finding from Checkmarx One for Hawk platform ingestion."""
    finding_id: str
    scan_id: str
    project_id: str
    project_name: str
    scanner_type: str  # sast, sca, kics, apisec
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    state: str  # TO_VERIFY, CONFIRMED, NOT_EXPLOITABLE, URGENT
    query_name: str
    query_group: str
    description: str
    remediation_advice: str
    file_path: str
    line_number: int
    cwe_id: str
    cve_id: str  # SCA only
    package_name: str  # SCA only
    package_version: str  # SCA only
    first_found_at: str
    found_at: str
    similarity_id: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckmarxPullResult:
    """Result of a full Checkmarx One data pull."""
    status: str  # "success", "error", "partial"
    error: str | None
    projects_pulled: int
    scans_pulled: int
    findings_pulled: int
    findings: list[CheckmarxFinding]
    scan_summaries: list[dict[str, Any]]
    raw_projects: list[dict[str, Any]]
    raw_scans: list[dict[str, Any]]


def _normalize_finding(result: dict[str, Any], scan_id: str, project: dict[str, Any]) -> CheckmarxFinding:
    """Normalize a Checkmarx One result into a Hawk-compatible finding."""
    data = result.get("data") or {}
    nodes = data.get("nodes") or []
    first_node = nodes[0] if nodes else {}

    # SCA-specific fields
    package_data = data.get("packageData") or [{}]
    first_package = package_data[0] if isinstance(package_data, list) and package_data else {}

    return CheckmarxFinding(
        finding_id=str(result.get("id", "")),
        scan_id=scan_id,
        project_id=str(project.get("id", "")),
        project_name=str(project.get("name", "")),
        scanner_type=str(result.get("type", "sast")).lower(),
        severity=str(result.get("severity", "MEDIUM")).upper(),
        state=str(result.get("state", "TO_VERIFY")).upper(),
        query_name=str(result.get("data", {}).get("queryName", "") or result.get("queryName", "")),
        query_group=str(data.get("group", "") or data.get("queryGroup", "")),
        description=str(result.get("description", "") or data.get("description", "")),
        remediation_advice=str(data.get("recommendedFix", "") or result.get("remediationAdvice", "")),
        file_path=str(first_node.get("fileName", "") or data.get("fileName", "")),
        line_number=int(first_node.get("line", 0) or data.get("line", 0)),
        cwe_id=str(data.get("cweId", "") or result.get("cweId", "")),
        cve_id=str(data.get("cveId", "") or first_package.get("id", "")),
        package_name=str(first_package.get("name", "") or data.get("packageName", "")),
        package_version=str(first_package.get("version", "") or data.get("packageVersion", "")),
        first_found_at=str(result.get("firstFoundAt", "")),
        found_at=str(result.get("foundAt", "")),
        similarity_id=str(result.get("similarityId", "") or data.get("similarityId", "")),
        raw=result,
    )


def pull_all_findings(
    client: CheckmarxOneClient,
    *,
    max_projects: int = 50,
    max_scans_per_project: int = 1,
    max_results_per_scan: int = 200,
    severity_filter: list[str] | None = None,
    state_filter: list[str] | None = None,
) -> CheckmarxPullResult:
    """Full data pull: projects → latest scans → results → normalized findings.

    This is what the Hawk monitoring connector calls every poll interval.
    """
    try:
        # 1) Pull projects
        projects_response = client.list_projects(limit=max_projects)
        projects = projects_response.get("projects", [])
        if not isinstance(projects, list):
            projects = []

        all_findings: list[CheckmarxFinding] = []
        all_scan_summaries: list[dict[str, Any]] = []
        all_scans: list[dict[str, Any]] = []
        total_scans = 0

        for project in projects:
            project_id = str(project.get("id", ""))
            if not project_id:
                continue

            # 2) Get latest completed scans per project
            scans_response = client.list_scans(
                project_id=project_id,
                statuses=["Completed"],
                limit=max_scans_per_project,
            )
            scans = scans_response.get("scans", [])
            if not isinstance(scans, list):
                scans = []
            all_scans.extend(scans)
            total_scans += len(scans)

            for scan in scans:
                scan_id = str(scan.get("id", ""))
                if not scan_id:
                    continue

                # 3) Pull results for this scan
                results_response = client.get_results(
                    scan_id,
                    limit=max_results_per_scan,
                    severity=severity_filter,
                    state=state_filter,
                )
                results = results_response.get("results", [])
                if not isinstance(results, list):
                    results = []

                for result in results:
                    finding = _normalize_finding(result, scan_id, project)
                    all_findings.append(finding)

                # 4) Get summary counts
                try:
                    summary = client.get_results_summary([scan_id])
                    all_scan_summaries.extend(summary.get("scansSummaries", []))
                except Exception:
                    pass  # Summary is best-effort

        return CheckmarxPullResult(
            status="success",
            error=None,
            projects_pulled=len(projects),
            scans_pulled=total_scans,
            findings_pulled=len(all_findings),
            findings=all_findings,
            scan_summaries=all_scan_summaries,
            raw_projects=projects,
            raw_scans=all_scans,
        )

    except CheckmarxAuthError as exc:
        return CheckmarxPullResult(
            status="error", error=f"Auth failed: {exc}",
            projects_pulled=0, scans_pulled=0, findings_pulled=0,
            findings=[], scan_summaries=[], raw_projects=[], raw_scans=[],
        )
    except Exception as exc:
        return CheckmarxPullResult(
            status="error", error=str(exc),
            projects_pulled=0, scans_pulled=0, findings_pulled=0,
            findings=[], scan_summaries=[], raw_projects=[], raw_scans=[],
        )


# ── Hawk signal normalization (for monitoring_service.py consumption) ────────

def findings_to_hawk_signals(pull_result: CheckmarxPullResult) -> list[dict[str, Any]]:
    """Convert Checkmarx findings into Hawk monitoring signals.

    These feed directly into ingest_monitoring_signal() in monitoring_service.py.
    """
    signals: list[dict[str, Any]] = []

    # Signal 1: Scan posture
    if pull_result.raw_scans:
        latest_scan = pull_result.raw_scans[0]
        signals.append({
            "signal_type": "appsec.checkmarx.scans",
            "severity": "high",
            "payload": {
                "signal_key": "scans",
                "control_id": "CTRL-TOOL-001",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "record": {
                    "scan_id": latest_scan.get("id"),
                    "status": latest_scan.get("status"),
                    "project_id": latest_scan.get("projectId"),
                    "created_at": latest_scan.get("createdAt"),
                    "engines": latest_scan.get("engines", []),
                    "total_scans_pulled": pull_result.scans_pulled,
                },
                "source_metadata": {
                    "provider_key": "checkmarx",
                    "provider_name": "Checkmarx One",
                    "provider_category": "appsec",
                    "auth_method": "OAuth2 client credentials / API key",
                    "transport_security": {"tls_minimum": "1.2+"},
                },
            },
        })

    # Signal 2: Project posture
    if pull_result.raw_projects:
        signals.append({
            "signal_type": "appsec.checkmarx.projects",
            "severity": "med",
            "payload": {
                "signal_key": "projects",
                "control_id": "CTRL-AI-IAM-001",
                "observed_at": datetime.now(timezone.utc).isoformat(),
                "record": {
                    "total_projects": pull_result.projects_pulled,
                    "projects": [
                        {
                            "id": p.get("id"),
                            "name": p.get("name"),
                            "tags": p.get("tags", {}),
                            "created_at": p.get("createdAt"),
                        }
                        for p in pull_result.raw_projects[:10]
                    ],
                },
                "source_metadata": {
                    "provider_key": "checkmarx",
                    "provider_name": "Checkmarx One",
                    "provider_category": "appsec",
                },
            },
        })

    # Signal 3: Findings (the critical one for enforcement)
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in pull_result.findings:
        sev = finding.severity.upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    critical_findings = [
        {
            "id": f.finding_id,
            "scanner": f.scanner_type,
            "severity": f.severity,
            "state": f.state,
            "query_name": f.query_name,
            "file": f.file_path,
            "line": f.line_number,
            "cwe": f.cwe_id,
            "cve": f.cve_id,
            "package": f.package_name,
            "project": f.project_name,
        }
        for f in pull_result.findings
        if f.severity in ("CRITICAL", "HIGH")
    ][:25]  # Cap at 25 for payload size

    signals.append({
        "signal_type": "appsec.checkmarx.findings",
        "severity": "high" if severity_counts["CRITICAL"] + severity_counts["HIGH"] > 0 else "med",
        "payload": {
            "signal_key": "findings",
            "control_id": "CTRL-DLP-001",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "record": {
                "total_findings": pull_result.findings_pulled,
                "severity_counts": severity_counts,
                "critical_high_findings": critical_findings,
                "scan_summaries": pull_result.scan_summaries[:5],
            },
            "source_metadata": {
                "provider_key": "checkmarx",
                "provider_name": "Checkmarx One",
                "provider_category": "appsec",
                "transport_security": {"tls_minimum": "1.2+"},
            },
        },
    })

    return signals


# ── Enforcement actions ──────────────────────────────────────────────────────

def enforce_scan_policy(
    client: CheckmarxOneClient,
    scan_id: str,
    *,
    max_critical: int = 0,
    max_high: int = 5,
    fail_on_new_critical: bool = True,
) -> dict[str, Any]:
    """Policy gate: check scan results against thresholds → pass/fail.

    This is what the Hawk gateway/simulation engine calls to enforce
    AppSec controls on AI system code.
    """
    summary = client.get_results_summary([scan_id])
    summaries = summary.get("scansSummaries", [])
    if not summaries:
        return {"decision": "block", "reason": "No scan summary available", "scan_id": scan_id}

    scan_summary = summaries[0]
    sast = scan_summary.get("sastCounters", {}).get("severityCounters", [])
    sca = scan_summary.get("scaCounters", {}).get("severityCounters", [])

    def _count_severity(counters: list[dict], sev: str) -> int:
        for c in counters:
            if str(c.get("severity", "")).upper() == sev.upper():
                return int(c.get("counter", 0))
        return 0

    critical_count = _count_severity(sast, "CRITICAL") + _count_severity(sca, "CRITICAL")
    high_count = _count_severity(sast, "HIGH") + _count_severity(sca, "HIGH")

    violations: list[str] = []
    if critical_count > max_critical:
        violations.append(f"Critical findings ({critical_count}) exceed threshold ({max_critical})")
    if high_count > max_high:
        violations.append(f"High findings ({high_count}) exceed threshold ({max_high})")

    if violations:
        return {
            "decision": "block",
            "reason": "; ".join(violations),
            "scan_id": scan_id,
            "critical_count": critical_count,
            "high_count": high_count,
            "thresholds": {"max_critical": max_critical, "max_high": max_high},
        }

    return {
        "decision": "allow",
        "reason": "Scan results within policy thresholds",
        "scan_id": scan_id,
        "critical_count": critical_count,
        "high_count": high_count,
    }


def remediate_finding(
    client: CheckmarxOneClient,
    *,
    project_id: str,
    similarity_id: str,
    new_state: str,
    comment: str = "",
    severity_override: str | None = None,
) -> dict[str, Any]:
    """Triage / remediate a finding by changing its state.

    new_state: TO_VERIFY | NOT_EXPLOITABLE | CONFIRMED | URGENT | PROPOSED_NOT_EXPLOITABLE
    """
    return client.update_result_predicate(
        project_id,
        similarity_id=similarity_id,
        state=new_state,
        severity=severity_override,
        comment=comment or f"Triaged by Hawk AI platform at {datetime.now(timezone.utc).isoformat()}",
    )


def trigger_scan(
    client: CheckmarxOneClient,
    *,
    project_id: str,
    repo_url: str,
    branch: str = "main",
    scan_types: list[str] | None = None,
) -> dict[str, Any]:
    """Trigger a new scan from Hawk platform (e.g., after remediation or on schedule)."""
    return client.create_scan(
        project_id,
        source_type="git",
        repo_url=repo_url,
        source_branch=branch,
        scan_types=scan_types or ["sast", "sca", "kics"],
    )
