"""
Checkmarx One integration router.

Provides direct API access to Checkmarx One for:
  - Health check and connector status
  - Project listing and management
  - Scan triggering and monitoring
  - Findings retrieval and policy enforcement
  - Result triage / remediation
  - Report generation
  - Full data pull into Hawk monitoring pipeline
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.monitoring import Connector
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.connector_secret_service import decrypt_connector_secrets
from app.services.checkmarx_one_service import (
    CheckmarxAuthError,
    CheckmarxOneClient,
    create_client_from_connector_config,
    enforce_scan_policy,
    findings_to_hawk_signals,
    pull_all_findings,
    remediate_finding,
    trigger_scan,
)
from app.services.evidence_service import create_evidence_node
from app.services.monitoring_service import ingest_monitoring_signal

router = APIRouter(prefix="/checkmarx", tags=["checkmarx"])


# ── Helpers ──────────────────────────────────────────────────────────────────

def _get_connector(db: Session, tenant_id: str, connector_id: str | None = None) -> Connector:
    """Load the Checkmarx connector for the tenant."""
    query = select(Connector).where(
        Connector.tenant_id == tenant_id,
        Connector.provider_key == "checkmarx",
    )
    if connector_id:
        query = query.where(Connector.id == connector_id)
    connector = db.scalar(query.order_by(Connector.created_at.desc()))
    if not connector:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Checkmarx One connector configured for this tenant.",
        )
    return connector


def _build_client(connector: Connector) -> CheckmarxOneClient:
    """Build an authenticated client from a stored connector."""
    config = dict(connector.config or {})
    secrets = decrypt_connector_secrets(connector.encrypted_secrets or "")
    try:
        return create_client_from_connector_config(config, secrets)
    except (ValueError, CheckmarxAuthError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Checkmarx One connection failed: {exc}",
        ) from exc


# ── Request / Response schemas ───────────────────────────────────────────────

class CheckmarxHealthResponse(BaseModel):
    provider: str = "checkmarx_one"
    ok: bool
    projects_accessible: int = 0
    error: str | None = None


class ScanTriggerRequest(BaseModel):
    project_id: str
    repo_url: str
    branch: str = "main"
    scan_types: list[str] = Field(default_factory=lambda: ["sast", "sca", "kics"])


class ScanPolicyRequest(BaseModel):
    scan_id: str
    max_critical: int = 0
    max_high: int = 5
    fail_on_new_critical: bool = True


class RemediateRequest(BaseModel):
    project_id: str
    similarity_id: str
    new_state: str  # TO_VERIFY, NOT_EXPLOITABLE, CONFIRMED, URGENT
    comment: str = ""
    severity_override: str | None = None


class PullRequest(BaseModel):
    max_projects: int = 50
    max_scans_per_project: int = 1
    max_results_per_scan: int = 200
    severity_filter: list[str] | None = None
    state_filter: list[str] | None = None
    ingest_into_monitoring: bool = True


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/health")
def checkmarx_health(
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
) -> CheckmarxHealthResponse:
    """Check Checkmarx One connectivity and authentication."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    result = client.health()
    return CheckmarxHealthResponse(**result)


@router.get("/projects")
def list_projects(
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
    name: str | None = Query(default=None),
):
    """List Checkmarx One projects."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.list_projects(limit=limit, offset=offset, name=name)


@router.get("/projects/{project_id}")
def get_project(
    project_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Get a single Checkmarx One project."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_project(project_id)


@router.get("/scans")
def list_scans(
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
    project_id: str | None = Query(default=None),
    limit: int = Query(default=20, le=100),
    offset: int = Query(default=0, ge=0),
):
    """List Checkmarx One scans."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.list_scans(limit=limit, offset=offset, project_id=project_id)


@router.get("/scans/{scan_id}")
def get_scan(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Get scan status and details."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_scan(scan_id)


@router.post("/scans/trigger")
def trigger_new_scan(
    payload: ScanTriggerRequest,
    ctx: TenantContext = Depends(require_permission("integrations.manage")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Trigger a new Checkmarx One scan from Hawk."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)

    result = trigger_scan(
        client,
        project_id=payload.project_id,
        repo_url=payload.repo_url,
        branch=payload.branch,
        scan_types=payload.scan_types,
    )

    # Audit the scan trigger
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="user",
        action="checkmarx.scan.triggered",
        resource_type="checkmarx_scan",
        resource_id=str(result.get("id", "")),
        payload={
            "project_id": payload.project_id,
            "repo_url": payload.repo_url,
            "branch": payload.branch,
            "scan_types": payload.scan_types,
        },
    )
    db.commit()

    return result


@router.get("/results/{scan_id}")
def get_results(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None, description="Comma-separated: CRITICAL,HIGH,MEDIUM,LOW,INFO"),
    state: str | None = Query(default=None, description="Comma-separated: TO_VERIFY,CONFIRMED,URGENT,NOT_EXPLOITABLE"),
):
    """Get scan results (all scanners: SAST, SCA, KICS, DAST)."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_results(
        scan_id,
        limit=limit,
        offset=offset,
        severity=severity.split(",") if severity else None,
        state=state.split(",") if state else None,
    )


@router.get("/results/{scan_id}/sast")
def get_sast_results(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Get SAST-specific results with code flow nodes."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_sast_results(scan_id, limit=limit, offset=offset)


@router.get("/results/{scan_id}/sca")
def get_sca_results(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Get SCA (open-source vulnerability) results."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_sca_results(scan_id, limit=limit, offset=offset)


@router.get("/results/{scan_id}/summary")
def get_results_summary(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Get severity summary counts for a scan."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_results_summary([scan_id])


@router.post("/enforce")
def enforce_policy(
    payload: ScanPolicyRequest,
    ctx: TenantContext = Depends(require_permission("integrations.operate")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Enforce AppSec policy gate on a scan.

    Returns { decision: "allow" | "block", reason: "..." }
    """
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    result = enforce_scan_policy(
        client,
        payload.scan_id,
        max_critical=payload.max_critical,
        max_high=payload.max_high,
        fail_on_new_critical=payload.fail_on_new_critical,
    )

    # Write evidence + audit
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="system",
        action=f"checkmarx.enforcement.{result['decision']}",
        resource_type="checkmarx_scan",
        resource_id=payload.scan_id,
        payload=result,
    )
    create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="appsec_enforcement",
        signal_type="checkmarx.enforcement",
        label=f"Checkmarx policy enforcement: {result['decision']}",
        payload=result,
    )
    db.commit()

    return result


@router.post("/remediate")
def remediate(
    payload: RemediateRequest,
    ctx: TenantContext = Depends(require_permission("integrations.manage")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Triage / remediate a Checkmarx finding (change state).

    new_state: TO_VERIFY | NOT_EXPLOITABLE | CONFIRMED | URGENT
    """
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    result = remediate_finding(
        client,
        project_id=payload.project_id,
        similarity_id=payload.similarity_id,
        new_state=payload.new_state,
        comment=payload.comment,
        severity_override=payload.severity_override,
    )

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="user",
        action="checkmarx.finding.remediated",
        resource_type="checkmarx_finding",
        resource_id=payload.similarity_id,
        payload={
            "project_id": payload.project_id,
            "new_state": payload.new_state,
            "comment": payload.comment,
        },
    )
    db.commit()

    return result


@router.post("/pull")
def full_data_pull(
    payload: PullRequest,
    ctx: TenantContext = Depends(require_permission("integrations.manage")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Full Checkmarx One data pull → normalize → optionally ingest into Hawk monitoring.

    This is the manual trigger for the same logic the scheduled connector pull runs.
    """
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)

    pull_result = pull_all_findings(
        client,
        max_projects=payload.max_projects,
        max_scans_per_project=payload.max_scans_per_project,
        max_results_per_scan=payload.max_results_per_scan,
        severity_filter=payload.severity_filter,
        state_filter=payload.state_filter,
    )

    if pull_result.status == "error":
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Checkmarx pull failed: {pull_result.error}",
        )

    response: dict[str, Any] = {
        "status": pull_result.status,
        "projects_pulled": pull_result.projects_pulled,
        "scans_pulled": pull_result.scans_pulled,
        "findings_pulled": pull_result.findings_pulled,
        "severity_breakdown": {},
    }

    # Count severities
    for finding in pull_result.findings:
        sev = finding.severity
        response["severity_breakdown"][sev] = response["severity_breakdown"].get(sev, 0) + 1

    # Ingest into Hawk monitoring pipeline
    if payload.ingest_into_monitoring and pull_result.findings:
        signals = findings_to_hawk_signals(pull_result)
        ingested_count = 0
        for signal in signals:
            try:
                ingest_monitoring_signal(
                    db,
                    tenant_id=ctx.tenant.id,
                    signal_type=signal["signal_type"],
                    severity=signal["severity"],
                    payload=signal["payload"],
                    source="checkmarx_one_connector",
                    source_metadata=signal["payload"].get("source_metadata", {}),
                )
                ingested_count += 1
            except Exception:
                pass  # Best-effort signal ingestion
        db.commit()
        response["signals_ingested"] = ingested_count

    # Audit
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="system",
        action="checkmarx.full_pull.completed",
        resource_type="checkmarx_connector",
        resource_id=connector.id,
        payload={
            "projects": pull_result.projects_pulled,
            "scans": pull_result.scans_pulled,
            "findings": pull_result.findings_pulled,
        },
    )
    db.commit()

    return response


@router.post("/reports/{scan_id}")
def generate_report(
    scan_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.operate")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
    file_format: str = Query(default="pdf", pattern="^(pdf|csv|json|sarif|cyclonedx)$"),
):
    """Generate a Checkmarx One scan report."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.create_report(scan_id, file_format=file_format)


@router.get("/reports/{report_id}/status")
def report_status(
    report_id: str,
    ctx: TenantContext = Depends(require_permission("integrations.inspect")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
):
    """Get report generation status."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_report_status(report_id)


@router.get("/audit-trail")
def audit_trail(
    ctx: TenantContext = Depends(require_permission("integrations.review")),
    db: Session = Depends(get_db),
    connector_id: str | None = Query(default=None),
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Get Checkmarx One audit trail (compliance events)."""
    connector = _get_connector(db, ctx.tenant.id, connector_id)
    client = _build_client(connector)
    return client.get_audit_trail(limit=limit, offset=offset)
