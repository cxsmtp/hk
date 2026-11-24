from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.policy import ToolFingerprint, ToolScanResult
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.external_capability_integrity import ExternalCapabilityIntegrityService


class MCPToolFingerprintNotFoundError(LookupError):
    pass


class MCPToolFingerprintConflictError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def list_mcp_tool_fingerprints(
    db: Session,
    *,
    tenant_id: str,
    trust_status: str | None,
    limit: int,
) -> dict[str, Any]:
    query = select(ToolFingerprint).where(ToolFingerprint.tenant_id == tenant_id)
    if trust_status is not None:
        query = query.where(ToolFingerprint.trust_status == trust_status)
    rows = list(
        db.scalars(
            query.order_by(
                ToolFingerprint.last_scanned_at.desc(),
                ToolFingerprint.id.asc(),
            ).limit(max(1, min(int(limit), 100)))
        )
    )
    return {
        "items": [_serialize_fingerprint(db, row) for row in rows],
        "count": len(rows),
    }


def decide_mcp_tool_fingerprint(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str,
    tool_fingerprint_id: str,
    decision: str,
    expected_manifest_hash: str,
    reason: str,
    commit: bool = True,
) -> dict[str, Any]:
    row = db.scalar(
        select(ToolFingerprint)
        .where(
            ToolFingerprint.id == tool_fingerprint_id,
            ToolFingerprint.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    if row is None:
        raise MCPToolFingerprintNotFoundError()
    if row.manifest_hash != expected_manifest_hash:
        raise MCPToolFingerprintConflictError(
            "mcp_tool_fingerprint_changed",
            "The MCP tool fingerprint changed before the decision was applied.",
        )

    authority = db.scalar(
        select(ToolScanResult).where(
            ToolScanResult.id == row.id,
            ToolScanResult.tenant_id == tenant_id,
            ToolScanResult.tool_fingerprint_id == row.id,
        )
    )
    if decision == "approve" and (
        authority is None or authority.trust_status != "poisoning:allow"
    ):
        raise MCPToolFingerprintConflictError(
            "mcp_tool_scan_not_approvable",
            "The current MCP tool scan is not eligible for approval.",
        )

    now = datetime.now(timezone.utc)
    if decision == "approve":
        row.trust_status = "approved"
        row.approved_hash = row.manifest_hash
    elif decision == "block":
        row.trust_status = "blocked"
        row.approved_hash = None
    else:
        row.trust_status = "under_review"
        row.approved_hash = None
    row.approved_by = actor_user_id
    row.approved_at = now

    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="mcp_tool_fingerprint_decision",
        signal_type="agentic.mcp.tool.fingerprint.decision",
        label=f"MCP tool fingerprint {row.trust_status}",
        payload={
            "tool_fingerprint_id": row.id,
            "mcp_server_id": row.mcp_server_id,
            "tool_name": row.tool_name,
            "tool_version": row.tool_version,
            "manifest_hash": row.manifest_hash,
            "trust_status": row.trust_status,
            "reason": reason,
        },
    )
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action=f"mcp_tool_fingerprint.{decision}",
        resource_type="mcp_tool_fingerprint",
        resource_id=row.id,
        payload={
            "manifest_hash": row.manifest_hash,
            "trust_status": row.trust_status,
            "evidence_node_id": evidence.id,
            "reason": reason,
        },
    )
    external_capability: dict[str, Any] | None = None
    if decision == "approve":
        try:
            state = ExternalCapabilityIntegrityService().accept_current_baseline(
                db,
                tenant_id=tenant_id,
                capability_ref=f"mcp:{row.mcp_server_id}",
                actor_ref=f"user:{actor_user_id}",
                reason=reason,
                accepted_at=now,
            )
            external_capability = {
                "capability_id": state.capability_id,
                "capability_ref": state.capability_ref,
                "trust_state": state.trust_state,
                "material_fingerprint": state.material_fingerprint,
                "baseline_material_fingerprint": state.baseline_material_fingerprint,
                "capability_epoch": state.capability_epoch,
            }
        except PermissionError:
            external_capability = {
                "trust_state": "UNKNOWN",
                "reason": "external_capability_not_observed",
            }
    if commit:
        db.commit()
    return {
        "tool_fingerprint_id": row.id,
        "trust_status": row.trust_status,
        "manifest_hash": row.manifest_hash,
        "approved_hash": row.approved_hash,
        "evidence_node_id": evidence.id,
        "audit_log_id": audit.id,
        "external_capability": external_capability,
    }


def _serialize_fingerprint(db: Session, row: ToolFingerprint) -> dict[str, Any]:
    latest_scan = db.scalar(
        select(ToolScanResult)
        .where(
            ToolScanResult.tenant_id == row.tenant_id,
            ToolScanResult.tool_fingerprint_id == row.id,
            ~ToolScanResult.trust_status.like("poisoning:%"),
        )
        .order_by(ToolScanResult.created_at.desc(), ToolScanResult.id.desc())
        .limit(1)
    )
    return {
        "id": row.id,
        "mcp_server_id": row.mcp_server_id,
        "tool_name": row.tool_name,
        "tool_version": row.tool_version,
        "manifest_hash": row.manifest_hash,
        "description_hash": row.description_hash,
        "schema_hash": row.schema_hash,
        "examples_hash": row.examples_hash,
        "approved_hash": row.approved_hash,
        "trust_status": row.trust_status,
        "risk_factors": list(latest_scan.risk_factors or []) if latest_scan else [],
        "evidence_node_id": latest_scan.evidence_node_id if latest_scan else None,
        "last_scanned_at": row.last_scanned_at,
        "approved_by": row.approved_by,
        "approved_at": row.approved_at,
    }
