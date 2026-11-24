from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.audit_evidence_service import explain_evidence_node


router = APIRouter(prefix="/audit", tags=["audit"])


class ViolatedPolicyResponse(BaseModel):
    policy_version_id: str | None = None
    policy_version: str | None = None
    policy_pack_id: str | None = None
    policy_pack_name: str | None = None


class FrameworkMappingResponse(BaseModel):
    framework: str
    controls: list[str]


class AuditEvidenceExplanationResponse(BaseModel):
    evidence_id: str
    decision: str
    reason: str
    violated_policy: ViolatedPolicyResponse
    confidence_score: float
    framework_mapping: list[FrameworkMappingResponse]
    signal_type: str
    label: str
    correlation_id: str | None = None
    created_at: datetime
    trace: dict[str, Any]


@router.get("/evidence/{evidence_id}", response_model=AuditEvidenceExplanationResponse)
def audit_evidence_explanation(
    evidence_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = explain_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        evidence_id=evidence_id,
    )
    if payload is None:
        raise HTTPException(status_code=404, detail="Evidence node not found")
    return AuditEvidenceExplanationResponse.model_validate(payload)
