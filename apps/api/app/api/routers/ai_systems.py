from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.ai_system import AISystem
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.policy_service import get_latest_policy_for_ai_system
from app.services.remediation import propose_remediation_action
from app.services.simulation_scheduler_service import (
    APPROVED_STATUSES,
    schedule_for_ai_system_approved,
    schedule_for_high_risk_tier,
)


router = APIRouter(prefix="/ai-systems", tags=["ai-systems"])

HIGH_RISK_TIERS = {"HIGH", "CRITICAL", "RESTRICTED", "PROHIBITED"}
RISK_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4, "RESTRICTED": 5, "PROHIBITED": 6}


def _risk_rank(value: str | None) -> int:
    return RISK_RANK.get(str(value or "").strip().upper(), 0)


def _owner_assigned(ai_system: AISystem) -> bool:
    metadata = dict(ai_system.metadata_json or {})
    return bool(
        str(metadata.get("owner_user_id") or "").strip()
        or str(metadata.get("owner_department") or "").strip()
        or str(metadata.get("business_owner_user_id") or "").strip()
        or str(metadata.get("technical_owner_user_id") or "").strip()
    )


def _build_lifecycle_missing_requirements(
    *,
    db: Session,
    tenant_id: str,
    ai_system: AISystem,
) -> list[str]:
    missing: list[str] = []
    if not str(ai_system.risk_tier or "").strip():
        missing.append("risk_classification")
    if not _owner_assigned(ai_system):
        missing.append("ownership_assignment")
    policy = get_latest_policy_for_ai_system(db, tenant_id=tenant_id, ai_system=ai_system, actor_type="human")
    if policy is None:
        missing.append("policy_mapping")
    return missing


def _merge_remediation_requirements(metadata: dict, requirements: list[str]) -> list[str]:
    merged = {
        *(str(item).strip() for item in (metadata.get("remediation_requirements") or []) if str(item).strip()),
        *(str(item).strip() for item in requirements if str(item).strip()),
    }
    return sorted(merged)


def _governance_state_snapshot(ai_system: AISystem) -> dict:
    metadata = dict(ai_system.metadata_json or {})
    return {
        "status": str(ai_system.status or ""),
        "risk_tier": str(ai_system.risk_tier or ""),
        "lifecycle_state": str(metadata.get("lifecycle_state") or ""),
        "governance_state": str(metadata.get("governance_state") or ""),
        "ownership_state": str(metadata.get("ownership_state") or ""),
        "business_owner_user_id": str(metadata.get("business_owner_user_id") or metadata.get("owner_user_id") or ""),
        "technical_owner_user_id": str(metadata.get("technical_owner_user_id") or ""),
    }


class AISystemCreate(BaseModel):
    name: str
    description: str = ""
    risk_tier: str
    asset_type: str | None = None
    provider: str | None = None
    version: str | None = None
    owner_team: str | None = None
    deployment_surface: str | None = None
    status_classification: str | None = Field(default=None, description="approved|shadow|under_review|blocked|deprecated")
    supported_clients: list[str] = Field(default_factory=list)
    connected_tools: list[str] = Field(default_factory=list)
    connected_data_sources: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    oauth_scopes: list[str] = Field(default_factory=list)
    blast_radius_score: float | None = None
    evidence_refs: list[str] = Field(default_factory=list)


class AISystemUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    risk_tier: str | None = None
    status: str | None = Field(default=None, description="draft|active|paused|retired")
    asset_type: str | None = None
    provider: str | None = None
    version: str | None = None
    owner_user_id: str | None = None
    owner_team: str | None = None
    deployment_surface: str | None = None
    status_classification: str | None = Field(default=None, description="approved|shadow|under_review|blocked|deprecated")
    supported_clients: list[str] | None = None
    connected_tools: list[str] | None = None
    connected_data_sources: list[str] | None = None
    permissions: list[str] | None = None
    oauth_scopes: list[str] | None = None
    blast_radius_score: float | None = None
    evidence_refs: list[str] | None = None


class AISystemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: str
    risk_tier: str
    status: str
    asset_type: str | None = None
    provider: str | None = None
    version: str | None = None
    owner_user_id: str | None = None
    owner_team: str | None = None
    deployment_surface: str | None = None
    status_classification: str | None = None
    supported_clients: list[str] = Field(default_factory=list)
    connected_tools: list[str] = Field(default_factory=list)
    connected_data_sources: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    oauth_scopes: list[str] = Field(default_factory=list)
    blast_radius_score: float | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    metadata_json: dict = Field(default_factory=dict)


def _metadata_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        normalized = str(item or "").strip()
        if normalized and normalized not in out:
            out.append(normalized)
    return out


def _to_ai_system_response(row: AISystem) -> AISystemResponse:
    metadata = dict(row.metadata_json or {})
    return AISystemResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        description=row.description,
        risk_tier=row.risk_tier,
        status=row.status,
        asset_type=str(metadata.get("asset_type") or "").strip() or None,
        provider=str(metadata.get("provider") or "").strip() or None,
        version=str(metadata.get("version") or "").strip() or None,
        owner_user_id=str(metadata.get("owner_user_id") or "").strip() or None,
        owner_team=str(metadata.get("owner_team") or "").strip() or None,
        deployment_surface=str(metadata.get("deployment_surface") or "").strip() or None,
        status_classification=str(metadata.get("status_classification") or "").strip() or None,
        supported_clients=_metadata_list(metadata.get("supported_clients")),
        connected_tools=_metadata_list(metadata.get("connected_tools")),
        connected_data_sources=_metadata_list(metadata.get("connected_data_sources")),
        permissions=_metadata_list(metadata.get("permissions")),
        oauth_scopes=_metadata_list(metadata.get("oauth_scopes")),
        blast_radius_score=(
            float(metadata.get("blast_radius_score"))
            if metadata.get("blast_radius_score") is not None
            else None
        ),
        evidence_refs=_metadata_list(metadata.get("evidence_refs")),
        metadata_json=metadata,
    )


@router.get("", response_model=ListEnvelope[AISystemResponse])
def list_ai_systems(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(AISystem).where(AISystem.tenant_id == ctx.tenant.id)).all()
    dto_rows = [_to_ai_system_response(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[AISystemResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.post("", response_model=AISystemResponse)
def create_ai_system(
    payload: AISystemCreate,
    ctx: TenantContext = Depends(require_permission("discovery.operate")),
    db: Session = Depends(get_db),
):
    metadata = {
        "asset_type": str(payload.asset_type or "").strip() or None,
        "provider": str(payload.provider or "").strip() or None,
        "version": str(payload.version or "").strip() or None,
        "owner_team": str(payload.owner_team or "").strip() or None,
        "deployment_surface": str(payload.deployment_surface or "").strip() or None,
        "status_classification": str(payload.status_classification or "").strip() or None,
        "supported_clients": _metadata_list(payload.supported_clients),
        "connected_tools": _metadata_list(payload.connected_tools),
        "connected_data_sources": _metadata_list(payload.connected_data_sources),
        "permissions": _metadata_list(payload.permissions),
        "oauth_scopes": _metadata_list(payload.oauth_scopes),
        "blast_radius_score": payload.blast_radius_score,
        "evidence_refs": _metadata_list(payload.evidence_refs),
    }
    row = AISystem(
        tenant_id=ctx.tenant.id,
        name=payload.name,
        description=payload.description,
        risk_tier=payload.risk_tier,
        status="draft",
        metadata_json=metadata,
    )
    db.add(row)
    db.flush()

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_system.create",
        resource_type="ai_system",
        resource_id=row.id,
        payload={"name": row.name, "risk_tier": row.risk_tier},
    )
    db.commit()
    db.refresh(row)
    return _to_ai_system_response(row)


@router.get("/{ai_system_id}", response_model=AISystemResponse)
def get_ai_system(
    ai_system_id: str,
    ctx: TenantContext = Depends(require_permission("discovery.view")),
    db: Session = Depends(get_db),
):
    row = db.scalar(select(AISystem).where(AISystem.id == ai_system_id, AISystem.tenant_id == ctx.tenant.id))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")
    return _to_ai_system_response(row)


@router.patch("/{ai_system_id}", response_model=AISystemResponse)
def update_ai_system(
    ai_system_id: str,
    payload: AISystemUpdate,
    ctx: TenantContext = Depends(require_permission("discovery.operate")),
    db: Session = Depends(get_db),
):
    row = db.scalar(select(AISystem).where(AISystem.id == ai_system_id, AISystem.tenant_id == ctx.tenant.id))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")

    previous_status = str(row.status or "").strip().lower()
    previous_risk_tier = str(row.risk_tier or "").strip().upper()
    metadata = dict(row.metadata_json or {})

    for field in ["name", "description", "risk_tier", "status"]:
        value = getattr(payload, field)
        if value is not None:
            setattr(row, field, value)

    metadata_updates = {
        "asset_type": payload.asset_type,
        "provider": payload.provider,
        "version": payload.version,
        "owner_user_id": payload.owner_user_id,
        "owner_team": payload.owner_team,
        "deployment_surface": payload.deployment_surface,
        "status_classification": payload.status_classification,
        "supported_clients": payload.supported_clients,
        "connected_tools": payload.connected_tools,
        "connected_data_sources": payload.connected_data_sources,
        "permissions": payload.permissions,
        "oauth_scopes": payload.oauth_scopes,
        "blast_radius_score": payload.blast_radius_score,
        "evidence_refs": payload.evidence_refs,
    }
    for key, value in metadata_updates.items():
        if value is None:
            continue
        if isinstance(value, list):
            metadata[key] = _metadata_list(value)
        else:
            normalized = str(value).strip() if isinstance(value, str) else value
            metadata[key] = normalized if normalized not in {"", []} else None
    row.metadata_json = metadata

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_system.update",
        resource_type="ai_system",
        resource_id=row.id,
        payload=payload.model_dump(exclude_none=True),
    )

    current_status = str(row.status or "").strip().lower()
    current_risk_tier = str(row.risk_tier or "").strip().upper()
    approved_transition = previous_status not in APPROVED_STATUSES and current_status in APPROVED_STATUSES
    risk_tier_changed = current_risk_tier != previous_risk_tier
    risk_escalated = _risk_rank(current_risk_tier) > _risk_rank(previous_risk_tier)

    if current_status == "live":
        missing_requirements = _build_lifecycle_missing_requirements(db=db, tenant_id=ctx.tenant.id, ai_system=row)
        if missing_requirements:
            before_state = _governance_state_snapshot(row)
            requested_live_transition = previous_status != "live"
            row.status = (previous_status or "draft") if requested_live_transition else "restricted"
            metadata = dict(row.metadata_json or {})
            metadata["compliance_state"] = "NON_COMPLIANT"
            metadata["lifecycle_state"] = "REVIEW" if requested_live_transition else "RESTRICTED"
            metadata["governance_state"] = "REVIEW"
            metadata["ownership_state"] = "MISSING" if "ownership_assignment" in missing_requirements else metadata.get("ownership_state")
            metadata["last_lifecycle_blocked_at"] = datetime.now(timezone.utc).isoformat()
            metadata["missing_requirements"] = sorted(set(missing_requirements))
            metadata["requires_reapproval"] = True
            metadata["remediation_requirements"] = _merge_remediation_requirements(
                metadata,
                [
                    *missing_requirements,
                    "governance_review",
                ],
            )
            row.metadata_json = metadata
            db.flush()
            after_state = _governance_state_snapshot(row)

            reason_code = (
                "trust_center_owner_missing"
                if set(missing_requirements) == {"ownership_assignment"}
                else "trust_center_lifecycle_prereq_missing"
            )
            finding_type = (
                "trust_center_ownership_missing"
                if reason_code == "trust_center_owner_missing"
                else "trust_center_lifecycle_block"
            )

            remediation = propose_remediation_action(
                db,
                tenant_id=ctx.tenant.id,
                source_trigger_type="guardian_violation",
                source_trigger_id=(
                    f"trust_center_ownership_missing:{row.id}"
                    if reason_code == "trust_center_owner_missing"
                    else f"trust_center_lifecycle_block:{row.id}:{uuid4().hex[:8]}"
                ),
                target_type="ai_system",
                target_id=row.id,
                severity="high",
                context={
                    "ai_system_id": row.id,
                    "finding_type": finding_type,
                    "reason_code": reason_code,
                    "regulated": True,
                    "lifecycle_transition_requested": "live",
                    "missing_requirements": missing_requirements,
                    "related_control_ids": ["CTRL-TENANT-ISO-001"],
                    "state_before": before_state,
                    "state_after": after_state,
                },
            )
            write_audit_log(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=None,
                actor_type="system",
                action="ai_system.lifecycle.transition_blocked",
                resource_type="ai_system",
                resource_id=row.id,
                payload={
                    "requested_status": "live",
                    "requested_transition_to_live": requested_live_transition,
                    "enforced_status": row.status,
                    "missing_requirements": missing_requirements,
                    "state_before": before_state,
                    "state_after": after_state,
                    "remediation_id": remediation.id,
                },
            )
            write_audit_log(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=None,
                actor_type="system",
                action="auditor.notify.remediation_required",
                resource_type="ai_system",
                resource_id=row.id,
                payload={
                    "reason_code": reason_code,
                    "missing_requirements": missing_requirements,
                    "remediation_id": remediation.id,
                    "state_after": after_state,
                },
            )
            db.commit()
            if requested_live_transition:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "code": "lifecycle_transition_blocked",
                        "message": "LIVE transition blocked until governance prerequisites are resolved.",
                        "missing_requirements": missing_requirements,
                        "remediation_id": remediation.id,
                    },
                )

    if approved_transition:
        metadata = dict(row.metadata_json or {})
        metadata["governance_state"] = "APPROVED"
        metadata["lifecycle_state"] = metadata.get("lifecycle_state") or "ACTIVE"
        metadata["approved_at"] = datetime.now(timezone.utc).isoformat()
        row.metadata_json = metadata
        schedule_for_ai_system_approved(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=row.id,
            actor_user_id=None,
        )
    if risk_tier_changed:
        schedule_for_high_risk_tier(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=row.id,
            risk_tier=row.risk_tier,
            actor_user_id=None,
        )
        if risk_escalated and current_risk_tier in HIGH_RISK_TIERS:
            before_state = _governance_state_snapshot(row)
            metadata = dict(row.metadata_json or {})
            metadata["risk_escalation_at"] = datetime.now(timezone.utc).isoformat()
            metadata["governance_state"] = "REVIEW"
            metadata["requires_reapproval"] = True
            metadata["remediation_requirements"] = _merge_remediation_requirements(
                metadata,
                ["risk_reassessment", "policy_alignment_review"],
            )
            if current_status == "live":
                row.status = "restricted"
                metadata["lifecycle_state"] = "RESTRICTED"
            row.metadata_json = metadata
            db.flush()
            after_state = _governance_state_snapshot(row)
            remediation = propose_remediation_action(
                db,
                tenant_id=ctx.tenant.id,
                source_trigger_type="runtime_pattern",
                # Keep both correlation fields intact within source_trigger_id's
                # 64-character contract, including the longest supported tier.
                source_trigger_id=f"risk_escalation:{row.id}:{current_risk_tier}",
                target_type="ai_system",
                target_id=row.id,
                severity="high",
                context={
                    "ai_system_id": row.id,
                    "finding_type": "trust_center_risk_escalation",
                    "reason_code": "runtime_or_monitoring_risk_escalation",
                    "related_control_ids": ["CTRL-TENANT-ISO-001", "CTRL-INPUT-001"],
                    "occurrence_count": 2,
                    "state_before": before_state,
                    "state_after": after_state,
                },
            )
            write_audit_log(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=None,
                actor_type="system",
                action="ai_system.risk.escalated",
                resource_type="ai_system",
                resource_id=row.id,
                payload={
                    "from_risk_tier": previous_risk_tier,
                    "to_risk_tier": current_risk_tier,
                    "state_before": before_state,
                    "state_after": after_state,
                    "remediation_id": remediation.id,
                },
            )
            write_audit_log(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=None,
                actor_type="system",
                action="auditor.notify.risk_escalation",
                resource_type="ai_system",
                resource_id=row.id,
                payload={
                    "from_risk_tier": previous_risk_tier,
                    "to_risk_tier": current_risk_tier,
                    "remediation_id": remediation.id,
                    "state_after": after_state,
                },
            )

    db.commit()
    db.refresh(row)
    return _to_ai_system_response(row)
