"""Tenant-safe APIs for the reusable Policy Pack Platform.

The router owns presentation, RBAC, audit, and transaction handling. All pack
compilation and precedence remains in the service layer and ultimately emits
the repository's existing deterministic PolicyVersion scoped rules.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import parse_policy_pack_platform_rollout, settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.policy_pack_platform import (
    PolicyPackAssignment,
    PolicyPackDefinition,
    PolicyPackInstance,
    PolicyPackPlatformEntitlement,
    PolicyPackSimulation,
    PolicyPackUserGroup,
)
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.policy_pack_platform.service import (
    PolicyPackPlatformError,
    accept_policy_pack_update,
    apply_policy_pack,
    bulk_assign_policy_pack_instance,
    capability_report_for_policy_pack,
    compare_policy_pack_update,
    create_policy_pack_group,
    framework_atlas,
    resolve_effective_policy_explanation,
    resolve_group_member_ids,
    resolved_definition_templates,
    simulate_policy_pack,
    transition_policy_pack_instance,
)


def _require_policy_pack_platform_enabled(ctx: TenantContext = Depends(require_role(min_role="viewer"))) -> None:
    rollout = parse_policy_pack_platform_rollout(settings.policy_pack_platform_rollout)
    if not settings.policy_pack_platform_enabled or rollout.get(str(ctx.tenant.id)) is not True:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


router = APIRouter(
    prefix="/policy-pack-platform",
    tags=["policy-pack-platform"],
    dependencies=[Depends(_require_policy_pack_platform_enabled)],
)


class ApplyPackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignments: list[dict[str, Any]] = Field(min_length=1, max_length=128)
    customer_parameters: dict[str, Any] = Field(default_factory=dict)
    local_overrides: dict[str, Any] = Field(default_factory=dict)
    disabled_template_ids: list[str] = Field(default_factory=list, max_length=128)
    added_customer_templates: list[dict[str, Any]] = Field(default_factory=list, max_length=128)
    requested_state: str = Field(default="DRAFT", min_length=3, max_length=32)


class SimulationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    historical_events: list[dict[str, Any]] | None = Field(default=None, max_length=1_000)


class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_state: str = Field(min_length=3, max_length=32)
    approver_ref: str | None = Field(default=None, min_length=3, max_length=255)


class GroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_key: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    group_type: str = Field(min_length=2, max_length=32)
    membership_rule: dict[str, Any] = Field(default_factory=dict)
    member_user_ids: list[str] = Field(default_factory=list, max_length=10_000)
    nested_group_ids: list[str] = Field(default_factory=list, max_length=32)


class BulkAssignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assignments: list[dict[str, Any]] = Field(min_length=1, max_length=128)


class UpdateAcceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=2_000)


def _actor_ref(ctx: TenantContext) -> str:
    return f"user:{ctx.user.id}"


def _error(exc: Exception) -> HTTPException:
    detail = str(exc)
    if detail.endswith("_not_found"):
        code = status.HTTP_404_NOT_FOUND
    elif "entitlement" in detail or "package_tier" in detail:
        code = status.HTTP_403_FORBIDDEN
    else:
        code = status.HTTP_422_UNPROCESSABLE_ENTITY
    return HTTPException(status_code=code, detail=detail)


def _definition_payload(
    row: PolicyPackDefinition,
    *,
    include_templates: bool = False,
    db: Session | None = None,
    tenant_id: str | None = None,
) -> dict[str, Any]:
    payload = {
        "id": row.id,
        "stable_pack_id": row.stable_pack_id,
        "version": row.version,
        "name": row.name,
        "description": row.description,
        "vertical": row.vertical,
        "department_persona": row.department_persona,
        "pack_family": row.pack_family,
        "maturity_status": row.maturity_status,
        "package_entitlement": row.package_entitlement,
        "applicable_jurisdictions": row.applicable_jurisdictions or [],
        "framework_mappings": row.framework_mappings or {},
        "inherited_pack_refs": row.inherited_pack_refs or [],
        "required_signals": row.required_signals or [],
        "required_control_capabilities": row.required_control_capabilities or [],
        "supported_deployment_surfaces": row.supported_deployment_surfaces or [],
        "default_parameters": row.default_parameters or {},
        "customization_schema": row.customization_schema or {},
        "simulation_required": row.simulation_required,
        "default_rollout": row.default_rollout,
        "exception_guidance": row.exception_guidance,
        "known_blind_spots": row.known_blind_spots or [],
        "owner_publisher": row.owner_publisher,
        "release_notes": row.release_notes,
        "state": row.state,
    }
    if include_templates and db is not None and tenant_id is not None:
        resolved = resolved_definition_templates(db, tenant_id=tenant_id, definition=row)
        payload["templates"] = resolved["local_templates"]
        payload["inherited_templates"] = resolved["inherited_templates"]
        payload["definition_lineage"] = resolved["definition_lineage"]
    elif include_templates and db is not None:
        from app.db.models.policy_pack_platform import PolicyPackTemplate

        payload["templates"] = [
            {
                "template_id": item.template_id,
                "title": item.title,
                "reason": item.reason,
                "condition_tree": item.condition_tree or {},
                "decision": item.decision,
                "applicable_surfaces": item.applicable_surfaces or [],
                "required_fields": item.required_fields or [],
                "required_control_capabilities": item.required_control_capabilities or [],
                "default_mode": item.default_mode,
                "recommended_mature_mode": item.recommended_mature_mode,
                "criticality": item.criticality,
                "override_behavior": item.override_behavior,
                "exception_rules": item.exception_rules or {},
                "simulation_expectations": item.simulation_expectations or {},
                "evidence_requirements": item.evidence_requirements or [],
                "human_explanation": item.human_explanation,
                "reference_mappings": item.reference_mappings or {},
                "non_overridable": item.non_overridable,
                "explicit_revocation": item.explicit_revocation,
            }
            for item in db.scalars(select(PolicyPackTemplate).where(PolicyPackTemplate.definition_id == row.id)).all()
        ]
    return payload


def _instance_payload(row: PolicyPackInstance) -> dict[str, Any]:
    return {
        "id": row.id,
        "definition_id": row.definition_id,
        "source_pack_id": row.source_pack_id,
        "source_pack_version": row.source_pack_version,
        "selected_vertical": row.selected_vertical,
        "selected_department_persona": row.selected_department_persona,
        "selected_applications": row.selected_applications or [],
        "selected_surfaces": row.selected_surfaces or [],
        "customer_parameters": row.customer_parameters or {},
        "local_overrides": row.local_overrides or {},
        "disabled_template_ids": row.disabled_template_ids or [],
        "rollout": row.rollout or {},
        "runtime_policy_pack_id": row.runtime_policy_pack_id,
        "effective_policy_version_id": row.effective_policy_version_id,
        "previous_effective_policy_version_id": row.previous_effective_policy_version_id,
        "last_simulation_id": row.last_simulation_id,
        "update_available": row.update_available,
        "owner_ref": row.owner_ref,
        "approver_ref": row.approver_ref,
        "state": row.state,
        "lineage": row.lineage or {},
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def _simulation_payload(row: PolicyPackSimulation) -> dict[str, Any]:
    return {
        "id": row.id,
        "instance_id": row.instance_id,
        "policy_version_id": row.policy_version_id,
        "sample_count": row.sample_count,
        "outcome_counts": row.outcome_counts or {},
        "scope_breakdown": row.scope_breakdown or {},
        "status": row.status,
        "evidence_refs": row.evidence_refs or [],
        "created_at": row.created_at,
    }


@router.get("/catalog")
def list_catalog(
    vertical: str | None = Query(default=None, max_length=128),
    department_persona: str | None = Query(default=None, max_length=128),
    surface: str | None = Query(default=None, max_length=64),
    package_tier: str | None = Query(default=None, max_length=16),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        from app.services.policy_pack_platform.service import list_policy_pack_definitions

        rows = list_policy_pack_definitions(
            db, tenant_id=ctx.tenant.id, vertical=vertical, department_persona=department_persona, surface=surface, package_tier=package_tier
        )
        return {"items": [_definition_payload(row) for row in rows], "count": len(rows)}
    except Exception as exc:
        raise _error(exc) from exc


@router.get("/framework-atlas")
def get_framework_atlas(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        return framework_atlas(db, tenant_id=ctx.tenant.id)
    except Exception as exc:
        raise _error(exc) from exc


@router.get("/definitions/{definition_id}")
def get_definition(
    definition_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(PolicyPackDefinition).where(
            PolicyPackDefinition.id == definition_id,
            (PolicyPackDefinition.publisher_tenant_id.is_(None) | (PolicyPackDefinition.publisher_tenant_id == ctx.tenant.id)),
        )
    )
    if row is None or row.state == "WITHDRAWN":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy_pack_definition_not_found")
    return _definition_payload(row, include_templates=True, db=db, tenant_id=ctx.tenant.id)


@router.get("/definitions/{definition_id}/preview")
def preview_definition(
    definition_id: str,
    surfaces: list[str] = Query(default=[]),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = db.scalar(
        select(PolicyPackDefinition).where(
            PolicyPackDefinition.id == definition_id,
            (PolicyPackDefinition.publisher_tenant_id.is_(None) | (PolicyPackDefinition.publisher_tenant_id == ctx.tenant.id)),
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy_pack_definition_not_found")
    try:
        return {"definition": _definition_payload(row, include_templates=True, db=db, tenant_id=ctx.tenant.id), "capability_coverage": capability_report_for_policy_pack(db, tenant_id=ctx.tenant.id, definition=row, selected_surfaces=surfaces or None)}
    except Exception as exc:
        raise _error(exc) from exc


@router.post("/definitions/{definition_id}/apply", status_code=status.HTTP_201_CREATED)
def apply_definition(
    definition_id: str,
    payload: ApplyPackRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        result = apply_policy_pack(
            db,
            tenant_id=ctx.tenant.id,
            definition_id=definition_id,
            assignments=payload.assignments,
            customer_parameters=payload.customer_parameters,
            local_overrides=payload.local_overrides,
            disabled_template_ids=payload.disabled_template_ids,
            added_customer_templates=payload.added_customer_templates,
            requested_state=payload.requested_state,
            requested_by_ref=_actor_ref(ctx),
        )
        write_audit_log(db, tenant_id=ctx.tenant.id, actor_user_id=ctx.user.id, actor_type="human", action="policy_pack.apply", resource_type="policy_pack_instance", resource_id=result.instance.id, payload={"definition_id": definition_id, "requested_state": result.instance.state, "assignment_count": len(payload.assignments)})
        db.commit()
        return {"instance": _instance_payload(result.instance), "capability_coverage": result.capability_report}
    except Exception as exc:
        db.rollback()
        raise _error(exc) from exc


@router.get("/instances")
def list_instances(
    state_filter: str | None = Query(default=None, alias="state", max_length=32),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(PolicyPackInstance).where(PolicyPackInstance.tenant_id == ctx.tenant.id)
    if state_filter:
        query = query.where(PolicyPackInstance.state == state_filter.upper())
    rows = list(db.scalars(query.order_by(PolicyPackInstance.updated_at.desc())).all())
    return {"items": [_instance_payload(row) for row in rows], "count": len(rows)}


@router.post("/instances/{instance_id}/simulate")
def simulate_instance(
    instance_id: str,
    payload: SimulationRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = simulate_policy_pack(db, tenant_id=ctx.tenant.id, instance_id=instance_id, historical_events=payload.historical_events)
        write_audit_log(db, tenant_id=ctx.tenant.id, actor_user_id=ctx.user.id, actor_type="human", action="policy_pack.simulate", resource_type="policy_pack_instance", resource_id=instance_id, payload={"simulation_id": row.id, "sample_count": row.sample_count, "status": row.status})
        db.commit()
        return _simulation_payload(row)
    except Exception as exc:
        db.rollback()
        raise _error(exc) from exc


@router.post("/instances/{instance_id}/transition")
def transition_instance(
    instance_id: str,
    payload: TransitionRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = transition_policy_pack_instance(db, tenant_id=ctx.tenant.id, instance_id=instance_id, target_state=payload.target_state, actor_ref=_actor_ref(ctx), approver_ref=payload.approver_ref)
        write_audit_log(db, tenant_id=ctx.tenant.id, actor_user_id=ctx.user.id, actor_type="human", action="policy_pack.transition", resource_type="policy_pack_instance", resource_id=row.id, payload={"state": row.state, "approver_ref": row.approver_ref})
        db.commit()
        return _instance_payload(row)
    except Exception as exc:
        db.rollback()
        raise _error(exc) from exc


@router.post("/instances/{instance_id}/assignments/bulk")
def bulk_assign(
    instance_id: str,
    payload: BulkAssignmentRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        result = bulk_assign_policy_pack_instance(db, tenant_id=ctx.tenant.id, instance_id=instance_id, assignments=payload.assignments, actor_ref=_actor_ref(ctx))
        write_audit_log(db, tenant_id=ctx.tenant.id, actor_user_id=ctx.user.id, actor_type="human", action="policy_pack.assignment.bulk", resource_type="policy_pack_instance", resource_id=instance_id, payload=result)
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _error(exc) from exc


@router.get("/instances/{instance_id}/assignments")
def list_assignments(
    instance_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    instance = db.scalar(select(PolicyPackInstance).where(PolicyPackInstance.tenant_id == ctx.tenant.id, PolicyPackInstance.id == instance_id))
    if instance is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy_pack_instance_not_found")
    rows = list(db.scalars(select(PolicyPackAssignment).where(PolicyPackAssignment.tenant_id == ctx.tenant.id, PolicyPackAssignment.instance_id == instance_id).order_by(PolicyPackAssignment.precedence_layer.desc())).all())
    return {"items": [{"id": row.id, "targets": row.targets or {}, "precedence_layer": row.precedence_layer, "inherited_path": row.inherited_path or [], "active": row.active} for row in rows]}


@router.get("/instances/{instance_id}/updates/{definition_id}/compare")
def compare_update(
    instance_id: str,
    definition_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        comparison = compare_policy_pack_update(db, tenant_id=ctx.tenant.id, instance_id=instance_id, new_definition_id=definition_id)
        db.commit()
        return comparison
    except Exception as exc:
        db.rollback()
        raise _error(exc) from exc


@router.post("/instances/{instance_id}/updates/{definition_id}/accept")
def accept_update(
    instance_id: str,
    definition_id: str,
    payload: UpdateAcceptRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = accept_policy_pack_update(db, tenant_id=ctx.tenant.id, instance_id=instance_id, new_definition_id=definition_id, actor_ref=_actor_ref(ctx), reason=payload.reason)
        write_audit_log(db, tenant_id=ctx.tenant.id, actor_user_id=ctx.user.id, actor_type="human", action="policy_pack.update.accept", resource_type="policy_pack_instance", resource_id=row.id, payload={"definition_id": definition_id})
        db.commit()
        return _instance_payload(row)
    except Exception as exc:
        db.rollback()
        raise _error(exc) from exc


@router.post("/groups", status_code=status.HTTP_201_CREATED)
def create_group(
    payload: GroupRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        row = create_policy_pack_group(db, tenant_id=ctx.tenant.id, group_key=payload.group_key, name=payload.name, group_type=payload.group_type, membership_rule=payload.membership_rule, member_user_ids=payload.member_user_ids, nested_group_ids=payload.nested_group_ids, actor_ref=_actor_ref(ctx))
        write_audit_log(db, tenant_id=ctx.tenant.id, actor_user_id=ctx.user.id, actor_type="human", action="policy_pack.group.create", resource_type="policy_pack_group", resource_id=row.id, payload={"group_key": row.group_key, "group_type": row.group_type})
        db.commit()
        return {"id": row.id, "group_key": row.group_key, "name": row.name, "group_type": row.group_type, "membership_rule": row.membership_rule or {}, "nested_group_ids": row.nested_group_ids or [], "active": row.active}
    except Exception as exc:
        db.rollback()
        raise _error(exc) from exc


@router.get("/groups/{group_id}/members")
def preview_group_members(
    group_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    group = db.scalar(select(PolicyPackUserGroup).where(PolicyPackUserGroup.tenant_id == ctx.tenant.id, PolicyPackUserGroup.id == group_id))
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="policy_pack_group_not_found")
    return {"group_id": group.id, "group_key": group.group_key, "membership_rule": group.membership_rule or {}, "members": resolve_group_member_ids(db, tenant_id=ctx.tenant.id, group_id=group.id)}


@router.get("/effective-policy")
def effective_policy(
    actor_user_id: str | None = Query(default=None),
    application: str | None = Query(default=None),
    provider: str | None = Query(default=None),
    model: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    source_surface: str | None = Query(default=None),
    action_class: str | None = Query(default=None),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return resolve_effective_policy_explanation(db, tenant_id=ctx.tenant.id, context={"actor_user_id": actor_user_id, "application": application, "provider": provider, "model": model, "agent_id": agent_id, "source_surface": source_surface, "action_class": action_class})
